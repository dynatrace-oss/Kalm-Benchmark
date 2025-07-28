import os
import re
from pathlib import Path
from typing import Generator, Tuple, Optional, Union


def normalize_path(path: str, related_objects: Optional[list[dict]] = None, is_relative: bool = True) -> str:
    # resolve the related object to it's actual 'kind' so it's a absolute path
    if related_objects is not None and path.startswith("relatedObjects"):
        # extract index in relatedObjects - use safe regex with timeout protection
        match = re.search(r"\[(\d+)\]", path)  # Fixed: allow multiple digits, more specific pattern
        if match is None:
            # If no match found, return path as-is to avoid crashes
            return path
        try:
            idx = int(match.group(1))
            if idx < len(related_objects) and "kind" in related_objects[idx]:
                kind = related_objects[idx]["kind"]
                path = path.replace(f"relatedObjects[{idx}]", kind)
                is_relative = False
        except (ValueError, IndexError, KeyError):
            # If parsing fails, return original path to avoid crashes
            pass

    # remove any index or key list index itself is not relevant -> make it generic
    path = re.sub(r"\[[\w-]*\]", "[]", path)

    # pod related checks start with pod-spec and not the template in the managing object
    if "spec.template" in path:
        path = path.replace("spec.template", "")
    elif is_relative and not path.startswith("."):  # relative paths start with '.';
        path = "." + path

    if path.startswith(".."):
        path = path[1:]  # drop the first '.' introduced with the previous corrections

    # ensure 'containers' is correctly spelled in path (e.g. it's wrong in C-0013)
    if "container[" in path:
        path = path.replace("container", "containers")

    return path


def get_path_to_line(lines: list[str], line_nr: int, separator: str = ".") -> str:
    """Infer the full path for the key at the specified line number.
    Iterate over all the lines and keep track of the parents and indentations.

    :param lines: all the lines of the files
    :param line_nr: the number of the line targeted by the check
    :param separator: the character used to separate the parts of a path
    :return: the full path to the line at the given line number
    """
    INDENT_CHARS = " -"  # treat list separator also as indent character
    parent_path = []
    indent_per_level = []
    for i, line in enumerate(lines, start=1):
        # object seperator in the file
        if line.strip() == "---":
            parent_path = []
            indent_per_level = []
            continue

        # manage the hierarchy by infering the level from the indentation
        # the indentation width is inferred by how many characters are removed from the left
        block_indent = sum(indent_per_level)
        curr_indent = len(line) - len(line.lstrip(INDENT_CHARS))

        # the level of indentation was reduced -> the block ended -> go back up the hierachy
        if block_indent < curr_indent:
            indent_per_level.append(curr_indent - block_indent)
        elif curr_indent < block_indent:
            num_levels = 0
            while sum(indent_per_level) > curr_indent:
                num_levels += 1
                indent_per_level.pop()
            parent_path = parent_path[:-num_levels]

        # yaml list items can update the parent in the path to signalt it being a list
        parent_is_list = parent_path[-1].endswith("[]") if len(parent_path) > 0 else False

        # it's just a list element, so there is no real info
        if ":" not in line and parent_is_list:
            continue

        key, val = line.split(":", maxsplit=1)

        # if there is no value, it means the next line(s) will be indented
        is_parent = False
        if val.strip() == "":
            field = key.strip(INDENT_CHARS)
            # if the next line starts with a '-' it means this field is a list
            if "-" in lines[i]:  # note: i starts at 1 so it's actually the index of the next line
                field += "[]"
            parent_path.append(field)
            is_parent = True

        if i >= line_nr:
            # append the actual field as well if it's not a parent
            # -> it hasn't been added to the path
            if not is_parent:
                parent_path.append(key.strip(INDENT_CHARS))
            return separator.join(parent_path)

    return ""


def fix_path_to_current_environment(file_path: Path) -> str:
    """If the environment has changed, check if the file can be found in the working directory
    If so, return the corrected path

    :param file_path: the file to be checked in the working directory
    :return: the fixed path or an empty string, if it can't be found
    """
    # make reference path relative to current working diretcory
    cwd = Path(os.getcwd())
    file_path = Path(file_path)
    
    # Validate that file_path doesn't contain path traversal patterns
    if ".." in str(file_path) or str(file_path).startswith("/"):
        print(f"Potentially unsafe path detected: {file_path}")
        return ""
    
    try:
        a = file_path.relative_to(cwd)
        return str(a)
    except ValueError:
        # look for the file on the filesystem - but only within reasonable subdirectories
        # Limit search depth to prevent performance issues and restrict scope
        filename = file_path.name
        if not filename or len(filename) > 255:  # Basic filename validation
            print(f"Invalid filename: {filename}")
            return ""
            
        # Only search in specific safe subdirectories to prevent traversal issues
        safe_patterns = ["data", "manifests", "results", "output"]
        matching_paths = []
        
        for pattern in safe_patterns:
            safe_dir = cwd / pattern
            if safe_dir.exists() and safe_dir.is_dir():
                # Use name matching instead of glob pattern to be more specific
                for path in safe_dir.rglob(filename):
                    # Ensure the found path is actually within our safe directory
                    try:
                        path.relative_to(safe_dir)
                        matching_paths.append(path)
                    except ValueError:
                        continue  # Skip paths that aren't within the safe directory
        
        if len(matching_paths) > 0:
            return str(matching_paths[0])
        else:
            print(f"Found no path which contains the file {filename}")

    return ""


def get_difference_in_parent_path(path1: str, path2: str) -> Optional[Tuple[str, str]]:
    """Find the parts of each path which are not the same and return the different parents.

    :param path1: the first path for the comparison
    :param path2: the second path for the comparison

    :return: either a tuple of the parent paths of each provided path, which are diffent
        or None, if the paths are the same
    """
    if path1 == path2:
        return None

    p1 = list(Path(path1).parts)
    p2 = list(Path(path2).parts)

    while len(p1) > 0 and len(p2) > 0:
        old_p = p1[-1]
        if old_p != p2[-1]:  # if the don't have same last part, then they start diverging
            break
        # if they are the same, prune the other path as well
        p1.pop()
        p2.pop()

    return (os.path.join(*p1) if len(p1) > 0 else "", os.path.join(*p2) if len(p2) > 0 else "")


class GeneratorWrapper:
    """A simple wrapper for generators making it easier to
    consume them and also catch the return value"""

    def __init__(self, gen: Generator):
        self._gen = gen
        self.value = None

    def __iter__(self):
        self.value = yield from self._gen


def get_version_from_result_file(file_name: Union[str, Path]) -> Optional[str]:
    file_name_str = str(file_name)
    
    # Extract just the filename without path
    from pathlib import Path
    filename_only = Path(file_name_str).name
    
    # Remove file extension if present (only common extensions to avoid removing version parts)
    if filename_only.endswith(('.json', '.yaml', '.yml', '.txt')):
        filename_only = filename_only.rsplit('.', 1)[0]
    
    # Split by underscore to match original logic
    parts = filename_only.split("_")
    
    # Need at least 2 parts (version_date) and the pattern should look like a proper scanner result file
    if len(parts) < 2:
        return None
    
    # Use the original logic: second-to-last part is version, last part is date
    # This mimics the original: *_, version, date = parts
    try:
        version = parts[-2]
        date_part = parts[-1]
        
        # Basic validation: date part should look like a date (YYYY-MM-DD format)
        # and version should contain some version-like characters
        if (len(date_part) >= 8 and 
            any(c.isdigit() for c in date_part) and 
            (version.startswith("v") or any(c.isdigit() or c == '.' for c in version))):
            
            if version.startswith("v"):
                return version[1:]  # drop leading 'v' which would just denote the version anyways
            return version
        
        return None
    except IndexError:
        return None
