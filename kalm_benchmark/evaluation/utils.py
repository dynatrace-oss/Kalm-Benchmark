import os
import re
from pathlib import Path
from typing import Generator, Optional, Tuple, Union

from loguru import logger


def normalize_path(path: str, related_objects: Optional[list[dict]] = None, is_relative: bool = True) -> str:
    if related_objects is not None and path.startswith("relatedObjects"):
        match = re.search(r"\[(\d+)\]", path)
        if match is None:
            return path
        try:
            idx = int(match.group(1))
            if idx < len(related_objects) and "kind" in related_objects[idx]:
                kind = related_objects[idx]["kind"]
                path = path.replace(f"relatedObjects[{idx}]", kind)
                is_relative = False
        except (ValueError, IndexError, KeyError):
            pass

    path = re.sub(r"\[[\w-]*\]", "[]", path)

    # pod related checks start with pod-spec and not the template in the managing object
    if "spec.template" in path:
        path = path.replace("spec.template", "")
    elif is_relative and not path.startswith("."):  # relative paths start with '.';
        path = "." + path

    if path.startswith(".."):
        path = path[1:]

    # ensure 'containers' is correctly spelled in path (e.g. it's wrong in C-0013)
    if "container[" in path:
        path = path.replace("container", "containers")

    return path


def _calculate_indentation(line: str, indent_chars: str) -> int:
    """Calculate the indentation level of a line."""
    return len(line) - len(line.lstrip(indent_chars))


def _update_hierarchy(parent_path: list[str], indent_per_level: list[int], block_indent: int, curr_indent: int) -> None:
    """Update the hierarchy based on current indentation level."""
    if block_indent < curr_indent:
        indent_per_level.append(curr_indent - block_indent)
    elif curr_indent < block_indent:
        num_levels = 0
        while sum(indent_per_level) > curr_indent:
            num_levels += 1
            indent_per_level.pop()
        # Remove the corresponding parent levels
        for _ in range(num_levels):
            if parent_path:
                parent_path.pop()


def _is_yaml_document_separator(line: str) -> bool:
    """Check if line is a YAML document separator."""
    return line.strip() == "---"


def _is_list_element_line(line: str, parent_is_list: bool) -> bool:
    """Check if line is just a list element with no key-value pair."""
    return ":" not in line and parent_is_list


def _process_yaml_field(
    line: str, lines: list[str], line_index: int, indent_chars: str, parent_path: list[str]
) -> bool:
    """Process a YAML field and update parent path if needed.

    Returns True if this field is a parent (has child elements).
    """
    key, val = line.split(":", maxsplit=1)

    if val.strip() == "":
        field = key.strip(indent_chars)
        # Check if next line indicates this is a list
        if line_index < len(lines) and "-" in lines[line_index]:
            field += "[]"
        parent_path.append(field)
        return True
    return False


def get_path_to_line(lines: list[str], line_nr: int, separator: str = ".") -> str:
    """Infer the full path for the key at the specified line number.
    Iterate over all the lines and keep track of the parents and indentations.

    :param lines: all the lines of the files
    :param line_nr: the number of the line targeted by the check
    :param separator: the character used to separate the parts of a path
    :return: the full path to the line at the given line number
    """
    INDENT_CHARS = " -"
    parent_path = []
    indent_per_level = []

    for i, line in enumerate(lines, start=1):
        if _is_yaml_document_separator(line):
            parent_path = []
            indent_per_level = []
            continue

        block_indent = sum(indent_per_level)
        curr_indent = _calculate_indentation(line, INDENT_CHARS)

        _update_hierarchy(parent_path, indent_per_level, block_indent, curr_indent)

        parent_is_list = len(parent_path) > 0 and parent_path[-1].endswith("[]")

        if _is_list_element_line(line, parent_is_list):
            continue

        if ":" not in line:
            continue

        is_parent = _process_yaml_field(line, lines, i, INDENT_CHARS, parent_path)

        if i >= line_nr:
            if not is_parent:
                key = line.split(":", maxsplit=1)[0]
                parent_path.append(key.strip(INDENT_CHARS))
            return separator.join(parent_path)

    return ""


def _is_safe_path(file_path: Path) -> bool:
    """Check if a file path is safe from path traversal attacks."""
    return ".." not in str(file_path) and not str(file_path).startswith("/")


def _is_valid_filename(filename: str) -> bool:
    """Check if a filename is valid and not too long."""
    return bool(filename) and len(filename) <= 255


def _find_in_safe_directories(cwd: Path, filename: str) -> list[Path]:
    """Search for a filename in predefined safe directories."""
    safe_patterns = ["data", "manifests", "results", "output"]
    matching_paths = []

    for pattern in safe_patterns:
        safe_dir = cwd / pattern
        if not (safe_dir.exists() and safe_dir.is_dir()):
            continue

        for path in safe_dir.rglob(filename):
            try:
                path.relative_to(safe_dir)
                matching_paths.append(path)
            except ValueError:
                continue

    return matching_paths


def fix_path_to_current_environment(file_path: Path) -> str:
    """If the environment has changed, check if the file can be found in the working directory
    If so, return the corrected path

    :param file_path: the file to be checked in the working directory
    :return: the fixed path or an empty string, if it can't be found
    """
    cwd = Path(os.getcwd())
    file_path = Path(file_path)

    if not _is_safe_path(file_path):
        logger.warning(f"Potentially unsafe path detected: {file_path}")
        return ""

    try:
        relative_path = file_path.relative_to(cwd)
        return str(relative_path)
    except ValueError:
        pass

    filename = file_path.name
    if not _is_valid_filename(filename):
        logger.warning(f"Invalid filename: {filename}")
        return ""

    matching_paths = _find_in_safe_directories(cwd, filename)

    if matching_paths:
        return str(matching_paths[0])

    logger.debug(f"Found no path which contains the file {filename}")
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
        if old_p != p2[-1]:
            break
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

    from pathlib import Path

    filename_only = Path(file_name_str).name

    if filename_only.endswith((".json", ".yaml", ".yml", ".txt")):
        filename_only = filename_only.rsplit(".", 1)[0]

    parts = filename_only.split("_")

    if len(parts) < 2:
        return None

    try:
        version = parts[-2]
        date_part = parts[-1]

        if (
            len(date_part) >= 8
            and any(c.isdigit() for c in date_part)
            and (version.startswith("v") or any(c.isdigit() or c == "." for c in version))
        ):

            if version.startswith("v"):
                return version[1:]
            return version

        return None
    except IndexError:
        return None
