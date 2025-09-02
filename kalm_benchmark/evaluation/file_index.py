import bisect
from dataclasses import dataclass

import yaml


@dataclass
class K8sObject:
    name: str
    kind: str
    namespace: str | None = None


class FileIndex:
    """Creates an index of all the objects within a YAML file.

    Provides efficient access to YAML objects within a multi-document file
    using either sequential index or line number-based lookup. Objects can
    be stored as parsed Python objects or as raw line collections.
    """

    def __init__(self, lines: list[str], sep: str = "---", store_as_objects: bool = True):
        """
        Parses multi-document YAML content and creates indexed access structures
        for efficient object retrieval by position or line number.

        :param lines: The list of lines within the file
        :param sep: Separator used to differentiate multiple objects. Defaults to "---"
        :param store_as_objects: Flag specifying if the lines of an object will be parsed to a Python object.
            Defaults to True
        """
        self.objects = []
        self.breakpoints = []

        curr_object = []

        for line_nr, line in enumerate(lines, start=1):
            if line.strip() != sep:
                curr_object.append(line)
            else:
                # store the breakpoints for the bisect-based retrieval
                self.breakpoints.append(line_nr)
                self._add_object(curr_object, store_as_object=store_as_objects)
                curr_object = []
        # ensure last object is also added
        self._add_object(curr_object, store_as_objects)

    def _add_object(self, obj_lines: list[str], store_as_object: bool = True) -> None:
        """Add an object to the index, either as a parsed YAML object or as raw lines.

        :param obj_lines: The lines that make up the object
        :param store_as_object: Whether to parse the lines as YAML object or store as raw lines
        """
        if store_as_object:
            obj = yaml.safe_load("\n".join(obj_lines))
            self.objects.append(obj)
        else:
            self.objects.append(obj_lines)

    def __getitem__(self, index: int) -> list[str]:
        return self.objects[index]

    def get_at_line(self, line_nr: int) -> list[str]:
        """Uses binary search on breakpoint markers to efficiently locate
        the object containing the specified line number.

        :param line_nr: The line number within the file
        :return: The indexed object containing the specified line
        """
        i = bisect.bisect_left(self.breakpoints, line_nr)
        return self.objects[i]

    def __len__(self):
        return len(self.objects)

    @classmethod
    def create_from_file(cls, path: str) -> "FileIndex":
        """Factory method that reads the specified file and creates an indexed
        representation of its YAML objects for efficient access.

        :param path: The path to the file which will be indexed
        :return: The created FileIndex instance
        """
        with open(path, "r") as f:
            lines = f.readlines()
        return cls(lines)
