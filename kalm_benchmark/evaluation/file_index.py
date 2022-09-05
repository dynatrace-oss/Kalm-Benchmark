import bisect
from dataclasses import dataclass

import yaml


@dataclass
class K8sObject:
    name: str
    kind: str
    namespace: str | None = None


class FileIndex:
    """Creates a index of all the objects within a YAML file.
    The objects can be accessed either via:
        - index in the order as they appear in the file
        - line number in the file
    """

    def __init__(self, lines: list[str], sep: str = "---", store_as_objects: bool = True):
        """Initializes a new FileIndex from the provided list of lines

        :param lines: the list of lines within the file
        :param sep: separator used to differentiate multiple objects, defaults to "---"
        :param store_as_objects: flag specifying if the lines of an object will be parsed
            to a Python object, defaults to True
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
        if store_as_object:
            obj = yaml.safe_load("\n".join(obj_lines))
            self.objects.append(obj)
        else:
            self.objects.append(obj_lines)

    def __getitem__(self, index: int) -> list[str]:
        return self.objects[index]

    def get_at_line(self, line_nr: int) -> list[str]:
        """Get the object of which the provided line number belongs to.

        :param line_nr: the line number within the file
        :return: the indexed object
        """
        i = bisect.bisect_left(self.breakpoints, line_nr)
        return self.objects[i]

    def __len__(self):
        return len(self.objects)

    @classmethod
    def create_from_file(cls, path: str) -> "FileIndex":
        """Creator function to initializes the FileIndex from a path to a file

        :param path: the path to the file which will be indexed
        :return: the created FileIndex
        """
        with open(path, "r") as f:
            lines = f.readlines()
        return cls(lines)
