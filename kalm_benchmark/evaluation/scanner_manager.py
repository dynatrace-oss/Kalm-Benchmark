import difflib
import importlib
import pkgutil
from typing import Optional

from loguru import logger

import kalm_benchmark.evaluation.scanner as scanner_ns

from .scanner.scanner_evaluator import ScannerBase


class ScannerManager:
    """
    Scanners are managed like plugins in the `scanner` directory.
    The only prequisite for a scanner to be automatically loaded is that the
    file contains a class called `Scanner`
    """

    def __init__(self):
        self.scanners = {}

    def discover_scanners(self):
        """Import all files from the scanner directiory and try to register them in the manager"""
        # taken from: https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins
        # Specifying the second argument (prefix) to iter_modules makes the
        # returned name an absolute name instead of a relative one. This allows
        # import_module to work without having to do additional modification to
        # the name.
        modules = list(pkgutil.iter_modules(scanner_ns.__path__, scanner_ns.__name__ + "."))
        if len(modules) == 0:
            logger.warning(f"No scanner modules found at '{scanner_ns.__path__[0]}'")

        for finder, name, ispkg in modules:
            try:
                module = importlib.import_module(name)
                if hasattr(module, "Scanner"):
                    self.scanners[module.Scanner.NAME] = module.Scanner()
            except Exception as exc:
                logger.error(f"Could not import module '{name}': {exc}")

    def get(self, name: str) -> Optional[ScannerBase]:
        """Getter to retrieve the scanner evaluator for the given name

        :param name: the name of the scanner
        :return: the evaluator handling the scanner evaluation
        """
        return self.scanners.get(name, None)

    def closest_matches(self, name: str, n: int = 2) -> list[str]:
        """Retrieve the name of a scanner which is the closest match to the given name.
        First, do a case insensitive lookup. If this does not yield any results look for
        names with minor deviations.

        :param name: the name to look up
        :param n: the number of closest matches to return
        :return: the name(s) of the closest matching scanner
        """
        # first, just check case insensitive version
        found_name = next((n for n in self.scanners.keys() if n.lower() == name.lower()), None)
        if found_name is not None:
            return [found_name]

        # if not, look for similar matches
        return difflib.get_close_matches(name, self.scanners.keys(), n=n)

    def items(self):
        return self.scanners.items()

    def keys(self):
        return self.scanners.keys()

    def index(self, name: str):
        return list(self.scanners.keys()).index(name)


# modules are loaded only once, so instantiating it here makes it basically a singleton
SCANNERS = ScannerManager()
SCANNERS.discover_scanners()
