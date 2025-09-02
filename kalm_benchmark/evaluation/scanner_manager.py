import difflib
import importlib
import pkgutil
from typing import Optional

from loguru import logger

import kalm_benchmark.evaluation.scanner as scanner_ns

from .scanner.scanner_evaluator import ScannerBase


class ScannerManager:
    """Plugin-based manager for security scanner tools.

    Automatically discovers and loads scanner implementations from the scanner
    directory using a plugin architecture. Each scanner module must contain
    a class called `Scanner` to be automatically registered.

    Provides case-insensitive lookup and similarity matching for scanner names
    to improve user experience and handle naming variations.
    """

    def __init__(self):
        """Initialize the scanner manager with an empty scanner registry."""
        self.scanners = {}

    def discover_scanners(self):
        """Import all files from the scanner directory and register them.

        Uses Python's plugin discovery mechanism to automatically load and
        register all scanner implementations found in the scanner package.
        Handles import errors gracefully and provides debug information.
        """
        # taken from: https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins
        # Specifying the second argument (prefix) to iter_modules makes the
        # returned name an absolute name instead of a relative one. This allows
        # import_module to work without having to do additional modification to
        # the name.
        modules = list(pkgutil.iter_modules(scanner_ns.__path__, scanner_ns.__name__ + "."))
        if len(modules) == 0:
            logger.warning(f"No scanner modules found at '{scanner_ns.__path__[0]}'")
            return

        for finder, name, ispkg in modules:
            try:
                module = importlib.import_module(name)
                if hasattr(module, "Scanner"):
                    scanner_name = module.Scanner.NAME
                    self.scanners[scanner_name] = module.Scanner()
                else:
                    # Skip logging for scanner_evaluator since it's the base class, not a scanner
                    if not name.endswith("scanner_evaluator"):
                        logger.debug(f"Module '{name}' does not have a Scanner class")
            except Exception as exc:
                logger.error(f"Could not import module '{name}': {exc}")

    def get(self, name: str) -> Optional[ScannerBase]:
        """Retrieve the scanner evaluator for the given name.

        Performs exact name lookup to find the registered scanner instance
        corresponding to the specified scanner name.

        :param name: The name of the scanner
        :return: The evaluator handling the scanner evaluation, or None if not found
        """
        return self.scanners.get(name, None)

    def closest_matches(self, name: str, n: int = 2) -> list[str]:
        """Retrieve scanner names that are closest matches to the given name.

        Performs fuzzy matching to help users find scanners when they provide
        inexact names. First attempts case-insensitive lookup, then uses
        string similarity algorithms for approximate matching.

        :param name: The name to look up
        :param n: The number of closest matches to return. Defaults to 2
        :return: List of the closest matching scanner names
        """
        # first, just check case insensitive version
        found_name = next((n for n in self.scanners.keys() if n.lower() == name.lower()), None)
        if found_name is not None:
            return [found_name]

        # if not, look for similar matches
        return difflib.get_close_matches(name, self.scanners.keys(), n=n)

    def items(self):
        """Return an iterator over scanner name-instance pairs.

        :return: Iterator over (name, scanner_instance) tuples
        """
        return self.scanners.items()

    def keys(self):
        """Return an iterator over registered scanner names.

        :return: Iterator over scanner names
        """
        return self.scanners.keys()

    def index(self, name: str):
        """Get the index position of a scanner name in the registry.

        :param name: The scanner name to find the index for
        :return: The index position of the scanner name
        :raises ValueError: If the scanner name is not found
        """
        return list(self.scanners.keys()).index(name)


# modules are loaded only once, so instantiating it here makes it basically a singleton
SCANNERS = ScannerManager()
SCANNERS.discover_scanners()
