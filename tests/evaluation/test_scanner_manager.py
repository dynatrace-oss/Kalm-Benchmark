from pathlib import Path
from unittest.mock import patch

import pytest
from loguru import logger

from kalm_benchmark.evaluation.scanner_manager import SCANNERS as real_manager
from kalm_benchmark.evaluation.scanner_manager import (
    ScannerBase,
    ScannerManager,
    scanner_ns,
)


@pytest.fixture
def caplog(caplog):
    # suppress default loggers and override caplog to capture loguru logs
    # https://github.com/Delgan/loguru/issues/59#issuecomment-1016516449
    logger.remove()
    handler_id = logger.add(caplog.handler, format="{message}")
    yield caplog
    logger.remove(handler_id)


class _MockScanner(ScannerBase):
    NAME: str = "mock"

    @classmethod
    def parse_results(cls, results):
        return []


@pytest.fixture()
def manager():
    return ScannerManager()


@pytest.fixture()
def prefilled_manager(manager):
    manager.scanners = {
        "a_scanner": _MockScanner(),
        "i-find-everything": _MockScanner(),
        "kubee": _MockScanner(),
        "another-tool": _MockScanner(),
    }
    return manager


def test_scanner_manager_is_instantated_at_runtime():
    assert isinstance(real_manager, ScannerManager)


class TestScannerDiscovery:
    def test_log_error_when_scanner_folder_does_not_exist(self, manager, caplog):
        # the discovery method uses the path of the scanners module as it's search directory
        # changing it to a bogus path will lead to no valid modules being found
        with patch(ScannerManager.__module__ + ".scanner_ns.__path__", ["/this/path/does/not/exist"]):
            manager.discover_scanners()
            assert "no scanner" in caplog.text.lower()

    def test_no_scanners_in_folder_is_no_problem(self, manager, fs):
        # try to discover scanners from the fake file system, which as no files (due to the fs mock)
        manager.discover_scanners()
        assert len(manager.keys()) == 0

    def test_malformed_file_is_handled_gracefully(self, manager, caplog, fs):
        scanner_name = "a_scanner"
        scanner_path = Path(scanner_ns.__path__[0]) / f"{scanner_name}.py"
        fs.create_file(scanner_path)
        with open(scanner_path, "w") as f:
            f.write("def i_am_an_invalid_function_defintion")
        manager.discover_scanners()
        err_msg = caplog.text.lower()
        assert scanner_name in err_msg
        assert "could not import module" in err_msg


class TestScannerRetrieval:
    def test_scanners_are_accessed_via_getter(self, prefilled_manager):
        res = prefilled_manager.get("a_scanner")
        assert isinstance(res, _MockScanner)

    def test_non_existing_scanner_yields_none(self, prefilled_manager):
        res = prefilled_manager.get("I-dont-exist")
        assert res is None


class TestClosestScannerLookup:
    def test_exact_match_is_single_result(self, manager):
        name = "This-Will-Be-An-Exact-Match"
        manager.scanners[name] = _MockScanner()
        res = manager.closest_matches(name)
        assert res == [name]

    def test_multiple_close_matches_returns_list(self, manager):
        close_matches = set(["my-scanner", "my-scar"])
        for s in close_matches:
            manager.scanners[s] = _MockScanner

        res = manager.closest_matches("my-scanr", n=len(close_matches))
        assert isinstance(res, list)
        assert set(res) == close_matches

    def test_no_close_match_returns_empty_collection(self, manager):
        res = manager.closest_matches("THERE_IS_NOT_A_SINGLE_EVEN_REMOTELY_CLOSE_SCANNER!!", n=10)
        assert len(res) == 0
