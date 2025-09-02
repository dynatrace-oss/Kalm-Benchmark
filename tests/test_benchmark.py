from unittest.mock import MagicMock, patch

import pytest

from kalm_benchmark import benchmark
from kalm_benchmark.evaluation.scanner_manager import ScannerBase, ScannerManager
from kalm_benchmark.utils import scan_utils
from kalm_benchmark.utils.constants import UpdateType

SCANNER_BOTH = "both"
SCANNER_MANIFESTS = "manifests"
SCANNER_CLUSTER = "cluster"
SCANNER_NONE = "none"


def _create_mock(name, can_scan_cluster=False, can_scan_manifests=False) -> MagicMock:
    mock_scanner = MagicMock(spec=ScannerBase)
    mock_scanner.NAME = name
    mock_scanner.can_scan_cluster = can_scan_cluster
    mock_scanner.can_scan_manifests = can_scan_manifests
    return mock_scanner


@pytest.fixture()
def manager():
    manager = ScannerManager()
    manager.scanners = {
        SCANNER_BOTH: _create_mock(SCANNER_BOTH, can_scan_cluster=True, can_scan_manifests=True),
        SCANNER_CLUSTER: _create_mock(SCANNER_CLUSTER, can_scan_cluster=True),
        SCANNER_MANIFESTS: _create_mock(SCANNER_MANIFESTS, can_scan_manifests=True),
        SCANNER_NONE: _create_mock(SCANNER_NONE),
    }
    return manager


@pytest.fixture(autouse=True)
def mock_scanners(manager):
    """Patch the scanner manager for all unittests"""
    with patch.object(scan_utils, "SCANNERS", manager):
        yield


class TestScanExecution:
    @pytest.fixture()
    def mock_scan_variants(self, monkeypatch):
        with patch.object(benchmark, "scan_manifests") as scan_manifests_mock, patch.object(
            benchmark, "scan_cluster"
        ) as scan_cluster_mock:
            scan_manifests_mock.return_value = iter([])
            scan_cluster_mock.return_value = iter([])
            yield scan_manifests_mock, scan_cluster_mock

    def test_no_source_starts_cluster_scan_with_default_context_if_supported(self, mock_scan_variants):
        scan_manifests, scan_cluster = mock_scan_variants
        res = benchmark.scan(SCANNER_CLUSTER)
        updates = list(res)
        scan_manifests.assert_not_called()
        scan_cluster.assert_called()

        # last update is the error message
        _, msg = updates[-1]
        assert "no source specified, scanning cluster" in msg.lower()

    def test_no_source_yields_error_if_cluster_scan_not_supported(self, mock_scan_variants):
        scan_manifests, scan_cluster = mock_scan_variants
        res = benchmark.scan(SCANNER_MANIFESTS)
        updates = list(res)
        scan_manifests.assert_not_called()
        scan_cluster.assert_not_called()

        # last update is the error message
        lvl, msg = updates[-1]
        assert lvl == UpdateType.Error
        assert "No source specified" in msg

    def test_both_sources_manifest_takes_precedence(self, mock_scan_variants):
        scan_manifests, scan_cluster = mock_scan_variants
        res = benchmark.scan(SCANNER_BOTH, context="cluster", target_path="./")
        updates = list(res)
        scan_manifests.assert_called()
        scan_cluster.assert_not_called()

        # last update is the error message
        lvl, msg = updates[-1]
        assert lvl == UpdateType.Warning
        assert "only the manifest scan will be executed" in msg.lower()

    def test_both_sources_scan_cluster_if_manifest_not_supported(self, mock_scan_variants):
        scan_manifests, scan_cluster = mock_scan_variants
        res = benchmark.scan(SCANNER_CLUSTER, context="cluster", target_path="./")
        updates = list(res)
        scan_manifests.assert_not_called()
        scan_cluster.assert_called()

        # last update is the error message
        lvl, _ = updates[-1]
        assert lvl == UpdateType.Warning

    def test_both_sources_yield_error_if_nothing_supported(self, mock_scan_variants):
        scan_manifests, scan_cluster = mock_scan_variants
        res = benchmark.scan(SCANNER_NONE, context="cluster", target_path="./")
        updates = list(res)
        scan_manifests.assert_not_called()
        scan_cluster.assert_not_called()

        # last update is the error message
        lvl, _ = updates[-1]
        assert lvl == UpdateType.Error

    def test_use_manifest_scan_if_path_is_specified(self, mock_scan_variants):
        scan_manifests, scan_cluster = mock_scan_variants
        res = benchmark.scan(SCANNER_MANIFESTS, target_path="./")
        _ = list(res)
        scan_manifests.assert_called()
        scan_cluster.assert_not_called()

    def test_yield_error_if_path_is_specified_but_scan_not_supported(self, mock_scan_variants):
        scan_manifests, scan_cluster = mock_scan_variants
        res = benchmark.scan(SCANNER_NONE, target_path="./")
        updates = list(res)
        scan_manifests.assert_not_called()
        scan_cluster.assert_not_called()

        # last update is the error message
        lvl, _ = updates[-1]
        assert lvl == UpdateType.Error

    def test_use_cluster_scan_if_context_is_specified(self, mock_scan_variants):
        scan_manifests, scan_cluster = mock_scan_variants
        res = benchmark.scan(SCANNER_CLUSTER, context="cluster")
        list(res)
        scan_manifests.assert_not_called()
        scan_cluster.assert_called()

    def test_yield_error_if_context_is_specified_but_cluster_scan_not_supported(self, mock_scan_variants):
        scan_manifests, scan_cluster = mock_scan_variants
        res = benchmark.scan(SCANNER_MANIFESTS, context="cluster")
        updates = list(res)
        scan_manifests.assert_not_called()
        scan_cluster.assert_not_called()

        # last update is the error message
        lvl, _ = updates[-1]
        assert lvl == UpdateType.Error
