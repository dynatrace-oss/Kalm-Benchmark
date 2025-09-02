from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kalm_benchmark.evaluation.evaluation import EvaluationSummary
from kalm_benchmark.evaluation.scanner_service import EvaluationService
from kalm_benchmark.ui.interface import gen_utils
from kalm_benchmark.utils.constants import LAST_SCAN_OPTION, SessionKeys


class TestDatabaseBasedSummaryLoading:
    """Test summary loading from database"""

    @patch("kalm_benchmark.ui.interface.gen_utils.get_unified_service")
    def test_summary_loaded_from_database(self, mock_get_service):
        tool = "my-tool"
        mock_service = MagicMock(spec=EvaluationService)
        mock_get_service.return_value = mock_service

        expected_summary = EvaluationSummary(
            version="1.0.0",
            checks_per_category={"security": [1]},
            score=0.8,
            coverage=0.9,
            extra_checks=0,
            missing_checks=1,
        )
        mock_service.load_scanner_summary.return_value = expected_summary

        summary = gen_utils._load_and_cache_scanner_summary(tool, "scan-run-id")
        assert summary == expected_summary
        mock_service.load_scanner_summary.assert_called_once_with(tool, None)

    @patch("kalm_benchmark.ui.interface.gen_utils.get_unified_service")
    def test_no_summary_returns_none(self, mock_get_service):
        tool = "my-tool"
        mock_service = MagicMock(spec=EvaluationService)
        mock_get_service.return_value = mock_service
        mock_service.load_scanner_summary.return_value = None

        summary = gen_utils._load_and_cache_scanner_summary(tool, "non-existent-id")
        assert summary is None

    @patch("kalm_benchmark.ui.interface.gen_utils.get_unified_service")
    def test_database_error_returns_none(self, mock_get_service):
        tool = "my-tool"
        mock_service = MagicMock(spec=EvaluationService)
        mock_get_service.return_value = mock_service
        mock_service.load_scanner_summary.side_effect = Exception("Database error")

        summary = gen_utils._load_and_cache_scanner_summary(tool, "scan-run-id")
        assert summary is None

    @patch("kalm_benchmark.ui.interface.gen_utils.get_unified_service")
    def test_ephemeral_results_handling(self, mock_get_service):
        """Test handling of ephemeral (latest scan) results"""
        tool = "my-tool"
        mock_service = MagicMock(spec=EvaluationService)
        mock_get_service.return_value = mock_service

        # First call returns None (no cached summary)
        # Second call should generate from ephemeral results
        mock_service.load_scanner_summary.return_value = None

        with patch.object(gen_utils, "is_ephemeral_scan_result", return_value=True), patch.object(
            gen_utils, "load_scan_result"
        ), patch.object(gen_utils, "SCANNERS") as mock_scanners, patch.object(
            gen_utils.evaluation, "evaluate_scanner"
        ), patch.object(
            gen_utils.evaluation, "create_summary"
        ) as mock_create:
            mock_scanner = MagicMock()
            mock_scanners.get.return_value = mock_scanner

            expected_summary = EvaluationSummary(
                version="1.0.0",
                checks_per_category={"test": [1]},
                score=0.8,
                coverage=0.9,
                extra_checks=0,
                missing_checks=1,
            )
            mock_create.return_value = expected_summary

            summary = gen_utils._load_and_cache_scanner_summary(tool, "ephemeral-result")
            assert summary == expected_summary

    @patch("kalm_benchmark.ui.interface.gen_utils.get_unified_service")
    @patch("kalm_benchmark.ui.interface.gen_utils.is_ephemeral_scan_result")
    def test_scan_timestamp_extraction(self, mock_is_ephemeral, mock_get_service):
        """Test proper scan timestamp extraction for database queries"""
        tool = "my-tool"
        mock_service = MagicMock(spec=EvaluationService)
        mock_get_service.return_value = mock_service

        # Make sure result is not considered ephemeral
        mock_is_ephemeral.return_value = False

        # Mock database scan runs
        mock_service.get_scanner_result_files.return_value = [{"name": "test-run", "id": "scan-id-123"}]
        mock_db = MagicMock()
        mock_service.db = mock_db
        mock_db.get_scan_runs.return_value = [{"id": "scan-id-123", "timestamp": "2024-01-01T12:00:00"}]

        expected_summary = EvaluationSummary(
            version="1.0.0",
            checks_per_category={"test": [1]},
            score=0.8,
            coverage=0.9,
            extra_checks=0,
            missing_checks=1,
        )
        mock_service.load_scanner_summary.return_value = expected_summary

        summary = gen_utils._load_and_cache_scanner_summary(tool, "test-run")
        assert summary == expected_summary
        # Verify timestamp was extracted and used
        mock_service.load_scanner_summary.assert_called_with(tool, "2024-01-01T12:00:00")


@pytest.mark.parametrize(
    "file_name,expected_version",
    [
        ("tool1_v3.0.19_2023-11-02.json", "3.0.19"),
        ("data/tool2_v1.6.6_2023-08-31.json", "1.6.6"),
        ("data/summary/tool3_v1.980.0_2024-01-01", "1.980.0"),
        ("/tool4/_v1.5_2024-01-01", "1.5"),
        ("_v0.4.0-0-gc37b7551f6_2024-01-01", "0.4.0-0-gc37b7551f6"),
        (Path("/home/user/tool6_v1.3.3-7_2024-01-01"), "1.3.3-7"),
    ],
)
def test_get_version_from_file_name(file_name: str | Path, expected_version: str):
    from kalm_benchmark.utils.eval_utils import get_version_from_result_file

    vers = get_version_from_result_file(file_name=file_name)
    assert vers == expected_version


class TestDatabaseIntegration:
    """Test database integration in UI utils"""

    @patch("kalm_benchmark.ui.interface.gen_utils.get_unified_service")
    @patch("kalm_benchmark.ui.interface.gen_utils.st.session_state", {SessionKeys.LatestScanResult: {}})
    def test_get_result_files_from_database(self, mock_get_service):
        """Test getting result files from database instead of filesystem"""
        mock_service = MagicMock(spec=EvaluationService)
        mock_get_service.return_value = mock_service

        mock_service.get_scanner_result_files.return_value = [
            {"name": "2024-01-01 (10 results)", "id": "scan-123"},
            {"name": "2024-01-02 (15 results)", "id": "scan-456"},
        ]

        files = gen_utils.get_result_files_of_scanner("trivy")

        assert len(files) == 2
        assert "2024-01-01 (10 results)" in files
        assert "2024-01-02 (15 results)" in files

    @patch("kalm_benchmark.ui.interface.gen_utils.get_unified_service")
    def test_load_scan_result_from_database(self, mock_get_service):
        """Test loading scan results from database"""
        mock_service = MagicMock(spec=EvaluationService)
        mock_get_service.return_value = mock_service

        mock_scanner = MagicMock()
        mock_scanner.NAME = "trivy"

        # Mock database scan runs for ID lookup
        mock_service.get_scanner_result_files.return_value = [{"name": "test-run", "id": "scan-123"}]

        expected_results = [{"check_id": "TEST-001", "severity": "HIGH"}]
        mock_service.load_scanner_results.return_value = expected_results

        with patch("kalm_benchmark.ui.interface.gen_utils.is_ephemeral_scan_result", return_value=False):
            results = gen_utils.load_scan_result(mock_scanner, "test-run")

        assert results == expected_results
        mock_service.load_scanner_results.assert_called_once_with("trivy", "scan-123")

    @patch("kalm_benchmark.ui.interface.gen_utils.get_unified_service")
    def test_is_ephemeral_scan_result(self, mock_get_service):
        """Test ephemeral scan result detection"""
        mock_service = MagicMock(spec=EvaluationService)
        mock_get_service.return_value = mock_service
        mock_service.is_ephemeral_scan_result.return_value = True

        # Test with traditional ephemeral indicators
        assert gen_utils.is_ephemeral_scan_result(LAST_SCAN_OPTION) is True
        assert gen_utils.is_ephemeral_scan_result("tool_latest_scan_result") is True

        # Test with database check
        assert gen_utils.is_ephemeral_scan_result("some-scan-id") is True
        mock_service.is_ephemeral_scan_result.assert_called_once_with("some-scan-id")

    @patch("kalm_benchmark.ui.interface.gen_utils.get_unified_service")
    def test_ephemeral_results_in_file_list(self, mock_get_service):
        """Test that ephemeral results appear in file list when available"""
        mock_service = MagicMock(spec=EvaluationService)
        mock_get_service.return_value = mock_service

        mock_service.get_scanner_result_files.return_value = [{"name": "2024-01-01 (10 results)", "id": "scan-123"}]

        # Mock session state with ephemeral data
        with patch(
            "kalm_benchmark.ui.interface.gen_utils.st.session_state",
            {SessionKeys.LatestScanResult: {"trivy": ["some-data"]}},
        ):
            files = gen_utils.get_result_files_of_scanner("trivy")

        # Should have both ephemeral and database results
        assert len(files) == 2
        assert LAST_SCAN_OPTION in files
        assert "2024-01-01 (10 results)" in files
        # Ephemeral should be first
        assert files[0] == LAST_SCAN_OPTION
