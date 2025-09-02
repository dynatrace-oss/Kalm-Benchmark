import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckResult, ScannerBase
from kalm_benchmark.utils.exceptions import HelmChartError
from kalm_benchmark.utils.helm_operations import (
    _add_helm_repository,
    _download_single_chart,
    _update_helm_repositories,
    check_helm_installed,
    download_popular_charts,
    get_popular_charts,
    render_helm_chart,
    scan_helm_chart_generator,
)


class TestHelmUtils:
    """Test Helm utility functions."""

    @patch("kalm_benchmark.utils.helm_operations.subprocess.run")
    def test_check_helm_installed_success(self, mock_run):
        """Test successful Helm installation check."""
        mock_run.return_value = Mock(returncode=0)
        assert check_helm_installed() is True

    @patch("kalm_benchmark.utils.helm_operations.subprocess.run")
    def test_check_helm_installed_failure(self, mock_run):
        """Test failed Helm installation check."""
        mock_run.side_effect = FileNotFoundError()
        assert check_helm_installed() is False

    @patch("kalm_benchmark.utils.helm_operations.subprocess.run")
    def test_check_helm_installed_timeout(self, mock_run):
        """Test Helm installation check timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["helm"], timeout=10)
        assert check_helm_installed() is False

    @patch("kalm_benchmark.utils.helm_operations.urllib.request.urlopen")
    def test_get_popular_charts_api_success(self, mock_urlopen):
        """Test successful API response for popular charts."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(
            {
                "packages": [
                    {
                        "name": "test-chart",
                        "repository": {
                            "name": "test-repo",
                            "url": "https://test.example.com",
                            "verified_publisher": True,
                        },
                        "description": "A test chart",
                        "display_name": "Test Chart",
                    }
                ]
            }
        ).encode("utf-8")

        mock_urlopen.return_value.__enter__.return_value = mock_response

        charts = get_popular_charts(1)

        assert len(charts) == 1
        assert charts[0]["name"] == "test-chart"
        assert charts[0]["repo"] == "test-repo"
        assert charts[0]["verified"] is True

    @patch("kalm_benchmark.utils.helm_operations.urllib.request.urlopen")
    def test_get_popular_charts_api_failure_fallback(self, mock_urlopen):
        """Test API failure falls back to hardcoded list."""
        mock_urlopen.side_effect = Exception("Network error")

        charts = get_popular_charts(3)

        assert len(charts) == 3
        # Should contain fallback charts
        chart_names = [chart["name"] for chart in charts]
        assert "nginx" in chart_names
        assert "mysql" in chart_names

    @patch("kalm_benchmark.utils.helm_operations.subprocess.run")
    def test_add_helm_repository_success(self, mock_run):
        """Test successful repository addition."""
        mock_run.return_value = Mock(returncode=0)
        result = _add_helm_repository("test-repo", "https://test.example.com")
        assert result is True

    @patch("kalm_benchmark.utils.helm_operations.subprocess.run")
    def test_add_helm_repository_failure(self, mock_run):
        """Test failed repository addition."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["helm"], timeout=30)
        result = _add_helm_repository("test-repo", "https://test.example.com")
        assert result is False

    @patch("kalm_benchmark.utils.helm_operations.subprocess.run")
    def test_update_helm_repositories_success(self, mock_run):
        """Test successful repository update."""
        mock_run.return_value = Mock(returncode=0)
        result = _update_helm_repositories()
        assert result is True

    @patch("kalm_benchmark.utils.helm_operations.subprocess.run")
    def test_download_single_chart_success(self, mock_run):
        """Test successful single chart download."""
        mock_run.return_value = Mock(returncode=0)

        # Mock destination directory with chart
        mock_destination = MagicMock()
        mock_chart_path = Mock()
        mock_chart_path.exists.return_value = True
        mock_destination.__truediv__.return_value = mock_chart_path

        result = _download_single_chart("nginx", "bitnami", mock_destination)
        assert result == mock_chart_path

    @patch("kalm_benchmark.utils.helm_operations.subprocess.run")
    def test_download_single_chart_failure(self, mock_run):
        """Test failed single chart download."""
        mock_run.return_value = Mock(returncode=1)

        mock_destination = Mock()
        result = _download_single_chart("nonexistent", "invalid", mock_destination)
        assert result is None


class TestHelmChartRendering:
    """Test Helm chart rendering functionality."""

    def test_render_helm_chart_success(self):
        """Test render_helm_chart method exists and handles basic validation."""
        assert render_helm_chart is not None

        fake_path = Path("/nonexistent/chart")
        success, message, result_path = render_helm_chart(fake_path)
        assert success is False
        assert "Chart directory not found" in message
        assert result_path is None

    def test_render_helm_chart_no_chart_yaml(self):
        """Test chart rendering with missing Chart.yaml."""
        mock_chart_path = MagicMock()
        mock_chart_path.exists.return_value = True
        mock_chart_path.is_dir.return_value = True
        mock_chart_path.__truediv__.side_effect = lambda x: Mock(exists=lambda: False)

        success, message, result_path = render_helm_chart(mock_chart_path)

        assert success is False
        assert "No Chart.yaml found" in message
        assert result_path is None

    def test_render_helm_chart_nonexistent_path(self):
        """Test chart rendering with nonexistent path."""
        mock_chart_path = Mock()
        mock_chart_path.exists.return_value = False

        success, message, result_path = render_helm_chart(mock_chart_path)

        assert success is False
        assert "Chart directory not found" in message
        assert result_path is None


class TestHelmScannerIntegration:
    """Test Helm scanning integration with scanners."""

    def test_scanner_base_helm_capability(self):
        """Test that ScannerBase has Helm scanning capability."""

        class MockScanner(ScannerBase):
            NAME = "MockScanner"
            SCAN_MANIFESTS_CMD = ["mock", "scan"]

            @classmethod
            def parse_results(cls, results):
                return [CheckResult(check_id="test", obj_name="test")]

        scanner = MockScanner()
        assert scanner.can_scan_manifests is True
        assert scanner.can_scan_helm is True

    def test_scanner_without_manifest_capability(self):
        """Test scanner without manifest scanning capability."""

        class MockScanner(ScannerBase):
            NAME = "MockScannerNoManifest"

            @classmethod
            def parse_results(cls, results):
                return []

        scanner = MockScanner()
        assert scanner.can_scan_manifests is False
        assert scanner.can_scan_helm is False

    @patch("kalm_benchmark.utils.helm_operations.check_helm_installed")
    @patch("kalm_benchmark.utils.helm_operations.render_helm_chart")
    def test_scan_helm_chart_generator_success(self, mock_render, mock_helm_check):
        """Test successful Helm chart scanning."""
        mock_helm_check.return_value = True
        mock_render.return_value = (True, "Success", Path("/tmp/manifests.yaml"))

        # Mock scanner
        mock_scanner = Mock()
        mock_scanner.scan_manifests.return_value = iter([("info", "Scanning..."), ("info", "Complete")])
        mock_scanner.scan_manifests.__next__ = Mock(
            side_effect=[("info", "Scanning..."), StopIteration([CheckResult(check_id="test")])]
        )

        # Test the generator
        generator = scan_helm_chart_generator(Path("/test/chart"), mock_scanner)

        updates = list(generator)
        assert len(updates) >= 2  # Should have multiple status updates

    @patch("kalm_benchmark.utils.helm_operations.check_helm_installed")
    def test_scan_helm_chart_generator_no_helm(self, mock_helm_check):
        """Test Helm chart scanning without Helm CLI."""
        mock_helm_check.return_value = False

        mock_scanner = Mock()
        generator = scan_helm_chart_generator(Path("/test/chart"), mock_scanner)

        updates = list(generator)
        assert any("Helm CLI is not installed" in str(update) for update in updates)


class TestHelmDownloadIntegration:
    """Test Helm chart download integration."""

    @patch("kalm_benchmark.utils.helm_operations._update_helm_repositories")
    @patch("kalm_benchmark.utils.helm_operations._add_helm_repository")
    @patch("kalm_benchmark.utils.helm_operations._download_single_chart")
    @patch("kalm_benchmark.utils.helm_operations.get_popular_charts")
    def test_download_popular_charts_success(self, mock_get_charts, mock_download, mock_add_repo, mock_update):
        """Test successful popular charts download."""
        mock_get_charts.return_value = [
            {"name": "nginx", "repo": "bitnami", "repo_url": "https://charts.bitnami.com/bitnami"}
        ]

        # Mock successful operations
        mock_update.return_value = True
        mock_add_repo.return_value = True
        mock_download.return_value = Path("/tmp/nginx")

        destination = Path("/tmp/charts")
        success, message, chart_paths = download_popular_charts(1, destination)

        assert success is True
        assert len(chart_paths) == 1
        assert "Downloaded 1 charts" in message

    @patch("kalm_benchmark.utils.helm_operations._update_helm_repositories")
    @patch("kalm_benchmark.utils.helm_operations._add_helm_repository")
    @patch("kalm_benchmark.utils.helm_operations._download_single_chart")
    @patch("kalm_benchmark.utils.helm_operations.get_popular_charts")
    def test_download_popular_charts_partial_failure(self, mock_get_charts, mock_download, mock_add_repo, mock_update):
        """Test popular charts download with some failures."""
        mock_get_charts.return_value = [
            {"name": "nginx", "repo": "bitnami", "repo_url": "https://charts.bitnami.com/bitnami"},
            {"name": "mysql", "repo": "bitnami", "repo_url": "https://charts.bitnami.com/bitnami"},
        ]

        # Mock mixed results
        mock_update.return_value = True
        mock_add_repo.return_value = True
        mock_download.side_effect = [Path("/tmp/nginx"), None]  # Second download fails

        destination = Path("/tmp/charts")
        success, message, chart_paths = download_popular_charts(2, destination)

        assert success is True  # At least one succeeded
        assert len(chart_paths) == 1
        assert "failed to download: mysql" in message


class TestScannerHelmMethods:
    """Test the new Helm methods added to ScannerBase."""

    def test_scan_helm_chart_method_exists(self):
        """Test that scan_helm_chart method exists on ScannerBase."""

        class MockScanner(ScannerBase):
            NAME = "MockScanner"
            SCAN_MANIFESTS_CMD = ["mock"]

            @classmethod
            def parse_results(cls, results):
                return []

        scanner = MockScanner()
        assert hasattr(scanner, "scan_helm_chart")
        assert hasattr(scanner, "scan_popular_charts")
        assert hasattr(scanner, "can_scan_helm")

    def test_scan_popular_charts_method_exists(self):
        """Test that scan_popular_charts method exists on ScannerBase."""

        class MockScanner(ScannerBase):
            NAME = "MockScanner"
            SCAN_MANIFESTS_CMD = ["mock"]

            @classmethod
            def parse_results(cls, results):
                return []

        scanner = MockScanner()
        generator = scanner.scan_popular_charts(5)
        assert generator is not None


@pytest.fixture
def mock_chart_path():
    """Fixture for mock chart path."""
    mock_path = Mock()
    mock_path.exists.return_value = True
    mock_path.is_dir.return_value = True
    mock_path.name = "test-chart"
    return mock_path


@pytest.fixture
def mock_scanner():
    """Fixture for mock scanner."""

    class MockScanner(ScannerBase):
        NAME = "TestScanner"
        SCAN_MANIFESTS_CMD = ["test", "scan"]

        @classmethod
        def parse_results(cls, results):
            return [CheckResult(check_id="test", obj_name="test")]

        def scan_manifests(self, path, **kwargs):
            # Mock generator that yields updates and returns results
            yield ("info", "Scanning manifests")
            return [CheckResult(check_id="test", obj_name="test")]

    return MockScanner()


class TestCCSSIntegration:
    """Test CCSS integration for Helm charts."""

    def test_ccss_helm_processing_exists(self):
        """Test that CCSS service has Helm processing capability."""
        from kalm_benchmark.evaluation.ccss.ccss_service import CCSSService

        assert hasattr(CCSSService, "process_helm_chart_results")

        import inspect

        sig = inspect.signature(CCSSService.process_helm_chart_results)
        expected_params = [
            "self",
            "scanner_name",
            "check_results",
            "chart_path",
            "is_research_dataset",
            "evaluation_run_id",
        ]
        assert list(sig.parameters.keys()) == expected_params

    def test_ccss_chart_info_extraction(self):
        """Test chart info extraction from path."""
        from kalm_benchmark.evaluation.ccss.ccss_converter import CCSSConverter

        # Test with a chart-like path
        chart_info = CCSSConverter.extract_chart_info_from_path("/charts/nginx/1.2.3/templates/deployment.yaml")

        assert chart_info["chart_name"] == "nginx"
        assert chart_info["chart_version"] == "1.2.3"
        assert "file_name" in chart_info


class TestHelmIntegrationE2E:
    """End-to-end integration tests for Helm functionality."""

    @patch("kalm_benchmark.utils.helm_operations.subprocess.run")
    @patch("kalm_benchmark.utils.helm_operations.check_helm_installed")
    def test_helm_workflow_integration(self, mock_helm_check, mock_subprocess):
        """Test the complete helm workflow from download to scan."""
        mock_helm_check.return_value = True
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")

        # Mock file system operations
        with patch("pathlib.Path.mkdir"), patch("pathlib.Path.exists", return_value=True), patch(
            "pathlib.Path.is_dir", return_value=True
        ), patch("pathlib.Path.iterdir", return_value=[Path("/tmp/nginx")]):
            from kalm_benchmark.utils.helm_operations import download_popular_charts

            success, message, _ = download_popular_charts(1, Path("/tmp/charts"))

            assert success is True
            assert "Downloaded 1 charts" in message

    def test_scanner_helm_integration(self):
        """Test scanner integration with helm functionality."""
        from kalm_benchmark.evaluation.scanner.kubescape import Scanner

        scanner = Scanner()

        # Verify scanner has helm capabilities
        assert hasattr(scanner, "scan_helm_chart")
        assert hasattr(scanner, "scan_popular_charts")
        assert scanner.can_scan_helm

        # Test that helm methods exist and are callable
        assert callable(scanner.scan_helm_chart)
        assert callable(scanner.scan_popular_charts)


class TestHelmErrorHandling:
    """Test error handling in Helm functionality."""

    def test_helm_chart_error(self):
        """Test HelmChartError exception."""

        with pytest.raises(HelmChartError):
            raise HelmChartError("Test error")

    @patch("kalm_benchmark.utils.helm_operations.subprocess.run")
    def test_download_chart_timeout_handling(self, mock_run):
        """Test timeout handling during chart download."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["helm"], timeout=60)

        result = _download_single_chart("nginx", "bitnami", Path("/tmp"))
        assert result is None

    def test_invalid_chart_path_handling(self):
        """Test handling of invalid chart paths."""
        # Test with invalid path
        success, message, path = render_helm_chart(Path("/nonexistent/path"))

        assert success is False
        assert "Chart directory not found" in message
        assert path is None


class TestHelmUtilityFunctions:
    """Test utility functions for better coverage."""

    @patch("kalm_benchmark.utils.helm_operations.urllib.request.urlopen")
    def test_get_popular_charts_partial_data(self, mock_urlopen):
        """Test handling of partial/malformed API data."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(
            {
                "packages": [
                    {"name": "complete-chart", "repository": {"name": "repo1", "url": "https://example.com"}},
                    {
                        "name": "incomplete-chart",
                    },
                    {"repository": {"name": "repo2"}},
                ]
            }
        ).encode("utf-8")

        mock_urlopen.return_value.__enter__.return_value = mock_response

        charts = get_popular_charts(5)

        assert len(charts) >= 1
        complete_chart = next(c for c in charts if c["name"] == "complete-chart")
        assert complete_chart["repo"] == "repo1"

    @patch("tempfile.TemporaryDirectory")
    @patch("kalm_benchmark.utils.helm_operations.check_helm_installed")
    def test_scan_generator_cleanup(self, mock_helm_check, mock_tempdir):
        """Test that generators properly clean up temporary files."""
        mock_helm_check.return_value = False
        mock_temp_context = MagicMock()
        mock_tempdir.return_value = mock_temp_context

        mock_scanner = Mock()
        generator = scan_helm_chart_generator(Path("/test"), mock_scanner)
        list(generator)

        assert mock_helm_check.called
