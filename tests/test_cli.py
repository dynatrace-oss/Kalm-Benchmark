from unittest.mock import ANY, MagicMock, patch

import pytest
from typer.testing import CliRunner

from kalm_benchmark.cli import app, benchmark
from kalm_benchmark.evaluation.scanner_manager import ScannerManager
from kalm_benchmark.utils.constants import UpdateType

SCANNER_NAME = "my-tool"


@pytest.fixture(scope="function")
def cli_runner():
    """Provide CLI runner with consistent configuration."""
    return CliRunner()


@pytest.fixture(scope="function")
def manager():
    """Create scanner manager with test scanner for CLI tests."""
    manager = ScannerManager()
    mock_scanner = MagicMock()
    mock_scanner.NAME = SCANNER_NAME
    mock_scanner.get_version = lambda: "0.0.1"
    mock_scanner.FORMATS = ["JSON", "Pretty"]
    manager.scanners = {SCANNER_NAME: mock_scanner}
    return manager


@pytest.fixture(autouse=True, scope="function")
def mock_scanners(manager):
    """Patch the scanner manager for all CLI tests."""
    with patch("kalm_benchmark.cli.SCANNERS", manager):
        yield


@pytest.fixture(scope="function")
def mock_scan():
    """Mock scan function for CLI tests."""

    def mock_gen(return_value):
        yield UpdateType.Info, "mock update"
        return return_value

    with patch.object(benchmark, "scan") as mock:
        mock.return_value = mock_gen(return_value=[])
        yield mock


@pytest.mark.unit
class TestScannerNameHandling:
    """Test scanner name handling and suggestion logic."""

    def test_exact_match_shows_no_suggestions(self, cli_runner, manager):
        """Test that exact scanner name matches don't show suggestions."""
        with patch.object(benchmark, "scan") as scan_mock:
            scan_mock.return_value = iter([])

            result = cli_runner.invoke(app, ["scan", SCANNER_NAME])

            assert result.exit_code == 0
            assert "no scanner" not in result.stdout.lower()

            # Verify that the scanner was really the one specified
            scan_mock.assert_called()
            used_scanner = scan_mock.call_args.args[0]
            assert used_scanner.NAME == SCANNER_NAME

    def test_show_suggestions_for_wrong_tool_name(self, cli_runner):
        """Test that similar scanner names trigger suggestions."""
        false_name = "Z" + SCANNER_NAME[1:]
        result = cli_runner.invoke(app, ["scan", false_name], input="Y")
        assert "Perhaps you meant" in result.stdout

    def test_one_suggestion_shows_confirmation_prompt(self, cli_runner):
        """Test that single suggestions show confirmation prompts."""
        false_name = "Z" + SCANNER_NAME[1:]
        with patch("typer.prompt") as prompt_mock:
            prompt_mock.return_value = SCANNER_NAME
            result = cli_runner.invoke(app, ["scan", false_name], input="Y")
        assert "[Y/n]" in result.stdout

    def test_multiple_suggestion_shows_choices(self, cli_runner, manager):
        """Test that multiple suggestions show choice menu."""
        scanner_alternatives = ["foo1", "foo2"]
        manager.scanners.update({s: MagicMock() for s in scanner_alternatives})

        result = cli_runner.invoke(app, ["scan", "foo"], input="1")
        assert all(a in result.stdout for a in scanner_alternatives)

    def test_abort_if_no_selection_is_made(self, cli_runner, manager, mock_scan):
        """Test that canceling scanner selection aborts the operation."""
        scanner_alternatives = ["foo1", "foo2"]
        manager.scanners.update({s: MagicMock() for s in scanner_alternatives})

        result = cli_runner.invoke(app, ["scan", "foo"], input="0")

        mock_scan.assert_not_called()
        assert "Aborting " in result.stdout


@pytest.mark.unit
class TestInvokeScan:
    """Test scan invocation with various parameters."""

    def test_both_context_and_files_are_optional(self, cli_runner, mock_scan):
        """Test that both context and files parameters are optional."""
        cli_runner.invoke(app, ["scan", SCANNER_NAME])
        mock_scan.assert_called_with(ANY, context=None, target_path=None)

    def test_manifests_scan_accepts_directory(self, cli_runner, mock_scan, temp_test_dir):
        """Test that manifest scanning accepts directory paths."""
        cli_runner.invoke(app, ["scan", SCANNER_NAME, "--files", str(temp_test_dir)])
        mock_scan.assert_called_with(ANY, context=None, target_path=temp_test_dir)

    def test_directory_must_exists(self, cli_runner, mock_scan, temp_test_dir):
        """Test that non-existent directories are rejected."""
        nonexistent_dir = temp_test_dir / "nonexistent"
        result = cli_runner.invoke(app, ["scan", SCANNER_NAME, "--files", str(nonexistent_dir)])

        mock_scan.assert_not_called()
        assert " does not exist" in result.stdout

    def test_manifests_scan_accepts_single_file(self, cli_runner, mock_scan, temp_test_dir):
        """Test that manifest scanning accepts single file paths."""
        file_path = temp_test_dir / "results.json"
        file_path.write_text("content: some content to ensure file exists")

        cli_runner.invoke(app, ["scan", SCANNER_NAME, "-f", str(file_path)])
        mock_scan.assert_called_with(ANY, context=None, target_path=file_path)

    def test_manifest_must_exist(self, cli_runner, mock_scan, temp_test_dir):
        """Test that non-existent files are rejected."""
        file_path = temp_test_dir / "nonexistent.json"
        result = cli_runner.invoke(app, ["scan", SCANNER_NAME, "-f", str(file_path)])

        mock_scan.assert_not_called()
        # Strip multiple whitespaces and drop any words with special characters (from rich)
        filtered_stdout = [w for w in result.stdout.replace("\n", " ").split() if all(c.isascii() for c in w)]
        assert " does not exist" in " ".join(filtered_stdout)

    def test_context_value_is_optional(self, cli_runner, mock_scan):
        """Test that context parameter can be specified without value."""
        cli_runner.invoke(app, ["scan", SCANNER_NAME, "-c"])
        mock_scan.assert_called()

    @patch("kalm_benchmark.cli.EvaluationService")
    def test_results_are_saved_to_database(self, mock_service_class, cli_runner, manager, temp_test_dir, mock_scan):
        """Test that scan results are properly saved to database."""
        mock_service = mock_service_class.return_value
        mock_service.save_scanner_results.return_value = "test-scan-id"

        cli_runner.invoke(app, ["scan", SCANNER_NAME, "--files", str(temp_test_dir)])

        mock_scan.assert_called()
        mock_service.save_scanner_results.assert_called_once()

    @patch("kalm_benchmark.cli.EvaluationService")
    def test_scan_creates_database_entry(self, mock_service_class, cli_runner, manager, temp_test_dir, mock_scan):
        """Test that scan operation creates proper database entry with metadata."""
        mock_service = mock_service_class.return_value
        mock_service.save_scanner_results.return_value = "test-scan-id"

        result = cli_runner.invoke(app, ["scan", SCANNER_NAME, "--files", str(temp_test_dir)])

        # Check that database save was called with correct parameters
        mock_service.save_scanner_results.assert_called_once()
        call_args = mock_service.save_scanner_results.call_args

        assert call_args.kwargs["scanner_name"] == SCANNER_NAME.lower()
        assert call_args.kwargs["scanner_version"] == "0.0.1"
        assert "database" in result.stdout
