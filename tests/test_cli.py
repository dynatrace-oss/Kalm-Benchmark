from datetime import datetime
from unittest.mock import ANY, MagicMock, patch

import pytest
from typer.testing import CliRunner

from kalm_benchmark.cli import app, benchmark
from kalm_benchmark.constants import UpdateType
from kalm_benchmark.evaluation.scanner_manager import ScannerManager

runner = CliRunner()


SCANNER_NAME = "my-tool"


@pytest.fixture()
def manager():
    manager = ScannerManager()
    mock_scanner = MagicMock()
    mock_scanner.NAME = SCANNER_NAME
    mock_scanner.get_version = lambda: "0.0.1"
    mock_scanner.FORMATS = ["JSON", "Pretty"]
    manager.scanners = {SCANNER_NAME: mock_scanner}
    return manager


@pytest.fixture(autouse=True)
def mock_scanners(manager):
    """Patch the scanner manager for all unittests"""
    with patch("kalm_benchmark.cli.SCANNERS", manager):
        yield


@pytest.fixture()
def mock_scan():
    """Patch the scanner manager for all unit-tests"""

    def mock_gen(return_value):
        yield UpdateType.Info, "mock update"
        return return_value

    with patch.object(benchmark, "scan") as mock:
        mock.return_value = mock_gen(return_value=[])
        yield mock


class TestScannerNameHandling:
    def test_exact_match_shows_no_suggestions(self, manager):
        with patch.object(benchmark, "scan") as scan_mock:
            scan_mock.return_value = iter([])
            # 0 = cancel in the case of multiple options
            result = runner.invoke(app, ["scan", SCANNER_NAME])
            # no suggestions where shown when the scan was started
            # yet no information about 'no scanner' is shown in the output
            assert result.exit_code == 0
            assert "no scanner" not in result.stdout.lower()
            # verify that the scanner was really the one specified
            scan_mock.assert_called()
            used_scanner = scan_mock.call_args.args[0]
            assert used_scanner.NAME == SCANNER_NAME

    def test_show_suggestions_for_wrong_tool_name(self, monkeypatch):
        false_name = "Z" + SCANNER_NAME[1:]
        result = runner.invoke(app, ["scan", false_name], input="Y")
        assert "Perhaps you meant" in result.stdout

    def test_one_suggestion_shows_confirmation_prompt(self):
        false_name = "Z" + SCANNER_NAME[1:]
        with patch("typer.prompt") as prompt_mock:
            prompt_mock.return_value = SCANNER_NAME
            result = runner.invoke(app, ["scan", false_name], input="Y")
        assert "[Y/n]" in result.stdout

    def test_multiple_suggestion_shows_choices(self, manager):
        scanner_alternatives = ["foo1", "foo2"]
        manager.scanners.update({s: MagicMock() for s in scanner_alternatives})

        result = runner.invoke(app, ["scan", "foo"], input="1")
        assert all(a in result.stdout for a in scanner_alternatives)

    def test_abort_if_no_selection_is_made(self, manager, mock_scan):
        scanner_alternatives = ["foo1", "foo2"]
        manager.scanners.update({s: MagicMock() for s in scanner_alternatives})
        # 0 = cancel in the case of multiple options
        result = runner.invoke(app, ["scan", "foo"], input="0")
        mock_scan.assert_not_called()
        assert "Aborting " in result.stdout


class TestInvokeScan:
    def test_both_context_and_files_are_optional(self, mock_scan):
        runner.invoke(app, ["scan", SCANNER_NAME])
        mock_scan.assert_called_with(ANY, context=None, target_path=None)

    def test_manifests_scan_accepts_directory(self, mock_scan, tmp_path):
        runner.invoke(app, ["scan", SCANNER_NAME, "--files", tmp_path])
        mock_scan.assert_called_with(ANY, context=None, target_path=tmp_path)

    def test_directory_must_exists(self, mock_scan, tmp_path):
        tmp_path.rmdir()
        res = runner.invoke(app, ["scan", SCANNER_NAME, "--files", tmp_path])
        mock_scan.assert_not_called()
        assert " does not exist" in res.stdout

    def test_manifests_scan_accepts_single_file(self, mock_scan, tmp_path):
        file_path = tmp_path / "results.json"
        with open(file_path, "w") as f:
            f.write("content: some content to ensure file exists")
        runner.invoke(app, ["scan", SCANNER_NAME, "-f", file_path])
        mock_scan.assert_called_with(ANY, context=None, target_path=file_path)

    def test_manifest_must_exist(self, mock_scan, tmp_path):
        file_path = tmp_path / "results.json"
        res = runner.invoke(app, ["scan", SCANNER_NAME, "-f", file_path])
        mock_scan.assert_not_called()
        assert " does not exist" in res.stdout

    def test_context_value_is_optional(self, mock_scan):
        runner.invoke(app, ["scan", SCANNER_NAME, "-c"])
        mock_scan.assert_called()

    def test_results_are_written_to_output_path(self, manager, tmp_path, mock_scan):
        scanner = manager.get(SCANNER_NAME)
        runner.invoke(app, ["scan", SCANNER_NAME, "--files", tmp_path, "--out", tmp_path])
        mock_scan.assert_called()
        scanner.save_results.assert_called()

    def test_results_are_only_saved_if_specified(self, manager, tmp_path, mock_scan):
        scanner = manager.get(SCANNER_NAME)
        runner.invoke(app, ["scan", SCANNER_NAME, "--files", tmp_path])
        mock_scan.assert_called()
        scanner.save_results.assert_not_called()

    def test_use_file_named_after_scanner_in_output_directory(self, manager, tmp_path, mock_scan):
        scanner = manager.get(SCANNER_NAME)
        date = datetime.now().strftime("%Y-%m-%d")
        res_file_name = tmp_path / f"{SCANNER_NAME}_v0.0.1_{date}.json"
        runner.invoke(app, ["scan", SCANNER_NAME, "--files", tmp_path, "--out", tmp_path])
        mock_scan.assert_called()
        scanner.save_results.assert_called_with(ANY, res_file_name)

    def test_use_txt_if_json_not_supported(self, manager, tmp_path, mock_scan):
        scanner = manager.get(SCANNER_NAME)
        scanner.FORMATS = ["Pretty"]  # no JSON affects the used suffix
        date = datetime.now().strftime("%Y-%m-%d")
        res_file_name = tmp_path / f"{SCANNER_NAME}_v0.0.1_{date}.txt"
        runner.invoke(app, ["scan", SCANNER_NAME, "--files", tmp_path, "--out", tmp_path])
        mock_scan.assert_called()
        scanner.save_results.assert_called_with(ANY, res_file_name)
