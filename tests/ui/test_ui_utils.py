import json
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

import pytest

from kalm_benchmark.evaluation.evaluation import EvaluationSummary
from kalm_benchmark.evaluation.scanner_manager import ScannerManager
from kalm_benchmark.ui import utils


class TestSummaryLoading:
    def test_summary_has_same_name_as_result_file(self, tmp_path):
        tool = "my-tool"
        file_name = f"{tool}.json"
        summary_file_path = tmp_path / utils.SUMMARIES_DIR_NAME / file_name
        with patch.object(utils, "evaluation"), patch.object(utils, "_save_summary") as save_mock:
            utils._load_and_cache_scanner_summary(tool, tmp_path / file_name)
            save_mock.assert_called_once_with(ANY, summary_file_path)

    def test_no_valid_result_file_yields_no_summary(self, tmp_path):
        tool = "my-tool"
        # this file does not exist, so it will lead to an error
        result_file = tmp_path / f"{tool}.json"

        with (
            patch.object(utils.evaluation, "load_scanner_results_from_file") as load_mock,
            patch.object(utils, "_save_summary") as save_mock,
        ):
            load_mock.side_effect = json.JSONDecodeError("invalid content", tool, 42)
            summary = utils._load_and_cache_scanner_summary(tool, result_file)
            assert summary is None
            # make sure nothing is saved if the results are flawed
            save_mock.assert_not_called()

    def test_no_valid_result_file_on_fs_yields_no_summary(self, tmp_path):
        tool = "my-tool"

        manager = ScannerManager()
        mock_scanner = MagicMock()
        mock_scanner.NAME = tool
        manager.scanners = {tool: mock_scanner}

        with (
            patch.object(utils, "SCANNERS", manager),
            patch.object(utils, "get_result_files_of_scanner") as load_mock,
            patch.object(utils, "_save_summary") as save_mock,
        ):
            load_mock.return_value = []
            # no explicit result file triggers lookup on local fs
            summary = utils._load_and_cache_scanner_summary(tool, None)
            assert summary is None
            # make sure nothing is saved if the results are flawed
            save_mock.assert_not_called()

    def test_create_summary_folder_if_not_exists(self, tmp_path):
        result_file = tmp_path / "tool.json"
        summary_folder = tmp_path / utils.SUMMARIES_DIR_NAME

        assert not summary_folder.exists()

        with patch.object(utils, "evaluation"), patch.object(utils, "_save_summary"):
            utils._load_and_cache_scanner_summary("anything", result_file)

        assert summary_folder.exists()

    def test_load_existing_summary(self, mocker, tmp_path):
        # df_cats = pd.DataFrame({"cat1": [15], "cat2": [0]})
        cats = {"cat1": [15], "cat2": [0]}
        version = "1.3.3-7"
        expected_summary = EvaluationSummary(
            version=version, checks_per_category=cats, score=0.73, coverage=0.42, extra_checks=1, missing_checks=2
        )
        data = expected_summary.to_dict()
        data = json.dumps(data)

        tool = "my-tool"
        date = "2024-01-01"
        file_name = f"{tool}_v{version}_{date}.json"
        summary_file = tmp_path / utils.SUMMARIES_DIR_NAME / file_name
        summary_file.parent.mkdir()
        with open(summary_file, "w") as f:
            f.write(data)

        result_file = tmp_path / file_name
        summary = utils._load_and_cache_scanner_summary(tool, result_file)
        assert summary == expected_summary

    def test_calculate_summary_if_file_does_not_exist(self, tmp_path):
        name = "my_tool"
        # in blank temp directory there is no summary_file -> trigger manual creation
        with patch.object(utils, "evaluation") as m, patch.object(utils, "_save_summary"):
            utils._load_and_cache_scanner_summary(name, tmp_path / f"{name}.json")
            m.create_summary.assert_called_once()

    def test_calculated_summary_is_stored(self, tmp_path):
        name = "my_tool"
        result_file = tmp_path / f"{name}.json"

        with patch.object(utils, "evaluation") as m:
            # empty summary is enough to verify if it was written to a file
            m.create_summary().to_dict = MagicMock(return_value="{}")
            utils._load_and_cache_scanner_summary(name, result_file)

        summary_dir = result_file.parent / utils.SUMMARIES_DIR_NAME
        # check if there now exists a file named after the tool in the summaries directory
        stored_summary_files = [f.name for f in summary_dir.iterdir()]
        assert f"{name}.json" in stored_summary_files

    def test_calculate_summary_if_cached_file_is_faulty(self, tmp_path):
        tool = "my-tool"
        file_name = f"{tool}.json"
        summary_file = tmp_path / utils.SUMMARIES_DIR_NAME / file_name
        summary_file.parent.mkdir()
        with open(summary_file, "w") as f:
            f.write("This is not valid json! So the parsing will fail!")

        with patch.object(utils, "evaluation") as m, patch.object(utils, "_save_summary"):
            utils._load_and_cache_scanner_summary("anything", tmp_path / file_name)
            m.create_summary.assert_called_once()


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
    vers = utils.get_version_from_result_file(file_name=file_name)
    assert vers == expected_version
