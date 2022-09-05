import json
from pathlib import Path

import streamlit as st
from loguru import logger

from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.evaluation import EvaluationSummary
from kalm_benchmark.evaluation.scanner_manager import SCANNERS, ScannerBase
from kalm_benchmark.ui.constants import (
    LAST_SCAN_OPTION,
    SELECTED_RESULT_FILE,
    SessionKeys,
)

SUMMARIES_DIR_NAME = "summaries"


def get_query_param(param: str, default: str | None = None) -> str | None:
    """Retrieves the value of the specified query parameter.
    If the query parameter is not found the default value is returned if specified.
    If no default value is specified, it defaults to None.

    :param param: the name of the query parameter
    :param default: the default value if the parameter is not set, defaults to None
    :return: the value of the specified query parameter or the default value if parameter is not set
    """
    query_params = st.experimental_get_query_params()
    param_values = query_params.get(param, {})
    if len(param_values) > 0:
        return param_values[0]
    else:
        return default


def get_selected_result_file(tool_name: str) -> str:
    file_name = None
    key = f"{tool_name}_{SELECTED_RESULT_FILE}"
    if key in st.session_state:
        file_name = st.session_state[key]
        # the <last scan> option is the same for every scanner
        # thus, just use the key so it's distinct from other tools
        if file_name == LAST_SCAN_OPTION:
            file_name = f"{tool_name}_{SessionKeys.LatestScanResult}"
    return file_name


def get_result_files_of_scanner(tool_name: str, data_dir: str | None = None) -> list[str]:
    """Retrieve all the files which have scan results store for a given scanner.
    :param tool_name: the name of the scanner
    :param data_dir: the directory in which to look for files.
        If no directory is provided, then the default will be loaded from the session state
    :return: the list of all available result files
    """
    if data_dir is None:
        data_dir = st.session_state[SessionKeys.DataDir]
    files = [str(p) for p in Path(data_dir).glob(f"{tool_name.lower()}*.*")]

    latest_scan_result_of_all_tools = st.session_state[SessionKeys.LatestScanResult]
    latest_scan_results = latest_scan_result_of_all_tools.get(tool_name, {})
    if len(latest_scan_results) > 0:
        files = [LAST_SCAN_OPTION] + files
    return files


def init():
    """
    Initialize the session with appropriate defaults
    """
    st.set_page_config(layout="wide", page_title="Kubernetes Scanner Benchmark")

    if SessionKeys.DataDir not in st.session_state:
        st.session_state[SessionKeys.DataDir] = "./data"
    if SessionKeys.LatestScanResult not in st.session_state:
        st.session_state[SessionKeys.LatestScanResult] = {}


def load_scan_result(scanner: ScannerBase, source: str | Path) -> list | dict:
    if is_ephemeral_scan_result(source):
        results = st.session_state[SessionKeys.LatestScanResult][scanner.NAME]
        return scanner.parse_results(results)
    else:
        return evaluation.load_scanner_results_from_file(scanner, source)


def _load_and_cache_scanner_summary(
    name: str, result_file: str | None = None, save_created_summary: bool = True
) -> EvaluationSummary | None:
    """Load the evaluation summary of a given scanner.
    If the there exists no valid result for the scanner None is returned
    To reduce loading speed, the evaluation summary is cached on disk.
    If no cache file is found, then the summary will be created from the evaluation result
    and then stored on disk for later retrieval.

    :param name: the name of the tool for which the summary is loaded
    :param result_file: the optional path to the evaluation result of the scann, defaults to None
        If no path is specified then the first matching file will be used
    :param save_created_summary: if the flag is set then the summary will be
        persisted in a file, if there was a need to calculate it
    :return: an EvaluationSummary object for the given tool
    """
    scanner = SCANNERS.get(name)
    if result_file is None:
        files = get_result_files_of_scanner(scanner.NAME)

        if len(files) == 0:
            logger.warning(f"No result files for '{name}' found, so no summary can be loaded")
            return None
        # default to the first file listed
        result_file = files[0]
    # ensure the file is a path
    result_path = Path(result_file)

    summary_dir = result_path.parent / SUMMARIES_DIR_NAME
    # ensure the directory exists
    summary_dir.mkdir(exist_ok=True)

    summary = None
    # load the file and return its content if it exists
    summary_file = summary_dir / f"{result_path.stem}.json"
    if summary_file.exists():
        summary = _load_summary_from_fs(summary_file)

    if summary is None:
        # calculate summary and save it for faster access later on
        try:
            results = load_scan_result(scanner, result_file)
            df = evaluation.evaluate_scanner(scanner, results)
            summary = evaluation.create_summary(df)
            # save summary in a file, so it needn't be calculated again
            if save_created_summary:
                _save_summary(summary, summary_file)
        except Exception as exc:
            logger.warning(f"Failed to load the results: {exc}")

    return summary


def _load_summary_from_fs(file_path: Path) -> EvaluationSummary | None:
    summary = None
    try:
        with open(file_path, "r") as f:
            data = json.loads(f.read())
            summary = EvaluationSummary.from_dict(data)
    except json.JSONDecodeError:
        # if an error occurs, no summary will be loaded
        summary = None
    return summary


def _save_summary(summary: EvaluationSummary, dest_path: Path) -> None:
    with open(dest_path, "w") as f:
        d = summary.to_dict()
        j = json.dumps(d)
        f.write(j)


def is_ephemeral_scan_result(result_name: str | Path | None) -> bool:
    """A helper function to determine if the result is persistent or ephemeral from the last scan.

    :param result_name: the name of the result based on which the state is determined
    :return: true if the name indicates, that the result from the latest scan. False otherwise
    """
    if result_name is None:
        return False
    elif not isinstance(result_name, str):
        result_name = str(result_name)
    return result_name == LAST_SCAN_OPTION or result_name.endswith(SessionKeys.LatestScanResult)


load_scanner_summary = st.experimental_memo(_load_and_cache_scanner_summary, show_spinner=False)
