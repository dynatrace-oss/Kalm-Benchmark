from datetime import datetime
from pathlib import Path
from typing import Optional, Union

import streamlit as st
from loguru import logger

from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.evaluation import EvaluationSummary
from kalm_benchmark.evaluation.scanner_manager import SCANNERS, ScannerBase
from kalm_benchmark.evaluation.service import EvaluationService
from kalm_benchmark.utils.constants import (
    LAST_SCAN_OPTION,
    SELECTED_RESULT_FILE,
    SessionKeys,
)


def parse_timestamp(timestamp: str) -> datetime:
    """Parse timestamp string into datetime object.

    Args:
        timestamp: Timestamp string to parse

    Returns:
        Parsed datetime object
    """
    if "T" in timestamp:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    else:
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")


def format_scan_timestamp(timestamp: str, format: str = "%b %d, %H:%M") -> str:
    """Format timestamp for display.

    Args:
        timestamp: Timestamp string to format
        format: Output format string

    Returns:
        Formatted timestamp string or "Unknown" if parsing fails
    """
    if not timestamp:
        return "Unknown"

    try:
        dt = parse_timestamp(timestamp)
        return dt.strftime(format)
    except Exception:
        return timestamp[:10] if len(timestamp) >= 10 else "Unknown"


def calculate_scan_age(timestamp: str) -> str:
    """Calculate and format scan age.

    Args:
        timestamp: Timestamp string to calculate age for

    Returns:
        Human-readable age string (e.g., "2h ago", "3d ago")
    """
    if not timestamp:
        return "Unknown"

    try:
        dt = parse_timestamp(timestamp)
        now = datetime.now()
        if dt.tzinfo:
            now = now.replace(tzinfo=dt.tzinfo)

        age_hours = int((now - dt).total_seconds() / 3600)
        if age_hours < 24:
            return f"{age_hours}h ago"
        else:
            age_days = age_hours // 24
            return f"{age_days}d ago"
    except Exception:
        return "Unknown"


def find_scan_by_id(selected_scan_id: str, scan_runs: list) -> dict:
    """Find scan run by ID.

    Args:
        selected_scan_id: The scan ID to search for
        scan_runs: List of scan run dictionaries

    Returns:
        The matching scan run dictionary or None if not found
    """
    return next((run for run in scan_runs if run["id"] == selected_scan_id), None)


def find_current_scan_index(selected_scan_id: str, scan_options: list) -> int:
    """Find the index of currently selected scan.

    Args:
        selected_scan_id: The scan ID to find
        scan_options: List of (text, scan_id) tuples

    Returns:
        Index of the matching scan or 0 if not found
    """
    if not selected_scan_id:
        return 0

    for i, (_, scan_id) in enumerate(scan_options):
        if scan_id == selected_scan_id:
            return i
    return 0


# Initialize service
@st.cache_resource
def get_unified_service() -> EvaluationService:
    """Get cached evaluation service instance"""
    data_dir = st.session_state.get(SessionKeys.DataDir, "./data")
    db_path = f"{data_dir}/kalm.db"
    return EvaluationService(db_path)


def get_query_param(param: str, default: Optional[str] = None) -> Optional[str]:
    """Retrieves the value of the specified query parameter.

    Args:
        param: The name of the query parameter
        default: The default value if the parameter is not set

    Returns:
        The value of the specified query parameter or the default value if parameter is not set
    """
    param_values = st.query_params.get(param, None)
    if param_values is None:
        return default
    return param_values


def get_selected_result_file(tool_name: str) -> str:
    file_name = None
    key = f"{tool_name}_{SELECTED_RESULT_FILE}"
    if key in st.session_state:
        file_name = st.session_state[key]
        if file_name == LAST_SCAN_OPTION:
            file_name = f"{tool_name}_{SessionKeys.LatestScanResult}"
    return file_name


def get_result_files_of_scanner(tool_name: str) -> list[str]:
    """Retrieve all the scan runs available for a given scanner.

    Args:
        tool_name: The name of the scanner

    Returns:
        The list of all available scan runs
    """
    unified_service = get_unified_service()

    scan_runs = unified_service.get_scanner_result_files(tool_name)
    files = [f"{run['name']}" for run in scan_runs]

    latest_scan_result_of_all_tools = st.session_state[SessionKeys.LatestScanResult]
    latest_scan_results = latest_scan_result_of_all_tools.get(tool_name, {})
    if len(latest_scan_results) > 0:
        files = [LAST_SCAN_OPTION] + files

    return files


def init():
    """Initialize the session with appropriate defaults."""
    if SessionKeys.DataDir not in st.session_state:
        st.session_state[SessionKeys.DataDir] = "./data"
    if SessionKeys.LatestScanResult not in st.session_state:
        st.session_state[SessionKeys.LatestScanResult] = {}


def load_scan_result(scanner: ScannerBase, source: Union[str, Path]) -> Union[list, dict]:
    if is_ephemeral_scan_result(source):
        results = st.session_state[SessionKeys.LatestScanResult][scanner.NAME]
        return scanner.parse_results(results)
    else:
        unified_service = get_unified_service()

        scan_runs = unified_service.get_scanner_result_files(scanner.NAME)
        scan_run_id = None

        source_str = str(source)
        for run in scan_runs:
            if source_str in run["name"] or source_str == run["id"]:
                scan_run_id = run["id"]
                break

        return unified_service.load_scanner_results(scanner.NAME, scan_run_id)


def _load_and_cache_scanner_summary(
    name: str, result_file: str | None = None, save_created_summary: bool = True
) -> EvaluationSummary | None:
    """Load the evaluation summary of a given scanner from unified database.

    Args:
        name: The name of the tool for which the summary is loaded
        result_file: The optional scan run identifier
        save_created_summary: Kept for backward compatibility (summaries are auto-saved in DB)

    Returns:
        An EvaluationSummary object for the given tool
    """
    unified_service = get_unified_service()

    try:
        scan_timestamp = None
        if result_file and not is_ephemeral_scan_result(result_file):
            scan_runs = unified_service.get_scanner_result_files(name)
            for run in scan_runs:
                if result_file in run["name"] or result_file == run["id"]:
                    db_scan_runs = unified_service.db.get_scan_runs(scanner_name=name)
                    for db_run in db_scan_runs:
                        if db_run["id"] == run["id"]:
                            scan_timestamp = db_run["timestamp"]
                            break
                    break

        summary = unified_service.load_scanner_summary(name, scan_timestamp)

        if summary is None and is_ephemeral_scan_result(result_file):
            scanner = SCANNERS.get(name)
            if scanner:
                try:
                    results = load_scan_result(scanner, result_file)
                    df = evaluation.evaluate_scanner(scanner, results)
                    summary = evaluation.create_summary(df)
                except Exception as exc:
                    logger.warning(f"Failed to create summary from ephemeral results: {exc}")

        return summary

    except Exception as exc:
        logger.warning(f"Failed to load scanner summary for {name}: {exc}")
        return None


def is_ephemeral_scan_result(result_name: str | Path | None) -> bool:
    """Determine if the result is persistent or ephemeral from the last scan.

    Args:
        result_name: The name of the result based on which the state is determined

    Returns:
        True if the name indicates that the result is from the latest scan, False otherwise
    """
    if result_name is None:
        return False
    elif not isinstance(result_name, str):
        result_name = str(result_name)

    if result_name == LAST_SCAN_OPTION or result_name.endswith(SessionKeys.LatestScanResult):
        return True

    try:
        unified_service = get_unified_service()
        return unified_service.is_ephemeral_scan_result(result_name)
    except Exception:
        return False


load_scanner_summary = st.cache_data(_load_and_cache_scanner_summary, show_spinner=False)
