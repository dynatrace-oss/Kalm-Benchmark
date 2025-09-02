from datetime import datetime
from pathlib import Path

import streamlit as st
from loguru import logger

from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.evaluation import EvaluationSummary
from kalm_benchmark.evaluation.scanner_manager import SCANNERS, ScannerBase
from kalm_benchmark.evaluation.scanner_service import EvaluationService
from kalm_benchmark.utils.constants import (
    LAST_SCAN_OPTION,
    SELECTED_RESULT_FILE,
    SessionKeys,
)
from kalm_benchmark.utils.exceptions import DatabaseError, EvaluationError

# Bind logger to scan component for proper log filtering
logger = logger.bind(component="ui")


def parse_timestamp(timestamp: str) -> datetime:
    """Parse timestamp string into datetime object.

    :param timestamp: Timestamp string to parse (ISO format or simple datetime)
    :return: Parsed datetime object
    """
    if "T" in timestamp:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    else:
        return datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")


def format_scan_timestamp(timestamp: str, format: str = "%b %d, %H:%M") -> str:
    """Format timestamp for display in the user interface.

    :param timestamp: Timestamp string to format
    :param format: Output format string (default: "%b %d, %H:%M")
    :return: Formatted timestamp string or "Unknown" if parsing fails
    """
    if not timestamp:
        return "Unknown"

    try:
        dt = parse_timestamp(timestamp)
        return dt.strftime(format)
    except Exception as e:
        logger.debug(f"Failed to parse timestamp '{timestamp}': {e}")
        return timestamp[:10] if len(timestamp) >= 10 else "Unknown"


def calculate_scan_age(timestamp: str) -> str:
    """Calculate and format scan age relative to current time.

    :param timestamp: Timestamp string to calculate age for
    :return: Human-readable age string (e.g., "2h ago", "3d ago")
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
    """Find scan run by ID from a list of scan runs.

    :param selected_scan_id: The scan ID to search for
    :param scan_runs: List of scan run dictionaries
    :return: The matching scan run dictionary or None if not found
    """
    return next((run for run in scan_runs if run["id"] == selected_scan_id), None)


def find_current_scan_index(selected_scan_id: str, scan_options: list) -> int:
    """Find the index of currently selected scan in options list.

    :param selected_scan_id: The scan ID to find
    :param scan_options: List of (text, scan_id) tuples
    :return: Index of the matching scan or 0 if not found
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
    """Get cached evaluation service instance.

    :return: Cached EvaluationService instance
    """
    data_dir = st.session_state.get(SessionKeys.DataDir, "./data")
    db_path = f"{data_dir}/kalm.db"
    logger.debug(f"Initializing EvaluationService with database: {db_path}")
    try:
        service = EvaluationService(db_path)
        logger.info("Successfully initialized EvaluationService")
        return service
    except (OSError, IOError) as e:
        logger.error(f"Database file access error: {e}")
        raise DatabaseError(f"Cannot access database: {e}") from e
    except Exception as e:
        logger.error(f"Failed to initialize EvaluationService: {e}")
        raise DatabaseError(f"Database initialization failed: {e}") from e


def get_query_param(param: str, default: str | None = None) -> str | None:
    """Retrieve the value of the specified query parameter from URL.

    :param param: Name of the query parameter to retrieve
    :param default: The default value if the parameter is not set
    :return: The value of the specified query parameter or the default value if parameter is not set
    """
    param_values = st.query_params.get(param, None)
    if param_values is None:
        return default
    return param_values


def get_selected_result_file(tool_name: str) -> str:
    """Get the selected result file for a specific scanner.

    :param tool_name: Name of the scanner
    :return: Selected result file name or None if not set
    """
    file_name = None
    key = f"{tool_name}_{SELECTED_RESULT_FILE}"
    if key in st.session_state:
        file_name = st.session_state[key]
        if file_name == LAST_SCAN_OPTION:
            file_name = f"{tool_name}_{SessionKeys.LatestScanResult}"
    return file_name


def get_result_files_of_scanner(tool_name: str) -> list[str]:
    """Retrieve all available scan run files for a given scanner.

    :param tool_name: The name of the scanner
    :return: List of available scan run file names, including latest scan option if available
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
    """Initialize the Streamlit session state with appropriate default values.

    :return: None
    """
    if SessionKeys.DataDir not in st.session_state:
        st.session_state[SessionKeys.DataDir] = "./data"
    if SessionKeys.LatestScanResult not in st.session_state:
        st.session_state[SessionKeys.LatestScanResult] = {}


def load_scan_result(scanner: ScannerBase, source: str | Path) -> list | dict:
    """Load scan results from either ephemeral session or persistent storage.

    :param scanner: Scanner instance to load results for
    :param source: Source identifier (file name, path, or scan ID)
    :return: Parsed scan results as list or dictionary
    """
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


def _load_and_cache_scanner_summary(name: str, result_file: str | None = None) -> EvaluationSummary | None:
    """Load the evaluation summary of a given scanner from unified database.

    :param name: The name of the scanner tool for which the summary is loaded
    :param result_file: The optional scan run identifier
    :return: An EvaluationSummary object for the given tool or None if loading fails
    """
    unified_service = get_unified_service()

    try:
        scan_timestamp = None
        if result_file and not is_ephemeral_scan_result(result_file):
            scan_timestamp = _find_scan_timestamp(unified_service, name, result_file)

        summary = unified_service.load_scanner_summary(name, scan_timestamp)
        summary = _check_summary(summary, result_file, name)
        return summary

    except Exception as exc:
        logger.warning(f"Failed to load scanner summary for {name}: {exc}")
        return None


def _find_scan_timestamp(unified_service: EvaluationService, name: str, result_file: str):
    """Find the timestamp for a specific scan run.

    :param unified_service: Evaluation service instance
    :param name: Scanner name
    :param result_file: Result file identifier
    :return: Timestamp string or None if not found
    """
    scan_timestamp = None
    scan_runs = unified_service.get_scanner_result_files(name)
    for run in scan_runs:
        if result_file in run["name"] or result_file == run["id"]:
            db_scan_runs = unified_service.db.get_scan_runs(scanner_name=name)
            for db_run in db_scan_runs:
                if db_run["id"] == run["id"]:
                    scan_timestamp = db_run["timestamp"]
                    break
            break
    return scan_timestamp


def _check_summary(summary: EvaluationSummary, result_file: str, name: str):
    """Check and potentially create summary for ephemeral scan results.

    :param summary: Existing evaluation summary or None
    :param result_file: Result file identifier
    :param name: Scanner name
    :return: EvaluationSummary object or None
    """
    if summary is None and is_ephemeral_scan_result(result_file):
        scanner = SCANNERS.get(name)
        if scanner:
            try:
                results = load_scan_result(scanner, result_file)
                df = evaluation.evaluate_scanner(scanner, results)
                summary = evaluation.create_summary(df)
            except (ValueError, KeyError) as exc:
                logger.warning(f"Invalid data format for ephemeral results: {exc}")
            except EvaluationError as exc:
                logger.warning(f"Evaluation failed for ephemeral results: {exc}")
            except Exception as exc:
                logger.error(f"Failed to create summary from ephemeral results: {exc}")
    return summary


def is_ephemeral_scan_result(result_name: str | Path | None) -> bool:
    """Determine if the result is persistent or ephemeral from the last scan.

    :param result_name: The name of the result based on which the state is determined
    :return: True if the name indicates that the result is from the latest scan, False otherwise
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
    except DatabaseError as e:
        logger.warning(f"Database error checking ephemeral scan status for '{result_name}': {e}")
        return False
    except Exception as e:
        logger.warning(f"Failed to check ephemeral scan status for '{result_name}': {e}")
        return False


load_scanner_summary = st.cache_data(_load_and_cache_scanner_summary, show_spinner=False)
