from datetime import datetime
from pathlib import Path

import pandas as pd

from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckCategory


def _get_category_ratio(category_summary: pd.Series | None) -> str:
    """Get category ratio in original KALM format 'covered/total (+extra)'.

    :param category_summary: Series of all result types for a particular scanner category
    :return: Ratio string in format 'covered/total (+extra)' matching original KALM format
    """
    if category_summary is None:
        return "0/0"

    # Handle case where category_summary is an integer or other non-dict type
    if not hasattr(category_summary, "get"):
        # If it's a simple count (integer), treat it as covered count with no missing/extra
        if isinstance(category_summary, (int, float)):
            return f"{int(category_summary)}/{int(category_summary)}"
        else:
            return "0/0"

    covered = category_summary.get(evaluation.ResultType.Covered, 0)
    missing = category_summary.get(evaluation.ResultType.Missing, 0)
    extra = category_summary.get(evaluation.ResultType.Extra, 0)

    total = covered + missing
    result = f"{covered}/{total}"

    if extra > 0:
        result += f" (+{extra})"

    return result


def _safe_merge_categories(cat1, cat2):
    """Safely merge two category dictionaries, handling mixed data types.

    :param cat1: First category data (dict, int, float, or other)
    :param cat2: Second category data (dict, int, float, or other)
    :return: Merged category data, handling various input types gracefully
    """
    if hasattr(cat1, "get") and hasattr(cat2, "get"):
        return cat1 | cat2
    if hasattr(cat1, "get"):
        return cat1
    elif hasattr(cat2, "get"):
        return cat2
    if isinstance(cat1, (int, float)) and isinstance(cat2, (int, float)):
        return int(cat1) + int(cat2)
    elif isinstance(cat1, (int, float)):
        return cat1
    elif isinstance(cat2, (int, float)):
        return cat2

    return {}


def process_source_filter(scan_runs: list, source_filter: str) -> list:
    """Apply source filtering logic to scan runs based on filter criteria.

    :param scan_runs: List of scan run records to filter
    :param source_filter: Filter string ("all", "manifests", "cluster", "type:name", etc.)
    :return: Filtered list of scan runs matching the specified criteria
    """
    if source_filter == "all" or not scan_runs:
        return scan_runs

    if ":" in source_filter:
        return _filter_by_specific_source(scan_runs, source_filter)
    else:
        return _filter_by_source_type(scan_runs, source_filter)


def _filter_by_specific_source(scan_runs: list, source_filter: str) -> list:
    """Handle specific source filtering with type:name format.

    :param scan_runs: List of scan run records to filter
    :param source_filter: Filter string in format "type:name"
    :return: Filtered scan runs matching the specific source type and name
    """
    filter_type, filter_name = source_filter.split(":", 1)
    filtered_runs = []

    for run in scan_runs:
        source_type = run.get("source_type", "")
        source_location = run.get("source_location", "")

        if ":" in source_type:
            run_type, run_name = source_type.split(":", 1)
            if run_type.lower() == filter_type.lower() and run_name == filter_name:
                filtered_runs.append(run)
        elif source_type.lower() == filter_type.lower() and (
            source_location == filter_name or Path(source_location).name == filter_name
        ):
            filtered_runs.append(run)

    return filtered_runs


def _filter_by_source_type(scan_runs: list, source_filter: str) -> list:
    """Handle source type filtering for scan runs.

    :param scan_runs: List of scan run records to filter
    :param source_filter: Source type to filter by (e.g., "manifests", "cluster")
    :return: Filtered scan runs matching the specified source type
    """
    return [run for run in scan_runs if run.get("source_type", "").lower().split(":")[0] == source_filter.lower()]


def parse_scan_timestamp(timestamp: str) -> str:
    """Parse and format timestamp string for display in overview.

    :param timestamp: Raw timestamp string from database
    :return: Formatted timestamp string in "Mon DD, YYYY HH:MM" format, or original string if parsing fails
    """
    try:
        if "T" in timestamp:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        else:
            dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%b %d, %Y %H:%M")
    except Exception:
        return timestamp


def create_scanner_summary(name: str, db_summary: dict, unified_service) -> tuple[evaluation.EvaluationSummary, bool]:
    """Create evaluation summary from database data or fallback values.

    :param name: Scanner name to create summary for
    :param db_summary: Summary data retrieved from database
    :param unified_service: Service instance for loading scanner summaries
    :return: Tuple of (EvaluationSummary object, boolean indicating if summary is valid)
    """
    if db_summary:
        summary = unified_service.load_scanner_summary(name.lower())
        is_valid_summary = summary is not None

        if summary is None:
            summary = evaluation.EvaluationSummary(
                version=db_summary["scanner_version"],
                checks_per_category={},
                score=db_summary["score"],
                coverage=db_summary["coverage"],
                extra_checks=db_summary["extra_checks"],
                missing_checks=db_summary["missing_checks"],
                ccss_alignment_score=db_summary["ccss_alignment_score"],
            )
        return summary, is_valid_summary
    else:
        return evaluation.EvaluationSummary(None, {}, 0, 0, 0, 0), False


def build_scanner_info(
    name: str,
    scanner,
    summary: evaluation.EvaluationSummary,
    is_valid_summary: bool,
    latest_scan_date: str,
) -> evaluation.ScannerInfo:
    """Build comprehensive scanner information object from summary and metadata.

    :param name: Scanner name
    :param scanner: Scanner class instance with configuration details
    :param summary: Evaluation summary containing performance metrics
    :param is_valid_summary: Boolean indicating whether the summary data is valid
    :param latest_scan_date: Formatted string of the most recent scan date
    :return: ScannerInfo object containing all scanner details and category ratios
    """
    categories = summary.checks_per_category

    return evaluation.ScannerInfo(
        name,
        image=scanner.IMAGE_URL,
        version=summary.version,
        score=summary.score,
        coverage=summary.coverage,
        ci_mode=scanner.CI_MODE,
        runs_offline=str(scanner.RUNS_OFFLINE),
        cat_admission_ctrl=_get_category_ratio(categories.get(CheckCategory.AdmissionControl, None)),
        cat_data_security=_get_category_ratio(categories.get(CheckCategory.DataSecurity, None)),
        cat_iam=_get_category_ratio(categories.get(CheckCategory.IAM, None)),
        cat_network=_get_category_ratio(categories.get(CheckCategory.Network, None)),
        cat_reliability=_get_category_ratio(categories.get(CheckCategory.Reliability, None)),
        cat_segregation=_get_category_ratio(categories.get(CheckCategory.Segregation, None)),
        cat_workload=_get_category_ratio(categories.get(CheckCategory.Workload, None)),
        cat_misc=_get_category_ratio(
            _safe_merge_categories(
                categories.get(CheckCategory.Misc, {}),
                categories.get(CheckCategory.Vulnerability, {}),
            )
        ),
        can_scan_manifests=scanner.can_scan_manifests,
        can_scan_cluster=scanner.can_scan_cluster,
        custom_checks=str(scanner.CUSTOM_CHECKS),
        formats=", ".join(scanner.FORMATS),
        is_valid_summary=is_valid_summary,
        latest_scan_date=latest_scan_date,
    )
