"""
Utility functions for the overview page to reduce cognitive complexity.
This module extracts complex logic from the main overview functions.
"""

from datetime import datetime
from pathlib import Path

from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckCategory


def process_source_filter(scan_runs: list, source_filter: str) -> list:
    """Extract the complex source filtering logic.

    Args:
        scan_runs: List of scan run records
        source_filter: Filter string ("all", "manifests", "cluster", "type:name", etc.)

    Returns:
        Filtered list of scan runs
    """
    if source_filter == "all" or not scan_runs:
        return scan_runs

    if ":" in source_filter:
        return _filter_by_specific_source(scan_runs, source_filter)
    else:
        return _filter_by_source_type(scan_runs, source_filter)


def _filter_by_specific_source(scan_runs: list, source_filter: str) -> list:
    """Handle specific source filtering with type:name format.

    Args:
        scan_runs: List of scan run records
        source_filter: Filter string in format "type:name"

    Returns:
        Filtered scan runs matching the specific source
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
    """Handle source type filtering.

    Args:
        scan_runs: List of scan run records
        source_filter: Source type to filter by

    Returns:
        Filtered scan runs matching the source type
    """
    return [run for run in scan_runs if run.get("source_type", "").lower().split(":")[0] == source_filter.lower()]


def parse_scan_timestamp(timestamp: str) -> str:
    """Extract timestamp parsing logic.

    Args:
        timestamp: Raw timestamp string from database

    Returns:
        Formatted timestamp string or original if parsing fails
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
    """Extract scanner summary creation logic.

    Args:
        name: Scanner name
        db_summary: Summary data from database
        unified_service: Service for loading scanner summaries

    Returns:
        Tuple of (EvaluationSummary, is_valid_summary)
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
    name: str, scanner, summary: evaluation.EvaluationSummary, is_valid_summary: bool, latest_scan_date: str
) -> evaluation.ScannerInfo:
    """Extract scanner info building logic.

    Args:
        name: Scanner name
        scanner: Scanner class instance
        summary: Evaluation summary
        is_valid_summary: Whether the summary is valid
        latest_scan_date: Formatted latest scan date

    Returns:
        ScannerInfo object
    """
    from kalm_benchmark.ui._pages.overview import _get_category_ratio

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
            categories.get(CheckCategory.Misc, {}) | categories.get(CheckCategory.Vulnerability, {})
        ),
        can_scan_manifests=scanner.can_scan_manifests,
        can_scan_cluster=scanner.can_scan_cluster,
        custom_checks=str(scanner.CUSTOM_CHECKS),
        formats=", ".join(scanner.FORMATS),
        is_valid_summary=is_valid_summary,
        latest_scan_date=latest_scan_date,
    )
