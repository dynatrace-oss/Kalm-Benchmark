"""Data filtering utilities for scanner results and evaluations."""

from datetime import datetime

from loguru import logger

from kalm_benchmark.ui.interface.source_filter import ScanSourceType
from kalm_benchmark.utils.data.normalization import normalize_scanner_name


def _parse_timestamp(timestamp_str: str):
    """Parse timestamp string to datetime object with fallback handling.

    :param timestamp_str: Timestamp string in various formats
    :return: datetime object or None if parsing fails
    """
    if not timestamp_str:
        return None

    try:
        if "T" in timestamp_str:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        else:
            return datetime.fromisoformat(timestamp_str + "T00:00:00+00:00")
    except (ValueError, TypeError):
        return None


def _check_timestamp_match(summary_timestamp: str, helm_timestamps: set, tolerance_seconds: float = 10.0) -> bool:
    """Check if summary timestamp matches any helm timestamp within tolerance.

    :param summary_timestamp: Summary timestamp string
    :param helm_timestamps: Set of helm timestamp strings
    :param tolerance_seconds: Tolerance in seconds for timestamp matching
    :return: True if timestamp matches within tolerance, False otherwise
    """
    summary_dt = _parse_timestamp(summary_timestamp)
    if not summary_dt:
        return any(summary_timestamp.split("T")[0] == helm_ts.split("T")[0] for helm_ts in helm_timestamps if helm_ts)

    for helm_ts in helm_timestamps:
        if not helm_ts:
            continue

        helm_dt = _parse_timestamp(helm_ts)
        if helm_dt:
            time_diff = abs((summary_dt - helm_dt).total_seconds())
            if time_diff <= tolerance_seconds:
                return True
        elif summary_timestamp.split("T")[0] == helm_ts.split("T")[0]:
            return True

    return False


def _check_scanner_match(summary_scanner: str, target_scanners: set) -> bool:
    """Check if summary scanner matches any target scanner after normalization.

    :param summary_scanner: Scanner name from summary
    :param target_scanners: Set of target scanner names
    :return:True if scanner matches, False otherwise
    """
    normalized_summary_scanner = normalize_scanner_name(summary_scanner)
    return any(
        normalized_summary_scanner.lower() == normalize_scanner_name(target_scanner).lower()
        for target_scanner in target_scanners
    )


def _filter_helm_summaries(all_summaries: list, scan_runs: list) -> list:
    """Filter summaries for helm charts with scanner and timestamp matching."""
    if not scan_runs:
        return []

    helm_scanners = {run.get("scanner_name") for run in scan_runs if run.get("scanner_name")}
    helm_timestamps = {run.get("timestamp") for run in scan_runs if run.get("timestamp")}

    helm_summaries = []
    for summary in all_summaries:
        summary_scanner = summary.get("scanner_name", "").lower()
        summary_timestamp = summary.get("scan_timestamp", "")

        if not _check_scanner_match(summary_scanner, helm_scanners):
            continue

        if not summary_timestamp:
            continue

        try:
            if _check_timestamp_match(summary_timestamp, helm_timestamps):
                helm_summaries.append(summary)
        except Exception as e:
            logger.warning(f"Failed to parse timestamps for summary matching: {e}")
            # Fallback to simple timestamp matching
            if summary_timestamp in helm_timestamps or any(
                summary_timestamp.split("T")[0] == helm_ts.split("T")[0] for helm_ts in helm_timestamps if helm_ts
            ):
                helm_summaries.append(summary)

    logger.info(f"Found {len(helm_summaries)} helm chart summaries from {len(all_summaries)} total summaries")
    return helm_summaries


def _filter_custom_summaries(all_summaries: list, scan_runs: list) -> list:
    """Filter summaries for custom manifests with simple matching."""
    if not scan_runs:
        return []

    custom_scanners = {run.get("scanner_name") for run in scan_runs if run.get("scanner_name")}
    custom_timestamps = {run.get("timestamp") for run in scan_runs if run.get("timestamp")}

    custom_summaries = []
    for summary in all_summaries:
        summary_scanner = summary.get("scanner_name", "").lower()
        summary_timestamp = summary.get("scan_timestamp", "")

        scanner_match = any(summary_scanner == custom_scanner.lower() for custom_scanner in custom_scanners)

        if scanner_match and summary_timestamp in custom_timestamps:
            custom_summaries.append(summary)

    return custom_summaries


def get_filtered_summaries(unified_service, source_type: ScanSourceType, chart_name: str = None):
    """Get evaluation summaries filtered by source type.

    :param unified_service: Unified service instance for database operations
    :param source_type: Type of scan source to filter by
    :param chart_name: Optional chart name for helm chart filtering
    :return: List of filtered evaluation summaries
    """
    try:
        all_summaries = unified_service.create_evaluation_summary_dataframe()

        if all_summaries is None or len(all_summaries) == 0:
            return []

        if source_type == ScanSourceType.ALL:
            return all_summaries

        if source_type == ScanSourceType.BENCHMARK:
            if hasattr(unified_service, "create_benchmark_evaluation_summary_dataframe"):
                return unified_service.create_benchmark_evaluation_summary_dataframe()
            else:
                return unified_service.db.get_benchmark_evaluation_summaries()

        elif source_type == ScanSourceType.HELM_CHARTS:
            if chart_name:
                scan_runs = unified_service.db.get_scan_runs(
                    source_filter="helm_charts", chart_name=f"helm-chart:{chart_name}"
                )
            else:
                scan_runs = unified_service.db.get_scan_runs(source_filter="helm_charts")

            return _filter_helm_summaries(all_summaries, scan_runs)

        elif source_type == ScanSourceType.CUSTOM_MANIFESTS:
            scan_runs = unified_service.db.get_scan_runs(source_filter="custom_manifests")
            return _filter_custom_summaries(all_summaries, scan_runs)

        return []
    except Exception as e:
        logger.error(f"Error filtering summaries: {e}")
        return []
