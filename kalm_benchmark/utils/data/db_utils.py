from typing import Any, Dict, List, Optional

from loguru import logger


def normalize_query_results(
    cursor_results: List, column_descriptions: List, column_mapping: Optional[Dict[str, str]] = None
) -> List[Dict[str, Any]]:
    """
    Normalize database query results to consistent dictionary format.

    :param cursor_results: Raw cursor results from database query
    :param column_descriptions: Column descriptions from cursor
    :param column_mapping: Optional mapping of old column names to new ones
    :return: List of dictionaries with normalized column names
    """
    if not cursor_results:
        return []

    results = []
    columns = [description[0] for description in column_descriptions]

    for row in cursor_results:
        if isinstance(row, dict):
            result_dict = dict(row)
        else:
            result_dict = {columns[i]: row[i] for i in range(len(columns))}

        if column_mapping:
            for old_col, new_col in column_mapping.items():
                if old_col in result_dict and new_col not in result_dict:
                    result_dict[new_col] = result_dict[old_col]

        results.append(result_dict)

    return results


def handle_scan_date_column(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Handle scan_date column normalization for historical queries.


    :param results: List of result dictionaries
    :return: Results with normalized scan_date column
    """
    for result in results:
        if "scan_date" not in result:
            result["scan_date"] = _extract_scan_date_from_result(result)

    return results


def _extract_scan_date_from_result(result: Dict[str, Any]) -> Optional[str]:
    """Extract scan_date from various column formats in a result dictionary."""
    alt_columns = ["DATE(sr.timestamp)", "date", "scan_timestamp"]
    for alt_col in alt_columns:
        if alt_col in result:
            return result[alt_col]

    return _extract_date_from_timestamp(result.get("timestamp"))


def _extract_date_from_timestamp(timestamp: Any) -> Optional[str]:
    """Extract date part from a timestamp value."""
    if not timestamp:
        return None

    try:
        timestamp_str = str(timestamp)
        return timestamp_str.split("T")[0] if "T" in timestamp_str else timestamp_str
    except (AttributeError, ValueError) as e:
        logger.warning(f"Failed to extract date from timestamp: {timestamp} - {e}")
        return None


def ensure_required_columns(
    results: List[Dict[str, Any]], required_columns: List[str], default_values: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Ensure all required columns exist in results with appropriate defaults.

    :param results: List of result dictionaries
    :param required_columns: List of required column names
    :param default_values: Default values for missing columns
    :return: Results with all required columns present
    """
    if not default_values:
        default_values = {}

    for result in results:
        for col in required_columns:
            if col not in result:
                result[col] = default_values.get(col, None)

    return results


def safe_db_query_execution(cursor, query: str, params: List = None) -> List[Dict[str, Any]]:
    """
    Safely execute a database query with proper error handling and result normalization.

    :param cursor: Database cursor
    :param query: SQL query string
    :param params: Query parameters
    :return: Normalized query results
    """
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        results = normalize_query_results(cursor.fetchall(), cursor.description)

        logger.debug(f"Query returned {len(results)} results")
        return results

    except Exception as e:
        logger.error(f"Database query failed: {e}")
        logger.debug(f"Query: {query}")
        logger.debug(f"Params: {params}")
        return []


def filter_results_by_source_type(
    results: List[Dict[str, Any]], source_type_filter: str, source_type_column: str = "source_type"
) -> List[Dict[str, Any]]:
    """
    Filter results based on source type criteria.

    :param results: List of result dictionaries
    :param source_type_filter: Filter criteria ('benchmark', 'helm_charts', etc.)
    :param source_type_column: Name of the source type column
    :return: Filtered results
    """
    if not source_type_filter or source_type_filter == "all":
        return results

    return [result for result in results if _matches_source_type_filter(result, source_type_filter, source_type_column)]


def _matches_source_type_filter(result: Dict[str, Any], filter_type: str, column_name: str) -> bool:
    """
    Check if a result matches the specified source type filter.

    :param result: Result dictionary to check
    :param filter_type: Filter criteria to match against
    :param column_name: Name of the source type column
    :return: True if result matches filter, False otherwise
    """
    source_type = result.get(column_name, "")

    filter_handlers = {
        "benchmark": _is_benchmark_source,
        "helm_charts": _is_helm_chart_source,
        "custom_manifests": _is_custom_manifest_source,
    }

    handler = filter_handlers.get(filter_type)
    if handler:
        return handler(source_type)

    return source_type == filter_type


def _is_benchmark_source(source_type: str) -> bool:
    """Check if source type represents benchmark data."""
    return source_type in ["manifest", "benchmark", ""] or source_type is None


def _is_helm_chart_source(source_type: str) -> bool:
    """Check if source type represents helm chart data."""
    return bool(source_type and source_type.startswith("helm-chart:"))


def _is_custom_manifest_source(source_type: str) -> bool:
    """Check if source type represents custom manifest data."""
    if not source_type:
        return False
    return not source_type.startswith("helm-chart:") and source_type not in ["manifest", "benchmark"]


def group_results_by_scanner(results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group results by scanner name for analysis.

    :param results: List of result dictionaries
    :return: Dictionary mapping scanner names to their results
    """
    grouped = {}

    for result in results:
        scanner_name = result.get("scanner_name", "Unknown")

        if scanner_name not in grouped:
            grouped[scanner_name] = []

        grouped[scanner_name].append(result)

    return grouped
