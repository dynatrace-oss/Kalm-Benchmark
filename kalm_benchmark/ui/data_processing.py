from typing import Dict, List, Optional

import pandas as pd


def normalize_scanner_names_in_dataframe(df: pd.DataFrame, name_column: str = "scanner_name") -> pd.DataFrame:
    """Standardize scanner name normalization across all UI functions.

    Args:
        df: DataFrame containing scanner names
        name_column: Column name containing scanner names

    Returns:
        DataFrame with normalized scanner names
    """
    from kalm_benchmark.ui._pages.scanner_comparison import normalize_scanner_name

    df = df.copy()
    df[name_column] = df[name_column].apply(normalize_scanner_name)
    return df


def group_scanner_summaries(summaries: List[Dict]) -> pd.DataFrame:
    """Common pattern for processing evaluation summaries.

    Args:
        summaries: List of evaluation summary dictionaries

    Returns:
        DataFrame with grouped and normalized scanner metrics
    """
    if not summaries:
        return pd.DataFrame()

    # Normalize scanner names
    summary_list = []
    for summary in summaries:
        from kalm_benchmark.ui._pages.scanner_comparison import normalize_scanner_name

        normalized_name = normalize_scanner_name(summary.get("scanner_name", ""))
        summary_normalized = summary.copy()
        summary_normalized["scanner_name"] = normalized_name
        summary_list.append(summary_normalized)

    perf_df = pd.DataFrame(summary_list)

    # Group by normalized scanner names and take the best metrics for each
    perf_df = (
        perf_df.groupby("scanner_name")
        .agg(
            {
                "score": "max",
                "coverage": "max",
                "extra_checks": "sum",
                "missing_checks": "min",
            }
        )
        .reset_index()
    )

    return perf_df


def fetch_severity_data(unified_service, has_ccss_column: bool) -> List[Dict]:
    """Extract severity data fetching and normalization.

    Args:
        unified_service: Service for database access
        has_ccss_column: Whether CCSS scoring column exists

    Returns:
        List of severity data records
    """
    with unified_service.db._get_connection() as conn:
        cursor = conn.cursor()

        # Focus on results that are likely from benchmark manifests
        if has_ccss_column:
            cursor.execute(
                """
                SELECT 
                    UPPER(TRIM(scanner_name)) as scanner_name,
                    severity,
                    COUNT(*) as finding_count,
                    AVG(CASE WHEN ccss_score IS NOT NULL THEN ccss_score END) as avg_ccss_score
                FROM scanner_results 
                WHERE severity IS NOT NULL 
                    AND severity != ''
                    AND severity != 'UNKNOWN'
                GROUP BY UPPER(TRIM(scanner_name)), severity
                ORDER BY scanner_name, finding_count DESC
            """
            )
        else:
            cursor.execute(
                """
                SELECT 
                    UPPER(TRIM(scanner_name)) as scanner_name,
                    severity,
                    COUNT(*) as finding_count
                FROM scanner_results 
                WHERE severity IS NOT NULL 
                    AND severity != ''
                    AND severity != 'UNKNOWN'
                GROUP BY UPPER(TRIM(scanner_name)), severity
                ORDER BY scanner_name, finding_count DESC
            """
            )

        return cursor.fetchall()


def normalize_severity_dataframe(severity_data: List, has_ccss_column: bool) -> pd.DataFrame:
    """Extract DataFrame creation and normalization logic.

    Args:
        severity_data: Raw severity data from database
        has_ccss_column: Whether CCSS scoring is available

    Returns:
        Normalized DataFrame with severity information
    """
    try:
        from kalm_benchmark.evaluation.ccss.ccss_converter import CCSSConverter
    except ImportError:
        # Fallback if CCSS module is not available
        class CCSSConverter:
            @staticmethod
            def _severity_to_score(severity: str) -> Optional[float]:
                severity_map = {
                    "CRITICAL": 9.0,
                    "HIGH": 7.0,
                    "DANGER": 7.0,
                    "MEDIUM": 4.0,
                    "WARNING": 2.5,
                    "LOW": 2.0,
                    "INFO": 1.0,
                }
                return severity_map.get(severity.upper())

    from kalm_benchmark.ui._pages.scanner_comparison import normalize_scanner_name

    severity_list = []
    for row in severity_data:
        scanner_name, severity, count = row["scanner_name"], row["severity"], row["finding_count"]
        avg_ccss = row.get("avg_ccss_score") if has_ccss_column else None
        score = CCSSConverter._severity_to_score(severity)

        # Normalize scanner names to match the SCANNERS registry
        normalized_name = normalize_scanner_name(scanner_name)

        severity_list.append(
            {"Scanner": normalized_name, "Severity": severity, "Score": score, "Count": count, "Avg_CCSS": avg_ccss}
        )

    severity_df = pd.DataFrame(severity_list)

    severity_df = (
        severity_df.groupby(["Scanner", "Severity", "Score"]).agg({"Count": "sum", "Avg_CCSS": "mean"}).reset_index()
    )

    return severity_df


def calculate_severity_percentages(severity_df: pd.DataFrame) -> pd.DataFrame:
    """Extract percentage calculation logic.

    Args:
        severity_df: DataFrame with severity counts

    Returns:
        DataFrame with added percentage columns
    """
    severity_pct_df = severity_df.copy()
    scanner_totals = severity_pct_df.groupby("Scanner")["Count"].sum().reset_index()
    scanner_totals.columns = ["Scanner", "Total"]
    severity_pct_df = severity_pct_df.merge(scanner_totals, on="Scanner")
    severity_pct_df["Percentage"] = (severity_pct_df["Count"] / severity_pct_df["Total"]) * 100

    return severity_pct_df


def get_normalized_performance_data(unified_service) -> pd.DataFrame:
    """Common function for getting normalized performance data.

    Args:
        unified_service: Service for accessing evaluation summaries

    Returns:
        Normalized performance DataFrame
    """
    summaries = unified_service.create_evaluation_summary_dataframe()
    if not summaries:
        return pd.DataFrame()

    return group_scanner_summaries(summaries)
