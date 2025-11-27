import pandas as pd
from loguru import logger

from kalm_benchmark.evaluation.ccss.ccss_converter import CCSSConverter
from kalm_benchmark.utils.data.normalization import normalize_scanner_name

logger = logger.bind(component="ui")


def group_scanner_summaries(summaries: list[dict]) -> pd.DataFrame:
    """Common pattern for processing evaluation summaries.

    : param summaries: list of evaluation summary dictionaries
    :return: DataFrame with grouped and normalized scanner metrics
    """
    if not summaries:
        logger.warning("No summaries provided to group_scanner_summaries")
        return pd.DataFrame()

    logger.debug(f"Processing {len(summaries)} scanner summaries for grouping")

    summary_list = []
    for summary in summaries:
        normalized_name = normalize_scanner_name(summary.get("scanner_name", ""))
        summary_normalized = summary.copy()
        summary_normalized["scanner_name"] = normalized_name
        summary_list.append(summary_normalized)

    perf_df = pd.DataFrame(summary_list)

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

    logger.info(f"Successfully grouped {len(perf_df)} unique scanner summaries")
    return perf_df


def fetch_severity_data(unified_service, has_ccss_column: bool) -> list[dict]:
    """Severity data fetching and normalization.

    :param unified_service: Service for database access
    :param has_ccss_column: Whether CCSS scoring column exists
    :return: list of severity data records
    """
    logger.debug(f"Fetching severity data, CCSS column available: {has_ccss_column}")

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

        result = cursor.fetchall()
        logger.info(f"Retrieved {len(result)} severity data records")
        return result


def normalize_severity_dataframe(severity_data: list, has_ccss_column: bool) -> pd.DataFrame:
    """DataFrame creation and normalization logic.

    :param severity_data: Raw severity data from database
    :param has_ccss_column: Whether CCSS scoring is available
    :returns: Normalized DataFrame with severity information
    """
    severity_list = []
    for row in severity_data:
        scanner_name, severity, count = row["scanner_name"], row["severity"].lower(), row["finding_count"]
        avg_ccss = row.get("avg_ccss_score") if has_ccss_column else None
        if "(" in severity and ")" in severity:
            try:
                severity = severity.split("(")[0].strip()
            except (IndexError, ValueError):
                pass


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

    logger.info(
        f"Severity dataframe normalized: {len(severity_df)} rows across {severity_df['Scanner'].nunique()} scanners"
    )
    return severity_df


def calculate_severity_percentages(severity_df: pd.DataFrame) -> pd.DataFrame:
    """Percentage calculation logic.

    :param severity_df: DataFrame with severity counts
    :return: DataFrame with added percentage columns
    """
    severity_pct_df = severity_df.copy()
    scanner_totals = severity_pct_df.groupby("Scanner")["Count"].sum().reset_index()
    scanner_totals.columns = ["Scanner", "Total"]
    severity_pct_df = severity_pct_df.merge(scanner_totals, on="Scanner")
    severity_pct_df["Percentage"] = (severity_pct_df["Count"] / severity_pct_df["Total"]) * 100

    return severity_pct_df


def get_normalized_performance_data(unified_service) -> pd.DataFrame:
    """Get normalized performance data.

    :param unified_service: Service for accessing evaluation summaries
    return: Normalized performance DataFrame
    """
    summaries = unified_service.create_evaluation_summary_dataframe()
    if not summaries:
        return pd.DataFrame()

    return group_scanner_summaries(summaries)
