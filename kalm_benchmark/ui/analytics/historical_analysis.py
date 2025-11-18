from datetime import datetime, timedelta

import altair as alt
import pandas as pd
import streamlit as st
from loguru import logger

from kalm_benchmark.ui.interface.source_filter import (
    ScanSourceType,
    get_source_filter_sql_condition,
)
from kalm_benchmark.utils.constants import DEFAULT_HELM_TRENDS_DAYS


def get_historical_scan_trends(
    unified_service, source_type: ScanSourceType, chart_name: str = None, days: int = DEFAULT_HELM_TRENDS_DAYS
) -> dict:
    """Get historical scan trends over time."""
    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()
            source_condition, source_params = get_source_filter_sql_condition(source_type, "sr2")

            if source_type == ScanSourceType.HELM_CHARTS and chart_name:
                source_condition = "AND sr.source_type = ?"
                source_params = [f"helm-chart:{chart_name}"]

            cutoff_date = datetime.now() - timedelta(days=days)
            cutoff_timestamp = cutoff_date.isoformat()

            query = f"""
                SELECT
                    DATE(sr.timestamp) as scan_date,
                    sr.scanner_name,
                    COUNT(DISTINCT sr.id) as scan_count,
                    COUNT(sr2.id) as total_findings,
                    AVG(CASE WHEN sr2.severity IN ('CRITICAL', 'HIGH', 'DANGER')
                        THEN 1.0 ELSE 0.0 END) as high_severity_rate
                FROM scan_runs sr
                LEFT JOIN scanner_results sr2 ON sr.timestamp = sr2.scan_timestamp
                    AND sr.scanner_name = sr2.scanner_name
                WHERE sr.timestamp >= ? {source_condition}
                GROUP BY DATE(sr.timestamp), sr.scanner_name
                ORDER BY scan_date DESC, sr.scanner_name
            """

            params = [cutoff_timestamp] + source_params

            from kalm_benchmark.utils.data.db_utils import (
                handle_scan_date_column,
                safe_db_query_execution,
            )

            results = safe_db_query_execution(cursor, query, params)

            results = handle_scan_date_column(results)

            return {"trends": results, "date_range": days, "cutoff_date": cutoff_timestamp}
    except Exception as e:
        logger.error(f"Error getting historical trends: {e}")
        return {"trends": [], "date_range": days, "cutoff_date": None}


def render_historical_scan_trends(unified_service, source_type: ScanSourceType, chart_name: str | None = None):
    """Render historical scan trends visualization."""
    st.markdown("### 📈 Historical Scan Trends")

    days = _render_date_range_selector()
    trends_data = get_historical_scan_trends(unified_service, source_type, chart_name, days)

    trends_df = _validate_and_prepare_trends_data(trends_data, source_type, chart_name)
    if trends_df is None:
        return

    _render_trend_tabs(trends_df)
    _render_trend_summary(trends_df, days)


def _render_date_range_selector() -> int:
    """Render date range selector and return selected days."""
    col1, col2 = st.columns([3, 1])

    with col1:
        date_ranges = {"Last 7 days": 7, "Last 30 days": 30, "Last 90 days": 90, "Last 6 months": 180}

        selected_range = st.selectbox(
            "Time Range:", options=list(date_ranges.keys()), index=1, key="historical_date_range"  # Default to 30 days
        )
        return date_ranges[selected_range]

    with col2:
        if st.button("🔄 Refresh Trends"):
            st.rerun()


def _validate_and_prepare_trends_data(
    trends_data: dict, source_type: ScanSourceType, chart_name: str = None
) -> pd.DataFrame | None:
    """Validate trends data and prepare DataFrame."""
    if not trends_data["trends"]:
        if source_type is None:
            source_type = ScanSourceType.BENCHMARK
        source_name = source_type.display_name()
        if chart_name:
            source_name += f" - {chart_name}"
        st.info(f"No scan history found for {source_name.lower()} in the selected time range.")
        return None

    trends_df = pd.DataFrame(trends_data["trends"])

    if trends_df.empty:
        if source_type is None:
            source_type = ScanSourceType.BENCHMARK
        source_name = source_type.display_name()
        if chart_name:
            source_name += f" - {chart_name}"
        st.info(f"No scan history found for {source_name.lower()} in the selected time range.")
        return None

    if "scan_date" not in trends_df.columns:
        st.error("Database query returned unexpected format. Missing scan_date column.")
        if not trends_df.empty:
            column_names = [str(col) for col in trends_df.columns.tolist()]
            st.info("Available columns: " + ", ".join(column_names))
        else:
            st.info("No columns found")
        return None

    trends_df["scan_date"] = pd.to_datetime(trends_df["scan_date"])
    return trends_df


def _render_trend_tabs(trends_df: pd.DataFrame):
    """Render the trend visualization tabs."""
    trend_tab1, trend_tab2, trend_tab3 = st.tabs(["🔄 Scan Activity", "🚨 Findings Over Time", "📊 Security Metrics"])

    with trend_tab1:
        _render_scan_activity_chart(trends_df)

    with trend_tab2:
        _render_findings_chart(trends_df)

    with trend_tab3:
        _render_severity_chart(trends_df)


def _render_scan_activity_chart(trends_df: pd.DataFrame):
    """Render scan activity chart."""
    st.markdown("**Scan Activity Over Time**")

    if not trends_df.empty:
        scan_activity_chart = (
            alt.Chart(trends_df)
            .mark_line(point=True)
            .encode(
                x=alt.X("scan_date:T", title="Date"),
                y=alt.Y("scan_count:Q", title="Number of Scans"),
                color=alt.Color("scanner_name:N", title="Scanner"),
                tooltip=["scan_date:T", "scanner_name:N", "scan_count:Q"],
            )
            .properties(title="Scan Activity Timeline", height=300)
            .interactive()
        )
        st.altair_chart(scan_activity_chart, use_container_width=True)
    else:
        st.info("No scan activity data available.")


def _render_findings_chart(trends_df: pd.DataFrame):
    """Render findings over time chart."""
    st.markdown("**Security Findings Over Time**")

    if not trends_df.empty:
        findings_chart = (
            alt.Chart(trends_df)
            .mark_area(opacity=0.7)
            .encode(
                x=alt.X("scan_date:T", title="Date"),
                y=alt.Y("total_findings:Q", title="Total Findings"),
                color=alt.Color("scanner_name:N", title="Scanner"),
                tooltip=["scan_date:T", "scanner_name:N", "total_findings:Q"],
            )
            .properties(title="Security Findings Timeline", height=300)
            .interactive()
        )
        st.altair_chart(findings_chart, use_container_width=True)
    else:
        st.info("No findings data available.")


def _render_severity_chart(trends_df: pd.DataFrame):
    """Render high severity rate chart."""
    st.markdown("**High Severity Issue Rate Over Time**")

    if not trends_df.empty:
        # Filter out null high_severity_rate values
        severity_df = trends_df.dropna(subset=["high_severity_rate"])

        if not severity_df.empty:
            severity_chart = (
                alt.Chart(severity_df)
                .mark_line(point=True)
                .encode(
                    x=alt.X("scan_date:T", title="Date"),
                    y=alt.Y("high_severity_rate:Q", title="High Severity Rate", scale=alt.Scale(domain=[0, 1])),
                    color=alt.Color("scanner_name:N", title="Scanner"),
                    tooltip=["scan_date:T", "scanner_name:N", alt.Tooltip("high_severity_rate:Q", format=".2%")],
                )
                .properties(title="High Severity Issue Rate Timeline", height=300)
                .interactive()
            )
            st.altair_chart(severity_chart, use_container_width=True)
        else:
            st.info("No severity trend data available.")
    else:
        st.info("No severity data available.")


def _render_trend_summary(trends_df: pd.DataFrame, days: int):
    """Render trend summary statistics."""
    if not trends_df.empty:
        st.markdown("---")
        st.markdown("**📊 Trend Summary**")

        col1, col2, col3 = st.columns(3)

        with col1:
            total_scans = trends_df["scan_count"].sum()
            st.metric("Total Scans", total_scans)

        with col2:
            avg_daily_scans = trends_df.groupby("scan_date")["scan_count"].sum().mean()
            st.metric("Avg Daily Scans", f"{avg_daily_scans:.1f}")

        with col3:
            active_days = len(trends_df["scan_date"].unique())
            st.metric("Active Days", f"{active_days}/{days}")


def get_scanner_performance_trends(
    unified_service, scanner_name: str, source_type: ScanSourceType = ScanSourceType.ALL, days: int = 30
) -> dict:
    """Get performance trends for a specific scanner."""
    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()

            source_condition, source_params = get_source_filter_sql_condition(source_type, "sr2")

            cutoff_date = datetime.now() - timedelta(days=days)
            cutoff_timestamp = cutoff_date.isoformat()

            query = f"""
                SELECT
                    DATE(sr.timestamp) as scan_date,
                    COUNT(DISTINCT sr.id) as scan_count,
                    COUNT(sr2.id) as total_findings,
                    COUNT(DISTINCT sr2.scanner_check_name) as unique_checks,
                    COUNT(DISTINCT CASE WHEN sr2.severity IN ('CRITICAL', 'HIGH', 'DANGER')
                        THEN sr2.scanner_check_name END) as high_severity_checks,
                    COUNT(DISTINCT sr2.kind) as resource_types_scanned
                FROM scan_runs sr
                LEFT JOIN scanner_results sr2 ON sr.timestamp = sr2.scan_timestamp
                    AND sr.scanner_name = sr2.scanner_name
                WHERE sr.timestamp >= ?
                AND LOWER(sr.scanner_name) = ? {source_condition}
                GROUP BY DATE(sr.timestamp)
                ORDER BY scan_date DESC
            """

            params = [cutoff_timestamp, scanner_name.lower()] + source_params

            from kalm_benchmark.utils.data.db_utils import (
                handle_scan_date_column,
                safe_db_query_execution,
            )

            results = safe_db_query_execution(cursor, query, params)

            results = handle_scan_date_column(results)

            return {"performance_trends": results, "scanner_name": scanner_name, "date_range": days}
    except Exception as e:
        logger.error(f"Error getting scanner performance trends: {e}")
        return {"performance_trends": [], "scanner_name": scanner_name, "date_range": days}


def render_scanner_performance_trends(
    unified_service, scanner_name: str, source_type: ScanSourceType = ScanSourceType.ALL
):
    """Render performance trends for a specific scanner."""
    st.markdown(f"### 📊 {scanner_name} Performance Trends")

    # Date range selector
    date_ranges = {"Last 7 days": 7, "Last 30 days": 30, "Last 90 days": 90}
    selected_range = st.selectbox(
        "Analysis Period:", options=list(date_ranges.keys()), index=1, key=f"perf_trends_{scanner_name}"
    )
    days = date_ranges[selected_range]

    trends_data = get_scanner_performance_trends(unified_service, scanner_name, source_type, days)

    if not trends_data["performance_trends"]:
        st.info(f"No performance trend data found for {scanner_name} in the selected period.")
        return

    trends_df = pd.DataFrame(trends_data["performance_trends"])
    if trends_df.empty or "scan_date" not in trends_df.columns:
        st.info(f"No performance trend data available for {scanner_name}.")
        return
    trends_df["scan_date"] = pd.to_datetime(trends_df["scan_date"])

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**🔍 Detection Capability Trends**")

        detection_chart = (
            alt.Chart(trends_df)
            .mark_line(point=True)
            .encode(
                x=alt.X("scan_date:T", title="Date"),
                y=alt.Y("unique_checks:Q", title="Unique Security Checks"),
                tooltip=["scan_date:T", "unique_checks:Q", "total_findings:Q"],
            )
            .properties(height=200)
        )

        st.altair_chart(detection_chart, use_container_width=True)

    with col2:
        st.markdown("**🎯 Coverage Trends**")

        coverage_chart = (
            alt.Chart(trends_df)
            .mark_line(point=True)
            .encode(
                x=alt.X("scan_date:T", title="Date"),
                y=alt.Y("resource_types_scanned:Q", title="Resource Types Covered"),
                tooltip=["scan_date:T", "resource_types_scanned:Q"],
            )
            .properties(height=200)
        )

        st.altair_chart(coverage_chart, use_container_width=True)

    # Summary metrics
    if not trends_df.empty:
        col1, col2, col3 = st.columns(3)

        with col1:
            avg_findings = trends_df["total_findings"].mean()
            st.metric("Avg Findings/Day", f"{avg_findings:.1f}")

        with col2:
            avg_checks = trends_df["unique_checks"].mean()
            st.metric("Avg Unique Checks", f"{avg_checks:.1f}")

        with col3:
            max_coverage = trends_df["resource_types_scanned"].max()
            st.metric("Max Resource Coverage", max_coverage or 0)
