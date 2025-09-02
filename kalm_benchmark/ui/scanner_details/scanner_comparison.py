from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st
from loguru import logger

from kalm_benchmark.utils.data.normalization import normalize_scanner_name

try:
    from kalm_benchmark.evaluation.ccss.ccss_converter import CCSSConverter
except ImportError:
    # Fallback until CCSS module is available
    class CCSSConverter:
        @staticmethod
        def _severity_to_score(severity: str) -> float | None:
            """Fallback severity to score mapping"""
            if not severity:
                return None

            severity_map = {
                "CRITICAL": 9.0,
                "HIGH": 7.0,
                "DANGER": 7.0,  # Polaris high severity
                "MEDIUM": 4.0,
                "WARNING": 2.5,  # Polaris medium-low severity
                "LOW": 2.0,
                "INFO": 1.0,
            }

            # Handle numeric severity values (kubesec format)
            try:
                numeric_score = float(severity)
                return numeric_score
            except (ValueError, TypeError):
                pass

            return severity_map.get(severity.upper())


from kalm_benchmark.ui.analytics.helm_analytics import (
    render_helm_chart_popularity_analysis,
    render_helm_chart_security_profile,
    render_helm_deployment_patterns_analysis,
)
from kalm_benchmark.ui.analytics.historical_analysis import (
    render_historical_scan_trends,
)
from kalm_benchmark.ui.analytics.performance_utils import (
    create_performance_details_table,
    create_performance_scatter_chart,
    normalize_and_aggregate_performance_data,
    render_performance_insights,
    render_performance_overview_metrics,
    render_performance_rankings,
    render_top_performers,
)
from kalm_benchmark.ui.components import (
    render_insights_section,
    render_no_data_message,
    render_scanner_metrics,
    render_scanner_pie_charts,
    render_severity_summary_table,
)
from kalm_benchmark.ui.data_processing import (
    calculate_severity_percentages,
    normalize_severity_dataframe,
)
from kalm_benchmark.ui.interface.gen_utils import get_unified_service
from kalm_benchmark.ui.interface.source_filter import (
    ScanSourceType,
    get_source_filter_sql_condition,
    render_helm_chart_selector,
    render_source_info_metrics,
    render_source_type_filter,
)
from kalm_benchmark.ui.visualization.chart_utils import create_severity_bar_chart


def show():
    """Display the main scanner comparison page with interactive filtering and analysis.
    Provides comprehensive scanner comparison across different source types with
    severity distribution analysis, performance metrics, and coverage insights.
    :return: None
    """

    # Scanner Comparison Header - Using same color scheme as other pages
    st.markdown(
        """
        <div style="text-align: center; padding: 3.5rem 0 2.5rem 0;
                    background: linear-gradient(
                        135deg, #6c5ce7 0%, #a29bfe 20%, #74b9ff 40%,
                        #00cec9 60%, #55efc4 80%, #6c5ce7 100%);
                    border-radius: 20px; margin-bottom: 2rem;
                    box-shadow: 0 15px 40px rgba(108, 92, 231, 0.5);
                    position: relative; overflow: hidden;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0;
                        background: radial-gradient(circle at 15% 25%, rgba(162, 155, 254, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 85% 75%, rgba(116, 185, 255, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 50% 15%, rgba(0, 206, 201, 0.3) 0%, transparent 45%),
                                    radial-gradient(circle at 25% 85%, rgba(85, 239, 196, 0.3) 0%, transparent 45%);
                        pointer-events: none;"></div>
            <div style="max-width: 800px; margin: 0 auto; padding: 0 2rem; position: relative; z-index: 1;">
                <h1 style="color: #FFFFFF; margin-bottom: 0.5rem; font-size: 3.2rem; font-weight: 800;
                           text-shadow: 0 4px 15px rgba(0,0,0,0.4); letter-spacing: -0.02em;">
                    🔍 Scanner Comparison
                </h1>
                <h3 style="color: rgba(255,255,255,0.95); font-weight: 500; margin-bottom: 1.5rem;
                          font-size: 1.6rem; text-shadow: 0 2px 8px rgba(0,0,0,0.3);">
                    Multi-Source Scanner Analysis
                </h3>
                <p style="color: rgba(255,255,255,0.9); max-width: 650px; margin: 0 auto;
                         line-height: 1.7; font-size: 1.15rem; text-shadow: 0 2px 6px rgba(0,0,0,0.25);">
                    Compare security scanner performance across benchmark tests, Helm charts, and custom manifests.
                    Analyze detection accuracy, coverage rates, and scoring alignment across different source types.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Get unified service
    unified_service = get_unified_service()

    # Source Type Filter Section
    st.markdown("### 🎯 Analysis Scope")
    col1, col2, col3 = st.columns([2, 2, 1])

    with col1:
        selected_source_type = render_source_type_filter(
            key="scanner_comparison_source_filter",
            default=ScanSourceType.BENCHMARK,
            show_counts=True,
            unified_service=unified_service,
        )

    with col2:
        # Show helm chart selector if helm charts are selected
        selected_chart = None
        if selected_source_type == ScanSourceType.HELM_CHARTS:
            selected_chart = render_helm_chart_selector(unified_service, key="scanner_comparison_helm_chart")

    with col3:
        if st.button("🔄 Refresh Data", help="Reload comparison data"):
            st.rerun()

    # Show source metrics
    render_source_info_metrics(unified_service)

    st.divider()

    # Check if we have data for the selected source type
    if not has_data_for_source_type(unified_service, selected_source_type, selected_chart):
        show_no_data_message(selected_source_type)
        return

    try:
        show_source_overview(unified_service, selected_source_type, selected_chart)

        st.divider()

        show_source_performance_comparison(unified_service, selected_source_type, selected_chart)

        st.divider()

        show_source_coverage_analysis(unified_service, selected_source_type, selected_chart)

        st.divider()

        show_source_severity_comparison(unified_service, selected_source_type, selected_chart)

        st.divider()

        show_source_detection_analysis(unified_service, selected_source_type, selected_chart)

        # Add helm-specific analysis if helm charts are selected
        if selected_source_type == ScanSourceType.HELM_CHARTS:
            st.divider()
            show_helm_specific_analysis(unified_service, selected_chart)

        # Add historical trends analysis
        st.divider()
        show_historical_trends_section(unified_service, selected_source_type, selected_chart)

    except Exception as e:
        st.error(f"An error occurred while loading comparison data: {str(e)}")
        st.info("Please ensure you have run scanner evaluations and the database is properly configured.")


def show_source_severity_comparison(unified_service, source_type: ScanSourceType, chart_name: str = None):
    """Display comprehensive severity distribution comparison for scanners.

    :param unified_service: Unified service instance for database operations
    :param source_type: Type of scan source to analyze
    :param chart_name: Optional chart name for helm chart specific analysis
    :return: None
    """
    source_display = source_type.display_name()
    if source_type == ScanSourceType.HELM_CHARTS and chart_name:
        source_display += f" - {chart_name}"

    st.subheader(f"⚖️ {source_display} Severity Analysis")

    has_ccss_column = check_ccss_column_exists(unified_service)
    severity_data = fetch_filtered_severity_data(unified_service, has_ccss_column, source_type, chart_name)

    if not severity_data:
        render_no_data_message(f"No severity scoring data available for {source_display.lower()}.")
        return

    severity_df = normalize_severity_dataframe(severity_data, has_ccss_column)

    _render_severity_overview(severity_df, source_display)
    _render_severity_visualizations(severity_df, source_display)
    _render_severity_insights(has_ccss_column)


def _render_severity_overview(severity_df: pd.DataFrame, source_display: str = "Results"):
    """Render the severity overview section."""
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"**📊 {source_display} Severity Distribution**")
        render_severity_summary_table(severity_df)

    with col2:
        st.markdown(f"**🎯 {source_display} Scoring Patterns**")
        scanner_patterns = severity_df.groupby("Scanner").agg({"Count": "sum", "Severity": "nunique"}).reset_index()
        render_scanner_metrics(scanner_patterns)


def _render_severity_visualizations(severity_df: pd.DataFrame, source_display: str = "Results"):
    """Render the severity visualization tabs."""
    if len(severity_df) == 0:
        return

    st.markdown(f"**📈 {source_display} Severity Distribution Analysis**")

    # Tabs for different visualization approaches
    viz_tab1, viz_tab2 = st.tabs(["🥧 Severity Distribution", "📊 Finding Counts"])

    with viz_tab1:
        st.markdown("**Severity Distribution by Scanner (Pie Charts)**")
        severity_pct_df = calculate_severity_percentages(severity_df)
        render_scanner_pie_charts(severity_pct_df)
        st.info(
            "💡 Pie charts show the relative severity distribution within each scanner, "
            "making it easy to compare severity patterns and see which scanners focus "
            "on different types of issues."
        )

    with viz_tab2:
        st.markdown("**Absolute Finding Counts by Scanner**")

        grouped_chart = create_severity_bar_chart(severity_df)
        st.altair_chart(grouped_chart, use_container_width=True)

        _render_severity_summary_stats(severity_df)


def _render_severity_summary_stats(severity_df: pd.DataFrame):
    """Render summary statistics for severity data."""
    st.markdown("**📋 Scanner Summary**")
    scanner_summary = severity_df.groupby("Scanner").agg({"Count": "sum", "Severity": "nunique"}).reset_index()
    scanner_summary.columns = ["Scanner", "Total Findings", "Severity Types"]
    scanner_summary = scanner_summary.sort_values("Total Findings", ascending=False)

    col1, col2 = st.columns(2)
    with col1:
        st.dataframe(scanner_summary, use_container_width=True, hide_index=True)

    with col2:
        for _, row in scanner_summary.iterrows():
            scanner_name = row["Scanner"]
            total = row["Total Findings"]
            types = row["Severity Types"]
            st.markdown(f"**{scanner_name}**: {total:,} findings across {types} severity levels")

    st.info(
        "💡 This view shows absolute counts, making it easy to see which scanners "
        "find more issues overall and compare finding volumes across different "
        "severity levels."
    )


def _render_severity_insights(has_ccss_column: bool):
    """Render severity analysis insights."""
    insights = [
        "**Severity patterns** show how scanners classify benchmark security issues",
        "**Distribution differences** may indicate varying security philosophies",
        "**Consistent patterns** across scanners suggest well-established security issues",
    ]

    if has_ccss_column:
        insights.insert(2, "**CCSS alignment** shows compliance with standardized scoring")
    else:
        insights.append("**CCSS scoring** not yet available - run CCSS evaluation for alignment analysis")

    render_insights_section(insights, "💡 Severity Analysis Insights")


def show_source_detection_analysis(unified_service, source_type: ScanSourceType, chart_name: str = None):
    """Display analysis of issue types and detection patterns across scanners.

    :param unified_service: Unified service instance for database operations
    :param source_type: Type of scan source to analyze
    :param chart_name: Optional chart name for helm chart specific analysis
    :return: None
    """
    source_display = source_type.display_name()
    if source_type == ScanSourceType.HELM_CHARTS and chart_name:
        source_display += f" - {chart_name}"

    st.subheader(f"🔍 {source_display} Detection Analysis")

    with unified_service.db._get_connection() as conn:
        cursor = conn.cursor()

        # Build the source filter condition
        source_condition, source_params = get_source_filter_sql_condition(source_type)

        if source_type == ScanSourceType.HELM_CHARTS and chart_name:
            source_condition = "AND scan_timestamp IN (SELECT timestamp FROM scan_runs WHERE source_type = ?)"
            source_params = [f"helm-chart:{chart_name}"]

        query = f"""
            SELECT
                UPPER(TRIM(scanner_name)) as scanner_name,
                kind,
                scanner_check_name,
                COUNT(*) as detection_count,
                COUNT(DISTINCT obj_name) as unique_objects,
                COUNT(DISTINCT source_file) as affected_manifests
            FROM scanner_results
            WHERE kind IS NOT NULL AND kind != '' {source_condition}
            GROUP BY UPPER(TRIM(scanner_name)), kind, scanner_check_name
            ORDER BY scanner_name, detection_count DESC
        """

        cursor.execute(query, source_params)
        detection_data = cursor.fetchall()

    if not detection_data:
        st.info(f"No detection pattern data available for {source_display.lower()}.")
        return

    detection_list = []
    for row in detection_data:
        normalized_name = normalize_scanner_name(row["scanner_name"])
        detection_list.append(
            {
                "Scanner": normalized_name,
                "Resource_Type": row["kind"],
                "Check_Name": row["scanner_check_name"],
                "Detection_Count": row["detection_count"],
                "Unique_Objects": row["unique_objects"],
                "Affected_Manifests": row["affected_manifests"],
            }
        )

    detection_df = pd.DataFrame(detection_list)

    detection_df = (
        detection_df.groupby(["Scanner", "Resource_Type", "Check_Name"])
        .agg(
            {
                "Detection_Count": "sum",
                "Unique_Objects": "sum",
                "Affected_Manifests": "sum",
            }
        )
        .reset_index()
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        total_detections = detection_df["Detection_Count"].sum()
        metric_label = f"Total {source_display} Detections"
        st.metric(metric_label, f"{total_detections:,}")

    with col2:
        unique_checks = detection_df["Check_Name"].nunique()
        st.metric("Unique Security Checks", unique_checks)

    with col3:
        resource_types = detection_df["Resource_Type"].nunique()
        st.metric("Resource Types Analyzed", resource_types)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("**📊 Benchmark Resource Coverage Matrix**")

        resource_summary = detection_df.groupby(["Scanner", "Resource_Type"])["Detection_Count"].sum().reset_index()
        resource_pivot = resource_summary.pivot(
            index="Scanner", columns="Resource_Type", values="Detection_Count"
        ).fillna(0)

        if not resource_pivot.empty:
            st.dataframe(resource_pivot, use_container_width=True)

    with col2:
        st.markdown(f"**🎯 Most Detected in {source_display}**")

        resource_totals = (
            detection_df.groupby("Resource_Type")["Detection_Count"].sum().sort_values(ascending=False).head(8)
        )

        for resource_type, count in resource_totals.items():
            scanner_count = detection_df[detection_df["Resource_Type"] == resource_type]["Scanner"].nunique()
            st.markdown(f"• **{resource_type}**: {count:,} findings ({scanner_count} scanners)")

    st.markdown(f"**🔴 Top Security Issues in {source_display}**")

    top_issues = (
        detection_df.groupby("Check_Name")
        .agg(
            {
                "Detection_Count": "sum",
                "Scanner": "nunique",
                "Affected_Manifests": "sum",
            }
        )
        .sort_values("Detection_Count", ascending=False)
        .head(10)
    )

    for check_name, data in top_issues.iterrows():
        count = data["Detection_Count"]
        scanners = data["Scanner"]
        manifests = data["Affected_Manifests"]

        display_name = check_name[:60] + "..." if len(check_name) > 60 else check_name

        st.markdown(
            f"""<div style="padding: 0.5rem; margin: 0.3rem 0; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>{display_name}</strong><br/>
                <small>{count} findings • {scanners} scanner(s) • {manifests} manifest(s)</small>
            </div>""",
            unsafe_allow_html=True,
        )

    if len(detection_df) > 0:
        st.markdown(f"**📈 {source_display} Detection Coverage Visualization**")

        viz_data = detection_df.groupby(["Scanner", "Resource_Type"])["Detection_Count"].sum().reset_index()

        chart = (
            alt.Chart(viz_data)
            .mark_circle(opacity=0.7)
            .encode(
                x=alt.X("Scanner:N", axis=alt.Axis(labelAngle=0)),
                y=alt.Y("Resource_Type:N", title="Kubernetes Resource Type"),
                size=alt.Size(
                    "Detection_Count:Q",
                    scale=alt.Scale(range=[50, 500]),
                    title="Detection Count",
                ),
                color=alt.Color(
                    "Detection_Count:Q",
                    scale=alt.Scale(scheme="viridis"),
                    title="Detection Count",
                ),
                tooltip=["Scanner:N", "Resource_Type:N", "Detection_Count:Q"],
            )
            .properties(
                width=600,
                height=400,
                title=f"{source_display} Detection Matrix (bubble size = detection count)",
            )
        )

        st.altair_chart(chart, use_container_width=True)

    st.markdown(
        f"""
    **💡 Detection Analysis Insights:**
    - **Resource coverage** shows which Kubernetes resources each scanner analyzes in {source_display.lower()}
    - **Detection patterns** reveal scanner strengths and focus areas
    - **Common issues** highlight widespread security problems in {source_display.lower()}
    - **Scanner overlap** indicates consensus on critical security checks
    """
    )


def has_data_for_source_type(unified_service, source_type: ScanSourceType, chart_name: str = None) -> bool:
    """Check if scan data is available for the specified source type.

    :param unified_service: Unified service instance for database operations
    :param source_type: Type of scan source to check
    :param chart_name: Optional chart name for helm chart filtering
    :return: True if data exists for the source type, False otherwise
    """
    try:
        if source_type == ScanSourceType.BENCHMARK:
            scan_runs = unified_service.db.get_scan_runs(source_filter="benchmark")
        elif source_type == ScanSourceType.HELM_CHARTS:
            if chart_name:
                # Single chart filtering - use the chart name as source_type in scan_runs
                scan_runs = unified_service.db.get_scan_runs(
                    source_filter="helm_charts", chart_name=f"helm-chart:{chart_name}"
                )
            else:
                scan_runs = unified_service.db.get_scan_runs(source_filter="helm_charts")
        elif source_type == ScanSourceType.CUSTOM_MANIFESTS:
            scan_runs = unified_service.db.get_scan_runs(source_filter="custom_manifests")
        else:
            scan_runs = unified_service.db.get_scan_runs()

        return len(scan_runs) > 0
    except Exception:
        return False


def show_no_data_message(source_type: ScanSourceType):
    """Display informative message when no scan data is available for the source type.

    :param source_type: The scan source type that has no available data
    :return: None
    """
    source_name = source_type.display_name()
    source_desc = source_type.description()

    if source_type == ScanSourceType.BENCHMARK:
        commands = [
            "kalm-benchmark evaluate --scanner trivy",
            "kalm-benchmark evaluate --scanner checkov",
            "kalm-benchmark evaluate --scanner polaris",
        ]
        command_desc = (
            "These benchmark scans analyze standardized Kubernetes manifests "
            "designed to test specific security misconfigurations."
        )
    elif source_type == ScanSourceType.HELM_CHARTS:
        commands = [
            "kalm-benchmark helm download --chart nginx",
            "kalm-benchmark helm scan --scanner trivy --chart nginx",
            "kalm-benchmark helm scan --scanner checkov --chart nginx",
        ]
        command_desc = "These helm commands download real-world charts and scan them for security issues."
    else:
        commands = [
            "kalm-benchmark scan --scanner trivy --file custom-manifest.yaml",
            "kalm-benchmark scan --scanner checkov --file custom-manifest.yaml",
        ]
        command_desc = "These commands scan custom Kubernetes manifests for security issues."

    st.markdown(
        f"""
        <div style="padding: 3rem; text-align: center; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                    border-radius: 15px; border: 2px dashed #dee2e6; margin: 2rem 0;">
            <h3 style="color: #6c757d; margin-bottom: 1.5rem;">📈 No {source_name} Results Available</h3>
            <p style="color: #495057; font-size: 1.1rem; margin-bottom: 2rem; max-width: 600px; margin-left: auto; margin-right: auto; line-height: 1.6;">
                To see scanner comparison for {source_desc.lower()}, you need to run evaluations first.
            </p>
            <div style="background: #fff; padding: 1.5rem; border-radius: 8px; margin: 1.5rem 0; text-align: left; max-width: 500px; margin-left: auto; margin-right: auto;">
                <h4 style="color: #28a745; margin-bottom: 1rem;">🚀 Quick Start:</h4>
                {"".join([f'<code style="background: #f8f9fa; padding: 0.5rem; border-radius: 4px; display: block; margin-bottom: 0.5rem;">{cmd}</code>' for cmd in commands])}
            </div>
            <p style="color: #6c757d; font-size: 0.9rem;">
                {command_desc}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def show_source_overview(unified_service, source_type: ScanSourceType, chart_name: str = None):
    """Display overview of evaluation results for the selected source type.

    :param unified_service: Unified service instance for database operations
    :param source_type: Type of scan source to analyze
    :param chart_name: Optional chart name for helm chart filtering
    :return: None
    """
    source_display = source_type.display_name()
    if source_type == ScanSourceType.HELM_CHARTS and chart_name:
        source_display += f" - {chart_name}"

    st.subheader(f"🏆 {source_display} Evaluation Results")

    summaries = get_filtered_summaries(unified_service, source_type, chart_name)
    if not summaries:
        st.warning(f"No evaluation summaries available for {source_display.lower()}.")
        return

    perf_df = normalize_and_aggregate_performance_data(summaries)

    # For Helm charts, modify F1 score display to show N/A
    if source_type == ScanSourceType.HELM_CHARTS:
        _render_helm_overview_metrics(perf_df)
        st.info("ℹ️ F1 scores and traditional performance rankings are not applicable to Helm chart scans.")
    else:
        render_performance_overview_metrics(perf_df)
        render_top_performers(perf_df)


def _render_helm_overview_metrics(perf_df: pd.DataFrame):
    """Render overview metrics for Helm charts without F1 scores.

    :param perf_df: Performance DataFrame containing Helm chart metrics
    :return: None
    """
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Scanners Evaluated", len(perf_df), help="Number of scanners with Helm chart evaluation results")

    with col2:
        st.metric("F1 Score", "N/A", help="F1 scores are not applicable to Helm chart scans")

    with col3:
        avg_coverage = perf_df["coverage"].mean() if len(perf_df) > 0 else 0
        st.metric(
            "Avg Coverage",
            f"{avg_coverage * 100:.1f}%",
            help="Average resource and check type coverage across all scanners",
        )

    with col4:
        total_extra = perf_df["extra_checks"].sum() if len(perf_df) > 0 else 0
        st.metric("Total Findings", total_extra, help="Total security findings across all Helm chart scans")


def show_source_performance_comparison(unified_service, source_type: ScanSourceType, chart_name: str = None):
    """Display performance comparison metrics between scanners.

    :param unified_service: Unified service instance for database operations
    :param source_type: Type of scan source to analyze
    :param chart_name: Optional chart name for helm chart filtering
    :return: None
    """
    source_display = source_type.display_name()
    if source_type == ScanSourceType.HELM_CHARTS and chart_name:
        source_display += f" - {chart_name}"

    st.subheader(f"🚀 {source_display} Performance Analysis")

    summaries = get_filtered_summaries(unified_service, source_type, chart_name)
    if not summaries:
        st.info(f"No evaluation summaries available for {source_display.lower()}.")
        return

    perf_df = normalize_and_aggregate_performance_data(summaries)
    if perf_df.empty:
        st.info(f"No performance data available for {source_display.lower()}.")
        return

    # For Helm charts, F1 scores are not meaningful - show N/A instead
    if source_type == ScanSourceType.HELM_CHARTS:
        st.info("ℹ️ F1 scores are not applicable to Helm chart scans as they lack expected results for comparison.")
        return

    _render_performance_visualization(perf_df)
    _render_performance_details(perf_df)
    render_performance_insights()


def _render_performance_visualization(perf_df: pd.DataFrame):
    """Render performance visualization section."""
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**📊 F1 Score vs Coverage Analysis**")
        scatter = create_performance_scatter_chart(perf_df)
        st.altair_chart(scatter, use_container_width=True)

    with col2:
        render_performance_rankings(perf_df)


def _render_performance_details(perf_df: pd.DataFrame):
    """Render detailed performance metrics section."""
    st.markdown("**📋 Detailed Benchmark Metrics**")
    display_df = create_performance_details_table(perf_df)
    st.dataframe(display_df, use_container_width=True, hide_index=True)


def show_source_coverage_analysis(unified_service, source_type: ScanSourceType, chart_name: str = None):
    """Display security check coverage analysis across different categories.

    :param unified_service: Unified service instance for database operations
    :param source_type: Type of scan source to analyze
    :param chart_name: Optional chart name for helm chart filtering
    :return: None
    """
    source_display = source_type.display_name()
    if source_type == ScanSourceType.HELM_CHARTS and chart_name:
        source_display += f" - {chart_name}"

    st.subheader(f"📋 {source_display} Coverage Analysis")

    # Pass source type and chart name for Helm-specific analysis
    # Local import to avoid circular dependency
    from kalm_benchmark.ui.analytics.coverage_utils import fetch_available_coverage_data

    coverage_info = fetch_available_coverage_data(unified_service, source_type=source_type, chart_name=chart_name)

    if coverage_info:
        _render_coverage_data(coverage_info, source_display)
    else:
        render_no_data_message(
            f"No coverage data available for {source_display.lower()}.\
                Run scanner evaluations to see coverage analysis."
        )

    # Only show coverage insights for non-Helm sources (Helm has its own specialized analysis)
    if source_type != ScanSourceType.HELM_CHARTS:
        # Local import to avoid circular dependency
        from kalm_benchmark.ui.analytics.coverage_utils import render_coverage_insights

        render_coverage_insights(source_type)


def _render_coverage_data(coverage_info: dict, source_display: str = "Results"):
    """Render coverage data using appropriate renderer."""
    data = coverage_info["data"]
    coverage_type = coverage_info["type"]

    if coverage_type == "helm_chart_analysis":
        # Local import to avoid circular dependency
        from kalm_benchmark.ui.analytics.coverage_utils import (
            render_helm_chart_analysis,
        )

        render_helm_chart_analysis(data)
    elif coverage_type == "category_coverage":
        # Local import to avoid circular dependency
        from kalm_benchmark.ui.analytics.coverage_utils import (
            render_category_coverage_analysis,
        )

        render_category_coverage_analysis(data)
    elif coverage_type == "basic_coverage":
        # Local import to avoid circular dependency
        from kalm_benchmark.ui.analytics.coverage_utils import (
            render_basic_coverage_analysis,
        )

        chart_title = f"Overall {source_display} Coverage by Scanner"
        render_basic_coverage_analysis(data, chart_title)


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
        # Get all evaluation summaries first
        all_summaries = unified_service.create_evaluation_summary_dataframe()

        if all_summaries is None or len(all_summaries) == 0:
            return []

        if source_type == ScanSourceType.ALL:
            return all_summaries

        # Handle benchmark scans
        if source_type == ScanSourceType.BENCHMARK:
            if hasattr(unified_service, "create_benchmark_evaluation_summary_dataframe"):
                return unified_service.create_benchmark_evaluation_summary_dataframe()
            else:
                return unified_service.db.get_benchmark_evaluation_summaries()

        # Handle helm chart scans
        elif source_type == ScanSourceType.HELM_CHARTS:
            if chart_name:
                scan_runs = unified_service.db.get_scan_runs(
                    source_filter="helm_charts", chart_name=f"helm-chart:{chart_name}"
                )
            else:
                scan_runs = unified_service.db.get_scan_runs(source_filter="helm_charts")

            return _filter_helm_summaries(all_summaries, scan_runs)

        # Handle custom manifest scans
        elif source_type == ScanSourceType.CUSTOM_MANIFESTS:
            scan_runs = unified_service.db.get_scan_runs(source_filter="custom_manifests")
            return _filter_custom_summaries(all_summaries, scan_runs)

        return []
    except Exception as e:
        st.error(f"Error filtering summaries: {e}")
        return []


def fetch_filtered_severity_data(
    unified_service,
    has_ccss_column: bool,
    source_type: ScanSourceType,
    chart_name: str = None,
):
    """Fetch scanner severity data with optional source type filtering.

    :param unified_service: Unified service instance for database operations
    :param has_ccss_column: Whether CCSS scores are available in the database
    :param source_type: Type of scan source to filter by
    :param chart_name: Optional chart name for helm chart filtering
    :return: List of database rows with severity statistics or empty list on error
    """
    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()
            source_condition, source_params = get_source_filter_sql_condition(source_type)

            if source_type == ScanSourceType.HELM_CHARTS and chart_name:
                source_condition = "AND scan_timestamp IN (SELECT timestamp FROM scan_runs WHERE source_type = ?)"
                source_params = [f"helm-chart:{chart_name}"]

            # Build column selection based on CCSS availability
            columns = "UPPER(TRIM(scanner_name)) as scanner_name, severity, COUNT(*) as finding_count"
            if has_ccss_column:
                columns += ", AVG(ccss_score) as avg_ccss_score"

            query = f"""
                SELECT {columns}
                FROM scanner_results
                WHERE severity IS NOT NULL AND severity != '' {source_condition}
                GROUP BY UPPER(TRIM(scanner_name)), severity
                ORDER BY scanner_name, finding_count DESC
            """

            cursor.execute(query, source_params)
            return cursor.fetchall()
    except Exception:
        return []


def show_helm_specific_analysis(unified_service, selected_chart: str = None):
    """Display Helm chart specific security analysis and patterns.

    :param unified_service: Unified service instance for database operations
    :param selected_chart: Optional specific chart name to analyze
    :return: None
    """
    st.subheader("⚓ Helm Chart Specific Analysis")

    if selected_chart:
        render_helm_chart_security_profile(unified_service, selected_chart)
    else:
        tab1, tab2 = st.tabs(["📊 Popularity Analysis", "🏗️ Deployment Patterns"])

        with tab1:
            render_helm_chart_popularity_analysis(unified_service)

        with tab2:
            render_helm_deployment_patterns_analysis(unified_service)


def show_historical_trends_section(unified_service, source_type: ScanSourceType, chart_name: str = None):
    """Display historical trends analysis for scan results over time.

    :param unified_service: Unified service instance for database operations
    :param source_type: Type of scan source to analyze
    :param chart_name: Optional chart name for helm chart filtering
    :return: None
    """
    with st.expander("📈 Historical Trends & Analysis", expanded=False):
        render_historical_scan_trends(unified_service, source_type, chart_name)


def check_ccss_column_exists(unified_service) -> bool:
    """Check if CCSS score column exists in scanner_results table.
    :param unified_service: Unified service instance for database operations
    :return: True if CCSS column exists, False otherwise
    """
    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scanner_results)")
            columns = [row[1] for row in cursor.fetchall()]
            return "ccss_score" in columns
    except Exception:
        return False


if __name__ == "__main__":
    from kalm_benchmark.ui.interface.gen_utils import init

    init()
    show()
