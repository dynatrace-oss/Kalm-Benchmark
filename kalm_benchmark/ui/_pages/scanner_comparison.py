from typing import Dict, Optional

import altair as alt
import pandas as pd
import streamlit as st

try:
    from kalm_benchmark.evaluation.ccss.ccss_converter import CCSSConverter
except ImportError:
    # Fallback until CCSS module is available
    class CCSSConverter:
        @staticmethod
        def _severity_to_score(severity: str) -> Optional[float]:
            """Fallback severity to score mapping"""
            severity_map = {
                "CRITICAL": 9.0,
                "HIGH": 7.0,
                "DANGER": 7.0,  # Polaris high severity
                "MEDIUM": 4.0,
                "WARNING": 2.5,  # Polaris medium-low severity
                "LOW": 2.0,
                "INFO": 1.0,
            }
            return severity_map.get(severity.upper())


from kalm_benchmark.ui.components import (
    render_insights_section,
    render_no_data_message,
    render_scanner_metrics,
    render_scanner_pie_charts,
    render_severity_summary_table,
)
from kalm_benchmark.ui.data_processing import (
    calculate_severity_percentages,
    fetch_severity_data,
    normalize_severity_dataframe,
)
from kalm_benchmark.ui.utils.chart_utils import create_severity_bar_chart
from kalm_benchmark.ui.utils.coverage_utils import (
    fetch_available_coverage_data,
    render_basic_coverage_analysis,
    render_category_coverage_analysis,
    render_coverage_insights,
)

# SCANNERS import removed - now handled in utility modules
from kalm_benchmark.ui.utils.gen_utils import get_unified_service
from kalm_benchmark.ui.utils.performance_utils import (
    create_performance_details_table,
    create_performance_scatter_chart,
    normalize_and_aggregate_performance_data,
    render_performance_insights,
    render_performance_overview_metrics,
    render_performance_rankings,
    render_top_performers,
)


def show():
    """Show the scanner comparison page focused on benchmark results comparison"""

    # Scanner Comparison Header - Using same color scheme as other pages
    st.markdown(
        """
        <div style="text-align: center; padding: 3.5rem 0 2.5rem 0; 
                    background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 20%, #74b9ff 40%, #00cec9 60%, #55efc4 80%, #6c5ce7 100%); 
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
                    Benchmark Results Comparison
                </h3>
                <p style="color: rgba(255,255,255,0.9); max-width: 650px; margin: 0 auto; 
                         line-height: 1.7; font-size: 1.15rem; text-shadow: 0 2px 6px rgba(0,0,0,0.25);">
                    Compare security scanners based on their performance against the Kalm benchmark manifests. 
                    Analyze detection accuracy, coverage rates, and scoring alignment across standardized test cases.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Get benchmark data for comparison
    unified_service = get_unified_service()

    # Check if we have benchmark evaluation results
    if not has_benchmark_results(unified_service):
        show_no_benchmark_data_message()
        return

    try:
        show_benchmark_overview(unified_service)

        st.divider()

        show_benchmark_performance_comparison(unified_service)

        st.divider()

        show_benchmark_coverage_analysis(unified_service)

        st.divider()

        show_benchmark_severity_comparison(unified_service)

        st.divider()

        show_benchmark_detection_analysis(unified_service)

    except Exception as e:
        st.error(f"An error occurred while loading benchmark comparison data: {str(e)}")
        st.info("Please ensure you have run benchmark evaluations and the database is properly configured.")


def show_benchmark_severity_comparison(unified_service):
    """Show severity scoring comparison for benchmark results.

    Refactored to use utility functions and reduce cognitive complexity.
    """
    st.subheader("⚖️ Benchmark Severity Analysis")

    has_ccss_column = check_ccss_column_exists(unified_service)
    severity_data = fetch_severity_data(unified_service, has_ccss_column)

    if not severity_data:
        render_no_data_message("No severity scoring data available from benchmark scans.")
        return

    severity_df = normalize_severity_dataframe(severity_data, has_ccss_column)

    _render_severity_overview(severity_df)
    _render_severity_visualizations(severity_df)
    _render_severity_insights(has_ccss_column)


def _render_severity_overview(severity_df: pd.DataFrame):
    """Render the severity overview section."""
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**📊 Benchmark Severity Distribution**")
        render_severity_summary_table(severity_df)

    with col2:
        st.markdown("**🎯 Benchmark Scoring Patterns**")
        scanner_patterns = severity_df.groupby("Scanner").agg({"Count": "sum", "Severity": "nunique"}).reset_index()
        render_scanner_metrics(scanner_patterns)


def _render_severity_visualizations(severity_df: pd.DataFrame):
    """Render the severity visualization tabs."""
    if len(severity_df) == 0:
        return

    st.markdown("**📈 Benchmark Severity Distribution Analysis**")

    # Create tabs for different visualization approaches
    viz_tab1, viz_tab2 = st.tabs(["🥧 Severity Distribution", "📊 Finding Counts"])

    with viz_tab1:
        st.markdown("**Severity Distribution by Scanner (Pie Charts)**")
        severity_pct_df = calculate_severity_percentages(severity_df)
        render_scanner_pie_charts(severity_pct_df)
        st.info(
            "💡 Pie charts show the relative severity distribution within each scanner, making it easy to compare severity patterns and see which scanners focus on different types of issues."
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
        "💡 This view shows absolute counts, making it easy to see which scanners find more issues overall and compare finding volumes across different severity levels."
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


def show_benchmark_detection_analysis(unified_service):
    """Show analysis of what types of issues different scanners detect in benchmark manifests"""
    st.subheader("🔍 Benchmark Detection Analysis")

    with unified_service.db._get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT 
                UPPER(TRIM(scanner_name)) as scanner_name,
                kind,
                scanner_check_name,
                COUNT(*) as detection_count,
                COUNT(DISTINCT obj_name) as unique_objects,
                COUNT(DISTINCT source_file) as affected_manifests
            FROM scanner_results 
            WHERE kind IS NOT NULL AND kind != ''
            GROUP BY UPPER(TRIM(scanner_name)), kind, scanner_check_name
            ORDER BY scanner_name, detection_count DESC
        """
        )

        detection_data = cursor.fetchall()

    if not detection_data:
        st.info("No benchmark detection pattern data available.")
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
        .agg({"Detection_Count": "sum", "Unique_Objects": "sum", "Affected_Manifests": "sum"})
        .reset_index()
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        total_detections = detection_df["Detection_Count"].sum()
        st.metric("Total Benchmark Detections", f"{total_detections:,}")

    with col2:
        unique_checks = detection_df["Check_Name"].nunique()
        st.metric("Unique Security Checks", unique_checks)

    with col3:
        resource_types = detection_df["Resource_Type"].nunique()
        st.metric("Resource Types Analyzed", resource_types)

    # Create resource type analysis
    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("**📊 Benchmark Resource Coverage Matrix**")

        # Create pivot table for resource type coverage
        resource_summary = detection_df.groupby(["Scanner", "Resource_Type"])["Detection_Count"].sum().reset_index()
        resource_pivot = resource_summary.pivot(
            index="Scanner", columns="Resource_Type", values="Detection_Count"
        ).fillna(0)

        if not resource_pivot.empty:
            st.dataframe(resource_pivot, use_container_width=True)

    with col2:
        st.markdown("**🎯 Most Detected Resource Types**")

        resource_totals = (
            detection_df.groupby("Resource_Type")["Detection_Count"].sum().sort_values(ascending=False).head(8)
        )

        for resource_type, count in resource_totals.items():
            scanner_count = detection_df[detection_df["Resource_Type"] == resource_type]["Scanner"].nunique()
            st.markdown(f"• **{resource_type}**: {count:,} findings ({scanner_count} scanners)")

    st.markdown("**🔴 Top Security Issues in Benchmark**")

    top_issues = (
        detection_df.groupby("Check_Name")
        .agg({"Detection_Count": "sum", "Scanner": "nunique", "Affected_Manifests": "sum"})
        .sort_values("Detection_Count", ascending=False)
        .head(10)
    )

    for check_name, data in top_issues.iterrows():
        count = data["Detection_Count"]
        scanners = data["Scanner"]
        manifests = data["Affected_Manifests"]

        # Truncate long check names
        display_name = check_name[:60] + "..." if len(check_name) > 60 else check_name

        st.markdown(
            f"""<div style="padding: 0.5rem; margin: 0.3rem 0; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                <strong>{display_name}</strong><br/>
                <small>{count} findings • {scanners} scanner(s) • {manifests} manifest(s)</small>
            </div>""",
            unsafe_allow_html=True,
        )

    if len(detection_df) > 0:
        st.markdown("**📈 Benchmark Detection Coverage Visualization**")

        # Aggregate by scanner and resource type for cleaner visualization
        viz_data = detection_df.groupby(["Scanner", "Resource_Type"])["Detection_Count"].sum().reset_index()

        chart = (
            alt.Chart(viz_data)
            .mark_circle(opacity=0.7)
            .encode(
                x=alt.X("Scanner:N", axis=alt.Axis(labelAngle=0)),
                y=alt.Y("Resource_Type:N", title="Kubernetes Resource Type"),
                size=alt.Size("Detection_Count:Q", scale=alt.Scale(range=[50, 500]), title="Detection Count"),
                color=alt.Color("Detection_Count:Q", scale=alt.Scale(scheme="viridis"), title="Detection Count"),
                tooltip=["Scanner:N", "Resource_Type:N", "Detection_Count:Q"],
            )
            .properties(width=600, height=400, title="Benchmark Detection Matrix (bubble size = detection count)")
        )

        st.altair_chart(chart, use_container_width=True)

    st.markdown(
        """
    **💡 Detection Analysis Insights:**
    - **Resource coverage** shows which Kubernetes resources each scanner analyzes
    - **Detection patterns** reveal scanner strengths and focus areas
    - **Common issues** highlight widespread security problems in the benchmark
    - **Scanner overlap** indicates consensus on critical security checks
    """
    )


def has_benchmark_results(unified_service) -> bool:
    """Check if we have benchmark evaluation results available"""
    try:
        summaries = unified_service.create_evaluation_summary_dataframe()
        return len(summaries) > 0
    except Exception:
        return False


def show_no_benchmark_data_message():
    """Show message when no benchmark data is available"""
    st.markdown(
        """
        <div style="padding: 3rem; text-align: center; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); 
                    border-radius: 15px; border: 2px dashed #dee2e6; margin: 2rem 0;">
            <h3 style="color: #6c757d; margin-bottom: 1.5rem;">📈 No Benchmark Results Available</h3>
            <p style="color: #495057; font-size: 1.1rem; margin-bottom: 2rem; max-width: 600px; margin-left: auto; margin-right: auto; line-height: 1.6;">
                To see scanner comparison based on benchmark results, you need to run evaluations against the Kalm benchmark manifests first.
            </p>
            <div style="background: #fff; padding: 1.5rem; border-radius: 8px; margin: 1.5rem 0; text-align: left; max-width: 500px; margin-left: auto; margin-right: auto;">
                <h4 style="color: #28a745; margin-bottom: 1rem;">🚀 Quick Start:</h4>
                <code style="background: #f8f9fa; padding: 0.5rem; border-radius: 4px; display: block; margin-bottom: 0.5rem;">kalm-benchmark evaluate --scanner trivy</code>
                <code style="background: #f8f9fa; padding: 0.5rem; border-radius: 4px; display: block; margin-bottom: 0.5rem;">kalm-benchmark evaluate --scanner checkov</code>
                <code style="background: #f8f9fa; padding: 0.5rem; border-radius: 4px; display: block;">kalm-benchmark evaluate --scanner polaris</code>
            </div>
            <p style="color: #6c757d; font-size: 0.9rem;">
                These benchmark scans analyze standardized Kubernetes manifests designed to test specific security misconfigurations.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def show_benchmark_overview(unified_service):
    """Show overview of benchmark evaluation results.

    Refactored to use utility functions and reduce complexity.
    """
    st.subheader("🏆 Benchmark Evaluation Results")

    summaries = unified_service.create_evaluation_summary_dataframe()
    if not summaries:
        st.warning("No evaluation summaries available.")
        return

    perf_df = normalize_and_aggregate_performance_data(summaries)

    render_performance_overview_metrics(perf_df)
    render_top_performers(perf_df)


def show_benchmark_performance_comparison(unified_service):
    """Show benchmark performance comparison between scanners.

    Refactored to use utility functions and reduce cognitive complexity.
    """
    st.subheader("🚀 Benchmark Performance Analysis")

    summaries = unified_service.create_evaluation_summary_dataframe()
    if not summaries:
        st.info("No benchmark evaluation summaries available.")
        return

    perf_df = normalize_and_aggregate_performance_data(summaries)
    if perf_df.empty:
        st.info("No benchmark performance data available.")
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


def show_benchmark_coverage_analysis(unified_service):
    """Show benchmark check coverage analysis across different security categories.

    Refactored to use utility functions and reduce cognitive complexity.
    """
    st.subheader("📋 Benchmark Coverage Analysis")

    coverage_info = fetch_available_coverage_data(unified_service)

    if coverage_info:
        _render_coverage_data(coverage_info)
    else:
        render_no_data_message("No coverage data available. Run benchmark evaluations to see coverage analysis.")

    render_coverage_insights()


def _render_coverage_data(coverage_info: Dict):
    """Render coverage data using appropriate renderer."""
    data = coverage_info["data"]
    coverage_type = coverage_info["type"]

    if coverage_type == "category_coverage":
        render_category_coverage_analysis(data)
    elif coverage_type == "basic_coverage":
        render_basic_coverage_analysis(data)


def normalize_scanner_name(scanner_name: str) -> str:
    """Normalize scanner names to match the SCANNERS registry"""
    if not scanner_name:
        return scanner_name

    name = scanner_name.strip()

    # Handle common variations
    name_mappings = {
        "KICS": "KICS",
        "kics": "KICS",
        "CHECKOV": "Checkov",
        "checkov": "Checkov",
        "TRIVY": "trivy",
        "Trivy": "trivy",
        "POLARIS": "polaris",
        "Polaris": "polaris",
        "polaris": "polaris",
        "KUBESCAPE": "Kubescape",
        "kubescape": "Kubescape",
        "SNYK": "Snyk",
        "snyk": "Snyk",
        "KUBE-SCORE": "kube-score",
        "kube-score": "kube-score",
        "KUBELINTER": "KubeLinter",
        "kubelinter": "KubeLinter",
        "KUBE-BENCH": "kube-bench",
        "kube-bench": "kube-bench",
    }

    return name_mappings.get(name, name)


def check_ccss_column_exists(unified_service) -> bool:
    """Check if ccss_score column exists in the database"""
    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scanner_results)")
            columns = [row[1] for row in cursor.fetchall()]
            return "ccss_score" in columns
    except Exception:
        return False


if __name__ == "__main__":
    from kalm_benchmark.ui.utils.gen_utils import init

    init()
    show()
