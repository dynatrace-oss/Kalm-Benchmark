import altair as alt
import pandas as pd
import streamlit as st
from loguru import logger

from kalm_benchmark.ui.analytics.helm_analytics import (
    render_helm_chart_popularity_analysis,
    render_helm_chart_security_profile,
    render_helm_deployment_patterns_analysis,
)
from kalm_benchmark.ui.interface.gen_utils import get_unified_service


def get_helm_scanner_comparison_data(chart_name: str | None = None) -> pd.DataFrame:
    """Retrieve and process scanner comparison data for Helm chart analysis.

    :param chart_name: Optional specific chart name to filter by
    :return: DataFrame containing scanner performance metrics and findings data
    """
    unified_service = get_unified_service()

    try:
        all_helm_runs = _fetch_helm_scan_runs(unified_service, chart_name)
        if not all_helm_runs:
            return pd.DataFrame()

        comparison_data = _process_scan_runs(unified_service, all_helm_runs)
        return pd.DataFrame(comparison_data) if comparison_data else pd.DataFrame()

    except Exception as e:
        logger.error(f"Error fetching helm scanner comparison data: {e}")
        return pd.DataFrame()


def _fetch_helm_scan_runs(unified_service, chart_name: str | None) -> list:
    """Fetch and filter Helm chart scan runs.

    :param unified_service: Database service instance
    :param chart_name: Optional chart name to filter by
    :return: List of filtered scan runs
    """
    all_helm_runs = unified_service.db.get_scan_runs(source_filter="helm_charts", limit=200)

    if not all_helm_runs:
        logger.warning("No helm chart scan runs found in database")
        return []

    logger.info(f"Found {len(all_helm_runs)} helm chart scan runs")

    if not chart_name:
        return all_helm_runs

    filtered_runs = []
    for run in all_helm_runs:
        source_type = run.get("source_type", "")
        run_chart_name = _extract_chart_name_from_source(source_type)

        if run_chart_name.lower() == chart_name.lower():
            filtered_runs.append(run)

    logger.info(f"Found {len(filtered_runs)} helm-related scan runs")
    return filtered_runs


def _process_scan_runs(unified_service, helm_scan_runs: list) -> list:
    """Process scan runs and generate comparison data"""
    comparison_data = []

    for run in helm_scan_runs:
        try:
            results = unified_service.db.load_scanner_results(scanner_name=run["scanner_name"], scan_run_id=run["id"])

            if not results:
                continue

            metrics = _calculate_scanner_metrics(results)
            run_chart_name = _extract_chart_name(run.get("source_type", ""))

            comparison_entry = {
                "scanner_name": run["scanner_name"],
                "chart_name": run_chart_name,
                "timestamp": run["timestamp"],
                "scan_id": run["id"],
                **metrics,
            }
            comparison_data.append(comparison_entry)

        except Exception as e:
            logger.warning(f"Error processing helm scan run {run.get('id', 'unknown')}: {e}")
            continue

    logger.info(f"Created {len(comparison_data)} comparison entries")
    return comparison_data


def _calculate_scanner_metrics(results) -> dict:
    """Calculate metrics for scanner results"""
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    unique_categories = set()

    for result in results:
        severity = _normalize_severity(result.severity)
        severity_counts[severity] += 1

        if result.scanner_check_name:
            category = _categorize_check(result.scanner_check_name.lower())
            unique_categories.add(category)

    detection_consistency = _calculate_consistency(unique_categories, len(results))

    return {
        "total_findings": len(results),
        "high_severity": severity_counts["HIGH"],
        "medium_severity": severity_counts["MEDIUM"],
        "low_severity": severity_counts["LOW"],
        "categories_found": len(unique_categories),
        "detection_consistency": detection_consistency,
    }


def _normalize_severity(severity: str | None) -> str:
    """Normalize severity values to standard categories"""
    if not severity:
        return "INFO"

    severity_upper = severity.upper()

    if severity_upper in ["HIGH", "MEDIUM", "LOW", "INFO"]:
        return severity_upper
    elif severity_upper in ["CRITICAL", "DANGER"]:
        return "HIGH"
    elif severity_upper == "WARNING":
        return "MEDIUM"
    else:
        return "INFO"


def _categorize_check(check_name: str) -> str:
    """Categorize security check by name."""
    category_keywords = {
        "RBAC": ["rbac", "role", "permission"],
        "Network": ["network", "ingress", "egress"],
        "Pod Security": ["pod", "container", "security"],
        "Resources": ["resource", "limit", "request"],
    }

    for category, keywords in category_keywords.items():
        if any(keyword in check_name for keyword in keywords):
            return category

    return "Other"


def _calculate_consistency(unique_categories: set, total_findings: int) -> float:
    """Calculate detection consistency score."""
    consistency = (len(unique_categories) * 10 + min(50, total_findings)) / 100
    return min(1.0, consistency)


def _extract_chart_name_from_source(source_type: str) -> str:
    """Extract chart name from source type for filtering."""
    if not source_type or not source_type.startswith("helm-chart:"):
        return "unknown"

    return source_type.split("helm-chart:")[1]


def _extract_chart_name(source_type: str) -> str:
    """Extract Helm chart name from database source_type field."""
    if not source_type:
        return "unknown"

    if source_type.startswith("helm-chart:"):
        # Format: "helm-chart:nginx" or "helm-chart:path/to/nginx"
        chart_part = source_type.split("helm-chart:")[1]
        if "/" in chart_part:
            return chart_part.split("/")[-1]  # Get last part
        return chart_part

    return "unknown"


def get_available_helm_charts() -> list[str]:
    """Retrieve list of all Helm charts that have scanner data available.

    :return: Sorted list of Helm chart names that have been scanned
    """
    unified_service = get_unified_service()

    try:
        helm_scan_runs = unified_service.db.get_scan_runs(
            source_filter="helm_charts", limit=500  # Higher limit to capture all helm charts
        )
        charts = set()

        for run in helm_scan_runs:
            source_type = run.get("source_type", "")

            if source_type.startswith("helm-chart:"):
                # Format: "helm-chart:chart-name"
                chart_name = source_type.split("helm-chart:")[1]
                if chart_name:
                    charts.add(chart_name)

        return sorted((charts))

    except Exception as e:
        logger.error(f"Error getting available helm charts: {e}")
        return []


def show():
    """Display the main Helm scanner analysis page with comprehensive comparison tools.

    :return: None
    """
    _render_page_header()

    available_charts = get_available_helm_charts()
    if not available_charts:
        _show_no_data_message()
        return

    chart_filter = _render_chart_selection(available_charts)
    scanner_data = get_helm_scanner_comparison_data(chart_filter)

    if scanner_data.empty:
        _show_no_scanner_data_message(chart_filter)
        return

    _render_summary_metrics(scanner_data)
    _render_scanner_comparison(scanner_data)
    _render_detailed_comparison_table(scanner_data)
    _render_finding_overlap_analysis(scanner_data)
    _render_security_dashboard(scanner_data, chart_filter)
    _render_help_section()


def _render_page_header():
    """Render the main page header with styling."""
    st.markdown(
        """
        <div style="text-align: center; padding: 3.5rem 0 2.5rem 0;
                    background: linear-gradient(135deg, #55efc4 0%, #00cec9 25%,
                    #74b9ff 50%, #6c5ce7 75%, #55efc4 100%);
                    border-radius: 20px; margin-bottom: 2rem;
                    box-shadow: 0 15px 40px rgba(85, 239, 196, 0.5);
                    position: relative; overflow: hidden;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0;
                        background: radial-gradient(circle at 15% 25%, rgba(108, 92, 231, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 85% 75%, rgba(116, 185, 255, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 50% 15%, rgba(0, 206, 201, 0.3) 0%, transparent 45%);
                        pointer-events: none;"></div>
            <div style="max-width: 800px; margin: 0 auto; padding: 0 2rem; position: relative; z-index: 1;">
                <h1 style="color: #FFFFFF; margin-bottom: 0.5rem; font-size: 3.2rem; font-weight: 800;
                           text-shadow: 0 4px 15px rgba(0,0,0,0.4); letter-spacing: -0.02em;">
                    🔍 Scanner Analysis
                </h1>
                <h3 style="color: rgba(255,255,255,0.95); font-weight: 500; margin-bottom: 1.5rem;
                          font-size: 1.6rem; text-shadow: 0 2px 8px rgba(0,0,0,0.3);">
                    Helm Chart Scanner Performance
                </h3>
                <p style="color: rgba(255,255,255,0.9); font-size: 1.1rem; line-height: 1.5;
                         text-shadow: 0 1px 4px rgba(0,0,0,0.2); max-width: 600px; margin: 0 auto;">
                    Compare how different security scanners perform on your Helm charts
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _show_no_data_message():
    """Show message when no Helm chart data is available."""
    st.warning("⚓ **No Helm chart scan data available**")
    st.markdown(
        """
        **To enable scanner analysis on Helm charts:**

        1. **Scan Helm charts with multiple scanners**:
           ```bash
           poetry run cli scan kubescape --helm-chart nginx
           poetry run cli scan trivy --helm-chart nginx
           poetry run cli scan kics --helm-chart nginx
           ```

        2. **Or scan chart directories**:
           ```bash
           poetry run cli scan <scanner> -f /path/to/helm/charts
           ```

        3. **Results will appear here** for scanner comparison
        """
    )


def _render_chart_selection(available_charts: list[str]) -> str | None:
    """Render chart selection interface"""
    st.subheader("🎯 Analysis Scope")
    col1, col2 = st.columns([2, 1])

    with col1:
        selected_chart = st.selectbox(
            "Select Helm Chart to analyze:",
            options=["All Charts"] + available_charts,
            help="Choose a specific chart or analyze all charts together",
        )

    chart_filter = None if selected_chart == "All Charts" else selected_chart

    with col2:
        chart_count = len(available_charts) if selected_chart == "All Charts" else 1
        st.info(
            f"📊 **Analysis Scope**: {chart_count} chart(s)\
                \n\nComparing scanner effectiveness on Helm chart security analysis."
        )

    return chart_filter


def _show_no_scanner_data_message(chart_filter: str | None):
    """Show message when no scanner data is available"""
    if chart_filter:
        st.warning(f"🔍 **No scanner data for chart '{chart_filter}'**")
    else:
        st.warning("🔍 **No scanner comparison data available**")


def _render_summary_metrics(scanner_data: pd.DataFrame):
    """Render summary metrics section"""
    st.markdown("---")
    col1, col2, col3, col4 = st.columns(4)

    unique_scanners = scanner_data["scanner_name"].nunique()
    total_scans = len(scanner_data)
    avg_findings = scanner_data["total_findings"].mean()
    total_high_severity = scanner_data["high_severity"].sum()

    with col1:
        st.metric("🔍 Scanners", unique_scanners, help="Number of different scanners that have analyzed the chart(s)")
    with col2:
        st.metric("🔄 Total Scans", total_scans, help="Total number of scans performed across all scanners")
    with col3:
        st.metric("📊 Avg Findings", f"{avg_findings:.1f}", help="Average number of findings per scan")
    with col4:
        st.metric(
            "🚨 High Risk Total",
            int(total_high_severity),
            help="Total high/critical severity findings across all scanners",
        )


def _render_scanner_comparison(scanner_data: pd.DataFrame):
    """Render scanner performance comparison section"""
    st.markdown("---")
    st.subheader("⚖️ Scanner Performance Comparison")

    unique_scanners = scanner_data["scanner_name"].nunique()

    if unique_scanners >= 2:
        _render_multi_scanner_comparison(scanner_data)
    else:
        _render_single_scanner_info(scanner_data)


def _render_multi_scanner_comparison(scanner_data: pd.DataFrame):
    """Render comparison for multiple scanners"""
    col1, col2 = st.columns([2, 1])

    with col1:
        _render_effectiveness_chart(scanner_data)

    with col2:
        _render_scanner_rankings(scanner_data)


def _render_effectiveness_chart(scanner_data: pd.DataFrame):
    """Render scanner effectiveness scatter plot"""
    scanner_summary = (
        scanner_data.groupby("scanner_name")
        .agg({"total_findings": "sum", "categories_found": "sum", "detection_consistency": "mean"})
        .reset_index()
    )

    effectiveness_chart = (
        alt.Chart(scanner_summary)
        .mark_circle(size=150, opacity=0.8)
        .add_selection(alt.selection_single())
        .encode(
            x=alt.X("categories_found:Q", title="Security Categories Covered"),
            y=alt.Y("total_findings:Q", title="Total Findings"),
            color=alt.Color("scanner_name:N", legend=alt.Legend(title="Scanner")),
            size=alt.Size(
                "detection_consistency:Q",
                scale=alt.Scale(range=[100, 400]),
                legend=alt.Legend(title="Consistency"),
            ),
            tooltip=["scanner_name:N", "total_findings:Q", "categories_found:Q", "detection_consistency:Q"],
        )
        .properties(
            width=500,
            height=350,
            title="Scanner Effectiveness: Findings vs Categories (bubble size = consistency)",
        )
    )

    st.altair_chart(effectiveness_chart, use_container_width=True)


def _render_scanner_rankings(scanner_data: pd.DataFrame):
    """Render scanner rankings by different criteria"""
    st.subheader("🏆 Scanner Rankings")

    scanner_summary = (
        scanner_data.groupby("scanner_name")
        .agg({"total_findings": "sum", "categories_found": "sum", "detection_consistency": "mean"})
        .reset_index()
    )

    ranking_tabs = st.tabs(["🔍 Total Findings", "📊 Categories", "🎯 High Severity"])

    with ranking_tabs[0]:
        _render_findings_ranking(scanner_summary)
    with ranking_tabs[1]:
        _render_categories_ranking(scanner_summary)
    with ranking_tabs[2]:
        _render_high_severity_ranking(scanner_data)


def _render_findings_ranking(scanner_summary: pd.DataFrame):
    """Render rankings by total findings"""
    findings_ranking = scanner_summary.sort_values("total_findings", ascending=False)
    for idx, row in findings_ranking.iterrows():
        rank = ["🥇", "🥈", "🥉"][idx] if idx < 3 else f"{idx+1}."
        st.markdown(f"**{rank} {row['scanner_name'].title()}**  \n{int(row['total_findings'])} findings")


def _render_categories_ranking(scanner_summary: pd.DataFrame):
    """Render rankings by categories found"""
    categories_ranking = scanner_summary.sort_values("categories_found", ascending=False)
    for idx, row in categories_ranking.iterrows():
        rank = ["🥇", "🥈", "🥉"][idx] if idx < 3 else f"{idx+1}."
        st.markdown(f"**{rank} {row['scanner_name'].title()}**  \n{int(row['categories_found'])} categories")


def _render_high_severity_ranking(scanner_data: pd.DataFrame):
    """Render rankings by high severity findings"""
    high_sev_ranking = scanner_data.groupby("scanner_name")["high_severity"].sum().sort_values(ascending=False)
    for idx, (scanner, count) in enumerate(high_sev_ranking.items()):
        rank = ["🥇", "🥈", "🥉"][idx] if idx < 3 else f"{idx+1}."
        st.markdown(f"**{rank} {scanner.title()}**  \n{int(count)} high severity")


def _render_single_scanner_info(scanner_data: pd.DataFrame):
    """Render information for single scanner scenario"""
    st.info("📊 Need at least 2 scanners for comparison visualization")

    if len(scanner_data) >= 1:
        scanner_row = scanner_data.iloc[0]
        st.markdown(
            f"""
        **Current Scanner: {scanner_row['scanner_name'].title()}**
        - Total Findings: {scanner_row['total_findings']}
        - High Severity: {scanner_row['high_severity']}
        - Categories: {scanner_row['categories_found']}
        - Consistency: {scanner_row['detection_consistency']:.2f}
        """
        )


def _render_detailed_comparison_table(scanner_data: pd.DataFrame):
    """Render detailed scanner comparison table"""
    st.markdown("---")
    st.subheader("📋 Detailed Scanner Comparison")

    detailed_summary = (
        scanner_data.groupby("scanner_name")
        .agg(
            {
                "total_findings": "sum",
                "high_severity": "sum",
                "medium_severity": "sum",
                "low_severity": "sum",
                "categories_found": "sum",
                "detection_consistency": "mean",
                "chart_name": "nunique",
            }
        )
        .round(2)
    )

    detailed_summary.columns = [
        "Total Findings",
        "High Severity",
        "Medium Severity",
        "Low Severity",
        "Categories",
        "Consistency",
        "Charts Scanned",
    ]
    detailed_summary = detailed_summary.sort_values("Total Findings", ascending=False)

    st.dataframe(
        detailed_summary,
        use_container_width=True,
        column_config={
            "Total Findings": st.column_config.NumberColumn(format="%d"),
            "High Severity": st.column_config.NumberColumn(format="%d"),
            "Medium Severity": st.column_config.NumberColumn(format="%d"),
            "Low Severity": st.column_config.NumberColumn(format="%d"),
            "Categories": st.column_config.NumberColumn(format="%d"),
            "Consistency": st.column_config.NumberColumn(format="%.2f"),
            "Charts Scanned": st.column_config.NumberColumn(format="%d"),
        },
    )


def _render_finding_overlap_analysis(scanner_data: pd.DataFrame):
    """Render finding overlap analysis section"""
    unique_scanners = scanner_data["scanner_name"].nunique()

    if unique_scanners >= 2:
        st.markdown("---")
        st.subheader("🔄 Finding Overlap Analysis")

        with st.expander("📊 Cross-Scanner Analysis", expanded=False):
            _render_severity_distribution_chart(scanner_data)


def _render_severity_distribution_chart(scanner_data: pd.DataFrame):
    """Render severity distribution chart"""
    severity_data = scanner_data.melt(
        id_vars=["scanner_name"],
        value_vars=["high_severity", "medium_severity", "low_severity"],
        var_name="severity_level",
        value_name="count",
    )

    severity_data["severity_level"] = severity_data["severity_level"].str.replace("_severity", "").str.title()

    overlap_chart = (
        alt.Chart(severity_data)
        .mark_bar()
        .encode(
            x=alt.X("scanner_name:N", title="Scanner"),
            y=alt.Y("count:Q", title="Number of Findings"),
            color=alt.Color(
                "severity_level:N",
                scale=alt.Scale(domain=["High", "Medium", "Low"], range=["#e74c3c", "#f39c12", "#f1c40f"]),
                legend=alt.Legend(title="Severity Level"),
            ),
            tooltip=["scanner_name:N", "severity_level:N", "count:Q"],
        )
        .properties(height=300, title="Finding & Severity Distribution by Scanner")
    )

    st.altair_chart(overlap_chart, use_container_width=True)


def _render_security_dashboard(scanner_data: pd.DataFrame, chart_filter: str | None):
    """Render security dashboard integration"""
    if not scanner_data.empty:
        st.markdown("---")
        st.subheader("📊 Chart Security Dashboard")

        with st.expander("🛡️ Security Analytics & Insights", expanded=False):
            _render_analytics_tabs(scanner_data, chart_filter)


def _render_analytics_tabs(scanner_data: pd.DataFrame, chart_filter: str | None):
    """Render analytics tabs"""
    analytics_tab1, analytics_tab2, analytics_tab3 = st.tabs(
        ["📈 Popular Charts", "🔍 Security Profiles", "📋 Deployment Patterns"]
    )

    unified_service = get_unified_service()

    with analytics_tab1:
        render_helm_chart_popularity_analysis(unified_service)

    with analytics_tab2:
        _render_security_profiles_tab(scanner_data, chart_filter, unified_service)

    with analytics_tab3:
        render_helm_deployment_patterns_analysis(unified_service)


def _render_security_profiles_tab(scanner_data: pd.DataFrame, chart_filter: str | None, unified_service):
    """Render security profiles tab content."""
    if chart_filter:
        render_helm_chart_security_profile(unified_service, chart_filter)
    else:
        unique_charts = scanner_data["chart_name"].unique()
        if len(unique_charts) > 0:
            selected_profile_chart = st.selectbox("Select chart for security profile:", unique_charts)
            if selected_profile_chart and selected_profile_chart != "unknown":
                render_helm_chart_security_profile(unified_service, selected_profile_chart)
        else:
            st.info("No valid chart data available for security profiles.")


def _render_help_section():
    """Render help section with usage information."""
    with st.expander("❓ Understanding Scanner Analysis", expanded=False):
        st.markdown(
            """
        **Scanner Analysis** compares how different security scanners perform on your Helm charts.

        **Key Metrics:**
        - **Total Findings**: Number of security issues detected by each scanner
        - **Categories**: Different types of security checks covered (RBAC, Network, Pod Security, etc.)
        - **Detection Consistency**: How consistently scanners find issues across different areas
        - **High Severity**: Critical and high-priority security findings

        **Interpreting Results:**
        - **High findings + High categories**: Comprehensive security coverage
        - **High findings + Low categories**: Deep but narrow focus area
        - **Low findings + High categories**: Broad but potentially shallow coverage
        - **High consistency**: Scanner provides reliable, balanced detection

        **Security Dashboard Features:**
        - **Popular Charts**: Analysis of most commonly scanned Helm charts
        - **Security Profiles**: Detailed security posture for individual charts
        - **Deployment Patterns**: Common deployment security patterns and issues

        **Best Practices:**
        - Use multiple scanners for comprehensive coverage
        - Focus on scanners that find high-severity issues
        - Consider consistency for reliable CI/CD integration
        - Balance thoroughness with false positive management
        """
        )


# Entry point for the page
if __name__ == "__main__":
    show()
