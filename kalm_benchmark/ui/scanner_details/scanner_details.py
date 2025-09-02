from pathlib import Path

import streamlit as st

from kalm_benchmark.evaluation.evaluation import Metric
from kalm_benchmark.evaluation.scanner_manager import SCANNERS
from kalm_benchmark.ui.analytics.historical_analysis import (
    render_historical_scan_trends,
    render_scanner_performance_trends,
)
from kalm_benchmark.ui.analytics.scanner_evaluation import (
    create_evaluation_summary,
    evaluate_scan_results,
    filter_excluded_checks,
    get_configuration_items,
    get_evaluation_configuration,
    get_scanner_instance,
    get_tool_capabilities,
)
from kalm_benchmark.ui.interface.gen_utils import (
    find_current_scan_index,
    find_scan_by_id,
    get_query_param,
    get_unified_service,
    init,
)
from kalm_benchmark.ui.interface.scanner_ui import (
    build_scan_options,
    get_latest_scan_text,
    render_evaluation_error,
    render_header_gradient_section,
    render_no_scans_message,
    render_scan_metrics,
    render_scan_summary_stats,
    render_scan_target_info,
)
from kalm_benchmark.ui.interface.source_filter import (
    ScanSourceType,
    get_source_filter_sql_condition,
    render_helm_chart_selector,
    render_source_type_filter,
)
from kalm_benchmark.ui.logging_config import get_ui_logger
from kalm_benchmark.ui.scanner_details.evaluation_result import (
    create_check_type_chart,
    get_confusion_matrix,
    show_detailed_analysis,
    show_tool_evaluation_results,
)
from kalm_benchmark.ui.scanner_details.scan import show_scan_buttons
from kalm_benchmark.ui.visualization.icon_utils import get_scanner_icon_html
from kalm_benchmark.utils.constants import QueryParam, SessionKeys


def show_scanner_header(tool_name: str, tool) -> None:
    """Display comprehensive scanner header with branding, metrics, and configuration details.

    :param tool_name: Name of the scanner to display
    :param tool: Scanner instance containing configuration details
    :return: None
    """
    icon_html = get_scanner_icon_html(tool_name)
    render_header_gradient_section(tool_name, icon_html)

    scan_runs = _get_scan_runs_for_tool(tool_name)
    _render_metrics_section(tool, scan_runs)
    _render_configuration_section(tool)
    _render_notes_section(tool)


def _get_scan_runs_for_tool(tool_name: str) -> list[dict[str, any]]:
    """Retrieve all scan runs from database for specified scanner."""
    unified_service = get_unified_service()
    return unified_service.db.get_scan_runs(scanner_name=tool_name.lower())


def show_historical_analysis_section(
    unified_service,
    tool_name: str,
    source_type: ScanSourceType,
    chart_name: str | None = None,
) -> None:
    """Display historical analysis and performance trends for scanner results.

    :param unified_service: Service instance for database access
    :param tool_name: Name of the scanner to analyze
    :param source_type: Type of scan source for filtering
    :param chart_name: Optional chart name for Helm-specific filtering
    :return: None
    """
    with st.expander("📈 Historical Analysis & Trends", expanded=False):
        hist_tab1, hist_tab2 = st.tabs(["📊 Scan Trends", "⚡ Performance Trends"])

        with hist_tab1:
            render_historical_scan_trends(unified_service, source_type, chart_name)

        with hist_tab2:
            render_scanner_performance_trends(unified_service, tool_name, source_type)


def get_filtered_scan_runs(
    unified_service,
    tool_name: str,
    source_type: ScanSourceType,
    chart_name: str | None = None,
) -> list[dict[str, any]]:
    """Retrieve scan runs filtered by source type and optional chart name.

    :param unified_service: Service instance for database access
    :param tool_name: Name of the scanner to filter by
    :param source_type: Type of scan source for filtering
    :param chart_name: Optional chart name for Helm-specific filtering
    :return: Filtered list of scan run dictionaries
    """
    if source_type == ScanSourceType.ALL and not chart_name:
        return unified_service.db.get_scan_runs(scanner_name=tool_name.lower())

    try:
        return _execute_filtered_query(unified_service, tool_name, source_type, chart_name)
    except Exception as e:
        st.error(f"Error filtering scan runs: {e}")
        return unified_service.db.get_scan_runs(scanner_name=tool_name.lower())


def _execute_filtered_query(
    unified_service,
    tool_name: str,
    source_type: ScanSourceType,
    chart_name: str | None,
) -> list[dict[str, any]]:
    """Execute database query with source type and chart filtering."""
    with unified_service.db._get_connection() as conn:
        cursor = conn.cursor()

        source_condition, source_params = get_source_filter_sql_condition(source_type)

        if source_condition.startswith("AND"):
            source_condition = "WHERE" + source_condition[3:]

        if source_type == ScanSourceType.HELM_CHARTS and chart_name:
            source_condition = "WHERE scan_timestamp IN (SELECT timestamp FROM scan_runs WHERE source_type = ?)"
            source_params = [f"helm-chart:{chart_name}"]

        query = f"""
            SELECT DISTINCT sr.*,
                   (SELECT COUNT(*) FROM scanner_results sr2
                    WHERE sr2.scan_timestamp = sr.timestamp
                    AND sr2.scanner_name = sr.scanner_name) as total_results
            FROM scan_runs sr
            JOIN scanner_results sr_filter
            ON sr.timestamp = sr_filter.scan_timestamp
            AND sr.scanner_name = sr_filter.scanner_name
            {source_condition}
            AND LOWER(sr.scanner_name) = ?
            ORDER BY sr.timestamp DESC
        """

        params = source_params + [tool_name.lower()]
        cursor.execute(query, params)

        return _process_query_results(cursor)


def _process_query_results(cursor) -> list[dict[str, any]]:
    """Convert database cursor results to list of dictionaries."""
    columns = [description[0] for description in cursor.description]
    results = []
    for row in cursor.fetchall():
        if isinstance(row, dict):
            results.append(row)
        else:
            row_dict = {columns[i]: row[i] for i in range(len(columns))}
            results.append(row_dict)
    return results


def _render_metrics_section(tool, scan_runs: list[dict[str, any]]) -> None:
    """Display scanner metrics in four-column layout."""
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "📊 Total Scans",
            len(scan_runs),
            help="Number of scan runs stored in the database",
        )

    with col2:
        latest_scan_text = get_latest_scan_text(scan_runs)
        st.metric(
            "⏰ Latest Scan",
            latest_scan_text,
            help="Timestamp of the most recent scan",
        )

    with col3:
        capabilities = get_tool_capabilities(tool)
        capability_text = ", ".join(capabilities) if capabilities else "None"
        st.metric(
            "🛠️ Capabilities",
            len(capabilities),
            delta=capability_text,
            help=f"Supported scan types: {capability_text}",
        )

    with col4:
        config_items = get_configuration_items(tool)
        config_text = ", ".join(config_items) if config_items else "Basic"
        st.metric(
            "⚙️ Configuration",
            len(config_items),
            delta=config_text,
            help=f"Configuration: {config_text}",
        )


def _render_configuration_section(tool) -> None:
    """Display expandable scanner configuration details."""
    with st.expander("📋 Detailed Scanner Configuration", expanded=False):
        col_a, col_b = st.columns(2)

        with col_a:
            _render_scanner_settings(tool)

        with col_b:
            _render_scanner_commands(tool)


def _render_scanner_settings(tool) -> None:
    """Display scanner configuration settings and capabilities."""
    st.markdown("**🔧 Scanner Settings:**")
    st.markdown(f"• **Name:** `{tool.NAME}`")
    st.markdown(f"• **CI Mode:** {'✅ Yes' if tool.CI_MODE else '❌ No'}")
    st.markdown(f"• **Custom Checks:** {tool.CUSTOM_CHECKS}")
    st.markdown(f"• **Runs Offline:** {tool.RUNS_OFFLINE}")
    st.markdown(f"• **Scan Per File:** {'✅ Yes' if tool.SCAN_PER_FILE else '❌ No'}")

    if tool.FORMATS:
        st.markdown(f"• **Output Formats:** {', '.join(tool.FORMATS)}")


def _render_scanner_commands(tool) -> None:
    """Display scanner command examples for different scan types."""
    st.markdown("**📝 Commands:**")

    if tool.SCAN_CLUSTER_CMD:
        st.markdown("**Cluster Scan:**")
        st.code(" ".join(tool.SCAN_CLUSTER_CMD), language="bash")

    if tool.SCAN_MANIFESTS_CMD:
        st.markdown("**Manifest Scan:**")
        st.code(" ".join(tool.SCAN_MANIFESTS_CMD), language="bash")

    if tool.VERSION_CMD:
        st.markdown("**Version Check:**")
        st.code(" ".join(tool.VERSION_CMD), language="bash")


def _render_notes_section(tool) -> None:
    """Display important scanner notes and warnings if available."""
    if tool.NOTES:
        st.markdown("---")
        with st.expander("⚠️ Important Scanner Notes", expanded=True):
            for note in tool.NOTES:
                st.warning(note)


def show_recent_activity(tool_name: str) -> None:
    """Display recent scan activity and log entries for the scanner.

    :param tool_name: Name of the scanner to show activity for
    :return: None
    """
    data_dir = Path(st.session_state.get(SessionKeys.DataDir, "./data"))
    ui_logger = get_ui_logger(data_dir)

    with st.expander("📜 Recent Activity", expanded=False):
        recent_logs = ui_logger.get_recent_scan_logs(tool_name, limit=10)

        if recent_logs:
            st.markdown("**Recent scan activities:**")
            for log in recent_logs[-5:]:
                if log.strip():
                    _render_log_entry(log)
        else:
            st.info("No recent activity found. Run a scan to see activity here.")


def _render_log_entry(log: str) -> None:
    """Display log entry with appropriate styling based on log level."""
    if "INFO" in log:
        st.info(f"ℹ️ {log.split('INFO')[-1].strip()}")
    elif "ERROR" in log:
        st.error(f"❌ {log.split('ERROR')[-1].strip()}")
    elif "SUCCESS" in log:
        st.success(f"✅ {log.split('SUCCESS')[-1].strip()}")
    else:
        st.text(log.strip())


def show() -> None:
    """Display the main scanner details page with selection interface and comprehensive analysis.

    :return: None
    """
    key = "scanner"

    def _on_change():
        st.query_params[QueryParam.SelectedScanner] = st.session_state[key]

    scanners = list(SCANNERS.keys())
    selected_tool = get_query_param(QueryParam.SelectedScanner, scanners[0])
    st.session_state[key] = selected_tool

    with st.sidebar:
        st.markdown("### 🔧 Scanner Selection")
        tool = st.selectbox(
            "Choose Scanner:",
            scanners,
            key=key,
            on_change=_on_change,
            help="Select a scanner to view its details and run scans",
        )

        st.markdown("---")

        scanner_obj = SCANNERS.get(tool)
        if scanner_obj:
            show_scan_buttons(scanner_obj)

        st.markdown("---")

        show_recent_activity(tool)

    scanner_obj = SCANNERS.get(tool)
    if not scanner_obj:
        st.error(f"Scanner '{tool}' not found!")
        return

    show_scanner_header(tool, scanner_obj)

    st.markdown("---")

    show_unified_scan_interface(tool, scanner_obj)


def show_unified_scan_interface(tool_name: str, _scanner_obj) -> None:
    """Display unified scan management interface with filtering and analysis sections.

    :param tool_name: Name of the scanner to display interface for
    :param _scanner_obj: Scanner instance (parameter kept for consistency)
    :return: None
    """
    unified_service = get_unified_service()

    # Render analysis scope and get selections
    selected_source_type, selected_chart = _render_analysis_scope_section(tool_name, unified_service)

    # Get filtered scan runs and handle scan selection
    scan_runs = get_filtered_scan_runs(unified_service, tool_name, selected_source_type, selected_chart)
    selected_scan_id = _handle_scan_selection(tool_name, scan_runs)

    st.divider()

    # Render insights and analysis sections
    _render_scan_sections(tool_name, unified_service, selected_scan_id, scan_runs, selected_source_type, selected_chart)


def _render_analysis_scope_section(tool_name: str, unified_service) -> tuple[ScanSourceType, str | None]:
    """Display analysis scope controls and return user selections."""
    st.markdown("### 🎯 Analysis Scope")

    col1, col2, col3 = st.columns([2, 2, 1])

    with col1:
        selected_source_type = render_source_type_filter(
            key=f"scanner_details_source_filter_{tool_name}",
            default=ScanSourceType.ALL,
            show_counts=True,
            unified_service=unified_service,
        )

    with col2:
        selected_chart = None
        if selected_source_type == ScanSourceType.HELM_CHARTS:
            selected_chart = render_helm_chart_selector(unified_service, key=f"scanner_details_helm_chart_{tool_name}")

    with col3:
        if st.button("🔄 Refresh", help="Reload scan data"):
            st.rerun()

    return selected_source_type, selected_chart


def _handle_scan_selection(tool_name: str, scan_runs: list[dict[str, any]]) -> str | None:
    """Display scan selection interface and return selected scan ID."""
    if not scan_runs:
        st.info("🔍 No scan results found. Run a scan to see analysis here.")
        return None

    st.markdown("**📁 Historical Scan Selection**")
    scan_options = build_scan_options(scan_runs)

    dropdown_key = f"{tool_name}_scan_history_selector"
    current_index = _get_current_scan_index(dropdown_key, scan_runs)

    selected_index = st.selectbox(
        "Choose scan to analyze:",
        range(len(scan_options)),
        index=current_index,
        format_func=lambda i: scan_options[i][0],
        key=dropdown_key,
        help="Select a historical scan to view its detailed analysis",
    )

    if selected_index is not None and selected_index < len(scan_runs):
        return scan_runs[selected_index]["id"]
    return None


def _get_current_scan_index(dropdown_key: str, scan_runs: list[dict[str, any]]) -> int:
    """Retrieve current scan index from session state with bounds checking."""
    if dropdown_key in st.session_state:
        selected_index = st.session_state[dropdown_key]
        if selected_index is not None and selected_index < len(scan_runs):
            return selected_index
    return 0


def _render_scan_sections(
    tool_name: str,
    unified_service,
    selected_scan_id: str | None,
    scan_runs: list[dict[str, any]],
    selected_source_type: ScanSourceType,
    selected_chart: str | None,
) -> None:
    """Display scan insights, historical analysis, and detailed results sections."""
    if selected_scan_id and scan_runs:
        _render_scan_insights_panel(selected_scan_id, scan_runs)
        st.markdown("---")

    if scan_runs:
        show_historical_analysis_section(unified_service, tool_name, selected_source_type, selected_chart)
        st.divider()

    show_results_for_selected_scan(tool_name, selected_scan_id)


def _render_scan_insights_panel(selected_scan_id: str, scan_runs: list[dict[str, any]]) -> None:
    """Display scan insights panel with metrics and target information."""
    st.markdown("### 📊 Scan Analysis Insights")

    if not selected_scan_id:
        st.info("👈 Select a scan to view analysis insights.")
        return

    selected_scan = find_scan_by_id(selected_scan_id, scan_runs)
    if not selected_scan:
        st.warning("Selected scan details not available.")
        return

    render_scan_metrics(selected_scan)
    render_scan_target_info(selected_scan)


def show_scan_history_panel(tool_name: str, selected_scan_id: str) -> None:
    """Display scan history panel with selection dropdown and summary statistics.

    :param tool_name: Name of the scanner to show history for
    :param selected_scan_id: Currently selected scan ID
    :return: None
    """
    st.markdown("### 📁 Scan History")

    scan_runs = _get_scan_runs_for_tool(tool_name)

    if not scan_runs:
        render_no_scans_message()
        return

    _render_scan_history_dropdown(tool_name, selected_scan_id, scan_runs)
    render_scan_summary_stats(scan_runs)


def _render_scan_history_dropdown(tool_name: str, selected_scan_id: str, scan_runs: list[dict[str, any]]) -> None:
    """Display detailed scan history dropdown with formatted options."""
    st.markdown("**Select scan to analyze:**")

    scan_options = build_scan_options(scan_runs, detailed=True)
    current_index = find_current_scan_index(selected_scan_id, scan_options)

    st.selectbox(
        "Choose scan:",
        range(len(scan_options)),
        index=current_index,
        format_func=lambda i: scan_options[i][0],
        key=f"{tool_name}_scan_history_selector",
        help="Select a scan to view its detailed analysis",
        label_visibility="collapsed",
    )

    st.markdown("---")


def show_results_for_selected_scan(tool_name: str, selected_scan_id: str | None) -> None:
    """Display comprehensive results and analysis for the selected scan.

    :param tool_name: Name of the scanner
    :param selected_scan_id: ID of the selected scan or None
    :return: None
    """
    st.markdown("### 📈 Results & Analysis")

    if not selected_scan_id:
        st.info("👈 Select a scan from the sidebar to view detailed results and analysis.")
        return

    unified_service = get_unified_service()
    scan_runs = unified_service.db.get_scan_runs(scanner_name=tool_name.lower())
    selected_scan = next((run for run in scan_runs if run["id"] == selected_scan_id), None)

    if not selected_scan:
        st.error("Selected scan not found.")
        return

    all_scan_runs = scan_runs

    st.markdown("### 📊 Scan Summary")
    col_a, col_b = st.columns(2)
    with col_a:
        total_results = sum(run.get("total_results", 0) for run in all_scan_runs)
        st.metric("Total Results", total_results)
    with col_b:
        source_types = len({run.get("source_type", "Unknown") for run in all_scan_runs})
        st.metric("Source Types", source_types)

    st.markdown("---")

    show_tool_evaluation_results_for_scan(tool_name, selected_scan_id)


def show_tool_evaluation_results_for_scan(tool_name: str, scan_id: str) -> None:
    """Display detailed evaluation results for a specific scan with error handling.

    :param tool_name: Name of the scanner
    :param scan_id: ID of the scan to analyze
    :return: None
    """
    if not scan_id:
        show_tool_evaluation_results(tool_name)
        return

    try:
        unified_service = get_unified_service()

        scan_runs = unified_service.db.get_scan_runs(scanner_name=tool_name.lower())
        selected_scan = next((run for run in scan_runs if run["id"] == scan_id), None)

        if not selected_scan:
            st.error("Could not find scan details.")
            return

        raw_results = unified_service.load_scanner_results(tool_name.lower(), scan_id)

        if not raw_results:
            st.warning("No detailed results found for this scan. This may be an older scan format.")

            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Results", selected_scan.get("total_results", 0))
            with col2:
                st.metric(
                    "Scanner Version",
                    selected_scan.get("scanner_version", "Unknown"),
                )
            with col3:
                st.metric("Source Type", selected_scan.get("source_type", "Unknown"))
            return

        show_scan_specific_evaluation_results(tool_name, raw_results, selected_scan)

    except Exception as e:
        _render_scan_error_info(e, scan_id, tool_name)


def _render_scan_error_info(error: Exception, scan_id: str, tool_name: str) -> None:
    """Display detailed error information for scan loading failures."""
    st.error(f"Error loading results for selected scan: {error}")

    with st.expander("🔍 Debug Information", expanded=False):
        st.markdown(f"**Error:** {str(error)}")
        st.markdown(f"**Scan ID:** `{scan_id}`")
        st.markdown(f"**Scanner:** `{tool_name}`")


def show_scan_specific_evaluation_results(tool_name: str, raw_results: any, scan_run: dict[str, any]) -> None:
    """Display comprehensive evaluation results for specific scan with standard metrics.

    :param tool_name: Name of the scanner
    :param raw_results: Raw scan results from database
    :param scan_run: Scan run metadata dictionary
    :return: None
    """
    scanner = get_scanner_instance(tool_name)
    if not scanner:
        return

    evaluation_config = get_evaluation_configuration(tool_name)

    try:
        df_results = evaluate_scan_results(scanner, raw_results, evaluation_config)
        if df_results is None or df_results.empty:
            st.warning("No evaluation results could be generated from the scan data.")
            return

        df_results = filter_excluded_checks(df_results, tool_name)
        summary = create_evaluation_summary(df_results, scan_run)

        _render_evaluation_metrics(summary, df_results, scan_run)
        _render_category_analysis(summary)
        _render_detailed_analysis(df_results)

    except Exception as e:
        render_evaluation_error(e, raw_results)


def _render_evaluation_metrics(summary, df_results, scan_run: dict[str, any] | None = None) -> None:
    """Display evaluation metrics in two-column layout with context-aware formatting."""
    is_helm_chart = scan_run and scan_run.get("source_type", "").startswith("helm-chart:")

    col1, col2 = st.columns(2)

    with col1:
        _render_score_metric(summary, is_helm_chart)
        _render_metric_details(summary, df_results, is_helm_chart)

    with col2:
        _render_coverage_metric(summary, is_helm_chart)
        st.altair_chart(altair_chart=create_check_type_chart(df_results))

    _render_analysis_info(is_helm_chart)


def _render_score_metric(summary, is_helm_chart: bool) -> None:
    """Display primary score metric with context-appropriate formatting."""
    if is_helm_chart:
        st.metric(
            "Risk Score",
            f"{summary.score * 100:.1f}%",
            help="Risk-based score: 100% = no high/medium severity issues",
        )
    else:
        st.metric(
            "F1 Score",
            f"{summary.score * 100:.1f}%",
            help="F1-Score based on benchmark accuracy",
        )


def _render_metric_details(summary, df_results, is_helm_chart: bool) -> None:
    """Display detailed metric information with context-specific content."""
    with st.expander("Details"):
        if is_helm_chart:
            _render_helm_details(summary, df_results)
        else:
            df_xtab = get_confusion_matrix(df_results)
            st.table(df_xtab)
            st.text(f"{Metric.F1} is used as the metric")


def _render_helm_details(summary, df_results) -> None:
    """Display Helm chart-specific metric details with severity breakdown."""
    total_findings = summary.total_ccss_findings or 0
    high_risk = (
        len(df_results[df_results["severity"].isin(["HIGH", "CRITICAL", "DANGER"])]) if df_results is not None else 0
    )
    medium_risk = len(df_results[df_results["severity"].isin(["MEDIUM", "WARNING"])]) if df_results is not None else 0

    st.markdown(f"**Total Findings:** {total_findings}")
    st.markdown(f"**High/Critical:** {high_risk}")
    st.markdown(f"**Medium/Warning:** {medium_risk}")
    st.markdown(f"**Low/Info:** {total_findings - high_risk - medium_risk}")
    st.info("💡 Risk score decreases with higher severity findings")


def _render_coverage_metric(summary, is_helm_chart: bool) -> None:
    """Display coverage metric with context-appropriate labeling."""
    if is_helm_chart:
        st.metric(
            "Mapping Coverage",
            f"{summary.coverage * 100:.1f}%",
            help="Percentage of helm findings mapped to benchmark checks",
        )
    else:
        st.metric(
            "Benchmark Coverage",
            f"{summary.coverage * 100:.1f}%",
            help="Percentage of benchmark checks covered by scanner",
        )


def _render_analysis_info(is_helm_chart: bool) -> None:
    """Display context-appropriate analysis information and guidance."""
    if is_helm_chart:
        st.info(
            """
        🔄 **Helm Chart Analysis**: This evaluation maps helm chart
        security findings to benchmark checks.
        - **Covered**: Findings successfully mapped to benchmark checks
        - **Extra**: Findings that don't correspond to benchmark checks
        (helm-specific issues)
        - **Risk Score**: Based on severity distribution (higher severity =
        lower score)
        - **Mapping Coverage**: Shows how well helm findings align with
        benchmark security categories
        """
        )
    else:
        st.info(
            """
        📊 **Benchmark Analysis**: This evaluation compares scanner
        results against expected benchmark outcomes.
        - **Covered**: Scanner correctly identified the issue
        - **Missing**: Scanner missed a benchmark check
        - **Extra**: Scanner found additional issues beyond benchmark scope
        - **F1 Score**: Harmonic mean of precision and recall
        """
        )


def _render_category_analysis(summary) -> None:
    """Display security checks breakdown by category."""
    st.subheader("Checks per category")

    if summary.checks_per_category is None:
        st.info("No category data available for this scan.")
        return

    if hasattr(summary.checks_per_category, "empty"):
        if not summary.checks_per_category.empty:
            df_transposed = summary.checks_per_category.T
            st.dataframe(df_transposed, use_container_width=True)
        else:
            st.info("No category data available for this scan.")
    else:
        st.dataframe(summary.checks_per_category, use_container_width=True)


def _render_detailed_analysis(df_results) -> None:
    """Display comprehensive detailed analysis of scan results."""
    show_detailed_analysis(df_results)


if __name__ == "__main__":
    init()
    show()
