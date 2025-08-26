from pathlib import Path

import streamlit as st

from kalm_benchmark.evaluation.scanner_manager import SCANNERS
from kalm_benchmark.ui.logging_config import get_ui_logger
from kalm_benchmark.ui.scanner_details.evaluation_result import (
    show_tool_evaluation_results,
)
from kalm_benchmark.ui.scanner_details.scan import show_scan_buttons
from kalm_benchmark.ui.utils.gen_utils import (
    calculate_scan_age,
    find_current_scan_index,
    find_scan_by_id,
    format_scan_timestamp,
    get_query_param,
    get_unified_service,
    init,
)
from kalm_benchmark.utils.constants import CUSTOM_CHECKS_LABEL, QueryParam, SessionKeys


def _get_scanner_icon_path(scanner_name: str) -> str:
    icon_mapping = {
        "KubeLinter": "kube-linter.svg",
        "kube-score": "kube-score.png",
        "Snyk": "snyk.svg",
        "kube-bench": "kube-bench.png",
        "trivy": "trivy.png",
        "polaris": "polaris.png",
        "Terrascan": "terrascan.png",
        "Kubescape": "kubescape.svg",
        "kubesec": "kubesec.png",
        "kubiscan": "kubiscan.png",
        "KICS": "kics.png",
        "Checkov": "checkov.png",
    }

    icon_filename = icon_mapping.get(scanner_name, "")
    if icon_filename:
        # Find project root by looking for pyproject.toml (deployment-agnostic)
        current_file = Path(__file__)
        project_root = current_file
        while project_root.parent != project_root:
            if (project_root / "pyproject.toml").exists():
                break
            project_root = project_root.parent

        icon_path = project_root / "docs" / "images" / "icons" / icon_filename
        return str(icon_path) if icon_path.exists() else ""
    return ""


def show_scanner_header(tool_name: str, tool):
    icon_html = _get_scanner_icon_html(tool_name)
    _render_header_section(tool_name, icon_html)

    scan_runs = _get_scan_runs_for_tool(tool_name)
    _render_metrics_section(tool, scan_runs)
    _render_configuration_section(tool)
    _render_notes_section(tool)


def _get_scanner_icon_html(tool_name: str) -> str:
    icon_path = _get_scanner_icon_path(tool_name)

    if icon_path:
        icon_html = _create_base64_icon(icon_path)
        if icon_html:
            return icon_html

    return _get_fallback_icon_html()


def _create_base64_icon(icon_path: str) -> str:
    try:
        import base64
        from pathlib import Path

        icon_file = Path(icon_path)
        if icon_file.exists():
            with open(icon_file, "rb") as f:
                icon_data = base64.b64encode(f.read()).decode()

            file_ext = icon_file.suffix.lower()
            mime_type = "image/svg+xml" if file_ext == ".svg" else f"image/{file_ext[1:]}"

            return f'<img src="data:{mime_type};base64,{icon_data}" style="width: 64px; height: 64px; object-fit: contain; filter: drop-shadow(0 4px 8px rgba(0,0,0,0.15));" />'
    except Exception:
        pass
    return ""


def _get_fallback_icon_html() -> str:
    return '<div style="width: 64px; height: 64px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 16px; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);"><span style="font-size: 2rem; color: white;">🔍</span></div>'


def _render_header_section(tool_name: str, icon_html: str):
    st.markdown(
        f"""
        <div style="background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 25%, #74b9ff 50%, #00cec9 75%, #6c5ce7 100%); 
                    padding: 2.5rem 2rem; border-radius: 16px; margin-bottom: 2rem; 
                    box-shadow: 0 10px 30px rgba(108, 92, 231, 0.4); position: relative; overflow: hidden;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; 
                        background: radial-gradient(circle at 20% 30%, rgba(162, 155, 254, 0.4) 0%, transparent 50%), 
                                    radial-gradient(circle at 80% 70%, rgba(116, 185, 255, 0.3) 0%, transparent 50%), 
                                    radial-gradient(circle at 50% 10%, rgba(0, 206, 201, 0.3) 0%, transparent 50%); 
                        pointer-events: none;"></div>
            <div style="position: relative; z-index: 1; display: flex; align-items: center; gap: 1.5rem;">
                <div style="background: rgba(255,255,255,0.25); padding: 14px; border-radius: 16px; 
                           backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.2);">
                    {icon_html}
                </div>
                <div>
                    <h1 style="color: #FFFFFF; margin: 0; font-size: 2.5rem; font-weight: 700; 
                               text-shadow: 0 3px 10px rgba(0,0,0,0.3);">{tool_name}</h1>
                    <p style="color: rgba(255,255,255,0.95); margin: 0.5rem 0 0 0; 
                              font-size: 1.1rem; font-weight: 400; text-shadow: 0 2px 6px rgba(0,0,0,0.25);">Security Scanner Dashboard</p>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _get_scan_runs_for_tool(tool_name: str) -> list:
    unified_service = get_unified_service()
    return unified_service.db.get_scan_runs(scanner_name=tool_name.lower())


def _render_metrics_section(tool, scan_runs: list):
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("📊 Total Scans", len(scan_runs), help="Number of scan runs stored in the database")

    with col2:
        latest_scan_text = _get_latest_scan_text(scan_runs)
        st.metric("⏰ Latest Scan", latest_scan_text, help="Timestamp of the most recent scan")

    with col3:
        capabilities = _get_tool_capabilities(tool)
        capability_text = ", ".join(capabilities) if capabilities else "None"
        st.metric(
            "🛠️ Capabilities", len(capabilities), delta=capability_text, help=f"Supported scan types: {capability_text}"
        )

    with col4:
        config_items = _get_configuration_items(tool)
        config_text = ", ".join(config_items) if config_items else "Basic"
        st.metric("⚙️ Configuration", len(config_items), delta=config_text, help=f"Configuration: {config_text}")


def _get_latest_scan_text(scan_runs: list) -> str:
    if not scan_runs:
        return "None"

    try:
        latest_run = scan_runs[0]
        timestamp = latest_run["timestamp"]
        return format_scan_timestamp(timestamp)
    except Exception:
        return "Unknown"


def _get_tool_capabilities(tool) -> list:
    capabilities = []
    if tool.can_scan_cluster:
        capabilities.append("Cluster")
    if tool.can_scan_manifests:
        capabilities.append("Manifests")
    if tool.CI_MODE:
        capabilities.append("CI/CD")
    return capabilities


def _get_configuration_items(tool) -> list:
    """Get list of configuration items."""
    config_items = []
    if tool.CUSTOM_CHECKS != "False":
        config_items.append(CUSTOM_CHECKS_LABEL)
    if tool.RUNS_OFFLINE:
        config_items.append("Offline")
    if tool.FORMATS:
        config_items.append(f"{len(tool.FORMATS)} Formats")
    return config_items


def _render_configuration_section(tool):
    """Render the expandable configuration section."""
    with st.expander("📋 Detailed Scanner Configuration", expanded=False):
        col_a, col_b = st.columns(2)

        with col_a:
            _render_scanner_settings(tool)

        with col_b:
            _render_scanner_commands(tool)


def _render_scanner_settings(tool):
    """Render scanner settings section."""
    st.markdown("**🔧 Scanner Settings:**")
    st.markdown(f"• **Name:** `{tool.NAME}`")
    st.markdown(f"• **CI Mode:** {'✅ Yes' if tool.CI_MODE else '❌ No'}")
    st.markdown(f"• **Custom Checks:** {tool.CUSTOM_CHECKS}")
    st.markdown(f"• **Runs Offline:** {tool.RUNS_OFFLINE}")
    st.markdown(f"• **Scan Per File:** {'✅ Yes' if tool.SCAN_PER_FILE else '❌ No'}")

    if tool.FORMATS:
        st.markdown(f"• **Output Formats:** {', '.join(tool.FORMATS)}")


def _render_scanner_commands(tool):
    """Render scanner commands section."""
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


def _render_notes_section(tool):
    """Render important notes section if present."""
    if tool.NOTES:
        st.markdown("---")
        with st.expander("⚠️ Important Scanner Notes", expanded=True):
            for note in tool.NOTES:
                st.warning(note)


def show_recent_activity(tool_name: str):
    """Show recent scan activity for the scanner."""
    data_dir = Path(st.session_state.get(SessionKeys.DataDir, "./data"))
    ui_logger = get_ui_logger(data_dir)

    with st.expander("📜 Recent Activity", expanded=False):
        recent_logs = ui_logger.get_recent_scan_logs(tool_name, limit=10)

        if recent_logs:
            st.markdown("**Recent scan activities:**")
            for log in recent_logs[-5:]:
                if log.strip():
                    # Parse log entry for better display
                    if "INFO" in log:
                        st.info(f"ℹ️ {log.split('INFO')[-1].strip()}")
                    elif "ERROR" in log:
                        st.error(f"❌ {log.split('ERROR')[-1].strip()}")
                    elif "SUCCESS" in log:
                        st.success(f"✅ {log.split('SUCCESS')[-1].strip()}")
                    else:
                        st.text(log.strip())
        else:
            st.info("No recent activity found. Run a scan to see activity here.")


def show() -> None:
    """Main function to show the scanner details page with tabbed interface."""
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


def show_unified_scan_interface(tool_name: str, _scanner_obj):
    """Show the unified scan management interface."""
    unified_service = get_unified_service()
    scan_runs = unified_service.db.get_scan_runs(scanner_name=tool_name.lower())

    selected_scan_id = None
    if scan_runs:
        selected_scan_id = scan_runs[0]["id"]

        dropdown_key = f"{tool_name}_scan_history_selector"
        if dropdown_key in st.session_state:
            selected_index = st.session_state[dropdown_key]
            if selected_index is not None and selected_index < len(scan_runs):
                selected_scan_id = scan_runs[selected_index]["id"]

    show_scan_selection_and_summary(tool_name, selected_scan_id, scan_runs)

    show_results_for_selected_scan(tool_name, selected_scan_id)


def show_scan_selection_and_summary(tool_name: str, selected_scan_id: str, scan_runs: list):
    """Show scan selection dropdown and summary statistics at the top of the page."""
    if not scan_runs:
        st.info("🔍 No scan results found. Run a scan to see analysis here.")
        return

    col1, col2 = st.columns([1, 1])

    with col1:
        _render_scan_selection_panel(tool_name, selected_scan_id, scan_runs)

    with col2:
        _render_scan_insights_panel(selected_scan_id, scan_runs)

    st.markdown("---")


def _render_scan_selection_panel(tool_name: str, selected_scan_id: str, scan_runs: list):
    """Render the scan selection dropdown panel."""
    st.markdown("### 📁 Scan Selection")

    scan_options = _build_scan_options(scan_runs)
    current_index = find_current_scan_index(selected_scan_id, scan_options)

    st.selectbox(
        "Choose scan to analyze:",
        range(len(scan_options)),
        index=current_index,
        format_func=lambda i: scan_options[i][0],
        key=f"{tool_name}_scan_history_selector",
        help="Select a scan to view its detailed analysis",
    )


def _render_scan_insights_panel(selected_scan_id: str, scan_runs: list):
    """Render the scan analysis insights panel."""
    st.markdown("### 📊 Scan Analysis Insights")

    if not selected_scan_id:
        st.info("👈 Select a scan to view analysis insights.")
        return

    selected_scan = find_scan_by_id(selected_scan_id, scan_runs)
    if not selected_scan:
        st.warning("Selected scan details not available.")
        return

    _render_scan_metrics(selected_scan)
    _render_scan_target_info(selected_scan)


def _build_scan_options(scan_runs: list, detailed: bool = False) -> list:
    scan_options = []
    for scan_run in scan_runs:
        if detailed:
            time_str = format_scan_timestamp(scan_run.get("timestamp", ""), format="%b %d %H:%M")
            source_type = scan_run.get("source_type", "Unknown")
            result_count = scan_run.get("total_results", 0)
            option_text = f"{time_str} • {source_type} ({result_count} results)"
        else:
            time_str = format_scan_timestamp(scan_run.get("timestamp", ""))
            source_type = scan_run.get("source_type", "Unknown").split(":")[0]
            option_text = f"{time_str} • {source_type}"
        scan_options.append((option_text, scan_run["id"]))
    return scan_options


def _render_scan_metrics(selected_scan: dict):
    """Render scan metrics in three columns."""
    col_a, col_b, col_c = st.columns(3)

    with col_a:
        st.metric("Findings", selected_scan.get("total_results", 0), help="Total security findings detected")

    with col_b:
        scanner_version = selected_scan.get("scanner_version", "Unknown")
        st.metric("Scanner Ver.", scanner_version, help="Version of the scanner used")

    with col_c:
        age_text = calculate_scan_age(selected_scan.get("timestamp", ""))
        st.metric("Scan Age", age_text, help="How long ago this scan was performed")


def _render_scan_target_info(selected_scan: dict):
    """Render scan target information."""
    source_info = selected_scan.get("source_type", "Unknown")
    if ":" in source_info:
        source_type, source_name = source_info.split(":", 1)
        st.info(f"🎯 **Scan Target**: {source_name} ({source_type})")
    else:
        st.info(f"🎯 **Scan Target**: {source_info}")


def show_scan_history_panel(tool_name: str, selected_scan_id: str):
    """Show scan history panel with scan selection and management options."""
    st.markdown("### 📁 Scan History")

    scan_runs = _get_scan_runs_for_tool(tool_name)

    if not scan_runs:
        _render_no_scans_message()
        return

    _render_scan_history_dropdown(tool_name, selected_scan_id, scan_runs)
    _render_scan_summary_stats(scan_runs)


def _render_no_scans_message():
    """Render message when no scans are found."""
    st.info("🔍 No scan results found.")

    with st.expander("💡 Getting Started", expanded=True):
        st.markdown(
            """
        **To see scan history and analysis:**
        
        1. Use the scan controls in the sidebar →
        2. Run cluster scans or manifest scans
        3. Results will appear here for selection and analysis
        
        **Scan Types Available:**
        - 🌐 **Cluster Scan**: Live Kubernetes resources
        - 📁 **Manifest Scan**: YAML manifest files  
        - ⚓ **Helm Chart Scan**: Rendered Helm charts
        """
        )


def _render_scan_history_dropdown(tool_name: str, selected_scan_id: str, scan_runs: list):
    """Render scan history dropdown with detailed options."""
    st.markdown("**Select scan to analyze:**")

    scan_options = _build_scan_options(scan_runs, detailed=True)
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


def _render_scan_summary_stats(scan_runs: list):
    """Render summary statistics for scan history."""
    if len(scan_runs) <= 1:
        return

    st.markdown("---")
    st.markdown("**📊 Summary:**")

    col_a, col_b = st.columns(2)
    with col_a:
        total_results = sum(run.get("total_results", 0) for run in scan_runs)
        st.metric("Total Results", total_results)
    with col_b:
        source_types = len({run.get("source_type", "Unknown") for run in scan_runs})
        st.metric("Source Types", source_types)


def show_results_for_selected_scan(tool_name: str, selected_scan_id: str):
    """Show results and analysis for the selected scan."""
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


def show_tool_evaluation_results_for_scan(tool_name: str, scan_id: str):
    """Show evaluation results for a specific scan."""
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
        st.error(f"Error loading results for selected scan: {e}")

        with st.expander("🔍 Debug Information", expanded=False):
            st.markdown(f"**Error:** {str(e)}")
            st.markdown(f"**Scan ID:** `{scan_id}`")
            st.markdown(f"**Scanner:** `{tool_name}`")


def show_scan_specific_evaluation_results(tool_name: str, raw_results, scan_run: dict):
    """Show evaluation results for a specific scan using the standard evaluation system."""
    scanner = _get_scanner_instance(tool_name)
    if not scanner:
        return

    evaluation_config = _get_evaluation_configuration(tool_name)

    try:
        df_results = _evaluate_scan_results(scanner, raw_results, evaluation_config)
        if df_results is None or df_results.empty:
            st.warning("No evaluation results could be generated from the scan data.")
            return

        df_results = _filter_excluded_checks(df_results, tool_name)
        summary = _create_evaluation_summary(df_results, scan_run)

        _render_evaluation_metrics(summary, df_results)
        _render_category_analysis(summary)
        _render_detailed_analysis(df_results)

    except Exception as e:
        _render_evaluation_error(e, raw_results)


def _get_scanner_instance(tool_name: str):
    """Get scanner instance with error handling."""
    from kalm_benchmark.evaluation.scanner_manager import SCANNERS

    scanner = SCANNERS.get(tool_name)
    if not scanner:
        st.error(f"Scanner '{tool_name}' not found!")
        return None
    return scanner


def _get_evaluation_configuration(tool_name: str) -> dict:
    """Get evaluation configuration from sidebar controls."""
    return {"keep_redundant": st.sidebar.checkbox("Keep redundant checks", value=False, key=f"{tool_name}_redundant")}


def _evaluate_scan_results(scanner, raw_results, config: dict):
    """Evaluate scan results with configuration."""
    from kalm_benchmark.evaluation.evaluation import evaluate_scanner

    return evaluate_scanner(scanner, raw_results, keep_redundant_checks=config["keep_redundant"])


def _filter_excluded_checks(df_results, tool_name: str):
    """Filter out excluded checks based on sidebar selection."""
    from kalm_benchmark.evaluation.evaluation import Col

    df_results = df_results.astype(str)
    all_checks = sorted(df_results[Col.ScannerCheckId].unique())
    excluded_checks = st.sidebar.multiselect("Excluded Checks:", all_checks, key=f"{tool_name}_excluded")

    return df_results[~df_results[Col.ScannerCheckId].isin(excluded_checks)]


def _create_evaluation_summary(df_results, scan_run: dict):
    """Create evaluation summary with metrics."""
    from kalm_benchmark.evaluation.evaluation import Metric, create_summary

    metric = Metric.F1
    version = scan_run.get("scanner_version")
    return create_summary(df_results, metric, version=version)


def _render_evaluation_metrics(summary, df_results):
    """Render evaluation metrics in two columns."""
    from kalm_benchmark.evaluation.evaluation import Metric
    from kalm_benchmark.ui.scanner_details.evaluation_result import (
        create_check_type_chart,
        get_confusion_matrix,
    )

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Score", f"{summary.score * 100:.1f}%")
        with st.expander("Details"):
            df_xtab = get_confusion_matrix(df_results)
            st.table(df_xtab)
            st.text(f"{Metric.F1} is used as the metric")

    with col2:
        st.metric("Coverage", f"{summary.coverage * 100:.1f}%")
        st.altair_chart(altair_chart=create_check_type_chart(df_results))


def _render_category_analysis(summary):
    """Render checks per category section."""
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


def _render_detailed_analysis(df_results):
    """Render detailed analysis section."""
    from kalm_benchmark.ui.scanner_details.evaluation_result import (
        show_detailed_analysis,
    )

    show_detailed_analysis(df_results)


def _render_evaluation_error(error: Exception, raw_results):
    """Render evaluation error information."""
    st.error(f"Error processing scan results: {error}")
    st.markdown(f"**Raw results type:** {type(raw_results)}")
    st.markdown(f"**Raw results length:** {len(raw_results) if hasattr(raw_results, '__len__') else 'N/A'}")

    if raw_results and len(raw_results) > 0:
        st.markdown(f"**First result type:** {type(raw_results[0])}")
        if hasattr(raw_results[0], "__dict__"):
            st.json(raw_results[0].__dict__)


if __name__ == "__main__":
    init()
    show()
