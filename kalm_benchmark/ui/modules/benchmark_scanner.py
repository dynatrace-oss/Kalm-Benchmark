from pathlib import Path
from typing import Optional

from kalm_benchmark.ui.interface.source_filter import ScanSourceType
import streamlit as st

from kalm_benchmark.evaluation.scanner_manager import SCANNERS
from kalm_benchmark.ui.analytics.historical_analysis import (
    render_historical_scan_trends,
    render_scanner_performance_trends,
)
from kalm_benchmark.ui.interface.gen_utils import (
    calculate_scan_age,
    format_scan_timestamp,
    get_query_param,
    get_unified_service,
)
from kalm_benchmark.ui.scanner_details.evaluation_result import (
    show_tool_evaluation_results,
)
from kalm_benchmark.ui.scanner_details.scan import show_scan_buttons
from kalm_benchmark.utils.constants import QueryParam


def _get_scanner_icon_path(scanner_name: str) -> str:
    """Get local filesystem path to scanner icon file."""
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
        # Find project root by looking for pyproject.toml
        current_file = Path(__file__)
        project_root = current_file
        while project_root.parent != project_root:
            if (project_root / "pyproject.toml").exists():
                break
            project_root = project_root.parent

        icon_path = project_root / "docs" / "images" / "icons" / icon_filename
        return str(icon_path) if icon_path.exists() else ""
    return ""


def show_benchmark_scanner_header(tool_name: str, tool):
    """Display comprehensive scanner header with benchmark-focused metrics and configuration.

    :param tool_name: Name of the scanner tool
    :param tool: Scanner tool instance with configuration details
    :return: None
    """
    icon_html = _get_scanner_icon_html(tool_name)
    _render_benchmark_header_section(tool_name, icon_html)

    scan_runs = _get_benchmark_scan_runs_for_tool(tool_name)
    _render_benchmark_metrics_section(tool, scan_runs)
    _render_configuration_section(tool)


def _get_scanner_icon_html(tool_name: str) -> str:
    """Generate HTML for scanner icon with fallback support."""
    icon_path = _get_scanner_icon_path(tool_name)

    if icon_path:
        icon_html = _create_base64_icon(icon_path)
        if icon_html:
            return icon_html

    return _get_fallback_icon_html()


def _create_base64_icon(icon_path: str) -> str:
    """Create base64-encoded HTML img tag from icon file path."""
    try:
        import base64
        from pathlib import Path

        icon_file = Path(icon_path)
        if icon_file.exists():
            with open(icon_file, "rb") as f:
                icon_data = base64.b64encode(f.read()).decode()

            file_ext = icon_file.suffix.lower()
            mime_type = "image/svg+xml" if file_ext == ".svg" else f"image/{file_ext[1:]}"

            return f'<img src="data:{mime_type};base64,{icon_data}" \
                style="width: 64px; height: 64px;\
                      object-fit: contain; filter: drop-shadow(0 4px 8px rgba(0,0,0,0.15));" />'
    except Exception:
        pass
    return ""


def _get_fallback_icon_html() -> str:
    """Return default icon HTML when scanner-specific icon is not available."""
    return '<div style="width: 64px; height: 64px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\
      border-radius: 16px; display: flex; align-items: center; justify-content: center;\
          box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);"><span style="font-size: 2rem; color: white;">🔍</span></div>'


def _render_benchmark_header_section(tool_name: str, icon_html: str):
    """Render gradient header section with scanner branding for benchmark analysis."""
    st.markdown(
        f"""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 25%, #f093fb 50%, #f857a6 75%, #667eea 100%);
                    padding: 2.5rem 2rem; border-radius: 16px; margin-bottom: 2rem;
                    box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4); position: relative; overflow: hidden;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0;
                        background: radial-gradient(circle at 20% 30%, rgba(240, 147, 251, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 80% 70%, rgba(248, 87, 166, 0.3) 0%, transparent 50%),
                                    radial-gradient(circle at 50% 10%, rgba(118, 75, 162, 0.3) 0%, transparent 50%);
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
                              font-size: 1.1rem; font-weight: 400; text-shadow: 0 2px 6px rgba(0,0,0,0.25);">Benchmark Performance Analysis</p>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _get_benchmark_scan_runs_for_tool(tool_name: str) -> list:
    """Filter scan runs to include only benchmark manifests, excluding Helm charts."""
    unified_service = get_unified_service()
    all_scan_runs = unified_service.db.get_scan_runs(scanner_name=tool_name.lower())

    # Filter to only benchmark/manifest scans (exclude helm charts)
    benchmark_runs = []
    for run in all_scan_runs:
        source_type = run.get("source_type", "")
        source_location = run.get("source_location", "")

        # Include if it's a manifest scan and NOT a helm chart
        if source_type == "manifest" or (
            not source_type.startswith("helm-chart:") and not (source_location and "helm-chart:" in source_location)
        ):
            benchmark_runs.append(run)

    return benchmark_runs


def _render_benchmark_metrics_section(tool, scan_runs: list):
    """Display key metrics for benchmark evaluation in three-column layout."""
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("📊 Benchmark Scans", len(scan_runs), help="Number of benchmark evaluations completed")

    with col2:
        if scan_runs:
            latest_scan = max(scan_runs, key=lambda x: x.get("timestamp", ""))
            scan_age = calculate_scan_age(latest_scan.get("timestamp", ""))
            st.metric("🕐 Latest Scan", scan_age, help="Time since most recent benchmark evaluation")
        else:
            st.metric("🕐 Latest Scan", "None", help="No benchmark scans found")

    with col3:
        # Get evaluation summary for this scanner (benchmark only)
        unified_service = get_unified_service()
        try:
            summaries = unified_service.create_evaluation_summary_dataframe()
            scanner_summaries = summaries[
                (summaries["scanner_name"].str.lower() == tool.name.lower())
                & (~summaries["scanner_name"].str.contains("helm-chart:", na=False))
            ]

            if not scanner_summaries.empty:
                latest_score = scanner_summaries.iloc[-1]["score"]
                st.metric("🎯 F1 Score", f"{latest_score:.3f}", help="Latest benchmark evaluation F1 score")
            else:
                st.metric("🎯 F1 Score", "N/A", help="No evaluation data available")
        except Exception:
            st.metric("🎯 F1 Score", "N/A", help="Unable to load evaluation data")


def _render_configuration_section(tool):
    """Display scanner capabilities and configuration information."""
    with st.expander("⚙️ Scanner Configuration", expanded=False):
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**Capabilities:**")
            if hasattr(tool, "supports_manifest_scanning") and tool.supports_manifest_scanning:
                st.success("✅ Manifest Scanning")
            if hasattr(tool, "supports_cluster_scanning") and tool.supports_cluster_scanning:
                st.success("✅ Cluster Scanning")
            if hasattr(tool, "supports_ci_mode") and tool.supports_ci_mode:
                st.success("✅ CI Mode")

        with col2:
            st.markdown("**Scanner Info:**")
            st.text(f"Name: {tool.name}")
            if hasattr(tool, "version"):
                st.text(f"Version: {tool.version}")
            if hasattr(tool, "executable_name"):
                st.text(f"Executable: {tool.executable_name}")


def _handle_no_scanner_selected() -> bool:
    """Handle UI state when no scanner is selected.

    :return: True if handled (stop processing), False to continue
    """
    selected_scanner = get_query_param(QueryParam.SelectedScanner, None)

    if selected_scanner:
        return False  # Continue processing

    st.warning("🔍 **No scanner selected**")
    st.markdown("**Please select a scanner to analyze:**")

    # Show available scanners for selection
    available_scanners = list(SCANNERS.keys())
    if available_scanners:
        selected = st.selectbox("Choose scanner:", available_scanners, key="scanner_select")
        if st.button("Analyze Scanner"):
            st.query_params[QueryParam.SelectedScanner] = selected
            st.rerun()
    else:
        st.markdown("No scanners available.")
    return True  # Handled, stop processing


def _get_scanner_tool(selected_scanner: str) -> tuple[Optional[str], Optional[object]]:
    """Retrieve scanner tool object with case-insensitive lookup.

    :param selected_scanner: Scanner name to search for
    :return: Tuple of (correct_scanner_name, tool_instance) or (None, None)
    """
    tool = SCANNERS.get(selected_scanner)
    if tool:
        return selected_scanner, tool

    # Try case variations
    for name, scanner in SCANNERS.items():
        if name.lower() == selected_scanner.lower():
            return name, scanner

    return None, None


def _handle_scanner_not_found(selected_scanner: str) -> None:
    """Display error message and available scanners when requested scanner is not found."""
    st.error(f"❌ **Scanner '{selected_scanner}' not found**")
    st.markdown("**Available scanners:** " + ", ".join(SCANNERS.keys()))


def _show_no_benchmark_data(selected_scanner: str) -> None:
    """Display guidance for generating benchmark data when none exists."""
    st.warning(f"🔍 **No benchmark evaluation data for {selected_scanner}**")
    st.markdown(
        f"""
    **To evaluate {selected_scanner} against benchmarks:**

    1. **Generate benchmark manifests**:
       ```bash
       poetry run cli generate
       ```

    2. **Run benchmark scan**:
       ```bash
       poetry run cli scan {selected_scanner.lower()} -f manifests
       ```

    3. **Create evaluation**:
       ```bash
       poetry run cli evaluate {selected_scanner.lower()}
       ```
    """
    )

    # Still show scan buttons for user convenience
    st.markdown("---")
    show_scan_buttons(selected_scanner)


def _format_scan_options(benchmark_scan_runs: list) -> list:
    """Convert scan run data into formatted display options for selection."""
    scan_options = []
    for run in benchmark_scan_runs:
        timestamp_display = format_scan_timestamp(run.get("timestamp", ""))
        scan_age = calculate_scan_age(run.get("timestamp", ""))
        total_results = run.get("total_results", 0)

        option_text = f"{timestamp_display} ({scan_age}) - {total_results} results"
        scan_options.append((option_text, run.get("id", "")))

    return scan_options


def _show_scan_selection_and_results(unified_service, selected_scanner: str, tool, benchmark_scan_runs: list) -> None:
    """Render scan selection interface and display detailed evaluation results."""
    st.markdown("---")
    st.subheader("📋 Scan Selection")

    scan_options = _format_scan_options(benchmark_scan_runs)

    if scan_options:
        selected_option = st.selectbox(
            "Select benchmark scan to analyze:",
            options=range(len(scan_options)),
            format_func=lambda x: scan_options[x][0],
            help="Choose which benchmark evaluation to analyze in detail",
        )

        selected_scan_id = scan_options[selected_option][1]

        # Show detailed evaluation results for selected scan
        st.markdown("---")
        show_tool_evaluation_results(
            unified_service=unified_service,
            tool_name=selected_scanner,
            tool=tool,
            scan_run_id=selected_scan_id,
            evaluation_mode="benchmark",  # Force benchmark evaluation mode
        )


def show():
    """Main function to display the benchmark scanner analysis page.

    :return: None
    """
    # Handle case when no scanner is selected
    if _handle_no_scanner_selected():
        return

    selected_scanner = get_query_param(QueryParam.SelectedScanner, None)

    # Get scanner tool object
    scanner_name, tool = _get_scanner_tool(selected_scanner)
    if not tool:
        _handle_scanner_not_found(selected_scanner)
        return

    selected_scanner = scanner_name  # Use the correctly cased name

    # Show scanner header
    show_benchmark_scanner_header(selected_scanner, tool)

    # Analysis scope section
    st.subheader("🎯 Analysis Scope")
    st.info("📊 **Benchmark Analysis Mode** - Analyzing scanner performance against KALM's 235+ vulnerable manifests")

    # Get scan runs for this scanner (benchmark only)
    unified_service = get_unified_service()
    benchmark_scan_runs = _get_benchmark_scan_runs_for_tool(selected_scanner)

    if not benchmark_scan_runs:
        _show_no_benchmark_data(selected_scanner)
        return

    # Show scan selection and results
    _show_scan_selection_and_results(unified_service, selected_scanner, tool, benchmark_scan_runs)

    # Historical analysis section
    st.markdown("---")
    show_benchmark_historical_analysis(unified_service, selected_scanner)

    # Scan management
    st.markdown("---")
    show_scan_buttons(selected_scanner)


def show_benchmark_historical_analysis(unified_service, tool_name: str):
    """Display historical trend analysis for benchmark scans with performance metrics.

    :param unified_service: Service instance for database access
    :param tool_name: Name of the scanner to analyze
    :return: None
    """
    with st.expander("📈 Historical Analysis & Trends", expanded=False):
        hist_tab1, hist_tab2 = st.tabs(["📊 Benchmark Trends", "⚡ Performance Trends"])

        with hist_tab1:
            st.markdown("**Benchmark Scan History**")
            render_historical_scan_trends(unified_service, source_type=ScanSourceType.BENCHMARK, chart_name=None)

        with hist_tab2:
            st.markdown(f"**{tool_name} Benchmark Performance Over Time**")
            render_scanner_performance_trends(unified_service, tool_name, source_type=ScanSourceType.BENCHMARK)


if __name__ == "__main__":
    show()
