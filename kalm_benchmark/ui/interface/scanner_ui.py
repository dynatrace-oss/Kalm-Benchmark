import streamlit as st

from kalm_benchmark.ui.interface.gen_utils import (
    calculate_scan_age,
    format_scan_timestamp,
)


def build_scan_options(scan_runs: list[dict[str, any]], detailed: bool = False) -> list[tuple[str, str]]:
    """Build formatted options for scan selection dropdown.

    :param scan_runs: List of scan run dictionaries containing metadata
    :param detailed: Whether to include detailed information like result counts
    :return: List of tuples containing (display_text, scan_id) for dropdown options
    """
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


def render_scan_metrics(selected_scan: dict[str, any]) -> None:
    """Render scan metrics display in a three-column layout.

    :param selected_scan: Dictionary containing scan metadata and results
    :return: None
    """
    col_a, col_b, col_c = st.columns(3)

    with col_a:
        st.metric(
            "Findings",
            selected_scan.get("total_results", 0),
            help="Total security findings detected",
        )

    with col_b:
        scanner_version = selected_scan.get("scanner_version", "Unknown")
        st.metric("Scanner Ver.", scanner_version, help="Version of the scanner used")

    with col_c:
        age_text = calculate_scan_age(selected_scan.get("timestamp", ""))
        st.metric("Scan Age", age_text, help="How long ago this scan was performed")


def render_scan_target_info(selected_scan: dict[str, any]) -> None:
    """Render scan target information with formatted display.

    :param selected_scan: Dictionary containing scan metadata including source information
    :return: None
    """
    source_info = selected_scan.get("source_type", "Unknown")
    if ":" in source_info:
        source_type, source_name = source_info.split(":", 1)
        st.info(f"🎯 **Scan Target**: {source_name} ({source_type})")
    else:
        st.info(f"🎯 **Scan Target**: {source_info}")


def render_no_scans_message() -> None:
    """Render informational message and guidance when no scans are available.

    :return: None
    """
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


def render_scan_summary_stats(scan_runs: list[dict[str, any]]) -> None:
    """Render summary statistics for scan history when multiple scans exist.

    :param scan_runs: List of scan run dictionaries to summarize
    :return: None
    """
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


def get_latest_scan_text(scan_runs: list[dict[str, any]]) -> str:
    """Get formatted text representation of the most recent scan timestamp.

    :param scan_runs: List of scan run dictionaries (assumed to be sorted by timestamp)
    :return: Formatted timestamp string or fallback text if unavailable
    """
    if not scan_runs:
        return "None"

    try:
        latest_run = scan_runs[0]
        timestamp = latest_run["timestamp"]
        return format_scan_timestamp(timestamp)
    except Exception:
        return "Unknown"


def render_evaluation_error(error: Exception, raw_results: any) -> None:
    """Render detailed error information for scan result processing failures.

    :param error: Exception that occurred during processing
    :param raw_results: Raw scan results that caused the error
    :return: None
    """
    st.error(f"Error processing scan results: {error}")
    st.markdown(f"**Raw results type:** {type(raw_results)}")
    st.markdown("**Raw results length:** " f"{len(raw_results) if hasattr(raw_results, '__len__') else 'N/A'}")

    if raw_results and len(raw_results) > 0:
        st.markdown(f"**First result type:** {type(raw_results[0])}")
        if hasattr(raw_results[0], "__dict__"):
            st.json(raw_results[0].__dict__)


def render_header_gradient_section(tool_name: str, icon_html: str) -> None:
    """Render an attractive header section with gradient background and scanner branding.

    :param tool_name: Name of the scanner tool to display
    :param icon_html: HTML string containing the scanner icon
    :return: None
    """
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
