from pathlib import Path

import streamlit as st

from kalm_benchmark.evaluation.scanner_manager import SCANNERS
from kalm_benchmark.ui.constants import QueryParam, SessionKeys
from kalm_benchmark.ui.logging_config import get_ui_logger
from kalm_benchmark.ui.scanner_details.evaluation_result import (
    show_tool_evaluation_results,
)
from kalm_benchmark.ui.scanner_details.scan import show_scan_buttons
from kalm_benchmark.ui.utils import get_query_param, init, get_result_files_of_scanner


def show_scanner_header(tool_name: str, tool):
    """Show header for the scanner details page."""
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.markdown(f"""
        <div style="margin-bottom: 1rem;">
            <h1 style="color: #1f77b4; margin-bottom: 0;">🔍 {tool_name}</h1>
            <p style="color: #666; margin: 0;">Security Scanner Analysis & Control</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        # Scanner capabilities
        capabilities = []
        if tool.can_scan_cluster:
            capabilities.append("🌐 Cluster")
        if tool.can_scan_manifests:
            capabilities.append("📁 Manifests")
        if tool.CI_MODE:
            capabilities.append("🔄 CI/CD")
        
        if capabilities:
            st.markdown("**Capabilities:**")
            for cap in capabilities:
                st.markdown(f"✅ {cap}")
    
    with col3:
        # Quick stats about results
        result_files = get_result_files_of_scanner(tool_name)
        st.metric("Result Files", len(result_files))
        
        if result_files:
            latest_file = sorted(result_files)[-1]
            st.markdown(f"**Latest:** `{Path(latest_file).name}`")


def show_scanner_info(tool) -> None:
    """Show scanner information and notes."""
    if tool.NOTES:
        with st.expander("ℹ️ Important Notes", expanded=True):
            for note in tool.NOTES:
                st.warning(note)
    
    # Scanner metadata
    with st.expander("📋 Scanner Details", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Configuration:**")
            st.markdown(f"• **CI Mode:** {'✅ Yes' if tool.CI_MODE else '❌ No'}")
            st.markdown(f"• **Custom Checks:** {tool.CUSTOM_CHECKS}")
            st.markdown(f"• **Runs Offline:** {tool.RUNS_OFFLINE}")
        
        with col2:
            st.markdown("**Output Formats:**")
            if tool.FORMATS:
                for fmt in tool.FORMATS:
                    st.markdown(f"• {fmt}")
            else:
                st.markdown("• *Not specified*")


def show_recent_activity(tool_name: str):
    """Show recent scan activity for the scanner."""
    data_dir = Path(st.session_state.get(SessionKeys.DataDir, "./data"))
    ui_logger = get_ui_logger(data_dir)
    
    with st.expander("📜 Recent Activity", expanded=False):
        recent_logs = ui_logger.get_recent_scan_logs(tool_name, limit=10)
        
        if recent_logs:
            st.markdown("**Recent scan activities:**")
            for log in recent_logs[-5:]:  # Show last 5 entries
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
    # if specified, use tool from query parameter as default selection
    selected_tool = get_query_param(QueryParam.SelectedScanner, scanners[0])
    st.session_state[key] = selected_tool

    # Sidebar scanner selection
    with st.sidebar:
        st.markdown("### 🔧 Scanner Selection")
        tool = st.selectbox(
            "Choose Scanner:", 
            scanners, 
            key=key, 
            on_change=_on_change,
            help="Select a scanner to view its details and run scans"
        )
        
        st.markdown("---")
        
        # Sidebar scan controls
        scanner_obj = SCANNERS.get(tool)
        if scanner_obj:
            show_scan_buttons(scanner_obj)
            
        st.markdown("---")
        
        # Recent activity in sidebar
        show_recent_activity(tool)

    # Main content area
    scanner_obj = SCANNERS.get(tool)
    if not scanner_obj:
        st.error(f"Scanner '{tool}' not found!")
        return
    
    show_scanner_header(tool, scanner_obj)
    
    show_scanner_info(scanner_obj)
    
    st.markdown("---")
    
    tab1, tab2, tab3 = st.tabs(["📊 Results & Analysis", "🔍 Scan History", "⚙️ Configuration"])
    
    with tab1:
        st.markdown("### 📈 Evaluation Results")
        show_tool_evaluation_results(tool)
    
    with tab2:
        show_scan_history_tab(tool)
    
    with tab3:
        show_configuration_tab(scanner_obj)


def show_scan_history_tab(tool_name: str):
    """Show scan history and management."""
    st.markdown("### 📁 Scan Results History")
    
    result_files = get_result_files_of_scanner(tool_name)
    
    if not result_files:
        st.info("🔍 No scan results found. Run a scan to see results here.")
        return
    
    # Display results in a nice format
    for i, file_path in enumerate(sorted(result_files)):
        file_obj = Path(file_path)
        
        with st.expander(f"📄 {file_obj.name}", expanded=(i == len(result_files) - 1)):
            col1, col2, col3 = st.columns([2, 1, 1])
            
            with col1:
                st.markdown(f"**File:** `{file_obj.name}`")
                st.markdown(f"**Path:** `{file_obj.parent}`")
                
                try:
                    stat = file_obj.stat()
                    size_mb = stat.st_size / (1024 * 1024)
                    st.markdown(f"**Size:** {size_mb:.2f} MB")
                    
                    import datetime
                    mod_time = datetime.datetime.fromtimestamp(stat.st_mtime)
                    st.markdown(f"**Modified:** {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
                except FileNotFoundError:
                    st.markdown("**Status:** File information unavailable")
            
            with col2:
                if st.button("📊 Analyze", key=f"analyze_{i}"):
                    st.info("Analysis feature coming soon!")
            
            with col3:
                if st.button("🗑️ Delete", key=f"delete_{i}"):
                    try:
                        file_obj.unlink()
                        st.success(f"Deleted {file_obj.name}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to delete: {e}")


def show_configuration_tab(scanner):
    """Show scanner configuration and settings."""
    st.markdown("### ⚙️ Scanner Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔧 Scan Settings")
        
        # Scanner-specific settings
        st.markdown(f"**Scanner Name:** `{scanner.NAME}`")
        st.markdown(f"**CI Mode Support:** {'✅ Yes' if scanner.CI_MODE else '❌ No'}")
        st.markdown(f"**Custom Checks:** {scanner.CUSTOM_CHECKS}")
        st.markdown(f"**Offline Capable:** {scanner.RUNS_OFFLINE}")
        st.markdown(f"**Scan Per File:** {'✅ Yes' if scanner.SCAN_PER_FILE else '❌ No'}")
        
        if scanner.FORMATS:
            st.markdown(f"**Output Formats:** {', '.join(scanner.FORMATS)}")
    
    with col2:
        st.markdown("#### 📝 Commands")
        
        if scanner.SCAN_CLUSTER_CMD:
            st.markdown("**Cluster Scan Command:**")
            st.code(' '.join(scanner.SCAN_CLUSTER_CMD))
        
        if scanner.SCAN_MANIFESTS_CMD:
            st.markdown("**Manifest Scan Command:**")
            st.code(' '.join(scanner.SCAN_MANIFESTS_CMD))
        
        if scanner.VERSION_CMD:
            st.markdown("**Version Command:**")
            st.code(' '.join(scanner.VERSION_CMD))


if __name__ == "__main__":
    init()
    show()
