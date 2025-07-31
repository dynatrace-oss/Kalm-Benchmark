from datetime import datetime
from pathlib import Path

import streamlit as st

from kalm_benchmark.constants import RunUpdateGenerator, UpdateType
from kalm_benchmark.evaluation.scanner.scanner_evaluator import ScannerBase
from kalm_benchmark.ui.constants import (
    LAST_SCAN_OPTION,
    SELECTED_RESULT_FILE,
    SessionKeys,
)
from kalm_benchmark.ui.logging_config import get_ui_logger


def show_scan_buttons(tool: ScannerBase) -> None:
    """Show scan buttons supported by the specified tool
    :param tool: the tool for which the scans can be triggered
    """
    with st.sidebar:
        st.markdown("### 🔍 Start New Scan")
        
        data_dir = Path(st.session_state.get(SessionKeys.DataDir, "./data"))
        ui_logger = get_ui_logger(data_dir)
        
        source = None
        gen = None
        
        # Cluster scan section
        if tool.can_scan_cluster:
            with st.expander("🌐 Cluster Scan", expanded=True):
                st.markdown("Scan resources directly from a Kubernetes cluster")
                
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown("**Current Context:** `kubectl config current-context`")
                with col2:
                    if st.button("🚀 Start", key="cluster_scan", type="primary"):
                        ui_logger.log_ui_action("cluster_scan_initiated", f"Tool: {tool.NAME}")
                        gen = tool.scan_cluster()
                        source = "cluster"
        
        # Manifest scan section  
        if tool.can_scan_manifests:
            with st.expander("📁 Manifest Scan", expanded=True):
                st.markdown("Scan YAML manifest files or directories")
                
                # Path input with validation
                path_input = st.text_input(
                    "Manifest Path:",
                    value="manifests",
                    help="Path to manifest files or directory containing YAML files"
                )
                path = Path(path_input)
                
                # Path validation feedback
                if path_input:
                    if path.exists():
                        if path.is_file():
                            st.success(f"✅ File found: `{path.name}`")
                        elif path.is_dir():
                            yaml_files = list(path.glob("*.yaml")) + list(path.glob("*.yml"))
                            st.success(f"✅ Directory found with {len(yaml_files)} YAML files")
                        else:
                            st.warning("⚠️ Path exists but is neither a file nor directory")
                    else:
                        st.error("❌ Path does not exist!")
                        st.info("💡 **Tip:** Run `poetry run cli generate` to create manifest files")
                
                # Scan button with proper state
                col1, col2 = st.columns([3, 1])
                with col1:
                    scan_enabled = path.exists()
                    if not scan_enabled:
                        st.markdown("*Please provide a valid path to enable scanning*")
                with col2:
                    if st.button(
                        "🚀 Start", 
                        key="manifest_scan", 
                        type="primary",
                        disabled=not scan_enabled
                    ):
                        ui_logger.log_ui_action("manifest_scan_initiated", f"Tool: {tool.NAME}, Path: {path}")
                        source = "manifest(s)"
                        gen = tool.scan_manifests(path.resolve())
                        # Update result file selection to latest scan
                        SEL_FILE_KEY = f"{tool.NAME}_{SELECTED_RESULT_FILE}"
                        st.session_state[SEL_FILE_KEY] = LAST_SCAN_OPTION
        
        # Show scan capabilities info
        st.markdown("---")
        st.markdown("### 📊 Scanner Capabilities")
        
        capabilities = []
        if tool.can_scan_cluster:
            capabilities.append("🌐 Cluster Scanning")
        if tool.can_scan_manifests:
            capabilities.append("📁 Manifest Scanning")
        
        if capabilities:
            for cap in capabilities:
                st.markdown(f"✅ {cap}")
        else:
            st.warning("⚠️ No scan capabilities available for this tool")

    # Execute scan if initiated
    if source is not None and gen is not None:
        show_scan_ui(tool, source, gen)


def show_scan_ui(tool: ScannerBase, source: str, generator: RunUpdateGenerator) -> None:
    """Show the UI elements for an ongoing scan with centralized logging

    :param tool: the tool for which the scan is started
    :param source: a string specifying the source of the scan
    :param generator: the generator yielding updates/results for the ongoing scan
    """
    # Get data directory and initialize logger
    data_dir = Path(st.session_state.get(SessionKeys.DataDir, "./data"))
    ui_logger = get_ui_logger(data_dir)
    
    ui_logger.log_scan_start(tool.NAME, source)
    
    # Progress tracking containers
    progress_container = st.container()
    status_container = st.container()
    
    with progress_container:
        progress_bar = st.progress(0.0, text=f"Initializing scan of {source}...")
        scan_status = st.empty()
    
    scan_success = False
    result_file = None
    error_messages = []
    
    try:
        step_count = 0
        while update := next(generator):
            update_type, msg = update
            if msg is None or len(msg.strip()) == 0:
                continue
                
            step_count += 1
            
            # Log to file instead of UI
            match update_type:
                case UpdateType.Warning:
                    ui_logger.log_scan_progress(tool.NAME, msg, "warning")
                    scan_status.warning(f"⚠️ {msg}")
                case UpdateType.Error:
                    ui_logger.log_scan_error(tool.NAME, msg)
                    scan_status.error(f"❌ {msg}")
                    error_messages.append(msg)
                case UpdateType.Progress:
                    ui_logger.log_scan_progress(tool.NAME, msg, "info")
                    progress_bar.progress(min(step_count * 0.1, 0.9), text=msg)
                case _:
                    ui_logger.log_scan_progress(tool.NAME, msg, "info")
                    scan_status.info(f"ℹ️ {msg}")
    
    except StopIteration as exc:
        # Scan completed - handle results
        progress_bar.progress(1.0, text="Scan completed!")
        
        if exc.value is not None:
            scan_success = True
            st.session_state[SessionKeys.LatestScanResult][tool.NAME] = exc.value
            
            # Save the scan results
            data_dir.mkdir(parents=True, exist_ok=True)
            version = tool.get_version() or "?"
            date = datetime.now().strftime("%Y-%m-%d")
            suffix = "json" if "json" in [f.lower() for f in tool.FORMATS] else "txt"
            # ensure resulting files are written as lowercase for consistency
            result_file = data_dir / f"{tool.NAME.lower()}_v{version}_{date}.{suffix}"
            
            try:
                tool.save_results(exc.value, result_file)
                ui_logger.log_scan_complete(tool.NAME, True, result_file)
                
                with status_container:
                    st.success(f"✅ Scan completed successfully! Results saved to `{result_file}`")
                    
                    # Show scan summary
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Scanner", tool.NAME)
                    with col2:
                        st.metric("Results", len(exc.value) if isinstance(exc.value, list) else "Generated")
                    with col3:
                        st.metric("Source", source)
                        
            except Exception as e:
                error_msg = f"Failed to save results to {result_file}: {e}"
                ui_logger.log_scan_error(tool.NAME, error_msg)
                st.error(f"❌ {error_msg}")
                scan_success = False
        else:
            ui_logger.log_scan_complete(tool.NAME, False)
            st.warning("⚠️ Scan completed but no results were generated")
    
    # Show log file info and errors summary
    with st.expander("📋 Scan Details", expanded=False):
        log_files = ui_logger.get_log_files()
        st.info(f"📁 Detailed logs saved to: `{log_files['scan_logs']}`")
        
        if error_messages:
            st.error("**Errors encountered during scan:**")
            for error in error_messages:
                st.text(f"• {error}")
        
        # Option to view recent logs
        if st.button("View Recent Logs", key=f"logs_{tool.NAME}"):
            recent_logs = ui_logger.get_recent_scan_logs(tool.NAME, limit=20)
            if recent_logs:
                st.text_area("Recent Log Entries", "\n".join(recent_logs), height=200)
            else:
                st.info("No recent logs found")
    
    # Auto-refresh page
    if scan_success:
        st.balloons()
        # Small delay to show success message before refresh
        import time
        time.sleep(1)
        st.rerun()
