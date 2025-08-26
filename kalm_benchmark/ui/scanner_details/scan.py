from pathlib import Path
from typing import Optional, Tuple

import streamlit as st

from kalm_benchmark.evaluation.scanner.scanner_evaluator import ScannerBase
from kalm_benchmark.ui.logging_config import get_ui_logger
from kalm_benchmark.ui.utils.gen_utils import get_unified_service
from kalm_benchmark.utils.constants import (
    LAST_SCAN_OPTION,
    SELECTED_RESULT_FILE,
    RunUpdateGenerator,
    SessionKeys,
    UpdateType,
)


def _get_kubectl_context() -> str:
    """Get current kubectl context or default."""
    try:
        import subprocess
        
        result = subprocess.run(
            ["kubectl", "config", "current-context"], 
            capture_output=True, 
            text=True, 
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "cluster"


def _resolve_project_path(path_input: str) -> Path:
    """Resolve path relative to project root if needed."""
    path = Path(path_input)
    
    if not path.is_absolute():
        current_file = Path(__file__)
        project_root = current_file
        while project_root.parent != project_root:
            if (project_root / "pyproject.toml").exists():
                break
            project_root = project_root.parent
        path = project_root / path_input
    
    return path


def _validate_manifest_path(path: Path) -> Tuple[bool, Optional[str]]:
    """Validate manifest path and return status with message."""
    if not path.exists():
        return False, "❌ Path does not exist!"
    
    if path.is_file():
        return True, f"✅ File found: `{path.name}`"
    elif path.is_dir():
        yaml_files = list(path.glob("*.yaml")) + list(path.glob("*.yml"))
        return True, f"✅ Directory found with {len(yaml_files)} YAML files"
    else:
        return False, "⚠️ Path exists but is neither a file nor directory"


def _validate_helm_chart_path(chart_path: Path) -> Tuple[bool, str]:
    """Validate Helm chart path."""
    if not chart_path.exists() or not chart_path.is_dir():
        return False, "❌ Chart directory does not exist!"
    
    if (chart_path / "Chart.yaml").exists() or (chart_path / "Chart.yml").exists():
        return True, f"✅ Valid Helm chart found: `{chart_path.name}`"
    else:
        return False, "⚠️ Directory found but no Chart.yaml detected"


def _extract_helm_chart_name(chart_url: str) -> Optional[str]:
    """Extract Helm chart name from Artifact Hub URL."""
    try:
        parts = chart_url.split("/")
        if "artifacthub.io" in chart_url and len(parts) >= 6:
            repo_name = parts[-2]
            chart_name = parts[-1]
            return f"{repo_name}-{chart_name}"
    except Exception:
        pass
    return None


def _render_cluster_scan_section(tool: ScannerBase, ui_logger) -> Optional[Tuple[str, RunUpdateGenerator]]:
    """Render cluster scan UI section."""
    with st.expander("🌐 Cluster Scan", expanded=True):
        st.markdown("Scan resources directly from a Kubernetes cluster")
        
        default_cluster_name = _get_kubectl_context()
        
        if default_cluster_name != "cluster":
            st.success(f"✅ Current context: `{default_cluster_name}`")
        else:
            st.warning("⚠️ kubectl not available or unable to get context")
        
        col_context, col_name = st.columns([2, 1])
        with col_context:
            st.markdown("**Kubernetes Context:**")
            st.code(f"kubectl config current-context → {default_cluster_name}")
        
        with col_name:
            cluster_name = st.text_input(
                "Cluster Name:",
                value=default_cluster_name,
                help="Name to identify this cluster scan (defaults to kubectl context)",
            )
        
        col1, col2 = st.columns([3, 1])
        with col1:
            scan_enabled = cluster_name.strip()
            if not scan_enabled:
                st.markdown("*Please provide a cluster name*")
        
        with col2:
            if st.button("🚀 Start", key="cluster_scan", type="primary", disabled=not scan_enabled):
                ui_logger.log_ui_action("cluster_scan_initiated", f"Tool: {tool.NAME}, Cluster: {cluster_name}")
                gen = tool.scan_cluster()
                source = f"cluster:{cluster_name}"
                st.session_state[f"{tool.NAME}_cluster_name"] = cluster_name
                return source, gen
    
    return None


def _render_manifest_scan_section(tool: ScannerBase, ui_logger) -> Optional[Tuple[str, RunUpdateGenerator]]:
    """Render manifest scan UI section."""
    with st.expander("📁 Manifest Scan", expanded=True):
        st.markdown("Scan YAML manifest files or directories")
        
        col_path, col_name = st.columns([2, 1])
        with col_path:
            path_input = st.text_input(
                "Manifest Path:",
                value="manifests",
                help="Path to manifest files or directory containing YAML files",
            )
        
        with col_name:
            default_name = Path(path_input).name if path_input else "manifests"
            manifest_name = st.text_input(
                "Scan Name:",
                value=default_name,
                help="Unique name for this manifest scan (for filtering and identification)",
            )
        
        path = _resolve_project_path(path_input)
        
        if path_input:
            is_valid, message = _validate_manifest_path(path)
            if is_valid:
                st.success(message)
            else:
                st.error(message)
                if not path.exists():
                    st.info(f"💡 **Looking for:** `{path.resolve()}`")
                    st.info("💡 **Tip:** Run `poetry run cli generate` to create manifest files")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            scan_enabled = path.exists() and manifest_name.strip()
            if not scan_enabled:
                if not path.exists():
                    st.markdown("*Please provide a valid path to enable scanning*")
                elif not manifest_name.strip():
                    st.markdown("*Please provide a scan name to enable scanning*")
        
        with col2:
            if st.button("🚀 Start", key="manifest_scan", type="primary", disabled=not scan_enabled):
                ui_logger.log_ui_action(
                    "manifest_scan_initiated", f"Tool: {tool.NAME}, Path: {path}, Name: {manifest_name}"
                )
                source = f"manifests:{manifest_name}"
                gen = tool.scan_manifests(path.resolve())
                st.session_state[f"{tool.NAME}_manifest_name"] = manifest_name
                SEL_FILE_KEY = f"{tool.NAME}_{SELECTED_RESULT_FILE}"
                st.session_state[SEL_FILE_KEY] = LAST_SCAN_OPTION
                return source, gen
    
    return None


def _render_helm_artifact_hub_inputs() -> Tuple[bool, str, str]:
    """Render Artifact Hub chart inputs."""
    chart_url = st.text_input(
        "Artifact Hub Chart URL:",
        value="",
        placeholder="https://artifacthub.io/packages/helm/...",
        help="Direct URL to a helm chart from Artifact Hub",
    )
    
    helm_name = ""
    if chart_url:
        helm_name = _extract_helm_chart_name(chart_url)
        if helm_name:
            st.success(f"✅ Chart name extracted: `{helm_name}`")
        else:
            st.warning("⚠️ Unable to extract chart name from URL")
    
    return bool(chart_url and helm_name), helm_name, chart_url


def _render_helm_popular_charts_inputs() -> Tuple[bool, str, int]:
    """Render popular charts inputs."""
    col1, col2 = st.columns([1, 2])
    with col1:
        num_charts = st.number_input(
            "Number of charts:",
            min_value=1,
            max_value=500,
            value=10,
            help="Number of top popular charts to scan (1-500)",
        )
    
    with col2:
        st.markdown("**Research Mode:**")
        st.markdown(f"Will download and scan top {num_charts} popular charts from Artifact Hub")
        st.info("💡 Chart names will be automatically extracted from metadata")
    
    helm_name = f"top-{num_charts}-charts"
    return True, helm_name, num_charts


def _render_helm_local_chart_inputs() -> Tuple[bool, str, str]:
    """Render local chart inputs."""
    col_path, col_name = st.columns([2, 1])
    with col_path:
        chart_path_input = st.text_input(
            "Local Chart Path:", 
            value="./charts/my-app", 
            help="Path to local helm chart directory"
        )
    
    with col_name:
        default_name = Path(chart_path_input).name if chart_path_input else "local-chart"
        helm_name = st.text_input(
            "Chart Name:", 
            value=default_name, 
            help="Unique name for this local helm chart"
        )
    
    chart_path = _resolve_project_path(chart_path_input)
    
    if chart_path_input:
        is_valid, message = _validate_helm_chart_path(chart_path)
        if is_valid:
            st.success(message)
        else:
            st.error(message)
            st.info(f"💡 **Looking for:** `{chart_path.resolve()}`)")
    
    scan_enabled = bool(chart_path_input and helm_name.strip() and chart_path.exists())
    return scan_enabled, helm_name, chart_path_input


def _render_helm_scan_section(tool: ScannerBase, ui_logger) -> Optional[Tuple[str, RunUpdateGenerator]]:
    """Render Helm chart scan UI section."""
    with st.expander("⚓ Helm Chart Scan", expanded=False):
        st.markdown("Scan Helm charts by rendering them to manifests first")
        st.info("📋 **Note:** Requires `helm` CLI to be installed")
        
        scan_type = st.radio(
            "Select Helm Chart Source:",
            options=[
                "🌐 Artifact Hub Chart (by URL)",
                "📊 Top Popular Charts (research)",
                "📁 Local Chart Directory",
            ],
            help="Choose how you want to specify the helm chart(s) to scan",
        )
        
        chart_url = ""
        num_charts = 0
        chart_path_input = ""
        
        if scan_type == "🌐 Artifact Hub Chart (by URL)":
            scan_enabled, helm_name, chart_url = _render_helm_artifact_hub_inputs()
        elif scan_type == "📊 Top Popular Charts (research)":
            scan_enabled, helm_name, num_charts = _render_helm_popular_charts_inputs()
        else:  # Local Chart Directory
            scan_enabled, helm_name, chart_path_input = _render_helm_local_chart_inputs()
        
        col1, col2 = st.columns(2)
        with col1:
            release_name = st.text_input(
                "Release Name:", value="test-release", help="Name for the Helm release"
            )
        with col2:
            _ = st.text_input(
                "Namespace:", value="default", help="Kubernetes namespace for the release"
            )
        
        col1, col2 = st.columns([3, 1])
        with col1:
            if not scan_enabled:
                st.markdown("*Please provide valid chart information to enable scanning*")
            elif not release_name:
                st.markdown("*Please provide a release name*")
        
        with col2:
            if st.button(
                "⚓ Render & Scan",
                key="helm_scan",
                type="secondary",
                disabled=not (scan_enabled and release_name),
            ):
                ui_logger.log_ui_action(
                    "helm_scan_initiated", f"Tool: {tool.NAME}, Type: {scan_type}, Name: {helm_name}"
                )
                st.session_state[f"{tool.NAME}_helm_name"] = helm_name
                st.session_state[f"{tool.NAME}_helm_type"] = scan_type
                
                if scan_type == "🌐 Artifact Hub Chart (by URL)":
                    st.session_state[f"{tool.NAME}_helm_url"] = chart_url
                elif scan_type == "📊 Top Popular Charts (research)":
                    st.session_state[f"{tool.NAME}_helm_count"] = num_charts
                else:
                    st.session_state[f"{tool.NAME}_helm_path"] = chart_path_input
                
                st.warning(
                    "🚧 Helm chart scanning is under development. Please use the CCSS page for helm chart evaluation."
                )
                # Note: This would need actual implementation
                # return source, gen
    
    return None


def show_scan_buttons(tool: ScannerBase) -> None:
    """Main function to render scan buttons with reduced complexity."""
    with st.sidebar:
        st.markdown("### 🔍 Start New Scan")
        
        data_dir = Path(st.session_state.get(SessionKeys.DataDir, "./data"))
        ui_logger = get_ui_logger(data_dir)
        
        scan_result = None
        
        if tool.can_scan_cluster:
            scan_result = _render_cluster_scan_section(tool, ui_logger)
        
        if tool.can_scan_manifests and not scan_result:
            scan_result = _render_manifest_scan_section(tool, ui_logger)
        
        if tool.can_scan_manifests and not scan_result:
            scan_result = _render_helm_scan_section(tool, ui_logger)
        
        if not (tool.can_scan_cluster or tool.can_scan_manifests):
            st.markdown("---")
            st.warning("⚠️ No scan capabilities available for this tool")
        
        if scan_result:
            source, gen = scan_result
            show_scan_ui(tool, source, gen)


def _process_scan_updates(generator: RunUpdateGenerator, tool: ScannerBase, progress_bar, scan_status, ui_logger) -> list[str]:
    """Process scan updates from generator."""
    error_messages = []
    step_count = 0
    
    while update := next(generator):
        update_type, msg = update
        if msg is None or len(msg.strip()) == 0:
            continue
        
        step_count += 1
        
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
    
    return error_messages


def _process_scan_results(tool: ScannerBase, results, ui_logger):
    """Process and convert scan results."""
    if not results or len(results) == 0:
        return []
    
    first_item = results[0] if isinstance(results, list) else results
    
    ui_logger.log_ui_action(
        "debug_scan_results",
        f"Tool: {tool.NAME}, Result type: {type(results)}, Length: {len(results) if hasattr(results, '__len__') else 'N/A'}",
    )
    
    if isinstance(first_item, str) or not hasattr(first_item, "check_id"):
        ui_logger.log_ui_action(
            "scan_results_conversion",
            f"Tool: {tool.NAME}, Converting raw results using parse_results method",
        )
        
        try:
            processed_results = tool.parse_results(results)
            ui_logger.log_ui_action(
                "scan_results_parsed", f"Tool: {tool.NAME}, Parsed {len(processed_results)} results"
            )
            return processed_results
        except Exception as parse_error:
            ui_logger.log_scan_error(tool.NAME, f"Failed to parse results: {parse_error}")
            return _create_fallback_results(tool, results)
    else:
        return results


def _create_fallback_results(tool: ScannerBase, results):
    """Create fallback CheckResult objects for unparseable results."""
    from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckResult
    
    fallback_results = []
    for i, item in enumerate(results):
        fallback_results.append(
            CheckResult(
                check_id=f"raw_{i}",
                obj_name="unknown",
                scanner_check_id=f"{tool.NAME.lower()}_{i}",
                scanner_check_name=str(item)[:100] if item else "empty",
                got="unknown",
                expected="unknown",
            )
        )
    return fallback_results


def _save_scan_results_to_db(tool: ScannerBase, results, source: str, ui_logger) -> Optional[str]:
    """Save scan results to database."""
    try:
        unified_service = get_unified_service()
        version = tool.get_version() or "unknown"
        
        if ":" in source:
            _, source_name = source.split(":", 1)
        else:
            source_name = source
        
        processed_results = _process_scan_results(tool, results, ui_logger)
        
        scan_run_id = unified_service.save_scanner_results(
            scanner_name=tool.NAME.lower(), 
            results=processed_results, 
            scanner_version=version, 
            source_file=None
        )
        
        # Update scan run with source information
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE scan_runs 
                SET source_type = ?, source_location = ?
                WHERE id = ?
            """,
                (source, source_name, scan_run_id),
            )
            conn.commit()
        
        ui_logger.log_scan_complete(tool.NAME, True, f"database:{scan_run_id}")
        ui_logger.log_ui_action(
            "database_save_complete", f"Tool: {tool.NAME}, Source: {source}, ID: {scan_run_id}"
        )
        
        return scan_run_id
    except Exception as e:
        error_msg = f"Failed to save results to database: {e}"
        ui_logger.log_scan_error(tool.NAME, error_msg)
        st.error(f"❌ {error_msg}")
        return None


def _render_scan_success_status(tool: ScannerBase, results, source: str, scan_run_id: str):
    """Render successful scan status display."""
    source_name = source.split(":", 1)[1] if ":" in source else source
    
    st.success(f"✅ Scan completed successfully! Results saved to database (ID: {scan_run_id})")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Scanner", tool.NAME)
    with col2:
        results_count = len(results) if isinstance(results, list) else "Generated"
        st.metric("Results", results_count)
    with col3:
        st.metric("Source", source_name)


def _render_scan_details(tool: ScannerBase, error_messages: list[str], ui_logger):
    """Render scan details section."""
    with st.expander("📋 Scan Details", expanded=False):
        log_files = ui_logger.get_log_files()
        st.info(f"📁 Detailed logs saved to: `{log_files['scan_logs']}`")
        
        if error_messages:
            st.error("**Errors encountered during scan:**")
            for error in error_messages:
                st.text(f"• {error}")
        
        if st.button("View Recent Logs", key=f"logs_{tool.NAME}"):
            recent_logs = ui_logger.get_recent_scan_logs(tool.NAME, limit=20)
            if recent_logs:
                st.text_area("Recent Log Entries", "\n".join(recent_logs), height=200)
            else:
                st.info("No recent logs found")


def show_scan_ui(tool: ScannerBase, source: str, generator: RunUpdateGenerator) -> None:
    """Main scan UI function with reduced complexity."""
    data_dir = Path(st.session_state.get(SessionKeys.DataDir, "./data"))
    ui_logger = get_ui_logger(data_dir)
    
    ui_logger.log_scan_start(tool.NAME, source)
    
    progress_container = st.container()
    status_container = st.container()
    
    with progress_container:
        progress_bar = st.progress(0.0, text=f"Initializing scan of {source}...")
        scan_status = st.empty()
    
    scan_success = False
    error_messages = []
    
    try:
        error_messages = _process_scan_updates(generator, tool, progress_bar, scan_status, ui_logger)
    except StopIteration as exc:
        progress_bar.progress(1.0, text="Scan completed!")
        
        if exc.value is not None:
            scan_success = True
            st.session_state[SessionKeys.LatestScanResult][tool.NAME] = exc.value
            
            scan_run_id = _save_scan_results_to_db(tool, exc.value, source, ui_logger)
            
            with status_container:
                if scan_run_id:
                    _render_scan_success_status(tool, exc.value, source, scan_run_id)
                    scan_success = True
                else:
                    scan_success = False
        else:
            ui_logger.log_scan_complete(tool.NAME, False)
            st.warning("⚠️ Scan completed but no results were generated")
    
    _render_scan_details(tool, error_messages, ui_logger)
    
    if scan_success:
        st.balloons()
        import time
        time.sleep(1)
        st.rerun()
