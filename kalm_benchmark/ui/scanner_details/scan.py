from pathlib import Path

import streamlit as st

from kalm_benchmark.evaluation.scanner.scanner_evaluator import ScannerBase
from kalm_benchmark.ui.interface.gen_utils import get_unified_service
from kalm_benchmark.ui.logging_config import get_ui_logger
from kalm_benchmark.utils.constants import (
    LAST_SCAN_OPTION,
    SELECTED_RESULT_FILE,
    RunUpdateGenerator,
    SessionKeys,
    UpdateType,
)


def _get_kubectl_context() -> str:
    """Get current kubectl context from system or return fallback value."""
    try:
        import subprocess

        result = subprocess.run(["kubectl", "config", "current-context"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "cluster"


def _resolve_project_path(path_input: str) -> Path:
    """Resolve input path relative to project root when not absolute."""
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


def _validate_manifest_path(path: Path) -> tuple[bool, str | None]:
    """Validate manifest file or directory path with descriptive feedback."""
    if not path.exists():
        return False, "❌ Path does not exist!"

    if path.is_file():
        return True, f"✅ File found: `{path.name}`"
    elif path.is_dir():
        yaml_files = list(path.glob("*.yaml")) + list(path.glob("*.yml"))
        return True, f"✅ Directory found with {len(yaml_files)} YAML files"
    else:
        return False, "⚠️ Path exists but is neither a file nor directory"


def _validate_helm_chart_path(chart_path: Path) -> tuple[bool, str]:
    """Validate Helm chart directory and check for Chart.yaml file."""
    if not chart_path.exists() or not chart_path.is_dir():
        return False, "❌ Chart directory does not exist!"

    if (chart_path / "Chart.yaml").exists() or (chart_path / "Chart.yml").exists():
        return True, f"✅ Valid Helm chart found: `{chart_path.name}`"
    else:
        return False, "⚠️ Directory found but no Chart.yaml detected"


def _extract_helm_chart_name(chart_url: str) -> str | None:
    """Extract chart name from Artifact Hub URL for identification."""
    try:
        parts = chart_url.split("/")
        if "artifacthub.io" in chart_url and len(parts) >= 6:
            repo_name = parts[-2]
            chart_name = parts[-1]
            return f"{repo_name}-{chart_name}"
    except Exception:
        pass
    return None


def _render_cluster_scan_section(tool: ScannerBase, ui_logger) -> tuple[str, RunUpdateGenerator] | None:
    """Render cluster scanning interface with kubectl context detection."""
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


def _render_manifest_scan_section(tool: ScannerBase, ui_logger) -> tuple[str, RunUpdateGenerator] | None:
    """Render manifest file scanning interface with path validation."""
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


def _render_helm_artifact_hub_inputs() -> tuple[bool, str, str]:
    """Render UI inputs for Artifact Hub chart URL selection."""
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


def _render_helm_popular_charts_inputs() -> tuple[bool, str, int]:
    """Render UI inputs for popular charts research mode selection."""
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
        st.markdown("Will download and scan popular charts from Artifact Hub")

        if st.button("🔍 Preview Charts", key="preview_charts"):
            from kalm_benchmark.utils.helm_operations import get_popular_charts

            charts = get_popular_charts(min(num_charts, 5))  # Preview up to 5

            st.markdown("**Preview (showing first 5):**")
            for chart in charts:
                verified_icon = "✅" if chart.get("verified", False) else ""
                st.markdown(f"• **{chart['name']}** ({chart['repo']}) {verified_icon}")
                if chart.get("description"):
                    st.markdown(f"  _{chart['description'][:80]}..._")

        st.info("💡 Charts fetched dynamically from Artifact Hub API")

    helm_name = f"top-{num_charts}-charts"
    return True, helm_name, num_charts


def _render_helm_local_chart_inputs() -> tuple[bool, str, str]:
    """Render UI inputs for local Helm chart directory selection."""
    col_path, col_name = st.columns([2, 1])
    with col_path:
        chart_path_input = st.text_input(
            "Local Chart Path:", value="./charts/my-app", help="Path to local helm chart directory"
        )

    with col_name:
        default_name = Path(chart_path_input).name if chart_path_input else "local-chart"
        helm_name = st.text_input("Chart Name:", value=default_name, help="Unique name for this local helm chart")

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


def _check_helm_availability() -> bool:
    """Verify Helm CLI installation and display status messages."""
    from kalm_benchmark.utils.helm_operations import check_helm_installed

    helm_available = check_helm_installed()
    if not helm_available:
        st.error("❌ Helm CLI is not installed or not accessible. Please install Helm CLI to use this feature.")
        st.markdown("**Installation Instructions:**")
        st.code("curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash")
        return False
    else:
        st.success("✅ Helm CLI is available")
        return True


def _get_helm_scan_inputs() -> tuple[str, bool, str, str, int, str]:
    """Collect and validate Helm chart scanning inputs from user interface."""
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

    return scan_type, scan_enabled, helm_name, chart_url, num_charts, chart_path_input


def _get_helm_release_config() -> tuple[str, str]:
    """Provide default Helm release configuration for chart rendering."""
    # Use sensible defaults - these don't affect security scan results
    release_name = "kalm-test-release"
    namespace = "default"
    return release_name, namespace


def _execute_helm_scan(
    tool: ScannerBase,
    scan_type: str,
    helm_name: str,
    chart_url: str,
    num_charts: int,
    chart_path_input: str,
    release_name: str,
    namespace: str,
) -> tuple[str, RunUpdateGenerator]:
    """Execute appropriate Helm scanning method based on selected scan type."""

    if scan_type == "🌐 Artifact Hub Chart (by URL)":
        source = f"helm-chart:{helm_name}"
        gen = tool.scan_helm_chart(chart_path=chart_url, release_name=release_name, namespace=namespace)
    elif scan_type == "📊 Top Popular Charts (research)":
        source = f"helm-chart:top-{num_charts}-charts"  # This will be intercepted for special handling
        gen = tool.scan_popular_charts(num_charts=num_charts, release_name=release_name, namespace=namespace)
    else:
        chart_path = _resolve_project_path(chart_path_input)
        source = f"helm-chart:{helm_name}"
        gen = tool.scan_helm_chart(chart_path=str(chart_path), release_name=release_name, namespace=namespace)

    return source, gen


def _render_helm_scan_section(tool: ScannerBase, ui_logger) -> tuple[str, RunUpdateGenerator] | None:
    """Render complete Helm chart scanning interface with all input options."""
    with st.expander("⚓ Helm Chart Scan", expanded=False):
        st.markdown("Scan Helm charts by rendering them to manifests first")

        # Check Helm availability
        if not _check_helm_availability():
            return None

        st.info("📋 **Note:** Charts will be rendered to Kubernetes manifests and then scanned")

        # Get scan inputs and release configuration
        scan_type, scan_enabled, helm_name, chart_url, num_charts, chart_path_input = _get_helm_scan_inputs()
        release_name, namespace = _get_helm_release_config()

        col1, col2 = st.columns([3, 1])
        with col1:
            if not scan_enabled:
                st.markdown("*Please provide valid chart information to enable scanning*")

        with col2:
            if st.button(
                "⚓ Render & Scan",
                key="helm_scan",
                type="secondary",
                disabled=not scan_enabled,
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

                return _execute_helm_scan(
                    tool, scan_type, helm_name, chart_url, num_charts, chart_path_input, release_name, namespace
                )

    return None


def show_scan_buttons(tool: ScannerBase) -> None:
    """Display main scanning interface with all available scan options for the tool.

    :param tool: Scanner instance to render scan options for
    :return: None
    """
    with st.sidebar:
        st.markdown("### 🔍 Start New Scan")

        data_dir = Path(st.session_state.get(SessionKeys.DataDir, "./data"))
        ui_logger = get_ui_logger(data_dir)

        scan_result = None

        if tool.can_scan_cluster:
            scan_result = _render_cluster_scan_section(tool, ui_logger)

        if tool.can_scan_manifests and not scan_result:
            scan_result = _render_manifest_scan_section(tool, ui_logger)

        if tool.can_scan_helm and not scan_result:
            scan_result = _render_helm_scan_section(tool, ui_logger)

        if not (tool.can_scan_cluster or tool.can_scan_manifests or tool.can_scan_helm):
            st.markdown("---")
            st.warning("⚠️ No scan capabilities available for this tool")

        if scan_result:
            source, gen = scan_result
            show_scan_ui(tool, source, gen)


def _process_scan_updates(
    generator: RunUpdateGenerator, tool: ScannerBase, progress_bar, scan_status, ui_logger
) -> list[str]:
    """Process and display scan progress updates from generator stream."""
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
    """Process and standardize scan results for database storage."""
    if not results or len(results) == 0:
        return []

    first_item = results[0] if isinstance(results, list) else results

    ui_logger.log_ui_action(
        "debug_scan_results",
        f"Tool: {tool.NAME}, Result type: {type(results)}, "
        f"Length: {len(results) if hasattr(results, '__len__') else 'N/A'}",
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
    """Create fallback CheckResult objects when result parsing fails."""
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


def _save_scan_results_to_db(tool: ScannerBase, results, source: str, ui_logger) -> str | None:
    """Save processed scan results to the unified database with metadata."""
    try:
        unified_service = get_unified_service()
        version = tool.get_version() or "unknown"

        if ":" in source:
            _, source_name = source.split(":", 1)
        else:
            source_name = source

        processed_results = _process_scan_results(tool, results, ui_logger)

        source_file = None
        if source.startswith("helm-chart:"):
            source_file = source

        scan_run_id = unified_service.save_scanner_results(
            scanner_name=tool.NAME.lower(), results=processed_results, scanner_version=version, source_file=source_file
        )

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
        ui_logger.log_ui_action("database_save_complete", f"Tool: {tool.NAME}, Source: {source}, ID: {scan_run_id}")

        return scan_run_id
    except Exception as e:
        error_msg = f"Failed to save results to database: {e}"
        ui_logger.log_scan_error(tool.NAME, error_msg)
        st.error(f"❌ {error_msg}")
        return None


def _render_scan_success_status(tool: ScannerBase, results, source: str, scan_run_id: str):
    """Display successful scan completion status with key metrics."""
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
    """Display detailed scan information including logs and error messages."""
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


def _handle_popular_charts_scan(tool: ScannerBase, source: str, generator: RunUpdateGenerator, ui_logger) -> bool:
    """Process popular charts scan results by saving each chart separately."""
    if not source.startswith("helm-chart:top-") or "-charts" not in source:
        return False

    st.info("🔄 Processing popular charts - each chart will be saved separately...")

    try:
        num_charts = int(source.split("top-")[1].split("-charts")[0])
    except (ValueError, IndexError):
        st.error("Failed to parse number of charts from source")
        return True

    from kalm_benchmark.utils.helm_operations import get_popular_charts

    charts = get_popular_charts(num_charts)

    chart_results = {}
    total_charts = len(charts)
    success_count = 0

    chart_progress = st.empty()

    try:
        step_count = 0
        while True:
            try:
                update = next(generator)
                _, msg = update
                if msg and len(msg.strip()) > 0:
                    step_count += 1
                    if "Scanning chart" in msg and ":" in msg:
                        try:
                            chart_name = msg.split(":")[-1].strip()
                            chart_index = step_count // 3
                            chart_progress.info(f"📊 Chart {min(chart_index, total_charts)}/{total_charts}: {msg}")
                        except Exception:
                            chart_progress.info(msg)
                    else:
                        chart_progress.info(msg)
            except StopIteration as exc:
                all_results = exc.value  # Split by chart
                if all_results and len(all_results) > 0:
                    # This is a heuristic - results from same chart tend to have similar obj_name prefixes
                    chart_results = _split_results_by_chart(all_results, charts)

                    for chart in charts:
                        chart_name = chart["name"]
                        chart_specific_results = chart_results.get(chart_name, [])

                        if chart_specific_results:
                            chart_source = f"helm-chart:{chart_name}"
                            scan_run_id = _save_scan_results_to_db(
                                tool, chart_specific_results, chart_source, ui_logger
                            )
                            if scan_run_id:
                                success_count += 1
                                st.success(
                                    f"✅ Saved {len(chart_specific_results)} results for chart "
                                    f"'{chart_name}' (ID: {scan_run_id})"
                                )
                            else:
                                st.error(f"❌ Failed to save results for chart '{chart_name}'")
                        else:
                            st.warning(f"⚠️ No results found for chart '{chart_name}'")

                    st.info(f"📊 Successfully processed {success_count}/{total_charts} charts individually")
                    return True
                else:
                    st.warning("⚠️ No results generated from popular charts scan")
                    return True
                break
    except Exception as e:
        st.error(f"Error processing popular charts: {str(e)}")
        return True


def _split_results_by_chart(all_results: list, charts: list) -> dict:
    """Distribute scan results to individual charts using name matching heuristics."""
    chart_results = {chart["name"]: [] for chart in charts}
    unassigned_results = []

    for result in all_results:
        obj_name = getattr(result, "obj_name", "") or ""
        assigned = False

        for chart in charts:
            chart_name = chart["name"]
            if (
                chart_name in obj_name.lower()
                or obj_name.lower().startswith(chart_name.lower())
                or obj_name.lower().endswith(chart_name.lower())
            ):
                chart_results[chart_name].append(result)
                assigned = True
                break

        if not assigned:
            unassigned_results.append(result)

    if unassigned_results and charts:
        chart_names = list(chart_results.keys())
        for i, result in enumerate(unassigned_results):
            chart_name = chart_names[i % len(chart_names)]
            chart_results[chart_name].append(result)

    return chart_results


def show_scan_ui(tool: ScannerBase, source: str, generator: RunUpdateGenerator) -> None:
    """Display scan execution interface with progress tracking and result handling.

    :param tool: Scanner instance executing the scan
    :param source: Source identifier for the scan (e.g., "cluster:name", "manifests:path")
    :param generator: Generator providing scan progress updates
    :return: None
    """
    data_dir = Path(st.session_state.get(SessionKeys.DataDir, "./data"))
    ui_logger = get_ui_logger(data_dir)

    ui_logger.log_scan_start(tool.NAME, source)

    if _handle_popular_charts_scan(tool, source, generator, ui_logger):
        _render_scan_details(tool, [], ui_logger)
        st.balloons()
        import time

        time.sleep(1)
        st.rerun()
        return

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
