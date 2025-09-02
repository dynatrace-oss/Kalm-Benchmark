import json
import shutil
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

from loguru import logger

from .constants import (
    ARTIFACT_HUB_API_TIMEOUT,
    ARTIFACT_HUB_DOMAIN,
    ARTIFACT_HUB_EXPECTED_PATH_PARTS,
    DEFAULT_HELM_NAMESPACE,
    DEFAULT_HELM_RELEASE_NAME,
    DEFAULT_POPULAR_CHARTS_COUNT,
    HELM_DOWNLOAD_TIMEOUT,
    HELM_RENDER_TIMEOUT,
    HELM_REPO_TIMEOUT,
    HELM_VERSION_COMMAND_TIMEOUT,
    HIGH_SEVERITY_LEVELS,
    RunUpdateGenerator,
    UpdateType,
)

# Bind logger to scan component for proper log filtering
logger = logger.bind(component="scan")


def normalize_helm_chart_results(results, chart_name: str):
    """
    Normalize CheckResult objects for helm chart scans by setting appropriate defaults.

    :param results: list of CheckResult objects from scanner
    :param chart_name: Name of the helm chart being scanned
    :return: list of normalized CheckResult objects
    """
    if not results:
        return results

    return [_normalize_single_result(result, chart_name) for result in results]


def _normalize_single_result(result, chart_name: str):
    """Normalize a single CheckResult object for helm chart context."""
    _set_result_got_value(result)
    _set_result_expected_value(result)
    _set_result_extra_info(result, chart_name)
    return result


def _set_result_got_value(result):
    """Set the 'got' value based on severity if it's currently None."""
    if hasattr(result, "got") and result.got is None:
        result.got = _determine_got_value_from_severity(result.severity)


def _determine_got_value_from_severity(severity) -> str:
    """Determine the 'got' value based on severity level."""
    if not severity:
        return "info"

    return "alert" if severity.upper() in HIGH_SEVERITY_LEVELS else "info"


def _set_result_expected_value(result):
    """Set expected value to None for helm charts (no predetermined expectations)."""
    if hasattr(result, "expected"):
        result.expected = None


def _set_result_extra_info(result, chart_name: str):
    """Add chart context to the extra field if available."""
    if not hasattr(result, "extra") or not chart_name:
        return

    existing_extra = result.extra or ""
    chart_prefix = f"helm_chart:{chart_name}"

    if existing_extra:
        result.extra = f"{chart_prefix}|{existing_extra}"
    else:
        result.extra = chart_prefix


def check_helm_installed() -> bool:
    """Check if Helm CLI is installed and available."""
    try:
        result = subprocess.run(
            ["helm", "version", "--short"], capture_output=True, text=True, timeout=HELM_VERSION_COMMAND_TIMEOUT
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def download_chart_from_artifact_hub(chart_url: str, destination: Path) -> tuple[bool, str, Path | None]:
    """
    Download Helm chart from Artifact Hub URL.

    :param chart_url: Artifact Hub URL to the chart
    :param destination: Directory to download the chart to

    :return: tuple of (success, message, chart_path)
    """
    try:
        # Extract chart information from Artifact Hub URL
        # Expected format: https://artifacthub.io/packages/helm/repo/chart
        parsed_url = urllib.parse.urlparse(chart_url)
        if ARTIFACT_HUB_DOMAIN not in parsed_url.netloc:
            return False, "URL is not from Artifact Hub", None

        path_parts = parsed_url.path.strip("/").split("/")
        if len(path_parts) < ARTIFACT_HUB_EXPECTED_PATH_PARTS or path_parts[0] != "packages" or path_parts[1] != "helm":
            return False, "Invalid Artifact Hub URL format", None

        repo_name = path_parts[2]
        chart_name = path_parts[3]

        destination.mkdir(parents=True, exist_ok=True)

        cmd = ["helm", "pull", f"{repo_name}/{chart_name}", "--untar", "--untardir", str(destination)]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=HELM_DOWNLOAD_TIMEOUT)

        if result.returncode == 0:
            chart_path = destination / chart_name
            if chart_path.exists() and chart_path.is_dir():
                return True, f"Successfully downloaded chart {chart_name}", chart_path
            else:
                dirs = [d for d in destination.iterdir() if d.is_dir()]
                if dirs:
                    return True, f"Successfully downloaded chart {chart_name}", dirs[0]

        return False, f"Failed to download chart: {result.stderr}", None

    except subprocess.TimeoutExpired:
        return False, "Download timed out", None
    except (subprocess.CalledProcessError, OSError) as e:
        return False, f"Download failed: {str(e)}", None


def _get_fallback_popular_charts() -> list[dict[str, str]]:
    """Get hardcoded list of popular charts as fallback."""
    return [
        {"name": "nginx", "repo": "bitnami", "repo_url": "https://charts.bitnami.com/bitnami"},
        {"name": "mysql", "repo": "bitnami", "repo_url": "https://charts.bitnami.com/bitnami"},
        {"name": "postgresql", "repo": "bitnami", "repo_url": "https://charts.bitnami.com/bitnami"},
        {"name": "redis", "repo": "bitnami", "repo_url": "https://charts.bitnami.com/bitnami"},
        {"name": "mongodb", "repo": "bitnami", "repo_url": "https://charts.bitnami.com/bitnami"},
        {
            "name": "prometheus",
            "repo": "prometheus-community",
            "repo_url": "https://prometheus-community.github.io/helm-charts",
        },
        {"name": "grafana", "repo": "grafana", "repo_url": "https://grafana.github.io/helm-charts"},
        {"name": "jenkins", "repo": "jenkins", "repo_url": "https://charts.jenkins.io"},
        {"name": "cert-manager", "repo": "jetstack", "repo_url": "https://charts.jetstack.io"},
        {"name": "ingress-nginx", "repo": "ingress-nginx", "repo_url": "https://kubernetes.github.io/ingress-nginx"},
    ]


def _parse_chart_from_package(package: dict) -> dict[str, str]:
    """Parse a single package from Artifact Hub API response."""
    repo_info = package.get("repository", {})
    return {
        "name": package.get("name", "unknown"),
        "repo": repo_info.get("name", "unknown"),
        "repo_url": repo_info.get("url", ""),
        "display_name": package.get("display_name", package.get("name", "unknown")),
        "description": package.get("description", ""),
        "verified": repo_info.get("verified_publisher", False),
    }


def _fetch_charts_from_api(num_charts: int) -> list[dict[str, str]] | None:
    """Fetch popular charts from Artifact Hub API based on the number of stars"""
    try:
        api_url = f"https://artifacthub.io/api/v1/packages/search?kind=0&sort=stars&limit={num_charts}"

        with urllib.request.urlopen(api_url, timeout=ARTIFACT_HUB_API_TIMEOUT) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                charts = [_parse_chart_from_package(package) for package in data.get("packages", [])]
                return charts[:num_charts]

    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, Exception) as e:
        logger.debug(f"Failed to fetch charts from Artifact Hub API: {e}")

    return None


def get_popular_charts(num_charts: int = DEFAULT_POPULAR_CHARTS_COUNT) -> list[dict[str, str]]:
    """
    Get list of popular Helm charts from Artifact Hub API.
    Falls back to hardcoded list if API is unavailable.

    :param num_charts: Number of charts to return
    :return: list of chart dictionaries with 'name', 'repo', and 'repo_url' keys
    """
    charts = _fetch_charts_from_api(num_charts)
    if charts:
        return charts

    fallback_charts = _get_fallback_popular_charts()
    return fallback_charts[: min(num_charts, len(fallback_charts))]


def _add_helm_repository(repo_name: str, repo_url: str) -> bool:
    """Add a Helm repository if it doesn't exist."""
    try:
        subprocess.run(["helm", "repo", "add", repo_name, repo_url], capture_output=True, timeout=HELM_REPO_TIMEOUT)
        return True
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.debug(f"Failed to add helm repository {repo_name}: {e}")
        return False


def _update_helm_repositories() -> bool:
    """Update Helm repositories."""
    try:
        subprocess.run(["helm", "repo", "update"], capture_output=True, timeout=HELM_REPO_TIMEOUT)
        return True
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.debug(f"Failed to update helm repositories: {e}")
        return False


def _download_single_chart(chart_name: str, repo_name: str, destination: Path) -> Path | None:
    """Download a single Helm chart."""
    try:
        cmd = ["helm", "pull", f"{repo_name}/{chart_name}", "--untar", "--untardir", str(destination)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=HELM_DOWNLOAD_TIMEOUT)

        if result.returncode == 0:
            chart_path = destination / chart_name
            if chart_path.exists():
                return chart_path
            else:
                dirs = [d for d in destination.iterdir() if d.is_dir() and chart_name in d.name]
                return dirs[0] if dirs else None
        return None

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
        logger.debug(f"Failed to download helm chart {chart_name}: {e}")
        return None


def download_popular_charts(num_charts: int, destination: Path) -> tuple[bool, str, list[Path]]:
    """
    Download popular Helm charts.

    :param num_charts: Number of popular charts to download
    :param destination: Directory to download charts to
    :return:tuple of (success, message, list of chart paths)
    """
    charts = get_popular_charts(num_charts)
    downloaded_charts = []
    failed_downloads = []

    destination.mkdir(parents=True, exist_ok=True)

    _update_helm_repositories()

    for chart in charts:
        chart_name = chart["name"]
        repo_name = chart["repo"]
        repo_url = chart.get("repo_url", f"https://{repo_name}.github.io/charts/")

        _add_helm_repository(repo_name, repo_url)
        chart_path = _download_single_chart(chart_name, repo_name, destination)

        if chart_path:
            downloaded_charts.append(chart_path)
        else:
            failed_downloads.append(chart_name)

    success = len(downloaded_charts) > 0
    message = f"Downloaded {len(downloaded_charts)} charts"
    if failed_downloads:
        message += f", failed to download: {', '.join(failed_downloads)}"

    return success, message, downloaded_charts


def render_helm_chart(
    chart_path: Path,
    release_name: str = DEFAULT_HELM_RELEASE_NAME,
    namespace: str = DEFAULT_HELM_NAMESPACE,
    output_dir: Path | None = None,
) -> tuple[bool, str, Path | None]:
    """
    Render Helm chart to valid Kubernetes manifests.

    :param chart_path: Path to the Helm chart directory
    :param release_name: Name for the Helm release
    :param namespace: Kubernetes namespace
    :param output_dir: Optional output directory for rendered manifests

    :return:tuple of (success, message, manifest_path)
    """
    logger.debug(f"Rendering chart: {chart_path}")

    if not chart_path.exists() or not chart_path.is_dir():
        logger.error(f"Chart directory not found: {chart_path}")
        return False, f"Chart directory not found: {chart_path}", None

    # Check for Chart.yaml
    chart_yaml_path = chart_path / "Chart.yaml" if (chart_path / "Chart.yaml").exists() else chart_path / "Chart.yml"
    if not chart_yaml_path.exists():
        logger.error(f"No Chart.yaml found in {chart_path}")
        return False, f"No Chart.yaml found in {chart_path}", None

    logger.debug(f"Found Chart.yaml at: {chart_yaml_path}")

    try:
        # Create output directory if not provided
        if output_dir is None:
            output_dir = chart_path / "rendered"
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Created output directory: {output_dir}")

        # Render the chart
        _ = output_dir / f"{release_name}-manifests.yaml"

        cmd = [
            "helm",
            "template",
            release_name,
            str(chart_path),
            "--namespace",
            namespace,
            "--output-dir",
            str(output_dir),
        ]

        logger.debug(f"Running helm command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=HELM_RENDER_TIMEOUT)
        logger.debug(f"Helm command completed with return code: {result.returncode}")

        if result.returncode == 0:
            # Helm template with --output-dir creates individual files in subdirectories
            logger.info(f"Successfully rendered chart to {output_dir}")
            if result.stdout:
                logger.debug(f"Helm stdout: {result.stdout[:200]}...")
            return True, f"Successfully rendered chart to {output_dir}", output_dir
        else:
            logger.error(f"Helm command failed with stderr: {result.stderr}")
            if result.stdout:
                logger.debug(f"Helm stdout: {result.stdout}")
            return False, f"Failed to render chart: {result.stderr}", None

    except subprocess.TimeoutExpired:
        return False, "Chart rendering timed out", None
    except (subprocess.CalledProcessError, OSError) as e:
        return False, f"Failed to render chart: {str(e)}", None


def _setup_temp_directory() -> Path:
    """Create and return the temporary directory for chart processing."""
    project_root = Path(__file__).parent.parent.parent  # Go up to kalm_benchmark root
    temp_path = project_root / "tmp" / "charts"
    temp_path.mkdir(parents=True, exist_ok=True)
    return temp_path


def _process_chart_download(chart_path: str, temp_path: Path) -> RunUpdateGenerator:
    """Handle chart download if it's a URL."""
    yield UpdateType.Progress, "Downloading chart from Artifact Hub..."
    success, message, downloaded_path = download_chart_from_artifact_hub(chart_path, temp_path)
    if not success:
        yield UpdateType.Error, message
        return None
    yield UpdateType.Info, message
    return downloaded_path


def _render_chart_manifests(chart_path: Path, release_name: str, namespace: str, temp_path: Path) -> RunUpdateGenerator:
    """Render Helm chart to Kubernetes manifests."""
    yield UpdateType.Progress, f"Rendering Helm chart at {chart_path}..."
    success, message, manifest_path = render_helm_chart(chart_path, release_name, namespace, temp_path / "manifests")

    if not success:
        yield UpdateType.Error, message
        return None

    yield UpdateType.Info, message
    return manifest_path


def _scan_chart_manifests(scanner_tool, manifest_path: Path, chart_name: str) -> RunUpdateGenerator:
    """Scan the rendered manifests and normalize results."""
    yield UpdateType.Progress, "Scanning rendered manifests..."

    try:
        results = yield from scanner_tool.scan_manifests(manifest_path)

        # Normalize results for helm chart context
        normalized_results = normalize_helm_chart_results(results, chart_name)

        yield UpdateType.Info, f"Scan completed, found {len(normalized_results) if normalized_results else 0} results"
        return normalized_results

    except Exception as e:
        yield UpdateType.Error, f"Scanning failed: {str(e)}"
        return None


def _cleanup_temp_files(temp_path: Path) -> RunUpdateGenerator:
    """Cleanup temporary chart files."""
    try:
        if temp_path.exists():
            shutil.rmtree(temp_path)
            yield UpdateType.Info, f"Cleaned up temporary chart data at {temp_path}"
    except OSError as e:
        yield UpdateType.Warning, f"Failed to cleanup temporary files: {str(e)}"


def scan_helm_chart_generator(
    chart_path: str | Path,
    scanner_tool,
    release_name: str = DEFAULT_HELM_RELEASE_NAME,
    namespace: str = DEFAULT_HELM_NAMESPACE,
) -> RunUpdateGenerator:
    """
    Generator function for scanning Helm charts.

    :param chart_path: Path to Helm chart or chart URL
    :param scanner_tool: Scanner tool instance
    :param release_name: Helm release name
    :param namespace: Kubernetes namespace
    :yield: Updates about the scanning process
    :return:Parsed scan results
    """
    if not check_helm_installed():
        yield UpdateType.Error, "Helm CLI is not installed or not accessible"
        return None

    yield UpdateType.Info, "Helm CLI is available"

    temp_path = _setup_temp_directory()

    try:
        working_chart_path = Path(chart_path)

        if str(chart_path).startswith("http"):
            working_chart_path = yield from _process_chart_download(str(chart_path), temp_path)
            if working_chart_path is None:
                return None

        manifest_path = yield from _render_chart_manifests(working_chart_path, release_name, namespace, temp_path)
        if manifest_path is None:
            return None

        chart_name = working_chart_path.name if working_chart_path else None
        results = yield from _scan_chart_manifests(scanner_tool, manifest_path, chart_name)
        return results

    finally:
        yield from _cleanup_temp_files(temp_path)


def _download_popular_charts(num_charts: int, temp_path: Path) -> RunUpdateGenerator:
    """Download popular charts and yield progress updates."""
    yield UpdateType.Progress, f"Downloading top {num_charts} popular charts..."

    success, message, chart_paths = download_popular_charts(num_charts, temp_path)

    if not success or not chart_paths:
        logger.error(f"Failed to download charts: {message}")
        yield UpdateType.Error, message
        return None

    logger.info(f"Successfully downloaded {len(chart_paths)} charts")
    yield UpdateType.Info, message
    return chart_paths


def _scan_single_chart(
    chart_path: Path,
    chart_index: int,
    total_charts: int,
    scanner_tool,
    release_name: str,
    namespace: str,
    temp_path: Path,
) -> RunUpdateGenerator:
    """Scan a single chart and return normalized results."""
    chart_name = chart_path.name
    yield UpdateType.Progress, f"Scanning chart {chart_index+1}/{total_charts}: {chart_name}"

    manifest_output_path = temp_path / "manifests" / chart_name

    success, render_message, manifest_path = render_helm_chart(
        chart_path, f"{release_name}-{chart_name}", namespace, manifest_output_path
    )

    if not success:
        logger.error(f"Helm: Failed to render {chart_name}: {render_message}")
        yield UpdateType.Warning, f"Failed to render {chart_name}: {render_message}"
        return None

    # Check if rendered files exist
    if manifest_path and manifest_path.exists():
        yaml_files = list(manifest_path.glob("**/*.yaml"))
        if len(yaml_files) == 0:
            logger.warning(f"Helm: No YAML files found in rendered output for {chart_name}")
    else:
        logger.warning(f"Helm: Manifest path does not exist: {manifest_path}")

    try:
        results = yield from scanner_tool.scan_manifests(manifest_path)

        # Normalize results for helm chart context
        normalized_results = normalize_helm_chart_results(results, chart_name)

        yield UpdateType.Info, f"Scanned {chart_name}: {len(normalized_results) if normalized_results else 0} findings"
        return normalized_results

    except Exception as e:
        yield UpdateType.Warning, f"Failed to scan {chart_name}: {str(e)}"
        return None


def scan_popular_charts_generator(
    num_charts: int,
    scanner_tool,
    release_name: str = DEFAULT_HELM_RELEASE_NAME,
    namespace: str = DEFAULT_HELM_NAMESPACE,
) -> RunUpdateGenerator:
    """
    Generator function for scanning popular Helm charts individually.

    This function now saves each chart as a separate scan result instead of combining them.
    Each chart gets its own scan_run entry with source_type="helm-chart:{chart_name}".


    :param num_charts: Number of popular charts to scan
    :param scanner_tool: Scanner tool instance
    :param release_name: Helm release name
    :param namespace: Kubernetes namespace
    :yield: Updates about the scanning process
    :return: list of scan run IDs for each chart that was successfully scanned
    """
    if not check_helm_installed():
        yield UpdateType.Error, "Helm CLI is not installed or not accessible"
        return None

    yield UpdateType.Info, "Helm CLI is available"

    temp_path = _setup_temp_directory()

    try:
        chart_paths = yield from _download_popular_charts(num_charts, temp_path)
        if chart_paths is None:
            return None

        all_results = []
        for i, chart_path in enumerate(chart_paths):
            chart_results = yield from _scan_single_chart(
                chart_path, i, len(chart_paths), scanner_tool, release_name, namespace, temp_path
            )

            if chart_results:
                all_results.extend(chart_results)

        yield UpdateType.Info, f"Completed scanning {len(chart_paths)} charts, total findings: {len(all_results)}"

        # Cleanup after all scanning is complete
        yield from _cleanup_temp_files(temp_path)

        return all_results

    except Exception as e:
        print(f"Chart generation failed due to {e}")
        try:
            yield from _cleanup_temp_files(temp_path)
        except Exception as e:
            print(f"Clean up failed due to error:{e}")
        raise
