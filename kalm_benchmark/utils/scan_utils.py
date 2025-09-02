from enum import Enum
from pathlib import Path

from kalm_benchmark.evaluation.scanner_manager import SCANNERS, ScannerBase
from kalm_benchmark.utils.constants import UpdateType


class ScanStrategy(Enum):
    """Scan strategy enumeration for cleaner logic.

    Defines available scanning strategies based on source type and tool capabilities,
    providing clear decision paths for scan execution.
    """

    CLUSTER_SCAN = "cluster"
    MANIFEST_SCAN = "manifest"
    DEFAULT_CLUSTER = "default_cluster"
    ERROR = "error"


def resolve_scanner_tool(tool: str | ScannerBase) -> ScannerBase:
    """Resolve scanner tool from string name or instance.

    Handles both string-based tool names and direct ScannerBase instances,
    providing unified tool resolution for flexible scanner specification.

    :param tool: Tool name string or ScannerBase instance
    :return: Resolved ScannerBase instance
    """
    if isinstance(tool, str):
        return SCANNERS.get(tool)
    return tool


def determine_scan_strategy(context: str, target_path: str | Path, tool: ScannerBase) -> ScanStrategy:
    """Determine appropriate scan strategy based on inputs and tool capabilities.

    Analyzes scan configuration (cluster context, manifest path) and tool
    capabilities to determine the optimal scanning strategy.

    :param context: Kubernetes context for cluster scanning
    :param target_path: Path for manifest scanning
    :param tool: Scanner tool instance with capability flags
    :return: Determined scan strategy enum value
    """
    scan_config = _get_scan_configuration(context, target_path)
    return _resolve_strategy_for_config(scan_config, tool)


def _get_scan_configuration(context: str, target_path: str | Path) -> tuple[bool, bool]:
    """Determines what scanning operations are requested based on the presence
    of cluster context and target path parameters.
    """
    return (context is not None, target_path is not None)


def _resolve_strategy_for_config(scan_config: tuple[bool, bool], tool: ScannerBase) -> ScanStrategy:
    """Matches requested scan operations with tool capabilities to determine
    the appropriate strategy, handling conflicts and fallbacks appropriately.
    """
    shall_scan_cluster, shall_scan_manifests = scan_config

    if not shall_scan_cluster and not shall_scan_manifests:
        return _handle_no_source_specified(tool)

    if shall_scan_cluster and shall_scan_manifests:
        return _handle_both_sources_specified(tool)

    if shall_scan_cluster:
        return _handle_cluster_only(tool)

    if shall_scan_manifests:
        return _handle_manifests_only(tool)

    return ScanStrategy.ERROR


def _handle_no_source_specified(tool: ScannerBase) -> ScanStrategy:
    """Handle case when no scan source is specified.
    Provides fallback behavior when neither cluster nor manifest scanning
    is explicitly requested, defaulting to cluster scan if supported.
    """
    return ScanStrategy.DEFAULT_CLUSTER if tool.can_scan_cluster else ScanStrategy.ERROR


def _handle_both_sources_specified(tool: ScannerBase) -> ScanStrategy:
    """Handle case when both cluster and manifest sources are specified.
    Resolves conflicts when both scan types are requested by prioritizing
    manifest scanning over cluster scanning based on tool capabilities.
    """
    if tool.can_scan_manifests:
        return ScanStrategy.MANIFEST_SCAN
    if tool.can_scan_cluster:
        return ScanStrategy.CLUSTER_SCAN
    return ScanStrategy.ERROR


def _handle_cluster_only(tool: ScannerBase) -> ScanStrategy:
    """Handle case when only cluster source is specified.

    Validates that the tool supports cluster scanning when only cluster
    context is provided.
    """
    return ScanStrategy.CLUSTER_SCAN if tool.can_scan_cluster else ScanStrategy.ERROR


def _handle_manifests_only(tool: ScannerBase) -> ScanStrategy:
    """Handle case when only manifest source is specified.

    Validates that the tool supports manifest scanning when only target
    path is provided.
    """
    return ScanStrategy.MANIFEST_SCAN if tool.can_scan_manifests else ScanStrategy.ERROR


def validate_scan_configuration(
    strategy: ScanStrategy, tool: ScannerBase, context: str, target_path: str | Path
) -> tuple[bool, str, UpdateType]:
    """Validate scan configuration and provide user feedback.

    Checks if the determined scan strategy is valid and generates appropriate
    user messages for errors, warnings, and informational updates.


    :param strategy: Determined scan strategy from strategy resolution.
    :param tool: Scanner tool instance with capability information.
    :param context: Kubernetes context string (may be None).
    :param target_path: Target path for manifests (may be None).

    :return: Validation result
    """
    if strategy == ScanStrategy.ERROR:
        # Determine specific error
        shall_scan_cluster = context is not None
        shall_scan_manifests = target_path is not None

        if not shall_scan_cluster and not shall_scan_manifests:
            return False, "No source specified! Please specify it using the '-f' argument.", UpdateType.Error
        elif shall_scan_cluster and shall_scan_manifests:
            return False, "Both scan sources specified, but the tool supports neither", UpdateType.Error
        elif shall_scan_cluster:
            return False, f"{tool.NAME} does not support scanning a cluster", UpdateType.Error
        elif shall_scan_manifests:
            return False, f"{tool.NAME} does not support scanning of manifests", UpdateType.Error
        else:
            return False, "No valid source specified", UpdateType.Error

    # Return appropriate info/warning messages
    shall_scan_cluster = context is not None
    shall_scan_manifests = target_path is not None

    if strategy == ScanStrategy.DEFAULT_CLUSTER:
        return True, "No source specified, scanning cluster with active kube-context", UpdateType.Info
    elif strategy == ScanStrategy.MANIFEST_SCAN and shall_scan_cluster and shall_scan_manifests:
        return True, "Both scan sources are specified. Only the manifest scan will be executed.", UpdateType.Warning
    elif strategy == ScanStrategy.CLUSTER_SCAN and shall_scan_cluster and shall_scan_manifests:
        return True, "Both scan sources are specified but tool supports only scanning of clusters.", UpdateType.Warning

    return True, "", UpdateType.Info


def get_scan_execution_message(strategy: ScanStrategy, target_path: str | Path) -> str:
    """Get appropriate execution message for the scan strategy.
    Generates user-friendly messages describing what type of scan will be
    executed based on the determined strategy.

    :param strategy: Scan strategy enum value.
    :param target_path: Target path for manifest scanning (may be None).
    :return: User-facing execution message describing the scan operation.
    """
    if strategy in [ScanStrategy.CLUSTER_SCAN, ScanStrategy.DEFAULT_CLUSTER]:
        return "Scanning cluster with the currently active context"
    elif strategy == ScanStrategy.MANIFEST_SCAN:
        return f"Scanning manifest(s) at {target_path}"
    else:
        return "Starting scan"
