from enum import Enum
from pathlib import Path
from typing import Tuple, Union

from kalm_benchmark.evaluation.scanner_manager import SCANNERS, ScannerBase
from kalm_benchmark.utils.constants import UpdateType


class ScanStrategy(Enum):
    """Scan strategy enumeration for cleaner logic."""

    CLUSTER_SCAN = "cluster"
    MANIFEST_SCAN = "manifest"
    DEFAULT_CLUSTER = "default_cluster"
    ERROR = "error"


def resolve_scanner_tool(tool: Union[str, ScannerBase]) -> ScannerBase:
    """Extract tool resolution logic.

    Args:
        tool: Tool name string or ScannerBase instance

    Returns:
        Resolved ScannerBase instance
    """
    if isinstance(tool, str):
        return SCANNERS.get(tool)
    return tool


def determine_scan_strategy(context: str, target_path: Union[str, Path], tool: ScannerBase) -> ScanStrategy:
    """Extract scan strategy determination logic.

    Args:
        context: Kubernetes context for cluster scanning
        target_path: Path for manifest scanning
        tool: Scanner tool instance

    Returns:
        Determined scan strategy
    """
    scan_config = _get_scan_configuration(context, target_path)
    return _resolve_strategy_for_config(scan_config, tool)


def _get_scan_configuration(context: str, target_path: Union[str, Path]) -> Tuple[bool, bool]:
    """Get scan configuration flags.

    Returns:
        Tuple of (shall_scan_cluster, shall_scan_manifests)
    """
    return (context is not None, target_path is not None)


def _resolve_strategy_for_config(scan_config: Tuple[bool, bool], tool: ScannerBase) -> ScanStrategy:
    """Resolve scan strategy based on configuration and tool capabilities.

    Args:
        scan_config: Tuple of (shall_scan_cluster, shall_scan_manifests)
        tool: Scanner tool instance

    Returns:
        Determined scan strategy
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
    """Handle case when no scan source is specified."""
    return ScanStrategy.DEFAULT_CLUSTER if tool.can_scan_cluster else ScanStrategy.ERROR


def _handle_both_sources_specified(tool: ScannerBase) -> ScanStrategy:
    """Handle case when both cluster and manifest sources are specified."""
    if tool.can_scan_manifests:
        return ScanStrategy.MANIFEST_SCAN
    if tool.can_scan_cluster:
        return ScanStrategy.CLUSTER_SCAN
    return ScanStrategy.ERROR


def _handle_cluster_only(tool: ScannerBase) -> ScanStrategy:
    """Handle case when only cluster source is specified."""
    return ScanStrategy.CLUSTER_SCAN if tool.can_scan_cluster else ScanStrategy.ERROR


def _handle_manifests_only(tool: ScannerBase) -> ScanStrategy:
    """Handle case when only manifest source is specified."""
    return ScanStrategy.MANIFEST_SCAN if tool.can_scan_manifests else ScanStrategy.ERROR


def validate_scan_configuration(
    strategy: ScanStrategy, tool: ScannerBase, context: str, target_path: Union[str, Path]
) -> Tuple[bool, str, UpdateType]:
    """Extract validation logic with clear error messages.

    Args:
        strategy: Determined scan strategy
        tool: Scanner tool instance
        context: Kubernetes context
        target_path: Target path for manifests

    Returns:
        Tuple of (is_valid, message, update_type)
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


def get_scan_execution_message(strategy: ScanStrategy, target_path: Union[str, Path]) -> str:
    """Get appropriate execution message for the scan strategy.

    Args:
        strategy: Scan strategy
        target_path: Target path for manifest scanning

    Returns:
        Execution message string
    """
    if strategy in [ScanStrategy.CLUSTER_SCAN, ScanStrategy.DEFAULT_CLUSTER]:
        return "Scanning cluster with the currently active context"
    elif strategy == ScanStrategy.MANIFEST_SCAN:
        return f"Scanning manifest(s) at {target_path}"
    else:
        return "Starting scan"
