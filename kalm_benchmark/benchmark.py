from pathlib import Path

from kalm_benchmark.evaluation.scanner_manager import ScannerBase
from kalm_benchmark.utils.constants import RunUpdateGenerator, UpdateType
from kalm_benchmark.utils.scan_utils import (
    ScanStrategy,
    determine_scan_strategy,
    resolve_scanner_tool,
    validate_scan_configuration,
)


def scan(
    tool: str | ScannerBase, context: str | None = None, target_path: str | Path | None = None
) -> RunUpdateGenerator:
    """Start a scan with the specified tool.

    Refactored to use utility functions and reduce cognitive complexity.

    Throughout the process status updates are generated and yielded to the caller, if the tool supports it.
    A status update is a message along with a severity level to inform the user of the ongoing scan process.
    2 types of scans are supported, but they are mutually exclusive.
    Either type is selected by the presence of the corresponding argument:
     - cluster scan: when the `context` argument set
     - manifest scan: started when a `target_path` to a file or directory is provided
    If both arguments are specified then the manifest scan will take precedence, because it is more conservative.
    If no argument is specified then it either
     - starts a cluster scan with the currently active kube-context, if this method is supported
     - or yields an error
    Any error during the process is reported as a status update with the corresponding level
    and leads to an empty set of results.

    :param tool: the wrapper of the tool used for the scan
    :param context: the name of the kubecontext to use for the cluster scan
    :param target_path: the path to the file or directory for the manifest scan
    :return: the parsed results from the scan
    :yield: provides status updates to the caller in the form of a level and a string
    """
    # Clean input processing using utilities
    resolved_tool = resolve_scanner_tool(tool)
    scan_strategy = determine_scan_strategy(context, target_path, resolved_tool)

    # Simple validation with clear error handling
    is_valid, message, update_type = validate_scan_configuration(scan_strategy, resolved_tool, context, target_path)
    if not is_valid:
        yield update_type, message
        return []

    # Yield info/warning messages if needed
    if message:
        yield update_type, message

    # Clean execution dispatch
    return (yield from _execute_scan_strategy(scan_strategy, resolved_tool, target_path))


def _execute_scan_strategy(
    strategy: ScanStrategy, tool: ScannerBase, target_path: str | Path | None
) -> RunUpdateGenerator:
    """Execute the determined scan strategy.

    Args:
        strategy: The scan strategy to execute
        tool: The scanner tool to use
        target_path: Target path for manifest scanning

    Returns:
        Generator yielding scan results
    """
    if strategy in [ScanStrategy.CLUSTER_SCAN, ScanStrategy.DEFAULT_CLUSTER]:
        return (yield from scan_cluster(tool))
    elif strategy == ScanStrategy.MANIFEST_SCAN:
        return (yield from scan_manifests(tool, target_path))
    else:
        return []


def scan_cluster(tool: ScannerBase) -> RunUpdateGenerator:
    """Start a scan of a kubernetes cluster designeted by the currently active kube-context.
    :param tool: the wrapper of the tool used for the scan
    :return: the parsed results from the scan
    :yield: provides updates to the caller in the form of a level and a string
    """
    yield UpdateType.Info, "Scanning cluster with the currently active context"
    res = yield from tool.scan_cluster()
    return res


def scan_manifests(tool: ScannerBase, target: str | Path) -> RunUpdateGenerator:
    """Start a scan of the specified file or files in a directory.

    :param tool: the wrapper of the tool used for the scan
    :param target: a path to the target file or directory
    :return: the parsed results from the scan
    :yield: provides updates to the caller in the form of a level and a string
    """
    yield UpdateType.Info, f"Scanning manifest(s) at {target}"
    res = yield from tool.scan_manifests(target)
    return res
