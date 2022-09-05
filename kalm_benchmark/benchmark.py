from pathlib import Path

from kalm_benchmark.constants import RunUpdateGenerator, UpdateType
from kalm_benchmark.evaluation.scanner_manager import SCANNERS, ScannerBase


def scan(
    tool: str | ScannerBase, context: str | None = None, target_path: str | Path | None = None
) -> RunUpdateGenerator:
    """Start a scan with the specified tool.
    Throughout the process status updates are generated  and yielded to the caller, if the tool supports it.
    A status update is a message along with a severity level to inform the user of the ongoing scan process.
    2 types of scans are supported, but they are mutually exclusive.
    Either type is selected by the presence of the corresponding argument:
     - cluster scan: when the `context` argument set
     - manifest scan: started when a `target_path` to a file or directory  is provided
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
    if isinstance(tool, str):
        tool = SCANNERS.get(tool)

    # the intention to use a certain scan is indicated be the presence of the respective argument
    shall_scan_cluster = context is not None
    shall_scan_manifests = target_path is not None
    res = []

    if not shall_scan_cluster and not shall_scan_manifests:
        # if intention is not clear due to missing arguments use the cluster scan as fallback, if it is supported
        if tool.can_scan_cluster:
            yield UpdateType.Info, "No source specified, scanning cluster with active kube-context"
            res = yield from scan_cluster(tool)
        else:
            yield UpdateType.Error, "No source specified! Please specify it using the '-f' argument."
    elif shall_scan_cluster and shall_scan_manifests:
        if tool.can_scan_manifests:
            yield UpdateType.Warning, "Both scan sources are specified. Only the manifest scan will be executed."
            res = yield from scan_manifests(tool, target_path)
        elif tool.can_scan_cluster:
            yield UpdateType.Warning, "Both scan sources are specified but tool supports only scanning of clusters."
            res = yield from scan_cluster(tool)
        else:
            yield UpdateType.Error, "Both scan sources specified, but the tool supports neither"
    elif shall_scan_cluster:
        if tool.can_scan_cluster:
            res = yield from scan_cluster(tool)
        else:
            yield UpdateType.Error, f"{tool.NAME} does not support scanning a cluster"
    elif shall_scan_manifests:
        if tool.can_scan_manifests:
            res = yield from scan_manifests(tool, target_path)
        else:
            yield UpdateType.Error, f"{tool.NAME} does not support scanning of manifests"
    else:
        yield UpdateType.Error, "No valid source specified"

    return res


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
