import json
import re
from pathlib import Path
from typing import Optional

import pandas as pd

from kalm_benchmark.constants import UpdateType

from ..utils import get_path_to_line, normalize_path
from .scanner_evaluator import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    RunUpdateGenerator,
    ScannerBase,
)

CHECK_MAPPING = {
    "Pod or Container Without LimitRange": (CheckCategory.Reliability, ".metadata.namespace"),
    "Pod or Container Without ResourceQuota": (CheckCategory.Reliability, ".metadata.namespace"),
    # the provided information of this check is inaccurate (points to rules and not the verbs)
    "RBAC Roles with Read Secrets Permissions": (CheckCategory.RBAC, ".rules[].verbs"),
    # search key points only to the requests field, not the cpu
    "CPU Requests Not Set": (CheckCategory.Reliability, ".spec.containers[].resources.requests.cpu"),
    # search key points only to the limits field, not the cpu
    "CPU Limits Not Set": (CheckCategory.Reliability, ".spec.containers[].resources.limits.cpu"),
}

META_NAME_PATTERN = re.compile(r"metadata.name=({{.*?}}|[\w-]*)")
# note: it's assumed that the captured array field ends with an 's'
ARRAY_NAME_PATTERN = re.compile(r"(\w*s).(name|kind)=({{.*?}}|[\w-]*)")
ARRAY_INDEX_PATTERN = re.compile(r"\[.*?\]")
ASSIGNED_VALUE_PATTERN = re.compile(r"=[\w-]*")
QUOTED_PATH_PATTERN = re.compile(r".*'(.*?)'.*")


MANIFESTS_DIR = Path("dist/")


class Scanner(ScannerBase):
    NAME = "KICS"
    IMAGE_URL = "https://kics.io/wp-content/uploads/2021/11/kics_hat_white_new.png"
    FORMATS = [
        "Plain",
        "JSON",
        "Sarif",
        "CycloneDX",
        "ASFF",
        "CSV",
        "Code Climate",
        "Gitlab SAST",
        "JUnit",
        "SonarQube",
        "HTML",
        "PDF",
    ]
    CUSTOM_CHECKS = True
    CI_MODE = True
    RUNS_OFFLINE = True
    VERSION_CMD = ["docker", "run", "checkmarx/kics", "version"]

    EXIT_CODES = {
        0: "No Results were Found",
        50: "Found any `HIGH` Results",
        40: "Found any `MEDIUM` Results",
        30: "Found any `LOW` Results",
        20: "Found any `INFO` Results",
        126: "Engine Error",
        130: "Signal-Interrupt",
    }

    def get_version(self) -> str:
        """Retrieve the version number of the tool by executing the corresponding command.
        :return: the version number of the tool
        """
        version = super().get_version()
        # the tool returns "Keeping Infrastructure as Code Secure v<version>"
        # extract the version number by slicing from the last 'v'
        v_start_idx = version.rfind("v")
        return version[v_start_idx + 1 :]

    def scan_manifests(self, path: Path) -> RunUpdateGenerator:
        """Start a scan of manifests at the specified location.
        If the path points to a directory, all yaml files within it will be scanned
        KICS (v.1.5.8) does not support printing the JSON results to stdout.
        This is why the results are written to a JSON file in the designated folder, which is mounted
        in the docker container performing the scan.
        The results will then be read read from the file, similar to how they do it in their
        [integrations documentation](https://github.com/Checkmarx/kics/blob/master/docs/integrations.md)
        Afterward reading the results from the file it will be deleted.

        :param path: the path to the location with the manifest(s)
        :return: a list of results per file
        """
        result_file_name = "kics-result.json"

        if path.is_file():
            yield UpdateType.Warning, (
                "Currently only paths to a folder are supported. Using the parent folder as target instead"
            )
            path = path.parent()

        cmd = [
            "docker",
            "run",
            "-v",
            f"{str(path.resolve())}:/manifests",
            "-v",
            f"/tmp/z_kics_result.json:/tmp/{result_file_name}",
            "checkmarx/kics:latest",
            "scan",
            "--ci",
            "-p",
            "/manifests",
            "--report-formats",
            "json",
            "-o",
            "/manifests/",
            "--output-name",
            result_file_name,
        ]

        results = None
        run_result = yield from self.run(cmd, parse_json=False, stream_process_output=True)

        if run_result is None:
            # no need to further "process" the results
            return run_result
        elif "No files were scanned" in run_result:
            err_detail = "The path must be absolute" if not path.is_absolute else ""
            if path.exists:
                err_detail = "The specified directory or file does not exist!"
            yield UpdateType.Warning, (
                f"No files were scanned! Please check if the path '{path}' is correct! " + err_detail
            )
        else:
            yield UpdateType.Progress, f"Loading results from file '{result_file_name}'"
            full_result_path = path / result_file_name

            if full_result_path.exists():
                with open(full_result_path, "r") as f:
                    content = f.read()

                try:
                    results = json.loads(content)
                except json.JSONDecodeError as exc:
                    yield UpdateType.Error, f"Malformed JSON response in '{result_file_name}': {exc}"

                yield UpdateType.Progress, f"Deleting results file '{result_file_name}'"
                full_result_path.unlink()
            else:
                yield UpdateType.Error, "No result file was created"

        return results

    @classmethod
    def parse_results(cls, results: list[list[dict]]) -> list[CheckResult]:
        """
        Parses the raw results and turns them into a flat list of check results.
        The results consists of a list of the results per file.
        Per file is a dict per resource within that file.
        For each resource there is a list of 'advises' by the tool, which are the individual checks.

        :param results: the results which will be parsed
        :returns: the list of check results
        """
        check_id_pattern = re.compile(r"^(\w+(?:-\d+)+)")  # match the first letters and then the numbers following it
        check_results = []
        for query in results["queries"]:
            scanner_check_id = query["query_id"]
            scanner_check_name = query["query_name"]

            # fill out remaining 'higher level' information and add it to final results
            for f in query["files"]:
                checked_path = ""
                obj_name = Path(f["file_name"]).stem[:-3]  # drop the appended ".k8s.yaml"
                m = check_id_pattern.search(obj_name)
                check_id = m.group(1).upper() if m is not None else None

                if scanner_check_name in CHECK_MAPPING:
                    _, checked_path = CHECK_MAPPING[scanner_check_name]
                elif query["platform"].lower() == "kubernetes":
                    checked_path = _extract_checked_path(f)

                if checked_path == "" or checked_path is None:
                    checked_path = get_path_to_line_from_file(f["file_name"], f["line"])
                    checked_path = normalize_path(checked_path)

                check_results.append(
                    CheckResult(
                        check_id=check_id,
                        obj_name=obj_name,
                        scanner_check_id=scanner_check_id,
                        scanner_check_name=scanner_check_name,
                        got=CheckStatus.Alert,
                        checked_path=checked_path,
                        severity=query["severity"],
                        details=query["description"],
                        extra=f'{query["category"]}:{f["issue_type"]}',
                    )
                )

        return check_results

    @classmethod
    def categorize_check(cls, check_id: str) -> Optional[str]:
        """Categorize a check depending on its ID.
        If the check id is invalid, no category will be assigned.

        :param check_id: the id used as the basis for the categorization
        :return: either a category for the check or None if no category can be assigned.
        """
        if pd.isnull(check_id) or not check_id:
            return None

        for scanner_check_id, (cat, _) in CHECK_MAPPING.items():
            if check_id == scanner_check_id:
                return cat
        return None


def _extract_checked_path(file: dict) -> str:
    """Extract a sensible path from various fields in the file dictionary by applying several heuristics.

    :param file: a dictionary with information of the query result of a file
    :return: the path used by the query
    """
    search_key = _normalize_path(file["search_key"])
    actual_val = _normalize_path(file["actual_value"])
    expected_val = _normalize_path(file["expected_value"])

    paths = sorted(set([search_key, actual_val, expected_val]), key=len, reverse=True)
    # unify the paths
    # if all paths are the same pick any
    if len(paths) == 1:
        return search_key

    # if one path is more specific, pick that
    # order paths by length descending
    sorted_paths = sorted(paths, key=len, reverse=True)
    paths = []
    for path in sorted_paths:
        is_parent_path = any([path in p for p in paths])
        if not is_parent_path:
            paths.append(path)

    # if there is only one specific path, return it
    if len(paths) == 1:
        return paths[0]

    # as last resort, try merging the paths
    path = _merge_paths(paths)
    return path


def _merge_paths(paths: list[str]) -> str:
    spec, other = [], []
    for p in paths:
        spec.append(p) if "spec" in p else other.append(p)

    # if there is a spec prefix and a single other, then simply append it
    if len(spec) == 1 and len(other) == 1:
        sep = "." if not other[0].startswith(".") else ""
        return f"{spec[0]}{sep}{other[0]}"

    return ""


def _is_fs_path_value(string: str) -> bool:
    # a FS path contains at least one path seperator (i.e. '/') and
    # is wrapped in quotes because it's a value in anothert string
    return "/" in string and string[0] == "'" and string[-1] == "'"


def _normalize_path(path: str) -> str:
    # a path is a token which contains a '.' but no '/' (this would be a path)
    if "." in path:
        tokens = [t for t in path.split(" ") if "." in t and not _is_fs_path_value(t)]

        if len(tokens) == 0:
            return ""
        # always take the first token as the path
        # if there are multiple tokens then the other are most likely values
        path = tokens[0]
    else:
        # if the path is describe as attribute the actual field is in quotes
        if path.startswith("Attribute"):
            return QUOTED_PATH_PATTERN.sub(r".\1", path)
        return ""

    # if a path is within quotes extract it
    path = QUOTED_PATH_PATTERN.sub(r"\1", path)

    # drop '.*.spec.template' prefix
    path = re.sub(r".?spec.template", "", path)

    # drop metadata name prefix as it's not a valid path
    path = META_NAME_PATTERN.sub("", path)

    # drop name or index information in arrays
    path = ARRAY_INDEX_PATTERN.sub("[]", path)

    # arrays with the '<obj>.name={{...}}' will be turned into just the braces '<obj>[]'
    path = ARRAY_NAME_PATTERN.sub(r"\1[]", path)  # re.sub(r"().name={{.*?}}", ".name", path)

    # ignore value specification (i.e. value after '=')
    # this shold be after conversion of ARRAY_NAME_PATTERN to array because of overlapping patterns
    path = ASSIGNED_VALUE_PATTERN.sub("", path)

    # ensure that paths not starting with uppercase (i.e. kind name) are relative
    if not path[0].isupper() and path[0] != ".":
        path = "." + path

    return path


def get_path_to_line_from_file(file_name: str, line_nr: int) -> str:
    """Get the path to the field specified by the line number.

    :param file_name: the name with the contents of the manifest
    :param line_nr: the number of the line targeted by the check
    :return: the path as a string
    """
    file_path = MANIFESTS_DIR / (Path(file_name).name)

    with open(file_path, "r") as f:
        return get_path_to_line(f.readlines(), line_nr)
