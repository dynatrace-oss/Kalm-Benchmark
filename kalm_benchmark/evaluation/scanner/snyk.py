from typing import Tuple

from loguru import logger

from kalm_benchmark.utils.path_normalization import normalize_snyk_path

from ...utils.eval_utils import (
    fix_path_to_current_environment,
    get_difference_in_parent_path,
)
from ..file_index import FileIndex
from .scanner_evaluator import CheckResult, CheckStatus, ScannerBase

CHECK_MAPPING = {}


class Scanner(ScannerBase):
    NAME = "Snyk"
    SCAN_MANIFESTS_CMD = ["snyk", "iac", "test", "--json"]
    NOTE = ["Cluster scans are available in Business and Enterprise plans."]
    IMAGE_URL = "https://res.cloudinary.com/snyk/image/upload/snyk-marketingui/brand-logos/wordmark-logo-color.svg"
    CI_MODE = True
    CUSTOM_CHECKS = "in Rego"
    FORMATS = ["Plain", "JSON", "SARIF"]
    EXIT_CODES = {
        0: "success, no vulnerabilities found",
        1: "action_needed, vulnerabilities found",
        2: "failure, try to re-run command",
        3: "failure, no supported projects detected",
    }
    VERSION_CMD = ["snyk", "version"]

    @classmethod
    def parse_results(cls, results: dict | list[list[dict]]) -> list[CheckResult]:
        """
        Parses the raw results and turns them into a flat list of check results.
        The results consists of a list of the results per file.
        Per file is a dict per resource within that file.
        For each resource there is a list of 'advises' by the tool, which are the individual checks.

        :param results: the results which will be parsed
        :returns: the list of check results
        """

        # in case only 1 file was scanned wrap it in a list, so it's consistent
        if isinstance(results, dict):
            results = [results]

        check_results = []
        path_adjustment: Tuple[str, str] | None = None

        for file in results:
            # as there is no information on the check and checked objects
            # this information has to be retrieved from the file

            file_path = file["targetFilePath"]
            if path_adjustment is not None:
                file_path = file_path.replace(*path_adjustment)
            try:
                file_index = FileIndex.create_from_file(file_path)
            except FileNotFoundError:
                fixed_path = fix_path_to_current_environment(file["targetFilePath"])
                if fixed_path == "":
                    logger.warning(f"Could not find file '{file_path}' it will be skipped - distorting the results")
                    continue
                path_adjustment = get_difference_in_parent_path(file_path, fixed_path)
                file_index = FileIndex.create_from_file(fixed_path)

            for issue in file["infrastructureAsCodeIssues"]:
                scanner_check_id = issue["id"]

                obj = file_index.get_at_line(issue["lineNumber"])
                obj_meta = obj["metadata"]
                obj_name = obj_meta["name"]
                ns = obj_meta.get("namespace", None)
                kind = obj["kind"]

                check_id = obj_meta.get("labels", {}).get("check", None)

                checked_path = _normalize_path(issue["msg"], kind=kind)
                status = CheckStatus.Alert

                # the information on the remediation is inconsinstent across checks
                if "resolve" in issue:
                    remediation = issue["resolve"]
                elif "remediation" in issue:
                    remediation = issue["remediation"]["kubernetes"]
                else:
                    remediation = None

                check_results.append(
                    CheckResult(
                        check_id=check_id,
                        obj_name=obj_name,
                        scanner_check_id=scanner_check_id,
                        scanner_check_name=issue["title"],
                        got=status,
                        severity=issue["severity"],
                        checked_path=checked_path,
                        kind=kind,
                        namespace=ns,
                        details=issue["impact"],
                        extra=remediation,
                    )
                )
        return check_results

    @classmethod
    def get_checked_path(cls, check_id: str) -> str:
        """Get the path(s) controlled by the check.

        :param check_id: the id of the check
        :return: the check(s) as single string or an empty string if no path could be retrieved.
        """
        _, paths = CHECK_MAPPING.get(check_id.lower(), (None, None))
        if isinstance(paths, str):
            return paths

        if isinstance(paths, list):
            return "|".join(paths)

        return ""

    def get_version(self) -> str:
        """Retrieve the version number of the tool by executing the corresponding command.
        The tool returns the version number in the format "<version> (<tag>)".
        :return: the version number of the tool
        """
        version = super().get_version()
        if " " in version:
            version, _ = version.split(" ", maxsplit=1)
        return version


def _normalize_path(path: str, kind: str | None = None) -> str:
    return normalize_snyk_path(path, kind)
