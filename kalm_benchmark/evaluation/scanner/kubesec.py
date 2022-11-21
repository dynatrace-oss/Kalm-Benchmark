import re

from .scanner_evaluator import CheckResult, CheckStatus, ScannerBase


class Scanner(ScannerBase):
    NAME = "kubesec"
    SCAN_MANIFESTS_CMD = ["kubesec", "scan", "-f", "json", "--exit-code", "0"]
    SCAN_PER_FILE = True
    IMAGE_URL = "http://casual-hosting.s3.amazonaws.com/kubesec-logo.png"
    RUNS_OFFLINE = True
    CI_MODE = True
    FORMATS = ["JSON", "Template"]
    VERSION_CMD = ["kubesec", "version"]

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
        for file in results:
            for resource in file:
                kind, name = resource["object"].split("/")

                m = check_id_pattern.search(name)
                check_id = m.group(1) if m is not None else None
                scoring = resource["scoring"]

                if len(scoring) == 0:
                    details = resource["message"]
                    # keep track if there were failed results which are not due to unsupported resources

                    if resource["valid"]:
                        # provide the message as id so it can be analyzed in the UI
                        scanner_check_id = resource["message"]
                        checked_path = "kind" if details == "This resource kind is not supported by kubesec" else None
                    elif ":" in details:
                        checked_path, *_, msg = details.split(":")
                        checked_path = _normalize_path(checked_path)
                        scanner_check_id = msg.strip()

                    extra = "" if resource["valid"] else "Failed to parse the resource"

                    check_results.append(
                        CheckResult(
                            check_id=check_id,
                            scanner_check_id=scanner_check_id,
                            checked_path=checked_path,
                            obj_name=name,
                            kind=kind,
                            details=details,
                            extra=extra,
                            got=CheckStatus.Other,
                        )
                    )
                    continue

                # look only into 'advise' section. The 'passed' entries are not of interest
                for advise in scoring.get("advise", []):
                    # if ":" in msg:
                    # scanner_check_id, details = msg.split(":", maxsplit=1)

                    checked_path = _normalize_path(advise["selector"])

                    check_results.append(
                        CheckResult(
                            check_id=check_id,
                            obj_name=name,
                            scanner_check_id=advise["id"],
                            got=CheckStatus.Alert,  # every advise is treated as alert
                            checked_path=checked_path,
                            severity=advise["points"],
                            kind=kind,
                            details=advise["reason"],
                        )
                    )

        return check_results

    def get_version(self) -> str:
        """Retrieve the hardcoded version number of the tool.
        The tool has a version command, but it's not working (see https://github.com/controlplaneio/kubesec/issues/337)
        :return: the version number of the tool
        """
        # version = super().get_version()
        return "2.12.0"


def _normalize_path(path: str) -> str:
    # remove spaces before '.'
    path = path.replace(" .", ".")
    # remove quotes
    path = path.replace('"', "")
    # prefix containrs[] with '.spec.'
    if path.startswith("containers"):
        path = ".spec." + path
    return path
