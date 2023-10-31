import re
from dataclasses import dataclass, fields

import pandas as pd

from .scanner_evaluator import (
    CheckCategory,
    CheckResult,
    CheckStatus,
    RunUpdateGenerator,
    ScannerBase,
)

CASE_PATTERN = re.compile(r"(?<!^)(?=[A-Z])")


@dataclass
class AlertObject:
    priority: str
    kind: str
    namespace: str
    name: str
    rules: str = None
    # 'PodName' will be mapped to the 'name'
    container_name: str = None
    service_account_namespace: str = None
    service_account_name: str = None
    decoded_token: str = None

    @classmethod
    def from_dict(cls, kwargs: dict) -> "AlertObject":
        """Instantiate a new AlertObject from the provided dictionary.

        :param kwargs: the dictionary with all keys and values
        :return: the newly created instance
        """
        valid_fields = [f.name for f in fields(cls)]

        valid_kwargs = {}
        # go over all the provided keyword arguments and convert/filter for only valid fields
        for key, value in kwargs.items():
            if key == "PodName":
                fixed_key = "name"
            else:
                fixed_key = re.sub(CASE_PATTERN, "_", key).replace(" ", "_").lower()

            if fixed_key in valid_fields:
                valid_kwargs[fixed_key] = value
        return cls(**valid_kwargs)


class Scanner(ScannerBase):
    NAME = "kubiscan"
    NOTES = ["KubiScan does not support JSON output"]
    FORMATS = ["Pretty"]
    RUNS_OFFLINE = True
    IMAGE_URL = "https://www.cyberark.com/wp-content/uploads/2018/12/kubiScan_logo-150x150.png"
    # note: it's assumed that the dependencies are installed in the virtual env
    # see https://github.com/cyberark/KubiScan#directly-with-python3
    SCAN_CLUSTER_CMD = ["kubiscan", "-a"]
    # the tool has no dedicated version command, but the version number is printed in the banner of the tool
    VERSION_CMD = ["kubiscan"]

    def scan_cluster(self) -> RunUpdateGenerator:
        res = yield from super().scan_cluster(parse_json=False)
        return res

    @classmethod
    def parse_results(cls, content: list[list[dict]]) -> list[CheckResult]:
        """
        Parses the raw results and turns them into a flat list of check results.
        The results consists of a list of the results per file.
        Per file is a dict per resource within that file.
        For each resource there is a list of 'advises' by the tool, which are the individual checks.

        :param results: the results which will be parsed
        :returns: the list of check results
        """
        if isinstance(content, str):
            content = content.split("\n")

        results = cls._preprocess_output(content)

        check_id_pattern = re.compile(r"^(\w+(?:-\d+)+)")  # match the first letters and then the numbers following it

        check_results = []
        for scanner_check_name, rows in results.items():
            checked_path = cls._get_checked_path_from_scan_name(scanner_check_name)
            for obj in rows:
                m = check_id_pattern.search(obj.name)
                check_id = m.group(1) if m is not None else None

                check_results.append(
                    CheckResult(
                        check_id=check_id,
                        obj_name=obj.name,
                        scanner_check_id=scanner_check_name,
                        got=CheckStatus.Alert,  # every advise is treated as alert
                        checked_path=checked_path,
                        severity=obj.priority,
                        kind=obj.kind,
                        namespace=obj.namespace,
                    )
                )
        return check_results

    @classmethod
    def categorize_check(cls, check_id: str) -> str:
        # this tool is all about RBAC and nothing else
        if pd.isnull(check_id) or not check_id:
            return None
        return CheckCategory.IAM

    @classmethod
    def _get_checked_path_from_scan_name(cls, scan_name: str) -> str:
        name = scan_name.lower()
        paths = []
        if "risky roles" in name or "risky clusterroles" in name:
            paths = [
                "ClusterRole.rules[].verbs",
                "ClusterRole.rules[].resources",
                "Role.rules[].verbs",
                "Role.rules[].resources",
                ".rules[].verbs",
                ".rules[].resources",
            ]
        elif "risky rolebindings" in name or "risky clusterrolebindings" in name:
            paths = [
                "RoleBinding.roleRef.name",
                "ClusterRoleBinding.roleRef.name",
                ".roleRef.name",
                "ClusterRoleBinding.subjects[].name",
                "RoleBinding.subjects[].name",
                ".subjects[].name",
            ]
        elif "risky users" in name:
            paths = [
                "ClusterRoleBinding.subjects[].name",
                "RoleBinding.subjects[].name",
                ".subjects[].name",
                "RoleBinding.roleRef.name",
                "ClusterRoleBinding.roleRef.name",
                ".roleRef.name",
            ]
        elif "risky containers" in name:
            paths = [
                "ClusterRoleBinding.subjects[].name",
                "RoleBinding.subjects[].name",
                ".subjects[].name",
                "ServiceAccount.metadata.name",
                ".metadata.name",
            ]

        return "|".join(paths)

    @classmethod
    def _preprocess_output(cls, lines: list[str]) -> dict[list]:
        """Processes the raw output of the tool and splits it into sections of the various checks.
        Any content besides the printed tables will be dropped.

        :param lines: the lines as read from the file
        :return: a dictionary mapping a
        """
        tables = {}
        curr_table = []
        for line in lines:
            if line.startswith(("+-", "|")):  # these symbols are part of a table
                curr_table.append(line)
            elif len(curr_table) > 0:
                name, table = cls._parse_table(curr_table)
                tables[name] = table
                curr_table = []
        return tables

    @classmethod
    def _parse_table(cls, lines: list[str]) -> tuple[str, list[dict]]:
        # because of the layout of the table is the name of the check always the 2nd line
        name = lines[1].strip("|\n")
        columns = [c.strip().lower() for c in lines[3].strip("|\n").split("|")]

        rows = []
        for row in lines[5:-1]:
            cells = [c.strip() for c in row.strip("|\n").split("|")]
            # drop the  color code from the priority
            m = re.search(r"[A-Z]+", cells[0])
            cells[0] = m.group() if m is not None else cells[0]
            alert_obj = AlertObject.from_dict(dict(zip(columns, cells)))
            rows.append(alert_obj)
        return name, rows

    def get_version(self) -> str:
        """Extract the version number from the banner of the tool
        The banner has a dedicated line with the format "\t*KubiScan version <version>"
        :return: the version number of the tool
        """
        banner = super().get_version()
        # look for the 'version' keyword to identify the relevant line with the version number
        version_line = next((line for line in banner.split("\n") if "version" in line), None)
        if version_line is None:
            return None

        _, version = version_line.rsplit(" ", maxsplit=1)
        return version
