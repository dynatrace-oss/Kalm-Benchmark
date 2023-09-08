from pathlib import Path
from typing import Optional

import pandas as pd

from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

run_in_cluster = False
local_run_cmd = (
    "docker run --pid=host -v /etc:/etc:ro -v -t aquasec/kube-bench:latest --json /var/results.json --version 1.22 run"
)
check_cluster_cmd = "" if run_in_cluster else local_run_cmd
check_configs_cmd = ""


CLUSTER_RES_FILE = Path("kubebench.json")

# mapping of the test number to the corresponding check-id in the benchmark and the check category
CHECK_MAPPING = {
    "5.1.1": ("RBAC-001", CheckCategory.RBAC),
    "5.1.2": ("RBAC-002", CheckCategory.RBAC),
    "5.1.3": ("RBAC-003", CheckCategory.RBAC),
    "5.1.4": ("RBAC-004", CheckCategory.RBAC),
    "5.1.5": ("POD-002", CheckCategory.PodSecurity),
    "5.1.6": ("POD-003", CheckCategory.PodSecurity),
    "5.1.7": ("RBAC-019", CheckCategory.RBAC),
    "5.1.8": ("RBAC-020", CheckCategory.RBAC),
    "5.2.1": ("PSS-001", CheckCategory.PSS),
    "5.2.2": ("PSS-002", CheckCategory.PSS),
    "5.2.3": ("PSS-004", CheckCategory.PSS),
    "5.2.4": ("PSS-005", CheckCategory.PSS),
    "5.2.5": ("PSS-006", CheckCategory.PSS),
    "5.2.6": ("PSS-003", CheckCategory.PSS),
    "5.2.7": ("PSS-008", CheckCategory.PSS),
    "5.2.8": ("PSS-010", CheckCategory.PSS),
    "5.2.9": ("PSS-011", CheckCategory.PSS),
    "5.2.10": ("PSS-012", CheckCategory.PSS),
    "5.2.11": ("PSS-013", CheckCategory.PSS),
    "5.2.12": ("PSS-014", CheckCategory.PSS),
    "5.2.13": ("PSS-015", CheckCategory.PSS),
    "5.3.1": ("NP-000", CheckCategory.Network),
    "5.3.2": ("NP-001", CheckCategory.Network),
    "5.4.1": ("POD-024", CheckCategory.SecretManagement),
    "5.4.2": ("SM-003", CheckCategory.SecretManagement),
    "5.5.1": ("SC-003", CheckCategory.SupplyChain),
    "5.7.1": ("NS-003", CheckCategory.Workload),
    "5.7.2": ("POD-022", CheckCategory.PodSecurity),
    "5.7.3": ("POD-016", CheckCategory.PodSecurity),
    "5.7.4": ("NS-001", CheckCategory.Workload),
}

CHECK_CATEGORY = {
    "1.1": "Control Plane Node Configuration Files",
    "1.2": "API Server",
    "1.3": "Controller Manager",
    "1.4": "Scheduler",
    "2": "ETCD",
    "3.1": "Authentication and Authorization",
    "3.2": "Logging",
    "4.1": "Worker Node Configuration Files",
    "4.2": "Kubelet",
    "5.1": "RBAC and Service Accounts",
    "5.2": "Pod Security Standards",
    "5.3": "Network Policies and CNI",
    "5.4": "Secrets Management",
    "5.5": "Extensible Admission Control",
    "5.7": "General Policies",
}


class Scanner(ScannerBase):
    NAME = "kube-bench"
    IMAGE_URL = "https://github.com/aquasecurity/kube-bench/raw/main/docs/images/kube-bench.png"
    FORMATS = ["Plain", "JSON", "JUnit", "PostgreSQL", "ASFF"]
    SCAN_CLUSTER_CMD = [
        "docker",
        "run",
        "--pid=host",
        "aquasec/kube-bench:latest",
        "--json",
        "run",
    ]
    NOTES = [
        "kube-bench is a tool to check whether Kubernetes itself is deployed securiely according to the CIS benchmark. "
        "It focuses on the infrastructure aspect and thus, is out of scope of this benchmark."
    ]
    CI_MODE = True
    VERSION_CMD = ["docker", "run", "aquasec/kube-bench:latest", "version"]

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
        check_results = []

        # a 'control` is a suit of test of a single category (i.e. a section in the CIS benchmark)
        for control in results["Controls"]:
            # a 'test' is sub-section in the CIS benchmark
            for test in control["tests"]:
                # a result is an actual check within that sub-section
                for result in test["results"]:
                    scanner_check_id = result["test_number"]
                    scanner_check_name = result["test_desc"]

                    status = CheckStatus.Pass if result["status"] == "PASS" else CheckStatus.Alert
                    check_results.append(
                        CheckResult(
                            scanner_check_id=scanner_check_id,
                            scanner_check_name=scanner_check_name,
                            got=status,
                            checked_path=result["audit"],
                            details=result["remediation"],
                            extra=result.get("reason", ""),
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

    @classmethod
    def categorize_check(cls, check_id: str) -> Optional[str]:
        """Categorize a check depending on its ID.
        If the check id is invalid, no category will be assigned.

        :param check_id: the id used as the basis for the categorization
        :return: either a category for the check or None if no category can be assigned.
        """
        if pd.isnull(check_id) or not check_id:
            return None

        _, cat = CHECK_MAPPING.get(check_id, (None, None))
        if cat is not None:
            return cat

        # section 2 has no sub-section, this means the id consists of 2 numbers (e.g. 2.x)
        if check_id.startswith("2."):
            return CHECK_CATEGORY["2"]
        else:
            # use only the first 2 parts of the id for the classification
            id_pfx = check_id[: check_id.rindex(".")]
            return CHECK_CATEGORY[id_pfx]
