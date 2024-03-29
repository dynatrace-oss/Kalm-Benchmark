import json
from pathlib import Path
from typing import Optional

import pandas as pd
from loguru import logger

from kalm_benchmark.constants import RunUpdateGenerator, UpdateType

from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

CONTROL_MAPPING = {
    "AllowPrivilegeEscalation": (
        CheckCategory.Workload,
        ".spec.containers[].securityContext.allowPrivilegeEscalation",
    ),
    "AppArmor": (CheckCategory.Workload, ".metadata.annotations.container.apparmor.security.beta.kubernetes.io"),
    "AutomountServiceAccountToken": (
        CheckCategory.Workload,
        [".spec.serviceAccount", ".spec.automountServiceAccountToken"],
    ),
    "Capability": (CheckCategory.Workload, ".spec.containers[].securityContext.capabilities"),
    "DeprecatedAPIUsed": (CheckCategory.Workload, ".apiVersion"),
    "Image": (CheckCategory.Workload, ".spec.containers[].image"),
    "Limits": (
        CheckCategory.Reliability,
        [".spec.containers[].resources.limits.cpu", ".spec.containers[].resources.limits.memory"],
    ),
    "NamespaceHost": (CheckCategory.Workload, [".spec.hostIPC", ".spec.hostPID", ".spec.hostNetwork"]),
    "MissingDefaultDeny": (CheckCategory.Segregation, ".spec.ingress"),
    "AllowAllIngressNetworkPolicyExists": (CheckCategory.Segregation, ".spec.ingress"),
    "AllowAllEgressNetworkPolicyExists": (CheckCategory.Segregation, ".spec.egress"),
    "Privileged": (CheckCategory.Workload, ".spec.containers[].securityContext.privileged"),
    "ReadOnlyRootFilesystem": (CheckCategory.Workload, ".spec.containers[].securityContext.readOnlyRootFilesystem"),
    "RunAsNonRootCSC": (CheckCategory.Workload, ".spec.containers[].securityContext.runAsNonRoot"),
    "RunAsNonRootPSC": (CheckCategory.Workload, ".spec.securityContext.runAsNonRoot"),
    "RunAsUserCSC": (CheckCategory.Workload, ".spec.containers[].securityContext.runAsUser"),
    "RunAsUserPSC": (CheckCategory.Workload, ".spec.securityContext.runAsUser"),
    "Seccomp": (
        CheckCategory.Workload,
        [
            ".metadata.annotations.seccomp.security.alpha.kubernetes.io/pod",
            ".metadata.annotationscontainer.seccomp.security.alpha.kubernetes.io",
            ".spec.securityContext.seccompProfile",
            ".spec.containers[].securityContext.seccompProfile",
        ],
    ),
    "SensitivePathsMounted": (CheckCategory.Workload, ".spec.volumes[].hostPath.path"),
}


class Scanner(ScannerBase):
    NAME = "kubeaudit"
    FORMATS = ["Plain", "JSON", "Sarif", "logrus"]
    CI_MODE = True
    CUSTOM_CHECKS = "by implementing custom Auditors"
    SCAN_CLUSTER_CMD = ["kubeaudit", "all", "-p", "json"]
    SCAN_MANIFESTS_CMD = ["kubeaudit", "all", "-p", "sarif", "-f"]
    SCAN_PER_FILE = True
    RUNS_OFFLINE = True
    VERSION_CMD = ["kubeaudit", "version"]

    def scan_manifests(self, path: Path) -> RunUpdateGenerator:
        res = yield from super().scan_manifests(path, parse_json=False)
        results = yield from self._parse_scan_result(res)
        return results

    def scan_cluster(self) -> RunUpdateGenerator:
        """
        Run the application against the benchmark cluster
        :returns the results as dictionary
        """
        res = yield from super().scan_cluster(parse_json=False)
        results = yield from self._parse_scan_result([res])
        return results

    def _parse_scan_result(self, res: list[str]) -> RunUpdateGenerator:
        """Parse the results from kubeaudit.
        Kubeaudit return results as "JSON lines" and not as a single JSON result.
        Individual lines are separated by the newline character '\n'.

        :param res: the list of results
        :return: the parsed results
        :yield: any error occuring while parsing
        """
        results = []
        for result in res:
            for line in result.rstrip().split("\n"):
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    yield UpdateType.Error, f"Malformed JSON result: '{exc}'"
        return results

    @classmethod
    def parse_results(cls, results: list[dict]) -> list[CheckResult]:
        """
        Parses the raw results and turns them into a flat list of check results.
        :param results: the results which will be parsed
        :returns: the list of check results
        """
        ctrls = [
            CheckResult(
                obj_name=r["ResourceName"],
                kind=r["ResourceKind"],
                got=CheckStatus.Alert,  # kubeaudit produces only alerts
                namespace=r.get("ResourceNamespace", None),
                details=r["msg"],
                scanner_check_id=r["AuditResultName"],
                severity=r["level"],
                checked_path=cls.get_checked_path(r["AuditResultName"]),
            )
            for r in results
            if "ResourceName" in r
        ]

        return ctrls

    @classmethod
    def categorize_check(cls, check_id: str) -> Optional[str]:
        """Categorize a check depending on its ID.
        If the check id is invalid, no category will be assigned.

        :param check_id: the id used as the basis for the categorization
        :return: either a category for the check or None if no category can be assigned.
        """
        if pd.isnull(check_id) or not check_id:
            return None

        for cat_prefix, (cat, _) in CONTROL_MAPPING.items():
            if check_id.startswith(cat_prefix):
                return cat
        logger.warning(f"No matching control found for check with ID '{check_id}'")
        return None

    @classmethod
    def get_checked_path(cls, check_id: str) -> str:
        """Get the path(s) controlled by the check.

        :param check_id: the id of the check
        :return: the check(s) as single string or an empty string if no path could be retrieved.
        """
        for cat_prefix, (_, paths) in CONTROL_MAPPING.items():
            if check_id.startswith(cat_prefix):
                if isinstance(paths, str):
                    return paths

                if isinstance(paths, list):
                    return "|".join(paths)

        return ""
