import re
from typing import Optional

import pandas as pd

from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

CHECK_MAPPING = {
    "automountServiceAccountToken": (CheckCategory.Workload, [".spec.automountServiceAccountToken","ServiceAccount.automountServiceAccountToken"]),
    "cpuLimitsMissing": (CheckCategory.Reliability, ".spec.containers[].resources.limits.cpu"),
    "cpuRequestsMissing": (CheckCategory.Reliability, ".spec.containers[].resources.requests.cpu"),
    "dangerousCapabilities": (CheckCategory.Workload, ".spec.containers[].securityContext.capabilities"),
    "deploymentMissingReplicas": (CheckCategory.Reliability, "Deployment.spec.replicas"),
    "hostIPCSet": (CheckCategory.Workload, ".spec.hostIPC"),
    "hostNetworkSet": (CheckCategory.Workload, ".spec.hostNetwork"),
    "hostPIDSet": (CheckCategory.Workload, ".spec.hostPID"),
    "hostPortSet": (CheckCategory.Workload, ".spec.containers[].ports"),
    "insecureCapabilities": (CheckCategory.Workload, ".spec.containers[].securityContext.capabilities"),
    "linuxHardening": (
        CheckCategory.Workload,
        [
            ".spec.securityContext.seccompProfile.type",
            ".spec.securityContext.seLinuxOptions",
            ".spec.containers[].securityContext.seccompProfile.type",
            ".spec.containers[].securityContext.seLinuxOptions",
            ".spec.containers[].securityContext.capabilities.drop",
        ],
    ),
    "livenessProbeMissing": (CheckCategory.Reliability, ".spec.containers[].livenessProbe"),
    "metadataAndInstanceMismatched": (CheckCategory.Reliability, ".metadata.labels"),
    "memoryLimitsMissing": (CheckCategory.Reliability, ".spec.containers[].resources.limits.memory"),
    "memoryRequestsMissing": (CheckCategory.Reliability, ".spec.containers[].resources.requests.memory"),
    "missingPodDisruptionBudget": (CheckCategory.Reliability, "PodDisruptionBudget"),  # ignored by default
    "missingNetworkPolicy": (CheckCategory.Segregation, ["NetworkPolicy.spec.podSelector", "NetworkPolicy.spec.ingress", "Networkpolicy.spec.egress"]),  
    "notReadOnlyRootFilesystem": (
        CheckCategory.Workload,
        ".spec.containers[].securityContext.readOnlyRootFilesystem",
    ),
    "privilegeEscalationAllowed": (
        CheckCategory.Workload,
        ".spec.containers[].securityContext.allowPrivilegeEscalation",
    ),
    "priorityClassNotSet": (CheckCategory.Reliability, ".spec.priorityClassName"),  # ignored by default
    "pullPolicyNotAlways": (CheckCategory.Workload, ".spec.containers[].imagePullPolicy"),
    "readinessProbeMissing": (CheckCategory.Reliability, ".spec.containers[].readinessProbe"),
    "runAsPrivileged": (CheckCategory.Workload, ".spec.containers[].securityContext.privileged"),
    "runAsRootAllowed": (
        CheckCategory.Workload,
        [".spec.securityContext.runAsNonRoot", ".spec.containers[].securityContext.runAsNonRoot"],
    ),
    "sensitiveContainerEnvVar": (
        CheckCategory.Workload,
        [".spec.containers[].env[].valueFrom", ".spec.containers[].env[].value"],
    ),
    "sensitiveConfigmapContent": (
        CheckCategory.DataSecurity,
        [".data.secret", ".data.bearer", ".data.token", "data.password"],
    ),
    "tagNotSpecified": (CheckCategory.Workload, ".spec.containers[].image"),
    "topologySpreadConstraint": (CheckCategory.Reliability, ".spec.topologySpreadConstraints[].topologyKey"),
    "tlsSettingsMissing": (CheckCategory.Network, "Ingress.spec.tls"),
    "clusterrolePodExecAttach": (CheckCategory.IAM, "ClusterRole.rules[].resources"),
    "rolePodExecAttach": (CheckCategory.IAM, "Role.rules[].resources"),
    "clusterrolebindingPodExecAttach": (CheckCategory.IAM, "ClusterRole.rules[].resources"),
    "rolebindingClusterRolePodExecAttach": (CheckCategory.IAM, "ClusterRole.rules[].resources"),
    "rolebindingRolePodExecAttach": (CheckCategory.IAM, "Role.rules[].resources"),
    "clusterrolebindingClusterAdmin": (CheckCategory.IAM, "ClusterRoleBinding.roleRef.name"),
    "rolebindingClusterAdminClusterRole": (CheckCategory.IAM, "RoleBinding.roleRef.name"),
    "rolebindingClusterAdminRole": (CheckCategory.IAM, ".rules[].resources"),
}


class Scanner(ScannerBase):
    NAME = "polaris"
    SCAN_MANIFESTS_CMD = ["polaris", "audit", "--audit-path"]
    CI_MODE = True
    FORMATS = ["Pretty", "JSON", "YAML"]
    EXIT_CODES = {0: "Success", 4: "Score is below threshold (1-100)", 3: "Audit contains danger-level issues"}
    CUSTOM_CHECKS = "as JSON/YAML files"
    RUNS_OFFLINE = True
    IMAGE_URL = "https://polaris.docs.fairwinds.com/img/polaris-logo.png"
    VERSION_CMD = ["polaris", "version"]

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
        for result in results["Results"]:
            name = result["Name"]
            m = check_id_pattern.search(name)
            check_id = m.group(1).upper() if m is not None else None

            ns = result["Namespace"]
            kind = result["Kind"]

            res = cls._parse_check_results(result["Results"])
            res += cls._parse_pod_results(result["PodResult"])

            # fill out remaining 'higher level' information and add it to final results
            for r in res:
                r.check_id = check_id
                r.obj_name = name
                r.kind = kind
                r.namespace = ns
                check_results.append(r)

        return check_results

    @classmethod
    def _parse_pod_results(cls, results: dict | None) -> list[CheckResult]:
        if results is None:
            return []
        check_results = cls._parse_check_results(results["Results"])
        if "ContainerResults" in results:
            for container_res in results["ContainerResults"]:
                check_results += cls._parse_check_results(container_res["Results"])
        return check_results

    @classmethod
    def _parse_check_results(cls, results: dict) -> list[CheckResult]:
        check_results = []
        for scanner_check_name, check in results.items():
            status = CheckStatus.Pass if check["Success"] else CheckStatus.Alert
            details = check["Details"] or ""
            scanner_check_id = check["ID"]
            _cat, checked_path = CHECK_MAPPING.get(scanner_check_id, (None, None))

            if checked_path is None:
                print(f"Unknown check {scanner_check_id}!")
                continue

            if isinstance(checked_path, list):
                checked_path = "|".join(checked_path)

            check_results.append(
                CheckResult(
                    checked_path=checked_path,
                    scanner_check_id=scanner_check_id,
                    scanner_check_name=scanner_check_name,
                    got=status,
                    severity=check["Severity"],
                    details=";".join([check["Message"], details]),
                    extra=f"Category: {check['Category']}",
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

    def get_version(self) -> str:
        """Retrieve the version number of the tool by executing the corresponding command.
        The tool returns the version in the format "Polaris version:<version>"
        :return: the version number of the tool
        """
        raw_version = super().get_version()
        label, version = raw_version.split(":", maxsplit=1)
        return version.strip()
