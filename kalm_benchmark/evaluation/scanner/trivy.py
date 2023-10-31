import re
from pathlib import Path

from loguru import logger

from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

CHECK_MAPPING = {
    "KSV001": (CheckCategory.PodSecurity, [".spec.containers[].securityContext.allowPrivilegeEscalation"]),
    "KSV002": (
        CheckCategory.PodSecurity,
        [
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io"
            ".metadata.annotations[container.apparmor.security.beta.kubernetes.io]",
        ],
    ),
    "KSV003": (CheckCategory.PodSecurity, [".spec.containers[].securityContext.capabilities.drop"]),
    "KSV004": (CheckCategory.PodSecurity, [".spec.containers[].securityContext.capabilities.drop"]),
    "KSV005": (CheckCategory.PodSecurity, [".spec.containers[].securityContext.capabilities.add"]),
    "KSV006": (CheckCategory.PodSecurity, [".spec.volumes[].hostPath.path"]),
    "KSV007": (CheckCategory.PodSecurity, [".spec.hostAliases"]),
    "KSV008": (CheckCategory.PodSecurity, [".spec.hostIPC"]),
    "KSV009": (CheckCategory.PodSecurity, [".spec.hostNetwork"]),
    "KSV010": (CheckCategory.PodSecurity, [".spec.hostPID"]),
    "KSV011": (CheckCategory.Reliability, [".spec.containers[].resources.limits.cpu"]),
    "KSV012": (
        CheckCategory.PodSecurity,
        [".spec.securityContext.runAsNonRoot", ".spec.containers[].securityContext.runAsNonRoot"],
    ),
    "KSV013": (CheckCategory.Workload, [".spec.containers[].image"]),
    "KSV014": (CheckCategory.PodSecurity, [".spec.containers[].securityContext.readOnlyRootFilesystem"]),
    "KSV015": (CheckCategory.Reliability, [".spec.containers[].resources.requests.cpu"]),
    "KSV016": (CheckCategory.Reliability, [".spec.containers[].resources.requests.memory"]),
    "KSV017": (CheckCategory.PodSecurity, [".spec.containers[].securityContext.privileged"]),
    "KSV018": (CheckCategory.Reliability, [".spec.containers[].resources.limits.memory"]),
    "KSV020": (CheckCategory.PodSecurity, [".spec.containers[].securityContext.runAsUser"]),
    "KSV021": (CheckCategory.PodSecurity, [".spec.containers[].securityContext.runAsGroup"]),
    "KSV022": (CheckCategory.PodSecurity, [".spec.containers[].securityContext.capabilities.add"]),
    "KSV023": (CheckCategory.PodSecurity, [".spec.volumes[].hostPath"]),
    "KSV024": (
        CheckCategory.PodSecurity,
        [".spec.containers[].ports[].hostPort", ".spec.initContainers[].ports[].hostPort"],
    ),
    "KSV025": (
        CheckCategory.PodSecurity,
        [".spec.securityContext.seLinuxOptions", ".spec.containers[].securityContext.seLinuxOptions"],
    ),
    "KSV026": (CheckCategory.PodSecurity, [".spec.securityContext.sysctls[]"]),
    "KSV027": (
        CheckCategory.PodSecurity,
        [".spec.containers[].securityContext.procMount", ".spec.initContainers[].securityContext.procMount"],
    ),
    "KSV028": (CheckCategory.PodSecurity, [".spec.volumes[]"]),
    "KSV029": (
        CheckCategory.PodSecurity,
        [
            ".spec.securityContext.fsGRoup",
            ".spec.securityContext.supplementalGroups",
            ".spec.securityContext.runAsGroup",
            ".spec.containers[].securityContext.runAsGroup",
        ],
    ),
    "KSV030": (
        CheckCategory.PodSecurity,
        [
            ".spec.securityContext.seccompProfile.type",
            ".spec.containers[].securityContext.seccompProfile.type",
            ".metadata.annotations[seccomp.security.alpha.kubernetes.io/pod",
        ],
    ),
    "KSV032": (CheckCategory.Workload, [".spec.containers[].image", ".spec.containers[].name"]),
    "KSV033": (CheckCategory.Workload, [".spec.containers[].image", ".spec.containers[].name"]),
    "KSV034": (CheckCategory.Workload, [".spec.containers[].image"]),
    "KSV035": (CheckCategory.Workload, [".spec.containers[].image", ".spec.containers[].name"]),
    "KSV036": (
        CheckCategory.PodSecurity,
        [
            ".spec.automountServiceAccountToken",
            ".automountServiceAccountToken",
            ".spec.containers[].volumeMounts[].mountPath",
        ],
    ),
    "KSV037": (CheckCategory.Workload, [".metadata.namespace"]),
    "KSV038": (
        CheckCategory.Network,
        [
            "NetworkPolicy.spec.podSelector",
            ".spec.podSelector",
            "NetworkPolicy.spec.podSelector.matchLabels",
            "NetworkPolicy.ingress[].from[].namespaceSelector",
            "NetworkPolicy.ingress[].from[].podSelector",
            "NetworkPolicy.egress[].from[].namespaceSelector",
            "NetworkPolicy.egress[].from[].podSelector",
            "NetworkPolicy.spec.policyTypes[]",
        ],
    ),
    "KSV039": (
        CheckCategory.Reliability,
        [
            "LimitRange.metadata.namespace",
            "LimitRange.spec.limits[].type",
            "LimitRange.spec.limits[].max",
            "LimitRange.spec.limits[].min",
            "LimitRange.spec.limits[].default",
            "LimitRange.spec.limits[].defaultRequest",
        ],
    ),
    "KSV040": (  # resource quota usage
        CheckCategory.Reliability,
        [
            "ResourceQuota.metadata.namespace",
            "ResourceQuota.spec.hard.requests.cpu",
            "ResourceQuota.spec.hard.requests.memory",
            "ResourceQuota.spec.hard.limits.cpu",
            "ResourceQuota.spec.hard.limits.memory",
            "ResourceQuota.spec.hard.limits[].defaultRequest",
        ],
    ),
    "KSV041": (  # Do not allow management of secrets
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV042": (  # Do not allow deletion of pod logs
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].apiGroups",
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].apiGroups",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV043": (  # Do not allow impersonation of privileged groups
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].apiGroups",
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].apiGroups",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV044": (  # No wildcard verb roles
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV045": (  # No wildcard verb roles
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV046": (  # No wildcard resource roles
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV047": (  # Do not allow privilege escalation from node proxy
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV048": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV049": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV050": (  # Do not allow management of RBAC resources
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV051": (  # Do not allow role binding creation and association with privileged role/clusterrole
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].apiGroups",
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "ClusterRole.rules[].resourceNames",
            "Role.rules[].apiGroups",
            "Role.rules[].resources",
            "Role.rules[].verbs",
            "Role.rules[].resourceNames",
        ],
    ),
    "KSV052": (  # Do not allow role to create ClusterRoleBindings and association with privileged role
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].apiGroups",
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "ClusterRole.rules[].resourceNames",
            "Role.rules[].apiGroups",
            "Role.rules[].resources",
            "Role.rules[].verbs",
            "Role.rules[].resourceNames",
        ],
    ),
    "KSV053": (  # Do not allow getting shell on pods  ('pods/exec')
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].apiGroups",
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].apiGroups",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV054": (  # Do not allow attaching to shell on pods (pods/attach)
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].apiGroups",
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].apiGroups",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV055": (  # Do not allow users in a rolebinding to add other users to their rolebindings
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].apiGroups",
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].apiGroups",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV056": (  # Do not allow management of networking resources
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV102": (CheckCategory.Workload, [".metadata.name", ".spec.containers[].image"]),
    "KSV105": (
        CheckCategory.AdmissionControl,
        [".spec.securityContext.runAsUser", ".spec.containers[].securityContext.runAsUser"],
    ),
    "KSV106": (
        CheckCategory.AdmissionControl,
        [".spec.containers[].securityContext.capabilities.drop", ".spec.containers[].securityContext.capabilities.add"],
    ),
}


class Scanner(ScannerBase):
    NAME = "trivy"
    SCAN_MANIFESTS_CMD = ["trivy", "config", "-f", "json"]
    FORMATS = ["JSON", "Table", "Sarif", "Template", "CycloneDX", "SPDX", "SPDX-JSON", "GitHub", "Cosign-Vuln"]
    CI_MODE = True
    VERSION_CMD = ["trivy", "--version"]
    IMAGE_URL = "https://github.com/aquasecurity/trivy/blob/main/docs/imgs/logo.png?raw=true"
    RUNS_OFFLINE = True
    CUSTOM_CHECKS = "in Rego"

    @classmethod
    def parse_results(cls, results: dict) -> list[CheckResult]:
        """
        Parses the raw results and turns them into a flat list of check results.
        The results consists of a list of the results per file.

        :param results: the results which will be parsed
        :returns: the list of check results
        """
        check_id_pattern = re.compile(r"^(\w+(?:-\d+)+)")  # match the first letters and then the numbers following it

        check_results = []
        for result in results["Results"]:
            for misconfig in result.get("Misconfigurations", []):
                obj_name = Path(result["Target"]).stem

                m = check_id_pattern.search(obj_name)
                check_id = m.group(1) if m is not None else None

                status = CheckStatus.Alert if misconfig["Status"] == "FAIL" else CheckStatus.Pass
                checked_path = cls.get_checked_path(misconfig["ID"])

                check_results.append(
                    CheckResult(
                        check_id=check_id,
                        obj_name=obj_name,
                        scanner_check_id=misconfig["ID"],
                        scanner_check_name=misconfig["Title"],
                        checked_path=checked_path,
                        severity=misconfig["Severity"],
                        got=status,
                        details=misconfig["Description"],
                        extra=misconfig["Message"],
                    )
                )

        return check_results

    @classmethod
    def get_checked_path(cls, check_id: str) -> str:
        """Get the path(s) controlled by the check.

        :param check_id: the id of the check
        :return: the check(s) as single string or an empty string if no path could be retrieved.
        """
        _, paths = CHECK_MAPPING.get(check_id, (None, None))

        if isinstance(paths, str):
            return paths

        if isinstance(paths, list):
            return "|".join(paths)

        if paths is None:
            logger.warning(f"{cls.NAME} check '{check_id}' not found in the mapping")
        return ""

    def get_version(self) -> str:
        """Retrieve the version number of the tool by executing the corresponding command.
        The tool returns the version in the format "Version: <version>"
        :return: the version number of the tool
        """
        raw_version = super().get_version()
        label, version = raw_version.split(" ")
        return version
