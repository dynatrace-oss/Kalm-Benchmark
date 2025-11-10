import re
from pathlib import Path

from loguru import logger

# Bind logger to scan component for proper log filtering
logger = logger.bind(component="scan")

from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

CHECK_MAPPING = {
    "KSV001": (CheckCategory.Workload, [".spec.containers[].securityContext.allowPrivilegeEscalation"]),
    "KSV002": (
        CheckCategory.Workload,
        [
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io"
            ".metadata.annotations[container.apparmor.security.beta.kubernetes.io]",
        ],
    ),
    "KSV003": (
        CheckCategory.Workload,
        [
            ".spec.containers[].securityContext.capabilities.drop", 
            ".spec.containers[].securityContext.capabilities",
        ],
    ),  # capabilities no drop all
    "KSV004": (
        CheckCategory.Workload,
        [
            ".spec.containers[].securityContext.capabilities.drop", 
            ".spec.containers[].securityContext.capabilities",
        ],
    ),  # capabilities no drop at least one
    "KSV005": (CheckCategory.Workload, [".spec.containers[].securityContext.capabilities.add", ".spec.containers[].securityContext.capabilities"]),  # SYS_ADMIN capability
    "KSV006": (CheckCategory.Workload, [".spec.volumes[].hostPath.path"]),  # mounts docker socket
    "KSV007": (CheckCategory.Workload, [".spec.hostAliases"]),
    "KSV008": (CheckCategory.Workload, [".spec.hostIPC"]),
    "KSV009": (CheckCategory.Workload, [".spec.hostNetwork"]),
    "KSV010": (CheckCategory.Workload, [".spec.hostPID"]),
    "KSV011": (CheckCategory.Reliability, [".spec.containers[].resources.limits.cpu", ".spec.containers[].resources.limits"]),
    "KSV012": (
        CheckCategory.Workload,
        [".spec.securityContext.runAsNonRoot", ".spec.containers[].securityContext.runAsNonRoot"],
    ),
    "KSV013": (CheckCategory.Workload, [".spec.containers[].image"]),
    "KSV014": (CheckCategory.Workload, [".spec.containers[].securityContext.readOnlyRootFilesystem"]),
    "KSV015": (CheckCategory.Reliability, [".spec.containers[].resources.requests.cpu", ".spec.containers[].resources.requests"]),
    "KSV016": (CheckCategory.Reliability, [".spec.containers[].resources.requests.memory", ".spec.containers[].resources.requests"]),
    "KSV017": (CheckCategory.Workload, [".spec.containers[].securityContext.privileged"]),
    "KSV018": (CheckCategory.Reliability, [".spec.containers[].resources.limits.memory", ".spec.containers[].resources.limits"]),
    "KSV020": (CheckCategory.Workload, [".spec.containers[].securityContext.runAsUser"]),
    "KSV021": (CheckCategory.Workload, [".spec.containers[].securityContext.runAsGroup"]),
    "KSV022": (
        CheckCategory.Workload,
        [
            ".spec.containers[].securityContext.capabilities.add",
            ".spec.containers[].securityContext.capabilities",
        ],
    ),  # specific capabilities added
    "KSV023": (CheckCategory.Workload, [".spec.volumes[].hostPath"]),
    "KSV024": (
        CheckCategory.Workload,
        [".spec.containers[].ports[].hostPort", ".spec.initContainers[].ports[].hostPort"],
    ),
    "KSV025": (
        CheckCategory.Workload,
        [".spec.securityContext.seLinuxOptions", ".spec.containers[].securityContext.seLinuxOptions"],
    ),
    "KSV026": (CheckCategory.Workload, [".spec.securityContext.sysctls[]"]),
    "KSV027": (
        CheckCategory.Workload,
        [".spec.containers[].securityContext.procMount", ".spec.initContainers[].securityContext.procMount"],
    ),
    "KSV028": (CheckCategory.Workload, [".spec.volumes[]"]),
    "KSV116": (  # 'runs with a root primary or supplementary GID' (was remapped from KSV029)
        CheckCategory.Workload,
        [
            ".spec.securityContext.fsGRoup",
            ".spec.securityContext.supplementalGroups",
            ".spec.securityContext.runAsGroup",
            ".spec.containers[].securityContext.runAsGroup",
        ],
    ),
    "KSV030": (
        CheckCategory.Workload,
        [
            ".spec.securityContext.seccompProfile.type",
            ".spec.containers[].securityContext.seccompProfile.type",
            ".metadata.annotations[seccomp.security.alpha.kubernetes.io/pod",
        ],
    ),  # runtime default seccomp profile not set
    "KSV032": (CheckCategory.Workload, [".spec.containers[].image", ".spec.containers[].name"]),
    "KSV033": (CheckCategory.Workload, [".spec.containers[].image", ".spec.containers[].name"]),
    "KSV034": (CheckCategory.Workload, [".spec.containers[].image"]),
    "KSV035": (CheckCategory.Workload, [".spec.containers[].image", ".spec.containers[].name"]),
    "KSV036": (
        CheckCategory.Workload,
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
    "KSV103": (
        CheckCategory.Workload, 
        [
            ".spec.containers[].securityContext.windowsOptions.hostProcess",
        ],
    ),
    "KSV104": (
        CheckCategory.Workload,
        [
            ".spec.securityContext.seccompProfile.type",
            ".spec.containers[].securityContext.seccompProfile.type",
            ".metadata.annotations[seccomp.security.alpha.kubernetes.io/pod",
        ],
    ),  # seccomp profile unconfined
    "KSV105": (
        CheckCategory.AdmissionControl,
        [".spec.securityContext.runAsUser", ".spec.containers[].securityContext.runAsUser"],
    ),
    "KSV106": (
        CheckCategory.AdmissionControl,
        [
            ".spec.containers[].securityContext.capabilities.drop", 
            ".spec.containers[].securityContext.capabilities.add",
            ".spec.containers[].securityContext.capabilities",
        ],
    ),  # drop all capabilities only add net bind service
    "KSV110": (
        CheckCategory.Workload,
        [
            ".metadata.namespace",
        ],
    ),  # default namespace
    "KSV111": (  # manage all resources in namespace (wildcard)
        CheckCategory.IAM,
        [
            "ClusterRoleBinding.roleRef.name",
            "RoleBinding.roleRef.name",
        ],
    ),  # cluster-admin role only used wherer required
    "KSV112": (  # manage all resources in namespace (wildcard)
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
    "KSV113": (  # manage namespace secrets
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
    "KSV114": (  # Manage webhookconfigurations
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV115": (  # Manage EKS IAM Auth ConfigMap
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    "KSV116": (  # Runs with a root primary or supplementary GID
        CheckCategory.Workload,
        [
            ".spec.securityContext.runAsGroup",
            ".spec.containers[].securityContext.runAsGroup",
        ],
    ),
    "KSV117": ( # Privileged port used
        CheckCategory.Workload,
        [
            ".spec.containers[].ports[].containerPort", 
            ".spec.initContainers[].ports[].containerPort",
        ],
    ),
    "KSV118": (  # default security context
        CheckCategory.Workload,
        [
            ".spec.securityContext",
            ".spec.containers[].securityContext",
        ],
    ),
    "KSV119": (CheckCategory.Workload, [".spec.containers[].securityContext.capabilities.add"]),  # NET_RAW capability
    "KSV120": (
        CheckCategory.Workload,
        [".spec.containers[].securityContext.capabilities.add"],
    ),  # SYS_MODULE capability
    "KSV121": (
        CheckCategory.Workload,
        [".spec.volumes[].hostPath.path"],
    ),  # K8s resource with disallowed volumes mounted (/, /boot, /dev, /etc, /lib, /proc, /sys, /usr, /var/lib/docker)
    "KSV122": (
        CheckCategory.IAM, 
        [
            "RoleBinding.roleRef.name", 
            "ClusterRoleBinding.roleRef.name",
            ".roleRef.name",
        ]
    ),  # Privilege escalation allowed in init container
    "KSV123": (
        CheckCategory.IAM, 
        [
            "RoleBinding.roleRef.name", 
            "ClusterRoleBinding.roleRef.name",
            ".roleRef.name",
        ]
    ),  # Binding to system:masters group
    "AVD-KSV-0109": (CheckCategory.DataSecurity, ["ConfigMap.data"]),  # ConfigMap with secrets
    "AVD-KSV-01010": (CheckCategory.DataSecurity, ["ConfigMap.data"]),  # ConfigMap with sensitive content
    "AVD-KSV-01011": (
        CheckCategory.IAM, 
        [
            "RoleBinding.roleRef.name", 
            "ClusterRoleBinding.roleRef.name",
            ".roleRef.name",
        ]
    ),  # Binding to system:authenticate group
    "no-user-pods-in-system-namespace": (CheckCategory.Workload, [".metadata.namespace"]),  # User pods in kube-system or kube-public namespace
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
    PATH_COLUMNS = ["checked_path"]

    @classmethod
    def parse_results(cls, results: dict) -> list[CheckResult]:
        """
        Parses the raw results and turns them into a flat list of check results.
        The results consists of a list of the results per file.

        :param results: the results which will be parsed
        :returns: the list of check results
        """
        check_id_pattern = re.compile(r"^(\w+(?:-\d+)+)")  # match the first letters and then the numbers following it

        total_files = len(results.get("Results", []))
        logger.debug(f"Trivy: Processing results from {total_files} files/targets")

        check_results = []
        for file_idx, result in enumerate(results["Results"]):
            misconfigs = result.get("Misconfigurations", [])
            if misconfigs:
                logger.debug(
                    f"Trivy: Processing {len(misconfigs)} misconfigurations from {result.get('Target', 'unknown')}"
                )
            for misconfig in misconfigs:
                obj_name = Path(result["Target"]).stem

                m = check_id_pattern.search(obj_name)
                check_id = m.group(1) if m is not None else None

                status = CheckStatus.Alert if misconfig["Status"] == "FAIL" else CheckStatus.Pass
                checked_path = cls.get_checked_path(misconfig["ID"])

                try:
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
                except Exception as e:
                    logger.warning(f"Trivy: Failed to parse misconfiguration {misconfig.get('ID', 'unknown')}: {e}")
                    continue

        logger.info(f"Trivy: Successfully parsed {len(check_results)} check results from {total_files} files")
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
            logger.debug(f"Trivy: Check '{check_id}' not found in the mapping")
        return ""

    def get_version(self) -> str:
        """Retrieve the version number of the tool by executing the corresponding command.
        The tool returns the version in the format "Version: <version>"
        :return: the version number of the tool
        """
        try:
            raw_version = super().get_version()
            version_line, *_ = raw_version.split("\n")
            _, version = version_line.split(" ")
            return version
        except Exception as e:
            logger.warning(f"Trivy: Failed to parse version: {e}")
            return "unknown"
