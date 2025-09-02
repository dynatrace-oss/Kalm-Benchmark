import re

from loguru import logger

from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

# Bind logger to scan component for proper log filtering
logger = logger.bind(component="scan")


CHECK_MAPPING = {
    "access-to-create-pods": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].verbs",
            "ClusterRole.rules[].resources",
            "Role.rules[].verbs",
            "Role.rules[].resources",
            ".rules[].verbs",
            ".rules[].resources",
        ],
    ),
    "access-to-secrets": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].verbs",
            "ClusterRole.rules[].resources",
            "Role.rules[].verbs",
            "Role.rules[].resources",
            ".rules[].verbs",
            ".rules[].resources",
        ],
    ),
    "cluster-admin-role-binding": (
        CheckCategory.IAM,
        [
            "RoleBinding.roleRef.name",
            "ClusterRoleBinding.roleRef.name",
            ".roleRef.name",
        ],
    ),
    "dangling-horizontalpodautoscaler": (
        CheckCategory.Workload,
        ["HorizontalPodAutoscaler.spec.scaleTargetRef", ".spec.scaleTargetRef"],
    ),
    "dangling-networkpolicy": (
        CheckCategory.Network,
        ["NetworkPolicy.spec.podSelector", ".spec.podSelector"],
    ),
    "dangling-networkpolicypeer-podselector": (
        CheckCategory.Network,
        [
            "NetworkPolicy.spec.ingress[].from[].podSelector",
            "NetworkPolicy.spec.egress[].to[].podSelector",
            ".spec.ingress[].from[].podSelector",
            ".spec.egress[].to[].podSelector",
        ],
    ),
    "dangling-service": (
        CheckCategory.Workload,
        [".spec.selector", ".metadata.labels"],
    ),
    "default-service-account": (
        CheckCategory.Workload,
        [".spec.serviceAccountName"],
    ),
    "deprecated-service-account-field": (
        CheckCategory.Workload,
        [".spec.serviceAccount"],
    ),
    "docker-sock": (
        CheckCategory.Workload,
        [
            ".spec.volumes[].hostPath",
            ".spec.volumes[].hostPath.path",
            ".spec.containers[].volumeMounts[].mountPath",
        ],
    ),
    "drop-net-raw-capability": (
        CheckCategory.Network,
        [".spec.containers[].securityContext.capabilities.drop"],
    ),
    "env-var-secret": (
        CheckCategory.DataSecurity,
        [".spec.containers[].env[].name"],
    ),
    "exposed-services": (
        CheckCategory.Workload,
        [
            "Service.spec.type",
            "Service.spec.ports[].nodePort",
            ".spec.type",
            ".spec.ports[].nodePort",
        ],
    ),
    "host-ipc": (
        CheckCategory.Workload,
        [".spec.hostIPC"],
    ),
    "host-network": (
        CheckCategory.Workload,
        [".spec.hostNetwork"],
    ),
    "host-pid": (
        CheckCategory.Workload,
        [".spec.hostPID"],
    ),
    "hpa-minimum-three-replicas": (
        CheckCategory.Reliability,
        ["HorizontalPodAutoscaler.spec.minReplicas", ".spec.minReplicas"],
    ),
    "latest-tag": (
        CheckCategory.Workload,
        [".spec.containers[].image"],
    ),
    "minimum-three-replicas": (
        CheckCategory.Reliability,
        ["Deployment.spec.replicas", ".spec.replicas"],
    ),
    "mismatching-selector": (
        CheckCategory.Workload,
        [".spec.selector.matchLabels", ".spec.template.metadata.labels"],
    ),
    "no-anti-affinity": (
        CheckCategory.Reliability,
        [".spec.affinity.podAntiAffinity"],
    ),
    "no-extensions-v1beta": (
        CheckCategory.Network,
        [".apiVersion"],
    ),
    "no-liveness-probe": (
        CheckCategory.Reliability,
        [".spec.containers[].livenessProbe"],
    ),
    "no-node-affinity": (
        CheckCategory.Reliability,
        [".spec.affinity.nodeAffinity"],
    ),
    "no-read-only-root-fs": (
        CheckCategory.Workload,
        [".spec.containers[].securityContext.readOnlyRootFilesystem"],
    ),
    "no-readiness-probe": (
        CheckCategory.Reliability,
        [".spec.containers[].readinessProbe"],
    ),
    "no-rolling-update-strategy": (
        CheckCategory.Reliability,
        ["Deployment.spec.strategy.type", ".spec.strategy.type"],
    ),
    "non-existent-service-account": (
        CheckCategory.IAM,
        [".spec.serviceAccountName", "ServiceAccount.metadata.name"],
    ),
    "non-isolated-pod": (
        CheckCategory.Network,
        ["NetworkPolicy.spec.podSelector", ".spec.podSelector"],
    ),
    "privilege-escalation-container": (
        CheckCategory.Workload,
        [".spec.containers[].securityContext.allowPrivilegeEscalation"],
    ),
    "privileged-container": (
        CheckCategory.Workload,
        [".spec.containers[].securityContext.privileged"],
    ),
    "privileged-ports": (
        CheckCategory.Workload,
        [".spec.containers[].ports[].containerPort"],
    ),
    "read-secret-from-env-var": (
        CheckCategory.DataSecurity,
        [".spec.containers[].env[].valueFrom.SecretKeyRef"],
    ),
    "required-annotation-email": (
        CheckCategory.Misc,
        [".metadata.annotations.email"],
    ),
    "required-label-owner": (
        CheckCategory.Misc,
        [".metadata.annotations.owner"],
    ),
    "run-as-non-root": (
        CheckCategory.Workload,
        [
            ".spec.securityContext.runAsNonRoot",
            ".spec.containers[].securityContext.runAsNonRoot",
        ],
    ),
    "sensitive-host-mounts": (
        CheckCategory.Workload,
        [
            ".spec.volumes[].hostPath",
            ".spec.volumes[].hostPath.path",
            ".spec.containers[].volumeMounts[].mountPath",
        ],
    ),
    "ssh-port": (
        CheckCategory.Workload,
        [".spec.containers[].ports[].containerPort"],
    ),
    "unsafe-proc-mount": (
        CheckCategory.Workload,
        [
            "spec.containers[].securityContext.procMount",
            "spec.initContainers[].securityContext.procMount",
            "spec.ephemeralContainers[].securityContext.procMount",
        ],
    ),
    "unsafe-sysctls": (
        CheckCategory.Workload,
        [".spec.securityContext.sysctls[].name"],
    ),
    "unset-cpu-requirements": (
        CheckCategory.Reliability,
        [
            ".spec.containers[].resources.requests.cpu",
            ".spec.containers[].resources.limits.cpu",
        ],
    ),
    "unset-memory-requirements": (
        CheckCategory.Network,
        [
            ".spec.containers[].resources.requests.memory",
            ".spec.containers[].resources.limits.memory",
        ],
    ),
    "use-namespace": (
        CheckCategory.Network,
        [".metadata.namespace"],
    ),
    "wildcard-in-rules": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].verbs",
            "ClusterRole.rules[].resources",
            "Role.rules[].verbs",
            "Role.rules[].resources",
            ".rules[].verbs",
            ".rules[].resources",
        ],
    ),
    "writable-host-mount": (
        CheckCategory.Workload,
        [
            ".spec.containers[].volumesMounts[].readOnly",
            ".spec.volumes[].hostPath",
        ],
    ),
}


class Scanner(ScannerBase):
    NAME = "KubeLinter"
    IMAGE_URL = "https://github.com/stackrox/kube-linter/raw/main/images/logo/KubeLinter-horizontal.svg"
    FORMATS = ["Plain", "JSON", "SARIF"]
    SCAN_MANIFESTS_CMD = [
        "kube-linter",
        "lint",
        "--add-all-built-in",
        "--format",
        "json",
    ]
    CUSTOM_CHECKS = "based on existing templates"
    CI_MODE = True
    RUNS_OFFLINE = True
    VERSION_CMD = ["kube-linter", "version"]

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
        reports = results.get("Reports", [])
        logger.debug(f"KubeLinter: Processing {len(reports)} reports")

        check_results = []
        check_id_pattern = re.compile(r"^(\w+(?:-\d+)+)")  # match the first letters and then the numbers following it

        for report in reports:
            try:
                scanner_check_id = report["Check"]

                obj = report["Object"]["K8sObject"]
                obj_name = obj["Name"]
                ns = obj["Namespace"]
                kind = obj["GroupVersionKind"]["Kind"]

                m = check_id_pattern.search(obj_name)
                check_id = m.group(1) if m is not None else None

                checked_path = cls.get_checked_path(scanner_check_id)
                status = CheckStatus.Alert

                # KubeLinter doesn't provide explicit severity levels in JSON output
                # All failures are treated as errors, but we can infer severity based on check type
                severity = "MEDIUM"  # Default severity for most security/best practice checks

                # Assign higher severity to critical security checks
                high_severity_checks = [
                    "privileged-container",
                    "run-as-non-root",
                    "host-network",
                    "host-pid",
                    "host-ipc",
                    "docker-sock",
                    "cluster-admin-role-binding",
                    "access-to-secrets",
                ]
                if scanner_check_id in high_severity_checks:
                    severity = "HIGH"

                # Assign lower severity to non-security checks
                low_severity_checks = [
                    "required-annotation-email",
                    "required-label-owner",
                    "latest-tag",
                    "minimum-three-replicas",
                    "hpa-minimum-three-replicas",
                ]
                if scanner_check_id in low_severity_checks:
                    severity = "LOW"

                check_results.append(
                    CheckResult(
                        check_id=check_id,
                        obj_name=obj_name,
                        scanner_check_id=scanner_check_id,
                        got=status,
                        checked_path=checked_path,
                        kind=kind,
                        namespace=ns,
                        details=report["Diagnostic"]["Message"],
                        extra=report["Remediation"],
                        severity=severity,
                    )
                )
            except Exception as e:
                logger.warning(f"KubeLinter: Failed to parse report for check {report.get('Check', 'unknown')}: {e}")
                continue

        logger.info(f"KubeLinter: Successfully parsed {len(check_results)} check results from {len(reports)} reports")
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
