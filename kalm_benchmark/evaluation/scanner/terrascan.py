import re

from loguru import logger

from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

CHECK_MAPPING = {
    "CpuRequestsCheck": (
        CheckCategory.Workload,
        [".spec.containers[].resources.requests"],
    ),
    "CpulimitsCheck": (
        CheckCategory.Workload,
        [".spec.containers[].resources.limits"],
    ),
    "MemoryRequestsCheck": (
        CheckCategory.Workload,
        [".spec.containers[].resources.requests"],
    ),
    "MemorylimitsCheck": (
        CheckCategory.Workload,
        [".spec.containers[].resources.limits"],
    ),
    "allowedHostPath": (
        CheckCategory.Workload,
        [".spec.containers[].volumesMounts[].mountPath", ".spec.volumes[].hostPath"],
    ),
    "allowedVolumes": (
        CheckCategory.Workload,
        [".spec.volumes[]", ".spec.containers[].volumeMounts[]"],
    ),
    "alwaysPullImages": (
        CheckCategory.Workload,
        [".spec.containers[].imagePullPolicy"],
    ),
    "appArmorProfile": (
        CheckCategory.Workload,
        [
            ".metadata.annotations.apparmor.security.beta.kubernetes.io/defaultProfileName",
            "container.apparmor.security.beta.kubernetes.io/app",
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io",
        ],
    ),
    "autoMountTokenEnabled": (
        CheckCategory.Workload,
        [".spec.automountServiceAccountToken"],
    ),
    "containersAsHighUID": (
        CheckCategory.Workload,
        [".spec.securityContext.runAsUser", ".spec.containers[].securityContext.runAsUser", ".spec.runAsUser"],
    ),
    "disallowedSysCalls": (
        CheckCategory.Workload,
        [
            ".spec.securityContext.sysctls[]",
        ],
    ),
    "disAllowedVolumes": (
        CheckCategory.Workload,
        [
            ".spec.volumes[]", 
            ".spec.containers[].volumeMounts[]"
        ],
    ),
    "dontConnectDockerSock": (
        CheckCategory.Workload,
        [
            ".spec.volumes[]",
            ".spec.volumes[].hostPath",
            ".spec.volumes[].hostPath.path",
            ".spec.containers[].volumeMounts[].mountPath",
        ],
    ),
    "falseHostIPC": (
        CheckCategory.Workload,
        [".spec.hostIPC"],
    ),
    "falseHostNetwork": (
        CheckCategory.Workload,
        [".spec.hostNetwork"],
    ),
    "falseHostPID": (
        CheckCategory.Workload,
        [".spec.hostPID"],
    ),
    "imageWithLatestTag": (
        CheckCategory.Workload,
        [".spec.containers[].image"],
    ),
    "imageWithoutDigest": (
        CheckCategory.Workload,
        [".spec.containers[].image"],
    ),
    "netRawCapabilityUsed": (
        CheckCategory.AdmissionControl,
        [".spec.containers[].securityContext.capabilities.drop"],
    ),
    "noOwnerLabel": (
        CheckCategory.Workload,
        [".metadata.annotations.owner"],
    ),
    "noReadinessProbe": (
        CheckCategory.Workload,
        [".spec.containers[].readinessProbe"],
    ),
    "nolivenessProbe": (
        CheckCategory.Workload,
        [".spec.containers[].livenessProbe"],
    ),
    "otherNamespace": (
        CheckCategory.Workload,
        [".metadata.namespace"],
    ),
    "privilegedContainersEnabled": (
        CheckCategory.AdmissionControl,
        [".spec.containers[].securityContext.privileged"],
    ),
    "privilegeEscalationCheck": (
        CheckCategory.Workload,
        [".spec.containers[].securityContext.allowPrivilegeEscalation"],
    ),
    "readOnlyFileSystem": (
        CheckCategory.Workload,
        [".spec.containers[].securityContext.readOnlyRootFilesystem"],
    ),
    "runAsNonRootCheck": (
        CheckCategory.Workload,
        [".spec.securityContext.runAsNonRoot", ".spec.containers[].securityContext.runAsNonRoot", ".spec.securityContext.runAsUser"],
    ),
    "secCompProfile": (
        CheckCategory.Workload,
        [
            ".metadata.annotations.seccomp.security.alpha.kubernetes.io",
            ".spec.securityContext.seccompProfile",
            ".spec.containers[].securityContext.seccompProfile.type",
        ],
    ),
    "securityContextUsed": (
        CheckCategory.Workload,
        [".spec.securityContext", ".spec.containers[].securityContext"],
    ),
}


class Scanner(ScannerBase):
    NAME = "Terrascan"
    SCAN_MANIFESTS_CMD = ["terrascan", "scan", "-o", "json", "--show-passed", "-d"]
    CUSTOM_CHECKS = "in Rego"
    RUNS_OFFLINE = True
    FORMATS = ["Plain", "JSON", "YAML", "SARIF", "XML", "JUnit"]
    IMAGE_URL = "https://raw.githubusercontent.com/tenable/runterrascan.io/main/static/images/TerrascanTM_BY_Logo.png"
    CI_MODE = True
    VERSION_CMD = ["terrascan", "version"]
    EXIT_CODES = {
        0: "scan summary has no violations or errors",
        1: "scan command errors out due to invalid inputs",
        3: "scan summary has violations but no errors",
        4: "scan summary has errors but no violations",
        5: "scan summary has errors and violations",
    }
    PATH_COLUMNS = ["checked_path"]
    # can be integrated with K8s admission webhooks: https://runterrascan.io/docs/integrations/_print/#overview

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
        check_id_pattern = re.compile(r"^(\w+(?:-\d+)+)")  # match the first letters and then the numbers following it

        for result in results["results"]["violations"]:
            obj_name = result["resource_name"]
            kind = result["resource_type"].replace("kubernetes_", "").title()

            m = check_id_pattern.search(obj_name)
            check_id = m.group(1) if m is not None else None

            checked_path = cls.get_checked_path(result["rule_name"])

            check_results.append(
                CheckResult(
                    check_id=check_id,
                    obj_name=obj_name,
                    scanner_check_id=result["rule_id"],
                    scanner_check_name=result["rule_name"],
                    got=CheckStatus.Alert,
                    checked_path=checked_path,
                    kind=kind,
                    severity=result["severity"],
                    details=result["description"],
                    extra=result["category"],
                )
            )
        return check_results

    @classmethod
    def get_checked_path(cls, check_id: str) -> str:
        """Get the path(s) controlled by the check.

        :param check_id: the id of the check
        :return: the check(s) as single string or an empty string if no path could be retrieved.
        """
        if check_id not in CHECK_MAPPING:
            logger.warning(f"No mapping for '{check_id}' found!")

        _, paths = CHECK_MAPPING.get(check_id, (None, None))
        if isinstance(paths, str):
            return paths

        if isinstance(paths, list):
            return "|".join(paths)

        return ""

    def get_version(self) -> str:
        """Retrieve the version number of the tool by executing the corresponding command.
        The tool returns the version number in the format "version: v<version>"
        :return: the version number of the tool
        """
        version = super().get_version()
        v_start_idx = version.rfind("v")
        return version[v_start_idx + 1 :]
