import re

from loguru import logger

from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

CHECK_MAPPING = {
    "CpuRequestsCheck": (
        CheckCategory.PodSecurity,
        [".spec.containers[].resources.requests.cpu"],
    ),
    "CpulimitsCheck": (
        CheckCategory.PodSecurity,
        [".spec.containers[].resources.limits.cpu"],
    ),
    "MemoryRequestsCheck": (
        CheckCategory.PodSecurity,
        [".spec.containers[].resources.requests.memory"],
    ),
    "MemorylimitsCheck": (
        CheckCategory.PodSecurity,
        [".spec.containers[].resources.limits.memory"],
    ),
    "allowedHostPath": (
        CheckCategory.PodSecurity,
        [".spec.containers[].volumesMounts[].mountPath", ".spec.volumes[].hostPath"],
    ),
    "allowedVolumes": (
        CheckCategory.PodSecurity,
        [".spec.volumes[]", ".spec.containers[].volumeMounts[]"],
    ),
    "alwaysPullImages": (
        CheckCategory.PodSecurity,
        [".spec.containers[].imagePullPolicy"],
    ),
    "appArmorProfile": (
        CheckCategory.PodSecurity,
        [
            ".metadata.annotations.apparmor.security.beta.kubernetes.io/defaultProfileName",
            "container.apparmor.security.beta.kubernetes.io/app",
        ],
    ),
    "autoMountTokenEnabled": (
        CheckCategory.PodSecurity,
        [".spec.automountServiceAccountToken"],
    ),
    "containersAsHighUID": (
        CheckCategory.PodSecurity,
        [".spec.securityContext.runAsUser", ".spec.containers[].securityContext.runAsUser", ".spec.runAsUser"],
    ),
    "dontConnectDockerSock": (
        CheckCategory.PodSecurity,
        [
            ".spec.volumes[].hostPath",
            ".spec.volumes[].hostPath.path",
            ".spec.containers[].volumeMounts[].mountPath",
        ],
    ),
    "falseHostIPC": (
        CheckCategory.PodSecurity,
        [".spec.hostIPC"],
    ),
    "falseHostNetwork": (
        CheckCategory.PodSecurity,
        [".spec.hostNetwork"],
    ),
    "falseHostPID": (
        CheckCategory.PodSecurity,
        [".spec.hostPID"],
    ),
    "imageWithLatestTag": (
        CheckCategory.PodSecurity,
        [".spec.containers[].image"],
    ),
    "imageWithoutDigest": (
        CheckCategory.PodSecurity,
        [".spec.containers[].image"],
    ),
    "netRawCapabilityUsed": (
        CheckCategory.AdmissionControl,
        [".spec.containers[].securityContext.capabilities.drop"],
    ),
    "noOwnerLabel": (
        CheckCategory.PodSecurity,
        [".metadata.annotations.owner"],
    ),
    "noReadinessProbe": (
        CheckCategory.PodSecurity,
        [".spec.containers[].readinessProbe"],
    ),
    "nolivenessProbe": (
        CheckCategory.PodSecurity,
        [".spec.containers[].livenessProbe"],
    ),
    "otherNamespace": (
        CheckCategory.PodSecurity,
        [".metadata.namespace"],
    ),
    "priviledgedContainersEnabled": (
        CheckCategory.AdmissionControl,
        [".spec.privileged"],
    ),
    "privilegeEscalationCheck": (
        CheckCategory.PodSecurity,
        [".spec.containers[].securityContext.allowPrivilegeEscalation"],
    ),
    "readOnlyFileSystem": (
        CheckCategory.PodSecurity,
        [".spec.containers[].securityContext.readOnlyRootFilesystem"],
    ),
    "runAsNonRootCheck": (
        CheckCategory.PodSecurity,
        [".spec.securityContext.runAsNonRoot", ".spec.containers[].securityContext.runAsNonRoot"],
    ),
    "secCompProfile": (
        CheckCategory.PodSecurity,
        [
            ".metadata.annotations.seccomp.security.alpha.kubernetes.io",
            ".spec.securityContext.seccompProfile.type",
            ".spec.containers[].securityContext.seccompProfile.type",
        ],
    ),
    "securityContextUsed": (
        CheckCategory.PodSecurity,
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
