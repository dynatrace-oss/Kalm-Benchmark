from enum import IntEnum

from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

CHECK_MAPPING = {
    "container-cpu-requests-equal-limits": (
        CheckCategory.Reliability,
        [".spec.containers[].resources.limits.cpu", ".spec.containers[].resources.requests.cpu"],
    ),
    "container-ephemeral-storage-request-and-limit": (
        CheckCategory.Reliability,
        [
            ".spec.containers[].resources.limits.ephemeral-storage",
            ".spec.containers[].resources.requests.ephemeral-storage",
        ],
    ),
    "container-ephemeral-storage-request-equals-limit": (
        CheckCategory.Reliability,
        [
            ".spec.containers[].resources.limits.ephemeral-storage",
            ".spec.containers[].resources.requests.ephemeral-storage",
        ],
    ),
    "container-image-pull-policy": (CheckCategory.Workload, ".spec.containers[].imagePullPolicy"),
    "container-image-tag": (CheckCategory.Workload, ".spec.containers[].image"),
    "container-memory-requests-equal-limits": (
        CheckCategory.Reliability,
        [".spec.containers[].resources.limits.memory", ".spec.containers[].resources.requests.memory"],
    ),
    "container-ports-check": (
        CheckCategory.PodSecurity,
        [".spec.containers[].ports[].containerPort", ".spec.containers[].ports[].name"],
    ),
    "container-resources": (
        CheckCategory.Workload,
        [
            ".spec.containers[].resources",
            ".spec.containers[].resources.limits",
            ".spec.containers[].resources.requests",
            ".spec.containers[].resources.limits.cpu",
            ".spec.containers[].resources.requests.cpu",
            ".spec.containers[].resources.limits.memory",
            ".spec.containers[].resources.requests.memory",
            ".spec.containers[].resources.limits.ephemeral-storage",
            ".spec.containers[].resources.requests.ephemeral-storage",
        ],
    ),
    "container-resource-requests-equal-limits": (
        CheckCategory.PodSecurity,
        [
            ".spec.containers[].resources.limits",
            ".spec.containers[].resources.requests",
        ],
    ),  # not effective?
    "container-seccomp-profile": (
        CheckCategory.PodSecurity,
        [
            ".metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName",
            ".spec.containers[].securityContext.seccompProfile",
            ".spec.securityContext.seccompProfile",
        ],
    ),
    "container-security-context-privileged": (
        CheckCategory.PodSecurity,
        ".spec.containers[].securityContext.privileged",
    ),
    "container-security-context-readonlyrootfilesystem": (
        CheckCategory.PodSecurity,
        ".spec.containers[].securityContext.readOnlyRootFilesystem",
    ),
    "container-security-context-user-group-id": (
        CheckCategory.Workload,
        [
            ".spec.securityContext.runAsGroup",
            ".spec.securityContext.runAsUser",
            ".spec.containers[].securityContext.runAsUser",
            ".spec.containers[].securityContext.runAsGroup",
        ],
    ),
    "cronjob-has-deadline": (CheckCategory.Workload, ""),  # ?
    "deployment-has-host-podantiaffinity": (CheckCategory.Reliability, ".spec.affinity.podAntiAffinity"),
    "deployment-has-poddisruptionbudget": (
        CheckCategory.Reliability,
        ["PodDisruptionBudget.spec.selector", ".spec.selector"],
    ),
    "deployment-pod-selector-labels-match-template-metadata-labels": (
        CheckCategory.Workload,
        [".spec.selector.matchLabels", ".metadata.labels"],
    ),
    "deployment-targeted-by-hpa-does-not-have-replicas-configured": (
        CheckCategory.Workload,
        ["HorizontalPodAutoscaler.spec.scaleTargetRef.name", ".spec.scaleTargetRef.name"],
    ),
    "environment-variable-key-duplication": (CheckCategory.Workload, ".spec.containers[].env[].name"),
    "horizontalpodautoscaler-has-target": (
        CheckCategory.Reliability,
        ["HorizontalPodAutoscaler.spec.scaleTargetRef", ".spec.scaleTargetRef"],
    ),
    "ingress-targets-service": (CheckCategory.Network, ".spec.rules[].http.paths[].backend.serviceName"),
    "label-values": (CheckCategory.Workload, ".metadata.labels"),
    "networkpolicy-targets-pod": (CheckCategory.Network, ".spec.podSelector"),
    "pod-networkpolicy": (CheckCategory.Network, ".spec.podSelector"),
    "pod-probes": (
        CheckCategory.Reliability,
        [".spec.containers[].livenessProbe", ".spec.containers[].readinessProbe"],
    ),
    "poddisruptionbudget-has-policy": (
        CheckCategory.Reliability,
        [
            "PodDisruptionBudget.spec.minAvailable",
            "PodDisruptionBudget.spec.maxAvailable",
            ".spec.minAvailable",
            ".spec.maxAvailable",
        ],
    ),
    "service-targets-pod": (CheckCategory.Workload, [".spec.selector", ".metadata.labels"]),
    "service-type": (CheckCategory.Workload, ".spec.type"),  # shouldn't be NodePort
    "stable-version": (CheckCategory.Misc, ".apiVersion"),
    "statefulset-has-host-podantiaffinity": (CheckCategory.Workload, ".spec.affinity.podAntiAffinity"),
    "statefulset-has-poddisruptionbudget": (
        CheckCategory.Workload,
        ["PodDisruptionBudget.spec.selector", ".spec.selector"],
    ),
    "statefulset-has-servicename": (CheckCategory.Workload, ".spec.serviceName"),
    "statefulset-pod-selector-labels-match-template-metadata-labels": (
        CheckCategory.Workload,
        ".spec.selector.matchLabels",
    ),
}


class Grade(IntEnum):
    Skipped = 0
    Critical = 1
    Warning = 5
    AlmostOk = 7
    Ok = 10


class Scanner(ScannerBase):
    NAME = "kube-score"
    SCAN_MANIFESTS_CMD = ["kube-score", "score", "-o", "json"]
    SCAN_PER_FILE = True
    NOTES = []
    FORMATS = ["Plain", "JSON", "SARIF", "CI"]
    CI_MODE = True
    RUNS_OFFLINE = True
    IMAGE_URL = "https://user-images.githubusercontent.com/47952/56085330-6c0a2480-5e41-11e9-89ba-0cfddd7714a8.png"
    VERSION_CMD = ["kube-score", "version"]

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
        for file in results:
            # some files resulting in "null" without any structured info
            # these will simply be skipped
            if file is None:
                continue
            for resource in file:
                obj_meta = resource["object_meta"]
                obj_name = obj_meta["name"]
                # cluster-wide objects have no namespace
                ns = obj_meta.get("namespace", None)
                kind = resource["type_meta"]["kind"]

                labels = obj_meta.get("labels", {})
                check_id = labels.get("check", None)

                for check in resource["checks"]:
                    c = check["check"]

                    comments = check["comments"]
                    extra = "; ".join([str(comment) for comment in comments or []])
                    checked_path = cls.get_checked_path(c["id"])

                    grade = Grade(check["grade"])
                    status = CheckStatus.Pass if Grade(grade) == Grade.Ok or check["skipped"] else CheckStatus.Alert

                    check_results.append(
                        CheckResult(
                            check_id=check_id,
                            obj_name=obj_name,
                            scanner_check_id=c["id"],
                            scanner_check_name=c["name"],
                            got=status,
                            checked_path=checked_path,
                            severity=f"{grade.name} ({grade})",  # e.g. "Ok (10)"
                            kind=kind,
                            namespace=ns,
                            details=c["comment"],
                            extra=extra,
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

    def get_version(self) -> str:
        """Retrieve the version number of the tool by executing the corresponding command.
        The tool returns version in the format "kube-score version: <version>, commit: <hash>, built: <date>"
        :return: the version number of the tool
        """
        # only the version number itself is relevant, which will be extracted
        raw_version = super().get_version()
        version_entry, *_ = raw_version.split(",", maxsplit=1)
        label, version = version_entry.split(":")

        return version.strip()
