import re
from typing import Optional

import pandas as pd

from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

CHECK_MAPPING = {
    "CONFIGMAP_CVE2021_25742_INCORRECT_SNIPPET_ANNOTATIONS_VALUE": (
        CheckCategory.Vulnerability,
        ".data.allow-snippet-annotation",
    ),
    "CONTAINERS_MISSING_IMAGE_VALUE_VERSION": (CheckCategory.Workload, ".spec.containers[].image"),
    "CONTAINERS_MISSING_IMAGE_VALUE_DIGEST": (CheckCategory.Workload, ".spec.containers[].image"),
    "CONTAINERS_MISSING_MEMORY_REQUEST_KEY": (
        CheckCategory.Reliability,
        ".spec.containers[].resources.requests.memory",
    ),
    "CONTAINERS_MISSING_CPU_REQUEST_KEY": (CheckCategory.Reliability, ".spec.containers[].resources.requests.cpu"),
    "CONTAINERS_MISSING_MEMORY_LIMIT_KEY": (CheckCategory.Reliability, ".spec.containers[].resources.limits.memory"),
    "CONTAINERS_MISSING_CPU_LIMIT_KEY": (CheckCategory.Reliability, ".spec.containers[].resources.limits.cpu"),
    "CONTAINERS_MISSING_LIVENESSPROBE_KEY": (CheckCategory.Reliability, ".spec.containers[].livenessProbe"),
    "CONTAINERS_MISSING_READINESSPROBE_KEY": (CheckCategory.Reliability, ".spec.containers[].readinessProbe"),
    "CONTAINERS_INCORRECT_PRIVILEGED_VALUE_TRUE": (
        CheckCategory.Workload,
        ".spec.containers[].securityContext.privileged",
    ),
    "CONTAINER_CVE2021_25741_INCORRECT_SUBPATH_KEY": (
        CheckCategory.Workload,
        ".spec.containers[].volumeMounts[].subPath",
    ),
    "CONTAINERS_INCORRECT_HOSTPID_VALUE_TRUE": (CheckCategory.Workload, ".spec.hostPID"),
    "CONTAINERS_INCORRECT_HOSTIPC_VALUE_TRUE": (CheckCategory.Workload, ".spec.hostIPC"),
    "CONTAINERS_INCORRECT_HOSTNETWORK_VALUE_TRUE": (CheckCategory.Workload, ".spec.hostNetwork"),
    "CONTAINERS_INCORRECT_PATH_VALUE_DOCKERSOCKET": (CheckCategory.Workload, ".spec.volumes[].hostPath.path"),
    "CONTAINERS_INCORRECT_RUNASUSER_VALUE_LOWUID": (
        CheckCategory.Workload,
        ".spec.containers[].securityContext.runAsUser",
    ),
    "CRONJOB_INVALID_SCHEDULE_VALUE": (CheckCategory.Misc, ".spec.schedule"),
    "CRONJOB_MISSING_CONCURRENCYPOLICY_KEY": (CheckCategory.Misc, ".spec.concurrencyPolicy"),
    "CRONJOB_MISSING_STARTINGDEADLINESECOND_KEY": (CheckCategory.Misc, ".spec.startingDeadlineSeconds"),
    "DEPLOYMENT_MISSING_LABEL_ENV_VALUE": (CheckCategory.Workload, ".metadata.labels.env"),
    "DEPLOYMENT_INCORRECT_REPLICAS_VALUE": (CheckCategory.Workload, "Deployment.spec.replicas"),
    "ENDPOINTSLICE_CVE2021_25373_INCORRECT_ADDRESSES_VALUE": (
        CheckCategory.Vulnerability,
        "EndpointSlice.endpoints[].addresses",
    ),
    "HPA_MISSING_MINREPLICAS_KEY": (CheckCategory.Workload, "HorizontalPodAutoscaler.minReplicas"),
    "HPA_MISSING_MAXREPLICAS_KEY": (CheckCategory.Workload, "HorizontalPodAutoscaler.maxReplicas"),
    "INGRESS_INCORRECT_HOST_VALUE_PERMISSIVE": (CheckCategory.Network, "Ingress.spec.rules[].host"),
    "INGRESS_CVE2021_25742_INCORRECT_SERVER_SNIPPET_KEY": (
        CheckCategory.Vulnerability,
        ".metadata.annotations.nginx.ingress.kubernetes.io/server-snippet",
    ),
    "K8S_DEPRECATED_APIVERSION": (CheckCategory.Misc, ".apiVersion"),
    "K8S_INCORRECT_KIND_VALUE_POD": (CheckCategory.Workload, ".kind"),
    "SERVICE_INCORRECT_TYPE_VALUE_NODEPORT": (CheckCategory.Network, "Service.spec.type"),
    "WORKLOAD_INCORRECT_NAMESPACE_VALUE_DEFAULT": (CheckCategory.Workload, ".metadata.namespace"),
    "WORKLOAD_INCORRECT_RESTARTPOLICY_VALUE_ALWAYS": (CheckCategory.Reliability, ".spec.restartPolicy"),
    "WORKLOAD_INVALID_LABELS_VALUE": (CheckCategory.Workload, ".metadata.labels"),
    "WORKLOAD_MISSING_LABEL_OWNER_VALUE": (CheckCategory.Workload, ".metadata.labels.owner"),
}


class Scanner(ScannerBase):
    NAME = "Datree"
    SCAN_MANIFESTS_CMD = ["datree", "test", "-o", "json"]
    VERSION_CMD = ["datree", "version"]
    # according to their documentation they support glob patterns, but when trying the run never finishes
    SCAN_PER_FILE = True
    RUNS_OFFLINE = "when enabled explicitely"
    IMAGE_URL = "https://github.com/datreeio/datree/blob/main/images/datree_ICON%20FLAT.png?raw=true"
    CUSTOM_CHECKS = "when in 'Policy as Code' mode"
    FORMATS = ["Plain", "JSON", "JUnit", "YAML", "XML"]
    CI_MODE = True
    EXIT_CODES = {
        0: "All validations and the policy check passed and found no violations",
        1: "The CLI ran into an error, or was used incorrectly (i.e. an unknown argument was passed)",
        2: "One of the validations (YAML or Kubernetes schema) OR the policy check found at least one violation",
    }

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
        for file_result in results:
            policy_results = file_result["policyValidationResults"] or []
            for policy_result in policy_results:
                for result in policy_result["ruleResults"]:
                    occ_details = result["occurrencesDetails"]
                    if len(occ_details) > 1:
                        print(f"having {len(occ_details)} policy occurence details")

                    for detail in result["occurrencesDetails"]:
                        obj_name = detail["metadataName"]
                        m = check_id_pattern.search(obj_name)
                        check_id = m.group(1) if m is not None else None
                        check_results.append(
                            CheckResult(
                                check_id=check_id,
                                obj_name=obj_name,
                                got=CheckStatus.Alert,
                                kind=detail["kind"],
                                scanner_check_id=result["identifier"],
                                scanner_check_name=result["name"],
                                details=result["messageOnFailure"],
                                checked_path=cls.get_checked_path(result["identifier"]),
                            )
                        )
        return check_results

    @classmethod
    def get_checked_path(cls, check_id: str) -> str:
        """Get the path(s) controlled by the check.

        :param check_id: the id of the check
        :return: the check(s) as single string or an empty string if no path could be retrieved.
        """
        for cat_prefix, (_, paths) in CHECK_MAPPING.items():
            if check_id.startswith(cat_prefix):
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

        for scanner_check_id, (cat, _) in CHECK_MAPPING.items():
            if check_id == scanner_check_id:
                return cat
        return None
