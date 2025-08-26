import re
from pathlib import Path

from loguru import logger

from kalm_benchmark.utils.constants import RunUpdateGenerator

from ..utils import normalize_path
from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

CONTROL_CATEGORY = {
    "C-0001": (CheckCategory.Workload, ".spec.containers[].image"),  # Forbidden Container Registries
    "C-0002": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),  # Exec into container
    "C-0004": (
        CheckCategory.Reliability,
        [
            ".spec.containers[].resources.limits.memory",
            ".spec.containers[].resources.requests.memory",
        ],
    ),  # Resource memory limit and request
    "C-0005": (CheckCategory.Infrastructure, "kube-api.insecure-port"),  # API server insecure port is enabled
    # "C-0006": (CheckCategory.PodSecurity, ""),  # gone?
    "C-0007": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),  # Data Destruction
    "C-0009": (
        CheckCategory.Reliability,  # Resource limits
        [
            ".spec.containers[].resources.limits.memory",
            ".spec.containers[].resources.requests.memory",
        ],
    ),
    # "C-0011": (CheckCategory.Network, ""),  # gone?
    "C-0012": (
        CheckCategory.DataSecurity,
        [
            ".data.secret",
            ".data.bearer",
            ".data.token",
            "data.password",
            ".spec.containers[].env[].valueFrom",
            ".spec.containers[].env[].value",
        ],
    ),  # Applications credentials in configuration files
    "C-0013": (
        CheckCategory.Workload,
        [
            ".spec.securityContext.runAsUser",
            ".spec.securityContext.runAsGroup",
            ".spec.containers[].securityContext.runAsUser",
            ".spec.containers[].securityContext.runAsGroup",
            ".spec.containers[].securityContext.allowPrivilegeEscalation",
        ],
    ),  # Non-root containers
    "C-0014": (
        CheckCategory.IAM,
        [
            "RoleBinding.roleRef.name",
            "ClusterRoleBinding.roleRef.name",
            ".roleRef.name",
        ],
    ),  # Access Kubernetes dashboard
    "C-0015": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),  # List Kubernetes secrets
    "C-0016": (
        CheckCategory.Workload,
        ".spec.containers[].securityContext.allowPrivilegeEscalation",
    ),  # Allow privilege escalation
    "C-0017": (
        CheckCategory.Workload,
        ".spec.containers[].securityContext.readOnlyRootFilesystem",
    ),  # Immutable container filesystem
    "C-0018": (CheckCategory.Reliability, ".spec.containers[].readinessProbe"),  # Configured readiness probe
    # "C-0019": (CheckCategory.PodSecurity, ""),  # gone?
    "C-0020": (CheckCategory.Workload, ".spec.volumes[].hostPath"),  # Mount service principal
    "C-0021": (
        CheckCategory.Workload,
        ["Service.spec.type", ".spec.containers[].ports[]"],
    ),  # Exposed sensitive interfaces
    # "C-0024": (CheckCategory.PodSecurity, ""),  # gone?
    # "C-0025": (CheckCategory.PodSecurity, ""),  # gone?
    "C-0026": (CheckCategory.Workload, "Cronjob"),  # Kubernetes CronJob
    # "C-0028": (CheckCategory.PodSecurity, ""),  # gone?
    "C-0030": (
        CheckCategory.Segregation,
        ["NetworkPolicy.spec.podSelector.matchLabels", "NetworkPolicy.spec.ingress", "NetworkPolicy.spec.egress"],
    ),  # Ingress and Egress blocked
    "C-0031": (
        CheckCategory.IAM,  # Delete Kubernetes events
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),
    # "C-0033": (CheckCategory.Workload, ""),  # gone?
    "C-0034": (
        CheckCategory.Workload,
        [".automountServiceAccountToken", ".spec.automountServiceAccountToken"],
    ),  # Automatic mapping of service account
    "C-0035": (
        CheckCategory.IAM,
        ["RoleBinding.roleRef.name", "ClusterRoleBinding.roleRef.name", ".roleRef.name"],
    ),  # Cluster-admin binding
    "C-0036": (
        CheckCategory.AdmissionControl,
        "ValidatingWebhookConfiguration",
    ),  # Validate admission controller (validating)
    "C-0037": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),  # CoreDNS poisoning
    "C-0038": (CheckCategory.Workload, [".spec.hostIPC", ".spec.hostPID"]),  # Host PID/IPC privileges
    "C-0039": (
        CheckCategory.AdmissionControl,
        "MutatingWebhookConfiguration",
    ),  # Validate admission controller (mutating)
    "C-0041": (CheckCategory.Workload, ".spec.hostNetwork"),  # HostNetwork access
    "C-0042": (CheckCategory.Workload, ".spec.containers[].ports[]"),  # SSH server running inside container
    "C-0044": (CheckCategory.Workload, ".spec.containers[].ports[].hostPort"),  # Container hostPort
    "C-0045": (CheckCategory.Workload, ".spec.volumes[].hostPath"),  # Writable hostPath mount
    "C-0046": (CheckCategory.Workload, ".spec.securityContext.capabilities"),  # Insecure capabilities
    # "C-0047": (CheckCategory.Workload, ""),  # gone?
    "C-0048": (CheckCategory.Workload, ".spec.volumes[].hostPath"),  # HostPath mount
    "C-0049": (CheckCategory.Segregation, "NetworkPolicy.metadata.namespace"),  # Network mapping
    "C-0050": (
        CheckCategory.Reliability,
        [
            ".spec.containers[].resources.limits.memory",
            ".spec.containers[].resources.requests.memory",
        ],
    ),  # Resources CPU limit and request
    "C-0052": (CheckCategory.Infrastructure, ""),  # Instance Metadata API (Run Kubescape with host sensor)
    "C-0053": (
        CheckCategory.IAM,
        ["ClusterRoleBinding.subjects[].name", "RoleBinding.subjects[].name", ".subjects[].name"],
    ),  # Access container service account
    "C-0054": (CheckCategory.Segregation, "NetworkPolicy.metadata.namespace"),  #  Cluster internal networking
    "C-0055": (
        CheckCategory.Workload,
        [
            ".spec.securityContext.seccompProfile",
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io",
            ".spec.securityContext.seLinuxOptions",
        ],
    ),  # Linux hardening
    "C-0056": (CheckCategory.Reliability, ".spec.livenessProbe"),  # Configured liveness probe
    "C-0057": (CheckCategory.Workload, ".spec.containers[].securityContext.privileged"),  # Privileged container
    "C-0058": (
        CheckCategory.Vulnerability,
        "kubelet",
    ),  # CVE-2021-25741 - Using symlink for arbitrary host file system access.
    "C-0059": (
        CheckCategory.Vulnerability,
        "Ingress.metadata.annotations.nginx",
    ),  # CVE-2021-25742-nginx-ingress-snippet-annotation-vulnerability
    # "C-0060": (CheckCategory.Workload, ""),  # gone?
    "C-0061": (CheckCategory.Segregation, ".metadata.namespace"),  # Pods in default namespace
    "C-0062": (CheckCategory.Workload, ".spec.containers[].command[]"),  # Sudo in container entrypoint
    "C-0063": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),  # Portforwarding privileges
    # "C-0064": (CheckCategory.PodSecurity, ""),  # gone?
    "C-0065": (
        CheckCategory.IAM,
        [
            "ClusterRole.rules[].resources",
            "ClusterRole.rules[].verbs",
            "Role.rules[].resources",
            "Role.rules[].verbs",
        ],
    ),  # No impersonation
    "C-0066": (CheckCategory.Infrastructure, "etcd"),  #  Secret/etcd encryption enabled
    "C-0067": (CheckCategory.Infrastructure, ""),  # Audit logs enabled
    "C-0068": (CheckCategory.AdmissionControl, ""),  # PSP enabled?
    "C-0069": (CheckCategory.Infrastructure, "kubelet"),  # Disable anonymous access to Kubelet service
    "C-0070": (CheckCategory.Infrastructure, "kubelet"),  # Enforce Kubelet client TLS authentication
    # "C-0071": (CheckCategory.Infrastructure, ""),  # gone?
    "C-0073": (CheckCategory.Workload, ".metadata.ownerReferences"),  # Naked pods
    "C-0074": (CheckCategory.Workload, ".spec.volumes[].hostPath"),  # Container runtime socket mounted
    "C-0075": (CheckCategory.Workload, ".spec.containers[].imagePullPolicy"),  #  Image pull policy on latest tag
    "C-0076": (CheckCategory.Workload, ".metadata.labels"),  # Label usage for resources
    "C-0077": (CheckCategory.Workload, ".metadata.labels"),  # K8s common labels usage
    "C-0078": (CheckCategory.Workload, ".spec.containers[].image"),  # Images from allowed registry
    "C-0079": (CheckCategory.Infrastructure, "Node"),  #  CVE-2022-0185-linux-kernel-container-escape
    # "C-0080"(: CheckCategory.SupplyChain,""),  # gone?
    "C-0081": (CheckCategory.Infrastructure, "Node"),  # CVE-2022-24348-argocddirtraversal
    # "C-0082": (CheckCategory.Infrastructure, ""), # gone?
}


class Scanner(ScannerBase):
    NAME = "Kubescape"
    IMAGE_URL = "https://www.armosec.io/wp-content/uploads/2023/01/Group-1000005089.svg"
    FORMATS = ["Plain", "JSON", "JUnit", "Prometheus", "PDF", "HTML", "Sarif"]
    # SCAN_MANIFESTS_CMD = ["kubescape", "scan", "--format", "sarif", "--verbose", "--keep-local"]
    SCAN_MANIFESTS_CMD = [
        "kubescape",
        "scan",
        "--format",
        "json",
        "--format-version",
        "v2",
        # "--verbose",
        # "--keep-local",
        # "--view",
        # "resource",
    ]  # Note: Removed framework to fix prioritizedResource missing issue
    RUNS_OFFLINE = "artifacts/frameworks can be downloaded"
    CUSTOM_CHECKS = True
    VERSION_CMD = ["kubescape", "version"]

    def scan_manifests(self, path: str | Path) -> RunUpdateGenerator:
        """Start a scan of manifests at the specified location.
        If the path points to a directory, all yaml files within it will be scanned

        :param path: the path to the location with the manifest(s)
        :return: a list of results per file
        """
        if path.is_dir():
            path = path / "*.yaml"
        results = yield from super().scan_manifests(path)
        return results

    def scan_cluster(self) -> RunUpdateGenerator:
        """
        Run the application against the benchmark cluster
        :param framework: the set of pre-defined checks to execute
        :returns the results as dictionary
        """
        cmd = ["kubescape", "scan", "--format", "json", "-s", "--verbose"]
        results = yield from self.run(cmd)
        return results

    @classmethod
    def parse_results(cls, scan_result: dict) -> list[CheckResult]:
        """
        Parses the raw results and turns them into a flat list of check results.
        :param scan_result: the results which will be parsed
        :returns: the list of check results
        """
        check_results = []

        resource_infos = {r["resourceID"]: r["object"] for r in scan_result["resources"]}

        for resource_results in scan_result["results"]:
            resource_id = resource_results["resourceID"]
            check_results += parse_resource_result(resource_results, resource_infos[resource_id])

        return check_results

    @classmethod
    def categorize_check(cls, check_id: str) -> str:
        cat, _ = CONTROL_CATEGORY.get(check_id, (None, None))
        return cat

    def get_version(self) -> str:
        """Retrieve the version number of the tool by executing the corresponding command.
        The tool returns the info in the format "Your vurrent version is: v<version>".
        :return: the version of the tool
        """
        raw_version = super().get_version()
        version = raw_version[raw_version.rindex("v") + 1 :]
        return version.strip()


def parse_resource_result(res_result: dict, resource_info: dict) -> list[CheckResult]:
    prio = res_result.get("prioritizedResource", {})

    obj = _parse_api_object(resource_info)
    results = []
    for ctrl in res_result["controls"]:
        ctrl_id = ctrl["controlID"]

        # Extract severity from multiple possible locations
        severity = None
        numeric_severity = None

        if prio and "severity" in prio:
            numeric_severity = prio["severity"]
        elif prio and "priorityVector" in prio:
            # Look for severity in priorityVector array
            for vector in prio["priorityVector"]:
                if "severity" in vector:
                    numeric_severity = vector["severity"]
                    break

        # If no numeric severity found, use scoreFactor as fallback
        if numeric_severity is None and "scoreFactor" in ctrl:
            score_factor = ctrl["scoreFactor"]
            if score_factor >= 8:
                numeric_severity = 3  # High
            elif score_factor >= 5:
                numeric_severity = 2  # Medium
            elif score_factor >= 2:
                numeric_severity = 1  # Low
            else:
                numeric_severity = 0  # Info

        # Convert numeric severity to text labels
        if numeric_severity is not None:
            severity_map = {3: "High", 2: "Medium", 1: "Low", 0: "Info"}
            severity = severity_map.get(numeric_severity, "Medium")

        for rule in ctrl["rules"]:
            checked_path = get_checked_path(ctrl_id, rule.get("paths", None), resource_info)
            status = _normalize_status(rule["status"])

            res = CheckResult(
                check_id=obj["check_id"],
                obj_name=obj["obj_name"],
                namespace=obj["namespace"],
                kind=resource_info["kind"],
                scanner_check_id=ctrl_id,
                scanner_check_name=ctrl["name"],
                details=f"Rule '{rule['name']}'",
                checked_path=checked_path,
                got=status,
                severity=severity,
            )
            results.append(res)

    return results


def get_checked_path(ctrl_id: str, paths: list | None = None, k8s_object: dict | None = None) -> str:
    """Get the path(s) controlled by the check.

    :param check_id: the id of the check
    :return: the check(s) as single string or an empty string if no path could be retrieved.
    """
    checked_paths = []
    if paths is not None:
        for p in paths:
            if (failed_path := p.get("failedPath", None)) is not None:
                # keys in data are treated as array index -> convert them to valid JSON Path
                failed_path = re.sub(r"data\[(.*)\]", r"data.\1", failed_path)
                normalized_path = normalize_path(failed_path, k8s_object)
                checked_paths.append(normalized_path)

    # fallback: derive checked path from control mapping, which may be less accurate
    if len(checked_paths) == 0:
        _, checked_paths = CONTROL_CATEGORY.get(ctrl_id, (None, None))

    if isinstance(checked_paths, str):
        return checked_paths
    if isinstance(checked_paths, list):
        return "|".join(checked_paths)


def _normalize_status(status: str) -> str:
    if status == "failed":
        return CheckStatus.Alert
    elif status in ["passed", "skipped"]:
        return CheckStatus.Pass
    else:
        logger.warning(f"Unknown status while parsing kubescape: '{status}'. Expected either 'failed' or 'success")
        return CheckStatus.Pass


def _parse_api_object(obj: dict) -> dict:
    check_infos = []
    meta = obj.get("metadata", None)
    check = {"check_id": None}
    if meta is not None:
        check = _parse_object_meta(meta)
    check["kind"] = obj["kind"]

    # ServiceAccounts have the namespace and name on the top level and not on the metaobject
    if check["kind"] == "ServiceAccount":
        check["namespace"] = obj.get("namespace", None)

    if "obj_name" not in check:
        check["obj_name"] = obj["name"]
    check_infos.append(check)
    if "relatedObjects" in obj:
        for rel_obj in obj["relatedObjects"]:
            check = _parse_object_meta(rel_obj.get("metadata", None))
            check["kind"] = rel_obj["kind"]
            check_infos.append(check)

    res = _consolidate_objects(check_infos)
    return res


# def _parse_rule_responses(responses: list[dict]) -> list[CheckResult]:
#     results = []
#     for r in responses:
#         checked_path = normalize_paths(r["failedPaths"], r["fixPaths"])
#         status = _normalize_status(r["ruleStatus"])
#         details = ", ".join(r["failedPaths"] or [""])

#         api_objs = r["alertObject"]["k8sApiObjects"]
#         for obj in api_objs:
#             checked_path = normalize_paths(r["failedPaths"], r["fixPaths"], obj.get("relatedObjects", None))
#             res = _parse_api_object(obj)
#             results.append(CheckResult(got=status, details=details, checked_path=checked_path, **res))
#     return results


# def normalize_paths(
#     failed_paths: list[str] | None = None,
#     fix_paths: list[dict[str, str]] | None = None,
#     related_objects: list[dict] | None = None,
# ) -> str:
#     if failed_paths is None and fix_paths is None:
#         return None

#     paths = []
#     if failed_paths is not None:
#         paths += failed_paths
#     if fix_paths is not None:
#         paths += [fix_path["path"] for fix_path in fix_paths]

#     normalized_paths = [normalize_path(p, related_objects) for p in paths]
#     return "|".join(set(normalized_paths))


def _consolidate_objects(check_infos: list[dict]) -> dict:
    """
    Consolidate/pick check infos from multiple objects with the following preferences:
    1) if there is a single object with a valid check_id, use all the information of that object
    2) if multiple objects have a valid check_id: use the single object where the id is part of it's name
    3) if none ore more than 1 object have a valid name, merge the check informations
    :param check_infos: the list of check_informations extracted from objects
    :returns: a single dictionary with the check information resulting from the consodliation.
    """
    num_objects = len(check_infos)
    if num_objects == 1:  # there is nothing to consolidate when only 1 object is there
        return check_infos[0]
    elif num_objects == 0:
        logger.error("no object has check meta attached, which should never happen!")

    # filter out objects without a check id
    rel_checks = [check for check in check_infos if check.get("check_id", None) is not None]
    # if exactly one object has the check meta info, only it is relevant
    if len(rel_checks) == 1:
        return rel_checks[0]
    elif len(rel_checks) == 0:
        return _merge_dicts(check_infos)

    # check id in name is case insensitive
    check_id = rel_checks[0]["check_id"].lower()
    # prefer objects where name starts with check_id
    named_objects = [check for check in rel_checks if check["obj_name"].startswith(check_id)]
    if len(named_objects) == 1:
        return rel_checks[0]

    return _merge_dicts(check_infos)


def _merge_dicts(dicts: list[dict]) -> dict:
    res = {}
    for d in dicts:
        for k, v in d.items():
            if k not in res:
                res[k] = v
            elif res[k] is None:
                res[k] = v
            elif v is not None and v not in res[k].split(";"):
                res[k] += ";" + v
    return res


def _parse_object_meta(meta: dict) -> dict[str, str]:
    return {
        "check_id": meta.get("labels", {}).get("check", None) if "labels" in meta else None,
        # default to 'pass', because benchmark is designed to have only on object that should actually trigger an alert
        # missing expect annotation means the check was not designed to trigger for that ojbect
        # "expected": meta.get("annotations", {}).get("expected", CheckStatus.Pass),
        "obj_name": meta["name"],
        "namespace": meta.get("namespace", None),
    }
