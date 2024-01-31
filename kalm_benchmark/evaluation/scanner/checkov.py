import json
import re
from pathlib import Path
from typing import Generator

from kalm_benchmark.constants import RunUpdateGenerator, UpdateType

from ..utils import normalize_path
from .scanner_evaluator import CheckCategory, CheckResult, CheckStatus, ScannerBase

# a list of all checks is here: https://www.checkov.io/5.Policy%20Index/kubernetes.html
CHECK_MAPPING = {
    "CKV_K8S_1": (CheckCategory.AdmissionControl, ".spec.hostPID"),
    "CKV_K8S_2": (CheckCategory.AdmissionControl, ".spec.privileged"),
    "CKV_K8S_3": (CheckCategory.AdmissionControl, [".spec.serviceAccount", ".spec.hostIPC"]),
    "CKV_K8S_4": (CheckCategory.AdmissionControl, ".spec.hostNetwork"),
    "CKV_K8S_5": (CheckCategory.AdmissionControl, ".spec.allowPrivilegeEscalation"),
    "CKV_K8S_6": (CheckCategory.AdmissionControl, ".spec.runAsUser.rule"),
    "CKV_K8S_7": (CheckCategory.AdmissionControl, ".spec.allowedCapabilities"),
    "CKV_K8S_8": (CheckCategory.Reliability, ".spec.containers[].livenessProbe"),
    "CKV_K8S_9": (CheckCategory.Reliability, ".spec.containers[].readinessProbe"),
    "CKV_K8S_10": (CheckCategory.Reliability, ".spec.containers[].resources.requests.cpu"),
    "CKV_K8S_11": (CheckCategory.Reliability, ".spec.containers[].resources.limits.cpu"),
    "CKV_K8S_12": (CheckCategory.Reliability, ".spec.containers[].resources.requests.memory"),
    "CKV_K8S_13": (CheckCategory.Reliability, ".spec.containers[].resources.limits.memory"),
    "CKV_K8S_14": (CheckCategory.Workload, ".spec.containers[].image"),
    "CKV_K8S_15": (CheckCategory.Workload, ".spec.containers[].imagePullPolicy"),
    "CKV_K8S_16": (CheckCategory.Workload, ".spec.containers[].securityContext.privileged"),
    "CKV_K8S_17": (CheckCategory.Workload, ".spec.hostPID"),
    "CKV_K8S_18": (CheckCategory.Workload, ".spec.hostIPC"),
    "CKV_K8S_19": (CheckCategory.Workload, ".spec.hostNetwork"),
    "CKV_K8S_20": (CheckCategory.Workload, ".spec.containers[].securityContext.allowPrivilegeEscalation"),
    "CKV_K8S_21": (CheckCategory.Workload, ".metadata.namespace"),
    "CKV_K8S_22": (CheckCategory.Workload, ".spec.containers[].securityContext.readOnlyRootFilesystem"),
    "CKV_K8S_23": (
        CheckCategory.Workload,
        [".spec.containers[].securityContext.runAsNonRoot", ".spec.containers[].securityContext.runAsUser"],
    ),
    "CKV_K8S_24": (CheckCategory.AdmissionControl, ".spec.allowedCapabilities"),
    "CKV_K8S_25": (CheckCategory.Workload, ".spec.containers[].securityContext.capabilities"),
    "CKV_K8S_26": (CheckCategory.Workload, ".spec.containers[].ports[].hostPort"),
    "CKV_K8S_27": (CheckCategory.Workload, ".spec.volumes[].hostPath.path"),
    "CKV_K8S_28": (CheckCategory.Workload, ".spec.containers[].securityContext.capabilities.drop"),
    "CKV_K8S_29": (CheckCategory.Workload, [".spec.containers[].securityContext", ".spec.securityContext"]),
    "CKV_K8S_30": (CheckCategory.Workload, [".spec.containers[].securityContext", ".spec.securityContext"]),
    "CKV_K8S_31": (CheckCategory.Workload, ".spec.securityContext.seccompProfile.type"),
    "CKV_K8S_32": (
        CheckCategory.AdmissionControl,
        ".metadata.annotations.seccomp.security.alpha.kubernetes.io/pod",
    ),
    "CKV_K8S_33": (
        CheckCategory.Workload,
        [".metadata.labels.app", ".metadata.labels.k8s-app", ".spec.containers[].image"],
    ),
    "CKV_K8S_34": (
        CheckCategory.Workload,
        [".metadata.labels.app", ".metadata.labels.name", ".spec.containers[].image"],
    ),
    "CKV_K8S_35": (
        CheckCategory.Workload,
        [".spec.containers[].env[].valueFrom.secretKeyRef", ".spec.containers[].envFrom[].secretRef"],
    ),
    "CKV_K8S_36": (CheckCategory.AdmissionControl, [".spec.allowedCapabilities", "requiredDropCapabilities"]),
    "CKV_K8S_37": (CheckCategory.Workload, ".spec.containers[].securityContext.capabilities.drop"),
    "CKV_K8S_38": (CheckCategory.Workload, ".spec.automountServiceAccountToken"),
    "CKV_K8S_39": (CheckCategory.Workload, ".spec.containers[].securityContext.capabilities.add"),
    "CKV_K8S_40": (
        CheckCategory.Workload,
        [".spec.securityContext.runAsUser", ".spec.containers[].securityContext.runAsUser"],
    ),
    "CKV_K8S_41": (CheckCategory.IAM, ["ServiceAccount.automountServiceAccountToken", "ServiceAccount.name"]),
    "CKV_K8S_42": (CheckCategory.IAM, ["RoleBinding.subjects[].name", "ClusterRoleBinding.subjects[].name"]),
    "CKV_K8S_43": (CheckCategory.Workload, ".spec.containers[].image"),
    "CKV_K8S_44": (CheckCategory.Workload, ["Service.metadata.labels.name", "Service.metadata.name"]),
    "CKV_K8S_45": (
        CheckCategory.Workload,
        [".spec.containers[].ports[].coontainerPort", ".metadata.name", ".metadata.labels.name"],
    ),
    "CKV_K8S_49": (
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
    "CKV_K8S_68": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K9S_69": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_70": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_71": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_72": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_73": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_74": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_75": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_77": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_78": (CheckCategory.Workload, "AdmissionConfiguration.plugins[].name"),  # has to be "EventRateLimit"
    "CKV_K8S_79": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_80": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_81": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_82": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_83": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_84": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_85": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_86": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_88": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_89": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_90": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_91": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_92": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_93": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_94": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_95": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_96": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_97": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_98": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_99": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_100": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_102": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_104": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_105": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_106": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_107": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_108": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_110": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_111": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_112": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_113": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_114": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_115": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_116": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_117": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_118": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_119": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_121": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_138": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_139": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_140": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_141": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_142": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_143": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_144": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_145": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_146": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_147": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_148": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_149": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_150": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_151": (CheckCategory.Infrastructure, [".spec.containers[].command", ".spec.containers[].args"]),
    "CKV_K8S_152": (
        CheckCategory.Network,
        "Ingress.metadata.annotations.nginx.ingress.kubernetes.io/server-snippet",
    ),  # check for CVE-2021-25742
    "CKV_K8S_153": (
        CheckCategory.Network,
        "Ingress.metadata.annotations.nginx.ingress.kubernetes.io/server-snippet",
    ),  # check for CVE-2021-25742
    "CKV_K8S_154": (
        CheckCategory.Network,
        "Ingress.metadata.annotations.nginx.ingress.kubernetes.io/server-snippet",
    ),  # check for CVE-2021-25742
}


class Scanner(ScannerBase):
    NAME = "Checkov"
    CUSTOM_CHECKS = True
    IMAGE_URL = (
        "https://raw.githubusercontent.com/bridgecrewio/checkov/master/docs/web/images/checkov_by_bridgecrew.png"
    )
    FORMATS = ["Plain", "CSV", "JSON", "CycloneDX", "JunitXML", "Github_failed_only", "Gitlab_SAST", "Sarif", "SPDX"]
    CI_MODE = True
    RUNS_OFFLINE = True
    VERSION_CMD = ["checkov", "--version"]

    def scan_manifests(self, path: Path) -> RunUpdateGenerator:
        """Start a scan of manifests at the specified location.
        If the path points to a directory, all yaml files within it will be scanned

        :param path: the path to the location with the manifest(s)
        :return: a list of results per file
        """
        # paths = [path] if path.is_file() else path.glob("*.yaml")
        scan_flag = "-f" if path.is_file() else "-d"
        cmd = ["checkov", "-o", "json", "--compact", scan_flag, str(path)]
        results = yield from self.run(cmd)
        return results

    def scan_cluster(self) -> RunUpdateGenerator:
        """Start a scan of the cluster resources by creating a job, which queries all resources and scans them.
        The job is configured using a prepared manifest, downloaded and adjusted from the Checkov repository
        (see https://github.com/bridgecrewio/checkov/tree/master/kubernetes).
        After the job is created the state of the pod and jobs are watched to handle any potential issues.

        :return: a list of the results from the scan
        :yield: sends updates as tuples with an updatelevel and a corresponding message
        """
        namespace = "checkov"

        creation_res = yield from self.run(
            ["kubectl", "apply", "-f", "checkov-job.yaml", "-n", namespace],
            parse_json=False,
        )

        created_resources = []
        if creation_res is not None:
            for msg in creation_res.strip().split("\n"):
                # the text is usually sth. like '<type>/<name> created'
                yield UpdateType.Info, msg
                # -> by splitting on space and using the first part both the 'kind' and the name are extracted
                created_resources.append(msg.split(" ", 1)[0])

        yield UpdateType.Info, "Job started, waiting for it to finish ... this may take several minutes"

        # check if the pod is spawnd correctly; in case of a problem it could lead to a loop, where the job would
        # just report 'pending' but the container is unable to start.
        wait_for_pod_gen = self.run(
            [
                "kubectl",
                "wait",
                "pods",
                "--for",
                "jsonpath={.status.phase}=Running",
                "-l",
                "job-name=checkov",
                "-n",
                namespace,
            ],
            parse_json=False,
        )
        if not (
            yield from self._wait_for_resource(
                wait_for_pod_gen,
                explanations={
                    "timed out waiting": "The pod failed to start. Please check it's state!",
                    "no matching resources": "No pod for the check found. Please check the cluster.",
                },
            )
        ):
            yield UpdateType.Info, (
                "Note: No resources were cleaned up, so the issue can be investigated. "
                "Please clean up any resources manually!"
            )
            return None

        # once the pod executing the scan is actually started wait for the job to finish
        wait_for_job_gen = self.run(
            # wait_result = yield from self.run(
            [
                "kubectl",
                "wait",
                "--for=condition=complete",
                "job/checkov",
                "--timeout=900s",  # wait for max. 15 minutes
                "-n",
                namespace,
            ],
            parse_json=False,
        )
        if not (
            yield from self._wait_for_resource(
                wait_for_job_gen,
                explanations={
                    "timed out waiting": "The scan has not finished within 15 minutes - please check its state!"
                },
            )
        ):
            yield from self._cleanup_resources(created_resources, namespace)
            return None

        results = yield from self.run(["kubectl", "logs", "job/checkov", "-n", namespace], parse_json=False)

        if len(results) == 0:
            yield UpdateType.Warning, "Scan concluded successfully, but could not retrieve logs from the job"
            results = None
        else:
            # if there are any outputs from stderr at the beginning, drop them
            # so the results can be parsed as regular JSON
            if not results.startswith("{"):
                idx = results.index("{")
                results = results[idx:]

            try:
                results = json.loads(results)
            except json.JSONDecodeError as exc:
                yield UpdateType.Error, f"Malformed JSON from the job logs: {exc}"
                results = None

        yield from self._cleanup_resources(created_resources, namespace)
        return results

    def _wait_for_resource(
        self, gen: RunUpdateGenerator, explanations: dict[str, str]
    ) -> Generator[tuple[UpdateType, str], None, bool]:
        """Consume all  messages from the provided generator.
        If there is an `Error` update it will signal the failure to the calling function,
            providing additional information based on the provided explanation mapping.
        If there is none, all the messages will be passed along.

        :param gen: the generator producesing updates of varying UpdateLevel
        :param explanations: a dictionary with a pattern in the generater message and the correspondign explanation
            If no pattern in this mapping matches the generated event, the original message will be used
        :return: boolean flag signaling if the wait has concluded successully or not
        :yield: all updates forwarded from the generator and additional explanation in case of an error
        """
        for level, msg in gen:
            if level == UpdateType.Error:
                reason = next((reason for pattern, reason in explanations.items() if pattern in msg), msg)
                yield level, reason + " The scan was aborted!"
                return False
            # if it's not a timeout of the wait, simply pass along the message
            yield level, msg
        return True

    def _cleanup_resources(self, resources: list[str], namespace: str) -> RunUpdateGenerator:
        """Delete all resources provided as names from the currently active kubernetes cluster in the designated namespace

        :param resources: a list of resource names, which will be deleted from the cluster
        :return: Nothing
        :yield: An update when starting the cleanup
        """
        yield UpdateType.Info, "Cleaning up created resources"
        # delete the in the reverse order of creation, to avoid any conflicts resulting due to dependencies among them
        for k8s_resource in reversed(resources):
            try:
                yield from self.run(
                    ["kubectl", "delete", "--ignore-not-found=true", k8s_resource, "-n", "namespace"], parse_json=False
                )
            except Exception as e:
                yield UpdateType.Error, e

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
        failed_checks = results["results"]["failed_checks"]
        for check in failed_checks:
            kind, ns, obj_name = check["resource"].split(".", maxsplit=2)
            m = check_id_pattern.search(obj_name)
            check_id = m.group(1) if m is not None else None
            check_result = check["check_result"]
            status = CheckStatus.Alert if check_result["result"] == "FAILED" else CheckStatus.Pass

            scanner_check_id = check["check_id"]
            checked_path = cls.get_checked_path(scanner_check_id, check_result["evaluated_keys"])

            check_results.append(
                CheckResult(
                    check_id=check_id,
                    obj_name=obj_name,
                    checked_path=checked_path,
                    got=status,
                    scanner_check_id=scanner_check_id,
                    scanner_check_name=check["check_name"],
                    extra=check["check_class"],
                    kind=kind,
                    namespace=ns,
                )
            )

        return check_results

    @classmethod
    def get_checked_path(cls, check_id: str, evaluated_keys: list[str]) -> str:
        """Get the path(s) controlled by the check.

        :param check_id: the id of the check
        :param evaluated_keys: the list of evaluated keys returned by the check
        :return: the check(s) as single string or an empty string if no path could be retrieved.
        """
        # some checks don't provide information the checked path -> look up by scanner check id
        if len(evaluated_keys) == 0:
            _, paths = CHECK_MAPPING.get(check_id.upper(), (None, None))
            if isinstance(paths, str):
                return paths
            if isinstance(paths, list):
                return "|".join(paths)
        else:
            normalized_paths = [_normalize_path(p) for p in evaluated_keys]
            return "|".join(set(normalized_paths))
        return ""


def _normalize_path(path: list[str]) -> str:
    """Transforms the path as provided by the tool into a normalized representation.
    This includes:
    - using '.' instead of '/' between path segments
    - dropping the path seperator before an array index in the path
    - removing any number in the brackets
    - dropping the spec.template in case of pod paths
    For example,"spec/template/spec/containers/[0]/image" will be converted to
    "'.spec.containers[].image'"

    :param path: the string which will be normalized
    :return: the normalized version of the provided path
    """
    path = normalize_path(path.replace("/", "."))
    path = path.replace(".[]", "[]")  # checkov has a '/' before the indexing bracke
    return path
