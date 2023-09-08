from dataclasses import dataclass
from enum import auto

from strenum import LowercaseStrEnum, SnakeCaseStrEnum, StrEnum  # will be default in python 3.11+

MAIN_NS = "kalm-benchmark"
UNRESTRICTED_NS = "kalm-benchmark-unrestricted-ns"


class CheckKey(SnakeCaseStrEnum):
    CheckId = "check"
    CheckPath = auto()
    Description = auto()
    Expect = "expected"


CMDS = [
    "bin/bash",
    "sbin/sh",
    "bin/ksh",
    "bin/tcsh",
    "bin/zsh",
    "usr/bin/scsh",
    "bin/csh",
    "bin/busybox",
    "usr/bin/busybox",
]
SENSITIVE_KEYS = [
    "aws_access_key_id",
    "aws_secret_access_key",
    "azure_batchai_storage_account",
    "azure_batchai_storage_key",
    "azure_batch_account",
    "azure_batch_key",
    "secret",
    "key",
    "password",
    "pwd",
    "token",
    "jwt",
    "bearer",
    "credential",
]
SENSITIVE_VALUES = "PRIVATE KEY eyJhbGciO JWT Bearer"
DANGEROUS_CAPABILITIES = ["ALL", "SYS_ADMIN", "NET_ADMIN"]
INSECURE_CAPABILITIES = [
    "AUDIT_WRITE",
    "BPF",
    "CHOWN",
    "DAC_OVERRIDES",
    "FOWNER",
    "FSETID",
    "KILL",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "MKNOD",
    "NET_BIND_SERVICE",
    "NET_RAW",
    "PERFMON",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_BOOT",
    "SYS_CHROOT",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_PTRACE",
]


class PodSecurityLevel(LowercaseStrEnum):
    Privileged = auto()
    Baseline = auto()
    Restricted = auto()


class PodSecurityAdmissionMode(LowercaseStrEnum):
    Warn = auto()
    Audit = auto()
    Enforce = auto()


class AppArmorProfile(StrEnum):
    # https://kubernetes.io/docs/tutorials/security/apparmor/#podsecuritypolicy-annotations
    Unconfined = "unconfined"  # disables AppArmor
    RuntimeDefault = "runtime/default"
    localhost = "localhost/"  # requires path to local profile after the slash


class SeccompProfile(StrEnum):
    Unconfined = "Unconfined"  # disables Seccomp
    RuntimeDefault = "RuntimeDefault"
    localhost = "Localhost/"  # requires path to local profile after the slash


class SeccompProfileForPSP(StrEnum):
    # name of same profile differ for PSP and pod itself
    Unconfined = "unconfined"  # disables Seccomp
    RuntimeDefault = "runtime/default"
    DockerDefault = "docker/default"  # docker/default is deprecated as of 1.11
    localhost = "localhost/"  # requires path to local profile after the slash


class SeLinuxRule(StrEnum):
    MustRunAs = "MustRunAs"  # Requires at least one range to be specified. Uses the minimum value
    # of the first range as the default. Validates against all ranges.
    RunAsAny = "RunAsAny"  # No default provided. Allows any fsGroup ID to be specified.


class GenericPspRule(StrEnum):
    MustRunAs = "MustRunAs"  # Requires at least one range to be specified. Uses the minimum value
    # of the first range as the default. Validates against all ranges.
    MayRunAs = "MayRunAs"  # Requires at least one range to be specified. Allows FSGroups to be left
    # unset without providing a default. Validates against all ranges if FSGroups is set.
    RunAsAny = "RunAsAny"  # No default provided. Allows any fsGroup ID to be specified.


class FsGroupRule(StrEnum):
    MustRunAs = "MustRunAs"  # Requires at least one range to be specified. Uses the minimum value
    # of the first range as the default. Validates against all ranges.
    MayRunAs = "MayRunAs"  # Requires at least one range to be specified. Allows FSGroups to be left
    # unset without providing a default. Validates against all ranges if FSGroups is set.
    RunAsAny = "RunAsAny"  # No default provided. Allows any fsGroup ID to be specified.


class RunAsUserRule(StrEnum):
    MustRunAsNonRoot = "MustRunAsNonRoot"
    MustRunAs = "MustRunAs"
    RunAsAny = "RunAsAny"


class SupplementalGroupsRule(StrEnum):
    MustRunAs = "MustRunAs"  # Requires at least one range to be specified. Uses the minimum value
    # of the first range as the default. Validates against all ranges.
    MayRunAs = "MayRunAs"  # Requires at least one range to be specified. Allows supplementalGroups to be left
    # unset without providing a default. Validates against all ranges if supplementalGroups is set.
    RunAsAny = "RunAsAny"  # No default provided. Allows any SupplementalGroup ID to be specified.


class CheckStatus(StrEnum):
    Pass = "pass"
    Alert = "alert"


class VolumeType(StrEnum):
    Empty = "empty"
    HostPath = "hostpath"


@dataclass
class MissingCheck:
    id: str
    name: str
    description: str
    checked_path: str | None = None
    expected: str | None = "alert"


MISSING_CHECKS = [
    MissingCheck(
        "RBAC-011",
        "minimize subjects per namespace",
        "Significant number of Subjects having access to a Namespace might be a potential security risk",
    ),
    MissingCheck(
        "RBAC-018",
        "Role that grant permissions to system reserved namespace",
        "A role was found that grants permission over system reserved namespace (either default or kube-system)",
    ),
    MissingCheck(
        "RBAC-019",
        "Avoid use of system:masters group",
        (
            "The system:masters group has unrestricted access to the Kubernetes API hard-coded into "
            "the API server source code. An authenticated user who is a member of this group cannot "
            "have their access reduced, even if all bindings and cluster role bindings which mention it, are removed."
        ),
        "ClusterRole.rules[].verbs|Role.rules[].verbs",
    ),
    MissingCheck("POD-004", "dont share service account between workloads", "", ".spec.serviceAccountName"),
    MissingCheck(
        "POD-005", "don't reference non-existing SA", "", ".spec.serviceAccountName|ServiceAccount.metadata.name"
    ),
    MissingCheck(
        "POD-015",
        "enable Seccomp",
        "annotation can be either a pod annotation, or a container annotation",
        ".spec.serviceAccountName|ServiceAccount.metadata.name",
    ),
    MissingCheck(
        "POD-020",
        "fsGroup / supplementalGroups should be non-zero",
        "",
        ".spec.securityContext.fsGroup|.spec.securityContext.supplementalGroups[]",
    ),
    MissingCheck(
        "POD-026",
        "Check SSH server running inside container",
        (
            "SSH server that is running inside a container may be used by attackers. "
            "If attackers gain valid credentials to a container, whether by brute force attempts "
            "or by other methods (such as phishing), they can use it to get remote access to the container by SSH."
        ),
        ".spec.containers[].ports[].containerPort",
    ),
    MissingCheck(
        "POD-026",
        "dont map privileged port into container",
        "",
        ".spec.containers[].ports.containerPort",  #
    ),
    MissingCheck(
        "POD-027",
        "Container is running with multiple open ports",
        "Having too many open ports increases the attack surface of the application and the container",
        ".spec.containers[].ports[].containerPort",
    ),
    MissingCheck(
        "POD-028",
        "don't use unsafe proc mounts",
        "",
        ".spec.containers[].securityContext.procMount",
    ),
    MissingCheck(
        "POD-047",
        "Container is running with shared mount propagation",
        "Shared volumes can overwrite data on the host, and are considered dangerous.",
        ".spec.containers[].volumeMounts[].mountPropagation",
    ),
    MissingCheck(
        "POD-048",
        "dont use disallowed volume types",
        "usage of non-ephemeral volume-types should be limited to those defined through PersistentVolumes",
        ".spec.volumes[]",
    ),
    MissingCheck(
        "NS-003",
        "ensure that components in a Namespace are restricted to only the necessary",
        (
            "Limiting the scope of user permissions can reduce the impact of mistakes or malicious activities. "
            "A Kubernetes namespace allows you to partition created resources into logically named groups. "
        ),
        ".metadata.namespace",
    ),
    MissingCheck(
        "NS-004",
        "No owner for namespace affects the operations",
        ("Limiting the scope of user permissions can reduce the impact of mistakes or malicious activities. "),
        ".metadata.namespace",
    ),
    MissingCheck(
        "CM-002",
        "Prevent ConfigMap security vulnerability (CVE-2021-25742)",
        (
            "users with limited access to a Kubernetes cluster, but with the ability to create an "
            "Ingress object based on the NGINX Ingress Controller, could elevate privilege and access "
            "full cluster secrets (NVD severity of this issue: High)."
        ),
        "Configmap.data.allow-snippet-annotation",
    ),
    MissingCheck(
        "NP-006",
        "ensure all workloads are referenced by a Network Policy",
        "",
        (
            "NetworkPolicy.spec.podSelector.matchLabels|"
            "NetworkPolicy.ingress[].from[].podSelector|"
            "NetworkPolicy.egress[].from[].podSelector"
        ),
    ),
    MissingCheck("SRV-001", "ensure all services target a pod", "", "Service.spec.selector"),
    MissingCheck(
        "SRV-002",
        "don’t use NodePort",
        (
            "NodePort services should be avoided as they are insecure, and can't be used together with NetworkPolicies."
            "Exposing a NodePort will open a port on all nodes to be reached by the cluster's external network. "
            "Using this method to expose the application is less secure and forces you to create unnecessary coupling "
            "between services in order to expose them all to external traffic."
        ),
        "Service.spec.type|Service.spec.ports[].nodePort",
    ),
    MissingCheck(
        "SC-003",
        "configure image provenance using ImagePolicyWebhook admission controller",
        "As suggeded by CIS benchmark (5.5.1)",
    ),
    MissingCheck(
        "SC-004",
        "Use trusted image registry",
        "Use trusted repo which scans images for known vulnerabilities and misconfigurations",
    ),
    MissingCheck(
        "ING-001",
        "Set HTTP security headers on the Kubernetes Ingress controller",
        "",
        (
            'Ingress.metadata.annotations["nginx.ingress.kubernetes.io/configuration-snippet"]|'
            'ConfigMap.data["proxy-set-headers"]'
        ),
    ),
    MissingCheck(
        "ING-002",
        "enable TLS for Ingress",
        "Configure tls in ingress. specifying a Secret that contains a TLS private key and certificate",
        'Ingress.spec.tls|Secret.data["tls.crt"]|Secret.data["tls.key"]',
    ),
    MissingCheck(
        "ING-003",
        "ensure ingress targets a Service",
        "",
        "Ingress.spec.rules[].paths[].backend.service",
    ),
    MissingCheck(
        "ING-004",
        "prevent ingress from forwarding all traffic to a single container",
        (
            "Misconfiguring the ingress host can unintended forward all traffic to a single pod "
            "instead of leveraging the load balancing capabilities. By verifying that ingress traffic is "
            "targeted by multiple pods, you will achieve higher application availability because you won't be "
            "dependent upon a single pod to serve all ingress traffic. "
            "(From https://hub.datree.io/built-in-rules/prevent-ingress-forwarding-traffic-to-single-containerdatree)"
        ),
        "Ingress.spec.rules[].host",
    ),
    MissingCheck(
        "ING-005",
        "CVE-2021-25742 nginx-ingress snippet annotation vulnerability",
        (
            "Security issue in ingress-nginx where a user that can create or update ingress objects "
            "can use the custom snippets feature to obtain all secrets in the cluster "
            "(see more at https://github.com/kubernetes/ingress-nginx/issues/7837) To mitigate this vulnerability"
            "Set allow-snippet-annotations to false in your ingress-nginx ConfigMap"
        ),
        'Ingress.metadata.annotations["nginx.ingress.kubernetes.io/server-snippet"]',
    ),
]
