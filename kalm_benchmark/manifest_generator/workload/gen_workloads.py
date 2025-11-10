from constructs import Construct

from ..cdk8s_imports import k8s
from ..check import Check
from ..constants import (
    CMDS,
    DANGEROUS_CAPABILITIES,
    INSECURE_CAPABILITIES,
    MAIN_NS,
    SENSITIVE_KEYS,
    SENSITIVE_VALUES,
    AppArmorProfile,
    CheckStatus,
    ContainerConfig,
    ContainerResourceConfig,
    PodSchedulingConfig,
    PodSecurityConfig,
)
from .pod_base import Pod, Workload


class PodCheck(Check):
    """
    A single checks of a Pod misconfiguration/best practice
    """

    def __init__(
        self,
        scope: Construct,
        check_id: str,
        name: str,
        namespace: str | None = MAIN_NS,
        expect: str = CheckStatus.Alert,
        descr: str = None,
        check_path: str | list[str] | None = None,
        standards: list[dict] | None = None,
        **kwargs,
    ):
        """
        Instantiates a new Pod check with all relevant kubernetes resources.

        :param scope: the cdk8s scope in which the resources will be placed
        :param check_id: the id of the check. This is the prefix of the resulting file name
        :param name: the name of the check. This will be part of the resulting file name.
        :param namespace: the namespace of the resulting resources. If none is provided, the main namespace will be used
        :param expect: the expected outcome of the check
        :param descr: an optional description for the check
        :param check_path: the path(s) which is the essence of the check
        :param kwargs: any additional keyword arguments will be passed on to the resource
        """
        super().__init__(scope, check_id, name, expect, descr, check_path, standards, kwargs, namespace)
        Workload(self, self.name, self.meta, **kwargs)


class NakedPodIsBad(Check):
    """
    A dedicated check for a pod without any managing resource
    """

    def __init__(
        self,
        scope: Construct,
        *args,
        **kwargs,
    ):
        """
        Instantiates a new Pod check with all relevant kubernetes resources.

        :param scope: the cdk8s scope in which the resources will be placed
        :param args: any arguments for the generic check
        :param kwargs: any keyword arguments for the generic check
        """
        super().__init__(scope, *args, **kwargs)
        Pod(self, self.name, self.meta)


class VolumeMountCheck(Check):
    """
    A dedicated check for misconfiguration around the use of volumes and volume mount
    """

    def __init__(
        self,
        scope: Construct,
        check_id: str,
        name: str,
        expect: str = CheckStatus.Alert,
        descr: str = None,
        volume_name: str = "my-vol",
        volume_type: str | None = None,
        mount_path: str | None = "/var/data",
        mount_type: str | None = None,  # e.g. File, Directory, etc.
        sub_path: str | None = None,
        read_only: bool | None = True,
        standards: list[dict] | None = None,
        **kwargs,
    ):
        """
        Instantiates a new volume/volumeMount check with all relevant kubernetes resources.

        :param scope: the cdk8s scope in which the resources will be placed
        :param check_id: the id of the check. This is the prefix of the resulting file name
        :param name: the name of the check. This will be part of the resulting file name.
        :param expect: the expected outcome of the check
        :param descr: an optional description for the check
        :param volume_name: the name of the volume, this will be the link between
        the volume and the volumeMount in the pod
        :param volume_type: the type of volume.
        The supported options are "empty" for EmptyDirVolumeSource and "hostpath".
        :param mount_path: the path where the volume will be mounted.
         For hostpath, it's also the source path on the host
        :param mount_type: the type of mount. See https://kubernetes.io/docs/concepts/storage/volumes/#hostpath
        :param sub_path: a subpath on the volume which will be mounted.
        See https://kubernetes.io/docs/concepts/storage/volumes/#using-subpath
        :param read_only: a flag indicating whether the mounted volume is read-only.
        :param kwargs: any additional keyword arguments will be passed on to the resource
        """
        super().__init__(
            scope,
            check_id,
            name,
            expect,
            descr,
            check_path=[
                ".spec.volumes[]",
                ".spec.volumes[].hostPath",
                ".spec.volumes[].hostPath.path",
                ".spec.containers[].volumeMounts[]",
            ],
            standards=standards
        )  # id, name, expect, descr)

        empty_dir = k8s.EmptyDirVolumeSource() if volume_type == "empty" else None
        host_path = k8s.HostPathVolumeSource(path=mount_path, type=mount_type) if volume_type == "hostpath" else None

        volumes = [k8s.Volume(name=volume_name, host_path=host_path, empty_dir=empty_dir)]
        container_kwargs = {
            "volume_mounts": [
                k8s.VolumeMount(
                    name=volume_name,
                    mount_path=mount_path,
                    sub_path=sub_path,
                    read_only=read_only,
                )
            ]
        }
        Workload(
            self,
            self.name,
            self.meta,
            volumes=volumes,
            container_kwargs=container_kwargs,
            **kwargs,
        )


class EnvVarCheck(Check):
    """
    A dedicated check for misconfiguration around environment variables in a pod
    """

    def __init__(
        self,
        scope: Construct,
        *args,
        env_keys: list[str],
        **kwargs,
    ):
        """
        Instantiates a new check misconfigurations of an environment variable.
        The provided `env_keys` will be used as environment variable and their
        corresponding values is predefined list of sensitive values.

        :param scope: the cdk8s scope in which the resources will be placed
        :param args: any additional arguments will be passed on the general check
        :param env_keys: the environment variable keys, which will be used for the check.
        :param kwargs: any additional keyword arguments will be passed on to the general check
        """
        env_vars = [k8s.EnvVar(name=name, value=SENSITIVE_VALUES) for name in env_keys]

        super().__init__(scope, *args, **kwargs)
        Workload(self, self.name, self.meta, container=ContainerConfig(env_vars=env_vars))


class ConfigMapCheck(Check):
    """
    A dedicated check for misconfiguration around the use of ConfigMaps
    """

    def __init__(
        self,
        scope: Construct,
        check_id: str,
        name: str,
        expect: str = CheckStatus.Alert,
        descr: str = None,
        data: dict | None = None,
        check_path: str | list[str] | None = None,
        standards: list[dict] | None = None,
        **kwargs,
    ):
        """
        Instantiates a new configMap check to test certain misconfigurations.

        :param scope: the cdk8s scope in which the resources will be placed
        :param check_id: the id of the check. This is the prefix of the resulting file name
        :param name: the name of the check. This will be part of the resulting file name.
        :param expect: the expected outcome of the check
        :param descr: an optional description for the check
        :param data: a dictionary representing the content of the configmap
        :param kwargs: any additional keyword arguments will be passed on to the resource
        """
        super().__init__(scope, check_id, name, expect, descr, check_path, standards)
        k8s.KubeConfigMap(self, check_id, metadata=self.meta, data=data)


def gen_workloads(app, main_ns: str, unrestricted_ns: str) -> None:
    NakedPodIsBad(
        app,
        "WL-001",
        "Unmanaged Pods are discouraged",
        descr="Pods shouldn't be deployed without a resource managing it",
        check_path=[".metadata.ownerReferences", ".kind"],
    )

    PodCheck(
        app,
        "POD-002-1",
        "Explicit Default ServiceAccountName",
        descr="`default` ServiceAccount should never be used. Create a dedicated ServiceAccount when access"
        " to API server is needed when access to API server is needed.",
        security=PodSecurityConfig(service_account_name="default"),
        check_path=".spec.serviceAccountName",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.1.5"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Protecting Pod service account tokens"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A9"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["1.2.a"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Service account tokens are not mounted in pods that don't require them.", "Avoid using the default ServiceAccount. Instead, create dedicated ServiceAccounts for each workload."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Use Pod security policies to control the security-related attributes of pods, which includes container privilege levels."]}],
    )
    PodCheck(
        app,
        "POD-002-2",
        "No ServiceAccountName specified",
        descr="if no service account is specified it defaults to the "
        "`default` ServiceAccount, which should be avoided. "
        "Create a dedicated ServiceAccount without any permissions instead.",
        security=PodSecurityConfig(service_account_name=None),
        check_path=".spec.serviceAccountName",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.1.5"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Protecting Pod service account tokens"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A9"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["1.2.a"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Service account tokens are not mounted in pods that don't require them.", "Avoid using the default ServiceAccount. Instead, create dedicated ServiceAccounts for each workload."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Use Pod security policies to control the security-related attributes of pods, which includes container privilege levels."]}],
    )

    pod_sa_automount_combos = [
        {
            "name": "Automount ServiceAccountToken by Default",
            "pod": None,
            "sa": None,
            "expect": CheckStatus.Alert,
            "descr": "relying on default on both pod and SA level leads to token being needlessly mounted",
        },
        {
            "name": "default-pod-automount-sa",
            "pod": None,
            "sa": True,
            "expect": CheckStatus.Alert,
            "descr": "allowing automounting on SA leads to all pods without explicit setting to mount it automatically",
        },
        {
            "name": "default-pod-no-automount-sa",
            "pod": None,
            "sa": False,
            "expect": CheckStatus.Pass,
            "descr": "disabling automounting at SA level will be the default for pods as well",
        },
        {
            "name": "automount-pod-default-sa",
            "pod": True,
            "sa": None,
            "expect": CheckStatus.Alert,
            "descr": "enabling automounting at Pod level takes precedence over SA",
        },
        {
            "name": "automount-pod-and-sa",
            "pod": True,
            "sa": True,
            "expect": CheckStatus.Alert,
            "descr": "enabling automounting at Pod level takes precedence over SA",
        },
        {
            "name": "automount-pod-no-automount-sa",
            "pod": True,
            "sa": False,
            "expect": CheckStatus.Alert,
            "descr": "enabling automounting at Pod level takes precedence over SA",
        },
        {
            "name": "no-automount-pod-default-sa",
            "pod": False,
            "sa": None,
            "expect": CheckStatus.Pass,
            "descr": "disabling automounting at Pod level takes precedence over SA",
        },
        {
            "name": "no-automount-pod-automount-sa",
            "pod": False,
            "sa": True,
            "expect": CheckStatus.Pass,
            "descr": "disabling automounting at Pod level takes precedence over SA",
        },
        {
            "name": "no-automount-pod-and-sa",
            "pod": False,
            "sa": False,
            "expect": CheckStatus.Pass,
            "descr": "disabling automounting at Pod level takes precedence over SA",
        },
    ]

    for i, cfg in enumerate(pod_sa_automount_combos):
        PodCheck(
            app,
            f"POD-003-{i + 1}",
            cfg["name"],
            security=PodSecurityConfig(automount_sa_token=cfg["pod"]),
            sa_kwargs={"automount_sa_token": cfg["sa"]},
            check_path=[".spec.automountServiceAccountToken", ".automountServiceAccountToken"],
            expect=cfg["expect"],
            descr=cfg["descr"],
            standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.1.6"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Protecting Pod service account tokens"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A9"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["1.5.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9025"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Service account tokens are not mounted in pods that don't require them.", "automountServiceAccountToken should be set to false unless the pod specifically requires access to the Kubernetes API to operate."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Use Pod security policies to control the security-related attributes of pods, which includes container privilege levels."]}],
        )

    PodCheck(
        app,
        "REL-004-1",
        "No nodeSelector or nodeAffinity specified",
        descr="Pods with high risk workloads can be assigned to specific node to separate them from other workloads",
        scheduling=PodSchedulingConfig(node_selector=None, node_affinity=False),
        check_path=[".spec.nodeSelector", ".spec.affinity.nodeAffinity"],
        standards=[{"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A14"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["16.2.a"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Sensitive applications are running isolated on nodes or with specific sandboxed runtimes."]}],
    )
    PodCheck(
        app,
        "REL-004-2",
        "Only nodeAffinity is enough",
        descr="Pods with high risk workloads can be assigned to specific node to separate them from other workloads",
        expect=CheckStatus.Pass,
        scheduling=PodSchedulingConfig(node_selector=None),
        check_path=[".spec.nodeSelector", ".spec.affinity.nodeAffinity"],
        standards=[{"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A14"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["16.2.a"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Sensitive applications are running isolated on nodes or with specific sandboxed runtimes."]}],
    )
    PodCheck(
        app,
        "REL-004-3",
        "Only nodeSelector is enough",
        descr="Pods with high risk workloads can be assigned to specific node to separate them from other workloads",
        expect=CheckStatus.Pass,
        scheduling=PodSchedulingConfig(node_affinity=False),
        check_path=[".spec.nodeSelector", ".spec.affinity.nodeAffinity"],
        standards=[{"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A14"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["16.2.a"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Sensitive applications are running isolated on nodes or with specific sandboxed runtimes."]}],
    )

    PodCheck(
        app,
        "REL-003",
        "No PriorityClass",
        descr="Pods with high risk workloads can be assigned higher PriorityClasses to ensure reliability",
        scheduling=PodSchedulingConfig(priority_class=None),
        check_path=".spec.priorityClassName",
        standards=[],
    )

    PodCheck(
        app,
        "REL-001",
        "No ReadinessProbe defined",
        descr="Configuring a readinessProbe is recommended as it's intended to "
        "ensure that workload is ready to process network traffic",
        container=ContainerConfig(),  # Will use defaults, need to handle readiness_probe separately
        container_kwargs={"readiness_probe": None},
        check_path=".spec.containers[].readinessProbe",
        standards=[],
    )

    PodCheck(
        app,
        "REL-002",
        "No LivenessProbe defined",
        descr="Configuring a livenessProbe is recommended as it's intended to ensure that workload "
        "remains healthy during its entire execution lifecycle, or otherwise restart the container.",
        container=ContainerConfig(),  # Will use defaults, need to handle liveness_probe separately
        container_kwargs={"liveness_probe": None},
        check_path=".spec.containers[].livenessProbe",
        standards=[],
    )

    PodCheck(
        app,
        "POD-008-1",
        "hostPID flag not set",
        expect=CheckStatus.Pass,
        descr="The hostPID defaults to `false` and thus should be okay",
        security=PodSecurityConfig(host_pid=None),
        check_path=".spec.hostPID",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.3"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

    PodCheck(
        app,
        "POD-008-2",
        "hostPID flag set",
        descr="Containers should be isolated from the host machine as much as possible. `hostPID` pods may allow "
        "cross-container influence and may expose the host itself to potentially malicious or destructive actions",
        security=PodSecurityConfig(host_pid=True),
        check_path=".spec.hostPID",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.3"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

    PodCheck(
        app,
        "POD-009-1",
        "hostIPC flag not set",
        expect=CheckStatus.Pass,
        descr="The hostIPC defaults to `false` and thus should be okay",
        security=PodSecurityConfig(host_ipc=None),
        check_path=".spec.hostIPC",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.4"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

    PodCheck(
        app,
        "POD-009-2",
        "hostIPC flag set",
        descr="Containers should be isolated from the host machine as much as possible. `hostIPC` on pods may allow"
        " cross-container influence and may expose the host itself to potentially malicious or destructive actions",
        security=PodSecurityConfig(host_ipc=True),
        check_path=".spec.hostIPC",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.4"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

    PodCheck(
        app,
        "POD-010-1",
        "hostNetwork flag not set",
        expect=CheckStatus.Pass,
        descr="The hostNetwork defaults to `false` and thus should be okay",
        security=PodSecurityConfig(host_network=None),
        check_path=".spec.hostNetwork",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.5"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Use Pod security policies to control the security-related attributes of pods, which includes container privilege levels."]}],
    )
    PodCheck(
        app,
        "POD-010-2",
        "hostNetwork flag set",
        descr="Containers should be isolated from the host machine as much as possible.",
        security=PodSecurityConfig(host_network=True),
        check_path=".spec.hostNetwork",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.5"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Use Pod security policies to control the security-related attributes of pods, which includes container privilege levels."]}],
    )

    PodCheck(
        app,
        "POD-011",
        "Pod uses hostPort",
        descr="When you bind a Pod to a hostPort, it limits the number of places the  Pod can be scheduled, "
        "because each <hostIP, hostPort, protocol> combination must be unique.",
        container_kwargs={"ports": [k8s.ContainerPort(container_port=31337, host_port=31335)]},
        check_path=".spec.containers[].ports[].hostPort",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.12"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242414"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

#    PodCheck(
#        app,
#        "POD-012",
#        "Pod uses HostAliases to modify its /etc/hosts",
#        descr="Managing /etc/hosts aliases can prevent Docker from modifying the file after a pod's"
#        " containers have already been started",
#        host_aliases=[k8s.HostAlias(ip="127.0.0.1", hostnames=["foo.com"])],
#        check_path=".spec.hostAliases",
#        standards=[{"standard": "BSI", "controls": ["APP.4.4.A4[B]"]}],
#    )

#    PodCheck(
#        app,
#        "POD-013",
#        "deprecated serviceAccount field used",
#        descr="ServiceAccount field is deprecated, ServiceAccountName should be used instead",
#        security=PodSecurityConfig(service_account="deprecated-sa", service_account_name=None),
#        check_path=".spec.serviceAccount",
#    )

    PodCheck(
        app,
        "POD-014",
        "no AppArmor profile defined",
        descr="AppArmor can be configured for any application to reduce "
        "its potential attack surface and provide greater in-depth defense.",
        apparmor_profile=None,
        check_path=[
            ".metadata.annotations",
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io/nginx",
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io",
            ".metadata.annotations[container.apparmor.security.beta.kubernetes.io]",
        ],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Hardening container environments"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["9.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9011"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Restrict a Container's Access to Resources with AppArmor"]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Prevent containers from loading unwanted kernel modules."]}],
    )

    # TODO implement seccomp check
    PodCheck(
        app,
        "POD-015",
        "seccomp not enabled",
        descr="A seccomp profile can be used to restrict the syscalls that a container can make.",
        security=PodSecurityConfig(pod_security_context=k8s.PodSecurityContext(seccomp_profile=None)),
        container=ContainerConfig(security_context_kwargs={"seccomp_profile": None}),
        check_path=[
            ".spec.containers[].securityContext.seccompProfile",
            ".spec.containers[].securityContext.seccompProfile.type",
            ".metadata.annotations.container.seccomp.security.alpha.kubernetes.io/pod",
            ".metadata.annotations.container.seccomp.security.alpha.kubernetes.io",
            ".metadata.annotations[container.seccomp.security.alpha.kubernetes.io/pod]",
        ],
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.6.2"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Hardening container environments"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["9.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9011"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced.", "For nodes that support it, Seccomp is enabled with appropriate syscalls profile for programs.", "Set the Seccomp Profile for a Container."]}],
    )

    # =============================== PodSecurityContext ======================================

    PodCheck(
        app,
        "POD-016",
        "no PodSecurityContext defined",
        descr="not providing a podSecurityContext leads to the use of too permissive settings for the pod",
        security=PodSecurityConfig(pod_security_context=None),
        check_path=".spec.securityContext",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.6.3"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9017"]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Apply security context to your pods and containers."]}],
    )

    # the hardened version in this benchmark prioritizes the run_as_user field,
    # which is why for this test, runAsUser will be disabled (mostly) to test only the runAsNonRoot field
    non_root_user_configs = [
        # setting run_as_non_root for pod
        {
            "name": "use runAsNonRoot flag on Pod",
            "expect": CheckStatus.Pass,
            "descr": "Using runAsNonRoot is a viable alternative to `runAsUser>1000`",
            "pod": {"run_as_non_root": True, "run_as_user": None},
            "container": {"run_as_non_root": None, "run_as_user": None},
        },
        {
            "name": "no runAsNonRoot defaults to root user",
            "descr": "Having neither runAsNonRoot nor `runAsUser>1000` means a user has elevated privileges",
            "pod": {"run_as_non_root": None, "run_as_user": None},
            "container": {"run_as_non_root": None, "run_as_user": None},
        },
        {
            "name": "runAsNonRoot is optional",
            "expect": CheckStatus.Pass,
            "descr": "Using runAsNonRoot is a viable alternative to `runAsUser>1000`",
            "pod": {"run_as_non_root": None, "run_as_user": 10000},
            "container": {"run_as_non_root": None, "run_as_user": None},
        },
        {
            "name": "use root user in pod",
            "descr": "Having neither runAsNonRoot nor `runAsUser>1000` means a user has elevated privileges",
            "pod": {"run_as_non_root": False, "run_as_user": None},
            "container": {"run_as_non_root": None, "run_as_user": None},
        },
        # setting run_as_non_root for container
        {
            "name": "use runAsNonRoot flag on container",
            "expect": CheckStatus.Pass,
            "descr": "Using runAsNonRoot is a viable alternative to `runAsUser>1000`",
            "pod": {"run_as_non_root": None, "run_as_user": None},
            "container": {"run_as_non_root": True, "run_as_user": None},
        },
        {
            "name": "runAsNonRoot is optional on container",
            "expect": CheckStatus.Pass,
            "descr": "Using runAsNonRoot is a viable alternative to `runAsUser>1000`",
            "pod": {"run_as_non_root": None, "run_as_user": None},
            "container": {"run_as_non_root": None, "run_as_user": 10000},
        },
        {
            "name": "use root user on container",
            "descr": "Having neither runAsNonRoot nor `runAsUser>1000` means a user has elevated privileges",
            "pod": {"run_as_non_root": None, "run_as_user": None},
            "container": {"run_as_non_root": False, "run_as_user": None},
        },
        # in case of conflicting settings container takes precedence
        {
            "name": "set runAsNonRoot correctly on container",
            "expect": CheckStatus.Pass,
            "descr": "runAsNonRoot setting on container takes precedence",
            "pod": {"run_as_non_root": False, "run_as_user": None},
            "container": {"run_as_non_root": True, "run_as_user": None},
        },
        {
            "name": "set runAsNonRoot not correctly on container",
            "descr": "runAsNonRoot setting on container takes precedence",
            "pod": {"run_as_non_root": True, "run_as_user": None},
            "container": {"run_as_non_root": False, "run_as_user": None},
        },
    ]

    for i, cfg in enumerate(non_root_user_configs):
        PodCheck(
            app,
            f"POD-017-{i+1}",
            cfg["name"],
            expect=cfg.get("expect", CheckStatus.Alert),
            descr=cfg.get("descr", ""),
            security=PodSecurityConfig(pod_security_context_kwargs=cfg["pod"]),
            container=ContainerConfig(security_context_kwargs=cfg["container"]),
            check_path=[
                ".spec.securityContext.runAsNonRoot",
                ".spec.containers[].securityContext.runAsNonRoot",
            ],
            standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.7"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Non-root containers and rootless container engines"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["12.3.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced.", "Set runAsNonRoot: true", "Configure the container to execute as a less privileged user (for example, using runAsUser and runAsGroup), and configure appropriate permissions on files and directories inside the container image.", "Container images are configured to be run as unprivileged user.", "Build images to directly start with an unprivileged user.", "The Security Context allows a container image to be started with a specific user and group with runAsUser and runAsGroup, even if not specified in the image manifest."]}],
        )

    # the configurations assume, that the user on the hardened pod
    # is managed via runAsUser and the runAsNonRoot is not set
    run_as_user_configs = [
        {
            "name": "no runAsUser defaults to root user",
            "descr": "Having neither runAsNonRoot nor `runAsUser>1000` means a user has elevated privileges",
            "pod": {"run_as_user": None},
            "container": {"run_as_user": None},
        },
        {
            "name": "use UID between 1k-10k on pod",
            "expect": CheckStatus.Pass,
            "descr": "An UID above 1000 is enough to avoid running as a system user",
            "pod": {"run_as_user": 1337},
            "container": {"run_as_user": None},
        },
        {
            "name": "use UID between 1k-10k on container",
            "expect": CheckStatus.Pass,
            "descr": "An UID above 1000 is enough to avoid running as a system user",
            "pod": {"run_as_user": None},
            "container": {"run_as_user": 1337},
        },
        {
            "name": "use UID set in container takes precedence",
            "descr": "in case of conflicting settings, the value on the container takes precedence",
            "expect": CheckStatus.Pass,
            "pod": {"run_as_user": 0},  # explicitly set to root, but effectively dosen't matter
            "container": {"run_as_user": 10000},
        },
        {
            "name": "use UID set in container takes precedence",
            "descr": "in case of conflicting settings, the value on the container takes precedence",
            "pod": {"run_as_user": 10000},
            "container": {"run_as_user": 0},  # explicitly set to root
        },
    ]

    for i, cfg in enumerate(run_as_user_configs):
        PodCheck(
            app,
            f"POD-018-{i+1}",
            cfg["name"],
            expect=cfg.get("expect", CheckStatus.Alert),
            descr=cfg.get("descr", ""),
            security=PodSecurityConfig(pod_security_context_kwargs=cfg["pod"]),
            container=ContainerConfig(security_context_kwargs=cfg["container"]),
            check_path=[
                ".spec.securityContext.runAsUser",
                ".spec.containers[].securityContext.runAsUser",
            ],
            standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.7"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Non-root containers and rootless container engines"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["12.3.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced.", "Set runAsNonRoot: true", "Configure the container to execute as a less privileged user (for example, using runAsUser and runAsGroup), and configure appropriate permissions on files and directories inside the container image.", "Container images are configured to be run as unprivileged user.", "Build images to directly start with an unprivileged user.", "The Security Context allows a container image to be started with a specific user and group with runAsUser and runAsGroup, even if not specified in the image manifest."]}],
        )

    run_as_group_configs = [
        {
            "name": "no runAsGroup defaults to root group",
            "descr": "by default GID 0 is used, which has elevated privileges",
            "pod": {"run_as_group": None},
            "container": {"run_as_group": None},
        },
        {
            "name": "use GID between 1k-10k on pod",
            "expect": CheckStatus.Pass,
            "descr": "An GID above 1000 is enough to avoid running as a system user",
            "pod": {"run_as_group": 1337},
            "container": {"run_as_group": None},
        },
        {
            "name": "use GID between 1k-10k on container",
            "expect": CheckStatus.Pass,
            "descr": "An GID above 1000 is enough to avoid running as a system user",
            "pod": {"run_as_group": None},
            "container": {"run_as_group": 1337},
        },
        {
            "name": "use GID set in container takes precedence",
            "descr": "in case of conflicting settings, the value on the container takes precedence",
            "expect": CheckStatus.Pass,
            "pod": {"run_as_group": 0},  # explicitly set to root, but effectively doesn't matter
            "container": {"run_as_group": 10000},
        },
        {
            "name": "use GID set in container takes precedence",
            "descr": "in case of conflicting settings, the value on the container takes precedence",
            "pod": {"run_as_group": 10000},
            "container": {"run_as_group": 0},  # explicitly set to root
        },
    ]

    for i, cfg in enumerate(run_as_group_configs):
        PodCheck(
            app,
            f"POD-019-{i+1}",
            cfg["name"],
            expect=cfg.get("expect", CheckStatus.Alert),
            descr=cfg.get("descr", ""),
            security=PodSecurityConfig(pod_security_context_kwargs=cfg["pod"]),
            container=ContainerConfig(security_context_kwargs=cfg["container"]),
            check_path=[".spec.securityContext.runAsGroup", ".spec.containers[].securityContext.runAsGroup"],
            standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.7"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Non-root containers and rootless container engines"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["12.3.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced.", "Set runAsNonRoot: true", "Configure the container to execute as a less privileged user (for example, using runAsUser and runAsGroup), and configure appropriate permissions on files and directories inside the container image.", "Container images are configured to be run as unprivileged user.", "Build images to directly start with an unprivileged user.", "The Security Context allows a container image to be started with a specific user and group with runAsUser and runAsGroup, even if not specified in the image manifest."]}],
        )

    for i, (sysctl, value) in enumerate(
        [
            ("kernel.oops_limit", "10000"),
            ("kernel.pid_max", "4194304"),
            ("net.core.rmem_default", "212992"),
        ]
    ):
        PodCheck(
            app,
            f"POD-021-{i}",
            f"using sysctl {sysctl}",
            descr="Giving dangerous capabilities to a container increases the impact of a container compromise",
            security=PodSecurityConfig(pod_security_context_kwargs={"sysctls": [k8s.Sysctl(name=sysctl, value=value)]}),
            check_path=".spec.securityContext.sysctls[]",
            standards=[],
        )

    # ============================= harden linux =============================

    # TODO check against combos with pod<->container level
    PodCheck(
        app,
        "POD-022-1",
        "linux is not hardened",
        descr="Not hardening a linux system can increase the impact of a compromise",
        security=PodSecurityConfig(pod_security_context_kwargs={"seccomp_profile": None, "se_linux_level": None}),
        container=ContainerConfig(security_context_kwargs={"seccomp_profile": None, "se_linux_level": None}),
        apparmor_profile=None,
        check_path=[
            ".metadata.annotations",
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io/nginx",
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io",
            ".metadata.annotations[container.apparmor.security.beta.kubernetes.io]",
            ".spec.securityContext.seccompProfile",
            ".spec.securityContext.seLinuxOptions",
            ".spec.containers[].securityContext.seccompProfile",
            ".spec.containers[].securityContext.seccompProfile.type",
            ".spec.containers[].securityContext.seLinuxOptions",
        ],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Hardening container environments"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["9.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9011"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Restrict a Container's Access to Resources with AppArmor", "Assign SELinux Labels to a Container."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Use Pod security policies to control the security-related attributes of pods, which includes container privilege levels.", "Prevent containers from loading unwanted kernel modules."]}],
    )

    PodCheck(
        app,
        "POD-022-2",
        "one approach to hardening linux is enough",
        expect=CheckStatus.Pass,
        descr="Not hardening a linux system can increase the impact of a compromise",
        security=PodSecurityConfig(pod_security_context_kwargs={"seccomp_profile": None}),
        container=ContainerConfig(security_context_kwargs={"seccomp_profile": None}),
        apparmor_profile=[("container.apparmor.security.beta.kubernetes.io", AppArmorProfile.RuntimeDefault)],
        check_path=[
            ".metadata.annotations",
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io/nginx",
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io",
            ".metadata.annotations[container.apparmor.security.beta.kubernetes.io]",
            ".spec.securityContext.seccompProfile",
            ".spec.securityContext.seLinuxOptions",
            ".spec.containers[].securityContext.seccompProfile",
            ".spec.containers[].securityContext.seLinuxOptions",
        ],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Hardening container environments"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["9.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9011"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Restrict a Container's Access to Resources with AppArmor", "Assign SELinux Labels to a Container."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Use Pod security policies to control the security-related attributes of pods, which includes container privilege levels.", "Prevent containers from loading unwanted kernel modules."]}],
    )
    PodCheck(
        app,
        "POD-022-3",
        "one approach to hardening linux is enough",
        expect=CheckStatus.Pass,
        descr="Not hardening a linux system can increase the impact of a compromise",
        security=PodSecurityConfig(pod_security_context_kwargs={"se_linux_level": None}),
        container=ContainerConfig(security_context_kwargs={"se_linux_level": None}),
        apparmor_profile=None,
        check_path=[
            ".metadata.annotations",
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io/nginx",
            ".metadata.annotations.container.apparmor.security.beta.kubernetes.io",
            ".metadata.annotations[container.apparmor.security.beta.kubernetes.io]",
            ".spec.securityContext.seccompProfile",
            ".spec.securityContext.seLinuxOptions",
            ".spec.containers[].securityContext.seccompProfile",
            ".spec.containers[].securityContext.seLinuxOptions",
        ],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Hardening container environments"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["9.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9011"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Restrict a Container's Access to Resources with AppArmor", "Assign SELinux Labels to a Container."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Use Pod security policies to control the security-related attributes of pods, which includes container privilege levels.", "Prevent containers from loading unwanted kernel modules."]}],
    )

    PodCheck(
        app,
        "POD-023",
        "no seccomp profile defined",
        descr="not providing a seccomp profile allows a process more capabilities than necessary",
        security=PodSecurityConfig(pod_security_context_kwargs={"seccomp_profile": None}),
        container=ContainerConfig(security_context_kwargs={"seccomp_profile": None}),
        apparmor_profile=[("container.apparmor.security.beta.kubernetes.io", AppArmorProfile.RuntimeDefault)],
        check_path=[
            ".metadata.annotations",
            ".metadata.annotations.container.seccomp.security.alpha.kubernetes.io/pod",
            ".metadata.annotations.seccomp.security.alpha.kubernetes.io/pod",  # deprecated and removed in v1.25
            ".metadata.annotations[seccomp.security.alpha.kubernetes.io/pod]",  # deprecated and removed in v1.25
            ".spec.securityContext.seccompProfile",
            ".spec.containers[].securityContext.seccompProfile",
            ".spec.containers[].securityContext.seccompProfile.type",
        ],
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.6.2"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Hardening container environments"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["9.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9011"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced.", "For nodes that support it, Seccomp is enabled with appropriate syscalls profile for programs.", "Set the Seccomp Profile for a Container."]}],
    )

    # =================== Container checks ====================================
#    for i, cmd in enumerate(CMDS):
#        PodCheck(
#            app,
#            f"POD-024-{i}",
#            f"usage of {cmd} in container",
#            descr="Attackers who can run a cmd/bash script inside a container can use it to execute malicious code",
#            container=ContainerConfig(),
#            container_kwargs={"command": [cmd]},
#            check_path=[".spec.containers[].command"],
#            standards=[{"standard": "Kubernetes Security Checklist", "controls": ["Images"]}],
#        )

    EnvVarCheck(
        app,
        "POD-025",
        "sensitive key referenced in environment variable",
        descr="Attackers can retrieve and use sensitive information provided via environment variables",
        env_keys=SENSITIVE_KEYS,
        check_path=[".spec.containers[].env[].name"],
        standards=[{"standard": "CIS", "version": "1.11.1", "controls": ["5.4.1"]},
                   {"standard": "NSA-CISA", "controls": ["Secrets"]},
                   {"standard": "Kubernetes STIG", "controls": ["V-242415"]},
                   {"standard": "BSI", "controls": ["SYS.1.6.A8"]},
                   {"standard": "Kubernetes Security Checklist", "controls": ["Secrets"]},
                   {"standard": "PCI-DSS", "controls": ["6.1"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9026"]},
                   {"standard": "OWASP", "controls": ["Finding exposed secrets"]}],
    )

    PodCheck(
        app,
        "SC-001-1",
        "imagePullPolicy defaults to always",
        expect=CheckStatus.Pass,
        descr="Kubernetes may run older version of the container images without user knowing about this",
        container=ContainerConfig(image_pull_policy=None),
        check_path=[".spec.containers[].imagePullPolicy"],
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["1.2.11"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["AlwaysPullImages - Enforces the usage of the latest version of a tagged image and ensures that the deployer has permissions to use the image."]}],
    )
    for i, img_pull_policy in enumerate(["Never", "IfNotPresent"]):
        PodCheck(
            app,
            f"SC-001-{i + 2}",
            "No proper imagePullPolicy set",
            descr="Kubernetes may run older version of the container images without user knowing about this",
            container=ContainerConfig(image_pull_policy=img_pull_policy),
            check_path=[".spec.containers[].imagePullPolicy"],
            standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["1.2.11"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["AlwaysPullImages - Enforces the usage of the latest version of a tagged image and ensures that the deployer has permissions to use the image."]}],
        )

    PodCheck(
        app,
        "SC-002-1",
        "tag instead of digest is fine",
        expect=CheckStatus.Pass,
        descr="Specify an explicit tag or digest to have full control over the running container image",
        container=ContainerConfig(image_tag=":1.12.6"),
        check_path=[".spec.containers[].image"],
        standards=[{"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.2.a"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["References to container images are made by sha256 digests (rather than tags) or the provenance of the image is validated by verifying the image's digital signature at deployment via admission control."]}],
    )

    PodCheck(
        app,
        "SC-002-2",
        "using latest image tag",
        descr="When using latest image tag the used image can change without the user knowing about this",
        container=ContainerConfig(image_tag=":latest"),
        check_path=[".spec.containers[].image"],
        standards=[{"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.2.a"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["References to container images are made by sha256 digests (rather than tags) or the provenance of the image is validated by verifying the image's digital signature at deployment via admission control."]}],
    )

    PodCheck(
        app,
        "SC-002-3",
        "no explicit tag",
        descr="Kubernetes may run older version of the container images without user knowing about this",
        container=ContainerConfig(image_tag=None),
        check_path=[".spec.containers[].image"],
        standards=[{"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.2.a"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["References to container images are made by sha256 digests (rather than tags) or the provenance of the image is validated by verifying the image's digital signature at deployment via admission control."]}],
    )

    # POD-029
    # manifest for kubernetes dashboard can be found here:
    # https://raw.githubusercontent.com/kubernetes/dashboard/v2.4.0/aio/deploy/recommended.yaml

    # ================= Container Security Context ==========================

    PodCheck(
        app,
        "POD-030",
        "no SecurityContext defined",
        descr="Not providing a securityContext leads to the use of too permissive settings for the containers",
        container=ContainerConfig(security_context=None),
        check_path=[".spec.containers[].securityContext"],
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.6.3"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9017"]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Apply security context to your pods and containers."]}],
    )

    PodCheck(
        app,
        "POD-031-1",
        "allowed privilege escalation by default",
        descr="Avoid using the privileged flag, and if your container does need additional capabilities, "
        "add only the ones you need through the capabilities settings. ",
        container=ContainerConfig(security_context_kwargs={"allow_privilege_escalation": None}),
        check_path=".spec.containers[].securityContext.allowPrivilegeEscalation",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.6"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced.", "Disable privilege escalations using allowPrivilegeEscalation: false."]}],
    )

    PodCheck(
        app,
        "POD-031-2",
        "allowed privilege escalation explicitly",
        descr="Avoid using the privileged flag, and if your container does need additional capabilities, "
        "add only the ones you need through the capabilities settings. ",
        container=ContainerConfig(security_context_kwargs={"allow_privilege_escalation": True}),
        check_path=".spec.containers[].securityContext.allowPrivilegeEscalation",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.6"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced.", "Disable privilege escalations using allowPrivilegeEscalation: false."]}],
    )

    PodCheck(
        app,
        "POD-032-1",
        "non privileged container by default",
        expect=CheckStatus.Pass,
        descr="Changing the privileged flag is optional as it defaults to False",
        container=ContainerConfig(security_context_kwargs={"privileged": None}),
        check_path=".spec.containers[].securityContext.privileged",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.2"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Avoid running privileged containers (set privileged: false)."]}],
    )

    PodCheck(
        app,
        "POD-032-2",
        "privileged container",
        descr="Privileged containers can do almost every action that can be performed directly on the host.",
        # privilege can't be set to True with when allowPrivilegeEscalation is explicitly disabled
        container=ContainerConfig(security_context_kwargs={"privileged": True}),
        check_path=[
            ".spec.containers[].securityContext.privileged",
        ],
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.2"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Avoid running privileged containers (set privileged: false)."]}],
    )

    PodCheck(
        app,
        "POD-033-1",
        "root FS is writeable by default",
        descr="Using an immutable root filesystem prevents against attackers from compromising the machine through "
        "permanent local changes.",
        container=ContainerConfig(security_context_kwargs={"read_only_root_filesystem": None}),
        check_path=".spec.containers[].securityContext.readOnlyRootFilesystem",
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Immutable container file systems"]},
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["8.2.a"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Configure the root filesystem to be read-only with readOnlyRootFilesystem: true."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Apply security context to your pods and containers."]}],
    )

    PodCheck(
        app,
        "POD-033-2",
        "root FS is explicitly writeable",
        descr="Using an immutable root filesystem prevents against attackers from compromising the machine through "
        "permanent local changes.",
        container=ContainerConfig(security_context_kwargs={"read_only_root_filesystem": False}),
        check_path=".spec.containers[].securityContext.readOnlyRootFilesystem",
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Immutable container file systems"]},
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["8.2.a"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Configure the root filesystem to be read-only with readOnlyRootFilesystem: true."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Apply security context to your pods and containers."]}],
    )

    # taken from:
    # - Polaris: https://github.com/FairwindsOps/polaris/blob/master/checks/dangerousCapabilities.yaml
    for (
        i,
        cap,
    ) in enumerate(DANGEROUS_CAPABILITIES):
        PodCheck(
            app,
            f"POD-034-{i+1}",
            f"using dangerous capability {cap}",
            descr="Dangerous capabilities can increase the impact of a container compromise",
            container=ContainerConfig(security_context_kwargs={"add_capabilities": [cap]}),
            check_path=[".spec.containers[].securityContext.capabilities", ".spec.containers[].securityContext.capabilities.add", ".spec.containers[].securityContext.capabilities.add[]", "spec.containers[app].securityContext.capabilities.add.SYS_ADMIN"],
            standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.9"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9011"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced.", "Drop all capabilities from the containers and add back only specific ones that are needed for operation of the container."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Apply security context to your pods and containers."]}],
        )

    # taken from:
    # - Kubernetes Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
    # - KubeScape: https://hub.armo.cloud/docs/configuration_parameter_insecurecapabilities
    # - Polaris: https://github.com/FairwindsOps/polaris/blob/master/checks/insecureCapabilities.yaml

    for (
        i,
        cap,
    ) in enumerate(INSECURE_CAPABILITIES):
        PodCheck(
            app,
            f"POD-035-{i+1}",
            f"using insecure capability {cap}",
            descr="Insecure capabilities can increase the impact of a container compromise",
            container=ContainerConfig(security_context_kwargs={"add_capabilities": [cap]}),
            check_path=[".spec.containers[].securityContext.capabilities", ".spec.containers[].securityContext.capabilities.add", ".spec.containers[].securityContext.capabilities.add[]"],
            standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.9"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9011"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced.", "Drop all capabilities from the containers and add back only specific ones that are needed for operation of the container."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Apply security context to your pods and containers."]}],
        )

    PodCheck(
        app,
        "POD-036",
        "keep default capabilities",
        # description source from https://snyk.io/blog/kubernetes-securitycontext-linux-capabilities/
        descr="When not dropping all capabilities the container gets the capabilities "
        "defined by the container runtime, which is often fairly generous and "
        "does not adhere to principle of least privilege",
        container=ContainerConfig(security_context_kwargs={"drop_capabilities": None}),  # remove  drop: "ALL"
        check_path=[".spec.containers[].securityContext.capabilities.drop", ".spec.containers[].securityContext.capabilities"],
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.9"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242437"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9011"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced.", "Drop all capabilities from the containers and add back only specific ones that are needed for operation of the container."]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Apply security context to your pods and containers."]}],

    )

    
    PodCheck(
        app,
        "POD-046",
        "Minimize the admission of Windows HostProcess Containers",
        descr="A Windows container making use of the hostProcess flag can interact with the "
              "underlying Windows cluster node. As per the Kubernetes documentation, this provides "
              "\"privileged access\" to the Windows node.",
        container=ContainerConfig(security_context_kwargs={"windows_options": {"host_process": True}}),
        check_path=".spec.containers[].securityContext.windowsOptions.hostProcess",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.10"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],

    )

    # ==================== pod resource requests/limits ===================
    resource_checks(app, main_ns, unrestricted_ns)

    # ===================== pod.volumes =========================

    VolumeMountCheck(
        app,
        "POD-042-1",
        "volume with read-only hostpath",
        expect=CheckStatus.Pass,
        descr="using hostPath is not ideal but can be tolerated when it's read-only",
        volume_type="hostpath",
        read_only=True,
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.11"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013", "MS-M9016"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

    VolumeMountCheck(
        app,
        "POD-042-2",
        "volume with writeable hostpath",
        descr="Attackers can use a writable hostpath to gain persistence on underlying host system",
        volume_type="hostpath",
        read_only=False,
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.11"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013", "MS-M9016"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

    VolumeMountCheck(
        app,
        "POD-042-3",
        "volume with writeable hostpath by default",
        descr="Attackers can use a writable hostpath to gain persistence on underlying host system",
        volume_type="hostpath",
        read_only=None,
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.11"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013", "MS-M9016"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

    files = [("azure", "/etc/kubernetes/azure.json")]
    for i, (name, path) in enumerate(files):
        VolumeMountCheck(
            app,
            f"POD-043-{i+1}",
            f"Mount {name} cloud credentials",
            descr="Mounting Docker socket (Unix socket) enables container to access Docker internals, "
            "retrieve sensitive information and execute Docker commands.",
            volume_name=f"mnt-{name}",
            volume_type="hostpath",
            mount_path=path,
            mount_type="File",
            read_only=True,
            standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.11"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013", "MS-M9016"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
        )

    VolumeMountCheck(
        app,
        "POD-044-1",
        "Mounting Docker socket",
        descr="Mounting Docker socket (Unix socket) enables container to access Docker internals, "
        "retrieve sensitive information and execute Docker commands.",
        volume_name="docker-mount",
        volume_type="hostpath",
        mount_path="/var/run/docker.sock",
        read_only=True,
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.11"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013", "MS-M9016"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

    VolumeMountCheck(
        app,
        "POD-044-2",
        "Mounting Docker directory",
        descr="mounting Docker socket (Unix socket) enables container to access Docker internals, "
        "retrieve sensitive information and execute Docker commands.",
        volume_name="docker-mount",
        volume_type="hostpath",
        mount_path="/var/lib/docker",
        read_only=True,
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.11"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013", "MS-M9016"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

    # this check requires special kubernetes version
    VolumeMountCheck(
        app,
        "POD-045",
        "Pod contains CVE-2021-25741",
        descr="A user may be able to create a container with subPath or subPathExpr volume mounts to access files &"
        " directories anywhere on the host filesystem. "
        "Following Kubernetes versions are affected: v1.22.0-v1.22.1, v1.21.0-v1.21.4, v1.20.0-v1.20.10, <v1.19.14",
        volume_name="vulnerable-mount",
        mount_path="/mnt/data",
        sub_path="symlink",
        volume_type="empty",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.2.11"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Pod security enforcement"]},
                    {"standard": "BSI APP.4.4 Kubernetes", "controls": ["APP.4.4.A4"]}, 
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["3.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9013", "MS-M9016"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["Appropriate Pod Security Standards policy is applied for all namespaces and enforced."]}],
    )

    ConfigMapCheck(
        app,
        "CM-001",
        "sensitive key referenced in configmap",
        descr="Attackers can retrieve and use sensitive information provided via config maps",
        data={sk: SENSITIVE_VALUES for sk in SENSITIVE_KEYS},
        check_path=[f".data.{key}" for key in SENSITIVE_KEYS] + ["ConfigMap.data"],
        standards=[{"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["6.1.a"]},
                    {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9026"]},
                    {"standard": "Kubernetes Security Checklist", "controls": ["ConfigMaps are not used to hold confidential data."]}],
    )

    # ================= Namespace checks ====================
    PodCheck(
        app,
        "NS-001",
        "use default namespace",
        descr="The default namespace should not be used for custom workloads",
        namespace="default",
        check_path=".metadata.namespace",
        standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.6.4"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Namespaces"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242383"]},
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["16.1.a"]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Code that uses namespaces to isolate Kubernetes resources."]}],
    )

    for i, ns in enumerate(["kube-system", "kube-public"]):
        PodCheck(
            app,
            f"NS-002-{i+1}",
            f"place pod in {ns}",
            descr=f"{ns} should not be used for custom workloads",
            namespace=ns,
            check_path=".metadata.namespace",
            standards=[{"standard": "CIS Kubernetes Benchmark", "version": "1.12", "controls": ["5.6.1"]}, 
                    {"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Namespaces"]},
                    {"standard": "CIS Kubernetes STIG", "controls": ["V-242417"]},
                    {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["16.1.a"]},
                    {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Code that uses namespaces to isolate Kubernetes resources."]}],
        )


def resource_checks(app, main_ns: str, unrestricted_ns: str):
    """
    Create configurations where for both limits and requests either CPU or memory is missing.
    This is done for 2 different namespaces. The main namespace has default values defined, which serve as fallback.
    The unrestricted namespace has no defaults defined, which would load to unrestricted pods.
    :param app: the context for the generation of the configs
    :param main_ns: the safe namespace with configured defaults
    :param unrestricted_ns: the unsafe namespace without any defaults
    """
    PodCheck(
        app,
        "RES-001-1",
        "default memory requests from namespace",
        expect=CheckStatus.Pass,
        descr="not setting default memory requests can lead to problems upon admission",
        container=ContainerConfig(resources=ContainerResourceConfig(request_memory=None)),
        namespace=main_ns,
        check_path=[".spec.containers[].resources.requests.memory", ".spec.containers[].resources.requests"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "Kubernetes Security Checklist", "controls": ["Memory limit is set for the workloads with a limit equal or inferior to the request."]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )
    PodCheck(
        app,
        "RES-001-2",
        "no memory requests",
        descr="not setting memory requests can lead to problems upon admission",
        container=ContainerConfig(resources=ContainerResourceConfig(request_memory=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.requests.memory", ".spec.containers[].resources.requests"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "Kubernetes Security Checklist", "controls": ["Memory limit is set for the workloads with a limit equal or inferior to the request."]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )

    PodCheck(
        app,
        "RES-002-1",
        "default memory limits from namespace",
        expect=CheckStatus.Pass,
        descr="not setting memory limit can lead to the pod suffocating the node by using all available memory",
        container=ContainerConfig(resources=ContainerResourceConfig(limits_memory=None)),
        namespace=main_ns,
        check_path=[".spec.containers[].resources.limits.memory", ".spec.containers[].resources.limits"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "Kubernetes Security Checklist", "controls": ["Memory limit is set for the workloads with a limit equal or inferior to the request."]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )
    PodCheck(
        app,
        "RES-002-2",
        "no memory limits",
        descr="not setting memory limit can lead to the pod suffocating the node by using all available memory",
        container=ContainerConfig(resources=ContainerResourceConfig(limits_memory=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.limits.memory", ".spec.containers[].resources.limits"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "Kubernetes Security Checklist", "controls": ["Memory limit is set for the workloads with a limit equal or inferior to the request."]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )

    PodCheck(
        app,
        "RES-003-1",
        "default CPU requests from namespace",
        expect=CheckStatus.Pass,
        descr="not setting default CPU requests can lead to problems upon admission",
        container=ContainerConfig(resources=ContainerResourceConfig(request_cpu=None)),
        namespace=main_ns,
        check_path=[".spec.containers[].resources.requests.cpu", ".spec.containers[].resources.requests"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "Kubernetes Security Checklist", "controls": ["CPU limit might be set on sensitive workloads."]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )
    PodCheck(
        app,
        "RES-003-2",
        "no CPU requests",
        descr="not setting CPU requests can lead to problems upon admission",
        container=ContainerConfig(resources=ContainerResourceConfig(request_cpu=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.requests.cpu", ".spec.containers[].resources.requests"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "Kubernetes Security Checklist", "controls": ["CPU limit might be set on sensitive workloads."]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )

    PodCheck(
        app,
        "RES-004-1",
        "default CPU limits from namespace",
        expect=CheckStatus.Pass,
        descr="not setting CPU limit can lead to the pod suffocating the node by using all available CPU",
        container=ContainerConfig(resources=ContainerResourceConfig(limits_cpu=None)),
        namespace=main_ns,
        check_path=[".spec.containers[].resources.limits.cpu", ".spec.containers[].resources.limits"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "Kubernetes Security Checklist", "controls": ["CPU limit might be set on sensitive workloads."]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )
    PodCheck(
        app,
        "RES-004-2",
        "no CPU limits",
        descr="not setting CPU limit can lead to the pod suffocating the node by using all available CPU",
        container=ContainerConfig(resources=ContainerResourceConfig(limits_cpu=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.limits.cpu", ".spec.containers[].resources.limits"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "Kubernetes Security Checklist", "controls": ["CPU limit might be set on sensitive workloads."]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )

    PodCheck(
        app,
        "RES-005-1",
        "default ephemeral storage requests from namespace",
        expect=CheckStatus.Pass,
        descr="not setting ephemeral storarge limit can suffocate the node by using all available storage",
        container=ContainerConfig(resources=ContainerResourceConfig(request_ephemeral_storage=None)),
        namespace=main_ns,
        check_path=[".spec.containers[].resources.requests.ephemeral-storage", ".spec.containers[].resources.requests"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )
    PodCheck(
        app,
        "RES-005-2",
        "no ephemeral storage requests",
        descr="not setting ephemeral storage limit can suffocate the node by using all available CPU",
        container=ContainerConfig(resources=ContainerResourceConfig(request_ephemeral_storage=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.requests.ephemeral-storage", ".spec.containers[].resources.requests"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )

    PodCheck(
        app,
        "RES-006-1",
        "default ephemeral storage limits from namespace",
        expect=CheckStatus.Pass,
        descr="not setting ephemeral storarge limit can suffocate the node by using all available storage",
        container=ContainerConfig(resources=ContainerResourceConfig(limits_ephemeral_storage=None)),
        namespace=main_ns,
        check_path=[".spec.containers[].resources.limits.ephemeral-storage", ".spec.containers[].resources.limits"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )
    PodCheck(
        app,
        "RES-006-2",
        "no ephemeral storage limits",
        descr="not setting ephemeral storage limit can suffocate the node by using all available CPU",
        container=ContainerConfig(resources=ContainerResourceConfig(limits_ephemeral_storage=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.limits.ephemeral-storage", ".spec.containers[].resources.limits"],
        standards=[{"standard": "NSA-CISA Kubernetes Hardening Guide", "controls": ["Resource policies"]},
                   {"standard": "PCI Guidance for Containers and Container Orchestration Tools", "controls": ["11.1.a"]},
                   {"standard": "Microsoft Threat Matrix for Kubernetes", "controls": ["MS-M9029"]},
                   {"standard": "OWASP Kubernetes Security Cheat Sheet", "controls": ["Limiting resource usage on a cluster."]}],
    )
