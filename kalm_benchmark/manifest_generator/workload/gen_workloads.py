from constructs import Construct

from ..cdk8s_imports import k8s
from ..check import Check
from ..constants import (
    DANGEROUS_CAPABILITIES,
    INSECURE_CAPABILITIES,
    MAIN_NS,
    SENSITIVE_KEYS,
    SENSITIVE_VALUES,
    AppArmorProfile,
    BsiK8sControls,
    CheckStatus,
    CisBenchmarkControls,
    CisBenchmarkVersions,
    ContainerConfig,
    ContainerResourceConfig,
    K8sChecklistControls,
    K8sStigControls,
    NsaCisaControls,
    MsThreatMatrixControls,
    OwaspControls,
    PciGuidanceControls,
    PodSchedulingConfig,
    PodSecurityConfig,
    StandardsAndGuidelines,
    StandardsFields,
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
        standards=[{
                        StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, 
                        StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, 
                        StandardsFields.controls.value: [CisBenchmarkControls.cis_5_1_5.value]
                    }, 
                    {
                        StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, 
                        StandardsFields.controls.value: [NsaCisaControls.service_account_tokens.value]
                    },
                    {
                        StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, 
                        StandardsFields.controls.value: [BsiK8sControls.app_4_4_a9.value]
                    }, 
                    {
                        StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, 
                        StandardsFields.controls.value: [PciGuidanceControls.pci_1_2_a.value]
                    },
                    {
                        StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, 
                        StandardsFields.controls.value: [K8sChecklistControls.sc_se_service_account_tokens.value, K8sChecklistControls.asc_sa_service_account.value]
                    },
                    {
                        StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, 
                        StandardsFields.controls.value: [OwaspControls.s4_pod_security_policies.value]
                    }],
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
        standards=[{
                        StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, 
                        StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, 
                        StandardsFields.controls.value: [CisBenchmarkControls.cis_5_1_5.value]
                    }, 
                    {
                        StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, 
                        StandardsFields.controls.value: [NsaCisaControls.service_account_tokens.value]
                    },
                    {
                        StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, 
                        StandardsFields.controls.value: [BsiK8sControls.app_4_4_a9.value]
                    }, 
                    {
                        StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, 
                        StandardsFields.controls.value: [PciGuidanceControls.pci_1_2_a.value]
                    },
                    {
                        StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, 
                        StandardsFields.controls.value: [K8sChecklistControls.sc_se_service_account_tokens.value, K8sChecklistControls.asc_sa_service_account.value]
                    },
                    {
                        StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, 
                        StandardsFields.controls.value: [OwaspControls.s4_pod_security_policies.value]
                    }],
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
            standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_1_6.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.service_account_tokens.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a9.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_1_5_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9025.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_se_service_account_tokens.value, K8sChecklistControls.asc_sa_service_account_token.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_pod_security_policies.value]}],
        )

    PodCheck(
        app,
        "REL-004-1",
        "No nodeSelector or nodeAffinity specified",
        descr="Pods with high risk workloads can be assigned to specific node to separate them from other workloads",
        scheduling=PodSchedulingConfig(node_selector=None, node_affinity=False),
        check_path=[".spec.nodeSelector", ".spec.affinity.nodeAffinity"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a14.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_16_2_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_pp_isolated.value]}],
    )
    PodCheck(
        app,
        "REL-004-2",
        "Only nodeAffinity is enough",
        descr="Pods with high risk workloads can be assigned to specific node to separate them from other workloads",
        expect=CheckStatus.Pass,
        scheduling=PodSchedulingConfig(node_selector=None),
        check_path=[".spec.nodeSelector", ".spec.affinity.nodeAffinity"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a14.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_16_2_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_pp_isolated.value]}],
    )
    PodCheck(
        app,
        "REL-004-3",
        "Only nodeSelector is enough",
        descr="Pods with high risk workloads can be assigned to specific node to separate them from other workloads",
        expect=CheckStatus.Pass,
        scheduling=PodSchedulingConfig(node_affinity=False),
        check_path=[".spec.nodeSelector", ".spec.affinity.nodeAffinity"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a14.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_16_2_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_pp_isolated.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_3.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
    )

    PodCheck(
        app,
        "POD-008-2",
        "hostPID flag set",
        descr="Containers should be isolated from the host machine as much as possible. `hostPID` pods may allow "
        "cross-container influence and may expose the host itself to potentially malicious or destructive actions",
        security=PodSecurityConfig(host_pid=True),
        check_path=".spec.hostPID",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_3.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
    )

    PodCheck(
        app,
        "POD-009-1",
        "hostIPC flag not set",
        expect=CheckStatus.Pass,
        descr="The hostIPC defaults to `false` and thus should be okay",
        security=PodSecurityConfig(host_ipc=None),
        check_path=".spec.hostIPC",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
    )

    PodCheck(
        app,
        "POD-009-2",
        "hostIPC flag set",
        descr="Containers should be isolated from the host machine as much as possible. `hostIPC` on pods may allow"
        " cross-container influence and may expose the host itself to potentially malicious or destructive actions",
        security=PodSecurityConfig(host_ipc=True),
        check_path=".spec.hostIPC",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
    )

    PodCheck(
        app,
        "POD-010-1",
        "hostNetwork flag not set",
        expect=CheckStatus.Pass,
        descr="The hostNetwork defaults to `false` and thus should be okay",
        security=PodSecurityConfig(host_network=None),
        check_path=".spec.hostNetwork",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_5.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_pod_security_policies.value]}],
    )
    PodCheck(
        app,
        "POD-010-2",
        "hostNetwork flag set",
        descr="Containers should be isolated from the host machine as much as possible.",
        security=PodSecurityConfig(host_network=True),
        check_path=".spec.hostNetwork",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_5.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_pod_security_policies.value]}],
    )

    PodCheck(
        app,
        "POD-011",
        "Pod uses hostPort",
        descr="When you bind a Pod to a hostPort, it limits the number of places the  Pod can be scheduled, "
        "because each <hostIP, hostPort, protocol> combination must be unique.",
        container_kwargs={"ports": [k8s.ContainerPort(container_port=31337, host_port=31335)]},
        check_path=".spec.containers[].ports[].hostPort",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_12.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242414.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
    )

#    PodCheck(
#        app,
#        "POD-012",
#        "Pod uses HostAliases to modify its /etc/hosts",
#        descr="Managing /etc/hosts aliases can prevent Docker from modifying the file after a pod's"
#        " containers have already been started",
#        host_aliases=[k8s.HostAlias(ip="127.0.0.1", hostnames=["foo.com"])],
#        check_path=".spec.hostAliases",
#        standards=[{StandardsFields.standard.value: "BSI", StandardsFields.controls.value: ["APP.4.4.A4[B]"]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.hardening_container.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_9_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9011.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_lcs_apparmor.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s5_unwanted_kernel_modules.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_6_2.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.hardening_container.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_9_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9011.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value, K8sChecklistControls.sc_ps_seccomp.value, K8sChecklistControls.asc_lcs_seccomp.value]}],
    )

    # =============================== PodSecurityContext ======================================

    PodCheck(
        app,
        "POD-016",
        "no PodSecurityContext defined",
        descr="not providing a podSecurityContext leads to the use of too permissive settings for the pod",
        security=PodSecurityConfig(pod_security_context=None),
        check_path=".spec.securityContext",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_6_3.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9017.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_security_context.value]}],
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
            standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_7.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.non_root_containers.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_12_3_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value, K8sChecklistControls.asc_pl_run_as_non_root.value, K8sChecklistControls.asc_pl_less_privileged.value, K8sChecklistControls.sc_im_unprivileged_user.value, K8sChecklistControls.sc_im_start_unprivileged.value, K8sChecklistControls.sc_im_security_context.value]}],
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
            standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_7.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.non_root_containers.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_12_3_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value, K8sChecklistControls.asc_pl_run_as_non_root.value, K8sChecklistControls.asc_pl_less_privileged.value, K8sChecklistControls.sc_im_unprivileged_user.value, K8sChecklistControls.sc_im_start_unprivileged.value, K8sChecklistControls.sc_im_security_context.value]}],
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
            standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_7.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.non_root_containers.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_12_3_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value, K8sChecklistControls.asc_pl_run_as_non_root.value, K8sChecklistControls.asc_pl_less_privileged.value, K8sChecklistControls.sc_im_unprivileged_user.value, K8sChecklistControls.sc_im_start_unprivileged.value, K8sChecklistControls.sc_im_security_context.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.hardening_container.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_9_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9011.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_lcs_apparmor.value, K8sChecklistControls.asc_lcs_selinux.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_pod_security_policies.value, OwaspControls.s5_unwanted_kernel_modules.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.hardening_container.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_9_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9011.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_lcs_apparmor.value, K8sChecklistControls.asc_lcs_selinux.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_pod_security_policies.value, OwaspControls.s5_unwanted_kernel_modules.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.hardening_container.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_9_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9011.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_lcs_apparmor.value, K8sChecklistControls.asc_lcs_selinux.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_pod_security_policies.value, OwaspControls.s5_unwanted_kernel_modules.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_6_2.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.hardening_container.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_9_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9011.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value, K8sChecklistControls.sc_ps_seccomp.value, K8sChecklistControls.asc_lcs_seccomp.value]}],
    )

    # =================== Container checks ====================================
    #for i, cmd in enumerate(CMDS):
    #    PodCheck(
    #        app,
    #        f"POD-024-{i}",
    #        f"usage of {cmd} in container",
    #        descr="Attackers who can run a cmd/bash script inside a container can use it to execute malicious code",
    #        container=ContainerConfig(),
    #        container_kwargs={"command": [cmd]},
    #        check_path=[".spec.containers[].command"],
    #        standards=[{StandardsFields.standard.value: "Kubernetes Security Checklist", StandardsFields.controls.value: ["Images"]}],
    #    )

    EnvVarCheck(
        app,
        "POD-025",
        "sensitive key referenced in environment variable",
        descr="Attackers can retrieve and use sensitive information provided via environment variables",
        env_keys=SENSITIVE_KEYS,
        check_path=[".spec.containers[].env[].name"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_4_1.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.secrets.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242415.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_se_mounted_volumes.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_6_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9026.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_finding_secrets.value]}],
    )

    PodCheck(
        app,
        "SC-001-1",
        "imagePullPolicy defaults to always",
        expect=CheckStatus.Pass,
        descr="Kubernetes may run older version of the container images without user knowing about this",
        container=ContainerConfig(image_pull_policy=None),
        check_path=[".spec.containers[].imagePullPolicy"],
            standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_1_2_11.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ac_always_pull_images.value]}],
    )
    for i, img_pull_policy in enumerate(["Never", "IfNotPresent"]):
        PodCheck(
            app,
            f"SC-001-{i + 2}",
            "No proper imagePullPolicy set",
            descr="Kubernetes may run older version of the container images without user knowing about this",
            container=ContainerConfig(image_pull_policy=img_pull_policy),
            check_path=[".spec.containers[].imagePullPolicy"],
            standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_1_2_11.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ac_always_pull_images.value]}],
        )

    PodCheck(
        app,
        "SC-002-1",
        "tag instead of digest is fine",
        expect=CheckStatus.Pass,
        descr="Specify an explicit tag or digest to have full control over the running container image",
        container=ContainerConfig(image_tag=":1.12.6"),
        check_path=[".spec.containers[].image"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_2_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_im_sha256_digest.value]}],
    )

    PodCheck(
        app,
        "SC-002-2",
        "using latest image tag",
        descr="When using latest image tag the used image can change without the user knowing about this",
        container=ContainerConfig(image_tag=":latest"),
        check_path=[".spec.containers[].image"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_2_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_im_sha256_digest.value]}],
    )

    PodCheck(
        app,
        "SC-002-3",
        "no explicit tag",
        descr="Kubernetes may run older version of the container images without user knowing about this",
        container=ContainerConfig(image_tag=None),
        check_path=[".spec.containers[].image"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_2_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_im_sha256_digest.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_6_3.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9017.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_security_context.value]}],
    )

    PodCheck(
        app,
        "POD-031-1",
        "allowed privilege escalation by default",
        descr="Avoid using the privileged flag, and if your container does need additional capabilities, "
        "add only the ones you need through the capabilities settings. ",
        container=ContainerConfig(security_context_kwargs={"allow_privilege_escalation": None}),
        check_path=".spec.containers[].securityContext.allowPrivilegeEscalation",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_6.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value, K8sChecklistControls.asc_cl_allow_privilege_escalation.value]}],
    )

    PodCheck(
        app,
        "POD-031-2",
        "allowed privilege escalation explicitly",
        descr="Avoid using the privileged flag, and if your container does need additional capabilities, "
        "add only the ones you need through the capabilities settings. ",
        container=ContainerConfig(security_context_kwargs={"allow_privilege_escalation": True}),
        check_path=".spec.containers[].securityContext.allowPrivilegeEscalation",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_6.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value, K8sChecklistControls.asc_cl_allow_privilege_escalation.value]}],
    )

    PodCheck(
        app,
        "POD-032-1",
        "non privileged container by default",
        expect=CheckStatus.Pass,
        descr="Changing the privileged flag is optional as it defaults to False",
        container=ContainerConfig(security_context_kwargs={"privileged": None}),
        check_path=".spec.containers[].securityContext.privileged",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_2.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_cl_privileged_false.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_2.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_cl_privileged_false.value]}],
    )

    PodCheck(
        app,
        "POD-033-1",
        "root FS is writeable by default",
        descr="Using an immutable root filesystem prevents against attackers from compromising the machine through "
        "permanent local changes.",
        container=ContainerConfig(security_context_kwargs={"read_only_root_filesystem": None}),
        check_path=".spec.containers[].securityContext.readOnlyRootFilesystem",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.immutable_filesystem.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_8_2_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_cl_read_only_root_filesystem.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_security_context.value]}],
    )

    PodCheck(
        app,
        "POD-033-2",
        "root FS is explicitly writeable",
        descr="Using an immutable root filesystem prevents against attackers from compromising the machine through "
        "permanent local changes.",
        container=ContainerConfig(security_context_kwargs={"read_only_root_filesystem": False}),
        check_path=".spec.containers[].securityContext.readOnlyRootFilesystem",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.immutable_filesystem.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_8_2_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_cl_read_only_root_filesystem.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_security_context.value]}],
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
            standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_9.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9011.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value, K8sChecklistControls.asc_cl_drop_capabilities.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_security_context.value]}],
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
            standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_9.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9011.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value, K8sChecklistControls.asc_cl_drop_capabilities.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_security_context.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_9.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242437.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9011.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value, K8sChecklistControls.asc_cl_drop_capabilities.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_security_context.value]}],

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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_10.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}]
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_11.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value, MsThreatMatrixControls.ms_m9016.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
    )

    VolumeMountCheck(
        app,
        "POD-042-2",
        "volume with writeable hostpath",
        descr="Attackers can use a writable hostpath to gain persistence on underlying host system",
        volume_type="hostpath",
        read_only=False,
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_11.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value, MsThreatMatrixControls.ms_m9016.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
    )

    VolumeMountCheck(
        app,
        "POD-042-3",
        "volume with writeable hostpath by default",
        descr="Attackers can use a writable hostpath to gain persistence on underlying host system",
        volume_type="hostpath",
        read_only=None,
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_11.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value, MsThreatMatrixControls.ms_m9016.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
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
            standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_11.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value, MsThreatMatrixControls.ms_m9016.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_11.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value, MsThreatMatrixControls.ms_m9016.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_11.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value, MsThreatMatrixControls.ms_m9016.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_2_11.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.security_enforcements.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.bsi_k8s.value, StandardsFields.controls.value: [BsiK8sControls.app_4_4_a4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_3_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9013.value, MsThreatMatrixControls.ms_m9016.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_ps_security_standards_policy.value]}],
    )

    ConfigMapCheck(
        app,
        "CM-001",
        "sensitive key referenced in configmap",
        descr="Attackers can retrieve and use sensitive information provided via config maps",
        data={sk: SENSITIVE_VALUES for sk in SENSITIVE_KEYS},
        check_path=[f".data.{key}" for key in SENSITIVE_KEYS] + ["ConfigMap.data"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_6_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9026.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.sc_se_config_maps.value]}],
    )

    # ================= Namespace checks ====================
    PodCheck(
        app,
        "NS-001",
        "use default namespace",
        descr="The default namespace should not be used for custom workloads",
        namespace="default",
        check_path=".metadata.namespace",
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_6_4.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.namespaces.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242383.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_16_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_namespace_isolation.value]}],
    )

    for i, ns in enumerate(["kube-system", "kube-public"]):
        PodCheck(
            app,
            f"NS-002-{i+1}",
            f"place pod in {ns}",
            descr=f"{ns} should not be used for custom workloads",
            namespace=ns,
            check_path=".metadata.namespace",
            standards=[{StandardsFields.standard.value: StandardsAndGuidelines.cis_benchmark.value, StandardsFields.version.value: CisBenchmarkVersions.v_1_12.value, StandardsFields.controls.value: [CisBenchmarkControls.cis_5_6_1.value]}, 
                    {StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.namespaces.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.k8s_stig.value, StandardsFields.controls.value: [K8sStigControls.v_242417.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_16_1_a.value]},
                    {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_namespace_isolation.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_ad_memory_limit.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
    )
    PodCheck(
        app,
        "RES-001-2",
        "no memory requests",
        descr="not setting memory requests can lead to problems upon admission",
        container=ContainerConfig(resources=ContainerResourceConfig(request_memory=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.requests.memory", ".spec.containers[].resources.requests"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_ad_memory_limit.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_ad_memory_limit.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
    )
    PodCheck(
        app,
        "RES-002-2",
        "no memory limits",
        descr="not setting memory limit can lead to the pod suffocating the node by using all available memory",
        container=ContainerConfig(resources=ContainerResourceConfig(limits_memory=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.limits.memory", ".spec.containers[].resources.limits"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_ad_memory_limit.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_ad_cpu_limit.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
    )
    PodCheck(
        app,
        "RES-003-2",
        "no CPU requests",
        descr="not setting CPU requests can lead to problems upon admission",
        container=ContainerConfig(resources=ContainerResourceConfig(request_cpu=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.requests.cpu", ".spec.containers[].resources.requests"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_ad_cpu_limit.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_ad_cpu_limit.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
    )
    PodCheck(
        app,
        "RES-004-2",
        "no CPU limits",
        descr="not setting CPU limit can lead to the pod suffocating the node by using all available CPU",
        container=ContainerConfig(resources=ContainerResourceConfig(limits_cpu=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.limits.cpu", ".spec.containers[].resources.limits"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.k8s_checklist.value, StandardsFields.controls.value: [K8sChecklistControls.asc_ad_cpu_limit.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
    )
    PodCheck(
        app,
        "RES-005-2",
        "no ephemeral storage requests",
        descr="not setting ephemeral storage limit can suffocate the node by using all available CPU",
        container=ContainerConfig(resources=ContainerResourceConfig(request_ephemeral_storage=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.requests.ephemeral-storage", ".spec.containers[].resources.requests"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
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
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
    )
    PodCheck(
        app,
        "RES-006-2",
        "no ephemeral storage limits",
        descr="not setting ephemeral storage limit can suffocate the node by using all available CPU",
        container=ContainerConfig(resources=ContainerResourceConfig(limits_ephemeral_storage=None)),
        namespace=unrestricted_ns,
        check_path=[".spec.containers[].resources.limits.ephemeral-storage", ".spec.containers[].resources.limits"],
        standards=[{StandardsFields.standard.value: StandardsAndGuidelines.nsa_cisa.value, StandardsFields.controls.value: [NsaCisaControls.resource_policies.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.pci_guidance.value, StandardsFields.controls.value: [PciGuidanceControls.pci_11_1_a.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.ms_threat_matrix.value, StandardsFields.controls.value: [MsThreatMatrixControls.ms_m9029.value]},
                   {StandardsFields.standard.value: StandardsAndGuidelines.owasp_k8s.value, StandardsFields.controls.value: [OwaspControls.s4_limiting_resource.value]}],
    )
