from constructs import Construct

from kalm_benchmark.manifest_generator.gen_namespaces import NamespaceCheck

from .cdk8s_imports import k8s
from .check import Check
from .constants import (
    AppArmorProfile,
    CheckStatus,
    FsGroupRule,
    GenericPspRule,
    PodSecurityAdmissionMode,
    PodSecurityLevel,
    RunAsUserRule,
    SeccompProfileForPSP,
    SeLinuxRule,
    SupplementalGroupsRule,
)


class PodSecurityAdmissionCheck(Check):
    """
    A single checks of a PodSecurityPolicies misconfiguration/best practice
    """

    def __init__(
        self,
        scope: Construct,
        check_id: str,
        name: str,
        expect: str = CheckStatus.Alert,
        descr: str = None,
        check_path: str | list[str] | None = None,
        **kwargs,
    ):
        """
        Instantiates a new PodSecurityPolicy check with all relevant kubernetes resources.
        :param scope: the cdk8s scope in which the resources will be placed
        :param check_id: the id of the check. This is the prefix of the resulting file name
        :param name: the name of the check. This will be part of the resulting file name.
        :param expect: the expected outcome of the check
        :param descr: an optional description for the check
        :param check_path: the path(s) which is the essence of the check
        :param kwargs: any additional keyword arguments will be passed on to the resource
        """
        super().__init__(scope, check_id, name, expect, descr, check_path)
        PodSecurityPolicy(self, self.name, self.meta, **kwargs)


def _parse_id_range(id_range: tuple[int, int] | None) -> dict:
    if id_range is not None:
        return {"ranges": [k8s.IdRangeV1Beta1(min=id_range[0], max=id_range[1])]}
    return {}


def _set_hardening_profile(
    meta: k8s.ObjectMeta, profile_name: str | None, is_apparmor: bool, is_allowed_field: bool = False
) -> k8s.ObjectMeta:
    """
    Sets the annotation in the meta object so the tool has to specified profile configured
    :param meta: the meta object, in which the profile will be configured for the corresponding tool.
    :param profile_name: the profile which will be set
    :param is_apparmor: whether this is an AppArmor profile (vs seccomp)
    :param is_allowed_field: if try the field 'allowedProfileNames' is set, otherwise 'defaultProfileName' is set
    :return: the updated meta object
    """
    if profile_name is None:
        return meta

    field_name = "allowedProfileNames" if is_allowed_field else "defaultProfileName"

    key = (
        f"apparmor.security.beta.kubernetes.io/{field_name}"
        if is_apparmor
        else f"seccomp.security.alpha.kubernetes.io/{field_name}"
    )

    if meta.annotations is None:
        meta = k8s.ObjectMeta(annotations={}, labels=meta.labels)
    meta.annotations[key] = profile_name
    return meta


class PodSecurityPolicy(Construct):
    """
    A cdk8s building block wrapping a Kubernetes PodSecurityPolicy
    """

    def __init__(
        self,
        scope: Construct,
        name: str,
        meta: k8s.ObjectMeta,
        allow_privilege_escalation: bool | None = False,
        allowed_capabilities: list[str] | str | None = None,
        allowed_host_paths: list[str] | str | None = "-",  # empty list = no restriction
        apparmor_profile_name: str | None = AppArmorProfile.RuntimeDefault,
        allowed_apparmor_profile_names: str | bool | None = None,
        fs_group_rule: str = FsGroupRule.RunAsAny,
        gid_range: tuple[int, int] | None = None,  # [min, max]
        host_ipc: bool | None = False,
        host_pid: bool | None = False,
        host_network: bool | None = False,
        run_as_group_rule: str | None = None,  # can be MayRunAs, MustRunAs, RunAsAny
        run_as_user_rule: str | None = RunAsUserRule.MustRunAsNonRoot,
        uid_range: tuple[int, int] | None = None,  # [min, max]
        read_only_root_filesystem: bool | None = False,
        drop_capabilities: list[str] | str | None = "ALL",
        privileged: bool | None = False,
        se_linux_rule: str | None = SeLinuxRule.MustRunAs,
        se_linux_level: str | None = "s0:c123,c456",
        seccomp_profile_name: str | None = SeccompProfileForPSP.RuntimeDefault,
        allowed_seccomp_profile_names: str | bool | None = None,
        supplemental_groups_rule: str = SupplementalGroupsRule.RunAsAny,
        **kwargs,
    ):
        super().__init__(scope, name, **kwargs)

        metadata = _set_hardening_profile(meta, apparmor_profile_name, is_apparmor=True)
        if allowed_apparmor_profile_names is not False:
            if allowed_apparmor_profile_names is None:
                allowed_apparmor_profile_names = AppArmorProfile.RuntimeDefault
            metadata = _set_hardening_profile(
                metadata, allowed_apparmor_profile_names, is_apparmor=True, is_allowed_field=True
            )
        metadata = _set_hardening_profile(metadata, seccomp_profile_name, is_apparmor=False)
        if allowed_seccomp_profile_names is not False:
            if allowed_seccomp_profile_names is None:
                allowed_seccomp_profile_names = ",".join(
                    [SeccompProfileForPSP.DockerDefault, SeccompProfileForPSP.RuntimeDefault]
                )
            metadata = _set_hardening_profile(
                metadata, allowed_seccomp_profile_names, is_apparmor=False, is_allowed_field=True
            )

        # convert single capability into a list of capacities
        if allowed_capabilities is not None and isinstance(allowed_capabilities, str):
            allowed_capabilities = [allowed_capabilities]
        if drop_capabilities is not None and isinstance(drop_capabilities, str):
            drop_capabilities = [drop_capabilities]

        if allowed_host_paths is not None:
            if isinstance(allowed_host_paths, str):
                if allowed_host_paths == "-":  # placeholder to not allow any host paths
                    # an empty list would mean all paths are allowed. To allow no hostpath a dummy path must be allowed.
                    allowed_host_paths = ["/foo/none/allowed"]
                else:
                    allowed_host_paths = [allowed_host_paths]
            # turn provided paths into the expected objects
            allowed_host_paths = [
                k8s.AllowedHostPathV1Beta1(path_prefix=path, read_only=True) for path in allowed_host_paths
            ]

        user_ranges_kwargs = _parse_id_range(uid_range)
        run_as_user_strategy = (
            k8s.RunAsUserStrategyOptionsV1Beta1(rule=run_as_user_rule, **user_ranges_kwargs)
            if run_as_user_rule is not None
            else None
        )
        group_ranges_kwargs = _parse_id_range(gid_range)
        run_as_group_strategy = (
            k8s.RunAsGroupStrategyOptionsV1Beta1(rule=run_as_group_rule, **group_ranges_kwargs)
            if run_as_group_rule is not None
            else None
        )
        se_linux_strategy = k8s.SeLinuxStrategyOptionsV1Beta1(
            rule=se_linux_rule,
            se_linux_options=k8s.SeLinuxOptions(level=se_linux_level),
        )

        k8s.KubePodSecurityPolicyV1Beta1(
            self,
            "psp",
            metadata=metadata,
            spec=k8s.PodSecurityPolicySpecV1Beta1(
                allow_privilege_escalation=allow_privilege_escalation,
                allowed_capabilities=allowed_capabilities,
                allowed_host_paths=allowed_host_paths,
                host_network=host_network,
                host_ipc=host_ipc,
                host_pid=host_pid,
                read_only_root_filesystem=read_only_root_filesystem,
                required_drop_capabilities=drop_capabilities,
                run_as_user=run_as_user_strategy,
                run_as_group=run_as_group_strategy,
                privileged=privileged,
                se_linux=se_linux_strategy,
                fs_group=k8s.FsGroupStrategyOptionsV1Beta1(rule=fs_group_rule),
                supplemental_groups=k8s.SupplementalGroupsStrategyOptionsV1Beta1(rule=supplemental_groups_rule),
            ),
        )


def gen_pod_security_admission_checks(app) -> None:
    """Generates manifests to check for use of used Pod Security Standards within a namespace.
    :param app: the cdk8s app which represent the scope of the checks.
    :return: nothing, the resources will be created directly in the provided app
    """
    NamespaceCheck(
        app,
        "PSA-001",
        "no Pod Security Admission label configured",
        descr="at least the baseline PodSecurity level should be used for the namespace",
        check_path=[
            "Namespace.metadata.labels.pod-security.kubernetes.io",
        ],
        pod_security_admission_mode=None,
        pod_security_level=None,
    )

    NamespaceCheck(
        app,
        "PSA-002",
        "Using `privileged` Pod Security Standard is insecure",
        descr="Privileged pod security standard imposes no restrictions and may allow for known privilege escalations",
        check_path=[
            "Namespace.metadata.labels.pod-security.kubernetes.io",
        ],
        pod_security_level=PodSecurityLevel.Privileged,
    )

    NamespaceCheck(
        app,
        "PSA-003",
        "Just warning about violations of the pod security standard level is insecure",
        descr="When only warnings for violations are generated insecure workloads can still be deployed",
        check_path=[
            "Namespace.metadata.labels.pod-security.kubernetes.io",
        ],
        pod_security_admission_mode=PodSecurityAdmissionMode.Warn,
    )


def gen_psps(app) -> None:
    """
    Deprecated: These checks should no longer be used.
    They are kept around in case future checks Validating Admission Policy
    will be added, which were added in Kubernetes v 1.26.

    Generates PodSecurityPolicy manifests for corresponding benchmark checks.
    :param app: the cdk8s app which represent the scope of the checks.
    :return: nothing, the resources will be created directly in the provided app
    """
    PodSecurityAdmissionCheck(
        app,
        "PSP-001-1",
        "allow privileged containers",
        descr="Allowing admission of privileged containers is a risk "
        "as they can performa almost every action that can be performed directly on the host",
        privileged=True,  # explicitly allows privileged pods
        check_path=".spec.privileged",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-001-2",
        "allow privileged containers by default",
        descr="Allowing admission of privileged containers is a risk "
        "as they can performa almost every action that can be performed directly on the host",
        privileged=None,
        check_path=".spec.privileged",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-002-1",
        "allow privilege escalation in containers",
        descr="Allowing admission of privileged containers is a risk "
        "as they can performa almost every action that can be performed directly on the host",
        allow_privilege_escalation=True,
        check_path=".spec.allowPrivilegeEscalation",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-002-2",
        "allow privilege escalation in containers by default",
        descr="Allowing admission of privileged containers is a risk "
        "as they can performa almost every action that can be performed directly on the host.",
        allow_privilege_escalation=None,
        check_path=".spec.allowPrivilegeEscalation",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-003-1",
        "allow pods sharing hostPID",
        descr="`hostPID` in pods may allow cross-container influence and may expose the host itself "
        "to potentially malicious or destructive actions",
        host_pid=True,
        check_path=".spec.hostPID",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-003-2",
        "allow pods sharing hostPID by default",
        descr="`hostPID` in pods may allow cross-container influence and may expose the host itself "
        "to potentially malicious or destructive actions",
        host_pid=None,
        check_path=".spec.hostPID",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-004-1",
        "allow pods sharing hostIPC namespace",
        descr="`hostIPC` on pods may allow cross-container influence and may expose the host itself "
        "to potentially malicious or destructive actions",
        host_ipc=True,
        check_path=".spec.hostIPC",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-004-2",
        "allow pods sharing hostIPC namespace by default",
        descr="`hostIPC` on pods may allow cross-container influence and may expose the host itself "
        "to potentially malicious or destructive actions",
        host_ipc=None,
        check_path=".spec.hostIPC",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-005-1",
        "allow pods sharing host network",
        descr="Containers should be isolated from the host machine as much as possible",
        host_network=True,
        check_path=".spec.hostNetwork",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-005-2",
        "allow pods sharing host network by default",
        descr="Containers should be isolated from the host machine as much as possible",
        host_network=None,
        check_path=".spec.hostNetwork",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-006-1",
        "allow all host_paths by default",
        descr="Attackers can use a writable hostPath to gain persistence on underlying host system",
        allowed_host_paths=None,
        check_path=".spec.allowedHostPaths",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-006-2",
        "allow all host_paths naive specification",
        descr="Attackers can use a writable hostPath to gain persistence on underlying host system",
        allowed_host_paths=[],
        check_path=".spec.allowedHostPaths",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-006-3",
        "disallow all host_paths properly",
        expect=CheckStatus.Pass,
        descr="Attackers can use a writable hostPath to gain persistence on underlying host system",
        allowed_host_paths=["/does/not/exist"],
        check_path=".spec.allowedHostPaths",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-007-1",
        "allow root users in pods",
        descr="a user should not have elevated privileges",
        run_as_user_rule=RunAsUserRule.RunAsAny,  # poses no restrictions on the users
        check_path=".spec.runAsUser",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-007-2",
        "allow root users in pods uid range",
        descr="a user should not have elevated privileges",
        run_as_user_rule=RunAsUserRule.MustRunAs,
        uid_range=(0, 65535),  # allowing all UIDs is basically no protection as well
        check_path=".spec.runAsUser",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-007-3",
        "don't allow root users in pods",
        expect=CheckStatus.Pass,
        descr="a user should not have elevated privileges",
        run_as_user_rule=RunAsUserRule.MustRunAs,
        uid_range=(10000, 65535),
        check_path=".spec.runAsUser",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-008-1",
        "allow root groups in pods must gid range",
        descr="container group should not have elevated privileges",
        run_as_group_rule=GenericPspRule.MustRunAs,
        gid_range=(0, 65535),  # allowing all GIDs is basically no protection as well
        check_path=".spec.runAsGroup",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-008-2",
        "allow root groups in pods may gid range",
        descr="container group should not have elevated privileges",
        run_as_group_rule=GenericPspRule.MayRunAs,
        gid_range=(0, 65535),  # allowing all GIDs is basically no protection as well
        check_path=".spec.runAsGroup",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-008-3",
        "allow root groups in pods may higher gid",
        expect=CheckStatus.Pass,
        descr="container group should not have elevated privileges",
        run_as_group_rule=GenericPspRule.MayRunAs,
        gid_range=(10000, 65535),
        check_path=".spec.runAsGroup",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-008-4",
        "allow root groups in pods must higher gid",
        expect=CheckStatus.Pass,
        descr="container group should not have elevated privileges",
        run_as_group_rule=GenericPspRule.MustRunAs,
        gid_range=(10000, 65535),
        check_path=".spec.runAsGroup",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-009",
        "allowing NET_RAW",
        descr="container group should not have elevated privileges",
        # the test PSP drops all capabilities, but by explicitly allowing net_raw the alert should be triggered
        allowed_capabilities=["NET_RAW"],
        check_path=".spec.allowedCapabilities",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-010",
        "not dropping all capabilities",
        descr="container group should not have elevated privileges",
        drop_capabilities=["NET_RAW"],  # drop only NET_RAW instead of ALL
        check_path=".spec.requiredDropCapabilities",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-011-1",
        "allowing read only root filesystem",
        descr="having a writeable root filesystem allows attackers to compromising the machine "
        "through permanent local changes",
        read_only_root_filesystem=True,
        check_path=".spec.readOnlyRootFilesystem",
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-011-2",
        "allowing read only root filesystem",
        descr="having a writeable root filesystem allows attackers to compromising the machine "
        "through permanent local changes",
        read_only_root_filesystem=None,
        check_path=".spec.readOnlyRootFilesystem",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-012",
        "not configuring SE linux",
        descr="Not hardening a linux system can increase the impact of a compromise",
        se_linux_rule=SeLinuxRule.RunAsAny,
        check_path=".spec.seLinux",
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-013-1",
        "not configuring AppArmor by default",
        descr="Not hardening a linux system can increase the impact of a compromise",
        apparmor_profile_name=None,
        check_path=[
            ".metadata.annotations.apparmor.security.beta.kubernetes.io/defaultProfileName"
            ".metadata.annotations[apparmor.security.beta.kubernetes.io/defaultProfileName]"
        ],
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-013-2",
        "not confining AppArmor",
        descr="Not hardening a linux system can increase the impact of a compromise",
        apparmor_profile_name=AppArmorProfile.Unconfined,
        check_path=[
            ".metadata.annotations.apparmor.security.beta.kubernetes.io/defaultProfileName",
            ".metadata.annotations[apparmor.security.beta.kubernetes.io/defaultProfileName]",
        ],
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-013-3",
        "not restricting allowed AppArmor profiles",
        descr="Not hardening a linux system can increase the impact of a compromise",
        allowed_apparmor_profile_names=False,
        check_path=[
            ".metadata.annotations.apparmor.security.beta.kubernetes.io/allowedProfileNames",
            ".metadata.annotations[apparmor.security.beta.kubernetes.io/allowedProfileNames]",
        ],
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-014-1",
        "not configuring Seccomp by default",
        descr="Not hardening a linux system can increase the impact of a compromise",
        seccomp_profile_name=None,
        check_path=[
            ".metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName",
            ".metadata.annotations.seccomp.security.alpha.kubernetes.io/pod",
            ".metadata.annotations[seccomp.security.alpha.kubernetes.io/defaultProfileName]",
            ".metadata.annotations[seccomp.security.alpha.kubernetes.io/pod]",
        ],
    )

    PodSecurityAdmissionCheck(
        app,
        "PSP-014-2",
        "not confining Seccomp",
        descr="Not hardening a linux system can increase the impact of a compromise",
        seccomp_profile_name=SeccompProfileForPSP.Unconfined,
        check_path=[
            ".metadata.annotations.seccomp.security.alpha.kubernetes.io/defaultProfileName",
            ".metadata.annotations.seccomp.security.alpha.kubernetes.io/pod",
            ".metadata.annotations[seccomp.security.alpha.kubernetes.io/defaultProfileName]",
            ".metadata.annotations[seccomp.security.alpha.kubernetes.io/pod]",
        ],
    )
    PodSecurityAdmissionCheck(
        app,
        "PSP-014-3",
        "not restricting allowed Seccomp profiles",
        descr="Not hardening a linux system can increase the impact of a compromise",
        allowed_seccomp_profile_names=False,
        check_path=[
            ".metadata.annotations.seccomp.security.alpha.kubernetes.io/allowedProfileNames",
            ".metadata.annotations[seccomp.security.alpha.kubernetes.io/allowedProfileNames]",
        ],
    )
