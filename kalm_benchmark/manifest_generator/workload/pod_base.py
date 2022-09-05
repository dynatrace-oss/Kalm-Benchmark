from typing import Tuple

from constructs import Construct

from ..cdk8s_imports import k8s
from ..constants import AppArmorProfile, SeccompProfile, SeccompProfileForPSP
from ..rbac import ServiceAccount
from ..utils import ensure_list


def _create_container_security_context(
    allow_privilege_escalation: bool | None = False,
    privileged: bool | None = False,
    run_as_group: int | None = 31337,  # by default the GID is set at pod level
    run_as_user: int | None = 31337,  # by default the UID is set at pod level
    run_as_non_root: bool | None = True,  # this is an alternative to runAsUser>1k
    read_only_root_filesystem: bool | None = True,
    drop_capabilities: list[str] | str | None = "ALL",
    add_capabilities: list[str] | str | None = None,
    seccomp_profile: str | None = SeccompProfile.RuntimeDefault,  # docker/default
    se_linux_level: str | None = "s0:c123,c456",
    **kwargs,
) -> k8s.SecurityContext:
    seccomp_prof = k8s.SeccompProfile(type=seccomp_profile) if seccomp_profile is not None else None
    se_linux_options = k8s.SeLinuxOptions(level=se_linux_level) if se_linux_level is not None else None

    # convert single capability into a list of capacities
    if add_capabilities is not None and isinstance(add_capabilities, str):
        add_capabilities = [add_capabilities]
    if drop_capabilities is not None and isinstance(drop_capabilities, str):
        drop_capabilities = [drop_capabilities]

    capabilities = k8s.Capabilities(add=add_capabilities, drop=drop_capabilities)

    return k8s.SecurityContext(
        allow_privilege_escalation=allow_privilege_escalation,
        run_as_group=run_as_group,
        run_as_user=run_as_user,
        run_as_non_root=run_as_non_root,
        privileged=privileged,
        capabilities=capabilities,
        read_only_root_filesystem=read_only_root_filesystem,
        seccomp_profile=seccomp_prof,
        se_linux_options=se_linux_options,
        **kwargs,
    )


def _create_pod_security_context(
    run_as_group: int = 31337,
    run_as_user: int = 31337,
    run_as_non_root: bool | None = True,  # this is an alternative to runAsUser>1k
    seccomp_profile: str | None = SeccompProfile.RuntimeDefault,  # docker/default is deprecated as of 1.11
    se_linux_level: str | None = "s0:c123,c456",
    sysctls: list[k8s.Sysctl] | None = None,
    **kwargs,
) -> k8s.PodSecurityContext:
    seccomp_prof = k8s.SeccompProfile(type=seccomp_profile) if seccomp_profile is not None else None
    se_linux_options = k8s.SeLinuxOptions(level=se_linux_level) if se_linux_level is not None else None

    return k8s.PodSecurityContext(
        run_as_group=run_as_group,
        run_as_user=run_as_user,
        run_as_non_root=run_as_non_root,
        seccomp_profile=seccomp_prof,
        se_linux_options=se_linux_options,
        sysctls=sysctls,
        **kwargs,
    )


def _pod_base(
    meta: k8s.ObjectMeta,
    name: str,
    apparmor_profile: str | None = AppArmorProfile.RuntimeDefault,
    labels: list[Tuple[str, str]] | Tuple[str, str] | None = ("app.kubernetes.io/part-of", "kalm-benchmark"),
    **kwargs,
) -> Tuple[k8s.ObjectMeta, k8s.PodSpec]:
    spec = _PodSpecBase(name, **kwargs)

    # create custom meta object in order to enable adjustment of the annotation and labels
    metadata = k8s.ObjectMeta(
        name=meta.name, namespace=meta.namespace, annotations=meta.annotations or {}, labels=meta.labels or {}
    )

    # metadata.labels[]
    if labels is not None:
        for k, v in ensure_list(labels):
            metadata.labels[k] = v

    if apparmor_profile is not None:
        annotations = metadata.annotations

        container_names = spec.container_names
        for container_name in container_names:
            apparmor_key = f"container.apparmor.security.beta.kubernetes.io/{container_name}"
            annotations[apparmor_key] = apparmor_profile
            seccomp_key = f"container.seccomp.security.alpha.kubernetes.io/{container_name}"
            annotations[seccomp_key] = SeccompProfileForPSP.RuntimeDefault
        # also add the deprecated version for seccomp (deprecated since > 1.18)
        annotations["seccomp.security.alpha.kubernetes.io/pod"] = SeccompProfileForPSP.RuntimeDefault

    return metadata, spec


def _create_containers(
    image: str = "nginx",
    image_tag: str | None = "@sha256:aed492c4dc93d2d1f6fe9a49f00bc7e1863d950334a93facd8ca1317292bf6aa",
    image_pull_policy: str | None = "Always",
    container_port: int = 8080,
    env_vars: list[Tuple[str, str]] | None = None,
    security_context: dict | bool | None = True,
    security_context_kwargs: dict | None = None,
    request_cpu: str | None = "1m",
    limits_cpu: str | None = "1m",
    request_memory: str | None = "1Mi",
    limits_memory: str | None = "1Mi",
    request_ephemeral_storage: str | None = "1Mi",
    limits_ephemeral_storage: str | None = "1Mi",
    **container_kwargs,
) -> Tuple[list[str], list[k8s.Container]]:
    if security_context is not None and security_context is True:
        if security_context_kwargs is None:
            security_context_kwargs = {}
        security_context = _create_container_security_context(**security_context_kwargs)

    container_names = ["app"]

    # only add field to requests/limits if it's not None.
    # The underlying library is not able to handle None s in requests/limits
    requests = {}
    limits = {}
    # CPU
    if request_cpu is not None:
        requests["cpu"] = k8s.Quantity.from_string(request_cpu)
    if limits_cpu is not None:
        limits["cpu"] = k8s.Quantity.from_string(limits_cpu)

    # memory
    if request_memory is not None:
        requests["memory"] = k8s.Quantity.from_string(request_memory)
    if limits_memory is not None:
        limits["memory"] = k8s.Quantity.from_string(limits_memory)

    # ephemeral storage
    if request_ephemeral_storage is not None:
        requests["ephemeral-storage"] = k8s.Quantity.from_string(request_ephemeral_storage)
    if limits_ephemeral_storage is not None:
        limits["ephemeral-storage"] = k8s.Quantity.from_string(limits_ephemeral_storage)

    container_cfg = dict(
        name="app",
        image=f"{image}{image_tag if image_tag is not None else ''}",
        image_pull_policy=image_pull_policy,
        security_context=security_context,
        ports=[k8s.ContainerPort(container_port=container_port)],
        liveness_probe=k8s.Probe(http_get=k8s.HttpGetAction(path="/live", port=k8s.IntOrString.from_number(8080))),
        readiness_probe=k8s.Probe(http_get=k8s.HttpGetAction(path="/ready", port=k8s.IntOrString.from_number(8080))),
        resources=k8s.ResourceRequirements(requests=requests, limits=limits),
    )
    container_args = {**container_cfg, **container_kwargs} if container_kwargs is not None else container_cfg
    containers = [k8s.Container(env=env_vars, **container_args)]
    return container_names, containers


class _PodSpecBase(k8s.PodSpec):
    def __init__(
        self,
        name: str,
        *args,
        service_account_name: str | None = "<POD>-dedicated-sa",
        service_account: str | None = None,
        automount_sa_token: bool | None = False,
        host_ipc: bool | None = False,
        host_pid: bool | None = False,
        host_network: bool | None = False,
        host_aliases: list[k8s.HostAlias] | None = None,
        pod_security_context: k8s.PodSecurityContext | bool | None = True,
        pod_security_context_kwargs: dict | None = None,
        image: str = "nginx",
        volumes: list[k8s.Volume] | None = None,
        container_kwargs: dict = None,
        node_selector: dict | None = {"kubernetes.io/arch": "amd64"},  # it will not be modified
        node_affinity: dict | bool | None = None,
        priority_class: str | None = "default-priority",
        **kwargs,
    ):
        """Creates a PodSpec according to the provided configuration

        :param name: the name of the pod
        :param service_account_name: the name of the used service account, defaults to "<POD>-dedicated-sa"
        :param service_account: deprecated alternative service_account_name, defaults to None
        :param automount_sa_token: flag if the SA token will be automounted, defaults to False
        :param host_ipc: flag for using hosts IPC namespace, defaults to False
        :param host_pid: flag for using hosts PID namespace, defaults to False
        :param host_network: flag for using node network namespace, defaults to False
        :param host_aliases: list of additional entries added to the `hosts` file, defaults to None
        :param pod_security_context: flag indicating if PodSecurityContext will be created, defaults to True
        :param pod_security_context_kwargs: the keywoard arguments for the PodSecurityContext.
            Any explicetly defined arguments will overwrite the defaults, defaults to None
        :param image: the image used for the container, defaults to "nginx"
        :param volumes: a list of volumes used by the pod, defaults to None
        :param container_kwargs: the keyword arguments forwarded to the creation of the container, defaults to None
        :param node_selector: the setting for the nodeSelector, defaults to {"kubernetes.io/arch": "amd64"}
        :param node_affinity: alternative to the node_selector to inform the schedulear which node to use.
            If it's false, then no nodeAffinity will be specified.
            Otherwise, any explicetly defined arguments will overwrite the defaults, defaults to None
        :param priority_class: the name of the associated priorityClass object, defaults to "default-priority"
        """
        if pod_security_context is not None and pod_security_context is True:
            if pod_security_context_kwargs is None:
                pod_security_context_kwargs = {}
            pod_security_context = _create_pod_security_context(**pod_security_context_kwargs)

        if container_kwargs is None:
            container_kwargs = {}

        self._container_names, containers = _create_containers(image, **container_kwargs)

        node_affinity = None if node_affinity is False else _parse_node_affinity(**(node_affinity or {}))
        affinity = k8s.Affinity(node_affinity=node_affinity)

        super().__init__(
            *args,
            containers=containers,
            volumes=volumes,
            security_context=pod_security_context,
            service_account_name=_adjust_sa_name(service_account_name, name),
            service_account=service_account,
            affinity=affinity,
            node_selector=node_selector,
            priority_class_name=priority_class,
            host_ipc=host_ipc,
            host_pid=host_pid,
            host_network=host_network,
            host_aliases=host_aliases,
            automount_service_account_token=automount_sa_token,
            **kwargs,
        )

    @property
    def container_names(self):
        return self._container_names


def _parse_node_affinity(preferred_during_scheduling_ignored_during_execution: dict | None = None) -> k8s.NodeAffinity:
    # default selector is not not place it on the control-plane node
    node_selector_requirement = {"key": "node-role.kubernetes.io/control-plane", "operator": "DoesNotExist"}
    if preferred_during_scheduling_ignored_during_execution is None:
        preferred_during_scheduling_ignored_during_execution = [
            {"preference": {"match_expressions": [node_selector_requirement]}, "weight": 1}
        ]
    pref_scheduling_terms = [
        k8s.PreferredSchedulingTerm(**term) for term in preferred_during_scheduling_ignored_during_execution
    ]
    return k8s.NodeAffinity(preferred_during_scheduling_ignored_during_execution=pref_scheduling_terms)


def _adjust_sa_name(sa_name: str | None, pod_name: str) -> str | None:
    if sa_name is not None and "<POD>" in sa_name:
        return sa_name.replace("<POD>", pod_name)
    return sa_name


class Workload(Construct):
    """
    A cdk8s building block for a managed pod
    """

    def __init__(
        self,
        scope: Construct,
        name: str,
        meta: k8s.ObjectMeta,
        replicas: int = 1,
        container_kwargs: dict = None,
        service_account_name: str | None = "<POD>-dedicated-sa",
        service_account: str | None = None,  # is deprecated and should not be used
        sa_kwargs: dict = None,
        **kwargs,
    ):
        """
        Instantiate a new managing resource for a pod and any related objects.
        :param scope: the cdk8s scope in which the resources will be placed
        :param name: the name of the resource.
        :param meta: the metadata of the parent object. Will be used to create the metadata of this object.
        :param replicas: the number of replicas of the pod
        :param container_kwargs: any keyword arguments forwarded to the pod
        :param service_account_name: the name of the corresponding service account
        :param service_account: deprecated setting for the corresponding service account
        :param sa_kwargs: any keyword arguments forwarded to the service account
        :param kwargs: any additional keyword arguments will be passed on to the resource
        """
        super().__init__(scope, name)

        if sa_kwargs is None:
            sa_kwargs = {"automount_sa_token": False}

        if service_account_name is not None and service_account_name != "default":
            service_account_name = _adjust_sa_name(service_account_name, name)
            ServiceAccount(self, service_account_name, meta, **sa_kwargs)
        if service_account is not None and service_account != service_account_name:
            ServiceAccount(self, service_account, meta, **sa_kwargs)

        pod_meta_data, pod_spec = _pod_base(
            k8s.ObjectMeta(labels=scope.labels),
            name,
            service_account_name=service_account_name,
            service_account=service_account,
            container_kwargs=container_kwargs,
            **kwargs,
        )

        k8s.KubeDeployment(
            self,
            "deployment",
            metadata=meta,
            spec=k8s.DeploymentSpec(
                replicas=replicas,
                selector=k8s.LabelSelector(match_labels=scope.labels),
                template=k8s.PodTemplateSpec(
                    metadata=pod_meta_data,
                    spec=pod_spec,
                ),
            ),
        )


class Pod(Construct):
    """
    A cdk8s building block for a pod without any object managing it
    """

    def __init__(
        self,
        scope: Construct,
        name: str,
        meta: k8s.ObjectMeta,
    ):
        """
        Instantiate a new a pod and a dedicated service account
        :param scope: the cdk8s scope in which the resources will be placed
        :param name: the name of the resource.
        :param meta: the metadata of the parent object. Will be used to create the metadata of the pod.
        """
        super().__init__(scope, name)

        ServiceAccount(self, f"{name}-dedicated-sa", meta)
        meta_data, spec = _pod_base(meta, name)
        k8s.KubePod(self, name, metadata=meta_data, spec=spec)
