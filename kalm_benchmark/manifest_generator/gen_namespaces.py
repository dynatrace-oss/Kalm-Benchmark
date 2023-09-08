from typing import Optional

from cdk8s import App, Chart
from constructs import Construct

from .cdk8s_imports import k8s
from .check import Check, Meta
from .constants import CheckStatus, PodSecurityAdmissionMode, PodSecurityLevel
from .network_policy import NetworkPolicy
from .utils import sanitize_name
from .workload.pod_base import Workload


class Namespace(Construct):
    def __init__(
        self, scope: Construct, name: str, meta: k8s.ObjectMeta | None = None, labels: dict | None = None, **kwargs
    ) -> None:
        super().__init__(scope, name)
        if labels is not None:
            other_meta_values = {k: v for k, v in meta._values.items() if k != "labels"}
            # TODO need to construct a special metadata object with new labels just for the namespace
            meta = k8s.ObjectMeta(**other_meta_values, labels={**meta.labels, **labels})
        k8s.KubeNamespace(self, name, metadata=meta, **kwargs)


class ConfiguredNamespace(Construct):
    def __init__(
        self,
        scope: Construct,
        name: str,
        meta: k8s.ObjectMeta | None = None,
        quota_kwargs: Optional[dict | bool] = True,
        limit_range_kwargs: Optional[dict | bool] = True,
        pod_security_admission_mode: Optional[PodSecurityAdmissionMode] = PodSecurityAdmissionMode.Enforce,
        pod_security_level: Optional[PodSecurityLevel] = PodSecurityLevel.Restricted,
        use_default_deny_all_network_policy: bool = False,
        network_policy_kwargs: Optional[dict | bool] = True,
        has_filler_workload: bool = True,
    ) -> None:
        """
        Instantiates a new Namespace with all relevant kubernetes resources.
        :param quota_kwargs: keyword arguments forwarded to the ResourceQuota created for the namespace
            Can be either dict or boolean. If boolean is True then the default arguments will be used.
        :param limit_range_kwargs: keyword arguments forwarded to the LimitRange created for the namespace.
            Can be either dict or boolean. If boolean is True then the default arguments will be used.
        :param pod_security_admission_mode: an optional PodSecurityAdmissionMode which will be applied
            to the namespace as label it will only be applied, if also `pod_security_level` is not None
        :param pod_security_level: an optional PodSecurityLevel which will be applied to the namespace as label value
            it will only be applied, if also `pod_security_admission_mode` is not None
        :param use_default_deny_all_network_policy: a flag indicating if an additional
            'default_deny_all' network policy will be generated.
        :param network_policy_kwargs: keywoard arguments forwarded to the NetworkPolicy created for the namespace.
            Can be either dict or boolean. If boolean is True then the default arguments will be used.
        :param has_filler_workload: boolean flag if a dummy workload will be created so the Namespace is not empty
        """

        super().__init__(scope, name)
        # this meta object will be applied to all the created resources
        if meta is None:
            meta = Meta(name=name)

        if pod_security_admission_mode is not None and pod_security_level is not None:
            ns_labels = {f"pod-security.kubernetes.io/{pod_security_admission_mode}": pod_security_level}
        else:
            ns_labels = None

        Namespace(self, name, meta, ns_labels)

        if quota_kwargs:
            # True means use defautl arguments
            if quota_kwargs:
                quota_kwargs = {}
            _resource_quota_base(self, meta, **quota_kwargs)

        if limit_range_kwargs:
            if limit_range_kwargs:
                limit_range_kwargs = {}
            _limit_range_base(self, meta, **limit_range_kwargs)

        # network policies are additive. If the flag is set,
        # then use the "deny all" netpol as the default
        # and then configure allowed exceptions with the additional network policy
        if use_default_deny_all_network_policy:
            NetworkPolicy(self, "default-deny-all", meta)

        if network_policy_kwargs:
            if network_policy_kwargs:
                network_policy_kwargs = {}
            NetworkPolicy(self, name, meta, **network_policy_kwargs)

        if has_filler_workload:
            # add an empty workload to avoid alerts regarding empty namespaces, resources, etc.
            Workload(scope, name + "-filler", meta)


class SetupBenchmarkNamespace(Chart):
    """
    The primary namespaces containing most the namespaced benchmark resources.
    It can have either properly defined resource limits and quotas or not.
    """

    def __init__(
        self,
        scope: Construct,
        name: str,
        with_resource_restrictions: bool = True,
    ):
        """
        Creates a namespace in the provided scope with the given name with option resource limits and quotas.
        :param scope: the scope of the resource
        :param name: the name of the resource
        :param with_resource_restrictions: flag specifying if
        proper ResourceQuota and LimitRange will be created as well.
        Ideally, the name should be alphabetically at the top, so the resource will
        be created before any of the objects within it when applying the entire folder.
        """
        super().__init__(scope, f"_{name}")

        meta = Meta(name=name)
        ConfiguredNamespace(
            self,
            name=name,
            meta=meta,
            quota_kwargs=with_resource_restrictions,
            limit_range_kwargs=with_resource_restrictions,
            has_filler_workload=False,
        )


def _limit_range_base(
    scope: Construct,
    meta,
    min_cpu: str = "1m",
    max_cpu: str = "100m",
    default_cpu_request: str = "1m",
    default_cpu_limit: str = "100m",
    min_memory: str = "1Ki",
    max_memory: str = "10Mi",
    default_memory_request: str = "1Ki",
    default_memory_limit: str = "1Mi",
) -> k8s.KubeLimitRange:
    return k8s.KubeLimitRange(
        scope,
        "limit-range",
        metadata=meta,
        spec=k8s.LimitRangeSpec(
            limits=[
                k8s.LimitRangeItem(
                    default=_set_resource_limit_if_no_none(default_cpu_limit, default_memory_limit),
                    default_request=_set_resource_limit_if_no_none(default_cpu_request, default_memory_request),
                    min=_set_resource_limit_if_no_none(min_cpu, min_memory),
                    max=_set_resource_limit_if_no_none(max_cpu, max_memory),
                    type="Container",
                )
            ]
        ),
    )


def _set_resource_limit_if_no_none(cpu: str | None, mem: str | None) -> dict:
    values = {}
    if cpu is not None:
        values["cpu"] = k8s.Quantity.from_string(cpu)
    if mem is not None:
        values["memory"] = k8s.Quantity.from_string(mem)
    return values


def _resource_quota_base(
    scope: Construct, meta, cpu: int | None = 30, memory: str | None = "20Gi", pods: int | None = 1000
) -> k8s.KubeResourceQuota:
    # use ridiculously high values on purpose to avoid any problems when testing in live cluster
    hard = {}
    if cpu is not None:
        hard["cpu"] = k8s.Quantity.from_number(cpu)
    if memory is not None:
        hard["memory"] = k8s.Quantity.from_string(memory)
    if pods is not None:
        hard["pods"] = k8s.Quantity.from_number(pods)

    return k8s.KubeResourceQuota(
        scope,
        "res-quota",
        metadata=meta,
        spec=k8s.ResourceQuotaSpec(
            hard=hard,
        ),
    )


class NamespaceCheck(Check):
    """
    A single checks for resource misconfiguration at namespace level
    """

    def __init__(
        self,
        scope: Construct,
        check_id: str,
        name: str,
        expect: str = CheckStatus.Alert,
        descr: str = None,
        check_path: str | list[str] | None = None,
        has_quota: bool = True,
        quota_kwargs: dict = None,
        has_limit_range: bool = True,
        limit_range_kwargs: dict = None,
        pod_security_level: PodSecurityLevel = PodSecurityLevel.Restricted,
        pod_security_admission_mode: PodSecurityAdmissionMode = PodSecurityAdmissionMode.Enforce,
        has_network_policy: bool = True,
        network_policy_kwargs: dict = None,
        **kwargs,
    ):
        """
        Instantiates a new NamespaceResourceCheck with all relevant kubernetes resources.
        :param scope: the cdk8s scope in which the resources will be placed
        :param check_id: the id of the check. This is the prefix of the resulting file name
        :param name: the name of the check. This will be part of the resulting file name.
        :param expect: the expected outcome of the check
        :param descr: an optional description for the check
        :param check_path: the path(s) which is the essence of the check
        :param has_quota: boolean flag if a ResourceQuota object will be created for the namespace
        :param quota_kwargs: keyword arguments forwarded to the generated ResourceQuota
        :param has_limit_range: : boolean flag if a LimitRange object will be created for the namespace
        :param limit_range_kwargs: keyword arguments forwarded to the generated LimitRange
        :param pod_security_level: the PSS level for pod security admission in the namespace
        :param pod_security_admission_mode: the enforcement mode violations against the selected PSS
        :param has_network_policy: boolean flag if a NetworkPolicy object will be created for the namespace
        :param network_policy_kwargs: keywoard arguments forwarded to the generated NetworkPolicy
        """
        # label names may at most have 63 characters, thus it restricts the namespace length
        # see https://kubernetes.io/docs/concepts/overview/working-with-objects/names/
        ns_name = sanitize_name(f"{check_id}-{name}", max_len=63)
        super().__init__(scope, check_id, ns_name, expect=expect, descr=descr, check_path=check_path, namespace=ns_name)

        ConfiguredNamespace(
            self,
            ns_name,
            meta=self.meta,
            quota_kwargs=quota_kwargs or has_quota,
            limit_range_kwargs=limit_range_kwargs or has_limit_range,
            network_policy_kwargs=network_policy_kwargs or has_network_policy,
            pod_security_level=pod_security_level,
            pod_security_admission_mode=pod_security_admission_mode,
            **kwargs,
        )


def gen_namespace_resource_checks(app: App) -> None:
    """
    Generate namespace manifests with resource quotas and limits for corresponding benchmark checks.
    :param app: the cdk8s app which represent the scope of the checks.
    :returns nothing, the resources will be created directly in the provided app
    """
    NamespaceCheck(
        app,
        "RES-007-0",
        "no LimitRange object for namespace",
        has_limit_range=False,
        check_path=["LimitRange.metadata.namespace", ".metadata.namespace"],
    )
    NamespaceCheck(
        app,
        "RES-007-1",
        "no default cpu request for namespace",
        limit_range_kwargs={"default_cpu_request": None},
        check_path=["LimitRange.spec.limits.defaultRequest.cpu", ".spec.limits.defaultRequest.cpu"],
    )
    NamespaceCheck(
        app,
        "RES-007-2",
        "no default cpu limits for namespace",
        limit_range_kwargs={"default_cpu_limit": None},
        check_path=["LimitRange.spec.limits.default.cpu", ".spec.limits.default.cpu"],
    )
    NamespaceCheck(
        app,
        "RES-007-3",
        "no cpu limits for namespace",
        limit_range_kwargs={"min_cpu": None, "max_cpu": None},
        check_path=[
            "LimitRange.spec.limits.min.cpu",
            "LimitRange.spec.limits.max.cpu",
            ".spec.limits.min.cpu",
            ".spec.limits.max.cpu",
        ],
    )

    NamespaceCheck(
        app,
        "RES-008-1",
        "no default memory request for namespace",
        limit_range_kwargs={"default_memory_request": None},
        check_path=["LimitRange.spec.limits.defaultRequest.memory", ".spec.limits.defaultRequest.memory"],
    )
    NamespaceCheck(
        app,
        "RES-008-2",
        "no default memory limits for namespace",
        limit_range_kwargs={"default_memory_limit": None},
        check_path=["LimitRange.spec.limits.default.memory", ".spec.limits.default.memory"],
    )
    NamespaceCheck(
        app,
        "RES-008-3",
        "no default memory limits for namespace",
        limit_range_kwargs={"min_memory": None, "max_memory": None},
        check_path=[
            "LimitRange.spec.limits.min.memory",
            "LimitRange.spec.limits.max.memory",
            ".spec.limits.min.memory",
            ".spec.limits.max.memory",
        ],
    )

    NamespaceCheck(
        app,
        "RES-009-1",
        "no resource quota applied to namespace",
        has_quota=False,
        check_path=["ResourceQuota.metadata.namespace", ".metadata.namespace"],
    )
    NamespaceCheck(
        app,
        "RES-009-2",
        "no hard quotas defined in ResourceQuota for namespace",
        quota_kwargs={"cpu": None, "memory": None, "pods": None},
        check_path=[
            "ResourceQuota.spec.hard.cpu",
            "ResourceQuota.spec.hard.memory",
            "ResourceQuota.spec.hard.requests.cpu",
            "ResourceQuota.spec.hard.requests.memory",
            "ResourceQuota.spec.hard.pods",
            ".spec.hard.cpu",
            ".spec.hard.memory",
            ".spec.hard.requests.cpu",
            ".spec.hard.requests.memory",
            ".spec.hard.pods",
        ],
    )


def gen_network_policy_checks(app) -> None:
    NamespaceCheck(
        app,
        "NP-001",
        "namespace without network policy",
        has_network_policy=False,
        use_default_deny_all_network_policy=False,
        check_path=["NetworkPolicy.metadata.namespace", ".metadata.namespace"],
    )

    for i, policy_type in enumerate(["Ingress", "Egress"], start=1):
        NamespaceCheck(
            app,
            f"NP-002-{i}",
            f"only {policy_type.lower()} is blocked",
            network_policy_kwargs={"policy_types": [policy_type]},
            check_path=["NetworkPolicy.spec.policyTypes[]", ".spec.policyTypes[]"],
        )

    NamespaceCheck(
        app,
        "NP-003",
        "network policy allows access to cloud metadata API",
        use_default_deny_all_network_policy=True,
        network_policy_kwargs={
            "egress": [{"to": [{"ipBlock": {"cidr": "169.254.169.254/32"}}]}],
            "policy_types": ["Egress"],
        },
        check_path=["NetworkPolicy.egress[].to[].ipBlock", ".egress[].to[].ipBlock"],
    )

    NamespaceCheck(
        app,
        "NP-004",
        "network policy allows access to kubelet",
        use_default_deny_all_network_policy=True,
        network_policy_kwargs={
            "egress": [{"ports": [{"port": 10250}], "to": [{"namespace_selector": {}}]}],
            "policy_types": ["Egress"],
        },
        check_path=["NetworkPolicy.spec.egress[].ports[].port", ".spec.egress[].ports[].port"],
    )

    NamespaceCheck(
        app,
        "NP-005",
        "network policy refers no valid workload",
        network_policy_kwargs={"pod_selector": {"match_labels": {"app": "does-not-exist"}}},
        check_path=["NetworkPolicy.spec.podSelector", ".spec.podSelector"],
    )
