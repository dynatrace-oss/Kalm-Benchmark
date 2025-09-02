from constructs import Construct
from strenum import StrEnum

from .cdk8s_imports import k8s
from .check import Check
from .constants import (
    MAIN_NS,
    CheckStatus,
    RBACBindingConfig,
    RoleConfig,
    SubjectConfig,
)
from .utils import ensure_list


class SubjectType(StrEnum):
    User = "User"
    Group = "Group"
    SA = "ServiceAccount"


class RoleType(StrEnum):
    Role = "Role"
    ClusteRole = "ClusterRole"


class ServiceAccount(Construct):
    """
    A cdk8s building block for a service account
    """

    def __init__(
        self,
        scope: Construct,
        name: str,
        meta: k8s.ObjectMeta,
        automount_sa_token: bool | None = None,  # leave it up to Kubernetes
    ):
        """
        Instantiate a new (Cluster-)RoleBinding
        :param scope: the cdk8s scope in which the resources will be placed
        :param name: the name of the resource.
        :param meta: the metadata of the parent object. Will be used to create the metadata of this role binding.
        :param automount_sa_token: boolean flag for the option to automount the token
        """
        super().__init__(scope, name)
        k8s.KubeServiceAccount(
            self,
            name,
            metadata=k8s.ObjectMeta(name=name, annotations=meta.annotations),
            automount_service_account_token=automount_sa_token,
        )


class RBACCheck(Check):
    """
    A single checks of a RBAC misconfiguration/best practice
    """

    def __init__(
        self,
        scope: Construct,
        check_id: str,
        name: str,
        expect: str = CheckStatus.Alert,
        descr: str = None,
        check_path: str | list[str] | None = None,
        subject: SubjectConfig = None,
        role: RoleConfig = None,
        binding: RBACBindingConfig = None,
        **kwargs,
    ):
        """
        Instantiates a new RBAC check with all relevant kubernetes resources.
        :param scope: the cdk8s scope in which the resources will be placed
        :param check_id: the id of the check. This is the prefix of the resulting file name
        :param name: the name of the check. This will be part of the resulting file name.
        :param expect: the expected outcome of the check
        :param descr: an optional description for the check
        :param check_path: the path(s) which is the essence of the check
        :param subject: configuration for the RBAC subject (user, group, or service account)
        :param role: configuration for the RBAC role settings
        :param binding: configuration for the RBAC binding settings
        """
        super().__init__(scope, check_id, name, expect, descr, check_path)

        subject, role, binding = self._get_configurations(subject, role, binding)
        subj_name = self._create_service_account_if_needed(subject)
        self._create_roles_and_bindings(check_id, subject, role, binding, subj_name, **kwargs)

    def _get_configurations(self, subject, role, binding):
        """
        Get configuration objects with defaults if None provided
        :param subject: configuration for the RBAC subject
        :param role: configuration for the RBAC role settings
        :param binding: configuration for the RBAC binding settings
        :return: tuple of (subject, role, binding) configurations
        """
        if subject is None:
            subject = SubjectConfig()
        if role is None:
            role = RoleConfig()
        if binding is None:
            binding = RBACBindingConfig()
        return subject, role, binding

    def _create_service_account_if_needed(self, subject):
        """
        Create a ServiceAccount if needed based on subject configuration
        :param subject: the subject configuration
        :return: the subject name to use
        """
        subj_name = subject.name or f"{self.name}-sa"
        if subject.type == SubjectType.SA and subj_name != "default":
            # default service account is created automatically by kubernetes
            ServiceAccount(self, subj_name, self.meta)
        return subj_name

    def _create_roles_and_bindings(self, check_id, subject, role, binding, subj_name, **kwargs):
        """
        Create roles and role bindings based on configurations
        :param check_id: the check ID for prefixing role names
        :param subject: the subject configuration
        :param role: the role configuration
        :param binding: the binding configuration
        :param subj_name: the subject name to use
        """
        if role.name is None:
            return

        role_names = [role.name] if isinstance(role.name, str) else role.name
        for role_name in role_names:
            final_role_name = self._get_final_role_name(check_id, role_name, role.exists)

            if subject.type is not None:
                self._create_role_binding(final_role_name, role, binding, subject, subj_name, **kwargs)

            if not role.exists:
                self._create_role(final_role_name, role)

    def _get_final_role_name(self, check_id, role_name, role_exists):
        """
        Get the final role name, potentially prefixed with check_id
        :param check_id: the check ID
        :param role_name: the original role name
        :param role_exists: whether the role already exists
        :return: the final role name
        """
        if not role_exists:
            return f"{check_id.lower()}-{role_name}"
        return role_name

    def _create_role_binding(self, role_name, role, binding, subject, subj_name, **kwargs):
        """
        Create a role binding
        :param role_name: the role name
        :param role: the role configuration
        :param binding: the binding configuration
        :param subject: the subject configuration
        :param subj_name: the subject name
        """
        role_type = RoleType.ClusteRole if role.is_cluster_role else RoleType.Role
        role_ref = k8s.RoleRef(
            name=role_name,
            kind=role_type,
            api_group="rbac.authorization.k8s.io",
        )

        RoleBinding(
            self,
            f"{self.name}-rb-{role_name}",
            self.meta,
            is_cluster=binding.is_cluster_binding,
            role_ref=role_ref,
            subject_name=subj_name,
            subject_type=subject.type,
            **kwargs,
        )

    def _create_role(self, role_name, role):
        """
        Create a role with the specified configuration
        :param role_name: the role name
        :param role: the role configuration
        """
        Role(
            self,
            role_name,
            self.meta,
            is_cluster=role.is_cluster_role,
            resources=ensure_list(role.resources),
            verbs=ensure_list(role.verbs),
            api_groups=ensure_list(role.api_groups),
        )


class RoleBinding(Construct):
    """
    A cdk8s building block for a RoleBinding
    """

    def __init__(
        self,
        scope: Construct,
        name: str,
        meta: k8s.ObjectMeta,
        role_ref: k8s.RoleRef,
        subject_name: str,
        subject_type: SubjectType,
        subject_namespace: str | None = MAIN_NS,
        is_cluster: bool = False,
        **kwargs,
    ):
        """
        Instantiate a new (Cluster-)RoleBinding

        :param scope: the cdk8s scope in which the resources will be placed
        :param name: the name of the resource.
        :param meta: the metadata of the parent object. Will be used to create the metadata of this role binding.
        :param role_ref: the name of the referenced role
        :param subject_name: the name of the referenced subject
        :param subject_type: the subject type. Can be one of "user", "group" or "serviceaccount"
        :param subject_namespace: if the subject thep is a serviceaccount, then the namespace where the it's located.
        :param is_cluster: boolean flag indicating if the created role binding is cluster wide
        :param kwargs: any additional keyword arguments will be passed on to the resource
        """
        super().__init__(scope, f"rb-{name}", **kwargs)

        metadata = k8s.ObjectMeta(
            name=name,
            annotations=meta.annotations,
            labels=meta.labels,
            namespace=meta.namespace,
        )

        if subject_type == SubjectType.SA:
            subject = k8s.Subject(name=subject_name, kind=subject_type, api_group="", namespace=subject_namespace)
        else:
            subject = k8s.Subject(name=subject_name, kind=subject_type, api_group="")
        rb_ctor = k8s.KubeClusterRoleBinding if is_cluster else k8s.KubeRoleBinding
        rb_ctor(self, "rb", metadata=metadata, role_ref=role_ref, subjects=[subject])


class Role(Construct):
    """
    A cdk8s building block for roles and its policy rules
    """

    def __init__(
        self,
        scope: Construct,
        name: str,
        meta: k8s.ObjectMeta,
        verbs: list[str],
        resources: list[str],
        api_groups: list[str] | None = None,
        is_cluster: bool = False,
        **kwargs,
    ):
        """
        Instantiate a new role with a single policy rules
        :param scope: the cdk8s scope in which the resources will be placed
        :param name: the name of the resource.
        :param meta: the metadata of the parent object. Will be used to create the metadata of this role.
        :param api_groups: the list of apiGroups in the policy rule
        :param verbs: the list of verbs in the policy rule
        :param resources: a list of resources to which the policy rule applies
        :param is_cluster: boolean flag indicating whether the role is cluster-wide or a namespaced role
        :param kwargs: any additional keyword arguments will be passed on to the resource
        """
        super().__init__(scope, f"role-{name}", **kwargs)

        if api_groups is None:
            api_groups = [""]

        rules = [k8s.PolicyRule(verbs=verbs, resources=resources, api_groups=api_groups)] if len(resources) > 0 else []

        metadata = k8s.ObjectMeta(
            name=name,
            annotations=meta.annotations,
            labels=meta.labels,
            namespace=meta.namespace,
        )

        role_ctor = k8s.KubeClusterRole if is_cluster else k8s.KubeRole
        role_ctor(self, "role", metadata=metadata, rules=rules)


def gen_rbac(app) -> None:
    """
    Generates manifests containing RBAC related resources for the corresponding benchmark checks.
    :param app: the cdk8s app which represent the scope of the checks.
    :return: nothing, the resources will be created directly in the provided app
    """
    for i, is_cluster in enumerate([False, True]):
        pfx = "cluster-" if is_cluster else ""
        RBACCheck(
            app,
            f"RBAC-001-{i + 1}",
            f"use cluster-admin role {'cluster wide' if is_cluster else ''}",
            descr="The role cluster-admin provides wide-ranging powers over the environment "
            "and should be used only where and when needed",
            check_path=["RoleBinding.roleRef.name", "ClusterRoleBinding.roleRef.name", ".roleRef.name"],
            subject=SubjectConfig(type=SubjectType.Group),
            role=RoleConfig(name="cluster-admin", exists=True, is_cluster_role=True),
            binding=RBACBindingConfig(is_cluster_binding=is_cluster),
        )

        # wildcards for both resource and verbs affect this as well, but it will be covered in RBAC-003
        for j, verb in enumerate(["get", "list", "watch"]):
            RBACCheck(
                app,
                f"RBAC-002-{(j + 1) + (i * 3)}",
                "read access to secrets",
                descr="Attackers who have permissions to retrieve the secrets can access sensitive information",
                check_path=["ClusterRole.rules[].resources", "Role.rules[].resources", ".rules[].resources"],
                role=RoleConfig(
                    name=f"secret-read-{verb}", is_cluster_role=is_cluster, resources="secrets", verbs=verb
                ),
            )

        RBACCheck(
            app,
            f"RBAC-003-{i + 1}",
            f"{pfx}role use resource wildcard",
            descr="Allowing wildcards violates principle of least privilege",
            check_path=["ClusterRole.rules[].resources", "Role.rules[].resources", ".rules[].resources"],
            role=RoleConfig(name=f"{pfx}all-resource-reader", is_cluster_role=is_cluster, resources="*", verbs="get"),
        )
        RBACCheck(
            app,
            f"RBAC-003-{(i + 3)}",  # continuation of the 2 checks above
            f"{pfx}role use verb wildcard",
            descr="Allowing wildcards violates principle of least privilege",
            check_path=["ClusterRole.rules[].verbs", "Role.rules[].verbs", ".rules[].verbs"],
            role=RoleConfig(name=f"{pfx}all-ns-verbs", is_cluster_role=is_cluster, resources="jobs", verbs="*"),
        )
        RBACCheck(
            app,
            f"RBAC-003-{(i + 5)}",  # continuation of the 4 checks above
            f"{pfx}role use verb wildcard",
            descr="Allowing wildcards violates principle of least privilege",
            check_path=["ClusterRole.rules[].verbs", "Role.rules[].verbs", ".rules[].verbs"],
            role=RoleConfig(
                name=f"{pfx}all-ns-verbs", is_cluster_role=is_cluster, resources="jobs", verbs="get", api_groups="*"
            ),
        )

        # wildcard variants are covered with RBAC-003
        for j, verb in enumerate(["create", "update", "patch", "delete"]):
            RBACCheck(
                app,
                f"RBAC-004-{(j + 1) + (i * 4)}",
                f"{pfx}role creates pods",
                descr="The ability to create pods in a cluster opens up possibilities for privilege escalation",
                check_path=[
                    "ClusterRole.rules[].verbs",
                    "ClusterRole.rules[].resources",
                    "Role.rules[].verbs",
                    "Role.rules[].resources",
                    ".rules[].verbs",
                    ".rules[].resources",
                ],
                role=RoleConfig(name=f"{pfx}pod-{verb}", is_cluster_role=is_cluster, resources="pod", verbs=verb),
            )

        RBACCheck(
            app,
            f"RBAC-005-{i + 1}",
            f"{pfx}role attaches to pods",
            descr="Allowing roles to attach to pods can be dangerous",
            check_path=[
                "ClusterRole.rules[].resources",
                "Role.rules[].resources",
                ".rules[].resources",
            ],
            role=RoleConfig(
                name=f"{pfx}pod-attach", is_cluster_role=is_cluster, resources="pods/attach", verbs="create"
            ),
        )

        RBACCheck(
            app,
            f"RBAC-006-{i + 1}",
            f"{pfx}role exec into pods",
            descr="Attackers can run malicious commands in containers in the cluster using exec command",
            check_path=[
                "ClusterRole.rules[].resources",
                "Role.rules[].resources",
                ".rules[].resources",
            ],
            role=RoleConfig(name=f"{pfx}pod-exec", is_cluster_role=is_cluster, resources="pods/exec", verbs="create"),
        )

        RBACCheck(
            app,
            f"RBAC-007-{i + 1}",
            f"{pfx}role binds default serviceaccount",
            descr="the default servicaccount should never be actively used",
            check_path=[
                "ClusterRoleBinding.subjects[].name",
                "RoleBinding.subjects[].name",
                ".subjects[].name",
            ],
            subject=SubjectConfig(name="default", type=SubjectType.SA),
            role=RoleConfig(
                name=f"{pfx}role-bind-default-sa",
                is_cluster_role=is_cluster,
                resources=[],  # create roles without rules
            ),
            binding=RBACBindingConfig(is_cluster_binding=is_cluster),
        )

        for j, verb in enumerate(["get", "list", "watch"]):
            RBACCheck(
                app,
                f"RBAC-008-{(j + 1) + (i * 3)}",
                f"{pfx}role port-forward pods",
                descr="Attackers can open a backdoor communication channel directly to the sockets inside target "
                "container bypassing network security restrictions",
                check_path=[
                    "ClusterRole.rules[].resources",
                    "Role.rules[].resources",
                    ".rules[].resources",
                ],
                role=RoleConfig(
                    name=f"{pfx}pod-forward", is_cluster_role=is_cluster, resources="pods/portforward", verbs="create"
                ),
            )

        RBACCheck(
            app,
            f"RBAC-009-{i + 1}",
            f"{pfx}role impersonation",
            descr=(
                "The impersonate privilege allows a subject to "
                "impersonate other users gaining their rights to the cluster"
            ),
            check_path=[
                "ClusterRole.rules[].verbs",
                "Role.rules[].verbs",
                ".rules[].verbs",
            ],
            role=RoleConfig(
                name=f"{pfx}role-bind-default-sa",
                is_cluster_role=is_cluster,
                resources=["users", "groups", "serviceaccounts"],
                verbs="impersonate",
            ),
        )

        for j, res in enumerate(["rolebindings", "clusterrolebindings", "roles", "clusterroles"]):
            RBACCheck(
                app,
                f"RBAC-010-{(j + 1) + (i * 4)}",
                f"{pfx}role manages rbac",
                descr="Attackers can escalate privileges if they can update roles",
                check_path=[
                    "ClusterRole.rules[].resources",
                    "ClusterRole.rules[].verbs",
                    "Role.rules[].resources",
                    "Role.rules[].verbs",
                    ".rules[].resources",
                    ".rules[].verbs",
                ],
                role=RoleConfig(
                    name=f"{pfx}role-destroy-resources", is_cluster_role=is_cluster, resources=res, verbs="bind"
                ),
            )

        for j, res in enumerate(["rolebindings", "clusterrolebindings", "roles", "clusterroles"]):
            RBACCheck(
                app,
                f"RBAC-020-{(j + 1) + (i * 4)}",
                f"{pfx}role manages rbac",
                descr="Attackers can escalate privileges if they can update roles",
                check_path=[
                    "ClusterRole.rules[].resources",
                    "ClusterRole.rules[].verbs",
                    "Role.rules[].resources",
                    "Role.rules[].verbs",
                    ".rules[].resources",
                    ".rules[].verbs",
                ],
                role=RoleConfig(
                    name=f"{pfx}role-escalate-resources", is_cluster_role=is_cluster, resources=res, verbs="escalate"
                ),
            )

        for j, verb in enumerate(["get", "list", "watch"]):
            RBACCheck(
                app,
                f"RBAC-012-{(j + 1) + (i * 3)}",
                f"{pfx}role info disclosure",
                descr="Attackers can use disclosed information to plan their next steps",
                check_path=[
                    "ClusterRole.rules[].resources",
                    "ClusterRole.rules[].verbs",
                    "Role.rules[].resources",
                    "Role.rules[].verbs",
                    ".rules[].resources",
                    ".rules[].verbs",
                ],
                role=RoleConfig(
                    name=f"{pfx}role-disclose-info",
                    is_cluster_role=is_cluster,
                    resources=[
                        "secrets",
                        "pods",
                        "services",
                        "deployments",
                        "replicasets",
                        "daemonsets",
                        "statefulsets",
                        "jobs",
                        "cronjobs",
                    ],
                    verbs=verb,
                ),
            )

        for j, verb in enumerate(["delete", "deletecollection"]):
            RBACCheck(
                app,
                f"RBAC-013-{(j + 1) + (i * 2)}",
                f"{pfx}role destructive",
                descr="Attackers can use destructive permissions to destroy data and resources",
                check_path=[
                    "ClusterRole.rules[].verbs",
                    "Role.rules[].verbs",
                    ".rules[].verbs",
                ],
                role=RoleConfig(
                    name=f"{pfx}role-destroy-resources",
                    is_cluster_role=is_cluster,
                    resources=[
                        "secrets",
                        "pods",
                        "services",
                        "deployments",
                        "replicasets",
                        "daemonsets",
                        "statefulsets",
                        "jobs",
                        "cronjobs",
                    ],
                    verbs=verb,
                ),
            )

        for j, verb in enumerate(["delete", "deletecollection"]):
            RBACCheck(
                app,
                f"RBAC-014-{(j+1) + (i * 2)}",
                f"{pfx}role event deletion",
                descr="attackers may want to delete events in an attempt to avoid detection of their activity",
                check_path=[
                    "ClusterRole.rules[].verbs",
                    "Role.rules[].verbs",
                    ".rules[].verbs",
                ],
                role=RoleConfig(
                    name=f"{pfx}-destroy-events", is_cluster_role=is_cluster, resources="events", verbs=verb
                ),
            )

        for j, verb in enumerate(["update", "patch"]):
            RBACCheck(
                app,
                f"RBAC-015-{(j+1) + (i * 2)}",
                f"{pfx}role core dns poisoning",
                descr="an attacker can poison the DNS server if he can modify configuration of the coreDNS server ",
                check_path=[
                    "ClusterRole.rules[].verbs",
                    "Role.rules[].verbs",
                    ".rules[].verbs",
                ],
                role=RoleConfig(
                    name=f"{pfx}role-poison-dns", is_cluster_role=is_cluster, resources="configmaps", verbs=verb
                ),
            )

        for j, verb in enumerate(["create", "update", "patch"]):
            RBACCheck(
                app,
                f"RBAC-021-{(j+1) + (i*3)}",
                name=f"only admins should be able to {verb} persistent volumes",
                descr="",
                check_path=[
                    "ClusterRole.rules[].resources",
                    "ClusterRole.rules[].verbs",
                    "Role.rules[].resources",
                    "Role.rules[].verbs",
                    ".rules[].resources",
                    ".rules[].verbs",
                ],
                subject=SubjectConfig(name=f"rbac-021-pv-{verb}"),
                role=RoleConfig(
                    name=f"pv-{verb}", is_cluster_role=is_cluster, resources="persistentvolumes", verbs=verb
                ),
            )

        for j, verb in enumerate(["create", "update", "patch"]):
            RBACCheck(
                app,
                f"RBAC-022-{(j + 1) + (i*3)}",
                f"{pfx}role can manage NetworkPolicy",
                descr=(),
                check_path=[
                    "ClusterRole.rules[].resources",
                    "ClusterRole.rules[].verbs",
                    "Role.rules[].resources",
                    "Role.rules[].verbs",
                    ".rules[].resources",
                    ".rules[].verbs",
                ],
                role=RoleConfig(
                    name=f"{pfx}role-{verb}-netpol", is_cluster_role=is_cluster, resources="networkpolicies", verbs=verb
                ),
            )

    RBACCheck(
        app,
        "RBAC-016",
        "serviceaccount without binding",
        descr="all service accounts should be bound to roles",
        check_path=[
            "ClusterRoleBinding.subjects[].name",
            "RoleBinding.subjects[].name",
            ".subjects[].name",
        ],
        subject=SubjectConfig(name="rbac-016-ronin-sa", type=SubjectType.SA),
        role=RoleConfig(name=None),
    )

    roles = [f"role-{i}-too-much" for i in range(10)]
    RBACCheck(
        app,
        "RBAC-017",
        "too many roles per subject",
        descr="",
        check_path=[
            "ClusterRoleBinding.subjects[].name",
            "RoleBinding.subjects[].name",
            ".subjects[].name",
        ],
        subject=SubjectConfig(name="poly-role-sa", type=SubjectType.User),
        role=RoleConfig(name=roles, resources="services", verbs="get"),
    )

    # for subject_ns in ["default", "kube-system"]:
    #     RBACCheck(
    #         app,
    #         "RBAC-018",
    #         "rolebinding grants permission to subject in reserved namespace",
    #         descr="Reserved namespaces should not be used for regular workload.",
    #         role_name="default-role",
    #         subject_type=SubjectType.SA,
    #         subject=
    #     )
