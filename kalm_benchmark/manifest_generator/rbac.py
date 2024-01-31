from constructs import Construct
from strenum import StrEnum

from .cdk8s_imports import k8s
from .check import Check
from .constants import MAIN_NS, CheckStatus
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
        subject: str | None = None,
        subject_type: SubjectType | None = None,
        resources: list[str] | str | None = None,  # if empty string, then role is created without rules
        role_name: str | list[str] | None = None,  # both for role-ref and (cluster-) role object
        role_exists: bool = False,
        is_cluster_binding: bool = False,
        is_cluster_role: bool = False,
        verbs: list[str] | str | None = None,
        api_groups: list[str] | str | None = None,
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
        :param subject: the name of the subject
        :param subject_type: the subject type. Can be one of "user", "group" or "serviceaccount"
        :param resources: the resources addressed in the role's policy
        :param role_name: the name of the role
        :param role_exists: boolean flag indicating if the role exists. If so, no additional role will be created.
        :param is_cluster_binding: boolean flag indicating if the created role binding is cluster wide
        :param is_cluster_role: boolean flag indicating if the created role is a ClusterRole
        :param verbs: the verbs used by the role's policy
        :param api_groups: the apiGroups used by the role's policy
        :param kwargs: any additional keyword arguments will be passed on to the resource
        """
        super().__init__(scope, check_id, name, expect, descr, check_path)

        # subjects are only used by role bindings;
        # having not subject type means there is no binding required
        subj_name = subject or f"{self.name}-sa"
        if subject_type == SubjectType.SA and subj_name != "default":
            # default service account is created automatically by kubernetes
            ServiceAccount(self, subj_name, self.meta)

        if role_name is not None:
            # it's possible to bind a subject to multiple roles
            role_names = [role_name] if isinstance(role_name, str) else role_name
            for role_name in role_names:
                if not role_exists:
                    # prefix it with the id, so it can be recovered from the results
                    role_name = f"{check_id.lower()}-{role_name}"

                if subject_type is not None:
                    role_type = RoleType.ClusteRole if is_cluster_role else RoleType.Role
                    role_ref = k8s.RoleRef(
                        name=role_name,
                        kind=role_type,
                        api_group="rbac.authorization.k8s.io",
                    )

                    RoleBinding(
                        self,
                        f"{self.name}-rb-{role_name}",
                        self.meta,
                        is_cluster=is_cluster_binding,
                        role_ref=role_ref,
                        subject_name=subj_name,
                        subject_type=subject_type,
                        **kwargs,
                    )

                # roles set the rules for the interaction with resources;
                # when no resources are defined roles are not needed
                if not role_exists:
                    Role(
                        self,
                        role_name,
                        self.meta,
                        is_cluster=is_cluster_role,
                        resources=ensure_list(resources),
                        verbs=ensure_list(verbs),
                        api_groups=ensure_list(api_groups),
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
    :returns nothing, the resources will be created directly in the provided app
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
            is_cluster_binding=is_cluster,
            is_cluster_role=True,
            role_name="cluster-admin",
            role_exists=True,
            subject_type=SubjectType.Group,  # type is not relevant for this check
        )

        # wildcards for both resource and verbs affect this as well, but it will be covered in RBAC-003
        for j, verb in enumerate(["get", "list", "watch"]):
            RBACCheck(
                app,
                f"RBAC-002-{(j + 1) + (i * 3)}",
                "read access to secrets",
                descr="Attackers who have permissions to retrieve the secrets can access sensitive information",
                check_path=["ClusterRole.rules[].resources", "Role.rules[].resources", ".rules[].resources"],
                is_cluster_role=is_cluster,
                role_name=f"secret-read-{verb}",
                resources="secrets",
                verbs=verb,
            )

        RBACCheck(
            app,
            f"RBAC-003-{i + 1}",
            f"{pfx}role use resource wildcard",
            descr="Allowing wildcards violates principle of least privilege",
            check_path=["ClusterRole.rules[].resources", "Role.rules[].resources", ".rules[].resources"],
            is_cluster_role=is_cluster,
            role_name=f"{pfx}all-resource-reader",
            resources="*",
            verbs="get",
        )
        RBACCheck(
            app,
            f"RBAC-003-{(i + 3)}",  # continuation of the 2 checks above
            f"{pfx}role use verb wildcard",
            descr="Allowing wildcards violates principle of least privilege",
            check_path=["ClusterRole.rules[].verbs", "Role.rules[].verbs", ".rules[].verbs"],
            is_cluster_role=is_cluster,
            role_name=f"{pfx}all-ns-verbs",
            resources="jobs",
            verbs="*",
        )
        RBACCheck(
            app,
            f"RBAC-003-{(i + 5)}",  # continuation of the 4 checks above
            f"{pfx}role use verb wildcard",
            descr="Allowing wildcards violates principle of least privilege",
            check_path=["ClusterRole.rules[].verbs", "Role.rules[].verbs", ".rules[].verbs"],
            is_cluster_role=is_cluster,
            role_name=f"{pfx}all-ns-verbs",
            resources="jobs",
            verbs="get",
            apiGroups="*",
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
                is_cluster_role=is_cluster,
                role_name=f"{pfx}pod-{verb}",
                resources="pod",
                verbs=verb,
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
            is_cluster_role=is_cluster,
            role_name=f"{pfx}pod-attach",
            resources="pods/attach",
            verbs="create",
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
            is_cluster_role=is_cluster,
            role_name=f"{pfx}pod-exec",
            resources="pods/exec",
            verbs="create",
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
            is_cluster_binding=is_cluster,
            is_cluster_role=is_cluster,
            subject="default",
            subject_type=SubjectType.SA,
            role_name=f"{pfx}role-bind-default-sa",
            resources=[],  # create roles without rules
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
                is_cluster_role=is_cluster,
                role_name=f"{pfx}pod-forward",
                resources="pods/portforward",
                verbs="create",
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
            is_cluster_role=is_cluster,
            role_name=f"{pfx}role-bind-default-sa",
            resources=["users", "groups", "serviceaccounts"],
            verbs="impersonate",
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
                is_cluster_role=is_cluster,
                role_name=f"{pfx}role-destroy-resources",
                resources=res,
                verbs="bind",
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
                is_cluster_role=is_cluster,
                role_name=f"{pfx}role-escalate-resources",
                resources=res,
                verbs="escalate",
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
                is_cluster_role=is_cluster,
                role_name=f"{pfx}role-disclose-info",
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
                is_cluster_role=is_cluster,
                role_name=f"{pfx}role-destroy-resources",
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
                is_cluster_role=is_cluster,
                role_name=f"{pfx}-destroy-events",
                resources="events",
                verbs=verb,
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
                is_cluster_role=is_cluster,
                role_name=f"{pfx}role-poison-dns",
                resources="configmaps",
                verbs=verb,
            )
            
        for j, verb in enumerate(["create", "update", "patch"]):
            RBACCheck(
                app,
                f"RBAC-021-{(j+1) + (i*3)}",
                name=f"only admins should be able to {verb} persistent volumes",
                descr="",
                role_name=f"pv-{verb}",
                check_path=[
                    "ClusterRole.rules[].resources",
                    "ClusterRole.rules[].verbs",
                    "Role.rules[].resources",
                    "Role.rules[].verbs",
                    ".rules[].resources",
                    ".rules[].verbs",
                ],
                is_cluster_role=is_cluster,
                resources="persistentvolumes", 
                subject=f"rbac-021-pv-{verb}",
                verbs=verb
            )

        RBACCheck(
            app,
            f"RBAC-022-{i + 1}",
            f"{pfx}role impersonation",
            descr=(),
            check_path=[
                    "ClusterRole.rules[].resources",
                    "ClusterRole.rules[].verbs",
                    "Role.rules[].resources",
                    "Role.rules[].verbs",
                    ".rules[].resources",
                    ".rules[].verbs",
            ],
            is_cluster_role=is_cluster,
            role_name=f"{pfx}role-bind-default-sa",
            resources=["users", "groups", "serviceaccounts"],
            verbs="impersonate",
        )

    RBACCheck(
        app,
        "RBAC-016",
        "serviceaccount without binding",
        descr="all service accounts should be bound to roles",
        role_name=None,
        subject_type=SubjectType.SA,
        check_path=[
            "ClusterRoleBinding.subjects[].name",
            "RoleBinding.subjects[].name",
            ".subjects[].name",
        ],
        subject="rbac-016-ronin-sa",
    )

    roles = [f"role-{i}-too-much" for i in range(10)]
    RBACCheck(
        app,
        "RBAC-017",
        "too many roles per subject",
        descr="",
        role_name=roles,
        subject_type=SubjectType.User,
        check_path=[
            "ClusterRoleBinding.subjects[].name",
            "RoleBinding.subjects[].name",
            ".subjects[].name",
        ],
        subject="poly-role-sa",
        resources="services",
        verbs="get",
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
