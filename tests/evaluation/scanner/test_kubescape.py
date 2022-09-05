from kalm_benchmark.evaluation.scanner.kubescape import (
    _consolidate_objects,
    _get_check_path,
    _parse_api_object,
)
from kalm_benchmark.manifest_generator.constants import CheckStatus


class TestAlertObjectParsing:
    def test_single_api_object(self):
        check_id = "POD-001"
        expect = CheckStatus.Alert
        name = "pod-001-naked-pod"
        ns = "my-namespace"
        kind = "Pod"
        api_obj = {
            "apiVersion": "v1",
            "kind": kind,
            "metadata": {
                "annotations": {
                    "expected": expect,
                    "description": "Pods shouldn't be deployed without a resource managing it",
                },
                "labels": {"check": check_id},
                "name": name,
                "namespace": ns,
            },
        }

        res = _parse_api_object(api_obj)
        assert res == {
            "check_id": check_id,
            "kind": kind,
            "obj_name": name,
            "namespace": ns,
        }

    def test_out_of_scope_object(self):
        obj_name = "kindnet"
        api_obj = {
            "kind": "ServiceAccount",
            "name": "kindnet",
            "namespace": "kube-system",
            "relatedObjects": [
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {
                        "name": "kindnet",
                    },
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "kindnet"},
                    "subjects": [{"kind": "ServiceAccount", "name": "kindnet", "namespace": "kube-system"}],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {
                        "name": "kindnet",
                    },
                    "rules": [
                        {
                            "apiGroups": ["policy"],
                            "resourceNames": ["kindnet"],
                            "resources": ["podsecuritypolicies"],
                            "verbs": ["use"],
                        },
                        {"apiGroups": [""], "resources": ["nodes"], "verbs": ["list", "watch"]},
                    ],
                },
            ],
        }
        res = _parse_api_object(api_obj)
        assert res == {
            "check_id": None,
            "kind": "ServiceAccount;ClusterRoleBinding;ClusterRole",
            "obj_name": obj_name,
            "namespace": "kube-system",
        }

    def test_single_api_object_missing_label(self):
        check_id = "POD-001"
        expect = CheckStatus.Alert
        name = "pod-001-naked-pod"
        ns = "my-namespace"
        kind = "Pod"
        api_obj = {
            "apiVersion": "v1",
            "kind": kind,
            "metadata": {
                "annotations": {
                    "expected": expect,
                    "description": "Pods shouldn't be deployed without a resource managing it",
                },
                "labels": {"check": check_id},
                "name": name,
                "namespace": ns,
            },
        }

        res = _parse_api_object(api_obj)
        assert res == {
            "check_id": check_id,
            "kind": kind,
            "obj_name": name,
            "namespace": ns,
        }

    def test_single_api_object_with_no_labels(self):
        kind = "Deployment"
        name = "local-path-provisioner"
        ns = "local-path-storage"
        api_obj = {
            "apiVersion": "apps/v1",
            "kind": kind,
            "metadata": {
                "annotations": {"deployment.kubernetes.io/revision": "1"},
                "name": name,
                "namespace": ns,
            },
        }

        res = _parse_api_object(api_obj)
        assert res == {
            "kind": kind,
            "check_id": None,
            "obj_name": name,
            "namespace": ns,
            # faulty object should be as local to the faulty object as possible
        }

    def test_single_api_object_with_no_check_meta(self):
        name = "local-path-provisioner"
        ns = "local-path-storage"
        kind = "Deployment"
        api_obj = {
            "apiVersion": "apps/v1",
            "kind": kind,
            "metadata": {
                "annotations": {"deployment.kubernetes.io/revision": "1"},
                "name": name,
                "namespace": ns,
            },
        }

        res = _parse_api_object(api_obj)
        assert res == {"check_id": None, "namespace": ns, "kind": kind, "obj_name": name}

    def test_api_object_with_related_objects_containing_check(self):
        # in case multiple objects are in the result, pick the one which has the check meta information
        check_id = "RBAC-001"
        expect = CheckStatus.Alert
        name = "binding-cluster-admin"
        ns = "my-namespace"
        kind = "RoleBinding"

        api_obj = {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Group",
            "name": "rbac-001-1-use-cluster-admin-role-sa",
            "relatedObjects": [
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": kind,
                    "metadata": {
                        "annotations": {
                            "description": "a description ...",
                            "expected": expect,
                        },
                        "labels": {"check": check_id},
                        "name": name,
                        "namespace": ns,
                    },
                    "roleRef": {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": "ClusterRole",
                        "name": "cluster-admin",
                    },
                    "subjects": [
                        {
                            "apiGroup": "rbac.authorization.k8s.io",
                            "kind": "Group",
                            "name": "rbac-001-1-use-cluster-admin-role-sa",
                        }
                    ],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {
                        "annotations": {"rbac.authorization.kubernetes.io/autoupdate": "true"},
                        "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"},
                        "name": "cluster-admin",
                    },
                    "rules": [
                        {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},
                    ],
                },
            ],
        }
        res = _parse_api_object(api_obj)

        assert res == {
            "kind": kind,
            "check_id": check_id,
            "obj_name": name,
            "namespace": ns,
        }

    def test_api_object_with_related_objects_with_no_check(self):
        # in case multiple objects are in the result, pick the one which has the check meta information
        root_name = "system:masters"
        root_kind = "Group"
        rel_name = "cluster-admin"
        rel_kind_1 = "RoleBinding"
        rel_kind_2 = "ClusterRole"

        api_obj = {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": root_kind,
            "name": root_name,
            "relatedObjects": [
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": rel_kind_1,
                    "metadata": {
                        "annotations": {"rbac.authorization.kubernetes.io/autoupdate": "true"},
                        "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"},
                        "name": rel_name,
                    },
                    "roleRef": {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": rel_kind_1,
                        "name": rel_name,
                    },
                    "subjects": [
                        {
                            "apiGroup": "rbac.authorization.k8s.io",
                            "kind": "Group",
                            "name": "system:masters",
                        }
                    ],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": rel_kind_2,
                    "metadata": {
                        "annotations": {"rbac.authorization.kubernetes.io/autoupdate": "true"},
                        "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"},
                        "name": rel_name,
                    },
                    "rules": [
                        {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},
                        {"nonResourceURLs": ["*"], "verbs": ["*"]},
                    ],
                },
            ],
        }
        res = _parse_api_object(api_obj)

        assert res == {
            "kind": f"{root_kind};{rel_kind_1};{rel_kind_2}",
            "check_id": None,
            "obj_name": f"{root_name};{rel_name}",  # duplicate names are collapsed
            "namespace": None,
        }


class TestObjectsConsolidation:
    def test_name_with_check_id_takes_priority(self):
        preferred_obj = {
            "check_id": "RBAC-001-2",
            "expected": "alert",
            "obj_name": "rbac-001-2-use-cluster-admin-role-cluster-wide-rb-cluster-admin",
            "namespace": None,
            "kind": "ClusterRoleBinding",
        }

        data = [
            {"check_id": None, "kind": "Group", "obj_name": "rbac-001-2-use-cluster-admin-role-cluster-wide-sa"},
            preferred_obj,
            {
                "check_id": None,
                "expected": CheckStatus.Pass,
                "obj_name": "cluster-admin",
                "namespace": None,
                "kind": "ClusterRole",
            },
        ]
        res = _consolidate_objects(data)

        assert res == preferred_obj

    def test_rbac_secondary_prefer_object_with_check_id_in_name(self):
        preferred_obj = {
            "check_id": "RBAC-009-1",
            "expected": "alert",
            "obj_name": "rbac-009-1-role-impersonation-rb-role-bind-default-sa",
            "namespace": "kalm-benchmark",
            "kind": "RoleBinding",
        }
        data = [
            {"check_id": None, "kind": "ServiceAccount", "obj_name": "default"},
            preferred_obj,
            {
                "check_id": "RBAC-009-1",
                "expected": "alert",
                "obj_name": "role-bind-default-sa",
                "namespace": "kalm-benchmark",
                "kind": "Role",
            },
        ]

        # should use the obj_name and its kind where name starts with id
        res = _consolidate_objects(data)

        assert res == preferred_obj

    def test_rbac_with_no_check_merges_all_fields(self):
        kinds = ["ServiceAccount", "RoleBinding", "Role"]
        names = ["kube-proxy", "kubeadm:node-proxier", "system:node-proxier"]
        status = CheckStatus.Pass
        ns = None

        data = [
            {"check_id": None, "expected": status, "obj_name": name, "namespace": ns, "kind": kind}
            for kind, name in zip(kinds, names)
        ]
        res = _consolidate_objects(data)
        expect = {
            "check_id": None,
            "expected": status,
            "obj_name": ";".join(names),
            "namespace": ns,
            "kind": ";".join(kinds),
        }

        assert res == expect


class TestCheckPathExtraction:
    def test_only_failed_paths(self):
        failed_paths = ["spec.template.metadata.labels"]

        res = _get_check_path(failed_paths)
        assert res == ".metadata.labels"

    def test_multiple_paths_are_concatinated(self):
        paths = [
            "relatedObjects[1].rules[2].resources[0]",
            "relatedObjects[1].rules[2].verbs[2]",
            "relatedObjects[0].roleRef.name",
        ]
        res = _get_check_path(paths)
        assert "|" in res
        resulting_paths = res.split("|")
        # note: implicit deduplication does not preserve order, so a set comparison will be done instead
        expect = set(
            [
                ".relatedObjects[].rules[].resources[]",
                ".relatedObjects[].rules[].verbs[]",
                ".relatedObjects[].roleRef.name",
            ]
        )
        assert len(set(resulting_paths) - expect) == 0

    def test_results_are_deduplicated(self):
        failed_paths = ["spec.template.metadata.labels", "metadata.labels"]
        res = _get_check_path(failed_paths)
        assert res == ".metadata.labels"

    def test_only_fix_paths(self):
        paths = [
            "spec.template.spec.containers[0].resources.limits.memory",
            "spec.template.spec.containers[0].resources.requests.memory",
        ]
        fix_paths = [{"path": p, "value": "-"} for p in paths]
        res = _get_check_path(None, fix_paths)
        assert "|" in res
        resulting_paths = res.split("|")
        expected_paths = set(
            [".spec.containers[].resources.limits.memory", ".spec.containers[].resources.requests.memory"]
        )
        assert len(set(resulting_paths) - expected_paths) == 0

    def test_no_paths_result_in_none(self):
        assert _get_check_path(None, None) is None
