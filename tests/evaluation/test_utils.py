import os
import re
from pathlib import Path

import pytest
import yaml

from kalm_benchmark.evaluation.utils import (
    fix_path_to_current_environment,
    get_difference_in_parent_path,
    get_path_to_line,
    normalize_path,
)


class TestPathNormalization:
    @pytest.mark.parametrize(
        "path,expected",
        [
            ("spec.template.metadata.labels", ".metadata.labels"),
            ("spec.template.spec.containers[].image", ".spec.containers[].image"),
            (
                "spec.template.spec.containers[].securityContext.capabilities.add[]",
                ".spec.containers[].securityContext.capabilities.add[]",
            ),
        ],
    )
    def test_normaliziation_drops_pod_template_prefix(self, path, expected):
        assert normalize_path(path) == expected
        # a path in corract format will not be changed
        assert normalize_path(expected) == expected

    @pytest.mark.parametrize(
        "path",
        [
            ".spec.containers[0].image",
            ".relatedObjects[1].rules[0].apiGroups[0]",
            ".relatedObjects[1].rules[2].verbs[4]",
        ],
    )
    def test_normaliziation_removes_indices(self, path):
        res = normalize_path(path)
        assert res == re.sub(r"\d", "", path)

    @pytest.mark.parametrize(
        "path",
        [
            ".data[password]",
            ".data[aws_secret_access_key]",
            ".data[token]",
            ".data[credential]",
            ".data[azure_batch_account]",
            ".data[key]",
            ".data[jwt]",
            ".data[azure_batchai_storage_key]",
            ".data[azure_batch_key]",
            ".data[pwd]",
            ".data[secret]",
            ".data[bearer]",
            ".data[aws_access_key_id]",
            ".data[azure_batchai_storage_account].hostPath",
            ".spec.volumes[docker-mount].hostPath.path",
        ],
    )
    def test_normalization_removes_text_in_brackets(self, path):
        pfx = path[: path.index("[")]
        sfx = path[path.index("]") + 1 :]

        assert normalize_path(path) == f"{pfx}[]{sfx}"

    @pytest.mark.parametrize(
        "path",
        [
            ".spec.template.spec.volumes[docker-mount].hostPath.path",
            ".spec.template.name",
            "spec.template.containers",
        ],
    )
    def test_pod_template_is_normalized_away(self, path):
        assert ".spec.template" not in normalize_path(path)

    def test_dont_normalize_annotation_in_brackets(self):
        path = ".metadata.annotations[container.apparmor.security.beta.kubernetes.io]"
        res = normalize_path(path)
        # it mustn't change
        assert path == res

    @pytest.mark.parametrize(
        "path,expected",
        [
            ("automountSAToken", ".automountSAToken"),
            ("metadata.labels", ".metadata.labels"),
            (".spec.containers[].image", ".spec.containers[].image"),  # no change
        ],
    )
    def test_normaliziation_ensures_relative_path(self, path, expected):
        assert normalize_path(path) == expected

    def test_normalization_fixes_typo_in_path_with_container(self):
        # check C-0013 returns this path, but 'container' is missing the final 's'
        path = ".spec.container[].securityContext.runAsNonRoot"
        res = normalize_path(path)
        assert res == ".spec.containers[].securityContext.runAsNonRoot"

    def test_normalization_does_not_make_needless_changes(self):
        # check C-0013 returns this path, but 'container' is missing the final 's'
        path = ".spec.containers[].securityContext.runAsNonRoot"
        res = normalize_path(path)
        assert res == path

    def test_normalization_resolves_related_objects(self):
        kind0 = "RoleBinding"
        kind1 = "ClusterRole"
        related_objs = [
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": kind0,
                "metadata": {
                    "annotations": {"expected": "alert"},
                    "labels": {"app.kubernetes.io/part-of": "kalm-benchmark", "check": "RBAC-001-1"},
                    "name": "rbac-001-1-use-cluster-admin-role-rb-cluster-admin",
                    "namespace": "kalm-benchmark",
                },
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
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
                "kind": kind1,
                "metadata": {
                    "annotations": {"rbac.authorization.kubernetes.io/autoupdate": "true"},
                    "name": "cluster-admin",
                },
                "rules": [
                    {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},
                    {"nonResourceURLs": ["*"], "verbs": ["*"]},
                ],
            },
        ]

        for path, expect in [
            ("relatedObjects[1].rules[0].resources[0]", f"{kind1}.rules[].resources[]"),
            ("relatedObjects[1].rules[4].verbs[1]", f"{kind1}.rules[].verbs[]"),
            ("relatedObjects[0].roleRef.subjects[0]", f"{kind0}.roleRef.subjects[]"),
            ("relatedObjects[0].roleRef.name", f"{kind0}.roleRef.name"),
        ]:
            assert normalize_path(path, related_objs) == expect

    def test_related_objects_are_only_resolved_when_objects_are_provided(self):
        # related objects are treated as any other part of the path
        for path, expect in [
            ("relatedObjects[1].rules[2].resources[0]", ".relatedObjects[].rules[].resources[]"),
            ("relatedObjects[1].rules[2].verbs[2]", ".relatedObjects[].rules[].verbs[]"),
            ("relatedObjects[0].roleRef.name", ".relatedObjects[].roleRef.name"),
        ]:
            assert normalize_path(path) == expect


class TestPathToLineFromManifest:
    def test_indent_width_is_inferred(self):
        spaces_per_indent = 7
        data = {"granny": {"parent": {"child": 42}}}

        lines = yaml.dump(data, indent=spaces_per_indent).split("\n")
        path = get_path_to_line(lines, line_nr=3)

        assert path == "granny.parent.child"

    def test_sibling_parents_are_ignored(self):
        parts = ["granny", "parent2", "child"]
        data = {parts[0]: {"parent1": {"child": {"grand_child": 1}}, parts[1]: {parts[2]: 1}}}
        lines = yaml.dump(data).split("\n")
        path = get_path_to_line(lines, line_nr=6)
        assert path == ".".join(parts)

    def test_triple_dash_is_new_object(self):
        data = [{"obj1": {"parent": {"child": 1}}}, {"obj2": {"foo": 42}}]
        lines = yaml.dump_all(data).split("\n")
        path = get_path_to_line(lines, line_nr=6)
        assert path == "obj2.foo"

    def test_list_parents_have_brackets(self):
        children = [{f"foo{i}": {"bar": i}} for i in range(1, 5)]
        data = {"obj": children}
        lines = yaml.dump(data).split("\n")
        path = get_path_to_line(lines, line_nr=7)
        assert path == "obj[].foo3.bar"

    def test_separator_is_used_to_join_path(self):
        SEPARATOR = "€"
        data = {"granny": {"parent": {"child": 42}}}
        lines = yaml.dump(data).split("\n")
        path = get_path_to_line(lines, line_nr=3, separator=SEPARATOR)

        assert path == SEPARATOR.join(["granny", "parent", "child"])

    @pytest.mark.parametrize("indent_list_item", [False, True])
    def test_list_item_can_be_indented(self, indent_list_item):
        data = {"parents": [{"alice": {"child": "kid"}}, {"bob": {"child": "hijo"}}]}
        lines = yaml.dump(data).split("\n")

        if indent_list_item:
            lines = [line.replace("-", " -") for line in lines]

        path = get_path_to_line(lines, line_nr=5)
        assert path == "parents[].bob.child"

    def test_path_to_list_parent_field_has_brackets(self):
        data = {"parent": [1, 2, 3]}
        lines = yaml.dump(data).split("\n")
        path = get_path_to_line(lines, line_nr=1)
        assert path == "parent[]"

    def test_real_manifest(self):
        lines = [
            "apiVersion: apps/v1\n",
            "kind: Deployment\n",
            "metadata:\n",
            "  annotations:\n",
            "    check_path: .spec.containers[].securityContext.allowPrivilegeEscalation\n",
            "  labels:\n",
            "    app.kubernetes.io/part-of: kalm-benchmark\n",
            "  name: pod-031-1-allowed-privilege-escalation-by-default\n",
            "  namespace: kalm-benchmark\n",
            "spec:\n",
            "  replicas: 1\n",
            "  selector:\n",
            "    matchLabels:\n",
            "      app.kubernetes.io/part-of: kalm-benchmark\n",
            "  template:\n",
            "    metadata:\n",
            "      annotations:\n",
            "        container.apparmor.security.beta.kubernetes.io/app: runtime/default\n",
            "      labels:\n",
            "        app.kubernetes.io/part-of: kalm-benchmark\n",
            "    spec:\n",
            "      automountServiceAccountToken: false\n",
            "      containers:\n",
            "        - image: nginx@sha256:aed492c4dc93d2d1f6fe9a49f00bc7e1863d950334a93facd8ca1317292bf6aa\n",
            "          imagePullPolicy: Always\n",
            "          name: app\n",
            "          ports:\n",
            "            - containerPort: 8080\n",
            "          securityContext:\n",
            "            capabilities:\n",
            "              drop:\n",
            "                - ALL\n",
            "            privileged: false\n",
            "            readOnlyRootFilesystem: true\n",
        ]
        path = get_path_to_line(lines, line_nr=29)

        assert path == "spec.template.spec.containers[].securityContext"


@pytest.fixture
def fake_fs(fs):
    # setup a fake current working directory of the app, simulating another environment
    cwd = "/home/user/dev/app"
    fs.create_dir(cwd)
    os.chdir(cwd)
    fs.CWD = cwd  # store the cwd for use in unit-tests
    yield fs


class TestFixPathToCurrentEnvironment:
    def test_paths_are_absolute(self):
        # Test that absolute paths are rejected for security reasons
        cwd = os.getcwd()
        file_name = "just-a-file.yaml"
        file_path = Path(f"{cwd}/manifests/{file_name}")
        res = fix_path_to_current_environment(file_path)
        # Security check should return empty string for absolute paths
        assert res == ""

    def test_paths_not_relative_to_cwd(self, fake_fs):
        # Test that absolute paths are rejected for security reasons
        file_name = "just-a-file.yaml"
        file_path = f"/usr/src/app/manifests/{file_name}"
        real_file_path = Path(f"{fake_fs.CWD}/manifests/bla/{file_name}")
        fake_fs.create_file(real_file_path)
        res = fix_path_to_current_environment(file_path)
        # Security check should return empty string for absolute paths
        assert res == ""

    def test_file_is_absolute_ref_is_relative(self, fake_fs):
        # Test that absolute paths are rejected for security reasons
        file_name = "just-a-file.yaml"
        file_path = f"/usr/src/app/manifests/{file_name}"
        real_file_path = Path(f"{fake_fs.CWD}/manifests/bla/{file_name}")
        fake_fs.create_file(real_file_path)
        res = fix_path_to_current_environment(file_path)
        # Security check should return empty string for absolute paths
        assert res == ""
    
    def test_relative_paths_work(self):
        # Test that valid relative paths are processed correctly
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as temp_dir:
            original_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                # Create manifests directory and file
                manifests_dir = Path(temp_dir) / "manifests"
                manifests_dir.mkdir(exist_ok=True)
                test_file = manifests_dir / "test-file.yaml"
                test_file.write_text("test content")
                
                # Use relative path - this should work
                rel_path = Path("manifests/test-file.yaml")
                res = fix_path_to_current_environment(rel_path)
                # Should return the relative path since file exists
                assert res == "manifests/test-file.yaml" or res.endswith("manifests/test-file.yaml")
            finally:
                os.chdir(original_cwd)


class TestGetDifferenceInParentPath:
    def test_paths_have_overlapping_subfolder(self):
        p1 = "/usr/src/app/manifests/file.yaml"
        p2 = "/home/user/manifests/file.yaml"
        old, new = get_difference_in_parent_path(p1, p2)
        assert old == str(Path("/usr/src/app"))
        assert new == str(Path("/home/user"))

    def test_same_paths_yields_none(self):
        p = "/usr/src/app/manifests/file.yaml"
        res = get_difference_in_parent_path(p, p)
        assert res is None

    def test_paths_have_no_overlap(self):
        p1 = "/usr/src/app/manifests/file.yaml"
        p2 = "/home/user/totally/different/thingy.json"
        old, new = get_difference_in_parent_path(p1, p2)
        assert old == str(Path(p1))
        assert new == str(Path(p2))
