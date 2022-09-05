import pytest

from kalm_benchmark.evaluation.scanner.kics import (
    _extract_checked_path,
    _merge_paths,
    _normalize_path,
)


class TestPathNormalization:
    def test_drop_explanation_after_path(self):
        path = ".spec.foobar"
        res = _normalize_path(f"{path} this is the text that will be dropped")
        assert res == path

    def test_remove_surrounding_quotes(self):
        path = ".spec.hostNetwork"
        res = _normalize_path(f"'{path}'")
        assert res == path

    @pytest.mark.parametrize(
        "path,expect",
        [
            (".spec.containers[container_name].securityContext", ".spec.containers[].securityContext"),
            (".rules[0].resources", ".rules[].resources"),
        ],
    )
    def test_drop_array_index(self, path, expect):
        res = _normalize_path(path)
        assert res == expect

    @pytest.mark.parametrize(
        "value,expect",
        [
            ("metadata.name=wl-001-naked-pod.spec.hostAliases is undefined", ".spec.hostAliases"),
            ("metadata.name={{the-pod}}.spec.template.spec.bla", ".spec.bla"),
        ],
    )
    def test_drop_metadata_name(self, value, expect):
        res = _normalize_path(value)
        assert res == expect

    @pytest.mark.parametrize(
        "value,expect",
        [
            (".spec.containers.name=app has CPU limits", ".spec.containers[]"),
            ("subjects.kind=ServiceAccount.name is not default", ".subjects[].name"),
            (" metadata.name={{rb-cluster-admin}}.roleRef.name=cluster-admin", ".roleRef.name"),
        ],
    )
    def test_object_names_are_removed(self, value, expect):
        res = _normalize_path(value)
        assert res == expect

    def test_drop_spec_template_prefix(self):
        path = ".spec.hostNetwork"
        res = _normalize_path(f"'spec.template{path}' is false or undefined")
        assert res == path

    @pytest.mark.parametrize(
        "path,expect",
        [
            (".spec.containers.name={{app}}.securityContext", ".spec.containers[].securityContext"),
            (".spec.volumes.name={{mnt-azure}}.hostPath", ".spec.volumes[].hostPath"),
            ("spec.containers.name={{app}}.volumeMounts.name={{my-vol}}", ".spec.containers[].volumeMounts[]"),
            (".spec.securityContext.sysctls.name={{net.ipv4.tcp_keepalive_time}}", ".spec.securityContext.sysctls[]"),
        ],
    )
    def test_convert_named_array_to_generic_array(self, path, expect):
        res = _normalize_path(path)
        assert res == expect

    @pytest.mark.parametrize(
        "value,expect",
        [
            ("Attribute 'allowPrivilegeEscalation' is set", ".allowPrivilegeEscalation"),
            ("Attribute 'allowPrivilegeEscalation' is undefined", ".allowPrivilegeEscalation"),
        ],
    )
    def test_extract_attributes(self, value, expect):
        res = _normalize_path(value)
        assert res == expect

    @pytest.mark.parametrize(
        "value",
        [
            "Roles should not be allowed to send read verbs to 'secrets' resources, verbs found: [get]",
            (
                "Workload name 'a-pod' of kind 'Deployment' is mounting a host sensitive OS directory "
                "'/var/data' with hostPath"
            ),
            (
                "Workload name 'a-pod' of kind 'Deployment' is mounting a host sensitive OS directory "
                "'/etc/kubernetes/azure.json' with hostPath"
            ),
        ],
    )
    def test_no_obvious_path_results_in_empty_string(self, value):
        res = _normalize_path(value)
        assert res == ""

    def test_default_to_relative_path_if_doesnt_start_with_uppercase_kind(self):
        value = "'metadata.namespace' is not set to default, kube-system or kube-public"
        res = _normalize_path(value)
        assert res == ".metadata.namespace"

    @pytest.mark.parametrize(
        "input,expect",
        [
            (
                (
                    "metadata.name={{pod-020-1-using-sysctl-net.ipv4.tcp-keepalive-time}}.spec"
                    ".template.spec.securityContext.sysctls.name={{net.ipv4.tcp_keepalive_time}} is not used"
                ),
                ".spec.securityContext.sysctls[]",
            ),
            (
                (
                    "metadata.name={{pod-032-2-privileged-container}}.spec.template"
                    ".spec.containers.name={{app}}.securityContext.privileged is unset or false"
                ),
                ".spec.containers[].securityContext.privileged",
            ),
            ("metadata.name={{wl-001-naked-pod}}.spec.hostAliases is defined", ".spec.hostAliases"),
            (
                (
                    "metadata.name={{pod-036-keep-default-capabilities}}"
                    ".spec.template.spec.containers.name={{app}}.securityContext.capabilities.drop is undefined"
                ),
                ".spec.containers[].securityContext.capabilities.drop",
            ),
            ("'spec.hostNetwork' is false or undefined", ".spec.hostNetwork"),
            ("'spec.allowedHostPaths' is defined and not null", ".spec.allowedHostPaths"),
            # ("'  password: PRIVATE KEY eyJhbGciO JWT Bearer' contains a secret", ".data.password"),
            ("subjects.kind=ServiceAccount.name is not default", ".subjects[].name"),
            (
                "spec.containers[app].securityContext.capabilities.drop is Defined",
                ".spec.containers[].securityContext.capabilities.drop",
            ),
            (
                (
                    "metadata.name={{pod-017-7-use-root-user-on-container}}.spec.template.spec.containers.name={{app}}"
                    ".securityContext.runAsUser is 0 and 'runAsNonRoot' is false"
                ),
                ".spec.containers[].securityContext.runAsUser",
            ),
            (
                (
                    "metadata.name={{pod-021-1-linux-is-not-hardened}}.spec.template.metadata.annotations "
                    "should specify an AppArmor profile for container {{app}}"
                ),
                ".metadata.annotations",
            ),
        ],
    )
    def test_real_examples(self, input, expect):
        res = _normalize_path(input)
        assert res == expect


class TestPathExtraction:
    @pytest.mark.parametrize(
        "search_key,expected_value,actual_value,expect",
        [
            (
                "metadata.name={{psp-002-2-allow-privilege-escalation-in-containers-by-default}}.spec",
                "Attribute 'allowPrivilegeEscalation' is set",
                "Attribute 'allowPrivilegeEscalation' is undefined",
                ".spec.allowPrivilegeEscalation",
            )
        ],
    )
    def test_psp_has_direct_attributes(self, search_key, expected_value, actual_value, expect):
        file = {
            "search_key": search_key,
            "expected_value": expected_value,
            "actual_value": actual_value,
        }

        res = _extract_checked_path(file)
        assert res == expect

    @pytest.mark.parametrize(
        "search_key,expected_value,actual_value,expect",
        [
            (
                "metadata.name={{my-pod}}.rules",
                "metadata.name={{my-pod}}.rules[0].verbs shouldn't contain value: '*'",
                "metadata.name={{rbac-003-3-all-ns-verbs}}.rules[0].verbs contains value: '*'",
                ".rules[].verbs",
            ),
            (
                "metadata.name={{my-pod}}.rules[0].verbs shouldn't contain value: '*'",
                "metadata.name={{my-pod}}.rules",
                "value without info",
                ".rules[].verbs",
            ),
        ],
    )
    def test_prefer_longer_paths(self, search_key, expected_value, actual_value, expect):
        file = {
            "search_key": search_key,
            "expected_value": expected_value,
            "actual_value": actual_value,
        }

        res = _extract_checked_path(file)
        assert res == expect


class TestPathMerging:
    def test_append_attribute(self):
        spec = ".spec"
        attr = "allowPrivilegeEscalation"
        res = _merge_paths([attr, spec])
        assert res == f"{spec}.{attr}"
