import numpy as np
import pytest

from kalm_benchmark.evaluation.scanner.kubeaudit import Scanner
from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckCategory


class TestCheckCategorization:
    @pytest.mark.parametrize(
        "check_id",
        [
            "AppArmorAnnotationMissing",
            "AppArmorDisabled",
            "AppArmorInvalidAnnotation",
        ],
    )
    def test_apparmor_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        [
            "AutomountServiceAccountTokenDeprecated",
            "AutomountServiceAccountTokenTrueAndDefaultSA",
        ],
    )
    def test_automount_sa_token_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        ["CapabilityAdded", "CapabilityShouldDropAll", "CapabilityOrSecurityContextMissing"],
    )
    def test_capabilities_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        [
            "NamespaceHostNetworkTrue",
            "NamespaceHostIPCTrue",
            "NamespaceHostPIDTrue",
        ],
    )
    def test_hostns_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        [
            "ImageTagMissing",
            "ImageTagIncorrect",
            "ImageCorrect",
        ],
    )
    def test_image_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        [
            "LimitsNotSet",
            "LimitsCPUNotSet",
            "LimitsMemoryNotSet",
            "LimitsCPUExceeded",
            "LimitsMemoryExceeded",
        ],
    )
    def test_limits_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Reliability

    @pytest.mark.parametrize(
        "check_id",
        [
            "SensitivePathsMounted",
        ],
    )
    def test_mounts_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        [
            "MissingDefaultDenyIngressAndEgressNetworkPolicy",
            "MissingDefaultDenyIngressNetworkPolicy",
            "MissingDefaultDenyEgressNetworkPolicy",
            "AllowAllIngressNetworkPolicyExists",
            "AllowAllEgressNetworkPolicyExists",
        ],
    )
    def test_netpol_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Segregation

    @pytest.mark.parametrize(
        "check_id",
        [
            "RunAsUserCSCRoot",
            "RunAsUserPSCRoot",
            "RunAsNonRootCSCFalse",
            "RunAsNonRootPSCNilCSCNil",
            "RunAsNonRootPSCFalseCSCNil",
        ],
    )
    def test_nonroot_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        [
            "AllowPrivilegeEscalationNil",
            "AllowPrivilegeEscalationTrue",
        ],
    )
    def test_privilege_escalation_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        [
            "PrivilegedTrue",
            "PrivilegedNil",
        ],
    )
    def test_privileged_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        [
            "ReadOnlyRootFilesystemFalse",
            "ReadOnlyRootFilesystemNil",
        ],
    )
    def test_root_fs_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        [
            "SeccompAnnotationMissing",
            "SeccompDeprecatedPod",
            "SeccompDisabledPod",
            "SeccompDeprecatedContainer",
            "SeccompDisabledContainer",
        ],
    )
    def test_seccomp_checks(self, check_id: str):
        cat = Scanner.categorize_check(check_id)
        assert cat == CheckCategory.Workload

    @pytest.mark.parametrize(
        "check_id",
        [
            "NotAValidCheck",
            "",
            None,
            np.nan,
        ],
    )
    def test_invalid_or_unknown_ids(self, check_id: str | None):
        cat = Scanner.categorize_check(check_id)
        assert cat is None  # no category assigned
