"""Tests for helm chart to benchmark mapping functionality."""

import pytest

from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckResult
from kalm_benchmark.ui.interface.gen_utils import get_unified_service
from kalm_benchmark.utils.helm_benchmark_mapper import (
    HelmBenchmarkMapper,
    MappingConfidence,
    create_helm_benchmark_comparison_df,
    enhance_helm_evaluation_with_benchmark_context,
)


def test_direct_scanner_check_mapping():
    """Test direct scanner check ID mappings (highest confidence)."""
    unified_service = get_unified_service()

    mapper = HelmBenchmarkMapper(unified_service)

    # Test Checkov mapping using a check ID that exists in the database
    result = CheckResult(
        scanner_check_id="CKV_K8S_10", scanner_check_name="CPU limits not set", severity="HIGH", obj_name="test-pod"
    )

    mappings = mapper._map_helm_findings_to_benchmark([result])
    assert len(mappings) == 1

    mapping = mappings[0]
    assert mapping.confidence == MappingConfidence.HIGH
    assert mapping.benchmark_check_id is not None
    assert "Database mapping" in mapping.reason


def test_pattern_based_mapping():
    """Test pattern-based mapping (medium confidence)."""
    mapper = HelmBenchmarkMapper()

    result = CheckResult(
        scanner_check_id="CUSTOM_001",
        scanner_check_name="Memory limits not set for container",
        severity="MEDIUM",
        obj_name="test-deployment",
    )

    mappings = mapper._map_helm_findings_to_benchmark([result])
    assert len(mappings) == 1

    mapping = mappings[0]
    assert mapping.confidence == MappingConfidence.MEDIUM
    assert mapping.benchmark_check_id == "POD-009-1"
    assert "Memory limits pattern match" in mapping.reason


def test_no_mapping_fallback():
    """Test fallback when no mapping is possible."""
    mapper = HelmBenchmarkMapper()

    result = CheckResult(
        scanner_check_id="UNKNOWN_CHECK",
        scanner_check_name="Some unknown security check",
        severity="LOW",
        obj_name="test-service",
    )

    mappings = mapper._map_helm_findings_to_benchmark([result])
    assert len(mappings) == 1

    mapping = mappings[0]
    assert mapping.confidence == MappingConfidence.NONE
    assert mapping.benchmark_check_id is None
    assert "No mapping pattern found" in mapping.reason


def test_coverage_summary():
    """Test coverage summary calculation."""
    # Get unified service to access database
    unified_service = get_unified_service()

    mapper = HelmBenchmarkMapper(unified_service)

    results = [
        CheckResult(scanner_check_id="CKV_K8S_10", scanner_check_name="Test 1", severity="HIGH"),
        CheckResult(scanner_check_id="CKV_K8S_11", scanner_check_name="Test 2", severity="MEDIUM"),
        CheckResult(scanner_check_id="UNKNOWN", scanner_check_name="Test 3", severity="LOW"),
    ]

    mappings = mapper._map_helm_findings_to_benchmark(results)
    summary = mapper.get_coverage_summary(mappings)

    assert summary["total"] == 3
    assert summary["mapped"] == 2  # First two should map from database
    assert abs(summary["coverage_rate"] - (2 / 3) * 100) < 0.01
    assert MappingConfidence.HIGH.value in summary["confidence_breakdown"]
    assert summary["benchmark_checks_covered"] == 2


def test_helm_benchmark_comparison_df():
    """Test creation of comparison DataFrame."""
    results = [
        CheckResult(
            scanner_check_id="CKV_K8S_10",
            scanner_check_name="CPU limits not set",
            severity="HIGH",
            obj_name="nginx-pod",
            kind="Pod",
            namespace="default",
        ),
        CheckResult(
            scanner_check_id="UNKNOWN_CHECK",
            scanner_check_name="Custom check",
            severity="LOW",
            obj_name="nginx-service",
            kind="Service",
        ),
    ]

    df = create_helm_benchmark_comparison_df(results)

    assert len(df) == 2
    assert "is_mapped" in df.columns
    assert "mapping_confidence" in df.columns
    assert "benchmark_check_id" in df.columns

    print(df[df["is_mapped"]])
    mapped_row = df[df["is_mapped"]]
    assert len(mapped_row) == 1
    assert mapped_row.iloc[0]["mapping_confidence"] == "high"

    unmapped_row = df[~df["is_mapped"]]
    assert len(unmapped_row) == 1
    assert unmapped_row.iloc[0]["mapping_confidence"] == "none"


def test_enhanced_evaluation():
    """Test enhanced helm evaluation with benchmark context."""
    results = [
        CheckResult(scanner_check_id="CKV_K8S_10", scanner_check_name="CPU limits not set", severity="HIGH"),
        CheckResult(scanner_check_id="CKV_K8S_11", scanner_check_name="Memory requests not set", severity="MEDIUM"),
    ]

    enhanced = enhance_helm_evaluation_with_benchmark_context(results)

    assert "coverage_metrics" in enhanced
    assert "category_analysis" in enhanced
    assert "mapping_confidence" in enhanced

    metrics = enhanced["coverage_metrics"]
    assert metrics["total_findings"] == 2
    assert metrics["mapped_findings"] == 2  # Both should map from database
    assert abs(metrics["coverage"] - 100.0) < 0.01


if __name__ == "__main__":
    pytest.main([__file__])
