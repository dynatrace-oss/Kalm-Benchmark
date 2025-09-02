import re
from dataclasses import dataclass
from enum import StrEnum

import pandas as pd
from loguru import logger

from ..evaluation.evaluation import CheckCategory
from ..evaluation.scanner.scanner_evaluator import CheckResult


class MappingConfidence(StrEnum):
    """Confidence levels for helm-to-benchmark mappings"""

    HIGH = "high"  # Direct scanner check ID match or strong pattern match
    MEDIUM = "medium"  # Semantic similarity or partial match
    LOW = "low"  # Category-based inference
    NONE = "none"  # No mapping possible


@dataclass
class HelmBenchmarkMapping:
    """Represents a mapping between a helm chart finding and benchmark check"""

    helm_check_id: str
    helm_check_name: str
    benchmark_check_id: str | None
    benchmark_check_name: str | None
    confidence: MappingConfidence
    category: str
    reason: str


class HelmBenchmarkMapper:
    """Maps helm chart findings to benchmark checks for unified analysis"""

    def __init__(self, unified_service=None):
        self.unified_service = unified_service
        self._db_mappings = None
        self._pattern_mappings = self._build_pattern_mappings()
        self._category_mappings = self._build_category_mappings()

    def _get_database_mappings(self) -> dict[str, str]:
        """Get scanner check ID to benchmark check ID mappings from database"""
        if self._db_mappings is not None:
            return self._db_mappings

        if not self.unified_service:
            # Fallback to empty mapping if no service provided
            self._db_mappings = {}
            return self._db_mappings

        try:
            with self.unified_service.db._get_connection() as conn:
                cursor = conn.cursor()

                # Get unique scanner_check_id -> check_id mappings from benchmark data
                cursor.execute(
                    """
                    SELECT DISTINCT scanner_check_id, check_id
                    FROM scanner_results
                    WHERE scanner_check_id IS NOT NULL
                    AND check_id IS NOT NULL
                    AND check_id != ''
                    AND scanner_check_id != ''
                    ORDER BY scanner_check_id
                """
                )

                mappings = {}
                for row in cursor.fetchall():
                    scanner_check_id = row[0]
                    check_id = row[1]

                    # Use the first mapping found for each scanner check ID
                    if scanner_check_id not in mappings:
                        mappings[scanner_check_id] = check_id

                self._db_mappings = mappings
                logger.info(f"Loaded {len(mappings)} scanner check mappings from database")
                return self._db_mappings

        except (AttributeError, KeyError, IndexError) as e:
            logger.error(f"Failed to load database mappings: {e}")
            self._db_mappings = {}
            return self._db_mappings

    def _build_pattern_mappings(self) -> dict[str, tuple[str, str]]:
        """Build pattern-based mappings (regex -> benchmark_check_id, reason)"""
        return {
            # Resource limit patterns
            r"(?i)memory.*limit": ("POD-009-1", "Memory limits pattern match"),
            r"(?i)cpu.*limit": ("POD-010-1", "CPU limits pattern match"),
            r"(?i)memory.*request": (
                "POD-007-1",
                "Memory requests pattern match",
            ),
            r"(?i)cpu.*request": ("POD-008-1", "CPU requests pattern match"),
            # Security context patterns
            r"(?i)privileged.*container": (
                "POD-015-1",
                "Privileged container pattern match",
            ),
            r"(?i)root.*filesystem": (
                "POD-020-1",
                "Root filesystem pattern match",
            ),
            r"(?i)run.*as.*root": ("POD-029-1", "Run as root pattern match"),
            r"(?i)privilege.*escalation": (
                "POD-019-1",
                "Privilege escalation pattern match",
            ),
            # Network patterns
            r"(?i)host.*network": ("POD-016-1", "Host network pattern match"),
            r"(?i)host.*pid": ("POD-017-1", "Host PID pattern match"),
            r"(?i)host.*ipc": ("POD-018-1", "Host IPC pattern match"),
            r"(?i)host.*port": ("POD-024-1", "Host port pattern match"),
            # Image patterns
            r"(?i)latest.*tag": ("POD-001-1", "Latest tag pattern match"),
            r"(?i)image.*pull.*policy": (
                "POD-002-1",
                "Image pull policy pattern match",
            ),
            r"(?i)image.*tag": ("POD-005-1", "Image tag pattern match"),
            # Namespace patterns
            r"(?i)default.*namespace": (
                "NP-001",
                "Default namespace pattern match",
            ),
            # Service account patterns
            r"(?i)service.*account.*token": (
                "RES-001",
                "Service account token pattern match",
            ),
            r"(?i)default.*service.*account": (
                "SEC-007-1",
                "Default service account pattern match",
            ),
            # Capabilities patterns
            r"(?i)cap.*sys.*admin": (
                "POD-022-1",
                "CAP_SYS_ADMIN capability pattern match",
            ),
            r"(?i)net.*raw": ("POD-023-1", "NET_RAW capability pattern match"),
            # Secrets patterns
            r"(?i)secret.*environment": (
                "SEC-005-1",
                "Secrets as environment variables pattern match",
            ),
        }

    def _build_category_mappings(self) -> dict[str, str]:
        """Build category-based fallback mappings"""
        return {
            CheckCategory.Workload: "POD-001-1",  # Default workload security check
            CheckCategory.Network: "NP-001",  # Default network policy check
            CheckCategory.IAM: "SEC-007-1",  # Default IAM check
            CheckCategory.DataSecurity: "SEC-005-1",  # Default data security check
            CheckCategory.AdmissionControl: "POD-015-1",  # Default admission control check
            CheckCategory.Reliability: "RES-001",  # Default reliability check
            CheckCategory.Vulnerability: "POD-005-1",  # Default vulnerability check
            CheckCategory.Infrastructure: "INFRA-001",  # Default infrastructure check
            CheckCategory.Segregation: "NP-002",  # Default segregation check
        }

    def _map_helm_findings_to_benchmark(self, helm_results: list[CheckResult]) -> list[HelmBenchmarkMapping]:
        """Map a list of helm chart findings to benchmark checks"""
        mappings = []

        for result in helm_results:
            mapping = self._map_single_finding(result)
            mappings.append(mapping)

        logger.info(f"Mapped {len(mappings)} helm findings to benchmark checks")
        self._log_mapping_statistics(mappings)

        return mappings

    def _try_database_mapping(self, result: CheckResult) -> HelmBenchmarkMapping | None:
        """Map using database mappings (highest confidence)."""
        db_mappings = self._get_database_mappings()
        if not (result.scanner_check_id and result.scanner_check_id in db_mappings):
            return None

        benchmark_id = db_mappings[result.scanner_check_id]
        return HelmBenchmarkMapping(
            helm_check_id=result.scanner_check_id,
            helm_check_name=result.scanner_check_name or "Unknown",
            benchmark_check_id=benchmark_id,
            benchmark_check_name=f"Benchmark check {benchmark_id}",
            confidence=MappingConfidence.HIGH,
            category=self._get_category_from_check_id(benchmark_id),
            reason=f"Database mapping: {result.scanner_check_id} -> {benchmark_id}",
        )

    def _try_pattern_mapping(self, result: CheckResult) -> HelmBenchmarkMapping | None:
        """Map using pattern matching (medium confidence)."""
        if not result.scanner_check_name:
            return None

        for pattern, (benchmark_id, reason) in self._pattern_mappings.items():
            if re.search(pattern, result.scanner_check_name):
                return HelmBenchmarkMapping(
                    helm_check_id=result.scanner_check_id or "unknown",
                    helm_check_name=result.scanner_check_name,
                    benchmark_check_id=benchmark_id,
                    benchmark_check_name=f"Benchmark check {benchmark_id}",
                    confidence=MappingConfidence.MEDIUM,
                    category=self._get_category_from_check_id(benchmark_id),
                    reason=reason,
                )
        return None

    def _try_category_mapping(self, result: CheckResult) -> HelmBenchmarkMapping | None:
        """Map using category-based mapping (low confidence)."""
        if not result.check_id:
            return None

        category = self._get_category_from_check_id(result.check_id)
        if category not in self._category_mappings:
            return None

        benchmark_id = self._category_mappings[category]
        return HelmBenchmarkMapping(
            helm_check_id=result.scanner_check_id or result.check_id,
            helm_check_name=result.scanner_check_name or "Unknown",
            benchmark_check_id=benchmark_id,
            benchmark_check_name=f"Benchmark check {benchmark_id}",
            confidence=MappingConfidence.LOW,
            category=category,
            reason=f"Category-based mapping to {category}",
        )

    def _create_fallback_mapping(self, result: CheckResult) -> HelmBenchmarkMapping:
        """Create fallback mapping when no other mapping succeeds."""
        return HelmBenchmarkMapping(
            helm_check_id=result.scanner_check_id or "unknown",
            helm_check_name=result.scanner_check_name or "Unknown",
            benchmark_check_id=None,
            benchmark_check_name=None,
            confidence=MappingConfidence.NONE,
            category=CheckCategory.Misc,
            reason="No mapping pattern found",
        )

    def _map_single_finding(self, result: CheckResult) -> HelmBenchmarkMapping:
        """Map a single helm finding to a benchmark check"""
        # Different mapping strategies in order of confidence
        mapping_strategies = [
            self._try_database_mapping,
            self._try_pattern_mapping,
            self._try_category_mapping,
        ]

        for strategy in mapping_strategies:
            mapping = strategy(result)
            if mapping:
                return mapping

        # Fallback if no mapping found
        return self._create_fallback_mapping(result)

    def _get_category_from_check_id(self, check_id: str) -> str:
        """Get category from check ID using existing evaluation logic"""
        from ..evaluation.evaluation import categorize_by_check_id

        return categorize_by_check_id(check_id)

    def _log_mapping_statistics(self, mappings: list[HelmBenchmarkMapping]):
        """Log statistics about mapping confidence levels"""
        confidence_counts = {}
        for mapping in mappings:
            confidence_counts[mapping.confidence] = confidence_counts.get(mapping.confidence, 0) + 1

        total = len(mappings)
        for confidence, count in confidence_counts.items():
            percentage = (count / total) * 100 if total > 0 else 0
            logger.info(f"Mapping confidence {confidence}: {count} ({percentage:.1f}%)")

    def create_unified_coverage_analysis(self, helm_results: list[CheckResult]) -> pd.DataFrame:
        """Create a unified coverage analysis combining helm findings with benchmark expectations

        :param helm_result: List of objects with helm scan results
        :return: DataFrame containing all helm chart results for further statistical
          & comparative analysis
        """

        mappings = self._map_helm_findings_to_benchmark(helm_results)

        # Convert to DataFrame for analysis
        mapping_data = []
        for mapping in mappings:
            mapping_data.append(
                {
                    "helm_check_id": mapping.helm_check_id,
                    "helm_check_name": mapping.helm_check_name,
                    "benchmark_check_id": mapping.benchmark_check_id,
                    "confidence": mapping.confidence.value,
                    "category": mapping.category,
                    "has_benchmark_mapping": mapping.benchmark_check_id is not None,
                    "reason": mapping.reason,
                }
            )

        df = pd.DataFrame(mapping_data)

        # Add coverage metrics
        if not df.empty:
            total_findings = len(df)
            mapped_findings = len(df[df["has_benchmark_mapping"]])
            high_confidence = len(df[df["confidence"] == MappingConfidence.HIGH])
            medium_confidence = len(df[df["confidence"] == MappingConfidence.MEDIUM])

            df.attrs = {
                "total_findings": total_findings,
                "mapped_findings": mapped_findings,
                "mapping_rate": (mapped_findings / total_findings) * 100 if total_findings > 0 else 0,
                "high_confidence_rate": (high_confidence / total_findings) * 100 if total_findings > 0 else 0,
                "medium_confidence_rate": (medium_confidence / total_findings) * 100 if total_findings > 0 else 0,
            }

        return df

    def get_coverage_summary(self, mappings: list[HelmBenchmarkMapping]) -> dict:
        """Get a summary of coverage metrics from helm-to-benchmark mappings

        :param mappings: Helm to Benchmark data model mapping
        :return: summary dictionary for scanner coverage for helm charts
        """
        total = len(mappings)
        if total == 0:
            return {
                "total": 0,
                "mapped": 0,
                "coverage_rate": 0,
                "confidence_breakdown": {},
            }

        mapped = len([m for m in mappings if m.benchmark_check_id is not None])
        confidence_counts = {}
        category_counts = {}

        for mapping in mappings:
            confidence_counts[mapping.confidence.value] = confidence_counts.get(mapping.confidence.value, 0) + 1
            category_counts[mapping.category] = category_counts.get(mapping.category, 0) + 1

        return {
            "total": total,
            "mapped": mapped,
            "coverage_rate": (mapped / total) * 100,
            "confidence_breakdown": confidence_counts,
            "category_breakdown": category_counts,
            "benchmark_checks_covered": len(([m.benchmark_check_id for m in mappings if m.benchmark_check_id])),
        }


def create_helm_benchmark_comparison_df(
    helm_results: list[CheckResult],
    unified_service=None,
    scanner_name: str = None,
) -> pd.DataFrame:
    """Create a comparison DataFrame showing helm findings alongside their benchmark mappings

    :param unified_service: Evaluation service instance with
        database integrations for comparison analysis
    :return: Dataframe containing the benchmark comparisons for helm chart scanss
    """
    if unified_service is None:
        from ..ui.interface.gen_utils import get_unified_service

        unified_service = get_unified_service()

    mapper = HelmBenchmarkMapper(unified_service)
    mappings = mapper._map_helm_findings_to_benchmark(helm_results)

    comparison_data = []
    for result, mapping in zip(helm_results, mappings):
        # Determine the scanner name from multiple sources
        actual_scanner_name = scanner_name or getattr(result, "scanner_name", None) or "Unknown"

        comparison_data.append(
            {
                "scanner_name": actual_scanner_name,
                "helm_check_id": result.scanner_check_id or "Unknown",
                "helm_check_name": result.scanner_check_name or "Unknown",
                "benchmark_check_id": mapping.benchmark_check_id,
                "benchmark_equivalent": mapping.benchmark_check_name,
                "mapping_confidence": mapping.confidence.value,
                "category": mapping.category,
                "severity": result.severity,
                "obj_name": result.obj_name,
                "kind": result.kind,
                "namespace": result.namespace,
                "got": result.got or "alert",  # Default to alert for helm findings
                "expected": "alert" if mapping.benchmark_check_id else None,  # Set expected based on mapping
                "is_mapped": mapping.benchmark_check_id is not None,
                "mapping_reason": mapping.reason,
            }
        )

    return pd.DataFrame(comparison_data)


def _extract_scanner_name_from_results(
    helm_results: list[CheckResult],
) -> str | None:
    """Extract scanner name from helm results if available."""
    if not helm_results:
        return None

    # Try to get scanner name from the first result
    scanner_name = getattr(helm_results[0], "scanner_name", None)
    if scanner_name:
        return scanner_name

    # Try to extract from extra field
    if hasattr(helm_results[0], "extra") and helm_results[0].extra:
        # Extract scanner name from extra field like "helm_chart:ingress-nginx|checkov.kubernetes.checks..."
        extra_parts = helm_results[0].extra.split("|")
        if len(extra_parts) > 1:
            return extra_parts[1].split(".")[0]

    return None


def _create_empty_evaluation_context() -> dict:
    """Create empty evaluation context when no data is available."""
    return {
        "enhanced_results": [],
        "coverage_metrics": {
            "coverage": 0,
            "mapped_findings": 0,
            "total_findings": 0,
        },
        "category_analysis": {},
        "mapping_confidence": {},
    }


def _calculate_coverage_metrics(comparison_df: pd.DataFrame, coverage_summary: dict) -> dict:
    """Calculate coverage metrics from comparison dataframe."""
    total_findings = len(comparison_df)
    mapped_findings = len(comparison_df[comparison_df["is_mapped"]])
    coverage_rate = (mapped_findings / total_findings) * 100 if total_findings > 0 else 0

    return {
        "coverage": coverage_rate,
        "mapped_findings": mapped_findings,
        "total_findings": total_findings,
        "benchmark_checks_covered": coverage_summary["benchmark_checks_covered"],
    }


def _analyze_categories_and_confidence(
    comparison_df: pd.DataFrame,
) -> tuple[dict, dict]:
    """Analyze categories and mapping confidence from comparison dataframe."""
    category_analysis = (
        comparison_df.groupby("category")
        .agg(
            {
                "is_mapped": ["count", "sum"],
                "mapping_confidence": lambda x: x.value_counts().to_dict(),
            }
        )
        .to_dict()
    )

    confidence_breakdown = comparison_df["mapping_confidence"].value_counts().to_dict()

    return category_analysis, confidence_breakdown


def enhance_helm_evaluation_with_benchmark_context(
    helm_results: list[CheckResult],
    unified_service=None,
    scanner_name: str = None,
) -> dict:
    """Enhance helm chart evaluation results with benchmark context for better UI display

    :param unified_service: Evaluation service instance with
        database integrations for comparison analysis
    :param scanner: Name of one of the supported scanners
    :return: Dictionary containing helm chart results compared to benchmark data
    """
    if unified_service is None:
        from ..ui.interface.gen_utils import get_unified_service

        unified_service = get_unified_service()

    # Extract scanner name from results if not provided
    if not scanner_name:
        scanner_name = _extract_scanner_name_from_results(helm_results)

    mapper = HelmBenchmarkMapper(unified_service)
    comparison_df = create_helm_benchmark_comparison_df(helm_results, unified_service, scanner_name)
    coverage_summary = mapper.get_coverage_summary(mapper._map_helm_findings_to_benchmark(helm_results))

    if comparison_df.empty:
        return _create_empty_evaluation_context()

    coverage_metrics = _calculate_coverage_metrics(comparison_df, coverage_summary)
    category_analysis, confidence_breakdown = _analyze_categories_and_confidence(comparison_df)

    return {
        "enhanced_results": comparison_df.to_dict("records"),
        "coverage_metrics": coverage_metrics,
        "category_analysis": category_analysis,
        "mapping_confidence": confidence_breakdown,
        "raw_dataframe": comparison_df,
    }
