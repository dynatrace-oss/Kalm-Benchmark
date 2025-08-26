import statistics
from typing import Any, Dict, List, Optional

from loguru import logger

from ..scanner.scanner_evaluator import CheckResult
from .ccss_converter import CCSSConverter
from .ccss_database import CCSSDatabase
from .ccss_models import MisconfigurationFinding, ScannerCCSSAlignment, SourceType


class CCSSService:
    """Main service for CCSS functionality - provides high-level interface"""

    def __init__(self, db_path: str = "./data/ccss_evaluation.db"):
        self.db = CCSSDatabase(db_path)
        self.converter = CCSSConverter()

    def create_evaluation_run(self, source_type: SourceType, **kwargs) -> str:
        """Create a new CCSS evaluation run"""
        return self.db.create_evaluation_run(source_type, **kwargs)

    def process_scanner_results(
        self,
        scanner_name: str,
        check_results: List[CheckResult],
        source_type: SourceType = SourceType.Manifest,
        manifest_source: str = "",
        is_research_dataset: bool = False,
        evaluation_run_id: Optional[str] = None,
    ) -> List[MisconfigurationFinding]:
        """Process scanner results and convert to CCSS format"""

        logger.info(f"Processing {len(check_results)} results from {scanner_name}")

        # Convert CheckResults to MisconfigurationFindings
        findings = self.converter.batch_convert_check_results(
            check_results=check_results,
            scanner_name=scanner_name,
            source_type=source_type,
            manifest_source=manifest_source,
            is_research_dataset=is_research_dataset,
        )

        self.db.save_misconfiguration_findings(findings, evaluation_run_id)

        return findings

    def process_helm_chart_results(
        self,
        scanner_name: str,
        check_results: List[CheckResult],
        chart_path: str,
        is_research_dataset: bool = False,
        evaluation_run_id: Optional[str] = None,
    ) -> List[MisconfigurationFinding]:
        """Process results from Helm chart scanning"""

        chart_info = self.converter.extract_chart_info_from_path(chart_path)

        findings = []
        for result in check_results:
            finding = self.converter.create_research_finding_from_result(
                check_result=result, scanner_name=scanner_name, chart_info=chart_info
            )
            finding.is_research_dataset = is_research_dataset
            findings.append(finding)

        # Save to database
        self.db.save_misconfiguration_findings(findings, evaluation_run_id)

        return findings

    def calculate_scanner_alignment(
        self, scanner_name: str, evaluation_run_id: Optional[str] = None
    ) -> Optional[ScannerCCSSAlignment]:
        """Calculate CCSS alignment for a scanner"""

        # Get findings for this scanner
        findings = self.db.get_misconfiguration_findings(scanner_name=scanner_name, evaluation_run_id=evaluation_run_id)

        if not findings:
            logger.warning(f"No findings found for scanner {scanner_name}")
            return None

        # Filter findings that have both native and CCSS scores
        scored_findings = [f for f in findings if f.native_score is not None and f.ccss_score is not None]

        if not scored_findings:
            logger.warning(f"No scored findings found for scanner {scanner_name}")
            return None

        # Calculate alignment scores
        alignment_scores = []
        category_scores = {}

        for finding in scored_findings:
            if finding.alignment_score is not None:
                alignment_scores.append(finding.alignment_score)

                if finding.category not in category_scores:
                    category_scores[finding.category] = []
                category_scores[finding.category].append(finding.alignment_score)

        if not alignment_scores:
            logger.warning(f"No alignment scores calculated for scanner {scanner_name}")
            return None

        avg_alignment = statistics.mean(alignment_scores)
        score_variance = statistics.variance(alignment_scores) if len(alignment_scores) > 1 else 0.0

        category_averages = {cat: statistics.mean(scores) for cat, scores in category_scores.items()}
        sorted_categories = sorted(category_averages.items(), key=lambda x: x[1], reverse=True)

        best_categories = [cat for cat, _ in sorted_categories[:3]]
        worst_categories = [cat for cat, _ in sorted_categories[-3:]]

        correlation = self._calculate_simple_correlation(scored_findings)

        alignment = ScannerCCSSAlignment(
            scanner_name=scanner_name,
            total_findings=len(findings),
            avg_alignment_score=avg_alignment,
            score_variance=score_variance,
            best_aligned_categories=best_categories,
            worst_aligned_categories=worst_categories,
            overall_ccss_correlation=correlation,
            evaluation_run_id=evaluation_run_id,
        )

        # Save to database
        self.db.save_scanner_alignment(alignment, evaluation_run_id)

        return alignment

    def _calculate_simple_correlation(self, findings: List[MisconfigurationFinding]) -> float:
        """Simple correlation calculation between native and CCSS scores"""
        if len(findings) < 2:
            return 0.0

        native_scores = [f.native_score for f in findings if f.native_score is not None and f.ccss_score is not None]
        ccss_scores = [f.ccss_score for f in findings if f.native_score is not None and f.ccss_score is not None]

        if len(native_scores) < 2:
            return 0.0

        # Simple Pearson correlation calculation
        n = len(native_scores)
        sum_native = sum(native_scores)
        sum_ccss = sum(ccss_scores)
        sum_native_sq = sum(x * x for x in native_scores)
        sum_ccss_sq = sum(x * x for x in ccss_scores)
        sum_products = sum(native_scores[i] * ccss_scores[i] for i in range(n))

        numerator = n * sum_products - sum_native * sum_ccss
        denominator = ((n * sum_native_sq - sum_native**2) * (n * sum_ccss_sq - sum_ccss**2)) ** 0.5

        if denominator == 0:
            return 0.0

        return numerator / denominator

    def simulate_ccss_scoring(self, findings: List[MisconfigurationFinding]) -> List[MisconfigurationFinding]:
        """Simulate CCSS scoring for development/testing purposes"""

        logger.info(f"Simulating CCSS scores for {len(findings)} findings")

        for finding in findings:
            if finding.native_score is not None:
                # Simulate CCSS score with some variance from native score
                import random

                variance_factor = random.uniform(0.8, 1.2)
                finding.ccss_score = min(10.0, max(0.0, finding.native_score * variance_factor))

                # Calculate simple alignment score
                if finding.ccss_score > 0:
                    finding.alignment_score = 1.0 - abs(finding.native_score - finding.ccss_score) / 10.0
                else:
                    finding.alignment_score = 0.0

        return findings

    def get_research_evaluation_summary(self, evaluation_run_id: Optional[str] = None) -> Dict[str, Any]:
        """Get summary statistics for research evaluation"""

        stats = self.db.get_alignment_statistics(evaluation_run_id)
        alignments = self.db.get_scanner_alignment_summary(evaluation_run_id)

        return {
            "overall_statistics": stats,
            "scanner_rankings": alignments,
            "total_scanners": len(alignments),
            "evaluation_run_id": evaluation_run_id,
        }

    def get_findings_for_scanner(self, scanner_name: str, research_only: bool = False) -> List[MisconfigurationFinding]:
        """Get findings for a specific scanner"""
        return self.db.get_misconfiguration_findings(scanner_name=scanner_name, research_dataset_only=research_only)

    def cleanup_old_data(self, keep_latest: int = 50):
        """Clean up old evaluation runs"""
        self.db.cleanup_old_runs(keep_latest)
