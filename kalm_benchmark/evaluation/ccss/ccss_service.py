import statistics

from loguru import logger

from ..scanner.scanner_evaluator import CheckResult
from .ccss_converter import CCSSConverter
from .ccss_database import CCSSDatabase
from .ccss_models import MisconfigurationFinding, ScannerCCSSAlignment, SourceType


class CCSSService:
    """Main service for CCSS functionality - provides high-level interface.

    Orchestrates CCSS evaluation workflows including scanner result processing,
    alignment calculations, and research dataset management. Acts as the primary
    entry point for all CCSS-related operations.
    """

    def __init__(self, db_path: str = None):
        """Initialize the CCSS service.

        :param db_path: Path to the CCSS evaluation database. If None, uses path from config.
        """
        self.db = CCSSDatabase(db_path)
        self.converter = CCSSConverter()

    def process_benchmark_evaluation(self, scanner_name: str, unique_scan_checks: list[CheckResult]) -> list[MisconfigurationFinding]:
        """Process all stored scanner results for benchmark evaluations.
        """                    
        ccss_run_id = self.create_evaluation_run(SourceType.Manifest)
        findings = self.process_scanner_results(
                        scanner_name=scanner_name,
                        check_results=unique_scan_checks,
                        evaluation_run_id=ccss_run_id,
                    )
        self.calculate_scanner_alignment(scanner_name=scanner_name, evaluation_run_id=ccss_run_id)

        logger.info(f"Processed {len(findings)} CCSS findings for {scanner_name}")
        return findings

    def create_evaluation_run(self, source_type: SourceType, **kwargs) -> str:
        """Create a new CCSS evaluation run.

        :param source_type: Type of source being evaluated (manifest, helm chart, etc.)
        :param kwargs: Additional parameters passed to database creation method
        :return: Unique identifier for the created evaluation run
        """
        return self.db.create_evaluation_run(source_type, **kwargs)

    def process_scanner_results(
        self,
        scanner_name: str,
        check_results: list[CheckResult],
        source_type: SourceType = SourceType.Manifest,
        manifest_source: str = "",
        is_research_dataset: bool = False,
        evaluation_run_id: str | None = None,
    ) -> list[MisconfigurationFinding]:
        """Process scanner results and convert to CCSS format.

        :param scanner_name: Name of the scanner that produced the results
        :param check_results: list of scanner check results to process
        :param source_type: Type of source being scanned. Defaults to Manifest
        :param manifest_source: Source identifier for the manifest or chart
        :param is_research_dataset: Whether results are part of research dataset
        :param evaluation_run_id: Optional evaluation run identifier for linkage
        :return: list of processed MisconfigurationFinding objects
        """

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
        check_results: list[CheckResult],
        chart_path: str,
        is_research_dataset: bool = False,
        evaluation_run_id: str | None = None,
    ) -> list[MisconfigurationFinding]:
        """Process results from Helm chart scanning.

        Extracts chart metadata from the file path and enriches findings
        with chart context information.

        :param scanner_name: Name of the scanner that produced the results
        :param check_results: list of scanner check results from chart scanning
        :param chart_path: Path to the Helm chart file being processed
        :param is_research_dataset: Whether these results are part of a research dataset
        :param evaluation_run_id: Optional ID to associate results with a specific run
        :return: Processed findings with chart metadata
        """

        chart_info = self.converter.extract_chart_info_from_path(chart_path)

        findings = []
        for result in check_results:
            finding = self.converter.create_research_finding_from_result(
                check_result=result,
                scanner_name=scanner_name,
                chart_info=chart_info,
            )
            finding.is_research_dataset = is_research_dataset
            findings.append(finding)

        self.db.save_misconfiguration_findings(findings, evaluation_run_id)

        return findings

    def calculate_scanner_alignment(
        self, scanner_name: str, evaluation_run_id: str | None = None
    ) -> ScannerCCSSAlignment | None:
        """Calculate CCSS alignment metrics for a scanner.

        Analyzes how well a scanner's native scoring aligns with CCSS scores,
        including category-level analysis and statistical correlation.

        :param scanner_name: Name of the scanner to analyze
        :param evaluation_run_id: Optional ID to filter analysis to specific run
        :return: Alignment metrics or None if insufficient data
        """

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

        aligned_categories = category_averages
        best_categories = [cat for cat, _ in sorted_categories[:3]]
        worst_categories = [cat for cat, _ in sorted_categories[-3:]]

        correlation = self._calculate_simple_correlation(scored_findings)
        mean_squared_deviation = self._calculate_mean_squared_deviation(scored_findings)
        mean_signed_deviation = self._calculate_mean_signed_deviation(scored_findings)

        alignment = ScannerCCSSAlignment(
            scanner_name=scanner_name,
            total_findings=len(findings),
            avg_alignment_score=avg_alignment,
            score_variance=score_variance,
            aligned_categories=aligned_categories,
            best_aligned_categories=best_categories,
            worst_aligned_categories=worst_categories,
            mean_squared_deviation=mean_squared_deviation,
            mean_signed_deviation=mean_signed_deviation,
            overall_ccss_correlation=correlation,
            evaluation_run_id=evaluation_run_id,
        )

        self.db.save_scanner_alignment(alignment, evaluation_run_id)

        return alignment

    def _calculate_mean_signed_deviation(self, findings: list[MisconfigurationFinding]) -> float:
        """Calculate mean signed deviation between native and CCSS scores.

        :param findings: list of findings with both native and CCSS scores
        :return: Mean signed deviation value
        """
        if not findings:
            return 0.0

        signed_diffs = [
            (f.native_score - f.ccss_score)
            for f in findings
            if f.native_score is not None and f.ccss_score is not None
        ]

        return sum(signed_diffs) / len(signed_diffs) if signed_diffs else 0.0


    def _calculate_mean_squared_deviation(self, findings: list[MisconfigurationFinding]) -> float:
        """Calculate mean squared deviation between native and CCSS scores.

        :param findings: list of findings with both native and CCSS scores
        :return: Mean squared deviation value
        """
        if not findings:
            return 0.0

        squared_diffs = [
            (f.native_score - f.ccss_score) ** 2
            for f in findings
            if f.native_score is not None and f.ccss_score is not None
        ]

        return sum(squared_diffs) / len(squared_diffs) if squared_diffs else 0.0


    def _calculate_simple_correlation(self, findings: list[MisconfigurationFinding]) -> float:
        """Simple Pearson correlation calculation between native and CCSS scores.

        :param findings: list of findings with both native and CCSS scores
        :return: Correlation coefficient (-1 to 1), or 0.0 if insufficient data
        """
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

    def simulate_ccss_scoring(self, findings: list[MisconfigurationFinding]) -> list[MisconfigurationFinding]:
        """Simulate CCSS scoring for development/testing purposes.

        Generates mock CCSS scores based on native scores with random variance
        to enable testing of alignment calculations without real CCSS integration.

        :param findings: list of findings to simulate CCSS scores for
        :return: Findings with simulated CCSS and alignment scores
        """

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

    def get_research_evaluation_summary(self, evaluation_run_id: str | None = None) -> dict[str, any]:
        """Get comprehensive summary statistics for research evaluation.

        :param evaluation_run_id: Optional ID to filter summary to specific run
        :return: dictionary containing overall_statistics, scanner_rankings, total_scanners, and evaluation_run_id
        """

        stats = self.db.get_alignment_statistics(evaluation_run_id)
        alignments = self.db.get_scanner_alignment_summary(evaluation_run_id)

        return {
            "overall_statistics": stats,
            "scanner_rankings": alignments,
            "total_scanners": len(alignments),
            "evaluation_run_id": evaluation_run_id,
        }

    def get_findings_for_scanner(self, scanner_name: str, research_only: bool = False) -> list[MisconfigurationFinding]:
        """Get findings for a specific scanner.

        :param scanner_name: Name of the scanner to retrieve findings for
        :param research_only: If True, only return research dataset findings
        :return: Findings from the specified scanner
        """
        return self.db.get_misconfiguration_findings(scanner_name=scanner_name, research_dataset_only=research_only)

    def cleanup_old_data(self, keep_latest: int = 50):
        """Clean up old evaluation runs to manage database size.

        :param keep_latest: Number of latest evaluation runs to retain. Defaults to 50
        """
        self.db.cleanup_old_runs(keep_latest)
