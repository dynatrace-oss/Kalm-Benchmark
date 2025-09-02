from loguru import logger

from kalm_benchmark.utils.helm_metrics import create_helm_evaluation_summary

from ..utils.constants import (
    DEFAULT_DATABASE_RETENTION_RUNS,
    DEFAULT_PERFORMANCE_HISTORY_LIMIT,
)
from .ccss.ccss_service import CCSSService
from .database import KalmDatabase
from .evaluation import EvaluationSummary, create_summary, evaluate_scanner
from .scanner.scanner_evaluator import CheckResult
from .scanner_manager import SCANNERS


class EvaluationService:
    """Unified service that replaces file-based storage with database storage.

    Provides centralized management of scanner results, evaluation summaries,
    and CCSS integration. Handles both benchmark manifest and Helm chart
    evaluations with appropriate metrics calculation and storage.
    """

    def __init__(self, db_path: str = None):
        """Initialize the evaluation service with database and CCSS integration.

        :param db_path: Path to the SQLite database file. If None, uses path from config.
        """
        self.db = KalmDatabase(db_path)
        self.ccss_service = CCSSService()  # Will use its own default config path

    def _get_scanner(self, scanner_name: str):
        """Get scanner instance with case-insensitive lookup.
        Performs flexible scanner lookup by trying exact match, capitalized match,
        and case-insensitive comparison to handle various naming conventions.
        """
        scanner = SCANNERS.get(scanner_name)
        if not scanner:
            scanner = SCANNERS.get(scanner_name.capitalize())
        if not scanner:
            for key in SCANNERS.keys():
                if key.lower() == scanner_name.lower():
                    scanner = SCANNERS.get(key)
                    break
        return scanner

    # Scanner Result Management (replaces JSON file operations)
    def save_scanner_results(
        self,
        scanner_name: str,
        results: list[CheckResult],
        scanner_version: str | None = None,
        source_file: str | None = None,
    ) -> str:
        """Save scanner results and create evaluation summary.

        Atomically saves scanner results to database and generates appropriate
        evaluation summary based on source type (benchmark vs Helm chart).
        Handles both traditional F1/coverage metrics and Helm-specific risk scoring.

        :param scanner_name: Name of the scanner that produced results
        :param results: list of CheckResult objects from scanner execution
        :param scanner_version: Optional version string of the scanner
        :param source_file: Optional source file or chart identifier
        :return: Unique scan run identifier for the saved results
        """
        # Save raw results to database
        scan_run_id = self.db.save_scanner_results(
            scanner_name=scanner_name, results=results, scanner_version=scanner_version, source_file=source_file
        )

        # Create and save evaluation summary using appropriate evaluation method
        scanner = self._get_scanner(scanner_name)
        if scanner:
            try:
                is_helm_chart = source_file and source_file.startswith("helm_chart:")

                if is_helm_chart:
                    # Use helm chart specific evaluation
                    summary = create_helm_evaluation_summary(
                        scanner_name=scanner_name,
                        helm_results=results,
                        unified_service=self,
                    )
                else:
                    # Use traditional benchmark evaluation
                    df = evaluate_scanner(scanner, results)
                    summary = create_summary(df, version=scanner_version)

                if summary:
                    # Get scan timestamp from database
                    scan_runs = self.db.get_scan_runs(scanner_name=scanner_name, limit=1)
                    scan_timestamp = scan_runs[0]["timestamp"] if scan_runs else ""

                    self.db.save_evaluation_summary(
                        scanner_name=scanner_name,
                        summary=summary,
                        scan_timestamp=scan_timestamp,
                        scanner_version=scanner_version,
                    )

                    evaluation_type = "helm chart" if is_helm_chart else "benchmark"
                    logger.info(
                        f"Created {evaluation_type} evaluation summary for {scanner_name} (score: {summary.score: .3f})"
                    )

            except Exception as e:
                logger.error(f"Failed to create evaluation summary for {scanner_name}: {e}")

        return scan_run_id

    def load_scanner_results(self, scanner_name: str, scan_run_id: str | None = None) -> list[CheckResult]:
        """Load scanner results from database.

        Retrieves stored scanner results with optional filtering by specific
        scan run identifier. Replaces file-based loading with database queries.

        :param scanner_name: Name of the scanner to load results for
        :param scan_run_id: Optional specific scan run identifier
        :return: list of CheckResult objects from database
        """
        return self.db.load_scanner_results(scanner_name, scan_run_id)

    def get_available_scanners(self) -> list[dict[str, any]]:
        """Get list of available scanners with results.

        Queries database to find all scanners that have stored scan results,
        providing metadata for scanner selection and overview displays.

        :return: list of scanner information dictionaries
        """
        return self.db.get_available_scanners()

    def get_scanner_result_files(
        self, scanner_name: str, source_filter: str | None = None, chart_name: str | None = None
    ) -> list[dict[str, any]]:
        """Get available scan runs for a scanner with optional filtering.

        Retrieves formatted scan run metadata for UI display, including
        source type indicators and result counts. Provides filtering
        capabilities for different scan contexts.

        :param scanner_name: Name of the scanner to get runs for
        :param source_filter: Optional filter for source type
        :param chart_name: Optional chart name filter for Helm scans
        :return: Formatted scan run information for UI
        """
        scan_runs = self.db.get_scan_runs(scanner_name=scanner_name, source_filter=source_filter, chart_name=chart_name)

        # Format for compatibility with existing UI expectations
        result_files = []
        for run in scan_runs:
            # Create display name based on source type
            if run.get("is_helm_chart"):
                chart_name_display = run.get("chart_name", "unknown")
                name = f"{run['timestamp']} - ⚓ {chart_name_display} ({run['total_results']} results)"
            elif run.get("source_file"):
                name = f"{run['timestamp']} - 📄 Custom ({run['total_results']} results)"
            else:
                name = f"{run['timestamp']} - 📊 Benchmark ({run['total_results']} results)"

            result_files.append(
                {
                    "name": name,
                    "id": run["id"],
                    "timestamp": run["timestamp"],
                    "version": run["scanner_version"],
                    "total_results": run["total_results"],
                    "source_type": run.get("source_type", "benchmark"),
                    "source_file": run.get("source_file"),
                    "is_helm_chart": run.get("is_helm_chart", False),
                    "chart_name": run.get("chart_name"),
                }
            )

        return result_files

    def load_scanner_summary(self, scanner_name: str, scan_timestamp: str | None = None) -> EvaluationSummary | None:
        """Load evaluation summary from database.
        Retrieves cached evaluation summary or generates new one from raw results
        if not found. Replaces file-based summary loading and caching.

        :param scanner_name: Name of the scanner to load summary for
        :param scan_timestamp: Optional specific timestamp to match
        :return: Evaluation summary if available, None otherwise
        """
        summary = self.db.load_evaluation_summary(scanner_name, scan_timestamp)

        if summary is None:
            logger.info(f"Generating summary for {scanner_name}")
            results = self.load_scanner_results(scanner_name)

            if results:
                scanner = self._get_scanner(scanner_name)
                if scanner:
                    try:
                        df = evaluate_scanner(scanner, results)
                        summary = create_summary(df)

                        scan_runs = self.db.get_scan_runs(scanner_name=scanner_name, limit=1)
                        scan_timestamp = scan_runs[0]["timestamp"] if scan_runs else ""

                        self.db.save_evaluation_summary(
                            scanner_name=scanner_name, summary=summary, scan_timestamp=scan_timestamp
                        )

                    except Exception as e:
                        logger.error(f"Failed to generate summary for {scanner_name}: {e}")

        return summary

    def create_evaluation_summary_dataframe(self) -> list[dict[str, any]]:
        """Create evaluation summary for overview page.
        Generates comprehensive evaluation data for all scanners including
        both benchmark and Helm chart evaluations.

        :return: Complete evaluation summary data
        """
        return self.db.get_all_evaluation_summaries()

    def create_benchmark_evaluation_summary_dataframe(self) -> list[dict[str, any]]:
        """Create evaluation summary for benchmark manifests only.
        Filters evaluation summaries to include only benchmark manifest
        evaluations, excluding Helm chart and other source types.

        :return: Benchmark-only evaluation summary data
        """
        return self.db.get_benchmark_evaluation_summaries()

    def process_scanner_results_with_ccss(
        self,
        scanner_name: str,
        results: list[CheckResult],
        source_type: str = "manifest",
        is_research_dataset: bool = False,
    ) -> str:
        """Process scanner results with CCSS integration.

        Saves scanner results and processes them through the CCSS service
        for alignment analysis and research dataset integration.

        :param scanner_name: Name of the scanner that produced results
        :param results: list of CheckResult objects to process
        :param source_type: Type of source being analyzed. Defaults to "manifest"
        :param is_research_dataset: Whether results are part of research dataset
        :return: Scan run identifier for the processed results
        """
        scan_run_id = self.save_scanner_results(scanner_name, results)

        if any(hasattr(r, "severity") and r.severity for r in results):
            findings = self.ccss_service.process_scanner_results(
                scanner_name=scanner_name,
                check_results=results,
                source_type=source_type,
                is_research_dataset=is_research_dataset,
            )

            logger.info(f"Processed {len(findings)} CCSS findings for {scanner_name}")

        return scan_run_id

    def cleanup_old_data(self, keep_latest: int = DEFAULT_DATABASE_RETENTION_RUNS):
        """Clean up old data to manage database size.

        Removes oldest scan runs and related data beyond the retention limit
        to prevent unlimited database growth.

        :param keep_latest: Number of latest scan runs to retain. Defaults to 50
        """
        self.db.cleanup_old_data(keep_latest)

    def get_scanner_result_file_paths(self, scanner_name: str) -> list[str]:
        """Get scan run identifiers for compatibility with file-based interfaces.
        Returns scan run identifiers instead of file paths to maintain
        compatibility with existing code that expects file-based storage.

        :param scanner_name: Name of the scanner to get runs for
        :return: list of scan run identifiers
        """
        scan_runs = self.db.get_scan_runs(scanner_name=scanner_name)
        return [run["id"] for run in scan_runs]

    def is_ephemeral_scan_result(self, result_identifier: str) -> bool:
        """Check if result is from the latest scan for UI compatibility.
        Determines whether a scan result identifier represents the most
        recent scan for its scanner, used for UI highlighting and caching.

        :param result_identifier: Scan run identifier to check
        :return: True if this is the latest scan for the scanner, False otherwise
        """
        if not result_identifier:
            return False

        try:
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT scanner_name, timestamp FROM scan_runs WHERE id = ?", (result_identifier,))
                result = cursor.fetchone()

                if not result:
                    return False

                scanner_name, timestamp = result["scanner_name"], result["timestamp"]

                cursor.execute(
                    """
                    SELECT MAX(timestamp) FROM scan_runs WHERE scanner_name = ?
                """,
                    (scanner_name,),
                )
                latest_timestamp = cursor.fetchone()[0]

                return timestamp == latest_timestamp

        except Exception:
            return False

    def get_scanner_performance_over_time(self, scanner_name: str) -> list[dict[str, any]]:
        """Get scanner performance metrics over time for trend analysis.
        Retrieves historical performance data including scores, coverage,
        and CCSS alignment metrics for tracking scanner evolution.

        :param scanner_name: Name of the scanner to analyze
        :return: Time series performance data
        """
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    es.scan_timestamp,
                    es.score,
                    es.coverage,
                    es.ccss_alignment_score,
                    sr.scanner_version
                FROM evaluation_summaries es
                LEFT JOIN scan_runs sr ON es.scan_timestamp = sr.timestamp
                WHERE es.scanner_name = ?
                ORDER BY es.scan_timestamp DESC
                LIMIT ?
            """,
                (scanner_name, DEFAULT_PERFORMANCE_HISTORY_LIMIT),
            )

            rows = cursor.fetchall()
            performance_data = []

            for row in rows:
                performance_data.append(
                    {
                        "timestamp": row["scan_timestamp"],
                        "score": row["score"],
                        "coverage": row["coverage"],
                        "ccss_alignment": row["ccss_alignment_score"],
                        "version": row["scanner_version"],
                    }
                )

            return performance_data

    def get_database_stats(self) -> dict[str, any]:
        """Get database statistics for monitoring and administration.
        Provides counts of stored data and recent activity information
        for database health monitoring and usage analytics.

        :return: Database statistics including counts and recent activity
        """
        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM scanner_results")
            total_results = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM scan_runs")
            total_scan_runs = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM evaluation_summaries")
            total_summaries = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT scanner_name) FROM scanner_results")
            unique_scanners = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT scanner_name, MAX(created_at) as last_activity
                FROM scan_runs
                GROUP BY scanner_name
                ORDER BY last_activity DESC
                LIMIT 5
            """
            )
            recent_activity = cursor.fetchall()

            return {
                "total_scanner_results": total_results,
                "total_scan_runs": total_scan_runs,
                "total_evaluation_summaries": total_summaries,
                "unique_scanners": unique_scanners,
                "recent_activity": [
                    {"scanner": row["scanner_name"], "last_activity": row["last_activity"]} for row in recent_activity
                ],
            }
