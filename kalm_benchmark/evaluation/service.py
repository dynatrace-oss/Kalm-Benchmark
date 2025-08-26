from typing import Any, Dict, List, Optional

from loguru import logger

from .ccss.ccss_service import CCSSService
from .database import KalmDatabase
from .evaluation import EvaluationSummary, create_summary, evaluate_scanner
from .scanner.scanner_evaluator import CheckResult
from .scanner_manager import SCANNERS


class EvaluationService:
    """Unified service that replaces file-based storage with database storage"""

    def __init__(self, db_path: str = "./data/kalm.db"):
        self.db = KalmDatabase(db_path)
        self.ccss_service = CCSSService(db_path)  # Use same database

    def _get_scanner(self, scanner_name: str):
        """Get scanner with case-insensitive lookup"""
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
        results: List[CheckResult],
        scanner_version: Optional[str] = None,
        source_file: Optional[str] = None,
    ) -> str:
        """Save scanner results and create evaluation summary"""
        # Save raw results to database
        scan_run_id = self.db.save_scanner_results(
            scanner_name=scanner_name, results=results, scanner_version=scanner_version, source_file=source_file
        )

        # Create and save evaluation summary
        scanner = self._get_scanner(scanner_name)
        if scanner:
            try:
                df = evaluate_scanner(scanner, results)
                summary = create_summary(df, version=scanner_version)

                # Get scan timestamp from database
                scan_runs = self.db.get_scan_runs(scanner_name=scanner_name, limit=1)
                scan_timestamp = scan_runs[0]["timestamp"] if scan_runs else ""

                self.db.save_evaluation_summary(
                    scanner_name=scanner_name,
                    summary=summary,
                    scan_timestamp=scan_timestamp,
                    scanner_version=scanner_version,
                )

                logger.info(f"Created evaluation summary for {scanner_name} (score: {summary.score:.3f})")

            except Exception as e:
                logger.error(f"Failed to create evaluation summary for {scanner_name}: {e}")

        return scan_run_id

    def load_scanner_results(self, scanner_name: str, scan_run_id: Optional[str] = None) -> List[CheckResult]:
        """Load scanner results from database (replaces load_scanner_results_from_file)"""
        return self.db.load_scanner_results(scanner_name, scan_run_id)

    def get_available_scanners(self) -> List[Dict[str, Any]]:
        """Get list of available scanners with results"""
        return self.db.get_available_scanners()

    def get_scanner_result_files(self, scanner_name: str) -> List[Dict[str, Any]]:
        """Get available scan runs for a scanner (replaces file listing)"""
        scan_runs = self.db.get_scan_runs(scanner_name=scanner_name)

        # Format for compatibility with existing UI expectations
        result_files = []
        for run in scan_runs:
            result_files.append(
                {
                    "name": f"{run['timestamp']} ({run['total_results']} results)",
                    "id": run["id"],
                    "timestamp": run["timestamp"],
                    "version": run["scanner_version"],
                    "total_results": run["total_results"],
                }
            )

        return result_files

    def load_scanner_summary(
        self, scanner_name: str, scan_timestamp: Optional[str] = None
    ) -> Optional[EvaluationSummary]:
        """Load evaluation summary from database (replaces _load_and_cache_scanner_summary)"""
        # Try to load from database first
        summary = self.db.load_evaluation_summary(scanner_name, scan_timestamp)

        if summary is None:
            # If not found, try to generate from raw results
            logger.info(f"Generating summary for {scanner_name}")
            results = self.load_scanner_results(scanner_name)

            if results:
                scanner = self._get_scanner(scanner_name)
                if scanner:
                    try:
                        df = evaluate_scanner(scanner, results)
                        summary = create_summary(df)

                        # Save for future use
                        scan_runs = self.db.get_scan_runs(scanner_name=scanner_name, limit=1)
                        scan_timestamp = scan_runs[0]["timestamp"] if scan_runs else ""

                        self.db.save_evaluation_summary(
                            scanner_name=scanner_name, summary=summary, scan_timestamp=scan_timestamp
                        )

                    except Exception as e:
                        logger.error(f"Failed to generate summary for {scanner_name}: {e}")

        return summary

    def create_evaluation_summary_dataframe(self) -> List[Dict[str, Any]]:
        """Create evaluation summary for overview page (replaces create_evaluation_summary)"""
        return self.db.get_all_evaluation_summaries()

    # CCSS Integration
    def process_scanner_results_with_ccss(
        self,
        scanner_name: str,
        results: List[CheckResult],
        source_type: str = "manifest",
        is_research_dataset: bool = False,
    ) -> str:
        """Process scanner results with CCSS integration"""
        scan_run_id = self.save_scanner_results(scanner_name, results)

        # Process with CCSS if needed
        if any(hasattr(r, "severity") and r.severity for r in results):
            findings = self.ccss_service.process_scanner_results(
                scanner_name=scanner_name,
                check_results=results,
                source_type=source_type,
                is_research_dataset=is_research_dataset,
            )

            logger.info(f"Processed {len(findings)} CCSS findings for {scanner_name}")

        return scan_run_id

    def cleanup_old_data(self, keep_latest: int = 50):
        """Clean up old data"""
        self.db.cleanup_old_data(keep_latest)

    def get_scanner_result_file_paths(self, scanner_name: str) -> List[str]:
        """Compatibility method that returns scan run identifiers instead of file paths"""
        scan_runs = self.db.get_scan_runs(scanner_name=scanner_name)
        return [run["id"] for run in scan_runs]

    def is_ephemeral_scan_result(self, result_identifier: str) -> bool:
        """Check if result is from latest scan (for UI compatibility)"""
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

                # Check if this is the latest scan for this scanner
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

    def get_scanner_performance_over_time(self, scanner_name: str) -> List[Dict[str, Any]]:
        """Get scanner performance metrics over time"""
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
                LIMIT 20
            """,
                (scanner_name,),
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

    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            # Get total counts
            cursor.execute("SELECT COUNT(*) FROM scanner_results")
            total_results = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM scan_runs")
            total_scan_runs = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM evaluation_summaries")
            total_summaries = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT scanner_name) FROM scanner_results")
            unique_scanners = cursor.fetchone()[0]

            # Get recent activity
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
