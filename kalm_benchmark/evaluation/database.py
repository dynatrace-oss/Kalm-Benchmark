import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from .ccss.ccss_models import MisconfigurationFinding
from .evaluation import EvaluationSummary
from .scanner.scanner_evaluator import CheckResult


class KalmDatabase:
    """Unified database for all KALM data including scanner results, evaluations, and CCSS data"""

    def __init__(self, db_path: str = "./data/kalm.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Scanner results table (replaces JSON files)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scanner_results (
                    id TEXT PRIMARY KEY,
                    scanner_name TEXT NOT NULL,
                    scanner_version TEXT,
                    check_id TEXT,
                    obj_name TEXT,
                    scanner_check_id TEXT,
                    scanner_check_name TEXT,
                    got TEXT,
                    expected TEXT,
                    checked_path TEXT,
                    severity TEXT,
                    kind TEXT,
                    namespace TEXT,
                    details TEXT,
                    extra TEXT,
                    scan_timestamp TEXT NOT NULL,
                    source_file TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Evaluation summaries table (replaces summary JSON files)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS evaluation_summaries (
                    id TEXT PRIMARY KEY,
                    scanner_name TEXT NOT NULL,
                    scanner_version TEXT,
                    score REAL NOT NULL,
                    coverage REAL NOT NULL,
                    extra_checks INTEGER NOT NULL,
                    missing_checks INTEGER NOT NULL,
                    checks_per_category TEXT NOT NULL,
                    ccss_alignment_score REAL,
                    ccss_correlation REAL,
                    total_ccss_findings INTEGER,
                    scan_timestamp TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Scan runs table (tracks individual scan executions)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id TEXT PRIMARY KEY,
                    scanner_name TEXT NOT NULL,
                    scanner_version TEXT,
                    timestamp TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_location TEXT,
                    configuration TEXT,
                    status TEXT DEFAULT 'completed',
                    total_results INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # CCSS evaluation runs
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ccss_evaluation_runs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    total_charts_scanned INTEGER,
                    scanners_evaluated TEXT,
                    configuration TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Misconfiguration findings
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS misconfiguration_findings (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_name TEXT NOT NULL,
                    scanner_name TEXT NOT NULL,
                    native_severity TEXT NOT NULL,
                    native_score REAL,
                    ccss_score REAL,
                    alignment_score REAL,
                    manifest_source TEXT DEFAULT '',
                    category TEXT DEFAULT '',
                    source_type TEXT DEFAULT 'manifest',
                    is_research_dataset BOOLEAN DEFAULT FALSE,
                    evaluation_run_id TEXT,
                    scan_run_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (evaluation_run_id) REFERENCES ccss_evaluation_runs (id),
                    FOREIGN KEY (scan_run_id) REFERENCES scan_runs (id)
                )
            """
            )

            # Scanner CCSS alignment (from original)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scanner_ccss_alignment (
                    id TEXT PRIMARY KEY,
                    scanner_name TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    avg_alignment_score REAL NOT NULL,
                    score_variance REAL NOT NULL,
                    best_aligned_categories TEXT NOT NULL,
                    worst_aligned_categories TEXT NOT NULL,
                    overall_ccss_correlation REAL NOT NULL,
                    evaluation_run_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (evaluation_run_id) REFERENCES ccss_evaluation_runs (id)
                )
            """
            )

            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scanner_results_scanner ON scanner_results(scanner_name)")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_scanner_results_timestamp ON scanner_results(scan_timestamp)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_evaluation_summaries_scanner ON evaluation_summaries(scanner_name)"
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_scanner ON scan_runs(scanner_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scanner ON misconfiguration_findings(scanner_name)")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_research ON misconfiguration_findings(is_research_dataset)"
            )

            conn.commit()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # Scanner Results Management (replaces JSON file storage)
    def save_scanner_results(
        self,
        scanner_name: str,
        results: List[CheckResult],
        scanner_version: Optional[str] = None,
        source_file: Optional[str] = None,
    ) -> str:
        """Save scanner results to database, replacing JSON file storage"""
        scan_run_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Create scan run record
            cursor.execute(
                """
                INSERT INTO scan_runs 
                (id, scanner_name, scanner_version, timestamp, source_type, source_location, total_results)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    scan_run_id,
                    scanner_name,
                    scanner_version,
                    timestamp,
                    "manifest",  # Default for now
                    source_file,
                    len(results),
                ),
            )

            # Save individual results
            for result in results:
                result_id = str(uuid.uuid4())
                cursor.execute(
                    """
                    INSERT INTO scanner_results 
                    (id, scanner_name, scanner_version, check_id, obj_name, scanner_check_id,
                     scanner_check_name, got, expected, checked_path, severity, kind, namespace,
                     details, extra, scan_timestamp, source_file)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        result_id,
                        scanner_name,
                        scanner_version,
                        result.check_id,
                        result.obj_name,
                        result.scanner_check_id,
                        result.scanner_check_name,
                        result.got,
                        result.expected,
                        result.checked_path,
                        result.severity,
                        result.kind,
                        result.namespace,
                        result.details,
                        result.extra,
                        timestamp,
                        source_file,
                    ),
                )

            conn.commit()

        logger.info(f"Saved {len(results)} scanner results for {scanner_name} (run: {scan_run_id})")
        return scan_run_id

    def load_scanner_results(
        self, scanner_name: str, scan_run_id: Optional[str] = None, latest_only: bool = True
    ) -> List[CheckResult]:
        """Load scanner results from database, replacing JSON file loading"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if scan_run_id:
                # Load specific scan run
                query = """
                    SELECT * FROM scanner_results 
                    WHERE scanner_name = ? AND scan_timestamp = (
                        SELECT timestamp FROM scan_runs WHERE id = ?
                    )
                """
                cursor.execute(query, (scanner_name, scan_run_id))
            elif latest_only:
                # Load latest scan for scanner
                query = """
                    SELECT * FROM scanner_results 
                    WHERE scanner_name = ? AND scan_timestamp = (
                        SELECT MAX(scan_timestamp) FROM scanner_results WHERE scanner_name = ?
                    )
                """
                cursor.execute(query, (scanner_name, scanner_name))
            else:
                # Load all results for scanner
                query = "SELECT * FROM scanner_results WHERE scanner_name = ?"
                cursor.execute(query, (scanner_name,))

            rows = cursor.fetchall()

            results = []
            for row in rows:
                result = CheckResult(
                    check_id=row["check_id"],
                    obj_name=row["obj_name"],
                    scanner_check_id=row["scanner_check_id"],
                    scanner_check_name=row["scanner_check_name"],
                    got=row["got"],
                    expected=row["expected"],
                    checked_path=row["checked_path"],
                    severity=row["severity"],
                    kind=row["kind"],
                    namespace=row["namespace"],
                    details=row["details"],
                    extra=row["extra"],
                )
                results.append(result)

            return results

    def get_available_scanners(self) -> List[Dict[str, Any]]:
        """Get list of scanners with available results"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    scanner_name,
                    scanner_version,
                    MAX(scan_timestamp) as latest_scan,
                    COUNT(*) as total_results
                FROM scanner_results 
                GROUP BY scanner_name, scanner_version
                ORDER BY latest_scan DESC
            """
            )

            rows = cursor.fetchall()
            scanners = []
            for row in rows:
                scanners.append(
                    {
                        "name": row["scanner_name"],
                        "version": row["scanner_version"],
                        "latest_scan": row["latest_scan"],
                        "total_results": row["total_results"],
                    }
                )

            return scanners

    def get_scan_runs(self, scanner_name: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        """Get scan run history"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if scanner_name:
                query = """
                    SELECT * FROM scan_runs 
                    WHERE scanner_name = ? 
                    ORDER BY created_at DESC 
                    LIMIT ?
                """
                cursor.execute(query, (scanner_name, limit))
            else:
                query = """
                    SELECT * FROM scan_runs 
                    ORDER BY created_at DESC 
                    LIMIT ?
                """
                cursor.execute(query, (limit,))

            rows = cursor.fetchall()
            runs = []
            for row in rows:
                runs.append(
                    {
                        "id": row["id"],
                        "scanner_name": row["scanner_name"],
                        "scanner_version": row["scanner_version"],
                        "timestamp": row["timestamp"],
                        "source_type": row["source_type"],
                        "source_location": row["source_location"],
                        "total_results": row["total_results"],
                        "status": row["status"],
                    }
                )

            return runs

    # Evaluation Summary Management (replaces summary JSON files)
    def save_evaluation_summary(
        self, scanner_name: str, summary: EvaluationSummary, scan_timestamp: str, scanner_version: Optional[str] = None
    ):
        """Save evaluation summary to database, replacing JSON summary files"""
        summary_id = str(uuid.uuid4())

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO evaluation_summaries 
                (id, scanner_name, scanner_version, score, coverage, extra_checks, missing_checks,
                 checks_per_category, ccss_alignment_score, ccss_correlation, total_ccss_findings, scan_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    summary_id,
                    scanner_name,
                    scanner_version,
                    summary.score,
                    summary.coverage,
                    summary.extra_checks,
                    summary.missing_checks,
                    json.dumps(summary.checks_per_category),
                    summary.ccss_alignment_score,
                    summary.ccss_correlation,
                    summary.total_ccss_findings,
                    scan_timestamp,
                ),
            )
            conn.commit()

        logger.info(f"Saved evaluation summary for {scanner_name}")
        return summary_id

    def load_evaluation_summary(
        self, scanner_name: str, scan_timestamp: Optional[str] = None
    ) -> Optional[EvaluationSummary]:
        """Load evaluation summary from database, replacing JSON summary loading"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if scan_timestamp:
                query = """
                    SELECT * FROM evaluation_summaries 
                    WHERE scanner_name = ? AND scan_timestamp = ?
                """
                cursor.execute(query, (scanner_name, scan_timestamp))
            else:
                # Load latest summary
                query = """
                    SELECT * FROM evaluation_summaries 
                    WHERE scanner_name = ? 
                    ORDER BY created_at DESC 
                    LIMIT 1
                """
                cursor.execute(query, (scanner_name,))

            row = cursor.fetchone()

            if not row:
                return None

            summary = EvaluationSummary(
                version=row["scanner_version"],
                checks_per_category=json.loads(row["checks_per_category"]),
                score=row["score"],
                coverage=row["coverage"],
                extra_checks=row["extra_checks"],
                missing_checks=row["missing_checks"],
                ccss_alignment_score=row["ccss_alignment_score"],
                ccss_correlation=row["ccss_correlation"],
                total_ccss_findings=row["total_ccss_findings"],
            )

            return summary

    def get_all_evaluation_summaries(self) -> List[Dict[str, Any]]:
        """Get all evaluation summaries for overview page"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    scanner_name,
                    scanner_version,
                    score,
                    coverage,
                    extra_checks,
                    missing_checks,
                    ccss_alignment_score,
                    scan_timestamp,
                    MAX(created_at) as latest_evaluation
                FROM evaluation_summaries 
                GROUP BY scanner_name
                ORDER BY score DESC
            """
            )

            rows = cursor.fetchall()
            summaries = []
            for row in rows:
                summaries.append(
                    {
                        "scanner_name": row["scanner_name"],
                        "scanner_version": row["scanner_version"],
                        "score": row["score"],
                        "coverage": row["coverage"],
                        "extra_checks": row["extra_checks"],
                        "missing_checks": row["missing_checks"],
                        "ccss_alignment_score": row["ccss_alignment_score"],
                        "scan_timestamp": row["scan_timestamp"],
                        "latest_evaluation": row["latest_evaluation"],
                    }
                )

            return summaries

    # CCSS Integration (delegate to existing CCSS functionality)
    def save_ccss_finding(self, finding: MisconfigurationFinding, evaluation_run_id: Optional[str] = None):
        """Save CCSS finding (delegates to existing CCSS database logic)"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO misconfiguration_findings 
                (id, title, description, resource_type, resource_name, scanner_name,
                 native_severity, native_score, ccss_score, alignment_score,
                 manifest_source, category, source_type, is_research_dataset, evaluation_run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    finding.id,
                    finding.title,
                    finding.description,
                    finding.resource_type,
                    finding.resource_name,
                    finding.scanner_name,
                    finding.native_severity,
                    finding.native_score,
                    finding.ccss_score,
                    finding.alignment_score,
                    finding.manifest_source,
                    finding.category,
                    finding.source_type.value,
                    finding.is_research_dataset,
                    evaluation_run_id,
                ),
            )
            conn.commit()

    def delete_scan_run(self, scan_run_id: str):
        """Delete a specific scan run and its associated data"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT timestamp FROM scan_runs WHERE id = ?", (scan_run_id,))
            result = cursor.fetchone()

            if not result:
                raise ValueError(f"Scan run {scan_run_id} not found")

            timestamp = result["timestamp"]

            # Delete related data
            cursor.execute("DELETE FROM scanner_results WHERE scan_timestamp = ?", (timestamp,))
            cursor.execute("DELETE FROM evaluation_summaries WHERE scan_timestamp = ?", (timestamp,))
            cursor.execute("DELETE FROM scan_runs WHERE id = ?", (scan_run_id,))

            conn.commit()
            logger.info(f"Deleted scan run {scan_run_id} and associated data")

    def cleanup_old_data(self, keep_latest_runs: int = 50):
        """Clean up old scan runs and results"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT id FROM scan_runs 
                ORDER BY created_at DESC 
                LIMIT -1 OFFSET ?
            """,
                (keep_latest_runs,),
            )

            old_runs = [row["id"] for row in cursor.fetchall()]

            if old_runs:
                placeholders = ",".join(["?"] * len(old_runs))
                cursor.execute(
                    f"DELETE FROM scanner_results WHERE scan_timestamp IN (SELECT timestamp FROM scan_runs WHERE id IN ({placeholders}))",
                    old_runs,
                )
                cursor.execute(
                    f"DELETE FROM evaluation_summaries WHERE scan_timestamp IN (SELECT timestamp FROM scan_runs WHERE id IN ({placeholders}))",
                    old_runs,
                )
                cursor.execute(f"DELETE FROM scan_runs WHERE id IN ({placeholders})", old_runs)

                conn.commit()
                logger.info(f"Cleaned up {len(old_runs)} old scan runs")
