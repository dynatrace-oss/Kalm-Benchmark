import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from loguru import logger

from ..utils.config import get_config
from ..utils.exceptions import DatabaseError
from .ccss.ccss_models import MisconfigurationFinding
from .evaluation import EvaluationSummary
from .scanner.scanner_evaluator import CheckResult


class KalmDatabase:
    """
    Provides centralized SQLite-based storage for scanner results, evaluation summaries,
    CCSS findings, and metadata. Replaces file-based storage with atomic database operations
    for improved reliability and performance.
    """

    def __init__(self, db_path: str = None):
        """Initialize the database with the specified path and create tables if they don't exist.

        :param db_path: Path to the SQLite database file. If None, uses path from config.
        """
        if db_path is None:
            config = get_config()
            self.db_path = config.database_path
        else:
            self.db_path = Path(db_path)

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):
        """Initialize the database schema with all required tables and indexes."""
        # Check if database is already initialized to avoid unnecessary writes
        if self._is_database_initialized():
            return

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

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
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_scanner_results_scanner ON scanner_results(scanner_name)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_scanner_results_timestamp ON scanner_results(scan_timestamp)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_evaluation_summaries_scanner ON evaluation_summaries(scanner_name)"
                )
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_scanner ON scan_runs(scanner_name)")
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_findings_scanner ON misconfiguration_findings(scanner_name)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_findings_research ON misconfiguration_findings(is_research_dataset)"
                )

                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize database: {e}")
            raise DatabaseError(f"Database initialization failed: {e}") from e

    def _is_database_initialized(self) -> bool:
        """Check if the database is already initialized by checking for core tables.

        :return: True if database is initialized, False otherwise
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name IN ('scanner_results', 'evaluation_summaries', 'scan_runs')
                    """
                )
                tables = cursor.fetchall()
                # Database is initialized if all core tables exist
                return len(tables) >= 3
        except Exception:
            return False

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections with automatic cleanup.

        :return: SQLite connection with row factory configured
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def save_scanner_results(
        self,
        scanner_name: str,
        results: list[CheckResult],
        scanner_version: str | None = None,
        source_file: str | None = None,
    ) -> str:
        """
        Atomically saves scanner results and creates corresponding scan run metadata.
        Handles both benchmark manifest and Helm chart results with conditional field semantics.

        :param scanner_name: Name of the scanner that produced the results
        :param results: list of CheckResult objects from scanner execution
        :param scanner_version: Optional version string of the scanner
        :param source_file: Optional source file or chart identifier
        :return: Unique scan run identifier for the saved results
        """
        scan_run_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        is_helm_chart = source_file and source_file.startswith("helm_chart:")
        source_type = source_file if is_helm_chart else "manifest"

        with self._get_connection() as conn:
            cursor = conn.cursor()

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
                    source_type,
                    source_file,
                    len(results),
                ),
            )

            for result in results:
                result_id = str(uuid.uuid4())

                if is_helm_chart:
                    check_id = f"HELM-{scanner_name}-{result.scanner_check_id}" if result.scanner_check_id else None
                    expected = None
                else:
                    check_id = result.check_id
                    expected = result.expected

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
                        check_id,
                        result.obj_name,
                        result.scanner_check_id,
                        result.scanner_check_name,
                        result.got,
                        expected,
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
        self, scanner_name: str, scan_run_id: str | None = None, latest_only: bool = True
    ) -> list[CheckResult]:
        """
        Retrieves scanner results with flexible filtering by scan run or timestamp.
        Reconstructs CheckResult objects from database records.

        :param scanner_name: Name of the scanner to load results for
        :param scan_run_id: Optional specific scan run identifier
        :param latest_only: Whether to load only the latest scan results. Defaults to True
        :return: list of CheckResult objects from database
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if scan_run_id:
                query = """
                    SELECT * FROM scanner_results
                    WHERE scanner_name = ? AND scan_timestamp = (
                        SELECT timestamp FROM scan_runs WHERE id = ?
                    )
                """
                cursor.execute(query, (scanner_name, scan_run_id))
            elif latest_only:
                query = """
                    SELECT * FROM scanner_results
                    WHERE scanner_name = ? AND scan_timestamp = (
                        SELECT MAX(scan_timestamp) FROM scanner_results WHERE scanner_name = ?
                    )
                """
                cursor.execute(query, (scanner_name, scanner_name))
            else:
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

    def get_available_scanners(self) -> list[dict[str, any]]:
        """
        Queries database to find all scanners that have stored results,
        including version information and scan statistics.

        :return: list of scanner dictionaries containing name, version, latest_scan, and total_results
        """
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

    def get_scan_runs(
        self,
        scanner_name: str | None = None,
        limit: int = 20,
        source_filter: str | None = None,
        chart_name: str | None = None,
    ) -> list[dict[str, any]]:
        """
        Retrieves scan run metadata with flexible filtering capabilities
        for building scan history views and analytics.

        :param scanner_name: Optional scanner name to filter results
        :param limit: Maximum number of scan runs to return. Defaults to 20
        :param source_filter: Optional filter for source type (benchmark, helm_charts, custom_manifests)
        :param chart_name: Optional chart name filter for Helm chart scans
        :return: list of scan run dictionaries with metadata including computed fields for UI convenience
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Build query based on filters
            where_conditions = []
            params = []

            if scanner_name:
                where_conditions.append("scanner_name = ?")
                params.append(scanner_name)

            where_conditions, params = self._source_filtering(source_filter, where_conditions, params)

            if chart_name:
                where_conditions.append("source_type = ?")
                params.append(chart_name)

            where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""

            query = f"""
                SELECT * FROM scan_runs
                {where_clause}
                ORDER BY created_at DESC
                LIMIT ?
            """
            params.append(limit)

            cursor.execute(query, params)

            rows = cursor.fetchall()
            runs = []
            for row in rows:
                source_location = row["source_location"] if "source_location" in row.keys() else None
                source_type = row["source_type"] if "source_type" in row.keys() else "benchmark"

                source_file = self._get_source_file(source_location, source_type)

                runs.append(
                    {
                        "id": row["id"],
                        "scanner_name": row["scanner_name"],
                        "scanner_version": row["scanner_version"],
                        "timestamp": row["timestamp"],
                        "source_type": source_type,
                        "source_location": source_location,
                        "source_file": source_file,
                        "total_results": row["total_results"],
                        "status": row["status"],
                        # Computed fields for UI convenience
                        "is_helm_chart": source_file and source_file.startswith("helm_chart:"),
                        "chart_name": (
                            source_file.replace("helm_chart:", "")
                            if source_file and source_file.startswith("helm_chart:")
                            else None
                        ),
                    }
                )

            return runs

    def _source_filtering(self, source_filter: str, where_conditions: dict, params: list):
        """Apply source type filtering to database query conditions.

        :param source_filter: Type of source filter to apply
        :param where_conditions: list of SQL WHERE conditions to modify
        :param params: list of SQL parameters to extend
        :return: Updated where_conditions and params lists
        """
        if source_filter == "benchmark":
            where_conditions.append("(source_type = ? OR source_type = ? OR source_type IS NULL)")
            params.extend(["manifest", "benchmark"])
        elif source_filter == "helm_charts":
            where_conditions.append("source_type LIKE ?")
            params.append("helm-chart:%")
        elif source_filter == "custom_manifests":
            where_conditions.append("source_type NOT LIKE ? AND source_type != ? AND source_type IS NOT NULL")
            params.extend(["helm-chart:%", "manifest"])
        return where_conditions, params

    def _get_source_file(self, source_location: str, source_type: str):
        """Generate source file identifier from location and type information.

        :param source_location: The source location string
        :param source_type: The type of source (helm_chart, manifest, etc.)
        :return: Formatted source file identifier or None
        """
        source_file = None
        if source_location and source_type == "helm_chart":
            source_file = f"helm_chart: {source_location}"
        elif source_location:
            source_file = source_location
        return source_file

    def save_evaluation_summary(
        self, scanner_name: str, summary: EvaluationSummary, scan_timestamp: str, scanner_version: str | None = None
    ):
        """
        Stores computed evaluation metrics including F1-score, coverage,
        and CCSS alignment data for performance tracking and reporting.

        :param scanner_name: Name of the scanner being evaluated
        :param summary: EvaluationSummary object containing computed metrics
        :param scan_timestamp: Timestamp linking to the corresponding scan run
        :param scanner_version: Optional scanner version for tracking
        :return: Unique identifier for the saved evaluation summary
        """
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

    def load_evaluation_summary(self, scanner_name: str, scan_timestamp: str | None = None) -> EvaluationSummary | None:
        """
        Retrieves evaluation summary with optional timestamp filtering,
        falling back to most recent summary if no timestamp specified.

        :param scanner_name: Name of the scanner to load summary for
        :param scan_timestamp: Optional specific timestamp to match
        :return: Evaluation summary if found, None otherwise
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if scan_timestamp:
                query = """
                    SELECT * FROM evaluation_summaries
                    WHERE scanner_name = ? AND scan_timestamp = ?
                """
                cursor.execute(query, (scanner_name, scan_timestamp))
            else:
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

    def get_all_evaluation_summaries(self) -> list[dict[str, any]]:
        """
        Retrieves the latest evaluation summary for each scanner,
        ordered by performance score for ranking displays.

        :return: list of evaluation summary dictionaries with all metrics and metadata
        """
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
                    ccss_correlation,
                    total_ccss_findings,
                    scan_timestamp,
                    created_at as latest_evaluation
                FROM evaluation_summaries
                WHERE (scanner_name, created_at) IN (
                    SELECT scanner_name, MAX(created_at)
                    FROM evaluation_summaries
                    GROUP BY scanner_name
                )
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
                        "ccss_correlation": row["ccss_correlation"],
                        "total_ccss_findings": row["total_ccss_findings"],
                        "scan_timestamp": row["scan_timestamp"],
                        "latest_evaluation": row["latest_evaluation"],
                    }
                )

            return summaries

    def get_benchmark_evaluation_summaries(self) -> list[dict[str, any]]:
        """
        Filters evaluation summaries to include only those from benchmark
        manifest scans, excluding Helm chart and other source evaluations.

        :return: list of benchmark evaluation summaries ordered by performance score
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT
                    es.scanner_name,
                    es.scanner_version,
                    es.score,
                    es.coverage,
                    es.extra_checks,
                    es.missing_checks,
                    es.ccss_alignment_score,
                    es.ccss_correlation,
                    es.total_ccss_findings,
                    es.scan_timestamp,
                    es.created_at as latest_evaluation
                FROM evaluation_summaries es
                INNER JOIN scan_runs sr ON es.scanner_name = sr.scanner_name AND es.scan_timestamp = sr.timestamp
                WHERE (sr.source_type = 'manifest'
                   OR sr.source_type = 'benchmark'
                   OR sr.source_type IS NULL)
                   AND sr.source_type NOT LIKE 'helm-chart:%'
                GROUP BY es.scanner_name
                HAVING es.created_at = MAX(es.created_at)
                ORDER BY es.score DESC
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
                        "ccss_correlation": row["ccss_correlation"],
                        "total_ccss_findings": row["total_ccss_findings"],
                        "scan_timestamp": row["scan_timestamp"],
                        "latest_evaluation": row["latest_evaluation"],
                    }
                )
            return summaries

    def save_ccss_finding(self, finding: MisconfigurationFinding, evaluation_run_id: str | None = None):
        """
        Stores CCSS misconfiguration finding with optional evaluation run
        association for research dataset tracking and alignment analysis.

        :param finding: MisconfigurationFinding object containing CCSS data
        :param evaluation_run_id: Optional evaluation run identifier for linkage
        """
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
        """
        Atomically removes scan run and all related data including
        scanner results and evaluation summaries.

        :param scan_run_id: Unique identifier of the scan run to delete
        :raises ValueError: If scan run is not found
        """
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
        """
        Removes oldest scan runs beyond the specified retention limit,
        cascading to all related data for space management.

        :param keep_latest_runs: Number of latest scan runs to retain. Defaults to 50
        """
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
                    f"DELETE FROM scanner_results WHERE scan_timestamp IN (SELECT timestamp\
                        FROM scan_runs WHERE id IN ({placeholders}))",
                    old_runs,
                )
                cursor.execute(
                    f"DELETE FROM evaluation_summaries WHERE scan_timestamp IN (SELECT timestamp\
                        FROM scan_runs WHERE id IN ({placeholders}))",
                    old_runs,
                )
                cursor.execute(f"DELETE FROM scan_runs WHERE id IN ({placeholders})", old_runs)

                conn.commit()
                logger.info(f"Cleaned up {len(old_runs)} old scan runs")
