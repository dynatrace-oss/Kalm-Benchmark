import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from loguru import logger

from ...utils.config import get_config
from .ccss_models import (
    CCSSEvaluationRun,
    MisconfigurationFinding,
    ScannerCCSSAlignment,
    SourceType,
)


class CCSSDatabase:
    """Database interface for CCSS evaluation data storage and retrieval.

    Manages SQLite database operations for storing scanner findings, evaluation runs,
    and alignment metrics for the Common Configuration Scoring System (CCSS).
    """

    def __init__(self, db_path: str = None):
        """Initialize the CCSS database.

        :param db_path: Path to the SQLite database file. If None, uses path from config.
        """
        if db_path is None:
            config = get_config()
            self.db_path = config.ccss_database_path
        else:
            self.db_path = Path(db_path)

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):
        """Initialize the database schema with all required tables and indexes."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

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
                    scanner_check_id TEXT NOT NULL,
                    native_severity TEXT NOT NULL,
                    native_score REAL,
                    ccss_score REAL,
                    kalm_check_id TEXT NOT NULL,
                    alignment_score REAL,
                    manifest_source TEXT DEFAULT '',
                    category TEXT DEFAULT '',
                    source_type TEXT DEFAULT 'manifest',
                    is_research_dataset BOOLEAN DEFAULT FALSE,
                    evaluation_run_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (evaluation_run_id) REFERENCES ccss_evaluation_runs (id)
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
                    aligned_categories TEXT NOT NULL,
                    best_aligned_categories TEXT NOT NULL,
                    worst_aligned_categories TEXT NOT NULL,
                    overall_ccss_correlation REAL NOT NULL,
                    mean_squared_deviation REAL,
                    mean_signed_deviation REAL,
                    evaluation_run_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (evaluation_run_id) REFERENCES ccss_evaluation_runs (id)
                )
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS category_alignment (
                    id TEXT PRIMARY KEY,
                    scanner_name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    alignment_score REAL NOT NULL,
                    findings_count INTEGER NOT NULL,
                    evaluation_run_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (evaluation_run_id) REFERENCES ccss_evaluation_runs (id)
                )
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_findings_scanner
                ON misconfiguration_findings(scanner_name)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_findings_research
                ON misconfiguration_findings(is_research_dataset)
            """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_findings_run
                ON misconfiguration_findings(evaluation_run_id)
            """
            )

            conn.commit()

    @contextmanager
    def _get_connection(self):
        """Get a database connection with proper row factory and cleanup.

        :return: Database connection with row factory enabled
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def create_evaluation_run(
        self,
        source_type: SourceType,
        total_charts_scanned: int | None = None,
        scanners_evaluated: list[str] | None = None,
        configuration: dict | None = None,
    ) -> str:
        """Create a new CCSS evaluation run record.

        :param source_type: Type of source being evaluated (manifest, helm chart, etc.)
        :param total_charts_scanned: Total number of charts scanned in this run
        :param scanners_evaluated: list of scanner names used in this evaluation
        :param configuration: Additional configuration parameters for the run
        :return: Unique identifier for the created evaluation run
        """
        run_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO ccss_evaluation_runs
                (id, timestamp, source_type, total_charts_scanned, scanners_evaluated, configuration)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    run_id,
                    timestamp,
                    source_type.value,
                    total_charts_scanned,
                    json.dumps(scanners_evaluated) if scanners_evaluated else None,
                    json.dumps(configuration) if configuration else None,
                ),
            )
            conn.commit()

        logger.info(f"Created CCSS evaluation run {run_id}")
        return run_id

    def save_misconfiguration_findings(
        self,
        findings: list[MisconfigurationFinding],
        evaluation_run_id: str | None = None,
    ):
        """Save misconfiguration findings to the database.

        :param findings: list of misconfiguration findings to save
        :param evaluation_run_id: Optional ID to associate findings with a specific run
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            for finding in findings:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO misconfiguration_findings
                    (id, title, description, resource_type, resource_name, scanner_name, scanner_check_id,
                     native_severity, native_score, ccss_score, kalm_check_id, alignment_score,
                     manifest_source, category, source_type, is_research_dataset, evaluation_run_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        finding.id,
                        finding.title,
                        finding.description,
                        finding.resource_type,
                        finding.resource_name,
                        finding.scanner_name,
                        finding.scanner_check_id,
                        finding.native_severity,
                        finding.native_score,
                        finding.ccss_score,
                        finding.kalm_check_id,
                        finding.alignment_score,
                        finding.manifest_source,
                        finding.category,
                        finding.source_type.value,
                        finding.is_research_dataset,
                        evaluation_run_id,
                    ),
                )

            conn.commit()

        logger.info(f"Saved {len(findings)} misconfiguration findings")

    def save_scanner_alignment(
        self,
        alignment: ScannerCCSSAlignment,
        evaluation_run_id: str | None = None,
    ):
        """Save scanner CCSS alignment metrics to the database.

        :param alignment: Scanner alignment metrics and statistics
        :param evaluation_run_id: Optional ID to associate alignment with a specific run
        """
        alignment_id = str(uuid.uuid4())

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scanner_ccss_alignment
                (id, scanner_name, total_findings, avg_alignment_score, score_variance, aligned_categories,
                 best_aligned_categories, worst_aligned_categories, overall_ccss_correlation,
                mean_squared_deviation, mean_signed_deviation, evaluation_run_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    alignment_id,
                    alignment.scanner_name,
                    alignment.total_findings,
                    alignment.avg_alignment_score,
                    alignment.score_variance,
                    json.dumps(alignment.aligned_categories),
                    json.dumps(alignment.best_aligned_categories),
                    json.dumps(alignment.worst_aligned_categories),
                    alignment.overall_ccss_correlation,
                    alignment.mean_squared_deviation,
                    alignment.mean_signed_deviation,
                    evaluation_run_id,
                ),
            )
            conn.commit()

        logger.info(f"Saved CCSS alignment for scanner {alignment.scanner_name}")

    def get_misconfiguration_findings(
        self,
        scanner_name: str | None = None,
        research_dataset_only: bool = False,
        evaluation_run_id: str | None = None,
    ) -> list[MisconfigurationFinding]:
        """Retrieve misconfiguration findings from the database.

        :param scanner_name: Filter by specific scanner name
        :param research_dataset_only: If True, only return research dataset findings
        :param evaluation_run_id: Filter by specific evaluation run ID
        :return: list of matching misconfiguration findings
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM misconfiguration_findings WHERE 1=1"
            params = []

            if scanner_name:
                query += " AND scanner_name = ?"
                params.append(scanner_name)

            if research_dataset_only:
                query += " AND is_research_dataset = 1"

            if evaluation_run_id:
                query += " AND evaluation_run_id = ?"
                params.append(evaluation_run_id)

            query += " GROUP BY scanner_name, kalm_check_id ORDER BY scanner_name, kalm_check_id"
            cursor.execute(query, params)
            rows = cursor.fetchall()

            findings = []
            for row in rows:
                finding = MisconfigurationFinding(
                    id=row["id"],
                    title=row["title"],
                    description=row["description"],
                    resource_type=row["resource_type"],
                    resource_name=row["resource_name"],
                    scanner_name=row["scanner_name"],
                    scanner_check_id = row["scanner_check_id"],
                    native_severity=row["native_severity"],
                    native_score=row["native_score"],
                    ccss_score=row["ccss_score"],
                    kalm_check_id = row["kalm_check_id"],
                    alignment_score=row["alignment_score"],
                    manifest_source=row["manifest_source"] or "",
                    category=row["category"] or "",
                    source_type=SourceType(row["source_type"]),
                    is_research_dataset=bool(row["is_research_dataset"]),
                )
                findings.append(finding)

            return findings

    def get_scanner_alignment_summary(self, evaluation_run_id: str | None = None) -> list[ScannerCCSSAlignment]:
        """Retrieve scanner alignment summaries ordered by alignment score.

        :param evaluation_run_id: Filter by specific evaluation run ID
        :return: list of scanner alignment summaries ordered by score
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM scanner_ccss_alignment WHERE 1=1"
            params = []

            if evaluation_run_id:
                query += " AND evaluation_run_id = ?"
                params.append(evaluation_run_id)

            query += " GROUP BY scanner_name ORDER BY avg_alignment_score DESC"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            alignments = []
            for row in rows:
                alignment = ScannerCCSSAlignment(
                    scanner_name=row["scanner_name"],
                    total_findings=row["total_findings"],
                    avg_alignment_score=row["avg_alignment_score"],
                    score_variance=row["score_variance"],
                    aligned_categories=json.loads(row["aligned_categories"]),
                    best_aligned_categories=json.loads(row["best_aligned_categories"]),
                    worst_aligned_categories=json.loads(row["worst_aligned_categories"]),
                    overall_ccss_correlation=row["overall_ccss_correlation"],
                    mean_squared_deviation=row["mean_squared_deviation"],
                    mean_signed_deviation=row["mean_signed_deviation"],
                    evaluation_run_id=row["evaluation_run_id"],
                )
                alignments.append(alignment)

            return alignments

    def get_evaluation_runs(self, limit: int = 10) -> list[CCSSEvaluationRun]:
        """Retrieve recent evaluation runs.

        :param limit: Maximum number of runs to return. Defaults to 10
        :return: list of evaluation runs ordered by creation time (newest first)
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM ccss_evaluation_runs
                ORDER BY created_at DESC
                LIMIT ?
            """,
                (limit,),
            )

            rows = cursor.fetchall()

            runs = []
            for row in rows:
                run = CCSSEvaluationRun(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    source_type=SourceType(row["source_type"]),
                    total_charts_scanned=row["total_charts_scanned"],
                    scanners_evaluated=json.loads(row["scanners_evaluated"]) if row["scanners_evaluated"] else None,
                    configuration=json.loads(row["configuration"]) if row["configuration"] else None,
                )
                runs.append(run)

            return runs

    def get_alignment_statistics(self, evaluation_run_id: str | None = None) -> dict[str, any]:
        """Get aggregate alignment statistics across all findings.

        :param evaluation_run_id: Filter by specific evaluation run ID
        :return: Dictionary containing total_findings, avg_alignment, min_alignment, max_alignment, and total_scanners
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            query_base = """
                SELECT
                    COUNT(*) as total_findings,
                    AVG(alignment_score) as avg_alignment,
                    MIN(alignment_score) as min_alignment,
                    MAX(alignment_score) as max_alignment,
                    COUNT(DISTINCT scanner_name) as total_scanners
                FROM misconfiguration_findings
                WHERE alignment_score IS NOT NULL
            """

            params = []
            if evaluation_run_id:
                query_base += " AND evaluation_run_id = ?"
                params.append(evaluation_run_id)

            cursor.execute(query_base, params)
            stats = cursor.fetchone()

            return {
                "total_findings": stats["total_findings"],
                "avg_alignment": stats["avg_alignment"],
                "min_alignment": stats["min_alignment"],
                "max_alignment": stats["max_alignment"],
                "total_scanners": stats["total_scanners"],
            }

    def cleanup_old_runs(self, keep_latest: int = 50):
        """Clean up old evaluation runs and associated data to manage database size.

        :param keep_latest: Number of latest runs to retain. Defaults to 50
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT id FROM ccss_evaluation_runs
                ORDER BY created_at DESC
                LIMIT -1 OFFSET ?
            """,
                (keep_latest,),
            )

            old_runs = [row["id"] for row in cursor.fetchall()]

            if old_runs:
                placeholders = ",".join(["?"] * len(old_runs))
                cursor.execute(
                    f"DELETE FROM misconfiguration_findings WHERE evaluation_run_id IN ({placeholders})",
                    old_runs,
                )
                cursor.execute(
                    f"DELETE FROM scanner_ccss_alignment WHERE evaluation_run_id IN ({placeholders})",
                    old_runs,
                )
                cursor.execute(
                    f"DELETE FROM category_alignment WHERE evaluation_run_id IN ({placeholders})",
                    old_runs,
                )
                cursor.execute(
                    f"DELETE FROM ccss_evaluation_runs WHERE id IN ({placeholders})",
                    old_runs,
                )

                conn.commit()
                logger.info(f"Cleaned up {len(old_runs)} old evaluation runs")
