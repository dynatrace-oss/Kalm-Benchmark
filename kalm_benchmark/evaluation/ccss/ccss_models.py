from dataclasses import dataclass
from enum import auto

from strenum import StrEnum


class SourceType(StrEnum):
    Manifest = auto()
    Cluster = auto()
    Helm = auto()


@dataclass
class MisconfigurationFinding:
    id: str
    title: str
    description: str
    resource_type: str
    resource_name: str
    scanner_name: str
    scanner_check_id : str
    native_severity: str
    native_score: float | None = None
    ccss_score: float | None = None
    kalm_check_id: str = ""
    alignment_score: float | None = None
    manifest_source: str = ""
    category: str = ""
    source_type: SourceType = SourceType.Manifest
    is_research_dataset: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "scanner_name": self.scanner_name,
            "scanner_check_id": self.scanner_check_id,
            "native_severity": self.native_severity,
            "native_score": self.native_score,
            "ccss_score": self.ccss_score,
            "kalm_check_id": self.kalm_check_id,
            "alignment_score": self.alignment_score,
            "manifest_source": self.manifest_source,
            "category": self.category,
            "source_type": self.source_type.value,
            "is_research_dataset": self.is_research_dataset,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MisconfigurationFinding":
        source_type = SourceType(data.get("source_type", SourceType.Manifest))
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            resource_type=data["resource_type"],
            resource_name=data["resource_name"],
            scanner_name=data["scanner_name"],
            scanner_check_id = data["scanner_check_id"],
            native_severity=data["native_severity"],
            native_score=data.get("native_score"),
            ccss_score=data.get("ccss_score"),
            kalm_check_id = data["kalm_check_id"],
            alignment_score=data.get("alignment_score"),
            manifest_source=data.get("manifest_source", ""),
            category=data.get("category", ""),
            source_type=source_type,
            is_research_dataset=data.get("is_research_dataset", False),
        )


@dataclass
class ScannerCCSSAlignment:
    scanner_name: str
    total_findings: int
    avg_alignment_score: float
    score_variance: float
    aligned_categories: list[str]
    best_aligned_categories: list[str]
    worst_aligned_categories: list[str]
    overall_ccss_correlation: float
    mean_squared_deviation: float | None = None
    mean_signed_deviation: float | None = None
    evaluation_run_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "total_findings": self.total_findings,
            "avg_alignment_score": self.avg_alignment_score,
            "score_variance": self.score_variance,
            "aligned_categories": self.aligned_categories,
            "best_aligned_categories": self.best_aligned_categories,
            "worst_aligned_categories": self.worst_aligned_categories,
            "overall_ccss_correlation": self.overall_ccss_correlation,
            "mean_squared_deviation": self.mean_squared_deviation,
            "mean_signed_deviation": self.mean_signed_deviation,
            "evaluation_run_id": self.evaluation_run_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScannerCCSSAlignment":
        return cls(
            scanner_name=data["scanner_name"],
            total_findings=data["total_findings"],
            avg_alignment_score=data["avg_alignment_score"],
            score_variance=data["score_variance"],
            aligned_categories=data["aligned_categories"],
            best_aligned_categories=data["best_aligned_categories"],
            worst_aligned_categories=data["worst_aligned_categories"],
            overall_ccss_correlation=data["overall_ccss_correlation"],
            mean_squared_deviation=data.get("mean_squared_deviation"),
            mean_signed_deviation=data.get("mean_signed_deviation"),
            evaluation_run_id=data.get("evaluation_run_id"),
        )


@dataclass
class CCSSEvaluationRun:
    id: str
    timestamp: str
    source_type: SourceType
    total_charts_scanned: int | None = None
    scanners_evaluated: list[str] | None = None
    configuration: dict | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source_type": self.source_type.value,
            "total_charts_scanned": self.total_charts_scanned,
            "scanners_evaluated": self.scanners_evaluated,
            "configuration": self.configuration,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CCSSEvaluationRun":
        source_type = SourceType(data.get("source_type", SourceType.Manifest))
        return cls(
            id=data["id"],
            timestamp=data["timestamp"],
            source_type=source_type,
            total_charts_scanned=data.get("total_charts_scanned"),
            scanners_evaluated=data.get("scanners_evaluated"),
            configuration=data.get("configuration"),
        )
