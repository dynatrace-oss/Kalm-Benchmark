import uuid
from pathlib import Path
import re

from ..scanner.scanner_evaluator import CheckResult
from .ccss_models import MisconfigurationFinding, SourceType


class CCSSConverter:
    """Converts between existing CheckResult format and new CCSS data models.

    Provides static methods for transforming scanner output data into standardized
    CCSS format for storage and analysis.
    """

    @staticmethod
    def checkresult_to_misconfiguration_finding(
        check_result: CheckResult,
        scanner_name: str,
        source_type: SourceType = SourceType.Manifest,
        manifest_source: str = "",
        is_research_dataset: bool = False,
    ) -> MisconfigurationFinding:
        """Convert a CheckResult to MisconfigurationFinding format.

        :param check_result: The scanner check result to convert
        :param scanner_name: Name of the scanner that produced the result
        :param source_type: Type of source (manifest, helm chart, etc.). Defaults to Manifest
        :param manifest_source: Source identifier for the manifest or chart
        :param is_research_dataset: Whether this finding is part of a research dataset
        :return: Converted finding in CCSS format
        """

        finding_id = str(uuid.uuid4())

        title = check_result.scanner_check_name or check_result.check_id or "Unknown Check"
        scanner_check_id = check_result.scanner_check_id or "Unknown Check"
        kalm_check_id = re.findall(r"^([A-Z]+-\d+)", check_result.check_id.upper())[0] if check_result.check_id else "Unknown Check"
        description = check_result.details or f"Check {check_result.check_id or 'unknown'} on {check_result.obj_name}"

        resource_type = check_result.kind or "Unknown"
        resource_name = check_result.obj_name or "Unknown"

        native_score = CCSSConverter._severity_to_score(check_result.severity)

        category = check_result.check_id.split("-")[0].lower() if check_result.check_id else "unknown"

        return MisconfigurationFinding(
            id=finding_id,
            title=title,
            description=description,
            resource_type=resource_type,
            resource_name=resource_name,
            scanner_name=scanner_name,
            scanner_check_id = scanner_check_id,
            native_severity=check_result.severity or "UNKNOWN",
            native_score=native_score,
            manifest_source=manifest_source,
            kalm_check_id = kalm_check_id,
            ccss_score=float(check_result.ccss_score) if check_result.ccss_score is not None else None,
            alignment_score=(1.0 - abs(native_score - (float(check_result.ccss_score))) / 10.0) if check_result.ccss_score is not None and native_score is not None else None,
            category=category,
            source_type=source_type,
            is_research_dataset=is_research_dataset,
        )

    @staticmethod
    def batch_convert_check_results(
        check_results: list[CheckResult],
        scanner_name: str,
        source_type: SourceType = SourceType.Manifest,
        manifest_source: str = "",
        is_research_dataset: bool = False,
    ) -> list[MisconfigurationFinding]:
        """Convert a batch of CheckResults to MisconfigurationFindings.

        :param check_results: list of scanner check results to convert
        :param scanner_name: Name of the scanner that produced the results
        :param source_type: Type of source (manifest, helm chart, etc.). Defaults to Manifest
        :param manifest_source: Source identifier for the manifest or chart
        :param is_research_dataset: Whether these findings are part of a research dataset
        :return: list of converted findings in CCSS format
        """

        findings = []
        for check_result in check_results:
            finding = CCSSConverter.checkresult_to_misconfiguration_finding(
                check_result=check_result,
                scanner_name=scanner_name,
                source_type=source_type,
                manifest_source=manifest_source,
                is_research_dataset=is_research_dataset,
            )
            findings.append(finding)

        return findings

    @staticmethod
    def _severity_to_score(severity: str | None) -> float | None:
        """Convert text severity to numeric score.

        Handles various severity formats from different scanners including:
        - Standard levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        - kube-score format with parenthetical scores
        - Scanner-specific terms (danger, warning, ok, skip)

        :param severity: Text severity level from scanner output
        :return: Numeric score (0-10 scale) or None if unmappable
        """
        if not severity:
            return None

        # Standard severity mapping (includes Checkov levels)
        severity_mapping = {
            "CRITICAL": 9.0,
            "HIGH": 7.0,
            "MEDIUM": 4.0,
            "LOW": 2.0,
            "INFO": 1.0,
            "INFORMATIONAL": 1.0,
            "UNKNOWN": None,
        }

        standard_score = severity_mapping.get(severity.upper())
        if standard_score is not None:
            return standard_score

        # Handle kube-score format like "Critical (1)", "Ok (10)", "Warning (5)"
        if "(" in severity and ")" in severity:
            try:
                score_str = severity.split("(")[1].split(")")[0]
                return float(score_str)
            except (IndexError, ValueError):
                pass

        # Handle other scanner-specific formats
        severity_lower = severity.lower()
        if "critical" in severity_lower:
            return 9.0
        elif "high" in severity_lower or "danger" in severity_lower:  # Polaris uses "danger"
            return 7.0
        elif "medium" in severity_lower or "warning" in severity_lower:  # Polaris uses "warning"
            return 4.0
        elif "low" in severity_lower:
            return 2.0
        elif "info" in severity_lower or "ok" in severity_lower:
            return 1.0
        elif "skip" in severity_lower:
            return 0.0

        return None

    @staticmethod
    def extract_chart_info_from_path(file_path: str) -> dict[str, str]:
        """Extract chart name and version from Helm chart file path.

        Attempts to parse chart information from common Helm chart directory structures
        like '/charts/nginx/1.2.3/templates/deployment.yaml'.

        :param file_path: Path to a file within a Helm chart
        :return: dictionary containing 'chart_name', 'chart_version', and 'file_name'
        """
        path = Path(file_path)

        parts = path.parts

        chart_name = "unknown"
        chart_version = "unknown"

        if len(parts) >= 3:
            for i, part in enumerate(parts):
                if part == "charts" and i + 2 < len(parts):
                    chart_name = parts[i + 1]
                    chart_version = parts[i + 2]
                    break
                elif "chart" in part.lower() and i + 1 < len(parts):
                    chart_name = parts[i + 1]
                    break

        return {
            "chart_name": chart_name,
            "chart_version": chart_version,
            "file_name": path.name,
        }

    @staticmethod
    def create_research_finding_from_result(
        check_result: CheckResult, scanner_name: str, chart_info: dict[str, str]
    ) -> MisconfigurationFinding:
        """Create a research dataset finding with enriched chart information.

        Creates a MisconfigurationFinding specifically for research datasets,
        enriching the description with chart context and metadata.

        :param check_result: The scanner check result to convert
        :param scanner_name: Name of the scanner that produced the result
        :param chart_info: dictionary containing chart metadata (name, version, file_name)
        :return: Research dataset finding with enhanced metadata
        """

        finding = CCSSConverter.checkresult_to_misconfiguration_finding(
            check_result=check_result,
            scanner_name=scanner_name,
            source_type=SourceType.Helm,
            manifest_source=f"{chart_info['chart_name']}: {chart_info['chart_version']}",
            is_research_dataset=True,
        )
        finding.description = (
            f"Chart: {chart_info['chart_name']} v{chart_info['chart_version']} - {finding.description}"
        )

        return finding
