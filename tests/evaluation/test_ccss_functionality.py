import math
import os
import tempfile

import pytest

from kalm_benchmark.evaluation.ccss.ccss_converter import CCSSConverter
from kalm_benchmark.evaluation.ccss.ccss_database import CCSSDatabase
from kalm_benchmark.evaluation.ccss.ccss_models import (
    MisconfigurationFinding,
    ScannerCCSSAlignment,
    SourceType,
)
from kalm_benchmark.evaluation.ccss.ccss_service import CCSSService
from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckResult


class TestCCSSModels:
    """Test CCSS data models"""

    def test_misconfiguration_finding_creation(self):
        finding = MisconfigurationFinding(
            id="test-001",
            title="Test Finding",
            description="Test description",
            resource_type="Pod",
            resource_name="test-pod",
            scanner_name="test-scanner",
            scanner_check_id="CHK-001",
            native_severity="HIGH",
            native_score=7.0,
            ccss_score=6.5,
            alignment_score=0.85,
        )

        assert finding.id == "test-001"
        assert math.isclose(finding.native_score, 7.0)
        assert math.isclose(finding.ccss_score, 6.5)
        assert math.isclose(finding.alignment_score, 0.85)
        assert finding.source_type == SourceType.Manifest

    def test_misconfiguration_finding_serialization(self):
        finding = MisconfigurationFinding(
            id="test-002",
            title="Test Finding 2",
            description="Test description 2",
            resource_type="Deployment",
            resource_name="test-deployment",
            scanner_name="trivy",
            scanner_check_id="TRV-002",
            native_severity="MEDIUM",
        )

        # Test to_dict
        data = finding.to_dict()
        assert data["id"] == "test-002"
        assert data["scanner_name"] == "trivy"
        assert data["source_type"] == "Manifest"

        # Test from_dict
        restored = MisconfigurationFinding.from_dict(data)
        assert restored.id == finding.id
        assert restored.scanner_name == finding.scanner_name
        assert restored.source_type == finding.source_type

    def test_scanner_ccss_alignment_creation(self):
        alignment = ScannerCCSSAlignment(
            scanner_name="test-scanner",
            total_findings=100,
            avg_alignment_score=0.82,
            score_variance=0.15,
            aligned_categories=["workload", "network", "iam", "data"],
            best_aligned_categories=["workload", "network"],
            worst_aligned_categories=["iam", "data"],
            overall_ccss_correlation=0.78,
        )

        assert alignment.scanner_name == "test-scanner"
        assert alignment.total_findings == 100
        assert math.isclose(alignment.avg_alignment_score, 0.82)
        assert len(alignment.best_aligned_categories) == 2


class TestCCSSDatabase:
    """Test CCSS database functionality"""

    @pytest.fixture
    def temp_db(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        db = CCSSDatabase(db_path)
        yield db

        # Cleanup
        os.unlink(db_path)

    def test_create_evaluation_run(self, temp_db):
        run_id = temp_db.create_evaluation_run(
            source_type=SourceType.Manifest, total_charts_scanned=10, scanners_evaluated=["trivy", "checkov"]
        )

        assert run_id is not None
        assert len(run_id) > 0

        # Check that run exists
        runs = temp_db.get_evaluation_runs(limit=1)
        assert len(runs) == 1
        assert runs[0].id == run_id

    def test_save_and_retrieve_findings(self, temp_db):
        # Create test findings
        findings = [
            MisconfigurationFinding(
                id="test-001",
                title="Test Finding 1",
                description="Description 1",
                resource_type="Pod",
                resource_name="pod-1",
                scanner_name="trivy",
                scanner_check_id="TRV-001",
                native_severity="HIGH",
                native_score=8.0,
                ccss_score=7.5,
                alignment_score=0.90,
            ),
            MisconfigurationFinding(
                id="test-002",
                title="Test Finding 2",
                description="Description 2",
                resource_type="Service",
                resource_name="svc-1",
                scanner_name="checkov",
                scanner_check_id="CKV-001",
                native_severity="MEDIUM",
                native_score=5.0,
                ccss_score=4.8,
                alignment_score=0.85,
            ),
        ]

        # Save findings
        temp_db.save_misconfiguration_findings(findings)

        # Retrieve all findings
        retrieved = temp_db.get_misconfiguration_findings()
        assert len(retrieved) == 2

        # Retrieve by scanner
        trivy_findings = temp_db.get_misconfiguration_findings(scanner_name="trivy")
        assert len(trivy_findings) == 1
        assert trivy_findings[0].scanner_name == "trivy"

    def test_alignment_statistics(self, temp_db):
        # Create test finding with alignment score
        finding = MisconfigurationFinding(
            id="test-stats",
            title="Stats Test",
            description="Test for stats",
            resource_type="Pod",
            resource_name="stats-pod",
            scanner_name="test-scanner",
            scanner_check_id="STAT-001",
            native_severity="HIGH",
            alignment_score=0.75,
        )

        temp_db.save_misconfiguration_findings([finding])

        stats = temp_db.get_alignment_statistics()
        assert stats["total_findings"] == 1
        assert math.isclose(stats["avg_alignment"], 0.75)


class TestCCSSConverter:
    """Test CCSS converter functionality"""

    def test_checkresult_to_misconfiguration_finding(self):
        check_result = CheckResult(
            check_id="POD-001",
            obj_name="test-pod",
            scanner_check_id="trivy-pod-security",
            scanner_check_name="Pod Security Check",
            got="alert",
            severity="HIGH",
            kind="Pod",
            namespace="default",
            details="Container runs as root",
        )

        finding = CCSSConverter.checkresult_to_misconfiguration_finding(
            check_result=check_result, scanner_name="trivy", source_type=SourceType.Manifest
        )

        assert finding.title == "Pod Security Check"
        assert finding.resource_type == "Pod"
        assert finding.resource_name == "test-pod"
        assert finding.scanner_name == "trivy"
        assert finding.native_severity == "HIGH"
        assert math.isclose(finding.native_score, 8.0)

    def test_batch_convert_check_results(self):
        check_results = [
            CheckResult(check_id="POD-001", obj_name="pod-1", severity="HIGH", kind="Pod"),
            CheckResult(check_id="SVC-001", obj_name="svc-1", severity="MEDIUM", kind="Service"),
        ]

        findings = CCSSConverter.batch_convert_check_results(check_results=check_results, scanner_name="test-scanner")

        assert len(findings) == 2
        assert findings[0].resource_name == "pod-1"
        assert findings[1].resource_name == "svc-1"
        assert all(f.scanner_name == "test-scanner" for f in findings)

    def test_severity_to_score_mapping(self):
        # Test severity mapping
        assert math.isclose(CCSSConverter._severity_to_score("CRITICAL"), 9.5)
        assert math.isclose(CCSSConverter._severity_to_score("HIGH"), 8.0)
        assert math.isclose(CCSSConverter._severity_to_score("MEDIUM"), 6.0)
        assert math.isclose(CCSSConverter._severity_to_score("LOW"), 2.0)
        assert math.isclose(CCSSConverter._severity_to_score("INFO"), 0.1)
        assert CCSSConverter._severity_to_score("UNKNOWN") is None
        assert CCSSConverter._severity_to_score(None) is None


class TestCCSSService:
    """Test CCSS service functionality"""

    @pytest.fixture
    def temp_service(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        service = CCSSService(db_path)
        yield service

        # Cleanup
        os.unlink(db_path)

    def test_process_scanner_results(self, temp_service):
        check_results = [CheckResult(check_id="TEST-001", obj_name="test-resource", severity="HIGH", kind="Pod")]

        findings = temp_service.process_scanner_results(
            scanner_name="test-scanner", check_results=check_results, source_type=SourceType.Manifest
        )

        assert len(findings) == 1
        assert findings[0].scanner_name == "test-scanner"
        assert findings[0].source_type == SourceType.Manifest

        # Verify it was saved to database
        retrieved = temp_service.db.get_misconfiguration_findings(scanner_name="test-scanner")
        assert len(retrieved) == 1

    def test_simulate_ccss_scoring(self, temp_service):
        findings = [
            MisconfigurationFinding(
                id="test-sim",
                title="Simulation Test",
                description="Test CCSS simulation",
                resource_type="Pod",
                resource_name="sim-pod",
                scanner_name="test-scanner",
                scanner_check_id="SIM-001",
                native_severity="HIGH",
                native_score=7.0,
            )
        ]

        scored_findings = temp_service.simulate_ccss_scoring(findings)

        assert len(scored_findings) == 1
        assert scored_findings[0].ccss_score is not None
        assert scored_findings[0].alignment_score is not None
        assert 0 <= scored_findings[0].ccss_score <= 10
        assert 0 <= scored_findings[0].alignment_score <= 1

    def test_create_evaluation_run(self, temp_service):
        run_id = temp_service.create_evaluation_run(
            source_type=SourceType.Helm, total_charts_scanned=100, scanners_evaluated=["trivy", "checkov", "polaris"]
        )

        assert run_id is not None

        # Verify run was created
        runs = temp_service.db.get_evaluation_runs(limit=1)
        assert len(runs) == 1
        assert runs[0].source_type == SourceType.Helm
        assert runs[0].total_charts_scanned == 100


if __name__ == "__main__":
    pytest.main([__file__])
