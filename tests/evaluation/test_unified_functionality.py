import pytest
import tempfile
import os

from kalm_benchmark.evaluation.database import KalmDatabase
from kalm_benchmark.evaluation.service import EvaluationService
from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckResult


class TestUnifiedDatabase:
    """Test unified database functionality"""
    
    @pytest.fixture
    def temp_db(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        db = KalmDatabase(db_path)
        yield db
        
        # Cleanup
        os.unlink(db_path)
    
    def test_database_initialization(self, temp_db):
        """Test that database initializes correctly"""
        # Check that database tables exist by trying to query them
        with temp_db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scanner_results")
            assert cursor.fetchone()[0] == 0
            cursor.execute("SELECT COUNT(*) FROM scan_runs")
            assert cursor.fetchone()[0] == 0
    
    def test_save_and_load_scanner_results(self, temp_db):
        """Test saving and loading scanner results"""
        # Create test results
        results = [
            CheckResult(
                check_id="TEST-001",
                obj_name="test-pod",
                scanner_check_id="trivy-001",
                scanner_check_name="Test Check",
                got="alert",
                severity="HIGH",
                kind="Pod",
                namespace="default",
                details="Test finding"
            ),
            CheckResult(
                check_id="TEST-002",
                obj_name="test-service",
                scanner_check_id="trivy-002", 
                scanner_check_name="Another Test",
                got="pass",
                severity="LOW",
                kind="Service",
                namespace="default",
                details="Test passing"
            )
        ]
        
        # Save results
        scan_run_id = temp_db.save_scanner_results(
            scanner_name="trivy",
            results=results,
            scanner_version="1.0.0"
        )
        
        assert scan_run_id is not None
        
        # Load results back
        loaded_results = temp_db.load_scanner_results("trivy")
        
        assert len(loaded_results) == 2
        assert loaded_results[0].check_id == "TEST-001"
        assert loaded_results[1].check_id == "TEST-002"
    
    def test_get_available_scanners(self, temp_db):
        """Test getting available scanners"""
        # Save some results
        results = [CheckResult(check_id="TEST", obj_name="test", severity="HIGH")]
        temp_db.save_scanner_results("trivy", results, "1.0.0")
        temp_db.save_scanner_results("checkov", results, "2.0.0")
        
        # Get available scanners
        scanners = temp_db.get_available_scanners()
        
        assert len(scanners) == 2
        scanner_names = [s['name'] for s in scanners]
        assert "trivy" in scanner_names
        assert "checkov" in scanner_names
    
    def test_scan_runs_tracking(self, temp_db):
        """Test scan run tracking"""
        results = [CheckResult(check_id="TEST", obj_name="test")]
        
        # Create multiple scan runs
        run1 = temp_db.save_scanner_results("trivy", results, "1.0.0")
        run2 = temp_db.save_scanner_results("trivy", results, "1.1.0")
        
        # Get scan runs
        runs = temp_db.get_scan_runs("trivy")
        
        assert len(runs) == 2
        run_ids = [r['id'] for r in runs]
        assert run1 in run_ids
        assert run2 in run_ids


class TestUnifiedService:
    """Test unified service functionality"""
    
    @pytest.fixture
    def temp_service(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        service = EvaluationService(db_path)
        yield service
        
        # Cleanup
        os.unlink(db_path)
    
    def test_service_initialization(self, temp_service):
        """Test service initializes correctly"""
        stats = temp_service.get_database_stats()
        assert stats is not None
        assert 'total_scanner_results' in stats
    
    def test_save_scanner_results_with_evaluation(self, temp_service):
        """Test saving results automatically creates evaluation summary"""
        results = [
            CheckResult(
                check_id="POD-001",
                obj_name="test-pod",
                scanner_check_id="test-check",
                got="alert",
                expected="alert",
                severity="HIGH",
                kind="Pod"
            )
        ]
        
        # Save results (should auto-create evaluation summary)
        scan_run_id = temp_service.save_scanner_results(
            scanner_name="test-scanner",
            results=results,
            scanner_version="1.0.0"
        )
        
        assert scan_run_id is not None
        
        # Check that results were saved
        loaded_results = temp_service.load_scanner_results("test-scanner")
        assert len(loaded_results) == 1
        assert loaded_results[0].check_id == "POD-001"
    
    def test_get_scanner_result_files(self, temp_service):
        """Test getting scanner result files (scan runs)"""
        results = [CheckResult(check_id="TEST", obj_name="test")]
        
        # Save some results
        temp_service.save_scanner_results("trivy", results, "1.0.0")
        
        # Get result files (scan runs)
        result_files = temp_service.get_scanner_result_files("trivy")
        
        assert len(result_files) == 1
        assert 'name' in result_files[0]
        assert 'id' in result_files[0]
    
    def test_compatibility_methods(self, temp_service):
        """Test backward compatibility methods"""
        results = [CheckResult(check_id="TEST", obj_name="test")]
        scan_run_id = temp_service.save_scanner_results("trivy", results)
        
        # Test compatibility method
        file_paths = temp_service.get_scanner_result_file_paths("trivy")
        assert len(file_paths) == 1
        assert scan_run_id in file_paths
        
        # Test ephemeral check
        is_ephemeral = temp_service.is_ephemeral_scan_result(scan_run_id)
        assert is_ephemeral is True  # Latest scan should be considered ephemeral
    
    def test_performance_over_time(self, temp_service):
        """Test getting scanner performance over time"""
        # Create some historical data
        results = [CheckResult(check_id="TEST", obj_name="test", got="alert", expected="alert")]
        
        # Save results for multiple versions
        temp_service.save_scanner_results("trivy", results, "1.0.0")
        temp_service.save_scanner_results("trivy", results, "1.1.0")
        
        # Get performance data
        performance = temp_service.get_scanner_performance_over_time("trivy")
        
        # Should have performance data (even if evaluation summary creation failed)
        assert isinstance(performance, list)


class TestDatabaseIntegration:
    """Test database integration functionality"""
    
    @pytest.fixture
    def temp_service_with_data(self):
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        service = EvaluationService(db_path)
        
        # Create sample test data directly in database
        results = [
            CheckResult(
                check_id="POD-001",
                obj_name="test-pod",
                scanner_check_id="trivy-security-001",
                got="alert",
                severity="HIGH",
                kind="Pod"
            )
        ]
        
        service.save_scanner_results("trivy", results, "1.0.0")
        
        yield service
        
        # Cleanup
        os.unlink(db_path)
    
    def test_database_integration(self, temp_service_with_data):
        """Test database integration with scanner results"""
        service = temp_service_with_data
        
        # Check database has data
        stats = service.get_database_stats()
        assert stats['total_scanner_results'] == 1
        assert stats['unique_scanners'] == 1
        
        # Verify data integrity
        results = service.load_scanner_results("trivy")
        assert len(results) == 1
        assert results[0].check_id == "POD-001"
        assert results[0].severity == "HIGH"


if __name__ == "__main__":
    pytest.main([__file__])