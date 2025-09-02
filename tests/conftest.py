"""
Centralized test configuration and fixtures for KALM benchmark tests.

This module provides shared fixtures and configurations that can be used
across all test modules to promote consistency and reduce duplication.
"""

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
from loguru import logger

from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckStatus
from kalm_benchmark.evaluation.scanner_manager import ScannerBase, ScannerManager
from kalm_benchmark.utils.config import reset_config


class MockScanner(ScannerBase):
    """A reusable mock scanner for testing purposes."""

    def __init__(
        self,
        name: str = "mock-scanner",
        version: str = "1.0.0",
        can_scan_cluster: bool = True,
        can_scan_manifests: bool = True,
    ):
        self.NAME = name
        self._version = version
        self.can_scan_cluster = can_scan_cluster
        self.can_scan_manifests = can_scan_manifests
        self.FORMATS = ["JSON", "Pretty"]

    def get_version(self) -> str:
        return self._version

    @classmethod
    def parse_results(cls, results):
        return []

    @classmethod
    def categorize_check(cls, check_id: str | None) -> str | None:
        if check_id is None:
            return None
        return "Mock Category"


@pytest.fixture(scope="session", autouse=True)
def test_database_isolation():
    """
    Ensure all tests use an isolated temporary database instead of production database.

    This fixture automatically sets the KALM_DB_PATH environment variable to point
    to a temporary database file, preventing tests from modifying the production
    data/kalm.db file.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
        original_db_path = os.environ.get("KALM_DB_PATH")
        os.environ["KALM_DB_PATH"] = tmp_db.name

        try:
            yield tmp_db.name
        finally:
            # Restore original environment variable
            if original_db_path is not None:
                os.environ["KALM_DB_PATH"] = original_db_path
            elif "KALM_DB_PATH" in os.environ:
                del os.environ["KALM_DB_PATH"]

            # Clean up temporary database file
            try:
                Path(tmp_db.name).unlink(missing_ok=True)
            except Exception:
                pass  # Ignore cleanup errors


@pytest.fixture(scope="session")
def temp_data_dir() -> Generator[Path, None, None]:
    """
    Create a temporary directory for test data that persists for the entire test session.

    This is useful for expensive setup operations like creating test databases
    or large test datasets that can be shared across multiple tests.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture(scope="function")
def temp_test_dir(tmp_path) -> Path:
    """
    Provide a temporary directory for individual test functions.

    This fixture uses pytest's built-in tmp_path but provides a consistent
    interface across all tests.
    """
    return tmp_path


@pytest.fixture(scope="function")
def isolated_test_database():
    """
    Provide a function-scoped isolated database for tests that need clean database state.

    This fixture creates a fresh temporary database for each test function that uses it,
    ensuring complete test isolation.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
        original_db_path = os.environ.get("KALM_DB_PATH")
        original_ccss_db_path = os.environ.get("KALM_CCSS_DB_PATH")

        # Set both database paths to the same temp directory for test isolation
        temp_dir = Path(tmp_db.name).parent
        os.environ["KALM_DB_PATH"] = tmp_db.name
        os.environ["KALM_CCSS_DB_PATH"] = str(temp_dir / "ccss_test.db")

        # Reset config cache so it picks up the new environment variables
        reset_config()

        try:
            yield tmp_db.name
        finally:
            # Restore original environment variables
            if original_db_path is not None:
                os.environ["KALM_DB_PATH"] = original_db_path
            elif "KALM_DB_PATH" in os.environ:
                del os.environ["KALM_DB_PATH"]

            if original_ccss_db_path is not None:
                os.environ["KALM_CCSS_DB_PATH"] = original_ccss_db_path
            elif "KALM_CCSS_DB_PATH" in os.environ:
                del os.environ["KALM_CCSS_DB_PATH"]

            # Reset config cache again to pick up restored environment
            reset_config()

            # Clean up temporary database files
            try:
                Path(tmp_db.name).unlink(missing_ok=True)
                Path(temp_dir / "ccss_test.db").unlink(missing_ok=True)
            except Exception:
                pass


@pytest.fixture(scope="session")
def scanner_manager() -> ScannerManager:
    """
    Create a clean scanner manager instance for testing.

    This is session-scoped since scanner discovery is expensive and the
    manager state doesn't change during test execution.
    """
    manager = ScannerManager()
    return manager


@pytest.fixture(scope="function")
def mock_scanner_manager() -> ScannerManager:
    """
    Create a scanner manager with predefined mock scanners for testing.

    This fixture provides a consistent set of mock scanners that can be
    used across different test modules.
    """
    manager = ScannerManager()
    manager.scanners = {
        "mock-scanner": MockScanner("mock-scanner", "1.0.0", True, True),
        "cluster-only": MockScanner("cluster-only", "2.0.0", True, False),
        "manifests-only": MockScanner("manifests-only", "1.5.0", False, True),
        "limited-scanner": MockScanner("limited-scanner", "0.5.0", False, False),
    }

    return manager


@pytest.fixture(scope="function")
def sample_scan_results() -> pd.DataFrame:
    """
    Provide sample scan results DataFrame for testing evaluation logic.

    This fixture creates realistic test data that mimics the structure
    of actual scan results from security scanners.
    """
    return pd.DataFrame(
        {
            "check_id": ["POD-001", "POD-002", "RBAC-001", "ING-001", "PSP-001"],
            "scanner_check_id": ["check-1", "check-2", "check-3", "check-4", "check-5"],
            "expected": [CheckStatus.Alert, CheckStatus.Pass, CheckStatus.Alert, CheckStatus.Pass, CheckStatus.Alert],
            "got": [CheckStatus.Alert, CheckStatus.Pass, CheckStatus.Pass, CheckStatus.Pass, CheckStatus.Alert],
            "category": ["Workload", "Workload", "IAM", "Network", "AdmissionControl"],
            "severity": ["HIGH", "MEDIUM", "CRITICAL", "LOW", "HIGH"],
            "namespace": ["default", "kube-system", None, "default", "kube-system"],
            "name": ["test-pod-1", "test-pod-2", "test-role", "test-ingress", "test-psp"],
        }
    )


@pytest.fixture(scope="function")
def sample_confusion_matrix_data() -> Dict[str, Any]:
    """
    Provide sample data for testing confusion matrix calculations.

    Returns a dictionary with known confusion matrix values for testing
    metric calculations like precision, recall, and F1-score.
    """
    return {
        "tp": 90,  # True Positives
        "fp": 5,  # False Positives
        "tn": 85,  # True Negatives
        "fn": 10,  # False Negatives
        "expected_precision": 0.947,  # tp / (tp + fp)
        "expected_recall": 0.9,  # tp / (tp + fn)
        "expected_f1": 0.923,  # 2 * (precision * recall) / (precision + recall)
    }


@pytest.fixture(scope="function", autouse=True)
def caplog_loguru(caplog):
    """
    Configure caplog to work with loguru logging.

    This fixture automatically configures loguru to work with pytest's
    caplog fixture, enabling log testing across all test modules.
    """
    logger.remove()
    handler_id = logger.add(caplog.handler, format="{message}")
    yield caplog
    logger.remove(handler_id)


@pytest.fixture(scope="function")
def mock_datetime():
    """
    Provide a mock datetime for consistent time-based testing.

    This fixture helps test time-sensitive functionality with predictable
    datetime values.
    """
    mock_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    with patch("kalm_benchmark.utils.datetime.parsing.datetime") as mock_dt:
        mock_dt.now.return_value = mock_time
        mock_dt.fromisoformat = datetime.fromisoformat
        mock_dt.strptime = datetime.strptime
        yield mock_time


@pytest.fixture(scope="function")
def mock_subprocess_success():
    """
    Mock successful subprocess execution for scanner testing.

    This fixture provides a common pattern for mocking subprocess calls
    that return successful results.
    """
    with patch("subprocess.run") as mock_run:
        mock_process = MagicMock()
        mock_process.stdout = '{"status": "success", "results": []}'
        mock_process.returncode = 0
        mock_process.stderr = ""
        mock_run.return_value = mock_process
        yield mock_run


@pytest.fixture(scope="function")
def mock_subprocess_failure():
    """
    Mock failed subprocess execution for error testing.

    This fixture provides a common pattern for testing error handling
    in subprocess calls.
    """
    with patch("subprocess.run") as mock_run:
        mock_process = MagicMock()
        mock_process.stdout = ""
        mock_process.returncode = 1
        mock_process.stderr = "Command failed: scanner not found"
        mock_run.return_value = mock_process
        yield mock_run


# Test data factories for common test scenarios
class TestDataFactory:
    """Factory class for creating test data objects."""

    @staticmethod
    def create_scan_result(
        check_id: str = "TEST-001",
        expected: CheckStatus = CheckStatus.Alert,
        got: CheckStatus = CheckStatus.Alert,
        category: str = "Test",
        **kwargs,
    ) -> Dict[str, Any]:
        """Create a single scan result dictionary."""
        result = {
            "check_id": check_id,
            "scanner_check_id": f"scanner-{check_id.lower()}",
            "expected": expected,
            "got": got,
            "category": category,
            "severity": "MEDIUM",
            "namespace": "default",
            "name": f"test-{check_id.lower()}",
        }
        result.update(kwargs)
        return result

    @staticmethod
    def create_scanner_results(count: int = 5, **kwargs) -> pd.DataFrame:
        """Create multiple scan results as a DataFrame."""
        results = []
        for i in range(count):
            check_id = f"TEST-{i+1:03d}"
            result = TestDataFactory.create_scan_result(check_id=check_id, **kwargs)
            results.append(result)
        return pd.DataFrame(results)


@pytest.fixture
def test_data_factory():
    """Provide access to the TestDataFactory for creating test data."""
    return TestDataFactory
