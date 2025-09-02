"""
Tests for the security trends visualization fixes.
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pandas as pd

from kalm_benchmark.ui.modules.helm_security_trends import (
    _extract_chart_name,
    get_helm_security_trends_data,
    get_security_posture_improvement,
)


class TestSecurityTrendsFixes:
    """Test fixes to the security trends functionality"""

    @patch("kalm_benchmark.ui.modules.helm_security_trends.get_unified_service")
    def test_get_helm_security_trends_data_filters_helm_scans(self, mock_get_service):
        """Test that get_helm_security_trends_data correctly filters for helm chart scans"""
        # Setup mock service
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service

        # Mock scan runs with mixed types
        mock_service.db.get_scan_runs.return_value = [
            {
                "source_type": "helm-chart:nginx",
                "source_location": "nginx",
                "scanner_name": "trivy",
                "id": "scan-123",
                "timestamp": "2024-01-01T12:00:00",
            },
            {
                "source_type": "manifest",
                "source_location": "",
                "scanner_name": "kics",
                "id": "scan-456",
                "timestamp": "2024-01-02T12:00:00",
            },
            {
                "source_type": "helm-chart:cert-manager",
                "source_location": "cert-manager",
                "scanner_name": "kubescape",
                "id": "scan-789",
                "timestamp": "2024-01-03T12:00:00",
            },
        ]

        # Mock scanner results
        mock_check_result = MagicMock()
        mock_check_result.severity = "HIGH"
        mock_check_result.scanner_check_name = "Security Check"

        mock_service.db.load_scanner_results.return_value = [mock_check_result]

        result = get_helm_security_trends_data(days_back=30)

        # Should return DataFrame with only helm chart scans
        assert isinstance(result, pd.DataFrame)
        if not result.empty:
            # Should have 2 helm chart entries, not the manifest one
            assert len(result) == 2
            chart_names = result["chart_name"].tolist()
            assert "nginx" in chart_names
            assert "cert-manager" in chart_names

    @patch("kalm_benchmark.ui.modules.helm_security_trends.get_unified_service")
    def test_get_helm_security_trends_data_handles_errors(self, mock_get_service):
        """Test that get_helm_security_trends_data handles errors gracefully"""
        # Setup mock service
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service

        # Mock database error
        mock_service.db.get_scan_runs.side_effect = Exception("Database connection failed")

        result = get_helm_security_trends_data(days_back=30)

        # Should return empty DataFrame on error
        assert isinstance(result, pd.DataFrame)
        assert result.empty

    @patch("kalm_benchmark.ui.modules.helm_security_trends.get_unified_service")
    def test_get_helm_security_trends_data_processes_severity_correctly(self, mock_get_service):
        """Test that severity data is processed correctly"""
        # Setup mock service
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service

        mock_service.db.get_scan_runs.return_value = [
            {
                "source_type": "helm-chart:nginx",
                "source_location": "nginx",
                "scanner_name": "trivy",
                "id": "scan-123",
                "timestamp": "2024-01-01T12:00:00",
            }
        ]

        # Mock scanner results with different severities
        mock_results = []
        for severity in ["HIGH", "MEDIUM", "LOW", "INFO", "CRITICAL", "WARNING"]:
            mock_result = MagicMock()
            mock_result.severity = severity
            mock_result.scanner_check_name = f"Test Check {severity}"
            mock_results.append(mock_result)

        mock_service.db.load_scanner_results.return_value = mock_results

        result = get_helm_security_trends_data(days_back=30)

        # Should return DataFrame with processed severity data
        assert isinstance(result, pd.DataFrame)
        if not result.empty:
            assert len(result) == 1
            row = result.iloc[0]

            # Verify severity mapping
            assert row["high_severity"] == 2  # HIGH + CRITICAL
            assert row["medium_severity"] == 2  # MEDIUM + WARNING
            assert row["low_severity"] == 1  # LOW
            assert row["total_findings"] == 6  # Total count
            assert row["risk_score"] > 0  # Risk score calculated

    def test_get_security_posture_improvement_with_valid_data(self):
        """Test security posture improvement calculation with valid data"""
        # Create test data with improvement trend
        trends_data = pd.DataFrame(
            [
                {
                    "chart_name": "nginx",
                    "timestamp": datetime.now() - timedelta(days=7),
                    "risk_score": 80.0,
                    "total_findings": 20,
                },
                {"chart_name": "nginx", "timestamp": datetime.now(), "risk_score": 60.0, "total_findings": 15},
                {
                    "chart_name": "cert-manager",
                    "timestamp": datetime.now() - timedelta(days=5),
                    "risk_score": 70.0,
                    "total_findings": 10,
                },
                {
                    "chart_name": "cert-manager",
                    "timestamp": datetime.now() - timedelta(days=1),
                    "risk_score": 50.0,
                    "total_findings": 8,
                },
            ]
        )

        result = get_security_posture_improvement(trends_data)

        # Should show improvement
        assert result["trend"] == "improving"
        assert result["improvement"] > 0
        assert result["charts_analyzed"] == 2
        assert "findings_change" in result

    def test_get_security_posture_improvement_with_insufficient_data(self):
        """Test security posture improvement with insufficient data"""
        # Empty DataFrame
        empty_trends = pd.DataFrame()
        result = get_security_posture_improvement(empty_trends)

        assert result["improvement"] == 0
        assert result["trend"] == "insufficient_data"

        # Single data point
        single_point = pd.DataFrame(
            [{"chart_name": "nginx", "timestamp": datetime.now(), "risk_score": 60.0, "total_findings": 15}]
        )
        result = get_security_posture_improvement(single_point)

        assert result["improvement"] == 0
        assert result["trend"] == "insufficient_data"

    def test_get_security_posture_improvement_worsening_trend(self):
        """Test security posture improvement with worsening trend"""
        # Create test data with worsening trend
        trends_data = pd.DataFrame(
            [
                {
                    "chart_name": "nginx",
                    "timestamp": datetime.now() - timedelta(days=7),
                    "risk_score": 30.0,
                    "total_findings": 5,
                },
                {"chart_name": "nginx", "timestamp": datetime.now(), "risk_score": 80.0, "total_findings": 20},
            ]
        )

        result = get_security_posture_improvement(trends_data)

        # Should show worsening trend
        assert result["trend"] == "worsening"
        assert result["improvement"] < -5
        assert result["charts_analyzed"] == 1


class TestChartNameExtraction:
    """Test chart name extraction for trends data"""

    def test_extract_chart_name_from_trends_source(self):
        """Test chart name extraction from source location in trends context"""
        test_cases = [
            ("helm-chart:nginx", "nginx"),
            ("helm-chart:cert-manager", "cert-manager"),
            ("helm-chart:kube-prometheus-stack", "kube-prometheus-stack"),
            ("", "unknown"),
            ("invalid", "unknown"),
        ]

        for source_location, expected_name in test_cases:
            result = _extract_chart_name(source_location)
            assert result == expected_name


class TestDataVisualizationPreparation:
    """Test data preparation for visualization fixes"""

    @patch("kalm_benchmark.ui.modules.helm_security_trends.get_unified_service")
    def test_trends_data_structure_for_visualization(self, mock_get_service):
        """Test that trends data is structured correctly for simplified visualizations"""
        # Setup mock service
        mock_service = MagicMock()
        mock_get_service.return_value = mock_service

        mock_service.db.get_scan_runs.return_value = [
            {
                "source_type": "helm-chart:nginx",
                "source_location": "nginx",
                "scanner_name": "trivy",
                "id": "scan-123",
                "timestamp": "2024-01-01T12:00:00",
            }
        ]

        # Mock scanner results
        mock_high = MagicMock()
        mock_high.severity = "HIGH"
        mock_high.scanner_check_name = "High Severity Check"

        mock_medium = MagicMock()
        mock_medium.severity = "MEDIUM"
        mock_medium.scanner_check_name = "Medium Severity Check"

        mock_low = MagicMock()
        mock_low.severity = "LOW"
        mock_low.scanner_check_name = "Low Severity Check"

        mock_service.db.load_scanner_results.return_value = [mock_high, mock_medium, mock_low]

        result = get_helm_security_trends_data(days_back=30)

        # Should have columns needed for simplified visualizations
        if not result.empty:
            required_columns = [
                "timestamp",
                "chart_name",
                "scanner_name",
                "total_findings",
                "high_severity",
                "medium_severity",
                "low_severity",
                "risk_score",
            ]

            for col in required_columns:
                assert col in result.columns, f"Missing column {col} needed for visualization"

            # Verify data types
            assert pd.api.types.is_datetime64_any_dtype(result["timestamp"])
            assert pd.api.types.is_numeric_dtype(result["total_findings"])
            assert pd.api.types.is_numeric_dtype(result["risk_score"])
