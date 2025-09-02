from unittest.mock import MagicMock, patch

import pandas as pd

from kalm_benchmark.ui.analytics.coverage_utils import (
    fetch_available_coverage_data,
    get_basic_coverage_data,
    get_category_coverage_data,
    render_coverage_insights,
)
from kalm_benchmark.ui.interface.source_filter import ScanSourceType


class TestCoverageUtilsSourceFiltering:
    """Test coverage utilities with source type filtering"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_unified_service = MagicMock()

        # Mock evaluation summaries for all data
        self.all_summaries = [
            {"scanner_name": "trivy", "score": 0.8, "coverage": 0.9, "source_type": "benchmark"},
            {"scanner_name": "checkov", "score": 0.7, "coverage": 0.85, "source_type": "benchmark"},
            {"scanner_name": "trivy", "score": 0.6, "coverage": 0.75, "source_type": "helm-chart"},
            {"scanner_name": "checkov", "score": 0.65, "coverage": 0.8, "source_type": "helm-chart"},
        ]

        # Mock filtered summaries for helm charts
        self.helm_summaries = [
            {"scanner_name": "trivy", "score": 0.6, "coverage": 0.75, "source_type": "helm-chart"},
            {"scanner_name": "checkov", "score": 0.65, "coverage": 0.8, "source_type": "helm-chart"},
        ]

        # Mock filtered summaries for benchmark
        self.benchmark_summaries = [
            {"scanner_name": "trivy", "score": 0.8, "coverage": 0.9, "source_type": "benchmark"},
            {"scanner_name": "checkov", "score": 0.7, "coverage": 0.85, "source_type": "benchmark"},
        ]

    def test_get_basic_coverage_data_no_source_filter(self):
        """Test get_basic_coverage_data without source filtering returns all data"""
        self.mock_unified_service.create_evaluation_summary_dataframe.return_value = self.all_summaries

        result = get_basic_coverage_data(self.mock_unified_service)

        assert result is not None
        assert len(result) == 2  # Should aggregate by scanner name
        # Scanner names are normalized - check actual result
        scanner_names = set(result["scanner_name"])
        assert len(scanner_names) == 2
        # Normalization might change case, so check if expected scanners are present (case insensitive)
        expected_scanners = {"trivy", "checkov"}
        actual_scanners = {name.lower() for name in scanner_names}
        assert actual_scanners == expected_scanners
        self.mock_unified_service.create_evaluation_summary_dataframe.assert_called_once()

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_filtered_summaries")
    def test_get_basic_coverage_data_with_helm_source_filter(self, mock_get_filtered_summaries):
        """Test get_basic_coverage_data with helm chart source filtering"""
        mock_get_filtered_summaries.return_value = self.helm_summaries

        result = get_basic_coverage_data(self.mock_unified_service, ScanSourceType.HELM_CHARTS, "nginx")

        assert result is not None
        assert len(result) == 2  # Should aggregate by scanner name
        # Scanner names are normalized - check actual result
        scanner_names = set(result["scanner_name"])
        assert len(scanner_names) == 2
        # Normalization might change case, so check if expected scanners are present (case insensitive)
        expected_scanners = {"trivy", "checkov"}
        actual_scanners = {name.lower() for name in scanner_names}
        assert actual_scanners == expected_scanners
        mock_get_filtered_summaries.assert_called_once_with(
            self.mock_unified_service, ScanSourceType.HELM_CHARTS, "nginx"
        )
        # Should not call the unfiltered method
        self.mock_unified_service.create_evaluation_summary_dataframe.assert_not_called()

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_filtered_summaries")
    def test_get_basic_coverage_data_with_benchmark_source_filter(self, mock_get_filtered_summaries):
        """Test get_basic_coverage_data with benchmark source filtering"""
        mock_get_filtered_summaries.return_value = self.benchmark_summaries

        result = get_basic_coverage_data(self.mock_unified_service, ScanSourceType.BENCHMARK)

        assert result is not None
        assert len(result) == 2  # Should aggregate by scanner name
        # Scanner names are normalized - check actual result
        scanner_names = set(result["scanner_name"])
        assert len(scanner_names) == 2
        # Normalization might change case, so check if expected scanners are present (case insensitive)
        expected_scanners = {"trivy", "checkov"}
        actual_scanners = {name.lower() for name in scanner_names}
        assert actual_scanners == expected_scanners
        mock_get_filtered_summaries.assert_called_once_with(self.mock_unified_service, ScanSourceType.BENCHMARK, None)
        # Should not call the unfiltered method
        self.mock_unified_service.create_evaluation_summary_dataframe.assert_not_called()

    def test_get_basic_coverage_data_empty_summaries(self):
        """Test get_basic_coverage_data with empty summaries returns None"""
        self.mock_unified_service.create_evaluation_summary_dataframe.return_value = []

        result = get_basic_coverage_data(self.mock_unified_service)

        assert result is None

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_filtered_summaries")
    def test_get_basic_coverage_data_filtered_empty_summaries(self, mock_get_filtered_summaries):
        """Test get_basic_coverage_data with empty filtered summaries returns None"""
        mock_get_filtered_summaries.return_value = []

        result = get_basic_coverage_data(self.mock_unified_service, ScanSourceType.HELM_CHARTS)

        assert result is None

    def test_get_basic_coverage_data_exception_handling(self):
        """Test get_basic_coverage_data handles exceptions gracefully"""
        self.mock_unified_service.create_evaluation_summary_dataframe.side_effect = Exception("Database error")

        result = get_basic_coverage_data(self.mock_unified_service)

        assert result is None

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_basic_coverage_data", autospec=True)
    def test_fetch_available_coverage_data_no_source_filter(self, mock_get_basic):
        """Test fetch_available_coverage_data without source filtering"""
        mock_df = pd.DataFrame([{"scanner_name": "Trivy", "coverage": 0.9}])
        mock_get_basic.return_value = mock_df

        result = fetch_available_coverage_data(self.mock_unified_service)

        assert result is not None
        assert result["type"] == "basic_coverage"
        assert result["data"] is mock_df
        mock_get_basic.assert_called_once_with(self.mock_unified_service, None, None)

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_helm_chart_analysis_data")
    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_category_coverage_data", autospec=True)
    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_basic_coverage_data", autospec=True)
    def test_fetch_available_coverage_data_with_source_filter(self, mock_get_basic, mock_get_category, mock_get_helm):
        """Test fetch_available_coverage_data with source filtering"""
        # Test that Helm charts use helm_chart_analysis when available
        mock_helm_data = {"scanner_analysis": [], "summary": {}}
        mock_get_helm.return_value = mock_helm_data

        result = fetch_available_coverage_data(self.mock_unified_service, ScanSourceType.HELM_CHARTS, "nginx")

        assert result is not None
        assert result["type"] == "helm_chart_analysis"
        assert result["data"] is mock_helm_data

        # Verify helm analysis was called
        mock_get_helm.assert_called_once_with(self.mock_unified_service, "nginx")
        # Standard coverage functions should not be called when helm analysis succeeds
        mock_get_category.assert_not_called()
        mock_get_basic.assert_not_called()

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_category_coverage_data", autospec=True)
    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_basic_coverage_data", autospec=True)
    def test_fetch_available_coverage_data_tries_category_first(self, mock_get_basic, mock_get_category):
        """Test fetch_available_coverage_data tries category coverage first"""
        mock_category_data = [{"Scanner": "Trivy", "Network": 0.8, "IAM": 0.9}]
        mock_get_category.return_value = mock_category_data

        result = fetch_available_coverage_data(self.mock_unified_service)

        assert result is not None
        assert result["type"] == "category_coverage"
        assert result["data"] is mock_category_data
        mock_get_category.assert_called_once_with(self.mock_unified_service, None, None)
        mock_get_basic.assert_not_called()  # Should not fall back to basic

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_category_coverage_data", autospec=True)
    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_basic_coverage_data", autospec=True)
    def test_fetch_available_coverage_data_fallback_to_basic(self, mock_get_basic, mock_get_category):
        """Test fetch_available_coverage_data falls back to basic when category fails"""
        mock_get_category.return_value = None
        mock_df = pd.DataFrame([{"scanner_name": "Trivy", "coverage": 0.9}])
        mock_get_basic.return_value = mock_df

        result = fetch_available_coverage_data(self.mock_unified_service)

        assert result is not None
        assert result["type"] == "basic_coverage"
        assert result["data"] is mock_df
        mock_get_category.assert_called_once_with(self.mock_unified_service, None, None)
        mock_get_basic.assert_called_once_with(self.mock_unified_service, None, None)

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_category_coverage_data", autospec=True)
    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_basic_coverage_data", autospec=True)
    def test_fetch_available_coverage_data_no_data_available(self, mock_get_basic, mock_get_category):
        """Test fetch_available_coverage_data when no data is available"""
        mock_get_category.return_value = None
        mock_get_basic.return_value = None

        result = fetch_available_coverage_data(self.mock_unified_service)

        assert result is None
        mock_get_category.assert_called_once_with(self.mock_unified_service, None, None)
        mock_get_basic.assert_called_once_with(self.mock_unified_service, None, None)

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_helm_chart_analysis_data")
    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_category_coverage_data", autospec=True)
    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_basic_coverage_data", autospec=True)
    def test_fetch_available_coverage_data_source_filtering_integration(
        self, mock_get_basic, mock_get_category, mock_get_helm
    ):
        """Integration test: verify source filtering parameters are passed correctly"""
        # Make category coverage return None (fall back to basic)
        mock_get_category.return_value = None
        # Make basic coverage return data
        mock_df = pd.DataFrame([{"scanner_name": "Trivy", "coverage": 0.75}])
        mock_get_basic.return_value = mock_df

        # Test cases - Helm charts use different logic
        test_cases = [
            (ScanSourceType.BENCHMARK, None, "basic_coverage"),
            (ScanSourceType.CUSTOM_MANIFESTS, None, "basic_coverage"),
        ]

        for source_type, chart_name, expected_type in test_cases:
            mock_get_category.reset_mock()
            mock_get_basic.reset_mock()
            mock_get_helm.reset_mock()

            result = fetch_available_coverage_data(self.mock_unified_service, source_type, chart_name)

            assert result is not None
            assert result["type"] == expected_type

            # Both functions should be called with the filtering parameters
            mock_get_category.assert_called_once_with(self.mock_unified_service, source_type, chart_name)
            mock_get_basic.assert_called_once_with(self.mock_unified_service, source_type, chart_name)
            # Helm analysis should not be called for non-Helm source types
            mock_get_helm.assert_not_called()

        # Test Helm charts separately since they use different logic
        mock_get_category.reset_mock()
        mock_get_basic.reset_mock()
        mock_get_helm.reset_mock()

        # Mock helm analysis to return data
        mock_helm_data = {"scanner_analysis": [], "summary": {}}
        mock_get_helm.return_value = mock_helm_data

        result = fetch_available_coverage_data(self.mock_unified_service, ScanSourceType.HELM_CHARTS, "nginx")

        assert result is not None
        assert result["type"] == "helm_chart_analysis"

        # Helm analysis should be called
        mock_get_helm.assert_called_once_with(self.mock_unified_service, "nginx")
        # Standard coverage functions should not be called
        mock_get_category.assert_not_called()
        mock_get_basic.assert_not_called()

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_helm_chart_analysis_data")
    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_category_coverage_data", autospec=True)
    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_basic_coverage_data", autospec=True)
    def test_fetch_available_coverage_data_helm_fallback(self, mock_get_basic, mock_get_category, mock_get_helm):
        """Test that Helm charts fall back to basic coverage when helm analysis fails"""
        # Make helm analysis fail
        mock_get_helm.return_value = None
        # Make category coverage return None (fall back to basic)
        mock_get_category.return_value = None
        # Make basic coverage return data
        mock_df = pd.DataFrame([{"scanner_name": "Trivy", "coverage": 0.75}])
        mock_get_basic.return_value = mock_df

        result = fetch_available_coverage_data(self.mock_unified_service, ScanSourceType.HELM_CHARTS, "nginx")

        assert result is not None
        assert result["type"] == "basic_coverage"
        assert result["data"] is mock_df

        # Verify all functions were called in order
        mock_get_helm.assert_called_once_with(self.mock_unified_service, "nginx")
        mock_get_category.assert_called_once_with(self.mock_unified_service, ScanSourceType.HELM_CHARTS, "nginx")
        mock_get_basic.assert_called_once_with(self.mock_unified_service, ScanSourceType.HELM_CHARTS, "nginx")

    @patch("kalm_benchmark.ui.analytics.coverage_utils.get_filtered_summaries")
    def test_get_category_coverage_data_with_source_filtering(self, mock_get_filtered_summaries):
        """Test get_category_coverage_data with source type filtering"""
        # Mock filtered summaries to return specific scanners with timestamps
        mock_get_filtered_summaries.return_value = [
            {"scanner_name": "trivy", "score": 0.6, "coverage": 0.75, "scan_timestamp": "2024-01-01T10:00:00"},
            {"scanner_name": "checkov", "score": 0.65, "coverage": 0.8, "scan_timestamp": "2024-01-01T11:00:00"},
        ]

        # Mock load_scanner_summary to return valid summary for filtered scanners only
        def mock_load_summary(scanner_name, scan_timestamp=None):
            if scanner_name in ["trivy", "checkov"]:
                mock_summary = MagicMock()
                mock_summary.checks_per_category = {
                    "Network": {"Covered": 8, "Missing": 2},
                    "IAM": {"Covered": 5, "Missing": 5},
                }
                return mock_summary
            return None

        self.mock_unified_service.load_scanner_summary.side_effect = mock_load_summary

        result = get_category_coverage_data(self.mock_unified_service, ScanSourceType.HELM_CHARTS, "nginx")

        assert result is not None
        assert len(result) == 2  # Only filtered scanners

        # Verify get_filtered_summaries was called with correct parameters
        mock_get_filtered_summaries.assert_called_once_with(
            self.mock_unified_service, ScanSourceType.HELM_CHARTS, "nginx"
        )

        # Verify only relevant scanners were loaded
        assert self.mock_unified_service.load_scanner_summary.call_count == 2

    def test_get_category_coverage_data_no_source_filtering(self):
        """Test get_category_coverage_data without source filtering loads all scanners"""

        # Mock _load_all_scanner_summaries behavior by setting up the unified service
        def mock_load_summary(scanner_name):
            mock_summary = MagicMock()
            mock_summary.checks_per_category = {
                "Network": {"Covered": 8, "Missing": 2},
                "IAM": {"Covered": 5, "Missing": 5},
            }
            return mock_summary

        self.mock_unified_service.load_scanner_summary.side_effect = mock_load_summary

        # Mock the SCANNERS constant used in _load_all_scanner_summaries
        with patch("kalm_benchmark.ui.analytics.coverage_utils.SCANNERS", {"trivy": None, "checkov": None}):
            result = get_category_coverage_data(self.mock_unified_service)

            assert result is not None
            assert len(result) == 2  # All scanners

            # Should have loaded all scanners, not called get_filtered_summaries
            assert self.mock_unified_service.load_scanner_summary.call_count == 2

    @patch("kalm_benchmark.ui.analytics.coverage_utils.st")
    def test_render_coverage_insights_source_specific(self, mock_st):
        """Test render_coverage_insights with different source types"""

        # Test benchmark insights
        render_coverage_insights(ScanSourceType.BENCHMARK)

        # Verify markdown calls for benchmark
        markdown_calls = [call[0][0] for call in mock_st.markdown.call_args_list if call[0]]
        assert any("benchmark testing" in call for call in markdown_calls)
        assert any("standardized security checks" in call for call in markdown_calls)

        # Verify info call for benchmark
        info_calls = [call[0][0] for call in mock_st.info.call_args_list if call[0]]
        assert any("standardized comparison" in call for call in info_calls)

        mock_st.reset_mock()

        # Test helm chart insights
        render_coverage_insights(ScanSourceType.HELM_CHARTS)

        markdown_calls = [call[0][0] for call in mock_st.markdown.call_args_list if call[0]]
        assert any("Helm Chart Coverage Analysis" in call for call in markdown_calls)
        assert any("real-world application deployments" in call for call in markdown_calls)

        info_calls = [call[0][0] for call in mock_st.info.call_args_list if call[0]]
        assert any("real-world charts" in call for call in info_calls)

        mock_st.reset_mock()

        # Test custom manifest insights
        render_coverage_insights(ScanSourceType.CUSTOM_MANIFESTS)

        markdown_calls = [call[0][0] for call in mock_st.markdown.call_args_list if call[0]]
        assert any("custom manifest analysis" in call for call in markdown_calls)
        assert any("your specific configurations" in call for call in markdown_calls)

        info_calls = [call[0][0] for call in mock_st.info.call_args_list if call[0]]
        assert any("most actionable metric" in call for call in info_calls)

    @patch("kalm_benchmark.ui.analytics.coverage_utils.st")
    def test_render_coverage_insights_no_source_type(self, mock_st):
        """Test render_coverage_insights without source type (backward compatibility)"""

        render_coverage_insights()

        markdown_calls = [call[0][0] for call in mock_st.markdown.call_args_list if call[0]]
        assert any("overall" in call for call in markdown_calls)
        assert any("security checks each scanner can detect" in call for call in markdown_calls)

        # Should not call st.info without source type
        assert not mock_st.info.called
