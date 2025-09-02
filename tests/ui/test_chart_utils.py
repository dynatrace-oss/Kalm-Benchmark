import pandas as pd
import pytest

from kalm_benchmark.ui.visualization.chart_utils import create_severity_pie_chart


class TestSeverityPieChart:
    """Test pie chart creation for severity distribution analysis."""

    def test_create_pie_chart_with_total_column(self):
        """Test pie chart creation with proper Total column"""
        scanner_data = pd.DataFrame(
            {
                "Scanner": ["Trivy", "Trivy", "Trivy"],
                "Severity": ["HIGH", "MEDIUM", "LOW"],
                "Count": [10, 5, 2],
                "Total": [17, 17, 17],
                "Percentage": [58.8, 29.4, 11.8],
            }
        )

        chart = create_severity_pie_chart(scanner_data, "Trivy")

        assert chart is not None
        chart_dict = chart.to_dict()
        assert "Trivy - 17 findings" in chart_dict["title"]
        assert chart_dict["mark"]["type"] == "arc"
        assert "theta" in chart_dict["encoding"]
        assert "color" in chart_dict["encoding"]

    def test_create_pie_chart_without_total_column(self):
        """Test pie chart creation without Total column - should calculate from Count sum"""
        scanner_data = pd.DataFrame(
            {
                "Scanner": ["Checkov", "Checkov"],
                "Severity": ["CRITICAL", "HIGH"],
                "Count": [8, 12],
                "Percentage": [40.0, 60.0],
            }
        )

        chart = create_severity_pie_chart(scanner_data, "Checkov")

        assert chart is not None
        assert "Checkov - 20 findings" in chart.to_dict()["title"]

    def test_create_pie_chart_with_na_total_column(self):
        """Test pie chart creation with Total column containing NaN values"""
        scanner_data = pd.DataFrame(
            {
                "Scanner": ["Polaris"],
                "Severity": ["MEDIUM"],
                "Count": [5],
                "Total": [None],  # This will become NaN
                "Percentage": [100.0],
            }
        )

        chart = create_severity_pie_chart(scanner_data, "Polaris")

        assert chart is not None
        assert "Polaris - 5 findings" in chart.to_dict()["title"]

    def test_create_pie_chart_empty_dataframe(self):
        """Test pie chart creation with empty dataframe raises ValueError"""
        empty_data = pd.DataFrame()

        with pytest.raises(ValueError, match="No data available for scanner: TestScanner"):
            create_severity_pie_chart(empty_data, "TestScanner")

    def test_create_pie_chart_no_count_column(self):
        """Test pie chart creation without Count column - should default to 0"""
        scanner_data = pd.DataFrame({"Scanner": ["NoCount"], "Severity": ["LOW"], "Percentage": [100.0]})

        chart = create_severity_pie_chart(scanner_data, "NoCount")

        assert chart is not None
        assert "NoCount - 0 findings" in chart.to_dict()["title"]

    def test_severity_color_encoding(self):
        """Test that severity colors are properly encoded"""
        scanner_data = pd.DataFrame({"Scanner": ["Trivy"], "Severity": ["CRITICAL"], "Count": [5], "Total": [5]})

        chart = create_severity_pie_chart(scanner_data, "Trivy")
        chart_dict = chart.to_dict()

        # Check color encoding
        assert chart_dict["encoding"]["color"]["field"] == "Severity"
        assert chart_dict["encoding"]["color"]["type"] == "nominal"
        assert "scale" in chart_dict["encoding"]["color"]

        # Check tooltip includes required fields
        tooltip_fields = [tooltip["field"] for tooltip in chart_dict["encoding"]["tooltip"]]
        assert "Severity" in tooltip_fields
        assert "Count" in tooltip_fields
        assert "Percentage" in tooltip_fields
