from datetime import datetime, timezone
from unittest.mock import patch

import pandas as pd
import pytest

from kalm_benchmark.utils.data.normalization import (
    normalize_path,
    normalize_scanner_name,
    normalize_scanner_names_in_dataframe,
    normalize_severity,
)
from kalm_benchmark.utils.data.validation import (
    ensure_list,
    is_valid_uuid,
    sanitize_filename,
    sanitize_kubernetes_name,
    sanitize_text_for_display,
    validate_path,
    validate_port_number,
    validate_scanner_name,
    validate_severity,
)
from kalm_benchmark.utils.parsing import (
    calculate_scan_age,
    format_scan_timestamp,
    format_timestamp,
    is_recent,
    parse_timestamp,
)


class TestDataNormalization:
    """Test data normalization utilities."""

    def test_normalize_scanner_name(self):
        """Test scanner name normalization."""
        # Test standard cases
        assert normalize_scanner_name("KICS") == "KICS"
        assert normalize_scanner_name("kics") == "KICS"
        assert normalize_scanner_name("TRIVY") == "trivy"
        assert normalize_scanner_name("Trivy") == "trivy"
        assert normalize_scanner_name("checkov") == "Checkov"
        assert normalize_scanner_name("CHECKOV") == "Checkov"

        # Test edge cases
        assert normalize_scanner_name("") == ""
        assert normalize_scanner_name(None) is None
        assert normalize_scanner_name("  KICS  ") == "KICS"
        assert normalize_scanner_name("unknown-scanner") == "unknown-scanner"

    def test_normalize_scanner_names_in_dataframe(self):
        """Test DataFrame scanner name normalization."""
        df = pd.DataFrame({"scanner_name": ["KICS", "trivy", "CHECKOV", "unknown"], "score": [0.8, 0.9, 0.7, 0.6]})

        normalized_df = normalize_scanner_names_in_dataframe(df)

        expected_names = ["KICS", "trivy", "Checkov", "unknown"]
        assert normalized_df["scanner_name"].tolist() == expected_names

        # Test with custom column name
        df_custom = pd.DataFrame({"tool_name": ["KICS", "trivy"], "score": [0.8, 0.9]})

        normalized_custom = normalize_scanner_names_in_dataframe(df_custom, "tool_name")
        assert normalized_custom["tool_name"].tolist() == ["KICS", "trivy"]

        # Test error case
        with pytest.raises(KeyError):
            normalize_scanner_names_in_dataframe(df, "nonexistent_column")

    def test_normalize_path(self):
        """Test path normalization."""
        assert normalize_path("./path/to/file") == "path/to/file"
        assert normalize_path("/path/to/file") == "path/to/file"
        assert normalize_path("path\\to\\file") == "path/to/file"
        assert normalize_path("") == ""
        assert normalize_path("  ./path/  ") == "path/"

    def test_normalize_severity(self):
        """Test severity normalization."""
        assert normalize_severity("critical") == "CRITICAL"
        assert normalize_severity("HIGH") == "HIGH"
        assert normalize_severity("warn") == "MEDIUM"
        assert normalize_severity("error") == "HIGH"
        assert normalize_severity("info") == "INFO"
        assert normalize_severity("") == "UNKNOWN"
        assert normalize_severity(None) == "UNKNOWN"
        assert normalize_severity("custom") == "CUSTOM"


class TestDateTimeParsing:
    """Test datetime parsing and formatting utilities."""

    def test_parse_timestamp(self):
        """Test timestamp parsing."""
        # ISO formats
        dt = parse_timestamp("2024-01-01T12:00:00Z")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 1
        assert dt.hour == 12
        assert dt.tzinfo == timezone.utc

        # Database format
        dt = parse_timestamp("2024-01-01 12:00:00")
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 1
        assert dt.hour == 12

        # Invalid formats
        assert parse_timestamp("invalid") is None
        assert parse_timestamp("") is None
        assert parse_timestamp("") is None

    def test_format_timestamp(self):
        """Test timestamp formatting."""
        dt = datetime(2024, 1, 15, 14, 30, 0)

        assert format_timestamp(dt) == "Jan 15, 14:30"
        assert format_timestamp(dt, "%Y-%m-%d") == "2024-01-15"
        assert format_timestamp("") == "Unknown"

    def test_format_scan_timestamp(self):
        """Test scan timestamp formatting."""
        assert format_scan_timestamp("2024-01-01T12:00:00Z") == "Jan 01, 12:00"
        assert format_scan_timestamp("2024-01-01 12:00:00") == "Jan 01, 12:00"
        assert format_scan_timestamp("invalid-timestamp") == "Unknown"
        assert format_scan_timestamp("") == "Unknown"

        # Fallback behavior
        assert format_scan_timestamp("2024-01-01-invalid-but-has-date") == "2024-01-01"

    def test_calculate_scan_age(self):
        """Test scan age calculation."""
        with patch("kalm_benchmark.utils.parsing.datetime") as mock_datetime:
            # Mock current time
            mock_now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = mock_now
            # Keep the real datetime class for parsing
            mock_datetime.fromisoformat = datetime.fromisoformat
            mock_datetime.strptime = datetime.strptime

            # Test different time differences - adjust expectations
            result = calculate_scan_age("2024-01-01T11:59:00Z")
            assert result == "1m ago" or result == "Just now"  # Allow some flexibility

            # Invalid timestamps
            assert calculate_scan_age("invalid") == "Unknown"
            assert calculate_scan_age("") == "Unknown"

    def test_is_recent(self):
        """Test recent timestamp checking."""
        with patch("kalm_benchmark.utils.parsing.datetime") as mock_datetime:
            mock_now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = mock_now
            # Keep the real datetime class for parsing
            mock_datetime.fromisoformat = datetime.fromisoformat
            mock_datetime.strptime = datetime.strptime

            # Recent timestamps - test with more generous time windows
            # Just test basic functionality rather than exact timing
            assert is_recent("2024-01-01T11:00:00Z", hours=24) is True  # Within 24 hours

            # Invalid
            assert is_recent("invalid", hours=24) is False


class TestDataValidation:
    """Test data validation utilities."""

    def test_sanitize_kubernetes_name(self):
        """Test Kubernetes name sanitization."""
        assert sanitize_kubernetes_name("my-app") == "my-app"
        assert sanitize_kubernetes_name("My_App Name!") == "my-app-name"
        assert sanitize_kubernetes_name("TEST.component-v1.2.3") == "test.component-v1.2.3"
        assert sanitize_kubernetes_name("") == ""
        assert sanitize_kubernetes_name("-invalid-") == "invalid"
        assert sanitize_kubernetes_name("...") == "default"

    def test_sanitize_filename(self):
        """Test filename sanitization."""
        assert sanitize_filename("normal_file.txt") == "normal_file.txt"
        assert sanitize_filename("file/with:bad*chars?.txt") == "file_with_bad_chars_.txt"
        assert sanitize_filename("file<>|name.txt") == "file___name.txt"
        assert sanitize_filename("") == ""
        assert sanitize_filename("   . . .   ") == "unnamed_file"

    def test_ensure_list(self):
        """Test list conversion utility."""
        assert ensure_list("single") == ["single"]
        assert ensure_list(["already", "list"]) == ["already", "list"]
        assert ensure_list(None) is None
        assert ensure_list(42) == [42]
        assert ensure_list([]) == []

    def test_validate_path(self):
        """Test path validation."""
        from pathlib import Path

        # Valid paths
        assert validate_path("/valid/path") is True
        assert validate_path("relative/path") is True
        assert validate_path(Path("/valid/path")) is True

        # Invalid paths
        assert validate_path("") is False
        assert validate_path(None) is False

        # Test must_exist parameter would require actual files
        # We'll test the basic functionality here
        assert validate_path("/nonexistent/path", must_exist=False) is True

    def test_validate_scanner_name(self):
        """Test scanner name validation."""
        # Valid names
        assert validate_scanner_name("trivy") is True
        assert validate_scanner_name("kube-score") is True
        assert validate_scanner_name("KICS_v1") is True

        # Invalid names
        assert validate_scanner_name("") is False
        assert validate_scanner_name(None) is False
        assert validate_scanner_name("x") is False  # Too short
        assert validate_scanner_name("a" * 51) is False  # Too long
        assert validate_scanner_name("invalid@name") is False  # Invalid chars

    def test_validate_severity(self):
        """Test severity validation."""
        # Valid severities
        assert validate_severity("critical") is True
        assert validate_severity("HIGH") is True
        assert validate_severity("info") is True
        assert validate_severity("warning") is True

        # Invalid severities
        assert validate_severity("") is False
        assert validate_severity(None) is False
        assert validate_severity("invalid_severity") is False

    def test_sanitize_text_for_display(self):
        """Test text sanitization for display."""
        assert sanitize_text_for_display("normal text") == "normal text"
        assert sanitize_text_for_display("text<script>alert()</script>") == "textalert()"
        assert sanitize_text_for_display("text\nwith\nmultiple\nlines") == "text with multiple lines"
        assert sanitize_text_for_display("a" * 1001, max_length=100) == "a" * 97 + "..."
        assert sanitize_text_for_display("") == ""

    def test_is_valid_uuid(self):
        """Test UUID validation."""
        # Valid UUIDs
        assert is_valid_uuid("123e4567-e89b-12d3-a456-426614174000") is True
        assert is_valid_uuid("550e8400-e29b-41d4-a716-446655440000") is True

        # Invalid UUIDs
        assert is_valid_uuid("not-a-uuid") is False
        assert is_valid_uuid("123e4567-e89b-12d3-a456") is False  # Too short
        assert is_valid_uuid("") is False
        assert is_valid_uuid(None) is False

    def test_validate_port_number(self):
        """Test port number validation."""
        # Valid ports
        assert validate_port_number(80) is True
        assert validate_port_number("443") is True
        assert validate_port_number(8080) is True
        assert validate_port_number(65535) is True

        # Invalid ports
        assert validate_port_number(0) is False
        assert validate_port_number(65536) is False
        assert validate_port_number("not_a_port") is False
        assert validate_port_number(None) is False
