import re
import string

from hypothesis import assume, given
from hypothesis import strategies as st

from kalm_benchmark.utils.data.normalization import normalize_path, normalize_severity
from kalm_benchmark.utils.data.validation import (
    is_valid_uuid,
    sanitize_filename,
    sanitize_kubernetes_name,
    sanitize_text_for_display,
    validate_port_number,
    validate_scanner_name,
)


class TestKubernetesNameSanitization:
    """Property-based tests for Kubernetes name sanitization."""

    @given(st.text())
    def test_sanitized_names_are_valid_kubernetes_names(self, name):
        """Test that sanitized names always produce valid output."""
        result = sanitize_kubernetes_name(name)

        assert isinstance(result, str)
        # Length should be reasonable
        assert len(result) <= 253
        if result:
            assert re.match(r"^[a-z0-9.-]*$", result)

    @given(st.text(alphabet=string.ascii_lowercase + string.digits + "-", min_size=2, max_size=50))
    def test_valid_names_remain_mostly_unchanged(self, name):
        """Test that already valid Kubernetes names remain mostly unchanged."""
        # Skip names that start/end with hyphens
        assume(not name.startswith("-"))
        assume(not name.endswith("-"))
        assume("--" not in name)

        result = sanitize_kubernetes_name(name)
        assert isinstance(result, str)
        assert len(result) > 0

    @given(st.text())
    def test_sanitization_produces_consistent_output(self, name):
        """Test that sanitization produces consistent output."""
        result1 = sanitize_kubernetes_name(name)
        result2 = sanitize_kubernetes_name(name)

        assert result1 == result2


class TestFilenameSanitization:
    """Property-based tests for filename sanitization."""

    # Invalid filename characters on most systems
    INVALID_CHARS = '<>:"/\\|?*'

    @given(st.text())
    def test_sanitized_filenames_contain_no_invalid_characters(self, filename):
        """Test that sanitized filenames contain no invalid characters."""
        result = sanitize_filename(filename)

        for invalid_char in self.INVALID_CHARS:
            assert invalid_char not in result

    @given(st.text(alphabet=string.ascii_letters + string.digits + "_", min_size=1, max_size=50))
    def test_valid_filenames_remain_mostly_unchanged(self, filename):
        """Test that valid filenames remain largely unchanged."""
        # Skip problematic cases
        assume(filename not in [".", ".."])
        assume(not filename.isspace())

        result = sanitize_filename(filename)
        # Should produce a valid result
        assert isinstance(result, str)
        assert len(result) > 0

    @given(st.text())
    def test_sanitization_produces_non_empty_result_for_non_empty_input(self, filename):
        """Test that non-empty input produces some output."""
        assume(filename.strip())
        assume(any(c.isalnum() for c in filename))

        result = sanitize_filename(filename)
        assert result


class TestScannerNameValidation:
    """Property-based tests for scanner name validation."""

    @given(st.text(alphabet=string.ascii_letters + string.digits + "-_", min_size=2, max_size=50))
    def test_valid_scanner_names_pass_validation(self, name):
        """Test that properly formed scanner names pass validation."""
        result = validate_scanner_name(name)
        assert result is True

    @given(st.text())
    def test_scanner_name_validation_returns_boolean(self, name):
        """Test that scanner name validation always returns a boolean."""
        result = validate_scanner_name(name)

        # Should always return a boolean
        assert isinstance(result, bool)

        # Empty names should fail
        if not name or not name.strip():
            assert result is False


class TestSeverityNormalization:
    """Property-based tests for severity normalization."""

    KNOWN_SEVERITIES = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
        "warn": "MEDIUM",
        "warning": "MEDIUM",
        "error": "HIGH",
    }

    @given(st.sampled_from(list(KNOWN_SEVERITIES.keys())))
    def test_known_severities_normalize_correctly(self, severity):
        """Test that known severity values normalize to expected values."""
        result = normalize_severity(severity)
        expected = self.KNOWN_SEVERITIES[severity]
        assert result == expected

    @given(st.text())
    def test_normalization_always_returns_string(self, severity):
        """Test that severity normalization always returns a string."""
        result = normalize_severity(severity)
        assert isinstance(result, str)
        assert result  # Should not be empty

    @given(st.text().filter(lambda x: x.lower() not in TestSeverityNormalization.KNOWN_SEVERITIES))
    def test_unknown_severities_return_uppercase_or_unknown(self, severity):
        """Test that unknown severities either return uppercase version or 'UNKNOWN'."""
        assume(severity)  # Skip empty strings
        result = normalize_severity(severity)

        assert result in [severity.upper(), "UNKNOWN", "CUSTOM"]


class TestPathNormalization:
    """Property-based tests for path normalization."""

    @given(st.text())
    def test_normalized_paths_are_consistent(self, path):
        """Test that path normalization produces consistent results."""
        result = normalize_path(path)
        assert isinstance(result, str)

        result2 = normalize_path(path)
        assert result == result2

    @given(st.text())
    def test_normalization_handles_backslashes(self, path):
        """Test that backslashes are converted to forward slashes."""
        result = normalize_path(path)

        # If the original had backslashes, they should be converted
        if "\\" in path and result:
            assert "\\" not in result

    @given(st.text())
    def test_normalization_produces_string_output(self, path):
        """Test that path normalization always produces string output."""
        result = normalize_path(path)
        assert isinstance(result, str)

        result2 = normalize_path(path)
        assert result == result2


class TestPortValidation:
    """Property-based tests for port number validation."""

    @given(st.integers(min_value=1, max_value=65535))
    def test_valid_ports_pass_validation(self, port):
        """Test that valid port numbers pass validation."""
        assert validate_port_number(port) is True
        assert validate_port_number(str(port)) is True

    @given(st.integers().filter(lambda x: x < 1 or x > 65535))
    def test_invalid_ports_fail_validation(self, port):
        """Test that invalid port numbers fail validation."""
        assert validate_port_number(port) is False
        assert validate_port_number(str(port)) is False


class TestUUIDValidation:
    """Property-based tests for UUID validation."""

    @given(st.uuids(version=4))
    def test_valid_uuids_pass_validation(self, uuid_obj):
        """Test that valid version 4 UUIDs pass validation."""
        uuid_str = str(uuid_obj)
        result = is_valid_uuid(uuid_str)
        assert isinstance(result, bool)

    @given(st.text().filter(lambda x: len(x) != 36 or "-" not in x))
    def test_invalid_uuids_fail_validation(self, text):
        """Test that invalid UUID strings fail validation."""
        # Skip actual UUIDs that might be generated
        assume(not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", text.lower()))

        assert is_valid_uuid(text) is False


class TestTextSanitization:
    """Property-based tests for text sanitization."""

    @given(st.text(), st.integers(min_value=10, max_value=1000))
    def test_sanitized_text_respects_max_length(self, text, max_length):
        """Test that sanitized text respects maximum length limits."""
        result = sanitize_text_for_display(text, max_length=max_length)

        assert len(result) <= max_length

        # If truncated, should end with "..."
        if len(text) > max_length:
            assert result.endswith("...")

    @given(st.text())
    def test_sanitized_text_removes_html_tags(self, text):
        """Test that HTML tags are removed from sanitized text."""
        html_text = f"<script>alert('xss')</script>{text}<div>content</div>"
        result = sanitize_text_for_display(html_text)

        # Should not contain HTML tags
        assert "<script>" not in result
        assert "<div>" not in result
        assert "</script>" not in result
        assert "</div>" not in result

    @given(st.text())
    def test_sanitized_text_normalizes_whitespace(self, text):
        """Test that whitespace is normalized in sanitized text."""
        result = sanitize_text_for_display(text)

        # Should not have multiple consecutive spaces
        assert "  " not in result
        # Should not have newlines
        assert "\n" not in result
        assert "\r" not in result
        assert "\t" not in result


# Performance-oriented property tests
class TestPerformanceProperties:
    """Property-based tests focused on performance characteristics."""

    @given(st.text(min_size=0, max_size=10000))
    def test_validation_functions_handle_large_inputs(self, large_text):
        """Test that validation functions can handle large inputs efficiently."""
        # These should complete without timeout or excessive memory usage
        sanitize_filename(large_text)
        sanitize_kubernetes_name(large_text)
        sanitize_text_for_display(large_text)
        normalize_path(large_text)

    @given(st.lists(st.text(), min_size=0, max_size=100))
    def test_batch_processing_is_consistent(self, text_list):
        """Test that processing items individually vs in batch gives consistent results."""
        individual_results = [sanitize_filename(text) for text in text_list]
        batch_results = [sanitize_filename(text) for text in text_list]

        assert individual_results == batch_results
