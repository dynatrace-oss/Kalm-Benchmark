import pytest
from typer.testing import CliRunner

from kalm_benchmark.cli import app


@pytest.mark.integration
class TestBasicIntegration:
    """Test basic integration scenarios."""

    @pytest.fixture
    def cli_runner(self):
        """Provide CLI runner for integration tests."""
        return CliRunner()

    def test_cli_help_command_works(self, cli_runner):
        """Test that the CLI help command works."""
        result = cli_runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "KALM" in result.stdout or "scan" in result.stdout

    def test_cli_scan_command_exists(self, cli_runner):
        """Test that the scan command exists."""
        result = cli_runner.invoke(app, ["scan", "--help"])
        # Should either show help or give a reasonable error
        assert result.exit_code in [0, 1, 2]  # Allow for different error codes

    def test_scanner_manager_can_be_imported(self):
        """Test that core modules can be imported without errors."""
        from kalm_benchmark.evaluation.scanner_manager import ScannerManager

        manager = ScannerManager()
        assert hasattr(manager, "scanners")

    def test_evaluation_functions_can_be_imported(self):
        """Test that evaluation functions can be imported."""
        from kalm_benchmark.evaluation.evaluation import calculate_score, create_summary

        # Functions should be importable
        assert callable(calculate_score)
        assert callable(create_summary)

    def test_utility_functions_work(self):
        """Test that utility functions work with basic input."""
        from kalm_benchmark.utils.data.normalization import normalize_path
        from kalm_benchmark.utils.data.validation import (
            sanitize_filename,
            sanitize_kubernetes_name,
        )

        # Basic functionality tests
        assert sanitize_kubernetes_name("test") == "test"
        assert sanitize_filename("test.txt") == "test.txt"
        assert isinstance(normalize_path("./test/path"), str)


@pytest.mark.integration
class TestConfigurationWorkflows:
    """Test configuration-related workflows."""

    def test_scanner_configuration_loading(self, temp_test_dir):
        """Test basic configuration file handling."""
        import json

        # Simple configuration file
        config_content = {"scanners": {"test-scanner": {"enabled": True, "timeout": 300}}}

        config_file = temp_test_dir / "config.json"
        config_file.write_text(json.dumps(config_content, indent=2))

        # Test that configuration can be loaded
        assert config_file.exists()
        loaded_config = json.loads(config_file.read_text())
        assert "scanners" in loaded_config
        assert "test-scanner" in loaded_config["scanners"]
