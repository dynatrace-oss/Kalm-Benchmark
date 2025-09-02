import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .constants import MAX_PORT_NUMBER, MIN_PORT_NUMBER, VALID_LOG_LEVELS
from .exceptions import ConfigurationError


@dataclass
class KalmConfig:
    """Centralized configuration for Kalm Benchmark."""

    database_path: Path = Path("./data/kalm.db")
    ccss_database_path: Path = Path("./data/ccss_evaluation.db")
    log_level: str = "INFO"
    ui_host: str = "localhost"
    ui_port: int = 8501
    scan_timeout: int = 300
    data_directory: Path = Path("./data")
    manifest_directory: Path = Path("./manifests")
    log_directory: Path = Path("./logs")
    max_results_cache: int = 1000
    cleanup_keep_runs: int = 50

    @classmethod
    def from_env(cls) -> "KalmConfig":
        """Load configuration from environment variables."""
        return cls(
            database_path=Path(os.getenv("KALM_DB_PATH", "./data/kalm.db")),
            ccss_database_path=Path(os.getenv("KALM_CCSS_DB_PATH", "./data/ccss_evaluation.db")),
            log_level=os.getenv("KALM_LOG_LEVEL", "INFO"),
            ui_host=os.getenv("KALM_UI_HOST", "localhost"),
            ui_port=int(os.getenv("KALM_UI_PORT", "8501")),
            scan_timeout=int(os.getenv("KALM_SCAN_TIMEOUT", "300")),
            data_directory=Path(os.getenv("KALM_DATA_DIR", "./data")),
            manifest_directory=Path(os.getenv("KALM_MANIFEST_DIR", "./manifests")),
            log_directory=Path(os.getenv("KALM_LOG_DIR", "./logs")),
            max_results_cache=int(os.getenv("KALM_MAX_CACHE", "1000")),
            cleanup_keep_runs=int(os.getenv("KALM_CLEANUP_KEEP", "50")),
        )

    def validate(self) -> None:
        """Validate configuration and create directories if needed."""
        directories = [
            self.data_directory,
            self.database_path.parent,
            self.ccss_database_path.parent,
            self.log_directory,
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

        # Validate log level
        if self.log_level.upper() not in VALID_LOG_LEVELS:
            raise ConfigurationError(f"Invalid log level: {self.log_level}. Must be one of {VALID_LOG_LEVELS}")

        # Validate port
        if not (MIN_PORT_NUMBER <= self.ui_port <= MAX_PORT_NUMBER):
            raise ConfigurationError(
                f"Invalid UI port: {self.ui_port}. Must be between {MIN_PORT_NUMBER} and {MAX_PORT_NUMBER}"
            )


# Global configuration instance
_config: Optional[KalmConfig] = None


def get_config() -> KalmConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = KalmConfig.from_env()
        _config.validate()
    return _config


def set_config(config: KalmConfig) -> None:
    """Set the global configuration instance."""
    global _config
    config.validate()
    _config = config


def reset_config() -> None:
    """Reset the global configuration instance to force reloading from environment for tests"""
    global _config
    _config = None
