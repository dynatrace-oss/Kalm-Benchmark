"""Configuration management for Kalm Benchmark."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class KalmConfig:
    """Centralized configuration for Kalm Benchmark."""

    database_path: Path = Path("./data/kalm.db")
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
            self.log_directory,
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

        # Validate log level
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_levels:
            raise ValueError(f"Invalid log level: {self.log_level}. Must be one of {valid_levels}")

        # Validate port
        if not (1 <= self.ui_port <= 65535):
            raise ValueError(f"Invalid UI port: {self.ui_port}. Must be between 1 and 65535")


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
