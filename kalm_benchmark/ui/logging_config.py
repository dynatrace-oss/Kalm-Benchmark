import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from loguru import logger


class UILogger:
    """Centralized logger for UI operations, particularly scan operations."""

    def __init__(self, data_dir: Optional[Path] = None):
        """Initialize the UI logger with optional data directory."""
        self.data_dir = data_dir or Path("./data")

        self.log_dir = Path("./logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.scan_log_file = self.log_dir / f"scan_{datetime.now().strftime('%Y%m%d')}.log"
        self.ui_log_file = self.log_dir / f"ui_{datetime.now().strftime('%Y%m%d')}.log"

        self._setup_loggers()

    def _setup_loggers(self):
        """Set up structured loggers for different components."""
        logger.remove()

        logger.add(
            sys.stderr,
            level="ERROR",
            format="<red>{time:HH:mm:ss}</red> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        )

        logger.add(
            str(self.scan_log_file),
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            rotation="100 MB",
            retention="30 days",
            filter=lambda record: record["extra"].get("component") == "scan",
        )

        logger.add(
            str(self.ui_log_file),
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            rotation="100 MB",
            retention="30 days",
            filter=lambda record: record["extra"].get("component") == "ui",
        )

    def log_scan_start(self, tool_name: str, source: str):
        """Log the start of a scan operation."""
        logger.bind(component="scan").info(f"Starting scan with {tool_name} on {source}")

    def log_scan_progress(self, tool_name: str, message: str, level: str = "info"):
        """Log scan progress messages."""
        log_func = getattr(logger.bind(component="scan"), level.lower(), logger.info)
        log_func(f"[{tool_name}] {message}")

    def log_scan_complete(self, tool_name: str, success: bool, result_file: Optional[Path] = None):
        """Log scan completion."""
        if success and result_file:
            logger.bind(component="scan").success(
                f"Scan completed successfully for {tool_name}. Results saved to {result_file}"
            )
        elif success:
            logger.bind(component="scan").success(f"Scan completed successfully for {tool_name}")
        else:
            logger.bind(component="scan").error(f"Scan failed for {tool_name}")

    def log_scan_error(self, tool_name: str, error: str):
        """Log scan errors."""
        logger.bind(component="scan").error(f"[{tool_name}] Error: {error}")

    def log_ui_action(self, action: str, details: Optional[str] = None):
        """Log UI actions for debugging."""
        message = f"UI Action: {action}"
        if details:
            message += f" - {details}"
        logger.bind(component="ui").info(message)

    def get_recent_scan_logs(self, tool_name: Optional[str] = None, limit: int = 50) -> list[str]:
        """Get recent scan log entries for display."""
        try:
            with open(self.scan_log_file, "r") as f:
                lines = f.readlines()

            if tool_name:
                lines = [line for line in lines if f"[{tool_name}]" in line or tool_name in line]

            return lines[-limit:] if len(lines) > limit else lines
        except FileNotFoundError:
            return []

    def get_log_files(self) -> dict[str, Path]:
        """Get paths to log files for external access."""
        return {"scan_logs": self.scan_log_file, "ui_logs": self.ui_log_file}


_ui_logger: Optional[UILogger] = None


def get_ui_logger(data_dir: Optional[Path] = None) -> UILogger:
    """Get or create the global UI logger instance."""
    global _ui_logger
    if _ui_logger is None:
        _ui_logger = UILogger(data_dir)
    return _ui_logger


def init_logging(data_dir: Optional[Path] = None):
    """Initialize the logging system."""
    global _ui_logger
    _ui_logger = UILogger(data_dir)
