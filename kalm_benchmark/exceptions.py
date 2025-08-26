"""Custom exception classes for Kalm Benchmark operations."""


class KalmBenchmarkError(Exception):
    """Base exception for Kalm Benchmark operations."""

    pass


class ScannerNotFoundError(KalmBenchmarkError):
    """Raised when a scanner is not found or available."""

    pass


class EvaluationError(KalmBenchmarkError):
    """Raised when evaluation fails."""

    pass


class DatabaseError(KalmBenchmarkError):
    """Raised when database operations fail."""

    pass


class ConfigurationError(KalmBenchmarkError):
    """Raised when configuration is invalid."""

    pass


class ScanError(KalmBenchmarkError):
    """Raised when scan operations fail."""

    pass
