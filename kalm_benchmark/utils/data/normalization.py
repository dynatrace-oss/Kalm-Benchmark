from typing import Dict, Optional

import pandas as pd

# Centralized scanner name mapping to ensure consistency across all modules
SCANNER_NAME_MAPPINGS: Dict[str, str] = {
    "KICS": "KICS",
    "kics": "KICS",
    "CHECKOV": "Checkov",
    "checkov": "Checkov",
    "TRIVY": "trivy",
    "Trivy": "trivy",
    "POLARIS": "polaris",
    "Polaris": "polaris",
    "polaris": "polaris",
    "KUBESCAPE": "Kubescape",
    "kubescape": "Kubescape",
    "SNYK": "Snyk",
    "snyk": "Snyk",
    "KUBE-SCORE": "kube-score",
    "kube-score": "kube-score",
    "KUBELINTER": "KubeLinter",
    "kubelinter": "KubeLinter",
    "KUBE-BENCH": "kube-bench",
    "kube-bench": "kube-bench",
    "KUBESEC": "kubesec",
    "kubesec": "kubesec",
    "KUBISCAN": "KubiScan",
    "kubiscan": "KubiScan",
    "TERRASCAN": "Terrascan",
    "terrascan": "Terrascan",
}


def normalize_scanner_name(scanner_name: str) -> str:
    """Normalize scanner names to match the standard registry format.
    This is the single source of truth for scanner name normalization
    across the entire application.

    :param scanner_name: Raw scanner name from various sources
    :return: Normalized scanner name according to standard format
    """
    if not scanner_name:
        return scanner_name

    name = scanner_name.strip()
    return SCANNER_NAME_MAPPINGS.get(name, name)


def normalize_scanner_names_in_dataframe(df: pd.DataFrame, name_column: str = "scanner_name") -> pd.DataFrame:
    """Standardize scanner name normalization across all UI functions.

    :param df: DataFrame containing scanner names
    :param name_column: Column name containing scanner names
    :return: DataFrame with normalized scanner names
    """
    if name_column not in df.columns:
        raise KeyError(f"Column '{name_column}' not found in DataFrame")

    df = df.copy()
    df[name_column] = df[name_column].apply(normalize_scanner_name)
    return df


def normalize_path(path: str) -> str:
    """Normalize YAML path for consistent comparison.

    :param path: Raw YAML path string
    :return: Normalized path string
    """
    if not path:
        return path

    # Strip whitespace first
    normalized = path.strip()

    # Remove leading dots and slashes
    normalized = normalized.lstrip("./")

    # Standardize path separators
    normalized = normalized.replace("\\", "/")

    return normalized


def normalize_severity(severity: Optional[str]) -> str:
    """Normalize severity levels to consistent format.

    :param severity: Raw severity string

    :return: Normalized severity level
    """
    if not severity:
        return "UNKNOWN"

    severity_mappings = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
        "informational": "INFO",
        "warn": "MEDIUM",
        "warning": "MEDIUM",
        "error": "HIGH",
        "fail": "HIGH",
        "pass": "INFO",
    }

    normalized = severity.lower().strip()
    return severity_mappings.get(normalized, severity.upper())
