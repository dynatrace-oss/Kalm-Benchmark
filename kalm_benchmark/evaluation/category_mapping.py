from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckCategory

# Specific check ID mappings that override prefix-based categorization
SPECIFIC_CHECK_MAPPINGS = {
    "pod-025": CheckCategory.DataSecurity,  # secrets in env vars
    "pod-043": CheckCategory.DataSecurity,  # Azure Cloud Credentials mounted
    "pod-045": CheckCategory.Vulnerability,  # CVE-2021-25741
    "cm-002": CheckCategory.Vulnerability,  # CVE-2021-25742
    "ing-005": CheckCategory.Vulnerability,  # CVE-2021-25742
    "rel-004": CheckCategory.Segregation,  # nodeSelector
}

# Prefix-based category mappings (prefix tuples -> category)
PREFIX_CATEGORY_MAPPINGS = {
    ("pod", "wl", "cj", "srv", "sc"): CheckCategory.Workload,
    ("pss", "psa", "psp"): CheckCategory.AdmissionControl,
    ("rbac",): CheckCategory.IAM,
    ("cm",): CheckCategory.DataSecurity,
    ("np", "ns"): CheckCategory.Segregation,
    ("ing",): CheckCategory.Network,
    ("rel", "res"): CheckCategory.Reliability,
    ("inf",): CheckCategory.Infrastructure,
}


def get_category_by_prefix(prefix: str) -> CheckCategory:
    """Get category by prefix using configuration-driven mapping.

    Args:
        prefix: The check ID prefix to categorize

    Returns:
        The appropriate CheckCategory, defaults to Misc if no match found
    """
    prefix_lower = prefix.lower()
    for prefixes, category in PREFIX_CATEGORY_MAPPINGS.items():
        if prefix_lower in prefixes:
            return category
    return CheckCategory.Misc


def get_category_by_specific_check(check_id: str) -> CheckCategory | None:
    """Get category for specific check IDs that override prefix-based categorization.

    Args:
        check_id: The specific check ID to look up

    Returns:
        The CheckCategory if found, None if not in specific mappings
    """
    return SPECIFIC_CHECK_MAPPINGS.get(check_id.lower())
