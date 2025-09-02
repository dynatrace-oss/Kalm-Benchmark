import streamlit as st
from loguru import logger

from kalm_benchmark.evaluation.evaluation import (
    Col,
    EvaluationSummary,
    Metric,
    create_summary,
    evaluate_scanner,
)
from kalm_benchmark.utils.constants import CUSTOM_CHECKS_LABEL
from kalm_benchmark.utils.helm_benchmark_mapper import (
    create_helm_benchmark_comparison_df,
)
from kalm_benchmark.utils.helm_metrics import normalize_helm_findings_for_ui


def get_scanner_instance(tool_name: str):
    """Get scanner instance with error handling.

    :param tool_name: Name of the scanner tool to retrieve
    :return: Scanner instance or None if not found
    """
    from kalm_benchmark.evaluation.scanner_manager import SCANNERS

    scanner = SCANNERS.get(tool_name)
    if not scanner:
        st.error(f"Scanner '{tool_name}' not found!")
        return None
    return scanner


def get_evaluation_configuration(tool_name: str) -> dict[str, any]:
    """Get evaluation configuration from sidebar controls.

    :param tool_name: Name of the scanner tool for unique key generation
    :return: Dictionary containing evaluation configuration settings
    """
    return {"keep_redundant": st.sidebar.checkbox("Keep redundant checks", value=False, key=f"{tool_name}_redundant")}


def evaluate_scan_results(scanner, raw_results, config: dict[str, any]):
    """Evaluate scan results with configuration settings.

    :param scanner: Scanner instance to evaluate
    :param raw_results: Raw scan results to process
    :param config: Configuration dictionary with evaluation settings
    :return: Processed evaluation results or None if processing fails
    """
    is_helm_chart = any(
        result.extra and result.extra.startswith("helm_chart:")
        for result in raw_results
        if hasattr(result, "extra") and result.extra
    )

    if is_helm_chart:
        logger.info(f"Processing {len(raw_results)} helm chart results for mapping")
        comparison_df = create_helm_benchmark_comparison_df(
            raw_results, unified_service=None, scanner_name=scanner.NAME
        )
        logger.info(
            f"Created comparison dataframe with shape: "
            f"{comparison_df.shape if not comparison_df.empty else 'empty'}"
        )

        if not comparison_df.empty:
            ui_df = normalize_helm_findings_for_ui(comparison_df, scanner.NAME)
            return ui_df
        else:
            return None
    else:
        return evaluate_scanner(scanner, raw_results, keep_redundant_checks=config["keep_redundant"])


def filter_excluded_checks(df_results, tool_name: str):
    """Filter out excluded checks based on sidebar selection.

    :param df_results: DataFrame containing scan results to filter
    :param tool_name: Name of the scanner tool for unique key generation
    :return: Filtered DataFrame with excluded checks removed
    """
    if df_results is None or df_results.empty:
        return df_results

    df_results = df_results.astype(str)
    all_checks = sorted(df_results[Col.ScannerCheckId].unique())
    excluded_checks = st.sidebar.multiselect("Excluded Checks:", all_checks, key=f"{tool_name}_excluded")

    return df_results[~df_results[Col.ScannerCheckId].isin(excluded_checks)]


def create_evaluation_summary(df_results, scan_run: dict[str, any]) -> EvaluationSummary:
    """Create evaluation summary with performance metrics.

    :param df_results: DataFrame containing processed scan results
    :param scan_run: Dictionary containing scan run metadata
    :return: EvaluationSummary object with calculated metrics
    """
    if df_results is None or df_results.empty:
        return EvaluationSummary(
            version=scan_run.get("scanner_version"),
            checks_per_category={},
            score=0.0,
            coverage=0.0,
            extra_checks=0,
            missing_checks=0,
            ccss_alignment_score=None,
            ccss_correlation=None,
            total_ccss_findings=0,
        )

    is_helm_chart = scan_run.get("source_type", "").startswith("helm-chart:")

    if is_helm_chart:
        version = scan_run.get("scanner_version")
        total_findings = len(df_results)
        mapped_findings = len(df_results[df_results["result_type"] == "Covered"])
        extra_findings = len(df_results[df_results["result_type"] == "Extra"])

        coverage = (mapped_findings / total_findings) if total_findings > 0 else 0

        high_severity = len(df_results[df_results["severity"].isin(["HIGH", "CRITICAL", "DANGER"])])
        medium_severity = len(df_results[df_results["severity"].isin(["MEDIUM", "WARNING"])])

        risk_score = max(
            0.0,
            min(1.0, (100.0 - (high_severity * 10) - (medium_severity * 3)) / 100.0),
        )

        checks_per_category = df_results.groupby("category").size().to_dict()

        return EvaluationSummary(
            version=version,
            checks_per_category=checks_per_category,
            score=risk_score,
            coverage=coverage,
            extra_checks=extra_findings,
            missing_checks=0,
            ccss_alignment_score=None,
            ccss_correlation=None,
            total_ccss_findings=total_findings,
        )
    else:
        metric = Metric.F1
        version = scan_run.get("scanner_version")
        return create_summary(df_results, metric, version=version)


def get_tool_capabilities(tool) -> list[str]:
    """Get list of scanner capabilities and supported modes.

    :param tool: Scanner tool instance to analyze
    :return: List of capability strings describing scanner features
    """
    capabilities = []
    if tool.can_scan_cluster:
        capabilities.append("Cluster")
    if tool.can_scan_manifests:
        capabilities.append("Manifests")
    if tool.CI_MODE:
        capabilities.append("CI/CD")
    return capabilities


def get_configuration_items(tool) -> list[str]:
    """Get list of scanner configuration options and settings.

    :param tool: Scanner tool instance to analyze
    :return: List of configuration strings describing scanner options
    """
    config_items = []
    if tool.CUSTOM_CHECKS != "False":
        config_items.append(CUSTOM_CHECKS_LABEL)
    if tool.RUNS_OFFLINE:
        config_items.append("Offline")
    if tool.FORMATS:
        config_items.append(f"{len(tool.FORMATS)} Formats")
    return config_items
