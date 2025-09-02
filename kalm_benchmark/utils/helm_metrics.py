import pandas as pd
from loguru import logger

from kalm_benchmark.evaluation.evaluation import EvaluationSummary
from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckResult
from kalm_benchmark.utils.helm_benchmark_mapper import (
    create_helm_benchmark_comparison_df,
)

from .constants import (
    HELM_FALLBACK_SCORE,
    HELM_HIGH_SEVERITY_WEIGHT,
    HELM_MAX_RISK_SCORE,
    HELM_MEDIUM_SEVERITY_WEIGHT,
    HELM_MIN_RISK_SCORE,
    HELM_RISK_SCORE_BASE,
    HIGH_SEVERITY_LEVELS,
    MEDIUM_SEVERITY_LEVELS,
)


def create_helm_evaluation_summary(
    scanner_name: str, helm_results: list[CheckResult], unified_service=None
) -> EvaluationSummary:
    """Create an evaluation summary specifically for helm chart results

    :param scanner_name: Name of one of the supported scanners
    :param helm_results: list of objects in the CheckResult format
    :param unified_service: Evaluation service instance with
        database integrations for comparison analysis
    :return: Object containing the evaluation summary for a helm chart scan
    """

    if not helm_results:
        return EvaluationSummary(
            version=None,
            checks_per_category={},
            score=0.0,
            coverage=0.0,
            extra_checks=0,
            missing_checks=0,
            ccss_alignment_score=None,
            ccss_correlation=None,
            total_ccss_findings=len(helm_results),
        )

    try:
        # Create helm-benchmark comparison
        comparison_df = create_helm_benchmark_comparison_df(
            helm_results, unified_service=unified_service, scanner_name=scanner_name
        )

        logger.debug(f"Comparison df shape: {comparison_df.shape if not comparison_df.empty else 'empty'}")
        if not comparison_df.empty:
            logger.debug(f"Comparison df columns: {list(comparison_df.columns)}")
            logger.debug(f"Sample mapping data: is_mapped={comparison_df['is_mapped'].value_counts().to_dict()}")

        if comparison_df.empty:
            logger.warning(f"Empty comparison dataframe for {scanner_name}")
            return _create_fallback_summary(helm_results)

        # Calculate helm-specific metrics
        total_findings = len(comparison_df)
        mapped_findings = len(comparison_df[comparison_df["is_mapped"]])
        extra_findings = len(comparison_df[~comparison_df["is_mapped"]])

        # Coverage based on mapping success rate
        coverage = (mapped_findings / total_findings) if total_findings > 0 else 0.0

        # Score based on risk (inverted from helm evaluation logic)
        high_severity_count = len(comparison_df[comparison_df["severity"].isin(HIGH_SEVERITY_LEVELS)])
        medium_severity_count = len(comparison_df[comparison_df["severity"].isin(MEDIUM_SEVERITY_LEVELS)])

        # Risk-based scoring: lower score for more high/medium severity issues
        risk_score = max(
            HELM_MIN_RISK_SCORE,
            min(
                HELM_MAX_RISK_SCORE,
                (
                    HELM_RISK_SCORE_BASE
                    - (high_severity_count * HELM_HIGH_SEVERITY_WEIGHT)
                    - (medium_severity_count * HELM_MEDIUM_SEVERITY_WEIGHT)
                )
                / HELM_RISK_SCORE_BASE,
            ),
        )

        checks_per_category = comparison_df.groupby("category").size().to_dict()

        logger.info(
            f"Created helm evaluation summary: {total_findings} findings, "
            f"{coverage:.2%} coverage, {risk_score:.3f} risk score"
        )

        return EvaluationSummary(
            version=getattr(helm_results[0], "scanner_version", None) if helm_results else None,
            checks_per_category=checks_per_category,
            score=risk_score,
            coverage=coverage,
            extra_checks=extra_findings,
            missing_checks=0,  # Not applicable for helm charts
            ccss_alignment_score=None,
            ccss_correlation=None,
            total_ccss_findings=total_findings,
        )

    except (KeyError, ValueError, IndexError) as e:
        logger.error(f"Error creating helm evaluation summary: {e}")
        return _create_fallback_summary(helm_results)


def _create_fallback_summary(helm_results: list[CheckResult]) -> EvaluationSummary:
    """Create a fallback summary when normal processing fails."""
    return EvaluationSummary(
        version=None,
        checks_per_category={"Helm": len(helm_results)},
        score=HELM_FALLBACK_SCORE,  # Neutral score
        coverage=0.0,
        extra_checks=len(helm_results),
        missing_checks=0,
        ccss_alignment_score=None,
        ccss_correlation=None,
        total_ccss_findings=len(helm_results),
    )


def _get_helm_scan_runs(unified_service, scanner_name: str = None) -> list:
    """Get helm chart scan runs, optionally filtered by scanner name."""
    if scanner_name:
        return unified_service.db.get_scan_runs(scanner_name=scanner_name, source_filter="helm_charts")
    else:
        return unified_service.db.get_scan_runs(source_filter="helm_charts")


def _should_recreate_summary(existing_summary) -> bool:
    """Determine if an evaluation summary should be recreated."""
    return not existing_summary or (existing_summary and existing_summary.coverage < 0.001)


def _process_single_helm_run(unified_service, run: dict) -> tuple[bool, bool]:
    """Process a single helm run to ensure evaluation summary exists.

    Returns:
        Tuple of (was_created, was_updated)
    """
    existing_summary = unified_service.db.load_evaluation_summary(run["scanner_name"], run["timestamp"])

    if not _should_recreate_summary(existing_summary):
        return False, False

    action = "Creating missing" if not existing_summary else "Recreating invalid"
    logger.info(f"{action} evaluation summary for {run['scanner_name']} at {run['timestamp']}")

    helm_results = unified_service.db.load_scanner_results(run["scanner_name"], run["id"])

    if not helm_results:
        return False, False

    summary = create_helm_evaluation_summary(
        run["scanner_name"],
        helm_results,
        unified_service,
    )

    unified_service.db.save_evaluation_summary(
        run["scanner_name"], summary, run["timestamp"], run.get("scanner_version")
    )

    was_created = not existing_summary
    was_updated = not was_created
    return was_created, was_updated


def ensure_helm_evaluation_summaries_exist(unified_service, scanner_name: str = None):
    """Ensure evaluation summaries exist for helm chart scans, creating them if missing

    :param unified_service: Evaluation service instance with
        database integrations for comparison analysis
    :param scanner_name: Name of one of the supported scanners
    :return: None
    """

    try:
        helm_runs = _get_helm_scan_runs(unified_service, scanner_name)

        if not helm_runs:
            logger.info("No helm chart scan runs found")
            return

        # Process each run and track counters
        created_count = 0
        updated_count = 0

        for run in helm_runs:
            was_created, was_updated = _process_single_helm_run(unified_service, run)
            if was_created:
                created_count += 1
            elif was_updated:
                updated_count += 1

        if created_count > 0 or updated_count > 0:
            logger.info(
                f"Created {created_count} missing and updated {updated_count} invalid helm chart evaluation summaries"
            )

    except (KeyError, ValueError, IndexError) as e:
        logger.error(f"Error ensuring helm evaluation summaries: {e}")


def _add_scanner_name_column(comparison_df: pd.DataFrame, scanner_name: str) -> pd.DataFrame:
    """Add scanner_name column if provided."""
    if scanner_name:
        comparison_df = comparison_df.copy()
        comparison_df["scanner_name"] = scanner_name
    return comparison_df


def _map_confidence_to_result_type(comparison_df: pd.DataFrame) -> pd.DataFrame:
    """Map confidence levels to result types for UI consistency."""
    confidence_to_result_type = {"high": "Covered", "medium": "Covered", "low": "Covered", "none": "Extra"}
    comparison_df["result_type"] = comparison_df["mapping_confidence"].map(confidence_to_result_type).fillna("Extra")
    return comparison_df


def _rename_columns_for_ui(comparison_df: pd.DataFrame) -> pd.DataFrame:
    """Rename columns for UI compatibility."""
    column_mapping = {
        "helm_check_id": "scanner_check_id",
        "helm_check_name": "scanner_check_name",
        "benchmark_check_id": "check_id",
        "benchmark_equivalent": "name",
        "mapping_reason": "details",
    }

    for old_col, new_col in column_mapping.items():
        if old_col in comparison_df.columns and new_col not in comparison_df.columns:
            comparison_df[new_col] = comparison_df[old_col]

    return comparison_df


def _add_required_ui_columns(comparison_df: pd.DataFrame) -> pd.DataFrame:
    """Add required columns for UI compatibility."""
    if "expected" not in comparison_df.columns:
        comparison_df["expected"] = comparison_df.apply(
            lambda row: "alert" if row.get("is_mapped", False) else "-", axis=1
        )

    if "got" not in comparison_df.columns:
        comparison_df["got"] = "alert"

    return comparison_df


def normalize_helm_findings_for_ui(comparison_df: pd.DataFrame, scanner_name: str = None) -> pd.DataFrame:
    """Normalize helm chart findings for consistent UI display

    :param comparison_df: Dataframe containing helm chart scanner findings
    :param scanner_name: Name of one of the supported scanners
    :return: Transformed helm chart findings for easier UI display
    """

    if comparison_df.empty:
        return comparison_df

    # Apply transformations in sequence
    comparison_df = _add_scanner_name_column(comparison_df, scanner_name)
    comparison_df = _map_confidence_to_result_type(comparison_df)
    comparison_df = _rename_columns_for_ui(comparison_df)
    comparison_df = _add_required_ui_columns(comparison_df)

    return comparison_df
