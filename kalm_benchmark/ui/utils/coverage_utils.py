from typing import Any, Dict, List, Optional, Tuple

import altair as alt
import pandas as pd
import streamlit as st

from kalm_benchmark.evaluation.scanner_manager import SCANNERS

# Configuration-driven coverage analysis
COVERAGE_CONFIG = {
    "data_sources": [
        {"name": "category_coverage", "fetcher": "get_category_coverage_data", "renderer": "_render_category_coverage"},
        {"name": "basic_coverage", "fetcher": "get_basic_coverage_data", "renderer": "_render_basic_coverage"},
    ],
    "insights": [
        "**Coverage** measures how many benchmark checks each scanner can detect",
        "**Categories** represent different security domains (Network, IAM, Workload, etc.)",
        "**Higher coverage** indicates more comprehensive security scanning capability",
        "**Gaps** in coverage highlight areas where multiple scanners may be beneficial",
    ],
    "metrics_aggregation": {"coverage": "max", "score": "max"},  # Take the best coverage  # Take the best score
}


def get_category_coverage_data(unified_service) -> Optional[List[Dict]]:
    """Extract category-wise coverage data with reduced complexity.

    Args:
        unified_service: Service for loading scanner summaries

    Returns:
        List of coverage dictionaries or None if no data available
    """
    try:
        scanner_summaries = _load_all_scanner_summaries(unified_service)
        coverage_data = _process_scanner_coverage_data(scanner_summaries)
        return coverage_data if coverage_data else None
    except Exception:
        return None


def get_basic_coverage_data(unified_service) -> Optional[pd.DataFrame]:
    """Get basic coverage data from evaluation summaries.

    Args:
        unified_service: Service for loading evaluation data

    Returns:
        DataFrame with basic coverage data or None if unavailable
    """
    try:
        summaries = unified_service.create_evaluation_summary_dataframe()
        if not summaries or len(summaries) == 0:
            return None

        return _normalize_and_aggregate_coverage_summaries(summaries)
    except Exception:
        return None


def fetch_available_coverage_data(unified_service) -> Optional[Dict]:
    """Try data sources in order until one succeeds.

    Args:
        unified_service: Service for loading data

    Returns:
        Dictionary with data, renderer, and type information
    """
    for source_config in COVERAGE_CONFIG["data_sources"]:
        try:
            fetcher_func = globals()[source_config["fetcher"]]
            data = fetcher_func(unified_service)
            if data is not None:
                return {"data": data, "renderer": source_config["renderer"], "type": source_config["name"]}
        except Exception:
            continue
    return None


def render_category_coverage_analysis(coverage_data: List[Dict]):
    """Render category-wise coverage analysis.

    Args:
        coverage_data: List of coverage dictionaries
    """
    st.markdown("**🎯 Security Category Coverage Comparison**")

    coverage_df = pd.DataFrame(coverage_data)

    # Show coverage matrix
    st.dataframe(coverage_df, use_container_width=True)

    # Show category insights
    _render_category_performance_insights(coverage_df)


def render_basic_coverage_analysis(coverage_df: pd.DataFrame):
    """Render basic coverage analysis when detailed category data is not available.

    Args:
        coverage_df: Basic coverage DataFrame
    """
    st.markdown("**📊 Basic Coverage Analysis**")
    st.info("Showing overall coverage metrics. Run detailed evaluations for category-specific analysis.")

    # Show coverage comparison chart
    coverage_chart = _create_basic_coverage_chart(coverage_df)
    st.altair_chart(coverage_chart, use_container_width=True)

    # Show coverage statistics
    _render_basic_coverage_statistics(coverage_df)


def create_coverage_metrics_display(coverage_df: pd.DataFrame) -> None:
    """Create metrics display for coverage data.

    Args:
        coverage_df: Coverage DataFrame
    """
    col1, col2, col3 = st.columns(3)

    with col1:
        avg_coverage = coverage_df["coverage"].mean()
        st.metric("Average Coverage", f"{avg_coverage:.1%}")

    with col2:
        max_coverage = coverage_df["coverage"].max()
        best_scanner = coverage_df.loc[coverage_df["coverage"].idxmax(), "scanner_name"]
        st.metric("Best Coverage", f"{max_coverage:.1%}", help=f"Achieved by {best_scanner}")

    with col3:
        coverage_range = coverage_df["coverage"].max() - coverage_df["coverage"].min()
        st.metric("Coverage Range", f"{coverage_range:.1%}", help="Difference between highest and lowest coverage")


def filter_numeric_columns_safely(df: pd.DataFrame) -> List[str]:
    """Safely filter numeric columns from DataFrame.

    Args:
        df: DataFrame to filter

    Returns:
        List of numeric column names
    """
    try:
        return list(df.select_dtypes(include=["number"]).columns)
    except Exception:
        return []


def render_coverage_insights():
    """Render coverage analysis insights using configuration."""
    st.markdown(
        """
    **💡 Coverage Analysis Insights:**
    - **Coverage** measures how many benchmark checks each scanner can detect
    - **Categories** represent different security domains (Network, IAM, Workload, etc.)
    - **Higher coverage** indicates more comprehensive security scanning capability
    - **Gaps** in coverage highlight areas where multiple scanners may be beneficial
    """
    )


def _load_all_scanner_summaries(unified_service) -> List[Tuple[str, Any]]:
    """Load scanner summaries for all available scanners.

    Args:
        unified_service: Service for loading summaries

    Returns:
        List of (scanner_name, summary) tuples
    """
    summaries = []
    for name in SCANNERS.keys():
        try:
            summary = unified_service.load_scanner_summary(name.lower())
            if _is_valid_summary(summary):
                summaries.append((name, summary))
        except Exception:
            continue  # Skip failed scanners
    return summaries


def _is_valid_summary(summary) -> bool:
    """Check if summary has valid coverage data.

    Args:
        summary: Scanner summary object

    Returns:
        True if summary is valid for coverage analysis
    """
    return summary and hasattr(summary, "checks_per_category") and summary.checks_per_category


def _process_scanner_coverage_data(scanner_summaries: List[Tuple[str, Any]]) -> List[Dict]:
    """Process scanner summaries into coverage data.

    Args:
        scanner_summaries: List of (name, summary) tuples

    Returns:
        List of coverage dictionaries
    """
    coverage_data = []
    for name, summary in scanner_summaries:
        scanner_coverage = _calculate_scanner_coverage(name, summary)
        if len(scanner_coverage) > 1:  # More than just scanner name
            coverage_data.append(scanner_coverage)
    return coverage_data


def _calculate_scanner_coverage(scanner_name: str, summary) -> Dict:
    """Calculate coverage for a single scanner.

    Args:
        scanner_name: Name of the scanner
        summary: Scanner summary object

    Returns:
        Dictionary with scanner coverage data
    """
    scanner_coverage = {"Scanner": scanner_name}

    for category, category_summary in summary.checks_per_category.items():
        if category_summary:
            coverage_rate = _calculate_category_coverage_rate(category_summary)
            category_key = category.value if hasattr(category, "value") else str(category)
            scanner_coverage[category_key] = round(coverage_rate, 3)

    return scanner_coverage


def _calculate_category_coverage_rate(category_summary: Dict) -> float:
    """Calculate coverage rate for a single category.

    Args:
        category_summary: Category summary data

    Returns:
        Coverage rate (0-1)
    """
    from kalm_benchmark.evaluation import evaluation

    covered = category_summary.get(evaluation.ResultType.Covered, 0)
    missing = category_summary.get(evaluation.ResultType.Missing, 0)
    total = covered + missing
    return covered / total if total > 0 else 0


def _normalize_and_aggregate_coverage_summaries(summaries: List[Dict]) -> pd.DataFrame:
    """Normalize scanner names and aggregate coverage summaries.

    Args:
        summaries: List of evaluation summary dictionaries

    Returns:
        Aggregated DataFrame with normalized scanner names
    """
    # Normalize scanner names
    summary_list = []
    for summary in summaries:
        normalized_name = _normalize_scanner_name(summary.get("scanner_name", ""))
        summary_normalized = summary.copy()
        summary_normalized["scanner_name"] = normalized_name
        summary_list.append(summary_normalized)

    perf_df = pd.DataFrame(summary_list)

    # Group by normalized scanner names and aggregate
    return perf_df.groupby("scanner_name").agg(COVERAGE_CONFIG["metrics_aggregation"]).reset_index()


def _render_category_performance_insights(coverage_df: pd.DataFrame):
    """Render insights for category performance.

    Args:
        coverage_df: Coverage DataFrame
    """
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**📈 Best Covered Categories**")
        numeric_columns = filter_numeric_columns_safely(coverage_df)
        if len(coverage_df) > 1 and numeric_columns:
            category_avg = coverage_df[numeric_columns].mean().sort_values(ascending=False)
            for category, avg_score in category_avg.head(5).items():
                st.markdown(f"• **{category}**: {avg_score:.2f} avg coverage")
        else:
            st.info("No numeric coverage data available")

    with col2:
        st.markdown("**🔴 Categories Needing Attention**")
        if len(coverage_df) > 1 and numeric_columns:
            category_avg = coverage_df[numeric_columns].mean().sort_values(ascending=True)
            for category, avg_score in category_avg.head(5).items():
                st.markdown(f"• **{category}**: {avg_score:.2f} avg coverage")
        else:
            st.info("No numeric coverage data available")


def _create_basic_coverage_chart(coverage_df: pd.DataFrame) -> alt.Chart:
    """Create basic coverage comparison chart.

    Args:
        coverage_df: Coverage DataFrame

    Returns:
        Altair coverage chart
    """
    return (
        alt.Chart(coverage_df)
        .mark_bar()
        .encode(
            x=alt.X("scanner_name:N", axis=alt.Axis(labelAngle=0), title="Scanner"),
            y=alt.Y("coverage:Q", axis=alt.Axis(format="%"), title="Coverage Rate"),
            color=alt.Color("coverage:Q", scale=alt.Scale(scheme="viridis"), title="Coverage"),
            tooltip=["scanner_name:N", "coverage:Q", "score:Q"],
        )
        .properties(width=600, height=300, title="Overall Benchmark Coverage by Scanner")
    )


def _render_basic_coverage_statistics(coverage_df: pd.DataFrame):
    """Render basic coverage statistics.

    Args:
        coverage_df: Coverage DataFrame
    """
    create_coverage_metrics_display(coverage_df)


def _normalize_scanner_name(scanner_name: str) -> str:
    """Normalize scanner names to match the SCANNERS registry.

    Args:
        scanner_name: Raw scanner name

    Returns:
        Normalized scanner name
    """
    if not scanner_name:
        return scanner_name

    # Remove extra whitespace and convert to proper case
    name = scanner_name.strip()

    # Handle common variations
    name_mappings = {
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
    }

    return name_mappings.get(name, name)
