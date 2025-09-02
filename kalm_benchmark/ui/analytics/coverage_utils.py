import altair as alt
import pandas as pd
import streamlit as st

from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.scanner_manager import SCANNERS
from kalm_benchmark.ui.interface.source_filter import ScanSourceType
from kalm_benchmark.utils.data.data_filtering import get_filtered_summaries
from kalm_benchmark.utils.data.normalization import (
    normalize_scanner_name as _normalize_scanner_name,
)

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
    "metrics_aggregation": {"coverage": "max", "score": "max"},
}


def get_category_coverage_data(unified_service, source_type=None, chart_name=None) -> list[dict] | None:
    """Extract category-wise coverage data with reduced complexity.

    :param unified_service: Service for loading scanner summaries
    :param source_type: Optional source type for filtering
    :param chart_name: Optional chart name for helm chart filtering
    :return: list of coverage dictionaries or None if no data available
    """
    try:
        if source_type is not None:
            scanner_summaries = _load_filtered_scanner_summaries(unified_service, source_type, chart_name)
        else:
            scanner_summaries = _load_all_scanner_summaries(unified_service)
        coverage_data = _process_scanner_coverage_data(scanner_summaries)
        return coverage_data if coverage_data else None
    except Exception:
        return None


def get_basic_coverage_data(unified_service, source_type=None, chart_name=None) -> pd.DataFrame | None:
    """Get basic coverage data from evaluation summaries.

    :param unified_service: Service for loading evaluation data
    :param source_type: Optional source type for filtering
    :param chart_name: Optional chart name for helm chart filtering
    :return: DataFrame with basic coverage data or None if unavailable
    """
    try:
        if source_type is not None:
            summaries = get_filtered_summaries(unified_service, source_type, chart_name)
        else:
            summaries = unified_service.create_evaluation_summary_dataframe()

        if not summaries or len(summaries) == 0:
            return None

        return _normalize_and_aggregate_coverage_summaries(summaries)
    except Exception:
        return None


def fetch_available_coverage_data(unified_service, source_type=None, chart_name=None) -> dict | None:
    """Try data sources in order until one succeeds.

    :param unified_service: Service for loading data
    :param source_type: Type of scan source (for Helm-specific analysis)
    :param chart_name: Optional chart name for Helm chart filtering
    :return: dictionary with data, renderer, and type information
    """
    if source_type and hasattr(source_type, "name") and source_type.name == "HELM_CHARTS":
        try:
            data = get_helm_chart_analysis_data(unified_service, chart_name)
            if data is not None:
                return {"data": data, "renderer": "render_helm_chart_analysis", "type": "helm_chart_analysis"}
        except Exception:
            pass

    # Fall back to standard coverage analysis
    for source_config in COVERAGE_CONFIG["data_sources"]:
        try:
            fetcher_func = globals()[source_config["fetcher"]]
            data = fetcher_func(unified_service, source_type, chart_name)
            if data is not None:
                return {"data": data, "renderer": source_config["renderer"], "type": source_config["name"]}
        except Exception:
            continue
    return None


def render_category_coverage_analysis(coverage_data: list[dict]):
    """Render category-wise coverage analysis.

    :param coverage_data: list of coverage dictionaries
    :return: None
    """
    st.markdown("**🎯 Security Category Coverage Comparison**")

    coverage_df = pd.DataFrame(coverage_data)
    st.dataframe(coverage_df, use_container_width=True)

    _render_category_performance_insights(coverage_df)


def render_basic_coverage_analysis(coverage_df: pd.DataFrame, chart_title: str = "Overall Coverage by Scanner"):
    """Render basic coverage analysis when detailed category data is not available.

    :param coverage_df: Basic coverage DataFrame
    :param chart_title: Title for the coverage chart
    :return: None
    """
    st.markdown("**📊 Basic Coverage Analysis**")
    st.info("Showing overall coverage metrics. Run detailed evaluations for category-specific analysis.")

    coverage_chart = _create_basic_coverage_chart(coverage_df, chart_title)
    st.altair_chart(coverage_chart, use_container_width=True)

    _render_basic_coverage_statistics(coverage_df)


def create_coverage_metrics_display(coverage_df: pd.DataFrame) -> None:
    """Create metrics display for coverage data.

    :param coverage_df: Coverage DataFrame
    :return: None
    """
    col1, col2, col3 = st.columns(3)

    with col1:
        avg_coverage = coverage_df["coverage"].mean()
        st.metric("Average Coverage", f"{avg_coverage: .1%}")

    with col2:
        max_coverage = coverage_df["coverage"].max()
        best_scanner = coverage_df.loc[coverage_df["coverage"].idxmax(), "scanner_name"]
        st.metric("Best Coverage", f"{max_coverage: .1%}", help=f"Achieved by {best_scanner}")

    with col3:
        coverage_range = coverage_df["coverage"].max() - coverage_df["coverage"].min()
        st.metric("Coverage Range", f"{coverage_range: .1%}", help="Difference between highest and lowest coverage")


def filter_numeric_columns_safely(df: pd.DataFrame) -> list[str]:
    """Safely filter numeric columns from DataFrame.

    :param df: DataFrame to filter
    :return: list of numeric column names
    """
    try:
        return list(df.select_dtypes(include=["number"]).columns)
    except Exception:
        return []


def render_coverage_insights(source_type=None):
    """Render coverage analysis insights using configuration.

    :param source_type: Optional source type for context-specific insights
    :return: None
    """
    if source_type is not None:
        if source_type == ScanSourceType.BENCHMARK:
            st.markdown(
                """
            **💡 Benchmark Coverage Analysis Insights:**
            - **Coverage** measures how many benchmark testing checks each scanner can detect
            - **Categories** represent different security domains (Network, IAM, Workload, etc.)
            - **Higher coverage** indicates more comprehensive standardized security checks capability
            - **Gaps** in coverage highlight areas where multiple scanners may be beneficial
            """
            )
            st.info(
                "🎯 Benchmark analysis provides standardized comparison across scanners using controlled test cases."
            )

        elif source_type == ScanSourceType.HELM_CHARTS:
            st.markdown(
                """
            **💡 Helm Chart Coverage Analysis Insights:**
            - **Coverage** measures detection of security issues in real-world application deployments
            - **Categories** show scanner effectiveness across different Helm chart security domains
            - **Higher coverage** indicates better detection of production-relevant security issues
            - **Gaps** in coverage highlight blind spots in real-world charts scanning
            """
            )
            st.info("⚓ Helm chart analysis reveals scanner performance on real-world charts from the community.")

        elif source_type == ScanSourceType.CUSTOM_MANIFESTS:
            st.markdown(
                """
            **💡 Custom Manifest Coverage Analysis Insights:**
            - **Coverage** measures detection of security issues in your specific configurations
            - **Categories** show scanner effectiveness across different domains in custom manifest analysis
            - **Higher coverage** indicates better detection of issues in your specific configurations
            - **Gaps** in coverage highlight areas where multiple scanners may be beneficial
            """
            )
            st.info("📋 Custom manifest analysis provides the most actionable metric for your specific use case.")

        else:
            # Default insights
            st.markdown(
                """
            **💡 Coverage Analysis Insights:**
            - **Coverage** measures how many security checks each scanner can detect
            - **Categories** represent different security domains (Network, IAM, Workload, etc.)
            - **Higher coverage** indicates more comprehensive security scanning capability
            - **Gaps** in coverage highlight areas where multiple scanners may be beneficial
            """
            )
    else:
        # Backward compatibility - no source type specified
        st.markdown(
            """
        **💡 Coverage Analysis Insights:**
        - **Coverage** measures how many overall security checks each scanner can detect
        - **Categories** represent different security domains (Network, IAM, Workload, etc.)
        - **Higher coverage** indicates more comprehensive security scanning capability
        - **Gaps** in coverage highlight areas where multiple scanners may be beneficial
        """
        )


def _load_all_scanner_summaries(unified_service) -> list[tuple[str, any]]:
    """Load scanner summaries for all available scanners.

    :param unified_service: Service for loading summaries
    :return: list of (scanner_name, summary) tuples
    """
    summaries = []
    for name in SCANNERS.keys():
        try:
            summary = unified_service.load_scanner_summary(name.lower())
            if _is_valid_summary(summary):
                summaries.append((name, summary))
        except Exception:
            continue
    return summaries


def _load_filtered_scanner_summaries(unified_service, source_type, chart_name=None) -> list[tuple[str, any]]:
    """Load scanner summaries filtered by source type.

    :param unified_service: Service for loading summaries
    :param source_type: Source type to filter by
    :param chart_name: Optional chart name for helm filtering
    :return: list of (scanner_name, summary) tuples
    """
    try:
        filtered_summaries = get_filtered_summaries(unified_service, source_type, chart_name)

        if not filtered_summaries:
            return []

        scanner_timestamps = {}
        for summary in filtered_summaries:
            scanner_name = summary.get("scanner_name", "").lower()
            timestamp = summary.get("scan_timestamp")
            if scanner_name and timestamp:
                scanner_timestamps[scanner_name] = timestamp

        summaries = []
        for scanner_name, timestamp in scanner_timestamps.items():
            try:
                summary = unified_service.load_scanner_summary(scanner_name, timestamp)
                if _is_valid_summary(summary):
                    summaries.append((scanner_name, summary))
            except Exception:
                continue

        return summaries
    except Exception:
        return []


def _is_valid_summary(summary) -> bool:
    """Check if summary has valid coverage data.

    :param summary: Scanner summary object
    :return: True if summary is valid for coverage analysis
    """
    return summary and hasattr(summary, "checks_per_category") and summary.checks_per_category


def _process_scanner_coverage_data(scanner_summaries: list[tuple[str, any]]) -> list[dict]:
    """Process scanner summaries into coverage data.

    :param scanner_summaries: list of (name, summary) tuples
    :return: list of coverage dictionaries
    """
    coverage_data = []
    for name, summary in scanner_summaries:
        scanner_coverage = _calculate_scanner_coverage(name, summary)
        if len(scanner_coverage) > 1:
            coverage_data.append(scanner_coverage)
    return coverage_data


def _calculate_scanner_coverage(scanner_name: str, summary) -> dict:
    """Calculate coverage for a single scanner.

    :param scanner_name: Name of the scanner
    :param summary: Scanner summary object
    :return: dictionary with scanner coverage data
    """
    scanner_coverage = {"Scanner": scanner_name}

    for category, category_summary in summary.checks_per_category.items():
        if category_summary:
            coverage_rate = _calculate_category_coverage_rate(category_summary)
            category_key = category.value if hasattr(category, "value") else str(category)
            scanner_coverage[category_key] = round(coverage_rate, 3)

    return scanner_coverage


def _calculate_category_coverage_rate(category_summary: dict) -> float:
    """Calculate coverage rate for a single category.

    :param category_summary: Category summary data
    :return: Coverage rate (0-1)
    """
    covered = category_summary.get(evaluation.ResultType.Covered, 0)
    missing = category_summary.get(evaluation.ResultType.Missing, 0)
    total = covered + missing
    return covered / total if total > 0 else 0


def _normalize_and_aggregate_coverage_summaries(summaries: list[dict]) -> pd.DataFrame:
    """Normalize scanner names and aggregate coverage summaries.

    :param summaries: list of evaluation summary dictionaries
    :return: Aggregated DataFrame with normalized scanner names
    """
    summary_list = []
    for summary in summaries:
        normalized_name = _normalize_scanner_name(summary.get("scanner_name", ""))
        summary_normalized = summary.copy()
        summary_normalized["scanner_name"] = normalized_name
        summary_list.append(summary_normalized)

    perf_df = pd.DataFrame(summary_list)

    return perf_df.groupby("scanner_name").agg(COVERAGE_CONFIG["metrics_aggregation"]).reset_index()


def _render_category_performance_insights(coverage_df: pd.DataFrame):
    """Render insights for category performance.

    :param overage_df: Coverage DataFrame
    :return: None
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


def _create_basic_coverage_chart(
    coverage_df: pd.DataFrame, chart_title: str = "Overall Coverage by Scanner"
) -> alt.Chart:
    """Create basic coverage comparison chart.

    :param coverage_df: Coverage DataFrame
    :param chart_title: Title for the chart
    :return: Altair coverage chart
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
        .properties(width=600, height=300, title=chart_title)
    )


def _render_basic_coverage_statistics(coverage_df: pd.DataFrame):
    """Render basic coverage statistics.

    :param coverage_df: Coverage DataFrame
    :return: None
    """
    create_coverage_metrics_display(coverage_df)


def get_helm_chart_analysis_data(unified_service, chart_name: str = None) -> dict | None:
    """Get Helm chart specific analysis data comparing benchmark check detection vs real-world findings.

    :param unified_service: Service for loading data
    :param chart_name: Optional specific chart name to analyze
    :return: Dictionary with Helm chart analysis data or None if unavailable
    """
    try:
        benchmark_checks = _get_benchmark_check_names(unified_service)
        helm_findings = _get_helm_chart_findings(unified_service, chart_name)

        if not helm_findings:
            return None

        analysis_data = _analyze_helm_chart_findings(helm_findings, benchmark_checks)
        return analysis_data

    except Exception as e:
        st.error(f"Error getting Helm chart analysis data: {e}")
        return None


def _get_benchmark_check_names(unified_service) -> set:
    """Get all unique check names from benchmark scans."""
    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT DISTINCT LOWER(TRIM(scanner_check_name)) as check_name
                FROM scanner_results sr
                JOIN scan_runs sr2 ON sr.scan_timestamp = sr2.timestamp
                WHERE sr2.source_type = 'manifest'
                AND scanner_check_name IS NOT NULL
                AND scanner_check_name != ''
            """
            )
            return {row["check_name"] for row in cursor.fetchall()}
    except Exception:
        return set()


def _get_helm_chart_findings(unified_service, chart_name: str = None) -> list:
    """Get findings from Helm chart scans with scanner information."""
    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()

            if chart_name:
                query = """SELECT
                        UPPER(TRIM(sr.scanner_name)) as scanner_name,
                        LOWER(TRIM(sr.scanner_check_name)) as check_name,
                        sr.severity,
                        COUNT(*) as finding_count,
                        COUNT(DISTINCT sr.obj_name) as unique_objects,
                        COUNT(DISTINCT sr.source_file) as affected_manifests
                    FROM scanner_results sr
                    JOIN scan_runs sr2 ON sr.scan_timestamp = sr2.timestamp
                    WHERE sr2.source_type = ?
                    AND sr.scanner_check_name IS NOT NULL
                    AND sr.scanner_check_name != ''
                    GROUP BY UPPER(TRIM(sr.scanner_name)), LOWER(TRIM(sr.scanner_check_name)), sr.severity
                """
                params = [f"helm-chart:{chart_name}"]
            else:
                query = """SELECT
                        UPPER(TRIM(sr.scanner_name)) as scanner_name,
                        LOWER(TRIM(sr.scanner_check_name)) as check_name,
                        sr.severity,
                        COUNT(*) as finding_count,
                        COUNT(DISTINCT sr.obj_name) as unique_objects,
                        COUNT(DISTINCT sr.source_file) as affected_manifests
                    FROM scanner_results sr
                    JOIN scan_runs sr2 ON sr.scan_timestamp = sr2.timestamp
                    WHERE sr2.source_type LIKE 'helm-chart:%'
                    AND sr.scanner_check_name IS NOT NULL
                    AND sr.scanner_check_name != ''
                    GROUP BY UPPER(TRIM(sr.scanner_name)), LOWER(TRIM(sr.scanner_check_name)), sr.severity
                """
                params = []

            cursor.execute(query, params)
            return cursor.fetchall()
    except Exception:
        return []


def _analyze_helm_chart_findings(helm_findings: list, benchmark_checks: set) -> dict:
    """Analyze Helm chart findings to categorize benchmark vs helm-specific issues."""
    scanner_analysis = {}

    for finding in helm_findings:
        scanner = _normalize_scanner_name(finding["scanner_name"])
        check_name = finding["check_name"]
        finding_count = finding["finding_count"]

        if scanner not in scanner_analysis:
            scanner_analysis[scanner] = {
                "benchmark_checks_found": 0,
                "helm_specific_checks": 0,
                "total_findings": 0,
                "benchmark_findings": 0,
                "helm_specific_findings": 0,
                "unique_checks": set(),
                "severity_distribution": {},
            }

        scanner_analysis[scanner]["unique_checks"].add(check_name)
        scanner_analysis[scanner]["total_findings"] += finding_count

        if check_name in benchmark_checks:
            scanner_analysis[scanner]["benchmark_checks_found"] += 1
            scanner_analysis[scanner]["benchmark_findings"] += finding_count
        else:
            scanner_analysis[scanner]["helm_specific_checks"] += 1
            scanner_analysis[scanner]["helm_specific_findings"] += finding_count

        severity = finding["severity"] or "UNKNOWN"
        if severity not in scanner_analysis[scanner]["severity_distribution"]:
            scanner_analysis[scanner]["severity_distribution"][severity] = 0
        scanner_analysis[scanner]["severity_distribution"][severity] += finding_count

    analysis_results = []
    for scanner, data in scanner_analysis.items():
        total_checks = len(data["unique_checks"])
        benchmark_ratio = data["benchmark_findings"] / data["total_findings"] if data["total_findings"] > 0 else 0
        helm_ratio = data["helm_specific_findings"] / data["total_findings"] if data["total_findings"] > 0 else 0

        analysis_results.append(
            {
                "scanner_name": scanner,
                "total_findings": data["total_findings"],
                "total_unique_checks": total_checks,
                "benchmark_checks_found": data["benchmark_checks_found"],
                "helm_specific_checks": data["helm_specific_checks"],
                "benchmark_findings": data["benchmark_findings"],
                "helm_specific_findings": data["helm_specific_findings"],
                "benchmark_ratio": benchmark_ratio,
                "helm_specific_ratio": helm_ratio,
                "severity_distribution": data["severity_distribution"],
            }
        )

    return {
        "scanner_analysis": analysis_results,
        "total_benchmark_checks": len(benchmark_checks),
        "summary": _create_helm_analysis_summary(analysis_results, benchmark_checks),
    }


def _create_helm_analysis_summary(analysis_results: list, benchmark_checks: set) -> dict:
    """Create summary statistics for Helm chart analysis."""
    if not analysis_results:
        return {}

    total_findings = sum(r["total_findings"] for r in analysis_results)
    total_benchmark_findings = sum(r["benchmark_findings"] for r in analysis_results)
    total_helm_findings = sum(r["helm_specific_findings"] for r in analysis_results)

    return {
        "total_findings": total_findings,
        "benchmark_findings": total_benchmark_findings,
        "helm_specific_findings": total_helm_findings,
        "benchmark_ratio": total_benchmark_findings / total_findings if total_findings > 0 else 0,
        "helm_ratio": total_helm_findings / total_findings if total_findings > 0 else 0,
        "total_benchmark_checks_available": len(benchmark_checks),
        "scanners_count": len(analysis_results),
    }


def render_helm_chart_analysis(analysis_data: dict):
    """Render Helm chart specific scanner analysis.

    :param analysis_data: Dictionary containing Helm chart analysis data
    :return: None
    """
    st.markdown("**⚓ Helm Chart Security Analysis**")
    st.info("Comparing benchmark check detection vs. real-world Helm chart security findings")

    scanner_data = analysis_data["scanner_analysis"]
    summary = analysis_data["summary"]

    # Overview metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Findings", f"{summary.get('total_findings', 0):,}")
    with col2:
        st.metric("Benchmark Issues Found", f"{summary.get('benchmark_findings', 0):,}")
    with col3:
        st.metric("Helm-Specific Issues", f"{summary.get('helm_specific_findings', 0):,}")
    with col4:
        benchmark_pct = summary.get("benchmark_ratio", 0) * 100
        st.metric("Benchmark Coverage", f"{benchmark_pct:.1f}%")

    # Scanner comparison chart
    if scanner_data:
        chart_data = []
        for scanner in scanner_data:
            chart_data.extend(
                [
                    {
                        "Scanner": scanner["scanner_name"],
                        "Type": "Benchmark Issues",
                        "Findings": scanner["benchmark_findings"],
                        "Percentage": scanner["benchmark_ratio"] * 100,
                    },
                    {
                        "Scanner": scanner["scanner_name"],
                        "Type": "Helm-Specific Issues",
                        "Findings": scanner["helm_specific_findings"],
                        "Percentage": scanner["helm_specific_ratio"] * 100,
                    },
                ]
            )

        chart_df = pd.DataFrame(chart_data)

        # Stacked bar chart showing benchmark vs helm-specific findings
        chart = (
            alt.Chart(chart_df)
            .mark_bar()
            .encode(
                x=alt.X("Scanner:N", axis=alt.Axis(labelAngle=0)),
                y=alt.Y("Findings:Q", title="Number of Findings"),
                color=alt.Color(
                    "Type:N",
                    scale=alt.Scale(domain=["Benchmark Issues", "Helm-Specific Issues"], range=["#2E86C1", "#F39C12"]),
                ),
                tooltip=["Scanner:N", "Type:N", "Findings:Q", "Percentage:Q"],
            )
            .properties(width=600, height=400, title="Benchmark vs Helm-Specific Security Findings")
        )

        st.altair_chart(chart, use_container_width=True)

        # Detailed scanner table
        st.markdown("**📊 Detailed Scanner Analysis**")
        display_df = pd.DataFrame(
            [
                {
                    "Scanner": s["scanner_name"],
                    "Total Findings": s["total_findings"],
                    "Unique Checks": s["total_unique_checks"],
                    "Benchmark Issues": s["benchmark_findings"],
                    "Helm-Specific Issues": s["helm_specific_findings"],
                    "Benchmark %": f"{s['benchmark_ratio']*100:.1f}%",
                    "Helm-Specific %": f"{s['helm_specific_ratio']*100:.1f}%",
                }
                for s in scanner_data
            ]
        )
        st.dataframe(display_df, use_container_width=True, hide_index=True)

        # Analysis insights
        st.markdown("**💡 Helm Chart Analysis Insights:**")
        insights = [
            f"**{summary.get('benchmark_findings', 0):,} benchmark security issues** were detected in real Helm charts",
            f"**{summary.get('helm_specific_findings', 0):,} additional issues** were found that aren't in benchmark tests",  # noqa: E501
            f"**{benchmark_pct:.1f}% of findings** match known benchmark security patterns",
            "**Higher benchmark percentages** indicate scanners find well-known security issues",
            "**Helm-specific findings** reveal real-world issues not covered by benchmark tests",
        ]

        for insight in insights:
            st.markdown(f"- {insight}")
    else:
        st.info("No Helm chart analysis data available.")
