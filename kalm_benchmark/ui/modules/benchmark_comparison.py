import altair as alt
import pandas as pd
import streamlit as st
from loguru import logger

from kalm_benchmark.ui.analytics.coverage_utils import (
    render_basic_coverage_analysis,
    render_category_coverage_analysis,
)
from kalm_benchmark.ui.analytics.historical_analysis import (
    render_historical_scan_trends,
)
from kalm_benchmark.ui.interface.gen_utils import get_unified_service


def get_benchmark_evaluation_summaries() -> pd.DataFrame:
    """Get evaluation summaries for benchmark manifests only (excludes helm charts).

    :return: DataFrame with benchmark evaluation summaries
    """
    unified_service = get_unified_service()

    try:
        # Use the database method directly if the service method doesn't exist (cache issue)
        if hasattr(unified_service, "create_benchmark_evaluation_summary_dataframe"):
            summaries_list = unified_service.create_benchmark_evaluation_summary_dataframe()
        else:
            logger.warning("Service method not available, using database directly")
            summaries_list = unified_service.db.get_benchmark_evaluation_summaries()

        if not summaries_list:
            return pd.DataFrame()

        summaries_df = pd.DataFrame(summaries_list)
        return summaries_df

    except Exception as e:
        logger.error(f"Error fetching benchmark evaluation summaries: {e}")
        return pd.DataFrame()


def show():
    """Show the benchmark scanner comparison page."""

    # Benchmark Comparison Header
    st.markdown(
        """
        <div style="text-align: center; padding: 3.5rem 0 2.5rem 0;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 30%,
                      #f093fb 60%, #f857a6 80%, #667eea 100%);
                    border-radius: 20px; margin-bottom: 2rem;
                    box-shadow: 0 15px 40px rgba(102, 126, 234, 0.5);
                    position: relative; overflow: hidden;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0;
                        background: radial-gradient(circle at 15% 25%, rgba(248, 87, 166, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 85% 75%, rgba(118, 75, 162, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 50% 15%, rgba(240, 147, 251, 0.3) 0%, transparent 45%);
                        pointer-events: none;"></div>
            <div style="max-width: 800px; margin: 0 auto; padding: 0 2rem; position: relative; z-index: 1;">
                <h1 style="color: #FFFFFF; margin-bottom: 0.5rem; font-size: 3.2rem; font-weight: 800;
                           text-shadow: 0 4px 15px rgba(0,0,0,0.4); letter-spacing: -0.02em;">
                    📈 Benchmark Analysis
                </h1>
                <h3 style="color: rgba(255,255,255,0.95); font-weight: 500; margin-bottom: 1.5rem;
                          font-size: 1.6rem; text-shadow: 0 2px 8px rgba(0,0,0,0.3);">
                    Scanner Effectiveness Analysis
                </h3>
                <p style="color: rgba(255,255,255,0.9); font-size: 1.1rem; line-height: 1.5;
                         text-shadow: 0 1px 4px rgba(0,0,0,0.2); max-width: 600px; margin: 0 auto;">
                    Compare security scanner accuracy and coverage on standardized benchmark manifests
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Get benchmark evaluation data
    evaluation_summaries = get_benchmark_evaluation_summaries()

    if evaluation_summaries.empty:
        st.warning("🔍 **No benchmark evaluation data available**")
        st.markdown(
            """
        **To enable benchmark comparison:**

        1. **Generate benchmark manifests**:
           ```bash
           poetry run cli generate
           ```

        2. **Run scanner evaluations**:
           ```bash
           poetry run cli scan <scanner-name> -f manifests
           poetry run cli evaluate <scanner-name>
           ```

        3. **Repeat for multiple scanners** to enable comparison

        📖 **Available scanners**: Kubescape, KICS, Trivy, Checkov, Polaris, and more
        """
        )
        return

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        scanner_count = len(evaluation_summaries)
        st.metric("📊 Scanners", scanner_count, help="Number of scanners evaluated against benchmark manifests")

    with col2:
        avg_f1_score = evaluation_summaries["score"].mean() if "score" in evaluation_summaries.columns else 0
        st.metric("🎯 Avg F1 Score", f"{avg_f1_score:.3f}", help="Average F1 score across all benchmark evaluations")

    with col3:
        avg_coverage = evaluation_summaries["coverage"].mean() if "coverage" in evaluation_summaries.columns else 0
        st.metric("📈 Avg Coverage", f"{avg_coverage * 100:.1f}%", help="Average benchmark coverage percentage")

    with col4:
        total_missing = (
            evaluation_summaries["missing_checks"].sum() if "missing_checks" in evaluation_summaries.columns else 0
        )
        st.metric("⚠️ Total Missing", int(total_missing), help="Total missed detections across all scanners")

    st.markdown("---")
    st.subheader("🏆 Scanner Performance Comparison")

    if len(evaluation_summaries) >= 2:
        # Performance scatter plot
        col1, col2 = st.columns([2, 1])

        with col1:
            scatter_data = evaluation_summaries[["scanner_name", "score", "coverage"]].copy()
            scatter_data.columns = ["Scanner", "F1_Score", "Coverage"]
            scatter_data["Coverage"] = scatter_data["Coverage"] * 100

            scatter_chart = (
                alt.Chart(scatter_data)
                .mark_circle(size=150, opacity=0.8)
                .add_selection(alt.selection_single())
                .encode(
                    x=alt.X("Coverage:Q", title="Coverage (%)", scale=alt.Scale(domain=[0, 100])),
                    y=alt.Y("F1_Score:Q", title="F1 Score", scale=alt.Scale(domain=[0, 1])),
                    color=alt.Color("Scanner:N", legend=alt.Legend(title="Scanner")),
                    tooltip=["Scanner:N", "F1_Score:Q", "Coverage:Q"],
                )
                .properties(width=500, height=400, title="Scanner Performance: F1 Score vs Coverage")
            )

            st.altair_chart(scatter_chart, use_container_width=True)

        with col2:
            st.subheader("🎯 Top Performers")

            top_scanners = evaluation_summaries.nlargest(3, "score")[["scanner_name", "score", "coverage"]]

            for idx, row in top_scanners.iterrows():
                rank = ["🥇", "🥈", "🥉"][idx] if idx < 3 else f"{idx+1}."
                st.markdown(
                    f"""
                **{rank} {row['scanner_name'].title()}**
                F1: {row['score']:.3f} | Coverage: {row['coverage'] * 100:.1f}%
                """
                )

    else:
        st.info("📊 Need at least 2 scanners for comparison visualization")

        if len(evaluation_summaries) == 1:
            scanner_row = evaluation_summaries.iloc[0]
            st.markdown(
                f"""
            **Current Scanner: {scanner_row['scanner_name'].title()}**
            - F1 Score: {scanner_row['score']:.3f}
            - Coverage: {scanner_row['coverage'] * 100:.1f}%
            - Missing Checks: {int(scanner_row['missing_checks'])}
            - Extra Checks: {int(scanner_row['extra_checks'])}
            """
            )

    # Detailed comparison table
    st.markdown("---")
    st.subheader("📋 Detailed Comparison")

    # Format data for display
    display_data = evaluation_summaries.copy()
    display_data["scanner_name"] = display_data["scanner_name"].str.title()
    display_data["score"] = display_data["score"].round(3)
    display_data["coverage"] = (display_data["coverage"] * 100).round(1)

    display_columns = ["scanner_name", "score", "coverage", "missing_checks", "extra_checks"]
    available_columns = [col for col in display_columns if col in display_data.columns]

    if available_columns:
        comparison_table = display_data[available_columns]
        comparison_table.columns = ["Scanner", "F1 Score", "Coverage (%)", "Missing", "Extra"]
        comparison_table = comparison_table.sort_values("F1 Score", ascending=False)

        st.dataframe(comparison_table, use_container_width=True, hide_index=True)

    st.markdown("---")
    unified_service = get_unified_service()

    coverage_tab1, coverage_tab2 = st.tabs(["📊 Basic Coverage", "🎯 Category Analysis"])

    benchmark_summaries = get_benchmark_evaluation_summaries()

    with coverage_tab1:
        if not benchmark_summaries.empty:
            render_basic_coverage_analysis(benchmark_summaries)
        else:
            st.info("No benchmark evaluation data available. Run benchmark evaluations to see coverage analysis.")

    with coverage_tab2:
        if not benchmark_summaries.empty:
            coverage_data = benchmark_summaries.to_dict("records")
            render_category_coverage_analysis(coverage_data)
        else:
            st.info(
                "No benchmark evaluation data available. Run benchmark evaluations to see category coverage analysis."
            )

    # Historical trends (if data available)
    st.markdown("---")
    with st.expander("📈 Historical Analysis", expanded=False):
        render_historical_scan_trends(unified_service, source_type=None, chart_name=None)

    # Help section
    with st.expander("❓ Understanding Benchmark Comparison", expanded=False):
        st.markdown(
            """
        **Benchmark Comparison** analyzes scanner performance against KALM's standardized test suite.

        **Key Metrics:**
        - **F1 Score**: Balance of precision and recall (0.0-1.0, higher = better)
        - **Coverage**: Percentage of 235+ benchmark checks detected
        - **Missing**: Vulnerabilities the scanner failed to detect (false negatives)
        - **Extra**: Additional findings beyond benchmark scope

        **Interpreting Results:**
        - **High F1 + High Coverage**: Excellent scanner for comprehensive security
        - **High F1 + Low Coverage**: Accurate but narrow detection scope
        - **Low F1 + High Coverage**: Broad detection but many false positives
        - **Low F1 + Low Coverage**: May need better configuration or different scanner

        **Best Practices:**
        - Compare multiple scanners on the same benchmark
        - Consider both accuracy (F1) and breadth (coverage)
        - Test with your specific manifest patterns when possible
        """
        )
