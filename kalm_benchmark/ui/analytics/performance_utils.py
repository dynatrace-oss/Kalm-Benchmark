import altair as alt
import pandas as pd
import streamlit as st

from kalm_benchmark.utils.data.normalization import (
    normalize_scanner_name as _normalize_scanner_name,
)

PERFORMANCE_CONFIG = {
    "medals": ["🥇", "🥈", "🥉"],
    "color_thresholds": [
        (0.8, "#28a745", "excellent"),
        (0.6, "#ffc107", "good"),
        (0.0, "#dc3545", "needs improvement"),
    ],
    "metrics_columns": {
        "score": "max",
        "coverage": "max",
        "extra_checks": "sum",
        "missing_checks": "min",  # Take minimum missing checks (best performance)
    },
}


def normalize_and_aggregate_performance_data(summaries: list[dict]) -> pd.DataFrame:
    """Normalize scanner names and aggregate performance metrics.

    :param summaries: list of evaluation summary dictionaries
    :return: DataFrame with normalized and aggregated performance data
    """
    if not summaries:
        return pd.DataFrame()

    summary_list = []
    for summary in summaries:
        normalized_name = _normalize_scanner_name(summary.get("scanner_name", ""))
        summary_normalized = summary.copy()
        summary_normalized["scanner_name"] = normalized_name
        summary_list.append(summary_normalized)

    perf_df = pd.DataFrame(summary_list)

    # Group by normalized scanner names and aggregate using configuration
    return perf_df.groupby("scanner_name").agg(PERFORMANCE_CONFIG["metrics_columns"]).reset_index()


def get_performance_medal(rank: int) -> str:
    """Get medal emoji for ranking position.

    :param rank: Ranking position (1-based)
    :return: Medal emoji or numbered position
    """
    if rank <= len(PERFORMANCE_CONFIG["medals"]):
        return PERFORMANCE_CONFIG["medals"][rank - 1]
    return f"{rank}."


def get_performance_color(score: float) -> str:
    """Get color code based on performance score.

    :param score: Performance score (0-1)
    :return: Color hex code
    """
    for threshold, color, _ in PERFORMANCE_CONFIG["color_thresholds"]:
        if score >= threshold:
            return color
    return PERFORMANCE_CONFIG["color_thresholds"][-1][1]


def create_performance_scatter_chart(perf_df: pd.DataFrame) -> alt.Chart:
    """Create F1 Score vs Coverage scatter plot.

    :param perf_df: Performance DataFrame
    :return: Altair scatter chart
    """
    return (
        alt.Chart(perf_df)
        .mark_circle(size=150, opacity=0.8)
        .encode(
            x=alt.X(
                "coverage:Q",
                title="Coverage (% of benchmark checks)",
                scale=alt.Scale(domain=[0, 1]),
                axis=alt.Axis(format="%"),
            ),
            y=alt.Y("score:Q", title="F1 Score", scale=alt.Scale(domain=[0, 1]), axis=alt.Axis(format="%")),
            color=alt.Color("scanner_name:N", title="Scanner", scale=alt.Scale(scheme="category10")),
            tooltip=["scanner_name:N", "score:Q", "coverage:Q", "extra_checks:Q", "missing_checks:Q"],
        )
        .properties(width=400, height=350, title="Benchmark Performance: F1 Score vs Coverage")
    )


def render_performance_card(scanner_data: pd.Series, medal: str, color: str, rank: int):
    """Render a performance ranking card for a scanner.

    :param scanner_data: Scanner performance data; medal: Medal or rank indicator
    :param color: Color code for performance level; rank: Ranking position
    :return: None
    """
    name = scanner_data["scanner_name"]
    score = scanner_data["score"]
    coverage = scanner_data["coverage"]
    extra = scanner_data.get("extra_checks", 0)
    missing = scanner_data.get("missing_checks", 0)

    st.markdown(
        f"""<div style="padding: 0.5rem; margin: 0.3rem 0; background: {color}15;
                       border-left: 4px solid {color}; border-radius: 4px;">
        <strong>{medal} {name}</strong><br/>
        <small>F1: {score:.3f} | Coverage: {coverage * 100:.1f}% | Extra: {extra} | Missing: {missing}</small>
        </div>""",
        unsafe_allow_html=True,
    )


def create_performance_details_table(perf_df: pd.DataFrame) -> pd.DataFrame:
    """Create formatted performance details table.

    :param perf_df: Performance DataFrame
    :return: Formatted DataFrame for display
    """
    display_df = perf_df[["scanner_name", "score", "coverage", "extra_checks", "missing_checks"]].copy()
    display_df = display_df.rename(
        columns={
            "scanner_name": "Scanner",
            "score": "F1 Score",
            "coverage": "Coverage",
            "extra_checks": "Extra Findings",
            "missing_checks": "Missing Checks",
        }
    )

    display_df["F1 Score"] = display_df["F1 Score"].round(3)
    display_df["Coverage"] = (display_df["Coverage"] * 100).round(1)

    return display_df.sort_values("F1 Score", ascending=False)


def render_performance_overview_metrics(perf_df: pd.DataFrame):
    """Render performance overview metrics section.

    :param perf_df: Performance DataFrame
    :return: None
    """
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Scanners Evaluated", len(perf_df), help="Number of scanners with benchmark evaluation results")

    with col2:
        avg_score = perf_df["score"].mean() if len(perf_df) > 0 else 0
        st.metric("Avg F1 Score", f"{avg_score:.3f}", help="Average F1 score across all evaluated scanners")

    with col3:
        avg_coverage = perf_df["coverage"].mean() if len(perf_df) > 0 else 0
        st.metric(
            "Avg Coverage", f"{avg_coverage * 100:.1f}%", help="Average benchmark check coverage across all scanners"
        )

    with col4:
        total_extra = perf_df["extra_checks"].sum() if len(perf_df) > 0 else 0
        st.metric("Total Extra Findings", total_extra, help="Total additional findings beyond benchmark checks")


def render_top_performers(perf_df: pd.DataFrame):
    """Render top performing scanners list.

    :param perf_df: Performance DataFrame
    :return: None
    """
    st.markdown("**🏅 Top Performing Scanners:**")

    top_scanners = perf_df.nlargest(5, "score")[["scanner_name", "score", "coverage"]]

    for i, (_, scanner) in enumerate(top_scanners.iterrows(), 1):
        name = scanner["scanner_name"]
        score = scanner["score"]
        coverage = scanner["coverage"]

        medal = get_performance_medal(i)
        st.markdown(f"{medal} **{name}** - Score: {score:.3f} | Coverage: {coverage * 100:.1f}%")


def render_performance_rankings(perf_df: pd.DataFrame):
    """Render detailed performance rankings section.

    :parm perf_df: Performance DataFrame
    :return: None
    """
    st.markdown("**🏆 Benchmark Rankings**")

    ranked_df = perf_df.sort_values("score", ascending=False)

    for i, (_, scanner) in enumerate(ranked_df.head(10).iterrows(), 1):
        medal = get_performance_medal(i)
        color = get_performance_color(scanner["score"])
        render_performance_card(scanner, medal, color, i)


def render_performance_insights():
    """Render performance analysis insights.

    :return: None
    """
    st.markdown(
        """
    **💡 Benchmark Insights:**
    - **F1 Score** measures the harmonic mean of precision and recall against benchmark checks
    - **Coverage** shows the percentage of benchmark checks the scanner can detect
    - **Extra Findings** are security issues found beyond the benchmark scope
    - **Missing Checks** are benchmark items the scanner failed to detect
    """
    )
