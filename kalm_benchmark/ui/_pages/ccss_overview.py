from typing import List, Optional

import altair as alt
import pandas as pd
import streamlit as st

from kalm_benchmark.evaluation.ccss.ccss_service import CCSSService
from kalm_benchmark.ui.utils.gen_utils import get_unified_service


def show():
    """Show the CCSS overview page"""

    # CCSS Overview Header with rich Dynatrace gradient palette
    st.markdown(
        """
        <div style="text-align: center; padding: 3.5rem 0 2.5rem 0; 
                    background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 20%, #74b9ff 40%, #00cec9 60%, #55efc4 80%, #6c5ce7 100%); 
                    border-radius: 20px; margin-bottom: 2rem; 
                    box-shadow: 0 15px 40px rgba(108, 92, 231, 0.5); 
                    position: relative; overflow: hidden;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; 
                        background: radial-gradient(circle at 15% 25%, rgba(162, 155, 254, 0.4) 0%, transparent 50%), 
                                    radial-gradient(circle at 85% 75%, rgba(116, 185, 255, 0.4) 0%, transparent 50%), 
                                    radial-gradient(circle at 50% 15%, rgba(0, 206, 201, 0.3) 0%, transparent 45%), 
                                    radial-gradient(circle at 25% 85%, rgba(85, 239, 196, 0.3) 0%, transparent 45%); 
                        pointer-events: none;"></div>
            <div style="max-width: 800px; margin: 0 auto; padding: 0 2rem; position: relative; z-index: 1;">
                <h1 style="color: #FFFFFF; margin-bottom: 0.5rem; font-size: 3.2rem; font-weight: 800; 
                           text-shadow: 0 4px 15px rgba(0,0,0,0.4); letter-spacing: -0.02em;">
                    🎯 CCSS Alignment Overview
                </h1>
                <h3 style="color: rgba(255,255,255,0.95); font-weight: 500; margin-bottom: 1.5rem; 
                          font-size: 1.6rem; text-shadow: 0 2px 8px rgba(0,0,0,0.3);">
                    Common Configuration Scoring System Analysis
                </h3>
                <p style="color: rgba(255,255,255,0.9); max-width: 650px; margin: 0 auto; 
                         line-height: 1.7; font-size: 1.15rem; text-shadow: 0 2px 6px rgba(0,0,0,0.25);">
                    Analyze how security scanners align with the official CCSS scores. 
                    Higher alignment scores indicate better agreement with standardized security scoring methodologies.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    unified_service = get_unified_service()
    ccss_service = unified_service.ccss_service

    evaluation_runs = ccss_service.db.get_evaluation_runs(limit=20)

    if not evaluation_runs:
        st.info("No CCSS evaluation runs found. Run a CCSS evaluation first to see alignment results.")
        return

    run_options = ["Latest"] + [f"{run.timestamp} ({run.source_type.value})" for run in evaluation_runs]
    selected_run_index = st.selectbox(
        "Select Evaluation Run", range(len(run_options)), format_func=lambda x: run_options[x]
    )

    selected_run_id = None if selected_run_index == 0 else evaluation_runs[selected_run_index - 1].id

    summary = ccss_service.get_research_evaluation_summary(selected_run_id)

    if not summary["scanner_rankings"]:
        st.warning("No scanner alignment data found for the selected evaluation run.")
        return

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Scanners", summary["total_scanners"])

    with col2:
        st.metric("Total Findings", summary["overall_statistics"]["total_findings"])

    with col3:
        avg_alignment = summary["overall_statistics"]["avg_alignment"] or 0
        st.metric("Avg Alignment", f"{avg_alignment:.2f}")

    with col4:
        max_alignment = summary["overall_statistics"]["max_alignment"] or 0
        st.metric("Best Alignment", f"{max_alignment:.2f}")

    st.divider()

    show_scanner_rankings(summary["scanner_rankings"])

    st.divider()

    show_alignment_distribution(ccss_service, selected_run_id)

    st.divider()

    show_category_performance(summary["scanner_rankings"])


def show_scanner_rankings(alignments: List):
    """Show scanner rankings by CCSS alignment"""
    st.subheader("📊 Scanner Rankings by CCSS Alignment")

    rankings_data = []
    for i, alignment in enumerate(alignments, 1):
        rankings_data.append(
            {
                "Rank": i,
                "Scanner": alignment.scanner_name,
                "Alignment Score": f"{alignment.avg_alignment_score:.3f}",
                "Findings Count": alignment.total_findings,
                "Score Variance": f"{alignment.score_variance:.3f}",
                "CCSS Correlation": f"{alignment.overall_ccss_correlation:.3f}",
                "Best Categories": ", ".join(alignment.best_aligned_categories[:2]),
                "Worst Categories": ", ".join(alignment.worst_aligned_categories[:2]),
            }
        )

    df_rankings = pd.DataFrame(rankings_data)

    styled_df = df_rankings.style.format(
        {"Alignment Score": "{:.3f}", "Score Variance": "{:.3f}", "CCSS Correlation": "{:.3f}"}
    ).apply(
        lambda x: [
            "background-color: #d4edda" if i == 0 else "background-color: #f8d7da" if i == len(x) - 1 else ""
            for i in range(len(x))
        ],
        axis=0,
    )

    st.dataframe(styled_df, use_container_width=True)

    chart_data = pd.DataFrame(
        {
            "Scanner": [a.scanner_name for a in alignments],
            "Alignment Score": [a.avg_alignment_score for a in alignments],
            "Findings": [a.total_findings for a in alignments],
        }
    )

    chart = (
        alt.Chart(chart_data)
        .mark_bar()
        .encode(
            x=alt.X("Scanner:N", sort="-y"),
            y=alt.Y("Alignment Score:Q", scale=alt.Scale(domain=[0, 1])),
            color=alt.Color("Alignment Score:Q", scale=alt.Scale(scheme="viridis")),
            tooltip=["Scanner", "Alignment Score", "Findings"],
        )
        .properties(width=600, height=400, title="Scanner CCSS Alignment Scores")
    )

    st.altair_chart(chart, use_container_width=True)


def show_alignment_distribution(ccss_service: CCSSService, evaluation_run_id: Optional[str]):
    """Show distribution of alignment scores"""
    st.subheader("📈 Alignment Score Distribution")

    findings = ccss_service.db.get_misconfiguration_findings(evaluation_run_id=evaluation_run_id)
    scored_findings = [f for f in findings if f.alignment_score is not None]

    if not scored_findings:
        st.info("No alignment scores available for distribution analysis.")
        return

    alignment_scores = [f.alignment_score for f in scored_findings]

    hist_data = pd.DataFrame(
        {"Alignment Score": alignment_scores, "Scanner": [f.scanner_name for f in scored_findings]}
    )

    histogram = (
        alt.Chart(hist_data)
        .mark_bar()
        .encode(
            x=alt.X("Alignment Score:Q", bin=alt.Bin(maxbins=20)),
            y="count()",
            color=alt.Color("Scanner:N"),
            tooltip=["count()", "Scanner"],
        )
        .properties(width=600, height=300, title="Distribution of CCSS Alignment Scores")
    )

    st.altair_chart(histogram, use_container_width=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Mean Alignment", f"{sum(alignment_scores) / len(alignment_scores):.3f}")
    with col2:
        st.metric("Median Alignment", f"{sorted(alignment_scores)[len(alignment_scores)//2]:.3f}")
    with col3:
        st.metric(
            "Std Deviation",
            f"{(sum((x - sum(alignment_scores)/len(alignment_scores))**2 for x in alignment_scores) / len(alignment_scores))**0.5:.3f}",
        )


def show_category_performance(alignments: List):
    """Show performance matrix by category"""
    st.subheader("🎯 Category Performance Matrix")

    all_categories = set()
    for alignment in alignments:
        all_categories.update(alignment.best_aligned_categories)
        all_categories.update(alignment.worst_aligned_categories)

    if not all_categories:
        st.info("No category performance data available.")
        return

    matrix_data = []
    for alignment in alignments:
        for category in sorted(all_categories):
            if category in alignment.best_aligned_categories:
                score = 0.8 + (alignment.avg_alignment_score * 0.2)
            elif category in alignment.worst_aligned_categories:
                score = alignment.avg_alignment_score * 0.6
            else:
                score = alignment.avg_alignment_score

            matrix_data.append({"Scanner": alignment.scanner_name, "Category": category, "Performance": score})

    df_matrix = pd.DataFrame(matrix_data)

    heatmap_data = df_matrix.pivot(index="Scanner", columns="Category", values="Performance")

    styled_heatmap = heatmap_data.style.background_gradient(cmap="RdYlGn", vmin=0, vmax=1)
    st.dataframe(styled_heatmap, use_container_width=True)

    heatmap_chart = (
        alt.Chart(df_matrix)
        .mark_rect()
        .encode(
            x=alt.X("Category:N"),
            y=alt.Y("Scanner:N"),
            color=alt.Color("Performance:Q", scale=alt.Scale(scheme="viridis")),
            tooltip=["Scanner", "Category", "Performance"],
        )
        .properties(width=600, height=400, title="Scanner Performance by Security Category")
    )

    st.altair_chart(heatmap_chart, use_container_width=True)


def show_research_insights():
    """Show insights from research evaluation"""
    st.subheader("🔬 Research Insights")

    st.markdown(
        """
    ### Key Findings:
    - **Scanner Variability**: Different scanners show significant variation in CCSS alignment
    - **Category Specialization**: Some scanners excel in specific security categories
    - **Correlation Patterns**: Strong correlation indicates consistent scoring methodology
    
    ### Recommendations:
    - Use multiple scanners for comprehensive coverage
    - Consider scanner strengths for specific security domains
    - Validate critical findings across multiple tools
    """
    )


if __name__ == "__main__":
    show()
