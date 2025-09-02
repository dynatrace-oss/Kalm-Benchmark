import pandas as pd
import streamlit as st
from loguru import logger

from kalm_benchmark.ui.visualization.chart_utils import create_severity_pie_chart
from kalm_benchmark.utils.constants import (
    EXCELLENT_COLOR,
    EXCELLENT_SCORE_THRESHOLD,
    GOOD_COLOR,
    GOOD_SCORE_THRESHOLD,
    NEEDS_IMPROVEMENT_COLOR,
)

# Bind logger to UI component for proper log filtering
logger = logger.bind(component="ui")


def render_metric_cards(metrics: dict[str, str], columns: int | str = None) -> None:
    if not metrics:
        return

    cols = st.columns(columns or len(metrics))
    for i, (name, value) in enumerate(metrics.items()):
        if i < len(cols):
            with cols[i]:
                st.metric(name, value)


def render_ranking_list(
    ranked_data: pd.DataFrame, score_col: str = "score", name_col: str = "scanner_name", limit: int = 10
) -> None:
    """Creates a ranking element in the UI displaying scanner coverage

    :param ranked_data: Scanners ranked in order of coverage in a DataFrame
    :param score_col: Column in DataFrame containing score results
    :param name_col: Column in DataFrame containing scanner names
    :param limit: Maximum number of scanner results to dispaly in the UI
    :return: None
    """
    for i, (_, row) in enumerate(ranked_data.head(limit).iterrows(), 1):
        ranking_item = _create_ranking_item(i, row, score_col, name_col)
        _render_ranking_item(ranking_item)


def _create_ranking_item(position: int, row: pd.Series, score_col: str, name_col: str) -> dict:
    name = row[name_col]
    score = row[score_col]

    return {
        "medal": _get_medal_for_position(position),
        "color": _get_color_for_score(score),
        "name": name,
        "extra_text": _build_extra_info_text(row, score),
    }


def _get_medal_for_position(position: int) -> str:
    medal_map = {1: "🥇", 2: "🥈", 3: "🥉"}
    return medal_map.get(position, f"{position}.")


def _get_color_for_score(score: float) -> str:
    if score >= EXCELLENT_SCORE_THRESHOLD:
        return EXCELLENT_COLOR
    elif score >= GOOD_SCORE_THRESHOLD:
        return GOOD_COLOR
    else:
        return NEEDS_IMPROVEMENT_COLOR


def _build_extra_info_text(row: pd.Series, score: float) -> str:
    extra_info = []

    info_fields = {
        "coverage": lambda x: f"Coverage: {x:.3f}",
        "extra_checks": lambda x: f"Extra: {x}",
        "missing_checks": lambda x: f"Missing: {x}",
    }

    for field, formatter in info_fields.items():
        if field in row:
            extra_info.append(formatter(row[field]))

    return " | ".join(extra_info) if extra_info else f"Score: {score:.3f}"


def _render_ranking_item(item: dict):
    st.markdown(
        f"""<div style="padding: 0.5rem; margin: 0.3rem 0; background: {item['color']}15;
                    border-left: 4px solid {item['color']}; border-radius: 4px;">
            <strong>{item['medal']} {item['name']}</strong><br/>
            <small>{item['extra_text']}</small>
        </div>""",
        unsafe_allow_html=True,
    )


def render_scanner_pie_charts(severity_pct_df: pd.DataFrame):
    scanners = severity_pct_df["Scanner"].unique()
    logger.debug(f"Rendering pie charts for {len(scanners)} scanners")

    try:
        layout_config = _get_chart_layout_config(len(scanners))
        _render_charts_with_layout(scanners, severity_pct_df, layout_config)
        logger.debug("Successfully rendered all scanner pie charts")
    except (ValueError, KeyError, TypeError) as e:
        logger.error(f"Chart rendering failed due to data issue: {e}")
        st.error("❌ Error rendering charts: Invalid data format")
    except Exception as e:
        logger.error(f"Failed to render scanner pie charts: {e}")
        st.error(f"❌ Error rendering charts: {e}")


def _get_chart_layout_config(num_scanners: int) -> dict:
    if num_scanners <= 2:
        return {"type": "single_row", "columns_per_row": num_scanners}
    else:
        return {"type": "multi_row", "columns_per_row": 2}


def _render_charts_with_layout(scanners: list, severity_pct_df: pd.DataFrame, layout_config: dict):
    if layout_config["type"] == "single_row":
        _render_single_row_charts(scanners, severity_pct_df, layout_config["columns_per_row"])
    else:
        _render_multi_row_charts(scanners, severity_pct_df, layout_config["columns_per_row"])


def _render_single_row_charts(scanners: list, severity_pct_df: pd.DataFrame, num_columns: int):
    cols = st.columns(num_columns)
    for i, col in enumerate(cols):
        if i < len(scanners):
            _render_single_pie_chart(col, scanners[i], severity_pct_df)


def _render_multi_row_charts(scanners: list, severity_pct_df: pd.DataFrame, columns_per_row: int):
    for i in range(0, len(scanners), columns_per_row):
        cols = st.columns(columns_per_row)
        for j, col in enumerate(cols):
            scanner_index = i + j
            if scanner_index < len(scanners):
                _render_single_pie_chart(col, scanners[scanner_index], severity_pct_df)


def _render_single_pie_chart(col, scanner: str, severity_pct_df: pd.DataFrame):
    """Render a single pie chart with breakdown"""
    scanner_data = severity_pct_df[severity_pct_df["Scanner"] == scanner]

    with col:
        try:
            if scanner_data.empty:
                logger.debug(f"No data available for scanner: {scanner}")
                st.info(f"No severity data for {scanner}")
                return

            pie_chart = create_severity_pie_chart(scanner_data, scanner)
            st.altair_chart(pie_chart, use_container_width=True)
        except (ValueError, KeyError) as e:
            logger.warning(f"Data issue rendering chart for {scanner}: {e}")
            st.warning(f"⚠️ Chart data unavailable for {scanner}")
        except Exception as e:
            logger.error(f"Failed to render pie chart for {scanner}: {e}")
            st.warning(f"⚠️ Chart unavailable for {scanner}")

        for _, row in scanner_data.iterrows():
            percentage = row["Percentage"]
            count = row["Count"]
            severity = row["Severity"]
            st.markdown(f"• {severity}: {percentage:.1f}% ({count} findings)")


def render_severity_summary_table(severity_df: pd.DataFrame):
    """Extract summary table rendering.

    :param severity_df: DataFrame with severity information
    :return: None
    """
    try:
        severity_pivot = severity_df.pivot_table(index="Scanner", columns="Severity", values="Count", fill_value=0)

        if not severity_pivot.empty:
            logger.debug(f"Rendering severity table with {len(severity_pivot)} scanners")
            st.dataframe(severity_pivot, use_container_width=True)
        else:
            logger.warning("No data available for severity summary table")
            st.info("ℹ️ No severity data available")
    except (ValueError, KeyError) as e:
        logger.warning(f"Data issue with severity summary table: {e}")
        st.error("❌ Error rendering summary table: Invalid data format")
    except Exception as e:
        logger.error(f"Failed to render severity summary table: {e}")
        st.error(f"❌ Error rendering summary table: {e}")


def render_scanner_metrics(scanner_patterns: pd.DataFrame):
    """Extract scanner pattern metrics display.

    :param scanner_patterns: DataFrame with scanner statistics
    :return: None
    """
    for _, row in scanner_patterns.iterrows():
        scanner = row["Scanner"]
        total_findings = row["Count"]
        severity_types = row["Severity"]

        st.markdown(f"• **{scanner}**: {total_findings:,} findings across {severity_types} severity levels")


def render_insights_section(insights: list[str], title: str = "💡 Insights"):
    """Render a consistent insights section.

    :param insights: list of insight strings
    :param title: Section title
    :return: None
    """
    if insights:
        st.markdown(f"**{title}:**\n" + "\n".join(f"- {insight}" for insight in insights))


def render_no_data_message(message: str, icon: str = "📊"):
    """Render a consistent no-data message.

    :param message: Message to display
    :param icon: Icon to show
    :return: None
    """
    st.info(f"{icon} {message}")


def render_performance_table(perf_df: pd.DataFrame, columns: list[str] | None = None):
    """Render a standardized performance table.

    :param perf_df: DataFrame with performance data
    :param columns: Optional list of columns to display
    :return: None
    """
    if perf_df.empty:
        render_no_data_message("No performance data available.")
        return

    display_df = perf_df.copy()
    if columns is None:
        columns = ["scanner_name", "score", "coverage", "extra_checks", "missing_checks"]

    available_columns = [col for col in columns if col in display_df.columns]
    display_df = display_df[available_columns]

    column_renames = {
        "scanner_name": "Scanner",
        "score": "F1 Score",
        "coverage": "Coverage",
        "extra_checks": "Extra Findings",
        "missing_checks": "Missing Checks",
    }

    display_df = display_df.rename(columns=column_renames)

    if "F1 Score" in display_df.columns:
        display_df["F1 Score"] = display_df["F1 Score"].round(3)
    if "Coverage" in display_df.columns:
        display_df["Coverage"] = display_df["Coverage"].round(3)

    if "F1 Score" in display_df.columns:
        display_df = display_df.sort_values("F1 Score", ascending=False)

    st.dataframe(display_df, use_container_width=True, hide_index=True)
