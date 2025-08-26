from typing import Optional

import altair as alt
import pandas as pd

# Common severity color scheme for consistency across charts
SEVERITY_COLOR_DOMAIN = ["CRITICAL", "danger", "HIGH", "MEDIUM", "warning", "LOW", "INFO"]
SEVERITY_COLOR_RANGE = ["#d62728", "#e74c3c", "#ff7f0e", "#ffbb78", "#f39c12", "#2ca02c", "#1f77b4"]


def create_severity_pie_chart(scanner_data: pd.DataFrame, scanner_name: str) -> alt.Chart:
    """Create reusable pie chart for severity distribution.

    Args:
        scanner_data: DataFrame with severity data for a single scanner
        scanner_name: Name of the scanner for the chart title

    Returns:
        Altair pie chart
    """
    total_findings = scanner_data["Total"].iloc[0] if not scanner_data.empty else 0

    return (
        alt.Chart(scanner_data)
        .mark_arc(innerRadius=20)
        .encode(
            theta=alt.Theta("Count:Q"),
            color=alt.Color(
                "Severity:N",
                scale=alt.Scale(domain=SEVERITY_COLOR_DOMAIN, range=SEVERITY_COLOR_RANGE),
                title="Severity",
            ),
            tooltip=["Severity:N", "Count:Q", "Percentage:Q"],
        )
        .properties(width=250, height=250, title=f"{scanner_name} - {total_findings} findings")
    )


def create_severity_bar_chart(severity_df: pd.DataFrame) -> alt.Chart:
    """Create reusable grouped bar chart for severity comparison.

    Args:
        severity_df: DataFrame with severity data for all scanners

    Returns:
        Altair bar chart
    """
    return (
        alt.Chart(severity_df)
        .mark_bar()
        .encode(
            x=alt.X("Severity:N", axis=alt.Axis(labelAngle=0), title="Severity Level", sort=SEVERITY_COLOR_DOMAIN),
            y=alt.Y("Count:Q", title="Number of Findings"),
            color=alt.Color("Scanner:N", scale=alt.Scale(scheme="category10"), title="Scanner"),
            xOffset=alt.XOffset("Scanner:N"),
            tooltip=["Scanner:N", "Severity:N", "Count:Q", "Score:Q"],
        )
        .properties(width=700, height=400, title="Finding Counts by Severity Level - All Scanners")
    )


def create_performance_scatter_plot(
    data: pd.DataFrame, x_col: str = "coverage", y_col: str = "score", title: str = "Performance Analysis"
) -> alt.Chart:
    """Standard scatter plot for performance metrics.

    Args:
        data: DataFrame with performance data
        x_col: Column name for x-axis
        y_col: Column name for y-axis
        title: Chart title

    Returns:
        Altair scatter plot
    """
    return (
        alt.Chart(data)
        .mark_circle(size=150, opacity=0.8)
        .encode(
            x=alt.X(f"{x_col}:Q", title=x_col.title(), scale=alt.Scale(domain=[0, 1]), axis=alt.Axis(format="%")),
            y=alt.Y(f"{y_col}:Q", title=y_col.title(), scale=alt.Scale(domain=[0, 1]), axis=alt.Axis(format="%")),
            color=alt.Color("scanner_name:N", title="Scanner", scale=alt.Scale(scheme="category10")),
            tooltip=["scanner_name:N", f"{y_col}:Q", f"{x_col}:Q", "extra_checks:Q", "missing_checks:Q"],
        )
        .properties(width=400, height=350, title=title)
    )


def create_comparison_bar_chart(
    data: pd.DataFrame, x_col: str, y_col: str, color_col: Optional[str] = None, title: str = "Comparison"
) -> alt.Chart:
    """Standard grouped bar chart for comparisons.

    Args:
        data: DataFrame with comparison data
        x_col: Column name for x-axis (categories)
        y_col: Column name for y-axis (values)
        color_col: Optional column name for color encoding
        title: Chart title

    Returns:
        Altair bar chart
    """
    encoding = {
        "x": alt.X(f"{x_col}:N", axis=alt.Axis(labelAngle=0), title=x_col.replace("_", " ").title()),
        "y": alt.Y(f"{y_col}:Q", title=y_col.replace("_", " ").title()),
        "tooltip": [f"{x_col}:N", f"{y_col}:Q"],
    }

    if color_col:
        encoding["color"] = alt.Color(
            f"{color_col}:Q", scale=alt.Scale(scheme="viridis"), title=color_col.replace("_", " ").title()
        )
        encoding["tooltip"].append(f"{color_col}:Q")

    return alt.Chart(data).mark_bar().encode(**encoding).properties(width=600, height=300, title=title)


def create_coverage_heatmap(
    data: pd.DataFrame, x_col: str, y_col: str, value_col: str, title: str = "Coverage Heatmap"
) -> alt.Chart:
    """Create a heatmap for coverage analysis.

    Args:
        data: DataFrame with coverage data
        x_col: Column name for x-axis
        y_col: Column name for y-axis
        value_col: Column name for color values
        title: Chart title

    Returns:
        Altair heatmap with text labels
    """
    heatmap = (
        alt.Chart(data)
        .mark_rect()
        .encode(
            x=alt.X(f"{x_col}:N", axis=alt.Axis(labelAngle=0), title=x_col.replace("_", " ").title()),
            y=alt.Y(f"{y_col}:N", title=y_col.replace("_", " ").title()),
            color=alt.Color(
                f"{value_col}:Q",
                scale=alt.Scale(scheme="blues", type="log"),
                title=f'{value_col.replace("_", " ").title()} (log scale)',
            ),
            tooltip=[f"{x_col}:N", f"{y_col}:N", f"{value_col}:Q"],
        )
        .properties(width=500, height=200, title=title)
    )

    text = (
        alt.Chart(data)
        .mark_text(align="center", baseline="middle", fontSize=12, fontWeight="bold")
        .encode(
            x=alt.X(f"{x_col}:N"),
            y=alt.Y(f"{y_col}:N"),
            text=alt.condition(alt.datum[value_col] > 0, alt.Text(f"{value_col}:Q"), alt.value("")),
            color=alt.condition(alt.datum[value_col] > 100, alt.value("white"), alt.value("black")),
        )
    )

    return heatmap + text
