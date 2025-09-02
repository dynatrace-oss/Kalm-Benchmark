import altair as alt
import pandas as pd

# Common severity color scheme for consistency across charts
SEVERITY_COLOR_DOMAIN = ["CRITICAL", "danger", "HIGH", "MEDIUM", "warning", "LOW", "INFO"]
SEVERITY_COLOR_RANGE = ["#d62728", "#e74c3c", "#ff7f0e", "#ffbb78", "#f39c12", "#2ca02c", "#1f77b4"]


def create_severity_pie_chart(scanner_data: pd.DataFrame, scanner_name: str) -> alt.Chart:
    """Create reusable pie chart visualization for severity distribution analysis.

    :param scanner_data: DataFrame containing severity data for a single scanner
    :param scanner_name: Name of the scanner for the chart title
    :return: Configured Altair pie chart with severity color scheme
    """
    if scanner_data.empty:
        raise ValueError(f"No data available for scanner: {scanner_name}")

    # Calculate total findings - handle both "Total" column and sum of "Count"
    if "Total" in scanner_data.columns and not scanner_data["Total"].isna().all():
        total_findings = scanner_data["Total"].iloc[0]
    elif "Count" in scanner_data.columns:
        total_findings = scanner_data["Count"].sum()
    else:
        total_findings = 0

    # Flexible color schema
    color_scale = alt.Scale(scheme="category10")

    return (
        alt.Chart(scanner_data)
        .mark_arc(innerRadius=20)
        .encode(
            theta=alt.Theta("Count:Q"),
            color=alt.Color(
                "Severity:N",
                scale=color_scale,
                title="Severity",
            ),
            tooltip=["Severity:N", "Count:Q", "Percentage:Q"],
        )
        .properties(width=250, height=250, title=f"{scanner_name} - {int(total_findings)} findings")
    )


def create_severity_bar_chart(severity_df: pd.DataFrame) -> alt.Chart:
    """Create grouped bar chart for comparing severity distributions across scanners.

    :param severity_df: DataFrame containing severity data for all scanners
    :return: Configured Altair grouped bar chart with scanner comparison
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
    """Create scatter plot visualization for scanner performance metrics analysis.

    :param data: DataFrame containing scanner performance data
    :param x_col: Column name for x-axis metric (default: "coverage")
    :param y_col: Column name for y-axis metric (default: "score")
    :param title: Title for the chart
    :return: Configured Altair scatter plot with percentage formatting
    """
    return (
        alt.Chart(data)
        .mark_circle(size=150, opacity=0.8)
        .encode(
            x=alt.X(f"{x_col}: Q", title=x_col.title(), scale=alt.Scale(domain=[0, 1]), axis=alt.Axis(format="%")),
            y=alt.Y(f"{y_col}: Q", title=y_col.title(), scale=alt.Scale(domain=[0, 1]), axis=alt.Axis(format="%")),
            color=alt.Color("scanner_name: N", title="Scanner", scale=alt.Scale(scheme="category10")),
            tooltip=["scanner_name: N", f"{y_col}:Q", f"{x_col}: Q", "extra_checks: Q", "missing_checks:Q"],
        )
        .properties(width=400, height=350, title=title)
    )


def create_comparison_bar_chart(
    data: pd.DataFrame, x_col: str, y_col: str, color_col: str | None = None, title: str = "Comparison"
) -> alt.Chart:
    """Create flexible bar chart for comparative analysis with optional color encoding.

    :param data: DataFrame containing comparison data
    :param x_col: Column name for x-axis categories
    :param y_col: Column name for y-axis values
    :param color_col: Optional column name for color encoding
    :param title: Title for the chart
    :return: Configured Altair bar chart with dynamic encoding
    """
    encoding = {
        "x": alt.X(f"{x_col}: N", axis=alt.Axis(labelAngle=0), title=x_col.replace("_", " ").title()),
        "y": alt.Y(f"{y_col}: Q", title=y_col.replace("_", " ").title()),
        "tooltip": [f"{x_col}: N", f"{y_col}: Q"],
    }

    if color_col:
        encoding["color"] = alt.Color(
            f"{color_col}: Q", scale=alt.Scale(scheme="viridis"), title=color_col.replace("_", " ").title()
        )
        encoding["tooltip"].append(f"{color_col}: Q")

    return alt.Chart(data).mark_bar().encode(**encoding).properties(width=600, height=300, title=title)


def create_coverage_heatmap(
    data: pd.DataFrame, x_col: str, y_col: str, value_col: str, title: str = "Coverage Heatmap"
) -> alt.Chart:
    """Create heatmap visualization with text overlay for coverage analysis.

    :param data: DataFrame containing coverage data
    :param x_col: Column name for x-axis categories
    :param y_col: Column name for y-axis categories
    :param value_col: Column name for color intensity values
    :param title: Title for the heatmap
    :return: Layered Altair chart with heatmap and text annotations
    """
    heatmap = (
        alt.Chart(data)
        .mark_rect()
        .encode(
            x=alt.X(f"{x_col}: N", axis=alt.Axis(labelAngle=0), title=x_col.replace("_", " ").title()),
            y=alt.Y(f"{y_col}: N", title=y_col.replace("_", " ").title()),
            color=alt.Color(
                f"{value_col}: Q",
                scale=alt.Scale(scheme="blues", type="log"),
                title=f'{value_col.replace("_", " ").title()} (log scale)',
            ),
            tooltip=[f"{x_col}: N", f"{y_col}: N", f"{value_col}: Q"],
        )
        .properties(width=500, height=200, title=title)
    )

    text = (
        alt.Chart(data)
        .mark_text(align="center", baseline="middle", fontSize=12, fontWeight="bold")
        .encode(
            x=alt.X(f"{x_col}: N"),
            y=alt.Y(f"{y_col}: N"),
            text=alt.condition(alt.datum[value_col] > 0, alt.Text(f"{value_col}: Q"), alt.value("")),
            color=alt.condition(alt.datum[value_col] > 100, alt.value("white"), alt.value("black")),
        )
    )

    return heatmap + text
