import time
from typing import Optional

import pandas as pd
import streamlit as st
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, JsCode

from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.scanner.scanner_evaluator import CheckCategory
from kalm_benchmark.evaluation.scanner_manager import SCANNERS
from kalm_benchmark.ui.constants import Page, QueryParam
from kalm_benchmark.ui.utils import (
    get_selected_result_file,
    init,
    is_ephemeral_scan_result,
    load_scanner_summary,
)


def collect_overview_information() -> pd.DataFrame:
    """Load all evaluation results of all scanners as a dataframe

    :return: a dataframe where every row corresponds to the information for a particular scanner
    """
    scanner_infos = []

    for name, scanner in SCANNERS.items():
        result_file = get_selected_result_file(name)

        summary = load_scanner_summary(
            name, result_file, save_created_summary=not is_ephemeral_scan_result(result_file)
        )
        is_valid_summary = True
        if summary is None:
            is_valid_summary = False
            summary = evaluation.EvaluationSummary(None, {}, 0, 0, 0, 0)
        categories = summary.checks_per_category

        scanner_info = evaluation.ScannerInfo(
            name,
            image=scanner.IMAGE_URL,
            version=summary.version,
            score=summary.score,
            coverage=summary.coverage,
            ci_mode=scanner.CI_MODE,
            runs_offline=str(scanner.RUNS_OFFLINE),
            cat_admission_ctrl=evaluation.get_category_sum(categories.get(CheckCategory.AdmissionControl, None)),
            cat_data_security=evaluation.get_category_sum(categories.get(CheckCategory.DataSecurity, None)),
            cat_IAM=evaluation.get_category_sum(categories.get(CheckCategory.IAM, None)),
            # cat_supply_chain=_get_category_sum(categories.get(CheckCategory.Workload, None)),
            cat_network=evaluation.get_category_sum(categories.get(CheckCategory.Network, None)),
            cat_reliability=evaluation.get_category_sum(categories.get(CheckCategory.Reliability, None)),
            cat_segregation=evaluation.get_category_sum(categories.get(CheckCategory.Segregation, None)),
            cat_workload=evaluation.get_category_sum(categories.get(CheckCategory.Workload, None)),
            cat_misc=evaluation.get_category_sum(
                categories.get(CheckCategory.Misc, {}) | categories.get(CheckCategory.Vulnerability, {})
            ),
            can_scan_manifests=scanner.can_scan_manifests,
            can_scan_cluster=scanner.can_scan_cluster,
            custom_checks=str(scanner.CUSTOM_CHECKS),
            formats=", ".join(scanner.FORMATS),  # Ag Grid does not support lists
            is_valid_summary=is_valid_summary,
        )
        scanner_infos.append(scanner_info)

    df = pd.DataFrame(scanner_infos)
    return df


def _configure_grid(df: pd.DataFrame) -> dict:
    """
    Create the configuration mapping for the AgGrid
    :param df: the dataftrame used for the generation of the initial config
    :return: the grid configuration as a dictionary
    """
    percent_formatter = JsCode("function (params) { return (params.value*100).toFixed(1) + '%'; }")
    bool_flag_formatter = JsCode(
        """
        function (params) {
            let sfx = '';
            let isTrue = false;

            if (typeof(params.value) === 'string') {
                isTrue = params.value !== "False";
                if (["True", "False"].indexOf(params.value) < 0) {
                    sfx = " " + params.value;
                }
            }
            else { isTrue = params.value; }
            let symbol = isTrue ? '✅' : '✗';
            return `${symbol}${sfx}`;
        }
    """
    )
    TOOLTIP_DELAY = 50  # in ms

    builder = GridOptionsBuilder.from_dataframe(df)
    builder.configure_default_column(filterable=False, tooltipShowDelay=50)
    builder.configure_selection(selection_mode="single")
    builder.configure_column("name", header_name="Scanner", pinned="left", lockPinned="true", filter=False)

    builder.configure_column("image", hide=True)
    builder.configure_column(
        "version",
        header_name="Version",
        # valueFormatter=percent_formatter,
        headerTooltip="The version the tool had when creating the results",
        width=130,
        tooltipShowDelay=TOOLTIP_DELAY,
    )
    builder.configure_column(
        "ci_mode",
        header_name="CI Mode",
        valueFormatter=bool_flag_formatter,
        headerTooltip="Use exit-code to signal scan success or has dedicated integrations for build pipelines",
        tooltipShowDelay=TOOLTIP_DELAY,
    )
    builder.configure_column(
        "score",
        header_name="Score",
        valueFormatter=percent_formatter,
        headerTooltip="The F1 score across all checks in the benchmark",
        tooltipShowDelay=TOOLTIP_DELAY,
    )
    builder.configure_column(
        "coverage",
        header_name="Coverage",
        valueFormatter=percent_formatter,
        headerTooltip="The ratio of checks covered by the tool",
        tooltipShowDelay=TOOLTIP_DELAY,
    )
    builder.configure_column(
        "custom_checks",
        header_name="Custom Checks",
        valueFormatter=bool_flag_formatter,
        headerTooltip="Adding of custom rules/checks is supported by the tool",
        tooltipShowDelay=TOOLTIP_DELAY,
    )
    builder.configure_column(
        "runs_offline",
        header_name="Runs Offline",
        valueFormatter=bool_flag_formatter,
        headerTooltip=(
            "In offline mode the tool can run in any (airgapped) environment "
            "and does not require an internet connection."
        ),
        tooltipShowDelay=TOOLTIP_DELAY,
    )
    builder.configure_column("is_valid_summary", hide=True)
    builder.configure_column("can_scan_manifests", header_name="Scan IaC", valueFormatter=bool_flag_formatter)
    builder.configure_column("can_scan_cluster", header_name="Scan Cluster", valueFormatter=bool_flag_formatter)
    builder.configure_column("formats", header_name="Report Formats", filter=True)

    cat_columns = [c for c in df.columns if c.startswith("cat_")]
    for c in cat_columns:
        builder.configure_column(
            c,
            header_name=evaluation.snake_case_to_title(c[4:]),
            headerTooltip="The number of covered vs all checks. Checks outside the benchmark are shown in parenthesis.",
            tooltipShowDelay=TOOLTIP_DELAY,
        )

    # generate the final dictionary
    grid_options = builder.build()

    # group has to be done after the dict is created, as the builder is not designed for this
    _group_columns(grid_options, "Scope", ["can_scan_manifests", "can_scan_cluster"])
    _group_columns(grid_options, "Category", cat_columns)

    grid_options["rowHeight"] = 30

    grid_options["rowClassRules"] = {
        "invalid-summary": JsCode("function(params) { return !params.data.is_valid_summary; }")
    }

    return grid_options


def show_overview_grid(df: Optional[pd.DataFrame] = None) -> Optional[dict]:
    """Load the overview data for all known scanners and display them in a grid.
    :param df: Optional dataframe to display. If None, loads all scanner data.
    :return a dictionary with the selected scanner entry or None, if nothing is selected
    """
    # make the hover color half as intensive as the selection color
    HOVER_COLOR = "rgba(255, 75, 75, .5)"
    
    if df is None:
        df = collect_overview_information()

    grid_options = _configure_grid(df)

    result = AgGrid(
        df,
        gridOptions=grid_options,
        update_mode=GridUpdateMode.SELECTION_CHANGED,
        allow_unsafe_jscode=True,
        fit_columns_on_grid_load=True,
        theme="streamlit",
        height=500,
        custom_css={
            ".ag-row-hover": {"background-color": HOVER_COLOR + " !important"},
            # remove padding on images and center them
            ".img-cell.ag-cell": {"padding-left": "0", "padding-right": "0", "text-align": "center"},
            ".invalid-summary.ag-row": {"color": "red", "font-style": "italic"},
        },
    )
    
    st.markdown("""
    <div style="background: linear-gradient(90deg, #e3f2fd 0%, #f3e5f5 100%); padding: 1rem; border-radius: 8px; margin: 1rem 0; border-left: 4px solid #1f77b4;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div style="color: #1565c0; font-weight: 500;">
                💡 <strong>Interactive Guide:</strong> Hover over column headers for descriptions • Select any row to see quick actions and details
            </div>
            {}
        </div>
    </div>
    """.format(
        f'<div style="color: #f57c00; font-weight: 600;">⚠️ {len(df) - df["is_valid_summary"].sum()} scanner(s) missing results</div>' 
        if df["is_valid_summary"].sum() < len(df) else 
        '<div style="color: #2e7d32; font-weight: 600;">✅ All scanners have valid results</div>'
    ), unsafe_allow_html=True)

    selected_rows = result["selected_rows"]
    return None if len(selected_rows) == 0 else selected_rows[0]


def _group_columns(grid_options: dict, group_name: str, columns_to_group: list[str]) -> dict:
    """A helper function to combine a list of columns into a column group.
    This is done be creating a column group and then deleting the individual columns.

    :param grid_options: the dictionary of grid options
    :param group_name: the name of the resulting column group
    :param columns_to_group: a collection of column names which should be grouped
    :return: the updated configuration where the specified columns are children of the column group
    """
    # split the columns for group from the ones to keep as is
    sub_columns = []
    new_cols = []
    for col in grid_options["columnDefs"]:
        if col["field"] in columns_to_group:
            sub_columns.append(col)
        else:
            new_cols.append(col)

    # add the specified columns as children to the column group
    new_cols.append({"field": group_name, "headerName": group_name, "children": sub_columns})
    grid_options["columnDefs"] = new_cols

    return grid_options


def show_header():
    """Show header with professional styling."""
    st.markdown("""
    <div style="text-align: center; padding: 3rem 0 2rem 0; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 10px; margin-bottom: 2rem;">
        <div style="max-width: 800px; margin: 0 auto; padding: 0 2rem;">
            <h1 style="color: #1f77b4; margin-bottom: 0.5rem; font-size: 2.5rem; font-weight: 700; text-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                🛡️ Kalm Benchmark
            </h1>
            <h3 style="color: #495057; font-weight: 400; margin-bottom: 1.5rem; font-size: 1.3rem;">
                Kubernetes Security Scanner Comparison Platform
            </h3>
            <p style="color: #6c757d; max-width: 650px; margin: 0 auto; line-height: 1.6; font-size: 1rem;">
                Comprehensive evaluation and comparison of Kubernetes workload compliance scanners. 
                Compare features, performance metrics, and coverage to make informed decisions about 
                your security toolchain.
            </p>
            <div style="margin-top: 1.5rem; padding: 1rem; background: rgba(255,255,255,0.7); border-radius: 8px; display: inline-block;">
                <span style="color: #28a745; font-weight: 600;">✨ Professional Security Analysis</span> • 
                <span style="color: #17a2b8; font-weight: 600;">📊 Data-Driven Insights</span> • 
                <span style="color: #6f42c1; font-weight: 600;">🚀 Open Source</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def show_quick_stats(df: pd.DataFrame):
    """Show quick statistics with professional styling."""
    total_scanners = len(df)
    valid_results = df["is_valid_summary"].sum()
    avg_score = df[df["is_valid_summary"]]["score"].mean() if valid_results > 0 else 0
    avg_coverage = df[df["is_valid_summary"]]["coverage"].mean() if valid_results > 0 else 0
    
    # stats with custom styling
    st.markdown("""
    <div style="background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%); padding: 1.5rem; border-radius: 12px; border: 1px solid #e9ecef; margin-bottom: 2rem; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
        <h4 style="text-align: center; color: #495057; margin-bottom: 1.5rem; font-weight: 600;">📈 Platform Statistics</h4>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="📊 Total Scanners",
            value=total_scanners,
            help="Number of scanners available in the benchmark"
        )
    
    with col2:
        st.metric(
            label="✅ With Results", 
            value=valid_results,
            help="Scanners with valid evaluation results"
        )
    
    with col3:
        st.metric(
            label="🎯 Avg Score",
            value=f"{avg_score:.1%}" if avg_score > 0 else "N/A",
            help="Average F1 score across all scanners with results"
        )
    
    with col4:
        st.metric(
            label="📈 Avg Coverage",
            value=f"{avg_coverage:.1%}" if avg_coverage > 0 else "N/A",
            help="Average check coverage across all scanners with results"
        )


def show_filter_options(df: pd.DataFrame) -> dict:
    """Show filtering options and return filter criteria."""
    with st.expander("🔍 Filter Options", expanded=False):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Score filter
            min_score = st.slider(
                "Minimum Score",
                min_value=0.0,
                max_value=1.0,
                value=0.0,
                step=0.1,
                format="%.1f",
                help="Filter scanners by minimum F1 score"
            )
        
        with col2:
            # Coverage filter
            min_coverage = st.slider(
                "Minimum Coverage", 
                min_value=0.0,
                max_value=1.0,
                value=0.0,
                step=0.1,
                format="%.1f",
                help="Filter scanners by minimum check coverage"
            )
        
        with col3:
            # Capability filter
            capabilities = st.multiselect(
                "Required Capabilities",
                options=["Cluster Scanning", "Manifest Scanning", "CI Mode", "Custom Checks"],
                default=[],
                help="Filter scanners that support selected capabilities"
            )
    
    return {
        "min_score": min_score,
        "min_coverage": min_coverage,
        "capabilities": capabilities
    }


def apply_filters(df: pd.DataFrame, filters: dict) -> pd.DataFrame:
    """Apply filters to the dataframe."""
    filtered_df = df.copy()
    
    # Score filter
    if filters["min_score"] > 0:
        filtered_df = filtered_df[filtered_df["score"] >= filters["min_score"]]
    
    # Coverage filter
    if filters["min_coverage"] > 0:
        filtered_df = filtered_df[filtered_df["coverage"] >= filters["min_coverage"]]
    
    # Capability filters
    if "Cluster Scanning" in filters["capabilities"]:
        filtered_df = filtered_df[filtered_df["can_scan_cluster"]]
    if "Manifest Scanning" in filters["capabilities"]:
        filtered_df = filtered_df[filtered_df["can_scan_manifests"]]
    if "CI Mode" in filters["capabilities"]:
        filtered_df = filtered_df[filtered_df["ci_mode"]]
    if "Custom Checks" in filters["capabilities"]:
        filtered_df = filtered_df[filtered_df["custom_checks"] != "False"]
    
    return filtered_df


def show_quick_actions(selection: Optional[dict]):
    """Show quick action buttons for selected scanner."""
    if selection is None:
        st.info("💡 **Tip:** Select a scanner from the table below to see quick actions")
        return
    
    tool_name = selection["name"]
    scanner = SCANNERS.get(tool_name)
    
    st.markdown("### ⚡ Quick Actions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 View Details", key="view_details", type="primary"):
            st.query_params = {QueryParam.Page: Page.Scanner, QueryParam.SelectedScanner: tool_name}
            time.sleep(0.1)
            st.rerun()
    
    with col2:
        if scanner and scanner.can_scan_manifests:
            if st.button("🚀 Quick Scan", key="quick_scan"):
                st.query_params = {
                    QueryParam.Page: Page.Scanner, 
                    QueryParam.SelectedScanner: tool_name,
                    "action": "scan"
                }
                time.sleep(0.1)
                st.rerun()
        else:
            st.button("🚀 Quick Scan", disabled=True, help="This scanner doesn't support manifest scanning")
    
    with col3:
        if selection.get("is_valid_summary"):
            score = selection.get("score", 0)
            coverage = selection.get("coverage", 0)
            st.markdown(f"**Score:** {score:.1%} | **Coverage:** {coverage:.1%}")
        else:
            st.warning("⚠️ No valid results available")


def show() -> None:
    """Show the overview page with professional styling and modern UI."""
    show_header()
    
    df = collect_overview_information()
    
    show_quick_stats(df)
    
    st.markdown("""
    <div style="height: 2px; background: linear-gradient(90deg, transparent 0%, #dee2e6 20%, #dee2e6 80%, transparent 100%); margin: 2rem 0;"></div>
    """, unsafe_allow_html=True)
    
    filters = show_filter_options(df)
    filtered_df = apply_filters(df, filters)
    
    if len(filtered_df) < len(df):
        st.markdown(f"""
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 0.75rem 1rem; border-radius: 6px; margin: 1rem 0;">
            🔍 <strong>Filtered View:</strong> Showing {len(filtered_df)} of {len(df)} scanners based on your criteria
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("""
    <div style="margin: 2rem 0 1rem 0;">
        <h3 style="color: #495057; font-weight: 600; display: flex; align-items: center; gap: 0.5rem;">
            📋 Scanner Comparison Table
        </h3>
        <p style="color: #6c757d; margin-top: 0.5rem; font-size: 0.9rem;">
            Interactive comparison of security scanners with detailed metrics and capabilities
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    selection = show_overview_grid(filtered_df)
    
    if selection:
        st.markdown("""
        <div style="margin-top: 2rem; padding: 1.5rem; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 10px; border: 1px solid #dee2e6;">
        """, unsafe_allow_html=True)
        show_quick_actions(selection)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        show_quick_actions(selection)


if __name__ == "__main__":
    init()
    show()
