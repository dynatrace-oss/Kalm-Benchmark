import time
from dataclasses import dataclass, field

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


@dataclass
class ScannerInfo:
    # note: the order of the fields dictates the initial order of the columns in the UI
    name: str
    image: str | None = None
    score: float = 0.0
    coverage: float = 0.0
    cat_IAM: str = "0/0"
    cat_network: str = "0/0"
    cat_admission_ctrl: str = "0/0"
    cat_data_security: str = "0/0"
    cat_workload: str = "0/0"
    cat_misc: str = "0/0"
    can_scan_manifests: bool = False
    can_scan_cluster: bool = False
    ci_mode: bool = False
    runs_offline: bool | str = False
    custom_checks: str = False
    formats: list[str] = field(default_factory=list)
    is_valid_summary: bool = True


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
            summary = evaluation.EvaluationSummary({}, 0, 0, 0, 0)
        categories = summary.checks_per_category

        scanner_info = ScannerInfo(
            name,
            image=scanner.IMAGE_URL,
            score=summary.score,
            coverage=summary.coverage,
            ci_mode=scanner.CI_MODE,
            runs_offline=str(scanner.RUNS_OFFLINE),
            cat_network=_get_category_sum(categories.get(CheckCategory.Network, None)),
            cat_IAM=_get_category_sum(categories.get(CheckCategory.IAM, None)),
            cat_admission_ctrl=_get_category_sum(categories.get(CheckCategory.AdmissionControl, None)),
            cat_data_security=_get_category_sum(categories.get(CheckCategory.DataSecurity, None)),
            # cat_supply_chain=_get_category_sum(categories.get(CheckCategory.Workload, None)),
            cat_workload=_get_category_sum(categories.get(CheckCategory.Workload, None)),
            cat_misc=_get_category_sum(
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


def _get_category_sum(category_summary: pd.Series | None) -> str:
    """Compress the information of the result types into a single string.

    :param category_summary: a series of all the result types of a particular scanner
    :return: the summary of the result types formatted as a string
    """
    if category_summary is None:
        covered, missing, extra = 0, 0, 0
    else:
        covered = category_summary.get(evaluation.ResultType.Covered, 0)
        missing = category_summary.get(evaluation.ResultType.Missing, 0)
        extra = category_summary.get(evaluation.ResultType.Extra, 0)
    res = f"{covered}/{covered+missing}"
    if extra > 0:
        res += f" (+{extra})"
    return res


def _configure_grid(df: pd.DataFrame) -> dict:
    """
    Create the configuration mapping for the AgGrid
    :param df: the dataftrame used for the generation of the initial config
    :return: the grid configuration as a dictionary
    """
    # render_image = JsCode(
    #     """function (params) {
    #         var element = document.createElement("span");
    #         element.classList.add("scanner-logo");
    #         var imageElement = document.createElement("img");
    #         if (params.data.image && params.data.image != "None") {
    #             imageElement.src = params.data.image;
    #             imageElement.height="20";
    #         } else {
    #             imageElement.src = "";
    #         }
    #         element.appendChild(imageElement);
    #         return element;
    #     }"""
    # )
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
    # Temporary workaround: hide image column, because with latest Ag-Grid version
    # a new HTML element to display an image can no longer be injected
    # builder.configure_column(
    #     "image",
    #     header_name="Image",
    #     cellRenderer=render_image,
    #     filter=False,
    #     sortable=False,
    #     maxWidth=120,
    #     cellClass="img-cell",
    # )
    builder.configure_column("image", hide=True)
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


def show_overview_grid() -> dict | None:
    """Load the overview data for all known scanners and display them in a grid.
    :return a dictionary with the selected scanner entry or None, if nothing is selected
    """
    # make the hover color half as intensive as the selection color
    HOVER_COLOR = "rgba(255, 75, 75, .5)"
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
    st.info("💡️ _to get a description of a column hover over the column name_")
    if df["is_valid_summary"].sum() < len(df):
        st.warning("No valid summaries were found for entries with a red font color")

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


def show() -> None:
    """Show the overview information for all known scanners."""
    st.title("Overview")

    selection = show_overview_grid()
    if selection is not None:
        tool_name = selection["name"]
        if st.button(f"Show Details for {tool_name}"):
            # trigger navigation by setting page query parameter and reloading the page
            st.query_params = {QueryParam.Page: Page.Scanner, QueryParam.SelectedScanner: tool_name}
            # wait a bit to ensure the query params are properly updated
            # because the rerun is triggered via an exception that stops everything
            time.sleep(0.2)
            st.rerun()


if __name__ == "__main__":
    init()
    show()
