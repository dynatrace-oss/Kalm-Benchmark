from pathlib import Path
from textwrap import dedent

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.evaluation import (
    CheckStatus,
    Col,
    EvaluationSummary,
    Metric,
    ResultType,
    evaluate_scanner,
)
from kalm_benchmark.evaluation.scanner_manager import SCANNERS
from kalm_benchmark.ui.constants import SELECTED_RESULT_FILE, Color
from kalm_benchmark.ui.utils import get_result_files_of_scanner, load_scan_result


def show_result_selection_ui(tool_name: str) -> str | None:
    """Shows UI elements to select the source with the data for the evaluation

    :param tool_name: the name of the tool for which the results will be shown
    :return: the name of the source or None, if there is no valid option
    """
    files = get_result_files_of_scanner(tool_name)
    SEL_FILE_KEY = f"{tool_name}_{SELECTED_RESULT_FILE}"

    if len(files) == 1:
        file = files[0]
    elif len(files) > 1:
        sel_file_index = 0
        if SEL_FILE_KEY in st.session_state:
            sel_file = st.session_state[SEL_FILE_KEY]
            if sel_file in files:
                sel_file_index = files.index(sel_file)
        file = st.sidebar.selectbox("Show results from", files, index=sel_file_index)
    else:
        file = None

    # store the selected file in a dedicated variable, so it's accessible in other pages as well
    st.session_state[SEL_FILE_KEY] = file
    return file


def show_tool_evaluation_results(tool_name: str) -> None:
    """Show UI elements related to the evaluation results of specific tool
    :param tool_name: the name of the tool
    """
    file = show_result_selection_ui(tool_name)

    if file is None:
        st.warning(f"No results are available for {tool_name}")
    else:
        show_results(tool_name, file)


@st.experimental_memo
def get_confusion_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Load the confusion matrix of the provided dataframe

    :param df: the dataframe for which the confusion matrix will be loaded
    :return: the confusion matrix as a dataframe
    """
    return evaluation.get_confusion_matrix(df)


def create_check_type_chart(df: pd.DataFrame) -> alt.Chart:
    """
    Create a chart displaying the distribution of the result types.
    :param df: the dataframe containing the execution results
    :return: an altair chart
    """
    _TYPE_COL = "Type"
    _COUNT_COL = "Count"

    # turn counts of each type of result into a dataframe
    df_counts = pd.DataFrame(dict(df["result_type"].value_counts()), index=[0])
    # pivot the dataframe so all types and their counts are dedicated columes so it
    # can be properly used by altair for visualization
    df_check_types = df_counts.melt(var_name=_TYPE_COL, value_name=_COUNT_COL)

    return (
        alt.Chart(df_check_types)
        .mark_bar()
        .encode(
            y=alt.Y(_TYPE_COL, sort="-x"),
            color=alt.Color(_TYPE_COL, legend=None),
            x=_COUNT_COL,
            tooltip=[_TYPE_COL, _COUNT_COL],
        )
    )


@st.experimental_memo
def calculate_coverage(df: pd.DataFrame) -> float:
    """Calculate the check coverage from the results in the provided dataframe

    :param df: the dataframe with the check results
    :return: the coverage as a single scalar value
    """
    return evaluation.calculate_coverage(df)


@st.experimental_memo()
def calculate_score(df: pd.DataFrame, metric: Metric = Metric.F1) -> float:
    """
    Calculate a score from the confusion matrix of the expected and actual check results.
    This calculation excludes missing check results or expected checks and focuses only
    on cases where both the expected and actual values are known.
    :param df: the dataframe from which the confusion matrix will be determined
    :param metric: the type of metric used as the score. Currently supported are F1 (default) and accuracy.
    The F1 is used as the default, because the confusion matrix is expected to be imbalanced
    and false classifications are of interest.
    :returns: the score as a single numeric value
    """
    return evaluation.calculate_score(df, metric)


@st.experimental_memo
def load_scanner_results(
    scanner_name: str, result_source: Path | None = None, keep_redundant_results: bool = False
) -> pd.DataFrame:
    """Load the results of the scanner evaluated on the benchmark instances in a tabular format

    :param scanner_name: the name of the scanner for which the results will be loaded
    :param result_file: optional path to the check results of the scanner
    :param keep_redundant_checks: if false then all checks that pass, yet have no 'expected' status will be removed.
    :return: the evaluation results as a dataframe
    """
    scanner = SCANNERS.get(scanner_name)
    results = load_scan_result(scanner, result_source)
    # ensure all columns are interpreted as string to avoid exception with
    # Apache Arrow misinterpreting mixed columns containing floats and '-'

    eval_results = evaluate_scanner(scanner, results, keep_redundant_checks=keep_redundant_results)
    df_results = eval_results.astype(str) if eval_results is not None else eval_results
    return df_results


@st.experimental_memo
def load_evaluation_summary(df: pd.DataFrame, metric: Metric) -> EvaluationSummary:
    """Load the evaluation summary of the given dataframe with check results.

    :param df: the dataframe which will be summarized
    :param metric: the metric used for the calculation of the score
    :return: an object with several summary artifacts and metrics
    """
    return evaluation.create_summary(df, metric)


def show_results(scanner_name: str, result_file: Path | None = None) -> None:
    """
    Display the overview and detail
    :param scanner_name: the name of the scanner whose results will be shown
    """
    keep_redundant_results = st.sidebar.checkbox("Keep redundant checks", value=False)
    df_results = load_scanner_results(scanner_name, result_file, keep_redundant_results=keep_redundant_results)

    if df_results is None:
        st.error(f"'{scanner_name}' did not yield any alerts")
        return

    # exclude selected checks from evaluation to ignore noisy or harmless checks
    all_checks = sorted(df_results[Col.ScannerCheckId].unique())
    excluded_checks = st.sidebar.multiselect("Excluded Checks:", all_checks)
    df_results = df_results[~df_results[Col.ScannerCheckId].isin(excluded_checks)]

    metric = Metric.F1
    summary = load_evaluation_summary(df_results, metric)
    col1, col2 = st.columns(2)

    with col1:
        st.metric("Score", f"{summary.score*100:.1f}%")
        with st.expander("Details"):
            df_xtab = get_confusion_matrix(df_results)
            st.table(df_xtab)
            st.text(f"{metric} is used as the metric")
    with col2:
        st.metric("Coverage", f"{summary.coverage*100:.1f}%")
        st.altair_chart(altair_chart=create_check_type_chart(df_results))

    st.subheader("Checks per category")
    st.dataframe(summary.checks_per_category)

    show_detailed_analysis(df_results)


def show_detailed_analysis(df_results):
    """Show the section with elements for a detailed breakdown of the results

    :param df_results: the dataframe containing the results
    """
    st.subheader("Detailed Overview")
    if not st.checkbox("Show Debug Columns"):
        debug_cols = ["expected_2", "compare_name", "compare_expected"]
        df_results = df_results.drop(debug_cols, axis=1)

    show_detailed_check_overview(df_results)
    show_drilldown_per_check(df_results)


@st.experimental_memo
def _create_results_per_scanner_check_histogram(df: pd.DataFrame, id_col: str) -> alt.Chart:
    # use only relevant columns to avoid problems with Streamlit's dataframe serialization
    df = df[[id_col, Col.Category]]
    df_with_checks = df[df[id_col] != "-"]  # filter results without a scanner check id

    return (
        alt.Chart(df_with_checks)
        .mark_bar()
        .encode(
            x=alt.X(f"{id_col}:N", title="Check ID"),
            y=alt.Y("count()", title="Number of Results"),
            tooltip=[id_col, "category"],
            color="category:N",
        )
    )


def show_detailed_check_overview(df: pd.DataFrame, result_types: list[ResultType] = None) -> None:
    """
    Show the full details of the checks results in a table. The shown check can be filtered
     to show only specific types of results.
    :param df: the dataframe which will be displayed
    :param result_types: a list of shown ResultTypes for which the dataframe will be filtered
    """
    if result_types is None:
        result_types = [ResultType.Covered, ResultType.Extra, ResultType.Missing]

    result_type_help = (
        "- `Covered`: valid checks\n"
        "- `Missing`: checks not implemented by the tool\n"
        "- `Extra`: checks implemented by the tool but not covered by the benchmark"
    )
    selected_categories = st.multiselect(
        "Checks",
        result_types,
        default=result_types,
        help=result_type_help,
    )  # show all categories by default

    if len(selected_categories) > 0:
        df = df.dropna(how="all", axis=1)  # drop all empty columns
        if set(selected_categories) == set(result_types):
            df_filtered = df
        else:
            df_filtered = df[df["result_type"].isin(selected_categories)]
        # convert '-' to Nan
        df_filtered = df_filtered.replace("-", np.nan)
        df_filtered = df_filtered.sort_values(by=["check_id", "scanner_check_id"]).reset_index(drop=True)
        st.dataframe(style_results(df_filtered))

        csv = df_filtered.to_csv().encode("utf-8")
        st.download_button("💾 Download", csv, "file.csv", "text/csv", key="download-csv")

    else:
        st.info("To show details please select at least one category!")


def show_drilldown_per_check(df: pd.DataFrame) -> None:
    """
    Show UI elements to further drill down into the results of a particular scanner check.
    :param df: the dataframe with the check results
    """
    st.subheader("Check Diagnostic")
    check_type = st.radio("Check Type:", options=["Check", "Scanner Check"])
    if check_type == "Check":
        id_col = Col.CheckId
        name_col = Col.Name
        info_text = dedent(
            """Ideally there is exactly one result per benchmark check.
        Occasionally, a scan alarms on multiple parts of the same incident.
        If that's the case all the alarm should be of the same category!"""
        )
    else:
        id_col = Col.ScannerCheckId
        name_col = Col.ScannerCheckName
        info_text = dedent(
            """
        The drilldown on check results of a scanner allows to quickly identify and analyse faulty checks.
        If a single scanner check shows multiple categories it's an indicator of an issue with the check
        """
        )
    st.markdown(info_text)

    # workaround for invisible tooltip when chart is fullscreen in streamlit
    # see:https://discuss.streamlit.io/t/tool-tips-in-fullscreen-mode-for-charts/6800/9
    st.markdown("<style>#vg-tooltip-element{z-index: 1000051}</style>", unsafe_allow_html=True)

    # histogram across scanner checks
    st.altair_chart(_create_results_per_scanner_check_histogram(df, id_col), use_container_width=True)

    # selection of a single scanner check
    scanner_check_ids = sorted(df[id_col].unique())
    sel_check = st.selectbox("Select check", scanner_check_ids)

    # show benchmark checks per scanner check
    if sel_check is not None:
        df_check = df[df[id_col] == sel_check]
        check_names = list(set(df_check[name_col]))
        if len(check_names) == 1 and check_names[0] != "-":
            st.write(f"Name of the check: `{check_names[0]}`")

        df_check = df_check.drop([id_col, name_col], axis=1)
        st.dataframe(df_check.reset_index(drop=True).astype(str))


def style_results(df: pd.DataFrame) -> "pd.Styler":
    """Emphasize relevant information by:
    - making the ID's bold,
    - visually grouping rows of same CheckId with same background,
    - setting the background of important fields according to their values
    - reducing focus on 'nan' values.

    :param df: the dataframe which will be styled
    :return: a dataframe styler object
    """

    def _bold_id(value: str) -> str:
        if not pd.isnull(value):
            return "font-weight:bold"
        return ""

    def _colorize_status(value: str) -> str:
        if value == CheckStatus.Alert:
            return f"background-color: {Color.Error}"
        elif value == CheckStatus.Pass:
            return f"background-color: {Color.Success}"
        return ""

    def _colorize_result_type(value: str) -> str:
        if value == ResultType.Covered:
            return f"background-color: {Color.Info}"
        elif value == ResultType.Extra:
            return f"background-color: {Color.Warn}"
        elif value == ResultType.Missing:
            return f"background-color: {Color.Error}"
        return ""

    def format_color_groups(df):
        colors = [Color.Background, "None"]
        colors = [Color.Background, "#00000000"]
        x = df.copy()
        # factors = list(x["publication"].unique())
        factors = list(x[Col.CheckId].unique())
        i = 0
        for factor in factors:
            style = f"background-color: {colors[i]}"
            x.loc[x[Col.CheckId] == factor, :] = style
            i = not i
        x.loc[x[Col.CheckId].isnull(), :] = ""
        return x

    # make ID's bold
    df_styled = (
        df.style.apply(format_color_groups, axis=None)
        .applymap(_bold_id, subset=[Col.CheckId, Col.ScannerCheckId])
        .applymap(_colorize_status, subset=[Col.Expected, Col.Got])
        .applymap(_colorize_result_type, subset=[Col.ResultType])
        .applymap(lambda v: f"color: {Color.Gray}" if pd.isnull(v) else "")  # make NaNs less prominet
    )

    return df_styled
