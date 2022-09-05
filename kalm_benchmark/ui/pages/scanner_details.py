import streamlit as st

from kalm_benchmark.evaluation.scanner_manager import SCANNERS
from kalm_benchmark.ui.constants import QueryParam
from kalm_benchmark.ui.scanner_details.evaluation_result import (
    show_tool_evaluation_results,
)
from kalm_benchmark.ui.scanner_details.scan import show_scan_buttons
from kalm_benchmark.ui.utils import get_query_param, init


def show() -> None:
    """Main function to show the entire page"""

    key = "scanner"

    def _on_change():
        params = st.experimental_get_query_params()
        params[QueryParam.SelectedScanner] = st.session_state[key]
        st.experimental_set_query_params(**params)

    scanners = list(SCANNERS.keys())
    # if specified, use tool from query parameter as default selection
    selected_tool = get_query_param(QueryParam.SelectedScanner, scanners[0])
    st.session_state[key] = selected_tool

    tool = st.sidebar.selectbox("Tools", scanners, key=key, on_change=_on_change)

    st.title(f"{tool} Evaluation")

    handle_tool(tool)


def handle_tool(tool_name: str) -> None:
    """Show UI elements related to the selected tool
    :param tool_name: the name of the selected tool
    """
    tool = SCANNERS.get(tool_name)
    for note in tool.NOTES:
        st.warning(note)

    show_scan_buttons(tool)
    show_tool_evaluation_results(tool_name)


if __name__ == "__main__":
    init()
    show()
