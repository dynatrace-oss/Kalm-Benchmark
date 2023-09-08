import warnings
from typing import TypeVar

import streamlit as st

warnings.filterwarnings(
    "ignore",
    message="Passing a dict as an indexer is deprecated and will raise in a future version. Use a list instead.*",
)

from kalm_benchmark.ui._pages import overview, scanner_details
from kalm_benchmark.ui.constants import Page, QueryParam, SessionKeys
from kalm_benchmark.ui.utils import get_query_param, init

PageType = TypeVar("PageType")


PAGES = {Page.Overview: overview, Page.Scanner: scanner_details}


def show_settings() -> None:
    """
    Show the available settings in a collapsable section in the sidebar
    :return: nothing, all ui elements will be place directly in the app
    """
    with st.sidebar.expander("Settings"):
        st.text_input("Data directory", key=SessionKeys.DataDir)


def show_page_navigation() -> Page:
    """Show UI elements to enable navigation between pages."""
    st.sidebar.title("Navigation")
    pages = list(PAGES.keys())
    key = "navigation"

    def _on_page_change():
        params = st.experimental_get_query_params()
        params[QueryParam.Page] = st.session_state[key]
        st.experimental_set_query_params(**params)

    # if specified, use page query parameter as initial selection
    initial_page = get_query_param(QueryParam.Page, pages[0])
    st.session_state[key] = initial_page
    selected_page = st.sidebar.radio("Go to", pages, key=key, on_change=_on_page_change)
    st.sidebar.markdown("-" * 6)

    return PAGES[selected_page]


def main() -> None:
    """
    Entrypoint for the UI
    """
    init()
    show_settings()

    page = show_page_navigation()
    page.show()


if __name__ == "__main__":
    main()
