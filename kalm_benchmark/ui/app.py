from pathlib import Path
from typing import TypeVar

import streamlit as st

from kalm_benchmark.ui._pages import overview, scanner_details
from kalm_benchmark.ui.constants import Page, QueryParam, SessionKeys
from kalm_benchmark.ui.logging_config import init_logging
from kalm_benchmark.ui.utils import get_query_param, init  # noqa: E402

PageType = TypeVar("PageType")


PAGES = {Page.Overview: overview, Page.Scanner: scanner_details}


def show_settings() -> None:
    """
    Show settings in a collapsible section in the sidebar
    :return: nothing, all ui elements will be placed directly in the app
    """
    with st.sidebar.expander("⚙️ Settings", expanded=False):
        # Data directory setting
        data_dir = st.text_input(
            "📁 Data Directory",
            key=SessionKeys.DataDir,
            help="Directory where scan results and logs are stored",
        )

        # Initialize logging with the selected data directory
        if data_dir:
            init_logging(Path(data_dir))

        # Show current directory status
        data_path = Path(data_dir)
        if data_path.exists():
            st.success("✅ Directory exists")

            try:
                result_files = list(data_path.glob("*.json")) + list(
                    data_path.glob("*.txt")
                )
                log_files = (
                    list(Path("./logs").glob("*.log"))
                    if Path("./logs").exists()
                    else []
                )

                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Results", len(result_files))
                with col2:
                    st.metric("Logs", len(log_files))
            except FileNotFoundError:
                st.warning("⚠️ Unable to read directory contents")
        else:
            st.info("📁 Directory will be created when needed")

        # Display options section
        st.markdown("---")
        st.markdown("**🎨 Display Options**")
        
        with st.container():
            # Auto-refresh option
            auto_refresh = st.checkbox(
                "🔄 Auto-refresh results",
                value=True,
                help="Automatically refresh evaluation results after scans",
            )
            st.session_state["auto_refresh"] = auto_refresh


def show_page_navigation() -> Page:
    """Show navigation with modern styling."""
    st.sidebar.markdown(
        """
    <div style="text-align: center; padding: 1rem 0; margin-bottom: 1rem;">
        <h2 style="color: #1f77b4; margin: 0;">🛡️ Kalm</h2>
        <p style="color: #666; font-size: 0.8rem; margin: 0;">Security Scanner Benchmark</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    pages = list(PAGES.keys())
    key = "navigation"

    def _on_page_change():
        st.query_params[QueryParam.Page] = st.session_state[key]

    # if specified, use page query parameter as initial selection
    initial_page = get_query_param(QueryParam.Page, pages[0])
    st.session_state[key] = initial_page

    page_options = {
        Page.Overview: "🏠 Overview",
        Page.Scanner: "🔍 Scanner Details",
    }

    selected_page = st.sidebar.radio(
        "📋 Navigation",
        pages,
        format_func=lambda x: page_options.get(x, x),
        key=key,
        on_change=_on_page_change,
    )

    st.sidebar.markdown("---")

    return PAGES[selected_page]


def configure_page():
    """Configure the Streamlit page settings."""
    st.set_page_config(
        page_title="Kalm Benchmark - Kubernetes Security Scanner Comparison",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            "Get Help": "https://github.com/dynatrace-oss/Kalm-Benchmark",
            "Report a bug": "https://github.com/dynatrace-oss/Kalm-Benchmark/issues",
            "About": """
            # Kalm Benchmark
            
            A comprehensive evaluation and comparison tool for Kubernetes security scanners.
            
            **Features:**
            - Compare multiple security scanners
            - Evaluate scanner performance and coverage
            - Run scans directly from the UI
            - Centralized logging and result management
            
            **Developed by:** Dynatrace
            """,
        },
    )


def show_footer():
    """Show clean footer with essential links."""
    st.markdown("---")
    
    # Center the links
    st.markdown("""
    <div style="text-align: center; margin: 1rem 0;">
        <a href="https://github.com/dynatrace-oss/Kalm-Benchmark" target="_blank" style="text-decoration: none; color: #1f77b4; margin: 0 2rem;">📚 Documentation</a>
        <a href="https://github.com/dynatrace-oss/Kalm-Benchmark/issues" target="_blank" style="text-decoration: none; color: #1f77b4; margin: 0 2rem;">🐛 Report Issue</a>
    </div>
    """, unsafe_allow_html=True)
    
    # Bottom credit line
    st.markdown("""
    <div style="text-align: center; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #f0f0f0; color: #999; font-size: 0.85rem;">
        Developed with ❤️ by <strong>Dynatrace</strong> • Open Source Security Tools
    </div>
    """, unsafe_allow_html=True)


def main() -> None:
    """
    Entrypoint for the UI with modern styling and logging
    """
    configure_page()

    init()

    data_dir = Path("./data")  # Default data directory
    init_logging(data_dir)  # Logging will use ./logs directory regardless of data_dir

    show_settings()

    page = show_page_navigation()

    page.show()

    show_footer()


if __name__ == "__main__":
    main()
