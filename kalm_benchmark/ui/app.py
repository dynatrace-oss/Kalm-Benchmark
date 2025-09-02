from pathlib import Path

import streamlit as st
from loguru import logger

from kalm_benchmark.ui.interface.gen_utils import get_unified_service, init
from kalm_benchmark.ui.logging_config import init_logging
from kalm_benchmark.ui.modules.benchmark_comparison import (
    show as show_benchmark_comparison,
)
from kalm_benchmark.ui.modules.ccss_overview import show as show_ccss_overview
from kalm_benchmark.ui.modules.helm_scanner_analysis import (
    show as show_helm_scanner_analysis,
)
from kalm_benchmark.ui.modules.helm_security_trends import (
    show as show_helm_security_trends,
)
from kalm_benchmark.ui.modules.overview import show as show_overview
from kalm_benchmark.ui.scanner_details.scanner_comparison import (
    show as show_scanner_comparison,
)
from kalm_benchmark.ui.scanner_details.scanner_details import (
    show as show_scanner_details,
)


def configure_page():
    """Configure the Streamlit page settings."""
    st.set_page_config(
        page_title="Kalm Benchmark - Kubernetes Security Scanner Comparison",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )


def show_home_page():
    """Show the main overview page with navigation to other sections."""

    # Main header
    st.markdown(
        """
        <div style="text-align: center; padding: 4rem 0 3rem 0;
                    background: linear-gradient(
                        135deg, #667eea 0%, #764ba2 25%, #6c5ce7 50%, #a29bfe 75%, #667eea 100%
                    );
                    border-radius: 20px; margin-bottom: 3rem;
                    box-shadow: 0 20px 50px rgba(108, 92, 231, 0.6);
                    position: relative; overflow: hidden;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0;
                        background: radial-gradient(circle at 20% 20%, rgba(162, 155, 254, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 80% 80%, rgba(118, 75, 162, 0.3) 0%, transparent 50%);
                        pointer-events: none;"></div>
            <div style="max-width: 900px; margin: 0 auto; padding: 0 2rem; position: relative; z-index: 1;">
                <h1 style="color: #FFFFFF; margin-bottom: 1rem; font-size: 4rem; font-weight: 900;
                           text-shadow: 0 4px 20px rgba(0,0,0,0.5); letter-spacing: -0.02em;">
                    🛡️ Kalm Benchmark
                </h1>
                <h2 style="color: rgba(255,255,255,0.95); font-weight: 500; margin-bottom: 2rem;
                          font-size: 1.8rem; text-shadow: 0 2px 10px rgba(0,0,0,0.3);">
                    Kubernetes Security Scanner Analysis Platform
                </h2>
                <p style="color: rgba(255,255,255,0.9); font-size: 1.2rem; line-height: 1.6;
                         text-shadow: 0 1px 4px rgba(0,0,0,0.3); max-width: 700px; margin: 0 auto;">
                    Compare scanner effectiveness, analyze security posture, and track improvements across
                    your Kubernetes deployments and Helm charts.
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Quick stats
    col1, col2, col3 = st.columns(3)

    try:
        unified_service = get_unified_service()
        scanner_count = len(unified_service.create_evaluation_summary_dataframe())
        scan_runs = unified_service.db.get_scan_runs()
        total_scans = len(scan_runs)

        with col1:
            st.metric("📊 Scanner Results", scanner_count, help="Number of scanner evaluations available")
        with col2:
            st.metric("🔄 Total Scans", total_scans, help="Total scans performed")
        with col3:
            st.metric(
                "📊 Database", "✅ Connected" if scanner_count > 0 else "⚠️ No Data", help="Database connection status"
            )
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        st.error(f"❌ Database connection issue: {e}")

    st.markdown("---")

    # Analysis sections
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
            ### 📊 Benchmark Analysis
            **Scanner Effectiveness Evaluation**

            Compare security scanners against 235+ vulnerable Kubernetes manifests to measure:
            - F1 scores and accuracy metrics
            - Coverage across security categories
            - False positive/negative rates
            - Scanner selection guidance

            *Perfect for: Security teams evaluating "Which scanner should we adopt?"*
            """
        )

    with col2:
        st.markdown(
            """
            ### ⚓ Helm Chart Security
            **Deployment Security Analysis**

            Analyze security posture of your Helm chart deployments with:
            - Risk scoring and trending
            - Finding distribution analysis
            - Scanner detection comparison
            - Security improvement tracking

            *Perfect for: DevOps teams asking "How secure is our nginx deployment?"*
            """
        )

    st.markdown("---")

    # Footer
    st.markdown(
        """
        <div style="text-align: center; margin: 2rem 0;">
            <p style="color: #666; font-size: 0.9rem;">
                Developed with ❤️ by <strong>Dynatrace</strong> •
                <a href="https://github.com/dynatrace-oss/Kalm-Benchmark" target="_blank">📚 Documentation</a> •
                <a href="https://github.com/dynatrace-oss/Kalm-Benchmark/issues" target="_blank">🐛 Report Issue</a>
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def main():
    """Main application using st.navigation."""
    configure_page()
    init()

    data_dir = Path("./data")
    init_logging(data_dir)

    # Define pages
    pages = [
        st.Page(show_home_page, title="Home", icon="🏠", url_path="home"),
        st.Page(show_overview, title="Scanner Overview", icon="📊", url_path="scanner_overview"),
        st.Page(show_scanner_comparison, title="Scanner Comparison", icon="⚖️", url_path="scanner_comparison"),
        st.Page(show_scanner_details, title="Scanner Details", icon="🔍", url_path="scanner_details"),
        st.Page(show_benchmark_comparison, title="Benchmark Analysis", icon="📈", url_path="benchmark_analysis"),
        st.Page(show_helm_scanner_analysis, title="Helm Scanner Analysis", icon="🔬", url_path="helm_scanner_analysis"),
        st.Page(show_helm_security_trends, title="Security Trends", icon="📊", url_path="helm_security_trends"),
        st.Page(show_ccss_overview, title="CCSS Alignment", icon="🎯", url_path="ccss_alignment"),
    ]

    pg = st.navigation(pages)
    pg.run()


if __name__ == "__main__":
    main()
