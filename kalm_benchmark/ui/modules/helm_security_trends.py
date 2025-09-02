from datetime import datetime, timedelta

import altair as alt
import pandas as pd
import streamlit as st
from loguru import logger

from kalm_benchmark.ui.analytics.historical_analysis import (
    render_historical_scan_trends,
)
from kalm_benchmark.ui.interface.gen_utils import get_unified_service


def get_helm_security_trends_data(days_back: int = 30, chart_name: str | None = None) -> pd.DataFrame:
    """Retrieve and process security trends data for Helm charts over specified time period.

    :param days_back: Number of days to look back for historical data
    :param chart_name: Optional specific chart name to filter by
    :return: DataFrame containing security trends with risk scores and finding counts
    """
    unified_service = get_unified_service()

    try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)

        all_helm_runs = unified_service.db.get_scan_runs(
            source_filter="helm_charts", limit=500  # Higher limit to capture historical data for trends
        )

        helm_scan_runs = []
        for run in all_helm_runs:
            try:
                run_date = datetime.fromisoformat(run.get("timestamp", "").replace("Z", "+00:00"))
                if start_date <= run_date <= end_date:
                    if chart_name:
                        run_chart_name = _extract_chart_name(run.get("source_type", ""))
                        if run_chart_name.lower() != chart_name.lower():
                            continue
                    helm_scan_runs.append(run)
            except Exception:
                if chart_name:
                    run_chart_name = _extract_chart_name(run.get("source_type", ""))
                    if run_chart_name.lower() != chart_name.lower():
                        continue
                helm_scan_runs.append(run)

        if not helm_scan_runs:
            return pd.DataFrame()

        trends_data = []
        for run in helm_scan_runs:
            try:
                results = unified_service.db.load_scanner_results(
                    scanner_name=run["scanner_name"], scan_run_id=run["id"]
                )

                if not results:
                    continue

                severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                total_findings = len(results)

                for result in results:
                    severity = result.severity.upper() if result.severity else "INFO"

                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    elif severity in ["CRITICAL", "DANGER"]:
                        severity_counts["HIGH"] += 1
                    elif severity == "WARNING":
                        severity_counts["MEDIUM"] += 1

                risk_score = (
                    (
                        severity_counts["HIGH"] * 9.0
                        + severity_counts["MEDIUM"] * 4.0
                        + severity_counts["LOW"] * 2.0
                        + severity_counts["INFO"] * 1.0
                    )
                    / max(total_findings, 1)
                    * 10
                )
                risk_score = min(100, risk_score)

                # Extract chart name from source_type
                chart_name = _extract_chart_name(run.get("source_type", ""))

                trend_entry = {
                    "timestamp": run["timestamp"],
                    "chart_name": chart_name,
                    "scanner_name": run["scanner_name"],
                    "total_findings": total_findings,
                    "high_severity": severity_counts["HIGH"],
                    "medium_severity": severity_counts["MEDIUM"],
                    "low_severity": severity_counts["LOW"],
                    "risk_score": risk_score,
                    "scan_id": run["id"],
                }
                trends_data.append(trend_entry)

            except Exception as e:
                logger.warning(f"Error processing helm scan run {run.get('id', 'unknown')}: {e}")
                continue

        df = pd.DataFrame(trends_data)
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            df = df.sort_values("timestamp")

        return df

    except Exception as e:
        logger.error(f"Error fetching helm security trends data: {e}")
        return pd.DataFrame()


def _extract_chart_name(source_type: str) -> str:
    """Extract Helm chart name from database source_type field."""
    if not source_type:
        return "unknown"

    if source_type.startswith("helm-chart:"):
        chart_part = source_type.split("helm-chart:")[1]
        if "/" in chart_part:
            return chart_part.split("/")[-1]
        return chart_part

    return "unknown"


def get_security_posture_improvement(trends_data: pd.DataFrame) -> dict:
    """Calculate security posture improvement metrics from trends data.

    :param trends_data: DataFrame containing security trends over time
    :return: Dictionary with improvement metrics including trend direction and statistics
    """
    if trends_data.empty or len(trends_data) < 2:
        return {"improvement": 0, "trend": "insufficient_data"}

    # Group by chart and calculate improvement
    improvements = []

    for chart in trends_data["chart_name"].unique():
        chart_data = trends_data[trends_data["chart_name"] == chart].sort_values("timestamp")

        if len(chart_data) < 2:
            continue

        # Compare first vs last scan
        first_scan = chart_data.iloc[0]
        last_scan = chart_data.iloc[-1]

        # Calculate improvement (lower risk score = better)
        risk_improvement = first_scan["risk_score"] - last_scan["risk_score"]
        findings_reduction = first_scan["total_findings"] - last_scan["total_findings"]

        improvements.append(
            {"chart": chart, "risk_improvement": risk_improvement, "findings_reduction": findings_reduction}
        )

    if not improvements:
        return {"improvement": 0, "trend": "no_data"}

    avg_risk_improvement = sum(imp["risk_improvement"] for imp in improvements) / len(improvements)
    avg_findings_reduction = sum(imp["findings_reduction"] for imp in improvements) / len(improvements)

    # Determine overall trend
    if avg_risk_improvement > 5:
        trend = "improving"
    elif avg_risk_improvement < -5:
        trend = "worsening"
    else:
        trend = "stable"

    return {
        "improvement": avg_risk_improvement,
        "findings_change": avg_findings_reduction,
        "trend": trend,
        "charts_analyzed": len(improvements),
    }


def show():
    """Display the main Helm security trends analysis page with historical security metrics.

    :return: None
    """

    # Helm Security Trends Header
    st.markdown(
        """
        <div style="text-align: center; padding: 3.5rem 0 2.5rem 0;
                    background: linear-gradient(135deg, #74b9ff 0%, #6c5ce7 25%,\
                      #00cec9 50%, #55efc4 75%, #74b9ff 100%);
                    border-radius: 20px; margin-bottom: 2rem;
                    box-shadow: 0 15px 40px rgba(116, 185, 255, 0.5);
                    position: relative; overflow: hidden;">
            <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0;
                        background: radial-gradient(circle at 15% 25%, rgba(85, 239, 196, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 85% 75%, rgba(0, 206, 201, 0.4) 0%, transparent 50%),
                                    radial-gradient(circle at 50% 15%, rgba(108, 92, 231, 0.3) 0%, transparent 45%);
                        pointer-events: none;"></div>
            <div style="max-width: 800px; margin: 0 auto; padding: 0 2rem; position: relative; z-index: 1;">
                <h1 style="color: #FFFFFF; margin-bottom: 0.5rem; font-size: 3.2rem; font-weight: 800;
                           text-shadow: 0 4px 15px rgba(0,0,0,0.4); letter-spacing: -0.02em;">
                    📈 Security Trends
                </h1>
                <h3 style="color: rgba(255,255,255,0.95); font-weight: 500; margin-bottom: 1.5rem;
                          font-size: 1.6rem; text-shadow: 0 2px 8px rgba(0,0,0,0.3);">
                    Helm Chart Security Evolution
                </h3>
                <p style="color: rgba(255,255,255,0.9); font-size: 1.1rem; line-height: 1.5;
                         text-shadow: 0 1px 4px rgba(0,0,0,0.2); max-width: 600px; margin: 0 auto;">
                    Track security posture improvements and vulnerability trends over time
                </p>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Analysis configuration
    st.subheader("🎯 Analysis Configuration")
    col1, col2, col3 = st.columns([2, 2, 1])

    with col1:
        time_range = st.selectbox(
            "Select time range for trends analysis:",
            options=[7, 14, 30, 60, 90],
            index=2,  # Default to 30 days
            format_func=lambda x: f"Last {x} days",
            help="Choose how far back to look for security trends",
        )

    # Get available charts for selection
    from kalm_benchmark.ui.modules.helm_scanner_analysis import (
        get_available_helm_charts,
    )

    available_charts = get_available_helm_charts()

    with col2:
        if available_charts:
            selected_chart = st.selectbox(
                "Select Helm Chart to analyze:",
                options=["All Charts"] + available_charts,
                help="Choose a specific chart or analyze all charts together",
            )
            chart_filter = None if selected_chart == "All Charts" else selected_chart
        else:
            chart_filter = None
            st.selectbox(
                "Select Helm Chart to analyze:",
                options=["No charts available"],
                disabled=True,
                help="No Helm chart data found",
            )

    with col3:
        scope_text = "All charts" if chart_filter is None else f"Chart: {chart_filter}"
        st.info(f"📊 **Scope**: {scope_text}\n\nTracking security trends over time.")

    # Get trends data
    trends_data = get_helm_security_trends_data(time_range, chart_filter)

    if trends_data.empty:
        st.warning("📈 **No security trends data available**")
        st.markdown(
            """
        **To enable security trends analysis:**

        1. **Scan Helm charts regularly**:
           ```bash
           poetry run cli scan <scanner> --helm-chart <chart-name>
           ```

        2. **Repeat scans over time** to track improvements:
           ```bash
           # Scan the same chart multiple times
           poetry run cli scan kubescape --helm-chart nginx
           # ... make security improvements ...
           poetry run cli scan kubescape --helm-chart nginx  # Rescan
           ```

        3. **Trends will appear** after multiple scans over time

        📖 **Tip**: Set up automated scanning to track continuous security posture
        """
        )
        return

    # Calculate security posture metrics
    posture_metrics = get_security_posture_improvement(trends_data)

    # Summary metrics
    st.markdown("---")
    col1, col2, col3, col4 = st.columns(4)

    unique_charts = trends_data["chart_name"].nunique()
    total_scans = len(trends_data)

    with col1:
        st.metric("⚓ Charts Tracked", unique_charts, help="Number of unique charts with security trend data")

    with col2:
        st.metric("📊 Total Scans", total_scans, help=f"Number of security scans in the last {time_range} days")

    with col3:
        improvement = posture_metrics.get("improvement", 0)
        trend_indicator = "↗️" if improvement > 0 else "↘️" if improvement < 0 else "→"
        st.metric(
            "🎯 Security Trend",
            f"{trend_indicator} {improvement:+.1f}",
            help="Average risk score improvement (positive = better security)",
        )

    with col4:
        findings_change = posture_metrics.get("findings_change", 0)
        findings_indicator = "↘️" if findings_change > 0 else "↗️" if findings_change < 0 else "→"
        st.metric(
            "📈 Finding Trends",
            f"{findings_indicator} {findings_change:+.1f}",
            help="Average change in total findings (negative = fewer issues)",
        )

    # Security posture over time
    st.markdown("---")
    st.subheader("📈 Security Posture Over Time")

    if len(trends_data) >= 2:
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**📊 Risk Score Evolution**")
            # Group by chart and show trend
            chart_risk_data = trends_data.groupby(["timestamp", "chart_name"])["risk_score"].mean().reset_index()

            if not chart_risk_data.empty:
                # Simple line chart for risk score
                risk_chart = (
                    alt.Chart(chart_risk_data)
                    .mark_line(point=True, strokeWidth=2)
                    .encode(
                        x=alt.X("timestamp:T", title="Date", axis=alt.Axis(format="%b %d")),
                        y=alt.Y("risk_score:Q", title="Risk Score", scale=alt.Scale(domain=[0, 100])),
                        color=alt.Color("chart_name:N", legend=alt.Legend(title="Chart")),
                    )
                    .properties(width=400, height=250)
                )
                st.altair_chart(risk_chart, use_container_width=True)
            else:
                st.info("No risk score data available")

        with col2:
            st.markdown("**🔍 Finding Counts**")
            # Aggregate findings by date
            findings_summary = (
                trends_data.groupby("timestamp")
                .agg({"high_severity": "sum", "medium_severity": "sum", "low_severity": "sum"})
                .reset_index()
            )

            if not findings_summary.empty:
                # Simple bar chart for findings
                findings_chart = (
                    alt.Chart(findings_summary)
                    .mark_bar()
                    .encode(
                        x=alt.X("timestamp:T", title="Date", axis=alt.Axis(format="%b %d")),
                        y=alt.Y("high_severity:Q", title="High Severity Findings"),
                        color=alt.value("#e74c3c"),
                    )
                    .properties(width=400, height=250)
                )
                st.altair_chart(findings_chart, use_container_width=True)
            else:
                st.info("No findings data available")

    else:
        st.info("📊 Need more scan data points to show meaningful trends")

    # Severity trends analysis
    st.markdown("---")
    st.subheader("🚨 Severity Distribution Trends")

    if not trends_data.empty and len(trends_data) >= 2:
        # Show severity distribution as stacked area chart
        severity_summary = (
            trends_data.groupby("timestamp")
            .agg({"high_severity": "sum", "medium_severity": "sum", "low_severity": "sum"})
            .reset_index()
        )

        # Create stacked data
        severity_melted = severity_summary.melt(
            id_vars=["timestamp"],
            value_vars=["high_severity", "medium_severity", "low_severity"],
            var_name="severity_level",
            value_name="count",
        )

        severity_melted["severity_level"] = severity_melted["severity_level"].str.replace("_severity", "").str.title()

        # Stacked area chart
        severity_chart = (
            alt.Chart(severity_melted)
            .mark_area(opacity=0.8)
            .encode(
                x=alt.X("timestamp:T", title="Date", axis=alt.Axis(format="%b %d")),
                y=alt.Y("count:Q", title="Number of Findings"),
                color=alt.Color(
                    "severity_level:N",
                    scale=alt.Scale(domain=["High", "Medium", "Low"], range=["#e74c3c", "#f39c12", "#f1c40f"]),
                    legend=alt.Legend(title="Severity Level"),
                ),
            )
            .properties(height=300, title="Severity Distribution Over Time")
        )

        st.altair_chart(severity_chart, use_container_width=True)
    else:
        st.info("📊 Need more data points for severity trend analysis")

    # Chart-specific improvement analysis
    st.markdown("---")
    st.subheader("🎯 Chart-Specific Security Progress")

    if unique_charts >= 1:
        progress_data = []

        for chart in trends_data["chart_name"].unique():
            chart_data = trends_data[trends_data["chart_name"] == chart].sort_values("timestamp")

            if len(chart_data) >= 2:
                first_scan = chart_data.iloc[0]
                last_scan = chart_data.iloc[-1]

                risk_change = last_scan["risk_score"] - first_scan["risk_score"]
                findings_change = last_scan["total_findings"] - first_scan["total_findings"]

                progress_data.append(
                    {
                        "Chart": chart,
                        "Risk Change": risk_change,
                        "Findings Change": findings_change,
                        "Latest Risk Score": last_scan["risk_score"],
                        "Latest Findings": last_scan["total_findings"],
                    }
                )

        if progress_data:
            progress_df = pd.DataFrame(progress_data)

            st.dataframe(
                progress_df,
                use_container_width=True,
                column_config={
                    "Risk Change": st.column_config.NumberColumn(
                        format="%.1f", help="Risk score change (negative = improvement)"
                    ),
                    "Findings Change": st.column_config.NumberColumn(
                        format="%d", help="Change in total findings (negative = fewer issues)"
                    ),
                    "Latest Risk Score": st.column_config.NumberColumn(format="%.1f"),
                    "Latest Findings": st.column_config.NumberColumn(format="%d"),
                },
            )

    # Historical analysis
    st.markdown("---")
    with st.expander("📊 Detailed Historical Analysis", expanded=False):
        unified_service = get_unified_service()
        render_historical_scan_trends(unified_service, source_type="helm", chart_name="")

    # Help section
    with st.expander("❓ Understanding Security Trends", expanded=False):
        st.markdown(
            """
        **Security Trends** tracks how your Helm chart security posture evolves over time.

        **Key Metrics:**
        - **Risk Score Trend**: Direction of security posture (lower = better)
        - **Finding Volume**: Total number of security issues detected
        - **Severity Distribution**: Breakdown of high/medium/low severity issues
        - **Chart Progress**: Individual chart security improvements

        **Interpreting Trends:**
        - **Downward Risk Score**: Security improvements (good trend)
        - **Upward Risk Score**: Security degradation (needs attention)
        - **Stable Risk Score**: Consistent security posture
        - **Decreasing High Severity**: Critical issues being addressed

        **Best Practices:**
        - Scan charts regularly (weekly/monthly) to track trends
        - Focus on reducing high severity findings first
        - Set up automated scanning for continuous monitoring
        - Track improvements after security fixes
        - Compare trends across different charts

        **Use Cases:**
        - **Security Teams**: Monitor overall security posture improvement
        - **DevOps Teams**: Track security impact of deployments
        - **Management**: Report on security program effectiveness
        - **Compliance**: Demonstrate continuous security improvement
        """
        )


# Entry point for the page
if __name__ == "__main__":
    show()
