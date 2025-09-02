import altair as alt
import pandas as pd
import streamlit as st

from kalm_benchmark.ui.interface.source_filter import extract_helm_chart_name


def get_helm_chart_popularity_metrics(unified_service) -> dict:
    """Extract popularity metrics for Helm charts from scan data.

    :param unified_service: Service for accessing scanner database
    :return: Dictionary containing chart metrics, total charts, and total scans
    """
    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT
                    source_file,
                    COUNT(DISTINCT scanner_name || '_' || scan_timestamp) as scan_count,
                    COUNT(*) as total_findings,
                    COUNT(DISTINCT scanner_name) as scanner_count,
                    MIN(created_at) as first_scan,
                    MAX(created_at) as last_scan
                FROM scanner_results
                WHERE source_file LIKE 'helm-chart:%'
                GROUP BY source_file
                ORDER BY scan_count DESC, total_findings DESC
            """

            cursor.execute(query)
            results = [dict(row) for row in cursor.fetchall()]

            chart_metrics = []
            for row in results:
                chart_name = extract_helm_chart_name(row["source_file"])
                if chart_name:
                    chart_metrics.append(
                        {
                            "chart_name": chart_name,
                            "scan_count": row["scan_count"],
                            "total_findings": row["total_findings"],
                            "scanner_count": row["scanner_count"],
                            "first_scan": row["first_scan"],
                            "last_scan": row["last_scan"],
                        }
                    )

            return {
                "charts": chart_metrics,
                "total_charts": len(chart_metrics),
                "total_scans": sum(chart["scan_count"] for chart in chart_metrics),
            }
    except Exception as e:
        st.error(f"Error getting helm chart metrics: {e}")
        return {"charts": [], "total_charts": 0, "total_scans": 0}


def render_helm_chart_popularity_analysis(unified_service):
    """Render popularity analysis visualization for Helm charts.

    :param unified_service: Service for accessing scanner database
    :return: None
    """
    st.markdown("### 📊 Helm Chart Popularity Analysis")

    metrics = get_helm_chart_popularity_metrics(unified_service)

    if not metrics["charts"]:
        st.info("No helm chart data available for analysis.")
        return

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Charts Scanned", metrics["total_charts"])

    with col2:
        st.metric("Total Scans", metrics["total_scans"])

    with col3:
        avg_scans = metrics["total_scans"] / metrics["total_charts"] if metrics["total_charts"] > 0 else 0
        st.metric("Avg Scans per Chart", f"{avg_scans: .1f}")

    if len(metrics["charts"]) > 0:
        chart_df = pd.DataFrame(metrics["charts"])

        st.markdown("**📋 Chart Scan Summary**")
        display_df = chart_df[["chart_name", "scan_count", "total_findings", "scanner_count"]]
        display_df.columns = [
            "Chart Name",
            "Scan Count",
            "Total Findings",
            "Scanner Count",
        ]
        st.dataframe(display_df, use_container_width=True, hide_index=True)


def get_helm_chart_security_profile(unified_service, chart_name: str) -> dict:
    """Extract security profile data for a specific Helm chart.

    :param unified_service: Service for accessing scanner database
    :param chart_name: Name of the Helm chart to analyze
    :return: Dictionary containing severity distribution and resource types
    """
    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT
                    scanner_name,
                    severity,
                    COUNT(*) as finding_count,
                    COUNT(DISTINCT scanner_check_name) as unique_checks
                FROM scanner_results
                WHERE source_file = ?
                GROUP BY scanner_name, severity
                ORDER BY scanner_name, severity
            """

            cursor.execute(query, [f"helm-chart:{chart_name}"])
            severity_results = [dict(row) for row in cursor.fetchall()]

            query = """
                SELECT
                    kind,
                    COUNT(*) as count,
                    COUNT(DISTINCT scanner_name) as scanner_count
                FROM scanner_results
                WHERE source_file = ? AND kind IS NOT NULL
                GROUP BY kind
                ORDER BY count DESC
            """

            cursor.execute(query, [f"helm-chart:{chart_name}"])
            resource_results = [dict(row) for row in cursor.fetchall()]

            return {
                "severity_distribution": severity_results,
                "resource_types": resource_results,
            }
    except Exception as e:
        st.error(f"Error getting chart security profile: {e}")
        return {"severity_distribution": [], "resource_types": []}


def render_helm_chart_security_profile(unified_service, chart_name: str):
    """Render security profile visualization for a specific Helm chart.

    :param unified_service: Service for accessing scanner database
    :param chart_name: Name of the Helm chart to analyze
    :return: None
    """
    st.markdown(f"### 🔒 Security Profile: {chart_name}")

    profile = get_helm_chart_security_profile(unified_service, chart_name)

    if not profile["severity_distribution"] and not profile["resource_types"]:
        st.info(f"No security data available for chart: {chart_name}")
        return

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**🚨 Severity Distribution**")
        if profile["severity_distribution"]:
            severity_df = pd.DataFrame(profile["severity_distribution"])

            chart = (
                alt.Chart(severity_df)
                .mark_bar()
                .encode(
                    x=alt.X("scanner_name:N", title="Scanner"),
                    y=alt.Y("finding_count:Q", title="Findings"),
                    color=alt.Color("severity:N", title="Severity"),
                    tooltip=[
                        "scanner_name:N",
                        "severity:N",
                        "finding_count:Q",
                        "unique_checks:Q",
                    ],
                )
                .properties(height=300)
            )

            st.altair_chart(chart, use_container_width=True)
        else:
            st.info("No severity data available")

    with col2:
        st.markdown("**🎯 Resource Types Analyzed**")
        if profile["resource_types"]:
            resource_df = pd.DataFrame(profile["resource_types"])

            pie_chart = (
                alt.Chart(resource_df)
                .mark_arc(innerRadius=50)
                .encode(
                    theta=alt.Theta("count:Q", title="Finding Count"),
                    color=alt.Color("kind:N", title="Resource Type"),
                    tooltip=["kind:N", "count:Q", "scanner_count:Q"],
                )
                .properties(height=300)
            )

            st.altair_chart(pie_chart, use_container_width=True)
        else:
            st.info("No resource type data available")


def get_helm_chart_deployment_patterns(unified_service) -> dict:
    """Analyze deployment patterns and common issues across Helm charts.

    :param unified_service: Service for accessing scanner database
    :return: Dictionary containing resource patterns and common security issues
    """
    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()

            query = """
                SELECT
                    source_file,
                    kind,
                    COUNT(*) as occurrences,
                    ROUND(AVG(CASE WHEN severity IN ('CRITICAL', 'HIGH', 'DANGER')
                        THEN 1.0 ELSE 0.0 END), 2) as high_severity_rate
                FROM scanner_results
                WHERE source_file LIKE 'helm-chart:%' AND kind IS NOT NULL
                GROUP BY source_file, kind
                ORDER BY source_file, occurrences DESC
            """

            cursor.execute(query)
            pattern_results = [dict(row) for row in cursor.fetchall()]

            query = """
                SELECT
                    scanner_check_name,
                    COUNT(DISTINCT source_file) as affected_charts,
                    COUNT(*) as total_occurrences,
                    severity,
                    COUNT(DISTINCT scanner_name) as detecting_scanners
                FROM scanner_results
                WHERE source_file LIKE 'helm-chart:%'
                GROUP BY scanner_check_name, severity
                HAVING affected_charts >= 2
                ORDER BY affected_charts DESC, total_occurrences DESC
                LIMIT 20
            """

            cursor.execute(query)
            issue_results = [dict(row) for row in cursor.fetchall()]

            return {
                "resource_patterns": pattern_results,
                "common_issues": issue_results,
            }
    except Exception as e:
        st.error(f"Error analyzing deployment patterns: {e}")
        return {"resource_patterns": [], "common_issues": []}


def render_helm_deployment_patterns_analysis(unified_service):
    """Render deployment patterns analysis visualization.

    :param unified_service: Service for accessing scanner database
    :return: None
    """
    st.markdown("### 🏗️ Helm Chart Deployment Patterns")

    patterns = get_helm_chart_deployment_patterns(unified_service)

    if not patterns["resource_patterns"] and not patterns["common_issues"]:
        st.info("No deployment pattern data available.")
        return

    if patterns["resource_patterns"]:
        st.markdown("**📦 Resource Usage Patterns by Chart**")

        pattern_df = pd.DataFrame(patterns["resource_patterns"])

        from kalm_benchmark.ui.interface.source_filter import extract_helm_chart_name

        pattern_df["chart_name"] = pattern_df["source_file"].apply(lambda x: extract_helm_chart_name(x) or x)

        chart = (
            alt.Chart(pattern_df)
            .mark_bar()
            .encode(
                x=alt.X(
                    "chart_name:N",
                    title="Helm Chart",
                    axis=alt.Axis(labelAngle=-45),
                ),
                y=alt.Y("occurrences:Q", title="Number of Resources/Findings"),
                color=alt.Color("kind:N", legend=alt.Legend(title="Resource Type")),
                tooltip=[
                    alt.Tooltip("chart_name:N", title="Chart"),
                    alt.Tooltip("kind:N", title="Resource Type"),
                    alt.Tooltip("occurrences:Q", title="Occurrences"),
                    alt.Tooltip(
                        "high_severity_rate:Q",
                        title="High Severity Rate",
                        format=".1%",
                    ),
                ],
            )
            .properties(
                title="Resource Usage Comparison Across Helm Charts",
                width=600,
                height=400,
            )
        )

        st.altair_chart(chart, use_container_width=True)

        st.markdown("**📋 Detailed Resource Breakdown by Chart**")

        pivot_df = pattern_df.pivot_table(
            index="chart_name",
            columns="kind",
            values="occurrences",
            fill_value=0,
        ).reset_index()

        resource_columns = [col for col in pivot_df.columns if col != "chart_name"]
        pivot_df["Total Resources"] = pivot_df[resource_columns].sum(axis=1)

        pivot_df = pivot_df.sort_values("Total Resources", ascending=False)

        st.dataframe(pivot_df, use_container_width=True, hide_index=True)

        st.info(
            "💡 Compare resource usage patterns to identify which charts are more complex "
            "or have different deployment strategies"
        )

    if patterns["common_issues"]:
        st.markdown("---")
        st.markdown("**🔴 Most Common Security Issues Across Charts**")

        issue_df = pd.DataFrame(patterns["common_issues"])
        top_issues = issue_df.head(10)

        for _, issue in top_issues.iterrows():
            severity_color = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "DANGER": "🟠",
                "MEDIUM": "🟡",
                "WARNING": "🟡",
                "LOW": "🟢",
                "INFO": "🔵",
            }.get(issue["severity"], "⚪")

            st.markdown(
                f"""
                <div style="padding: 0.5rem; margin: 0.3rem 0; background: #f8f9fa; "
                "border-left: 4px solid #17a2b8; border-radius: 4px;">
                <strong>{severity_color} {issue["scanner_check_name"]}</strong><br/>
                <small>Affects {issue["affected_charts"]} charts • {issue["total_occurrences"]} occurrences • "
                "Detected by {issue["detecting_scanners"]} scanner(s)</small>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_helm_chart_comparative_analysis(unified_service, chart_names: list[str]):
    """Render comparative security analysis between multiple Helm charts.

    :param unified_service: Service for accessing scanner database
    :param chart_names: List of Helm chart names to compare
    :return: None
    """
    if len(chart_names) < 2:
        st.info("Select at least 2 charts for comparative analysis.")
        return

    st.markdown(f"### ⚖️ Comparative Analysis: {len(chart_names)} Charts")

    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()

            chart_conditions = " OR ".join(["source_file = ?" for _ in chart_names])
            source_files = [f"helm-chart:{chart}" for chart in chart_names]

            query = f"""
                SELECT
                    source_file,
                    severity,
                    COUNT(*) as finding_count
                FROM scanner_results
                WHERE {chart_conditions}
                GROUP BY source_file, severity
                ORDER BY source_file, severity
            """

            cursor.execute(query, source_files)
            comparison_data = [dict(row) for row in cursor.fetchall()]

            if comparison_data:
                comparison_df = pd.DataFrame(comparison_data)
                comparison_df["chart_name"] = comparison_df["source_file"].apply(
                    lambda x: extract_helm_chart_name(x) or x
                )

                chart = (
                    alt.Chart(comparison_df)
                    .mark_bar()
                    .encode(
                        x=alt.X("chart_name:N", title="Helm Chart"),
                        y=alt.Y("finding_count:Q", title="Number of Findings"),
                        color=alt.Color("severity:N", title="Severity"),
                        tooltip=[
                            "chart_name:N",
                            "severity:N",
                            "finding_count:Q",
                        ],
                    )
                    .properties(
                        title="Security Findings Comparison Across Charts",
                        height=400,
                    )
                )

                st.altair_chart(chart, use_container_width=True)

                st.markdown("**📊 Summary Comparison**")
                summary = (
                    comparison_df.groupby("chart_name")
                    .agg({"finding_count": "sum"})
                    .sort_values("finding_count", ascending=False)
                    .reset_index()
                )
                summary.columns = ["Chart Name", "Total Findings"]
                st.dataframe(summary, use_container_width=True, hide_index=True)
            else:
                st.info("No comparison data available for selected charts.")

    except Exception as e:
        st.error(f"Error in comparative analysis: {e}")
