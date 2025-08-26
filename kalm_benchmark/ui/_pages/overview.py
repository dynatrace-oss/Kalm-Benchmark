import base64
import time
from pathlib import Path
from typing import Optional

import pandas as pd
import streamlit as st
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, JsCode

from kalm_benchmark.evaluation import evaluation
from kalm_benchmark.evaluation.scanner_manager import SCANNERS
from kalm_benchmark.ui.utils.gen_utils import get_unified_service, init
from kalm_benchmark.ui.utils.overview_utils import (
    build_scanner_info,
    create_scanner_summary,
    parse_scan_timestamp,
    process_source_filter,
)
from kalm_benchmark.utils.constants import (
    CI_MODE_LABEL,
    CLUSTER_SCANNING_LABEL,
    CUSTOM_CHECKS_LABEL,
    MANIFEST_SCANNING_LABEL,
    OUTPUT_FORMATS_ALTAIR,
    OUTPUT_FORMATS_LABEL,
    SEVERITY_SUPPORT_LABEL,
    STANDARD_SEVERITY_SCORES,
    Page,
    QueryParam,
)


def _get_scanner_icon_path(scanner_name: str) -> str:
    """Get local path to scanner icon based on scanner name.

    :param scanner_name: The name of the scanner
    :return: Absolute path to the local icon file
    """
    icon_mapping = {
        "KubeLinter": "kube-linter.svg",
        "kube-score": "kube-score.png",
        "Snyk": "snyk.svg",
        "kube-bench": "kube-bench.png",
        "trivy": "trivy.png",
        "polaris": "polaris.png",
        "Terrascan": "terrascan.png",
        "Kubescape": "kubescape.svg",
        "kubesec": "kubesec.png",
        "kubiscan": "kubiscan.png",
        "KICS": "kics.png",
        "Checkov": "checkov.png",
    }

    icon_filename = icon_mapping.get(scanner_name, "")
    if icon_filename:
        # Find project root by looking for pyproject.toml (deployment-agnostic)
        current_file = Path(__file__)
        project_root = current_file
        while project_root.parent != project_root:
            if (project_root / "pyproject.toml").exists():
                break
            project_root = project_root.parent

        icon_path = project_root / "docs" / "images" / "icons" / icon_filename
        return str(icon_path) if icon_path.exists() else ""
    return ""


def _get_category_ratio(category_summary: pd.Series | None) -> str:
    """Get category ratio in original KALM format 'covered/total (+extra)'.

    :param category_summary: a series of all the result types of a particular scanner
    :return: the ratio as string in format 'covered/total (+extra)' matching original KALM
    """
    if category_summary is None:
        return "0/0"

    covered = category_summary.get(evaluation.ResultType.Covered, 0)
    missing = category_summary.get(evaluation.ResultType.Missing, 0)
    extra = category_summary.get(evaluation.ResultType.Extra, 0)

    total = covered + missing
    result = f"{covered}/{total}"

    if extra > 0:
        result += f" (+{extra})"

    return result


def collect_overview_information(source_filter: str = "all") -> pd.DataFrame:
    """Load all evaluation results of all scanners from unified database.

    Refactored to reduce cognitive complexity by extracting helper functions.

    :param source_filter: filter results by source type ("all", "manifests", "cluster", etc.)
    :return: a dataframe where every row corresponds to the information for a particular scanner
    """
    scanner_infos = []
    unified_service = get_unified_service()
    db_summaries = unified_service.create_evaluation_summary_dataframe()
    summary_map = {s["scanner_name"]: s for s in db_summaries}

    for name, scanner in SCANNERS.items():
        # Get and filter scan runs
        scan_runs = unified_service.db.get_scan_runs(scanner_name=name.lower())
        scan_runs = process_source_filter(scan_runs, source_filter)

        # Parse latest scan date
        latest_scan_date = parse_scan_timestamp(scan_runs[0]["timestamp"]) if scan_runs else "Never"

        # Create scanner summary
        db_summary = summary_map.get(name.lower())
        summary, is_valid_summary = create_scanner_summary(name, db_summary, unified_service)

        # Build scanner info object
        scanner_info = build_scanner_info(name, scanner, summary, is_valid_summary, latest_scan_date)
        scanner_infos.append(scanner_info)

    return pd.DataFrame(scanner_infos)


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
    builder.configure_column(
        "name",
        header_name="Scanner",
        pinned="left",
        lockPinned="true",
        filter=False,
    )

    builder.configure_column("image", hide=True)
    builder.configure_column(
        "version",
        header_name="Version",
        headerTooltip="The version the tool had when creating the results",
        width=130,
        tooltipShowDelay=TOOLTIP_DELAY,
    )
    builder.configure_column(
        "ci_mode",
        header_name=CI_MODE_LABEL,
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
        header_name=CUSTOM_CHECKS_LABEL,
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
    builder.configure_column(
        "can_scan_manifests",
        header_name="Scan IaC",
        valueFormatter=bool_flag_formatter,
    )
    builder.configure_column(
        "can_scan_cluster",
        header_name="Scan Cluster",
        valueFormatter=bool_flag_formatter,
    )
    builder.configure_column("formats", header_name="Report Formats", filter=True)
    builder.configure_column(
        "latest_scan_date",
        header_name="Last Scan",
        width=150,
        headerTooltip="Date of the most recent scan for this scanner",
        tooltipShowDelay=TOOLTIP_DELAY,
    )

    cat_columns = [c for c in df.columns if c.startswith("cat_")]

    for c in cat_columns:
        header_text = evaluation.snake_case_to_title(c[4:])

        builder.configure_column(
            c,
            header_name=header_text,
            headerTooltip="The number of covered vs all checks. Checks outside the benchmark are shown in parenthesis.",
            tooltipShowDelay=TOOLTIP_DELAY,
        )

    grid_options = builder.build()

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
        height=520,
        custom_css={
            ".ag-row-hover": {"background-color": HOVER_COLOR + " !important"},
            ".img-cell.ag-cell": {
                "padding-left": "0",
                "padding-right": "0",
                "text-align": "center",
            },
            ".invalid-summary.ag-row": {"color": "red", "font-style": "italic"},
        },
    )

    st.markdown(
        """
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
            if df["is_valid_summary"].sum() < len(df)
            else '<div style="color: #2e7d32; font-weight: 600;">✅ All scanners have valid results</div>'
        ),
        unsafe_allow_html=True,
    )

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
    sub_columns = []
    new_cols = []
    for col in grid_options["columnDefs"]:
        if col["field"] in columns_to_group:
            sub_columns.append(col)
        else:
            new_cols.append(col)

    new_cols.append({"field": group_name, "headerName": group_name, "children": sub_columns})
    grid_options["columnDefs"] = new_cols

    return grid_options


def show_header():
    """Show header with professional styling and supported scanners."""
    st.markdown(
        """
    <div style="text-align: center; padding: 3.5rem 0 2.5rem 0; 
                background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 20%, #74b9ff 40%, #00cec9 60%, #55efc4 80%, #6c5ce7 100%); 
                border-radius: 20px; margin-bottom: 2rem; 
                box-shadow: 0 15px 40px rgba(108, 92, 231, 0.5); 
                position: relative; overflow: hidden;">
        <div style="position: absolute; top: 0; left: 0; right: 0; bottom: 0; 
                    background: radial-gradient(circle at 15% 25%, rgba(162, 155, 254, 0.4) 0%, transparent 50%), 
                                radial-gradient(circle at 85% 75%, rgba(116, 185, 255, 0.4) 0%, transparent 50%), 
                                radial-gradient(circle at 50% 15%, rgba(0, 206, 201, 0.3) 0%, transparent 45%), 
                                radial-gradient(circle at 25% 85%, rgba(85, 239, 196, 0.3) 0%, transparent 45%); 
                    pointer-events: none;"></div>
        <div style="max-width: 800px; margin: 0 auto; padding: 0 2rem; position: relative; z-index: 1;">
            <h1 style="color: #FFFFFF; margin-bottom: 0.5rem; font-size: 3.2rem; font-weight: 800; 
                       text-shadow: 0 4px 15px rgba(0,0,0,0.4); letter-spacing: -0.02em;">
                🛡️ Kalm Benchmark
            </h1>
            <h3 style="color: rgba(255,255,255,0.95); font-weight: 500; margin-bottom: 1.5rem; 
                      font-size: 1.6rem; text-shadow: 0 2px 8px rgba(0,0,0,0.3);">
                Kubernetes Security Scanner Comparison Platform
            </h3>
            <p style="color: rgba(255,255,255,0.9); max-width: 650px; margin: 0 auto; 
                     line-height: 1.7; font-size: 1.15rem; text-shadow: 0 2px 6px rgba(0,0,0,0.25);">
                Comprehensive evaluation and comparison of Kubernetes workload compliance scanners. 
                Compare features, performance metrics, and coverage to make informed decisions about 
                your security toolchain.
            </p>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
    <div style="text-align: center; margin: 2rem 0;">
        <h4 style="color: #474ecf; margin-bottom: 1.5rem; font-weight: 700; font-size: 1.4rem; 
                   text-shadow: 0 1px 3px rgba(71, 78, 207, 0.3);">
            Supported Security Scanners
        </h4>
    </div>
    """,
        unsafe_allow_html=True,
    )

    scanner_names = list(SCANNERS.keys())

    icons_per_row = 5
    rows_needed = (len(scanner_names) + icons_per_row - 1) // icons_per_row

    for row in range(rows_needed):
        cols = st.columns(icons_per_row)
        for col_idx in range(icons_per_row):
            scanner_idx = row * icons_per_row + col_idx
            if scanner_idx < len(scanner_names):
                scanner_name = scanner_names[scanner_idx]
                icon_path = _get_scanner_icon_path(scanner_name)

                with cols[col_idx]:
                    if icon_path and Path(icon_path).exists():
                        try:
                            with open(icon_path, "rb") as f:
                                image_data = f.read()

                            mime_type = "svg+xml" if icon_path.endswith(".svg") else "png"
                            b64_image = base64.b64encode(image_data).decode()

                            st.markdown(
                                f"""
                            <div style="display: flex; justify-content: center; align-items: center; height: 80px; padding: 8px;">
                                <img src="data:image/{mime_type};base64,{b64_image}" 
                                     style="max-width: 70px; max-height: 70px; object-fit: contain; filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1));" 
                                     alt="{scanner_name}">
                            </div>
                            """,
                                unsafe_allow_html=True,
                            )
                        except Exception:
                            st.markdown(
                                f"""
                            <div style="display: flex; justify-content: center; align-items: center; height: 80px; padding: 8px; 
                                        background: #f8f9fa; border-radius: 8px; border: 2px dashed #dee2e6;">
                                <span style="color: #666; font-size: 0.8rem; text-align: center;">{scanner_name}</span>
                            </div>
                            """,
                                unsafe_allow_html=True,
                            )
                    else:
                        st.markdown(
                            f"""
                        <div style="display: flex; justify-content: center; align-items: center; height: 80px; padding: 8px; 
                                    background: #f8f9fa; border-radius: 8px; border: 2px dashed #dee2e6;">
                            <span style="color: #666; font-size: 0.8rem; text-align: center;">{scanner_name}</span>
                        </div>
                        """,
                            unsafe_allow_html=True,
                        )


def show_quick_stats(df: pd.DataFrame):
    """Show quick statistics with professional styling."""
    total_scanners = len(df)
    valid_results = df["is_valid_summary"].sum()
    avg_score = df[df["is_valid_summary"]]["score"].mean() if valid_results > 0 else 0
    avg_coverage = df[df["is_valid_summary"]]["coverage"].mean() if valid_results > 0 else 0

    st.markdown(
        """
    <div style="background: #f8f9fa; padding: 1.5rem; border-radius: 8px; border: 1px solid #e9ecef; margin-bottom: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
        <h4 style="text-align: center; color: #495057; margin-bottom: 1.5rem; font-weight: 600; font-size: 1.1rem;">📈 Platform Statistics</h4>
    </div>
    """,
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="📊 Total Scanners",
            value=total_scanners,
            help="Number of scanners available in the benchmark",
        )

    with col2:
        st.metric(
            label="✅ With Results",
            value=valid_results,
            help="Scanners with valid evaluation results",
        )

    with col3:
        st.metric(
            label="🎯 Avg F1 Score",
            value=f"{avg_score:.1%}" if avg_score > 0 else "N/A",
            help="Average F1 score across all scanners with results",
        )

    with col4:
        st.metric(
            label="📈 Avg Coverage",
            value=f"{avg_coverage:.1%}" if avg_coverage > 0 else "N/A",
            help="Average check coverage across all scanners with results",
        )


def show_scanner_capabilities_matrix():
    """Show general scanner capabilities matrix (moved from scanner comparison page)"""
    st.subheader("Scanner Capabilities Matrix")

    # Define scanner capabilities based on their implementations
    scanner_capabilities = {
        "Scanner": [],
        MANIFEST_SCANNING_LABEL: [],
        CLUSTER_SCANNING_LABEL: [],
        "CI/CD Mode": [],
        "Offline Capability": [],
        CUSTOM_CHECKS_LABEL: [],
        OUTPUT_FORMATS_LABEL: [],
        SEVERITY_SUPPORT_LABEL: [],
    }

    from kalm_benchmark.evaluation.scanner_manager import SCANNERS

    for scanner_name, scanner_class in SCANNERS.items():
        scanner_capabilities["Scanner"].append(scanner_name)
        scanner_capabilities["Manifest Scanning"].append("✅" if hasattr(scanner_class, "scan_manifests") else "❌")
        scanner_capabilities["Cluster Scanning"].append("✅" if hasattr(scanner_class, "scan_cluster") else "❌")
        scanner_capabilities["CI/CD Mode"].append("✅" if getattr(scanner_class, "CI_MODE", False) else "❌")
        scanner_capabilities["Offline Capability"].append(
            "✅" if getattr(scanner_class, "RUNS_OFFLINE", False) else "❌"
        )
        scanner_capabilities["Custom Checks"].append("✅" if getattr(scanner_class, "CUSTOM_CHECKS", False) else "❌")

        formats = getattr(scanner_class, "FORMATS", [])
        formats_str = f"{len(formats)} formats" if formats else "Basic"
        scanner_capabilities["Output Formats"].append(formats_str)

        # Check if scanner supports severity (based on our audit)
        severity_support = scanner_name.lower() in [
            "checkov",
            "kics",
            "kube-score",
            "trivy",
            "polaris",
            "snyk",
            "kubescape",
        ]
        scanner_capabilities["Severity Support"].append("✅" if severity_support else "❌")

    capabilities_df = pd.DataFrame(scanner_capabilities)

    # Display as interactive table
    st.dataframe(capabilities_df, use_container_width=True)

    # Show feature summary
    col1, col2, col3 = st.columns(3)

    with col1:
        manifest_scanners = sum(1 for x in scanner_capabilities["Manifest Scanning"] if x == "✅")
        st.metric("Manifest Scanners", f"{manifest_scanners}/{len(scanner_capabilities['Scanner'])}")

    with col2:
        cluster_scanners = sum(1 for x in scanner_capabilities["Cluster Scanning"] if x == "✅")
        st.metric("Cluster Scanners", f"{cluster_scanners}/{len(scanner_capabilities['Scanner'])}")

    with col3:
        severity_scanners = sum(1 for x in scanner_capabilities["Severity Support"] if x == "✅")
        st.metric(SEVERITY_SUPPORT_LABEL, f"{severity_scanners}/{len(scanner_capabilities['Scanner'])}")


def show_severity_support_analysis():
    """Show analysis of which scanners support severity scoring (moved from scanner comparison page)"""
    st.subheader("⚖️ Severity Scoring Support Analysis")

    # Severity support data based on our audit
    severity_data = {
        "Scanner": [
            "Checkov",
            "KICS",
            "Kube-score",
            "Trivy",
            "Polaris",
            "Snyk",
            "Kubescape",
            "KubeLinter",
            "Kube-bench",
        ],
        "Severity Support": ["✅", "✅", "✅", "✅", "✅", "✅", "✅", "❌", "❌"],
        "Severity Levels": [
            "CRITICAL, HIGH, MEDIUM, LOW",
            "CRITICAL, HIGH, MEDIUM, LOW, INFO",
            "Critical (1), Warning (5), Ok (10), Skipped (0)",
            "CRITICAL, HIGH, MEDIUM, LOW",
            "danger, warning, success",
            "critical, high, medium, low",
            "High, Medium, Low",
            "N/A",
            "N/A (Infrastructure focus)",
        ],
        "Score Mapping": [
            STANDARD_SEVERITY_SCORES,
            "Standard (9.0, 7.0, 4.0, 2.0, 1.0)",
            "Numeric from output (1, 5, 10, 0)",
            STANDARD_SEVERITY_SCORES,
            "Custom mapping needed",
            STANDARD_SEVERITY_SCORES,
            STANDARD_SEVERITY_SCORES,
            "N/A",
            "N/A",
        ],
    }

    severity_df = pd.DataFrame(severity_data)

    col1, col2 = st.columns([3, 1])

    with col1:
        st.markdown("**📊 Severity Support Matrix**")
        st.dataframe(severity_df, use_container_width=True)

    with col2:
        st.markdown("**📈 Support Statistics**")

        supported = len([x for x in severity_data["Severity Support"] if x == "✅"])
        total = len(severity_data["Scanner"])
        not_supported = total - supported

        st.metric("With Severity", supported)
        st.metric("Without Severity", not_supported)
        st.metric("Support Rate", f"{(supported/total)*100:.0f}%")

    st.markdown(
        """
    **💡 Key Insights:**
    - **7/9 scanners** support severity scoring
    - **Standard mapping** (CRITICAL=9.0, HIGH=7.0, etc.) works for most scanners
    - **Kube-score** uses unique numeric format that maps directly to scores
    - **KubeLinter** focuses on best practices without severity classification
    - **Kube-bench** is infrastructure-focused and doesn't use application-level severity
    """
    )


def show_scanner_deployment_comparison():
    """Show scanner deployment and format options (moved from scanner comparison page)"""
    st.subheader("🚀 Deployment & Format Comparison")

    # Create deployment comparison data
    deployment_data = []

    import altair as alt

    from kalm_benchmark.evaluation.scanner_manager import SCANNERS

    for scanner_name, scanner_class in SCANNERS.items():
        formats = getattr(scanner_class, "FORMATS", ["Plain"])

        deployment_data.append(
            {
                "Scanner": scanner_name,
                CI_MODE_LABEL: "✅" if getattr(scanner_class, "CI_MODE", False) else "❌",
                "Runs Offline": "✅" if getattr(scanner_class, "RUNS_OFFLINE", False) else "❌",
                OUTPUT_FORMATS_LABEL: len(formats),
                "Format Details": ", ".join(formats[:3]) + ("..." if len(formats) > 3 else ""),
                CUSTOM_CHECKS_LABEL: "✅" if getattr(scanner_class, "CUSTOM_CHECKS", False) else "❌",
            }
        )

    deployment_df = pd.DataFrame(deployment_data)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("**📋 Deployment Capabilities**")
        st.dataframe(deployment_df, use_container_width=True)

    with col2:
        st.markdown("**🎯 Quick Stats**")

        ci_ready = len([x for x in deployment_df[CI_MODE_LABEL] if x == "✅"])
        offline_capable = len([x for x in deployment_df["Runs Offline"] if x == "✅"])
        custom_checks = len([x for x in deployment_df[CUSTOM_CHECKS_LABEL] if x == "✅"])
        avg_formats = deployment_df[OUTPUT_FORMATS_LABEL].mean()

        st.metric(CI_MODE_LABEL, f"{ci_ready}/{len(deployment_df)}")
        st.metric("Offline Capable", f"{offline_capable}/{len(deployment_df)}")
        st.metric(CUSTOM_CHECKS_LABEL, f"{custom_checks}/{len(deployment_df)}")
        st.metric("Avg Formats", f"{avg_formats:.1f}")

    # Show format variety chart
    st.markdown("**📊 Output Format Variety**")

    format_chart = (
        alt.Chart(deployment_df)
        .mark_bar()
        .encode(
            x=alt.X("Scanner:N", axis=alt.Axis(labelAngle=0)),
            y=alt.Y(OUTPUT_FORMATS_ALTAIR),
            color=alt.Color(OUTPUT_FORMATS_ALTAIR, scale=alt.Scale(scheme="viridis")),
            tooltip=["Scanner:N", OUTPUT_FORMATS_ALTAIR, "Format Details:N"],
        )
        .properties(width=600, height=300, title="Number of Supported Output Formats by Scanner")
    )

    st.altair_chart(format_chart, use_container_width=True)


def get_available_sources() -> dict:
    """Get list of available source instances from the database."""
    unified_service = get_unified_service()
    source_mapping = {}

    try:
        for name in SCANNERS.keys():
            scan_runs = unified_service.db.get_scan_runs(scanner_name=name.lower())
            for run in scan_runs:
                source_type = run.get("source_type", "unknown")
                source_location = run.get("source_location", "")

                if source_type and source_type != "unknown":
                    if ":" in source_type:
                        actual_type, source_name = source_type.split(":", 1)

                        if actual_type.lower() in ["manifest", "manifests"]:
                            display_name = f"📁 {source_name}"
                            filter_value = f"manifests:{source_name}"
                        elif actual_type.lower() == "cluster":
                            display_name = f"🌐 {source_name}"
                            filter_value = f"cluster:{source_name}"
                        elif actual_type.lower() in ["helm-chart", "helm"]:
                            display_name = f"⚓ {source_name}"
                            filter_value = f"helm-chart:{source_name}"
                        else:
                            display_name = f"🔧 {source_name}"
                            filter_value = f"{actual_type}:{source_name}"

                        source_mapping[display_name] = filter_value

                    else:
                        if source_location:
                            if source_type.lower() in ["manifest", "manifests"]:
                                path_name = Path(source_location).name if source_location else source_type
                                display_name = f"📁 {path_name}"
                                filter_value = f"manifests:{path_name}"
                            elif source_type.lower() == "cluster":
                                display_name = f"🌐 {source_location}"
                                filter_value = f"cluster:{source_location}"
                            elif source_type.lower() in ["helm-chart", "helm"]:
                                display_name = f"⚓ {source_location}"
                                filter_value = f"helm-chart:{source_location}"
                            else:
                                display_name = f"🔧 {source_type}: {source_location}"
                                filter_value = f"{source_type}:{source_location}"

                            source_mapping[display_name] = filter_value
                        else:
                            display_name = f"🔧 {source_type.title()}"
                            source_mapping[display_name] = source_type

    except Exception as e:
        from loguru import logger

        logger.error(f"Error getting available sources: {e}")

    return source_mapping


def show_filter_options() -> dict:
    """Show filtering options and return filter criteria."""
    with st.expander("🔍 Advanced Filter Options", expanded=False):
        st.markdown("**Customize your scanner comparison view:**")

        col1, col2 = st.columns(2)
        with col1:
            min_score = st.slider(
                "📊 Minimum Score",
                min_value=0.0,
                max_value=1.0,
                value=0.0,
                step=0.05,
                format="%.2f",
                help="Filter scanners by minimum F1 score (0.0 = show all)",
            )

        with col2:
            min_coverage = st.slider(
                "📈 Minimum Coverage",
                min_value=0.0,
                max_value=1.0,
                value=0.0,
                step=0.05,
                format="%.2f",
                help="Filter scanners by minimum check coverage (0.0 = show all)",
            )

        st.markdown("---")

        col3, col4 = st.columns(2)

        with col3:
            st.markdown("**🎯 Scan Source Filter:**")

            available_source_mapping = get_available_sources()

            source_options = ["All Sources"] + list(available_source_mapping.keys())

            selected_source_display = st.selectbox(
                "Select specific source to filter:",
                options=source_options,
                index=0,
                help="Filter scanners by specific manifest paths, cluster names, or helm charts they've scanned",
            )

            if selected_source_display == "All Sources":
                selected_source = "all"
            else:
                selected_source = available_source_mapping.get(selected_source_display, "all")

        with col4:
            st.markdown("**⚙️ Required Capabilities:**")
            capabilities = st.multiselect(
                "Must support:",
                options=[
                    "🌐 Cluster Scanning",
                    "📁 Manifest Scanning",
                    "🔄 CI/CD Mode",
                    "🛠️ Custom Checks",
                    "📱 Offline Mode",
                ],
                default=[],
                help="Only show scanners that support ALL selected capabilities",
            )

            capability_mapping = {
                "🌐 Cluster Scanning": CLUSTER_SCANNING_LABEL,
                "📁 Manifest Scanning": MANIFEST_SCANNING_LABEL,
                "🔄 CI/CD Mode": CI_MODE_LABEL,
                "🛠️ Custom Checks": CUSTOM_CHECKS_LABEL,
                "📱 Offline Mode": "Offline Mode",
            }

            capabilities = [capability_mapping.get(cap, cap) for cap in capabilities]

        active_filters = []
        if min_score > 0:
            active_filters.append(f"Score ≥ {min_score:.2f}")
        if min_coverage > 0:
            active_filters.append(f"Coverage ≥ {min_coverage:.2f}")
        if selected_source != "all":
            active_filters.append(f"Source: {selected_source_display}")
        if capabilities:
            active_filters.append(f"Capabilities: {len(capabilities)} required")

        if active_filters:
            st.markdown(f"**🎯 Active filters:** {' • '.join(active_filters)}")
        else:
            st.markdown("**💡 No filters active** - showing all scanners")

    return {
        "min_score": min_score,
        "min_coverage": min_coverage,
        "capabilities": capabilities,
        "source": selected_source,
    }


def apply_filters(df: pd.DataFrame, filters: dict) -> pd.DataFrame:
    """Apply filters to the dataframe."""
    filtered_df = df.copy()

    if filters["min_score"] > 0:
        filtered_df = filtered_df[filtered_df["score"] >= filters["min_score"]]

    if filters["min_coverage"] > 0:
        filtered_df = filtered_df[filtered_df["coverage"] >= filters["min_coverage"]]

    if CLUSTER_SCANNING_LABEL in filters["capabilities"]:
        filtered_df = filtered_df[filtered_df["can_scan_cluster"]]
    if MANIFEST_SCANNING_LABEL in filters["capabilities"]:
        filtered_df = filtered_df[filtered_df["can_scan_manifests"]]
    if CI_MODE_LABEL in filters["capabilities"]:
        filtered_df = filtered_df[filtered_df["ci_mode"]]
    if CUSTOM_CHECKS_LABEL in filters["capabilities"]:
        filtered_df = filtered_df[filtered_df["custom_checks"] != "False"]
    if "Offline Mode" in filters["capabilities"]:
        filtered_df = filtered_df[filtered_df["runs_offline"] != "False"]

    return filtered_df


def show_quick_actions(selection: Optional[dict]):
    """Show quick action buttons for selected scanner."""
    if selection is None:
        return

    tool_name = selection["name"]
    scanner = SCANNERS.get(tool_name)

    st.markdown("### ⚡ Quick Actions")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("📊 View Details", key="view_details", type="primary"):
            st.query_params = {
                QueryParam.Page: Page.Scanner,
                QueryParam.SelectedScanner: tool_name,
            }
            time.sleep(0.1)
            st.rerun()

    with col2:
        if scanner and scanner.can_scan_manifests:
            if st.button("🚀 Quick Scan", key="quick_scan"):
                st.query_params = {
                    QueryParam.Page: Page.Scanner,
                    QueryParam.SelectedScanner: tool_name,
                    "action": "scan",
                }
                time.sleep(0.1)
                st.rerun()
        else:
            st.button(
                "🚀 Quick Scan",
                disabled=True,
                help="This scanner doesn't support manifest scanning",
            )

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

    st.markdown(
        """
    <div style="height: 2px; background: linear-gradient(90deg, transparent 0%, #dee2e6 20%, #dee2e6 80%, transparent 100%); margin: 2rem 0;"></div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
    <div style="margin: 2rem 0 1rem 0;">
        <h3 style="color: #474ecf; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; 
                   font-size: 1.5rem; text-shadow: 0 1px 3px rgba(71, 78, 207, 0.2);">
            📋 Scanner Comparison Table
        </h3>
        <p style="color: #2f6863; margin-top: 0.5rem; font-size: 1rem; margin-bottom: 1.5rem; font-weight: 500;">
            Interactive comparison of security scanners with detailed metrics and capabilities
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    filters = show_filter_options()

    df_filtered = collect_overview_information(source_filter=filters.get("source", "all"))
    filtered_df = apply_filters(df_filtered, filters)

    if len(filtered_df) < len(df):
        st.markdown(
            f"""
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 0.75rem 1rem; border-radius: 6px; margin: 1rem 0;">
            🔍 <strong>Filtered View:</strong> Showing {len(filtered_df)} of {len(df)} scanners based on your criteria
        </div>
        """,
            unsafe_allow_html=True,
        )

    selection = show_overview_grid(filtered_df)

    if selection:
        st.markdown(
            """
        <div style="margin-top: 2rem; padding: 1.5rem; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 10px; border: 1px solid #dee2e6;">
        """,
            unsafe_allow_html=True,
        )
        show_quick_actions(selection)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        show_quick_actions(selection)

    # Add divider and show general scanner capabilities
    st.markdown(
        """
    <div style="height: 2px; background: linear-gradient(90deg, transparent 0%, #dee2e6 20%, #dee2e6 80%, transparent 100%); margin: 3rem 0 2rem 0;"></div>
    """,
        unsafe_allow_html=True,
    )

    show_scanner_capabilities_matrix()

    st.divider()

    show_severity_support_analysis()

    st.divider()

    show_scanner_deployment_comparison()


if __name__ == "__main__":
    init()
    show()
