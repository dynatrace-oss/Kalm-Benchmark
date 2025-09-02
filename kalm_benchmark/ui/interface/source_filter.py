from enum import Enum

import streamlit as st


class ScanSourceType(str, Enum):
    """Enum for different scan source types."""

    BENCHMARK = "benchmark"
    HELM_CHARTS = "helm_charts"
    CUSTOM_MANIFESTS = "custom_manifests"
    ALL = "all"

    def display_name(self) -> str:
        """Get human-readable display name for UI components.

        :return: Formatted display name for the scan source type
        """
        display_names = {
            self.BENCHMARK: "Benchmark",
            self.HELM_CHARTS: "Helm Charts",
            self.CUSTOM_MANIFESTS: "Custom Manifests",
            self.ALL: "All Sources",
        }
        return display_names.get(self, self.value)

    def description(self) -> str:
        """Get detailed description for help text and tooltips.

        :return: Descriptive text explaining the scan source type
        """
        descriptions = {
            self.BENCHMARK: "KALM benchmark test manifests for security assessment",
            self.HELM_CHARTS: "Real-world Helm chart deployments from Artifact Hub",
            self.CUSTOM_MANIFESTS: "User-uploaded custom Kubernetes manifests",
            self.ALL: "Combined view of all scan sources",
        }
        return descriptions.get(self, "Unknown source type")


def render_source_type_filter(
    key: str = "source_type_filter",
    default: ScanSourceType = ScanSourceType.BENCHMARK,
    show_all_option: bool = True,
    show_counts: bool = True,
    unified_service=None,
) -> ScanSourceType:
    """Render the source type filter selectbox component.

    :param key: Unique key for the Streamlit component
    :param default: Default selected source type
    :param show_all_option: Whether to show "All Sources" option
    :param show_counts: Whether to show scan counts for each type
    :param unified_service: Service instance for getting scan counts
    :return: Selected ScanSourceType from user interaction
    """
    counts = {}
    if show_counts and unified_service:
        counts = get_source_type_counts(unified_service)

    options = [ScanSourceType.BENCHMARK, ScanSourceType.HELM_CHARTS, ScanSourceType.CUSTOM_MANIFESTS]
    if show_all_option:
        options = [ScanSourceType.ALL] + options

    option_labels = []
    for scan_type in options:
        label = scan_type.display_name()
        if show_counts and scan_type in counts:
            count = counts[scan_type]
            label += f" ({count})"
        option_labels.append(label)

    try:
        default_index = options.index(default)
    except ValueError:
        default_index = 0

    selected_label = st.selectbox(
        "**Scan Source**",
        options=option_labels,
        index=default_index,
        key=key,
        help="Choose the type of scans to analyze",
    )

    selected_index = option_labels.index(selected_label)
    return options[selected_index]


def get_source_filter_sql_condition(scan_type: ScanSourceType, scanner_results_alias: str = None) -> tuple[str, list]:
    """Generate SQL WHERE condition and parameters for filtering by source type.

    :param scan_type: The selected scan source type to filter by
    :param scanner_results_alias: Optional alias for scanner_results table (e.g., 'sr2')
    :return: Tuple of (SQL WHERE condition string, list of parameters)
    """
    timestamp_col = f"{scanner_results_alias}.scan_timestamp" if scanner_results_alias else "scan_timestamp"

    if scan_type == ScanSourceType.BENCHMARK:
        return (
            f"AND {timestamp_col} IN (SELECT timestamp FROM scan_runs\
                WHERE source_type = ? OR source_type = ? OR source_type IS NULL)",
            ["manifest", "benchmark"],
        )
    elif scan_type == ScanSourceType.HELM_CHARTS:
        return f"AND {timestamp_col} IN (SELECT timestamp FROM scan_runs WHERE source_type LIKE ?)", ["helm-chart:%"]
    elif scan_type == ScanSourceType.CUSTOM_MANIFESTS:
        return (
            f"AND {timestamp_col} IN (SELECT timestamp FROM scan_runs \
                WHERE source_type NOT LIKE ? AND source_type != ? AND source_type IS NOT NULL)",
            ["helm-chart:%", "manifest"],
        )
    else:  # ALL
        return "", []


def extract_helm_chart_name(source_file: str) -> str | None:
    """Extract Helm chart name from source file identifier.

    :param source_file: Source file string (e.g., "helm-chart:nginx")
    :return: Chart name without prefix or None if not a Helm chart
    """
    if source_file and source_file.startswith("helm-chart:"):
        return source_file.replace("helm-chart:", "")
    return None


def get_source_type_from_source_file(source_file: str | None) -> ScanSourceType:
    """Determine source type from source file identifier string.

    :param source_file: Source file identifier or None
    :return: Corresponding ScanSourceType based on file identifier pattern
    """
    if not source_file:
        return ScanSourceType.BENCHMARK
    elif source_file.startswith("helm-chart:"):
        return ScanSourceType.HELM_CHARTS
    else:
        return ScanSourceType.CUSTOM_MANIFESTS


def get_source_type_counts(unified_service) -> dict[ScanSourceType, int]:
    """Get count of scan runs grouped by source type from database.

    :param unified_service: The unified service instance for database access
    :return: Dictionary mapping ScanSourceType to scan count integers
    """
    counts = {
        ScanSourceType.BENCHMARK: 0,
        ScanSourceType.HELM_CHARTS: 0,
        ScanSourceType.CUSTOM_MANIFESTS: 0,
        ScanSourceType.ALL: 0,
    }

    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()

            # Count latest benchmark scans (latest per scanner)
            cursor.execute(
                """
                WITH latest_benchmark AS (
                    SELECT DISTINCT scanner_name,
                           MAX(timestamp) as latest_timestamp
                    FROM scan_runs
                    WHERE source_type = 'manifest' OR source_type IS NULL OR source_type = 'benchmark'
                    GROUP BY scanner_name
                )
                SELECT COUNT(*) as count FROM latest_benchmark
            """
            )
            result = cursor.fetchone()
            if result:
                counts[ScanSourceType.BENCHMARK] = result["count"]

            # Count latest Helm chart scans (latest per scanner per chart)
            cursor.execute(
                """
                WITH latest_helm AS (
                    SELECT DISTINCT scanner_name, source_type,
                           MAX(timestamp) as latest_timestamp
                    FROM scan_runs
                    WHERE source_type LIKE 'helm-chart:%'
                    GROUP BY scanner_name, source_type
                )
                SELECT COUNT(*) as count FROM latest_helm
            """
            )
            result = cursor.fetchone()
            if result:
                counts[ScanSourceType.HELM_CHARTS] = result["count"]

            # Count latest custom manifest scans (latest per scanner per source)
            cursor.execute(
                """
                WITH latest_custom AS (
                    SELECT DISTINCT scanner_name, source_type,
                           MAX(timestamp) as latest_timestamp
                    FROM scan_runs
                    WHERE source_type = 'custom' OR source_type = 'custom_manifest'
                    GROUP BY scanner_name, source_type
                )
                SELECT COUNT(*) as count FROM latest_custom
            """
            )
            result = cursor.fetchone()
            if result:
                counts[ScanSourceType.CUSTOM_MANIFESTS] = result["count"]

            # Count all latest scans
            cursor.execute(
                """
                WITH latest_all AS (
                    SELECT DISTINCT scanner_name, source_type,
                           MAX(timestamp) as latest_timestamp
                    FROM scan_runs
                    GROUP BY scanner_name, source_type
                )
                SELECT COUNT(*) as count FROM latest_all
            """
            )
            result = cursor.fetchone()
            if result:
                counts[ScanSourceType.ALL] = result["count"]

    except Exception as e:
        st.error(f"Error getting scan counts: {e}")

    return counts


def get_available_helm_charts(unified_service) -> list[str]:
    """Get list of unique Helm charts that have been scanned.

    :param unified_service: The unified service instance for database access
    :return: Sorted list of Helm chart names that have scan results
    """
    charts = []

    try:
        with unified_service.db._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT DISTINCT source_type
                FROM scan_runs
                WHERE source_type LIKE 'helm-chart:%'
                ORDER BY source_type
            """
            )

            results = cursor.fetchall()
            for row in results:
                source_type = row["source_type"]
                if source_type and source_type.startswith("helm-chart:"):
                    chart_name = source_type.replace("helm-chart:", "")
                    if chart_name and chart_name not in charts:
                        charts.append(chart_name)

    except Exception as e:
        st.error(f"Error getting helm charts: {e}")

    return sorted(charts)


def render_helm_chart_selector(unified_service, key: str = "helm_chart_selector", allow_all: bool = True) -> str | None:
    """Render Helm chart selector component when Helm charts source is selected.

    :param unified_service: The unified service instance for database access
    :param key: Unique key for the Streamlit component
    :param allow_all: Whether to show "All Charts" option
    :return: Selected chart name or None for all charts selection
    """
    charts = get_available_helm_charts(unified_service)

    if not charts:
        st.info("No helm chart scans found in the database.")
        return None

    options = charts.copy()
    if allow_all:
        options = ["All Charts"] + options

    selected = st.selectbox(
        "**Helm Chart**", options=options, key=key, help="Select a specific helm chart to analyze, or view all charts"
    )

    return None if selected == "All Charts" else selected


def render_source_info_metrics(unified_service):
    """Render informational metrics showing scan counts by source type in columns.

    :param unified_service: The unified service instance for database access
    :return: None
    """
    counts = get_source_type_counts(unified_service)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="Benchmark", value=counts[ScanSourceType.BENCHMARK], help="Scans against KALM benchmark manifests"
        )

    with col2:
        st.metric(
            label="Helm Charts", value=counts[ScanSourceType.HELM_CHARTS], help="Scans against Helm chart deployments"
        )

    with col3:
        st.metric(label="Custom", value=counts[ScanSourceType.CUSTOM_MANIFESTS], help="Scans against custom manifests")

    with col4:
        st.metric(label="Total", value=counts[ScanSourceType.ALL], help="All scan results in database")
