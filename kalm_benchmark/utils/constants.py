from enum import Enum, auto
from typing import Generator

from strenum import SnakeCaseStrEnum, StrEnum


class UpdateType(Enum):
    Info = auto()
    Warning = auto()
    Error = auto()
    Progress = auto()


RunUpdateGenerator = Generator[tuple[UpdateType, str], None, list | dict | None]


class Color(StrEnum):
    Error = "#f7a59c"
    Warn = "#f3a04e"
    Success = "#7dcea0"
    Info = "#6a98ca"
    Background = "#DDDDDD"
    Gray = "#999999"


class SessionKeys(SnakeCaseStrEnum):
    DataDir = auto()
    LatestScanResult = auto()


class QueryParam(SnakeCaseStrEnum):
    SelectedScanner = "scanner"
    Page = auto()


class Page(StrEnum):
    # Benchmark Analysis Mode
    BenchmarkOverview = "benchmark_overview"
    BenchmarkComparison = "benchmark_comparison"
    BenchmarkScanner = "benchmark_scanner"

    # Helm Chart Security Analysis Mode
    HelmDashboard = "helm_dashboard"
    HelmScannerAnalysis = "helm_scanner_analysis"
    HelmSecurityTrends = "helm_security_trends"

    # Legacy pages (for backward compatibility)
    Overview = auto()
    Scanner = auto()
    Comparison = auto()
    CCSS = auto()


LAST_SCAN_OPTION = "<last scan>"
SELECTED_RESULT_FILE = "selected_result_file"

# Scanner Capability Labels
CI_MODE_LABEL = "CI Mode"
CUSTOM_CHECKS_LABEL = "Custom Checks"
MANIFEST_SCANNING_LABEL = "Manifest Scanning"
CLUSTER_SCANNING_LABEL = "Cluster Scanning"
OUTPUT_FORMATS_LABEL = "Output Formats"
SEVERITY_SUPPORT_LABEL = "Severity Support"
OFFLINE_CAPABILITY_LABEL = "Offline Capability"

# Standard Severity Scores
STANDARD_SEVERITY_SCORES = "Standard (9.0, 7.0, 4.0, 2.0)"

# Chart/Altair Constants
OUTPUT_FORMATS_ALTAIR = "Output Formats:Q"

# Evaluation Constants
MAX_EXPECTED_CHECKS = 50
MAX_EXPECTED_RESOURCES = 10
DEFAULT_DATABASE_RETENTION_RUNS = 50
DEFAULT_HELM_TRENDS_DAYS = 30
DEFAULT_PERFORMANCE_HISTORY_LIMIT = 20
DEFAULT_TOP_SCANNERS_LIMIT = 5

# Severity Weights for Risk Calculation
SEVERITY_WEIGHTS = {
    "HIGH": 9.0,
    "MEDIUM": 4.0,
    "LOW": 2.0,
    "INFO": 1.0,
}

# Risk Score Constants
RISK_SCORE_MULTIPLIER = 10.0
MAX_RISK_SCORE = 100.0

# Timestamp Matching Tolerance (seconds)
TIMESTAMP_MATCH_TOLERANCE = 10

# UI Layout Constants
TOOLTIP_DELAY_MS = 50
MAX_ICON_SIZE_PX = 70
ROW_HEIGHT_PX = 30
CHART_HEIGHT_PX = 300
SCANNER_ICONS_PER_ROW = 5
DATE_RANGES_HISTORICAL = {
    "Last 7 days": 7,
    "Last 30 days": 30,
    "Last 90 days": 90,
    "Last 6 months": 180,
}

# Percentage and Score Thresholds
EXCELLENT_SCORE_THRESHOLD = 0.8
GOOD_SCORE_THRESHOLD = 0.6
STANDARD_PERCENTAGE_MULTIPLIER = 100

# Chart Dimensions
CHART_WIDTH_PX = 600
CHART_HEIGHT_SMALL_PX = 200
SCANNER_OVERVIEW_GRID_HEIGHT_PX = 520

# File Size Limits
LOG_ROTATION_SIZE_MB = 100
LOG_RETENTION_DAYS = 30

# Color Constants
HOVER_COLOR_RGBA = "rgba(255, 75, 75, .5)"
EXCELLENT_COLOR = "#28a745"
GOOD_COLOR = "#ffc107"
NEEDS_IMPROVEMENT_COLOR = "#dc3545"

# Path Normalization Constants
MAX_FILENAME_LENGTH = 255
SAFE_DIRECTORY_PATTERNS = ["data", "manifests", "results", "output"]
YAML_DOCUMENT_SEPARATOR = "---"
INDENT_CHARS = " -"

# Parsing Constants
TIMESTAMP_MATCH_TOLERANCE_SECONDS = 10
SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400
SECONDS_PER_MONTH = 2592000
MONTHS_PER_YEAR = 12
DEFAULT_FORMAT_STRING = "%b %d, %H:%M"
MIN_DATE_STRING_LENGTH = 10

# Config Validation Constants
MIN_PORT_NUMBER = 1
MAX_PORT_NUMBER = 65535
VALID_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Helm Operations Constants
HELM_VERSION_COMMAND_TIMEOUT = 10
HELM_DOWNLOAD_TIMEOUT = 60
HELM_RENDER_TIMEOUT = 60
HELM_REPO_TIMEOUT = 30
DEFAULT_HELM_RELEASE_NAME = "kalm-test-release"
DEFAULT_HELM_NAMESPACE = "default"
ARTIFACT_HUB_DOMAIN = "artifacthub.io"
ARTIFACT_HUB_EXPECTED_PATH_PARTS = 4
ARTIFACT_HUB_API_TIMEOUT = 10
DEFAULT_POPULAR_CHARTS_COUNT = 10

# Risk Scoring Constants (Helm)
HELM_HIGH_SEVERITY_WEIGHT = 10
HELM_MEDIUM_SEVERITY_WEIGHT = 3
HELM_RISK_SCORE_BASE = 100.0
HELM_MIN_RISK_SCORE = 0.0
HELM_MAX_RISK_SCORE = 1.0
HELM_FALLBACK_SCORE = 0.5

# Severity Level Constants
HIGH_SEVERITY_LEVELS = ["HIGH", "CRITICAL", "DANGER"]
MEDIUM_SEVERITY_LEVELS = ["MEDIUM", "WARNING"]
