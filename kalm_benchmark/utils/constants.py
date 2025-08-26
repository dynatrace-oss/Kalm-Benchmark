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
