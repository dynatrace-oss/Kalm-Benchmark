from enum import auto

from strenum import SnakeCaseStrEnum, StrEnum


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


LAST_SCAN_OPTION = "<last scan>"
SELECTED_RESULT_FILE = "selected_result_file"
