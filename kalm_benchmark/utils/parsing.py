from datetime import datetime, timezone

from loguru import logger

from .constants import (
    DEFAULT_FORMAT_STRING,
    MIN_DATE_STRING_LENGTH,
    MONTHS_PER_YEAR,
    SECONDS_PER_DAY,
    SECONDS_PER_HOUR,
    SECONDS_PER_MINUTE,
    SECONDS_PER_MONTH,
)


def parse_timestamp(timestamp: str) -> datetime | None:
    """Parse timestamp string into datetime object with unified handling.

    This function handles various timestamp formats commonly used across the application:
    - ISO format with timezone: "2024-01-01T12:00:00Z" or "2024-01-01T12:00:00+00:00"
    - Standard database format: "2024-01-01 12:00:00"
    - Various other common formats

    :param timestamp: Timestamp string to parse
    :return: Parsed datetime object, or None if parsing fails
    """
    if not timestamp or not isinstance(timestamp, str):
        return None

    timestamp = timestamp.strip()

    formats_to_try = [
        # ISO formats
        ("%Y-%m-%dT%H:%M:%SZ", True),
        ("%Y-%m-%dT%H:%M:%S%z", False),
        ("%Y-%m-%dT%H:%M:%S", False),
        ("%Y-%m-%d %H:%M:%S", False),
        ("%Y-%m-%d %H:%M:%S.%f", False),
        ("%Y-%m-%d", False),
        ("%m/%d/%Y %H:%M:%S", False),
        ("%d/%m/%Y %H:%M:%S", False),
    ]

    for fmt, is_utc in formats_to_try:
        try:
            if is_utc:
                # Handle Z timezone manually since strptime doesn't handle it well
                clean_timestamp = timestamp.replace("Z", "")
                dt = datetime.strptime(clean_timestamp, fmt.replace("Z", ""))
                return dt.replace(tzinfo=timezone.utc)
            else:
                return datetime.strptime(timestamp, fmt)
        except ValueError:
            continue

    try:
        if "T" in timestamp:
            # Try fromisoformat as last resort
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        pass

    return None


def format_timestamp(dt: datetime, format_string: str = DEFAULT_FORMAT_STRING) -> str:
    """Format datetime object for display.

    :param dt: Datetime object to format
    :param format_string: Output format string (default: "Jan 01, 12:00")
    return: Formatted timestamp string
    """
    if not dt:
        return "Unknown"

    try:
        return dt.strftime(format_string)
    except (AttributeError, ValueError) as e:
        logger.warning(f"Failed to format timestamp {dt}: {e}")
        return "Invalid Date"


def format_scan_timestamp(timestamp: str, format_string: str = DEFAULT_FORMAT_STRING) -> str:
    """Format timestamp string for display with unified parsing.

    :param timestamp: Timestamp string to format
    :param format_string: Output format string
    :return: Formatted timestamp string or fallback if parsing fails
    """
    if not timestamp:
        return "Unknown"

    dt = parse_timestamp(timestamp)
    if dt:
        return format_timestamp(dt, format_string)

    # Fallback: try to extract date portion if possible
    if len(timestamp) >= MIN_DATE_STRING_LENGTH and timestamp[4] in ["-", "/"]:
        return timestamp[:MIN_DATE_STRING_LENGTH]

    return "Unknown"


def calculate_scan_age(timestamp: str) -> str:
    """Calculate and format scan age in human-readable format.

    :param timestamp: Timestamp string to calculate age for
    :return: Human-readable age string (e.g., "2h ago", "3d ago", "Just now")
    """
    if not timestamp:
        return "Unknown"

    dt = parse_timestamp(timestamp)
    if not dt:
        return "Unknown"

    try:
        now = datetime.now()

        # Convert to same timezone for comparison
        if dt.tzinfo and not now.tzinfo:
            now = now.replace(tzinfo=timezone.utc)
        elif not dt.tzinfo and now.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)

        diff = now - dt

        total_seconds = int(diff.total_seconds())

        if total_seconds < SECONDS_PER_MINUTE:
            return "Just now"
        elif total_seconds < SECONDS_PER_HOUR:
            minutes = total_seconds // SECONDS_PER_MINUTE
            return f"{minutes}m ago"
        elif total_seconds < SECONDS_PER_DAY:
            hours = total_seconds // SECONDS_PER_HOUR
            return f"{hours}h ago"
        elif total_seconds < SECONDS_PER_MONTH:
            days = total_seconds // SECONDS_PER_DAY
            return f"{days}d ago"
        else:
            months = total_seconds // SECONDS_PER_MONTH
            if months < MONTHS_PER_YEAR:
                return f"{months}mo ago"
            else:
                years = months // MONTHS_PER_YEAR
                return f"{years}y ago"

    except (AttributeError, ValueError, TypeError) as e:
        logger.debug(f"Failed to calculate scan age for timestamp {timestamp}: {e}")
        return "Unknown"


def is_recent(timestamp: str, hours: int = 24) -> bool:
    """Check if a timestamp is within the specified number of hours from now.

    :param timestamp: Timestamp string to check
    :param hours: Number of hours to consider as "recent"
    :return: True if timestamp is within the specified hours, False otherwise
    """
    dt = parse_timestamp(timestamp)
    if not dt:
        return False

    try:
        now = datetime.now()

        # Convert to same timezone for comparison
        if dt.tzinfo and not now.tzinfo:
            now = now.replace(tzinfo=timezone.utc)
        elif not dt.tzinfo and now.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)

        diff = now - dt
        return diff.total_seconds() <= hours * SECONDS_PER_HOUR

    except (AttributeError, ValueError, TypeError) as e:
        logger.debug(f"Failed to check if timestamp {timestamp} is recent: {e}")
        return False
