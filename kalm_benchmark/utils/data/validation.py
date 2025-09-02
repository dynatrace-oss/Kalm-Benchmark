import re
from pathlib import Path
from typing import Any, List, Optional, Union


def sanitize_kubernetes_name(name: str, max_len: int = 253) -> str:
    """Sanitize a string to be a valid Kubernetes resource name.

    Valid resource names must be valid DNS subdomain names as defined in RFC 1123.
    See: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/

    :param name: The string to be sanitized
    :param max_len: Maximum length of the resulting name (default: 253)
    :return: Sanitized string that follows Kubernetes naming conventions
    """
    if not name:
        return name

    # Limit length and avoid leading/trailing whitespaces
    name = name[:max_len].lower().strip()

    # Replace invalid characters with '-'
    # Only alphanumeric, '-' and '.' are allowed
    name = re.sub(r"[^a-zA-Z0-9.\-]", "-", name)

    # Ensure it doesn't start or end with special characters
    name = re.sub(r"^[-.]", "", name)
    name = re.sub(r"[-.]$", "", name)

    # Ensure it's not empty after sanitization
    if not name or name == "." or name == "-":
        return "default"

    return name


def sanitize_filename(filename: str, max_len: int = 255) -> str:
    """Sanitize a string to be a valid filename.

    :param filename: The string to be sanitized
    :param max_len: Maximum length of the resulting filename
    :return: Sanitized filename safe for most filesystems
    """
    if not filename:
        return filename

    # Remove or replace invalid characters for filenames
    # Invalid chars: < > : " | ? * / \
    filename = re.sub(r'[<>:"|?*\\/]', "_", filename)

    # Limit length
    filename = filename[:max_len].strip()

    # Remove leading/trailing dots and spaces (problematic on Windows)
    filename = filename.strip(". ")

    # Ensure it's not empty
    if not filename:
        return "unnamed_file"

    return filename


def ensure_list(thing: Union[Any, List[Any], None]) -> Optional[List[Any]]:
    """Ensure that the provided object is a list, except if it's None.
    If it's not a list, it will be wrapped in a list.

    :param thing: The object to ensure is a list
    :return: Either a list or None
    """
    if isinstance(thing, list):
        return thing
    elif thing is None:
        return None
    else:
        return [thing]


def validate_path(path: Union[str, Path], must_exist: bool = False) -> bool:
    """Validate that a path is properly formed and optionally exists.

    :param path: Path to validate
    :param must_exist: Whether the path must exist on the filesystem
    :return: True if path is valid, False otherwise
    """
    if not path:
        return False

    try:
        path_obj = Path(path)

        # Check if path is properly formed
        str(path_obj)

        # Check existence if required
        if must_exist and not path_obj.exists():
            return False

        return True

    except Exception:
        return False


def validate_scanner_name(scanner_name: str) -> bool:
    """Validate that a scanner name follows expected conventions.

    :param scanner_name: Scanner name to validate
    :return: True if valid, False otherwise
    """
    if not scanner_name or not isinstance(scanner_name, str):
        return False

    scanner_name = scanner_name.strip()

    # Basic validation: alphanumeric, hyphens, underscores allowed
    # Length between 2 and 50 characters
    if not re.match(r"^[a-zA-Z0-9_-]{2,50}$", scanner_name):
        return False

    return True


def validate_severity(severity: str) -> bool:
    """Validate that a severity level is recognized.

    :param severity: Severity level to validate
    :return: True if valid severity level, False otherwise
    """
    if not severity or not isinstance(severity, str):
        return False

    valid_severities = {
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "informational",
        "warn",
        "warning",
        "error",
        "fail",
        "pass",
        "unknown",
    }

    return severity.lower().strip() in valid_severities


def sanitize_text_for_display(text: str, max_length: int = 1000) -> str:
    """Sanitize text for safe display in UI components.

    :param text: Text to sanitize
    :param max_length: Maximum allowed length
    :return: Sanitized text safe for display
    """
    if not text:
        return ""

    original_length = len(str(text))

    # Remove potentially dangerous characters for HTML context
    # Remove < > & " and everything between < and >
    text = re.sub(r"<[^>]*>", "", str(text))  # Remove HTML tags
    text = re.sub(r'[&"]', "", text)  # Remove remaining dangerous chars

    # Limit length based on original text length
    if original_length > max_length:
        text = text[: max_length - 3] + "..."

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text


def is_valid_uuid(uuid_string: str) -> bool:
    """Check if a string is a valid UUID.

    :param uuid_string: String to validate
    :return: True if valid UUID, False otherwise
    """
    if not uuid_string or not isinstance(uuid_string, str):
        return False

    uuid_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE
    )

    return bool(uuid_pattern.match(uuid_string.strip()))


def validate_port_number(port: Union[int, str]) -> bool:
    """Validate that a port number is valid (1-65535).

    :param port: Port number to validate
    :return: True if valid port number, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False
