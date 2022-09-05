import re
from typing import Any


def sanitize_name(name: str, max_len: int = 253) -> str:
    """
    Valid resource names must be valid DNS subdomain names as defined in RFC 1123
    See: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/
    :param name: the string which will be sanitized
    :param max_len: the maximum length of the resulting name
    :return: the sanitized copy of the string
    """
    # the regex pattern used by K8s: r"[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"
    # limit length and avoid leading/trailing whitespaces:
    name = name[:max_len].lower().strip()
    # replace invalid characters with '-', ie. only alphanumeric, '-' and '.' are allowed
    name = re.sub(r"[^a-zA-Z0-9.-]", "-", name)
    return name


def ensure_list(thing: Any | list[Any] | None) -> list[Any] | None:
    """
    Ensure that the provided object is a list, except if it's nothing.
    If it's not a list, then it will be wrapped in alist.
    :param thing: the object which is ensured to be a list
    :return: either a list or None
    """
    if isinstance(thing, list):
        return thing
    elif thing is None:
        return None

    return [thing]
