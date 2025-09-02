import re
from enum import Enum


class ScannerType(Enum):
    """Enumeration of supported scanner types."""

    CHECKOV = "checkov"
    KICS = "kics"
    KUBESEC = "kubesec"
    SNYK = "snyk"
    GENERAL = "general"


class PathNormalizationService:
    """Centralized service for path normalization across all scanners."""

    # Compiled regex patterns for better performance
    QUOTED_PATH_PATTERN = re.compile(r"'([^']*)'")
    ARRAY_INDEX_PATTERN = re.compile(r"\[[\w-]*\]")
    SPEC_TEMPLATE_PATTERN = re.compile(r".?spec.template")

    # KICS-specific patterns
    KICS_QUOTED_PATH_PATTERN = re.compile(r".*'(.*?)'.*")
    KICS_META_NAME_PATTERN = re.compile(r"metadata.name=({{.*?}}|[\w-]*)")
    KICS_ARRAY_NAME_PATTERN = re.compile(r"(\w*s).(name|kind)=({{.*?}}|[\w-]*)")
    KICS_ARRAY_INDEX_PATTERN = re.compile(r"\[[^\]]*\]")
    KICS_ASSIGNED_VALUE_PATTERN = re.compile(r"=[\w-]*")

    @classmethod
    def normalize_path(
        cls,
        path: str,
        scanner_type: ScannerType = ScannerType.GENERAL,
        related_objects: list[dict[str, any]] | None = None,
        is_relative: bool = True,
        kind: str | None = None,
    ) -> str:
        """
        Normalize a path based on scanner type and context.

        Args:
            path: The raw path string to normalize
            scanner_type: The type of scanner that generated this path
            related_objects: Related objects for path resolution (Kubescape)
            is_relative: Whether the path should be treated as relative
            kind: Kubernetes resource kind for context

        Returns:
            Normalized path string

        Examples:
            >>> service = PathNormalizationService()
            >>> service.normalize_path("spec/containers/[0]/image", ScannerType.CHECKOV)
            ".spec.containers[].image"
        """
        if not path or not isinstance(path, str):
            return path or ""

        # Handle list input for Checkov
        if isinstance(path, list):
            path = "/".join(path)

        # Apply scanner-specific normalization
        if scanner_type == ScannerType.CHECKOV:
            return cls._normalize_checkov_path(path)
        elif scanner_type == ScannerType.KICS:
            return cls._normalize_kics_path(path)
        elif scanner_type == ScannerType.KUBESEC:
            return cls._normalize_kubesec_path(path)
        elif scanner_type == ScannerType.SNYK:
            return cls._normalize_snyk_path(path, kind)
        else:
            return cls._normalize_general_path(path, related_objects, is_relative)

    @classmethod
    def _normalize_checkov_path(cls, path: str) -> str:
        """Normalize path for Checkov scanner."""
        # Convert to dot notation and handle arrays
        path = path.replace("/", ".")
        path = cls._apply_general_normalization(path)
        path = path.replace(".[]", "[]")  # Checkov has '/' before indexing brackets
        return path

    @classmethod
    def _normalize_kics_path(cls, path: str) -> str:
        """Normalize path for KICS scanner."""
        # Handle paths with dots (actual paths vs values)
        if "." in path:
            tokens = [t for t in path.split(" ") if "." in t and not cls._is_fs_path_value(t)]
            if len(tokens) == 0:
                return ""
            path = tokens[0]  # Take first token as path
        else:
            # Handle attribute descriptions
            if path.startswith("Attribute"):
                return cls.KICS_QUOTED_PATH_PATTERN.sub(r".\1", path)
            return ""

        # Extract quoted paths
        path = cls.KICS_QUOTED_PATH_PATTERN.sub(r"\1", path)

        # Remove spec.template prefix
        path = cls.SPEC_TEMPLATE_PATTERN.sub("", path)

        # Remove metadata name prefix
        path = cls.KICS_META_NAME_PATTERN.sub("", path)

        # Handle array indices
        path = cls.KICS_ARRAY_INDEX_PATTERN.sub("[]", path)

        # Handle array names with values
        path = cls.KICS_ARRAY_NAME_PATTERN.sub(r"\1[]", path)

        # Remove assigned values
        path = cls.KICS_ASSIGNED_VALUE_PATTERN.sub("", path)

        # Ensure relative paths start with dot
        if path and not path[0].isupper() and path[0] != ".":
            path = "." + path

        return path

    @classmethod
    def _normalize_kubesec_path(cls, path: str) -> str:
        """Normalize path for Kubesec scanner."""
        # Clean up spaces and quotes
        path = path.replace(" .", ".")
        path = path.replace('"', "")

        # Add spec prefix for containers
        if path.startswith("containers"):
            path = ".spec." + path

        return path

    @classmethod
    def _normalize_snyk_path(cls, path: str, kind: str | None) -> str:
        """Normalize path for Snyk scanner."""
        # Handle input prefix
        if path.startswith("input."):
            path = path[6:]  # Remove 'input.' prefix
            is_relative = True
        else:
            is_relative = not (kind and path.startswith(kind.lower()))

        return cls._normalize_general_path(path, None, is_relative)

    @classmethod
    def _normalize_general_path(
        cls, path: str, related_objects: list[dict[str, any]] | None = None, is_relative: bool = True
    ) -> str:
        """Apply general path normalization rules."""
        # Handle related objects (Kubescape specific)
        if related_objects is not None and path.startswith("relatedObjects"):
            path = cls._resolve_related_objects(path, related_objects)
            is_relative = False

        # Normalize array indices
        path = cls.ARRAY_INDEX_PATTERN.sub("[]", path)

        # Remove spec.template for pod-related checks
        if "spec.template" in path:
            path = path.replace("spec.template", "")
        elif is_relative and not path.startswith("."):
            path = "." + path

        # Clean up double dots
        if path.startswith(".."):
            path = path[1:]

        # Fix container vs containers
        if "container[" in path:
            path = path.replace("container", "containers")

        return path

    @classmethod
    def _apply_general_normalization(cls, path: str) -> str:
        """Apply common normalization rules."""
        # Normalize array indices
        path = cls.ARRAY_INDEX_PATTERN.sub("[]", path)

        # Handle spec.template removal
        if "spec.template" in path:
            path = path.replace("spec.template", "")

        # Ensure relative paths start with dot
        if not path.startswith(".") and not path.startswith("/"):
            path = "." + path

        # Clean up double dots
        if path.startswith(".."):
            path = path[1:]

        # Fix container vs containers
        if "container[" in path:
            path = path.replace("container", "containers")

        return path

    @classmethod
    def _resolve_related_objects(cls, path: str, related_objects: list[dict[str, any]]) -> str:
        """Resolve related object references in path."""
        match = re.search(r"\[(\d+)\]", path)
        if match is None:
            return path

        try:
            idx = int(match.group(1))
            if idx < len(related_objects) and "kind" in related_objects[idx]:
                kind = related_objects[idx]["kind"]
                path = path.replace(f"relatedObjects[{idx}]", kind)
        except (ValueError, IndexError, KeyError):
            pass

        return path

    @classmethod
    def _is_fs_path_value(cls, token: str) -> bool:
        """Check if token represents a filesystem path value."""
        # Simple heuristic: contains forward slash or backslash
        return "/" in token or "\\" in token


# Convenience functions for backward compatibility
def normalize_checkov_path(path: str) -> str:
    """Normalize path for Checkov scanner."""
    if isinstance(path, list):
        path = "/".join(path)
    service = PathNormalizationService()
    return service.normalize_path(path, ScannerType.CHECKOV)


def normalize_kics_path(path: str) -> str:
    """Normalize path for KICS scanner."""
    service = PathNormalizationService()
    return service.normalize_path(path, ScannerType.KICS)


def normalize_kubesec_path(path: str) -> str:
    """Normalize path for Kubesec scanner."""
    service = PathNormalizationService()
    return service.normalize_path(path, ScannerType.KUBESEC)


def normalize_snyk_path(path: str, kind: str | None = None) -> str:
    """Normalize path for Snyk scanner."""
    service = PathNormalizationService()
    return service.normalize_path(path, ScannerType.SNYK, kind=kind)


def normalize_general_path(
    path: str, related_objects: list[dict[str, any]] | None = None, is_relative: bool = True
) -> str:
    """General path normalization."""
    service = PathNormalizationService()
    return service.normalize_path(path, ScannerType.GENERAL, related_objects, is_relative)
