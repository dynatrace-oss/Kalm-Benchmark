import base64
from pathlib import Path
from typing import Optional

# Icon mapping for different scanners
SCANNER_ICONS = {
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

# Fallback icon HTML
FALLBACK_ICON_HTML = (
    '<div style="width: 64px; height: 64px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); '
    "border-radius: 16px; display: flex; align-items: center; justify-content: center; "
    'box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);">'
    '<span style="font-size: 2rem; color: white;">🔍</span></div>'
)


def get_scanner_icon_path(scanner_name: str) -> Optional[str]:
    """Get the filesystem path for a scanner's icon file.

    :param scanner_name: Name of the scanner to get icon for
    :return: Absolute path to icon file or None if not found
    """
    icon_filename = SCANNER_ICONS.get(scanner_name)
    if not icon_filename:
        return None

    # Find project root by looking for pyproject.toml
    current_file = Path(__file__)
    project_root = current_file
    while project_root.parent != project_root:
        if (project_root / "pyproject.toml").exists():
            break
        project_root = project_root.parent

    icon_path = project_root / "docs" / "images" / "icons" / icon_filename
    return str(icon_path) if icon_path.exists() else None


def create_base64_icon(icon_path: str) -> Optional[str]:
    """Create base64-encoded HTML img tag from icon file path.

    :param icon_path: Filesystem path to the icon file
    :return: HTML img tag with base64 data URL or None if processing fails
    """
    try:
        icon_file = Path(icon_path)
        if not icon_file.exists():
            return None

        with open(icon_file, "rb") as f:
            icon_data = base64.b64encode(f.read()).decode()

        file_ext = icon_file.suffix.lower()
        mime_type = "image/svg+xml" if file_ext == ".svg" else f"image/{file_ext[1:]}"

        return (
            f'<img src="data:{mime_type};base64,{icon_data}" '
            f'style="width: 64px; height: 64px; object-fit: contain; '
            f'filter: drop-shadow(0 4px 8px rgba(0,0,0,0.15));" />'
        )
    except Exception:
        return None


def get_scanner_icon_html(scanner_name: str) -> str:
    """Get HTML representation of scanner icon with automatic fallback handling.

    :param scanner_name: Name of the scanner to get icon HTML for
    :return: HTML string containing either scanner-specific icon or fallback icon
    """
    icon_path = get_scanner_icon_path(scanner_name)

    if icon_path:
        icon_html = create_base64_icon(icon_path)
        if icon_html:
            return icon_html

    return FALLBACK_ICON_HTML
