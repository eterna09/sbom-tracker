from packaging.utils import canonicalize_name


def normalize_package_name(ecosystem: str, name: str) -> str:
    """Return the package name in the form used for matching (PEP 503 for PyPI)."""
    if ecosystem == "PyPI":
        return canonicalize_name(name)
    return name
