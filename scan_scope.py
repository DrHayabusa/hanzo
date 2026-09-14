"""Conservative single-target validation for the automated scan workflow."""
import re
from urllib.parse import urlsplit


def validate_scan_target(value):
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("A single target URL, hostname, or IP is required")
    if value.startswith("-") or not re.fullmatch(r"[A-Za-z0-9._:/%?=~\[\]-]+", value):
        raise ValueError("Use a single target without shell operators, whitespace, credentials, or query separators")
    parsed = urlsplit(value if "://" in value else "//" + value)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP(S) target URLs are supported")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("A valid hostname or IP without credentials is required")
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("Invalid target port") from error
    return value
