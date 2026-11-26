"""Small, bounded helpers for the newline-delimited TCP protocol."""

import json
import re

MAX_HEADER_BYTES = 64 * 1024
MAX_FILE_SIZE = 1 << 40  # 1 TiB safety ceiling; normal transfers are unrestricted below it.
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def read_json_header(reader):
    """Read one bounded JSON object terminated by a newline."""
    line = reader.readline(MAX_HEADER_BYTES + 1)
    if not line:
        raise ValueError("empty protocol header")
    if len(line) > MAX_HEADER_BYTES:
        raise ValueError("protocol header is too large")
    if not line.endswith(b"\n"):
        raise ValueError("incomplete protocol header")
    try:
        value = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON protocol header") from exc
    if not isinstance(value, dict):
        raise ValueError("protocol header must be a JSON object")
    return value


def validate_file_header(header):
    """Validate untrusted file metadata before creating files or prompting users."""
    if header.get("type") != "file":
        raise ValueError("invalid message type")

    version = header.get("ver")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("invalid protocol version")

    size = header.get("size")
    if isinstance(size, bool):
        raise ValueError("invalid file size")
    try:
        size = int(size)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("invalid file size") from exc
    if size < 0 or size > MAX_FILE_SIZE:
        raise ValueError("file size is outside the supported range")

    name = header.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 255:
        raise ValueError("invalid file name")

    rel = header.get("rel", name)
    if not isinstance(rel, str) or len(rel) > 4096:
        raise ValueError("invalid relative file path")

    sender = header.get("sender", "")
    if not isinstance(sender, str) or len(sender) > 128:
        raise ValueError("invalid sender name")

    sender_id = header.get("sender_id", "")
    if not isinstance(sender_id, str) or len(sender_id) > 64:
        raise ValueError("invalid sender identifier")

    digest = header.get("sha256", "")
    if not isinstance(digest, str) or (digest and not _SHA256_RE.fullmatch(digest)):
        raise ValueError("invalid SHA-256 digest")

    return size
