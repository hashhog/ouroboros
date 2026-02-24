"""
Cookie-based RPC authentication compatible with Bitcoin Core.

At startup the node writes ``{data_dir}/.cookie`` containing
``__cookie__:<random_hex>``.  RPC clients read this file to authenticate.
The cookie is deleted on clean shutdown and regenerated on every restart.
"""

import logging
import os
import secrets
from pathlib import Path
from typing import Tuple

logger = logging.getLogger(__name__)

COOKIE_FILENAME = ".cookie"
COOKIE_USER = "__cookie__"


def generate_cookie(data_dir: str) -> Tuple[str, str]:
    """
    Create a fresh ``.cookie`` file in *data_dir*.

    Returns ``(username, password)``.
    """
    password = secrets.token_hex(32)
    cookie_path = Path(data_dir) / COOKIE_FILENAME
    cookie_path.parent.mkdir(parents=True, exist_ok=True)
    cookie_path.write_text(f"{COOKIE_USER}:{password}")
    try:
        cookie_path.chmod(0o600)
    except OSError:
        pass  # Windows doesn't support Unix permissions
    logger.info(f"RPC cookie written to {cookie_path}")
    return COOKIE_USER, password


def read_cookie(data_dir: str) -> Tuple[str, str]:
    """
    Read credentials from an existing ``.cookie`` file.

    Raises ``FileNotFoundError`` if the cookie file does not exist.
    """
    cookie_path = Path(data_dir) / COOKIE_FILENAME
    if not cookie_path.exists():
        raise FileNotFoundError(f"Cookie file not found: {cookie_path}")
    content = cookie_path.read_text().strip()
    if ":" not in content:
        raise ValueError(f"Malformed cookie file: {cookie_path}")
    username, password = content.split(":", 1)
    return username, password


def delete_cookie(data_dir: str) -> None:
    """Remove the cookie file (called on clean shutdown)."""
    cookie_path = Path(data_dir) / COOKIE_FILENAME
    try:
        cookie_path.unlink(missing_ok=True)
    except OSError:
        pass
