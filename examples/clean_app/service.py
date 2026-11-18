"""A sample with patterns that look risky but are safe."""
import abc
import hashlib
import logging
import os
import re
import secrets
import sqlite3

LOG = logging.getLogger(__name__)
HELP_TEXT = "Never call eval(input) or use shell=True here. TODO is only a word in this string."
PASSWORD_FIELD = "password"


class Store(abc.ABC):
    @abc.abstractmethod
    def load(self, key):
        raise NotImplementedError


def token():
    return os.environ["APP_TOKEN"] or secrets.token_hex(32)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_user(conn: sqlite3.Connection, user_id: int):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def first_word(text: str):
    match = re.compile(r"\w+").search(text)
    return match.group(0) if match else None


def parse_port(value: str, default: int) -> int:
    try:
        return int(value)
    except ValueError:
        LOG.warning("invalid port %r", value)
        return default
