"""SQLite 访问助手：每服务独立库文件，WAL 模式，显式事务。"""
import sqlite3
from contextlib import contextmanager

from . import config


def connect(name: str) -> sqlite3.Connection:
    config.DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(config.DATA_DIR / name, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.isolation_level = None
    conn.execute("pragma journal_mode=wal")
    conn.execute("pragma busy_timeout=5000")
    return conn


@contextmanager
def tx(conn: sqlite3.Connection):
    conn.execute("begin immediate")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
