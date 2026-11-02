"""LLM 结果缓存（方案 §9.5）。

SQLite 持久化；键为 evidence_pkg 的确定性 hash（code_hash + prompt_hash 合并），
支持增量扫描：code_hash 未变的候选不重跑 LLM。
"""
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union


def evidence_key(evidence_pkg: Dict[str, Any]) -> str:
    """evidence_pkg 的确定性 SHA-256 键。"""
    payload = json.dumps(evidence_pkg, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class VerdictCache:
    """按 evidence_key 存取 LLM 判定结果的 SQLite 缓存。"""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.db_path = str(
            db_path or os.environ.get("ACCESS_SCAN_CACHE", ".access_scan_cache.db")
        )
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS verdicts ("
            "  key TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        self._conn.commit()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT payload FROM verdicts WHERE key = ?", (key,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO verdicts (key, payload, created_at) VALUES (?, ?, ?)",
                (key, json.dumps(payload, ensure_ascii=False),
                 datetime.now(timezone.utc).isoformat()),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# 兼容方案 §9.5 的模块级函数形态（内部即开即用，适合一次性场景）
def get_verdict(evidence_pkg: Dict[str, Any], db_path=None) -> Optional[Dict[str, Any]]:
    c = VerdictCache(db_path)
    try:
        return c.get(evidence_key(evidence_pkg))
    finally:
        c.close()


def store_verdict(evidence_pkg: Dict[str, Any], payload: Dict[str, Any], db_path=None) -> None:
    c = VerdictCache(db_path)
    try:
        c.put(evidence_key(evidence_pkg), payload)
    finally:
        c.close()


class ScanState:
    """增量扫描基线（方案 M3.2）：文件内容 hash → 上次分析产物（候选/守卫/链路/资源）。"""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.db_path = str(
            db_path or os.environ.get("ACCESS_SCAN_STATE", ".access_scan_state.db")
        )
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS files ("
            "  path TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        self._conn.commit()

    def get(self, path: str) -> Optional[Dict[str, Any]]:
        """返回该文件上次的分析产物（内含 content hash）；未记录返回 None。"""
        row = self._conn.execute(
            "SELECT payload FROM files WHERE path = ?", (path,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, path: str, content_hash: str, payload: Dict[str, Any]) -> None:
        data = dict(payload)
        data["hash"] = content_hash
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO files (path, payload, updated_at) VALUES (?, ?, ?)",
                (path, json.dumps(data, ensure_ascii=False),
                 datetime.now(timezone.utc).isoformat()),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()