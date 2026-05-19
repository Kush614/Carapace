"""Tamper-evident, append-only unified audit chain.

One NDJSON line per event, SHA-256 hash-chained: each entry binds the
previous entry's hash, so any retroactive edit, deletion, or reordering
breaks the chain and is detectable by :meth:`AuditChain.verify`.

The chain is *unified*: it interleaves

* **Carapace** action-layer decisions (:class:`DecisionRecord`), and
* **Lobster Trap** conversation-layer decisions (its own JSONL audit lines),

into a single ordered trail — the "audit a regulator could read": for any
blocked action you can read, in order, both *why the conversation was
flagged* and *why the action was gated*.

I/O lives here on purpose; the decision engine stays pure.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional

from .types import DecisionRecord

GENESIS = "sha256:" + "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj: Mapping[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash_entry(entry: Mapping[str, Any]) -> str:
    """Hash of an entry *excluding* its own ``entry_hash`` field."""
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    return "sha256:" + hashlib.sha256(_canonical(payload).encode()).hexdigest()


class AuditChain:
    """Append-only hash-chained audit log backed by an NDJSON file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._last_hash = self._recover()

    # -- recovery ------------------------------------------------------- #

    def _recover(self) -> tuple[int, str]:
        """Resume an existing chain (next seq, last hash)."""
        if not self.path.exists():
            return 0, GENESIS
        seq, last = 0, GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                seq = int(entry["seq"]) + 1
                last = entry["entry_hash"]
        return seq, last

    # -- append --------------------------------------------------------- #

    def _commit(self, kind: str, payload: Mapping[str, Any],
                signed_hash: str, audit_id: str) -> dict[str, Any]:
        with self._lock:
            entry: dict[str, Any] = {
                "seq": self._seq,
                "audit_id": audit_id,
                "ts": _utc_now(),
                "kind": kind,  # "carapace" | "lobstertrap"
                "signed_hash": signed_hash,
                "prev_hash": self._last_hash,
                "payload": payload,
            }
            entry["entry_hash"] = _hash_entry(entry)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
            self._seq += 1
            self._last_hash = entry["entry_hash"]
            return entry

    def append(
        self, record: DecisionRecord, *, audit_id: Optional[str] = None
    ) -> dict[str, Any]:
        """Append a Carapace action-layer decision."""
        aid = audit_id or record.audit_id or self._mint_id("cp")
        return self._commit("carapace", record.to_dict(), record.signed_hash, aid)

    def append_lobstertrap(self, lt_audit_line: Mapping[str, Any]) -> dict[str, Any]:
        """Append a Lobster Trap conversation-layer audit line (its JSONL).

        Lets the unified chain show *why the conversation was flagged*
        immediately before *why the action was gated*.
        """
        signed = "sha256:" + hashlib.sha256(
            _canonical(lt_audit_line).encode()
        ).hexdigest()
        rid = str(lt_audit_line.get("request_id") or lt_audit_line.get("RequestID") or "")
        return self._commit(
            "lobstertrap", dict(lt_audit_line), signed,
            self._mint_id("lt", rid),
        )

    def _mint_id(self, prefix: str, suffix: str = "") -> str:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        base = f"{prefix}-{day}-{self._seq:05d}"
        return f"{base}-{suffix}" if suffix else base

    # -- read / verify -------------------------------------------------- #

    def entries(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        return list(self.entries())[-n:]

    def verify(self) -> tuple[bool, Optional[int]]:
        """Recompute the whole chain. Returns ``(ok, first_broken_seq)``.

        Detects content tampering, reordering, and deleted/inserted lines.
        """
        prev = GENESIS
        for idx, entry in enumerate(self.entries()):
            if entry.get("seq") != idx:
                return False, idx
            if entry.get("prev_hash") != prev:
                return False, idx
            if _hash_entry(entry) != entry.get("entry_hash"):
                return False, idx
            prev = entry["entry_hash"]
        return True, None
