"""Per-caller, bounded A2A task storage.

The A2A SDK files tasks under an "owner" string derived from the request. Its default is the
authenticated user name, which this app never sets, so every caller shared one owner and
could list or fetch everyone else's tasks (and their results). Here the owner is a hash of
the caller's own PacketFabric credentials, so a task is only visible to whoever holds the
same API key (and On-Behalf customer). Callers without a key have no owner and never get a
task stored.

The store is also bounded: tasks expire after a TTL, and both the total count and the
per-caller count are capped (oldest evicted first).
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict

from a2a.server.context import ServerCallContext
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import Task

from .client import credentials_from_headers

ANONYMOUS = ""


def caller_owner(context: ServerCallContext | None) -> str:
    """Stable, non-reversible owner id for the caller's credentials ('' if none)."""
    headers = ((context.state or {}).get("headers") if context is not None else None) or {}
    creds = credentials_from_headers(headers)
    if creds is None or not creds.token:
        return ANONYMOUS
    raw = f"{creds.token}\x00{creds.on_behalf or ''}".encode()
    return "pf:" + hashlib.sha256(raw).hexdigest()


class ScopedTaskStore(InMemoryTaskStore):
    def __init__(
        self,
        max_tasks: int | None = None,
        max_tasks_per_owner: int | None = None,
        ttl_seconds: float | None = None,
    ) -> None:
        super().__init__(owner_resolver=caller_owner)
        self.max_tasks = max_tasks or int(os.environ.get("PF_A2A_MAX_TASKS", "10000"))
        self.max_tasks_per_owner = max_tasks_per_owner or int(os.environ.get("PF_A2A_MAX_TASKS_PER_CALLER", "200"))
        self.ttl_seconds = ttl_seconds or float(os.environ.get("PF_A2A_TASK_TTL_SECONDS", "3600"))
        self._order: OrderedDict[tuple[str, str], float] = OrderedDict()  # (owner, task_id) -> saved_at
        self._lock = threading.Lock()

    # The SDK's in-memory impl keeps {owner: {task_id: Task}}; we prune it directly.
    def _drop(self, owner: str, task_id: str) -> None:
        owner_tasks = self._impl.tasks.get(owner)
        if owner_tasks is not None:
            owner_tasks.pop(task_id, None)
            if not owner_tasks:
                self._impl.tasks.pop(owner, None)

    def _prune(self, now: float) -> None:
        cutoff = now - self.ttl_seconds
        while self._order:
            (owner, task_id), saved_at = next(iter(self._order.items()))
            if saved_at >= cutoff and len(self._order) <= self.max_tasks:
                break
            self._order.popitem(last=False)
            self._drop(owner, task_id)

    async def save(self, task: Task, context: ServerCallContext) -> None:
        owner = caller_owner(context)
        if owner == ANONYMOUS:
            return  # never persist anything for callers without credentials
        await super().save(task, context)
        now = time.monotonic()
        with self._lock, self._impl.lock:
            key = (owner, task.id)
            self._order.pop(key, None)
            self._order[key] = now
            mine = [k for k in self._order if k[0] == owner]  # oldest first
            for k in mine[: max(0, len(mine) - self.max_tasks_per_owner)]:
                self._order.pop(k, None)
                self._drop(*k)
            self._prune(now)

    async def get(self, task_id: str, context: ServerCallContext) -> Task | None:
        with self._lock, self._impl.lock:
            self._prune(time.monotonic())
        return await super().get(task_id, context)

    async def list(self, params, context: ServerCallContext):  # type: ignore[override]
        with self._lock, self._impl.lock:
            self._prune(time.monotonic())
        return await super().list(params, context)

    def __len__(self) -> int:
        return sum(len(v) for v in self._impl.tasks.values())
