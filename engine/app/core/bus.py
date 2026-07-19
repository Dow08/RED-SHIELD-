"""Bus d'événements in-process (pub/sub).

Les modules ne s'appellent jamais directement : ils publient/consomment via ce bus.
Un abonné qui plante ne casse pas les autres.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

Handler = Callable[[Any], None]


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, list[Handler]] = defaultdict(list)
        self._on_error: Callable[[str, Exception], None] | None = None

    def set_error_handler(self, handler: Callable[[str, Exception], None]) -> None:
        self._on_error = handler

    def subscribe(self, topic: str, callback: Handler) -> None:
        self._subs[topic].append(callback)

    def publish(self, topic: str, payload: Any = None) -> None:
        for callback in list(self._subs.get(topic, ())):
            try:
                callback(payload)
            except Exception as exc:  # un abonné défaillant est isolé
                if self._on_error is not None:
                    self._on_error(topic, exc)
