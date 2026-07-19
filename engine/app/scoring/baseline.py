"""Baseline utilisateur : mémorise les couples (process, IP distante) habituels.

Jalon 1 : en mémoire, apprentissage sur la session. La persistance (diff dans le
temps) arrive au Jalon 2/3 via SQLite.
"""
from __future__ import annotations


class Baseline:
    def __init__(self) -> None:
        self._seen: set[tuple[str, str]] = set()
        self.warmed = False

    def _key(self, conn) -> tuple[str, str]:
        return (conn.process, conn.remote_addr)

    def is_new(self, conn) -> bool:
        return self._key(conn) not in self._seen

    def learn(self, conn) -> None:
        self._seen.add(self._key(conn))
