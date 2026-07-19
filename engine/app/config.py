"""Configuration RED, chargée depuis l'environnement (.env)."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("RED_HOST", "127.0.0.1")
    port: int = int(os.getenv("RED_PORT", "8787"))
    # air-gapped ACTIF par défaut : aucun appel réseau externe.
    airgapped: bool = _as_bool(os.getenv("RED_AIRGAPPED"), True)
    sample_interval: float = float(os.getenv("RED_SAMPLE_INTERVAL", "2"))
    db_path: str = os.getenv("RED_DB_PATH", "engine/data/red.db")
    storage_budget_go: float = float(os.getenv("RED_STORAGE_BUDGET_GO", "1.0"))
    purge_on_exit: bool = _as_bool(os.getenv("RED_PURGE_ON_EXIT"), True)


settings = Settings()
