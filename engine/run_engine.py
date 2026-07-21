"""Lanceur du moteur RED SHIELD — point d'entrée pour le sidecar empaqueté (PyInstaller/Tauri).

Démarre l'API FastAPI liée à 127.0.0.1 (jamais exposée hors de l'app). Utilisé tel quel
en développement (`python run_engine.py`) et comme binaire sidecar dans le packaging Tauri.
"""
from __future__ import annotations

import os

import uvicorn

if __name__ == "__main__":
    host = os.getenv("RED_HOST", "127.0.0.1")
    port = int(os.getenv("RED_PORT", "8787"))
    uvicorn.run("app.main:app", host=host, port=port, log_level="info")
