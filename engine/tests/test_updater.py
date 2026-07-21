"""Tests du module de mise à jour (parseur winget + garde-fous d'installation)."""
from app.core.bus import EventBus
from app.modules.updater import UpdaterModule, parse_upgrade_table

_SAMPLE = (
    "Name                         Id                        Version          Available            Source\n"
    "---------------------------------------------------------------------------------------------------\n"
    "Docker Desktop               Docker.DockerDesktop      4.76.0           4.83.0               winget\n"
    "Ollama version 0.31.1        Ollama.Ollama             0.31.1           0.32.1               winget\n"
    "Oracle VirtualBox 7.2.8      Oracle.VirtualBox         7.2.8            7.2.12               winget\n"
    "2 upgrades available.\n"
)


def test_parse_upgrade_table():
    rows = parse_upgrade_table(_SAMPLE)
    assert len(rows) == 3
    ids = {r["id"] for r in rows}
    assert ids == {"Docker.DockerDesktop", "Ollama.Ollama", "Oracle.VirtualBox"}
    docker = next(r for r in rows if r["id"] == "Docker.DockerDesktop")
    assert docker["current"] == "4.76.0" and docker["available"] == "4.83.0" and docker["source"] == "winget"


def test_parse_empty_or_noise():
    assert parse_upgrade_table("") == []
    assert parse_upgrade_table("Aucune mise à jour disponible.\n") == []


def test_upgrade_dry_run_and_id_validation():
    m = UpdaterModule(EventBus())
    m.start()
    dry = m.upgrade("Docker.DockerDesktop", dry_run=True)
    assert dry["ok"] and dry.get("dry_run")
    assert "--id" in dry["command"] and "Docker.DockerDesktop" in dry["command"] and "--silent" in dry["command"]
    # injection / identifiant invalide rejeté
    assert not m.upgrade("evil & rm -rf", dry_run=True)["ok"]
    assert not m.upgrade("", dry_run=True)["ok"]
