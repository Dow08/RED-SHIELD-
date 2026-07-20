"""Tests de la surveillance mail IMAP (gate air-gapped/config, sans serveur réel)."""
import json

from app.core.bus import EventBus
from app.modules.imapmail import ImapMailModule
from app.runtime import runtime


class _Conn:
    def __init__(self, val=None):
        self._val = val
    def get(self, name):
        return self._val


def test_status_not_configured():
    m = ImapMailModule(EventBus(), _Conn(None), mail=None)
    assert m.status()["configured"] is False


def test_status_configured_masks_password():
    cfg = json.dumps({"host": "imap.x", "username": "a@x", "password": "secret"})
    m = ImapMailModule(EventBus(), _Conn(cfg), mail=None)
    st = m.status()
    assert st["configured"] is True and st["host"] == "imap.x" and st["username"] == "a@x"
    assert "password" not in st and "secret" not in json.dumps(st)  # le mot de passe n'est jamais renvoyé


def test_check_gate_airgapped(monkeypatch):
    cfg = json.dumps({"host": "imap.x", "username": "a@x", "password": "s"})
    m = ImapMailModule(EventBus(), _Conn(cfg), mail=None)
    monkeypatch.setattr(runtime, "airgapped", True)
    r = m.check()
    assert r.available is False and "air-gapped" in r.reason


def test_check_gate_not_configured(monkeypatch):
    m = ImapMailModule(EventBus(), _Conn(None), mail=None)
    monkeypatch.setattr(runtime, "airgapped", False)
    r = m.check()
    assert r.available is False and "non configuré" in r.reason
