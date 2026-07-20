"""Module Surveillance Mail (IMAP) — analyse automatique des derniers mails de la boîte.

Se connecte à TA boîte via IMAP (SSL), récupère les N derniers messages et les passe
à l'analyse existante (SPF/DKIM/DMARC, liens, pièces jointes) → verdict phishing/ransomware.
Identifiants (mot de passe d'application) chiffrés en keyring (connecteur « imap »).
Gated par le mode air-gapped ET la présence d'une config. Le mot de passe n'est jamais
journalisé ni renvoyé. 100 % factuel : aucune analyse inventée.
"""
from __future__ import annotations

import email
import imaplib
import json

from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus
from app.runtime import runtime


class ImapMail(BaseModel):
    uid: str = ""
    from_addr: str = ""
    subject: str = ""
    date: str = ""
    spf: str = "?"
    dkim: str = "?"
    dmarc: str = "?"
    risk: int = 0
    severity: str = "safe"
    reasons: list[str] = []


class ImapResult(BaseModel):
    available: bool = False
    reason: str = ""
    error: str = ""
    checked: int = 0
    suspicious: int = 0
    mails: list[ImapMail] = []


class ImapMailModule(Module):
    name = "imapmail"
    version = "0.1.0"
    description = "Surveillance mail IMAP (analyse auto)"
    consumes = ["connectors"]

    def __init__(self, bus: EventBus, connectors, mail) -> None:
        super().__init__(bus)
        self._conn = connectors
        self._mail = mail  # MailModule (réutilise .analyze)

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    def _config(self) -> dict | None:
        raw = self._conn.get("imap")
        if not raw:
            return None
        try:
            cfg = json.loads(raw)
        except Exception:
            return None
        if not (cfg.get("host") and cfg.get("username") and cfg.get("password")):
            return None
        return cfg

    def status(self) -> dict:
        cfg = self._config()
        return {
            "configured": cfg is not None,
            "airgapped": runtime.airgapped,
            "host": (cfg or {}).get("host", ""),
            "username": (cfg or {}).get("username", ""),
        }

    def check(self, limit: int = 15) -> ImapResult:
        if runtime.airgapped:
            return ImapResult(available=False, reason="mode air-gapped actif — désactive-le pour relever la boîte")
        cfg = self._config()
        if cfg is None:
            return ImapResult(available=False, reason="boîte IMAP non configurée (onglet Connecteurs)")
        try:
            box = imaplib.IMAP4_SSL(cfg["host"], int(cfg.get("port", 993)))
            box.login(cfg["username"], cfg["password"])
            box.select(cfg.get("folder", "INBOX"), readonly=True)  # lecture seule : ne modifie rien
            typ, data = box.search(None, "ALL")
            ids = (data[0].split() if data and data[0] else [])[-limit:]
            mails: list[ImapMail] = []
            for mid in reversed(ids):
                typ, msg_data = box.fetch(mid, "(RFC822)")
                if not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                a = self._mail.analyze(raw)
                mails.append(ImapMail(
                    uid=mid.decode() if isinstance(mid, bytes) else str(mid),
                    from_addr=a.from_addr, subject=a.subject, date=a.date,
                    spf=a.spf, dkim=a.dkim, dmarc=a.dmarc,
                    risk=a.risk, severity=a.severity, reasons=a.reasons,
                ))
            try:
                box.logout()
            except Exception:
                pass
            suspicious = sum(1 for m in mails if m.severity in ("suspect", "crit"))
            return ImapResult(available=True, checked=len(mails), suspicious=suspicious, mails=mails)
        except imaplib.IMAP4.error as exc:
            return ImapResult(available=True, error=f"authentification/IMAP : {exc}")
        except Exception as exc:
            return ImapResult(available=True, error=str(exc))
