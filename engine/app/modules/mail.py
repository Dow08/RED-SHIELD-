"""Module Mail Security (.eml) — analyse locale d'un email, sans identifiants.

L'utilisateur fournit un fichier .eml (ou colle la source). Analyse 100 % locale :
SPF / DKIM / DMARC (depuis l'en-tête Authentication-Results), alignement expéditeur,
liens et pièces jointes suspects → verdict + explication (orienté remédiation).
Aucun accès boîte mail, aucun credential, aucun appel externe.
"""
from __future__ import annotations

import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr

from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

_RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".ps1", ".hta",
              ".docm", ".xlsm", ".pptm", ".lnk", ".iso", ".img", ".msi", ".jse", ".wsf")
_RISKY_TLD = (".zip", ".mov", ".xyz", ".top", ".tk", ".gq", ".ml", ".cf", ".click", ".country")
_URL_RE = re.compile(r'https?://[^\s"\'<>)]+', re.I)


class MailLink(BaseModel):
    url: str
    suspicious: bool = False
    reason: str = ""


class MailAttachment(BaseModel):
    filename: str
    risky: bool = False


class MailAnalysis(BaseModel):
    from_addr: str = ""
    from_name: str = ""
    subject: str = ""
    date: str = ""
    spf: str = "?"
    dkim: str = "?"
    dmarc: str = "?"
    links: list[MailLink] = []
    attachments: list[MailAttachment] = []
    risk: int = 0
    severity: str = "safe"
    reasons: list[str] = []
    error: str | None = None


class MailRequest(BaseModel):
    eml: str


class MailModule(Module):
    name = "mail"
    version = "0.1.0"
    description = "Mail Security (.eml) — SPF/DKIM/DMARC"
    produces = ["mail"]

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    @staticmethod
    def _mech(auth: str, mech: str) -> str:
        m = re.search(mech + r"\s*=\s*(\w+)", auth, re.I)
        return m.group(1).lower() if m else "?"

    def _body(self, msg) -> str:
        texts: list[str] = []
        try:
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html"):
                    try:
                        texts.append(str(part.get_content()))
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            texts.append(payload.decode("utf-8", "ignore"))
        except Exception:
            pass
        return "\n".join(texts)

    def _links(self, body: str) -> list[MailLink]:
        out: list[MailLink] = []
        for url in list(dict.fromkeys(_URL_RE.findall(body)))[:40]:
            host = re.sub(r"^https?://", "", url).split("/")[0].lower()
            suspicious, reason = False, ""
            if re.match(r"\d+\.\d+\.\d+\.\d+", host):
                suspicious, reason = True, "URL basée sur une IP"
            elif host.startswith("xn--") or ".xn--" in host:
                suspicious, reason = True, "domaine punycode (usurpation possible)"
            elif host.endswith(_RISKY_TLD):
                suspicious, reason = True, "TLD à risque"
            elif host.count("-") >= 4 or len(host) > 40:
                suspicious, reason = True, "domaine inhabituel"
            out.append(MailLink(url=url[:200], suspicious=suspicious, reason=reason))
        return out

    def _attachments(self, msg) -> list[MailAttachment]:
        out: list[MailAttachment] = []
        for part in msg.walk():
            fn = part.get_filename()
            if fn:
                out.append(MailAttachment(filename=fn, risky=fn.lower().endswith(_RISKY_EXT)))
        return out

    def analyze(self, raw: str) -> MailAnalysis:
        if not raw or not raw.strip():
            return MailAnalysis(error="email vide")
        try:
            msg = Parser(policy=policy.default).parsestr(raw)
        except Exception as exc:
            return MailAnalysis(error=f"parsing impossible: {exc}")

        name, addr = parseaddr(msg.get("From", ""))
        subject = str(msg.get("Subject", ""))
        date = str(msg.get("Date", ""))
        auth = f"{msg.get('Authentication-Results', '')} {msg.get('ARC-Authentication-Results', '')} {msg.get('Received-SPF', '')}"
        spf, dkim, dmarc = self._mech(auth, "spf"), self._mech(auth, "dkim"), self._mech(auth, "dmarc")

        links = self._links(self._body(msg))
        attachments = self._attachments(msg)

        reasons: list[str] = []
        risk = 0
        if dmarc == "fail":
            risk += 40; reasons.append("DMARC en échec — usurpation d'expéditeur probable")
        elif dmarc == "?":
            reasons.append("DMARC non évalué (en-tête absent)")
        if spf == "fail":
            risk += 25; reasons.append("SPF en échec — l'émetteur n'est pas autorisé pour ce domaine")
        if dkim == "fail":
            risk += 20; reasons.append("DKIM en échec — signature invalide")

        rp = parseaddr(msg.get("Return-Path", ""))[1]
        fdom = addr.split("@")[-1].lower() if "@" in addr else ""
        rdom = rp.split("@")[-1].lower() if "@" in rp else ""
        if fdom and rdom and fdom != rdom:
            risk += 15; reasons.append(f"désalignement From ({fdom}) / Return-Path ({rdom})")

        susp_links = [l for l in links if l.suspicious]
        if susp_links:
            risk += 20; reasons.append(f"{len(susp_links)} lien(s) suspect(s)")
        risky_atts = [a for a in attachments if a.risky]
        if risky_atts:
            risk += 35; reasons.append("pièce(s) jointe(s) à risque : " + ", ".join(a.filename for a in risky_atts))

        risk = min(risk, 100)
        severity = "crit" if risk >= 70 else "suspect" if risk >= 45 else "watch" if risk >= 20 else "safe"
        return MailAnalysis(from_addr=addr, from_name=name, subject=subject, date=date,
                            spf=spf, dkim=dkim, dmarc=dmarc, links=links, attachments=attachments,
                            risk=risk, severity=severity, reasons=reasons)
