"""Tests du Mail Security (.eml)."""
from app.core.bus import EventBus
from app.modules.mail import MailModule

PHISH = """From: "Support" <security@paypa1-alerts.zip>
To: victim@example.com
Return-Path: <bounce@spammer.ru>
Subject: Votre compte va etre suspendu
Date: Mon, 19 Jul 2026 10:00:00 +0000
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=spammer.ru; dkim=fail; dmarc=fail header.from=paypa1-alerts.zip
Content-Type: text/plain; charset=utf-8

Bonjour, cliquez ici : http://185.99.12.34/login pour verifier votre compte.
"""

LEGIT = """From: "Google" <no-reply@accounts.google.com>
To: user@example.com
Return-Path: <no-reply@accounts.google.com>
Subject: Alerte de securite
Date: Mon, 19 Jul 2026 10:00:00 +0000
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=accounts.google.com; dkim=pass; dmarc=pass header.from=accounts.google.com
Content-Type: text/plain; charset=utf-8

Une nouvelle connexion a ete detectee. https://myaccount.google.com/security
"""


def test_phishing_flagged_critical():
    mod = MailModule(EventBus())
    mod.start()
    a = mod.analyze(PHISH)
    assert a.spf == "fail" and a.dkim == "fail" and a.dmarc == "fail"
    assert a.severity in ("suspect", "crit")
    assert any("DMARC" in r for r in a.reasons)
    assert any(l.suspicious for l in a.links)  # URL sur IP
    assert any("désalignement" in r for r in a.reasons)  # from .zip vs return-path .ru


def test_legit_mail_safe():
    mod = MailModule(EventBus())
    mod.start()
    a = mod.analyze(LEGIT)
    assert a.spf == "pass" and a.dmarc == "pass"
    assert a.severity == "safe"
    assert a.reasons == []


def test_empty_mail():
    mod = MailModule(EventBus())
    mod.start()
    assert mod.analyze("").error is not None
