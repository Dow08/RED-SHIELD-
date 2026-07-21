"""Tests du helper réseau centralisé core.http (sans réseau réel)."""
from app.core import http


def test_result_error_is_never_ok():
    r = http.Result(error="connexion refusée")
    assert r.ok is False
    assert r.status_code == 0
    assert r.error == "connexion refusée"
    assert r.json() is None
    assert r.text == ""


def test_request_to_invalid_host_returns_error_not_raise():
    # Adresse non routable : aucune exception ne doit traverser, on récupère un Result.error.
    r = http.get("http://127.0.0.1:1/never", timeout=1)
    assert r.ok is False
    assert r.error is not None
    assert r.status_code == 0


class _FakeResp:
    status_code = 200
    text = "ok"

    @staticmethod
    def json():
        return {"a": 1}


def test_result_wraps_response():
    r = http.Result(resp=_FakeResp())
    assert r.ok is True and r.status_code == 200
    assert r.json() == {"a": 1} and r.text == "ok"
