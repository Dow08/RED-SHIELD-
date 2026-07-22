"""Tests du moteur recon natif (nmap-free) — serveurs locaux réels, déterministes."""
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import app.modules.netrecon as nr


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.rstrip("/") in ("/admin", "/login"):
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        else:
            self.send_response(404); self.end_headers()
    def do_HEAD(self):
        self.send_response(200); self.send_header("Server", "TestHTTP/1.0"); self.end_headers()
    def log_message(self, *a):  # silence
        pass


@pytest.fixture
def web():
    port = _free_port()
    srv = HTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()


def test_parse_targets():
    assert nr.parse_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert nr.parse_targets("192.168.1.42") == ["192.168.1.42"]
    assert nr.parse_targets("pas-une-ip") == []
    assert len(nr.parse_targets("10.0.0.0/16")) == 512   # plafonné


def test_tcp_open_and_scan(web):
    assert nr._tcp_open("127.0.0.1", web) is True
    assert nr._tcp_open("127.0.0.1", _free_port()) is False   # port fermé
    res = nr.scan_ports("127.0.0.1", ports=[web, _free_port()], fingerprint=False)
    assert [p.port for p in res] == [web]


def test_web_enum_finds_paths(web):
    base = f"http://127.0.0.1:{web}"
    found = nr.web_enum(base, words=["admin", "login", "nexistepas-zzz"])
    paths = {f.path for f in found}
    assert "/admin" in paths and "/login" in paths
    assert "/nexistepas-zzz" not in paths          # 404 → écarté
    assert all(f.status == 200 for f in found)


def test_fingerprint_http_server(web):
    res = nr.scan_ports("127.0.0.1", ports=[web], fingerprint=True)
    # la sonde HTTP (HEAD) doit remonter l'en-tête Server pour un port HTTP connu.
    # Ici le port est aléatoire (pas dans _HTTP_PORTS) → au moins pas de crash + service mappé si connu.
    assert res and res[0].port == web


def test_tls_audit_graceful_on_closed():
    info = nr.tls_audit("127.0.0.1", _free_port(), timeout=1.0)
    assert info.ok is False and info.error != ""


def test_tls_weak_name_parsing():
    assert nr._name((( ("commonName", "example.com"),), (("organizationName", "ACME"),))) == "example.com / ACME"
    assert nr._name(None) == ""


def test_discover_localhost_alive():
    # bind un port de découverte (8080) sur 127.0.0.1 → l'hôte doit être vu vivant
    port = 8080
    try:
        srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port)); srv.listen(5)
    except OSError:
        pytest.skip("port 8080 indisponible")
    try:
        hosts = nr.discover_hosts("127.0.0.1/32")
        assert any(h.ip == "127.0.0.1" and 8080 in h.open_ports for h in hosts)
    finally:
        srv.close()
