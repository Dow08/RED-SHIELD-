"""Point d'entrée FastAPI de RED : coquille + endpoints de base.

Lancer : py -m uvicorn app.main:app --reload  (depuis engine/)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

from app import __version__
from app.config import settings
from app.core.bus import EventBus
from app.core.registry import Registry
from pydantic import BaseModel

from app.modules.analytics import AnalyticsModule
from app.modules.base import ModuleStatus
from app.modules.bandwidth import BandwidthModule
from app.modules.connectors import ConnectorsModule
from app.modules.cracker import CrackerModule, CrackRequest
from app.modules.defender import DefenderModule
from app.modules.intel import IntelModule
from app.modules.llm import LlmModule
from app.modules.osint import OsintModule
from app.runtime import runtime
from app.modules.firewall import FirewallModule, FwRequest, FwPortRequest
from app.modules.health import HealthModule
from app.modules.hids import HidsModule
from app.modules.imapmail import ImapMailModule
from app.modules.lan import LanModule
from app.modules.mail import MailModule, MailRequest
from app.modules.diagnostic import DiagnosticModule
from app.modules.persistence import PersistenceModule
from app.modules.procvuln import ProcVulnModule
from app.modules.scan import ScanModule, ScanRequest
from app.modules.scoring import ScoringModule
from app.modules.shield import ShieldModule
from app.modules.siem import SiemModule
from app.modules.throughput import ThroughputModule
from app.modules.trace import TraceModule
from app.modules.wifi import WifiModule
from app.report.markdown import build_markdown

logging.basicConfig(level=logging.INFO)


class AirgapReq(BaseModel):
    airgapped: bool


class KeyReq(BaseModel):
    key: str


class OsintReq(BaseModel):
    domain: str


class LlmReq(BaseModel):
    text: str
    kind: str = "rapport"


class CleanReq(BaseModel):
    dry_run: bool = True


def register_modules(registry: Registry, bus: EventBus) -> None:
    """Enregistre les modules concrets (rempli au fil des étapes du Jalon 1).

    Diagnostic en premier : il s'abonne au bus avant les autres pour capter leurs logs.
    """
    registry.register(DiagnosticModule(bus))
    shield = ShieldModule(bus)
    registry.register(shield)
    registry.register(BandwidthModule(bus))
    registry.register(ThroughputModule(bus))
    scoring = ScoringModule(bus)
    registry.register(scoring)
    registry.register(PersistenceModule(bus))
    registry.register(TraceModule(bus))
    registry.register(WifiModule(bus))
    registry.register(CrackerModule(bus))
    registry.register(FirewallModule(bus))
    registry.register(LanModule(bus))
    registry.register(HealthModule(bus))
    registry.register(ScanModule(bus))
    registry.register(ProcVulnModule(bus))
    registry.register(HidsModule(bus))
    registry.register(DefenderModule(bus))
    mail = MailModule(bus)
    registry.register(mail)
    connectors = ConnectorsModule(bus)
    registry.register(connectors)
    registry.register(IntelModule(bus, connectors))
    registry.register(SiemModule(bus, connectors))
    registry.register(ImapMailModule(bus, connectors, mail))
    registry.register(OsintModule(bus))
    registry.register(LlmModule(bus, connectors))
    registry.register(AnalyticsModule(bus, shield, scoring))


def create_app() -> FastAPI:
    bus = EventBus()
    registry = Registry(bus)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        register_modules(registry, bus)
        registry.start_all()
        yield
        registry.stop_all()

    app = FastAPI(title="RED — Network Shield & Recon", version=__version__, lifespan=lifespan)
    app.state.bus = bus
    app.state.registry = registry

    # Un abonné défaillant est journalisé sans republier sur le bus (évite toute récursion).
    bus.set_error_handler(
        lambda topic, exc: logging.getLogger("red").error("bus[%s]: %s", topic, exc)
    )

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "ok",
            "service": "RED",
            "version": __version__,
            "airgapped": runtime.airgapped,
        }

    @app.get("/config")
    def config_get() -> dict:
        return {
            "airgapped": runtime.airgapped,
            "purge_on_exit": settings.purge_on_exit,
            "storage_budget_go": settings.storage_budget_go,
            "sample_interval": settings.sample_interval,
        }

    @app.post("/config/airgapped")
    def config_airgapped(req: AirgapReq) -> dict:
        runtime.airgapped = req.airgapped
        bus.publish("log", {"level": "warn", "module": "config", "message": f"air-gapped = {req.airgapped}"})
        return {"airgapped": runtime.airgapped}

    @app.get("/modules", response_model=list)
    def modules() -> list:
        return registry.list()

    def _require(name: str):
        module = registry.get(name)
        if module is None or module.health() != ModuleStatus.ACTIVE:
            raise HTTPException(status_code=503, detail=f"module '{name}' indisponible")
        return module

    @app.get("/shield/connections")
    def shield_connections() -> list:
        conns = _require("shield").get_connections()
        scoring = registry.get("scoring")
        if scoring is not None and scoring.health() == ModuleStatus.ACTIVE:
            return scoring.score_connections(conns)
        return conns

    @app.get("/shield/top-talkers")
    def shield_top_talkers() -> list:
        return _require("shield").top_talkers()

    @app.get("/shield/listeners")
    def shield_listeners() -> list:
        return _require("shield").get_listeners()

    @app.get("/shield/geo")
    def shield_geo():
        trace_mod = registry.get("trace")
        geo = trace_mod._geo_lookup if (trace_mod is not None and getattr(trace_mod, "geo_available", False)) else None
        shield = _require("shield")
        scoring = registry.get("scoring")
        conns = shield.get_connections()
        scored = scoring.score_connections(conns) if (scoring is not None and scoring.health() == ModuleStatus.ACTIVE) else conns
        return shield.geo_points(scored, geo)

    @app.get("/shield/metrics")
    def shield_metrics():
        # Géolocalisation des pays via la base hors-ligne du module trace (si dispo).
        trace_mod = registry.get("trace")
        geo = None
        if trace_mod is not None and getattr(trace_mod, "geo_available", False):
            geo = trace_mod._geo_lookup
        return _require("shield").metrics(geo=geo)

    @app.get("/bandwidth")
    def bandwidth():
        return _require("bandwidth").get_rates()

    @app.get("/throughput/status")
    def throughput_status():
        module = registry.get("throughput")
        return module.status() if module is not None else {"available": False, "reason": "module indisponible"}

    @app.get("/throughput/processes")
    def throughput_processes():
        module = registry.get("throughput")
        return module.processes() if module is not None else []

    @app.get("/exposure")
    def exposure():
        conns = _require("shield").get_connections()
        scoring = _require("scoring")
        return scoring.exposure_summary(scoring.score_connections(conns))

    @app.get("/diagnostic/logs")
    def diagnostic_logs(since: str | None = None, until: str | None = None, level: str | None = None):
        return _require("diagnostic").get_logs(since=since, until=until, level=level)

    @app.get("/diagnostic/logs/export", response_class=PlainTextResponse)
    def diagnostic_export():
        text = _require("diagnostic").export_text()
        return PlainTextResponse(
            text, headers={"Content-Disposition": "attachment; filename=red-logs.txt"}
        )

    @app.post("/snapshot")
    def snapshot():
        scoring = _require("scoring")
        persist = _require("persistence")
        summary = scoring.exposure_summary(scoring.score_connections(_require("shield").get_connections()))
        snap = persist.record_snapshot(summary)
        persist.add_audit("snapshot", f"score={summary.score}")
        return snap

    @app.get("/history")
    def history(limit: int = 100):
        return _require("persistence").history(limit=limit)

    @app.get("/trace")
    def trace(target: str | None = None):
        return _require("trace").get(target)

    @app.post("/trace/run")
    def trace_run(target: str | None = None):
        module = _require("trace")
        module.run_async(target or module.default_target)
        return {"running": True, "target": target or module.default_target}

    @app.get("/wifi/networks")
    def wifi_networks():
        module = registry.get("wifi")
        if module is None:
            return {"networks": [], "message": "module WiFi indisponible"}
        return module.result()

    @app.post("/crack")
    def crack(req: CrackRequest):
        return _require("cracker").crack(req)

    @app.get("/scan")
    def scan_get():
        module = registry.get("scan")
        return module.get() if module is not None else {}

    @app.post("/scan/run")
    def scan_run(req: ScanRequest):
        module = registry.get("scan")
        if module is None:
            raise HTTPException(status_code=503, detail="module scan indisponible")
        result = module.run_async(req.target, req.mode)
        persist = registry.get("persistence")
        if persist is not None and persist.health() == ModuleStatus.ACTIVE and result.get("ok"):
            persist.add_audit("scan", f"{req.target} ({req.mode})")
        return result

    @app.get("/procvuln")
    def procvuln_get():
        module = registry.get("procvuln")
        return module.get() if module is not None else {"available": False}

    @app.post("/procvuln/run")
    def procvuln_run():
        module = registry.get("procvuln")
        return module.run_async() if module is not None else {"ok": False, "error": "indisponible"}

    @app.get("/hids")
    def hids_get():
        module = registry.get("hids")
        return module.get() if module is not None else {}

    @app.post("/hids/run")
    def hids_run():
        module = registry.get("hids")
        return module.run_async() if module is not None else {"ok": False, "error": "indisponible"}

    @app.get("/defender")
    def defender_get():
        module = registry.get("defender")
        return module.get() if module is not None else {"available": False, "reason": "module indisponible"}

    @app.post("/defender/run")
    def defender_run():
        module = registry.get("defender")
        return module.run_async() if module is not None else {"ok": False, "error": "indisponible"}

    @app.post("/mail/analyze")
    def mail_analyze(req: MailRequest):
        return _require("mail").analyze(req.eml)

    @app.get("/imap/status")
    def imap_status():
        module = registry.get("imapmail")
        return module.status() if module is not None else {"configured": False}

    @app.get("/imap/check")
    def imap_check(limit: int = 15):
        module = registry.get("imapmail")
        return module.check(limit=limit) if module is not None else {"available": False, "reason": "indisponible"}

    @app.get("/connectors")
    def connectors_status():
        module = registry.get("connectors")
        return module.status() if module is not None else []

    @app.post("/connectors/{name}")
    def connectors_set(name: str, req: KeyReq):
        _require("connectors").set(name, req.key)
        return {"ok": True, "name": name}

    @app.delete("/connectors/{name}")
    def connectors_delete(name: str):
        _require("connectors").delete(name)
        return {"ok": True, "name": name}

    @app.get("/intel/ip")
    def intel_ip(ip: str):
        return _require("intel").lookup_ip(ip)

    @app.get("/siem/status")
    def siem_status():
        module = registry.get("siem")
        return module.status() if module is not None else {"configured": False}

    @app.post("/siem/test")
    def siem_test():
        return _require("siem").test()

    @app.get("/siem/alerts")
    def siem_alerts():
        return _require("siem").alerts()

    @app.post("/osint/subdomains")
    def osint_subdomains(req: OsintReq):
        return _require("osint").subdomains(req.domain)

    @app.post("/llm/analyze")
    def llm_analyze(req: LlmReq):
        return _require("llm").analyze(req.text, req.kind)

    @app.get("/analytics/timeline")
    def analytics_timeline(limit: int = 100):
        return _require("analytics").timeline(limit=limit)

    @app.get("/analytics/beaconing")
    def analytics_beaconing():
        return _require("analytics").beaconing()

    @app.get("/health/report")
    def health_report():
        module = registry.get("health")
        return module.get() if module is not None else {"available": False}

    @app.post("/health/run")
    def health_run():
        module = registry.get("health")
        return module.run_async() if module is not None else {"ok": False}

    @app.post("/health/clean")
    def health_clean(req: CleanReq):
        module = registry.get("health")
        if module is None:
            raise HTTPException(status_code=503, detail="module health indisponible")
        result = module.clean_temp(dry_run=req.dry_run)
        persist = registry.get("persistence")
        if persist is not None and persist.health() == ModuleStatus.ACTIVE and not req.dry_run:
            persist.add_audit("health_clean", f"{result.deleted_files} fichiers, {result.freed_mb} Mo")
        return result

    @app.get("/lan/devices")
    def lan_devices():
        module = registry.get("lan")
        return module.devices() if module is not None else []

    @app.post("/firewall/block")
    def firewall_block(req: FwRequest):
        result = _require("firewall").block(req.ip, dry_run=req.dry_run)
        persist = registry.get("persistence")
        if persist is not None and persist.health() == ModuleStatus.ACTIVE and not req.dry_run:
            persist.add_audit("firewall_block", req.ip)
        return result

    @app.post("/firewall/unblock")
    def firewall_unblock(req: FwRequest):
        result = _require("firewall").unblock(req.ip)
        persist = registry.get("persistence")
        if persist is not None and persist.health() == ModuleStatus.ACTIVE:
            persist.add_audit("firewall_unblock", req.ip)
        return result

    @app.post("/firewall/block-port")
    def firewall_block_port(req: FwPortRequest):
        result = _require("firewall").block_port(req.port, req.protocol, dry_run=req.dry_run)
        persist = registry.get("persistence")
        if persist is not None and persist.health() == ModuleStatus.ACTIVE and not req.dry_run:
            persist.add_audit("firewall_block_port", f"{req.protocol}/{req.port}")
        return result

    @app.post("/firewall/unblock-port")
    def firewall_unblock_port(req: FwPortRequest):
        result = _require("firewall").unblock_port(req.port, req.protocol)
        persist = registry.get("persistence")
        if persist is not None and persist.health() == ModuleStatus.ACTIVE:
            persist.add_audit("firewall_unblock_port", f"{req.protocol}/{req.port}")
        return result

    @app.get("/firewall/rules")
    def firewall_rules():
        module = registry.get("firewall")
        return module.list_rules() if module is not None else []

    @app.get("/report/markdown", response_class=PlainTextResponse)
    def report_markdown():
        scoring = _require("scoring")
        scored = scoring.score_connections(_require("shield").get_connections())
        summary = scoring.exposure_summary(scored)
        persist = registry.get("persistence")
        if persist is not None and persist.health() == ModuleStatus.ACTIVE:
            persist.add_audit("report", "markdown")
        return PlainTextResponse(
            build_markdown(summary, scored),
            headers={"Content-Disposition": "attachment; filename=red-report.md"},
        )

    return app


app = create_app()
