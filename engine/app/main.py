"""Point d'entrée FastAPI de RED : coquille + endpoints de base.

Lancer : py -m uvicorn app.main:app --reload  (depuis engine/)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
from app.modules.grc import GrcModule
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
from app.modules.updater import UpdaterModule
from app.modules.throughput import ThroughputModule
from app.modules.trace import TraceModule
from app.modules.wifi import WifiModule
from app.report.markdown import build_markdown
from app.report import mission as mission_report
from app.report.mission import build_model

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
    category: str = "temp"
    dry_run: bool = True


class StartupReq(BaseModel):
    name: str
    enabled: bool


class UpgradeReq(BaseModel):
    id: str
    dry_run: bool = True


class GrcControlReq(BaseModel):
    id: str
    status: str          # conforme / a_traiter / non_conforme / na / manuel / auto
    note: str = ""
    attachments: list | None = None   # [{name, type, data(data-URL)}] — preuve jointe


class ReportMetaReq(BaseModel):
    meta: dict | None = None   # override optionnel (client, périmètre, consultant…)


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
    registry.register(UpdaterModule(bus))
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

    def _grc_signals() -> dict:
        """Rassemble l'état réel de la machine pour l'auto-évaluation GRC (best-effort)."""
        sig: dict = {"audit_logging": True, "monitoring": True}
        try:
            m = shield.metrics(geo=None)
            sig["exposed_ports"] = m.listeners_exposed
            sig["clear_flows"] = m.clear
        except Exception:
            pass
        try:
            sc = scoring.score_connections(shield.get_connections())
            sig["suspect_conns"] = sum(1 for c in sc if getattr(c, "severity", "") in ("suspect", "crit"))
        except Exception:
            pass
        d = registry.get("defender")
        if d is not None:
            try:
                st = d.get()
                sig["av_enabled"] = st.antivirus_enabled
                sig["rt_protection"] = st.realtime_protection
            except Exception:
                pass
        u = registry.get("updater")
        if u is not None:
            try:
                res = u.get()
                if getattr(res, "available_tool", False):
                    sig["pending_updates"] = len(getattr(res, "updates", []) or [])
            except Exception:
                pass
        return sig

    registry.register(GrcModule(bus, _grc_signals))


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

    # CORS : l'app native (Tauri, origine tauri.localhost) et le dev server appellent le
    # moteur lié à 127.0.0.1. On autorise uniquement ces origines locales (jamais le réseau).
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^(https?://(tauri\.)?localhost(:\d+)?|tauri://localhost)$",
        allow_methods=["*"],
        allow_headers=["*"],
    )

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

    def _audit(action: str, detail: str, when: bool = True) -> None:
        """Trace une action système dans la piste d'audit (best-effort, jamais bloquant)."""
        if not when:
            return
        persist = registry.get("persistence")
        if persist is not None and persist.health() == ModuleStatus.ACTIVE:
            persist.add_audit(action, detail)

    def _geo():
        """Fonction de géoloc hors-ligne du module trace (ou None)."""
        trace_mod = registry.get("trace")
        return trace_mod.geo_lookup_fn() if trace_mod is not None else None

    def _optional(name: str, method: str, *args, fallback=None, **kwargs):
        """Lecture souple : appelle `module.method(...)` si le module existe, sinon `fallback`.

        Convention : **lecture = souple** (dégrade proprement si un module manque),
        **action système = stricte** (`_require`, renvoie 503). Les endpoints avec effet
        de bord/audit gardent leur logique explicite."""
        module = registry.get(name)
        if module is None:
            return fallback
        return getattr(module, method)(*args, **kwargs)

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
        from app.modules.shield import GeoPoint, GeoView
        trace_mod = registry.get("trace")
        geo = _geo()
        shield = _require("shield")
        scoring = registry.get("scoring")
        conns = shield.get_connections()
        scored = scoring.score_connections(conns) if (scoring is not None and scoring.health() == ModuleStatus.ACTIVE) else conns
        # Point « chez toi » = géoloc de l'IP publique de sortie (depuis le traceroute par défaut).
        home = None
        if geo is not None and trace_mod is not None:
            try:
                tr = trace_mod.get()
                if tr.public_ip:
                    g = geo(tr.public_ip)
                    if g and g.get("lat") is not None:
                        home = GeoPoint(ip=tr.public_ip, dns="", lat=g["lat"], lon=g["lon"],
                                        country=g.get("country") or "", city=g.get("city") or "",
                                        process="Ma sortie réseau", severity="safe")
            except Exception:
                home = None
        return GeoView(home=home, points=shield.geo_points(scored, geo))

    @app.get("/shield/metrics")
    def shield_metrics():
        # Géolocalisation des pays via la base hors-ligne du module trace (si dispo).
        return _require("shield").metrics(geo=_geo())

    @app.get("/bandwidth")
    def bandwidth():
        return _require("bandwidth").get_rates()

    @app.get("/throughput/status")
    def throughput_status():
        return _optional("throughput", "status", fallback={"available": False, "reason": "module indisponible"})

    @app.get("/throughput/processes")
    def throughput_processes():
        return _optional("throughput", "processes", fallback=[])

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
        return _optional("wifi", "result", fallback={"networks": [], "message": "module WiFi indisponible"})

    @app.post("/crack")
    def crack(req: CrackRequest):
        return _require("cracker").crack(req)

    @app.get("/scan")
    def scan_get():
        return _optional("scan", "get", fallback={})

    @app.post("/scan/run")
    def scan_run(req: ScanRequest):
        module = registry.get("scan")
        if module is None:
            raise HTTPException(status_code=503, detail="module scan indisponible")
        result = module.run_async(req.target, req.mode)
        action = "scan_hors_perimetre" if req.bypass else "scan"
        detail = f"{req.target} ({req.mode})" + (" — HORS PÉRIMÈTRE (bypass)" if req.bypass else "")
        _audit(action, detail, when=bool(result.get("ok")))
        return result

    @app.get("/procvuln")
    def procvuln_get():
        return _optional("procvuln", "get", fallback={"available": False})

    @app.post("/procvuln/run")
    def procvuln_run():
        return _optional("procvuln", "run_async", fallback={"ok": False, "error": "indisponible"})

    @app.get("/hids")
    def hids_get():
        return _optional("hids", "get", fallback={})

    @app.post("/hids/run")
    def hids_run():
        return _optional("hids", "run_async", fallback={"ok": False, "error": "indisponible"})

    @app.get("/defender")
    def defender_get():
        return _optional("defender", "get", fallback={"available": False, "reason": "module indisponible"})

    @app.post("/defender/run")
    def defender_run():
        return _optional("defender", "run_async", fallback={"ok": False, "error": "indisponible"})

    @app.post("/mail/analyze")
    def mail_analyze(req: MailRequest):
        return _require("mail").analyze(req.eml)

    @app.get("/imap/status")
    def imap_status():
        return _optional("imapmail", "status", fallback={"configured": False})

    @app.get("/imap/check")
    def imap_check(limit: int = 15):
        return _optional("imapmail", "check", limit=limit, fallback={"available": False, "reason": "indisponible"})

    @app.get("/connectors")
    def connectors_status():
        return _optional("connectors", "status", fallback=[])

    @app.post("/connectors/{name}")
    def connectors_set(name: str, req: KeyReq):
        try:
            _require("connectors").set(name, req.key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"ok": True, "name": name}

    @app.delete("/connectors/{name}")
    def connectors_delete(name: str):
        try:
            _require("connectors").delete(name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"ok": True, "name": name}

    @app.get("/intel/ip")
    def intel_ip(ip: str):
        return _require("intel").lookup_ip(ip)

    @app.get("/siem/status")
    def siem_status():
        return _optional("siem", "status", fallback={"configured": False})

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
        return _optional("health", "get", fallback={"available": False})

    @app.post("/health/run")
    def health_run():
        return _optional("health", "run_async", fallback={"ok": False})

    @app.post("/health/clean")
    def health_clean(req: CleanReq):
        module = registry.get("health")
        if module is None:
            raise HTTPException(status_code=503, detail="module health indisponible")
        result = module.clean(req.category, dry_run=req.dry_run)
        _audit("health_clean", f"{req.category}: {result.deleted_files} fichiers, {result.freed_mb} Mo", when=not req.dry_run)
        return result

    @app.post("/health/startup")
    def health_startup(req: StartupReq):
        module = registry.get("health")
        if module is None:
            raise HTTPException(status_code=503, detail="module health indisponible")
        result = module.set_startup(req.name, req.enabled)
        _audit("health_startup", f"{req.name} enabled={req.enabled}", when=bool(result.get("ok")))
        return result

    @app.post("/health/restore-point")
    def health_restore_point():
        module = registry.get("health")
        if module is None:
            raise HTTPException(status_code=503, detail="module health indisponible")
        result = module.create_restore_point()
        _audit("restore_point", "créé", when=bool(result.get("ok")))
        return result

    @app.get("/updater/list")
    def updater_list():
        return _optional("updater", "get", fallback={"available_tool": False})

    @app.post("/updater/run")
    def updater_run():
        return _optional("updater", "run_async", fallback={"ok": False})

    @app.post("/updater/upgrade")
    def updater_upgrade(req: UpgradeReq):
        module = registry.get("updater")
        if module is None:
            raise HTTPException(status_code=503, detail="module updater indisponible")
        result = module.upgrade(req.id, dry_run=req.dry_run)
        _audit("app_upgrade", req.id, when=not req.dry_run)
        return result

    @app.get("/lan/devices")
    def lan_devices():
        return _optional("lan", "devices", fallback=[])

    @app.post("/firewall/block")
    def firewall_block(req: FwRequest):
        result = _require("firewall").block(req.ip, dry_run=req.dry_run)
        _audit("firewall_block", req.ip, when=not req.dry_run)
        return result

    @app.post("/firewall/unblock")
    def firewall_unblock(req: FwRequest):
        result = _require("firewall").unblock(req.ip)
        _audit("firewall_unblock", req.ip)
        return result

    @app.post("/firewall/block-port")
    def firewall_block_port(req: FwPortRequest):
        result = _require("firewall").block_port(req.port, req.protocol, dry_run=req.dry_run)
        _audit("firewall_block_port", f"{req.protocol}/{req.port}", when=not req.dry_run)
        return result

    @app.post("/firewall/unblock-port")
    def firewall_unblock_port(req: FwPortRequest):
        result = _require("firewall").unblock_port(req.port, req.protocol)
        _audit("firewall_unblock_port", f"{req.protocol}/{req.port}")
        return result

    @app.get("/firewall/rules")
    def firewall_rules():
        return _optional("firewall", "list_rules", fallback=[])

    @app.get("/grc")
    def grc_posture():
        return _require("grc").posture()

    @app.post("/grc/control")
    def grc_set_control(req: GrcControlReq):
        try:
            result = _require("grc").set_control(req.id, req.status, req.note, req.attachments)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        _audit("grc_control", f"{req.id}={req.status}")
        return result

    @app.get("/grc/export", response_class=PlainTextResponse)
    def grc_export():
        return PlainTextResponse(
            _require("grc").export(),
            headers={"Content-Disposition": "attachment; filename=red-conformite.md"},
        )

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

    @app.post("/report/mission")
    def report_mission(req: ReportMetaReq = ReportMetaReq()):
        """Assemble le rapport de mission à partir des données RÉELLES du poste local."""
        raw: dict = {"meta": req.meta}
        scoring = registry.get("scoring")
        shield = registry.get("shield")
        if scoring is not None and shield is not None:
            try:
                summary = scoring.exposure_summary(scoring.score_connections(shield.get_connections()))
                raw["exposure"] = summary.model_dump()
            except Exception:
                pass
        if shield is not None:
            try:
                raw["exposed_ports"] = shield.metrics(geo=None).listeners_exposed
            except Exception:
                pass
        grc = registry.get("grc")
        if grc is not None:
            try:
                raw["grc"] = grc.posture()
            except Exception:
                pass
        pv = registry.get("procvuln")
        if pv is not None:
            try:
                raw["procvuln"] = pv.get().model_dump()
            except Exception:
                pass
        model = build_model(raw)
        _audit("report_mission", f"score={model.score}, findings={len(model.findings)}")
        return model

    @app.get("/report/draft")
    def report_draft_get():
        """Brouillon éditable sauvegardé (ou {exists:false})."""
        draft = mission_report.load_draft()
        return draft if draft is not None else {"exists": False}

    @app.post("/report/draft")
    def report_draft_save(model: dict):
        """Sauvegarde le rapport édité/annoté (document vivant)."""
        mission_report.save_draft(model)
        _audit("report_draft", "sauvegardé")
        return {"ok": True}

    @app.delete("/report/draft")
    def report_draft_clear():
        mission_report.clear_draft()
        return {"ok": True}

    return app


app = create_app()
