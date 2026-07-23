import { useEffect, useState } from "react";
import { api, IS_MOBILE } from "./api";
import type { Severity } from "./api";
import { usePolling } from "./hooks";
import { CyberBackground } from "./viz";
import { bandColor, bandLabel, fr } from "./shared";
import Dashboard from "./tabs/Dashboard";
import Bouclier from "./tabs/Bouclier";
import CarteReseau from "./tabs/CarteReseau";
import Remediation from "./tabs/Remediation";
import Grc from "./tabs/Grc";
import Recon from "./tabs/Recon";
import Offensif from "./tabs/Offensif";
import Soc from "./tabs/Soc";
import Health from "./tabs/Health";
import Connecteurs from "./tabs/Connecteurs";
import Diagnostic from "./tabs/Diagnostic";

const TABS: [string, string, string?][] = [
  ["dashboard", "Dashboard"],
  ["bouclier", "Bouclier"],
  ["carte", "Carte réseau"],
  ["remediation", "Remédiation"],
  ["conformite", "Conformité"],
  ["recon", "Recon"],
  ["offensif", "Offensif"],
  ["soc", "SOC local"],
  ["sante", "Santé"],
  ["connecteurs", "Connecteurs"],
  ["diagnostic", "Diagnostic"],
];

// Mise en page mobile : nav réduite aux onglets utilisables sans moteur Python
// (recon natif + cracker offline). `?mobile=1` force l'aperçu depuis un navigateur.
const MOBILE_UI = IS_MOBILE || (typeof location !== "undefined" && new URLSearchParams(location.search).has("mobile"));
const MOBILE_TABS = new Set(["recon", "offensif"]);

export default function App() {
  const [tab, setTab] = useState(MOBILE_UI ? "recon" : "dashboard");
  const [showAirgapHelp, setShowAirgapHelp] = useState(false);
  const [sevFilter, setSevFilter] = useState<Record<Severity, boolean>>({ safe: true, watch: true, suspect: true, crit: true });
  const health = usePolling(api.health, 10000);
  const modules = usePolling(api.modules, 5000);
  const exposure = usePolling(api.exposure, 3000);
  const connections = usePolling(api.connections, 3000);
  const bandwidth = usePolling(api.bandwidth, 1500);
  const top = usePolling(api.topTalkers, 5000, tab === "dashboard");
  const metrics = usePolling(api.metrics, 5000);
  const listeners = usePolling(api.listeners, 8000);
  const thrStatus = usePolling(api.throughputStatus, 6000, tab === "dashboard");
  const thrProcs = usePolling(api.throughputProcesses, 2000, tab === "dashboard");
  const geoPoints = usePolling(api.geoPoints, 6000, tab === "carte" || tab === "dashboard");
  const logs = usePolling(() => api.logs(), 5000);
  const history = usePolling(api.history, 8000);
  const [traceTarget, setTraceTarget] = useState("1.1.1.1");
  const trace = usePolling(() => api.trace(traceTarget), 6000, tab === "carte" || tab === "dashboard");
  const wifi = usePolling(api.wifi, 15000, tab === "offensif");
  const timeline = usePolling(api.timeline, 6000, tab === "diagnostic");
  const beaconing = usePolling(api.beaconing, 10000, tab === "dashboard" || tab === "diagnostic");
  const lan = usePolling(api.lan, 20000, tab === "recon");
  const scan = usePolling(api.scan, 4000, tab === "recon");
  const procvuln = usePolling(api.procvuln, 10000, tab === "recon");
  const hids = usePolling(api.hids, 8000, tab === "soc");
  const defender = usePolling(api.defender, 12000, tab === "soc");
  const connectors = usePolling(api.connectors, 6000);
  const config = usePolling(api.config, 15000);
  const healthRep = usePolling(api.healthReport, 12000, tab === "sante");
  const updater = usePolling(api.updaterList, 20000, tab === "sante");
  const [traceLabel, setTraceLabel] = useState("");
  const runTrace = (t: string) => { setTraceTarget(t); api.traceRun(t); };
  const selectEndpoint = (ip: string) => {
    const c = (connections.data || []).find((x) => x.remote_addr === ip);
    setTraceLabel(c ? `${c.process} → ${ip}` : ip);
    runTrace(ip);
    setTab("carte");
  };

  const [bwHist, setBwHist] = useState<{ d: number; u: number }[]>([]);
  const [scoreHist, setScoreHist] = useState<number[]>([]);
  useEffect(() => { if (bandwidth.data) setBwHist((h) => [...h.slice(-59), { d: bandwidth.data!.down_mo_s, u: bandwidth.data!.up_mo_s }]); }, [bandwidth.data]);
  useEffect(() => { if (exposure.data) setScoreHist((h) => [...h.slice(-47), exposure.data!.score]); }, [exposure.data]);

  const conns = connections.data || [];
  const mods = modules.data || [];
  const airgapped = health.data?.airgapped ?? true;
  const bwLast = bwHist.at(-1);

  const offline = connections.error && !connections.data;

  // Détection de mise à jour (via le moteur, gated air-gapped) — awareness, install manuelle.
  const [update, setUpdate] = useState<{ update_available?: boolean; latest?: string; url?: string } | null>(null);
  useEffect(() => { if (!airgapped && !MOBILE_UI) api.updateCheck().then(setUpdate).catch(() => {}); }, [airgapped]);

  return (
    <>
    <CyberBackground />
    <div className="wrap">
      <div className="top">
        <div className="brand">
          <div className="logo" aria-hidden style={{ background: "transparent", boxShadow: "none", width: 46, height: 52 }}>
            <svg viewBox="0 0 128 142" width="46" height="52" fill="none" style={{ filter: "drop-shadow(0 4px 12px rgba(255,122,47,.5))" }}>
              <defs>
                <linearGradient id="rsBody" x1="20" y1="6" x2="108" y2="132" gradientUnits="userSpaceOnUse"><stop stopColor="#233a5c" /><stop offset="1" stopColor="#0a1526" /></linearGradient>
                <linearGradient id="rsRim" x1="20" y1="6" x2="108" y2="130" gradientUnits="userSpaceOnUse"><stop stopColor="#ffd7a8" /><stop offset="0.45" stopColor="#ff7a2f" /><stop offset="1" stopColor="#b83512" /></linearGradient>
                <linearGradient id="rsChk" x1="42" y1="52" x2="86" y2="92" gradientUnits="userSpaceOnUse"><stop stopColor="#fff2e6" /><stop offset="1" stopColor="#ff9a4d" /></linearGradient>
                <linearGradient id="rsGloss" x1="40" y1="8" x2="58" y2="80" gradientUnits="userSpaceOnUse"><stop stopColor="#ffffff" stopOpacity="0.6" /><stop offset="1" stopColor="#ffffff" stopOpacity="0" /></linearGradient>
              </defs>
              <path d="M64 6 112 24V62c0 34-20 58-48 72C36 120 16 96 16 62V24Z" fill="url(#rsBody)" stroke="url(#rsRim)" strokeWidth="4" />
              <path d="M64 8 24 23v20c0 15 5 27 13 37 6-8 9-18 9-31V19Z" fill="url(#rsGloss)" />
              <path d="M44 64 58 79 88 46" stroke="url(#rsChk)" strokeWidth="11" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <div><h1>RED <span style={{ color: "var(--accent)" }}>SHIELD</span></h1><div className="sub">Network Shield &amp; Recon</div></div>
        </div>
        <div className="gm"><div className="num" style={{ color: bandColor(exposure.data?.band ?? "faible") }}>{exposure.data?.score ?? "—"}</div><div><div className="lab">Exposition</div><div className="band" style={{ color: bandColor(exposure.data?.band ?? "faible") }}>{exposure.data ? bandLabel(exposure.data.band).replace("Exposition ", "") : "…"}</div></div></div>
        <div className="bw"><span><span className="k">↓ DL</span> <span className="dl mono">{fr(bwLast?.d ?? 0)}</span> <span className="k">Mo/s</span></span><span><span className="k">↑ UL</span> <span className="ul mono">{fr(bwLast?.u ?? 0)}</span> <span className="k">Mo/s</span></span></div>
        <div className="spacer"></div>
        <div className={`pill ${airgapped ? "" : "off"}`} style={{ cursor: "pointer" }} onClick={async () => { await api.setAirgapped(!airgapped); }} title="Cliquer pour activer/désactiver le mode air-gapped">
          <span className="on"></span>Air-gapped&nbsp;<b>{airgapped ? "ACTIF" : "OFF"}</b>
          <span style={{ marginLeft: 6, color: "var(--faint)" }}>⇄</span>
        </div>
        <button className="pill" style={{ cursor: "pointer", padding: "7px 11px", fontWeight: 700 }} title="C'est quoi le mode air-gapped ?" onClick={() => setShowAirgapHelp(true)}>?</button>
      </div>

      {offline && !MOBILE_UI && <div className="note" style={{ borderRadius: 12, marginBottom: 12 }}>⚠️ Moteur injoignable sur <b>127.0.0.1:8787</b>. Lance le backend : <span className="mono">py -m uvicorn app.main:app</span> (depuis <span className="mono">engine/</span>).</div>}
      {update?.update_available && <div className="note" style={{ borderRadius: 12, marginBottom: 12, borderColor: "var(--accent)" }}>🔔 <b>Version {update.latest} disponible</b> (tu utilises une version antérieure). {update.url && <a href={update.url} target="_blank" rel="noreferrer" style={{ color: "var(--accent)" }}>Voir la release →</a>}</div>}
      {MOBILE_UI && <div className="note" style={{ borderRadius: 12, marginBottom: 12 }}>📱 <b>Mode terrain (mobile)</b> — recon natif embarqué (sans moteur Python). Les modules d'analyse du poste (Dashboard, Bouclier, Santé…) sont réservés à la version desktop.</div>}

      <div className="nav">
        {TABS.filter(([id]) => !MOBILE_UI || MOBILE_TABS.has(id)).map(([id, label, mini]) => (
          <button key={id} className={`navb ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>{label}{mini && <span className="mini">{mini}</span>}</button>
        ))}
      </div>

      {tab === "dashboard" && <Dashboard conns={conns} exposure={exposure.data} metrics={metrics.data} modules={mods} logs={logs.data || []} bwHist={bwHist} bw={bandwidth.data} scoreHist={scoreHist} top={top.data || []} thrStatus={thrStatus.data} thrProcs={thrProcs.data || []} trace={trace.data} beaconing={beaconing.data || []} sevFilter={sevFilter} onGo={setTab} onSelect={selectEndpoint} />}
      {tab === "bouclier" && <Bouclier conns={conns} active={sevFilter} setActive={setSevFilter} />}
      {tab === "carte" && <CarteReseau conns={conns} listeners={listeners.data || []} trace={trace.data} traceLabel={traceLabel} geoPoints={geoPoints.data || null} onRun={runTrace} onSelect={selectEndpoint} />}
      {tab === "remediation" && <Remediation conns={conns} />}
      {tab === "conformite" && <Grc />}
      {tab === "recon" && <Recon lan={lan.data} scan={scan.data} procvuln={procvuln.data} onScan={(t, m, b) => api.scanRun(t, m, b)} />}
      {tab === "offensif" && <Offensif airgapped={airgapped} wifi={wifi.data} />}
      {tab === "soc" && <Soc hids={hids.data} defender={defender.data} />}
      {tab === "sante" && <Health report={healthRep.data} updater={updater.data} />}
      {tab === "connecteurs" && <Connecteurs airgapped={airgapped} connectors={connectors.data || []} onRefresh={() => api.connectors().then((d) => (connectors.data = d)).catch(() => {})} />}
      {tab === "diagnostic" && <Diagnostic logs={logs.data || []} history={history.data || []} timeline={timeline.data || []} beaconing={beaconing.data || []} config={config.data} />}

      <div className="foot">RED SHIELD · Network Shield &amp; Recon · analyses 100 % locales, données réelles (aucune inventée)</div>

      {showAirgapHelp && (
        <div onClick={() => setShowAirgapHelp(false)} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)", zIndex: 200, display: "grid", placeItems: "center", padding: 20 }}>
          <div className="card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 540, backdropFilter: "blur(20px)" }}>
            <div className="card-h"><h2>🛡️ Le mode « Air-gapped » en clair</h2></div>
            <div style={{ padding: 18, fontSize: 13.5, lineHeight: 1.65, color: "var(--soft)" }}>
              <p style={{ margin: "0 0 10px" }}><b style={{ color: "var(--ink)" }}>« Air-gapped »</b> veut dire « isolé du réseau ». Quand le mode est <b style={{ color: "var(--safe)" }}>ACTIF</b> (par défaut), RED Shield <b style={{ color: "var(--ink)" }}>n'envoie aucune de tes données vers Internet</b> : toutes les analyses restent <b>sur ta machine</b>. Aucune IP, aucun mail, aucun résultat de scan n'est transmis à un service extérieur.</p>
              <p style={{ margin: "0 0 10px" }}><b style={{ color: "var(--ink)" }}>Pourquoi ?</b> Pour garantir la confidentialité — indispensable en mission, où l'on n'a souvent pas le droit d'envoyer des infos sur une cible à des tiers.</p>
              <p style={{ margin: "0 0 10px" }}><b style={{ color: "var(--ink)" }}>Quand le désactiver ?</b> Uniquement pour enrichir une analyse via un service en ligne (réputation d'IP VirusTotal, OSINT, LLM distant…). Il faut alors ajouter tes clés dans l'onglet <b>Connecteurs</b>. Un LLM <b>Ollama local</b> fonctionne même en air-gapped.</p>
              <p style={{ margin: "0 0 14px", color: "var(--accent)" }}>👉 En cas de doute, laisse-le <b>ACTIF</b> (sécurité maximale).</p>
              <button className="btn" onClick={() => setShowAirgapHelp(false)}>Compris</button>
            </div>
          </div>
        </div>
      )}
    </div>
    </>
  );
}
