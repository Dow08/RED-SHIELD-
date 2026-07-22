import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";

function ScanAiButton({ scan }: { scan: ScanResult }) {
  const [res, setRes] = useState<LlmResult | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true); setRes(null);
    const text = scan.hosts.map((h) => `Hôte ${h.ip} (${h.os || "?"}):\n` + h.ports.map((p) => `  ${p.port}/${p.protocol} ${p.service} ${p.product} ${p.version}${p.cves.length ? " CVE:" + p.cves.map((c) => c.cve).join(",") : ""}`).join("\n")).join("\n");
    try { setRes(await api.llmAnalyze(text, "résultat de scan nmap")); } catch { setRes({ ok: false, error: "moteur injoignable" }); }
    setBusy(false);
  };
  return (
    <div style={{ padding: "10px 16px" }}>
      <button className="btn" onClick={run} disabled={busy}>{busy ? "Analyse IA…" : "🤖 Analyser le scan avec l'IA"}</button>
      {res && !res.ok && <div className="disc" style={{ paddingTop: 8, color: "var(--watch)" }}>{res.error} (configure le connecteur LLM)</div>}
      {res?.ok && <div className="rbody" style={{ whiteSpace: "pre-wrap", marginTop: 8, padding: 12, background: "var(--card-solid)", borderRadius: 8 }}>{res.analysis}</div>}
    </div>
  );
}

/* ============ RECON ============ */
export default function Recon({ lan, scan, procvuln, onScan }: { lan: LanDevice[] | null; scan: ScanResult | null; procvuln: import("../api").ProcVulnResult | null; onScan: (t: string, m: string, bypass?: boolean) => void }) {
  const devices = lan || [];
  const pv = procvuln;
  const withCve = (pv?.apps || []).filter((a) => a.cves.length > 0);
  useEffect(() => { api.procvulnRun().catch(() => {}); }, []);
  const [target, setTarget] = useState("scanme.nmap.org");
  const [mode, setMode] = useState("discret");
  const [help, setHelp] = useState("");
  const [perimeter, setPerimeter] = useState(() => { try { return localStorage.getItem("rs.mission.perimeter") || ""; } catch { return ""; } });
  const savePerimeter = (v: string) => { setPerimeter(v); try { localStorage.setItem("rs.mission.perimeter", v); } catch { /* */ } };
  const inScope = (t: string) => {
    const p = perimeter.trim(); if (!p) return true;   // pas de périmètre déclaré → pas de garde-fou
    return p.split(/[\s,;]+/).filter(Boolean).some((s) => t === s || t.includes(s) || s.includes(t));
  };
  const launch = () => {
    if (!inScope(target)) {
      if (!window.confirm(`⚠️ Cible HORS du périmètre de mission déclaré :\n\n${target}\n\nPérimètre autorisé : ${perimeter}\n\nLancer quand même ? L'action sera JOURNALISÉE dans la piste d'audit.`)) return;
      onScan(target, mode, true);
    } else {
      onScan(target, mode, false);
    }
  };
  const PRESETS = [
    { label: "Ma machine", target: "127.0.0.1", mode: "discret", help: "Scanne ta propre machine (services en écoute). Sans risque, toujours autorisé — idéal pour un premier test." },
    { label: "Réseau local /24", target: "192.168.1.0/24", mode: "discret", help: "Balaye ton sous-réseau local (top 100 ports) pour découvrir les hôtes et services exposés." },
    { label: "scanme.nmap.org", target: "scanme.nmap.org", mode: "discret", help: "Cible de test officielle de nmap, explicitement autorisée pour l'entraînement." },
    { label: "Scan complet 1-1024", target: "", mode: "complet", help: "Ports système 1-1024 + détection de version sur la cible courante. Plus long mais plus exhaustif." },
  ];
  return (
    <div className="grid">
      <div className="col">
        <Card title="Scan hôte (nmap + CVE)" right={scan && scan.nmap_available === false ? "nmap absent" : "prêt"}>
          <div className="note">Cibles <b>autorisées uniquement</b> (propriété ou autorisation écrite). Chaque service détecté est croisé avec <b>NVD en ligne</b> (source officielle, à jour) → lien NVD. Nécessite <b>air-gapped OFF</b>.</div>
          <div className="toolbar" style={{ flexWrap: "wrap" }}>
            <span className="lbl" title="Cible(s) autorisée(s) : IP/CIDR/hôtes séparés par des espaces. Vide = pas de garde-fou.">🎯 Périmètre</span>
            <input className="key" style={{ letterSpacing: 0, width: 260 }} value={perimeter} onChange={(e) => savePerimeter(e.target.value)} placeholder="Cible(s) autorisée(s) — ex. 192.168.1.0/24 scanme.nmap.org" />
            <span className="muted" style={{ fontSize: 11 }}>{perimeter.trim() ? (inScope(target) ? "✅ cible dans le périmètre" : "⚠️ cible hors périmètre") : "aucun garde-fou"}</span>
          </div>
          <div className="toolbar">
            <input className="key" style={{ letterSpacing: 0, width: 220 }} value={target} onChange={(e) => setTarget(e.target.value)} placeholder="IP / CIDR / hôte" />
            <span className="seg">
              <button className={mode === "discret" ? "on" : ""} onClick={() => setMode("discret")}>Discret</button>
              <button className={mode === "complet" ? "on" : ""} onClick={() => setMode("complet")}>Complet</button>
            </span>
            <button className="btn" disabled={!target || scan?.running || scan?.nmap_available === false} onClick={launch}>{scan?.running ? "Scan en cours…" : "Lancer le scan"}</button>
          </div>
          <div style={{ padding: "0 14px 8px", display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            <span className="lbl">Presets</span>
            {PRESETS.map((p) => (
              <button key={p.label} className="chip" style={{ cursor: "pointer" }} onClick={() => { if (p.target) setTarget(p.target); setMode(p.mode); setHelp(p.help); }}>{p.label}</button>
            ))}
          </div>
          {help && <div className="disc" style={{ padding: "0 14px 10px" }}>ℹ️ {help}</div>}
          {scan?.nmap_available === false && <div className="empty">nmap non installé — installe-le puis relance (ex. winget install Insecure.Nmap).</div>}
          {scan?.error && <div className="empty">Erreur : {scan.error}</div>}
          {(scan?.hosts || []).map((h) => (
            <div key={h.ip}>
              <div className="row"><span className="nm mono">{h.ip}</span><span className="ds">{[h.hostname, h.os].filter(Boolean).join(" · ")}</span></div>
              {h.ports.map((p) => (
                <div key={p.port} style={{ borderBottom: "1px solid var(--hair)", padding: "10px 16px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                    <span className="nm mono" style={{ minWidth: 70 }}>{p.port}/{p.protocol}</span>
                    <span className="ds">{[p.service, p.product, p.version].filter(Boolean).join(" ")}</span>
                    <span className="badge" style={{ borderColor: "var(--accent)", color: "var(--accent)" }}>{p.osi_label}</span>
                    <span style={{ marginLeft: "auto", display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {p.cves.length === 0 ? <span className="stt on">aucune CVE (NVD)</span> : p.cves.map((c) => <a key={c.cve} className="badge m" href={c.url} target="_blank" rel="noopener">{c.cve} · {c.cvss} ↗</a>)}
                    </span>
                  </div>
                  {p.compliance.length > 0 && (
                    <div className="rmeta" style={{ margin: "8px 0 0" }}>
                      {p.compliance.map((c, i) => <span key={i} className="badge" title={c.note}>{c.framework} {c.control} — {c.note}</span>)}
                    </div>
                  )}
                  {p.suggestions.length > 0 && (
                    <div className="disc" style={{ padding: "6px 0 0" }}>⚔️ Pistes : {p.suggestions.join(" · ")}</div>
                  )}
                </div>
              ))}
            </div>
          ))}
          {scan && !scan.running && scan.hosts.length === 0 && scan.target && !scan.error && <div className="empty">Aucun port ouvert détecté sur {scan.target}.</div>}
          {scan && scan.hosts.length > 0 && <ScanAiButton scan={scan} />}
        </Card>
      </div>
      <div className="col">
        <Card title="Découverte LAN" right={`${devices.length} appareils`}>
          <div className="note">Voisins du réseau local (table ARP, passif). Un appareil au <b>fabricant inconnu</b> mérite vérification.</div>
          {devices.map((d) => (
            <div className="row" key={d.mac}>
              <span className="nm mono">{d.ip}</span>
              <span className="ds mono">{d.mac}</span>
              <span className="stt" style={{ marginLeft: "auto", color: d.vendor ? "var(--safe)" : "var(--watch)", borderColor: d.vendor ? "var(--card-b)" : "var(--watch)" }}>{d.vendor || "fabricant inconnu"}</span>
            </div>
          ))}
          {devices.length === 0 && <div className="empty">Aucun voisin dans le cache ARP (ping le réseau pour le peupler).</div>}
        </Card>
        <Card title="CVE des applications locales" right={<><span style={{ marginRight: 8, color: withCve.length ? "var(--crit)" : "var(--safe)" }}>{withCve.length} vulnérable(s)</span><button className="btn ghost" style={{ padding: "5px 10px" }} onClick={() => api.procvulnRun()}>Analyser</button></>}>
          <div className="note">Croise le <b>produit + version réels</b> de tes applications avec connexions (métadonnées de l'exécutable) contre <b>NVD en ligne</b> (air-gapped OFF). Factuel : « aucune CVE » = rien remonté par NVD, pas une garantie d'absence de faille.</div>
          {pv?.note && <div className="disc" style={{ padding: "6px 16px" }}>ℹ️ {pv.note}</div>}
          {!pv || pv.running ? <div className="empty">{pv?.running ? "Analyse des applications…" : "Chargement…"}</div>
            : (pv.apps.length === 0 ? <div className="empty">Aucune application avec connexion détectée.</div>
              : (
                <>
                  {withCve.map((a, i) => (
                    <div className="rcard" key={i} style={{ borderLeft: "3px solid var(--crit)" }}>
                      <div className="rhead"><span className="pr c">CVE</span><span className="rtitle" style={{ fontSize: 13 }}>{a.process} <span className="muted" style={{ fontWeight: 400 }}>{a.product} {a.version}</span></span></div>
                      <div className="rmeta">{a.cves.map((c) => <a key={c.cve} className="badge m" href={c.url} target="_blank" rel="noopener">{c.cve} · {c.cvss} ↗</a>)}</div>
                    </div>
                  ))}
                  {withCve.length === 0 && <div className="disc" style={{ color: "var(--safe)", padding: "8px 16px" }}>Aucune CVE remontée par NVD pour les {pv.scanned} application(s) analysée(s) ✅</div>}
                  <div className="disc" style={{ padding: "6px 16px 12px" }}>{pv.scanned} application(s) analysée(s) · {withCve.length} avec CVE connue.</div>
                </>
              ))}
        </Card>
      </div>
    </div>
  );
}

/* ============ OFFENSIF (cracker de hash) ============ */
