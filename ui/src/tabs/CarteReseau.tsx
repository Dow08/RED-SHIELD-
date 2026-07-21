import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";

export default function CarteReseau({ conns, listeners, trace, traceLabel, geoPoints, onRun, onSelect }: { conns: ScoredConnection[]; listeners: import("../api").Listener[]; trace: TraceResult | null; traceLabel: string; geoPoints: import("../api").GeoView | null; onRun: (t: string) => void; onSelect: (ip: string) => void }) {
  const [view, setView] = useState("sortant");
  const [target, setTarget] = useState("1.1.1.1");
  const labels: Record<string, string> = { sortant: "Sortant", entrant: "Entrant", local: "Local (LAN)", tous: "Tous" };
  const inboundCount = conns.filter((c) => c.direction === "entrant").length;
  const exposed = listeners.filter((l) => l.exposed);
  const viewHint: Record<string, string> = {
    sortant: "Connexions initiées par cette machine vers l'extérieur.",
    entrant: inboundCount > 0 ? `${inboundCount} connexion(s) entrante(s) active(s) vers un port en écoute.` : "Aucune connexion entrante active — chemin affiché jusqu'à l'IP publique de la box.",
    local: "Échanges avec les appareils du réseau local (LAN).",
    tous: "Toutes les connexions actives, entrantes et sortantes.",
  };
  return (
    <>
      <Card title="Carte réseau" resizable right={<span className="seg">{Object.keys(labels).map((v) => <button key={v} className={view === v ? "on" : ""} onClick={() => setView(v)}>{labels[v]}{v === "entrant" && inboundCount > 0 ? ` (${inboundCount})` : ""}</button>)}</span>}>
        <div className="stage"><NetworkGraph conns={conns} view={view} onSelect={onSelect} trace={trace} /></div>
        <div className="disc" style={{ paddingBottom: 0 }}>{viewHint[view]}</div>
        <div className="legend">
          <span><span className="d" style={{ background: "var(--accent)" }}></span>Cet appareil</span>
          <span><span className="d" style={{ background: "var(--safe)" }}></span>Sain</span>
          <span><span className="d" style={{ background: "var(--watch)" }}></span>À surveiller</span>
          <span><span className="d" style={{ background: "var(--crit)" }}></span>Suspect / critique</span>
          <span style={{ marginLeft: "auto", color: "var(--faint)" }}>Molette = zoom · glisser = déplacer · survol = détail · Vue : <b style={{ color: "var(--accent)" }}>{labels[view]}</b></span>
        </div>
      </Card>
      <div style={{ height: 12 }} />
      <Card title="Ports en écoute — surface d'exposition entrante" right={<span><b style={{ color: exposed.length ? "var(--watch)" : "var(--safe)" }}>{exposed.length}</b> exposé(s) / {listeners.length}</span>}>
        <div className="note">Chaque port en écoute est une <b>porte d'entrée potentielle</b>. « Exposé » = lié à <span className="mono">0.0.0.0/::</span> (joignable depuis le réseau) ; « local » = <span className="mono">127.0.0.1</span> (inaccessible de l'extérieur).</div>
        {listeners.length === 0 ? <div className="empty">Aucun port en écoute détecté.</div> : (
          <div className="tscroll">
            <table>
              <thead><tr><th>Port</th><th>Proto</th><th>Process</th><th>PID</th><th>Liaison</th><th>Exposition</th><th>Action</th></tr></thead>
              <tbody>
                {[...listeners].sort((a, b) => Number(b.exposed) - Number(a.exposed) || a.port - b.port).map((l, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ fontWeight: 700 }}>{l.port}</td>
                    <td className="mono muted">{l.protocol}</td>
                    <td><span className="proc">{l.process}</span></td>
                    <td className="pid mono">{l.pid ?? "—"}</td>
                    <td className="mono muted">{l.addr}</td>
                    <td>{l.exposed
                      ? <span className="sev w"><span className="d"></span>Exposé</span>
                      : <span className="sev s"><span className="d"></span>Local</span>}</td>
                    <td>{l.exposed ? <ClosePortButton port={l.port} protocol={l.protocol} /> : <span className="muted">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <div style={{ height: 12 }} />
      <Card title="Tracé de connexion — carte du monde" resizable right={<><div className="search" style={{ marginRight: 8 }}><input value={target} onChange={(e) => setTarget(e.target.value)} style={{ width: 120 }} /></div><button className="btn ghost" onClick={() => onRun(target)}>Lancer le tracé</button></>}>
        <div className="stage"><TraceMap trace={trace} destLabel={traceLabel} points={geoPoints?.points} home={geoPoints?.home ?? null} onSelect={onSelect} /></div>
        <div className="legend" style={{ paddingBottom: 0 }}>
          <span><span className="d" style={{ background: "var(--accent)" }}></span>Ta sortie réseau (box)</span>
          <span><span className="d" style={{ background: "var(--accent2)" }}></span>Flux sortant</span>
          <span><span className="d" style={{ background: "var(--watch)" }}></span>Flux entrant</span>
          <span><span className="d" style={{ background: "var(--crit)" }}></span>Suspect / critique</span>
          <span style={{ color: "var(--faint)" }}>· {geoPoints?.points.length ?? 0} connexion(s) · <b style={{ color: "var(--accent)" }}>survole</b> (IP/DNS/pays) ou <b style={{ color: "var(--accent)" }}>clique</b> un point</span>
        </div>
        <div className="disc">
          Molette = zoom · glisser = déplacer.{" "}
          {trace?.vpn_active && <b style={{ color: "var(--safe)" }}>VPN {trace.vpn_adapter} · </b>}
          {trace?.public_ip && `IP publique ${trace.public_ip}. `}
          {trace && !trace.geo_available && "⚠️ base GeoIP absente (dbip-city-lite.mmdb)."}
        </div>
        {trace && trace.hops.length > 0 && (
          <div className="tscroll">
            <table>
              <thead><tr><th>#</th><th>IP</th><th>Hôte (DNS)</th><th>Localisation</th></tr></thead>
              <tbody>
                {trace.hops.map((h) => (
                  <tr key={h.hop}>
                    <td className="mono">{h.hop}</td>
                    <td className="mono muted">{h.ip}</td>
                    <td className="muted">{h.dns || "—"}</td>
                    <td className="muted">{[h.city, h.country].filter(Boolean).join(", ") || (h.private ? "réseau local" : "—")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
