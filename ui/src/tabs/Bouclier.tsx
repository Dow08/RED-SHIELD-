import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";

/* ============ BOUCLIER ============ */
export default function Bouclier({ conns, active, setActive }: { conns: ScoredConnection[]; active: Record<Severity, boolean>; setActive: (v: Record<Severity, boolean>) => void }) {
  const [cols, setCols] = useState<Record<string, boolean>>({ risk: true, geo: true, port: true, dns: true });
  const [q, setQ] = useState("");
  const [desc, setDesc] = useState(true);
  const [ddOpen, setDdOpen] = useState(false);

  const list = useMemo(() => {
    let l = conns.filter((c) => active[c.severity]);
    if (q) l = l.filter((c) => (c.process + c.remote_addr + (c.remote_dns || "")).toLowerCase().includes(q.toLowerCase()));
    return [...l].sort((a, b) => (desc ? b.risk - a.risk : a.risk - b.risk));
  }, [conns, active, q, desc]);

  return (
    <Card title="Connexions actives" right={`${list.length}/${conns.length} · temps réel`}>
      <div className="note">Connexions de ta machine, notées en temps réel (process → destination, risque, MITRE). Filtre, trie, exporte le rapport ; la coupure se fait depuis <b>Remédiation</b>.</div>
      <div className="toolbar">
        <div className="dd">
          <button className="dd-btn" onClick={() => setDdOpen((o) => !o)}>▾ Filtres</button>
          {ddOpen && (
            <div className="dd-panel">
              <div className="dd-grp">Sévérité</div>
              {(Object.keys(SEV_META) as Severity[]).map((s) => (
                <label className="dd-item" key={s}>
                  <input type="checkbox" checked={active[s]} onChange={(e) => setActive({ ...active, [s]: e.target.checked })} />
                  <span className={`d ${SEV_META[s].c}`}></span>{SEV_META[s].l}
                </label>
              ))}
              <div className="dd-grp">Colonnes</div>
              {[["risk", "Risque"], ["port", "Port"], ["dns", "DNS distant"]].map(([k, label]) => (
                <label className="dd-item" key={k}>
                  <input type="checkbox" checked={cols[k]} onChange={(e) => setCols({ ...cols, [k]: e.target.checked })} />
                  {label}
                </label>
              ))}
            </div>
          )}
        </div>
        <div className="search">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
          <input placeholder="process / ip / dns…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>
      <div className="tscroll">
        <table>
          <thead>
            <tr>
              <th>Process</th>
              {cols.dns && <th>DNS distant</th>}
              <th>Distant</th>
              {cols.port && <th>Port</th>}
              {cols.risk && <th onClick={() => setDesc((d) => !d)}>Risque {desc ? "▼" : "▲"}</th>}
              <th>État</th>
            </tr>
          </thead>
          <tbody>
            {list.map((c, i) => <ConnRow key={i} c={c} showCols={cols} />)}
            {list.length === 0 && <tr><td colSpan={6} className="empty">Aucune connexion ne correspond aux filtres</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="actions">
        <a className="btn" href={api.reportUrl} download>Exporter le rapport (Markdown)</a>
        <button className="btn ghost" onClick={() => api.snapshot()}>Enregistrer un instantané</button>
      </div>
    </Card>
  );
}
