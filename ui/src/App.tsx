import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "./api";
import { usePolling } from "./hooks";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "./viz";

const SEV_META: Record<Severity, { c: string; l: string }> = {
  safe: { c: "s", l: "Sain" },
  watch: { c: "w", l: "À surveiller" },
  suspect: { c: "p", l: "Suspect" },
  crit: { c: "c", l: "Critique" },
};
const bandColor = (band: string) => (band === "critique" ? "var(--crit)" : band === "elevee" ? "var(--watch)" : "var(--safe)");
const bandLabel = (band: string) => (band === "critique" ? "Exposition critique" : band === "elevee" ? "Exposition élevée" : "Exposition faible");
const fr = (n: number) => n.toFixed(1).replace(".", ",");

function Card({ title, right, children, className }: { title: string; right?: React.ReactNode; children: React.ReactNode; className?: string }) {
  const [collapsed, setCollapsed] = useState(false);
  return (
    <div className={`card ${collapsed ? "collapsed " : ""}${className || ""}`}>
      <div className="card-h">
        <h2>{title}</h2>
        {right && <span className="r">{right}</span>}
        <button className="chev" aria-label="Réduire / agrandir" onClick={() => setCollapsed((c) => !c)}>
          {collapsed ? "▸" : "▾"}
        </button>
      </div>
      {children}
    </div>
  );
}

function ReputationButton({ ip }: { ip: string }) {
  const [res, setRes] = useState<IntelResult | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => { setBusy(true); try { setRes(await api.intelIp(ip)); } catch { setRes(null); } setBusy(false); };
  return (
    <span style={{ display: "inline-flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
      <button className="btn ghost" onClick={run} disabled={busy}>{busy ? "…" : "Réputation"}</button>
      {res && !res.available && <span className="muted" style={{ fontSize: 11 }}>{res.reason}</span>}
      {res?.available && res.sources.map((s: any, i: number) => (
        <span key={i} className="badge" style={{ borderColor: s.malicious || s.score ? "var(--crit)" : "var(--card-b)" }}>
          {s.source}: {s.error ? s.error : s.malicious !== undefined ? `${s.malicious} malveillant` : s.score !== undefined ? `score ${s.score}` : "ok"}
        </span>
      ))}
    </span>
  );
}

function CutButton({ ip }: { ip: string }) {
  const [stage, setStage] = useState<"idle" | "confirm" | "done">("idle");
  const [msg, setMsg] = useState("");
  const dry = async () => { try { const r = await api.firewallBlock(ip, true); setMsg(r.command || ""); setStage("confirm"); } catch { setMsg("moteur injoignable"); } };
  const apply = async () => { try { const r = await api.firewallBlock(ip, false); setMsg(r.ok ? "Connexion bloquée ✅" : (r.error || "échec")); setStage("done"); } catch { setMsg("échec"); } };
  const undo = async () => { try { await api.firewallUnblock(ip); setMsg("Débloqué"); setStage("idle"); } catch { setMsg("échec"); } };
  if (stage === "idle") return <button className="btn ghost" onClick={dry}>Couper (dry-run)</button>;
  if (stage === "confirm") return (
    <span style={{ display: "inline-flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
      <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>{msg}</span>
      <button className="btn" onClick={apply}>Confirmer le blocage</button>
      <button className="btn ghost" onClick={() => setStage("idle")}>Annuler</button>
    </span>
  );
  return <span style={{ display: "inline-flex", gap: 8, alignItems: "center" }}><span style={{ color: "var(--safe)", fontSize: 12 }}>{msg}</span><button className="btn ghost" onClick={undo}>Débloquer (undo)</button></span>;
}

function Reorderable({ ids, render, storageKey }: { ids: string[]; render: (id: string) => React.ReactNode; storageKey: string }) {
  const [order, setOrder] = useState<string[]>(() => {
    try { const saved = JSON.parse(localStorage.getItem(storageKey) || "[]"); if (Array.isArray(saved) && saved.length) return [...saved.filter((s: string) => ids.includes(s)), ...ids.filter((i) => !saved.includes(i))]; } catch { /* noop */ }
    return ids;
  });
  const drag = useRef<string | null>(null);
  const move = (from: string, to: string) => {
    if (from === to) return;
    setOrder((o) => { const a = [...o]; const fi = a.indexOf(from), ti = a.indexOf(to); a.splice(fi, 1); a.splice(ti, 0, from); localStorage.setItem(storageKey, JSON.stringify(a)); return a; });
  };
  return (
    <>
      {order.map((id) => (
        <div key={id} draggable onDragStart={() => (drag.current = id)} onDragOver={(e) => e.preventDefault()} onDrop={() => drag.current && move(drag.current, id)} style={{ cursor: "grab" }}>
          {render(id)}
        </div>
      ))}
    </>
  );
}

function Gauge({ score, band }: { score: number; band: string }) {
  const circ = 314;
  const off = circ * (1 - score / 100);
  return (
    <div className="gauge">
      <svg viewBox="0 0 118 118" width="118" height="118">
        <circle cx="59" cy="59" r="50" fill="none" stroke="#1c2230" strokeWidth="10" />
        <circle cx="59" cy="59" r="50" fill="none" stroke={bandColor(band)} strokeWidth="10" strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={off} transform="rotate(-90 59 59)" />
      </svg>
      <div className="v">
        <div className="n" style={{ color: bandColor(band) }}>{score}</div>
        <div className="d">/ 100</div>
      </div>
    </div>
  );
}

function ConnRow({ c, showCols }: { c: ScoredConnection; showCols: Record<string, boolean> }) {
  const m = SEV_META[c.severity];
  const rc = c.severity === "safe" ? "var(--safe)" : c.severity === "watch" ? "var(--watch)" : "var(--crit)";
  return (
    <tr>
      <td>
        <span className="proc">{c.process}</span> <span className="pid mono">{c.pid}</span>
        {c.mitre.map((t) => <span key={t.id} className="mtag">MITRE {t.id}</span>)}
        {c.exe && c.exe.toLowerCase().includes("temp") && <div className="path">{c.exe}</div>}
      </td>
      {showCols.dns && <td>{c.remote_dns ? <span className="muted">{c.remote_dns}</span> : c.dns_resolved ? <span className="nodns">— aucun —</span> : <span className="muted">…</span>}</td>}
      <td className="mono muted">{c.remote_addr}</td>
      {showCols.port && <td className="mono">{c.port}</td>}
      {showCols.risk && <td><span className="risk" style={{ color: rc }}>{c.risk}</span></td>}
      <td><span className={`sev ${m.c}`}><span className="d"></span>{m.l}</span></td>
    </tr>
  );
}

/* ============ DASHBOARD ============ */
function Dashboard({ conns, exposure, modules, logs, bwHist, scoreHist, top, trace, beaconing, onGo, onSelect }: any) {
  const risky = (conns as ScoredConnection[]).filter((c) => c.severity === "suspect" || c.severity === "crit").sort((a, b) => b.risk - a.risk);
  const topConns = [...(conns as ScoredConnection[])].sort((a, b) => b.risk - a.risk).slice(0, 4);
  const [sub, setSub] = useState<"debit" | "top">("debit");
  const counts = exposure?.counts || { safe: 0, watch: 0, suspect: 0, crit: 0 };
  const maxTalk = Math.max(1, ...top.map((t: any) => t.connections));
  return (
    <div className="grid">
      <div className="col">
        <div className="bento">
          <Card title="Score d'exposition" right="temps réel" className="span2 row2">
            <div className="scardbody">
              <Gauge score={exposure?.score ?? 0} band={exposure?.band ?? "faible"} />
              <div>
                <div className="band-lbl" style={{ color: bandColor(exposure?.band ?? "faible") }}>{bandLabel(exposure?.band ?? "faible")}</div>
                <div className="chips">
                  <span className="chip g">{counts.safe} saines</span>
                  <span className="chip w">{counts.watch} à surveiller</span>
                  <span className="chip r">{counts.suspect + counts.crit} suspectes</span>
                </div>
                <div style={{ marginTop: 10 }}><a onClick={() => onGo("remediation")}>{risky.length} action(s) prioritaire(s) →</a></div>
              </div>
            </div>
            <div style={{ padding: "0 16px 14px" }}><Sparkline values={scoreHist} color="--watch" /></div>
          </Card>

          <Card title="Bande passante" right={`${fr(bwHist.at(-1)?.d ?? 0)}↓ / ${fr(bwHist.at(-1)?.u ?? 0)}↑ Mo/s`} className="span2 row2">
            <div className="subtabs">
              <button className={`subtab ${sub === "debit" ? "on" : ""}`} onClick={() => setSub("debit")}>Débit</button>
              <button className={`subtab ${sub === "top" ? "on" : ""}`} onClick={() => setSub("top")}>Top process</button>
            </div>
            {sub === "debit" ? (
              <div className="stage"><BandwidthChart history={bwHist} /></div>
            ) : (
              <div className="bars">
                {top.length === 0 && <div className="empty">Aucune donnée</div>}
                {top.map((t: any) => (
                  <div className="barrow" key={t.pid}>
                    <span className="bn">{t.process}</span>
                    <span className="track"><span className="fill" style={{ width: `${(t.connections / maxTalk) * 100}%` }} /></span>
                    <span className="bv">{t.connections} conn.</span>
                  </div>
                ))}
                <div className="disc">Top par nombre de connexions (débit par process = Jalon ultérieur).</div>
              </div>
            )}
          </Card>
        </div>

        <Card title="Connexions — aperçu" right={<a onClick={() => onGo("bouclier")}>{`tout voir (${conns.length}) →`}</a>}>
          <div className="tscroll">
            <table>
              <thead><tr><th>Process</th><th>Distant</th><th>Risque</th><th>État</th></tr></thead>
              <tbody>
                {topConns.map((c, i) => (
                  <tr key={i}>
                    <td><span className="proc">{c.process}</span> <span className="pid mono">{c.pid}</span></td>
                    <td className="mono muted">{c.remote_dns || c.remote_addr}</td>
                    <td><span className="risk" style={{ color: c.severity === "safe" ? "var(--safe)" : c.severity === "watch" ? "var(--watch)" : "var(--crit)" }}>{c.risk}</span></td>
                    <td><span className={`sev ${SEV_META[c.severity].c}`}><span className="d"></span>{SEV_META[c.severity].l}</span></td>
                  </tr>
                ))}
                {topConns.length === 0 && <tr><td colSpan={4} className="empty">Aucune connexion active</td></tr>}
              </tbody>
            </table>
          </div>
        </Card>

        <Card title="Carte réseau (aperçu)" right={<a onClick={() => onGo("carte")}>ouvrir →</a>}>
          <div className="stage"><NetworkGraph conns={conns} view="tous" onSelect={onSelect} /></div>
          <div className="disc">Clique une IP pour tracer son chemin sur la carte du monde.</div>
        </Card>
      </div>

      <div className="col">
        <div className="disc" style={{ padding: "0 2px 2px" }}>↕ Glisse les cartes pour réorganiser ton tableau de bord.</div>
        <Reorderable
          storageKey="red-dash-side"
          ids={["trace", "vue", "modules", "remed", "journal"]}
          render={(id) => ({
            trace: (
              <Card title="Tracé de connexion" right={<a onClick={() => onGo("carte")}>carte →</a>}>
                {trace && (trace.public_ip || trace.hops?.length) ? (
                  <>
                    <div className="recap"><span className="ic">🌍</span>IP publique<span className="v mono">{trace.public_ip || "—"}</span></div>
                    <div className="recap"><span className="ic">🔒</span>VPN<span className="v" style={{ color: trace.vpn_active ? "var(--safe)" : "var(--faint)" }}>{trace.vpn_active ? (trace.vpn_adapter || "actif") : "inactif"}</span></div>
                    <div className="recap"><span className="ic">🛰️</span>Sauts<span className="v">{trace.hops.length}</span></div>
                    <div className="disc">{trace.hops.filter((h: any) => h.city || h.country).map((h: any) => h.city || h.country).slice(0, 5).join(" → ") || "chemin en cours de géolocalisation"}</div>
                    <div className="stage" style={{ marginTop: 8 }}><TraceMap trace={trace} /></div>
                  </>
                ) : <div className="empty">{trace?.running ? "Traceroute en cours…" : "Ouvre l'onglet Carte réseau pour lancer un tracé"}</div>}
              </Card>
            ),
            vue: (
              <Card title="Vue d'ensemble">
                <div className="recap"><span className="ic">🛰️</span>Connexions actives<span className="v">{conns.length}</span></div>
                <div className="recap"><span className="ic">🚨</span>Alertes critiques<span className="v" style={{ color: "var(--crit)" }}>{counts.crit}</span></div>
                <div className="recap"><span className="ic">⚠️</span>Suspectes<span className="v" style={{ color: "var(--crit)" }}>{counts.suspect}</span></div>
                <div className="recap"><span className="ic">📡</span>Beaconing C2<span className="v" style={{ color: beaconing?.length ? "var(--crit)" : "var(--faint)" }}>{beaconing?.length || 0}</span></div>
                <div className="recap"><span className="ic">🌐</span>Endpoints distincts<span className="v">{new Set((conns as ScoredConnection[]).map((c) => c.remote_addr)).size}</span></div>
                <div className="recap"><span className="ic">💾</span>Budget journal<span className="v">≤ 1 Go</span></div>
              </Card>
            ),
            modules: (
              <Card title="Modules" right={String(modules.length)}>
                {modules.map((m: any) => (
                  <div className="mod" key={m.name}>
                    <span className={`st2 ${m.status === "active" ? "on" : m.status === "error" ? "err" : "off"}`}></span>
                    {m.description || m.name}
                    <span className={`stl ${m.status === "active" ? "on" : m.status === "error" ? "err" : "off"}`}>{m.status}</span>
                  </div>
                ))}
              </Card>
            ),
            remed: (
              <Card title="Top remédiations" right={<a onClick={() => onGo("remediation")}>tout voir →</a>}>
                {risky.slice(0, 3).map((c, i) => (
                  <div className="rcard" key={i}>
                    <div className="rhead"><span className={`pr ${c.severity === "crit" ? "c" : "w"}`}>{c.severity === "crit" ? "CRITIQUE" : "HAUTE"}</span><span className="rtitle" style={{ fontSize: 12.5 }}>{c.process} → {c.remote_addr}:{c.port}</span></div>
                    {c.mitre[0] && <div className="rmeta"><span className="badge m">{c.mitre[0].id}</span></div>}
                  </div>
                ))}
                {risky.length === 0 && <div className="empty">Aucune connexion suspecte. Machine saine ✅</div>}
              </Card>
            ),
            journal: (
              <Card title="Journal récent" right={<a onClick={() => onGo("diagnostic")}>ouvrir →</a>}>
                {logs.slice(-4).reverse().map((l: any, i: number) => (
                  <div className="log" key={i}><span className="ts">{l.ts.slice(11, 16)}</span><span className={`lv ${l.level}`}>{l.level.slice(0, 4).toUpperCase()}</span><span className="ms">{l.message}</span></div>
                ))}
                {logs.length === 0 && <div className="empty">Journal vide</div>}
              </Card>
            ),
          }[id])}
        />
      </div>
    </div>
  );
}

/* ============ BOUCLIER ============ */
function Bouclier({ conns }: { conns: ScoredConnection[] }) {
  const [active, setActive] = useState<Record<Severity, boolean>>({ safe: true, watch: true, suspect: true, crit: true });
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

/* ============ CARTE RÉSEAU ============ */
function CarteReseau({ conns, trace, traceLabel, onRun, onSelect }: { conns: ScoredConnection[]; trace: TraceResult | null; traceLabel: string; onRun: (t: string) => void; onSelect: (ip: string) => void }) {
  const [view, setView] = useState("sortant");
  const [target, setTarget] = useState("1.1.1.1");
  const labels: Record<string, string> = { sortant: "Sortant", entrant: "Entrant", local: "Local (LAN)", tous: "Tous" };
  return (
    <>
      <Card title="Carte réseau" right={<span className="seg">{Object.keys(labels).map((v) => <button key={v} className={view === v ? "on" : ""} onClick={() => setView(v)}>{labels[v]}</button>)}</span>}>
        <div className="stage"><NetworkGraph conns={conns} view={view} onSelect={onSelect} trace={trace} /></div>
        <div className="legend">
          <span><span className="d" style={{ background: "var(--accent)" }}></span>Cet appareil</span>
          <span><span className="d" style={{ background: "var(--safe)" }}></span>Sain</span>
          <span><span className="d" style={{ background: "var(--watch)" }}></span>À surveiller</span>
          <span><span className="d" style={{ background: "var(--crit)" }}></span>Suspect / critique</span>
          <span style={{ marginLeft: "auto", color: "var(--faint)" }}>Molette = zoom · glisser = déplacer · survol = détail · Vue : <b style={{ color: "var(--accent)" }}>{labels[view]}</b></span>
        </div>
      </Card>
      <div style={{ height: 12 }} />
      <Card title="Tracé de connexion — carte du monde" right={<><div className="search" style={{ marginRight: 8 }}><input value={target} onChange={(e) => setTarget(e.target.value)} style={{ width: 120 }} /></div><button className="btn ghost" onClick={() => onRun(target)}>Lancer le tracé</button></>}>
        <div className="stage"><TraceMap trace={trace} destLabel={traceLabel} /></div>
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

/* ============ REMÉDIATION ============ */
function Remediation({ conns }: { conns: ScoredConnection[] }) {
  const risky = conns.filter((c) => c.severity === "suspect" || c.severity === "crit").sort((a, b) => b.risk - a.risk);
  return (
    <Card title="Remédiation — diagnostic approfondi" right={`${risky.length} à traiter`}>
      {risky.length === 0 && <div className="empty">Aucune connexion suspecte au moment de l'analyse. Ta machine est saine ✅</div>}
      {risky.map((c, i) => (
        <div className="rcard" key={i}>
          <div className="rhead">
            <span className={`pr ${c.severity === "crit" ? "c" : "w"}`}>{c.severity === "crit" ? "CRITIQUE" : "HAUTE"}</span>
            <span className="rtitle">{c.process} (PID {c.pid}) → {c.remote_addr}:{c.port}</span>
          </div>
          {c.lineage && <div className="rbody"><b>Arbre :</b> <span className="mono">{c.lineage}</span></div>}
          {c.exe && <div className="rbody"><b>Exécutable :</b> <span className="mono">{c.exe}</span></div>}
          {c.reasons.length > 0 && <div className="rbody"><b>Ce que Red a vu :</b> {c.reasons.join(" ; ")}</div>}
          {c.mitre.length > 0 && (
            <div className="rmeta">{c.mitre.map((t) => <a key={t.id} className="badge m" href={t.url} target="_blank" rel="noopener">{t.id} — {t.name} ↗</a>)}</div>
          )}
          <div className="rbody"><b>Remédiation :</b> investiguer le process et sa légitimité, vérifier la persistance, couper la connexion si non autorisée.</div>
          <div className="actions" style={{ border: "none", padding: "8px 0 0" }}><CutButton ip={c.remote_addr} /><ReputationButton ip={c.remote_addr} /></div>
        </div>
      ))}
    </Card>
  );
}

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
function Recon({ wifi, lan, scan, onScan }: { wifi: { networks: WifiNet[]; message: string } | null; lan: LanDevice[] | null; scan: ScanResult | null; onScan: (t: string, m: string) => void }) {
  const nets = wifi?.networks || [];
  const devices = lan || [];
  const rc = (r: string) => (r === "crit" ? "var(--crit)" : r === "watch" ? "var(--watch)" : "var(--safe)");
  const [target, setTarget] = useState("scanme.nmap.org");
  const [mode, setMode] = useState("discret");
  const [help, setHelp] = useState("");
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
          <div className="note">Cibles <b>autorisées uniquement</b> (propriété ou autorisation écrite). Chaque service détecté est croisé avec la base CVE locale → lien NVD.</div>
          <div className="toolbar">
            <input className="key" style={{ letterSpacing: 0, width: 220 }} value={target} onChange={(e) => setTarget(e.target.value)} placeholder="IP / CIDR / hôte" />
            <span className="seg">
              <button className={mode === "discret" ? "on" : ""} onClick={() => setMode("discret")}>Discret</button>
              <button className={mode === "complet" ? "on" : ""} onClick={() => setMode("complet")}>Complet</button>
            </span>
            <button className="btn" disabled={!target || scan?.running || scan?.nmap_available === false} onClick={() => onScan(target, mode)}>{scan?.running ? "Scan en cours…" : "Lancer le scan"}</button>
          </div>
          <div style={{ padding: "0 14px 8px", display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            <span className="lbl">Presets</span>
            {PRESETS.map((p) => (
              <button key={p.label} className="chip" style={{ cursor: "pointer" }} onClick={() => { if (p.target) setTarget(p.target); setMode(p.mode); setHelp(p.help); }}>{p.label}</button>
            ))}
          </div>
          {help && <div className="disc" style={{ padding: "0 14px 10px" }}>ℹ️ {help}</div>}
          {scan?.nmap_available === false && <div className="empty">nmap non installé — voir le dossier A_INSTALLER.</div>}
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
                      {p.cves.length === 0 ? <span className="stt on">aucune CVE (base locale)</span> : p.cves.map((c) => <a key={c.cve} className="badge m" href={c.url} target="_blank" rel="noopener">{c.cve} · {c.cvss} ↗</a>)}
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
        <Card title="Audit WiFi — alternative aircrack" right="natif Windows">
          <div className="note">Audit réel des réseaux à portée (chiffrement, signal). La <b>capture/crack de handshake</b> (aircrack) reste Linux + carte monitor (Jalon 4).</div>
          {wifi?.message && <div className="empty">{wifi.message}</div>}
          {nets.map((n) => (
            <div className="row" key={n.bssid || n.ssid}>
              <span className="nm">{n.ssid}</span>
              <span className="ds">{n.auth || "?"} · canal {n.channel || "?"} · {n.signal}%</span>
              <span className="stt" style={{ marginLeft: "auto", color: rc(n.risk), borderColor: n.risk === "safe" ? "var(--card-b)" : rc(n.risk) }}>{n.reason}</span>
            </div>
          ))}
        </Card>
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
      </div>
      <div className="col">
        <Card title="WiFi offensif (aircrack)" right="Jalon 4 · Linux">
          <div className="note"><b>Linux uniquement</b> · carte monitor requise · cible autorisée obligatoire. Sous Windows, utilise l'<b>Audit WiFi</b> ci-contre.</div>
          <div className="row"><span className="nm">Interface monitor</span><span className="ds">non disponible (Windows)</span><span className="stt off" style={{ marginLeft: "auto" }}>indisponible</span></div>
        </Card>
      </div>
    </div>
  );
}

/* ============ OFFENSIF (cracker de hash) ============ */
function OsintCard({ airgapped }: { airgapped: boolean }) {
  const [domain, setDomain] = useState("");
  const [res, setRes] = useState<OsintResult | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => { setBusy(true); setRes(null); try { setRes(await api.osintSubdomains(domain.trim())); } catch { setRes({ available: true, error: "moteur injoignable", subdomains: [] }); } setBusy(false); };
  return (
    <Card title="OSINT passif — sous-domaines (crt.sh)" right="passif · air-gapped OFF">
      <div className="note">Recon <b>100 % passif</b> (aucun paquet vers la cible) via la transparence des certificats. Nécessite d'avoir <b>désactivé air-gapped</b> (pastille en haut).</div>
      <div className="toolbar">
        <input className="key" style={{ letterSpacing: 0, width: 200 }} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="exemple.com" />
        <button className="btn" disabled={!domain.trim() || busy || airgapped} onClick={run}>{busy ? "Recherche…" : "Énumérer"}</button>
      </div>
      {airgapped && <div className="empty">Mode air-gapped actif — désactive-le pour lancer l'OSINT.</div>}
      {res && !res.available && <div className="empty">{res.reason}</div>}
      {res?.error && <div className="empty">Erreur : {res.error}</div>}
      {res?.available && res.subdomains.length > 0 && (
        <>
          <div className="disc" style={{ padding: "8px 16px 0" }}>{res.subdomains.length} sous-domaine(s) :</div>
          <div style={{ padding: "6px 16px 12px", display: "flex", flexDirection: "column", gap: 2, maxHeight: 260, overflowY: "auto" }}>
            {res.subdomains.map((s) => <span key={s} className="mono" style={{ fontSize: 11, color: "var(--soft)" }}>{s}</span>)}
          </div>
        </>
      )}
      {res?.available && !res.error && res.subdomains.length === 0 && <div className="empty">Aucun sous-domaine trouvé.</div>}
    </Card>
  );
}

function Offensif({ airgapped }: { airgapped: boolean }) {
  const [algo, setAlgo] = useState("md5");
  const [target, setTarget] = useState("");
  const [salt, setSalt] = useState("");
  const [iters, setIters] = useState(100000);
  const [words, setWords] = useState("");
  const [res, setRes] = useState<CrackResult | null>(null);
  const [busy, setBusy] = useState(false);
  const pbkdf2 = algo.startsWith("pbkdf2");
  const run = async () => {
    setBusy(true); setRes(null);
    try {
      const r = await api.crack({ algo, target: target.trim(), salt, iterations: iters, dklen: 32, words: words.split("\n") });
      setRes(r);
    } catch {
      setRes({ found: null, tried: 0, algo, error: "moteur injoignable" });
    }
    setBusy(false);
  };
  const ta: React.CSSProperties = { width: "100%", background: "var(--card-solid)", border: "1px solid var(--card-b)", borderRadius: 8, color: "var(--ink)", fontFamily: "var(--mono)", fontSize: 12, padding: 10 };
  return (
    <div className="grid">
      <div className="col">
        <Card title="Cracker de hash (dictionnaire)" right="CTF / pentest autorisé">
          <div className="note">Outil offensif repris de <b>sk-security-toolkit</b>. 100 % local, aucune donnée envoyée. Fournis le hash cible et ta wordlist — <b>usage sur données autorisées uniquement</b>.</div>
          <div className="row"><span className="nm">Algorithme</span><span className="seg" style={{ marginLeft: "auto" }}>{["md5", "sha1", "sha256", "pbkdf2_sha256"].map((a) => <button key={a} className={algo === a ? "on" : ""} onClick={() => setAlgo(a)}>{a}</button>)}</span></div>
          <div className="row"><span className="nm">Hash cible (hex)</span><input className="key" style={{ marginLeft: "auto", width: 280, letterSpacing: 0 }} value={target} onChange={(e) => setTarget(e.target.value)} placeholder="5f4dcc3b5aa765d61d8327deb882cf99" /></div>
          {pbkdf2 && (
            <>
              <div className="row"><span className="nm">Sel (hex)</span><input className="key" style={{ marginLeft: "auto", width: 200, letterSpacing: 0 }} value={salt} onChange={(e) => setSalt(e.target.value)} /></div>
              <div className="row"><span className="nm">Itérations</span><input className="key" type="number" style={{ marginLeft: "auto", width: 120, letterSpacing: 0 }} value={iters} onChange={(e) => setIters(+e.target.value)} /></div>
            </>
          )}
          <div style={{ padding: "12px 16px" }}>
            <div className="lbl" style={{ marginBottom: 6 }}>Wordlist (un mot par ligne)</div>
            <textarea value={words} onChange={(e) => setWords(e.target.value)} rows={6} style={ta} placeholder={"password\nadmin\n123456\nletmein"} />
          </div>
          <div className="actions"><button className="btn" onClick={run} disabled={busy || !target || !words.trim()}>{busy ? "Crack en cours…" : "Lancer le crack"}</button></div>
          {res && (
            <div className="rcard">
              {res.error ? <div style={{ color: "var(--crit)" }}>Erreur : {res.error}</div>
                : res.found ? <div><b style={{ color: "var(--safe)" }}>Trouvé :</b> <span className="mono">{res.found}</span> <span className="muted">({res.tried} essais)</span></div>
                  : <div className="muted">Non trouvé ({res.tried} essais). Élargis la wordlist.</div>}
            </div>
          )}
        </Card>
      </div>
      <div className="col">
        <OsintCard airgapped={airgapped} />
        <Card title="Suggestions d'attaque" right="Jalon 3">
          <div className="note">La logique de <b>sk-recon</b> (suggestions hydra/netexec/feroxbuster selon les services) sera greffée sur le scan nmap au Jalon 3.</div>
        </Card>
      </div>
    </div>
  );
}

/* ============ SOC LOCAL (HIDS + Mail Security) ============ */
function Soc({ hids }: { hids: HidsResult | null }) {
  const [eml, setEml] = useState("");
  const [mail, setMail] = useState<MailAnalysis | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.hidsRun().catch(() => {}); }, []); // lance l'analyse des événements à l'ouverture
  const ta: React.CSSProperties = { width: "100%", background: "var(--card-solid)", border: "1px solid var(--card-b)", borderRadius: 8, color: "var(--ink)", fontFamily: "var(--mono)", fontSize: 12, padding: 10 };
  const analyze = async () => { setBusy(true); setMail(null); try { setMail(await api.mailAnalyze(eml)); } catch { setMail({ from_addr: "", from_name: "", subject: "", date: "", spf: "?", dkim: "?", dmarc: "?", links: [], attachments: [], risk: 0, severity: "safe", reasons: [], error: "moteur injoignable" }); } setBusy(false); };
  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => { const f = e.target.files?.[0]; if (!f) return; const r = new FileReader(); r.onload = () => setEml(String(r.result || "")); r.readAsText(f); };
  const mech = (v: string) => (v === "pass" ? "var(--safe)" : v === "fail" ? "var(--crit)" : "var(--faint)");
  const sevCol = (s: string) => (s === "crit" ? "var(--crit)" : s === "suspect" ? "var(--crit)" : s === "watch" ? "var(--watch)" : "var(--safe)");
  return (
    <div className="grid">
      <div className="col">
        <Card title="Mail Security (.eml)" right="local · sans identifiant">
          <div className="note">Dépose ou colle un email (.eml — via « Afficher l'original »). Analyse <b>SPF/DKIM/DMARC</b> + liens/pièces jointes. Aucun accès à ta boîte, aucun mot de passe, aucun appel externe.</div>
          <div style={{ padding: "10px 16px" }}>
            <input type="file" accept=".eml,.txt,message/rfc822" onChange={onFile} style={{ marginBottom: 8, color: "var(--soft)", fontSize: 12 }} />
            <textarea value={eml} onChange={(e) => setEml(e.target.value)} rows={6} style={ta} placeholder="…ou colle ici la source de l'email" />
          </div>
          <div className="actions"><button className="btn" disabled={!eml.trim() || busy} onClick={analyze}>{busy ? "Analyse…" : "Analyser le mail"}</button></div>
          {mail?.error && <div className="empty">Erreur : {mail.error}</div>}
          {mail && !mail.error && (
            <div className="rcard">
              <div className="rhead">
                <span className="pr" style={{ color: sevCol(mail.severity), borderColor: sevCol(mail.severity), background: "transparent" }}>{mail.severity.toUpperCase()} · {mail.risk}/100</span>
                <span className="rtitle" style={{ fontSize: 13 }}>{mail.subject || "(sans objet)"}</span>
              </div>
              <div className="rbody"><b>Expéditeur :</b> {mail.from_name} &lt;{mail.from_addr}&gt;</div>
              <div className="rmeta">
                <span className="badge" style={{ color: mech(mail.spf), borderColor: mech(mail.spf) }}>SPF {mail.spf}</span>
                <span className="badge" style={{ color: mech(mail.dkim), borderColor: mech(mail.dkim) }}>DKIM {mail.dkim}</span>
                <span className="badge" style={{ color: mech(mail.dmarc), borderColor: mech(mail.dmarc) }}>DMARC {mail.dmarc}</span>
              </div>
              {mail.reasons.length > 0 && <div className="rbody"><b>Ce qui ne va pas :</b><ul className="steps">{mail.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul></div>}
              {mail.links.some((l) => l.suspicious) && <div className="rbody"><b>Liens suspects :</b> {mail.links.filter((l) => l.suspicious).map((l) => `${l.url} (${l.reason})`).join(" · ")}</div>}
              {mail.attachments.some((a) => a.risky) && <div className="rbody" style={{ color: "var(--crit)" }}><b>Pièces jointes à risque :</b> {mail.attachments.filter((a) => a.risky).map((a) => a.filename).join(", ")}</div>}
              <div className="rbody"><b>Remédiation :</b> {mail.severity === "safe" ? "Aucune anomalie majeure — rester vigilant sur les liens." : "Ne clique aucun lien, n'ouvre aucune pièce jointe, ne réponds pas. Signale/supprime après vérification de l'expéditeur par un autre canal."}</div>
            </div>
          )}
        </Card>
      </div>
      <div className="col">
        <Card title="HIDS-lite — événements Windows" right={<button className="btn ghost" style={{ padding: "5px 10px" }} onClick={() => api.hidsRun()}>Analyser</button>}>
          <div className="note">Mini-SOC local : services installés, échecs de connexion, détections Defender, Sysmon si présent. Lecture seule, aucun SIEM.</div>
          {hids?.note && <div className="disc" style={{ padding: "6px 16px" }}>ℹ️ {hids.note}</div>}
          {(hids?.events || []).slice(0, 40).map((e, i) => (
            <div className="log" key={i}>
              <span className="ts">{e.ts.slice(0, 19).replace("T", " ")}</span>
              <span className={`lv ${e.severity === "crit" ? "error" : e.severity === "watch" ? "warn" : "info"}`}>{e.event_id}</span>
              <span className="ms">{e.label} <span className="muted">({e.log.split("/").pop()})</span></span>
            </div>
          ))}
          {(!hids || hids.events.length === 0) && <div className="empty">{hids?.running ? "Analyse en cours…" : "Clique « Analyser » pour lire les événements."}</div>}
        </Card>
      </div>
    </div>
  );
}

/* ============ CONNECTEURS ============ */
function Connecteurs({ airgapped, connectors, onRefresh }: { airgapped: boolean; connectors: ConnectorStatus[]; onRefresh: () => void }) {
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [llm, setLlm] = useState({ provider: "ollama", url: "http://localhost:11434", model: "llama3", key: "" });
  const connected = (n: string) => connectors.find((c) => c.name === n)?.connected;
  const save = async (n: string) => { await api.connectorSet(n, keys[n] || ""); setKeys({ ...keys, [n]: "" }); onRefresh(); };
  const del = async (n: string) => { await api.connectorDelete(n); onRefresh(); };
  const saveLlm = async () => { await api.connectorSet("llm", JSON.stringify(llm)); onRefresh(); };
  const simple: [string, string][] = [["virustotal", "VirusTotal"], ["abuseipdb", "AbuseIPDB"], ["greynoise", "GreyNoise"], ["shodan", "Shodan"]];
  return (
    <Card title="Connecteurs — clés API" right="chiffrées (keyring OS)">
      <div className="note">Actifs seulement si <b>air-gapped désactivé</b> (actuellement <b style={{ color: airgapped ? "var(--watch)" : "var(--safe)" }}>{airgapped ? "ACTIF" : "OFF"}</b> — bascule via la pastille en haut à droite). Clés chiffrées dans le trousseau de l'OS, jamais réaffichées. <b>Je ne génère aucun compte</b> : utilise tes propres clés.</div>
      {simple.map(([name, label]) => (
        <div className="row" key={name}>
          <span className="nm">{label}</span>
          <input className="key" type="password" placeholder={connected(name) ? "•••• (configuré)" : "clé API"} value={keys[name] || ""} onChange={(e) => setKeys({ ...keys, [name]: e.target.value })} style={{ marginLeft: "auto" }} />
          <button className="btn ghost" disabled={!(keys[name] || "").trim()} onClick={() => save(name)}>Enregistrer</button>
          {connected(name) ? <><span className="stt on">connecté ✓</span><button className="btn ghost" onClick={() => del(name)}>Supprimer</button></> : <span className="stt off">non connecté</span>}
        </div>
      ))}
      <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
        <span className="nm">LLM (analyse IA)</span>
        <span className="seg">{["ollama", "anthropic", "openai"].map((p) => <button key={p} className={llm.provider === p ? "on" : ""} onClick={() => setLlm({ ...llm, provider: p })}>{p}</button>)}</span>
        {llm.provider === "ollama"
          ? <input className="key" style={{ letterSpacing: 0, width: 180 }} value={llm.url} onChange={(e) => setLlm({ ...llm, url: e.target.value })} placeholder="http://localhost:11434" />
          : <input className="key" type="password" style={{ width: 160 }} value={llm.key} onChange={(e) => setLlm({ ...llm, key: e.target.value })} placeholder="clé API" />}
        <input className="key" style={{ letterSpacing: 0, width: 130 }} value={llm.model} onChange={(e) => setLlm({ ...llm, model: e.target.value })} placeholder="modèle" />
        <button className="btn ghost" onClick={saveLlm}>Enregistrer</button>
        {connected("llm") ? <><span className="stt on">connecté ✓</span><button className="btn ghost" onClick={() => del("llm")}>Supprimer</button></> : <span className="stt off">non connecté</span>}
      </div>
      <div className="disc" style={{ padding: "10px 16px" }}>💡 Ollama (local, gratuit, hors-ligne) fonctionne même sous air-gapped. Anthropic/OpenAI = clé perso + air-gapped OFF.</div>
    </Card>
  );
}

/* ============ DIAGNOSTIC ============ */
const KIND_ICON: Record<string, string> = { nouvelle_connexion: "➕", connexion_fermee: "➖", alerte: "🚨" };
function Diagnostic({ logs, history, timeline, beaconing }: { logs: any[]; history: any[]; timeline: TimelineEvent[]; beaconing: Beacon[] }) {
  const [level, setLevel] = useState("");
  const shown = level ? logs.filter((l) => l.level === level) : logs;
  return (
    <div className="grid">
      <div className="col">
        <Card title="Journal" right={<a href={api.logsExportUrl} download>Télécharger (.txt)</a>}>
          <div className="jrow">
            <span className="lbl">Niveau</span>
            <span className="seg">
              {["", "info", "warn", "error"].map((lv) => <button key={lv} className={level === lv ? "on" : ""} onClick={() => setLevel(lv)}>{lv || "tous"}</button>)}
            </span>
          </div>
          {shown.slice(-40).reverse().map((l, i) => (
            <div className="log" key={i}><span className="ts">{l.ts.slice(11, 19)}</span><span className={`lv ${l.level}`}>{l.level.slice(0, 4).toUpperCase()}</span><span className="ms">{l.module ? `${l.module}: ` : ""}{l.message}</span></div>
          ))}
          {shown.length === 0 && <div className="empty">Aucun log</div>}
        </Card>
        <Card title="Timeline des événements" right={`${(timeline || []).length}`}>
          {(timeline || []).slice(0, 40).map((e, i) => (
            <div className="log" key={i}>
              <span className="ts">{e.ts.slice(11, 19)}</span>
              <span className={`lv ${e.severity === "crit" || e.severity === "suspect" ? "error" : e.severity === "watch" ? "warn" : "info"}`}>{KIND_ICON[e.kind] || "•"}</span>
              <span className="ms">{e.process} → {e.remote} <span className="muted">({e.kind.replace("_", " ")})</span></span>
            </div>
          ))}
          {(!timeline || timeline.length === 0) && <div className="empty">Aucun événement encore (échantillonnage en cours).</div>}
        </Card>
      </div>
      <div className="col">
        <Card title="Beaconing C2 détecté" right={`${(beaconing || []).length}`}>
          <div className="note">Connexions réapparaissant à intervalle régulier (motif de Command &amp; Control).</div>
          {(beaconing || []).map((b, i) => (
            <div className="row" key={i}>
              <span className="nm">{b.process}</span>
              <span className="ds mono">{b.remote} · ~{b.period_s}s · régularité {Math.round(b.regularity * 100)}%</span>
              <span className="stt" style={{ marginLeft: "auto", color: "var(--crit)", borderColor: "var(--crit)" }}>beacon</span>
            </div>
          ))}
          {(!beaconing || beaconing.length === 0) && <div className="empty">Aucun beaconing détecté ✅</div>}
        </Card>
        <Card title="Historique (snapshots)" right={String(history.length)}>
          {history.slice(0, 12).map((s) => (
            <div className="recap" key={s.id}><span className="mono" style={{ color: "var(--faint)" }}>{s.taken_at.slice(0, 16).replace("T", " ")}</span><span className="v" style={{ color: bandColor(s.band) }}>{s.exposure_score}/100</span></div>
          ))}
          {history.length === 0 && <div className="empty">Aucun instantané. Utilise « Enregistrer un instantané » dans Bouclier.</div>}
        </Card>
        <Card title="Rétention & réglages">
          <div className="row"><span className="nm">Purge à la fermeture</span><span className="stt on" style={{ marginLeft: "auto" }}>activée</span></div>
          <div className="row"><span className="nm">Budget stockage</span><span className="stt on" style={{ marginLeft: "auto" }}>≤ 1 Go</span></div>
          <div className="row"><span className="nm">Rotation automatique</span><span className="stt on" style={{ marginLeft: "auto" }}>activée</span></div>
        </Card>
      </div>
    </div>
  );
}

/* ============ APP ============ */
const TABS: [string, string, string?][] = [
  ["dashboard", "Dashboard"],
  ["bouclier", "Bouclier"],
  ["carte", "Carte réseau"],
  ["remediation", "Remédiation"],
  ["recon", "Recon & WiFi", "J3-J4"],
  ["offensif", "Offensif"],
  ["soc", "SOC local"],
  ["connecteurs", "Connecteurs", "J2"],
  ["diagnostic", "Diagnostic"],
];

export default function App() {
  const [tab, setTab] = useState("dashboard");
  const health = usePolling(api.health, 10000);
  const modules = usePolling(api.modules, 5000);
  const exposure = usePolling(api.exposure, 3000);
  const connections = usePolling(api.connections, 3000);
  const bandwidth = usePolling(api.bandwidth, 1500);
  const top = usePolling(api.topTalkers, 5000);
  const logs = usePolling(() => api.logs(), 5000);
  const history = usePolling(api.history, 8000);
  const [traceTarget, setTraceTarget] = useState("1.1.1.1");
  const trace = usePolling(() => api.trace(traceTarget), 6000);
  const wifi = usePolling(api.wifi, 15000);
  const timeline = usePolling(api.timeline, 6000);
  const beaconing = usePolling(api.beaconing, 10000);
  const lan = usePolling(api.lan, 20000);
  const scan = usePolling(api.scan, 4000);
  const hids = usePolling(api.hids, 8000);
  const connectors = usePolling(api.connectors, 6000);
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

  return (
    <div className="wrap">
      <div className="top">
        <div className="brand">
          <div className="logo" aria-hidden><svg viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3v6c0 5-3.4 8.4-8 11-4.6-2.6-8-6-8-11V5l8-3z" fill="#fff" fillOpacity=".95" /><path d="M12 7v6M9 10h6" stroke="#7d1d24" strokeWidth="1.7" strokeLinecap="round" /></svg></div>
          <div><h1>RED</h1><div className="sub">Network Shield &amp; Recon</div></div>
        </div>
        <div className="gm"><div className="num" style={{ color: bandColor(exposure.data?.band ?? "faible") }}>{exposure.data?.score ?? "—"}</div><div><div className="lab">Exposition</div><div className="band" style={{ color: bandColor(exposure.data?.band ?? "faible") }}>{exposure.data ? bandLabel(exposure.data.band).replace("Exposition ", "") : "…"}</div></div></div>
        <div className="bw"><span><span className="k">↓ DL</span> <span className="dl mono">{fr(bwLast?.d ?? 0)}</span> <span className="k">Mo/s</span></span><span><span className="k">↑ UL</span> <span className="ul mono">{fr(bwLast?.u ?? 0)}</span> <span className="k">Mo/s</span></span></div>
        <div className="spacer"></div>
        <div className={`pill ${airgapped ? "" : "off"}`} style={{ cursor: "pointer" }} onClick={async () => { await api.setAirgapped(!airgapped); }} title="Mode air-gapped : coupe TOUT appel réseau externe (VirusTotal, OSINT, LLM…). Les analyses restent 100 % locales. Clique pour activer/désactiver — désactive-le pour utiliser les connecteurs.">
          <span className="on"></span>Air-gapped&nbsp;<b>{airgapped ? "ACTIF" : "OFF"}</b>
          <span style={{ marginLeft: 6, color: "var(--faint)" }}>⇄</span>
        </div>
      </div>

      {offline && <div className="note" style={{ borderRadius: 12, marginBottom: 12 }}>⚠️ Moteur injoignable sur <b>127.0.0.1:8787</b>. Lance le backend : <span className="mono">py -m uvicorn app.main:app</span> (depuis <span className="mono">engine/</span>).</div>}

      <div className="nav">
        {TABS.map(([id, label, mini]) => (
          <button key={id} className={`navb ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>{label}{mini && <span className="mini">{mini}</span>}</button>
        ))}
      </div>

      {tab === "dashboard" && <Dashboard conns={conns} exposure={exposure.data} modules={mods} logs={logs.data || []} bwHist={bwHist} scoreHist={scoreHist} top={top.data || []} trace={trace.data} beaconing={beaconing.data || []} onGo={setTab} onSelect={selectEndpoint} />}
      {tab === "bouclier" && <Bouclier conns={conns} />}
      {tab === "carte" && <CarteReseau conns={conns} trace={trace.data} traceLabel={traceLabel} onRun={runTrace} onSelect={selectEndpoint} />}
      {tab === "remediation" && <Remediation conns={conns} />}
      {tab === "recon" && <Recon wifi={wifi.data} lan={lan.data} scan={scan.data} onScan={(t, m) => api.scanRun(t, m)} />}
      {tab === "offensif" && <Offensif airgapped={airgapped} />}
      {tab === "soc" && <Soc hids={hids.data} />}
      {tab === "connecteurs" && <Connecteurs airgapped={airgapped} connectors={connectors.data || []} onRefresh={() => api.connectors().then((d) => (connectors.data = d)).catch(() => {})} />}
      {tab === "diagnostic" && <Diagnostic logs={logs.data || []} history={history.data || []} timeline={timeline.data || []} beaconing={beaconing.data || []} />}

      <div className="foot">RED Shield · Jalon 1 · style mix moderne · données réelles (aucune inventée)</div>
    </div>
  );
}
