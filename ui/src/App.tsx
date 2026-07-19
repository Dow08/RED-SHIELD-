import { useEffect, useMemo, useState } from "react";
import { api } from "./api";
import type { ScoredConnection, Severity } from "./api";
import { usePolling } from "./hooks";
import { BandwidthChart, NetworkGraph, Radar, Sparkline, WorldTrace } from "./viz";

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
function Dashboard({ conns, exposure, modules, logs, bwHist, scoreHist, top, onGo }: any) {
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

        <Card title="Radar réseau"><div className="stage"><Radar counts={counts} /></div></Card>
      </div>

      <div className="col">
        <Card title="Vue d'ensemble">
          <div className="recap"><span className="ic">🛰️</span>Connexions actives<span className="v">{conns.length}</span></div>
          <div className="recap"><span className="ic">🚨</span>Alertes critiques<span className="v" style={{ color: "var(--crit)" }}>{counts.crit}</span></div>
          <div className="recap"><span className="ic">⚠️</span>Suspectes<span className="v" style={{ color: "var(--crit)" }}>{counts.suspect}</span></div>
          <div className="recap"><span className="ic">🌐</span>Endpoints distincts<span className="v">{new Set((conns as ScoredConnection[]).map((c) => c.remote_addr)).size}</span></div>
          <div className="recap"><span className="ic">💾</span>Budget journal<span className="v">≤ 1 Go</span></div>
        </Card>
        <Card title="Modules" right={String(modules.length)}>
          {modules.map((m: any) => (
            <div className="mod" key={m.name}>
              <span className={`st2 ${m.status === "active" ? "on" : m.status === "error" ? "err" : "off"}`}></span>
              {m.description || m.name}
              <span className={`stl ${m.status === "active" ? "on" : m.status === "error" ? "err" : "off"}`}>{m.status}</span>
            </div>
          ))}
        </Card>
        <Card title="Top remédiations" right={<a onClick={() => onGo("remediation")}>tout voir →</a>}>
          {risky.slice(0, 3).map((c, i) => (
            <div className="rcard" key={i}>
              <div className="rhead"><span className={`pr ${c.severity === "crit" ? "c" : "w"}`}>{c.severity === "crit" ? "CRITIQUE" : "HAUTE"}</span><span className="rtitle" style={{ fontSize: 12.5 }}>{c.process} → {c.remote_addr}:{c.port}</span></div>
              {c.mitre[0] && <div className="rmeta"><span className="badge m">{c.mitre[0].id}</span></div>}
            </div>
          ))}
          {risky.length === 0 && <div className="empty">Aucune connexion suspecte. Machine saine ✅</div>}
        </Card>
        <Card title="Journal récent" right={<a onClick={() => onGo("diagnostic")}>ouvrir →</a>}>
          {logs.slice(-4).reverse().map((l: any, i: number) => (
            <div className="log" key={i}><span className="ts">{l.ts.slice(11, 16)}</span><span className={`lv ${l.level}`}>{l.level.slice(0, 4).toUpperCase()}</span><span className="ms">{l.message}</span></div>
          ))}
          {logs.length === 0 && <div className="empty">Journal vide</div>}
        </Card>
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
function CarteReseau({ conns }: { conns: ScoredConnection[] }) {
  const [view, setView] = useState("sortant");
  const labels: Record<string, string> = { sortant: "Sortant", entrant: "Entrant", local: "Local (LAN)", tous: "Tous" };
  return (
    <>
      <Card title="Carte réseau" right={<span className="seg">{Object.keys(labels).map((v) => <button key={v} className={view === v ? "on" : ""} onClick={() => setView(v)}>{labels[v]}</button>)}</span>}>
        <div className="stage"><NetworkGraph conns={conns} view={view} /></div>
        <div className="legend">
          <span><span className="d" style={{ background: "var(--accent)" }}></span>Cet appareil</span>
          <span><span className="d" style={{ background: "var(--safe)" }}></span>Sain</span>
          <span><span className="d" style={{ background: "var(--watch)" }}></span>À surveiller</span>
          <span><span className="d" style={{ background: "var(--crit)" }}></span>Suspect / critique</span>
          <span style={{ marginLeft: "auto", color: "var(--faint)" }}>Vue : <b style={{ color: "var(--accent)" }}>{labels[view]}</b> · particules = trafic</span>
        </div>
      </Card>
      <div style={{ height: 12 }} />
      <Card title="Tracé de connexion — carte du monde" right="Jalon 2">
        <div className="stage"><WorldTrace /></div>
        <div className="note">Le <b>traceroute géolocalisé hors-ligne</b> (base IP embarquée + carte vectorielle, aucune API externe) arrive au Jalon 2. Le fond de carte est déjà en place ; aucune donnée inventée n'est affichée.</div>
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
        </div>
      ))}
    </Card>
  );
}

/* ============ RECON ============ */
function Recon() {
  return (
    <div className="grid">
      <div className="col">
        <Card title="Scan hôte (nmap)" right="Jalon 3">
          <div className="note">Le scan de cibles autorisées (ports/services/OS + CVE → NVD) arrive au <b>Jalon 3</b>. nmap n'est pas installé sur cette machine.</div>
          <div className="row"><span className="nm">nmap</span><span className="ds">non installé</span><span className="stt off" style={{ marginLeft: "auto" }}>indisponible</span></div>
        </Card>
        <Card title="Découverte LAN" right="Jalon 2">
          <div className="note">Le balayage du réseau local (appareils, IP/MAC/fabricant, alertes) arrive au <b>Jalon 2</b>.</div>
        </Card>
      </div>
      <div className="col">
        <Card title="WiFi offensif (aircrack)" right="Jalon 4 · isolé">
          <div className="note"><b>Linux uniquement</b> · carte monitor requise · cible autorisée obligatoire. Un auto-test du service vérifiera l'environnement avant toute action.</div>
          <div className="row"><span className="nm">Interface monitor</span><span className="ds">non détectée (Windows)</span><span className="stt off" style={{ marginLeft: "auto" }}>indisponible</span></div>
        </Card>
      </div>
    </div>
  );
}

/* ============ CONNECTEURS ============ */
function Connecteurs({ airgapped }: { airgapped: boolean }) {
  const items = ["VirusTotal", "AbuseIPDB", "GreyNoise", "Shodan", "Wazuh (SIEM)", "Microsoft Defender (EDR)", "LLM (rapport IA)"];
  return (
    <Card title="Connecteurs — clés API" right="chiffrées (keyring)">
      <div className="note">Actifs uniquement si le <b>mode air-gapped est désactivé</b> (actuellement {airgapped ? "ACTIF" : "inactif"}). Aucune clé en clair. Branchement effectif : Jalon 2.</div>
      {items.map((n) => (
        <div className="row" key={n}>
          <span className="nm">{n}</span>
          <input className="key" type="password" placeholder="clé API" disabled style={{ marginLeft: "auto" }} />
          <span className="stt off">non connecté</span>
        </div>
      ))}
    </Card>
  );
}

/* ============ DIAGNOSTIC ============ */
function Diagnostic({ logs, history }: { logs: any[]; history: any[] }) {
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
      </div>
      <div className="col">
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
        <div className={`pill ${airgapped ? "" : "off"}`}><span className="on"></span>Air-gapped&nbsp;<b>{airgapped ? "ACTIF" : "OFF"}</b></div>
      </div>

      {offline && <div className="note" style={{ borderRadius: 12, marginBottom: 12 }}>⚠️ Moteur injoignable sur <b>127.0.0.1:8787</b>. Lance le backend : <span className="mono">py -m uvicorn app.main:app</span> (depuis <span className="mono">engine/</span>).</div>}

      <div className="nav">
        {TABS.map(([id, label, mini]) => (
          <button key={id} className={`navb ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>{label}{mini && <span className="mini">{mini}</span>}</button>
        ))}
      </div>

      {tab === "dashboard" && <Dashboard conns={conns} exposure={exposure.data} modules={mods} logs={logs.data || []} bwHist={bwHist} scoreHist={scoreHist} top={top.data || []} onGo={setTab} />}
      {tab === "bouclier" && <Bouclier conns={conns} />}
      {tab === "carte" && <CarteReseau conns={conns} />}
      {tab === "remediation" && <Remediation conns={conns} />}
      {tab === "recon" && <Recon />}
      {tab === "connecteurs" && <Connecteurs airgapped={airgapped} />}
      {tab === "diagnostic" && <Diagnostic logs={logs.data || []} history={history.data || []} />}

      <div className="foot">RED Shield · Jalon 1 · style mix moderne · données réelles (aucune inventée)</div>
    </div>
  );
}
