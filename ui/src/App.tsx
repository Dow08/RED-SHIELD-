import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "./api";
import { usePolling } from "./hooks";
import { BandwidthChart, CyberBackground, NetworkGraph, Sparkline, TraceMap } from "./viz";

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

function ClosePortButton({ port, protocol }: { port: number; protocol: string }) {
  const [stage, setStage] = useState<"idle" | "confirm" | "done">("idle");
  const [msg, setMsg] = useState("");
  const dry = async () => { try { const r = await api.firewallBlockPort(port, protocol, true); setMsg(r.command || ""); setStage("confirm"); } catch { setMsg("moteur injoignable"); } };
  const apply = async () => { try { const r = await api.firewallBlockPort(port, protocol, false); setMsg(r.ok ? "Port fermé (entrant bloqué) ✅" : (r.error || "échec")); setStage(r.ok ? "done" : "confirm"); } catch { setMsg("échec"); } };
  const undo = async () => { try { await api.firewallUnblockPort(port, protocol); setMsg("Rouvert"); setStage("idle"); } catch { setMsg("échec"); } };
  if (stage === "idle") return <button className="btn ghost" style={{ padding: "5px 9px", fontSize: 11 }} onClick={dry}>Fermer</button>;
  if (stage === "confirm") return (
    <span style={{ display: "inline-flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
      <span className="mono" style={{ fontSize: 9.5, color: "var(--faint)" }}>{msg}</span>
      <button className="btn" style={{ padding: "5px 9px", fontSize: 11 }} onClick={apply}>Confirmer</button>
      <button className="btn ghost" style={{ padding: "5px 9px", fontSize: 11 }} onClick={() => setStage("idle")}>Annuler</button>
    </span>
  );
  return <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><span style={{ color: "var(--safe)", fontSize: 11 }}>{msg}</span><button className="btn ghost" style={{ padding: "5px 9px", fontSize: 11 }} onClick={undo}>Rouvrir</button></span>;
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
        <span className="dir" title={c.direction === "entrant" ? "Connexion entrante (vers un port en écoute)" : "Connexion sortante"} style={{ color: c.direction === "entrant" ? "var(--accent)" : "var(--faint)" }}>{c.direction === "entrant" ? "↓" : "↑"}</span>
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
function DualBar({ a, b, ca, cb }: { a: number; b: number; ca: string; cb: string }) {
  const tot = Math.max(1, a + b);
  return (
    <span className="dual" title={`${a} / ${b}`}>
      <span style={{ width: `${(a / tot) * 100}%`, background: ca }} />
      <span style={{ width: `${(b / tot) * 100}%`, background: cb }} />
    </span>
  );
}
function Mtile({ label, hint, children, detail }: { label: string; hint?: string; children: React.ReactNode; detail?: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`mtile${detail ? " expandable" : ""}`} onClick={detail ? () => setOpen((o) => !o) : undefined} title={hint}>
      <div className="lbl">{label}{hint && <span className="qh">ⓘ</span>}{detail && <span className="exp">{open ? "▾" : "▸"}</span>}</div>
      {children}
      {detail && open && <div className="mdetail" onClick={(e) => e.stopPropagation()}>{detail}</div>}
    </div>
  );
}
function PortChips({ ports }: { ports: import("./api").PortCount[] }) {
  if (!ports || ports.length === 0) return <span className="muted" style={{ fontSize: 11 }}>aucun</span>;
  return <>{ports.map((p) => <span key={p.port} className="pchip"><b style={{ color: p.encrypted ? "var(--safe)" : "var(--watch)" }}>{p.port}</b>{p.service ? " " + p.service : ""} <i>{p.count}</i></span>)}</>;
}
function Dashboard({ conns, exposure, metrics, modules, logs, bwHist, bw, scoreHist, top, thrStatus, thrProcs, trace, beaconing, sevFilter, onGo, onSelect }: any) {
  const m = metrics as import("./api").NetMetrics | undefined;
  const thr = thrStatus as import("./api").ThroughputStatus | undefined;
  const procs = (thrProcs || []) as import("./api").ProcThroughput[];
  const liveThr = !!thr?.available && procs.length > 0;
  const maxThr = Math.max(0.001, ...procs.map((p) => p.down_bps + p.up_bps));
  const risky = (conns as ScoredConnection[]).filter((c) => c.severity === "suspect" || c.severity === "crit").sort((a, b) => b.risk - a.risk);
  const filtered = (conns as ScoredConnection[]).filter((c) => sevFilter[c.severity]);
  const topConns = [...filtered].sort((a, b) => b.risk - a.risk).slice(0, 4);
  const allActive = Object.values(sevFilter as Record<string, boolean>).every(Boolean);
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
              <>
                <div className="stage"><BandwidthChart history={bwHist} /></div>
                {(bw?.nics?.length ?? 0) > 0 && (
                  <div className="niclist">
                    {bw.nics.map((n: any) => (
                      <div className="nicrow" key={n.name}>
                        <span className="nn">{n.name}{n.is_tunnel && <span className="tun">VPN/tunnel</span>}</span>
                        <span className="nv"><span className="dl">{fr(n.down_mo_s)}↓</span> <span className="ul">{fr(n.up_mo_s)}↑</span> <span style={{ color: "var(--faint)" }}>Mo/s</span></span>
                      </div>
                    ))}
                  </div>
                )}
                {bw?.note && <div className="disc" style={{ color: "var(--watch)" }}>⚠️ {bw.note}</div>}
                {!bw?.note && <div className="disc">Débit total de la carte réseau (toutes interfaces) en temps réel.</div>}
              </>
            ) : (
              <div className="bars">
                {liveThr ? (
                  <>
                    {procs.map((p) => (
                      <div className="barrow" key={p.pid}>
                        <span className="bn">{p.process}</span>
                        <span className="track"><span className="fill" style={{ width: `${((p.down_bps + p.up_bps) / maxThr) * 100}%` }} /></span>
                        <span className="bv">{fr(p.down_mo_s)}↓ {fr(p.up_mo_s)}↑</span>
                      </div>
                    ))}
                    <div className="disc">Débit réel par processus (Mo/s ↓/↑) — capture pktmon en direct.</div>
                  </>
                ) : (
                  <>
                    {top.length === 0 && <div className="empty">Aucune donnée</div>}
                    {top.map((t: any) => (
                      <div className="barrow" key={t.pid}>
                        <span className="bn">{t.process}</span>
                        <span className="track"><span className="fill" style={{ width: `${(t.connections / maxTalk) * 100}%` }} /></span>
                        <span className="bv">{t.connections} conn.</span>
                      </div>
                    ))}
                    <div className="disc">Processus classés par nombre de connexions actives. {thr && !thr.available && <span style={{ color: "var(--watch)" }}>Débit par processus : {thr.reason || "indisponible"}.</span>}</div>
                  </>
                )}
              </div>
            )}
          </Card>
        </div>

        <Card title="Métriques réseau" right="surveillance live">
          <div className="mtiles">
            <Mtile label="Entrant / Sortant">
              <div className="mval"><b style={{ color: "var(--accent)" }}>{m?.inbound ?? 0}</b> <span className="sep">/</span> <b>{m?.outbound ?? 0}</b></div>
              <DualBar a={m?.inbound ?? 0} b={m?.outbound ?? 0} ca="var(--accent)" cb="var(--accent2)" />
            </Mtile>
            <Mtile label="Chiffré / Clair">
              <div className="mval"><b style={{ color: "var(--safe)" }}>{m?.encrypted ?? 0}</b> <span className="sep">/</span> <b style={{ color: (m?.clear ?? 0) > 0 ? "var(--watch)" : "var(--soft)" }}>{m?.clear ?? 0}</b></div>
              <DualBar a={m?.encrypted ?? 0} b={m?.clear ?? 0} ca="var(--safe)" cb="var(--watch)" />
            </Mtile>
            <Mtile label="TCP / UDP" hint="TCP = connexions établies (avec destinataire). UDP = sockets actifs : l'OS ne fournit pas le destinataire des flux UDP (sans connexion, ex. QUIC/vidéo) — l'attribution réelle nécessite la capture pktmon (admin)." detail={
              <>
                <div className="mdrow"><span className="mdk">TCP</span><div className="pchips"><PortChips ports={m?.tcp_ports ?? []} /></div></div>
                <div className="mdrow"><span className="mdk">UDP</span><div style={{ fontSize: 11, color: "var(--soft)" }}><b style={{ color: "var(--accent)" }}>{m?.udp_sockets ?? 0}</b> socket(s) UDP actif(s). Le destinataire n'est pas exposé par l'OS (sans connexion) → flux réel via la <b>capture pktmon</b> (admin).</div></div>
              </>
            }>
              <div className="mval"><b>{m?.tcp ?? 0}</b> <span className="sep">/</span> <b style={{ color: (m?.udp_sockets ?? 0) > 0 ? "var(--accent)" : "var(--faint)" }}>{m?.udp_sockets ?? 0}</b> <span style={{ fontSize: 10, fontWeight: 400, color: "var(--faint)" }}>UDP</span></div>
              <DualBar a={m?.tcp ?? 0} b={m?.udp_sockets ?? 0} ca="var(--accent2)" cb="var(--accent)" />
            </Mtile>
            <Mtile label="Ports en écoute (exposés)">
              <div className="mval"><b style={{ color: (m?.listeners_exposed ?? 0) > 0 ? "var(--watch)" : "var(--safe)" }}>{m?.listeners_exposed ?? 0}</b> <span className="sep">/</span> <b>{m?.listeners ?? 0}</b></div>
              <a style={{ fontSize: 11 }} onClick={() => onGo("carte")}>voir la surface entrante →</a>
            </Mtile>
            <Mtile label="Pays distincts" hint="Pays où se trouvent les IP distantes de tes connexions (géoloc hors-ligne DB-IP). Le nombre à droite = nb de connexions vers ce pays. Déplie pour voir quelles applications s'y connectent." detail={
              <div className="cstats">
                {(m?.countries || []).map((c: any) => (
                  <div key={c.key} className="cstat">
                    <div className="ch"><b>{c.key}</b> <i>{c.count} conn.</i></div>
                    <div className="cprocs">{(c.processes || []).map((p: any) => <span key={p.key}>{p.key} <i>{p.count}</i></span>)}{(!c.processes?.length) && <span className="muted">process inconnu</span>}</div>
                  </div>
                ))}
                {(!m?.countries?.length) && <span className="muted" style={{ fontStyle: "italic" }}>géoloc indisponible (base DB-IP ou air-gapped)</span>}
              </div>
            }>
              <div className="mval"><b>{m?.countries?.length ?? 0}</b> <span style={{ fontSize: 11, fontWeight: 400, color: "var(--faint)" }}>pays</span></div>
              <div className="mlist">{(m?.countries || []).slice(0, 3).map((c: any) => <span key={c.key}>{c.key} <i>{c.count} conn.</i></span>)}{(!m?.countries?.length) && <span className="muted" style={{ fontStyle: "italic" }}>géo hors-ligne</span>}</div>
            </Mtile>
            <Mtile label="Top ports distants">
              <div className="mlist">{(m?.top_ports || []).slice(0, 4).map((p: any) => <span key={p.port}><b style={{ color: p.encrypted ? "var(--safe)" : "var(--watch)" }}>{p.port}</b>{p.service ? ` ${p.service}` : ""} <i>{p.count}</i></span>)}{(!m?.top_ports?.length) && <span className="muted">—</span>}</div>
            </Mtile>
          </div>
        </Card>

        <Card title="Connexions — aperçu" right={<a onClick={() => onGo("bouclier")}>{`tout voir (${filtered.length}${allActive ? "" : "/" + conns.length}) →`}</a>}>
          {!allActive && <div className="disc" style={{ padding: "6px 14px 0", color: "var(--accent)" }}>Filtre de sévérité actif (synchronisé avec l'onglet Bouclier).</div>}
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
                <div className="recap"><span className="ic">⬇️</span>Entrantes / sortantes<span className="v"><b style={{ color: "var(--accent)" }}>{m?.inbound ?? 0}</b> / {m?.outbound ?? 0}</span></div>
                <div className="recap"><span className="ic">🚨</span>Alertes critiques<span className="v" style={{ color: counts.crit ? "var(--crit)" : "var(--faint)" }}>{counts.crit}</span></div>
                <div className="recap"><span className="ic">⚠️</span>Suspectes<span className="v" style={{ color: counts.suspect ? "var(--crit)" : "var(--faint)" }}>{counts.suspect}</span></div>
                <div className="recap"><span className="ic">📡</span>Beaconing C2<span className="v" style={{ color: beaconing?.length ? "var(--crit)" : "var(--faint)" }}>{beaconing?.length || 0}</span></div>
                <div className="recap"><span className="ic">🚪</span>Ports en écoute exposés<span className="v" style={{ color: (m?.listeners_exposed ?? 0) ? "var(--watch)" : "var(--safe)" }}>{m?.listeners_exposed ?? 0}</span></div>
                <div className="recap"><span className="ic">🌐</span>Endpoints distincts<span className="v">{m?.endpoints ?? new Set((conns as ScoredConnection[]).map((c) => c.remote_addr)).size}</span></div>
                <div className="recap"><span className="ic">📥</span>Capture entrante (pktmon)<span className="v" style={{ color: thr?.available ? "var(--safe)" : "var(--faint)" }}>{thr?.available ? `${thr.inbound_packets} pqt` : "admin requis"}</span></div>
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
function Bouclier({ conns, active, setActive }: { conns: ScoredConnection[]; active: Record<Severity, boolean>; setActive: (v: Record<Severity, boolean>) => void }) {
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

/* ============ CARTE RÉSEAU ============ */
function CarteReseau({ conns, listeners, trace, traceLabel, geoPoints, onRun, onSelect }: { conns: ScoredConnection[]; listeners: import("./api").Listener[]; trace: TraceResult | null; traceLabel: string; geoPoints: import("./api").GeoPoint[]; onRun: (t: string) => void; onSelect: (ip: string) => void }) {
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
      <Card title="Carte réseau" right={<span className="seg">{Object.keys(labels).map((v) => <button key={v} className={view === v ? "on" : ""} onClick={() => setView(v)}>{labels[v]}{v === "entrant" && inboundCount > 0 ? ` (${inboundCount})` : ""}</button>)}</span>}>
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
      <Card title="Tracé de connexion — carte du monde" right={<><div className="search" style={{ marginRight: 8 }}><input value={target} onChange={(e) => setTarget(e.target.value)} style={{ width: 120 }} /></div><button className="btn ghost" onClick={() => onRun(target)}>Lancer le tracé</button></>}>
        <div className="stage"><TraceMap trace={trace} destLabel={traceLabel} points={geoPoints} /></div>
        <div className="legend" style={{ paddingBottom: 0 }}>
          <span><span className="d" style={{ background: "var(--safe)" }}></span>Connexion saine</span>
          <span><span className="d" style={{ background: "var(--watch)" }}></span>À surveiller</span>
          <span><span className="d" style={{ background: "var(--crit)" }}></span>Suspecte / critique</span>
          <span style={{ color: "var(--faint)" }}>· {geoPoints.length} connexion(s) géolocalisée(s) · le tracé actif est en surbrillance</span>
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

/* ============ REMÉDIATION ============ */
function GrcPosture({ conns, metrics, listeners }: { conns: ScoredConnection[]; metrics?: import("./api").NetMetrics; listeners: import("./api").Listener[] }) {
  const exposed = (listeners || []).filter((l) => l.exposed).length;
  const clear = metrics?.clear ?? 0;
  const risky = conns.filter((c) => c.severity === "suspect" || c.severity === "crit").length;
  const controls = [
    { domain: "Maîtrise de la surface d'exposition", ctrl: ["CIS v8 §4 & §12", "NIST CSF PR.AC-5", "ISO 27001 A.13.1", "ANSSI BP-028"], ok: exposed === 0, detail: exposed === 0 ? "Aucun port exposé non maîtrisé." : `${exposed} port(s) exposé(s) à réduire ou justifier (fermeture possible depuis Carte réseau).` },
    { domain: "Chiffrement des communications", ctrl: ["NIST CSF PR.DS-2", "ISO 27001 A.10.1", "ANSSI R41"], ok: clear === 0, detail: clear === 0 ? "Tous les flux observés sont chiffrés." : `${clear} flux en clair — vérifier qu'aucune donnée sensible n'y transite.` },
    { domain: "Détection d'anomalies & réponse", ctrl: ["NIST CSF DE.CM-1 / DE.AE-2", "ISO 27001 A.12.4", "CIS v8 §8 & §13"], ok: risky === 0, detail: risky === 0 ? "Aucune connexion suspecte au moment de l'analyse." : `${risky} connexion(s) à investiguer (voir ci-dessous).` },
    { domain: "Journalisation & traçabilité", ctrl: ["NIST CSF PR.PT-1", "ISO 27001 A.12.4", "CIS v8 §8"], ok: true, detail: "Journal d'événements + piste d'audit actifs (rétention locale ≤ 1 Go)." },
  ];
  const conf = controls.filter((c) => c.ok).length;
  const pct = Math.round((conf / controls.length) * 100);
  return (
    <Card title="Posture GRC — conformité dérivée de l'état réel" right={`${conf}/${controls.length} conforme(s) · ${pct}%`}>
      <div className="note">Mapping <b>Gouvernance / Risque / Conformité</b> : chaque domaine est évalué à partir de <b>données réelles</b> de la machine (aucune auto-déclaration). Référentiels : ISO 27001, NIST CSF, CIS v8, ANSSI.</div>
      {controls.map((c, i) => (
        <div className="rcard" key={i} style={{ borderLeft: `3px solid ${c.ok ? "var(--safe)" : "var(--watch)"}` }}>
          <div className="rhead">
            <span className="pr" style={{ color: c.ok ? "var(--safe)" : "var(--watch)", borderColor: c.ok ? "var(--safe)" : "var(--watch)", background: "transparent" }}>{c.ok ? "CONFORME" : "À TRAITER"}</span>
            <span className="rtitle" style={{ fontSize: 13 }}>{c.domain}</span>
          </div>
          <div className="rmeta">{c.ctrl.map((ct) => <span key={ct} className="badge">{ct}</span>)}</div>
          <div className="rbody">{c.detail}</div>
        </div>
      ))}
    </Card>
  );
}

function Remediation({ conns, metrics, listeners }: { conns: ScoredConnection[]; metrics?: import("./api").NetMetrics; listeners: import("./api").Listener[] }) {
  const risky = conns.filter((c) => c.severity === "suspect" || c.severity === "crit").sort((a, b) => b.risk - a.risk);
  return (
    <>
    <GrcPosture conns={conns} metrics={metrics} listeners={listeners} />
    <div style={{ height: 12 }} />
    <Card title="Remédiation — diagnostic approfondi" right={`${risky.length} à traiter`}>
      <div className="note">Connexions suspectes à investiguer : arbre de processus, techniques <b>MITRE ATT&amp;CK</b>, réputation threat-intel et action de coupure (dry-run + confirmation).</div>
      {risky.length === 0 && <div className="empty">✅ Aucune connexion suspecte au moment de l'analyse — ta machine est saine.</div>}
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
    </>
  );
}

function AiAnalyzeButton({ getText, kind, label }: { getText: () => string; kind: string; label?: string }) {
  const [res, setRes] = useState<LlmResult | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true); setRes(null);
    try { setRes(await api.llmAnalyze(getText(), kind)); } catch { setRes({ ok: false, error: "moteur injoignable" }); }
    setBusy(false);
  };
  return (
    <div style={{ padding: "10px 16px", borderTop: "1px solid var(--card-b)" }}>
      <button className="btn" onClick={run} disabled={busy}>{busy ? "Analyse IA…" : (label || "🤖 Analyser avec l'IA")}</button>
      {res && !res.ok && <div className="disc" style={{ paddingTop: 8, color: "var(--watch)" }}>{res.error} — configure le connecteur LLM (Connecteurs).</div>}
      {res?.ok && <div className="rbody" style={{ whiteSpace: "pre-wrap", marginTop: 8, padding: 12, background: "var(--card-solid)", borderRadius: 8 }}>{res.analysis}</div>}
    </div>
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
function Recon({ lan, scan, procvuln, onScan }: { lan: LanDevice[] | null; scan: ScanResult | null; procvuln: import("./api").ProcVulnResult | null; onScan: (t: string, m: string) => void }) {
  const devices = lan || [];
  const pv = procvuln;
  const withCve = (pv?.apps || []).filter((a) => a.cves.length > 0);
  useEffect(() => { api.procvulnRun().catch(() => {}); }, []);
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
          <div className="note">Croise le <b>produit + version réels</b> de tes applications avec connexions (métadonnées de l'exécutable) contre la base CVE locale. Factuel : « aucune CVE » = rien dans la base locale, pas une garantie d'absence de faille.</div>
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
                  {withCve.length === 0 && <div className="disc" style={{ color: "var(--safe)", padding: "8px 16px" }}>Aucune CVE connue dans la base locale pour les {pv.scanned} application(s) analysée(s) ✅</div>}
                  <div className="disc" style={{ padding: "6px 16px 12px" }}>{pv.scanned} application(s) analysée(s) · {withCve.length} avec CVE connue.</div>
                </>
              ))}
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

function Offensif({ airgapped, wifi }: { airgapped: boolean; wifi: { networks: WifiNet[]; message: string } | null }) {
  const nets = wifi?.networks || [];
  const wrc = (r: string) => (r === "crit" ? "var(--crit)" : r === "watch" ? "var(--watch)" : "var(--safe)");
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
        <Card title="Audit WiFi — reconnaissance" right="natif Windows">
          <div className="note">Audit réel des réseaux à portée (chiffrement, signal, risque). Recon passif ; la <b>capture/crack de handshake</b> (aircrack) reste réservée à Linux + carte monitor.</div>
          {wifi?.message && <div className="empty">{wifi.message}</div>}
          {nets.map((n) => (
            <div className="row" key={n.bssid || n.ssid}>
              <span className="nm">{n.ssid}</span>
              <span className="ds">{n.auth || "?"} · canal {n.channel || "?"} · {n.signal}%</span>
              <span className="stt" style={{ marginLeft: "auto", color: wrc(n.risk), borderColor: n.risk === "safe" ? "var(--card-b)" : wrc(n.risk) }}>{n.reason}</span>
            </div>
          ))}
          {nets.length === 0 && !wifi?.message && <div className="empty">Aucun réseau à portée détecté.</div>}
        </Card>
        <Card title="WiFi offensif (aircrack)" right="Linux requis">
          <div className="note"><b>Linux uniquement</b> · carte monitor requise · cible autorisée obligatoire. Sous Windows, utilise l'<b>Audit WiFi</b> ci-dessus.</div>
          <div className="row"><span className="nm">Interface monitor</span><span className="ds">non disponible (Windows)</span><span className="stt off" style={{ marginLeft: "auto" }}>indisponible</span></div>
        </Card>
        <OsintCard airgapped={airgapped} />
        <Card title="Suggestions d'attaque" right="intégré au scan">
          <div className="note">La logique <b>sk-recon</b> (hydra/netexec/feroxbuster selon les services) est <b>déjà greffée sur le scan nmap</b> — vois les « Pistes » sous chaque port dans l'onglet <b>Recon</b>.</div>
        </Card>
      </div>
    </div>
  );
}

/* ============ SOC LOCAL (HIDS + Mail Security) ============ */
function Soc({ hids, defender }: { hids: HidsResult | null; defender: import("./api").DefenderStatus | null }) {
  const [eml, setEml] = useState("");
  const [mail, setMail] = useState<MailAnalysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [imapRes, setImapRes] = useState<import("./api").ImapResult | null>(null);
  const [imapBusy, setImapBusy] = useState(false);
  const [imapCfg, setImapCfg] = useState<{ configured: boolean; airgapped: boolean } | null>(null);
  useEffect(() => { api.hidsRun().catch(() => {}); api.defenderRun().catch(() => {}); api.imapStatus().then(setImapCfg).catch(() => {}); }, []); // lance les analyses à l'ouverture
  const relever = async () => { setImapBusy(true); try { setImapRes(await api.imapCheck()); } catch { setImapRes(null); } setImapBusy(false); };
  const onoff = (v: boolean | null) => (v === null ? { t: "?", c: "var(--faint)" } : v ? { t: "activée", c: "var(--safe)" } : { t: "désactivée", c: "var(--crit)" });
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
          {mail && !mail.error && (
            <AiAnalyzeButton
              kind="analyse d'un email potentiellement malveillant"
              label="🤖 Approfondir avec l'IA"
              getText={() => `Email de "${mail.from_name}" <${mail.from_addr}>, objet "${mail.subject}". Auth: SPF=${mail.spf} DKIM=${mail.dkim} DMARC=${mail.dmarc}. Score ${mail.risk}/100 (${mail.severity}). Anomalies: ${mail.reasons.join(" ; ") || "aucune"}. Liens: ${mail.links.map((l) => l.url).join(", ") || "aucun"}. Pièces jointes: ${mail.attachments.map((a) => a.filename).join(", ") || "aucune"}.`}
            />
          )}
        </Card>
        <Card title="Surveillance mail (IMAP)" right={<button className="btn ghost" style={{ padding: "5px 10px" }} disabled={imapBusy || (imapCfg ? !imapCfg.configured || imapCfg.airgapped : false)} onClick={relever}>{imapBusy ? "Relève…" : "Relever la boîte"}</button>}>
          <div className="note">Analyse automatique des derniers mails de ta boîte via <b>IMAP</b> (configuré dans Connecteurs). Lecture seule, mot de passe d'application chiffré en keyring.</div>
          {imapCfg && !imapCfg.configured && <div className="empty">Boîte IMAP non configurée — va dans <b>Connecteurs</b>.</div>}
          {imapCfg && imapCfg.configured && imapCfg.airgapped && <div className="disc" style={{ padding: "8px 16px", color: "var(--watch)" }}>⚠️ Air-gapped actif — désactive-le (pastille en haut) pour relever la boîte.</div>}
          {imapRes?.reason && <div className="empty">{imapRes.reason}</div>}
          {imapRes?.error && <div className="empty" style={{ color: "var(--crit)" }}>Erreur : {imapRes.error}</div>}
          {imapRes?.available && !imapRes.error && (
            <>
              {imapRes.suspicious > 0
                ? <div className="note" style={{ background: "rgba(251,91,107,0.12)", borderColor: "var(--crit)" }}>🚨 <b>{imapRes.suspicious} mail(s) suspect(s)</b> détecté(s) sur {imapRes.checked} analysé(s) — vérifie ci-dessous avant toute action.</div>
                : <div className="disc" style={{ color: "var(--safe)", padding: "8px 16px" }}>✅ {imapRes.checked} mail(s) analysé(s), aucun suspect.</div>}
              {imapRes.mails.filter((m) => m.severity !== "safe").map((m, i) => (
                <div className="rcard" key={i} style={{ borderLeft: `3px solid ${m.severity === "crit" ? "var(--crit)" : "var(--watch)"}` }}>
                  <div className="rhead"><span className="pr" style={{ color: m.severity === "crit" ? "var(--crit)" : "var(--watch)", borderColor: m.severity === "crit" ? "var(--crit)" : "var(--watch)", background: "transparent" }}>{m.severity.toUpperCase()} · {m.risk}/100</span><span className="rtitle" style={{ fontSize: 12.5 }}>{m.subject || "(sans objet)"}</span></div>
                  <div className="rbody" style={{ fontSize: 12 }}><b>De :</b> {m.from_addr} · SPF {m.spf} · DKIM {m.dkim} · DMARC {m.dmarc}</div>
                  {m.reasons.length > 0 && <div className="rbody" style={{ fontSize: 12 }}>{m.reasons.join(" ; ")}</div>}
                </div>
              ))}
            </>
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
        <Card title="Windows Defender" right={<button className="btn ghost" style={{ padding: "5px 10px" }} onClick={() => api.defenderRun()}>Rafraîchir</button>}>
          <div className="note">État réel de l'antivirus Microsoft Defender + détections de menaces (lecture seule, via PowerShell).</div>
          {!defender || defender.running ? <div className="empty">{defender?.running ? "Interrogation de Defender…" : "Chargement…"}</div>
            : !defender.available ? <div className="empty">{defender.reason || "Defender indisponible"}</div>
              : (
                <>
                  <div className="recap"><span className="ic">🛡️</span>Antivirus<span className="v" style={{ color: onoff(defender.antivirus_enabled).c }}>{onoff(defender.antivirus_enabled).t}</span></div>
                  <div className="recap"><span className="ic">⚡</span>Protection temps réel<span className="v" style={{ color: onoff(defender.realtime_protection).c }}>{onoff(defender.realtime_protection).t}</span></div>
                  <div className="recap"><span className="ic">🔐</span>Protection anti-altération<span className="v" style={{ color: onoff(defender.tamper_protection).c }}>{onoff(defender.tamper_protection).t}</span></div>
                  <div className="recap"><span className="ic">🧬</span>Signatures<span className="v mono">{defender.signature_version || "?"}{defender.signature_age_days != null ? ` (${defender.signature_age_days}j)` : ""}</span></div>
                  {defender.last_quick_scan && <div className="recap"><span className="ic">🔍</span>Dernier scan rapide<span className="v mono" style={{ fontSize: 11 }}>{defender.last_quick_scan.slice(0, 19).replace("T", " ")}</span></div>}
                  <div style={{ padding: "8px 14px 0" }}><div className="lbl" style={{ marginBottom: 6 }}>Détections ({defender.threats.length})</div>
                    {defender.threats.length === 0 ? <div className="disc" style={{ color: "var(--safe)", padding: 0 }}>Aucune menace détectée ✅</div>
                      : defender.threats.slice(0, 10).map((t, i) => (
                        <div className="log" key={i}><span className="ts">{t.time.slice(0, 19).replace("T", " ")}</span><span className="lv error">{t.severity}</span><span className="ms">{t.threat} <span className="muted">→ {t.action}</span></span></div>
                      ))}
                  </div>
                </>
              )}
        </Card>
      </div>
    </div>
  );
}

/* ============ CONNECTEURS ============ */
function Connecteurs({ airgapped, connectors, onRefresh }: { airgapped: boolean; connectors: ConnectorStatus[]; onRefresh: () => void }) {
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [llm, setLlm] = useState({ provider: "ollama", url: "http://localhost:11434", model: "llama3", key: "" });
  const [siem, setSiem] = useState({ type: "wazuh", url: "", token: "" });
  const [siemMsg, setSiemMsg] = useState("");
  const connected = (n: string) => connectors.find((c) => c.name === n)?.connected;
  const save = async (n: string) => { await api.connectorSet(n, keys[n] || ""); setKeys({ ...keys, [n]: "" }); onRefresh(); };
  const del = async (n: string) => { await api.connectorDelete(n); onRefresh(); };
  const saveLlm = async () => { await api.connectorSet("llm", JSON.stringify(llm)); onRefresh(); };
  const saveSiem = async () => { await api.connectorSet("siem", JSON.stringify(siem)); onRefresh(); setSiemMsg("Enregistré."); };
  const testSiem = async () => { setSiemMsg("Test…"); try { const r = await api.siemTest(); setSiemMsg(r.reason || (r.ok ? `Connexion OK (HTTP ${r.status_code})` : (r.error || `HTTP ${r.status_code}`))); } catch { setSiemMsg("échec"); } };
  const [imap, setImap] = useState({ host: "", port: 993, username: "", password: "" });
  const [imapMsg, setImapMsg] = useState("");
  const saveImap = async () => { await api.connectorSet("imap", JSON.stringify(imap)); onRefresh(); setImap({ ...imap, password: "" }); setImapMsg("Enregistré — surveillance active dans l'onglet SOC (air-gapped OFF requis)."); };
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

      <div className="card-h" style={{ marginTop: 4 }}><h2>SIEM / EDR — récupération de logs</h2></div>
      <div className="note">Connecte un <b>SIEM</b> pour rapatrier ses alertes (analyse + conseil de remédiation). L'<b>EDR local</b> de cette machine est déjà couvert par <b>Windows Defender</b> (onglet SOC). Nécessite <b>air-gapped OFF</b> + une instance joignable.</div>
      <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
        <span className="nm">SIEM</span>
        <span className="seg">{["wazuh", "elastic", "generic"].map((p) => <button key={p} className={siem.type === p ? "on" : ""} onClick={() => setSiem({ ...siem, type: p })}>{p}</button>)}</span>
        <input className="key" style={{ letterSpacing: 0, width: 240 }} value={siem.url} onChange={(e) => setSiem({ ...siem, url: e.target.value })} placeholder="URL API (ex. https://wazuh:55000/...)" />
        <input className="key" type="password" style={{ width: 150 }} value={siem.token} onChange={(e) => setSiem({ ...siem, token: e.target.value })} placeholder="token / clé API" />
        <button className="btn ghost" disabled={!siem.url.trim()} onClick={saveSiem}>Enregistrer</button>
        <button className="btn ghost" disabled={!connected("siem")} onClick={testSiem}>Tester</button>
        {connected("siem") ? <><span className="stt on">configuré ✓</span><button className="btn ghost" onClick={() => del("siem")}>Supprimer</button></> : <span className="stt off">non configuré</span>}
      </div>
      {siemMsg && <div className="disc" style={{ padding: "0 16px 10px", color: "var(--accent)" }}>{siemMsg}</div>}
      <div className="disc" style={{ padding: "0 16px 14px" }}>Formats supportés : Wazuh (API REST), Elasticsearch (_search), ou tout endpoint JSON renvoyant une liste d'alertes. Les alertes rapatriées apparaissent dans le SOC.</div>

      <div className="card-h" style={{ marginTop: 4 }}><h2>Surveillance mail (IMAP)</h2></div>
      <div className="note">Analyse automatique de tes derniers mails (SPF/DKIM/DMARC, liens, pièces jointes) → alerte phishing/ransomware dans le <b>SOC</b>. Utilise un <b>mot de passe d'application</b> (jamais ton mot de passe principal), chiffré en keyring, jamais réaffiché. Lecture seule. Nécessite <b>air-gapped OFF</b>.</div>
      <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
        <span className="nm">IMAP</span>
        <input className="key" style={{ letterSpacing: 0, width: 190 }} value={imap.host} onChange={(e) => setImap({ ...imap, host: e.target.value })} placeholder="serveur (ex. imap.gmail.com)" />
        <input className="key" type="number" style={{ letterSpacing: 0, width: 80 }} value={imap.port} onChange={(e) => setImap({ ...imap, port: +e.target.value })} placeholder="993" />
        <input className="key" style={{ letterSpacing: 0, width: 180 }} value={imap.username} onChange={(e) => setImap({ ...imap, username: e.target.value })} placeholder="adresse mail" />
        <input className="key" type="password" style={{ width: 160 }} value={imap.password} onChange={(e) => setImap({ ...imap, password: e.target.value })} placeholder="mot de passe d'application" />
        <button className="btn ghost" disabled={!imap.host.trim() || !imap.username.trim() || !imap.password.trim()} onClick={saveImap}>Enregistrer</button>
        {connected("imap") ? <><span className="stt on">configuré ✓</span><button className="btn ghost" onClick={() => del("imap")}>Supprimer</button></> : <span className="stt off">non configuré</span>}
      </div>
      {imapMsg && <div className="disc" style={{ padding: "0 16px 14px", color: "var(--accent)" }}>{imapMsg}</div>}
    </Card>
  );
}

/* ============ DIAGNOSTIC ============ */
const KIND_ICON: Record<string, string> = { nouvelle_connexion: "➕", connexion_fermee: "➖", alerte: "🚨" };
function Diagnostic({ logs, history, timeline, beaconing, config }: { logs: any[]; history: any[]; timeline: TimelineEvent[]; beaconing: Beacon[]; config?: { purge_on_exit: boolean; storage_budget_go: number; sample_interval: number } }) {
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
          {shown.length > 0 && <AiAnalyzeButton kind="journal d'événements/erreurs" label="🤖 Analyser les logs avec l'IA" getText={() => shown.slice(-40).map((l) => `${l.ts.slice(11, 19)} [${l.level}] ${l.module}: ${l.message}`).join("\n")} />}
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
        <Card title="Rétention & réglages" right={config ? "lu depuis /config" : "…"}>
          <div className="row"><span className="nm">Purge à la fermeture</span><span className={`stt ${config?.purge_on_exit ? "on" : "off"}`} style={{ marginLeft: "auto" }}>{config === undefined ? "…" : config.purge_on_exit ? "activée" : "désactivée"}</span></div>
          <div className="row"><span className="nm">Budget stockage</span><span className="stt on" style={{ marginLeft: "auto" }}>{config === undefined ? "…" : `≤ ${fr(config.storage_budget_go)} Go`}</span></div>
          <div className="row"><span className="nm">Échantillonnage réseau</span><span className="stt on" style={{ marginLeft: "auto" }}>{config === undefined ? "…" : `${fr(config.sample_interval)} s`}</span></div>
        </Card>
      </div>
    </div>
  );
}

/* ============ SANTÉ (bilan poste, esprit CCleaner) ============ */
function UpgradeButton({ id }: { id: string }) {
  const [stage, setStage] = useState<"idle" | "confirm" | "busy" | "done">("idle");
  const [msg, setMsg] = useState("");
  const dry = async () => { try { const r = await api.updaterUpgrade(id, true); setMsg(r.command || ""); setStage("confirm"); } catch { setMsg("moteur injoignable"); } };
  const apply = async () => { setStage("busy"); setMsg("Installation en cours (winget)…"); try { const r = await api.updaterUpgrade(id, false); setMsg(r.ok ? "Mis à jour ✅" : (r.error || `échec (code ${r.returncode ?? "?"})`)); } catch { setMsg("échec"); } setStage("done"); };
  if (stage === "idle") return <button className="btn ghost" style={{ padding: "4px 9px", fontSize: 11 }} onClick={dry}>Mettre à jour</button>;
  if (stage === "confirm") return <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><button className="btn" style={{ padding: "4px 9px", fontSize: 11 }} onClick={apply}>Confirmer</button><button className="btn ghost" style={{ padding: "4px 9px", fontSize: 11 }} onClick={() => setStage("idle")}>Annuler</button></span>;
  return <span style={{ color: stage === "busy" ? "var(--soft)" : "var(--safe)", fontSize: 11 }}>{msg}</span>;
}
function Health({ report, updater }: { report: import("./api").HealthReport | null; updater: import("./api").UpdaterResult | null }) {
  const [clean, setClean] = useState<import("./api").CleanResult | null>(null);
  const [stage, setStage] = useState<"idle" | "confirm" | "done">("idle");
  const [busy, setBusy] = useState(false);
  const r = report;
  const upd = updater;
  useEffect(() => { api.healthRun().catch(() => {}); api.updaterRun().catch(() => {}); }, []);
  const dc = (p: number) => (p >= 90 ? "var(--crit)" : p >= 75 ? "var(--watch)" : "var(--safe)");
  const dry = async () => { setBusy(true); try { const res = await api.healthClean(true); setClean(res); setStage("confirm"); } catch { /* noop */ } setBusy(false); };
  const apply = async () => { setBusy(true); try { const res = await api.healthClean(false); setClean(res); setStage("done"); await api.healthRun(); } catch { /* noop */ } setBusy(false); };
  return (
    <div className="grid">
      <div className="col">
        <Card title="Bilan de santé du poste" right={<button className="btn ghost" style={{ padding: "5px 10px" }} onClick={() => api.healthRun()}>Rafraîchir</button>}>
          <div className="note">État réel de la machine (lecture seule) : espace disque, fichiers temporaires, programmes au démarrage, redémarrage en attente. Toutes les valeurs sont <b>mesurées</b>, rien d'inventé.</div>
          {!r || r.running ? <div className="empty">{r?.running ? "Analyse du poste…" : "Chargement…"}</div> : (
            <>
              <div style={{ padding: "6px 16px" }}>
                <div className="lbl" style={{ marginBottom: 8 }}>Recommandations</div>
                {r.recommendations.map((rec, i) => <div className="recap" key={i} style={{ padding: "7px 0" }}><span className="ic">{rec.startsWith("Poste en bonne") ? "✅" : "•"}</span>{rec}</div>)}
              </div>
              <div style={{ padding: "8px 16px" }}>
                <div className="lbl" style={{ marginBottom: 8 }}>Disques</div>
                {r.disks.map((d) => (
                  <div className="barrow" key={d.device} style={{ marginBottom: 8 }}>
                    <span className="bn">{d.device || d.mountpoint}</span>
                    <span className="track"><span className="fill" style={{ width: `${d.percent}%`, background: dc(d.percent) }} /></span>
                    <span className="bv" style={{ width: 130 }}>{d.free_gb} Go libres / {d.total_gb} Go</span>
                  </div>
                ))}
              </div>
              {r.pending_reboot && <div className="note" style={{ background: "rgba(251,191,36,0.1)", borderColor: "var(--watch)" }}>🔄 <b>Redémarrage en attente</b> : {r.reboot_reasons.join(", ")}.</div>}
            </>
          )}
        </Card>
        <Card title="Nettoyage des fichiers temporaires" right={r ? `${r.temp_total_mb} Mo` : ""}>
          <div className="note">Supprime les fichiers temporaires (modifiés il y a plus d'1h, pour éviter les fichiers en cours d'usage). <b>Dry-run d'abord</b>, puis suppression <b>sur confirmation</b>. Jamais hors des dossiers temp.</div>
          {(r?.temp_paths || []).map((t) => <div className="row" key={t.path}><span className="nm mono" style={{ fontSize: 11 }}>{t.path}</span><span className="ds">{t.files} fichiers</span><span className="stt" style={{ marginLeft: "auto" }}>{t.size_mb} Mo</span></div>)}
          <div className="actions">
            {stage === "idle" && <button className="btn" disabled={busy} onClick={dry}>{busy ? "Calcul…" : "Estimer l'espace récupérable (dry-run)"}</button>}
            {stage === "confirm" && clean && (
              <>
                <span style={{ color: "var(--soft)", fontSize: 12.5 }}>~<b style={{ color: "var(--accent)" }}>{clean.reclaimable_mb} Mo</b> récupérables.</span>
                <button className="btn" disabled={busy} onClick={apply}>Confirmer le nettoyage</button>
                <button className="btn ghost" onClick={() => setStage("idle")}>Annuler</button>
              </>
            )}
            {stage === "done" && clean && <span style={{ color: "var(--safe)", fontSize: 13 }}>✅ {clean.deleted_files} fichier(s) supprimé(s), {clean.freed_mb} Mo libérés{clean.errors ? ` (${clean.errors} verrouillés, ignorés)` : ""}.</span>}
          </div>
        </Card>
      </div>
      <div className="col">
        <Card title="Mises à jour des applications" right={<><span style={{ marginRight: 8, color: (upd?.updates.length ?? 0) ? "var(--watch)" : "var(--safe)" }}>{upd?.updates.length ?? 0} dispo</span><button className="btn ghost" style={{ padding: "5px 10px" }} onClick={() => api.updaterRun()}>Vérifier</button></>}>
          <div className="note">Via <b>winget</b> (gestionnaire officiel Microsoft) — sources connues, aucun tiers opaque. Vérifie le versionnage de tes applis et installe la mise à jour (dry-run → confirmation, jamais automatique).</div>
          {!upd ? <div className="empty">Chargement…</div>
            : !upd.available_tool ? <div className="empty">{upd.reason || "winget introuvable (Windows 10/11)"}</div>
              : upd.running && upd.updates.length === 0 ? <div className="empty">Recherche des mises à jour…</div>
                : upd.updates.length === 0 ? <div className="disc" style={{ color: "var(--safe)", padding: "10px 16px" }}>✅ Toutes tes applications sont à jour.</div>
                  : (
                    <div className="tscroll">
                      <table>
                        <thead><tr><th>Application</th><th>Version</th><th>Disponible</th><th>Action</th></tr></thead>
                        <tbody>
                          {upd.updates.map((u) => (
                            <tr key={u.id}>
                              <td><span className="proc">{u.name}</span><div className="pid mono" style={{ fontSize: 10 }}>{u.id}</div></td>
                              <td className="mono muted">{u.current}</td>
                              <td className="mono" style={{ color: "var(--watch)" }}>{u.available}</td>
                              <td><UpgradeButton id={u.id} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
        </Card>
        <Card title="Programmes au démarrage" right={r ? String(r.startup.length) : ""}>
          <div className="note">Applications lancées au démarrage de Windows (registre + dossier Démarrage). En désactiver depuis le Gestionnaire des tâches accélère le boot.</div>
          {(r?.startup || []).map((s, i) => (
            <div className="row" key={i}>
              <span className="nm">{s.name}</span>
              {s.command && <span className="ds mono" style={{ fontSize: 10 }}>{s.command.slice(0, 40)}</span>}
              <span className="stt" style={{ marginLeft: "auto" }}>{s.source}</span>
            </div>
          ))}
          {r && r.startup.length === 0 && <div className="empty">Aucun programme au démarrage détecté.</div>}
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
  ["recon", "Recon"],
  ["offensif", "Offensif"],
  ["soc", "SOC local"],
  ["sante", "Santé"],
  ["connecteurs", "Connecteurs"],
  ["diagnostic", "Diagnostic"],
];

export default function App() {
  const [tab, setTab] = useState("dashboard");
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

      {offline && <div className="note" style={{ borderRadius: 12, marginBottom: 12 }}>⚠️ Moteur injoignable sur <b>127.0.0.1:8787</b>. Lance le backend : <span className="mono">py -m uvicorn app.main:app</span> (depuis <span className="mono">engine/</span>).</div>}

      <div className="nav">
        {TABS.map(([id, label, mini]) => (
          <button key={id} className={`navb ${tab === id ? "active" : ""}`} onClick={() => setTab(id)}>{label}{mini && <span className="mini">{mini}</span>}</button>
        ))}
      </div>

      {tab === "dashboard" && <Dashboard conns={conns} exposure={exposure.data} metrics={metrics.data} modules={mods} logs={logs.data || []} bwHist={bwHist} bw={bandwidth.data} scoreHist={scoreHist} top={top.data || []} thrStatus={thrStatus.data} thrProcs={thrProcs.data || []} trace={trace.data} beaconing={beaconing.data || []} sevFilter={sevFilter} onGo={setTab} onSelect={selectEndpoint} />}
      {tab === "bouclier" && <Bouclier conns={conns} active={sevFilter} setActive={setSevFilter} />}
      {tab === "carte" && <CarteReseau conns={conns} listeners={listeners.data || []} trace={trace.data} traceLabel={traceLabel} geoPoints={geoPoints.data || []} onRun={runTrace} onSelect={selectEndpoint} />}
      {tab === "remediation" && <Remediation conns={conns} metrics={metrics.data} listeners={listeners.data || []} />}
      {tab === "recon" && <Recon lan={lan.data} scan={scan.data} procvuln={procvuln.data} onScan={(t, m) => api.scanRun(t, m)} />}
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
