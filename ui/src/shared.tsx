import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import type { IntelResult, LlmResult, ScoredConnection, Severity } from "./api";

export const SEV_META: Record<Severity, { c: string; l: string }> = {
  safe: { c: "s", l: "Sain" },
  watch: { c: "w", l: "À surveiller" },
  suspect: { c: "p", l: "Suspect" },
  crit: { c: "c", l: "Critique" },
};
export const bandColor = (band: string) => (band === "critique" ? "var(--crit)" : band === "elevee" ? "var(--watch)" : "var(--safe)");
export const bandLabel = (band: string) => (band === "critique" ? "Exposition critique" : band === "elevee" ? "Exposition élevée" : "Exposition faible");
export const fr = (n: number) => n.toFixed(1).replace(".", ",");

export function Card({ title, right, children, className, resizable }: { title: string; right?: React.ReactNode; children: React.ReactNode; className?: string; resizable?: boolean }) {
  const storeKey = "rs.card." + title;
  const [collapsed, setCollapsed] = useState(() => {
    try { return localStorage.getItem(storeKey) === "1"; } catch { return false; }
  });
  const toggle = () => setCollapsed((c) => {
    const n = !c;
    try { localStorage.setItem(storeKey, n ? "1" : "0"); } catch { /* ignore */ }
    return n;
  });
  return (
    <div className={`card ${collapsed ? "collapsed " : ""}${resizable ? "resizable " : ""}${className || ""}`}>
      <div className="card-h">
        <h2>{title}</h2>
        {right && <span className="r">{right}</span>}
        <button className="chev" aria-label="Réduire / agrandir" onClick={toggle}>
          {collapsed ? "▸" : "▾"}
        </button>
      </div>
      {children}
    </div>
  );
}

export function ReputationButton({ ip }: { ip: string }) {
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

export function CutButton({ ip }: { ip: string }) {
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

export function ClosePortButton({ port, protocol }: { port: number; protocol: string }) {
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

export function Reorderable({ ids, render, storageKey }: { ids: string[]; render: (id: string) => React.ReactNode; storageKey: string }) {
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

export function Gauge({ score, band }: { score: number; band: string }) {
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

export function ConnRow({ c, showCols }: { c: ScoredConnection; showCols: Record<string, boolean> }) {
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
      {showCols.dns && <td>{c.remote_dns ? <span className="muted">{c.remote_dns}</span> : c.dns_resolved ? <span className="muted" style={{ fontStyle: "italic" }} title="Aucun DNS inverse : IP directe (CDN/serveur cloud, fréquent)">serveur distant</span> : <span className="muted">…</span>}</td>}
      <td className="mono muted">{c.remote_addr}</td>
      {showCols.port && <td className="mono">{c.port}</td>}
      {showCols.risk && <td><span className="risk" style={{ color: rc }}>{c.risk}</span></td>}
      <td><span className={`sev ${m.c}`}><span className="d"></span>{m.l}</span></td>
    </tr>
  );
}
export function DualBar({ a, b, ca, cb }: { a: number; b: number; ca: string; cb: string }) {
  const tot = Math.max(1, a + b);
  return (
    <span className="dual" title={`${a} / ${b}`}>
      <span style={{ width: `${(a / tot) * 100}%`, background: ca }} />
      <span style={{ width: `${(b / tot) * 100}%`, background: cb }} />
    </span>
  );
}
export function Mtile({ label, hint, children, detail }: { label: string; hint?: string; children: React.ReactNode; detail?: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`mtile${detail ? " expandable" : ""}`} onClick={detail ? () => setOpen((o) => !o) : undefined} title={hint}>
      <div className="lbl">{label}{hint && <span className="qh">ⓘ</span>}{detail && <span className="exp">{open ? "▾" : "▸"}</span>}</div>
      {children}
      {detail && open && <div className="mdetail" onClick={(e) => e.stopPropagation()}>{detail}</div>}
    </div>
  );
}
export function PortChips({ ports }: { ports: import("./api").PortCount[] }) {
  if (!ports || ports.length === 0) return <span className="muted" style={{ fontSize: 11 }}>aucun</span>;
  return <>{ports.map((p) => <span key={p.port} className="pchip"><b style={{ color: p.encrypted ? "var(--safe)" : "var(--watch)" }}>{p.port}</b>{p.service ? " " + p.service : ""} <i>{p.count}</i></span>)}</>;
}
export function AiAnalyzeButton({ getText, kind, label }: { getText: () => string; kind: string; label?: string }) {
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
