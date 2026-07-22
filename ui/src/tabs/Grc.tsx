import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";
import Rapport from "./Rapport";
import { toAttachment } from "../lib/img";

const GRC_STATUS_META: Record<string, { label: string; color: string; short: string }> = {
  conforme: { label: "Conforme", color: "var(--safe)", short: "CONFORME" },
  a_traiter: { label: "À traiter", color: "var(--watch)", short: "À TRAITER" },
  non_conforme: { label: "Non conforme", color: "var(--crit)", short: "NON CONFORME" },
  na: { label: "Non applicable", color: "var(--faint)", short: "N/A" },
  manuel: { label: "À évaluer", color: "var(--accent2)", short: "À ÉVALUER" },
};

function ScoreRing({ score, label, sub }: { score: number; label: string; sub: string }) {
  const rad = 30, C = 2 * Math.PI * rad, dash = (score / 100) * C;
  const col = score >= 80 ? "var(--safe)" : score >= 50 ? "var(--watch)" : "var(--crit)";
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 3, minWidth: 92 }}>
      <svg viewBox="0 0 80 80" width="82" height="82">
        <circle cx="40" cy="40" r={rad} fill="none" stroke="var(--card-b)" strokeWidth="8" />
        <circle cx="40" cy="40" r={rad} fill="none" stroke={col} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={`${dash} ${C - dash}`} transform="rotate(-90 40 40)" />
        <text x="40" y="38" textAnchor="middle" fontSize="17" fontWeight="800" fill="var(--ink)">{score}</text>
        <text x="40" y="52" textAnchor="middle" fontSize="7" fill="var(--faint)">/ 100</text>
      </svg>
      <b style={{ fontSize: 12, color: "var(--soft)", textAlign: "center" }}>{label}</b>
      <span style={{ fontSize: 10.5, color: "var(--faint)" }}>{sub}</span>
    </div>
  );
}

type Att = import("../api").Attachment;
const STATUS_FR: Record<string, string> = { conforme: "Conforme", a_traiter: "À traiter", non_conforme: "Non conforme", na: "Non applicable", manuel: "À évaluer" };

function EvidenceBox({ note, setNote, atts, setAtts }: { note: string; setNote: (v: string) => void; atts: Att[]; setAtts: (a: Att[]) => void }) {
  const addFiles = async (files: FileList | null) => {
    if (!files) return;
    const news: Att[] = [];
    for (const f of Array.from(files).slice(0, 10)) news.push(await toAttachment(f, { maxDim: 1600, quality: 0.82 }));
    setAtts([...atts, ...news]);
  };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <input className="key" style={{ width: "100%", letterSpacing: 0 }} placeholder="Preuve / justification (référence ticket, procédure, commentaire…)" value={note} onChange={(e) => setNote(e.target.value)} />
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <label className="btn ghost" style={{ cursor: "pointer", padding: "4px 10px", fontSize: 11 }}>📎 Joindre un fichier (capture, PDF…)
          <input type="file" multiple accept="image/*,.pdf,.txt,.doc,.docx" onChange={(e) => addFiles(e.target.files)} style={{ display: "none" }} />
        </label>
        {atts.length === 0 && <span className="muted" style={{ fontSize: 11 }}>aucune pièce jointe</span>}
      </div>
      {atts.length > 0 && (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {atts.map((a, i) => (
            <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 6, border: "1px solid var(--card-b)", borderRadius: 6, padding: "3px 6px", fontSize: 11, background: "var(--card-solid)" }}>
              {a.type.startsWith("image/") ? <img src={a.data} alt="" style={{ width: 26, height: 26, objectFit: "cover", borderRadius: 3 }} /> : <span>📄</span>}
              <a href={a.data} download={a.name} style={{ maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.name}</a>
              <button className="btn ghost" style={{ padding: "0 5px", fontSize: 11 }} onClick={() => setAtts(atts.filter((_, j) => j !== i))}>✕</button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function GrcControlEditor({ c, busy, onSet }: { c: import("../api").GrcControl; busy: boolean; onSet: (id: string, status: string, note: string, atts: Att[]) => void }) {
  const [note, setNote] = useState(c.note);
  const [atts, setAtts] = useState<Att[]>(c.attachments || []);
  const [override, setOverride] = useState<string>(c.overridden ? c.status : "conforme");
  const [showOverride, setShowOverride] = useState(false);
  const [mstatus, setMstatus] = useState<string>(c.status === "manuel" ? "conforme" : c.status);
  useEffect(() => {
    setNote(c.note); setAtts(c.attachments || []); setShowOverride(false);
    setMstatus(c.status === "manuel" ? "conforme" : c.status);
  }, [c.id]); // eslint-disable-line
  const isAuto = !!c.signal;

  if (isAuto) {
    // Contrôle AUTO : le verdict calculé fait foi. On documente (preuve) ; la surcharge est délibérée.
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        <div className="disc" style={{ padding: 0 }}>
          <b style={{ color: "var(--accent)" }}>Évalué automatiquement</b> depuis l'état réel de la machine{c.overridden && <b style={{ color: "var(--watch)" }}> — surchargé manuellement</b>}. Joins une preuve si besoin ; surcharge uniquement si tu contestes le verdict.
        </div>
        <EvidenceBox note={note} setNote={setNote} atts={atts} setAtts={setAtts} />
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <button className="btn" disabled={busy} onClick={() => onSet(c.id, "auto", note, atts)}>{busy ? "…" : "💾 Enregistrer la preuve"}</button>
          {!showOverride && <button className="btn ghost" disabled={busy} onClick={() => setShowOverride(true)}>Surcharger le verdict…</button>}
          {c.overridden && <button className="btn ghost" disabled={busy} onClick={() => onSet(c.id, "auto", note, atts)}>↻ Revenir à l'auto</button>}
          {showOverride && (
            <>
              <select className="key" style={{ width: "auto", letterSpacing: 0 }} value={override} onChange={(e) => setOverride(e.target.value)}>
                {["conforme", "a_traiter", "non_conforme", "na"].map((s) => <option key={s} value={s}>{STATUS_FR[s]}</option>)}
              </select>
              <button className="btn" disabled={busy} onClick={() => onSet(c.id, override, note, atts)}>Appliquer la surcharge</button>
            </>
          )}
        </div>
      </div>
    );
  }

  // Contrôle MANUEL : à toi de l'évaluer. Le statut + la preuve sont le contenu.
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div className="disc" style={{ padding: 0 }}><b style={{ color: "var(--accent2)" }}>À évaluer par toi</b> (contrôle organisationnel) : choisis un statut et <b>joins une preuve</b> (procédure, capture, attestation…).</div>
      <EvidenceBox note={note} setNote={setNote} atts={atts} setAtts={setAtts} />
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <span className="muted" style={{ fontSize: 11 }}>Statut :</span>
        <select className="key" style={{ width: "auto", letterSpacing: 0 }} value={mstatus} onChange={(e) => setMstatus(e.target.value)}>
          {["conforme", "a_traiter", "non_conforme", "na"].map((s) => <option key={s} value={s}>{STATUS_FR[s]}</option>)}
        </select>
        <button className="btn" disabled={busy} onClick={() => onSet(c.id, mstatus, note, atts)}>{busy ? "…" : "💾 Enregistrer l'évaluation"}</button>
        {c.overridden && <button className="btn ghost" disabled={busy} onClick={() => onSet(c.id, "auto", note, atts)}>Réinitialiser</button>}
      </div>
    </div>
  );
}

function Posture() {
  const [post, setPost] = useState<import("../api").GrcPosture | null>(null);
  const [fam, setFam] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const load = () => api.grcPosture().then(setPost).catch(() => setPost(null));
  useEffect(() => { load(); }, []);
  const setControl = async (id: string, status: string, note: string, atts?: import("../api").Attachment[]) => {
    setBusy(id);
    try { setPost(await api.grcSetControl(id, status, note, atts)); } catch { /* ignore */ }
    setBusy(null);
  };
  if (!post) return <Card title="Conformité — assistant CISO"><div className="empty">Chargement de la posture de conformité…</div></Card>;
  const controls = post.controls.filter((c) =>
    (fam === "ALL" || c.families.includes(fam)) &&
    (statusFilter === "ALL" || c.status === statusFilter));
  const domains = [...new Set(controls.map((c) => c.domain))];
  const sum = post.summary.counts;
  return (
    <>
      <Card title="Conformité — assistant CISO" right={<a className="btn ghost" href={api.grcExportUrl}>⬇ Rapport d'audit</a>}>
        <div className="note">Suivi de conformité <b>réel</b> sur trois référentiels — <b>ISO/IEC 27001:2022</b>, <b>NIST CSF 2.0</b>, <b>CIS Controls v8</b>. Les contrôles techniques sont <b>auto-évalués</b> depuis l'état réel de ta machine ; les contrôles organisationnels sont à <b>évaluer manuellement</b> avec une preuve. Aucune donnée inventée, aucun envoi externe (fonctionne en air-gapped).</div>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", justifyContent: "center", padding: "12px 0 4px" }}>
          {post.scores.map((s) => (
            <ScoreRing key={s.framework} score={s.score} label={s.label} sub={`${s.counts.conforme} conforme(s) / ${s.assessed} évalué(s)`} />
          ))}
        </div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", justifyContent: "center", fontSize: 11, color: "var(--faint)", paddingTop: 6 }}>
          <span>✅ {sum.conforme} conforme(s)</span><span>·</span>
          <span>🟠 {sum.a_traiter} à traiter</span><span>·</span>
          <span>🔴 {sum.non_conforme} non conforme(s)</span><span>·</span>
          <span>◻️ {sum.manuel} à évaluer</span>
        </div>
      </Card>
      <div style={{ height: 12 }} />
      <Card title="Contrôles de sécurité" right={`${controls.length}/${post.controls.length}`}>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12, alignItems: "center" }}>
          <div className="seg">
            {["ALL", "ISO", "NIST", "CIS"].map((f) => <button key={f} className={fam === f ? "on" : ""} onClick={() => setFam(f)}>{f === "ALL" ? "Tous" : f}</button>)}
          </div>
          <select className="key" style={{ width: "auto", letterSpacing: 0 }} value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="ALL">Tous statuts</option>
            <option value="conforme">Conforme</option>
            <option value="a_traiter">À traiter</option>
            <option value="non_conforme">Non conforme</option>
            <option value="manuel">À évaluer</option>
            <option value="na">Non applicable</option>
          </select>
        </div>
        {controls.length === 0 && <div className="empty">Aucun contrôle pour ce filtre.</div>}
        {domains.map((dom) => (
          <div key={dom} style={{ marginBottom: 4 }}>
            <div className="grc-dom">{dom}</div>
            {controls.filter((c) => c.domain === dom).map((c) => {
              const meta = GRC_STATUS_META[c.status];
              const isOpen = open === c.id;
              return (
                <div className="rcard" key={c.id} style={{ borderLeft: `3px solid ${meta.color}` }}>
                  <div className="rhead" style={{ cursor: "pointer" }} onClick={() => setOpen(isOpen ? null : c.id)}>
                    <span className="pr" style={{ color: meta.color, borderColor: meta.color, background: "transparent", border: `1px solid ${meta.color}` }}>{meta.short}</span>
                    <span className="rtitle" style={{ fontSize: 13 }}>{c.title}</span>
                    {c.attachments.length > 0 && <span className="badge" style={{ marginLeft: "auto", borderColor: "var(--accent)", color: "var(--accent)" }}>📎 {c.attachments.length}</span>}
                    <span className="badge" style={{ marginLeft: c.attachments.length > 0 ? 0 : "auto", opacity: 0.65 }}>{c.source === "auto" ? "auto" : "manuel"}</span>
                    <span style={{ color: "var(--faint)" }}>{isOpen ? "▾" : "▸"}</span>
                  </div>
                  <div className="rmeta">
                    {c.refs.ISO && <span className="badge">ISO {c.refs.ISO}</span>}
                    {c.refs.NIST && <span className="badge">NIST {c.refs.NIST}</span>}
                    {c.refs.CIS && <span className="badge">CIS {c.refs.CIS}</span>}
                  </div>
                  {c.finding && <div className="rbody">{c.finding}</div>}
                  {c.note && <div className="rbody" style={{ color: "var(--accent2)" }}>📝 {c.note}</div>}
                  {isOpen && (
                    <div style={{ marginTop: 10, borderTop: "1px solid var(--card-b)", paddingTop: 10 }}>
                      <div style={{ fontSize: 12, color: "var(--soft)", marginBottom: 6, lineHeight: 1.5 }}><b>Pourquoi :</b> {c.why}</div>
                      <div style={{ fontSize: 12, color: "var(--soft)", marginBottom: 10, lineHeight: 1.5 }}><b>Recommandation :</b> {c.remediation}</div>
                      <GrcControlEditor c={c} busy={busy === c.id} onSet={setControl} />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </Card>
    </>
  );
}

export default function Grc() {
  const [view, setView] = useState<"posture" | "rapport">("posture");
  return (
    <>
      <div className="seg no-print" style={{ marginBottom: 12, width: "fit-content" }}>
        <button className={view === "posture" ? "on" : ""} onClick={() => setView("posture")}>Posture GRC</button>
        <button className={view === "rapport" ? "on" : ""} onClick={() => setView("rapport")}>Rapport de mission</button>
      </div>
      {view === "posture" ? <Posture /> : <Rapport />}
    </>
  );
}
