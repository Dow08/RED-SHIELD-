import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { ReportMeta, ReportMission, ReportFinding, Sev, Attachment, ReportBlock } from "../api";
import { Card } from "../shared";
import { toAttachment } from "../lib/img";

const RING = (band: string) => (band === "critique" ? "#b4232a" : band === "elevee" ? "#b7791f" : "#2f7d4f");

// Nettoyage du HTML riche : liste blanche de balises, pas d'attributs (ni style/on*/script).
const _ALLOWED = new Set(["B", "STRONG", "I", "EM", "U", "UL", "OL", "LI", "BR", "P", "DIV", "SPAN"]);
function sanitizeHtml(html: string): string {
  const tpl = document.createElement("template");
  tpl.innerHTML = html;
  const walk = (node: ParentNode) => {
    Array.from(node.children).forEach((el) => {
      if (!_ALLOWED.has(el.tagName)) { el.replaceWith(...Array.from(el.childNodes)); return; }
      Array.from(el.attributes).forEach((a) => el.removeAttribute(a.name));
      walk(el);
    });
  };
  walk(tpl.content);
  return tpl.innerHTML.trim();
}

/** Zone éditable directement sur le document. `rich` : gras/italique/listes (innerHTML sanitizé) ; sinon texte brut. */
function Editable({ value, onCommit, ph, className, style, rich }: { value: string; onCommit: (v: string) => void; ph?: string; className?: string; style?: React.CSSProperties; rich?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current; if (!el) return;
    // Sanitisation AUSSI au rendu (pas seulement au commit) : une valeur peut venir
    // d'un brouillon rechargé ou d'un champ dérivé du backend (bannière/CVE) → jamais
    // d'HTML brut injecté via innerHTML.
    const cur = rich ? el.innerHTML : el.textContent;
    if (cur !== value) { if (rich) el.innerHTML = sanitizeHtml(value); else el.textContent = value; }
  }, [value, rich]);
  return (
    <div ref={ref} contentEditable suppressContentEditableWarning
      className={`r-edit ${className || ""}`} style={style} data-ph={ph} title="Cliquer pour éditer"
      onBlur={(e) => { const t = rich ? sanitizeHtml(e.currentTarget.innerHTML) : (e.currentTarget.textContent || ""); if (t !== value) onCommit(t); }} />
  );
}

/** Petite barre de format agissant sur la zone éditable focalisée (execCommand sur la sélection). */
function FormatBar() {
  const cmd = (c: string) => (e: React.MouseEvent) => { e.preventDefault(); document.execCommand(c); };
  return (
    <span style={{ display: "inline-flex", gap: 4, alignItems: "center" }}>
      <span className="muted" style={{ fontSize: 11 }}>Format :</span>
      <button className="btn ghost" style={{ padding: "2px 8px", fontWeight: 800 }} onMouseDown={cmd("bold")} title="Gras (sélectionne du texte)">G</button>
      <button className="btn ghost" style={{ padding: "2px 8px", fontStyle: "italic" }} onMouseDown={cmd("italic")} title="Italique">I</button>
      <button className="btn ghost" style={{ padding: "2px 8px" }} onMouseDown={cmd("insertUnorderedList")} title="Liste à puces">• Liste</button>
    </span>
  );
}
const SEVS: Sev[] = ["crit", "haut", "moyen", "faible"];
const SECTIONS: [string, string][] = [["constats", "Constats"], ["remediation", "Remédiation"], ["conformite", "Conformité"], ["annexe", "Annexe / captures"]];

export default function Rapport() {
  const [model, setModel] = useState<ReportMission | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [showEditor, setShowEditor] = useState(true);
  const [aiBusy, setAiBusy] = useState(false);
  const [aiMsg, setAiMsg] = useState("");

  // -- chargement : brouillon sauvegardé, sinon assemblage frais ----------
  useEffect(() => {
    (async () => {
      try {
        const d = await api.reportDraftGet();
        if (d && (d as ReportMission).findings) { setModel(d as ReportMission); return; }
      } catch { /* moteur injoignable */ }
      assemble();
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const assemble = async (over?: Partial<ReportMeta>) => {
    setBusy(true); setMsg("");
    const meta: Partial<ReportMeta> = { ...(model?.meta || {}), ...(over || {}) };
    try { setModel(await api.reportMission(meta)); } catch { /* */ }
    setBusy(false);
  };
  const reassemble = () => {
    if (confirm("Ré-assembler depuis les données réelles ? Tes retouches (annotations, ordre, masquages) seront remplacées.")) assemble();
  };
  const save = async () => {
    if (!model) return;
    setBusy(true);
    try { await api.reportDraftSave(model); setMsg("Brouillon enregistré ✅"); } catch { setMsg("échec de sauvegarde"); }
    setBusy(false);
  };

  // -- synthèse assistée IA (réutilise le connecteur LLM ; gated air-gapped) --
  const aiSynth = async () => {
    if (!model) return;
    setAiBusy(true); setAiMsg("");
    const inc = model.findings.filter((f) => f.included);
    const text = `Score d'exposition ${model.score}/100 (${model.band_label}). `
      + (inc.length ? `Constats : ${inc.map((f) => `${f.severity} — ${f.title}`).join(" ; ")}. ` : "Aucun constat prioritaire. ")
      + (model.conformity.length ? `Conformité : ${model.conformity.map((c) => `${c.label} ${c.score}/100 (${c.ecarts} écart(s))`).join(" ; ")}.` : "");
    try {
      const r = await api.llmAnalyze(text, "synthèse exécutive d'un rapport d'audit de sécurité — ton professionnel et factuel, en français, 4 à 6 phrases, sans inventer de détail");
      if (r.ok && r.analysis) { setModel((mm) => mm && { ...mm, verdict: r.analysis! }); setAiMsg("Synthèse générée ✅ — relis et ajuste, c'est toi qui signes."); }
      else { setAiMsg((r.error || "échec") + " — connecteur LLM requis (onglet Connecteurs) + air-gapped désactivé."); }
    } catch { setAiMsg("moteur injoignable"); }
    setAiBusy(false);
  };

  // -- mutateurs -----------------------------------------------------------
  const upMeta = (patch: Partial<ReportMeta>) => setModel((m) => m && { ...m, meta: { ...m.meta, ...patch } });
  const upFinding = (id: string, patch: Partial<ReportFinding>) =>
    setModel((m) => m && { ...m, findings: m.findings.map((f) => (f.id === id ? { ...f, ...patch } : f)) });
  const move = (id: string, dir: -1 | 1) => setModel((m) => {
    if (!m) return m;
    const a = [...m.findings]; const i = a.findIndex((f) => f.id === id); const j = i + dir;
    if (i < 0 || j < 0 || j >= a.length) return m;
    [a[i], a[j]] = [a[j], a[i]]; return { ...m, findings: a };
  });
  const toggleSection = (k: string) => setModel((m) => m && { ...m, sections: { ...m.sections, [k]: !m.sections[k] } });
  // -- sections libres (blocs) --------------------------------------------
  const addBlock = () => setModel((mm) => mm && { ...mm, blocks: [...(mm.blocks || []), { id: "b" + Date.now().toString(36) + Math.random().toString(36).slice(2, 5), title: "Nouvelle section", body: "", placement: "intro" as const }] });
  const upBlock = (id: string, patch: Partial<ReportBlock>) => setModel((mm) => mm && { ...mm, blocks: (mm.blocks || []).map((b) => (b.id === id ? { ...b, ...patch } : b)) });
  const removeBlock = (id: string) => setModel((mm) => mm && { ...mm, blocks: (mm.blocks || []).filter((b) => b.id !== id) });
  const moveBlock = (id: string, dir: -1 | 1) => setModel((mm) => {
    if (!mm) return mm;
    const a = [...(mm.blocks || [])]; const i = a.findIndex((b) => b.id === id); const j = i + dir;
    if (i < 0 || j < 0 || j >= a.length) return mm;
    [a[i], a[j]] = [a[j], a[i]]; return { ...mm, blocks: a };
  });
  const onLogo = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]; if (!f) return;
    const att = await toAttachment(f, { maxDim: 320, mime: "image/png" });
    upMeta({ logo: att.data });
  };
  const addAnnexes = async (files: FileList | null) => {
    if (!files) return;
    setMsg("Traitement des captures…");
    const news: Attachment[] = [];
    for (const f of Array.from(files).slice(0, 12)) news.push(await toAttachment(f, { maxDim: 1600, quality: 0.82 }));
    setModel((mm) => mm && { ...mm, annexes: [...(mm.annexes || []), ...news] });
    setMsg(`${news.length} capture(s) ajoutée(s) — pense à Enregistrer`);
  };

  const m = model;
  const shown = (m?.findings || []).filter((f) => f.included);
  const withRemed = shown.filter((f) => f.remediation);
  const sec = m?.sections || {};
  const blocks = m?.blocks || [];

  return (
    <>
      {/* ================= ÉDITEUR (ne s'imprime pas) ================= */}
      <div className="no-print">
        <Card title="Rapport de mission — éditeur" right={
          <span style={{ display: "inline-flex", gap: 8, alignItems: "center" }}>
            {msg && <span className="muted" style={{ fontSize: 11, color: "var(--safe)" }}>{msg}</span>}
            <button className="btn ghost" onClick={() => setShowEditor((s) => !s)}>{showEditor ? "Masquer l'éditeur" : "Éditer"}</button>
            <button className="btn ghost" disabled={busy} onClick={reassemble}>↻ Ré-assembler</button>
            <button className="btn ghost" disabled={busy || !m} onClick={save}>💾 Enregistrer</button>
            <button className="btn" disabled={!m} onClick={() => window.print()}>⬇ Générer le PDF</button>
          </span>
        }>
          <div className="note">Document <b>vivant</b> : les faits viennent des <b>données réelles</b> (rien d'inventé). ✏️ <b>Clique directement dans l'aperçu</b> pour éditer n'importe quel texte (titres compris) ; sélectionne du texte puis utilise la barre <b>Format</b> pour gras/italique/listes. Le panneau ci-dessous gère le structurel. Pense à <b>Enregistrer</b>.</div>
          <div style={{ padding: "0 16px 8px" }}><FormatBar /></div>

          {showEditor && m && (
            <div style={{ padding: "4px 16px 14px", display: "flex", flexDirection: "column", gap: 12 }}>
              {/* méta */}
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                <input className="key" style={{ letterSpacing: 0, width: 190 }} placeholder="Client" value={m.meta.client} onChange={(e) => upMeta({ client: e.target.value })} />
                <input className="key" style={{ letterSpacing: 0, width: 220 }} placeholder="Périmètre" value={m.meta.perimetre} onChange={(e) => upMeta({ perimetre: e.target.value })} />
                <input className="key" style={{ letterSpacing: 0, width: 150 }} placeholder="Consultant" value={m.meta.consultant} onChange={(e) => upMeta({ consultant: e.target.value })} />
                <input className="key" style={{ letterSpacing: 0, width: 140 }} placeholder="Référence" value={m.meta.reference} onChange={(e) => upMeta({ reference: e.target.value })} />
                <input className="key" style={{ letterSpacing: 0, width: 230 }} placeholder="Réf. autorisation (mandat, ordre de mission…)" value={m.meta.autorisation} onChange={(e) => upMeta({ autorisation: e.target.value })} />
                <label className="btn ghost" style={{ cursor: "pointer" }}>{m.meta.logo ? "Logo ✓" : "Logo…"}<input type="file" accept="image/*" onChange={onLogo} style={{ display: "none" }} /></label>
                {m.meta.logo && <button className="btn ghost" style={{ padding: "4px 9px" }} onClick={() => upMeta({ logo: "" })}>✕</button>}
              </div>

              {/* annexes / captures */}
              <div>
                <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>Captures / annexes (jointes au rapport)</div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <label className="btn ghost" style={{ cursor: "pointer", padding: "4px 10px", fontSize: 11 }}>📎 Ajouter des captures
                    <input type="file" multiple accept="image/*" onChange={(e) => addAnnexes(e.target.files)} style={{ display: "none" }} />
                  </label>
                  {(m.annexes || []).length === 0 && <span className="muted" style={{ fontSize: 11 }}>aucune capture</span>}
                  {(m.annexes || []).map((a, i) => (
                    <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 5, border: "1px solid var(--card-b)", borderRadius: 6, padding: "3px 6px", fontSize: 11, background: "var(--card-solid)" }}>
                      <img src={a.data} alt="" style={{ width: 26, height: 26, objectFit: "cover", borderRadius: 3 }} />
                      <span style={{ maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.name}</span>
                      <button className="btn ghost" style={{ padding: "0 5px" }} onClick={() => setModel((mm) => mm && { ...mm, annexes: mm.annexes.filter((_, j) => j !== i) })}>✕</button>
                    </span>
                  ))}
                </div>
              </div>

              {/* sections libres */}
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
                  <span className="muted" style={{ fontSize: 11 }}>Sections libres (intro, contexte, méthodo, conclusion…)</span>
                  <button className="btn ghost" style={{ padding: "3px 9px", fontSize: 11 }} onClick={addBlock}>➕ Ajouter une section</button>
                  {blocks.length === 0 && <span className="muted" style={{ fontSize: 11 }}>— le corps de chaque section s'écrit dans l'aperçu</span>}
                </div>
                {blocks.map((b) => (
                  <div key={b.id} className="rcard" style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <input className="key" style={{ flex: 1, minWidth: 160, letterSpacing: 0 }} value={b.title} onChange={(e) => upBlock(b.id, { title: e.target.value })} placeholder="Titre de la section" />
                    <select className="key" style={{ width: "auto", letterSpacing: 0 }} value={b.placement} onChange={(e) => upBlock(b.id, { placement: e.target.value as "intro" | "fin" })}>
                      <option value="intro">Au début (après couverture)</option>
                      <option value="fin">À la fin</option>
                    </select>
                    <button className="btn ghost" style={{ padding: "2px 8px" }} onClick={() => moveBlock(b.id, -1)}>▲</button>
                    <button className="btn ghost" style={{ padding: "2px 8px" }} onClick={() => moveBlock(b.id, 1)}>▼</button>
                    <button className="btn ghost" style={{ padding: "2px 8px" }} onClick={() => removeBlock(b.id)}>✕</button>
                  </div>
                ))}
              </div>

              {/* sections */}
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center", fontSize: 12 }}>
                <span className="muted" style={{ fontSize: 11 }}>Sections :</span>
                {SECTIONS.map(([k, label]) => (
                  <label key={k} style={{ display: "inline-flex", gap: 5, alignItems: "center", color: "var(--soft)" }}>
                    <input type="checkbox" checked={sec[k] !== false} onChange={() => toggleSection(k)} />{label}
                  </label>
                ))}
              </div>

              {/* verdict éditable */}
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
                  <span className="muted" style={{ fontSize: 11 }}>Synthèse / verdict (éditable)</span>
                  <button className="btn ghost" style={{ padding: "3px 9px", fontSize: 11 }} disabled={aiBusy} onClick={aiSynth}>{aiBusy ? "Rédaction IA…" : "🤖 Rédiger avec l'IA"}</button>
                  {aiMsg && <span className="muted" style={{ fontSize: 11, color: aiMsg.includes("✅") ? "var(--safe)" : "var(--watch)" }}>{aiMsg}</span>}
                </div>
                <textarea value={m.verdict} onChange={(e) => setModel((mm) => mm && { ...mm, verdict: e.target.value })}
                  rows={3} style={{ width: "100%", background: "var(--card-solid)", border: "1px solid var(--card-b)", borderRadius: 8, color: "var(--ink)", fontFamily: "var(--ui)", fontSize: 12.5, padding: 8 }} />
              </div>

              {/* findings */}
              <div>
                <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>Constats — inclure / réordonner / annoter</div>
                {m.findings.length === 0 && <div className="empty">Aucun constat (poste sain).</div>}
                {m.findings.map((f) => (
                  <div key={f.id} className="rcard" style={{ opacity: f.included ? 1 : 0.5, borderLeft: `3px solid ${f.severity === "crit" ? "var(--crit)" : f.severity === "haut" ? "#c77416" : f.severity === "moyen" ? "var(--watch)" : "var(--safe)"}` }}>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                      <input type="checkbox" checked={f.included} onChange={(e) => upFinding(f.id, { included: e.target.checked })} title="Inclure dans le rapport" />
                      <select className="key" style={{ width: "auto", letterSpacing: 0, padding: "3px 6px" }} value={f.severity} onChange={(e) => upFinding(f.id, { severity: e.target.value as Sev })}>
                        {SEVS.map((s) => <option key={s} value={s}>{s}</option>)}
                      </select>
                      <span className="rtitle" style={{ fontSize: 12.5, flex: 1, minWidth: 140 }}>{f.title}</span>
                      <button className="btn ghost" style={{ padding: "2px 8px" }} onClick={() => move(f.id, -1)}>▲</button>
                      <button className="btn ghost" style={{ padding: "2px 8px" }} onClick={() => move(f.id, 1)}>▼</button>
                    </div>
                    <input className="key" style={{ width: "100%", letterSpacing: 0, marginTop: 6 }} placeholder="Annotation (ta lecture d'expert — apparaît dans le rapport)" value={f.note} onChange={(e) => upFinding(f.id, { note: e.target.value })} />
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
        <div style={{ height: 12 }} />
      </div>

      {!m && <div className="empty">Assemblage du rapport…</div>}

      {/* ================= APERÇU / IMPRESSION ================= */}
      {m && (
        <div className="report-doc">
          {/* ---------- COUVERTURE (Éditorial) ---------- */}
          <div className="rpage rp-cover">
            <div className="r-top">
              {m.meta.logo ? <img src={m.meta.logo} alt="logo" style={{ width: 46, height: 46, objectFit: "contain", borderRadius: 7 }} /> : <div className="r-logo">LOGO<br />DP</div>}
              <div className="r-mark">DP <span>Cyber</span> Consulting</div>
              <div className="r-conf">Confidentiel</div>
            </div>
            <div className="r-hero">
              <svg viewBox="0 0 400 150" width="100%" height="100%" preserveAspectRatio="xMidYMid slice">
                <g stroke="#3a352f" strokeWidth="1.2" fill="none" opacity=".8">
                  <path d="M28 120 L110 55 L200 95 L300 40 L380 80" />
                  <path d="M28 120 L160 128 L200 95 L270 124 L380 80" />
                  <path d="M110 55 L160 128 M200 95 L300 40 M270 124 L300 40" />
                </g>
                <g fill="#e8620e"><circle cx="28" cy="120" r="4" /><circle cx="300" cy="40" r="4.5" /></g>
                <g fill="#f4d9c4"><circle cx="110" cy="55" r="2.6" /><circle cx="200" cy="95" r="2.6" /><circle cx="160" cy="128" r="2.6" /><circle cx="270" cy="124" r="2.6" /><circle cx="380" cy="80" r="2.6" /></g>
              </svg>
            </div>
            <Editable className="r-title" value={m.meta.titre} ph="Titre du rapport" onCommit={(v) => upMeta({ titre: v })} />
            <Editable className="r-sub" value={`${m.meta.perimetre} — ${m.meta.client}`} ph="Sous-titre" onCommit={(v) => { const [p, ...rest] = v.split(" — "); upMeta({ perimetre: p.trim(), client: (rest.join(" — ") || m.meta.client).trim() }); }} />
            <div className="r-big">
              <div className="v">{m.score}</div>
              <div className="x">/100 · {m.band_label.toLowerCase()}<br />{m.meta.date} · {m.meta.reference}</div>
            </div>
            <div className="r-meta">
              <div><span>Client</span><b>{m.meta.client}</b></div>
              <div><span>Référence</span><b>{m.meta.reference}</b></div>
              <div><span>Périmètre</span><b>{m.meta.perimetre}</b></div>
              <div><span>Date</span><b>{m.meta.date}</b></div>
              <div><span>Consultant</span><b>{m.meta.consultant}</b></div>
              <div><span>Autorisation</span><b>{m.meta.autorisation || "—"}</b></div>
            </div>
            <div className="rp-lbl">Couverture</div>
          </div>

          {/* ---------- SECTIONS LIBRES — intro (après couverture) ---------- */}
          {blocks.filter((b) => b.placement === "intro").length > 0 && (
            <div className="rpage rp-body">
              <div className="r-top"><div className="r-mark">DP <span>Cyber</span></div><div className="r-ref">{m.meta.reference}</div></div>
              {blocks.filter((b) => b.placement === "intro").map((b) => (
                <div key={b.id} style={{ marginBottom: 8 }}>
                  <Editable value={b.title} onCommit={(v) => upBlock(b.id, { title: v })} ph="Titre de section" style={{ fontFamily: "Georgia, serif", fontSize: 17, margin: "18px 0 8px", fontWeight: 700 }} />
                  <Editable rich value={b.body} onCommit={(v) => upBlock(b.id, { body: v })} ph="Rédige cette section…" style={{ fontSize: 13, color: "#33322f", lineHeight: 1.55 }} />
                </div>
              ))}
              <div className="rp-foot">{m.meta.marque} · {m.meta.confidentialite}</div>
              <div className="rp-lbl">Contexte</div>
            </div>
          )}

          {/* ---------- SYNTHÈSE + CONSTATS (Cabinet) ---------- */}
          <div className="rpage rp-body">
            <div className="r-top"><div className="r-mark">DP <span>Cyber</span></div><div className="r-ref">{m.meta.reference} · p.2</div></div>
            <div className="r-eyebrow">Synthèse pour la direction</div>
            <div className="r-syn">
              <div className="r-ring" style={{ ["--v" as any]: m.score, ["--rc" as any]: RING(m.band) }}><b>{m.score}</b></div>
              <Editable rich className="r-verdict" value={m.verdict} ph="Rédige la synthèse…" onCommit={(v) => setModel((mm) => mm && { ...mm, verdict: v })} />
            </div>
            <div className="r-kpi">
              <div><div className="n">{shown.length}</div><div className="t">à traiter</div></div>
              <div><div className="n">{shown.filter((f) => f.severity === "crit").length}</div><div className="t">critique(s)</div></div>
              <div><div className="n">{m.kpis.exposes ?? 0}</div><div className="t">ports exposés</div></div>
            </div>
            {sec.constats !== false && <>
              <h3>Constats prioritaires</h3>
              {shown.length === 0 && <div className="r-verdict">Aucun constat retenu — posture saine sur le périmètre évalué.</div>}
              {shown.length > 0 && (
                <table className="r-fnd"><tbody>
                  {shown.map((f) => (
                    <tr key={f.id}>
                      <td style={{ width: 70 }}><span className={`r-sev ${f.severity}`}>{f.severity}</span></td>
                      <td>
                        <Editable className="rt" value={f.title} ph="Titre du constat" onCommit={(v) => upFinding(f.id, { title: v })} />
                        <Editable className="rd" value={f.detail || f.description} ph="Détail du constat…" onCommit={(v) => upFinding(f.id, { detail: v })} />
                        <Editable rich className="r-annot" value={f.note} ph="✏️ annoter ce constat…" onCommit={(v) => upFinding(f.id, { note: v })} />
                      </td>
                      <td className="mono" style={{ width: 90, textAlign: "right" }}>
                        {f.cve || [f.refs.ISO, f.refs.NIST, f.refs.CIS].filter(Boolean)[0] || ""}
                        {f.cvss ? <div>CVSS {f.cvss}</div> : null}
                      </td>
                    </tr>
                  ))}
                </tbody></table>
              )}
            </>}
            <div className="rp-foot">{m.meta.marque} · {m.meta.confidentialite}</div>
            <div className="rp-lbl">Synthèse</div>
          </div>

          {/* ---------- REMÉDIATION + CONFORMITÉ (Cabinet) ---------- */}
          <div className="rpage rp-body">
            <div className="r-top"><div className="r-mark">DP <span>Cyber</span></div><div className="r-ref">{m.meta.reference} · p.3</div></div>
            {sec.remediation !== false && <>
              <h3>Plan de remédiation</h3>
              {withRemed.length === 0 && <div className="r-verdict">Aucune action requise.</div>}
              {withRemed.map((f) => (
                <div className="r-rem" key={f.id}>
                  <div className="rt"><span className={`r-sev ${f.severity}`} style={{ marginRight: 6 }}>{f.severity}</span>{f.title}</div>
                  <Editable rich className="rd" value={f.remediation} ph="Remédiation…" onCommit={(v) => upFinding(f.id, { remediation: v })} />
                </div>
              ))}
            </>}
            {sec.conformite !== false && m.conformity.length > 0 && <>
              <h3>Conformité (référentiels)</h3>
              {m.conformity.map((c) => (
                <div className="r-conf-row" key={c.framework}>
                  <span style={{ width: 150, fontWeight: 600 }}>{c.label}</span>
                  <span className="r-conf-bar"><i style={{ width: `${c.score}%` }} /></span>
                  <span className="mono" style={{ width: 120, textAlign: "right" }}>{c.score}/100 · {c.ecarts} écart(s)</span>
                </div>
              ))}
            </>}
            {sec.annexe !== false && <>
              <h3>Annexe — visuels</h3>
              {(m.annexes || []).length === 0
                ? <div className="r-shot">[ Ajoute des captures via l'éditeur — carte du réseau, scan nmap, preuve… ]</div>
                : <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {m.annexes.map((a, i) => (
                      <figure key={i} style={{ margin: 0 }}>
                        <img src={a.data} alt={a.name} style={{ width: "100%", border: "1px solid #e5e3db", borderRadius: 4 }} />
                        <figcaption style={{ fontSize: 10, color: "#8a877f", marginTop: 3 }}>{a.name}</figcaption>
                      </figure>
                    ))}
                  </div>}
            </>}
            <div className="rp-foot">{m.meta.marque} · {m.meta.confidentialite}</div>
            <div className="rp-lbl">Remédiation</div>
          </div>

          {/* ---------- SECTIONS LIBRES — fin ---------- */}
          {blocks.filter((b) => b.placement === "fin").length > 0 && (
            <div className="rpage rp-body">
              <div className="r-top"><div className="r-mark">DP <span>Cyber</span></div><div className="r-ref">{m.meta.reference}</div></div>
              {blocks.filter((b) => b.placement === "fin").map((b) => (
                <div key={b.id} style={{ marginBottom: 8 }}>
                  <Editable value={b.title} onCommit={(v) => upBlock(b.id, { title: v })} ph="Titre de section" style={{ fontFamily: "Georgia, serif", fontSize: 17, margin: "18px 0 8px", fontWeight: 700 }} />
                  <Editable rich value={b.body} onCommit={(v) => upBlock(b.id, { body: v })} ph="Rédige cette section…" style={{ fontSize: 13, color: "#33322f", lineHeight: 1.55 }} />
                </div>
              ))}
              <div className="rp-foot">{m.meta.marque} · {m.meta.confidentialite}</div>
              <div className="rp-lbl">Conclusion</div>
            </div>
          )}
        </div>
      )}
    </>
  );
}
