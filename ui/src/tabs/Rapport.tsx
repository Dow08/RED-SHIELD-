import { useEffect, useState } from "react";
import { api } from "../api";
import type { ReportMeta, ReportMission } from "../api";

const RING = (band: string) => (band === "critique" ? "#b4232a" : band === "elevee" ? "#b7791f" : "#2f7d4f");

export default function Rapport() {
  const [model, setModel] = useState<ReportMission | null>(null);
  const [busy, setBusy] = useState(false);
  const [client, setClient] = useState("");
  const [perimetre, setPerimetre] = useState("");
  const [consultant, setConsultant] = useState("D. Poncelet");

  const assemble = async () => {
    setBusy(true);
    const meta: Partial<ReportMeta> = { consultant };
    if (client.trim()) meta.client = client.trim();
    if (perimetre.trim()) meta.perimetre = perimetre.trim();
    try { setModel(await api.reportMission(meta)); } catch { /* moteur injoignable */ }
    setBusy(false);
  };
  useEffect(() => { assemble(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const m = model;
  const withRemed = (m?.findings || []).filter((f) => f.remediation);

  return (
    <>
      <div className="no-print">
        <div className="note">Rapport de <b>mission</b> — assemblé depuis les <b>données réelles</b> du poste (exposition, conformité GRC, vulnérabilités applicatives). Rien d'inventé. Renseigne le client, puis <b>Générer le PDF</b> (impression → « Enregistrer en PDF »). L'édition/annotation complète arrive en phase 2.</div>
        <div className="toolbar" style={{ gap: 8, flexWrap: "wrap" }}>
          <input className="key" style={{ letterSpacing: 0, width: 190 }} placeholder="Client" value={client} onChange={(e) => setClient(e.target.value)} />
          <input className="key" style={{ letterSpacing: 0, width: 190 }} placeholder="Périmètre" value={perimetre} onChange={(e) => setPerimetre(e.target.value)} />
          <input className="key" style={{ letterSpacing: 0, width: 150 }} placeholder="Consultant" value={consultant} onChange={(e) => setConsultant(e.target.value)} />
          <button className="btn ghost" disabled={busy} onClick={assemble}>{busy ? "Assemblage…" : "↻ Assembler"}</button>
          <button className="btn" disabled={!m} onClick={() => window.print()}>⬇ Générer le PDF</button>
        </div>
      </div>

      {!m && <div className="empty">Assemblage du rapport…</div>}

      {m && (
        <div className="report-doc">
          {/* ---------- COUVERTURE (Éditorial) ---------- */}
          <div className="rpage rp-cover">
            <div className="r-top">
              <div className="r-logo">LOGO<br />DP</div>
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
            <div className="r-title">Audit<br /><em>sécurité</em></div>
            <div className="r-sub">{m.meta.perimetre} — {m.meta.client}</div>
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
              <div><span>Diffusion</span><b>Restreinte</b></div>
            </div>
            <div className="rp-lbl">Couverture</div>
          </div>

          {/* ---------- SYNTHÈSE + CONSTATS (Cabinet) ---------- */}
          <div className="rpage rp-body">
            <div className="r-top"><div className="r-mark">DP <span>Cyber</span></div><div className="r-ref">{m.meta.reference} · p.2</div></div>
            <div className="r-eyebrow">Synthèse pour la direction</div>
            <div className="r-syn">
              <div className="r-ring" style={{ ["--v" as any]: m.score, ["--rc" as any]: RING(m.band) }}><b>{m.score}</b></div>
              <div className="r-verdict">{m.verdict}</div>
            </div>
            <div className="r-kpi">
              <div><div className="n">{m.kpis.findings ?? 0}</div><div className="t">à traiter</div></div>
              <div><div className="n">{m.kpis.critiques ?? 0}</div><div className="t">critique(s)</div></div>
              <div><div className="n">{m.kpis.exposes ?? 0}</div><div className="t">ports exposés</div></div>
            </div>
            <h3>Constats prioritaires</h3>
            {m.findings.length === 0 && <div className="r-verdict">Aucun constat prioritaire — posture saine sur le périmètre évalué.</div>}
            {m.findings.length > 0 && (
              <table className="r-fnd">
                <tbody>
                  {m.findings.map((f, i) => (
                    <tr key={i}>
                      <td style={{ width: 70 }}><span className={`r-sev ${f.severity}`}>{f.severity}</span></td>
                      <td>
                        <div className="rt">{f.title}</div>
                        {(f.detail || f.description) && <div className="rd">{f.detail || f.description}</div>}
                        {f.note && <div className="r-annot"><b>Note :</b> {f.note}</div>}
                      </td>
                      <td className="mono" style={{ width: 90, textAlign: "right" }}>
                        {f.cve || [f.refs.ISO, f.refs.NIST, f.refs.CIS].filter(Boolean)[0] || ""}
                        {f.cvss ? <div>CVSS {f.cvss}</div> : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <div className="rp-foot">{m.meta.marque} · {m.meta.confidentialite}</div>
            <div className="rp-lbl">Synthèse</div>
          </div>

          {/* ---------- REMÉDIATION + CONFORMITÉ (Cabinet) ---------- */}
          <div className="rpage rp-body">
            <div className="r-top"><div className="r-mark">DP <span>Cyber</span></div><div className="r-ref">{m.meta.reference} · p.3</div></div>
            <h3>Plan de remédiation</h3>
            {withRemed.length === 0 && <div className="r-verdict">Aucune action requise.</div>}
            {withRemed.map((f, i) => (
              <div className="r-rem" key={i}>
                <div className="rt"><span className={`r-sev ${f.severity}`} style={{ marginRight: 6 }}>{f.severity}</span>{f.title}</div>
                <div className="rd">{f.remediation}</div>
              </div>
            ))}
            {m.conformity.length > 0 && (
              <>
                <h3>Conformité (référentiels)</h3>
                {m.conformity.map((c) => (
                  <div className="r-conf-row" key={c.framework}>
                    <span style={{ width: 150, fontWeight: 600 }}>{c.label}</span>
                    <span className="r-conf-bar"><i style={{ width: `${c.score}%` }} /></span>
                    <span className="mono" style={{ width: 120, textAlign: "right" }}>{c.score}/100 · {c.ecarts} écart(s)</span>
                  </div>
                ))}
              </>
            )}
            <h3>Annexe — visuels</h3>
            <div className="r-shot">[ Emplacement capture — ex. carte du réseau, scan nmap ]</div>
            <div className="rp-foot">{m.meta.marque} · {m.meta.confidentialite}</div>
            <div className="rp-lbl">Remédiation</div>
          </div>
        </div>
      )}
    </>
  );
}
