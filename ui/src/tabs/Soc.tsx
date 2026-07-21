import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";

export default function Soc({ hids, defender }: { hids: HidsResult | null; defender: import("../api").DefenderStatus | null }) {
  const [eml, setEml] = useState("");
  const [mail, setMail] = useState<MailAnalysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [imapRes, setImapRes] = useState<import("../api").ImapResult | null>(null);
  const [imapBusy, setImapBusy] = useState(false);
  const [imapCfg, setImapCfg] = useState<{ configured: boolean; airgapped: boolean } | null>(null);
  const [siemRes, setSiemRes] = useState<{ available: boolean; alerts: { time: string; level: string; rule: string; agent: string; description: string }[]; error?: string; reason?: string } | null>(null);
  const [siemBusy, setSiemBusy] = useState(false);
  const releverSiem = async () => { setSiemBusy(true); try { setSiemRes(await api.siemAlerts()); } catch { setSiemRes(null); } setSiemBusy(false); };
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
        <Card title="SIEM — alertes" right={<button className="btn ghost" style={{ padding: "5px 10px" }} disabled={siemBusy} onClick={releverSiem}>{siemBusy ? "Relève…" : "Relever"}</button>}>
          <div className="note">Alertes rapatriées de ton SIEM (Wazuh/Elastic, configuré dans <b>Connecteurs</b>). Nécessite air-gapped OFF + instance joignable.</div>
          {!siemRes ? <div className="empty">Clique « Relever » pour interroger le SIEM.</div>
            : siemRes.reason ? <div className="empty">{siemRes.reason}</div>
              : siemRes.error ? <div className="empty" style={{ color: "var(--crit)" }}>Erreur : {siemRes.error}</div>
                : siemRes.alerts.length === 0 ? <div className="disc" style={{ color: "var(--safe)", padding: "8px 16px" }}>Aucune alerte remontée.</div>
                  : siemRes.alerts.map((a, i) => (
                    <div className="log" key={i}><span className="ts">{a.time.slice(0, 19).replace("T", " ")}</span><span className={`lv ${+a.level >= 10 ? "error" : +a.level >= 5 ? "warn" : "info"}`}>{a.level || "—"}</span><span className="ms">{a.rule} {a.agent && <span className="muted">({a.agent})</span>}</span></div>
                  ))}
        </Card>
      </div>
    </div>
  );
}

/* ============ CONNECTEURS ============ */
