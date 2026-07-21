import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";

const KIND_ICON: Record<string, string> = { nouvelle_connexion: "➕", connexion_fermee: "➖", alerte: "🚨" };
const sevClass = (s: string) => (s === "crit" || s === "suspect" ? "error" : s === "watch" ? "warn" : "info");
function frDay(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return "Date inconnue";
  const s = d.toLocaleDateString("fr-FR", { weekday: "long", day: "numeric", month: "long", year: "numeric" });
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function groupTimelineByDay(events: TimelineEvent[]): { key: string; label: string; events: TimelineEvent[] }[] {
  const map = new Map<string, TimelineEvent[]>();
  for (const e of events) {
    const key = (e.ts || "").slice(0, 10) || "?";
    (map.get(key) || map.set(key, []).get(key)!).push(e);
  }
  return [...map.entries()]
    .sort((a, b) => b[0].localeCompare(a[0]))
    .map(([k, v]) => ({ key: k, label: k === "?" ? "Date inconnue" : frDay(v[0].ts), events: v }));
}
export default function Diagnostic({ logs, history, timeline, beaconing, config }: { logs: any[]; history: any[]; timeline: TimelineEvent[]; beaconing: Beacon[]; config?: { purge_on_exit: boolean; storage_budget_go: number; sample_interval: number } | null }) {
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
          <div className="note">Événements réseau notables <b>regroupés par jour</b> pour une lecture rapide. Le <b>résumé IA</b> synthétise la période en langage clair (nécessite un connecteur LLM + air-gapped désactivé).</div>
          {(timeline || []).length > 0 && (
            <AiAnalyzeButton
              kind="timeline d'événements réseau (analyse de sécurité)"
              label="🤖 Résumer la période avec l'IA"
              getText={() => (timeline || []).slice(0, 60).map((e) => `${e.ts.slice(0, 19).replace("T", " ")} [${e.severity}] ${e.kind}: ${e.process} → ${e.remote}`).join("\n")}
            />
          )}
          {groupTimelineByDay(timeline || []).map((grp) => (
            <div key={grp.key}>
              <div className="grc-dom">{grp.label} · {grp.events.length} événement{grp.events.length > 1 ? "s" : ""}</div>
              {grp.events.slice(0, 30).map((e, i) => (
                <div className="log" key={i}>
                  <span className="ts">{e.ts.slice(11, 19)}</span>
                  <span className={`lv ${sevClass(e.severity)}`}>{KIND_ICON[e.kind] || "•"}</span>
                  <span className="ms">{e.process} → {e.remote} <span className="muted">({e.kind.replace(/_/g, " ")})</span></span>
                </div>
              ))}
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
          <div className="row"><span className="nm">Purge à la fermeture</span><span className={`stt ${config?.purge_on_exit ? "on" : "off"}`} style={{ marginLeft: "auto" }}>{!config ? "…" : config.purge_on_exit ? "activée" : "désactivée"}</span></div>
          <div className="row"><span className="nm">Budget stockage</span><span className="stt on" style={{ marginLeft: "auto" }}>{!config ? "…" : `≤ ${fr(config.storage_budget_go)} Go`}</span></div>
          <div className="row"><span className="nm">Échantillonnage réseau</span><span className="stt on" style={{ marginLeft: "auto" }}>{!config ? "…" : `${fr(config.sample_interval)} s`}</span></div>
        </Card>
      </div>
    </div>
  );
}

/* ============ SANTÉ (bilan poste, esprit CCleaner) ============ */
