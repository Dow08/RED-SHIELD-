import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";

export default function Remediation({ conns }: { conns: ScoredConnection[] }) {
  const risky = conns.filter((c) => c.severity === "suspect" || c.severity === "crit").sort((a, b) => b.risk - a.risk);
  return (
    <>
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
