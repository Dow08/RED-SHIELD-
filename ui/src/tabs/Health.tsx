import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";

function UpgradeButton({ id }: { id: string }) {
  const [stage, setStage] = useState<"idle" | "confirm" | "busy" | "done">("idle");
  const [msg, setMsg] = useState("");
  const dry = async () => { try { const r = await api.updaterUpgrade(id, true); setMsg(r.command || ""); setStage("confirm"); } catch { setMsg("moteur injoignable"); } };
  const apply = async () => { setStage("busy"); setMsg("Installation en cours (winget)…"); try { const r = await api.updaterUpgrade(id, false); setMsg(r.ok ? "Mis à jour ✅" : (r.error || `échec (code ${r.returncode ?? "?"})`)); } catch { setMsg("échec"); } setStage("done"); };
  if (stage === "idle") return <button className="btn ghost" style={{ padding: "4px 9px", fontSize: 11 }} onClick={dry}>Mettre à jour</button>;
  if (stage === "confirm") return <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><button className="btn" style={{ padding: "4px 9px", fontSize: 11 }} onClick={apply}>Confirmer</button><button className="btn ghost" style={{ padding: "4px 9px", fontSize: 11 }} onClick={() => setStage("idle")}>Annuler</button></span>;
  return <span style={{ color: stage === "busy" ? "var(--soft)" : "var(--safe)", fontSize: 11 }}>{msg}</span>;
}
function CleanButton({ category, onDone }: { category: string; onDone: () => void }) {
  const [stage, setStage] = useState<"idle" | "confirm" | "done">("idle");
  const [res, setRes] = useState<import("../api").CleanResult | null>(null);
  const [busy, setBusy] = useState(false);
  const dry = async () => { setBusy(true); try { const x = await api.healthClean(category, true); setRes(x); setStage("confirm"); } catch { /* */ } setBusy(false); };
  const apply = async () => { setBusy(true); try { const x = await api.healthClean(category, false); setRes(x); setStage("done"); onDone(); } catch { /* */ } setBusy(false); };
  if (stage === "idle") return <button className="btn ghost" style={{ padding: "4px 9px", fontSize: 11 }} disabled={busy} onClick={dry}>{busy ? "…" : "Nettoyer"}</button>;
  if (stage === "confirm") return <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><span style={{ fontSize: 11, color: "var(--soft)" }}>~{res?.reclaimable_mb} Mo</span><button className="btn" style={{ padding: "4px 9px", fontSize: 11 }} disabled={busy} onClick={apply}>Confirmer</button><button className="btn ghost" style={{ padding: "4px 9px", fontSize: 11 }} onClick={() => setStage("idle")}>Annuler</button></span>;
  return <span style={{ fontSize: 11, color: res?.error ? "var(--crit)" : "var(--safe)" }}>{res?.error || `${res?.freed_mb} Mo libérés`}</span>;
}
function StartupToggle({ item, onDone }: { item: import("../api").StartupItem; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const managed = item.source.startsWith("HKCU");   // seules les entrées HKCU\Run sont modifiables ici (sans admin)
  const toggle = async () => { setBusy(true); setErr(""); try { const x = await api.healthStartup(item.name, !item.enabled); if (!x.ok) setErr(x.error || "échec"); onDone(); } catch { setErr("échec"); } setBusy(false); };
  if (!managed) return <span className="muted" style={{ fontSize: 10 }}>{item.source.includes("Dossier") ? "dossier" : "admin requis"}</span>;
  return <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>{err && <span style={{ color: "var(--crit)", fontSize: 10 }}>{err}</span>}<button className="btn ghost" style={{ padding: "4px 9px", fontSize: 11 }} disabled={busy} onClick={toggle}>{item.enabled ? "Désactiver" : "Réactiver"}</button></span>;
}
function CleanDonut({ items }: { items: { label: string; size_mb: number }[] }) {
  const data = items.filter((i) => i.size_mb > 0);
  const total = data.reduce((s, i) => s + i.size_mb, 0);
  if (total <= 0) return <div className="disc" style={{ color: "var(--safe)", textAlign: "center" }}>✅ Rien à nettoyer</div>;
  const cx = 50, cy = 50, rad = 36, C = 2 * Math.PI * rad;
  const colors = ["var(--accent)", "var(--accent2)", "var(--safe)", "var(--watch)", "#a78bfa", "#f472b6", "var(--crit)"];
  let acc = 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16, padding: "8px 16px", flexWrap: "wrap" }}>
      <svg viewBox="0 0 100 100" width="112" height="112" style={{ flex: "none" }}>
        {data.map((d, i) => {
          const frac = d.size_mb / total; const dash = frac * C; const off = acc * C; acc += frac;
          return <circle key={i} cx={cx} cy={cy} r={rad} fill="none" stroke={colors[i % colors.length]} strokeWidth="14"
            strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={-off} transform={`rotate(-90 ${cx} ${cy})`} />;
        })}
        <text x={cx} y={cy - 1} textAnchor="middle" fontSize="15" fontWeight="800" fill="var(--ink)">{total >= 1000 ? (total / 1000).toFixed(1) : Math.round(total)}</text>
        <text x={cx} y={cy + 12} textAnchor="middle" fontSize="7" fill="var(--faint)">{total >= 1000 ? "Go" : "Mo"} récupérables</text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11.5, minWidth: 180 }}>
        {data.map((d, i) => (
          <span key={d.label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 9, height: 9, borderRadius: 2, background: colors[i % colors.length], flex: "none" }}></span>
            <span style={{ color: "var(--soft)" }}>{d.label}</span>
            <b style={{ marginLeft: "auto", fontVariantNumeric: "tabular-nums", color: "var(--faint)" }}>{d.size_mb >= 1000 ? `${(d.size_mb / 1000).toFixed(1)} Go` : `${d.size_mb} Mo`}</b>
          </span>
        ))}
      </div>
    </div>
  );
}
export default function Health({ report, updater }: { report: import("../api").HealthReport | null; updater: import("../api").UpdaterResult | null }) {
  const r = report;
  const upd = updater;
  const [restoreMsg, setRestoreMsg] = useState("");
  useEffect(() => { api.healthRun().catch(() => {}); api.updaterRun().catch(() => {}); }, []);
  const refresh = () => { api.healthRun().catch(() => {}); };
  const dc = (p: number) => (p >= 90 ? "var(--crit)" : p >= 75 ? "var(--watch)" : "var(--safe)");
  const restore = async () => { setRestoreMsg("Création du point de restauration…"); try { const x = await api.healthRestorePoint(); setRestoreMsg(x.ok ? "Point de restauration créé ✅" : (x.error || "échec")); } catch { setRestoreMsg("échec"); } };
  return (
    <div className="masonry">
        <Card title="Bilan de santé du poste" right={<button className="btn ghost" style={{ padding: "5px 10px" }} onClick={refresh}>Rafraîchir</button>}>
          <div className="note">État <b>réel</b> de la machine (lecture seule) : disques, mémoire, nettoyables, redémarrage en attente. Toutes les valeurs sont mesurées, rien d'inventé.</div>
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
                <div className="barrow" style={{ marginTop: 4 }}>
                  <span className="bn">Mémoire vive</span>
                  <span className="track"><span className="fill" style={{ width: `${r.ram_percent}%`, background: dc(r.ram_percent) }} /></span>
                  <span className="bv" style={{ width: 130 }}>{r.ram_used_gb} / {r.ram_total_gb} Go ({r.ram_percent}%)</span>
                </div>
              </div>
              {r.windows_old && <div className="note" style={{ background: "rgba(251,191,36,0.08)" }}>🗂️ <b>Windows.old</b> présent (plusieurs Go) — supprimable via le Nettoyage de disque Windows.</div>}
              {r.pending_reboot && <div className="note" style={{ background: "rgba(251,191,36,0.1)", borderColor: "var(--watch)" }}>🔄 <b>Redémarrage en attente</b> : {r.reboot_reasons.join(", ")}.</div>}
              <div className="actions">
                <button className="btn ghost" onClick={restore}>🛟 Créer un point de restauration</button>
                {restoreMsg && <span style={{ fontSize: 12, color: restoreMsg.includes("✅") ? "var(--safe)" : "var(--soft)" }}>{restoreMsg}</span>}
              </div>
            </>
          )}
        </Card>
        <Card title="Nettoyage" right={r ? `${r.cleanable_total_mb} Mo récupérables` : ""}>
          <div className="note">Nettoie par catégorie (temp, corbeille, caches navigateurs, miniatures, Windows Update). Chaque nettoyage : taille réelle → <b>dry-run → confirmation</b>. Protège les fichiers récents / en cours d'usage.</div>
          {r && !r.running && <CleanDonut items={r.cleanables} />}
          {(r?.cleanables || []).map((c) => (
            <div className="row" key={c.id}>
              <span className="nm">{c.label}{c.admin && <span className="badge" style={{ marginLeft: 6, fontSize: 9 }}>admin</span>}</span>
              <span className="ds">{c.files ? `${c.files} élément(s)` : ""}{c.warn ? ` · ${c.warn}` : ""}</span>
              <span className="stt" style={{ marginLeft: "auto", marginRight: 8 }}>{c.size_mb} Mo</span>
              <CleanButton category={c.id} onDone={refresh} />
            </div>
          ))}
          {r && r.cleanables.length === 0 && <div className="empty">Rien à nettoyer.</div>}
        </Card>
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
          <div className="note">Lancés au démarrage de Windows. Tu peux <b>désactiver</b> une entrée <span className="mono">HKCU\Run</span> (réversible : sauvegardée pour réactivation).</div>
          {(r?.startup || []).map((s, i) => (
            <div className="row" key={i}>
              <span className="nm" style={{ color: s.enabled ? "var(--ink)" : "var(--faint)" }}>{s.name}{!s.enabled && " (désactivé)"}</span>
              <span className="ds mono" style={{ fontSize: 10 }}>{s.source}</span>
              <span style={{ marginLeft: "auto" }}><StartupToggle item={s} onDone={refresh} /></span>
            </div>
          ))}
          {r && r.startup.length === 0 && <div className="empty">Aucun programme au démarrage détecté.</div>}
        </Card>
        <Card title="Plus gros fichiers" right="dossiers utilisateur">
          <div className="note">Les plus gros fichiers de tes dossiers Téléchargements/Documents/Vidéos… (lecture seule, pour repérer quoi supprimer manuellement).</div>
          {(r?.largest_files || []).map((f, i) => (
            <div className="row" key={i}><span className="nm mono" style={{ fontSize: 11 }}>{f.path.split("\\").pop()}</span><span className="ds mono" style={{ fontSize: 10 }}>{f.path.slice(0, 46)}</span><span className="stt" style={{ marginLeft: "auto" }}>{f.size_mb >= 1000 ? `${(f.size_mb / 1000).toFixed(1)} Go` : `${f.size_mb} Mo`}</span></div>
          ))}
          {r && r.largest_files.length === 0 && <div className="empty">Aucun fichier volumineux détecté.</div>}
        </Card>
        <Card title="Mémoire — top consommateurs" right={r ? `${r.ram_percent}%` : ""}>
          {(r?.top_memory || []).map((p, i) => (
            <div className="row" key={i}><span className="nm">{p.process}</span><span className="stt" style={{ marginLeft: "auto" }}>{p.mb >= 1000 ? `${(p.mb / 1000).toFixed(1)} Go` : `${Math.round(p.mb)} Mo`}</span></div>
          ))}
          {r && r.top_memory.length === 0 && <div className="empty">—</div>}
        </Card>
    </div>
  );
}

/* ============ APP ============ */
