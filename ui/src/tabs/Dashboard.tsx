import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";

export default function Dashboard({ conns, exposure, metrics, modules, logs, bwHist, bw, scoreHist, top, thrStatus, thrProcs, trace, beaconing, sevFilter, onGo, onSelect }: any) {
  const m = metrics as import("../api").NetMetrics | undefined;
  const thr = thrStatus as import("../api").ThroughputStatus | undefined;
  const procs = (thrProcs || []) as import("../api").ProcThroughput[];
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
