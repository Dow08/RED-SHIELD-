import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";

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

export default function Offensif({ airgapped, wifi }: { airgapped: boolean; wifi: { networks: WifiNet[]; message: string } | null }) {
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
