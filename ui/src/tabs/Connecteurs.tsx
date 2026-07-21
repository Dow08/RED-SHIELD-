import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api";
import type { Beacon, ConnectorStatus, CrackResult, HidsResult, IntelResult, LanDevice, LlmResult, MailAnalysis, OsintResult, ScanResult, ScoredConnection, Severity, TimelineEvent, TraceResult, WifiNet } from "../api";
import { BandwidthChart, NetworkGraph, Sparkline, TraceMap } from "../viz";
import { SEV_META, bandColor, bandLabel, fr, Card, ReputationButton, CutButton, ClosePortButton, Reorderable, Gauge, ConnRow, DualBar, Mtile, PortChips, AiAnalyzeButton } from "../shared";

const IMAP_PROVIDERS: Record<string, [string, number]> = {
  "gmail.com": ["imap.gmail.com", 993], "googlemail.com": ["imap.gmail.com", 993],
  "outlook.com": ["outlook.office365.com", 993], "outlook.fr": ["outlook.office365.com", 993],
  "hotmail.com": ["outlook.office365.com", 993], "hotmail.fr": ["outlook.office365.com", 993],
  "live.com": ["outlook.office365.com", 993], "live.fr": ["outlook.office365.com", 993], "msn.com": ["outlook.office365.com", 993],
  "yahoo.com": ["imap.mail.yahoo.com", 993], "yahoo.fr": ["imap.mail.yahoo.com", 993],
  "icloud.com": ["imap.mail.me.com", 993], "me.com": ["imap.mail.me.com", 993],
  "aol.com": ["imap.aol.com", 993], "gmx.com": ["imap.gmx.net", 993], "gmx.fr": ["imap.gmx.net", 993],
  "orange.fr": ["imap.orange.fr", 993], "wanadoo.fr": ["imap.orange.fr", 993], "free.fr": ["imap.free.fr", 993],
  "laposte.net": ["imap.laposte.net", 993], "sfr.fr": ["imap.sfr.fr", 993], "bbox.fr": ["imap.bbox.fr", 993],
  "zoho.com": ["imap.zoho.com", 993],
};
function imapAutodetect(email: string): { host: string; port: number } | null {
  const dom = email.split("@")[1]?.toLowerCase().trim();
  if (!dom) return null;
  if (IMAP_PROVIDERS[dom]) return { host: IMAP_PROVIDERS[dom][0], port: IMAP_PROVIDERS[dom][1] };
  return { host: "imap." + dom, port: 993 }; // supposition raisonnable (convention imap.<domaine>)
}
export default function Connecteurs({ airgapped, connectors, onRefresh }: { airgapped: boolean; connectors: ConnectorStatus[]; onRefresh: () => void }) {
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [llm, setLlm] = useState({ provider: "ollama", url: "http://localhost:11434", model: "llama3", key: "" });
  const [siem, setSiem] = useState({ type: "wazuh", url: "", username: "", password: "", token: "" });
  const [siemMsg, setSiemMsg] = useState("");
  const connected = (n: string) => connectors.find((c) => c.name === n)?.connected;
  const save = async (n: string) => { await api.connectorSet(n, keys[n] || ""); setKeys({ ...keys, [n]: "" }); onRefresh(); };
  const del = async (n: string) => { await api.connectorDelete(n); onRefresh(); };
  const saveLlm = async () => { await api.connectorSet("llm", JSON.stringify(llm)); onRefresh(); };
  const saveSiem = async () => { await api.connectorSet("siem", JSON.stringify(siem)); onRefresh(); setSiemMsg("Enregistré."); };
  const testSiem = async () => { setSiemMsg("Test…"); try { const r = await api.siemTest(); setSiemMsg(r.reason || (r.ok ? `Connexion OK (HTTP ${r.status_code})` : (r.error || `HTTP ${r.status_code}`))); } catch { setSiemMsg("échec"); } };
  const [imap, setImap] = useState({ host: "", port: 993, username: "", password: "" });
  const [imapMsg, setImapMsg] = useState("");
  const saveImap = async () => { await api.connectorSet("imap", JSON.stringify(imap)); onRefresh(); setImap({ ...imap, password: "" }); setImapMsg("Enregistré — surveillance active dans l'onglet SOC (air-gapped OFF requis)."); };
  const simple: [string, string][] = [["virustotal", "VirusTotal"], ["abuseipdb", "AbuseIPDB"], ["greynoise", "GreyNoise"], ["shodan", "Shodan"]];
  return (
    <Card title="Connecteurs — clés API" right="chiffrées (keyring OS)">
      <div className="note">Actifs seulement si <b>air-gapped désactivé</b> (actuellement <b style={{ color: airgapped ? "var(--watch)" : "var(--safe)" }}>{airgapped ? "ACTIF" : "OFF"}</b> — bascule via la pastille en haut à droite). Clés chiffrées dans le trousseau de l'OS, jamais réaffichées. <b>Je ne génère aucun compte</b> : utilise tes propres clés.</div>
      {simple.map(([name, label]) => (
        <div className="row" key={name}>
          <span className="nm">{label}</span>
          <input className="key" type="password" placeholder={connected(name) ? "•••• (configuré)" : "clé API"} value={keys[name] || ""} onChange={(e) => setKeys({ ...keys, [name]: e.target.value })} style={{ marginLeft: "auto" }} />
          <button className="btn ghost" disabled={!(keys[name] || "").trim()} onClick={() => save(name)}>Enregistrer</button>
          {connected(name) ? <><span className="stt on">connecté ✓</span><button className="btn ghost" onClick={() => del(name)}>Supprimer</button></> : <span className="stt off">non connecté</span>}
        </div>
      ))}
      <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
        <span className="nm">LLM (analyse IA)</span>
        <span className="seg">{["ollama", "anthropic", "openai"].map((p) => <button key={p} className={llm.provider === p ? "on" : ""} onClick={() => setLlm({ ...llm, provider: p })}>{p}</button>)}</span>
        {llm.provider === "ollama"
          ? <input className="key" style={{ letterSpacing: 0, width: 180 }} value={llm.url} onChange={(e) => setLlm({ ...llm, url: e.target.value })} placeholder="http://localhost:11434" />
          : <input className="key" type="password" style={{ width: 160 }} value={llm.key} onChange={(e) => setLlm({ ...llm, key: e.target.value })} placeholder="clé API" />}
        <input className="key" style={{ letterSpacing: 0, width: 130 }} value={llm.model} onChange={(e) => setLlm({ ...llm, model: e.target.value })} placeholder="modèle" />
        <button className="btn ghost" onClick={saveLlm}>Enregistrer</button>
        {connected("llm") ? <><span className="stt on">connecté ✓</span><button className="btn ghost" onClick={() => del("llm")}>Supprimer</button></> : <span className="stt off">non connecté</span>}
      </div>
      <div className="disc" style={{ padding: "10px 16px" }}>💡 Ollama (local, gratuit, hors-ligne) fonctionne même sous air-gapped. Anthropic/OpenAI = clé perso + air-gapped OFF.</div>

      <div className="card-h" style={{ marginTop: 4 }}><h2>SIEM / EDR — récupération de logs</h2></div>
      <div className="note">Connecte un <b>SIEM</b> pour rapatrier ses alertes (analyse + conseil de remédiation). L'<b>EDR local</b> de cette machine est déjà couvert par <b>Windows Defender</b> (onglet SOC). Nécessite <b>air-gapped OFF</b> + une instance joignable. <b>Wazuh</b> : pointe vers l'<b>indexeur</b> (ex. <span className="mono">https://wazuh:9200</span>) avec identifiant/mot de passe → requête <span className="mono">wazuh-alerts-*/_search</span>.</div>
      <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
        <span className="nm">SIEM</span>
        <span className="seg">{["wazuh", "elastic", "generic"].map((p) => <button key={p} className={siem.type === p ? "on" : ""} onClick={() => setSiem({ ...siem, type: p })}>{p}</button>)}</span>
        <input className="key" style={{ letterSpacing: 0, width: 220 }} value={siem.url} onChange={(e) => setSiem({ ...siem, url: e.target.value })} placeholder="URL indexeur (https://wazuh:9200)" />
        <input className="key" style={{ letterSpacing: 0, width: 120 }} value={siem.username} onChange={(e) => setSiem({ ...siem, username: e.target.value })} placeholder="identifiant" />
        <input className="key" type="password" style={{ width: 120 }} value={siem.password} onChange={(e) => setSiem({ ...siem, password: e.target.value })} placeholder="mot de passe" />
        <input className="key" type="password" style={{ width: 120 }} value={siem.token} onChange={(e) => setSiem({ ...siem, token: e.target.value })} placeholder="ou token/ApiKey" />
        <button className="btn ghost" disabled={!siem.url.trim()} onClick={saveSiem}>Enregistrer</button>
        <button className="btn ghost" disabled={!connected("siem")} onClick={testSiem}>Tester</button>
        {connected("siem") ? <><span className="stt on">configuré ✓</span><button className="btn ghost" onClick={() => del("siem")}>Supprimer</button></> : <span className="stt off">non configuré</span>}
      </div>
      {siemMsg && <div className="disc" style={{ padding: "0 16px 10px", color: "var(--accent)" }}>{siemMsg}</div>}
      <div className="disc" style={{ padding: "0 16px 14px" }}>Wazuh / Elasticsearch (<span className="mono">_search</span>) ou tout endpoint JSON. Certificat auto-signé du lab accepté. Les alertes apparaissent dans le SOC.</div>

      <div className="card-h" style={{ marginTop: 4 }}><h2>Surveillance mail (IMAP)</h2></div>
      <div className="note">Analyse automatique de tes derniers mails (SPF/DKIM/DMARC, liens, pièces jointes) → alerte phishing/ransomware dans le <b>SOC</b>. <b>Serveur/port détectés automatiquement</b> depuis ton adresse (gmail, outlook, yahoo, orange, free…). Utilise un <b>mot de passe d'application</b> (jamais ton mot de passe principal), chiffré en keyring, jamais réaffiché. Lecture seule. Nécessite <b>air-gapped OFF</b>.</div>
      <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
        <span className="nm">IMAP</span>
        <input className="key" style={{ letterSpacing: 0, width: 180 }} value={imap.username} onChange={(e) => { const u = e.target.value; const d = imapAutodetect(u); setImap({ ...imap, username: u, host: d ? d.host : imap.host, port: d ? d.port : imap.port }); }} placeholder="adresse mail (auto-détection)" />
        <input className="key" style={{ letterSpacing: 0, width: 190 }} value={imap.host} onChange={(e) => setImap({ ...imap, host: e.target.value })} placeholder="serveur (auto)" />
        <input className="key" type="number" style={{ letterSpacing: 0, width: 80 }} value={imap.port} onChange={(e) => setImap({ ...imap, port: +e.target.value })} placeholder="993" />
        <input className="key" type="password" style={{ width: 160 }} value={imap.password} onChange={(e) => setImap({ ...imap, password: e.target.value })} placeholder="mot de passe d'application" />
        <button className="btn ghost" disabled={!imap.host.trim() || !imap.username.trim() || !imap.password.trim()} onClick={saveImap}>Enregistrer</button>
        {connected("imap") ? <><span className="stt on">configuré ✓</span><button className="btn ghost" onClick={() => del("imap")}>Supprimer</button></> : <span className="stt off">non configuré</span>}
      </div>
      {imapMsg && <div className="disc" style={{ padding: "0 16px 14px", color: "var(--accent)" }}>{imapMsg}</div>}
    </Card>
  );
}

/* ============ DIAGNOSTIC ============ */
