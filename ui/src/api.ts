// Client API RED. En dev, /api est proxifié par Vite vers le moteur (127.0.0.1:8787).
// Dans le build natif (Tauri, pas de proxy), on appelle le moteur directement.
const BASE = import.meta.env.DEV ? "/api" : "http://127.0.0.1:8787";

export type Severity = "safe" | "watch" | "suspect" | "crit";

export interface MitreTag { id: string; name: string; url: string; }

export interface ScoredConnection {
  pid: number | null;
  process: string;
  exe: string;
  lineage: string;
  local_addr: string;
  remote_addr: string;
  remote_dns: string | null;
  dns_resolved: boolean;
  port: number;
  protocol: string;
  status: string;
  direction: string;
  risk: number;
  severity: Severity;
  reasons: string[];
  mitre: MitreTag[];
}

export interface Listener { pid: number | null; process: string; exe: string; addr: string; port: number; protocol: string; exposed: boolean; }
export interface PortCount { port: number; count: number; service: string; encrypted: boolean; }
export interface KeyCount { key: string; count: number; }
export interface CountryStat { key: string; count: number; processes: KeyCount[]; }
export interface NetMetrics {
  total: number; inbound: number; outbound: number; tcp: number; udp: number; udp_sockets: number;
  encrypted: number; clear: number; endpoints: number;
  listeners: number; listeners_exposed: number;
  countries: CountryStat[]; top_ports: PortCount[];
  tcp_ports: PortCount[]; udp_ports: PortCount[];
}

export interface Exposure {
  score: number;
  band: string;
  total: number;
  counts: Record<Severity, number>;
}

export interface NicRate { name: string; down_mo_s: number; up_mo_s: number; is_tunnel: boolean; }
export interface Bandwidth { down_bps: number; up_bps: number; down_mo_s: number; up_mo_s: number; nics: NicRate[]; note: string; }
export interface ProcThroughput { pid: number; process: string; down_bps: number; up_bps: number; down_mo_s: number; up_mo_s: number; }
export interface ThroughputStatus { available: boolean; admin: boolean; platform_ok: boolean; pktmon_present: boolean; capturing: boolean; reason: string; inbound_packets: number; packets_seen: number; }
export interface ModuleInfo { name: string; version: string; description: string; status: string; message: string; }
export interface TopTalker { pid: number; process: string; connections: number; }
export interface LogEntry { ts: string; level: string; module: string; message: string; }
export interface Hop { hop: number; ip: string; dns: string | null; city: string | null; country: string | null; lat: number | null; lon: number | null; private: boolean; }
export interface GeoPoint { ip: string; dns: string; lat: number; lon: number; country: string; city: string; process: string; count: number; severity: Severity; direction: string; }
export interface GeoView { home: GeoPoint | null; points: GeoPoint[]; }
export interface TraceResult { target: string; hops: Hop[]; public_ip: string | null; vpn_active: boolean; vpn_adapter: string | null; geo_available: boolean; running: boolean; error: string | null; }
export interface WifiNet { ssid: string; auth: string; encryption: string; channel: string; bssid: string; signal: number; risk: string; reason: string; }
export interface CrackResult { found: string | null; tried: number; algo: string; error: string | null; }
export interface TimelineEvent { ts: string; kind: string; severity: string; process: string; remote: string; }
export interface Beacon { process: string; remote: string; period_s: number; count: number; regularity: number; }
export interface LanDevice { ip: string; mac: string; vendor: string; }
export interface FwResult { ok: boolean; dry_run?: boolean; command?: string; output?: string; error?: string; }
export interface ScanCve { cve: string; cvss: number; severity: string; summary: string; url: string; }
export interface Compliance { framework: string; control: string; note: string; }
export interface ScanPort { port: number; protocol: string; state: string; service: string; product: string; version: string; cves: ScanCve[]; osi_layer: number; osi_label: string; compliance: Compliance[]; suggestions: string[]; }
export interface ScanHost { ip: string; hostname: string; os: string; ports: ScanPort[]; }
export interface ScanResult { target: string; mode: string; hosts: ScanHost[]; running: boolean; error: string | null; nmap_available: boolean; }
export interface ProcCve { cve: string; cvss: number; severity: string; summary: string; url: string; }
export interface ProcVuln { process: string; pid: number | null; exe: string; product: string; version: string; cves: ProcCve[]; }
export interface ProcVulnResult { apps: ProcVuln[]; scanned: number; running: boolean; available: boolean; note: string; }
export interface HidsEvent { ts: string; log: string; event_id: number; severity: string; label: string; message: string; }
export interface HidsResult { events: HidsEvent[]; running: boolean; available: boolean; note: string; }
export interface MailLink { url: string; suspicious: boolean; reason: string; }
export interface MailAttachment { filename: string; risky: boolean; }
export interface MailAnalysis { from_addr: string; from_name: string; subject: string; date: string; spf: string; dkim: string; dmarc: string; links: MailLink[]; attachments: MailAttachment[]; risk: number; severity: string; reasons: string[]; error: string | null; }
export interface DefenderThreat { time: string; threat: string; severity: string; action: string; resource: string; }
export interface DefenderStatus { available: boolean; reason: string; antivirus_enabled: boolean | null; realtime_protection: boolean | null; antispyware_enabled: boolean | null; tamper_protection: boolean | null; signature_version: string; signature_age_days: number | null; last_quick_scan: string; last_full_scan: string; threats: DefenderThreat[]; running: boolean; }
export interface ImapMail { uid: string; from_addr: string; subject: string; date: string; spf: string; dkim: string; dmarc: string; risk: number; severity: string; reasons: string[]; }
export interface ImapResult { available: boolean; reason: string; error: string; checked: number; suspicious: number; mails: ImapMail[]; }
export interface ConnectorStatus { name: string; connected: boolean; }
export interface IntelResult { available: boolean; reason?: string; ip?: string; sources: Record<string, unknown>[]; }
export interface OsintResult { available: boolean; reason?: string; error?: string; domain?: string; subdomains: string[]; }
export interface LlmResult { ok: boolean; analysis?: string; error?: string; }
export interface Snapshot { id: number; taken_at: string; exposure_score: number; band: string; total: number; safe: number; watch: number; suspect: number; crit: number; }
export interface DiskInfo { device: string; mountpoint: string; total_gb: number; used_gb: number; free_gb: number; percent: number; }
export interface Cleanable { id: string; label: string; size_mb: number; files: number; admin: boolean; warn: string; }
export interface StartupItem { name: string; command: string; source: string; enabled: boolean; }
export interface BigFile { path: string; size_mb: number; }
export interface ProcMem { process: string; mb: number; }
export interface HealthReport { available: boolean; platform_ok: boolean; disks: DiskInfo[]; cleanables: Cleanable[]; cleanable_total_mb: number; startup: StartupItem[]; pending_reboot: boolean; reboot_reasons: string[]; windows_old: boolean; largest_files: BigFile[]; ram_percent: number; ram_total_gb: number; ram_used_gb: number; top_memory: ProcMem[]; recommendations: string[]; running: boolean; }
export interface CleanResult { category: string; dry_run: boolean; reclaimable_mb: number; freed_mb: number; deleted_files: number; errors: number; error: string; }
export interface AppUpdate { name: string; id: string; current: string; available: string; source: string; }
export interface UpdaterResult { available_tool: boolean; reason: string; updates: AppUpdate[]; running: boolean; }
export interface UpgradeResult { ok: boolean; dry_run?: boolean; command?: string; output?: string; error?: string; returncode?: number; }
export type GrcStatus = "conforme" | "a_traiter" | "non_conforme" | "na" | "manuel";
export interface Attachment { name: string; type: string; data: string; }
export interface GrcControl { id: string; domain: string; title: string; why: string; refs: Record<string, string>; remediation: string; families: string[]; signal: string | null; status: GrcStatus; finding: string; note: string; attachments: Attachment[]; overridden: boolean; source: "auto" | "manuel"; }
export interface GrcScore { framework: string; label: string; score: number; assessed: number; total: number; counts: Record<GrcStatus, number>; }
export interface GrcPosture { frameworks: Record<string, string>; scores: GrcScore[]; controls: GrcControl[]; summary: { total: number; counts: Record<GrcStatus, number>; a_traiter_ids: string[] }; }
export type Sev = "crit" | "haut" | "moyen" | "faible";
export interface ReportMeta { marque: string; titre: string; consultant: string; client: string; perimetre: string; reference: string; date: string; confidentialite: string; logo: string; autorisation: string; }
export interface ReportFinding { id: string; included: boolean; severity: Sev; title: string; description: string; detail: string; asset: string; remediation: string; refs: Record<string, string>; cve: string; cvss: number | null; source: string; note: string; }
export interface ReportFrameworkScore { framework: string; label: string; score: number; ecarts: number; }
export interface ReportMission { meta: ReportMeta; score: number; band: string; band_label: string; counts: Record<string, number>; verdict: string; kpis: Record<string, number>; findings: ReportFinding[]; conformity: ReportFrameworkScore[]; annexes: Attachment[]; sections: Record<string, boolean>; generated_at: string; }

async function get<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(BASE + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => get<{ status: string; version: string; airgapped: boolean }>("/health"),
  modules: () => get<ModuleInfo[]>("/modules"),
  connections: () => get<ScoredConnection[]>("/shield/connections"),
  topTalkers: () => get<TopTalker[]>("/shield/top-talkers"),
  listeners: () => get<Listener[]>("/shield/listeners"),
  metrics: () => get<NetMetrics>("/shield/metrics"),
  geoPoints: () => get<GeoView>("/shield/geo"),
  bandwidth: () => get<Bandwidth>("/bandwidth"),
  throughputStatus: () => get<ThroughputStatus>("/throughput/status"),
  throughputProcesses: () => get<ProcThroughput[]>("/throughput/processes"),
  exposure: () => get<Exposure>("/exposure"),
  logs: (level?: string) => get<LogEntry[]>("/diagnostic/logs" + (level ? `?level=${level}` : "")),
  history: () => get<Snapshot[]>("/history"),
  snapshot: async (): Promise<Snapshot> => {
    const res = await fetch(BASE + "/snapshot", { method: "POST" });
    if (!res.ok) throw new Error("snapshot");
    return res.json();
  },
  trace: (target?: string) => get<TraceResult>("/trace" + (target ? `?target=${encodeURIComponent(target)}` : "")),
  traceRun: async (target?: string) => {
    await fetch(BASE + "/trace/run" + (target ? `?target=${encodeURIComponent(target)}` : ""), { method: "POST" });
  },
  wifi: () => get<{ networks: WifiNet[]; message: string }>("/wifi/networks"),
  timeline: () => get<TimelineEvent[]>("/analytics/timeline"),
  beaconing: () => get<Beacon[]>("/analytics/beaconing"),
  lan: () => get<LanDevice[]>("/lan/devices"),
  firewallBlock: (ip: string, dry_run: boolean) => post<FwResult>("/firewall/block", { ip, dry_run }),
  firewallUnblock: (ip: string) => post<FwResult>("/firewall/unblock", { ip, dry_run: false }),
  firewallBlockPort: (port: number, protocol: string, dry_run: boolean) => post<FwResult>("/firewall/block-port", { port, protocol, dry_run }),
  firewallUnblockPort: (port: number, protocol: string) => post<FwResult>("/firewall/unblock-port", { port, protocol, dry_run: false }),
  firewallRules: () => get<string[]>("/firewall/rules"),
  scan: () => get<ScanResult>("/scan"),
  scanRun: (target: string, mode: string, bypass = false) => post<{ ok: boolean; error?: string }>("/scan/run", { target, mode, bypass }),
  procvuln: () => get<ProcVulnResult>("/procvuln"),
  procvulnRun: () => post<{ ok: boolean; error?: string }>("/procvuln/run", {}),
  hids: () => get<HidsResult>("/hids"),
  hidsRun: () => post<{ ok: boolean; error?: string }>("/hids/run", {}),
  defender: () => get<DefenderStatus>("/defender"),
  defenderRun: () => post<{ ok: boolean; error?: string }>("/defender/run", {}),
  mailAnalyze: async (eml: string): Promise<MailAnalysis> => {
    try {
      const res = await fetch(BASE + "/mail/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ eml }) });
      if (res.ok) return res.json();
    } catch { /* moteur absent (mobile) → repli local */ }
    const { analyzeEml } = await import("./mobile/offline");
    return analyzeEml(eml) as unknown as MailAnalysis;
  },
  imapStatus: () => get<{ configured: boolean; airgapped: boolean; host: string; username: string }>("/imap/status"),
  imapCheck: () => get<ImapResult>("/imap/check"),
  config: () => get<{ airgapped: boolean; purge_on_exit: boolean; storage_budget_go: number; sample_interval: number }>("/config"),
  setAirgapped: (airgapped: boolean) => post<{ airgapped: boolean }>("/config/airgapped", { airgapped }),
  connectors: () => get<ConnectorStatus[]>("/connectors"),
  connectorSet: (name: string, key: string) => post<{ ok: boolean }>(`/connectors/${name}`, { key }),
  connectorDelete: async (name: string) => { await fetch(BASE + `/connectors/${name}`, { method: "DELETE" }); },
  intelIp: (ip: string) => get<IntelResult>(`/intel/ip?ip=${encodeURIComponent(ip)}`),
  siemStatus: () => get<{ configured: boolean; airgapped: boolean; type: string; url: string }>("/siem/status"),
  siemTest: () => post<{ available: boolean; ok?: boolean; status_code?: number; error?: string; reason?: string }>("/siem/test", {}),
  siemAlerts: () => get<{ available: boolean; alerts: { time: string; level: string; rule: string; agent: string; description: string }[]; error?: string; reason?: string }>("/siem/alerts"),
  osintSubdomains: (domain: string) => post<OsintResult>("/osint/subdomains", { domain }),
  llmAnalyze: (text: string, kind: string) => post<LlmResult>("/llm/analyze", { text, kind }),
  crack: async (payload: { algo: string; target: string; salt?: string; iterations?: number; dklen?: number; words: string[] }): Promise<CrackResult> => {
    try {
      const res = await fetch(BASE + "/crack", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      if (res.ok) return res.json();
    } catch { /* moteur absent (mobile) → repli local */ }
    // Repli hors-ligne : md5/sha1/sha256/sha512 (PBKDF2 reste côté moteur desktop).
    if (payload.algo.startsWith("pbkdf2")) return { found: null, tried: 0, algo: payload.algo, error: "PBKDF2 nécessite le moteur (desktop)" };
    const { crackHash } = await import("./mobile/offline");
    const r = await crackHash(payload.algo, payload.target, payload.words);
    return { found: r.found, tried: r.tried, algo: r.algo, error: null };
  },
  healthReport: () => get<HealthReport>("/health/report"),
  healthRun: () => post<{ ok: boolean }>("/health/run", {}),
  healthClean: (category: string, dry_run: boolean) => post<CleanResult>("/health/clean", { category, dry_run }),
  healthStartup: (name: string, enabled: boolean) => post<{ ok: boolean; error?: string }>("/health/startup", { name, enabled }),
  healthRestorePoint: () => post<{ ok: boolean; error?: string }>("/health/restore-point", {}),
  updaterList: () => get<UpdaterResult>("/updater/list"),
  updaterRun: () => post<{ ok: boolean }>("/updater/run", {}),
  updaterUpgrade: (id: string, dry_run: boolean) => post<UpgradeResult>("/updater/upgrade", { id, dry_run }),
  reportMission: (meta?: Partial<ReportMeta>) => post<ReportMission>("/report/mission", { meta: meta || null }),
  reportDraftGet: () => get<ReportMission | { exists: false }>("/report/draft"),
  reportDraftSave: (model: ReportMission) => post<{ ok: boolean }>("/report/draft", model),
  reportDraftClear: async () => { await fetch(BASE + "/report/draft", { method: "DELETE" }); },
  grcPosture: () => get<GrcPosture>("/grc"),
  grcSetControl: (id: string, status: string, note: string, attachments?: Attachment[]) => post<GrcPosture>("/grc/control", { id, status, note, attachments: attachments ?? null }),
  grcExportUrl: BASE + "/grc/export",
  reportUrl: BASE + "/report/markdown",
  logsExportUrl: BASE + "/diagnostic/logs/export",
};
