// Client API RED. En dev, /api est proxifié vers le moteur (127.0.0.1:8787).
const BASE = "/api";

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
  risk: number;
  severity: Severity;
  reasons: string[];
  mitre: MitreTag[];
}

export interface Exposure {
  score: number;
  band: string;
  total: number;
  counts: Record<Severity, number>;
}

export interface Bandwidth { down_bps: number; up_bps: number; down_mo_s: number; up_mo_s: number; }
export interface ModuleInfo { name: string; version: string; description: string; status: string; message: string; }
export interface TopTalker { pid: number; process: string; connections: number; }
export interface LogEntry { ts: string; level: string; module: string; message: string; }
export interface Hop { hop: number; ip: string; dns: string | null; city: string | null; country: string | null; lat: number | null; lon: number | null; private: boolean; }
export interface TraceResult { target: string; hops: Hop[]; public_ip: string | null; vpn_active: boolean; vpn_adapter: string | null; geo_available: boolean; running: boolean; error: string | null; }
export interface WifiNet { ssid: string; auth: string; encryption: string; channel: string; bssid: string; signal: number; risk: string; reason: string; }
export interface CrackResult { found: string | null; tried: number; algo: string; error: string | null; }
export interface TimelineEvent { ts: string; kind: string; severity: string; process: string; remote: string; }
export interface Beacon { process: string; remote: string; period_s: number; count: number; regularity: number; }
export interface LanDevice { ip: string; mac: string; vendor: string; }
export interface FwResult { ok: boolean; dry_run?: boolean; command?: string; output?: string; error?: string; }
export interface Snapshot { id: number; taken_at: string; exposure_score: number; band: string; total: number; safe: number; watch: number; suspect: number; crit: number; }

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
  bandwidth: () => get<Bandwidth>("/bandwidth"),
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
  firewallRules: () => get<string[]>("/firewall/rules"),
  crack: async (payload: { algo: string; target: string; salt?: string; iterations?: number; dklen?: number; words: string[] }): Promise<CrackResult> => {
    const res = await fetch(BASE + "/crack", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (!res.ok) throw new Error("crack");
    return res.json();
  },
  reportUrl: BASE + "/report/markdown",
  logsExportUrl: BASE + "/diagnostic/logs/export",
};
