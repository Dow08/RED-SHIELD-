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
export interface Snapshot { id: number; taken_at: string; exposure_score: number; band: string; total: number; safe: number; watch: number; suspect: number; crit: number; }

async function get<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path);
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
  reportUrl: BASE + "/report/markdown",
  logsExportUrl: BASE + "/diagnostic/logs/export",
};
