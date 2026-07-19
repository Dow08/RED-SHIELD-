import { useEffect, useRef } from "react";
import type { ScoredConnection } from "./api";

function cvar(name: string, fallback: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}
const reduceMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function fitCanvas(cv: HTMLCanvasElement, ctx: CanvasRenderingContext2D, W: number, H: number) {
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const cw = cv.clientWidth || W;
  const ch = cw * (H / W);
  cv.width = cw * dpr;
  cv.height = ch * dpr;
  ctx.setTransform((dpr * cw) / W, 0, 0, (dpr * cw) / W, 0, 0);
}

const sevRank: Record<string, number> = { safe: 0, watch: 1, suspect: 2, crit: 3 };
const sevKey = ["safe", "watch", "suspect", "crit"];

function isPrivate(ip: string): boolean {
  if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") || ip === "::1") return true;
  const m = ip.match(/^172\.(\d+)\./);
  return !!m && +m[1] >= 16 && +m[1] <= 31;
}

/* ---------------- Sparkline ---------------- */
export function Sparkline({ values, color }: { values: number[]; color: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext("2d")!;
    const W = 440, H = 70;
    fitCanvas(cv, ctx, W, H);
    ctx.clearRect(0, 0, W, H);
    if (values.length < 2) return;
    const max = Math.max(...values, 1), min = Math.min(...values, 0);
    const c = cvar(color, "#fbbf24");
    const x = (i: number) => (i / (values.length - 1)) * W;
    const y = (v: number) => H - ((v - min) / (max - min || 1)) * (H - 8) - 4;
    ctx.beginPath();
    ctx.moveTo(0, H);
    values.forEach((v, i) => ctx.lineTo(x(i), y(v)));
    ctx.lineTo(W, H);
    ctx.closePath();
    const g = ctx.createLinearGradient(0, 0, 0, H);
    g.addColorStop(0, c + "55");
    g.addColorStop(1, c + "05");
    ctx.fillStyle = g;
    ctx.fill();
    ctx.beginPath();
    values.forEach((v, i) => (i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))));
    ctx.strokeStyle = c;
    ctx.lineWidth = 1.8;
    ctx.stroke();
  }, [values, color]);
  return <canvas ref={ref} />;
}

/* ---------------- Bandwidth (Débit) ---------------- */
export function BandwidthChart({ history }: { history: { d: number; u: number }[] }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext("2d")!;
    const W = 520, H = 120;
    fitCanvas(cv, ctx, W, H);
    ctx.clearRect(0, 0, W, H);
    ctx.strokeStyle = "#141a26";
    ctx.lineWidth = 1;
    for (let y = 0; y <= H; y += 30) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(W, y);
      ctx.stroke();
    }
    const n = history.length;
    if (n < 2) return;
    const max = Math.max(1, ...history.map((h) => Math.max(h.d, h.u)));
    const area = (get: (h: { d: number; u: number }) => number, color: string) => {
      const y = (v: number) => H - (v / max) * (H - 10) - 4;
      ctx.beginPath();
      ctx.moveTo(0, H);
      history.forEach((h, i) => ctx.lineTo((i / (n - 1)) * W, y(get(h))));
      ctx.lineTo(W, H);
      ctx.closePath();
      const g = ctx.createLinearGradient(0, 0, 0, H);
      g.addColorStop(0, color + "4d");
      g.addColorStop(1, color + "05");
      ctx.fillStyle = g;
      ctx.fill();
      ctx.beginPath();
      history.forEach((h, i) => {
        const px = (i / (n - 1)) * W, py = y(get(h));
        i ? ctx.lineTo(px, py) : ctx.moveTo(px, py);
      });
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.6;
      ctx.stroke();
    };
    area((h) => h.d, cvar("--safe", "#34d399"));
    area((h) => h.u, cvar("--accent", "#2fe0d0"));
  }, [history]);
  return <canvas ref={ref} />;
}

/* ---------------- Radar (décoratif — conservé à l'identique) ---------------- */
export function Radar({ counts }: { counts?: Record<string, number> }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const countsRef = useRef(counts);
  countsRef.current = counts;
  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext("2d")!;
    const W = 480, H = 300;
    const ro = new ResizeObserver(() => fitCanvas(cv, ctx, W, H));
    ro.observe(cv);
    fitCanvas(cv, ctx, W, H);
    const cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 14;
    const blips = [
      { a: 0.7, d: 0.55, s: "g" }, { a: 2.1, d: 0.8, s: "r" }, { a: 3.4, d: 0.4, s: "w" },
      { a: 4.6, d: 0.7, s: "r" }, { a: 5.5, d: 0.6, s: "g" }, { a: 1.3, d: 0.35, s: "g" },
    ];
    const reduce = reduceMotion();
    let ang = 0, raf = 0;
    const draw = () => {
      const c = cvar("--accent", "#2fe0d0");
      const col: Record<string, string> = { g: cvar("--safe", "#34d399"), w: cvar("--watch", "#fbbf24"), r: cvar("--crit", "#fb5b6b") };
      ctx.clearRect(0, 0, W, H);
      ctx.strokeStyle = c;
      ctx.globalAlpha = 0.22;
      ctx.lineWidth = 1;
      [0.33, 0.66, 1].forEach((r) => { ctx.beginPath(); ctx.arc(cx, cy, R * r, 0, 7); ctx.stroke(); });
      for (let i = 0; i < 6; i++) { const a = (i / 6) * Math.PI * 2; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R); ctx.stroke(); }
      ctx.globalAlpha = 1;
      if (!reduce) ang += 0.02;
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(ang);
      const g = ctx.createLinearGradient(0, 0, R, 0);
      g.addColorStop(0, c + "66");
      g.addColorStop(1, c + "00");
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, R, -0.45, 0);
      ctx.closePath();
      ctx.fill();
      ctx.restore();
      blips.forEach((b) => {
        const x = cx + Math.cos(b.a) * R * b.d, y = cy + Math.sin(b.a) * R * b.d, cc = col[b.s];
        const pulse = b.s === "r" ? 0.6 + 0.4 * Math.sin(ang * 3) : 0.7;
        ctx.beginPath(); ctx.fillStyle = cc; ctx.globalAlpha = 0.2 * pulse; ctx.arc(x, y, 7, 0, 7); ctx.fill();
        ctx.globalAlpha = pulse; ctx.beginPath(); ctx.arc(x, y, 3, 0, 7); ctx.fill(); ctx.globalAlpha = 1;
      });
      ctx.beginPath(); ctx.fillStyle = c; ctx.arc(cx, cy, 3, 0, 7); ctx.fill();
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); ro.disconnect(); };
  }, []);
  return <canvas ref={ref} />;
}

/* ---------------- Network graph (données réelles) ---------------- */
interface GNode { x: number; y: number; r: number; s: string; label: string; parts: number[]; }
export function NetworkGraph({ conns, view }: { conns: ScoredConnection[]; view: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const state = useRef<{ conns: ScoredConnection[]; view: string; dirty: boolean }>({ conns, view, dirty: true });
  useEffect(() => { state.current = { conns, view, dirty: true }; }, [conns, view]);
  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext("2d")!;
    const W = 1000, H = 440;
    const ro = new ResizeObserver(() => fitCanvas(cv, ctx, W, H));
    ro.observe(cv);
    fitCanvas(cv, ctx, W, H);
    let nodes: GNode[] = [];
    let dev = { x: W * 0.16, y: H / 2 };
    const reduce = reduceMotion();
    let t = 0, raf = 0;

    const build = () => {
      const { conns, view } = state.current;
      const byRemote = new Map<string, { sev: string; label: string }>();
      for (const c of conns) {
        const priv = isPrivate(c.remote_addr);
        if (view === "sortant" && priv) continue;
        if (view === "local" && !priv) continue;
        if (view === "entrant") continue; // pas de connexions entrantes suivies au Jalon 1
        const key = c.remote_addr;
        const prev = byRemote.get(key);
        const label = c.remote_dns || c.remote_addr;
        if (!prev || sevRank[c.severity] > sevRank[prev.sev]) byRemote.set(key, { sev: c.severity, label });
      }
      const list = [...byRemote.values()].slice(0, 40);
      dev = { x: W * 0.16, y: H / 2 };
      const R = Math.min(W * 0.33, H * 0.42), cx = W * 0.62, cy = H / 2;
      nodes = list.map((it, i) => {
        const a = -Math.PI / 2 + (i / Math.max(1, list.length)) * Math.PI * 2;
        const crit = it.sev === "crit" || it.sev === "suspect";
        return { x: cx + Math.cos(a) * R, y: cy + Math.sin(a) * R, r: crit ? 9 : 7, s: it.sev, label: it.label, parts: [Math.random(), Math.random()] };
      });
      state.current.dirty = false;
    };

    const col = (s: string) =>
      s === "crit" || s === "suspect" ? cvar("--crit", "#fb5b6b") : s === "watch" ? cvar("--watch", "#fbbf24") : cvar("--safe", "#34d399");

    const draw = () => {
      if (state.current.dirty) build();
      t += 0.016;
      ctx.clearRect(0, 0, W, H);
      ctx.strokeStyle = "#141a26";
      ctx.lineWidth = 1;
      for (let x = 0; x <= W; x += 38) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
      for (let y = 0; y <= H; y += 38) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
      const crit = (s: string) => s === "crit" || s === "suspect";
      nodes.forEach((n) => {
        const c = col(n.s);
        ctx.strokeStyle = c;
        ctx.globalAlpha = crit(n.s) ? 0.3 + 0.2 * Math.sin(t * 3) : 0.13;
        ctx.lineWidth = crit(n.s) ? 1.4 : 1;
        ctx.beginPath(); ctx.moveTo(dev.x, dev.y); ctx.lineTo(n.x, n.y); ctx.stroke(); ctx.globalAlpha = 1;
        n.parts.forEach((p, i) => {
          if (!reduce) { n.parts[i] += crit(n.s) ? 0.011 : 0.006; if (n.parts[i] > 1) n.parts[i] -= 1; }
          const tp = n.parts[i];
          ctx.beginPath(); ctx.fillStyle = c; ctx.globalAlpha = 0.9;
          ctx.arc(dev.x + (n.x - dev.x) * tp, dev.y + (n.y - dev.y) * tp, crit(n.s) ? 2.3 : 1.8, 0, 7); ctx.fill(); ctx.globalAlpha = 1;
        });
      });
      nodes.forEach((n) => {
        const c = col(n.s);
        if (crit(n.s)) { ctx.beginPath(); ctx.fillStyle = c; ctx.globalAlpha = 0.12 + 0.08 * Math.sin(t * 3); ctx.arc(n.x, n.y, n.r + 7, 0, 7); ctx.fill(); ctx.globalAlpha = 1; }
        ctx.beginPath(); ctx.fillStyle = c; ctx.globalAlpha = 0.16; ctx.arc(n.x, n.y, n.r + 3, 0, 7); ctx.fill(); ctx.globalAlpha = 1;
        ctx.beginPath(); ctx.fillStyle = c; ctx.arc(n.x, n.y, n.r, 0, 7); ctx.fill();
        ctx.beginPath(); ctx.fillStyle = "#0a0c10"; ctx.arc(n.x, n.y, n.r - 2.5, 0, 7); ctx.fill();
        ctx.beginPath(); ctx.fillStyle = c; ctx.arc(n.x, n.y, Math.max(n.r - 5, 1.4), 0, 7); ctx.fill();
        const right = n.x >= dev.x;
        ctx.fillStyle = cvar("--ink", "#e8ecf2");
        ctx.font = "10px Consolas, monospace";
        ctx.textAlign = right ? "left" : "right";
        ctx.fillText(n.label.slice(0, 26), right ? n.x + n.r + 6 : n.x - n.r - 6, n.y + 3);
      });
      ctx.strokeStyle = cvar("--accent", "#2fe0d0");
      ctx.lineWidth = 2;
      ctx.fillStyle = "#0d1017";
      ctx.beginPath();
      (ctx as any).roundRect(dev.x - 56, dev.y - 15, 112, 30, 6);
      ctx.fill();
      ctx.stroke();
      ctx.fillStyle = cvar("--accent", "#2fe0d0");
      ctx.font = "700 11px Consolas, monospace";
      ctx.textAlign = "center";
      ctx.fillText("CET APPAREIL", dev.x, dev.y + 4);
      if (nodes.length === 0) {
        ctx.fillStyle = cvar("--faint", "#586372");
        ctx.font = "12px system-ui";
        ctx.textAlign = "center";
        ctx.fillText(view === "entrant" ? "Connexions entrantes : suivi au Jalon 2" : "Aucune connexion dans cette vue", W / 2 + 120, H / 2);
      }
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); ro.disconnect(); };
  }, []);
  return <canvas ref={ref} />;
}

/* ---------------- Carte du monde (tracé — placeholder honnête Jalon 2) ---------------- */
export function WorldTrace() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext("2d")!;
    const W = 820, H = 380;
    const ro = new ResizeObserver(() => { fitCanvas(cv, ctx, W, H); draw(); });
    ro.observe(cv);
    fitCanvas(cv, ctx, W, H);
    const proj = (lon: number, lat: number): [number, number] => [((lon + 180) / 360) * W, ((90 - lat) / 180) * H];
    const conts: [number, number, number, number][] = [
      [-100, 48, 30, 20], [-95, 63, 44, 10], [-88, 13, 10, 9], [-60, -18, 17, 28],
      [12, 52, 24, 12], [20, 2, 23, 33], [92, 52, 52, 23], [78, 22, 12, 14], [112, 8, 16, 12], [134, -25, 15, 11],
    ];
    const inLand = (lon: number, lat: number) => conts.some(([cx, cy, rx, ry]) => ((lon - cx) / rx) ** 2 + ((lat - cy) / ry) ** 2 <= 1);
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      ctx.strokeStyle = "#12181f";
      ctx.lineWidth = 1;
      for (let lon = -180; lon <= 180; lon += 30) { const [x] = proj(lon, 0); ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
      for (let lat = -90; lat <= 90; lat += 30) { const [, y] = proj(0, lat); ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
      ctx.fillStyle = cvar("--card-b", "#202a3a");
      for (let lon = -180; lon < 180; lon += 3) for (let lat = -86; lat < 86; lat += 3) if (inLand(lon, lat)) { const [x, y] = proj(lon, lat); ctx.beginPath(); ctx.arc(x, y, 1.1, 0, 7); ctx.fill(); }
    };
    draw();
    return () => ro.disconnect();
  }, []);
  return <canvas ref={ref} />;
}
