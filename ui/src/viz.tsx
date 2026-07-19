import { useEffect, useRef } from "react";
import type { ScoredConnection, TraceResult } from "./api";

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

interface View { s: number; ox: number; oy: number; }

function attachPanZoom(cv: HTMLCanvasElement, view: View, W: number, H: number) {
  const toLogical = (clientX: number, clientY: number) => {
    const r = cv.getBoundingClientRect();
    return [(clientX - r.left) * (W / r.width), (clientY - r.top) * (H / r.height)];
  };
  const clamp = () => {
    view.s = Math.min(6, Math.max(1, view.s));
    view.ox = Math.min(0, Math.max(-(view.s - 1) * W, view.ox));
    view.oy = Math.min(0, Math.max(-(view.s - 1) * H, view.oy));
    if (view.s === 1) { view.ox = 0; view.oy = 0; }
  };
  const onWheel = (e: WheelEvent) => {
    e.preventDefault();
    const [mx, my] = toLogical(e.clientX, e.clientY);
    const ns = Math.min(6, Math.max(1, view.s * (e.deltaY < 0 ? 1.15 : 1 / 1.15)));
    view.ox = mx - ((mx - view.ox) * ns) / view.s;
    view.oy = my - ((my - view.oy) * ns) / view.s;
    view.s = ns;
    clamp();
  };
  let dragging = false, px = 0, py = 0;
  const onDown = (e: PointerEvent) => { dragging = true; px = e.clientX; py = e.clientY; cv.setPointerCapture(e.pointerId); };
  const onMove = (e: PointerEvent) => {
    if (!dragging) return;
    const r = cv.getBoundingClientRect();
    view.ox += (e.clientX - px) * (W / r.width);
    view.oy += (e.clientY - py) * (H / r.height);
    px = e.clientX; py = e.clientY;
    clamp();
  };
  const onUp = () => { dragging = false; };
  cv.addEventListener("wheel", onWheel, { passive: false });
  cv.addEventListener("pointerdown", onDown);
  cv.addEventListener("pointermove", onMove);
  cv.addEventListener("pointerup", onUp);
  cv.addEventListener("pointerleave", onUp);
  cv.style.cursor = "grab";
  return () => {
    cv.removeEventListener("wheel", onWheel);
    cv.removeEventListener("pointerdown", onDown);
    cv.removeEventListener("pointermove", onMove);
    cv.removeEventListener("pointerup", onUp);
    cv.removeEventListener("pointerleave", onUp);
  };
}

const sevRank: Record<string, number> = { safe: 0, watch: 1, suspect: 2, crit: 3 };
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
    g.addColorStop(0, c + "55"); g.addColorStop(1, c + "05");
    ctx.fillStyle = g; ctx.fill();
    ctx.beginPath();
    values.forEach((v, i) => (i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))));
    ctx.strokeStyle = c; ctx.lineWidth = 1.8; ctx.stroke();
  }, [values, color]);
  return <canvas ref={ref} />;
}

/* ---------------- Bandwidth ---------------- */
export function BandwidthChart({ history }: { history: { d: number; u: number }[] }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext("2d")!;
    const W = 520, H = 120;
    fitCanvas(cv, ctx, W, H);
    ctx.clearRect(0, 0, W, H);
    ctx.strokeStyle = "#141a26"; ctx.lineWidth = 1;
    for (let y = 0; y <= H; y += 30) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }
    const n = history.length;
    if (n < 2) return;
    const max = Math.max(1, ...history.map((h) => Math.max(h.d, h.u)));
    const area = (get: (h: { d: number; u: number }) => number, color: string) => {
      const y = (v: number) => H - (v / max) * (H - 10) - 4;
      ctx.beginPath(); ctx.moveTo(0, H);
      history.forEach((h, i) => ctx.lineTo((i / (n - 1)) * W, y(get(h))));
      ctx.lineTo(W, H); ctx.closePath();
      const g = ctx.createLinearGradient(0, 0, 0, H);
      g.addColorStop(0, color + "4d"); g.addColorStop(1, color + "05");
      ctx.fillStyle = g; ctx.fill();
      ctx.beginPath();
      history.forEach((h, i) => { const px = (i / (n - 1)) * W, py = y(get(h)); i ? ctx.lineTo(px, py) : ctx.moveTo(px, py); });
      ctx.strokeStyle = color; ctx.lineWidth = 1.6; ctx.stroke();
    };
    area((h) => h.d, cvar("--safe", "#34d399"));
    area((h) => h.u, cvar("--accent", "#2fe0d0"));
  }, [history]);
  return <canvas ref={ref} />;
}

/* ---------------- Network graph (réel, survol + zoom/pan) ---------------- */
interface GNode { x: number; y: number; r: number; s: string; label: string; ip: string; parts: number[]; }
export function NetworkGraph({ conns, view, onSelect }: { conns: ScoredConnection[]; view: string; onSelect?: (ip: string) => void }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const state = useRef<{ conns: ScoredConnection[]; view: string; dirty: boolean }>({ conns, view, dirty: true });
  const mouse = useRef<{ x: number; y: number; on: boolean }>({ x: 0, y: 0, on: false });
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  useEffect(() => { state.current = { conns, view, dirty: true }; }, [conns, view]);
  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext("2d")!;
    const W = 1000, H = 440;
    const vw: View = { s: 1, ox: 0, oy: 0 };
    const ro = new ResizeObserver(() => fitCanvas(cv, ctx, W, H));
    ro.observe(cv); fitCanvas(cv, ctx, W, H);
    const detachPZ = attachPanZoom(cv, vw, W, H);
    const onMove = (e: PointerEvent) => { const r = cv.getBoundingClientRect(); mouse.current = { x: (e.clientX - r.left) * (W / r.width), y: (e.clientY - r.top) * (H / r.height), on: true }; };
    const onLeave = () => { mouse.current.on = false; };
    cv.addEventListener("pointermove", onMove); cv.addEventListener("pointerleave", onLeave);
    // clic sur un nœud (distinct du glisser) → sélection de l'endpoint
    let downX = 0, downY = 0;
    const onDownClick = (e: PointerEvent) => { downX = e.clientX; downY = e.clientY; };
    const onUpClick = (e: PointerEvent) => {
      if (Math.hypot(e.clientX - downX, e.clientY - downY) > 5) return;
      const r = cv.getBoundingClientRect();
      const mx = (e.clientX - r.left) * (W / r.width), my = (e.clientY - r.top) * (H / r.height);
      for (const n of nodes) {
        const nx = n.x * vw.s + vw.ox, ny = n.y * vw.s + vw.oy;
        if (Math.hypot(mx - nx, my - ny) < n.r * vw.s + 6) { onSelectRef.current?.(n.ip); break; }
      }
    };
    cv.addEventListener("pointerdown", onDownClick); cv.addEventListener("pointerup", onUpClick);
    let nodes: GNode[] = [];
    let dev = { x: W * 0.16, y: H / 2 };
    const reduce = reduceMotion();
    let t = 0, raf = 0;
    const build = () => {
      const { conns, view } = state.current;
      const byRemote = new Map<string, { sev: string; label: string; ip: string }>();
      for (const c of conns) {
        const priv = isPrivate(c.remote_addr);
        if (view === "sortant" && priv) continue;
        if (view === "local" && !priv) continue;
        if (view === "entrant") continue;
        const prev = byRemote.get(c.remote_addr);
        if (!prev || sevRank[c.severity] > sevRank[prev.sev]) byRemote.set(c.remote_addr, { sev: c.severity, label: c.remote_dns || c.remote_addr, ip: c.remote_addr });
      }
      const list = [...byRemote.values()].slice(0, 40);
      dev = { x: W * 0.16, y: H / 2 };
      const R = Math.min(W * 0.33, H * 0.42), cx = W * 0.62, cy = H / 2;
      nodes = list.map((it, i) => {
        const a = -Math.PI / 2 + (i / Math.max(1, list.length)) * Math.PI * 2;
        const crit = it.sev === "crit" || it.sev === "suspect";
        return { x: cx + Math.cos(a) * R, y: cy + Math.sin(a) * R, r: crit ? 9 : 7, s: it.sev, label: it.label, ip: it.ip, parts: [Math.random(), Math.random()] };
      });
      state.current.dirty = false;
    };
    const col = (s: string) => (s === "crit" || s === "suspect" ? cvar("--crit", "#fb5b6b") : s === "watch" ? cvar("--watch", "#fbbf24") : cvar("--safe", "#34d399"));
    const T = (x: number, y: number): [number, number] => [x * vw.s + vw.ox, y * vw.s + vw.oy];
    const draw = () => {
      if (state.current.dirty) build();
      t += 0.016;
      ctx.clearRect(0, 0, W, H);
      ctx.strokeStyle = "#141a26"; ctx.lineWidth = 1;
      for (let x = 0; x <= W; x += 38) { const [ax, ay] = T(x, 0), [bx, by] = T(x, H); ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(bx, by); ctx.stroke(); }
      for (let y = 0; y <= H; y += 38) { const [ax, ay] = T(0, y), [bx, by] = T(W, y); ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(bx, by); ctx.stroke(); }
      const crit = (s: string) => s === "crit" || s === "suspect";
      const [dx, dy] = T(dev.x, dev.y);
      let hover: GNode | null = null;
      nodes.forEach((n) => {
        const c = col(n.s); const [nx, ny] = T(n.x, n.y);
        ctx.strokeStyle = c; ctx.globalAlpha = crit(n.s) ? 0.3 + 0.2 * Math.sin(t * 3) : 0.13; ctx.lineWidth = crit(n.s) ? 1.4 : 1;
        ctx.beginPath(); ctx.moveTo(dx, dy); ctx.lineTo(nx, ny); ctx.stroke(); ctx.globalAlpha = 1;
        n.parts.forEach((p, i) => { if (!reduce) { n.parts[i] += crit(n.s) ? 0.011 : 0.006; if (n.parts[i] > 1) n.parts[i] -= 1; } const tp = n.parts[i]; ctx.beginPath(); ctx.fillStyle = c; ctx.globalAlpha = 0.9; ctx.arc(dx + (nx - dx) * tp, dy + (ny - dy) * tp, crit(n.s) ? 2.3 : 1.8, 0, 7); ctx.fill(); ctx.globalAlpha = 1; });
        if (mouse.current.on && Math.hypot(mouse.current.x - nx, mouse.current.y - ny) < n.r * vw.s + 5) hover = n;
      });
      nodes.forEach((n) => {
        const c = col(n.s); const [nx, ny] = T(n.x, n.y); const r = n.r * Math.min(vw.s, 2);
        if (crit(n.s)) { ctx.beginPath(); ctx.fillStyle = c; ctx.globalAlpha = 0.12 + 0.08 * Math.sin(t * 3); ctx.arc(nx, ny, r + 7, 0, 7); ctx.fill(); ctx.globalAlpha = 1; }
        ctx.beginPath(); ctx.fillStyle = c; ctx.globalAlpha = 0.16; ctx.arc(nx, ny, r + 3, 0, 7); ctx.fill(); ctx.globalAlpha = 1;
        ctx.beginPath(); ctx.fillStyle = c; ctx.arc(nx, ny, r, 0, 7); ctx.fill();
        ctx.beginPath(); ctx.fillStyle = "#0a0c10"; ctx.arc(nx, ny, Math.max(r - 2.5, 1), 0, 7); ctx.fill();
        ctx.beginPath(); ctx.fillStyle = c; ctx.arc(nx, ny, Math.max(r - 5, 1.4), 0, 7); ctx.fill();
        const right = nx >= dx;
        ctx.fillStyle = cvar("--ink", "#e8ecf2"); ctx.font = "10px Consolas, monospace"; ctx.textAlign = right ? "left" : "right";
        ctx.fillText(n.label.slice(0, 26), right ? nx + r + 6 : nx - r - 6, ny + 3);
      });
      ctx.strokeStyle = cvar("--accent", "#2fe0d0"); ctx.lineWidth = 2; ctx.fillStyle = "#0d1017";
      ctx.beginPath(); (ctx as any).roundRect(dx - 56, dy - 15, 112, 30, 6); ctx.fill(); ctx.stroke();
      ctx.fillStyle = cvar("--accent", "#2fe0d0"); ctx.font = "700 11px Consolas, monospace"; ctx.textAlign = "center";
      ctx.fillText("CET APPAREIL", dx, dy + 4);
      if (hover) {
        const h = hover as GNode; const [hx, hy] = T(h.x, h.y);
        const txt = `${h.label}  ·  ${h.ip}  ·  ${h.s}`;
        ctx.font = "11px Consolas, monospace"; const w = ctx.measureText(txt).width + 16;
        ctx.fillStyle = "#0d1119"; ctx.strokeStyle = cvar("--card-b", "#2fe0d0");
        (ctx as any).roundRect(hx + 10, hy - 12, w, 22, 5); ctx.fill(); ctx.stroke();
        ctx.fillStyle = cvar("--ink", "#e8ecf2"); ctx.textAlign = "left"; ctx.fillText(txt, hx + 18, hy + 3);
      }
      if (nodes.length === 0) {
        ctx.fillStyle = cvar("--faint", "#586372"); ctx.font = "12px system-ui"; ctx.textAlign = "center";
        ctx.fillText(view === "entrant" ? "Connexions entrantes : suivi au Jalon 2" : "Aucune connexion dans cette vue", W / 2, H / 2);
      }
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); ro.disconnect(); detachPZ(); cv.removeEventListener("pointermove", onMove); cv.removeEventListener("pointerleave", onLeave); cv.removeEventListener("pointerdown", onDownClick); cv.removeEventListener("pointerup", onUpClick); };
  }, []);
  return <canvas ref={ref} />;
}

/* ---------------- Traceroute — carte du monde réelle (zoom/pan) ---------------- */
const CONTS: [number, number, number, number][] = [
  [-100, 48, 30, 20], [-95, 63, 44, 10], [-88, 13, 10, 9], [-60, -18, 17, 28],
  [12, 52, 24, 12], [20, 2, 23, 33], [92, 52, 52, 23], [78, 22, 12, 14], [112, 8, 16, 12], [134, -25, 15, 11],
];
export function TraceMap({ trace }: { trace: TraceResult | null }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const dataRef = useRef<TraceResult | null>(trace);
  useEffect(() => { dataRef.current = trace; }, [trace]);
  useEffect(() => {
    const cv = ref.current!;
    const ctx = cv.getContext("2d")!;
    const W = 820, H = 400;
    const vw: View = { s: 1, ox: 0, oy: 0 };
    const ro = new ResizeObserver(() => fitCanvas(cv, ctx, W, H));
    ro.observe(cv); fitCanvas(cv, ctx, W, H);
    const detach = attachPanZoom(cv, vw, W, H);
    const proj = (lon: number, lat: number): [number, number] => [((lon + 180) / 360) * W, ((90 - lat) / 180) * H];
    const inLand = (lon: number, lat: number) => CONTS.some(([cx, cy, rx, ry]) => ((lon - cx) / rx) ** 2 + ((lat - cy) / ry) ** 2 <= 1);
    const T = (x: number, y: number): [number, number] => [x * vw.s + vw.ox, y * vw.s + vw.oy];
    const reduce = reduceMotion();
    // image de mappemonde équirectangulaire (bundlée, hors-ligne)
    const img = new Image();
    let imgOk = false;
    img.onload = () => { imgOk = true; };
    img.src = "/worldmap.jpg";
    let parts = [0, 0.4, 0.8], raf = 0, t = 0;
    const draw = () => {
      t += 0.016;
      ctx.clearRect(0, 0, W, H);
      if (imgOk) {
        ctx.globalAlpha = 0.55;
        ctx.drawImage(img, vw.ox, vw.oy, W * vw.s, H * vw.s);
        ctx.globalAlpha = 1;
        ctx.fillStyle = "rgba(8,10,15,0.5)"; // teinte sombre pour cohérence avec le thème
        ctx.fillRect(0, 0, W, H);
      } else {
        ctx.fillStyle = cvar("--card-b", "#202a3a");
        const step = vw.s >= 3 ? 2 : 3;
        for (let lon = -180; lon < 180; lon += step) for (let lat = -86; lat < 86; lat += step) if (inLand(lon, lat)) { const [x, y] = proj(lon, lat); const [px, py] = T(x, y); ctx.beginPath(); ctx.arc(px, py, 1.1, 0, 7); ctx.fill(); }
      }
      ctx.strokeStyle = "rgba(120,220,225,0.10)"; ctx.lineWidth = 1;
      for (let lon = -180; lon <= 180; lon += 30) { const [x] = proj(lon, 0); const [ax, ay] = T(x, 0), [bx, by] = T(x, H); ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(bx, by); ctx.stroke(); }
      for (let lat = -90; lat <= 90; lat += 30) { const [, y] = proj(0, lat); const [ax, ay] = T(0, y), [bx, by] = T(W, y); ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(bx, by); ctx.stroke(); }
      const tr = dataRef.current;
      const geoHops = (tr?.hops || []).filter((h) => h.lat != null && h.lon != null);
      const pts = geoHops.map((h) => { const [x, y] = proj(h.lon!, h.lat!); const [px, py] = T(x, y); return { px, py, h }; });
      const cm = { gold: cvar("--accent", "#2fe0d0"), crit: cvar("--crit", "#fb5b6b"), ink: cvar("--ink", "#e8ecf2"), faint: cvar("--faint", "#586372") };
      for (let i = 0; i < pts.length - 1; i++) {
        const a = pts[i], b = pts[i + 1]; const last = i === pts.length - 2;
        ctx.strokeStyle = last ? cm.crit : cm.gold; ctx.globalAlpha = 0.4; ctx.lineWidth = 1.4;
        const cx = (a.px + b.px) / 2, cy = (a.py + b.py) / 2 - Math.hypot(b.px - a.px, b.py - a.py) * 0.2;
        ctx.beginPath(); for (let f = 0; f <= 1; f += 0.04) { const u = 1 - f; const x = u * u * a.px + 2 * u * f * cx + f * f * b.px, y = u * u * a.py + 2 * u * f * cy + f * f * b.py; f ? ctx.lineTo(x, y) : ctx.moveTo(x, y); } ctx.stroke(); ctx.globalAlpha = 1;
      }
      if (!reduce && pts.length > 1) parts = parts.map((p) => (p + 0.005 > 1 ? p + 0.005 - 1 : p + 0.005));
      if (pts.length > 1) parts.forEach((p) => { const seg = p * (pts.length - 1), i = Math.min(Math.floor(seg), pts.length - 2), f = seg - i; const a = pts[i], b = pts[i + 1]; const cx = (a.px + b.px) / 2, cy = (a.py + b.py) / 2 - Math.hypot(b.px - a.px, b.py - a.py) * 0.2; const u = 1 - f; const x = u * u * a.px + 2 * u * f * cx + f * f * b.px, y = u * u * a.py + 2 * u * f * cy + f * f * b.py; ctx.beginPath(); ctx.fillStyle = cm.gold; ctx.globalAlpha = 0.9; ctx.arc(x, y, 2.2, 0, 7); ctx.fill(); ctx.globalAlpha = 1; });
      pts.forEach((pt, i) => {
        const isDest = i === pts.length - 1; const c = isDest ? cm.crit : cm.gold;
        ctx.beginPath(); ctx.fillStyle = c; ctx.globalAlpha = 0.22; ctx.arc(pt.px, pt.py, 7, 0, 7); ctx.fill(); ctx.globalAlpha = 1;
        ctx.beginPath(); ctx.fillStyle = c; ctx.arc(pt.px, pt.py, 3.4, 0, 7); ctx.fill();
        ctx.beginPath(); ctx.fillStyle = "#0a0c10"; ctx.arc(pt.px, pt.py, 1.7, 0, 7); ctx.fill();
        ctx.textAlign = "left"; ctx.fillStyle = cm.ink; ctx.font = "700 9.5px Consolas, monospace";
        ctx.fillText(`${pt.h.country || pt.h.ip}`, pt.px + 7, pt.py - 3);
        ctx.fillStyle = cm.faint; ctx.font = "8.5px Consolas, monospace"; ctx.fillText(pt.h.city || pt.h.ip, pt.px + 7, pt.py + 7);
      });
      if (pts.length === 0) {
        ctx.fillStyle = cm.faint; ctx.font = "12px system-ui"; ctx.textAlign = "center";
        ctx.fillText(tr?.running ? "Traceroute en cours…" : tr?.error ? `Erreur : ${tr.error}` : "Lance un tracé pour voir le chemin", W / 2, H / 2);
      }
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); ro.disconnect(); detach(); };
  }, []);
  return <canvas ref={ref} />;
}
