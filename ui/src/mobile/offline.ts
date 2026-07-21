// Moteur hors-ligne RED SHIELD (client) — tourne 100 % dans l'app, sur l'appareil,
// sans serveur ni réseau. Utilisé sur mobile (où le moteur Python n'existe pas) et en
// repli. Chaque fonction est pure et testable (Vitest). Aucune donnée inventée.

export interface OfflineMailLink { url: string; suspicious: boolean; reason: string; }
export interface OfflineMailAttachment { filename: string; risky: boolean; }
export interface OfflineMailAnalysis {
  from_addr: string; from_name: string; subject: string; date: string;
  spf: string; dkim: string; dmarc: string;
  links: OfflineMailLink[]; attachments: OfflineMailAttachment[];
  risk: number; severity: string; reasons: string[]; error?: string;
}

const RISKY_EXT = [".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".ps1", ".hta",
  ".docm", ".xlsm", ".pptm", ".lnk", ".iso", ".img", ".msi", ".jse", ".wsf"];
const RISKY_TLD = [".zip", ".mov", ".xyz", ".top", ".tk", ".gq", ".ml", ".cf", ".click", ".country"];
const URL_RE = /https?:\/\/[^\s"'<>)]+/gi;

function parseAddr(s: string): { name: string; addr: string } {
  if (!s) return { name: "", addr: "" };
  const m = s.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  if (m) return { name: m[1].replace(/^"|"$/g, "").trim(), addr: m[2].trim().toLowerCase() };
  return { name: "", addr: s.trim().toLowerCase() };
}

/** Sépare les en-têtes (dépliés) du corps ; renvoie une map insensible à la casse (valeurs concaténées). */
function splitHeadersBody(raw: string): { headers: Map<string, string>; body: string } {
  const norm = raw.replace(/\r\n/g, "\n");
  const sep = norm.indexOf("\n\n");
  const headerBlock = sep >= 0 ? norm.slice(0, sep) : norm;
  const body = sep >= 0 ? norm.slice(sep + 2) : "";
  const lines = headerBlock.split("\n");
  const headers = new Map<string, string>();
  let curKey = "", curVal = "";
  const flush = () => {
    if (curKey) {
      const k = curKey.toLowerCase();
      headers.set(k, headers.has(k) ? headers.get(k) + " " + curVal : curVal);
    }
  };
  for (const line of lines) {
    if (/^[ \t]/.test(line)) { curVal += " " + line.trim(); continue; } // en-tête replié
    const idx = line.indexOf(":");
    if (idx > 0) { flush(); curKey = line.slice(0, idx).trim(); curVal = line.slice(idx + 1).trim(); }
  }
  flush();
  return { headers, body };
}

function mech(auth: string, m: string): string {
  const r = new RegExp(m + "\\s*=\\s*(\\w+)", "i").exec(auth);
  return r ? r[1].toLowerCase() : "?";
}

export function extractLinks(text: string): OfflineMailLink[] {
  const seen = new Set<string>();
  const out: OfflineMailLink[] = [];
  const found = text.match(URL_RE) || [];
  for (const url of found) {
    if (seen.has(url)) continue;
    seen.add(url);
    if (out.length >= 40) break;
    const host = url.replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
    let suspicious = false, reason = "";
    if (/^\d+\.\d+\.\d+\.\d+/.test(host)) { suspicious = true; reason = "URL basée sur une IP"; }
    else if (host.startsWith("xn--") || host.includes(".xn--")) { suspicious = true; reason = "domaine punycode (usurpation possible)"; }
    else if (RISKY_TLD.some((t) => host.endsWith(t))) { suspicious = true; reason = "TLD à risque"; }
    else if ((host.match(/-/g) || []).length >= 4 || host.length > 40) { suspicious = true; reason = "domaine inhabituel"; }
    out.push({ url: url.slice(0, 200), suspicious, reason });
  }
  return out;
}

function extractAttachments(raw: string): OfflineMailAttachment[] {
  const out: OfflineMailAttachment[] = [];
  const seen = new Set<string>();
  const re = /filename\*?=\s*"?([^";\r\n]+)"?/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    const fn = m[1].trim();
    if (fn && !seen.has(fn)) {
      seen.add(fn);
      out.push({ filename: fn, risky: RISKY_EXT.some((e) => fn.toLowerCase().endsWith(e)) });
    }
  }
  return out;
}

/** Analyse anti-phishing d'un email brut (.eml) — SPF/DKIM/DMARC, alignement, liens, pièces jointes. */
export function analyzeEml(raw: string): OfflineMailAnalysis {
  const base: OfflineMailAnalysis = {
    from_addr: "", from_name: "", subject: "", date: "", spf: "?", dkim: "?", dmarc: "?",
    links: [], attachments: [], risk: 0, severity: "safe", reasons: [],
  };
  if (!raw || !raw.trim()) return { ...base, error: "email vide" };
  const { headers, body } = splitHeadersBody(raw);
  const from = parseAddr(headers.get("from") || "");
  const auth = [headers.get("authentication-results"), headers.get("arc-authentication-results"), headers.get("received-spf")]
    .filter(Boolean).join(" ");
  const spf = mech(auth, "spf"), dkim = mech(auth, "dkim"), dmarc = mech(auth, "dmarc");
  const links = extractLinks(body || raw);
  const attachments = extractAttachments(raw);

  const reasons: string[] = [];
  let risk = 0;
  if (dmarc === "fail") { risk += 40; reasons.push("DMARC en échec — usurpation d'expéditeur probable"); }
  else if (dmarc === "?") { reasons.push("DMARC non évalué (en-tête absent)"); }
  if (spf === "fail") { risk += 25; reasons.push("SPF en échec — l'émetteur n'est pas autorisé pour ce domaine"); }
  if (dkim === "fail") { risk += 20; reasons.push("DKIM en échec — signature invalide"); }

  const rp = parseAddr(headers.get("return-path") || "").addr;
  const fdom = from.addr.includes("@") ? from.addr.split("@").pop()! : "";
  const rdom = rp.includes("@") ? rp.split("@").pop()! : "";
  if (fdom && rdom && fdom !== rdom) { risk += 15; reasons.push(`désalignement From (${fdom}) / Return-Path (${rdom})`); }

  const susp = links.filter((l) => l.suspicious);
  if (susp.length) { risk += 20; reasons.push(`${susp.length} lien(s) suspect(s)`); }
  const risky = attachments.filter((a) => a.risky);
  if (risky.length) { risk += 35; reasons.push("pièce(s) jointe(s) à risque : " + risky.map((a) => a.filename).join(", ")); }

  risk = Math.min(risk, 100);
  const severity = risk >= 70 ? "crit" : risk >= 45 ? "suspect" : risk >= 20 ? "watch" : "safe";
  return {
    ...base, from_addr: from.addr, from_name: from.name,
    subject: headers.get("subject") || "", date: headers.get("date") || "",
    spf, dkim, dmarc, links, attachments, risk, severity, reasons,
  };
}

// ---------------- Cracker de hash (hors-ligne, sur l'appareil) ----------------
/** MD5 (RFC 1321), opère sur l'UTF-8. Web Crypto ne fournit pas MD5 → implémentation locale. */
export function md5(message: string): string {
  const msg = new TextEncoder().encode(message);
  const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const bits = msg.length * 8;
  const padLen = (msg.length + 1 + 8 + 63) & ~63;
  const buf = new Uint8Array(padLen);
  buf.set(msg);
  buf[msg.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, bits >>> 0, true);
  dv.setUint32(padLen - 4, Math.floor(bits / 4294967296) >>> 0, true);
  const rl = (x: number, c: number) => (x << c) | (x >>> (32 - c));
  for (let off = 0; off < padLen; off += 64) {
    const M = new Uint32Array(16);
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(off + j * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + rl(F, s[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const hx = (n: number) => { let h = ""; for (let i = 0; i < 4; i++) h += ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, "0"); return h; };
  return hx(a0) + hx(b0) + hx(c0) + hx(d0);
}

/** Types de hash plausibles selon la longueur/charset (hex). */
export function identifyHash(hash: string): string[] {
  const s = hash.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(s)) return [];
  return ({ 32: ["md5"], 40: ["sha1"], 64: ["sha256"], 128: ["sha512"] } as Record<number, string[]>)[s.length] || [];
}

async function digestHex(algo: string, text: string): Promise<string> {
  if (algo === "md5") return md5(text);
  const map: Record<string, string> = { sha1: "SHA-1", sha256: "SHA-256", sha512: "SHA-512" };
  const buf = await crypto.subtle.digest(map[algo], new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Attaque par dictionnaire hors-ligne : hache chaque mot et compare à la cible. */
export async function crackHash(algo: string, target: string, words: string[]): Promise<{ found: string | null; tried: number; algo: string }> {
  const t = target.trim().toLowerCase();
  let tried = 0;
  for (const w of words) {
    const word = w.trim();
    if (!word) continue;
    tried++;
    if ((await digestHex(algo, word)) === t) return { found: word, tried, algo };
  }
  return { found: null, tried, algo };
}
