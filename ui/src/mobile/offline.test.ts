import { describe, it, expect } from "vitest";
import { analyzeEml, extractLinks, md5, identifyHash, crackHash } from "./offline";

const PHISH = [
  'From: "PayPal" <security@paypa1-verify.tk>',
  "Return-Path: <bounce@evil.ru>",
  "Subject: Verifiez votre compte",
  "Date: Mon, 21 Jul 2026 10:00:00 +0000",
  "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail",
  'Content-Type: application/octet-stream; name="facture.exe"',
  'Content-Disposition: attachment; filename="facture.exe"',
  "",
  "Bonjour, confirmez ici http://192.168.5.9/login sinon suspension.",
].join("\n");

const CLEAN = [
  "From: Alice Martin <alice@example.com>",
  "Return-Path: <alice@example.com>",
  "Subject: Reunion de mardi",
  "Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass",
  "",
  "Bonjour, l'agenda est ici https://example.com/agenda a bientot.",
].join("\n");

describe("analyzeEml", () => {
  it("détecte un phishing (DMARC fail + lien IP + pièce jointe .exe)", () => {
    const r = analyzeEml(PHISH);
    expect(r.spf).toBe("fail");
    expect(r.dkim).toBe("fail");
    expect(r.dmarc).toBe("fail");
    expect(r.from_addr).toBe("security@paypa1-verify.tk");
    expect(r.attachments.some((a) => a.filename === "facture.exe" && a.risky)).toBe(true);
    expect(r.links.some((l) => l.suspicious && l.reason.includes("IP"))).toBe(true);
    // DMARC 40 + SPF 25 + DKIM 20 + désalignement 15 + lien 20 + PJ 35 => plafonné à 100
    expect(r.risk).toBe(100);
    expect(r.severity).toBe("crit");
  });

  it("classe un mail légitime en 'safe'", () => {
    const r = analyzeEml(CLEAN);
    expect(r.spf).toBe("pass");
    expect(r.dmarc).toBe("pass");
    expect(r.attachments.length).toBe(0);
    expect(r.links.every((l) => !l.suspicious)).toBe(true);
    expect(r.severity).toBe("safe");
    expect(r.risk).toBe(0);
  });

  it("gère l'entrée vide", () => {
    expect(analyzeEml("").error).toBeTruthy();
  });
});

describe("extractLinks", () => {
  it("repère IP, punycode et TLD à risque", () => {
    const links = extractLinks("a http://8.8.8.8/x b http://xn--e1afmkfd.top/y c https://ok.example.com/z");
    const byReason = (frag: string) => links.find((l) => l.reason.includes(frag));
    expect(byReason("IP")).toBeTruthy();
    expect(links.find((l) => l.url.includes("xn--"))?.suspicious).toBe(true);
    expect(links.find((l) => l.url.includes("ok.example.com"))?.suspicious).toBe(false);
  });
});

describe("cracker de hash (hors-ligne)", () => {
  it("MD5 conforme (vecteurs RFC connus)", () => {
    expect(md5("")).toBe("d41d8cd98f00b204e9800998ecf8427e");
    expect(md5("abc")).toBe("900150983cd24fb0d6963f7d28e17f72");
    expect(md5("password")).toBe("5f4dcc3b5aa765d61d8327deb882cf99");
  });
  it("identifie le type par longueur", () => {
    expect(identifyHash("5f4dcc3b5aa765d61d8327deb882cf99")).toEqual(["md5"]);
    expect(identifyHash("a".repeat(64))).toEqual(["sha256"]);
    expect(identifyHash("zzz")).toEqual([]);
  });
  it("casse un hash md5 et sha256 par dictionnaire", async () => {
    const md5r = await crackHash("md5", "5f4dcc3b5aa765d61d8327deb882cf99", ["admin", "123456", "password"]);
    expect(md5r.found).toBe("password");
    // sha256("letmein")
    const sha = await crackHash("sha256", "1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032", ["x", "letmein"]);
    expect(sha.found).toBe("letmein");
  });
});
