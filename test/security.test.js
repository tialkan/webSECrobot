import test from "node:test";
import assert from "node:assert/strict";
import { isPrivateIp, normalizeTarget } from "../src/security.js";
import { parseHtml } from "../src/parser.js";
import { calculateScores } from "../src/scoring.js";
import { buildFixPrompt, reportToMarkdown } from "../src/report.js";

test("hedef adresini HTTPS ile normalleştirir", () => {
  assert.equal(normalizeTarget("example.com/path").href, "https://example.com/path");
  assert.throws(() => normalizeTarget("ftp://example.com"), /HTTP ve HTTPS/);
});

test("özel ve bağlantı-yerel IP aralıklarını engeller", () => {
  for (const ip of ["127.0.0.1", "10.0.0.2", "169.254.1.1", "192.168.1.1", "::1", "fd00::1", "::ffff:127.0.0.1"]) assert.equal(isPrivateIp(ip), true, ip);
  assert.equal(isPrivateIp("1.1.1.1"), false);
});

test("HTML kaynaklarını, formları ve parola alanlarını ayrıştırır", () => {
  const page = parseHtml('<script src="http://cdn.example/a.js"></script><form method="post" action="/login"><input type="password"></form>', "https://example.com/");
  assert.deepEqual(page.resources, [{ tag: "script", url: "http://cdn.example/a.js" }]);
  assert.deepEqual(page.forms, [{ method: "post", action: "https://example.com/login" }]);
  assert.equal(page.passwordInputs, 1);
});

test("kritik bulgu ilgili alan puanını düşürür", () => {
  const scores = calculateScores([{ kategori: "tasima", seviye: "kritik" }]);
  assert.equal(scores.tasima, 60);
  assert.equal(scores.tarayici, 100);
});

test("rapor ve yapay zekâ istemi kanıtı taşır", () => {
  const report = { hedef: { girilen: "https://example.com", son: "https://example.com/" }, olusturuldu: "2026-01-01", ozet: { incelenenSayfa: 1 }, puanlar: { tasima: 80 }, sinirlar: ["Pasif"], bulgular: [{ kod: "HSTS-MISSING", kategori: "tasima", seviye: "orta", baslik: "HSTS yok", aciklama: "Yok", kanit: { url: "https://example.com", bulunan: "başlık yok" }, etkisi: "Risk", cozum: "Ekle", kaynaklar: ["https://owasp.org"] }] };
  assert.match(reportToMarkdown(report), /başlık yok/);
  assert.match(buildFixPrompt(report), /Exploit, parola denemesi/);
});
