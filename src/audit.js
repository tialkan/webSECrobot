import { normalizeTarget, assertPublicUrl } from "./security.js";
import { safeFetch, tryFetch } from "./http.js";
import { parseHtml } from "./parser.js";
import { calculateScores } from "./scoring.js";
import { SOURCES } from "./sources.js";

const MAX_PAGES = Math.min(8, Math.max(1, Number(process.env.AUDIT_MAX_PAGES || 4)));
const ORDER = { kritik: 0, "yüksek": 1, orta: 2, "düşük": 3, bilgi: 4 };

export async function auditSite(input, options = {}) {
  const started = Date.now();
  const target = normalizeTarget(input);
  await assertPublicUrl(target);
  const findings = [];
  const mainAttempt = await tryFetch(target.href);
  if (!mainAttempt.ok) {
    findings.push(finding("SITE-UNREACHABLE", "tasima", "kritik", "Siteye güvenli bağlantı kurulamadı", mainAttempt.error, target.href, undefined, "Dış kullanıcılar hizmete erişemeyebilir veya bağlantının güvenliği doğrulanamaz.", "DNS, TLS sertifikası ve sunucu yapılandırmasını kontrol edin.", [SOURCES.tls]));
    return finalize({ target, main: null, pages: [], findings, started, securityTxt: null });
  }

  const main = mainAttempt.result;
  inspectTransport(target, main, findings);
  await inspectHttpVariant(main.url, findings);
  const parsedMain = parseHtml(main.body, main.url);
  const pages = [];
  inspectPage(main, parsedMain, findings);
  pages.push(summary(main));

  const base = new URL(main.url);
  const limit = Math.min(MAX_PAGES, Math.max(1, Number(options.maxPages || MAX_PAGES)));
  const candidates = [...new Set(parsedMain.anchors)]
    .filter((href) => { try { const url = new URL(href); return url.origin === base.origin && /^https?:$/.test(url.protocol) && !/\.(?:pdf|zip|jpe?g|png|gif|webp|svg|mp4|mp3)$/i.test(url.pathname); } catch { return false; } })
    .filter((href) => href !== main.url)
    .slice(0, Math.max(0, limit - 1));

  for (const url of candidates) {
    const attempt = await tryFetch(url);
    if (!attempt.ok || !/text\/html|application\/xhtml/i.test(attempt.result.headers["content-type"] || "")) continue;
    const parsed = parseHtml(attempt.result.body, attempt.result.url);
    inspectPage(attempt.result, parsed, findings);
    pages.push(summary(attempt.result));
  }

  await inspectCors(main.url, findings);
  const securityTxt = await inspectSecurityTxt(base, findings);
  return finalize({ target, main, pages, findings, started, securityTxt });
}

function inspectTransport(target, response, findings) {
  const final = new URL(response.url);
  if (final.protocol !== "https:") {
    findings.push(finding("HTTPS-MISSING", "tasima", "kritik", "Site HTTPS kullanmıyor", `Son adres ${response.url}`, target.href, response.status, "Trafik ağ üzerinde okunabilir veya değiştirilebilir.", "Geçerli bir TLS sertifikası kurun ve tüm HTTP trafiğini kalıcı olarak HTTPS'e yönlendirin.", [SOURCES.tls]));
    return;
  }
  const temporary = response.chain.slice(0, -1).find((step) => [302, 307].includes(step.durumKodu));
  if (temporary) findings.push(finding("HTTPS-REDIRECT-TEMPORARY", "tasima", "orta", "HTTPS geçişinde geçici yönlendirme var", `HTTP ${temporary.durumKodu}`, temporary.url, temporary.durumKodu, "Kalıcı HTTPS tercihi istemcilere daha zayıf bildirilir.", "Kalıcı geçiş için 301 veya 308 kullanın; yol ve sorguyu koruyun.", [SOURCES.tls]));
  if (response.chain.length > 2) findings.push(finding("REDIRECT-CHAIN", "tasima", "düşük", "Güvenli hedefe birden fazla yönlendirme var", `${response.chain.length - 1} yönlendirme`, target.href, response.chain[0]?.durumKodu, "Ek geçişler hata yüzeyini ve gecikmeyi artırır.", "İlk isteği doğrudan nihai HTTPS adresine yönlendirin.", [SOURCES.tls]));
  inspectHsts(response, findings);
}

async function inspectHttpVariant(finalUrl, findings) {
  const secure = new URL(finalUrl);
  if (secure.protocol !== "https:") return;
  const http = new URL(secure);
  http.protocol = "http:";
  http.port = "";
  const attempt = await tryFetch(http.href, { maxBytes: 300_000 });
  if (!attempt.ok) {
    findings.push(finding("HTTP-VARIANT-UNREACHABLE", "tasima", "bilgi", "HTTP sürümü yanıt vermiyor", attempt.error, http.href, undefined, "HTTPS doğrudan çalışsa da eski HTTP bağlantılarının davranışı doğrulanamadı.", "HTTP kullanmıyorsanız bu bilinçli olabilir; kullanıyorsanız tek adımda HTTPS'e yönlendirin.", [SOURCES.tls]));
    return;
  }
  const result = attempt.result;
  if (!result.url.startsWith("https://")) {
    findings.push(finding("HTTP-NO-HTTPS-REDIRECT", "tasima", "yüksek", "HTTP sürümü HTTPS'e yönlenmiyor", `Son adres ${result.url}`, http.href, result.chain[0]?.durumKodu, "Kullanıcı trafiği şifresiz kalabilir.", "HTTP isteklerini nihai HTTPS adresine yönlendirin.", [SOURCES.tls]));
  }
  const first = result.chain[0];
  if (first && [302, 307].includes(first.durumKodu)) findings.push(finding("HTTP-REDIRECT-TEMPORARY", "tasima", "orta", "HTTP'den HTTPS'e geçiş geçici yönlendirme kullanıyor", `HTTP ${first.durumKodu}`, first.url, first.durumKodu, "Kalıcı güvenli adres tercihi daha zayıf ifade edilir.", "HTTP'den nihai HTTPS adresine 301 veya 308 yönlendirmesi kullanın.", [SOURCES.tls]));
  if (result.chain.length > 2) findings.push(finding("HTTP-REDIRECT-CHAIN", "tasima", "düşük", "HTTP'den HTTPS'e birden fazla yönlendirme var", `${result.chain.length - 1} yönlendirme`, http.href, first?.durumKodu, "Ek geçişler hata yüzeyini ve gecikmeyi artırır.", "HTTP isteğini doğrudan nihai HTTPS adresine yönlendirin.", [SOURCES.tls]));
}

function inspectHsts(response, findings) {
  const hsts = response.headers["strict-transport-security"] || "";
  if (!hsts) {
    findings.push(finding("HSTS-MISSING", "tasima", "orta", "HSTS başlığı bulunamadı", "Strict-Transport-Security yok", response.url, response.status, "Kullanıcının ilk HTTP isteği HTTPS'e ulaşmadan önce ağ saldırısına açık kalabilir.", "HTTPS tüm alt alanlarda doğrulandıktan sonra uygun max-age ile HSTS ekleyin; includeSubDomains seçimini kapsamı bilerek yapın.", [SOURCES.headers, SOURCES.tls]));
    return;
  }
  const maxAge = Number(/max-age\s*=\s*(\d+)/i.exec(hsts)?.[1]);
  if (!Number.isFinite(maxAge)) findings.push(finding("HSTS-INVALID", "tasima", "yüksek", "HSTS max-age değeri okunamıyor", hsts, response.url, response.status, "Tarayıcı HTTPS zorlamasını uygulamayabilir.", "Başlığı geçerli bir max-age yönergesiyle düzeltin.", [SOURCES.headers]));
  else if (maxAge < 15_552_000) findings.push(finding("HSTS-SHORT", "tasima", "düşük", "HSTS süresi kısa", hsts, response.url, response.status, "HTTPS zorlaması beklenenden erken sona erebilir.", "Dağıtımı kademeli test ettikten sonra max-age süresini en az 180 güne yükseltmeyi değerlendirin.", [SOURCES.headers]));
}

function inspectPage(response, page, findings) {
  const { headers, url, status } = response;
  const csp = headers["content-security-policy"] || "";
  const cspReportOnly = headers["content-security-policy-report-only"] || "";
  if (!csp) findings.push(finding("CSP-MISSING", "tarayici", "yüksek", "Content Security Policy uygulanmıyor", cspReportOnly ? "Yalnızca Report-Only başlığı var" : "Content-Security-Policy yok", url, status, "Başarılı bir içerik enjeksiyonunun tarayıcıdaki etkisini sınırlayan savunma katmanı eksik.", "Önce Report-Only ile ölçün, gerekli kaynakları açıkça izinli kılan bir CSP hazırlayın ve sonra zorunlu moda alın; mevcut uygulamayı körlemesine bozmayın.", [SOURCES.headers, SOURCES.csp]));
  else inspectCsp(csp, url, status, findings);
  const frameProtected = /(?:^|;)\s*frame-ancestors\b/i.test(csp) || /^(deny|sameorigin)$/i.test(headers["x-frame-options"] || "");
  if (!frameProtected) findings.push(finding("FRAME-PROTECTION-MISSING", "tarayici", "orta", "Çerçeveleme koruması bulunamadı", "CSP frame-ancestors ve geçerli X-Frame-Options yok", url, status, "Sayfa uygun olmayan bir sitede çerçevelenerek tıklama kaçırma saldırılarına yardımcı olabilir.", "Tercihen CSP frame-ancestors kullanın; eski istemciler gerekiyorsa uyumlu X-Frame-Options da ekleyin.", [SOURCES.headers]));
  if ((headers["x-content-type-options"] || "").toLowerCase() !== "nosniff") findings.push(finding("NOSNIFF-MISSING", "tarayici", "düşük", "MIME türü koklama koruması eksik", `X-Content-Type-Options=${headers["x-content-type-options"] || "yok"}`, url, status, "Bazı yanlış içerik türleri tarayıcı tarafından beklenmedik biçimde yorumlanabilir.", "X-Content-Type-Options: nosniff gönderin ve doğru Content-Type kullanın.", [SOURCES.headers]));
  if (!headers["referrer-policy"]) findings.push(finding("REFERRER-POLICY-MISSING", "tarayici", "düşük", "Referrer Policy açıkça belirtilmemiş", "Referrer-Policy yok", url, status, "Dış isteklere gereğinden fazla adres bilgisi taşınabilir.", "Uygulama ihtiyacına uygun, örneğin strict-origin-when-cross-origin gibi açık bir politika belirleyin.", [SOURCES.headers]));
  if (!headers["permissions-policy"]) findings.push(finding("PERMISSIONS-POLICY-MISSING", "tarayici", "düşük", "Permissions Policy bulunamadı", "Permissions-Policy yok", url, status, "Sayfanın ihtiyaç duymadığı güçlü tarayıcı özellikleri açıkça sınırlandırılmıyor.", "Kamera, mikrofon ve konum gibi kullanılmayan özellikleri kapatan ölçülü bir politika belirleyin.", [SOURCES.headers]));
  inspectCookies(response, findings);
  inspectMixedContent(response, page, findings);
  inspectForms(response, page, findings);
  if (headers["x-powered-by"]) findings.push(finding("TECH-HEADER-EXPOSED", "sizinti", "düşük", "Teknoloji başlığı yayımlanıyor", `X-Powered-By: ${headers["x-powered-by"]}`, url, status, "Gereksiz teknoloji bilgisi hedefe yönelik araştırmayı kolaylaştırabilir.", "İşlev için gerekmiyorsa X-Powered-By başlığını kaldırın; bunu tek başına güçlü bir güvenlik önlemi saymayın.", [SOURCES.headers]));
  if (page.generator) findings.push(finding("GENERATOR-EXPOSED", "sizinti", "bilgi", "Üretici bilgisi HTML içinde açıklanıyor", `generator=${page.generator}`, url, status, "Kullanılan ürün veya sürüm hakkında ek ipucu verebilir.", "İşlevsel gereksinim yoksa generator etiketini kaldırmayı değerlendirin.", []));
}

function inspectCsp(csp, url, status, findings) {
  const lowered = csp.toLowerCase();
  if (/script-src[^;]*'unsafe-eval'/.test(lowered)) findings.push(finding("CSP-UNSAFE-EVAL", "tarayici", "yüksek", "CSP script-src unsafe-eval içeriyor", "script-src içinde 'unsafe-eval'", url, status, "Kod enjeksiyonu durumunda dinamik kod çalıştırma savunmayı zayıflatır.", "Bağımlılıkları ve derlemeyi inceleyip unsafe-eval gereksinimini kaldırın; doğrulamadan politikayı değiştirmeyin.", [SOURCES.csp]));
  if (/script-src[^;]*'unsafe-inline'/.test(lowered) && !/script-src[^;]*(?:'nonce-|sha256-|sha384-|sha512-)/.test(lowered)) findings.push(finding("CSP-UNSAFE-INLINE", "tarayici", "orta", "CSP satır içi betiklere geniş izin veriyor", "script-src içinde hash/nonce olmadan 'unsafe-inline'", url, status, "Satır içi betik enjeksiyonlarına karşı CSP koruması azalır.", "Nonce veya hash tabanlı kademeli bir CSP'ye geçin; framework gereksinimlerini test edin.", [SOURCES.csp]));
  if (/script-src[^;]*(?:^|\s)\*(?:\s|;|$)/.test(lowered)) findings.push(finding("CSP-SCRIPT-WILDCARD", "tarayici", "yüksek", "CSP betik kaynaklarında joker izin var", "script-src *", url, status, "Güvenilmeyen bir kaynaktan betik yüklenmesine izin verilebilir.", "Gerekli betik kaynaklarını açıkça listeleyin ve joker izni kaldırın.", [SOURCES.csp]));
  if (!/(?:^|;)\s*(?:default-src|script-src)\b/.test(lowered)) findings.push(finding("CSP-SCRIPT-DIRECTIVE-MISSING", "tarayici", "orta", "CSP betik kaynaklarını sınırlandırmıyor", "default-src ve script-src yok", url, status, "Betik yükleme davranışı politika tarafından kontrol edilmiyor.", "default-src veya script-src yönergesini uygulamanın gerçek kaynaklarına göre tanımlayın.", [SOURCES.csp]));
}

function inspectCookies(response, findings) {
  for (const raw of response.setCookies || []) {
    const [pair, ...parts] = raw.split(";");
    const name = pair.split("=", 1)[0].trim() || "(adsız)";
    const attrs = new Set(parts.map((part) => part.trim().split("=", 1)[0].toLowerCase()));
    const sameSite = parts.find((part) => /^\s*samesite=/i.test(part))?.split("=")[1]?.trim().toLowerCase();
    const sessionLike = /(session|sess|auth|token|jwt|sid|login)/i.test(name);
    if (!attrs.has("secure")) findings.push(finding("COOKIE-SECURE-MISSING", "cerezler", sessionLike ? "yüksek" : "orta", "Çerezde Secure niteliği yok", `${name}: Secure yok`, response.url, response.status, "Çerez şifrelenmemiş bir HTTP isteğine eklenebilir.", "Site yalnızca HTTPS çalıştıktan sonra çereze Secure ekleyin.", [SOURCES.cookies]));
    if (!attrs.has("httponly")) findings.push(finding("COOKIE-HTTPONLY-MISSING", "cerezler", sessionLike ? "yüksek" : "düşük", "Çerezde HttpOnly niteliği yok", `${name}: HttpOnly yok`, response.url, response.status, "JavaScript erişimi gerekmeyen hassas bir çerez XSS durumunda okunabilir.", "Çerez JavaScript tarafından okunmayacaksa HttpOnly ekleyin; işlevi doğrulamadan istemci çerezlerine uygulamayın.", [SOURCES.cookies]));
    if (!sameSite) findings.push(finding("COOKIE-SAMESITE-MISSING", "cerezler", sessionLike ? "orta" : "düşük", "Çerezde SameSite açıkça belirtilmemiş", `${name}: SameSite yok`, response.url, response.status, "Tarayıcı varsayılanına bağlı çapraz site gönderim davranışı oluşur.", "İş akışına göre SameSite=Lax veya Strict belirleyin; gerçek çapraz site ihtiyacını önce doğrulayın.", [SOURCES.cookies]));
    if (sameSite === "none" && !attrs.has("secure")) findings.push(finding("COOKIE-NONE-WITHOUT-SECURE", "cerezler", "yüksek", "SameSite=None çerezinde Secure yok", `${name}: SameSite=None; Secure yok`, response.url, response.status, "Modern tarayıcılar çerezi reddedebilir ve güvenli taşıma garantisi yoktur.", "Gerçek çapraz site ihtiyacı varsa Secure ekleyin; yoksa Lax veya Strict kullanın.", [SOURCES.cookies]));
  }
}

function inspectMixedContent(response, page, findings) {
  if (!response.url.startsWith("https://")) return;
  const mixed = page.resources.filter((resource) => resource.url.startsWith("http://"));
  if (mixed.length) findings.push(finding("MIXED-CONTENT", "tasima", "yüksek", "HTTPS sayfası HTTP kaynağı çağırıyor", mixed.slice(0, 3).map((item) => `${item.tag}: ${item.url}`).join(", "), response.url, response.status, "Kaynak engellenebilir veya ağ üzerinde değiştirilerek sayfanın bütünlüğünü bozabilir.", "Kaynakları doğrulanmış HTTPS adreslerinden yükleyin veya güvenli biçimde kendi alanınızda sunun.", [SOURCES.tls]));
}

function inspectForms(response, page, findings) {
  if (page.passwordInputs && !response.url.startsWith("https://")) findings.push(finding("PASSWORD-OVER-HTTP", "tasima", "kritik", "Parola alanı şifrelenmemiş sayfada", `${page.passwordInputs} parola alanı`, response.url, response.status, "Kullanıcı parolası ağ üzerinde ele geçirilebilir.", "Giriş sayfasını ve form hedefini yalnızca HTTPS üzerinden sunun.", [SOURCES.tls]));
  const insecure = page.forms.filter((form) => form.action?.startsWith("http://"));
  if (insecure.length) findings.push(finding("FORM-ACTION-HTTP", "tasima", "yüksek", "Form verisi HTTP adresine gönderiliyor", insecure.map((form) => `${form.method.toUpperCase()} ${form.action}`).join(", "), response.url, response.status, "Form verisi aktarım sırasında okunabilir veya değiştirilebilir.", "Form action hedefini HTTPS yapın ve hedefte TLS yapılandırmasını doğrulayın.", [SOURCES.tls]));
}

async function inspectCors(url, findings) {
  const probeOrigin = "https://websecrobot.invalid";
  const attempt = await tryFetch(url, { origin: probeOrigin, maxBytes: 300_000 });
  if (!attempt.ok) return;
  const allowOrigin = attempt.result.headers["access-control-allow-origin"] || "";
  const credentials = (attempt.result.headers["access-control-allow-credentials"] || "").toLowerCase() === "true";
  if (allowOrigin === probeOrigin && credentials) findings.push(finding("CORS-REFLECTS-ORIGIN", "caprazKoken", "yüksek", "CORS bilinmeyen kökeni kimlik bilgileriyle kabul ediyor", `Origin ${probeOrigin} → Access-Control-Allow-Origin ${allowOrigin}; credentials=true`, url, attempt.result.status, "Tarayıcı, oturum bilgileriyle dönen veriyi saldırgan kökenin okumasına izin verebilir.", "Sabit ve doğrulanmış izin listesi kullanın; Origin değerini körlemesine yansıtmayın ve credentials gereksinimini yeniden değerlendirin.", [SOURCES.cors]));
  else if (allowOrigin === "*" && credentials) findings.push(finding("CORS-WILDCARD-CREDENTIALS", "caprazKoken", "orta", "CORS joker kökeni credentials ile birlikte bildiriyor", "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true", url, attempt.result.status, "Tarayıcılar bu birleşimi reddeder; yapılandırma beklenen erişim modelini doğru ifade etmiyor.", "Genel kaynakta credentials kapatın veya kimlik bilgili erişimde doğrulanmış açık köken kullanın.", [SOURCES.cors]));
  else if (allowOrigin === "*") findings.push(finding("CORS-WILDCARD", "caprazKoken", "bilgi", "Kaynak tüm kökenlerden okunabiliyor", "Access-Control-Allow-Origin: *", url, attempt.result.status, "Bu genel veriler için bilinçli olabilir; hassas veri dönüyorsa erişim kapsamı gereğinden geniştir.", "Yanıtın gerçekten herkese açık olduğunu doğrulayın; hassas veride açık köken izin listesi kullanın.", [SOURCES.cors]));
}

async function inspectSecurityTxt(base, findings) {
  const url = new URL("/.well-known/security.txt", base).href;
  const attempt = await tryFetch(url, { maxBytes: 200_000 });
  const valid = attempt.ok && attempt.result.status === 200 && /(?:^|\n)Contact\s*:/i.test(attempt.result.body);
  if (!valid) findings.push(finding("SECURITY-TXT-MISSING", "sizinti", "bilgi", "Standart güvenlik bildirim adresi bulunamadı", attempt.ok ? `HTTP ${attempt.result.status}` : attempt.error, url, attempt.ok ? attempt.result.status : undefined, "İyi niyetli araştırmacılar güvenlik sorununu özel olarak nereye bildireceğini bulamayabilir.", "Gerçek ve izlenen bir iletişim kanalı varsa RFC 9116 uyumlu security.txt yayımlayın; sahte adres üretmeyin.", [SOURCES.securityTxt]));
  return { url, durumKodu: attempt.ok ? attempt.result.status : null, gecerli: valid };
}

function summary(response) {
  return { url: response.url, durumKodu: response.status, basliklar: pickHeaders(response.headers), cerezSayisi: response.setCookies?.length || 0 };
}

function pickHeaders(headers) {
  return Object.fromEntries(["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "access-control-allow-origin"].filter((key) => headers[key]).map((key) => [key, headers[key]]));
}

function finalize({ target, main, pages, findings, started, securityTxt }) {
  const unique = [...new Map(findings.map((item) => [`${item.kod}:${item.kanit.url}:${item.kanit.bulunan || ""}`, item])).values()]
    .sort((a, b) => ORDER[a.seviye] - ORDER[b.seviye]);
  return {
    surum: "0.1.0",
    olusturuldu: new Date().toISOString(),
    hedef: { girilen: target.href, son: main?.url || null },
    ozet: { sureMs: Date.now() - started, incelenenSayfa: pages.length, bulgu: unique.length, kritik: unique.filter((item) => item.seviye === "kritik").length, yuksek: unique.filter((item) => item.seviye === "yüksek").length },
    puanlar: calculateScores(unique),
    bulgular: unique,
    sayfalar: pages,
    securityTxt,
    sinirlar: ["Yalnızca herkese açık HTTP yanıtları ve sınırlı, güvenli GET istekleri incelenir.", "Port taraması, parola denemesi, payload enjeksiyonu veya açık istismarı yapılmaz.", "JavaScript çalıştırılmaz ve giriş gerektiren alanlara erişilmez.", "Bulgu olmaması sitenin güvenli olduğunu kanıtlamaz.", "Rapor bir sızma testi veya mevzuat uygunluk belgesi değildir."]
  };
}

function finding(kod, kategori, seviye, baslik, bulunan, url, durumKodu, etkisi, cozum, kaynaklar) {
  return { kod, kategori, seviye, baslik, aciklama: `${bulunan}. Bu gözlem canlı ve herkese açık HTTP davranışına dayanır.`, kanit: { url, ...(durumKodu ? { durumKodu } : {}), bulunan }, etkisi, cozum, otomatikDuzeltilebilir: false, kaynaklar };
}
