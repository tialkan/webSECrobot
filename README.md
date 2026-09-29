# WebSECRobot

WebSECRobot, bir internet sitesinin dışarıdan gözlenebilen güvenlik sinyallerini **canlı HTTP davranışına bakarak** denetleyen açık kaynak ve pasif bir araçtır.

Bir sızma testi değildir ve “site tamamen güvenli” garantisi vermez. HTTPS/HSTS, güvenlik başlıkları, çerez nitelikleri, CORS, karışık içerik ve gereksiz teknoloji sızıntılarını kanıtlarıyla gösterir. Çıktıyı JSON/Markdown olarak indirebilir veya güvenli düzeltme istemini kendi yapay zekâ aracınıza verebilirsiniz.

TezAtlas sayfasında ayrıca sıfırdan geliştirilen bir siteye teknik SEO ve güvenlik temelini birlikte kurduran kopyalanabilir bir master prompt bulunur. Prompt production için pasif doğrulamayı varsayılan tutar; açık yetki ve local/staging kapsamı verildiğinde güvenli-aktif testlere kademeli geçer.

**Kolay kullanım ve yöntem:** [tezatlas.com/websecrobot](https://tezatlas.com/websecrobot)

**Kaynak kod:** [github.com/tialkan/webSECrobot](https://github.com/tialkan/webSECrobot)

## Hızlı başlangıç

Node.js 20.11 veya üstü yeterlidir; çalışma zamanı bağımlılığı yoktur.

```bash
npm start
# http://localhost:3000/websecrobot
```

Komut satırından:

```bash
node bin/websecrobot.js https://example.com --format json
node bin/websecrobot.js https://example.com --format markdown --output rapor.md
```

## Neleri denetler?

- HTTPS kullanımı, yönlendirme zinciri ve HSTS
- Content Security Policy ve riskli betik izinleri
- Çerçeveleme, MIME koklama, referrer ve tarayıcı izin politikaları
- `Secure`, `HttpOnly` ve `SameSite` çerez nitelikleri
- CORS'ta bilinmeyen köken yansıtma ve aşırı geniş izinler
- HTTPS sayfasındaki şifresiz kaynaklar ve form hedefleri
- `X-Powered-By`, generator ve standart `security.txt` sinyalleri

## Bilerek yapmadıkları

- Port taraması ve servis keşfi
- Parola denemesi veya kimlik doğrulama saldırısı
- SQLi, XSS, dosya yolu ya da başka saldırı payload'ları gönderme
- Açığı istismar etme veya veri çıkarma
- JavaScript çalıştırma ve giriş gerektiren alanlara erişme

Bu sınırlar aracı günlük, düşük riskli bir ilk kontrol için kullanışlı kılar; profesyonel sızma testinin yerini tutmaz.

## API

```bash
curl -X POST http://localhost:3000/websecrobot/api/audit \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com"}'
```

JSON şeması ve puanların anlamı [`docs/REPORT.md`](docs/REPORT.md) içindedir.

## Kaynaklar

Kurallar öncelikle [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/), [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html), MDN'nin [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP), [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS) ve [güvenli çerez](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies) rehberlerine dayanır.

## Lisans

[MIT](LICENSE) · Tarık İsmet ALKAN tarafından geliştirilmiştir ve TezAtlas üzerinden sunulur.
