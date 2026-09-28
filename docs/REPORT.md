# Rapor şeması

Rapor JSON biçimindedir. `bulgular` dizisindeki her kayıt kod, kategori, önem seviyesi, canlı kanıt, etki, çözüm ve birincil kaynakları taşır.

Puan alanları:

- `tasima`: HTTPS, yönlendirme, HSTS ve karışık içerik
- `tarayici`: CSP, çerçeveleme, MIME, referrer ve izin politikaları
- `cerezler`: Secure, HttpOnly ve SameSite nitelikleri
- `caprazKoken`: dışarıdan gözlenebilir CORS davranışı
- `sizinti`: gereksiz teknoloji işaretleri ve güvenlik bildirim kanalı

Puanlar önceliklendirme yardımcısıdır; sitenin güvenli olduğunu kanıtlamaz. JSON sonundaki `sinirlar` alanı her tüketici tarafından korunmalıdır.
