const CATEGORY_NAMES = {
  tasima: "Taşıma güvenliği",
  tarayici: "Tarayıcı korumaları",
  cerezler: "Çerez güvenliği",
  caprazKoken: "Çapraz köken",
  sizinti: "Bilgi sızıntısı"
};

export function reportToMarkdown(report) {
  const lines = [
    "# WebSECRobot raporu",
    "",
    `- Hedef: ${report.hedef.girilen}`,
    `- Son adres: ${report.hedef.son || "erişilemedi"}`,
    `- Oluşturulma: ${report.olusturuldu}`,
    `- İncelenen sayfa: ${report.ozet.incelenenSayfa}`,
    "",
    "## Alan puanları",
    ""
  ];
  for (const [key, value] of Object.entries(report.puanlar)) lines.push(`- ${CATEGORY_NAMES[key] || key}: ${value}/100`);
  lines.push("", "## Bulgular", "");
  if (!report.bulgular.length) lines.push("Pasif denetim sınırları içinde bulgu bulunmadı.", "");
  for (const item of report.bulgular) {
    lines.push(`### [${item.seviye.toUpperCase()}] ${item.baslik}`, "", item.aciklama, "", `**Kanıt:** ${item.kanit.url}${item.kanit.bulunan ? ` — ${item.kanit.bulunan}` : ""}`, "", `**Etkisi:** ${item.etkisi}`, "", `**Çözüm:** ${item.cozum}`, "");
    if (item.kaynaklar?.length) lines.push(`**Kaynaklar:** ${item.kaynaklar.join(", ")}`, "");
  }
  lines.push("## Sınırlar", "", ...report.sinirlar.map((item) => `- ${item}`));
  return lines.join("\n");
}

export function buildFixPrompt(report) {
  const payload = report.bulgular
    .filter((item) => ["kritik", "yüksek", "orta"].includes(item.seviye))
    .map((item) => ({ kod: item.kod, kategori: item.kategori, seviye: item.seviye, baslik: item.baslik, kanit: item.kanit, cozum: item.cozum, kaynaklar: item.kaynaklar }));
  return `Aşağıdaki WebSECRobot bulgularını yalnızca sahibi olduğum veya test etmeye yetkili olduğum mevcut projede güvenli biçimde düzelt. Önce repoyu, tüm AGENTS.md dosyalarını, framework belgelerini ve ilgili birincil güvenlik kaynaklarını incele. Kullanıcının ilgisiz değişikliklerini koru. Her bulguyu canlı HTTP davranışıyla doğrula; yalnızca kaynak kodda doğru görünmesini başarı sayma. CSP, CORS, çerez veya oturum ayarlarını körlemesine değiştirme; mevcut giriş, ödeme, form ve üçüncü taraf entegrasyonlarını bozmayacak en dar politikayı seç. Uydurma iletişim adresi veya security.txt üretme. Exploit, parola denemesi, veri çıkarma ya da yetkisiz tarama yapma. Değişikliklerden sonra testleri çalıştır; her bulgunun nasıl doğrulandığını ve kalan riskleri raporla.\n\nHedef: ${report.hedef.son || report.hedef.girilen}\n\nBulgular:\n${JSON.stringify(payload, null, 2)}`;
}
