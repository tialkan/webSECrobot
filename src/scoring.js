const PENALTY = { kritik: 40, "yüksek": 22, orta: 11, "düşük": 4, bilgi: 0 };
const CATEGORIES = ["tasima", "tarayici", "cerezler", "caprazKoken", "sizinti"];

export function calculateScores(findings) {
  return Object.fromEntries(CATEGORIES.map((category) => {
    const unique = [...new Map(findings.filter((finding) => finding.kategori === category).map((finding) => [finding.kod, finding])).values()];
    const penalty = unique
      .reduce((sum, finding) => sum + (PENALTY[finding.seviye] || 0), 0);
    return [category, Math.max(0, 100 - penalty)];
  }));
}
