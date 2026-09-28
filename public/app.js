const form = document.querySelector("#audit-form");
const status = document.querySelector("#status");
const results = document.querySelector("#results");
let report;

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = document.querySelector("#site-url").value.trim();
  if (!url) return;
  status.classList.remove("hidden"); results.classList.add("hidden");
  try {
    const response = await fetch("/websecrobot/api/audit", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.hata || "Denetim tamamlanamadı.");
    report = data; render(data); status.classList.add("hidden"); results.classList.remove("hidden"); results.scrollIntoView({ behavior: "smooth" });
  } catch (error) { status.textContent = error.message; }
});

function render(data) {
  document.querySelector("#summary").innerHTML = [[data.ozet.incelenenSayfa,"SAYFA"],[data.ozet.bulgu,"BULGU"],[data.ozet.kritik,"KRİTİK"],[`${(data.ozet.sureMs/1000).toFixed(1)} sn`,"SÜRE"]].map(([v,l]) => `<div><b>${esc(v)}</b><span>${l}</span></div>`).join("");
  const names={tasima:"Taşıma",tarayici:"Tarayıcı",cerezler:"Çerezler",caprazKoken:"Çapraz köken",sizinti:"Sızıntı"};
  document.querySelector("#scores").innerHTML=Object.entries(data.puanlar).map(([k,v])=>`<article><b>${v}</b><span>${names[k]||k}</span></article>`).join("");
  document.querySelector("#findings").innerHTML=data.bulgular.length?data.bulgular.map((f,i)=>`<details ${i===0?"open":""}><summary><span data-level="${esc(f.seviye)}">${esc(f.seviye)}</span><b>${esc(f.baslik)}</b></summary><div><section><h3>KANIT</h3><code>${esc(f.kanit.url)}\n${esc(f.kanit.bulunan||"")}</code></section><section><h3>ETKİ</h3><p>${esc(f.etkisi)}</p></section><section><h3>ÇÖZÜM</h3><p>${esc(f.cozum)}</p></section></div></details>`).join(""):"<p>Pasif denetim sınırları içinde bulgu bulunmadı.</p>";
}

document.querySelector("#json").addEventListener("click",()=>download(JSON.stringify(clean(report),null,2),"websecrobot-raporu.json","application/json"));
document.querySelector("#md").addEventListener("click",()=>download(report?.markdown,"websecrobot-raporu.md","text/markdown"));
document.querySelector("#prompt").addEventListener("click",async(event)=>{await navigator.clipboard.writeText(report?.duzeltmeIstemi||"");event.currentTarget.textContent="Kopyalandı ✓";});
function clean(value){const copy={...value};delete copy.markdown;delete copy.duzeltmeIstemi;return copy}
function download(content,name,type){if(!content)return;const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([content],{type}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function esc(value){return String(value??"").replace(/[&<>'"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[c]))}
