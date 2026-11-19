# Paket: HIZ — Apple silikonda hızlandırma (E1, E2, E5) — plan paketi

Opus başarım / plan paketi. Ürün kodunu değiştirmiyorsun; var olan veriden ölçüyor, kodu okuyor ve uygulanabilir plan yazıyorsun. Önce `ORTAK_BRIF.md` ("yasak cevap / aykırı öncül" sana uygulanmaz), `KARARLAR.md`.

Dizinlerin: `docs/arge/2026-11-19_mythos/hiz/`, `scripts/arge/hiz/`, `~/karadul_olcum/runs/arge-2026-11-19/hiz/`.

## Soru (Berke, 2026-11-19)

"Optimizasyon üzerine çalışıldı mı? M silikonlarda daha nasıl hızlandırırız?"

ÖLÇEK paketi (`OLCEK.md`, `olcek/`) mimariyi ele alıyor: neyi hiç koşmamalı, neyi önbelleğe almalı. Bu paket ötekidir: **koşan her adımı aynı makinede nasıl hızlandırırız.** İkisinin kesiştiği yeri yaz, yineleme.

## Elde olan ölçüm

**Gösteri koşusu 2** (Ollama.app 0.40.3, arm64 dilimi 26,6 MB, Ghidra'nın bulduğu 13 559 fonksiyon; main 2381dce; "Objective-C Message Analyzer" kapalı; makine ağır yük altındaydı: yük ortalaması 40–60, 14 çekirdek). Dosya zamanlarından (`~/karadul_olcum/runs/gosteri-2026-11-19/ollama/ws/…/static/ghidra_output/`):

| Zaman | Biten adım | Adım süresi |
|---|---|---|
| 11:10:50 | başlangıç | — |
| 11:16:25 | `functions.json` (içe aktarma + otomatik analiz) | 5,6 dk |
| 11:17:23 | `call_graph.json` | 1,0 dk |
| 11:26:07 | `decompiled.json` (13 554 `.c`) | 8,7 dk |
| 11:32:03 | `xrefs.json` | 5,9 dk |
| 11:32:06 | `pcode.jsonl` (122 MB) | — |
| 11:42:06 | `cfg.json` (122 MB) | 10,0 dk |
| 12:14:38 | `bsim_matches.json` (sonuç boş) | **32,5 dk** |
| 12:29:30 | `intelligence_report.json` | 14,7 dk |
| 12:37 | yeniden kurma aşamaları sürüyordu | — |

- Ghidra adımı boyunca JVM'de "Python Reference Queue" iş parçacığının işlemci süresi 1 714 sn idi (jstack, 49. dakika): Python ↔ Java geçişi (JPype) kendi başına büyük bir maliyet.
- İlk denemede aynı ikili "Objective-C Message Analyzer"da 22 dk tek fonksiyonda döndü (`deneme1_jstack.txt`).
- Koşu `CIKIS` dosyası oluşunca bitmiş demektir; `kosu.log` sonunda `/usr/bin/time -l` çıktısı (tepe bellek) olacak. Bittiyse aşama kırılımının kalanını da çıkar.

**Önceki ölçümler:** P16c (toplu BSim: Ghidra köprüsü 2,8×–6,7×; "Decompiler Switch Analysis" otomatik analizin %55'i; decompile işçi sayısı yük altında ölçülemedi; `docs/arge/2026-11-18_onarim/P16c.md`), P01b (istihbarat taraması 196 ikilide 208 sn → 14 sn), taban koşusu 119 ikili (`docs/arge/2026-11-19_birlesik_olcum/sonuc.md` §9), bilgi bankası `~/.claude/knowledge/perf-reference.md`.

**Makine:** Apple M4 Max, 10 başarım + 4 verim çekirdeği, 36 GB birleşik bellek.

## Kalemler (hepsi)

1. **Zaman çizelgesi.** Yukarıdaki tabloyu koşu çıktılarından betikle yeniden üret ve tamamla (Ghidra sonrası aşamalar dahil; ürünün kendi aşama süre kaydı varsa onu kullan). 119 ikilik taban koşusunda aynı aşamaların payını çıkar: küçük ikilide ve büyük ikilide baskın aşama aynı mı?
2. **Sıcak noktalar koddan** (dosya:satır): her uzun adım için döngünün nerede olduğu, Python ↔ Java geçiş sayısının neyle ölçeklendiği, tek iş parçacığı mı, belleğe ne alındığı, diske nasıl yazıldığı. En az şunlar: `_extract_xrefs`, `_extract_cfg`, `_extract_pcode`, decompile dökümü (`karadul/ghidra/headless.py`), BSim (`karadul/ghidra/bsim.py`: 13 559 fonksiyonda 32,5 dk ve boş sonuç neden), istihbarat taraması (`karadul/analyzers/binary_intelligence.py`: 26 MB'de 14,7 dk neden), yeniden kurma aşamaları (`karadul/pipeline/steps/`).
3. **Ghidra'sız profil.** Yük altında mutlak süre güvenilmez ama sıcak nokta sırası geçerlidir. Küçük bir çalışma alanının kopyasında (ör. taban koşusundan `mac/tmux`) Ghidra sonrası aşamaları `cProfile` ile profille (yöntem: `docs/arge/2026-11-18_onarim/P12a.md` yeniden oynatma). Aynı anda tek profil koşusu; işçi sayısını düşük tut (makine yüklü). İlk 20 fonksiyon tablosu.
4. **Apple silikona özgü seçenekler** (her biri: beklenen etki, nasıl ölçülür, risk):
   - başarım / verim çekirdeği ayrımı: işçi sayısı öntanımları (`karadul/config.py` `CPU_PERF_CORES` ve kullanan yerler), decompile işçi sayısı (6 / 9 / 12), verim çekirdeklerine düşen işler;
   - JVM: yığın boyutu (bugün RAM'in %40'ı), çöp toplayıcı seçimi, JIT ısınması; birleşik bellekte Ghidra + Python + (KaradulLM modeli) paylaşımı;
   - Python ↔ Java geçişini azaltma: döngüyü Java tarafına taşıma (derlenmiş yardımcı sınıf ya da Ghidra betiği), toplu çağrı, akış biçimli yazma;
   - çok süreçlilik: `spawn` maliyeti, paylaşılan salt okur veri, süreç havuzunun yeniden kullanımı;
   - disk: on binlerce küçük dosya yazımı (APFS), 122 MB'lik tek parça JSON'lar, sıkıştırma;
   - yerel kod: sıcak Python döngülerinde vektörleştirme / yerel uzantı (hangileri değer?).
5. **Gereksiz iş.** Sonucu kullanılmayan ya da boş çıkan adımlar (bu koşuda BSim 32,5 dk koştu, eşleşme dosyası boş); iki kez hesaplanan şeyler; `cfg.json` ile `pcode.jsonl`'in örtüşmesi. Atlanabilecek her adım için koşul.
6. **Öncelik tablosu.** Öneri × (beklenen kazanç aralığı **tahmin** etiketiyle, emek, risk, çıktıyı değiştirir mi). Çıktıyı değiştirmeyen hızlandırmalar ayrı listede (bayt eşitliğiyle kabul edilebilir).
7. **PLAN.** Opus paketleri: amaç, dokunacağı / dokunmayacağı dosyalar (tam yol; doğrulanmış), 5–8 adım, kabul ölçütü (aynı ikilide önce / sonra süre, üç tekrar medyanı, **boş makinede**; çıktı bayt bayt aynı ya da ad ölçümü değişmedi), ön kayıt metni, sınama beklentisi. Ayrı bir ilk paket: boş makinede taban ölçümü (E1; üç boyutta ikili; aşama başına süre ve tepe bellek) — öbür paketlerin "önce" sayısı buradan gelir.
8. **Çakışma.** ÖLÇEK planı, yayın kapısı G1–G4 ve ÜST VERİ planıyla kesişen dosyalar.

## Kurallar

- Ghidra koşma; `karadul analyze` koşma (gösteri koşusu sürüyor olabilir). Gösteri dizini salt okur.
- Ürün kodunu, testleri, ortak ölçüm betiklerini değiştirme. Git'te durumu değiştiren komut yok. İndirme, silme yok. Alt ajan ya da codex çağırma. Kilitli setlere ve `~/karadul_olcum/ozkod_nufus/`'a dokunma.
- Makine yüklü: ağır koşu yok; profil koşusu tek ve küçük.
- Her sayı betikten; kazanç öngörüleri "tahmin" etiketiyle ve aralıkla. Ölçmediğin şeyi ölçülmüş gibi yazma.
- Çıktı: `DEFTER.md`, `BULGULAR.md`, `PLAN.md`, `BERKE.md`. `PLAN.md` yazanı olmadan uygulanabilir olmalı.
- Zaman kısıtın yok; kalemleri atlama. Türkçe yaz, Türkçe karakterleri doğru kullan.
- Son mesaj: en çok 10 satır özet + yollar + `## PAKET BİTTİ`.
