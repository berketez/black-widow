# ÖLÇ-1 ön kaydı — taban ölçümü (A-18'e göre yeniden yazıldı; koşudan ÖNCE commit)

- Yazıldı: 2026-11-20, Dalga 0 OLCEK paketi. Koşu henüz yapılmadı; hiçbir hedef bu ürünle koşulmadı.
- Dayanak belgeler: `olcek/PLAN.md` ÖLÇ-1 (taslak), `KARARLAR.md` A-18 (T100 / T300 / PAKET duvarı 8 sa → **2 sa**; ÖLÇ-1 ile HZ-0 tek koşu), `olcek/BULGULAR.md` §3.4–§3.6, `hiz/BULGULAR.md` §1.1, `olcek/OLC0.md`. Sayıların kaynağı her satırda; kaynağı olmayan sayı yazılmadı.
- Taslaktan farklar: (1) duvarlar 2 sa; (2) T25 ayrı koşulmaz, HZ-0'ın B hedefi T25'tir (3 tekrar, duvar 10 800 sn); (3) aralığı duvarı içeren öngörü **belirsiz** diye yazıldı ve tuttu / tutmadı hükmü verilmeyecek, yalnız sonuç kayda geçecek; (4) T25 tepe bellek satırı OLC0 bulgusuyla yeniden yazıldı (aşağıda gerekçe).

## Koşu düzeni (değişmez)

- Koşucu `scripts/measurement/olcek_kos.py` (ÖLÇ-A), kuyruk `scripts/arge/olcek/gece_kosusu.py` (`--gece 2` grubu `olc1`; T25 = `--gece 1` grubu `hz0`'ın B'si). Ürün ağacı `~/karadul_olcum/urun-<commit>` (commit koşu künyesinde: `kunye.json` → `agac.commit`); her koşu `ghidra_kuyruk.sh` ile, aynı anda tek Ghidra; `PYTHONHASHSEED=0`; koşuya özel `KARADUL_CACHE_DIR`; JVM GC günlüğü.
- Boş makine (`hiz/PLAN.md` §1): koşu başında ve sonunda 1 dk yük < 0,25 × `os.cpu_count()` (bu makinede 3,5). Geçersiz koşunun öngörüleri "ölçülmedi (geçersiz koşu)" diye yazılır; en çok 2 yineleme.
- Hedefler (`olcek/PLAN.md` ÖLÇ-1 tablosu): T25 = Ollama 0.40.3 arm64 dilimi (`~/karadul_olcum/runs/gosteri-2026-11-19/ollama/girdi/Ollama`), **ayar `gosteri.yaml`** ("Objective-C Message Analyzer" kapalı: gösteri koşusunun koşulu; açıkken 1. denemede tek fonksiyonda 22+ dk takıldı); T100 = `mlir-transform-opt` (LLVM 23.1.6); T300 = `libtensorflow_cc.2.dylib` (TensorFlow 2.19.0); PAKET = `/Applications/FreeCAD.app` (1.1.4); PAKET-E = `/Applications/Element.app` (isteğe bağlı). T100 / T300 / PAKET / PAKET-E öntanım ayarla.
- Duvar: T25 10 800 sn; T100 / T300 / PAKET / PAKET-E 7 200 sn. Duvarda karadul'a SIGTERM, 60 sn sonra SIGKILL; `BITTI` = `zaman_asimi`.

## Öngörüler

Hüküm sütunu koşudan sonra `OLC1.md`'de doldurulur. "Kesin" = aralığın tamamı duvarın bir yanında; "belirsiz" = aralık duvarı içeriyor (hüküm yok, yalnız kayıt).

### T25 (HZ-0 B; 3 geçerli tekrarın her biri ve ortancası)

| No | Öngörü | Dayanak | Tür |
|---|---|---|---|
| Ö1 | Ghidra köprüsü (`ghidra_status.json` `duration_seconds`) ∈ [3 052; 4 578] sn | gösteri 3 815,4 sn ± %20 (`olcek/PLAN.md` ÖLÇ-1 taslağı; gösteri yük altında, yük 40–60). Boş makinede alt sınırın altına inerse "tutmadı (iyi yönde)" yazılır | kesin |
| Ö2 | Uçtan uca koşu 10 800 sn duvarında biter (`BITTI` ≠ `zaman_asimi`) | gösteri 7 729 sn (yük altında); TAHMİN [3 170; 7 730] sn (`GECE_PLANI.md`): aralık duvarın altında | kesin |
| Ö3 | `time -l` azami RSS ∈ [3,74; 5,62] GB (10⁹ B) | gösteri 2. deneme 4 680 646 656 B ± %20 (aynı ayar; `hiz/BULGULAR.md` §1.1, `OLC0.md`) | kesin |
| Ö4 | Örnekleyicinin tepe ağaç RSS'i ≥ `time -l` azami RSS | yapı gereği: ağaç toplamı (karadul + yerel decompiler süreçleri) ≥ tek sürecin azamisi. Örnekleme 10 sn aralıklı olduğu için tepeyi kaçırırsa tutmayabilir; kayda geçer | kesin |

**Taslaktaki "T25 tepe RSS ≥ 6,4 GB" satırı neden değişti:** o sayı 1. denemenin (ObjC çözümleyicisi açık, otomatik analizde takılı kalmış, SIGTERM) `time -l` değeriydi. Aynı ayarla (`gosteri.yaml`) biten 2. deneme 4,68 GB verdi (`OLC0.md`). Öngörü koşunun gerçek koşuluna (ObjC kapalı) bağlandı. Taslak satırı commit'lenmiş bir ön kayıt değildi; burada silinmedi, gerekçesiyle değiştirildi.

### T100 — `mlir-transform-opt` (94 869 440 B; kod 56 755 068 B; 163 141 fonksiyon başlangıcı; duvar 7 200 sn)

| No | Öngörü | Dayanak | Tür |
|---|---|---|---|
| Ö5 | Ghidra köprüsü 7 200 sn içinde bitmez (`static/ghidra_status.json` yok; `BITTI` = `zaman_asimi`) | köprü TAHMİN A [14,5; 39,4] sa, kötümser B 136,5 sa (`BULGULAR.md` §3.5): aralığın tamamı duvarın üstünde. Biterse "tutmadı (iyi yönde)" | kesin |
| Ö6 | İlk adım (JVM + içe aktarma + otomatik analiz + fonksiyon listesi; `ghidra_output/functions.json` yazılır) 7 200 sn içinde biter | TAHMİN A [1 830; 3 811] sn (`egri.json` → `dis_degerleme_TAHMIN` → T100 → `otomatik_analiz+fonksiyonlar`): aralık duvarın altında. Kötümser B 19 847 sn bu öngörüyü bozar; tutmazsa B'nin yönü kayda geçer | kesin (A'ya göre) |
| Ö7 | Duvar anında koşu decompile adımındadır: `call_graph.json` yazılmış, `decompiled.json` yazılmamış, `decompiled/` altında ≥ 1 `.c` | A: ilk adım + dizgi + çağrı grafiği [2 283; 4 328] sn < 7 200 sn; decompile alt ucu 16 214 sn kalan süreden uzun (`egri.json` T100 adımları). Ürünün kendi decompile sınırı (`timeouts.ghidra` 7 200 sn; dosya < 100 MB → çarpan 1) duvardan önce bağlamaz | kesin (A'ya göre) |
| Ö8 | Duvar anında yazılmış `.c` sayısı | öngörü yok (decompile hızı büyük ikilide ölçülmedi); yalnız sayı | — |
| Ö9 | Tepe RSS | öngörü yok (otomatik analiz / decompile sırasında bellek büyük ikilide hiç ölçülmedi; `BULGULAR.md` §3.4'teki 7,0–55,2 GB köprü bütün adımları bitirince geçerli); yalnız sayı | — |

### T300 — `libtensorflow_cc.2.dylib` (646 577 920 B; kod 220 438 340 B; 746 814 fonksiyon başlangıcı; duvar 7 200 sn)

| No | Öngörü | Dayanak | Tür |
|---|---|---|---|
| Ö10 | Ghidra köprüsü 7 200 sn içinde bitmez | köprü TAHMİN A [77,9; 447,5] sa (`BULGULAR.md` §3.5) | kesin |
| Ö11 | İlk adım (otomatik analiz dahil) 7 200 sn içinde biter mi | TAHMİN A [5 041; 16 085] sn (`egri.json` T300 `otomatik_analiz+fonksiyonlar`): **aralık duvarı içeriyor → belirsiz**. Kayda: `functions.json` yazıldı mı, yazıldıysa koşu başından kaçıncı saniyede; yazılmadıysa duvar otomatik analizde (ürünün kendi sınırı dosya > 100 MB → 28 800 sn, duvardan önce bağlamaz) | **belirsiz** |
| Ö12 | Tepe ağaç RSS ≥ 14 745 MB (JVM yığın sınırına dayanır) | taslak hipotezi (`olcek/PLAN.md` ÖLÇ-1): yığın sınırı bu makinede `GHIDRA_HEAP_MB` = 14 745 (`karadul/config.py:222`; `BULGULAR.md` §3.4). Dayanak zayıf: 2 sa içinde yığının dolacağını gösteren ölçüm yok (tek bellek ölçümü 26 MB dilimin otomatik analizinde 6,4 GB). Tutmazsa kayda geçer | kesin (zayıf dayanaklı) |

### PAKET — FreeCAD.app (2,48 GiB; duvar 7 200 sn)

| No | Öngörü | Dayanak | Tür |
|---|---|---|---|
| Ö13 | Bileşenlerin hepsi bitmez: `components/*/static/ghidra_status.json` sayısı < bileşen sayısı | bugünkü kuralla 1 903 bileşen (`BULGULAR.md` §1, `envanter.py` taklidi); statik aşama TAHMİN S0 doğrusal [177,2; 345,3] sa (§3.6): alt sınır duvarın 88 katı. Ürünün gerçek bileşen sayısı künyeden okunur (`paket.bilesen_dizini`; taklit sayısı tutmazsa ayrıca kayda) | kesin |
| Ö14 | `static/bundle_analysis.json` yazılmaz | ürün kodu: yalnız bütün bileşenler bitince yazılıyor (`karadul/analyzers/app_bundle.py:469-474`; `BULGULAR.md` P5) | kesin |
| Ö15 | Biten bileşen sayısı ve bileşen başına Ghidra süresi | öngörü yok (bileşen sırası ve boyutları bu koşul için ölçülmedi); yalnız sayı | — |

### PAKET-E — Element.app (isteğe bağlı; duvar 7 200 sn)

| No | Öngörü | Dayanak | Tür |
|---|---|---|---|
| Ö16 | bitti / nerede kaldı | öngörü yok: Electron JS hattı büyük `asar` ile hiç koşulmadı (BICIM-09); lisans paket içindeki lisans dosyasından koşudan önce doğrulanmalı | — |

### Genel

| No | Öngörü | Dayanak | Tür |
|---|---|---|---|
| Ö17 | Koşulan her ÖLÇ-1 koşusunun künyesi eksiksiz (`kunye.json`: başlangıç / bitiş, çıkış, `time -l`, tepe RSS, tepe disk, yük, Ghidra adımları ya da "nerede kaldı", GC özeti) ve her biri için "bitti / şurada kaldı" hükmü verilebilir | ÖLÇ-1 kabul ölçütü; ÖLÇ-A duman koşusunda künye alanları denendi (`GECE_PLANI.md` kalem 2) | kesin |

## Hüküm biçimi (`OLC1.md`)

- Her satır: gözlenen değer, hüküm (tuttu / tutmadı / belirsiz-kayıt / ölçülmedi), kaynak dosya (`kunye.json` alanı). Tutmayan satır silinmez; eşik sonradan değişmez.
- Ö1–Ö4 için T25'in 3 geçerli tekrarının her biri ayrı ve ortancası; hükmü ortanca verir, tekrarlardan biri aralık dışındaysa ayrıca yazılır.
- Yayın notu cümlesi ÖLÇ-2'de (`olcek/PLAN.md` ÖLÇ-2); ÖLÇ-1 yalnız "bugün" sayısını verir.
