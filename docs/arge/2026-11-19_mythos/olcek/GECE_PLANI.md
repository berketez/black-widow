# OLCEK paketi (Dalga 0) — ilerleme ve gece koşusu planı

- Paket: `docs/arge/2026-11-20_dalga0/gonderim/OLCEK.md` (ÖLÇ-A → duman → ÖLÇ-0 → gece koşusu tasarımı; gece koşusu KOŞULMAZ).
- Taban: main `e996200` (worktree `--ff-only` ile ilerletildi; `karadul.__file__` worktree yolunu gösteriyor).
- Başlangıç: 2026-11-20 08:15 (`uptime` 1 dk yük 4,28).

## Kalem durumu

| # | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | ÖLÇ-A `olcek_kos.py` + testler + mutantlar | bitti | `45ac0f2` |
| 2 | Uçtan uca duman (cat) | 1. deneme 08:48'de 0 sn'de düştü (Ghidra başlamadı: `gece_kosusu` `--java-ek` değerini ayrı belirteçte veriyordu, argparse "-XX:"'i seçenek sandı; düzeltildi + test + mutant); 2. deneme kuyrukta | — |
| 3 | ÖLÇ-0 (`gosteri_son.json`, `OLC0.md`) | bitti | `ac8ac3f` |
| 4a, 4b | Ön kayıtlar `olcek/on_kayit_olc1.md`, `hiz/on_kayit_hz0.md` | bitti (koşudan önce) | `5f260d9` |
| 4c–4e | `hz0_ek.py`, `gece_kosusu.py`, `zaman_cizelgesi.py` eki, bu belge | bitti | (bu commit) |
| 5 | Testler ve mutasyon (`gece_kosusu` dahil) | testler bu commit'te; mutasyon dumandan sonra (duman aynı dosyaları kullanıyor) | — |

**08:50 — şu an bekleniyor:** duman 2. denemesi Ghidra kuyruğunda (`OLCEK bekliyor duman:cat`, 08:49:49); önünde ANA (S8-AA), HZ1 (S8 sonra kolu) ve OK5 koşuları var, kilit sırası FIFO değil. Tahmini bitiş 09:10–09:40 (TAHMİN: kuyruktakilerin bugünkü süreleri 36–291 sn / koşu). Mutasyon koşusu dumandan sonra (duman `olcek_kos.py` / `hz0_ek.py`'yi kilit alınınca yüklüyor; mutasyon o dosyaları değiştirir).

## Kalem 1 — ÖLÇ-A (`scripts/measurement/olcek_kos.py`)

- Arayüz planın adım 1'iyle aynı; ek seçenekler: `--java-ek` (JFR / AppCDS gibi ek JVM seçenekleri; gece kuyruğu kullanır), `--ornek-aralik` (10), `--disk-aralik` (60), `--kill-bekle-sn` (60), `--komut` (yalnız test kancası).
- Ağaç denetimi `urun_kos.agac_kunyesi` içe aktarılarak (kod kopyalanmadı); koşu başında ve sonunda.
- Duvar: `time`'ın çocuğuna (karadul) SIGTERM, 60 sn sonra gruba SIGKILL. `time`'a SIGTERM gönderilmez: kısa kesilen koşuda da `time -l` satırları kalır (gösteri 1. denemedeki gibi).
- `pid.json` (time ve karadul süreç numarası) eşlik eden örnekleyiciler için (HZ-0 `hz0_ek.py`).
- Disk taraması uzarsa (çok dosya) bir sonraki tarama `max(60, 5 × tarama süresi)` sn sonra: ölçüm koşuyu boğmasın. Plandan küçük sapma; künyede `disk_tarama_en_uzun_sn`.
- Ghidra adım süreleri: `ghidra_status.json` `adim_sureleri` (HZ-1) varsa o, yoksa `ghidra_output` dosya zamanları (`olcek_topla.ghidra_adim_sureleri` mantığı buraya taşındı); kaynak künyede `ghidra.adim_kaynagi`. Köprü yarıda kaldıysa her çıktının koşu başından beri saniyesi, son biten adım ve `decompiled/` sayısı.
- Testler: `tests/test_olcek_kos.py` 16 test (koşucu gerçek alt süreç; sahte analiz komutu; Ghidra yok). PLAN kabulü: duvar 5 sn → `zaman_asimi`, süre ≤ 67 sn (ölçülen ≈ 5 sn); varsayılan aralıklarla 30 sn'lik sahte koşuda `ornekler.csv` ≥ 3 satır (testte).
- Mutasyon: `scripts/measurement/mutation_specs_olcek_kos.json` 6 / 6 öldü (duvar eşiği, SIGKILL, SIGTERM'in hedefi, tepe RSS seçimi, ağaç RSS'i, adım kaynağı önceliği); `git diff` temiz.

## Kalem 3 — ÖLÇ-0 (salt okur)

- `gosteri_son.json` yazıldı (`~/karadul_olcum/runs/arge-2026-11-19/olcek/`); ayrıntı ve tablo `OLC0.md`.
- Ön kayıt kıyası: 10 satırın 3'ü tuttu, 7'si tutmadı (reconstruct süresi 2 353 sn ↔ öngörü üst sınırı 710–732; toplam 7 729 sn ↔ 1 632–1 827; disk / dosya / `out/` eksenlerin birinde tutuyor, öbüründe %1–15 kaçırıyor).
- 2. denemenin azami RSS'i 4,68 GB; PLAN'daki "T25 ≥ 6,4 GB" ön kayıt taslağı 1. denemenin (ObjC çözümleyicisi açık, takılı) sayısına dayanıyordu → `on_kayit_olc1.md` Ö3'te yeniden yazıldı.

## Kalem 4 — gece koşusu tasarımı (KOŞULMADI)

### Araçlar

- `scripts/arge/olcek/gece_kosusu.py`: verilen ürün commit'i için ağaç `~/karadul_olcum/urun-<kısa>` (yoksa `git worktree add --detach` + `urun_kos.CALISMA_VERISI` bağları), tek kök `~/karadul_olcum/runs/gece-<kısa>/`, Avast kolu kökü `~/karadul_olcum/runs/hiz-avast-dislama/<kısa>/`. Her koşu `olcek_kos.py` ile ve `ghidra_kuyruk.sh` içinde (etiket `<grup>:<kod>#<tekrar>`). `--kuru` planı ve TAHMİNİ süreyi basar, hiçbir şey oluşturmaz. `--gece 1|2|hepsi`, `--yalniz <grup>`; sonda `ozet.json` (+ zaman damgalı kopyası), `plan.json`, `gece.log`.
- Boş makine: başlamadan önce 1 dk yük < 0,25 × `os.cpu_count()` (= 3,5) olana dek en çok 900 sn bekler, inmezse başlatmaz; başlangıç yükü koşucunun kendi kaydı (kuyruk kilidi alındıktan sonra); bitişte en çok 180 sn içinde eşiğin altına inmeli (koşunun kendi yükünün sönümü: 14 × e^−3 ≈ 0,7). Geçersiz deneme `<tekrar>.gecersiz<k>` adıyla saklanır, en çok 2 kez yinelenir. Sonuç her koşu kökünde `gece_durum.json`.
- Sürdürme: `BITTI` olan koşu atlanır (`kesildi` hariç); yarım dizin `<tekrar>.yarim<k>` olarak saklanıp yeniden koşulur; pid'i canlı yarım koşuya dokunulmaz; ikinci bir `gece_kosusu` aynı kökte başlamaz (`gece.pid`). Kesilirse (SIGTERM / Ctrl-C) koşan gruba SIGTERM gider; koşucu karadul'u kapatıp `BITTI` = `kesildi` yazar.
- HZ-0 kabulü: bir hedefin geçerli tekrarlarında uçtan uca yayılım > 0,10 ise o hedefe en çok 2 ek tekrar (`--yayilim-ek-yok` kapatır).
- Disk: koşu öncesi boş alan < 40 GB ise kuyruk durur (silme yok).
- `scripts/arge/hiz/hz0_ek.py` (HZ-0 adım 2): koşunun karadul sürecini 30 sn'de bir `ps -M` ile izler (iş parçacığı işlemci süreleri; ayrıştırma `is_parcacigi._sn`), başta ve sonda `acma_gecikmesi.py --n 1000` (başvuru: `urun-onarim-a62f15e/mac/tmux` `decompiled/`; sonda ayrıca koşunun kendi `decompiled/`'ı) ve donanım künyesi (`hiz/PLAN.md` §1 alanları: çip, perflevel'ler, bellek, `sw_vers`, JPype / pyghidra / JDK / Ghidra sürümü, `systemextensionsctl list`, yük). Çıktı `<koşu kökü>/hz0_ek.json`.
- `scripts/arge/hiz/zaman_cizelgesi.py` eki: `BASLADI` yoksa başlangıcı `kunye.json`'dan alır (`basladi_kaynagi`).

### Kuyruk ve TAHMİNİ süreler

**Hepsi TAHMİN; hiçbiri boş makinede ölçülmedi.** Kaynaklar: S8 tabanı `b6aceb9` (ana oturum, 2026-11-20 08:04–08:22, yük ~5–11; `s8_taban_b6aceb9/*/reports/pipeline_result.json`), 119'luk birleşik koşu `a62f15e` (`olcek_a62f15e.json`; 3 paralel + 5–7 ajan), gösteri (`OLC0.md`), `olcek/BULGULAR.md` §3.5–§3.6. B'nin alt ucu: gösteri 7 729 sn × 0,41; 0,41 = S8 tabanı ↔ 119 koşusu süre oranlarının en küçüğü (8 ikilide 0,41–0,90: cat 0,41, sort 0,44, tree 0,55, mac/tmux 0,54, sqlite3 0,63, tmux 0,68, htop 0,78, zstd 0,90). Koşu arası pay [60; 180] sn: yük sönümü (14 → 3,5 için ≥ 60 × ln 4 = 83 sn; üst = bitiş bekleme sınırı).

| Grup | Koşular (sıra) | Duvar | Koşu başına TAHMİN | Kaynak |
|---|---|---|---|---|
| `hz0` | K1 O1 B1 K2 O2 B2 K3 O3 B3 (+ `hz0_ek`) | 10 800 sn | K [47; 108], O [219; 403], B [3 170; 7 730] sn | K: S8 47,3 ↔ 119 107,9; O: S8 219,5 ↔ 119 403,2; B: yukarıda |
| `p16c` | K + O tek JVM (`p16c_sure.py kos`) | 3 600 sn (dış) | [103; 231] sn | köprü: sort 17,0–41,6 + tmux 86,2–145,2 sn |
| `k_appcds` | K × 4 (`-XX:+AutoCreateSharedArchive`) | 10 800 sn | K gibi | — |
| `avast` | K1 O1 K2 O2 K3 O3 (+ `hz0_ek`) | 10 800 sn | K / O gibi | — |
| `b_jfr` | B × 1 (JFR `settings=profile`, + `hz0_ek`) | 10 800 sn | B gibi (JFR ek yükü ölçülmedi) | — |
| `olc1` | T100, T300, PAKET | 7 200 sn | [7 200; 7 290] sn (üçü de duvara dayanır) | köprü TAHMİN A T100 [14,5; 39,4] sa, T300 [77,9; 447,5] sa; PAKET S0 [177; 345] sa |
| `paket_e` (isteğe bağlı) | PAKET-E | 7 200 sn | [?; 7 290] sn | alt bilinmiyor |

Toplam (`gece_kosusu.py --kuru`, koşu arası pay dahil):

| Kapsam | TAHMİN | Tek geceye (≈ 10 sa) |
|---|---|---|
| Hepsi (PAKET-E'siz) | [10,4; 16,9] sa | **sığmaz** |
| Gece 1 = `hz0` + `p16c` + `k_appcds` + `avast` | [3,5; 8,5] sa | sığar |
| Gece 2 = `b_jfr` + `olc1` | [6,9; 8,4] sa | sığar |
| Gece 2 + PAKET-E | [7,0; 10,5] sa | üst uçta sığmaz |
| Ek tekrar en kötü durumu (Gece 1) | + en çok 4,9 sa (yalnız B: + 4,4 sa) | Gece 1 üst ucu aşılır; kuyruk sürdürülebilir, kalan ertesi gece |

### Bölme önerisi

İki geceye bölünür; **önce Gece 1 (HZ-0)**:
1. HIZ hattının ilk kod paketi HZ-7a (Dalga 1) ve HZ-1'in süre oranı kabulü "önce" sayısını HZ-0'dan alır; ÖLÇEK'in kod paketleri (ÖL-1, ÖL-2) Dalga 1–2'de, ÖLÇ-1 sayısına daha geç ihtiyaç duyar.
2. Avast kolu dışlamasız kolla (HZ-0 K, O) aynı gece, aynı koşullarda koşulmalı; Berke'nin tek işi bu geceye bağlı.
3. Gece 2'nin süresi duvarlarla belirli (≈ 6,1 sa + B_jfr); kayma riski düşük. PAKET-E istenirse Gece 2'ye eklenir ama üst uçta 10 sa'i aşar; ayrı bir geceye bırakılması önerilir.

Ürün commit'i: Dalga 0 main'e alındıktan sonraki main ucu önerilir (BAYRAK ön paketi yalnız okunmayan alan ekler, HZ-1 yalnız süre kaydı ekler: ürün davranışı aynı; HZ-1 girmişse adım süreleri `ghidra_status.json`'dan, çözümleyici süreleri `analysis`'ten gelir). İki gece aynı commit'le koşulmalı.

### Çalıştırma (ana oturum; makine boşken, ajan yokken)

```
cd /Users/apple/Black_Widow
PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/gece_kosusu.py --commit <hash> --gece 1 --kuru
PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/gece_kosusu.py --commit <hash> --avast-hazirla   # Avast için dizini oluşturur, yolunu basar
PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/gece_kosusu.py --commit <hash> --gece 1 --avast-dislama-yapildi
# ertesi gece
PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/gece_kosusu.py --commit <hash> --gece 2 [--paket-e]
```

Yarıda kalırsa aynı komut yeniden verilir (biten koşular atlanır). Sonuç `~/karadul_olcum/runs/gece-<kısa>/ozet.json`; Avast kolu `~/karadul_olcum/runs/hiz-avast-dislama/<kısa>/`. Çözümleme: `HZ0.md` (`hiz/on_kayit_hz0.md` hüküm biçimi), `OLC1.md` (`olcek/on_kayit_olc1.md`).

### Berke'nin tek işi: Avast dışlaması

Gece 1'i başlatmadan hemen önce Avast'ın ayarlarındaki istisnalar (hariç tutulanlar) listesine yalnız şu klasörü ekle: `/Users/apple/karadul_olcum/runs/hiz-avast-dislama/<kısa-commit>/` (ana oturum klasörü `--avast-hazirla` ile oluşturup tam yolunu sana verir). Bütün `karadul_olcum`'u ya da masaüstünü dışlama: deneme yalnız bu klasörde, iki açık kaynak programın (Debian `sort` ve `tmux`) analiziyle koşar. Gece 1 bitip `ozet.json` yazılınca (sabah) istisnayı sil. Dışlama yapmak istemezsen hiçbir şey yapma: o kol atlanır ve "Berke onayı yok" diye kayda geçer, öbür ölçümler etkilenmez.

### Riskler (gece öncesi bilinmesi gereken)

- **JFR ile AppCDS aynı koşuda olmaz:** JVM, arşiv dökülürken JFR'ı kapatıyor (`java -version` denemesi: "JFR will be disabled during CDS dumping"). Bu yüzden `b_jfr` ve `k_appcds` ayrı gruplar; duman yalnız JFR'ı sınadı.
- **T100 / T300 / PAKET öntanım ayarla koşar:** "Objective-C Message Analyzer" açık. Gösteri 1. denemede bu çözümleyici tek fonksiyonda 22+ dk takıldı; C++ ağırlıklı T100 / T300'te ObjC kodu beklenmez, FreeCAD'de olabilir. 2 saatlik duvar her durumda bağlar; nerede kaldığı künyede.
- **T300 belleği:** JVM yığını 14,7 GB + Python; 36 GB'lık makinede takas olasılığı (TAHMİN; ölçülmedi). Örnekleyici tepe RSS'i yazar.
- **Disk:** T100 decompile adımında `.c` yazıyor olacak; T300'ün Ghidra projesi bilinmiyor. Koşu öncesi < 40 GB boşta kuyruk durur; büyük veri `~/karadul_olcum/runs/gece-<kısa>/` altında kalır (silme Berke onayına bağlı).
- **Avast dışlamasının gerçekten etkin olduğu** araçla doğrulanamıyor (güvenlik ayarı okunmaz); hüküm biçimindeki denetim dizini (dışlanmayan başvuru dizini) farkın dışlamaya özgü olup olmadığını gösterir.
- `p16c_sure.py` girdileri öntanım tabanlardan (`~/karadul_olcum/n1_debian13`, `workspaces/olcum_mac/runs/ol7-c-b7faeac`; ikisi de var).
- Element.app'in lisansı koşudan önce paket içindeki lisans dosyasından doğrulanmalı (`olcek/PLAN.md` ÖLÇ-1 tablosu).
