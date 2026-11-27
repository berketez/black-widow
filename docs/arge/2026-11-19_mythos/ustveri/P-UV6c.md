# P-ÜV6c — Go tutarlılık damgası, okuyucu düzeltmeleri, yanıltıcı "kısmi" (ilerleme)

Gönderim metni: `docs/arge/2026-11-23_dalga1/gonderim/PUV6c.md`; bugünün koşulları `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`
§7. Ajan: Opus 5.5. Başlangıç 2026-11-27 22:22 (dal `worktree-agent-a72d36643fec4ac64`, `git merge --ff-only main` →
`c59d3c0e`). Sert son 2026-11-28 00:45.

`karadul.__file__` worktree'yi gösteriyor (`…/agent-a72d36643fec4ac64/karadul/__init__.py`).

Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/PUV6c/` (özetler `ozet/`, betikler `betik/`).

## Durum

| Sıra | Kalem | Durum | Commit |
|---|---|---|---|
| 1 | Ön kayıt | yazıldı | `a10bb811` |
| 2 | Okuyucu düzeltmeleri (hüküm 4) + H3 | bitti; H3 `ozgun_ad` farkı 0 TUTTU, `paket` sayısı TUTMADI (neden aşağıda) | `ad4ebe3f` |
| 3 | Damga bağlama + testler + mutasyon → dondurma | bitti: 41 test, puv6c 20 / 20 mutant öldü; hüküm 5 + 6'nın kodu da `d6cc3fbd`'de (aynı dosya) | `d6cc3fbd`, **DONDURMA `72b3a637`**, rapor sayısı düzeltmesi `b3ce5bb1` |
| 4 | Ghidra'sız yeniden oynatmalar (H1, H2, H4) | bitti: H1 (Ollama yarısı), H2, H4, H5 (yeniden oynatma), H6 TUTTU; H1'in S8 yarısı ürün koşusunda | `68bcd268` |
| 5 | Hüküm 5 + 6 | bitti: kod `d6cc3fbd` (kalem 3'le aynı commit; aynı dosya), H5 yeniden oynatmada TUTTU, hüküm 6 test + mutant | `d6cc3fbd`, `68bcd268` |
| 6 | Ürün koşusu (isteğe bağlı) | koşuldu: terminal-notifier ObjC 32 / 32 duruyor | `0c1af921` |
| 7 | Tam takım | — | — |

## Kalem 2 — okuyucu düzeltmeleri (hüküm 4) ve H3

**Kod** (`karadul/analyzers/ustveri/go_pclntab.py`, `tutarlilik.py`):

- (4a) `GoSonuc.pcln`: okuyucu nesnesi (`GoPclntab`), yalnız `calisti` sonucunda dolu; `field(repr=False,
  compare=False)`, `kayit()` / `go_functions.json` yazmaz. `tutarlilik.denetle(..., *, sonuc=None)`: `sonuc` verilirse
  okuyucu, fonksiyonlar, buildinfo ve yapı denetimleri ondan alınır (okuyucu yeniden kurulmaz). Konumsal imza aynı
  (`ustveri_bozma.py` beş konumsal argümanla çağırıyor; değişmedi).
- (4b) `fonksiyon_paketi(ad)`: ürünün `paket` alanı. Alıcılı adda ilk `.(`'dan önceki önekte paket yolu, o önekte
  son `/`'tan sonraki ilk noktaya kadar (satır içi kapanış `crypto/x509.policiesValid.(*policyGraph)…` → `crypto/x509`;
  ilk denemede yalnız "ilk `.(`'dan önceki önek" kuralı bu adlarda `crypto/x509.policiesValid` yazıyordu — Ollama 3,
  docker-cli 11 yeni yanlış; gerçek veride görüldü ve düzeltildi, ilk deneme ürün koduna girmedi). Derleyici
  sarmalayıcısında alıcı tip adsızsa (`go:(*struct { … })`, `go:struct { … }`, `go:interface { … }`) paket `go:`.
  Alıcısız adlar (`type:.eq.…` dahil) eski kuralla aynı. **`paket_adi` (eski kural) bilerek değişmedi:** P-ÜV7'nin
  araştırma tanımlı T2p / T3 / T4 sayaçları ve `ustveri_bozma.py`'nin örneklemi o kurala bağlı (dondurulmuş sayılar;
  `ustveri_bozma.py` bu paketin dosyası değil). `go_pclntab.DERLEYICI_ONEKLERI` eklendi (`paket_sinifi` artık onu
  kullanıyor); `tutarlilik.py`'de aynı değerli kopyası duruyor (hüküm 4'ün izin verdiği değişiklik 4a / 4c ile sınırlı;
  sonraki pakette içe aktarılabilir).
- (4c) `FUNC_ID`, `FUNC_ID_ADI`, `FUNC_ID_SARMALAYICI` tek tanım `go_pclntab.py`'de; `tutarlilik.py` içe aktarır
  (adlar modülde aynı kaldı: `T.FUNC_ID is G.FUNC_ID`).

**H3 ölçümü** (ürünün okuma yolu `go_metadata_recovery._goruntu_ac` + `go_pclntab.oku`; önce = `a10bb811`'in kodu,
sonra = bu commit; betik `PUV6c/betik/h3_dok.py`, `h3_kiyas.py`; sayılar `PUV6c/ozet/h3_paket.json`,
`h3_kirilim.txt`; ad dökümleri geçici, koşu kökünde, silinecek):

| İkili | Kayıt | `ozgun_ad` kümesi farkı | `paket` değişen | eski kuralda `(` / `)` taşıyan → sonra | `sinif` değişen |
|---|---|---|---|---|---|
| Ollama arm64 (`ANA/ollama_kabul/ws/…/raw/Ollama_arm64`) | 10 601 | **0** | **8** | 4 → 0 | 0 |
| docker-cli (`ustveri_set/docker-cli/bin`) | 35 049 | **0** | **506** | 264 → 0 | 0 |

Değişenlerin kırılımı (adın biçimine göre):

| İkili | adsız gösterici alıcı `go:(*struct { … })` | adsız değer alıcı `go:struct { … }` / `go:interface { … }` | yükseltilmiş dışa kapalı yöntem |
|---|---|---|---|
| Ollama | 4 | 4 | 0 |
| docker-cli | 242 | 243 | 21 |

- **H3 → `ozgun_ad` yarısı TUTTU (fark 0 / 0); `paket` sayısı TUTMADI** (beklenen 4 / 264, ölçülen 8 / 506). Neden:
  PUV7'nin sayımı "`paket` alanında `(` / `)` geçen fonksiyon" idi; bu sayım (4 / 264) yeni kodda birebir 0'a indi.
  Ama (1) PUV7'nin "yükseltilmiş dışa kapalı yöntem" diye adlandırdığı 264'ün yalnız 21'i öyle; 243'ü derleyicinin
  adsız tip sarmalayıcısı (`go:(*struct { … }).M`, `go:interface { … }.M-fm`); Ollama'nın 4'ünün 4'ü sarmalayıcı.
  (2) Aynı sarmalayıcıların değer alıcılı ikizleri (`go:struct { io.Reader; io.WriterTo }.Read`) paketi
  `go:struct { io` yazıyordu (parantez yok, PUV7'nin sayımına girmemiş): Ollama 4, docker-cli 242 (kırılım
  tablosundaki 243'ün 1'i parantezli `go:interface { F(context.Context) … }`, 264'ün içinde). Hüküm 4b'nin kuralı ("alıcılı adlarda tip adından önceki önek") ikisini birlikte kapsıyor;
  yalnız parantezlileri düzeltmek aynı kusurun yarısını bırakırdı.
- Sınıf (`sinif`) hiçbir fonksiyonda değişmedi (sarmalayıcılar `go:` önekiyle zaten `derleyici`; 21 yükseltilmiş
  yöntemin eski ve yeni paketi aynı modülün altında).
- **Kalan (bu paketin dışında):** alıcısız derleyici adlarında (`type:.eq.struct { … }`) `paket` hâlâ tip metninin
  bir parçası (Ollama 7, docker-cli 53; sınıf `derleyici`). Hüküm 4b alıcılı adları kapsıyor; dokunulmadı.
- Okuma süresi (yük altında, `uptime` 22:31 yük 14,2 / 8,2 / 6,9): Ollama 0,29 → 0,43–0,55 sn, docker-cli 0,60 →
  0,54–0,73 sn (aynı makine yükünde tekrar dalgalanması; ayrı süre hükmü yok).

## Kalem 3 — damga bağlama, testler, mutasyon

**Tasarım (koddan):**

- **Üretici** (`go_metadata_recovery.py`): `go_integrity_enabled(cfg)` (yalnız gerçek `True`). Açıkken ve okuyucu
  `calisti` verdiyse `tutarlilik.denetle(g, sonuc=sonuc)` (okuyucu yeniden kurulmaz); `damgala` her fonksiyon kaydına
  `dogrulama` (= `ts.damga(giris)`) ve `tutarsiz`'da `dogrulama_isaretleri` (güçlü T + K4 / K10) yazar;
  `tutarlilik_ozeti` durum sözlüğüne `tutarlilik` (durum, karar, karar nedeni, fonksiyon / adlı sayısı, güçlü
  işaretli, çift kaynaklı, K4 / K10, damga dağılımı, güçlü denetim dağılımı — T3 / T4 hariç) yazar; aynı özet
  `reconstruct.stats["go_metadata_integrity"]`'de. Bayrak kapalıyken hiçbir alan eklenmez (test: kayıtlar
  `f.kayit()` ile birebir; durum `{"durum", "neden"}`).
- **Ad kanalı** (`_add_go_pclntab`): sıra pcsp (P-ÜV6a, değişmedi) → ikili kararı `ust_veri_supheli` ise kayıt kanıt
  satırı (`ust_veri_supheli`, `ikili_karari_nedeni`) → damga `tutarsiz` ise kanıt satırı (`tutarsiz`, `isaretler`) →
  aday. Damga künyeye (`ust_veri_dogrulama`) ve köken kaydına geçer. Sayaçlar: `dogrulama` (damga dağılımı),
  `ikili_karari`, `tutarsiz_elendi`, `ust_veri_supheli_elendi`. Sabitler `tutarlilik.DAMGA_TUTARSIZ` /
  `KARAR_UST_VERI_SUPHELI`'den (tek tanım).
- **Köken kaydı** (`_feedback_naming_merger.metadata_decision`): `ust_veri_dogrulama = künyedeki damga ya da olculmedi`;
  `label` her zaman `üst veriden` (hüküm 3; `cift_kaynak` `kesin` yapmaz), güven tablodan (değişmedi).
- **Rapor** (tek dosya: `karadul/reporting/report_data.py`, `_naming` bölümü "Name Reliability"): karar `uyari` ya da
  `ust_veri_supheli` ise `extra["go_metadata_warning"]` (karar, güçlü işaretli / fonksiyon, güçlü denetim dağılımı,
  `tutarsiz` damgalı adlı fonksiyon, kanıt satırına inen ad sayısı, neden, metin) ve özet satırına
  `; WARNING: Go metadata integrity check verdict '…'; N of M Go functions carry a strong inconsistency signal
  [T1: …, T2: …]; …`. Var olan uyarı düzeni (`_sigdb_note`: özet satırında `WARNING:` + `extra` alanı) izlendi;
  `report.json` bölüm özetine ve okunur rapora (`markdown` / `html` özet satırı) aynı cümle girer. Bölüm durumu
  değişmez (temiz / bulgu sayımı etiket dağılımından).
- **Hüküm 5** (`stages._note_universal_special_slices` + `go_metadata_recovery._eski_evrensel_iletiyi_indir`): statik
  aşama hata dizgisini `go_hatti_error` istatistiğinde de tutar; üretici aynı koşuda `calisti` verince o dizgiyi
  (birebir) statik aşamanın hata listesinden çıkarır, `go_hatti_status = bilgi`, `go_hatti_bilgi` = "eski
  çözümleyici evrensel dosyayı açmıyor; ad ve fonksiyon bilgisi yeni okuyucudan (go_metadata_recovery, ürün
  dilimi)", `go_hatti_eski_ileti` = eski dizgi; kendi istatistiğine `go_universal_note = bilgi`. Okuyucu kapalı /
  `veri_yok` / `hata` → hata aynen kalır. Bun dilimine dokunulmaz. Statik aşama Faz 1'den önce bittiği için
  `--verbose` canlı akışta ileti statik aşamanın bitişinde yine basılır (`core/pipeline.py`, GS1'in dosyası); son
  durum (çıkış kodu, `partial` nedenleri, rapor) indirmeden sonra hesaplanır.
- **Hüküm 6:** P-ÜV6a'nın düzeni (`exclude_keys = metadata_keys`; `go_demangler` sayacı `ust_veri_onde`) yeterli;
  bu pakette test + mutant (`puv6c_iki_go_kanali_ayni_adrese`). Not: `tutarsiz` / şüpheli kayıt aday vermediği için
  anahtarı `metadata_keys`'te değildir; sembollü ikilide nm o adrese aday verebilir (sembol tablosu ayrı kaynak; o
  durumda "ikinci aday" değil ilk aday). Soyulmuş Go ikilisinde (hedef seti) nm kanalı `veri_yok`.

**Testler** `tests/test_puv6c_go_damga.py`: 26 test işlevi (parametrelerle 40 koşu) — okuyucu (14 ad biçimi, eski kural,
`oku` paket alanı, `pcln` alanı, `denetle(sonuc=)` okuyucuyu kurmaz, `FUNC_ID` tek tanım), üretici (kapalı kol bayt aynı,
bayrak yalnız `True`, öntanım kapalı, açık kolda damga + özet), ad kanalı (tutarsız kanıt satırı, şüpheli ikili,
uyarıda adlar yazılır / damgasız kayıt aynı, iki Go kanalı), köken kaydı (×3 damga; etiket `kesin` değil), rapor
(uyarı sayıları, şüpheli, ×3 uyarısız), hüküm 5 (iniyor + tek iletide durum `tam`; kapalı / `veri_yok`'ta kalıyor;
Bun'a dokunulmuyor).

**Mutasyon** `scripts/measurement/mutation_specs_puv6c.json`: **19 / 19 öldü** (gönderimdeki sekiz zorunlu tür +
11 ek: damga köken kaydına taşınmaz, bayrak okunmaz, damga yazılmaz, özete zayıf işaret, uyarı sayısı yanlış nicelik,
statik hata dizgisi tutulmaz, satır içi kapanış, adsız sarmalayıcı, okuyucu nesnesi kullanılmaz / taşınmaz).
Günlük `PUV6c/ozet/mutasyon_puv6c.log`; koşudan sonra `git status` temiz.

## DONDURMA (ölçümden önce; bu commit)

Bu commit'ten sonra H1 / H2 / H4 / H5 ölçümlerine dek aşağıdaki dosyaların kural yolları değişmez; ölçümler birer kez,
bu kodla alınır. (Sınama ikilisi yok: hükümler keşif / hedef ikililerinde; docker-compose, iTerm2, llama-server
açılmadı.)

| Dosya | sha256 (ilk 16) |
|---|---|
| `karadul/analyzers/ustveri/go_pclntab.py` | `1fe9b08ca0a19865` |
| `karadul/analyzers/ustveri/tutarlilik.py` | `a8118a39a0aaafeb` |
| `karadul/pipeline/steps/go_metadata_recovery.py` | `df6764344234644d` |
| `karadul/pipeline/steps/_feedback_naming_candidates.py` | `64dd303f4d650713` |
| `karadul/pipeline/steps/_feedback_naming_merger.py` | `9bc69ef638d2e4f1` |
| `karadul/reporting/report_data.py` | `3b407b0475cf742b` |
| `karadul/stages.py` | `327e09c7a26d9d80` |
| `karadul/core/naming_labels.py` | `c05bd8826276b6a9` |

### Dondurmadan sonra tek değişiklik: rapor uyarısının sayısı (kural değil; bu commit)

H4'ün ilk koşusunda (22:49) uyarı metni "67 named function(s) stamped 'tutarsiz'; … withheld as evidence rows (66)"
yazdı: 67'nin 1'i K4 `kisa` (P-ÜV1) fonksiyonu, damgadan önce pcsp denetimiyle (P-ÜV6a) kanıt satırına iniyor; metin
onu saymıyordu (eksik sayı = analisti yanıltır). Düzeltme yalnız `report_data.go_metadata_warning`'de: `withheld_pcsp`
alanı ve metne "N; M more withheld earlier by the pcsp coverage check (K4)". Ad kararı, damga, kanal, köken kaydı
değişmedi (H4'ün ad sayıları ilk koşuyla aynı: 66 yazılmadı / 134 yazıldı). Test +1
(`test_rapor_pcsp_ile_inen_damgali_ad_ayri_sayilir`), mutant +1 (`puv6c_uyari_pcsp_sayilmaz`): **20 / 20 öldü**.
`report_data.py` sha256 (ilk 16) `3b407b0475cf742b` → `39a3eb025541222f`; öbür yedi dosya dondurmadaki gibi. H2 / H4
yeniden oynatmaları bu değişiklikten sonra yeniden koşuldu (aşağıdaki sayılar ikinci koşunun; ilk koşuyla ad
sayıları aynı).

## Kalem 4 — Ghidra'sız yeniden oynatmalar (dondurma `72b3a637` + rapor sayısı `b3ce5bb1`; 22:49–22:50, yük altında `uptime` 7,7 / 8,3 / 9,2)

### Ollama (H1'in Ollama yarısı, H2, H5, H6)

Girdi (salt okundu): `ANA/ollama_kabul/ws/workspaces/Ollama/20261124_101017` — `raw/Ollama_arm64` (sha256 ilk 12
`7d5b1e847e1b`, PUV7'nin Ollama.arm64 kopyasıyla aynı), `static/ghidra_functions.json` (Ghidra görüntü tabanı
`ustveri_urun.goruntu_tabani`), `raw/target_info.json` (`universal_binary`, `go_slice: true`), `reports/pipeline_result.json`
(statik aşamanın gerçek hata listesi). Betik `PUV6c/betik/oynat_puv6c.py`; sonuç `PUV6c/ozet/oynat_ollama.json`. Akış
ürün kodu: `stages._note_universal_special_slices` (statik aşama, koşunun öbür hatası korunarak) →
`GoMetadataRecoveryStep.run` (gerçek dilim) → `add_k4_channels` (yalnız Go kanalı) → `validate_merged_names` →
`metadata_decision` → `report_data._naming`.

| Kol | Üretici kaydı | Kanal adayı | Aday damgası | Kanıt satırı | Süzgeçten geçen (yazılan) | Yazılanın damgası | Etiket | `kesin` | Rapor uyarısı | Statik "evrensel ikilide go dilimi" iletisi | Statik aşama |
|---|---|---|---|---|---|---|---|---|---|---|---|
| bütünlük kapalı (H1) | 10 601 | **10 475** | **`olculmedi` 10 475** | 0 | 10 475 | `olculmedi` 10 475 | `üst veriden` 10 475 | 0 | 0 | **1 → 0** | kısmi (bekçi hatası kalır) |
| bütünlük açık (H2) | 10 601 | 10 475 | **`cift_kaynak` 3 907, `tek_kaynak` 6 568, `tutarsiz` 0** | 0 | **10 475** | `cift_kaynak` 3 907, `tek_kaynak` 6 568 | `üst veriden` 10 475 | 0 | **0** | 1 → 0 | kısmi (aynı) |
| okuyucu kapalı (H5 karşı kol) | 0 (`kapali`) | 0 | — | 0 | 0 | — | — | 0 | 0 | **1 → 1** | kısmi (iki hata) |

- İkili kararı (açık kol): **`temiz`**, güçlü işaretli 0, çift kaynaklı 3 907, K4 / K10 uyumsuz 0 / 0; üretici düzeyinde
  10 601 kaydın 3 907'si çift, 6 694'ü tek (1 adsız giriş; adlı 10 600'ün 6 693'ü tek — PUV7'nin sayısıyla aynı).
- **H1 (Ollama yarısı) → TUTTU:** Go ad adayı 10 475, hepsinde `olculmedi`.
- **H2 → TUTTU:** `cift_kaynak` 3 907 (= beklenen), `tek_kaynak` 6 568 (beklenen 6 568 ± 130; tam), `tutarsiz` 0; yazılan
  10 475; karar `temiz`; rapora uyarı 0.
- **H5 → TUTTU (yeniden oynatmada):** statik aşamanın hata listesinde evrensel ikili iletisi 1 → 0 (bilgi satırı:
  `go_hatti_status = bilgi`, `go_hatti_bilgi` = "eski çözümleyici evrensel dosyayı açmıyor; ad ve fonksiyon bilgisi
  yeni okuyucudan (go_metadata_recovery, ürün dilimi)"); okuyucu kapalı kolda 1 kalır. Statik aşama bu koşuda yine
  `kismi`: öbür hata (ÖL-1 bekçisinin "Objective-C Message Analyzer"ı kapatması) gerçek ve kalıyor — ana oturumun
  24 Kasım notundaki "çıkış 3'ün iki nedeni"nden yalnız yanıltıcı olanı kalktı. Statik aşamanın kendisi Ghidra'sız
  koşulamadığı için ileti `_note_universal_special_slices` ile gerçek `target_info.json`'dan üretildi; uçtan uca ürün
  koşusunda (Ollama) **ölçülmedi** (ana oturumun işi).
- **H6 → TUTTU (bu akışlarda):** üst veri kaynaklı ad 10 475 / 10 475 `üst veriden`, `kesin` 0 (iki kolda da).
- Ek gözlem (bu paketin değil): ad geçerliliği süzgeci (`validate_merged_names`) 10 475 adın 587'sine ek veriyor
  (adı değiştiriyor). Nedeni bu pakette incelenmedi (TAHMİN: aynı C tanımlayıcısına inen ya da var olan bir adla
  çakışan Go adları). Köken kaydında karar birleştiricinin adıyla yazıldığı için damga sayısı etkilenmiyor.
- Süre (yük altında): adım 0,29–0,30 sn (okuma + damga), damga (`denetle`) 0,12 sn.

### H4 — bozuk `gh` (A türü), Ghidra'sız kanal sınaması

Girdi: P-ÜV7'nin araştırma kopyası `arge-2026-11-19/ustveri/hedef/gh` (sha256 ilk 12 `ca6c859f0ff8`, PUV7 tablosuyla
aynı). Bozma bellekte, `ustveri_bozma.deney`'in A kolunun satırlarıyla birebir (tohum 20261119, 200 fonksiyon, aynı aday
süzgeci); bozuk görüntü `GoMetadataRecoveryStep.run`'a, kayıtlar `add_k4_channels`'a ("her fonksiyon adsız" sahte Ghidra
dizini). Betik `PUV6c/betik/h4_bozuk_gh.py`; sonuç `PUV6c/ozet/h4_gh_A.json`.

| Kol | Bozulan | ikinci kaynaklı / kaynaksız | ikinci kaynaklıda yazılmayan | ikinci kaynaksızda yazılan | İkili kararı | Güçlü işaret | Rapor uyarısı | `kesin` |
|---|---|---|---|---|---|---|---|---|
| bütünlük kapalı | 200 | 66 / 134 | 0 (66 bozuk ad yazıldı) | 134 | — | — | 0 | 0 |
| **bütünlük açık** | 200 | 66 / 134 | **66** (kanıt satırı, neden `tutarsiz`) | **134** | **`uyari`** | T1 29, T2 66 (66 / 40 384 fonksiyon) | **1** | 0 |

- **H4 → TUTTU:** ikinci kaynaklı 66 bozuk fonksiyonun 66'sı `tutarsiz` damgası aldı ve adı yazılmadı; ikinci
  kaynaksız 134'ün bozuk adı yazıldı (beklenen sınır: denetimin ikinci kaynağı yok, ad `tek_kaynak`); karar `uyari`;
  rapora uyarı 1. Bozulmayan fonksiyonlarda yeni kanıt satırı 0 (tek kanıt satırı P-ÜV1'in K4 `kisa` fonksiyonu, iki
  kolda da `pcsp_kisa`).
- Raporun metni (naming bölümü, `report.json` bölüm özeti ve okunur rapor): "WARNING: Go metadata integrity check
  verdict 'uyari'; 66 of 40384 Go functions carry a strong inconsistency signal [T1: 29, T2: 66]; reason: güçlü
  işaretli 66 / 40384 fonksiyon; 67 named function(s) stamped 'tutarsiz'; names stamped 'tutarsiz' withheld as
  evidence rows (66; 1 more withheld earlier by the pcsp coverage check (K4)); the other Go names are written,
  labelled 'üst veriden' (consistent forgery is not detectable)".
- `kesin` etiketli ad 0 (H6).

## Kalem 6 — ürün koşusu: terminal-notifier (isteğe bağlı; koşuldu)

Ağaç `~/karadul_olcum/urun-72b3a637` (dondurma; altı veri bağı), yaml `PUV6c/bayraklar_acik.yaml`: Ollama kabul
koşusunun dört üst veri bayrağı (Go / ObjC üretici + ad) + `enable_go_metadata_integrity: true`. Komut
`ustveri_urun.py kos --ad terminal-notifier` (soyulmuş kopya, sha256 ilk 12 `d352c10594f2`), Ghidra kuyruğunda
(`PUV6c urun:terminal-notifier`, ikinci yuva), 22:53:23–22:54:29, 66,2 sn, yük altında (`uptime` 7,4 → 9,8). Sayım
`ustveri_urun.py urun` → `PUV6c/ozet/urun_terminal-notifier.json`.

- Çıkış `tamam` (0). **ObjC adı 32 / 32 duruyor** (haritada 32, kodda 32, `üst veriden` 32, `ozgun_ad` dolu 32, güven
  tablodan 32, A-28 31, GT'ye göre doğru 32); ad bekleyen 40'ta doğru 1 / 40 (PUV6a / 6b ile aynı).
- Go kanalı `veri_yok` (ikilide `pclntab` yok); `go_metadata_integrity` istatistiği yok (denetim yalnız `calisti`'da
  koşar); rapora Go uyarısı 0. Yamasız ağaçta koşu günlüğünde "enable_go_metadata_integrity etkisiz … P-ÜV6
  bağlayacak" uyarısı basılıyor (değer okunuyor; yama uygulanınca kalkar).

## Eski mutasyon tanımları (22:52–22:57; kod `b3ce5bb1`)

Dokunulan sekiz ürün dosyasına (`go_pclntab.py`, `tutarlilik.py`, `go_metadata_recovery.py`,
`_feedback_naming_candidates.py`, `_feedback_naming_merger.py`, `report_data.py`, `stages.py`, `naming_labels.py`) bakan
bütün eski tanımlar (`grep`: 22 tanım dosyası, 222 mutant); her tanımdan **yalnız bu dosyalardaki mutantlar** (`--id`)
koşuldu. Önce bayatlık denetimi: `find` metninin `c59d3c0e`'deki ve bugünkü sayısı (tekil mi). Bayatlayan tek mutant
`mutation_specs_ps4.json` `ps4_k4_hata_satiri_yok` (`stages.py`; hüküm 5 hata satırını `error` değişkenine aldı): `find`
`result.errors.append(f"Desteklenmiyor: {reason}")` → `result.errors.append(error)` (yalnız `find`; `replace` aynı).
Betik `PUV6c/betik/eski_mutasyon.sh`, günlükler `PUV6c/ozet/mutasyon_eski/<ad>.log`; her tanımdan sonra `git diff --
karadul` temiz.

| Tanım | Sonuç | Tanım | Sonuç |
|---|---|---|---|
| puv6a | 18 / 18 | ps4 (`find` düzeltildi) | 21 / 21 |
| puv6b | 17 / 17 | rapor_sayaclari | 3 / 3 |
| puv1 | 19 / 19 | p12a | 2 / 2 |
| puv7 | 12 / 12 | bayrak | 3 / 3 |
| pk1 | 3 / 3 | pguv | 7 / 7 |
| p13b | 10 / 10 | p13a | 8 / 8 |
| puv5 | 15 / 15 | ps1 | 15 / 15 |
| adim3_hat | 28 / 28 | ps2 | 8 / 8 |
| ps3 | 7 / 7 | ps3b | 3 / 3 |
| ps3b_yama | 5 / 5 | p07 | 9 / 9 |
| p15c | 4 / 4 | adim3_bicimlendirici | 5 / 5 |

**Toplam 222 / 222 öldü**, hayatta 0, hata 0. Başka paketin dosyasına bakan mutantlara dokunulmadı ve koşulmadı.

## Bekleme (22:58)

Şu an: tam takım arka planda (worktree kökünden, yamasız; günlük `PUV6c/ozet/tam_takim.log`; TAHMİN bitiş 23:08–23:20,
yük altında) ve H1'in S8 koşusu (`PUV6c/s8_sonra`, 8 ikili, ana oturumun sırası; 6 / 8 bitti, TAHMİN bitiş 23:05).
Çalışma verisi bağları tam takım için geçici kuruldu (commit'lenmez; bitince kaldırılacak).

## Yama

`docs/arge/2026-11-23_dalga1/yamalar/PUV6c__config.py.patch`: `enable_go_metadata_integrity` alanının yorumu
(`ETKİSİZ: P-ÜV6 bağlayacak` → `okuyan: pipeline/steps/go_metadata_recovery.py (P-ÜV6c)`; üstteki açıklama satırı
"`tutarsiz` damgalı ad yazılmaz") ve `INERT_SETTINGS`'teki satır (+ "P-ÜV6 (Dalga 3)" başlığı) silinir. Öntanım
`False` kalır. `git apply --check` temiz; ağaca uygulanmadı (A-34). Yamasız dalda beklenen tek kırmızı:
`tests/test_p15a_etkisiz.py::test_inert_registry_is_accurate` — "kayıtta ama okunuyor:
{'binary_reconstruction.enable_go_metadata_integrity': ['karadul/pipeline/steps/go_metadata_recovery.py']}"
(P-ÜV6a / 6b'den farklı olarak bu alan `getattr(…, "enable_go_metadata_integrity", …)` dizgisiyle okunuyor; `_reads`
bunu okuma sayar). Yama uygulanınca kayıt kalkar ve test yeşile döner (yamalı kopyada koşulmadı: worktree dışı kopya
kurulmadı).

## PUV6d ve açılış ölçümü için notlar

- **Bayrağın öntanımda açılması (açılış ölçümü, A-14):** bütünlük denetimi ad yazmaz, yalnız ad SİLER (`tutarsiz`,
  şüpheli ikili). Bozulmamış 11 / 11 dilimde (PUV7) ve Ollama'da (bu paket) `tutarsiz` damgası yalnız P-ÜV1'in K4
  `kisa` fonksiyonunda (gh / limactl / arduino-cli'de 1'er; o kayıt pcsp denetimiyle zaten kanıt satırına iniyor) →
  doğru ada maliyet bugüne dek ölçülen her ikilide 0. Süre: Ollama'da 0,12 sn (yük altında). Bu yüzden bütünlük
  bayrağının Go ad kanalı bayrağıyla birlikte açılması önerilir (Go ad kanalı damgasız çalışırsa A-10'un tek
  koruyucusu devre dışı kalır). Karar ana oturumun.
- **Rapor alanı:** uyarı `report.json`'da `sections.naming.extra.go_metadata_warning` (+ `summary`'de "WARNING: …");
  `report.md` / `report.html` aynı özet cümlesini basıyor. Arayüzde ayrıca gösterilmiyor (`ui/` bu paketin dosyası
  değil).
- **Ad haritası:** `output_formatter._merger_metadata_records` köken kararını ad haritasına taşırken
  `ust_veri_dogrulama`'yı taşıyor mu, bu pakette bakılmadı (`output_formatter.py` dokunulmaz listesinde). Taşımıyorsa
  damga yalnız köken kaydında (`naming_provenance.json` → `name_merger.decisions`) görünür; PUV6d ya da arayüz paketi
  için not.
- **Tutarsız ad ile nm:** `tutarsiz` / şüpheli kaydın anahtarı `metadata_keys`'e girmediği için sembollü bir Go
  ikilisinde `go_demangler` (nm) o adrese aday verebilir (sembol tablosu ayrı kaynak). Soyulmuş hedeflerde nm kanalı
  `veri_yok`; sembollü ve oynanmış ikilide hangisinin yazılması gerektiği ölçülmedi.
- **`paket_adi` iki kural:** ürün `fonksiyon_paketi`'ni, araştırma sayaçları (P-ÜV7 T2p araştırma, T3, T4,
  `ustveri_bozma.py`) `paket_adi`'yi kullanıyor. T3 / T4 zayıf işaretler; kararı etkilemiyor. İleride T3 / T4'ün yeni
  kurala geçmesi dondurulmuş PUV7 sayılarını değiştirir: ayrı ön kayıtla.
- **Evrensel ikili iletisi canlı akışta:** `--verbose`'da statik aşama bitince ileti yine basılır (aşama sonucunun
  hata listesi o an dolu); son durum (çıkış kodu, `partial`, rapor) indirmeden sonra. Canlı akışı da düzeltmek
  `core/pipeline.py`'de (GS1'in dosyası) ayrı iş.
- **Ollama çıkış kodu:** bu düzeltmeyle evrensel ileti kalkıyor; ÖL-1 bekçisi koşuda çözümleyici kapatırsa statik aşama
  yine `kismi` (dürüst). Bekçi devreye girmezse Ollama koşusunun `tam` (çıkış 0) olması beklenir — uçtan uca
  ölçülmedi.
