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
| 3 | Damga bağlama + testler + mutasyon → dondurma | bitti: 40 test, puv6c 19 / 19 mutant öldü; hüküm 5 + 6'nın kodu da bu commit'te (aynı dosya) | `d6cc3fbd`, dondurma (bu commit) |
| 4 | Ghidra'sız yeniden oynatmalar (H1, H2, H4) | — | — |
| 5 | Hüküm 5 + 6 | — | — |
| 6 | Ürün koşusu (isteğe bağlı) | — | — |
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
