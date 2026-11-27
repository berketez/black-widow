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
| 2 | Okuyucu düzeltmeleri (hüküm 4) + H3 | bitti; H3 `ozgun_ad` farkı 0 TUTTU, `paket` sayısı TUTMADI (neden aşağıda) | (bu commit) |
| 3 | Damga bağlama + testler + mutasyon → dondurma | — | — |
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
