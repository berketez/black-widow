# P-ÜV1 — Go `pclntab` okuyucu ve üretici adım: ilerleme (2026-11-20)

Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/PUV1.md`. Plan: `ustveri/PLAN.md` "P-ÜV1".
Dal: `worktree-agent-ae969d253c02cdadb`, taban `3eb32df` (main). Sert son 15:15.
Geçici dosyalar: `~/karadul_olcum/runs/dalga0-2026-11-20/PUV1/`.

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| Ön kayıt (`on_kayit_PUV1.md`) | yazıldı | 42fdd11 |
| 1–4, 6 okuyucu + yapı denetimleri + karar + satır içi sayaç | yazıldı, sentetik 36 test yeşil | (bu commit) |
| 5 üretici adım | bekliyor | — |
| Mutasyon (≥ 10) | bekliyor | — |
| Yama `PUV1__config.py.patch` | bekliyor | — |
| Rebase (PUV0 gelince) + 11 dilim kabulü + docker-cli GT | PUV0 mesajı bekleniyor | — |
| Okuyucu dondurma + docker-compose SINAMA GT | bekliyor | — |
| 7 süre ve bellek | bekliyor | — |
| Tam takım | bekliyor | — |

## Kalem 1–4, 6: okuyucu (`karadul/analyzers/ustveri/go_pclntab.py`)

- Arayüz: P-ÜV0 `Goruntu` (b049837, PUV0 dalında; salt okundu). Kullanılan yöntemler: `bolumler`
  (`Bolum.ad` kısa ad, `adres`, `boyut`, `kod`), `kod_bolumleri`, `oku`, `gosterici` (`int` dışı —
  `Bag` / `None` — gösterici yok sayılır), `fonksiyon_baslangiclari()`, `mimari`, `gosterici_boyutu`.
  Gerçek `goruntu.py` bu dalda yok; okuyucu onu içe aktarmaz (ördek tipleme), test dosyası
  `BellekGoruntu`'yu dener, yoksa aynı imzalı geçici sahte sınıfa düşer (rebase'de kaldırılacak).
- `pclntab` bulma: bölüm adı (`__gopclntab`, `.gopclntab`, `.data.rel.ro.gopclntab`), yoksa kod
  dışı bölümlerde imza taraması + başlık akıl sağlığı (dolgu 0, minLC ∈ {1,2,4}, ptrSize 8,
  0 < nfunc < 10⁷, ofset sırası).
- `moduledata` bulma: göstericiler düzeltme kodlu olabildiği için aday ham tamsayıyla bulunur:
  17.–18. sözcük = ftab uzunluk / sığa = `nfunc + 1`; 2.–3. sözcük = funcnametab uzunluğu
  (`cuOffset − funcnameOffset`). Aday iki göstericisi çözülerek (`gosterici`) doğrulanır. Bu iki
  bağıntı araştırma kopyasında (`gh`, Ollama x86_64; `scripts/arge/ustveri/macho.py` ile, salt okuma)
  sözcük sözcük denetlendi: ftab 40 385 = nfunc + 1, funcnametab uzunluğu = ofset farkı (2 / 2).
  Bulunamazsa `desteklenmiyor` (tahmin yok).
- Başlıktaki eski `textStart` `gosterici()` ile okunur (1.18–1.25'te düzeltme yeri; ham sözcük
  Mach-O zincirli düzeltmede adres değildir). Metin tabanı önceliği: `moduledata.text`, yoksa
  `pcHeader.textStart`; ikisi farklıysa not.
- pc-değer tablosu `runtime.step` anlamıyla: "ilk" = `pc == giriş` (başvuru betiği yalnız ilk
  yinelemeyi ilk sayıyordu; geçerli tablolarda fark yok).
- Ek denetim **K0** (ftab girişi = `_func.entryOff`): ihlal ad eşlemesini belirsiz kılar, karar
  kuralına eklendi (plandaki K1, K2, K5, K9, K4 > %1'e ek). Okunamayan `_func` / ad / dosya
  (sınır dışı) → `tutarsiz` (istisna yok).
- Satır içi ad sayacı: `nameOff 0` "ad yok" demektir, bağ sayılmaz (başvuru betiği 0'ı bağ
  sayıyordu: sayım en çok 1 farklı olabilir).
- Paket adı kuralı `runtime.funcpkgpath` (son yol öğesindeki nokta bağlayıcıda `%2e` yazılır).
- Testler: `tests/test_puv1_go_pclntab.py` 36 test (1.20+ / 1.18 başlık, imza taraması, buildinfo,
  sınıflar, pc tablosu zikzak + minLC, K0/K1/K2/K4/K5/K7/K9, komşu pcsp takası → K4 ihlali 2,
  Go değil → `veri_yok`, eski imza / moduledata yok / `Bag` / 32 bit → `desteklenmiyor`, kesik
  tablo → istisnasız).
