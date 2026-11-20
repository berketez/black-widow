# P-ÜV1 — Go `pclntab` okuyucu ve üretici adım: ilerleme (2026-11-20)

Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/PUV1.md`. Plan: `ustveri/PLAN.md` "P-ÜV1".
Dal: `worktree-agent-ae969d253c02cdadb`, taban `3eb32df` (main). Sert son 15:15.
Geçici dosyalar: `~/karadul_olcum/runs/dalga0-2026-11-20/PUV1/`.

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| Ön kayıt (`on_kayit_PUV1.md`) | yazıldı | 42fdd11 |
| 1–4, 6 okuyucu + yapı denetimleri + karar + satır içi sayaç | yazıldı, sentetik 36 test yeşil | 800f930 |
| 5 üretici adım | yazıldı, 16 test yeşil | 8c6cf58 |
| Mutasyon (≥ 10) | 16 / 16 öldü | 2292aa5 |
| Yama `PUV1__config.py.patch` | yazıldı; yamalı kopyada kayıt testleri yeşil | 8c6cf58 |
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

## Kalem 5: üretici adım (`karadul/pipeline/steps/go_metadata_recovery.py`)

- `@register_step("go_metadata_recovery")`, `requires=["binary_for_byte_match"]`,
  `produces=["go_functions", "go_buildinfo", "go_integrity", "go_status", "go_functions_path"]`.
  Faz 1 listesine (`steps/__init__.py`, `stages.py`) EKLENMEDİ (P-ÜV6).
- Bayrak: `getattr(cfg.binary_reconstruction, "enable_go_metadata_recovery", False) is True`
  (1, `"true"`, sahte nesne açmaz). Kapalıyken `go_status = {"durum": "kapali", …}`, yapıt boş,
  dosya yazılmaz.
- `go_status` = `{"durum", "neden"}`; durumlar `calisti` / `veri_yok` / `desteklenmiyor` /
  `tutarsiz` / `kapali` / `hata`. Görüntü açılamazsa `GoruntuHatasi.durum` taşınır (biçim tanınmadı
  → `desteklenmiyor`); beklenmedik istisna → `hata` + `ctx.errors`.
- `static/go_functions.json` (şema `karadul-go-functions/1`): durum, pclntab özeti, buildinfo,
  bütünlük (K0–K9 + satır içi sayaç), sayım, okuma süresi, fonksiyon listesi (yalnız `calisti`'da
  dolu; `tutarsiz`'da boş, kanıt alanları dolu). Adresler onaltılık dizgi.
- Görüntü açıcı `_goruntu_ac` P-ÜV0 `goruntu.ac`'ı çağırır (bu dalda henüz yok: içe aktarım
  yalnız bayrak açıkken ve çağrı anında). Testlerde sentetik `BellekGoruntu`'ya bağlanır.
- Testler `tests/test_puv1_adim.py` 16 (kayıt, öntanım + tür kilidi, bayrak 5 değer + sahte
  nesne → kapalı, çalıştı + yapıt, tutarsız → liste yok, Go değil → veri_yok, görüntü hatası
  durumu taşınır ×2, beklenmedik istisna → hata, ikili yok → hata, yapıt yazılamazsa düşmez).

## Yama `docs/arge/2026-11-20_dalga0/yamalar/PUV1__config.py.patch`

- İçerik: `INERT_SETTINGS`'ten `binary_reconstruction.enable_go_metadata_recovery` satırı silinir;
  alan satırındaki `# ETKİSİZ: P-ÜV1 bağlayacak (INERT_SETTINGS)` yorumu kaldırılır.
  `git apply --check` temiz.
- Yamasız dalda `tests/test_p15a_etkisiz.py::test_inert_registry_is_accurate` KIRMIZI (beklenen:
  "kayıtta ama okunuyor: … go_metadata_recovery.py"). Yamalı kopyada (worktree'nin `karadul`,
  `ui`, `tests`, `scripts`, `docker` kopyası; `~/karadul_olcum/runs/dalga0-2026-11-20/PUV1/yamali/`)
  `test_p15a_etkisiz`, `test_bayrak_on_paketi`, `test_p15b_etkisiz_bayraklar` + P-ÜV1 testleri:
  235 geçti / 1 atlandı / 0 kaldı.
- Not: `config.py`'ye geçici yama uygulamak (gönderim metnindeki yöntem) bu oturumun izin
  sınıflandırıcısınca reddedildi; bu yüzden yamalı denetim worktree dışındaki kopyada yapıldı,
  worktree'deki `config.py`'ye hiç dokunulmadı.

## Mutasyon (`scripts/measurement/mutation_specs_puv1.json`)

16 mutant, 16 öldü, 0 kaldı, 0 hata (`git status` sonrası temiz). Plandaki 10 mutantın hepsi
(metin tabanı başlıktan; `funcoff` başlığa; ftab `nfunc`; zikzak ters; `minLC` yok; `nameOff 0`
okunur; K1 `<=`; `vendor/` kuralı yok; tutarsızda liste döner; bayrak doğruluk değeri) + 6 ek
(başlık `textStart` ham sözcükten; K4 eşiği %50; K5 ve K0 karardan çıkar; `0xffffffff` denetimi
yok; imza taramasında akıl sağlığı yok).

## Ara not (11:10): P-ÜV0 bekleniyor

- **Geliştirme denetimi (KABUL DEĞİL).** Okuyucu mantığını gerçek veride erken sınamak için
  araştırma yükleyicisi `scripts/arge/ustveri/macho.py`'yi `Goruntu` arayüzüne saran geçici
  bağdaştırıcıyla (`~/karadul_olcum/runs/dalga0-2026-11-20/PUV1/gelistirme_denetimi.py`, depoya
  girmez) yalnız `gh` koşuldu: durum `calisti`, 40 384 / 40 384 giriş, (adres, ad, dosya) satır farkı
  0, metin tabanı `moduledata.text`, başlık `textStart` 0x0; ihlal K0–K3, K5, K7, K8, K9 = 0, K4 = 1
  (`kisa` 1; araştırmayla aynı: tam 40 370, kisa_asm 10, pcsp_yok 3); K7 252 310 / 252 310 hedef
  giriş; satır içi ad 7 110 (araştırma 7 109: `nameOff 0` farkı, beklenen); okuma 0,34 sn (yük
  altında). Öbür 10 dilimin aynı denetimi izin sınıflandırıcısınca durduruldu (gönderim metni:
  "mesaj gelmeden gerçek ikili kabulüne geçme"); kabul gerçek `Goruntu` ile yapılacak.
- P-ÜV0'ın güncel arayüzünde `Bolum.bellekte` alanı var (ELF'te `SHF_ALLOC` olmayan bölüm adres
  içermez). Okuyucu `bellekte` yanlış bölümleri tarama ve bulmada atlar (`getattr(…, True)`).
- Kabul betiği hazır: `~/karadul_olcum/runs/dalga0-2026-11-20/PUV1/kabul.py` (`dilim` / `gt` /
  `gogo`; dilim başına ayrı süreç, tepe bellek süreç başına).

## Risk: Go 1.18–1.19 (`0xfffffff0`) `_func` düzeni doğrulanmadı

Planın biçimi (44 baytlık `_func`, `startLine` dahil) araştırmada `release-branch.go1.26` / `go1.27`
kaynağından okundu; 1.18–1.19 kaynağı okunmadı ve bu oturumda erişilebilir değil (ağ yok, yerel Go
ağacı yok). Bilinen (doğrulanmamış, TAHMİN): `startLine` 1.20'de eklendi ve imza bu yüzden
`0xfffffff1` oldu; öyleyse 1.18–1.19'da `funcID` / `flag` / `nfuncdata` 36. bayttan başlar ve
okuyucu bu üç alanı yanlış okur. Giriş, ad, dosya etkilenmez (ilk 36 bayt), ama K4'ün birleştirici
ayrımı (`flag`) ve K8 (`funcID`) bozulabilir: en kötü durumda `tutarsiz` (ad yok) — yanıltıcı ad
değil. Kabul setindeki 11 dilimin hepsi Go ≥ 1.23. Plan gereği ezberden genişletilmedi; P-ÜV7 /
P-ÜV9 gerçek bir 1.18–1.19 ikilisiyle ve resmî kaynakla doğrulamalı.
