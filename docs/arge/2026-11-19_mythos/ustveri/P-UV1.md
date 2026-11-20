# P-ÜV1 — Go `pclntab` okuyucu ve üretici adım: ilerleme (2026-11-20)

Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/PUV1.md`. Plan: `ustveri/PLAN.md` "P-ÜV1".
Dal: `worktree-agent-ae969d253c02cdadb`, taban `3eb32df` (main). Sert son 15:15.
Geçici dosyalar: `~/karadul_olcum/runs/dalga0-2026-11-20/PUV1/`.

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| Ön kayıt (`on_kayit_PUV1.md`) | yazıldı | d8814e5 (rebase öncesi 42fdd11) |
| 1–4, 6 okuyucu + yapı denetimleri + karar + satır içi sayaç | yazıldı | 699c97f, 0f18f64, cb1cac4, 564163e, 2594bde |
| 5 üretici adım | yazıldı | b00fae8, 2594bde |
| Mutasyon (≥ 10) | 19 / 19 öldü | a6af752, 29fce0f |
| Yama `PUV1__config.py.patch` | yazıldı; yamalı kopyada kayıt testleri yeşil | b00fae8 |
| Rebase (main 8844a08) + 11 dilim kabulü + docker-cli GT | yapıldı: 11 / 11 satır farkı 0; docker-cli 35 048 / 35 048 | 29fce0f |
| Okuyucu dondurma + docker-compose SINAMA GT | dondurma 29fce0f; SINAMA 90 077 / 90 077 | (bu commit) |
| 7 süre ve bellek | ölçüldü (yük altında) | 29fce0f |
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

## Bekleme (11:10)

Şu an: P-ÜV0'ın main'e girişi bekleniyor (ana oturum mesajı; arka planda ana ağaçta `goruntu.py`
var mı diye bakılıyor). Aynı sürede tam takımın ön koşusu (rebase öncesi, yamasız; bilinen
`test_inert_registry_is_accurate` dışarıda) arka planda; günlük
`~/karadul_olcum/runs/dalga0-2026-11-20/PUV1/tam_takim_on.log`. Hazır betikler: `kabul.py`
(11 dilim, GT, Go olmayan 5), `bozma_e.py` (H5 için E türü kopya). Tahmini bitiş: P-ÜV0'a bağlı.

## Rebase ve kabul (11:11–11:14, yük altında: `uptime` yük ortalaması 4,97 / 5,69 / 6,28)

- Ana oturum mesajıyla bir kez `git rebase main` (main `8844a08`, P-ÜV0 dahil): çatışma yok.
  `karadul.analyzers.ustveri.goruntu.__file__` worktree yolunda. Rebase sonrası hash'ler: ön kayıt
  `d8814e5`, okuyucu `699c97f`, adım + yama `b00fae8`, mutasyon `a6af752`.
- Test dosyası gerçek `BellekGoruntu` / `Bag` / `Bolum`'a bağlandı, geçici sahte sınıf silindi
  (`564163e`). Okuyucu ortak durumları (`calisti`, `veri_yok`, `desteklenmiyor`, `hata`)
  `goruntu`'dan içe aktarır.
- Kabul sırasında eklenen iki onarım (`2594bde`): fonksiyon başına K4 sonucu (`pcsp_kapsama`,
  H5'te görülen açık için); adım evrensel dosyada ürünün dilimini (`goruntu.urun_dilimi`) açar
  (Ollama evrensel → arm64, 10 601 giriş = ince dilim).

### H1 — 11 dilim, (adres, ad, dosya) ↔ `$V/go/<ad>.tsv` → TUTTU (11 / 11, satır farkı 0)

Betik `~/karadul_olcum/runs/dalga0-2026-11-20/PUV1/kabul.py dilim` (dilim başına ayrı süreç),
çıktı `kabul_dilim2.jsonl`. Girdi `$V/hedef/<ad>` (araştırma kopyaları, ince dilim).

| Dilim | Go | Giriş (biz / başvuru) | Satır farkı | Metin tabanı | Başlık textStart | K1 / K2 / K5 / K9 | K4 ihlal | K7 başka gövde içi | Okuma sn | Açma sn | Tepe RSS MB | sha256 (ilk 12) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gh | go1.27.4 | 40 384 / 40 384 | 0 | moduledata.text | 0x0 | 0 / 0 / 0 / 0 | 1 | 0 | 0,331 | 0,387 | 219,9 | `ca6c859f0ff8` |
| limactl | go1.27.3 | 40 321 / 40 321 | 0 | moduledata.text | 0x0 | 0 / 0 / 0 / 0 | 1 | 0 | 0,445 | 0,181 | 240,0 | `f0b05d095116` |
| Ollama.arm64 | go1.26.0 | 10 601 / 10 601 | 0 | moduledata.text | 0x0 | 0 / 0 / 0 / 0 | 0 | 0 | 0,135 | 0,175 | 132,6 | `7d5b1e847e1b` |
| Ollama.x86_64 | go1.26.0 | 10 676 / 10 676 | 0 | moduledata.text | 0x0 | 0 / 0 / 0 / 0 | 0 | x86_64: yok | 0,119 | 0,153 | 125,7 | `72edc4c1e8cf` |
| ollama-cli.arm64 | go1.26.0 | 25 164 / 25 164 | 0 | moduledata.text | 0x0 | 0 / 0 / 0 / 0 | 0 | 0 | 0,299 | 0,13 | 179,9 | `65484dbd099f` |
| ollama-cli.x86_64 | go1.26.0 | 25 267 / 25 267 | 0 | moduledata.text | 0x0 | 0 / 0 / 0 / 0 | 0 | x86_64: yok | 0,257 | 0,15 | 151,9 | `b1ecfea3e35a` |
| colima | go1.26.4 | 13 082 / 13 082 | 0 | moduledata.text | 0x0 | 0 / 0 / 0 / 0 | 0 | 0 | 0,14 | 0,056 | 110,5 | `55278419bd42` |
| docker-brew | go1.27.4 | 35 749 / 35 749 | 0 | moduledata.text | 0x0 | 0 / 0 / 0 / 0 | 0 | 0 | 0,389 | 0,151 | 211,3 | `cd9e0b149e44` |
| arduino-cli | go1.27.3 | 29 711 / 29 711 | 0 | moduledata.text | 0x0 | 0 / 0 / 0 / 0 | 1 | 0 | 0,366 | 0,353 | 196,2 | `e47aa40da285` |
| docker-cli | go1.24.4 | 35 049 / 35 049 | 0 | moduledata.text | 0x100001000 | 0 / 0 / 0 / 0 | 0 | 0 | 0,279 | 0,233 | 198,5 | `1b2b4029ea6b` |
| docker-compose | go1.23.8 | 90 078 / 90 078 | 0 | moduledata.text | 0x100002d30 | 0 / 0 / 0 / 0 | 0 | 0 | 0,754 | 0,483 | 395,7 | `fc9b9e22a113` |

- Giriş sayıları plandakiyle aynı: 40 384, 40 321, 10 601, 10 676, 25 164, 25 267, 13 082, 35 749,
  29 711, 35 049, 90 078.
- K1, K2, K5, K9 ihlali 11 dilimde 0; K7 "başka gövde içi hedef" arm64 dilimlerinde 0 (Duff içi
  çağrı docker-cli 6 413, docker-compose 21 159; Go ≤ 1.25'te olağan); K0 11 / 11'de 0.
- K4 ihlali en çok 1 (gh, limactl, arduino-cli; `kisa` 1) — eşik %1'in çok altında.
- Süre (kalem 7): okuma 0,12–0,75 sn, açma (P-ÜV0) 0,06–0,48 sn; eşik dilim başına ≤ 10 sn → TUTTU.
  Tepe bellek (süreç RSS, Python + dosya baytları + sha256 için ikinci okuma dahil; üst sınır):
  93–396 MB. Yük altında ölçüldü; boş makine ölçümü değil.

### H3 → TUTTU

Go ≥ 1.26 olan 9 dilimde (gh, limactl, Ollama ×2, ollama-cli ×2, colima, docker-brew,
arduino-cli) başlıktaki `textStart` 0x0; okuyucu `moduledata.text` kullanıyor. Başlığa güvenen
taban (`textStart + entryoff`) bu 9 dilimde doğru adres 0 / N verir (ölçüldü: 0 / 40 384, 0 / 40 321,
0 / 10 601, 0 / 10 676, 0 / 25 164, 0 / 25 267, 0 / 13 082, 0 / 35 749, 0 / 29 711); mutant
`puv1_metin_tabani_basliktan` sentetikte öldü. Go 1.23 / 1.24 (docker-compose, docker-cli)
başlıktaki `textStart` (`gosterici()` ile çözülmüş) = `moduledata.text`.

### H4 → TUTTU

Bozulmamış 11 dilimin hiçbiri `tutarsiz` vermedi (11 / 11 `calisti`).

### H2 (keşif yarısı) — docker-cli ad = sembol → TUTTU

`kabul.py gt docker-cli`: HEDEF setinin soyulmuş kopyası (`ustveri_set/docker-cli/bin`, sha256
`4b6b084536de`), GT `gt/docker-cli.gt.json` (`ustveri_set.gt_oku`), eşitlik
`ustveri_olc.kanal_olc` (Go yazım kuralları). Adlı giriş 35 048 / 35 049; doğru 35 048, yanlış 0,
GT'siz 0; yazım: birebir 34 710, `.abi0` eki 328, orta nokta 10. Wilson %95 alt sınırı 0,99989 ≥
0,999 → eşik TUTTU.

### H5 → TUTTU (bu paketin bozma betiğiyle; P-ÜV7'nin kopyası yok)

`bozma_e.py` (araştırma E kolunun aynısı, tohum 20261120): gh ve limactl'de 100 komşu çiftin
ftab `funcoff`'u takas, `_func.entryOff` yeni girişe uyduruldu (kopyalar yalnız
`PUV1/` dizininde). K4 ihlali gh 173 (taban 1; `kisa` 87, `tasan` 86), limactl 163 (taban 1) → > 0.
**Ek bulgu:** ihlal fonksiyonların %0,43 / %0,40'ı, ikili düzeyindeki %1 eşiğinin altında: durum
`calisti` ve takas edilen ~170 fonksiyonun yanlış adı listede kalıyor; K0 ve K1 bu bozmayı görmez
(entryOff uyduruldu). Bu yüzden fonksiyon başına `pcsp_kapsama` alanı eklendi; ad kanalı (P-ÜV6) ve
damga (P-ÜV7) `kisa` / `tasan` olan fonksiyona ad yazmamalı. Karar kuralı plan gereği değişmedi.

### H6 → TUTTU (5 / 5; ek 2 Mac)

`kabul.py gogo`, girdiler `~/karadul_olcum/runs/urun-onarim-a62f15e/<…>/raw/<ad>` (geliştirme seti):

| İkili | Biçim | Durum | Ad | sha256 (ilk 12) |
|---|---|---|---|---|
| debian/htop | elf | veri_yok | 0 | `9b61e8bec98f` |
| debian/tmux | elf | veri_yok | 0 | `0ad19f45a67c` |
| debian/coreutils | elf | veri_yok | 0 | `0d5a5dd543ed` |
| debian/zstd | elf | veri_yok | 0 | `77866a8bf262` |
| mac/htop | macho | veri_yok | 0 | `50d172cee23c` |
| mac/tmux | macho | veri_yok | 0 | `10fa041195a8` |
| debian/ls | elf | veri_yok | 0 | `0c062cc32ec1` |

(debian/coreutils = `cat`, debian/zstd = `pzstd`.) Adım uçtan uca (gerçek `goruntu`, sahte çalışma
alanı): gh `calisti` 40 384; bayrak kapalı → `kapali`, yapıt yok; debian htop → `veri_yok`.

## Okuyucu dondurma

Dondurulan dosyalar (bu commit'ten sonra SINAMA ölçümüne dek değişmez):
`karadul/analyzers/ustveri/go_pclntab.py` sha256 `8b1d38ff4dc1…`, `karadul/pipeline/steps/go_metadata_recovery.py`
sha256 `804250083dcb…` (dondurma commit'i: bu commit). SINAMA (docker-compose) GT'sine bu commit'ten
sonra bir kez bakılır.

### H2 (SINAMA yarısı) — docker-compose ad = sembol → TUTTU; H2 bütünü TUTTU

Dondurma commit'i `29fce0f`'dan sonra, okuyucu sha256 `8b1d38ff4dc1…` değişmeden, bir kez:
`kabul.py gt docker-compose` (soyulmuş kopya sha256 `9f39c9662989`). Adlı giriş 90 077 / 90 078;
doğru 90 077, yanlış 0, GT'siz 0; yazım: birebir 89 699, `.abi0` eki 360, orta nokta 18; Wilson
%95 alt sınırı 0,999957 ≥ 0,999. Bütün yapı denetimlerinde ihlal 0. Okuma 0,88 sn (yük altında).

**H2: 125 125 / 125 125** (docker-cli 35 048 + docker-compose 90 077) → TUTTU.

## Yama denetimi (rebase sonrası, 11:17)

`git apply --check` temiz. Güncel kodun yamalı kopyasında (`PUV1/yamali2/`: `karadul`, `ui`,
`tests`, `docker`, `scripts/measurement`, `scripts/arge`) `test_p15a_etkisiz`, `test_bayrak_on_paketi`,
`test_p15b_etkisiz_bayraklar`, `test_puv0_goruntu`, P-ÜV1 testleri: 278 geçti / 1 atlandı / 0 kaldı.

Şu an: tam takım (yamasız dal, worktree kökünden) arka planda; günlük
`~/karadul_olcum/runs/dalga0-2026-11-20/PUV1/tam_takim.log`; tahmini 10–20 dk (yük altında).
Çalışma verisi bağları kuruldu (`sigs`, `vendor`, `scripts/node_modules`, `signatures*.json`,
`sigs_macos_system.json`, `signatures.lmdb`; commit'lenmez). Ön koşuda (bağlar yokken)
`test_deobfuscator::test_extract_webpack_modules` `@babel/parser` bulunamadığı için kalmıştı.
