# P15b — veri kökü (GHIDRA-14) + yeni imza veritabanı (K-5): ölçüm ön kaydı

- **Tarih:** 2026-11-18. **Durum:** KESİN (kod değişmeden ve yeni kol koşulmadan önce commit'lendi).
- **Kapsam:** GHIDRA-14 (`project_root` yalnız çıktı kökü; ayrı `data_root` veri kökü) ve K-5 (ürünün ve geliştirmenin yeni şema 2 veritabanını açması). Bunlar şu kanalları etkileyebilir: n-gram yerel ad kanalı (veritabanı `sigs/ngram_name_db`; bugün `--output-dir`'le koşulan ürün ve ölçümde hiç koşmuyor), FLIRT dış bayt imzaları (bugün `--output-dir`'de yüklenmiyor; B-D3 kararıyla bekletiliyor), dış imza JSON'ları (yalnız LMDB yokken yüklenir), imza veritabanının kitaplık iddiası (şema 1 ↔ şema 2).
- **FLIRT kararı (ölçümden önce yazılıyor):** veri kökündeki dış bayt imzaları (`signatures_homebrew_bytes.json`, `sigs/**/*.pat`) bu pakette de OTOMATİK YÜKLENMEZ; bekletme (B-D3, 2026-09-25: redis-server 162 ad / 0 doğru) artık giriş noktasından bağımsız ve istatistikte gerekçesiyle yazılı olur. Bugün yalnız depo kökünden `--output-dir`'siz koşuda açık olan (yanlış ad üreten) yol da kapanır. Açık yol `binary_reconstruction.external_signature_paths` ile açıkça verilen dosya (değişmez).

## 1. Kollar
Alt küme (6 ikili, koşudan önce sabit): `debian/coreutils/cat`, `debian/coreutils/expr`, `debian/tree/tree`, `debian/htop/htop`, `debian/zstd/pzstd`, `mac/htop`. Girdiler `urun_kos.py::isleri_topla` (sha256 denetimli). Hepsi `--paralel 1`, `PYTHONHASHSEED=0`, kol başına ayrı ve boş `KARADUL_CACHE_DIR` (BSim deposu kollar arasında sızmasın, GHIDRA-02), komut `python -m karadul analyze <girdi> --skip-dynamic --output-dir <d>/ws --output <d>/out`.

| Kol | Kod | Veritabanı | Kök |
|---|---|---|---|
| **T** (taban) | bugünkü `main` = d2f205d (1.24.1), `git archive` kopyası | öntanım: `~/.karadul/signatures.lmdb` (şema 1) | `~/karadul_olcum/runs/onarim-2026-11-18/P15b/T` |
| **Y1** (yalnız veri kökü) | bu paketin kodu (kalem 1 + 2), dondurulmuş kopya | `KARADUL_SIG_LMDB_PATH=~/.karadul/signatures.lmdb` (eski, şema 1) | `…/P15b/Y1` |
| **Y** (yeni) | aynı kod | veri kökündeki `signatures.lmdb` → `~/karadul_olcum/sigdb/s2-20261118/signatures.lmdb` (şema 2) | `…/P15b/Y` |

T ↔ Y1 farkı = veri kökü; Y1 ↔ Y farkı = veritabanı.

## 2. Ölçütler ve önceden yazılan beklentiler
"Uygulanan ad" = `out/naming_map.json` ya da `ws/.../reconstructed/src/naming_map.json`'daki fonksiyon adı haritası (`global` + `per_function`); karşılaştırma ikili başına anahtar–değer farkı.

| # | Ölçüt | Beklenti | "Tutmadı" denir eğer |
|---|---|---|---|
| H1 | T ↔ Y1 uygulanan fonksiyon adı farkı | 0 (n-gram yalnız yerel değişken adı yazar; FLIRT bekletiliyor; LMDB varken dış JSON yüklenmez) | herhangi bir ikilide > 0 |
| H2 | Y1 ve Y'de `ngram_naming_durum` | 6/6 `calisti` (T'de alan ya `veri_yok` ya yok) | Y1'de < 6/6 |
| H3 | Y1 ↔ Y uygulanan fonksiyon adı farkı (K-5; P08'in alt küme bulgusu) | 0 | herhangi bir ikilide > 0 → farklar tek tek yazılır |
| H4 | Y'de istatistik künyesi: `sigdb_schema_version=2`, `sigdb_lmdb_symbol_count=9092473`, `sigdb_build_id=s2-b32ee9f65b1a-20261118`, `data_root` ve dış imza durumu | 6/6 | < 6/6 |
| H5 | `flirt_signatures_loaded` T ↔ Y | eşit (yalnız ikilinin kendi simgelerinden çıkarılan) | Y > T |
| H6 | İmza adaylarının kitaplık iddiası (Y1 ↔ Y; `signature_matches.json` / `naming_map` adayları): eski veritabanına özgü yanlış aileler (`_stdio.h`, `libintl.h`, `gcc`, `CoreGraphics`) | Y'de 0 | Y'de > 0 |

- **n-gram'ın doğruluğu** (yerel ad) bu pakette ölçülmez (yerel ad GT'si yok; P09'un notu). Yalnız sayaçlar (`ngram_names_applied`, `ngram_rejected_*`) yazılır; kanalın açılması bir ad davranışı değişikliğidir ve ana oturuma bildirilir.

## 3. Giriş noktası bağımsızlığı (GHIDRA-14 kabulü)
Aynı ikili (`debian/coreutils/true`) yeni kodla üç biçimde: (a) ağaç kökünden `--output-dir`'siz (`cwd` = ağaç), (b) başka bir dizinden (`cwd` = ölçüm dizini) `--output-dir` ile, (c) `ui/server.py`'nin kurduğu komutla (`--output-dir <run>/ws --output <run>/out`). Beklenti: üçünde uygulanan ad haritası aynı; istatistikteki `data_root`, dış imza durumu, FLIRT ve n-gram durumu aynı. Tutmazsa fark yazılır.

## 4. Yapılmayacak olan
- Eşik, kaynak listesi ya da FLIRT kararı yeni kolun sonucuna göre ayarlanmaz; ayarlanırsa yeni ön kayıt yazılır.
- İmza veritabanının adsız fonksiyonlara verdiği betimleyici adlar (P11: `call_pattern` 0/76, `string_ref` 0/132) bu paketin konusu değil (P15c).
- `~/.karadul/**` yazılmaz; masum kapı eşik dosyasına yazılmaz.
