# P08 — imza veritabanı onarımı: ölçüm ön kaydı

- **Tarih:** 2026-11-18. **Durum:** KESİN (yeni kol ölçülmeden önce commit'lendi).
- **Kapsam:** IMZA-07 (veritabanının yeniden kurulması, ad başına kitaplık listesi), IMZA-08 (`lstrip("_")`), IMZA-09 (protobuf kısmi eşleşmesi), MEK-11 (`entry`), IMZA-12 (yerleşik sözlükte ezilen POSIX kayıtları). Bunlar imza katmanının **kitaplık iddiasını** ve aday adını değiştirir; kod içine uygulanan adları değiştirmesi beklenmez.
- **Taban kol:** `~/karadul_olcum/runs/urun-yeni2-f30ac9a` (119 ikili; 1.22.1; imza katmanı bugünküyle aynı) ve eski veritabanı `~/.karadul/signatures.lmdb` (9 217 381 ad, `version.txt` ilk satırı `99af8608…`).
- **Yeni kol:** bu paketin kodu + yeni veritabanı (`~/karadul_olcum/sigdb/<build_id>/signatures.lmdb`).

## 1. Ölçüm yolu (Ghidra'sız yeniden oynatma)
İmza eşlemesi Ghidra'nın fonksiyon listesi üstünde yapılıyor. Taban kolun her ikilisi için saklı `deobfuscated/ghidra_functions.json`, `ghidra_strings.json`, `ghidra_call_graph.json` ve `decompiled/` ile `SignatureDB.match_all` iki kez koşulur: (a) taban kod + eski veritabanı, (b) yeni kod + yeni veritabanı. Önce (a)'nın saklı `reconstructed/signature_matches.json` ile aynı kayıtları verdiği denetlenir (yeniden oynatmanın geçerliliği; tutmazsa fark yazılır, ölçüm sürer ama "yeniden oynatma birebir değil" notu düşülür).

**Kitaplık GT'si (iddia doğru mu):** ikilinin kendi içe aktarım tablosundan, Karadul çıktısından bağımsız.
- ELF: `.dynsym`'deki tanımsız (SHN_UNDEF) simgenin sürüm dizini → `.gnu.version_r`'deki dosya adı (ör. `__printf_chk@GLIBC_2.17` → `libc.so.6`). Sürümsüz içe aktarımın GT'si yok (bakılmadı kovası).
- Mach-O: iki düzeyli ad alanı bağlama kaydı → dylib (lief). Okunamazsa GT yok.
- Kitaplık ailesi eşlemesi önceden sabit: `c, libc, glibc, libc6, pthread, libpthread, dl, libdl, rt, librt, m, libm, ld-linux*` → **glibc**; `libSystem*, libsystem_*, system, libc` (yalnız Mach-O'da) → **libSystem**; `openssl, ssl, crypto, libssl, libcrypto` → **openssl**; diğerleri `lib` öneki ve `.so.N` / `.dylib` / `.N.dylib` soneki atılarak küçük harfle karşılaştırılır. `BrokenLocale` glibc ailesine KATILMAZ (ikili o dosyaya bağlanmıyor).
- Puanlanan kayıt: `method == "symbol"` ve `original` adı ikilinin GT'li bir içe aktarımı.
- Kova: **doğru** (iddia ailesi = GT ailesi), **yanlış** (iddia var, aile farklı), **iddia yok** (kitaplık boş: eşleşme yok ya da çok kitaplıklı).

## 2. Ölçütler ve önceden yazılan beklentiler
| # | Ölçüt (119 ikili, toplam) | Beklenti | "Tutmadı" denir eğer |
|---|---|---|---|
| H1 | yanlış kitaplık iddiası (GT'li içe aktarımlar) | ≥ %90 düşer | yeni ≥ tabanın %10'u |
| H2 | kitaplık iddiası kesinliği = doğru / (doğru + yanlış) | ≥ %95 | < %95 |
| H3 | PyPI paket adlı ya da `pypi_native` kategorili kitaplık iddiası (bütün kayıtlar) | 0 | > 0 |
| H4 | ELF/PE'de `matched` ≠ `original` olan sembol kaydı (IMZA-08 sınıfı) | 0 | > 0 |
| H5 | protobuf kısmi eşleşmesi (`google::protobuf::` önekli olmayan addan protobuf'a) | 0 | > 0 |
| H6 | `entry` adına imza kaydı (MEK-11) | 0 | > 0 |
| H7 | doğru kitaplık iddiası sayısı | tabanın ≥ %50'si (kapsam kaybı sınırı) | < %50 → "kapsam kaybı" diye yazılır; kesinlik (H2) önceliklidir |

- H7'nin tutmaması bekleniyor olabilir: içe aktarımı ayırt edemeyen iki kaynak (`ubuntu_elf_signatures.json`, `pypi_native_symbols.json`) dışarıda kalırsa glibc'nin bazı adlarının (`__printf_chk` vb.) tek kaynağı kalmayabilir. Bu bir başarısızlık değil, bilinen bedeldir; sayı yazılır.
- **Ad davranışı (ikincil, alt küme):** `urun_kos.py` ile en çok 14 ikililik alt kümede yeni kol koşulur, `urun_olc.py karsilastir` taban `urun-yeni2-f30ac9a` ile. Beklenti: koda uygulanan adlar (`naming_map` `global`) değişmez. **Tutmadı:** herhangi bir ikilide doğru ad kaybı > 0. Alt kümenin ikilileri koşudan önce `P08.md`'ye yazılır; BSim deposu çakışması olursa not düşülür.

## 3. Yapılmayacak olan
- Eşik ya da kaynak listesi yeni kolun sonucuna göre ayarlanmaz; ayarlanırsa yeni bir ön kayıt yazılır ve bu ölçüm "geliştirme" diye etiketlenir.
- Masum kapı eşik dosyasına yazılmaz.
