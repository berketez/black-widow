# P13b ön kayıt — bağlı olmayan ad kanalları (K-4)

Yazıldığı an: kod değişmeden ÖNCE (taban `0e190bd`, yerel `main` ucu). Sonuçlar bu dosyaya
göre değerlendirilir; ölçüt sonradan değiştirilmez.

## GT sızıntısı (bağlayıcı)
DWARF ve PDB kanalı ikilinin KENDİ hata ayıklama bilgisini okur; geliştirme setinin GT'si de
dbgsym'den (DWARF) gelir. Bu iki kanalın "doğruluğu" GT ile ÖLÇÜLMEZ (GT'yi kopyalar). İki
kanal (a) kanalın ürettiği anahtarın Ghidra'nın fonksiyon adıyla (adres → `FUN_<adres>`)
tutup tutmadığı ve (b) bağımsız ikinci kaynakla (PE ihraç tablosu) çapraz denetim üzerinden
değerlendirilir; öntanım kararı "sembol varsa onu kullan" ürün davranışı olarak verilir.

## Kanal başına öngörü

| # | Kanal | Girdi | Öngörü (ölçülecek) | Kabul ölçütü (öntanımda açılması için) |
|---|---|---|---|---|
| H1 | `type_recovery_consumer` (BORU-14 b) | birim: sahte PDB sembolü döndüren üretici + koşucu | tabanda `parallel_steps=True` → tüketici görmez (`no-data`), `False` → görür; sonra iki kipte aynı sonuç | iki kip aynı (zorunlu) |
| H2 | PDB | `libz3.dll` + `libz3.pdb` (gerçek, x64; Ghidra bağımlılık deposundaki indirme) | bugünkü `_add_pdb_symbols` anahtarı bölüm İÇİ ofsetten kurar (`FUN_<ofset>`): VA ile tutan anahtar ≈ %0. Onarımdan sonra (görüntü tabanı + bölüm VA + ofset) ihraç tablosundaki fonksiyonların ≥ %95'inde PDB adı = ihraç adı, aynı VA | ≥ %95 çapraz tutarlılık ve anahtar biçimi Ghidra ile aynı → öntanımda AÇIK önerilir (yalnız PE + yan `.pdb` varken çalışır; geliştirme setinde etkisiz) |
| H3 | DWARF | geliştirme setinin soyulmuş ELF'leri (cat, expr, tree, ls, pzstd) | 5 / 5 ikilide `no-debug-info` ya da aday 0; ad haritası değişmez | geliştirme setinde ölçülemez (soyulmuş; GT sızıntısı) → öntanım KAPALI; açılması ayrı ön kayıtla (ayrı hata ayıklama dosyası senaryosu) |
| H4 | Rust demangler (IMZA-14) | `~/.cargo/bin/rustup` (`nm`: 9 197 legacy, 10 v0 simge) | tabanda `$…$` kaçışlı adların %100'ü çözülmemiş (`$LT$`, `$u7b$` kalır); onarımdan sonra 0; `llvm-cxxfilt`'in (bağımsız uygulama) çıktısıyla v0 simgelerde birebir aynı | kaçış kalmayan ad %100, v0 birebir; ama C tanımlayıcısına çevrilen adın ürün değeri ölçülmedi → kanal öntanımda KAPALI |
| H5 | C++ adı Rust kanalına düşmesi (IMZA-13 ek) | `pzstd` (C++), `_ZN3foo3barEi` | tabanda `_ZN…` C++ simgeleri Rust adayı oluyor; sonra 0 | 0 (zorunlu) |
| H6 | Go demangler | makinede Go ikilisi (`/opt/homebrew/bin/gh`) | aday üretir ama Ghidra anahtarıyla tutup tutmadığı Ghidra koşusu olmadan ölçülemez | öntanım KAPALI |
| H7 | Binary Ninja / TRex | bu makinede BN yok, TRex `ghidra_lifted_il_path` üreten adım yok | durum `arac_yok` / `desteklenmiyor` + neden; aday 0 | — (araç yok) |
| H8 | RTTI (IMZA-16) | `pzstd` (C++) | `cpp_rtti` sınıf / vtable adı üretir (≥ 1 sınıf); ad kanalına bayrak arkasında; öntanımda ad haritası değişmez | öntanım KAPALI (ad doğruluğu ölçülmedi) |
| H9 | Parametre adı yayılımı (BORU-10 / MUH-08) | geliştirme setinde `param_names_propagated` (tree tabanında 4) | uygulanan ad 0; sayaç gerçeğe çekilir ya da ad kapısından geçirilip uygulanır | sayaç = koda yazılan ad sayısı (zorunlu) |
| H10 | Geliştirme seti ad haritası (öntanım) | cat, expr, tree, ls, pzstd; T0 (`0e190bd`) ↔ S (P13b) | `naming_map.json` `global` 5 / 5 ikilide AYNI | aynı (zorunlu; değişirse nedeni yazılır) |
| H11 | Geliştirme seti, bütün yeni bayraklar AÇIK | aynı 5 ikili | soyulmuş C ikililerinde değişen ad 0; pzstd'de yalnız RTTI kaynaklı fark olabilir | birleşik 119 ölçümü için beklenti olarak yazılır |

## Ürün koşusu
`kos.sh` (P13a aracının kopyası, `git archive` ağacı), `PYTHONHASHSEED=0`, `--paralel 1`, koşu
başına ayrı `KARADUL_CACHE_DIR`; kök `~/karadul_olcum/runs/onarim-2026-11-18/P13b/`. Taban T0 =
bugünkü `main` (`0e190bd`), aynı 5 ikili.
