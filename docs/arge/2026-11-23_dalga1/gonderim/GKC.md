# GKC — GK-C: birim önsözü ve bildirim üretimi (A-41; yalnız yeni dosya)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5–§7 dahil; §7 bugünün koşullarıdır), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-13, A-17, A-19, A-34, A-35, A-41), `docs/arge/2026-11-19_mythos/gerikurma/GERI_KURMA_TASARIM.md` (tamamı; paketinin tanımı §8.0 + aşağıda yazılı alt bölüm) §1.3, §1.4 ve §8.3.

## Neden

`types.h` devre dışı bırakıldığında bile dosyaların yalnız %12,3'ü (S8) derleniyor; kalan hataların %82,4'ü eksik bildirim: `.c` dosyaları çağırdıkları işlevlerin ve kullandıkları veri simgelerinin bildirimini görmüyor. Bildirimin kaynağı çoğu yerde elde (işlev imzaları, içe aktarım dökümü). Bu paket birim başına önsözü üreten saf işlevi yazar ve etkisini ölçer; ürüne bağlama sonraki paketin (GK-M) işi.

## Ana oturumun hükümleri (tasarım belgesi §8.3'ün önüne geçer)

1. **Paketin tanımı tasarım belgesi §8.3'tür:** altı kalem, dosya listesi, ön kayıt H1–H4, kabul. Aynen uygula.
2. **Uydurma yok (belgenin 2 numaralı riski):** kaynağı olmayan bildirim yazılmaz. `int f()` biçiminde örtük dolgu YASAK; iki kaynak çelişiyorsa bildirim yazılmaz, sayılır. Tipi bilinmeyen veri simgesi yalnız kalem 4'teki biçimle ve ayrı sınıfta sayılarak.
3. **Ürün davranışı değişmez:** yeni modül hiçbir yerden çağrılmaz (bağlama yok); ölçüm önsözü `-include` ile vererek. `karadul/reconstruction/gerikurma/` dışındaki ürün dosyalarına yazmazsın.
4. **Ölçüm aracı:** `scripts/arge/gerikurma/derlenebilirlik.py` (main'de; değiştirme) ya da GK-A main'e girdiyse `scripts/measurement/gk_derlenebilirlik.py`. Hangisini kullandığını yaz. GK-B aynı anda `types.h`'yi onarıyor olabilir: sen §1.3'ün önsöz kipinde ölçersin (ürünün `types.h`'si devre dışı), sonucun GK-B'den bağımsızdır.
5. **Hiçbir şey çalıştırılmaz;** yalnız `/usr/bin/clang -fsyntax-only`. Ghidra koşusu yok. `karadul/ghidra/headless.py`'ye dokunma; veri simgesi dökümü önerini not olarak yaz.
6. Girdiler salt okunur: §1.1'deki kökler ve çalışma alanları.

## Yazabileceğin dosyalar

Tasarım belgesi §8.3 "Dosyalar" satırı (hepsi yeni). Koşu kökün `~/karadul_olcum/runs/dalga1-2026-11-23/GKC/`.

## Sıra

1. Kalem 1'in envanteri (gerçek çalışma alanlarında say) → ön kayıt → commit. 2. Saf işlev + testler + mutasyon. 3. Ölçüm: S8'in 8 çıktısı, sonra Ollama (H1–H4). 4. Tam takım.

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır gerçek sayı: önsöz kipinde derlenen dosya, bildirimsiz → bildirimli (S8 toplamı ve Ollama ayrı). Sonra H1–H4, bildirim kaynağı başına üretilen bildirim sayısı, çelişki yüzünden yazılmayan sayı, tipi bilinmeyen veri simgesi sayısı, üretilen bildirimin doğurduğu yeni hata sayısı, kalan hata sınıfları (GK-G'ye girdi), test / mutant sayıları, commit listesi, ÖL-3 (veri simgesi dökümü) ve GK-M için notlar, koşu kökünün yolu ve boyutu.
