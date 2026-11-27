# GKB — GK-B: `types.h` onarımı (A-41; `c_project_builder.py` zincirinin başı)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5–§7 dahil; §7 bugünün koşullarıdır), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-13, A-17, A-19, A-34, A-35, A-41), `docs/arge/2026-11-19_mythos/gerikurma/GERI_KURMA_TASARIM.md` (tamamı; paketinin tanımı §8.0 + aşağıda yazılı alt bölüm) §1.2, §1.4 ve §8.2; ayrıca P18'in ilerleme dosyası (Ghidra'sız yeniden oynatma yöntemi: `grep -rl "P18" docs/arge/2026-11-19_mythos/ docs/arge/2026-11-20_dalga0/ | head` ile bul).

## Neden

Bugünkü çıktıda hiçbir `.c` dosyası derlenmiyor (S8 0 / 7 127; Ollama örneklemi 0 / 1 000) ve neden tek yerde: her dosyanın içerdiği `include/types.h` kendisi derlenmiyor (yeniden tanım, bilinmeyen Ghidra temel tip adları, ayrıştırma hatası; hataların S8'de %92,8'i başlıkta). Bu bilgi eksikliği değil, üretici kusuru. Bu paket onu onarır; sonunda projenin ilk gerçek derlenme oranı çıkar.

## Ana oturumun hükümleri (tasarım belgesi §8.2'nin önüne geçer)

1. **Paketin tanımı tasarım belgesi §8.2'dir:** yedi kalem, dosya listesi, ölçüm yolu, ön kayıt H1–H4, kabul. Aynen uygula.
2. **Uydurma yok (belgenin 2 numaralı riski):** derlenir kılmak için tip uydurulmaz. Tanımı Ghidra'nın tip dökümünde olmayan tip, yorumla "tanımsız tip" diye yazılır ve sayılır; `int` ile doldurulmaz. Enum sabit adı çevrilirken değer korunur. Her kalemin kaç tanımı etkilediği gerçek çıktılarda sayılır.
3. **`.c` gövdeleri ve ad haritası değişmez (H3):** fark yalnız `include/types.h` ve üç derleme dosyasında. Enum sabit adı değişikliği bir `.c` gövdesinde kullanılan adı değiştiriyorsa DUR, sayısını yaz ve o kalemi "kalan" bırak (gövdeye dokunmak bu paketin işi değil).
4. **Ölçüm aracı:** GK-A aynı anda yazılıyor olabilir; sen `scripts/arge/gerikurma/derlenebilirlik.py`'yi kullan (main'de; değiştirme). Hedef üçlüsü ölçümü gerekiyorsa aracın dışından, kendi betiğinle ve yazarak.
5. **Hiçbir şey çalıştırılmaz;** yalnız `/usr/bin/clang -fsyntax-only`. Ghidra koşusu yok.
6. **`config.py`'ye yazmazsın.** Ürün çalışma anında clang çağırmaz (karar K-5 bekliyor): clang yalnız test ve ölçümde.
7. **Dokunma:** `c_project_builder.py`'nin yerleşim ve dosya adlandırma işlevleri (ÇA zinciri), `output_formatter.py`, `c_namer.py` ve `api_param_db.py` (HZ7a), `karadul/reconstruction/gerikurma/` (GK-C), `karadul/pipeline/`, `karadul/ghidra/`.

## Yazabileceğin dosyalar

Tasarım belgesi §8.2 "Dosyalar" satırı. Koşu kökün `~/karadul_olcum/runs/dalga1-2026-11-23/GKB/`. Dokunduğun iki ürün dosyasına bakan eski mutasyon tanımlarını (`grep -l`) yeniden koş; bayatlayanı düzelt ve yaz.

## Sıra

1. Ön kayıt → commit. 2. Kalem 1–5 + testler + mutasyon (kalem başına ayrı commit). 3. S8 yeniden oynatması (H1, H2, H3). 4. 119 ikili (H4; girdi `~/karadul_olcum/runs/urun-onarim-a62f15e/` çalışma alanları; uzun sürerse arka planda). 5. Ollama çıktısı (H1, H2'nin 9.'su). 6. Tam takım.

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır gerçek sayı: S8'in 8 çıktısında ve Ollama'da tek başına derlenen dosya sayısı önce → sonra (ürün kipi), başlık kaynaklı hata önce → sonra. Sonra H1–H4, kalem başına etkilenen tanım sayısı, "tanımsız tip" diye yazılan tip sayısı, kalan hata sınıflarının dağılımı (GK-C ve GK-G'ye girdi), test / mutant sayıları, eski tanımların durumu, commit listesi, ÇA-B / GK-G için notlar, koşu kökünün yolu ve boyutu.
