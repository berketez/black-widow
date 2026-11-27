# GKA — GK-A: derlenebilirlik ölçüm aracı, taban ve "geriye gitme yok" kapısı (A-41)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5–§7 dahil; §7 bugünün koşullarıdır), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-13, A-17, A-19, A-34, A-35, A-41), `docs/arge/2026-11-19_mythos/gerikurma/GERI_KURMA_TASARIM.md` (tamamı; paketinin tanımı §8.0 + aşağıda yazılı alt bölüm) §8.1.

## Neden

Projenin ana amacı geri kurma (A-41): ikiliden yeniden derlenebilen kod. Bugünkü çıktının 0'ı derleniyor (S8 0 / 7 127). Bundan sonraki her GK paketi bu sayıyı oynatacak; sayıyı veren araç bugün bir keşif betiği (`scripts/arge/gerikurma/derlenebilirlik.py`). Bu paket onu kalıcı, sınanmış ölçüm aracına çevirir ve tabanı kilitler.

## Ana oturumun hükümleri (tasarım belgesi §8.1'in önüne geçer)

1. **Paketin tanımı tasarım belgesi §8.1'dir:** yedi kalem, dosya listesi, ön kayıt H1–H4, kabul. Aynen uygula.
2. **Girdiler salt okunur:** §1.1'deki kökler (`ANA/s8_taban_534e252b` 8 çıktı, `ANA/ollama_ba_kapali/out`). H1 bu köklerle verilir (sayıların ölçüldüğü girdi). Yerinde olmayan girdi varsa dur ve bildir; başka kökle "yeniden üretildi" deme. Ayrıca taban dosyası yeni S8 tabanı (`ANA/s8_taban_ed28e36b`) için de üretilir ve iki S8 tabanının sayıları yan yana yazılır (beklenen: aynı; `.c` gövdeleri 24 Kasım'da 8 / 8 ham eşitti).
3. **Hiçbir şey çalıştırılmaz:** araç yalnız derler (`-fsyntax-only`, nesne kipinde `-c`); üretilen nesne dosyası bağlanmaz ve çalıştırılmaz. Nesne dosyaları koşu kökünde kalır, depoya girmez.
4. **Sahte sayı yok:** clang yoksa araç "derleyici yok" der ve sayı üretmez; testler clang yoksa atlanır (atlandığı görünür).
5. **Ürün kodu değişmez.** `karadul/` altına yazmazsın. GK-B (`c_project_builder.py`, `c_type_recoverer.py`) ve GK-C (`karadul/reconstruction/gerikurma/`) aynı anda çalışıyor olabilir: onların dosyalarına dokunma.
6. Kapı (kalem 6'nın karşılaştırma kipi) bu pakette tam takıma BAĞLANMAZ (taban GK-B ile değişecek); komut ve çıkış kodu sözleşmesi yazılır, bağlama GK-B main'e girdikten sonra ana oturumun işi.

## Yazabileceğin dosyalar

Tasarım belgesi §8.1 "Dosyalar" satırı (hepsi yeni dosya). Koşu kökün `~/karadul_olcum/runs/dalga1-2026-11-23/GKA/`; özet `ozet/` altında (`gk_taban.json` dahil; depoya yalnız sayılar ve sha256 girer).

## Sıra

1. Ön kayıt → commit. 2. Araç + testler + mutasyon. 3. H1 (eski sayıların birebir yeniden üretimi) → H2, H3. 4. Taban dosyaları. 5. Tam takım.

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır gerçek sayı: 9 çıktıda derlenen dosya (ana makine üçlüsü ve hedef üçlüsü ayrı), §1.2 / §1.3 tablolarıyla fark (0 değilse nerede). Sonra H1–H4, hedef üçlüsünün değiştirdiği sınıflar, işlev sayısı farkı, test / mutant sayıları, commit listesi, kapının komutu, GK-B / GK-C / GK-I için notlar, koşu kökünün yolu ve boyutu.
