# ARGE — Mythos soru listesinin son hâli (ilerleme)

- **Görev:** `docs/arge/2026-11-18_arge_soru_listesi.md` ARA SÜRÜM → SON SÜRÜM ADAYI (2026-11-19). Birleşik 119 ölçümünün sayıları `⟨ÖLÇÜM: …⟩` yer tutucularına ana oturum tarafından girecek.
- **Taban:** worktree `git merge --ff-only main` → `0984090` (a62f15e + oturum notları ve P12c metni; yalnız belge).
- **Kaynaklar (salt okur):** `DURUM.md` (40 paket satırı, K-1…K-10, ara noktalar), `gonderim/OKU.md` (DURUŞ, atanmamış bulgular), `gonderim/OTURUM_2026-11-19.md`, `docs/arge/2026-11-18_genel_tarama/RAPOR.md`, paket dosyaları `P*.md`, `gonderim/P*.md` (süren / sıradaki paket metinleri).
- **Ek görev (ana oturum, 2026-11-19 08:2x):** Berke'nin hipotezi ("imzalı kütüphanelerden adı bilinmeyen fonksiyonu tahmin et") A2 ve A5'e üç ayrımla (kütüphane kopyası / programın kendi kodu / birleşim hattı) ve A1 bağıyla yazılacak.

## Adımlar
| Adım | Bölüm | Durum | Commit |
|---|---|---|---|
| 1 | Başlık (durum satırı, okuma sırası) + §0 okuma tablosu | bitti | 41ea923 |
| 2 | §1: iki sütunlu ad tablosu (1.22.1 → a62f15e), ölçüm altyapısı (urun_kos hijyeni, masum kapı setleri, Ghidra'sız yeniden oynatma, toplu BSim, mutasyon düzeni), olumsuz sonuçlar tablosu (16 satır; kaynak DURUM.md) | bitti | 09c728a |
| 3 | §1.1 onarımın özeti: kapananlar (yanıltan çıktılar, güvenlik, hız), bekletilenler (K-1), açık kalanlar (süren / sıradaki paketler), K-1…K-10 + 2026-11-19 kararları, ölçüm zemininde değişenler | bitti | 4122587 |
| 4 | §2 K-2 notu; §3 alan listesine "Onarım sonrası"; A1–A6 onarım sonrası satırları; Berke'nin hipotezi A2 (üç kollu ayrım: P08 0,695 → 0,975, P-S3b 732 / 0, P15b FLIRT bekletme → P08b) ve A5 (P11 0 / 208, P15c 19 / 83 ve 5 / 153, P16b 597 → 0); A5 Karar 2 + GTK / GLib aday nüfus; A1 bağı | bitti | 0a1588c |
| 5 | §3 B–H onarım sonrası satırları (40 sorunun 40'ında satır var); yeni G4 (belirlenimcilik, bayatlayan güven tablosu; P12a, P16a, P-S3, P14, P16d, gnulib 0,706); bayat "Bugün" satırları tarihlendi (B2, D1, E1, H6) | bitti | 2a8e8d4 |
| 6 | §3.I onarımdan doğan araştırma soruları I1–I6 (I1 = Berke'nin hipotezinin birleşim hattı; I2 Mach-O `main`; I3 Ghidra dizgi kaçışı; I4 üst verinin düşman girdiye dayanıklılığı; I5 parametre adı yayılımı; I6 yapı alanı adları). Yinelenmesin diye alt soru olarak eklenenler: `string_intel` → A5, bileşim kanıt kuralı → H1 (imza VT davranış H2'de, CAST / PTRSUB H5'te, capa CRT C5'te). Uzunluk için sıkıştırma: A3 / B3 alt maddeleri, §1.1 güvenlik, K-5…K-8, altyapı satırları, iki yinelenen olumsuz sonuç maddesi | bitti | (bu commit) |
