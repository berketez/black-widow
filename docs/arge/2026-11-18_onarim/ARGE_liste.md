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
| 6 | §3.I onarımdan doğan araştırma soruları I1–I6 (I1 = Berke'nin hipotezinin birleşim hattı; I2 Mach-O `main`; I3 Ghidra dizgi kaçışı; I4 üst verinin düşman girdiye dayanıklılığı; I5 parametre adı yayılımı; I6 yapı alanı adları). Yinelenmesin diye alt soru olarak eklenenler: `string_intel` → A5, bileşim kanıt kuralı → H1 (imza VT davranış H2'de, CAST / PTRSUB H5'te, capa CRT C5'te). Uzunluk için sıkıştırma: A3 / B3 alt maddeleri, §1.1 güvenlik, K-5…K-8, altyapı satırları, iki yinelenen olumsuz sonuç maddesi | bitti | ed70a57 |
| 7 | §4 öncelik önerisi onarım sonrasına göre (0 taban a62f15e; 1 G1 + B3 + G4; 2 A1; 3 A3 + I2 + I4; 4 A5 + I1 + H2; 5 A2 + D1; 6 yapı ve hız; 7 F, önce gerçek model dumanı); "yalnız bir görüş; Mythos itiraz edebilir" başlıkta kaldı. §6: taban a62f15e, süren / sıradaki paketlerin etkisi yok, alt küme sayıları birleşik sayının yerine geçmez | bitti | 0108cd0 |

## ⟨ÖLÇÜM⟩ yer tutucuları (ana oturum dolduracak; satır numaraları 0108cd0'daki listeye göre)
| Yer tutucu | Bölüm (satır) | Kaynak |
|---|---|---|
| `havuz` | §1 ad tablosu (43) | `sonuc.md` |
| `doğru (%; %95 GA)` | §1 ad tablosu (44) | `sonuc.md` |
| `yanlış (%; %95 GA); makro yanlış` | §1 ad tablosu (45) | `sonuc.md` |
| `nüfus` | §1 ad tablosu (46); GT'den, 21 371 beklenir | `sonuc.md` |
| `ad verilen kapsam` | §1 ad tablosu (47) | `sonuc.md` |
| `doğru ad kapsamı` | §1 ad tablosu (48); A1 (158) | `sonuc.md` |
| `kesin etiketli doğru / toplam; kapsam` | §1 ad tablosu (49) | `sonuc.md` |
| `tuttu / tutmadı` (yanlış ≤ %10) | §1 ad tablosu (50) | `sonuc.md` |
| `kanal kırılımı farkı` | §1 tablo altı (52); A2 (164); B1 (201); E5 buna atıf yapar | `urun_olc.py karsilastir` (1.22.1 ↔ a62f15e) |
| `urun_kos süresi (119 ikili, --paralel 3)` | §1 ölçüm altyapısı (58) | koşu kökü / ön kayıt |
| `masum kapı çıktı kipi, 119 ikili` | §1 ölçüm altyapısı (59); koşulmadıysa "koşulmadı" | `masum_kapi.py` çıktı kipi |
| `sağlamlık denetimi kusur sayıları, 119 ikili` | §1 ölçüm altyapısı (60); koşulmadıysa "koşulmadı" | `saglamlik_denetle.py` |
| `gnulib ön ad kanalının yeni kesinliği` | §1.1 ölçüm zemini (126); G4 (352) | kanal kırılımı (`on_ad:gnulib`) |
| `Mac htop / tmux ad sayısı ve doğrusu` | A3 (172); §4 madde 3 (431) | `sonuc.md` program kırılımı |
| `süre — toplam; varsa ikili başına medyan` | E1 (287) | koşu kökü |

Başlıktaki (4) ve §6'daki (454) `⟨ÖLÇÜM: …⟩` / `⟨ÖLÇÜM⟩` kural metnidir, yer tutucu değil.

## Notlar
- Kaynaklarda bulunamayan sayı yazılmadı; her sayının yanında paket kimliği var (DURUM.md'nin o paketin satırı); DURUM.md'de olmayanlar için paket dosyası adı yazılı (`P12b.md`, `P16a.md`, `P13a.md`).
- Birleşik ölçüm dizini (`docs/arge/2026-11-19_birlesik_olcum/`) bu iş sırasında henüz yoktu; listeye yol olarak yazıldı.
- Liste 456 satır (sınır ~450).

## PAKET BİTTİ
