# Kapanış denetimi (yayın kapısı Y3) — salt okur

Opus denetim paketi (2026-11-19). İki ajan, kulvarlar ayrık. Kod ve belge değiştirmiyorsun; yalnız kendi rapor dosyanı yazıyorsun.

## Amaç

Genel taramanın (2026-11-18) 137 bulgusu ve 105 küçük kaleminin bugünkü main'deki (HEAD) durumunu tek tabloda göstermek. Yayın kararı bu tabloya bakılarak verilecek.

## Kaynaklar

- Bulgular: `docs/arge/2026-11-18_genel_tarama/DIZIN.md` (137 bulgu; kimlik, önem, kulvar), `RAPOR.md`, kulvar dosyaları (`kulvar_*.md`; küçük kalemler orada).
- Onarım kaydı: `docs/arge/2026-11-18_onarim/DURUM.md` (paket tablosu, kararlar K-1…K-10), paket dosyaları `P*.md`, `gonderim/OKU.md` (kalanlar, atanmamış bulgular), `gonderim/OTURUM_2026-11-19.md`.
- Taban ölçümü: `docs/arge/2026-11-19_birlesik_olcum/sonuc.md`.

## Kulvarlar

- **Ajan A** (`docs/arge/2026-11-19_yayin/denetim_A.md`): BORU, AD, TIP, IMZA, MUH.
- **Ajan B** (`docs/arge/2026-11-19_yayin/denetim_B.md`): ARAYUZ, LM, BICIM, GHIDRA, MEK.

Kulvar adları `DIZIN.md`'deki öneklerdir; önek listesi farklıysa gerçeğini kullan ve raporun başına yaz.

## Kalemler

1. Kulvarlarının her bulgusu için bir satır: kimlik | önem | durum | kanıt.
   - **Durum:** `kapandı` / `kısmen` / `bekletildi (K-1…)` / `açık` / `gereksizleşti`.
   - **Kanıt:** kapatan paket ve commit'i; **kritik ve yüksek** bulgularda ayrıca bugünkü koddan doğrulama (dosya:satır ya da çalıştırdığın salt okur komut ve çıktısı). "DURUM.md öyle diyor" kritik / yüksek için yetmez.
2. Orta ve düşük bulgularda onarım kaydına dayanabilirsin; kaydı olmayan bulgu `açık` sayılır.
3. Küçük kalemler (kulvar dosyalarından): aynı tablo, kısa.
4. **Yayını durduranlar listesi:** açık ya da kısmen kalan kritik / yüksek bulgular; her biri için tek cümle: kullanıcıya etkisi ne, onarımı hangi dosyalara değer.
5. **Ertelenebilirler:** açık kalan orta / düşük; yayın notunun "bilinen kusurlar" bölümüne girecek biçimde birer satır.
6. Sayım özeti: önem × durum tablosu.

## Kurallar

- Salt okur: `karadul/`, `tests/`, `scripts/`, belgeler değişmez. Yalnız kendi `denetim_*.md` dosyanı yaz.
- Git'te durumu değiştiren komut yok. Ghidra koşma; ağır test koşma (tek dosyalık `pytest` denemesi olur). Tam takım koşma.
- Kilitli setlere (`targets/test_seti`, `targets/dogrulama_seti`) dokunma. İndirme, silme yok. Alt ajan ya da codex çağırma.
- Emin olamadığın satıra `doğrulanamadı` yaz ve nedenini belirt; tahmini "kapandı" yazma.
- Türkçe yaz; Türkçe karakterleri doğru kullan.
- Çalışırken dosyayı kulvar kulvar yaz (yarıda kalırsan kalan kulvar belli olsun). Son mesaj: sayım özeti + yayını durduranlar + `## DENETİM BİTTİ`.
