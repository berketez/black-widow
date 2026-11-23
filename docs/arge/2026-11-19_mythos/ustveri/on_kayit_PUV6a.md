# Ön kayıt — P-ÜV6a (Go ve ObjC üst veri adlarının ürün çıktısına bağlanması)

Yazıldı: 2026-11-23, ölçümden ve kanal kodundan önce. Metin gönderim metninden (`docs/arge/2026-11-23_dalga1/gonderim/PUV6a.md` "Ön kayıt") aynen alındı; sayılar değiştirilmez. Tutmayan hüküm silinmez; neden ilerleme dosyasına (`P-UV6a.md`) ayrıca yazılır.

## Hükümler

> H1 (öntanım değişmez): bütün bayraklar kapalıyken S8'in 5 ikilisinde (debian cat, tree, sqlite3, zstd; mac/tmux) `naming_map.json` tabanla bayt bayt aynı; `ghidra_output` ve `.c` farkı yalnız bilinen çağıran sırası (sıra-normal karşılaştırmada 0).
> H2 (düz C etkilenmez): dört bayrak açıkken aynı 5 ikilide değişen ad 0; iki kanalın durumu `veri_yok`.
> H3 (terminal-notifier, soyulmuş kopya, ürün koşusu, bayraklar açık): üst veri kaynaklı ad ≥ 30 / 32 ürün çıktısında (`naming_map` ve `out/src`); GT'ye göre yanlış 0; ad bekleyen 40 fonksiyonda doğru ad 0 → ≥ 30.
> H4 (Ollama arm64, gösteri çalışma alanı üstünde Ghidra'sız yeniden oynatma): `go_pclntab` kanalında `tuttu` ≥ 9 540 (P-ÜV8 H4); `pcsp_elendi` sayısı raporlanır (ilk ölçüm).
> H5 (Ollama ObjC, A-28): 151 yöntemin ≥ 140'ına tam ad yazılır (HEDEF: 148'i Ghidra'da yalnız seçiciyle adlı).
> H6 (docker-cli, keşif, Ghidra'sız aday listesi ↔ GT): süzgeçlerden geçen Go adaylarının ≥ %99,9'u GT ile aynı (`ozgun_ad` üstünden).
> H7 (etiket): üst veri kaynaklı hiçbir ad `kesin` etiketi taşımaz; hepsinde `label = üst veriden`, `ozgun_ad` dolu, güven tablodan.
> H8 (SINAMA; kurallar dondurulduktan sonra BİR kez, Ghidra'sız aday listesi ↔ GT): iTerm2'de süzgeçlerden (hüküm 3) geçen ObjC adaylarında yanlış ≤ %1 ve doğru ≥ 33 000; docker-compose'da Go adaylarında yanlış ≤ %0,1.
> H9 (süre): bayraklar kapalıyken iki adımın koşu süresine etkisi ≤ 0,1 sn / ikili.

## "Önce" sayıları (taban; yeniden koşulmadı, hazır kökten okundu)

| Hedef | Taban | Kaynak |
|---|---|---|
| terminal-notifier (soyulmuş, ürün `b6aceb9`, bayraklar öntanımlı) | ad bekleyen 40 fonksiyonda doğru ad **0 / 40**; ürünün ad verdiği fonksiyon 0; üst veri kanalından ad 0 | `docs/arge/2026-11-19_mythos/ustveri/olcum/HEDEF.md` kalem 4; ölçüm `~/karadul_olcum/runs/dalga0-2026-11-20/HEDEF/urun_terminal-notifier.json` |
| Ollama arm64 dilimi (gösteri koşusu) | 13 160 fonksiyonun 17'sine ad | gönderim metni "Neden bu paket ilk" (DURUM / ARGE kaydı) |
| Ollama Go girişi (Ghidra'da jenerik adlı, kanalın yazabileceği) | 10 457 / 10 600 (yok 28, thunk 112, adlı 3) | HEDEF.md P-ÜV9 kalem 1 G2 |
| Ollama ObjC yöntemi | 151; Ghidra 148'ini yalnız seçiciyle adlandırıyor | HEDEF.md G4 |

## Ölçüm tanımları (ön kayıt anında sabit)

- Ad eşitliği `scripts/measurement/ustveri_olc.py` kalem 2 kurallarıyla, `ozgun_ad` üstünden (Go: birebir / `.abi0` eki / orta nokta; ObjC: birebir / kategori soyma).
- "Ad bekleyen nüfus": HEDEF kalem 4'teki `ustveri_olc.urun_nufusu` (GT'de program sınıfı, Ghidra'da thunk olmayan ve jenerik adlı fonksiyon). A-28 adları (Ghidra'nın seçiciyle adlandırdığı) bu nüfusa girmez; ayrı satırda sayılır.
- Not (ön kayıt anında, ölçümden önce görülen gerilim; hüküm değiştirilmedi): HEDEF'e göre terminal-notifier'daki 32 ObjC IMP'inin 31'i Ghidra'da seçiciyle adlı, yani "ad bekleyen 40" nüfusunda değil; nüfustaki ObjC IMP 1. Bu tanımla H3'ün üçüncü yan cümlesi ("40 fonksiyonda doğru ad ≥ 30") tutmayabilir. Tanım ve eşik değiştirilmez; A-28 adları ayrı satırda raporlanır.
- Sınama ikilileri (docker-compose, iTerm2) kurallar dondurulmadan açılmaz; dondurma commit'i ilerleme dosyasına yazılır.
- Kanal düzeyi kesinlik tablosu (`MEASURED_METADATA_PRECISION`): Go docker-compose 90 077 / 90 077 (P-UV1.md), ObjC iTerm2 33 611 / 33 611 (P-UV2.md); Wilson alt sınırı betikle hesaplanır.
