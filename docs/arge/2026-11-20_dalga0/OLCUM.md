# OLCUM — ilerleme (Dalga 0; P-Ö1 → ölçüm aracı kusurları)

Gönderim: `docs/arge/2026-11-20_dalga0/gonderim/OLCUM.md`. Dal tabanı `e996200` (`git merge --ff-only main`; `karadul.__file__` worktree'de). Ghidra koşusu yok; her sayı hazır çıktılardan (salt okur). Disk başta: 740,4 GB kullanılmış (2026-11-20 08:23).

## Ön kayıt ve beklentiler (kod yazılmadan önce; ayrı commit)

- P-Ö1 ön kaydı: `docs/arge/2026-11-19_mythos/olcu/P-O1_on_kayit.md` (PLAN.md metni aynen + karşılaştırma kuralı).
- Kalem 2–7 için "göster" sayımı kod yazılmadan yapıldı; beklenen "sonra" sayıları aşağıda, ölçümden önce:

| Kalem | Önce (sayıldı, 2026-11-20) | Beklenen sonra |
|---|---|---|
| 2 `ks1_olc` `BITTI` | a62f15e ve f30ac9a kökünde `BITTI` 119 / 119, içerik hepsinde `0`. Eski `n1_debian13` kökünde 117 / 117 `ok <sn>` (eski koşucu biçimi). `~/karadul_olcum/runs` ve `n1_debian13`'teki 579 `BITTI`'nin 459'u `0`, 117'si `ok`, 2'si `gosteri` dizininde (urun_kos düzeni değil). Bugün kısmi (`3`) içerik hiçbir kökte yok; Mac birimlerinde `BITTI` okunmuyor (2 / 2 yalnız `ws/` ile bitmiş sayılıyor). | İki kolda biten 119, kısmi 0, hatalı 0; P-Ö1 sayıları değişmez. Sentetik kökte `3` / hatalı içerik / Mac'te `BITTI` yokluğu bitmiş sayılmaz ve özete girer. |
| 3 `masum_kapi` `sarif` | a62f15e çıktı kipinde `sarif` yanlış 12 (`KRDL001:OpenSSL_Library` 5, `KRDL007:GCC_Compiler` 2, `KRDL007:Zlib_Library` 2, `KRDL007:Zstd_Library` 2, `KRDL007:LZ4_Library` 1; birleşik ölçüm `masum_kapi_cikti.md`). Kök neden: SARIF'teki YARA sonucunun etiketi `KRDL00x:<kural>`, `dogru_iddialar`'ın YARA kuralları `kural:<kural>` biçimini ve `yara` katmanını arıyor; `sarif` katmanına hiçbir doğru iddia kuralı uymuyor. | a62f15e: `sarif` yanlış 12 → 0, doğru bilinen 0 → 12. f30ac9a (1.22.1): YARA isabetinin şüpheli / paketli / gizlenmiş diye (KRDL003 / 004 / 005) raporlandığı iddialar yanlış kalır (kategori yanlış iddiadır); bu kolda yanlış sayısı ölçümle yazılır. |
| 4 `saglamlik_denetle` "yazıldı" | a62f15e kökünün 119 `kosu.log`'unun 119'unda `OK n dosya yazıldı (…)` satırı Türkçe; betiğin düzenli ifadesi `yazildi` (ASCII) → 119 / 119 `log_yazildi_satiri_yok`. f30ac9a kökünde 119 / 119 ASCII `yazildi`. | a62f15e: `log_yazildi_satiri_yok` 119 → 0, `yazilan` / `kaynak` / `rapor` sayıları 119 ikilide okunur; f30ac9a: 0 → 0. |
| 5 `function_f1.read_elf_info` | NUFUS.md §8 not 3: 86 seçilen ELF'ten 2'sinde (postgresql-17 / ayar, python3.13-minimal / kör) BuildID stapsdt notundan. | İki ELF'te `read_elf_info` BuildID'si `tabaka_indir.elf_bilgisi`'ninkiyle eşit (önce: 2 / 2 farklı). |
| 6 `urun_kos` künyesi | `kosu_kunyesi.json`'da `KARADUL_CACHE_DIR` ve imza VT şeması yok (a62f15e künyesinde de yok). | Künyede iki yeni alan; var olan alanlar ve `agac_kunyesi(agac)` imzası aynı. |
| 7 `urun_olc` sınıflayıcı | Betik, ölçülen ürün ağacının sınıflayıcısıyla aynı olup olmadığına bakmıyor. Worktree ↔ `urun-f30ac9a`: `naming_labels.py` ve `alt_kanal.py` sha256 farklı. | f30ac9a kökünü worktree sınıflayıcısıyla ölçmek DURUR (hata); ürün ağacından yükleme seçeneğiyle eski `urun_olcumu_yeni2.json`'un var olan alanları bayt düzeyinde yeniden üretilir. |

## Kalemler

(her kalem bitince aşağıya eklenir: önce → onarım (dosya:satır) → sonra → test / mutant → commit)

### Kalem 1 — P-Ö1 biçim satırı (bitti)

- Ön kayıt `992c9cc`. Ayrıntı ve kabul tablosu: `docs/arge/2026-11-19_mythos/olcu/P-O1.md`.
- Onarım: yeni `scripts/measurement/ad_bicimi.py`; `urun_olc.py` `degerlendir_elf` (`bicim` alanı), `fonksiyon_ozeti` (`bicim_normallestirmesi`, `bicim_yanlis_orani`), `DUYARLILIK_OLCULERI`, `bicim_cumlesi` + iki Markdown. `ks1_olc.py`'ye dokunulmadı.
- Sonuç: **altı sayının altısı tuttu** (a62f15e: biçim 40, yanlış 79 / 1 800, makro 0,1914; f30ac9a: biçim 47, yanlış 625 / 2 261, makro 0,4077). a62f15e'de var olan alanlar bayt düzeyinde aynı (`arac` dışında); f30ac9a'da yalnız `kanal_grubu` farklı (sınıflayıcı sürümü; kalem 7'de yeniden denetlenecek).
- Test: `tests/test_ad_bicimi.py` 9 yeni; `tests/test_urun_olc.py` +4 (36 / 36 yeşil). Mutant: `mutation_specs_po1.json` 7 / 7 öldü; `mutation_specs_urun_olc.json` 65 / 65 öldü.
- Commit: `4125a04`.

### Kalem 2 — `ks1_olc` `BITTI` (bitti)

- Önce: (a) `debian_elfleri` yalnız `BITTI`'nin varlığına bakıyordu: `urun_kos`'un kısmi koşuya yazdığı `3` bitmiş sayılıyordu; (b) `mac_elfleri` `BITTI`'ye hiç bakmıyordu (yalnız `ws/`): `urun_kos` düzeninde başarısız ya da süren Mac koşusu (`kosu.log` var, `BITTI` yok) bitmiş sayılıyordu. Gerçek köklerde sayı: a62f15e ve f30ac9a `BITTI` 119 / 119 `0`; `n1_debian13` 117 / 117 `ok <sn>`; ol7 Mac 2 / 2 `run.json` (kısmi ya da hatalı birim yok).
- Onarım: `scripts/measurement/ks1_olc.py` — yeni `bitti_durumu` (içerik: `0` ve eski `ok …` tamam; `3` kısmi; başka içerik hatalı; Mac'te `BITTI` yoksa eski `run.json`, `urun_kos` düzeninde (`kosu.log`) bekliyor), `Elf.durum` / `Elf.isaret` (öntanımlı alanlar; var olan çağrılar değişmedi), `mac_elfleri` / `debian_elfleri` bunu kullanır, `nufus_denetle` özetine `durumlar` (tamam / kısmi / hatalı / bekliyor / çıktısız) ve `bitti_isareti` girer; sorun metni "n ELF bitmemiş ya da hatalı (kısmi n, hatalı n, bekliyor n)". `urun_olc.py` Markdown'a "Bitmişlik" satırı (`bitmislik_cumlesi`).
- **Bilerek gevşek bırakılan iki durum** (gerçek koşu düzeninde yok, yalnız sentetik sınama köklerinde): içi boş `BITTI` ve hiçbir işareti olmayan Mac dizini bitmiş sayılır; işaret biçimi özete `bos` / `isaretsiz` diye ayrı yazılır. Neden: var olan sınama kökleri (`tests/test_urun_olc.py`, `tests/test_harita_olc.py`, `tests/test_ks1_olc.py`) bu biçimle kuruluyor ve iki dosya bu paketin yalnız ek yapabildiği / hiç dokunamadığı dosyalar. Gerçek köklerde sayısı 0 (yukarıdaki sayım).
- Sonra: iki kolda bitmişlik 119 / 0 / 0 / 0 / 0, işaret `0` × 119; P-Ö1'in altı sayısı değişmedi (P-O1.md'ye satır eklendi). Eski kökler (`n1_debian13` + ol7-a / ol7-c) 119 tamam (`ok` × 117, `run.json` × 2).
- Test: `tests/test_olcum_araci_d0.py` (yeni) kalem 2 için 9 sınama (parametreli dahil); `test_ks1_olc` / `test_urun_olc` / `test_harita_olc` yeşil (157 / 157 ilgili). Mutant: `mutation_specs_olcum_araci.json` kalem 2'nin 8'i 8 / 8 öldü; var olan `mutation_specs_ks1.json` 67 / 67 öldü.
- Not: `ks1_olc.py` KS-1 ön kaydının sabitlediği dosyalardandır (`OLCUM_DOSYALARI`); `ks1_olc.py olc` (KS-1 ölçümü) artık sapma kaydı 1'in sha256'sıyla tutmaz ve durur. KS-1 ölçümü yeniden koşulacaksa yeni bir sapma kaydı gerekir (ana oturuma risk olarak bildirildi). `urun_olc` bu denetimi yapmaz.
