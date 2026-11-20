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
- Commit: `90cb08b`.

### Kalem 3 — `masum_kapi` `sarif` (bitti)

- Önce (çıktı kipi, `--katman sarif,yara_cikti`, ürün ağacı `~/karadul_olcum/urun-a62f15e`): a62f15e kökünde `sarif` 12 iddia, **12 yanlış**, 0 doğru bilinen (`KRDL001:OpenSSL_Library` 5, `KRDL007:GCC_Compiler` 2, `KRDL007:Zlib_Library` 2, `KRDL007:Zstd_Library` 2, `KRDL007:LZ4_Library` 1); aynı isabetler `yara_cikti`'de 12 / 12 doğru bilinen. f30ac9a (1.22.1) kökünde `sarif` 81 iddia, 81 yanlış (hepsi KRDL003 "SuspiciousPattern"; 11'i `yara_cikti`'de doğru bilinen kural: GCC 2, OpenSSL 5, Zstd 2, Zlib 2).
- Kök neden: SARIF'teki YARA sonucunun etiketi `KRDL00x:<kural>`; `dogru_iddialar`'ın YARA kuralları `katman: yara`, `etiket_re: ^kural:<ad>$`. `_uyar` `sarif` katmanını `yara`'ya eşlemiyor ve etiket biçimi uymuyor → hiçbir doğru iddia kuralı `sarif`'e uygulanmıyordu.
- Onarım: `scripts/measurement/masum_kapi.py` — `_sarif_yara_kurali` (P07 sonrası `properties.source == "yara"` + `yara_rule`; öncesi `technology_name`), `cikti_sarif` iddiaya `yara_kurali` yazar (aynı etikette YARA dışı sonuç varsa yazmaz), `hukumle` → `_sarif_yara_dogru`: SARIF kategorisi bilgi düzeyindeyse (`_SARIF_YARA_BILGI_KURALLARI` = KRDL001, KRDL007) iddia `yara` katmanının doğru iddia kuralıyla (`kural:<ad>`, ikili listesi ve set dahil) hükme bağlanır. Şüpheli / paketli / gizlenmiş / zararlı kategorisindeki (KRDL003–006) aynı isabet yanlış suçlamadır, yanlış kalır. Eşik dosyasına (`masum_kapi_esik.json`) dokunulmadı.
- Sonra: a62f15e `sarif` yanlış **12 → 0**, doğru bilinen **0 → 12** (masum set); f30ac9a `sarif` yanlış **81 → 81** (doğru kural, yanlış kategori: kontrol seti, değişmedi), doğru bilinen 0 → 0. `yara_cikti` iki kökte değişmedi (0 / 12; 70 / 11). Kapı çıkışı iki kökte 0. Çıktılar: `~/karadul_olcum/runs/dalga0-2026-11-20/OLCUM/k3/{once,sonra}_{a62f15e,f30ac9a}/`.
- **Eşik nasıl yazılır (ana oturumun işi; bu paket yazmadı):** onarım main'e alındıktan sonra, ana ağaç kökünden
  - `sarif` için (öbür katmanlara dokunmadan): `PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/masum_kapi.py --agac ~/karadul_olcum/urun-a62f15e --kosu ~/karadul_olcum/runs/urun-onarim-a62f15e --kosu-seti gelistirme --katman sarif --cikti-dizin ~/karadul_olcum/runs/onarim-2026-11-19/OLCUM/masum_cikti_sarif` ve ardından `python scripts/measurement/masum_kapi.py --esik-yaz ~/karadul_olcum/runs/onarim-2026-11-19/OLCUM/masum_cikti_sarif/masum_kapi.json` (beklenen: `cikti/sarif/gelistirme: yanlış 0 (119 ikili)`).
  - OKU.md'deki öbür katmanların eşiği (`--esik-yaz ~/karadul_olcum/runs/onarim-2026-11-19/OLCUM/masum_cikti/masum_kapi.json`) eski kodla üretilmiş JSON'dan `sarif`'i 12 diye yazar: o komut koşulacaksa ÖNCE o, SONRA yukarıdaki `sarif` komutu koşulmalı (son yazan kazanır), ya da çıktı kipi bütün katmanlarla yeni kodla yeniden koşulup tek `--esik-yaz` yapılmalı.
- Test: `tests/test_olcum_araci_d0.py` +2 (gerçek eşik dosyasının kurallarıyla: 7 iddia, 3 yanlış, 4 doğru bilinen; `yara_kurali` alanı ve karışık kaynak; pozitif sette hüküm değişmez). `tests/test_masum_kapi.py` 21 / 21 yeşil. Mutant: kalem 3'ün 5'i 5 / 5 öldü (biri ilk yazımda hayatta kaldı: küme sırası yüzünden `None` seçiliyordu; tanım düzeltildi); var olan `mutation_specs_p00.json` 41 / 41 öldü.
- Commit: `d184113`.

### Kalem 4 — `saglamlik_denetle` "yazıldı" (bitti)

- Önce (`saglamlik_denetle.py --kok ~/karadul_olcum/runs/urun-onarim-a62f15e --is 6`, eski kod): 119 / 119 ikilide `log_yazildi_satiri_yok`; buna bağlı `sayi:log_yazilan_dosya` 119 ve `sayi:log_kaynak_dosya` 119 (günlükteki sayı okunamadığı için "eşit değil"); `yazilan` okunan 0 / 119. Neden: bugünkü ürün (`karadul/cli.py:488`) satırı Türkçe yazıyor (`OK n dosya yazıldı (…)`), düzenli ifade ASCII `yazildi` arıyordu.
- Onarım: `scripts/measurement/saglamlik_denetle.py` — modül sabiti `LOG_YAZILDI_RE` (`yaz[ıi]ld[ıi]`: iki yazım), K1 günlük okuması onu kullanır. Kusur adı (`log_yazildi_satiri_yok`) değişmedi.
- Sonra: a62f15e `log_yazildi_satiri_yok` **119 → 0**, `sayi:log_yazilan_dosya` **119 → 0**, `sayi:log_kaynak_dosya` **119 → 0** (119 ikilide günlükteki sayı diskteki dosya sayısıyla eşit), `yazilan` okunan 0 → 119; öbür kusur sayıları aynı. f30ac9a (ASCII günlük, denetim): `log_yazildi_satiri_yok` 0, `yazilan` okunan 119 / 119; `sayi:log_*` 1 (debian/zstd/pzstd: günlük 12 762 dosya, disk 1 206; 1.22.1 çıktısının kendi tutarsızlığı, araç kusuru değil). `genel-tarama-2026-11-18` kökü silinmiş (e8d993a), ölçüm a62f15e ve f30ac9a'da. Çıktılar: `~/karadul_olcum/runs/dalga0-2026-11-20/OLCUM/k4/`. Yük altında (8:45 `uptime` yük 15,2 / 12,0 / 9,7); süre 131 / 116 sn (karar dışı).
- Test: `tests/test_saglamlik_denetle.py` +1 (Türkçe ve ASCII satır, "yazılamadı" eşleşmez, sentetik koşuda günlük sayıları okunur); 12 geçti / 1 atlandı (atlanan: `genel-tarama` kökü yok). Mutant: kalem 4'ün 2'si 2 / 2 öldü; `mutation_specs_p00.json` (içinde `saglamlik_denetle` mutantları da var) bu değişiklikten sonra yeniden koşuldu: 41 / 41 öldü.
- Not: düzenleme sırasında `~/.claude/hooks/check-consistency.sh` `ORNEK_SINIRI` (saglamlik_denetle 5 ↔ akis_sadelestirme_olcum 40) uyarısı verdi; iki betikte ayrı kavram, bu paketten önce de vardı, dokunulmadı.
- Commit: `561b76c`.

### Kalem 5 — `function_f1.read_elf_info` not sahibi (bitti)

- Önce: `read_elf_info` notun sahibine bakmıyordu; pyelftools SystemTap notunu (sahibi `stapsdt`, tür 3) da `NT_GNU_BUILD_ID` diye etiketliyor, son gelen not kazanıyordu. `ozkod_nufus/nufus.json`'daki seçilen 86 ELF'te (ayar 9, kör 77) `read_elf_info` BuildID'si `tabaka_indir.elf_bilgisi`'ninkinden farklı olan: **2** (ayar 1 = postgresql-17, kör 1 = python3.13-minimal; NUFUS.md §8 not 3 ile aynı). Bu iki ELF'te ikili ve `.debug` dosyasının dördünde de dönen değer bir bayt dizisiydi (stapsdt notunun gövdesi), BuildID değil; ikili ↔ `.debug` "eşit" çıkıyordu çünkü ikisinde de aynı stapsdt notu var (`extract_gt`'nin BuildID denetimi yanlış şeyi karşılaştırıp geçiyordu).
- Onarım: `scripts/measurement/function_f1.py` `read_elf_info` — `note["n_type"] == "NT_GNU_BUILD_ID" and note["n_name"] == "GNU"`.
- Sonra: 86 ELF'te farklı **2 → 0**; iki ELF'in ikili ve `.debug`'ında (4 dosya) `read_elf_info` = `elf_bilgisi` (BuildID önekleri ayar `7ec6760ecbf3`, kör `9e7f76dabfdf`), ikili ↔ `.debug` gerçek GNU BuildID'siyle eşit. Kör paketin yalnız BuildID'si ve sayılar basıldı (yol, ad, dizgi basılmadı). Geliştirme setinde etki yok: `urun_olc` iki kolda kalem 2 çıktısıyla `arac` dışında aynı (GT `read_elf_info` üstünden yükleniyor).
- Test: `tests/test_olcum_araci_d0.py` +1, sentetik ELF64 (iki `SHT_NOTE` bölümü: GNU BuildID, sonra stapsdt; ters sıra; yalnız stapsdt → `None`). `tests/test_function_f1.py` 31 / 31 yeşil. Mutant: kalem 5'in 1'i 1 / 1 öldü; var olan `mutation_specs_function_f1.json` 18 / 18 öldü.
- Not: `function_f1.py` da KS-1 ön kaydının sabitlediği dosyalardandır (kalem 2 notu).
- Commit: `2daed48`.

### Kalem 6 — `urun_kos` künyesi (bitti)

- Önce: `kosu_kunyesi.json`'da `KARADUL_CACHE_DIR` yok, imza veritabanının yolu ve şeması yok (a62f15e künyesinde de yok; `CALISMA_VERISI` yalnız `signatures.lmdb`'nin VARLIĞINI şart koşuyordu).
- Onarım: `scripts/measurement/urun_kos.py` — (a) künyeye `KARADUL_CACHE_DIR` (ortamdaki değer; yoksa `null` = ürünün öntanımlı önbelleği); (b) yeni `imza_vt_kunyesi(agac)`: ürün ağacının kendi çözücüsüyle (`karadul.config.resolve_data_root` + `resolve_sig_lmdb_path`; ürünün koşu ortamıyla aynı `PYTHONPATH` / cwd, ayrı süreç) açılacak veritabanının yolu, yolun kaynağı ve `meta` kayıtları (`schema_version`, `build_id`, `source_hash`, `build_time`); salt okur, kilitsiz; okunamayan alan `null`, nedeni `hata`'da; asla hata fırlatmaz. (c) `agac_kunyesi(agac)` dönüşüne yalnız `imza_vt` alanı eklendi (imza ve var olan beş alan aynı; sınandı); (d) bitişte `imza_vt_degisti` (koşu sırasında veritabanı yolu ya da künyesi değişti mi). `agac_degisti`'nin anlamı değişmedi.
- Sonra (Ghidra koşusu yok; `imza_vt_kunyesi` gerçek ürün ağaçlarında, ~0,17 sn): `urun-b6aceb9` ve `urun-a62f15e` → `~/karadul_olcum/sigdb/s2-20261118/signatures.lmdb`, kaynak `data_root:signatures.lmdb`, şema `2`, `build_id` `s2-b32ee9f65b1a-20261118`; `urun-f30ac9a` (1.22.1) → okunamadı: `ImportError: cannot import name 'resolve_data_root'` (o sürümde çözücü yok; alanlar `null`, uydurulmadı). `KARADUL_CACHE_DIR` alanı sentetik `main` koşusuyla sınandı (gerçek koşu bu pakette yok).
- Test: `tests/test_olcum_araci_d0.py` +3 (sahte ürün ağacı + gerçek küçük LMDB: şema 2 / künyesiz / çözücüsüz; `agac_kunyesi` imzası ve alan kümesi, geçici git deposunda; `main` künyesi: önbellek dizini, `imza_vt_degisti`, var olan alanlar). `tests/test_p15b_kismi_cikis.py` (urun_kos) 5 / 5 yeşil. Mutant: kalem 6'nın 5'i 5 / 5 öldü.
- Commit: `3d57fee`.

### Kalem 7 — `urun_olc` sınıflayıcı sürümü (bitti)

- Önce: `urun_olc` ad sınıflayıcısını (`naming_labels.py`, `alt_kanal.py`) betiğin ağacından alıyor, ölçülen ürünle aynı olup olmadığına bakmıyordu. Gösterim: kalem 1'de f30ac9a kökü worktree sınıflayıcısıyla ölçüldüğünde sessizce bitti ve `kanal_grubu` eski ölçümden 92 alanda farklı çıktı (birim 64, toplam 28; ör. debian/tmux "kalan" ad 295 → 194). Uyarı yoktu.
- Onarım: `scripts/measurement/urun_olc.py` — `kok_kunyesi` (kökte ya da üstünde `kosu_kunyesi.json`: `agac.commit` / eski N1 `commit`; ol7 Mac `session.json`), `commit_siniflayicisi` (ürün commit'indeki iki dosyanın sha256'sı, depodan `git show`), `siniflayici_denetle` (kök başına `ayni` / `farkli` / `denetlenemedi` + neden), `siniflayici_farki`; `olc` CLI'ı fark varsa **durur** (çıkış 2, `DURDU: ad sınıflayıcısı ölçülen ürününkiyle farklı …`). Yeni seçenek `--siniflayici-agac <ürün ağacı>`: iki modül o ağaçtan yüklenir (`siniflayici_modulleri`: `alt_kanal`'ın içe aktardığı `naming_labels` da o ağacınki; `sys.modules` sonra geri gelir; `siniflayiciyi_kur` türeyen sabitleri de günceller). Çıktıya `siniflayici` alanı ve Markdown satırı. Denetlenemeyen kök (künye ya da commit yok; sınıflayıcı koşu anında kirli; ürün commit'inde dosyalar yok) durdurmaz ama yazılır. `karsilastir` değişmedi.
- Sonra: f30ac9a kökü worktree sınıflayıcısıyla → **DURDU** (çıkış 2); `--siniflayici-agac ~/karadul_olcum/urun-f30ac9a` ile → iki kök `ayni`, çıktı eski `urun_olcumu_yeni2.json` ile yeni alanlar / `arac` / `kol` dışında metin olarak **aynı** (P-Ö1'in ertelenen bayt denetimi tuttu; P-O1.md). a62f15e kökü betiğin sınıflayıcısıyla → `ayni`, eski çıktıyla aynı. Eski kökler: `n1_debian13` (a10fde3) ve ol7-c (b7faeac) → `denetlenemedi` ("ürün commit'inde naming_labels.py, alt_kanal.py yok"; o sürümlerde alt kanal zaten betiğin sınıflayıcısıyla sonradan sınıflanıyordu); `urun-yeni-93a2956` → `farkli` (bu kök artık seçeneksiz ölçülemez). `karsilastir` eski JSON'la çalıştı, birleşik ölçümün fark dosyasıyla (yeni alanlar, `arac`, `kol` dışında) aynı.
- Test: `tests/test_olcum_araci_d0.py` +4 (künye biçimleri; denetim durumları gerçek commit'lerle: HEAD / f30ac9a / a10fde3 / olmayan / kirli / künyesiz; ürün ağacından modül yükleme ve `sys.modules`'ün geri gelmesi; CLI: farkta durur, seçenekle ölçer). `tests/test_urun_olc.py` 36 / 36. Mutant: kalem 7'nin 5'i 5 / 5 öldü. Bu kalemden sonra bütün tanımlar yeniden koşuldu: `mutation_specs_olcum_araci.json` 26 / 26, `mutation_specs_po1.json` 7 / 7, `mutation_specs_urun_olc.json` 65 / 65 öldü.
- Commit: `45fca9c`.

### Tam takım

- 09:07: tam takım başlıyor (worktree kökünden; çalışma verisi bağları kuruldu, commit'lenmedi). Yük altında (`uptime` 8,1 / 12,0 / 13,4); TAHMİNİ bitiş 09:20–09:35. Günlük: `~/karadul_olcum/runs/dalga0-2026-11-20/OLCUM/tam_takim.log`.
- Sonuç (`PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider`, `45fca9c`): **10 322 geçti / 11 atlandı / 0 kaldı** (152 seçim dışı; 591 sn, yük altında). Taban b6aceb9: 10 289 / 11; fark +33 = bu paketin yeni sınamaları (`test_ad_bicimi` 9, `test_urun_olc` +4, `test_olcum_araci_d0` 19, `test_saglamlik_denetle` +1).

## Özet

| Kalem | Durum | Önce → sonra | Test | Mutant | Commit |
|---|---|---|---|---|---|
| ön kayıt | — | — | — | — | `992c9cc` |
| 1 P-Ö1 biçim satırı | bitti | altı sayının altısı tuttu; var olan alanlar iki kolda eski çıktıyla aynı (f30ac9a kalem 7'den sonra) | +13 | po1 7 / 7 | `4125a04` |
| 2 `ks1_olc` `BITTI` | bitti | gerçek köklerde 119 tamam → 119 tamam (kısmi / hatalı yok); sentetikte kısmi / hatalı / Mac `BITTI`'siz artık bitmiş sayılmaz | +9 | 8 / 8 | `90cb08b` |
| 3 `masum_kapi` `sarif` | bitti | a62f15e yanlış 12 → 0 (doğru bilinen 0 → 12); f30ac9a 81 → 81 (kontrol) | +2 | 5 / 5 | `d184113` |
| 4 `saglamlik_denetle` "yazıldı" | bitti | a62f15e `log_yazildi_satiri_yok` 119 → 0, `sayi:log_*` 119 → 0 | +1 | 2 / 2 | `561b76c` |
| 5 `read_elf_info` not sahibi | bitti | 86 ELF'te farklı BuildID 2 → 0 | +1 | 1 / 1 | `2daed48` |
| 6 `urun_kos` künyesi | bitti | künyede önbellek dizini ve imza VT künyesi yok → var (şema 2, `s2-b32ee9f65b1a-20261118`) | +3 | 5 / 5 | `3d57fee` |
| 7 `urun_olc` sınıflayıcı | bitti | f30ac9a sessizce yanlış sınıflanıyordu (92 alan) → durur; seçenekle eski çıktıyla aynı | +4 | 5 / 5 | `45fca9c` |

Var olan tanımlar (son kodla): `urun_olc` 65 / 65, `ks1` 67 / 67, `p00` 41 / 41, `function_f1` 18 / 18 öldü.

**Yamalar:** yok (her değişiklik bu paketin dosyalarında).

**Riskler ve ana oturumun bilmesi gerekenler:**
1. `ks1_olc.py` ve `function_f1.py` KS-1 ön kaydının sabitlediği dosyalar (`OLCUM_DOSYALARI`). Bu paketten önce `ks1_olc.py olc` sapma kaydı 1'in sha256'larıyla tutuyordu; şimdi durur. KS-1 ölçümü yeniden koşulacaksa yeni sapma kaydı (`ks1_sapma_2`) gerekir. `urun_olc` / `taban_dok` bu denetimi yapmaz, etkilenmez.
2. `masum_kapi` `sarif` eşiği yazılmadı; komut kalem 3'te. Eski çıktı JSON'undan (`onarim-2026-11-19/OLCUM/masum_cikti/`) `--esik-yaz` yapılırsa `sarif` 12 yazılır; önce o, sonra `sarif`'e özel yeni çıktı (son yazan kazanır).
3. Kalem 7'den sonra sınıflayıcısı bugünkünden farklı bir ürünün kökü (`urun-yeni2-f30ac9a`, `urun-yeni-93a2956` …) `urun_olc olc` ile seçeneksiz ölçülemez: `--siniflayici-agac <o ürünün ağacı>` gerekir. Bilerek böyle (sessiz yanlış sınıflama yerine durma). Sınıflayıcı dosyası olmayan eski kökler (`n1_debian13`, ol7) durmaz, `denetlenemedi` yazılır.
4. `ks1_olc` BITTI kuralında iki bilerek gevşek durum (boş `BITTI`, işaretsiz Mac dizini; yalnız sentetik köklerde; özete ayrı işaretle girer). Gerçek köklerde sayısı 0.
5. Aynı kusur deseni başka yerde: `masum_kapi.kosu_ikilileri` `BITTI`'nin yalnız varlığına bakıyor (kısmi `3` bitmiş görünür). Bu paketin kalem listesinde yoktu; dokunulmadı (ayrı küçük iş).
6. `urun_kos.agac_kunyesi` artık imza VT künyesi için ayrı bir Python süreci açıyor (~0,2 sn; LMDB salt okur, kilitsiz, bütünlük karması yok). Çözücüsü olmayan eski ağaçta `hata` alanı doludur, işlev hata fırlatmaz.
7. Worktree'de çalışma verisi bağları (`sigs`, `vendor`, `scripts/node_modules` git'te izlenmeyen olarak görünüyor) duruyor; commit'lenmedi.

Disk: 740,4 GB (08:23) → 746,0 GB (09:2x; ortak makine). Bu paketin çıktısı `~/karadul_olcum/runs/dalga0-2026-11-20/OLCUM/` 8,5 MB.

## PAKET BİTTİ
