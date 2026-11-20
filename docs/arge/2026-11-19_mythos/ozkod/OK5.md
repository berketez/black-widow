# OK5 — ÖK-V adım 5–6 → ÖK-5 kör ölçümü (ilerleme dosyası)

Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/OK5.md`. Plan: `ozkod/PLAN.md` "ÖK-V" (adım 5–7), "ÖK-5" (adım 1–8). Ortak brif: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`.

**Körlük.** Kör taraftaki paketlerin fonksiyon adları, dizgileri, kaynak kodu ve ELF yolları bu dosyaya, commit'lere ve ekrana yazılmaz; kör tarafta yalnız betik sayar ve yalnız sayı yazar.

## 0. Başlangıç (2026-11-20 08:15 +03)

- Worktree: `/Users/apple/Black_Widow/.claude/worktrees/agent-a6b44e6ccb8e6088a`; `git merge --ff-only main` → `e996200` (= `main`).
- `karadul.__file__` worktree yolunu gösteriyor.
- Dondurulmuş betiklerin sha256'ları (koşudan önce; DEFTER §4, §7, §10 ile karşılaştırıldı):

| betik | DEFTER | şimdi | aynı |
|---|---|---|---|
| `scripts/arge/ozkod/ek_kurali.py` | `7d02a6b58e05f2dc…` | `7d02a6b58e05f2dc8c70b8bb0764fd89b59e040079d7f470fca79ac6e994741c` | evet |
| `scripts/arge/ozkod/kayit_cifti.py` | `69201c56df4b10ed…` | `69201c56df4b10ed347d3ecfa88337c95b8ba3c68f6ea5dd2580ad22f91e9cbc` | evet |
| `scripts/arge/ozkod/ozkod_veri.py` | `8767bde0647f411f…` | `8767bde0647f411ff092469f6a7dfbd4f148a672d0552283cc63295f9e94e6a9` | evet |
| `scripts/arge/ozkod/oz_ad_ayrim.py` | `ccc73f5c5dbba90b…` | `ccc73f5c5dbba90b09f7b5657ea810c5cb24dc24ea375042d94059f22e8c541b` | evet |
| `scripts/arge/ozkod/oz_ad_uretici.py` | `7ee4edfc59265ea9…` | `7ee4edfc59265ea9cce522ab04a0503c9a3ded1fd4876047f9ced82035ac0acb` | evet |

- Disk (08:15): `739.6 GB (739641937920 Bytes)` kullanılan.
- Yük (08:15): `load averages: 3.98 5.12 5.08`.

## 1. ÖK-V adım 5 — taban ürün koşusu

- Koşucu: `scripts/measurement/ozkod_nufus_kur.py` yeni alt komutlar `kos-plan`, `kos` (tek ELF; kuyruğun içinde), `kos-hepsi` (bekleyen her ELF'i **ayrı** `~/karadul_olcum/ghidra_kuyruk.sh OK5 <paket>:eNN …` çağrısıyla), `kos-ozet`. Koşu `urun_kos.calistir` ile (içe aktarılır; komut `python -m karadul analyze <ikili> --skip-dynamic --output-dir <d>/ws --output <d>/out`, cwd ve `PYTHONPATH` = sabit ağaç), ikili başına sınır 3 600 sn; girdinin sha256'sı `nufus.json`'daki değerle karşılaştırılır.
- Ürün ağacı: `~/karadul_olcum/urun-b6aceb9` (`urun_kos.agac_kunyesi`: commit `b6aceb9bdad5…`, kirli 0, `karadul.__file__` = `~/karadul_olcum/urun-b6aceb9/karadul/__init__.py`, sürüm 1.24.1). Her koşudan önce yeniden denetlenir.
- Kök: `~/karadul_olcum/ozkod_nufus/runs/taban-b6aceb9/debian/<paket>/eNN/` (`ks1_olc.debian_elfleri` yerleşimi). ELF dizini adı paket içindeki sıra numarası: kör ELF'in dosya adı kuyruk günlüğüne de yazılmaz. `PYTHONHASHSEED=0`, `PYTHONDONTWRITEBYTECODE=1`, `KARADUL_CACHE_DIR=<kök>/cache`.
- Her koşu bitince `<d>/kunye.json` (durum, süre, yük başı / sonu, ağaç commit'i, BITTI içeriği); `BITTI` `urun_kos.calistir`'ın kuralıyla (0 tam, 3 kısmi; zaman aşımında yok, künyede `zaman_asimi`).
- `nufus.json` sha256: `65513ae4a8627e0d…` (NUFUS.md §7 ile aynı).

**İş listesi ve TAHMİNİ süre** (`kos-plan`; model: bugünkü S8 taban koşularından kaba okuma, alt 25 sn + 100 sn/MB, üst 60 sn + 250 sn/MB; ölçüm değildir):

| taraf | paket | ELF | toplam bayt | TAHMİN (sn) |
|---|---:|---:|---:|---|
| ayar | 9 | 9 | 17 032 912 | 1 928–4 798 (0,5–1,3 sa) |
| kör | 14 | 76 | 22 635 072 | 4 164–10 219 (1,2–2,8 sa) |
| **toplam** | 23 | 85 | 39 668 024 | 1,7–4,1 sa (kuyrukta başka paketlerin beklemesi hariç) |

En büyük iki iş: postgresql-17 (ayar, 10,3 MB; TAHMİN 1 052–2 628 sn) ve python3.13-minimal (kör, 6,7 MB; 692–1 728 sn). TAHMİN 6 saatin altında: BİLDİRİM gerekmedi. Disk TAHMİNİ (a62f15e çalışma alanlarından: ≈ 190–250 MB / MB ikili + küçük ikili başına onlarca MB) 8–14 GB; 20 GB sınırına yaklaşırsa durulur.

**Bekleme (08:2x):** şu an `kos-hepsi` arka planda; önce ayar (9), sonra kör (76). TAHMİNİ bitiş: kuyrukta başka paket yoksa 10:15–12:35 arası; başka paketler sıraya girdikçe kayar. Beklerken `ozkod_olc.py`, testler ve ön kayıt yazılıyor.

**Sayaç (08:42):** ayar 6 / 9 bitti (6 tamam; toplam 649 sn, yük altında), kör 0 / 76. Kuyrukta HZ1 ve OLCEK paketleri de var (işler aralanıyor). Disk: 742,5 GB kullanılan (başta 739,6); koşu kökü 1,2 GB.
**Bekleme (12:04):** kör 75 / 76 bitti (75 tamam, zaman aşımı 0, hata 0). Son iş python3.13-minimal (6,7 MB) 12:02'de başladı; TAHMİNİ bitiş 12:25–12:45 (sınır 13:02). Biten 75 kör ELF'in önbelleği kuruldu (hata 0); kör sayım bu işi bekliyor.

**Sayaç (11:38):** kör 69 / 76 bitti (69 tamam). Ana oturumun sert sınırı 15:15 (Berke'nin oturumu 16:00'da bitiyor): kalan 7 iş (en büyüğü python3.13-minimal) TAHMİNEN 12:10'a kadar biter; sonra kör önbellek, kör sayım, hükümler, döküm, tam takım. Yetişmeyen kalem olursa "kalan" diye yazılır; hükümler yalnız koşulan ELF'lerle ve kısmi olduğu belirtilerek verilir.

**Sayaç (11:17):** kör 40 / 76 bitti (40 tamam; 838 sn). 10:48'de ana oturum KIMLIK'in yeni koşularını OK5 kör işleri bitene kadar bekletti; 11:12'den beri kuyruk OK5'te. TAHMİNİ kör bitişi 11:50–12:20.

**Sayaç (10:50):** kör 27 / 76 bitti (27 tamam, zaman aşımı 0, hata 0; 538 sn). Kuyrukta KIMLIK'in uzun işleri (redis-cli, tmux) arasında bekleniyor; TAHMİNİ kör bitişi 12:00–13:30.

**Sayaç (10:22):** kör 11 / 76 bitti (11 tamam; 218 sn). Kuyruk payı arttı (10:12–10:22: OK5 ve KIMLIK sırayla); bu hızla kalan 65 iş TAHMİNEN 1,5–3 saat. Tam takım (ara, kod değişmedikçe son sayılır): 10 316 geçti / 11 atlandı / 0 kaldı (531 sn, yük altında; `~/karadul_olcum/runs/dalga0-2026-11-20/OK5/tam_takim_1.log`; çalışma verisi bağları worktree'de, commit'lenmedi).

**BİLDİRİM (10:09):** kör tarafın 76 işi 09:52'de kuyruğa girdi; 10:08'e kadar yalnız 2'si koşabildi (kuyrukta KIMLIK, HZ1, ANA, HEDEF işleri arasında; kilit boşalınca bekleyenlerden rastgele biri alıyor). Kendi işlerimiz küçük (ilk ikisi 19 ve 17 sn), darboğaz kuyruk payı: son 15 dakikada OK5 2 iş, öbür paketler 8 iş. Bu hızla (saatte ≈ 8 iş) kalan 74 iş ≈ 9 saat sürer; paketin toplamı 6 saati aşar (başlangıç 08:22). TAHMİN aralığı: öbür paketlerin işleri azalırsa 2–3 saat, bu yoğunluk sürerse 8–10 saat. Kör sayım ve hükümler kör koşuların bitmesini bekliyor; ayar dondurması (commit `4601218`) tamam. Ana oturumdan istek (karar onun): kuyrukta OK5'in küçük kör işlerine öncelik verilmesi ya da başka paketlerin işlerinin seyreltilmesi.

**Sayaç (09:33):** postgresql-17 hâlâ koşuyor (28 dk; yük 9–14); ayar 8 / 9, kör 0 / 76. Önbellek ayar tarafında 8 ELF için kuruldu (hata 0).

**Bekleme (09:06):** ayar 8 / 9 bitti (8 tamam; neomutt 528 sn, yük ≈ 16). postgresql-17 09:05:41'de başladı (kuyrukta ANA, HZ1, OLCEK işleri arasında); TAHMİNİ bitiş 09:45–10:05 (sınır 10:05:41; yük yüksek, zaman aşımı olasılığı var — olursa kayda geçer, ayar dondurması kalan 8 ELF'le yapılır). Kör tarafın 76 işi ardından; kuyruk paylaşıldığı için TAHMİNİ kör bitişi 12:30–14:30.

**Ortak scratchpad uyarısı (08:5x, ana oturum):** bu paketin geçici betikleri `<scratchpad>/OK5/` alt dizinine taşındı (`bekle.py`, `duman_gelistirme.py`, `nufus_yapi.py`, `sure_model.py`, `tekil_denetle.py`; hepsi yalnız betik, kör tarafa ait içerik yok — denetlendi). Ölçüm çıktıları baştan beri yalnız `~/karadul_olcum/runs/dalga0-2026-11-20/OK5/` ve `~/karadul_olcum/ozkod_nufus/runs/` altında; ortak adlı bir dosyadan sonuç okunmadı.

**Bekleme (08:43):** şu an ayar tarafının son üç işini bekliyorum (pidgin, neomutt, postgresql-17; postgresql-17 TAHMİN 1 052–2 628 sn). TAHMİNİ ayar bitişi 09:10–09:45; ardından `ozkod_olc.py kur --taraf ayar` ve `ayar` (G1 kapısı + K1 karakter eki dondurma).

## 3. ÖK-5 adım 1–2 — `ozkod_olc.py` ve geliştirme setinde eşdeğerlik

- `scripts/measurement/ozkod_olc.py` (yeni): kurallar `scripts/arge/ozkod/`'dan **içe aktarılır** (`ek_kurali.adaylar` / `tahmin` / `_ek_oyu` / `olc`, `kayit_cifti.say` / `gt_esit` / `ek_cikar`, `oz_ad_ayrim.ozellikler` / `kural_tut`, `oz_ad_uretici.g1`, `tavan.main`); yüklemeden önce beş dondurulmuş betiğin sha256'sı denetlenir (tutmazsa `DondurmaHatasi`, hiçbir şey sayılmaz). Parametre olan yalnız modül düzeyi veri kökleri ve birim listeleri (`etkin` bağlam yöneticisi; çıkışta eski değerler geri yüklenir). Ölçüm döngüleri (`ek_kurali_belirtec.py`, `ek_kurali_capa.py`, `oz_ad_harf.py` tanımları) betikte; her biri yalnız görünür tarafta döner.
- Taraf eşlemesi: ayar → araştırma betiklerinin `kesif`, kör → `sinama`. Kör sayımında ayar birim listesi boş (ve tersi): karışma yapısal olarak olanaksız.
- **Eşdeğerlik (zorunlu: keşif 754 / 740, sınama 126 / 103).** Komut `PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/ozkod_olc.py esdeger --onbellek yeniden`. Olgu önbelleği a62f15e koşusundan **yeniden kuruldu** (araştırma turunun önbelleği kopyalanmadı; çıktı `~/karadul_olcum/runs/dalga0-2026-11-20/OK5/gelistirme/esdeger.json`). Sonuç:

| ölçü | araştırma turu | `ozkod_olc.py` | aynı |
|---|---|---|---|
| K1 kâhin, keşif (ad / doğru) | 754 / 740 | 754 / 740 | evet |
| K1 kâhin, sınama | 126 / 103 | 126 / 103 | evet |
| G1 düz, keşif | 484 / 454 | 484 / 454 | evet |
| G1 düz, sınama | 143 / 114 | 143 / 114 | evet |
| nüfus / V ∪ C (iki taraf) | 20 747 / 1 279 | 20 747 / 1 279 | evet |
| sandviç ≤ 32 (karar / doğru) | 1 454 / 1 212 | 1 454 / 1 212 | evet |
| sandviç sınırsız | 2 545 / 2 216 | 2 545 / 2 216 | evet |
| K1 kip A (ad / doğru) | 98 / 95 | 98 / 95 | evet |
| K1 kip C (A + G1) | 242 / 239 | 242 / 239 | evet |
| R1 + harf koruma (tutulan / doğru) | 111 / 106 | 111 / 106 | evet |

  10 / 10 aynı; zorunlu iki satır tuttu. Kaynak: DEFTER §3–§14, BULGULAR §1.2, §2.1; `tavan.json` ve `ek_kurali_capa.txt` (araştırma turu çıktıları, salt okur).
- Testler: `tests/test_ozkod_olc.py` 25 test (dondurma denetimi, taraf ayrımı ve geri yükleme, Wilson, ön kayıtlı eşiklerin sınırları, kip A / C / C-kapılı / D, G1 kapısı, K1 karakter eki, körlük temizliği) — 25 geçti.

## 4. Ön kayıt

- `docs/arge/2026-11-19_mythos/ozkod/on_kayit_OK5.md`, commit **`c5a57ea`** (ayar okumasından ve kör sayımdan önce; kör tarafta önbellek bile kurulmamıştı). Planın metni aynen + İ-1/3 satırı + uygulama tanımları + K1 karakter ekinin dondurma kuralı + hüküm dışı ek raporlama.

## 5. ÖK-5 adım 4 — ayar tarafında dondurma (09:53; kör sayımdan önce)

- Ayar ürün koşusu bitti: 9 / 9 ELF tamam (toplam 4 184 sn, yük altında; postgresql-17 2 779 sn, sınırın altında). Önbellek 9 / 9 kuruldu, hata 0; ayar nüfusu 12 137 fonksiyon (evince 691, gawk 800, gedit 667, hexchat 903, jq 7, lighttpd 269, neomutt 3 360, pidgin 1 233, postgresql-17 4 207).
- Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/ozkod_olc.py ayar` → `~/karadul_olcum/ozkod_nufus/runs/ok5/ayar.json` (sha256 `d7200b78f6f0892e3e1f410e7cfabc74306a25bcf28a1bef2a2a2934a9984c2c`, 2026-11-20T09:53:15+0300). Yalnız ayar birimleri görünür; betiklerin sha256'ları dosyada (dondurulmuş beşi DEFTER ile aynı).

**(a) G1 kapısı — ön kayıt §3.6 gereği aynen donduruldu:** "ikilinin `reconstructed/kesin_capalar.json`'ında KS-1 çapası ≥ 1 ya da `__assert_fail` / `__assert_rtn` içe aktarımı" (`ozkod_olc.g1_kapisi`, commit `06ef538`'deki tanım).

| | ikili | kapıdan geçen | KS-1 çapalı | assert içe aktaran | G1 ad (nüfusta) | doğru |
|---|---:|---:|---:|---:|---:|---|
| düz G1 | 9 | — | — | — | 1 595 | 1 462 (%91,7; Wilson %90,2–%92,9) |
| kapılı G1 | 9 | 2 | 0 | 2 | 606 | 564 (%93,1; %90,8–%94,8) |

- Bulgu (kayıt için; kapı değişmedi): bu ürün sürümünde (b6aceb9) KS-1 hiçbir ayar ikilisinde çapa vermiyor (`kesin_capalar.json` `durum: ok`, `capalar` boş; postgresql-17'de 13 `func_kalibi` adayının hepsi "zaten adlı" diye elendi). Kapı fiilen "assert içe aktarımı"na indi ve ayar tarafında 9 ikilinin 2'sinde açık (postgresql-17 595 / 564, lighttpd 11 / 0); en çok G1 adı veren neomutt (657 / 612) kapının dışında kaldı.
- Ayrıca görüldü (K1 karakter eki hesabının yan ürünü; hiçbir K1 parametresi değişmedi): ayar tarafında K1 kâhin 282 ad, norm doğru 232.

**(b) K1 karakter eki — dönüşüm kümesi (ön kayıt §4 kuralı):**

| dönüşüm | kullanıldığı ad | karakter doğru | kural (n ≥ 5 ve < %50 → çıkar) |
|---|---:|---:|---|
| `aynen` | 137 | 113 | kalır |
| `alt_cizgi` | 40 | 24 | kalır (%60) |
| `bitisik` | 0 | 0 | kalır (n < 5) |
| `kucuk_alt_cizgi` | 103 | 95 | kalır |
| `kucuk_bitisik` | 0 | 0 | kalır |
| `deve` | 0 | 0 | kalır |
| `pascal` | 0 | 0 | kalır |
| `buyuk_alt_cizgi` | 0 | 0 | kalır |

- **Dondurulan küme:** sekizinin hepsi, aday sırasıyla (`aynen`, `alt_cizgi`, `bitisik`, `kucuk_alt_cizgi`, `kucuk_bitisik`, `deve`, `pascal`, `buyuk_alt_cizgi`). Ayar tarafında: norm adının karakter eşitliği 227 / 282, yüzey öğrenilmiş adın karakter eşitliği 232 / 282 (yüzey 280 adda öğrenildi).
- Kör sayım bu dosyayı (`ayar.json`, yukarıdaki sha256) okur; K1'in grup tanımı, `MIN_DESTEK` = 2, `MIN_ORAN` = 0,5 değişmedi.

## 8. Hedef erişimi (KARŞI İ-1 düzeltme 3) — Ollama, gösteri koşusu (salt okur)

- Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/ozkod_olc.py hedef` → `~/karadul_olcum/runs/dalga0-2026-11-20/OK5/hedef/hedef.json`. Girdi `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/girdi/Ollama` (sha256 `233793c7cab5afa4…`, 0.40.3, universal); analiz edilen arm64 dilimi (Karadul'un `raw/Ollama_arm64`'ü, sha256 `7d5b1e847e1b1e93…`). Ürün çıktısı gösteri koşusununki (1.23.x, 2026-11-19); Ghidra koşulmadı.
- Veri katmanı `ozkod_veri.ikili_kur` aynen; yalnız iki uyarlama (`ozkod_olc._gtsiz_erisim`, bağlam içinde): GT yok (`gt_mac` boş GT verir; erişim sayımı ad hükmü gerektirmez) ve ölçüm nüfusunun C++ süzgeci uygulanmaz (Ollama C++ içeriyor). Dilim yolu, `ks1_olc.mac_elfleri` yerleşiminde bir bağ dizinindeki `raw/target_info.json` ile verildi (`static`, `reconstructed` gösteri koşusuna sembolik bağ).
- Go / Go dışı kümeleri ÜST VERİ `butce.py`'nin tanımlarıyla (`LC_FUNCTION_STARTS`, `pclntab`, ObjC IMP, sembol tablosu): nüfus 12 952, Go 10 600, **Go dışı 2 352, kalan 1 676** — ÜST VERİ BULGULAR §7 ile aynı (bağımsız yeniden sayım).

| küme | fonksiyon | Ghidra'da | V ∪ C (K1-b tanımı) | K1 aday grubu (T / N / C) | G1 düz | G1 kapılı | `oz_ad` adı | R1 |
|---|---:|---:|---|---|---:|---:|---:|---:|
| Go dışı | 2 352 | 2 344 | 125 (%5,3) | 219 (%9,3; Wilson %8,2–%10,5); T 196, N 12, C 12 | 7 (%0,3) | 7 | 9 | 2 |
| Go dışı, üst veri ve sembolden sonra kalan | 1 676 | 1 668 | 125 (%7,5) | 173 (%10,3; %9,0–%11,9) | 7 | 7 | 9 | 2 |
| Go | 10 600 | 10 572 | 0 | 0 | 0 | 0 | 0 | 0 |

- Payda "fonksiyon"; Wilson %95. G1 kapısı Ollama'da açık (KS-1 çapası 0, `__assert_rtn` içe aktarımı var). 9 `oz_ad` adı gösteri koşusunun 9 `string_context/oz_ad` adıyla aynı sayı (KARŞI İ-1 kanıtı).
- **Okuma (eşik yok):** K1'in hedefteki erişimi Go dışı kodun yaklaşık onda biri (aday grubu) ya da yirmide biri (K1-b tanımı); G1 ve R1 neredeyse hiç (7 ve 2 fonksiyon). Go kodunda kayıt çifti yok (Go adları zaten `pclntab`'da).

## 2. Koşu ve önbellek sonucu (ÖK-V adım 5–6)

| taraf | paket | ELF | tamam | kısmi | zaman aşımı | hatalı | önbellek kuruldu / hata | süre (sn; yük altında) | nüfus |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| ayar | 9 | 9 | 9 | 0 | 0 | 0 | 9 / 0 | 4 184 | 12 137 |
| kör | 14 | 76 | 76 | 0 | 0 | 0 | 76 / 0 | 4 677 | 14 773 |

- Paket başına tablo, BuildID ve kabul ölçütü: `NUFUS.md` §9 (yeni bölüm). BuildID 85 / 85 (GNU notu); stapsdt sapması 2 (aşıldı, §9). ÖK-V kabulü tuttu (23 paket; ayar 9, kör 14; 85 / 85).
- Ana oturumun 12:2x mesajındaki "python3.13-minimal 12:35'e kadar bitmezse sonlandır" koşulu doğmadı: iş 12:21:35'te bitti (1 171 sn, tamam). Kör sayım **76 / 76 ELF** ile yapıldı; eksik ELF yok.

## 6. ÖK-5 adım 5–6 — kör sayım (12:22–12:33; ayar dondurması `4601218`'den sonra)

- Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/measurement/ozkod_olc.py kor` → `~/karadul_olcum/ozkod_nufus/runs/ok5/kor_sayim.json` (sha256 `f3e2c25b1acfce81c6fbe1ee3934411c58ec3e98b5ea50da83137fb7556b80ab`) ve `kor_sayim.md`. Yalnız kör birimleri görünür; dönüşüm kümesi `ayar.json`'dan; beş dondurulmuş betiğin sha256'ları DEFTER ile aynı (koşudan sonra da; aşağıda).
- **Etiket düzeltmesi (sayıları değiştirmez):** ilk kör koşusunda K1-a'nın karar metni "hacim şartı tutmadı" çıktı; oysa tutmayan şart kesinlikti (Wilson alt %80,01, kesinlik %81,7 < %85). `hukum_k1a`'nın "planın üç kolu dışında" kolunun metni "kesinlik ya da hacim şartı" diye düzeltildi (eşik ve sayı aynı; yeni test `test_k1a_wilson_tamam_kesinlik_eksik_kol_disi`), sayım yeniden koşuldu, sayılar bayt bayt aynı. Ön kayıt §3.3 bu durumu (Wilson tutar, kesinlik tutmaz) öngörmemişti; aşağıda açıkça yazılıyor.

- Dondurulmuş beş betiğin sha256'ları kör sayımdan sonra yeniden denetlendi: 5 / 5 DEFTER ile aynı (`7d02a6b5…`, `69201c56…`, `8767bde0…`, `ccc73f5c…`, `7ee4edfc…`).

### 6.1 Havuz (kör, 14 paket, 76 ELF, nüfus 14 773)

| ölçü | ad / karar | doğru | kesinlik (Wilson %95) |
|---|---:|---:|---|
| K1 kâhin, norm eşitliği | 2 048 | 1 674 | %81,7 (%80,0–%83,4) |
| K1 kâhin, karakter eşitliği (kural snake_case yazar) | 2 048 | 1 169 | %57,1 (%54,9–%59,2) |
| K1 kâhin, ayraçsız eşitlik | 2 048 | 1 705 | %83,3 (%81,6–%84,8) |
| K1 kâhin, karakter eki ayarda dondurulan yüzeyle (ÖK-7 A) | 2 048 | 1 664 | %81,2 (%79,5–%82,9) |
| K1 kâhin, belirteç kesinliği / duyarlılığı (mikro) | 6 557 / 6 376 belirteç | 6 078 | %92,7 / %95,3 |
| K1 kâhin, tekil (kaynak grubu + GT adı; A-14) | 1 691 | 1 373 | %81,2 (%79,3–%83,0) |
| K1 kip A (ürünün ön adları + Ghidra adları) | 98 | 87 | %88,8 (%81,0–%93,6) |
| K1 kip C (A + düz G1) | 258 | 170 | %65,9 (%59,9–%71,4) |
| K1 kip C-kapılı (A + kapılı G1) | 107 | 97 | %90,7 (%83,7–%94,8) |
| K1 kip D (ürünün bütün adları) | 291 | 242 | %83,2 (%78,4–%87,0) |
| G1 düz | 593 | 487 | %82,1 (%78,8–%85,0) |
| G1 kapılı (kapı 76 ikilinin 12'sinde açık; KS-1 çapalı 12, assert 10) | 146 | 101 | %69,2 (%61,3–%76,1) |
| `oz_ad` (ürün, bugün) | 366 | 168 | %45,9 (%40,9–%51,0) |
| `oz_ad`, kanıt harfleriyle | 366 | 192 | %52,5 (%47,3–%57,5) |
| R1 + harf koruma | 168 | 134 | %79,8 (%73,0–%85,1) |
| Ö: sandviç, aralık ≤ 32 | 2 414 | 1 169 | %48,4 (%46,4–%50,4) |
| Ö: sandviç, aralık sınırsız | 3 663 | 1 842 | %50,3 (%48,7–%51,9) |
| Ö: iki adres komşusu uzlaşıyor (kâhin) | 7 124 | 6 314 | %88,6 (%87,9–%89,3) |
| Ö: çağrı komşusu çoğunluğu (kâhin) | 8 062 | 3 893 | %48,3 (%47,2–%49,4) |

- K1 aday türü (kâhin): T (tablo) 1 828 / 1 497 doğru, C (çağrı) 193 / 167, N (nesne) 22 / 6, N + T 5 / 4. Kâhin K1'in doğru adlarının 1 646'sı bugün adsız, 13'ü bugün yanlış adlı, 15'i bugün de doğru. Çekimser: çapa yok 1 222, çelişki 85. Ürün çapasıyla (≥ 2; `ek_kurali.olc` "urun" kipi) 316 ad, 262 doğru; eksiz C 346 / 7.
- Çapa benzetimi (5 tohum toplamı): p = %5 → 3 277 ad, 2 742 doğru (%83,7); p = %10 → 4 947 / 3 772 (%76,2).
- V ∪ C erişimi (havuz): 4 071 / 14 773 (%27,6).
- Program (kaynak grubu) düzeyi K1 kâhin kesinliği (İ-7; yalnız rapor): irssi 164 / 170, python3.13 (stdlib modülleri) 806 / 956, lua-socket + lua-cjson 336 / 408, tcl 184 / 254, nginx 104 / 133, xterm 36 / 49, busybox 23 / 31, mc 17 / 27, bash 4 / 19, xfce4-terminal 0 / 1. Makro ortalama (ad ≥ 10 olan 9 program): %71,7.

### 6.2 Paket başına (kör)

| paket | nüfus | V ∪ C | K1 ad | K1 doğru (norm) | K1 karakter | G1 düz ad / doğru | G1 kapılı ad / doğru | kip A ad / doğru | sandviç ≤ 32 doğru / karar |
|---|---:|---:|---:|---:|---:|---|---|---|---|
| bash | 504 | 51 | 19 | 4 | 4 | 7 / 2 | 7 / 2 | 0 / 0 | 46 / 106 |
| busybox | 2 053 | 76 | 31 | 23 | 22 | 6 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| irssi | 1 371 | 913 | 170 | 164 | 164 | 275 / 259 | 0 / 0 | 0 / 0 | 122 / 363 |
| libpython3.13-stdlib | 1 987 | 1 148 | 956 | 806 | 534 | 81 / 48 | 60 / 46 | 72 / 63 | 1 / 33 |
| libtcl8.6 | 1 928 | 589 | 254 | 184 | 0 | 2 / 0 | 0 / 0 | 2 / 0 | 321 / 932 |
| lua-cjson | 88 | 40 | 40 | 28 | 28 | 4 / 0 | 4 / 0 | 0 / 0 | 0 / 0 |
| lua-socket | 1 292 | 580 | 368 | 308 | 300 | 0 / 0 | 0 / 0 | 24 / 24 | 24 / 24 |
| mc | 2 193 | 85 | 27 | 17 | 17 | 46 / 35 | 46 / 35 | 0 / 0 | 35 / 38 |
| mousepad | 0 | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| nginx | 1 102 | 291 | 133 | 104 | 82 | 15 / 0 | 0 / 0 | 0 / 0 | 355 / 355 |
| python3.13-minimal | 911 | 3 | 0 | 0 | 0 | 27 / 18 | 27 / 18 | 0 / 0 | 265 / 563 |
| tcl8.6 | 2 | 0 | 0 | 0 | 0 | 1 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| xfce4-terminal | 364 | 91 | 1 | 0 | 0 | 127 / 125 | 0 / 0 | 0 / 0 | 0 / 0 |
| xterm | 978 | 204 | 49 | 36 | 18 | 2 / 0 | 2 / 0 | 0 / 0 | 0 / 0 |

- K1-b payları (V ∪ C / nüfus; payda nüfusu > 0 olan 13 paket): irssi %66,6, libpython3.13-stdlib %57,8, lua-cjson %45,5, lua-socket %44,9, libtcl8.6 %30,5, nginx %26,4, xfce4-terminal %25,0, xterm %20,9, bash %10,1 (≥ %5: 9); mc %3,9, busybox %3,7, python3.13-minimal %0,3, tcl8.6 %0.
- Üretilmiş kod notu (PLAN riski): GObject / Vala paketleri kör tarafta yalnız mousepad ve xfce4-terminal; mousepad'in nüfusu 0, xfce4-terminal'de K1 1 ad. K1'in kör havuzunu taşıyan paketler Python stdlib modülleri (`PyMethodDef` tabloları; 956 ad), lua-socket / lua-cjson (`luaL_Reg`; 408), tcl (254), irssi (170), nginx (133). K1 adlarının %47'si tek kaynak grubundan (python3.13).

## 7. Ön kayıtlı hükümler (on_kayit_OK5.md, commit `c5a57ea`)

| satır | eşik | ölçülen (kör) | hüküm |
|---|---|---|---|
| **K1-a** (kâhin, norm) | havuz kesinliği ≥ %85 ve Wilson alt ≥ %80; ad ≥ 200; en az 5 pakette ≥ 10 ad | %81,7 (1 674 / 2 048); Wilson alt %80,01; ad 2 048; ≥ 10 adlı paket 10 | **TUTMADI** (kesinlik şartı). Beklenti "%85–%95" tutmadı. |
| K1-a karar kolu | Wilson alt %70–%80 → yeniden ön kayıt; < %70 → bırakılır | Wilson alt %80,01: üç kolun hiçbirine tam düşmüyor (Wilson şartı tutuyor, kesinlik tutmuyor) | ÖK-4b **açılmaz**; "%70–%80" koluna 0,01 puanla girmiyor, "< %70" durma ölçütü tetiklenmedi. Yeniden ön kayıt mı kapalı mı: **ana oturumun kararı** (öneri aşağıda). |
| **K1-b** (erişim) | V ∪ C ≥ %5, paketlerin en az yarısında | 13 paketin 9'unda | **TUTTU.** Beklenti (kabuk, sunucu, GTK'da var; kitaplıklarda değişken): kısmen — bash %10, nginx %26, xfce4-terminal %25 var; kitaplıklar (stdlib, lua, tcl) en yüksek; busybox ve mc %4 altında. |
| **K1-c** (kip A) | nüfusun < %2'si; kesinlik ≥ %90 (n ≥ 30 ise) | 98 ad = nüfusun %0,66'sı; 87 / 98 = %88,8 | "küçük" beklentisi **tuttu**; kesinlik **TUTMADI** (n = 98 ≥ 30, hükme girdi). |
| **G1-a** (düz) | kesinlik ≥ %85 | %82,1 (487 / 593) | **TUTMADI** (beklenti "tutmaz" — tuttu). |
| **G1-b** (kapılı) | kesinlik ≥ %90, Wilson alt ≥ %85, ad ≥ 50 | %69,2 (101 / 146); Wilson alt %61,3; ad 146 | **TUTMADI.** |
| **Ö-a** (sandviç ≤ 32) | önek kesinliği ≥ %85 | %48,4 (1 169 / 2 414) | **TUTMADI** (geliştirme setinde %83,4). |
| İ-1/3 (hedef erişimi; eşik yok) | — | Ollama Go dışı 2 352: V ∪ C 125 (%5,3), K1 aday grubu 219 (%9,3), G1 7, R1 2 (§8) | raporlandı |
| (bilgi) ÖK-2 şartı: R1 kesinliği ≥ %90 | — | R1 + harf koruma 134 / 168 = %79,8 (%73,0–%85,1) | tutmadı → `oz_ad_uniqueness_gate` öntanımı açılmaz |

### 7.1 Karar satırları

- **ÖK-3 (G1 üretici): KAPALI KALIR.** G1-b tutmadı (%69,2). PLAN durma ölçütü ("ÖK-3'te G1'in kapılı hâli bağımsız nüfusta < %85 kalırsa G1 bırakılır; ÖK-1 ve R1 kalır") tetiklendi: G1 ad kanalı olarak bırakılır. Not: bu ürün sürümünde KS-1 ayar tarafında hiç çapa vermedi, kör tarafta 12 ikilide verdi; kapı kör tarafta düz G1'den kötü seçti (kapılı %69,2 < düz %82,1).
- **ÖK-4b (K1 ad kanalı): AÇILMAZ; yeniden ön kayıt ana oturumun kararı.** K1-a'nın kesinlik şartı tutmadı (%81,7 < %85); Wilson alt %80,01 (planın "%70–%80 → yeniden ön kayıt" kolunun 0,01 puan üstünde, "< %70 → bırak" durma ölçütünün çok üstünde). Öneri (karar değil): PLAN'ın yeniden ön kayıt kolundaki "ek yüzey biçimi + tablo türü" kısıtları — tablo (T) adayları %81,9, çağrı (C) %86,5, nesne (N) 6 / 22; karakter eki ayarda dondurulan yüzeyle karakter eşitliği %57,1 → %81,2'ye çıkıyor (ÖK-4b H5'in girdisi). Bağımsız nüfusta bile K1'in kesinliği A-13 / A-14 ad eşiğinin (Wilson alt ≥ 0,909) çok altında: kanal açılsa da öntanımda ad değil kanıt satırı yazmalı (A-14).
- **ÖK-6 (modül öneki kanıt satırı): KAPALI KALIR.** Ö-a tutmadı (%48,4; geliştirme setinde %83,4). İki adres komşusunun kâhin uzlaşısı kör tarafta %88,6 (geliştirmede %96,4): adres sırası önek taşıyor ama bugünkü adlarla sandviç taşımıyor (çapalar bu nüfusta seyrek ve karışık: libtcl8.6 321 / 932, python3.13-minimal 265 / 563, bash 46 / 106).
- **ÖK-2 (R1 kapısı) için bilgi:** bağımsız nüfusta R1 + harf koruma %79,8 (PLAN'ın açılma şartı ≥ %90): bayrak öntanımı kapalı kalmalı. ÖK-1'in harf koruması kör tarafta 366 `oz_ad` adında doğru sayısını 168'den 192'ye çıkarıyor (net +24).
- **Hat düzeyinde okuma (TAHMİN değil, sayı):** geliştirme setinde ölçülen dört kuralın hepsi bağımsız nüfusta düştü — K1 kâhin %98,1 / %81,7 (keşif / sınama) → %81,7; G1 %93,8 / %79,7 → %82,1 (kapılı %69,2); sandviç %83,4 → %48,4. K1'in sınamadaki %81,7'si bağımsız nüfusta aynen tekrarlandı (aşırı uyumun keşif tarafında olduğu doğrulandı). Erişim (K1-b) beklenenden geniş: V ∪ C havuzda %27,6.

## 9. Testler ve mutasyon

- `tests/test_ozkod_olc.py`: 28 test, 28 geçti.
- `scripts/measurement/mutation_specs_ozkod_olc.json`: 16 mutant (kör / ayar karışması × 2, birim listesi, Wilson, K1-a kesinlik eşiği, K1-a paket şartı, K1-b yarısı, K1-c n şartı, G1-b ad şartı, kip A'ya `oz_ad`, G1'in kip A'ya yazılması, G1 kapısı ve / ya da, karakter eki tek oy, dönüşüm dondurma eşiği, GNU BuildID bağlamı, dondurulmuş betik denetimi) — son koşu aşağıda (§10).

## Kalemler

| # | kalem | durum |
|---|---|---|
| 1 | ÖK-V adım 5 — taban ürün koşusu | bitti: 85 / 85 tamam (ayar 9, kör 76); zaman aşımı 0, hata 0 |
| 2 | ÖK-V adım 6 — olgu önbelleği | bitti: 85 / 85, GT BuildID 85 / 85, hata 0 (`NUFUS.md` §9) |
| 3 | ÖK-5 adım 1–2 — `ozkod_olc.py` + eşdeğerlik | bitti: 10 / 10 aynı (K1 754 / 740, 126 / 103) |
| 4 | ön kayıt `on_kayit_OK5.md` | bitti: `c5a57ea` |
| 5 | ayar tarafında dondurma (G1 kapısı, K1 karakter eki) | bitti: `4601218` |
| 6 | kör sayım | bitti (§6) |
| 7 | `OK5.md` hükümleri | bitti (§7) |
| 8 | hedef erişimi (Ollama) | bitti (§8) |
| 9 | testler ve mutasyon | bitti (§9, §10) |
