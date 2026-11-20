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

## Kalemler

| # | kalem | durum |
|---|---|---|
| 1 | ÖK-V adım 5 — taban ürün koşusu | başlamadı |
| 2 | ÖK-V adım 6 — olgu önbelleği | başlamadı |
| 3 | ÖK-5 adım 1–2 — `ozkod_olc.py` + eşdeğerlik | başlamadı |
| 4 | ön kayıt `on_kayit_OK5.md` | başlamadı |
| 5 | ayar tarafında dondurma (G1 kapısı, K1 karakter eki) | başlamadı |
| 6 | kör sayım | başlamadı |
| 7 | `OK5.md` hükümleri | başlamadı |
| 8 | hedef erişimi (Ollama) | başlamadı |
| 9 | testler ve mutasyon | başlamadı |
