# KİMLİK — Dalga 0 paketi (PK-6 + PK-11): ilerleme

- Başlangıç: 2026-11-20 08:54. Dal: `worktree-agent-a2e74e17f3b864d9d`; taban `6551f2f` (main; `3ec5c77` atası).
- Gönderim metni: `docs/arge/2026-11-20_dalga0/gonderim/KIMLIK.md`. Plan: `kimlik/PLAN.md` §3 PK-6, PK-11.
- Kip: PK-3 (`kimlik_olc`) yok → ölçüm dondurulmuş araştırma betikleriyle (`scripts/arge/kimlik/`); yeni grup
  tanımları `scripts/measurement/kimlik_ciftler.py`, yükleyici eki ve sarmalayıcılar `scripts/arge/kimlik/d0_*.py`.
- Koşu çıktıları: `~/karadul_olcum/runs/dalga0-2026-11-20/KIMLIK/` (iş listesi `isler.txt`, günlük `kos.jsonl`).

## Durum

| Kalem | Durum | Commit |
|---|---|---|
| 1 Ön kayıtlar (`PK-6_on_kayit.md`, `PK-11_on_kayit.md`, grup tanımları) | bitti | `93788e5` |
| 2 PK-6 `mimari`, `derleyici_surumu` | koşu sırada | — |
| 3 PK-6 `surum_esli` (V1) | bitti: 4 / 4 program; (e) 4 / 4 → "tmux'a özgü değil"; (b) kararsız; (d) tree tutmadı | `1ceed86` |
| 4 `iyilestirme` | veri yok (tabaka C Dalga 2'de) | — |
| 5 PK-11 | bitti (`PK-11.md`): kural 242 / 1, alt 0,977 → (a) hat hedefi; (b) kapsam %33,6 tutmadı; (c) 0 / 199 tuttu | `ee8d78d` |
| 6 Kilit süzgeci sınaması + mutant | bitti: 14 / 14 sınama, mutant 3 / 3 öldü | `329e9bc` |

## Ghidra koşu planı (kuyruğa girmeden önce)

- Koşu sayısı: **68** (`--stage static`, ürün `~/karadul_olcum/urun-b6aceb9`, her ikili ayrı `ghidra_kuyruk.sh` çağrısı):
  PK-11 1 (libzstd) + tabaka A 19 + tabaka B Debian 12 19 + tabaka B Ubuntu 24.04 19 + V1 10 (5 ikili × 2 derleyici).
  Debian 13 arm64 tarafı yeniden koşulmuyor (a62f15e koşusu).
- **TAHMİNİ süre** (yük altında; dayanak bugünkü kuyruk günlüğünün tam boru hattı süreleri: cat 33 sn, sort 57,
  tree 51, htop 81, sqlite3 102, tmux 285): saf Ghidra süresi ~105 dk [80–160]; kuyruk başka paketlerle
  paylaşıldığı için duvar saati **2,5–4,5 saat** [TAHMİN].
- **BİLDİRİM:** tahmini duvar süresi 3 saati aşabilir. Sıra buna göre (09:15 güncellendi; V1 derlemesi erken bitti): PK-11 (1 koşu) → V1 `surum_esli` (küçükten büyüğe) → `mimari` (küçükten büyüğe)
  → `derleyici_surumu` Debian 12 → Ubuntu 24.04
  (her biri küçükten büyüğe). Zaman yetmezse en sondaki büyük ikililer eksik kalır ve "ölçülmedi" yazılır.

## V1 derlemesi (kalem 3; 09:08–09:16)

- Açma: `python -I scripts/arge/kimlik/d0_derle.py ac` → `~/karadul_olcum/kimlik_v1/x_{tree,libzstd,sqlite3,redis}/`
  (sha256'lar `v1_veri.json` ile tuttu; `tarfile` `data` süzgeci). Debian yamalarının hepsi uygulandı
  (tree 1 / 1, libzstd 10 / 10, sqlite3 15 / 15, redis 14 / 14; uygulanamayan 0).
- Derleme: `d0_derle.py derle` (kopyalar `KIMLIK/v1/src/{gcc,clang}/<paket>`, `sandbox-exec` ile ağ kapalı, `-O2`;
  GCC = Homebrew GCC 16.2.0, clang = Apple clang 21.0.0). 8 / 8 derleme başarılı. redis'ten yalnız `redis-cli`,
  `redis-benchmark`; derleme günlüğünde deps/lua yalnız `make clean` (derlenen lua nesnesi 0).
- Hazırlık (`d0_derle.py hazirla`; `macho_measure prepare`): GT fonksiyon sayıları — GCC: tree 111, zstd 1 009,
  sqlite3 309, redis-cli 631, redis-benchmark 471; clang (fonksiyon / program sınıfı): tree 168 / 111, zstd 1 321 / 952,
  sqlite3 365 / 291, redis-cli 818 / 590, redis-benchmark 561 / 445 (clang farkı soğuk parça ve dışlanmış parça).

### Sapmalar (sayılardan önce)

1. **GCC redis ikililerinde dışa aktarım ağacı:** GCC'nin Darwin'deki öykünmeli TLS'si (`___emutls_get_address`,
   `___emutls_register_common`; redis `__thread` kullanıyor) dışa aktarım ağacında kalıyor; Apple strip kaldırmıyor;
   `macho_measure prepare` ikiliyi reddediyor (GT sızıntısı koruması). Önce iki derleyicide aynı bağlayıcı bayrağı
   (`-Wl,-exported_symbol,__mh_execute_header`) denendi: GCC sürücüsü kendi `-exported_symbol`'lerini eklediği için
   kalan ad 2 → 4'e çıktı; bayrak geri alındı, iki derleyici özgün bayraklarla yeniden derlendi. Yerine
   `d0_derle.gcc_tls_hazirla`: `prepare`'ın aynı işlevleriyle (strip, export okuma, `build_gt`) ama dışa aktarımda
   ve soyulmuş kopyanın `nm` simgelerinde YALNIZ bu iki çalışma zamanı adı kaldıysa kabul (başka her şey hata).
   Etkisi: Ghidra GCC redis ikililerinde bu iki libgcc fonksiyonunu adlı görür; program adı değil, nüfusa girmez.
2. **workspaces bağı:** doğrulama için (`derleyici` grubu `mac/tmux` GT'si) worktree'ye
   `workspaces/olcum_mac → /Users/apple/Black_Widow/workspaces/olcum_mac` salt bağlantısı kuruldu (`.gitignore`'da;
   commit'lenmez).

### Sarmalayıcı denetimi (yeniden üretim)

`python scripts/arge/kimlik/d0_olc.py hepsi --grup derleyici --etiket denetim_derleyici` tur 1 sayılarını birebir
verdi: kural 3 908 / 38, tutucu 3 709 / 28, kural_v2 4 281 / 36, tutucu_v2 4 170 / 26; hata sınıfları
4 / 13 / 16 / 3 / 2 (BULGULAR §3.6). Yükleyici eki eski kimlikleri değiştirmiyor.

## Bekleme (09:20)

- Şu an Ghidra kuyruğunu bekliyorum: ilk işim `kitaplik/libzstd` 09:07'den beri sırada (önde OK5 postgresql-17, ANA S8-AA, HZ1 S8). Sonra V1 10 koşu, ardından `mimari` 19 ve `derleyici_surumu` 38. TAHMİNİ bitiş 12:00–13:30 (yük altında; kuyruk paylaşımlı).

## Bekleme (10:49)

- Ana oturum KIMLIK'in yeni koşularını OK5'in kısa işleri bitene kadar bekletti (`ghidra_kuyruk.bekle.KIMLIK`;
  en geç ~12:05). Sürücü durdurulmadı; bekletme kalkınca kendiliğinden sürer. Şu an bekliyorum: tabaka A'nın son
  iki ikilisi (openssl, zstd; tmux 10:42'de başladı), sonra tabaka B 38 koşu. TAHMİNİ bitiş 13:00–14:00.
  Bu sürede Ghidra gerektirmeyen işler (belge, hüküm hesapları) sürüyor.

## Kalem 3 — `surum_esli` (V1) sonucu (10:23)

- Koşular: 10 / 10 `tamam` (`--stage static`, b6aceb9, kuyruk; tek koşu 16–120 sn, kuyruk beklemesi dahil değil).
- Komut: `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/kimlik/d0_olc.py hepsi --grup surum_esli` → `KIMLIK/olcum/
  {yayilim,hata_*,envanter,ciplak,hukum}_surum_esli.*`. Çift: macOS arm64 Mach-O, aynı kaynak (Debian yamalı), aynı
  bayraklar (`-O2`); yalnız derleyici farklı (GCC 16 ↔ Apple clang).

| Nokta | iki yön havuzu (doğru / yanlış = kesinlik [Wilson]; kapsam) | gcc → clang | clang → gcc | grup (zayıf yön) |
|---|---|---|---|---|
| **kural** | 2 398 / 77 = 0,969 [0,961–0,975]; %51,6 | 1 220 / 38 = 0,970 [0,959–0,978]; %53,0 | 1 178 / 39 = 0,968 [0,957–0,977]; %50,3 | **hat hedefi tuttu** (alt 0,957) |
| tutucu | 2 152 / 57 = 0,974 [0,967–0,980]; %46,3 | 1 096 / 28 | 1 056 / 29 | hat hedefi (0,962) |
| kural_v2 | 2 588 / 83 = 0,969 [0,962–0,975]; %55,7 | 1 314 / 40 | 1 274 / 43 | hat hedefi (0,956) |
| tutucu_v2 | 2 426 / 57 = 0,977 [0,970–0,982]; %52,3 | 1 229 / 28 | 1 197 / 29 | hat hedefi (0,966) |

Program başına, `kural` (yön başına; hüküm zayıf yönün Wilson alt sınırıyla):

| Program | gcc → clang | clang → gcc | zayıf yön alt | (a) |
|---|---|---|---|---|
| tree | 82 / 0 = 1,000 [0,955–1]; %74,5 | 82 / 0 = 1,000 [0,955–1]; %73,9 | 0,955 | hat hedefi tuttu |
| zstd | 368 / 12 = 0,968 [0,946–0,982]; %41,9 | 370 / 14 = 0,964 [0,940–0,978]; %39,6 | 0,940 | ad yazabilir (A-2) |
| sqlite3 (kabuk) | 209 / 5 = 0,977 [0,947–0,990]; %74,1 | 217 / 4 = 0,982 [0,954–0,993]; %74,8 | 0,947 | ad yazabilir (A-2) |
| redis (cli + benchmark) | 561 / 21 = 0,964 [0,946–0,976]; %54,3 | 509 / 21 = 0,960 [0,940–0,974]; %50,6 | 0,940 | ad yazabilir (A-2) |

`tutucu_v2` (ikincil): tree 0,954, zstd 0,951, sqlite3 0,950, redis 0,955 → zstd, redis, tree "hat hedefi", sqlite3
"ad yazabilir"; hepsi ≥ 0,909.

**Ön kayıtlı hükümler (`surum_esli`):**
- **(a)** grup: hat hedefi tuttu (dört noktada da; `kural` zayıf yön alt 0,957). Program: tree hat hedefi; zstd,
  sqlite3, redis "ad yazabilir (A-2)" (0,940–0,947; 0,95'in altında, 0,909'un üstünde).
- **(b)** tek taraflı pay 18 / 77 = %23,4 → **kararsız** (≤ %20 değil, > %50 değil). Not: bu çiftte kaynak sürümü
  birebir aynı; tek taraflı sınıf burada yeniden adlandırma OLAMAZ (tur 1'in "aynı sürümde 0–10, iki tarafta farklı
  fonksiyonların satır içine alınması" okumasıyla uyumlu). Sınıflar: tek taraflı 18, satır içi 14, komşu 21,
  aile 2, diğer 22; tavan içi kesinlik 2 398 / 2 443 = 0,982 [0,975–0,986].
- **(d)** program başına (iki yön havuzu): zstd (738 / 26 → 862 / 35; 659 / 23 → 813 / 23), sqlite3 (426 / 9 →
  464 / 9; 354 / 9 → 452 / 9), redis (1 070 / 42 → 1 100 / 39; 973 / 25 → 1 001 / 25) **tuttu**; **tree tutmadı
  (kapsam artmadı)**: kural 164 / 0 → kural_v2 162 / 0, tutucu 166 / 0 → tutucu_v2 160 / 0 (kesinlik değişmedi,
  kapsam 2 ve 6 fonksiyon düştü). Ön kayıt metni gereği: "tutmayan program çıkarsa PK-4 öntanımı `TUTUCU`'ya
  döner" — tetiklendi (neden yalnız kapsam; yanlış artmadı). Karar ana oturumun.
- **(e) Genelleme hükmü (birincil `kural`): ölçülen 4 programın 4'ü Wilson alt ≥ 0,909 (tree 0,955, sqlite3 0,947,
  zstd 0,940, redis 0,940) → "tmux'a özgü değil".** İkincil `tutucu_v2`: 4 / 4, aynı hüküm. Planın durma ölçütü (a)
  tetiklenmedi. A-14'ün "en az 3 bağımsız program" şartı bu grupta sağlandı (4).
- A-14 tekil düzey (`kural`): gcc → clang 1 015 / 33 öğe (alt 0,956), clang → gcc 1 001 / 33 (alt 0,956); program
  başına en düşük redis 0,930 / 0,931 — hepsi ≥ 0,909.
- Aşama kırılımı (`kural`, havuz): tekil dizgi çapası 581 / 6 = 0,990 [0,978–…]; yayılım 1 817 / 71 = 0,962. Ad
  ailesi küme isabeti 423 / 482 = 0,878 (tur 1 G7 ile aynı yönde: aile ad değil, kanıt satırı).
- Çıplak yöntemler (`ciplak`): BSim "depoda başvuru yok" (her koşunun deposu yalnız kendi ikilisi; ölçülmedi);
  CFG yapısı / CFG + komut kümesi GCC ↔ clang arasında yine çok az eşleşme (ör. zstd 4 / 0 ve 5 / 1).
- Tur 1 ile karşılaştırma (beklenti değildi): tmux 0,990, htop 0,984 (`kural`, iki yön havuzu); bu dört programda
  havuz 0,969. Aynı sürümde kesinlik 0,96–0,98 bandında, tmux'tan biraz düşük; kapsam %40–75.

### Ek satır (A6; ön kayıtta "yalnız rapor"): `surum_esli_platform` — Debian 13 Linux GCC 14 ikilisi ↔ macOS clang derlemesi, aynı kaynak sürümü

| Nokta | iki yön havuzu | debian → v1clang | v1clang → debian | grup (zayıf yön) |
|---|---|---|---|---|
| kural | 1 446 / 70 = 0,954 [0,942–0,963]; %36,4 | 554 / 28 = 0,952 [0,931–0,967] | 892 / 42 = 0,955 [0,940–0,967] | ad yazabilir (0,931) |
| tutucu_v2 | 1 406 / 68 = 0,954 [0,942–0,963]; %35,4 | 570 / 30 | 836 / 38 | ad yazabilir (0,929) |

Program (`kural`, zayıf yön alt): tree 0,945 ve sqlite3 0,935 "ad yazabilir"; **zstd 0,875 ve redis 0,856 "kanıt
satırı"**. Okuma (yön gösterici): platform + derleyici + ikili biçimi birlikte değişince iki program eşiğin altına
iniyor; Debian ikilileri macOS derlemelerinden farklı yapılandırılmış (bağlı kitaplıklar `lief` ile okundu: Debian zstd zlib + lzma + lz4,
redis-cli / benchmark libssl + jemalloc + systemd + lzf, sqlite3 readline + zlib; V1 derlemelerinde zstd yalnız zlib, redis TLS'siz, sqlite3 readline'sız). Bu satır yapılandırmayı eşlemediği için
"platform etkisi" diye okunmamalı; A6 kısmen açık kalır.

## x86-64 koşularında capa adımı (11:15; ürün bulgusu, ölçüme etkisi yok)

- `tabA/tmux/tmux` sürücünün 1 800 sn süre sınırına takıldı (`ZAMAN_ASIMI`, çıkış 124). Ghidra adımı 10:43'te
  76,6 sn'de bitmiş, `ghidra_status.json` `success: true`, çıktılar tam (2 376 fonksiyon); kalan ~29 dk statik
  aşamanın **capa** taramasında geçti (kosu.log: vivisect `graph building` iletileri). `tabA/redis-tools/redis-cli`
  aynı nedenle 522 sn sürdü; AArch64 / Mach-O koşularında capa çalışmıyor (desteklenmiyor) ve koşular 14–120 sn.
- Ürün nedeni (okundu, değiştirilmedi): `karadul/analyzers/capa_scanner.py` `_scan_via_api` süreç içi yol;
  belgesi "``timeout`` uygulanamaz" diyor → `capa_timeout = 600` bu yolda geçersiz. Analist açısından: x86-64 ELF'te
  statik aşama yarım saati aşabiliyor ve Ghidra kuyruğunu tutuyor. HIZ / ÖLÇEK hattının bilmesi gereken bir olgu.
- Ölçüme etkisi: eşleyici yalnız Ghidra çıktılarını okuyor; `d0_olc.kosu_durumu` her koşuda `ghidra_status.success`
  denetler, zaman aşımına uğrayan ama Ghidra'sı başarılı koşuları künyede ayrıca listeler (başarısızsa ölçüm durur).
- Sıra: `tabA/zstd/zstd` (x86-64, en büyük) iş listesinin en sonuna alındı ki kısa AArch64 işleri (tabaka B)
  onun arkasında beklemesin; `tabA/openssl/openssl` zaten kuyruktaydı (bekletmede).

## Ana oturum yönergesi (11:3x) ve uygulanışı

- **Sert son 15:15.** O saate kadar koşulamayan çiftler "kalan" diye yazılır; hüküm yalnız koşulan çiftlerle
  verilir ve "kısmi" diye etiketlenir.
- **capa kapalı:** sürücü durduruldu (bekletmedeki `tabA/openssl` çağrısı Ghidra'ya hiç girmeden sonlandırıldı;
  dizininde yalnız boş `kosu.log`), `d0_kos.py`'ye `--ayar` eklendi, sürücü 11:32'de
  `--ayar ~/karadul_olcum/runs/dalga0-2026-11-20/KIMLIK/capa_kapali.yaml` (`binary_reconstruction: {enable_capa:
  false}`; ürün `Config.load` ile denendi: `enable_capa False`, `enable_capa_code_feed False`) ile yeniden başladı.
  **Künye: koşu 29'dan itibaren (11:32) capa kapalı; ilk 28 koşu (libzstd 1, V1 10, tabaka A 17) öntanımla.
  Kimlik ölçümünün girdisi değişmez:** ölçüm kodunda capa çıktısını okuyan yer yok
  (`grep -rln "capa_scan\|capa_capabilities\|CAPAScanner\|capa_status" scripts/arge/kimlik/ scripts/measurement/
  {ks1_olc,function_f1,macho_f1,macho_measure,kimlik_ciftler}.py` → eşleşme 0; yükleyici yalnız Ghidra JSON'larını,
  `pcode.jsonl`'u ve `raw/target_info.json`'u okur); capa statik aşamada Ghidra'dan SONRA koşar ve AArch64 / Mach-O
  hedeflerinde zaten "desteklenmiyor".
- **Sıra (genişlik önce):** iş listesi yeniden kuruldu: önce `derleyici_surumu` (Debian 12 ve Ubuntu 24.04) ve
  `mimari` için program başına ilk çift (18 koşu: 8 + 8 + tabaka A'nın eksik iki programı openssl, zstd), sonra kalan
  22 çift (coreutils'in öbür 10 ikilisi × 2 dağıtım, redis-benchmark × 2), küçükten büyüğe.

## Ara sonuç: `mimari` 17 / 19 çift (11:36; KISMİ — openssl, zstd kuyrukta; son hüküm aşağıda yinelenecek)

`python scripts/arge/kimlik/d0_olc.py hepsi --grup mimari --etiket mimari_ara --kismi` (v1 noktaları; v2
desteklenmiyor). `tabA/tmux` süre sınırına takıldı, Ghidra çıktısı tamam (`success`).

- `kural`: iki yön havuzu **6 146 / 4 = 0,999 [0,998–1,000]**, kapsam %77,2; amd64 → arm64 3 063 / 2,
  arm64 → amd64 3 083 / 2 → grup **hat hedefi tuttu** (zayıf yön alt 0,998). `tutucu`: 5 920 / 2.
- Program (`kural`, zayıf yön alt): coreutils 0,994, tmux 0,998, sqlite3 0,983, redis 0,976, htop 0,970, tree 0,955
  → hepsi "hat hedefi tuttu".
- (b) yanlış toplamı 4 (< 10) → "sayı yetmedi" (tek taraflı 0). A-14 tekil düzey 2 563 / 2 ve 2 575 / 2 (alt 0,997).
- Okuma: aynı paket sürümü + aynı derleyici sürümünde yalnız mimari değişince eşleyici neredeyse hatasız; kanıt
  türleri (dizgi, içe aktarım, P-code sabitleri, çağrı grafiği) mimariden bağımsız.

## Tam takım (11:54–12:03, commit `2d3cbea`, yük altında)

- `PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider` (worktree kökü): **10 463 geçti / 11 atlandı /
  0 kaldı** (152 seçim dışı; 561 sn). Günlük `~/karadul_olcum/runs/dalga0-2026-11-20/KIMLIK/tam_takim2.log`.
- İlk deneme (09:19, `d900cc4`) 7 kaldı: hepsi worktree'de çalışma verisi bağlarının yokluğundan (`scripts/node_modules`
  → `@babel/parser`, `vendor/gnulib-ref`); ORTAK_D0 §2'deki bağlar kurulunca 7 / 7 geçti. Paketin değişikliğiyle ilgisi
  yok. Bu ölçüm koşusundan sonra yalnız `d0_*` sarmalayıcıları ve belgeler değişecek (takımın içe aktarmadığı dosyalar).
