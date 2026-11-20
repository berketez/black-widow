# PK-6 ön kaydı — sürüm ↔ derleyici ↔ mimari ayrımı (Dalga 0, 2026-11-20)

- Yazıldı: 2026-11-20 09:1x, **hiçbir yeni koşu ve sayım yapılmadan** (yeni Ghidra koşusu yok, V1 derlemesi yok,
  yeni grupların hiçbir sayısı görülmedi). Bu belge kendi commit'inde; ölçüm commit'leri bundan sonra gelir.
- Plan: `kimlik/PLAN.md` §3 PK-6. Gönderim: `docs/arge/2026-11-20_dalga0/gonderim/KIMLIK.md`.
- Kip: PK-3 (`kimlik_olc`) yok → ölçüm tur 1'in dondurulmuş araştırma betikleriyle: `scripts/arge/kimlik/esle.py`
  (`NOKTALAR` = `KURAL`, `TUTUCU`, `KURAL_V2`, `TUTUCU_V2`; hiçbir parametre değişmez), `yayilim_olc.py`,
  `hata_dok.py`, `ciplak.py`, `envanter.py`. Bu betikler değiştirilmez; yeni kimlik kökleri ve gruplar
  `scripts/arge/kimlik/d0_veri.py` (yükleyici eki) ve `scripts/measurement/kimlik_ciftler.py` (grup tanımları)
  üzerinden süreç içinde bağlanır.

## 1. Planın ön kayıt metni (aynen)

> PK-6 ön kaydı. Açık ölçüm; beklenen sayı yok, eşikler var. Grup başına, havuz ve program düzeyinde:
> (a) tam ad kesinliği Wilson alt ≥ 0,95 → "hat hedefi tuttu"; ≥ 0,909 → "ad yazabilir (A-2)"; altı → "kanıt satırı".
> (b) Sürümü eşli gruplarda (`iyilestirme`, `mimari`, `surum_esli`) "tek taraflı" yanlış payı ≤ %20 → "tek taraflı
> sınıf sürüm kaynaklıdır" okuması destek bulur; > %50 → çürür (sınıf başka bir şeydir; tur 1 yorumu geri çekilir).
> (c) `iyilestirme` grubunda satır içi + komşu türü yanlış sayısı düzey farkıyla artar (`-O0` ↔ `-O2` en çok;
> tur 1'de GCC ile 93 ↔ 50); artmıyorsa "satır içi" sınıflaması yanlış adlandırılmıştır. (d) v2'nin kapsamı v1'den
> büyük ve kesinlik farkı Wilson aralıkları içinde (tur 1: dört taze çiftte tuttu) → v2 öntanım kalır; tutmayan
> program çıkarsa PK-4 öntanımı `TUTUCU`'ya döner. (e) **Genelleme hükmü:** `surum_esli` grubunda (tmux dışı
> programlar) program başına Wilson alt ≥ 0,909 olan program sayısı / toplam; ≥ 3 programın en az 2'si → "tmux'a
> özgü değil". Tur 1 değerleri (karşılaştırma için, beklenti değil): tmux 0,990 [0,987–0,993], htop 0,984
> [0,974–0,990]. Eşikler sonradan değişmez.

Planın durma ölçütü (a) (§0) da bu ölçüme bağlı: başka programlarda / mimaride, sürümü eşlenmiş başvuruyla tam ad
kesinliği Wilson alt sınırı < 0,909 çıkarsa "tmux'a özgü" hükmü verilir.

## 2. Gruplar ve seçim kuralları (sayılara bakılmadan)

Tanımların kodu: `scripts/measurement/kimlik_ciftler.py` (bu commit'te).

| Grup | Sorgu ↔ başvuru (iki yön) | Değişen etken | Durum |
|---|---|---|---|
| `mimari` | `tabA/<p>/<i>` (Debian 13 amd64) ↔ `debian/<p>/<i>` (Debian 13 arm64) | yalnız mimari (aynı paket sürümü, GCC 14.2) | koşulacak |
| `derleyici_surumu` (= `_d12` + `_u24`) | `tabB12/<p>/<i>` (Debian 12 arm64, GCC 12.2) ve `tabB24/<p>/<i>` (Ubuntu 24.04 arm64, GCC 13.2 / 13.3) ↔ `debian/<p>/<i>` | derleyici sürümü **ve** program sürümü (TABAKA_VERI.md §3, §5) | koşulacak |
| `surum_esli` | `v1gcc/<i>` (Homebrew GCC 16) ↔ `v1clang/<i>` (Apple clang), macOS arm64 Mach-O | yalnız derleyici (aynı kaynak, aynı bayraklar) | koşulacak (önce derleme) |
| `surum_esli_platform` (ek, PLAN §5 A6) | `debian/<p>/<i>` (Linux GCC 14) ↔ `v1clang/<i>` (macOS clang), aynı kaynak sürümü | derleyici + platform + ikili biçimi | yalnız rapor; (e)'ye girmez |
| `iyilestirme` | tabaka C (`-O2` ↔ `-O0/-O1/-Os/-O3/-flto`) | iyileştirme düzeyi | **veri yok**: tabaka C (ÖLÇÜ P-Ö6) Dalga 2'de; (c) hükmü verilmez |

**İkili seçimi (tabaka grupları; üç tabakada aynı küme):**
- tree, htop, sqlite3, openssl, tmux (her biri tek ikili); zstd → yalnız `zstd`; redis-tools → `redis-cli` ve
  `redis-benchmark`; coreutils → ada göre sıralı 106 ikiliden her 10.'su (indis 0, 10, …, 100: `[`, `chmod`, `df`,
  `false`, `link`, `nice`, `printenv`, `sha1sum`, `stat`, `touch`, `users`; tur 1 `sinama_cu_ic`'in sorgu kümesiyle
  aynı kural). Toplam 19 ikili / tabaka.
- Dışarıda: `pzstd` (C++; tam ad eşitliği tanımsız, PLAN §5 A10); `redis-check-aof` ve `redis-check-rdb`
  (redis-server kopyası, aynı build-id; **deps/lua içerir**; lua kilitli setin stres alt kümesinde, KARARLAR A-23).
  `redis-cli` ve `redis-benchmark`'ın Debian 13 hata ayıklama dosyasında derleme birimleri yalnız `src`,
  `deps/hiredis`, `deps/linenoise`, `deps/hdr_histogram` (deps/lua birimi 0; bu belgeden önce denetlendi).

**V1 (`surum_esli`) derlemesi:** dört kaynak paketi (`tree 2.2.1-1`, `libzstd 1.5.7+dfsg-1`, `sqlite3 3.46.1-7+deb13u2`,
`redis 5:8.0.2-3+deb13u2`; künye `~/karadul_olcum/kimlik_v1/v1_veri.json`). Her paket önce kendi yeni boş dizinine
açılır (`~/karadul_olcum/kimlik_v1/x_<paket>/`), Debian yamaları (`debian/patches/series`) uygulanabiliyorsa
uygulanır (uygulanamayan yama künyeye yazılır; iki derleyicide aynı kaynak), sonra her derleyici için ayrı bir
kopyada (`~/karadul_olcum/runs/dalga0-2026-11-20/KIMLIK/v1/src/<derleyici>/<paket>`) aynı bayraklarla
(`-O2`; tur 1 `derle_gcc.sh` düzeni) derlenir. Ağ kapalı; derleme çıktıları ÇALIŞTIRILMAZ (test hedefi /
`make check` yok). Hedefler: `tree`; `programs/zstd`; `sqlite3` kabuğu; redis'ten **yalnız** `redis-cli` ve
`redis-benchmark` (lua hedefi derlenmez ve bağlanmaz). Soyma `/usr/bin/strip`, GT sembollü ikilinin `nm`
çıktısından (`scripts/measurement/macho_measure.py prepare`). Derlenemeyen program olursa nedeni yazılır,
kalanlarla devam edilir; derleme seçenekleri sayılara bakılarak değiştirilmez.
Program birimi: `tree`, `zstd`, `sqlite3`, `redis` (`redis-cli` + `redis-benchmark` tek program).

**Koşu:** her ikili için ürün `~/karadul_olcum/urun-b6aceb9`, `python -m karadul analyze <ikili> --skip-dynamic
--stage static` (tur 1 §5.13 ile aynı aşama; eşleyicinin okuduğu olgu tam koşuyla aynı, BULGULAR §3.6),
`~/karadul_olcum/ghidra_kuyruk.sh KIMLIK <etiket> …` ile, koşuya özel `KARADUL_CACHE_DIR`, `PYTHONHASHSEED=0`,
süre sınırı. Debian 13 arm64 tarafı yeniden koşulmaz: geliştirme setinin a62f15e koşusu
(`~/karadul_olcum/runs/urun-onarim-a62f15e/debian/…`; tam boru hattı) kullanılır; kuşak farkı (a62f15e tam ↔
b6aceb9 statik) künyeye yazılır (tur 1 O11: koşu kuşağı farkı sonucu değiştirmedi).

**GT:** tabaka ikilileri `ks1_olc.gt_elf` ile (build-id → tabakanın kendi `-dbgsym` paketi); geliştirme seti
tarafı tur 1'deki gibi; V1 `ks1_olc.gt_mac`.

## 3. Sayım ve hüküm tanımları

- Ölçü tur 1 ile aynı (`DEFTER.md` §3): nüfus içi tam ad eşitliği (`esle.hukum`: Mach-O `_` soyulur, derleyici
  klonu tabana iner), Wilson %95 (`ks1_olc.oran`), kapsam = doğru / nüfus.
- **Yön başına (A-15):** her (sorgu → başvuru) yönü ayrı satır. Program düzeyinde bir hüküm, programın **iki
  yönünden zayıf olanıyla** verilir (iki yönün Wilson alt sınırlarının küçüğü). İki yönün havuzu tur 1 ile
  karşılaştırma için ayrıca yazılır; hükmü belirlemez. Grup düzeyi hüküm: yön başına havuz (ör. `mimari` amd64 →
  arm64 ve arm64 → amd64), küçüğü.
- **Birincil nokta `kural`** (planın tur 1 karşılaştırma değerleri bu noktada). (a) dört noktanın her biri için
  ayrıca yazılır; `tutucu_v2` (PK-4 öntanımı) ikincil hüküm satırıdır.
- `derleyici_surumu` hükmü iki dağıtımın havuzuyla; `_d12` ve `_u24` alt satırları ayrıca yazılır.
- **(a)** havuz ve program: Wilson alt ≥ 0,95 → "hat hedefi tuttu"; 0,909 ≤ alt < 0,95 → "ad yazabilir (A-2)";
  alt < 0,909 → "kanıt satırı". 0,909 = `AD_ESIGI` = L / (L + 1) (KARARLAR A-13, A-25).
- **(b)** tek taraflı pay = `hata_dok` sınıfı `tavan_disi_tek_tarafli` / toplam yanlış, `kural` noktası, grubun iki
  yönünün havuzu. ≤ %20 → "destek buldu"; > %50 → "çürüdü"; arası → "kararsız". `mimari` ve `surum_esli` için;
  `iyilestirme` veri yok. Toplam yanlış < 10 ise pay yazılır, hüküm "sayı yetmedi".
- **(c)** `iyilestirme` veri yok → hüküm yok.
- **(d)** program başına (iki yönün havuzu) ve iki çift için (`kural` → `kural_v2`, `tutucu` → `tutucu_v2`):
  "tuttu" ⇔ v2 kapsamı v1'den **büyük** ve iki kesinliğin Wilson aralıkları örtüşür (v2 kesinliği yüksekse örtüşme
  aranmaz). Eşit kapsam "tutmadı (kapsam artmadı)", aralık dışı düşüş "tutmadı (kesinlik düştü)" diye ayrı yazılır.
  Gruplar: `derleyici_surumu`, `surum_esli` (AArch64 / Mach-O; yuva okuyucusu var). **`mimari`'de v2
  "desteklenmiyor":** `veri.isaretci_yuvalari` yalnız `R_AARCH64_RELATIVE` ve Mach-O zincirli düzeltmeyi okuyor;
  x86-64 (`R_X86_64_RELATIVE`) PK-2'de eklenmedi (PK-2 yapılmadı). Bu grupta v2 noktaları koşulmaz.
- **(e)** `surum_esli`, birincil nokta `kural`: program başına (iki yönün küçüğü) Wilson alt ≥ 0,909 olan program
  sayısı / ölçülen program sayısı. Ölçülen program ≥ 3 ve geçen ≥ 2 → "tmux'a özgü değil"; ölçülen ≥ 3 ve geçen
  < 2 → "tmux'a özgü" (planın durma ölçütü (a)); ölçülen < 3 → "sayı yetmedi" (hüküm yok). İkincil satır
  `tutucu_v2` aynı kuralla yazılır, birincil hükmü değiştirmez.
- **A-14 iki düzey:** örnek düzeyi (her ikilideki her fonksiyon ayrı) birincildir. Tekil kaynak fonksiyonu düzeyi
  ayrıca: program içinde aynı (normalleştirilmiş) GT ad kümesini taşıyan sorgu fonksiyonları tek öğe sayılır;
  öğe, herhangi bir örneği yanlışsa yanlış, hiçbiri yanlış değil ve en az biri doğruysa doğrudur (tutucu).
- Hata sınıfları `hata_dok` ile (tek taraflı / satır içi / komşu / aile / diğer) dört noktada; çıplak yöntemler
  `ciplak` ile (BSim sütunu bu koşularda anlamsız: her koşunun BSim deposu yalnız kendi ikilisini içeriyor →
  "ölçülmedi" yazılır).
- Tutmayan hipotez silinmez; eşik sonradan değişmez; koşulamayan grup "veri yok" yazılır (0 yazılmaz).

## 4. Kendi tahminim (bağlayıcı değil)

- `mimari`: sürüm aynı, derleyici aynı; tek taraflı pay düşük, kesinlik tur 1 `derleyici` (0,990) civarı; x86-64'te
  Ghidra'nın fonksiyon sınırı farkları satır içi türünü artırabilir.
- `derleyici_surumu`: program sürümü de değiştiği için tur 1 `surum` / `surum_gcc` (0,94–0,95) civarı; tek taraflı
  pay yüksek.
- `surum_esli`: dört programın en az üçünde alt ≥ 0,909; sqlite3 kabuğu ve redis için emin değilim.
