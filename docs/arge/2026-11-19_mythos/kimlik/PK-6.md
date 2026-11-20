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
| 3 PK-6 `surum_esli` (V1) | 4 / 4 program iki derleyiciyle derlendi, soyuldu, GT çıktı; koşu sırada | — |
| 4 `iyilestirme` | veri yok (tabaka C Dalga 2'de) | — |
| 5 PK-11 | koşu sırada (iş listesinde ilk) | — |
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
