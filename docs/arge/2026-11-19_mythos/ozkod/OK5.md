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
