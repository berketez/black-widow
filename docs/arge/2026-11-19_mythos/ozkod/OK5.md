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
