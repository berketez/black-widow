# BA1 — BA-1: blok açıklama kalıplarında üstel geri izleme (ilerleme)

- Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/BA1.md`
- Dal: `worktree-agent-a6cebf741f6009eac`; taban main `0b4d948` (ff-only, 19:35)
- Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/BA1/`
- Sert son: 21:05

## Durum

- 19:36 başladı; belgeler okundu (ORTAK_D1 §5 dahil, ORTAK_D0, ONARIM_BRIF, KARARLAR A-17 / A-27 / A-35, DURUM "Ollama uçtan uca koşusu", ANA OZET).

## Kalem 1 — kusurun yeniden üretimi (19:40)

- Adımın girdisi: `capa_annotation_decompiled_dir` = `comment_generation`'ın çıktısı `reconstructed/commented/` (CAPA kod beslemesi K-1 gereği kapalı, dizin değişmeden geçer). Kusurlu dosya `…/ws/workspaces/Ollama/20261123_063359/reconstructed/commented/FUN_100295d40.c`, satır 211, `strip()` sonrası 89 karakter: `runtime_memmove(field_ptr_3,iVar14,status_2 << 3,ctx,i,status,accumulator,pbVar13,iVar14,` (çağrı satıra bölünmüş, kapanan ayraç yok). Dosya sıralı listede 7 311. sırada: eski koşunun yazdığı 7 310 dosyanın hemen ardından.
- Araç: `scripts/arge/ba1/kalip_sure.py satir <dosya> 211 --zaman-asimi 20` (her kalıp ayrı çocuk süreçte; `subprocess.run(timeout=…)` süre dolunca SIGKILL).
- Sonuç (eski kalıplar, main `0b4d948`; yük altında): `memcpy` 0,001 ms (eşleşme yok), `memset` 0,001 ms (eşleşme yok), **`memmove` 20 sn'de bitmedi (zaman aşımı, çocuk öldürüldü)**. Ham çıktı `~/karadul_olcum/runs/dalga1-2026-11-23/BA1/ozet/yeniden_uretim_eski.json`. Asılı süreç kalmadı (`pgrep` boş).
- Ön kayıt: `docs/arge/2026-11-23_dalga1/on_kayit_BA1.md` (ayrı commit, hash aşağıda).
