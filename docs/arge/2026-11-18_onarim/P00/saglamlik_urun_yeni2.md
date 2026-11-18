# Sağlamlık denetimi — urun-yeni2-f30ac9a

- Koşu kökü: `/Users/apple/karadul_olcum/runs/urun-yeni2-f30ac9a`; ikili: 119 (künyede beklenen: 119); koşunun ağacı `f30ac9a1d2`
- Denetim: 2026-11-18T09:57:27+0300, 66.2 sn, betik `scripts/measurement/saglamlik_denetle.py`

| Kusur | İkili | Toplam | Örnek |
|---|---|---|---|
| `eski_fonksiyon_adi_yorumda_kalan` | 117 | 1927 | debian/coreutils/[: FUN_001021c0 -> main; debian/coreutils/arch: FUN_001021a0 -> main |
| `fonksiyon_anahtari_ghidrada_yok` | 117 | 234 | debian/coreutils/[: FUN_00102400 -> _start; debian/coreutils/arch: FUN_00102640 -> _start |
| `yerel_ad_uygulanmamis_fonksiyon` | 116 | 2458 |  |
| `bsim_yedege_dustu` | 78 | 78 |  |
| `yerel_son_tur_baska_adla_fonksiyon` | 37 | 5356 |  |
| `yerel_ilk_tur_baska_adla_fonksiyon` | 34 | 122 |  |
| `decompiled_json_kirpik` | 21 | 25640 |  |
| `baslik_tanim_farkli` | 5 | 20 | debian/redis-tools/redis-check-aof: out/src/src/subsystem_misc/long_mul__unsigned_short_62_.c: başlık long_mul<(unsigned_short)62> / tanım 62>; debian/redis-too |
| `yeni_ad_var_olan_fonksiyonla_cakisiyor` | 5 | 6 | debian/htop/htop: FUN_001322e4 -> full_write; debian/redis-tools/redis-benchmark: FUN_0010a000 -> _start |
| `cift_tanim_adres` | 1 | 5 | debian/zstd/pzstd: 00103bc0: out/src/entry.c, out/src/main.c |
| `eski_fonksiyon_adi_kodda_kalan` | 1 | 2 | debian/tmux/tmux: FUN_00164a80 -> screen_reflow |
| `out_proje_agacindan_farkli` | 1 | 1 |  |
| `sayi:log_kaynak_dosya` | 1 | 1 |  |
| `sayi:log_yazilan_dosya` | 1 | 1 |  |
| `turlar_arasi_fonksiyon_adi_farki` | 1 | 2 |  |
