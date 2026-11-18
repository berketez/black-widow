# Sağlamlık denetimi — genel-tarama-2026-11-18

- Koşu kökü: `/Users/apple/karadul_olcum/runs/genel-tarama-2026-11-18`; ikili: 14 (künyede beklenen: 14); koşunun ağacı `e9d2d08ab5`
- Denetim: 2026-11-18T09:55:55+0300, 18.9 sn, betik `scripts/measurement/saglamlik_denetle.py`

| Kusur | İkili | Toplam | Örnek |
|---|---|---|---|
| `eski_fonksiyon_adi_yorumda_kalan` | 13 | 773 | debian/coreutils/cat: FUN_001025e0 -> main; debian/coreutils/expr: FUN_001025a0 -> main |
| `bsim_yedege_dustu` | 12 | 12 |  |
| `fonksiyon_anahtari_ghidrada_yok` | 12 | 25 | debian/coreutils/cat: FUN_00103340 -> _start; debian/coreutils/expr: FUN_00102800 -> _start |
| `decompiled_json_kirpik` | 11 | 13664 |  |
| `yerel_ad_uygulanmamis_fonksiyon` | 11 | 490 |  |
| `yerel_son_tur_baska_adla_fonksiyon` | 11 | 2695 |  |
| `yerel_ilk_tur_baska_adla_fonksiyon` | 8 | 35 |  |
| `baslik_tanim_farkli` | 3 | 18 | debian/zstd/pzstd: out/src/src/subsystem_misc/operator.new__.c: başlık operator.new[] / tanım operator_new__; mac/htop: out/src/src/subsystem_misc/_fdopen_DARWI |
| `yeni_ad_var_olan_fonksiyonla_cakisiyor` | 2 | 3 | debian/htop/htop: FUN_001322e4 -> full_write; debian/redis-tools/redis-cli: FUN_00129d40 -> _start |
| `eski_fonksiyon_adi_kodda_kalan` | 1 | 2 | debian/tmux/tmux: FUN_00164a80 -> screen_reflow |
| `turlar_arasi_fonksiyon_adi_farki` | 1 | 2 |  |
