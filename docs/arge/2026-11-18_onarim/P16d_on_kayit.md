# P16d — ön kayıt (sonra ölçümünden önce yazıldı)

Taban ölçümü (`taban1` ↔ `taban2`, `P16d.md` Kalem 1) bitti; onarım kodu yazıldı ve sahte nesnelerle sınandı; **sonra kolu (`sonra1`, `sonra2`) koşulmadan** bu dosya commit'lendi.

Onarım: (a) `pcode_high_vars` (PyGhidra decompile yolu, tam P-Code yolu) ve CLI betiğinin `high_variables` listesi üretim noktasında depolama yerine göre (alan, sayısal ofset, genişlik; sonra ad, tip, boyut) sıralanır; (b) `c_type_recoverer._load_ghidra_high_vars` kayıtları aynı anahtarla sıralar, aynı ad birden çok kez geçerse bu sıradaki ilk çözülmüş tipi seçer, farklı tipli öbürlerini `ghidra_high_var_duplicates`'e ve günlüğe yazar.

Ölçüm: `sonra1`, `sonra2` = onarım commit'inin ağaç kopyası, `kos.sh` ile (3 ikili, sıralı, taze önbellek, `PYTHONHASHSEED=0`). `karsilastir.py` ve `p09_olc.py` (DWARF; `tree` ve hizalaması varsa `htop`).

| # | Hipotez | Tutma ölçütü |
|---|---|---|
| H1 | `sonra1` ↔ `sonra2`: Ghidra dökümlerinde (zaman / yol dışı) farklı alan 0; `pcode_high_vars` / `vars` sırası farklı fonksiyon 0 (taban: cat 2, tree 7, Mac htop 18 / 30) | 3 / 3 ikilide 0 |
| H2 | `sonra1` ↔ `sonra2`: ürün çıktısında (`out/`, `reconstructed/`, `static/`) zaman alanları dışında fark 0 | 3 / 3 ikilide 0 |
| H3 | `taban1` ↔ `sonra1`, Ghidra dökümleri: fark yalnız `pcode_high_vars` / `vars` sırası (küme aynı); öbür dökümler ve `decompiled/*.c` aynı | 3 / 3 |
| H4 | `taban1` ↔ `sonra1`, ad: `naming_map.json` (out + reconstructed/src), `naming_provenance.json`, `out/src/**/*.c` adları aynı (ad katmanı listeyi okumuyor) | 3 / 3 ikilide `naming_map.json` ve `naming_provenance.json` aynı |
| H5 | `taban1` ↔ `sonra1`, tip: `reconstructed/typed/` farklı dosya ≤ 3 / ikili (2e değişim sırası yalnız önek çakışmasında etkili; taban iki koşusunda sıra farkı varken `typed/` aynıydı) | her ikilide ≤ 3 |
| H6 | DWARF (`p09_olc.py`, hizalaması olan ikililer): Karadul `yanlis` parametre tipi sayısı tabandan fazla değil, `dogru` sayısı tabandan az değil | tutar / tutmaz; fark varsa sayı ve yön yazılır |

Tutmayan hipotez ayrıca yazılır; ölçütler ölçümden sonra değiştirilmez.
