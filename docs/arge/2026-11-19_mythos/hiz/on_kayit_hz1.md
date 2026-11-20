# HZ-1 ön kaydı (ölçüm kancaları; çıktıyı değiştirmez)

Tarih: 2026-11-20. Paket: Dalga 0, HZ1. Plan: `docs/arge/2026-11-19_mythos/hiz/PLAN.md` "HZ-1". Bu metin kod yazılmadan ve "sonra" koşusu başlamadan önce commit'lenir; tutmayan beklenti silinmez, eşik ve hariç alan listesi sonradan değişmez.

## Planın ön kaydı (aynen)

"S8 8 / 8 çıktı eşit; `analyzer_times` 8 / 8 dolu."

## Ölçümün tanımı

- **Önce kolu:** ana oturumun S8 tabanı, `~/karadul_olcum/runs/dalga0-2026-11-20/s8_taban_b6aceb9/` (ürün ağacı `~/karadul_olcum/urun-b6aceb9`). Bu paket tabanı koşmaz.
- **Sonra kolu:** bu dalın son kod commit'inden ürün ağacı `~/karadul_olcum/urun-<kısa-hash>`; ORTAK_D0 §6'daki komutun aynısı, aynı sıra (cat, sort, tree, sqlite3, htop, debian tmux, zstd, mac tmux), kök `~/karadul_olcum/runs/dalga0-2026-11-20/HZ1/s8_sonra_<kısa-hash>/`, kök başına boş `KARADUL_CACHE_DIR=$K/cache` (BSim deposu taban koşusundaki gibi sırayla dolar). `b6aceb9` ile bu dalın tabanı (`e996200`) arasında kod farkı yok (yalnız belge; `git diff --stat b6aceb9 e996200 -- karadul/ scripts/ ui/` boş).
- **Karşılaştırma aracı:** `scripts/arge/hiz/s8_esitlik.py` (bu pakette yazılır). Çalışma alanının zaman damgalı dizini (`ws/workspaces/<ad>/<zaman>/`) eşlenerek kıyaslanır.

## Beklentiler

- **H1 (çıktı eşitliği, 8 / 8):** her ikilide
  - `static/ghidra_output/*.json` ve `static/ghidra_*.json` kopyaları (`ghidra_status.json` hariç): JSON eşit, aşağıdaki hariç alanlar dışında;
  - `static/ghidra_output/decompiled/*.c`: dosya kümesi aynı, her dosya bayt eşit;
  - `naming_map.json` (üç kopya: `out/`, `reconstructed/src/`, `reconstructed/src_iter1/`; hangisi varsa): bayt eşit.
- **H2 (durum dosyası, 8 / 8):** `static/ghidra_status.json`'da önce ↔ sonra farkı yalnız yeni alanlarda: `analysis`, `adim_sureleri`, `decompile_parcalari`; öbür alanlar hariç alanlar dışında eşit.
- **H3 (planın ikinci yarısı, 8 / 8):** `ghidra_status.json` → `analysis.analyzer_times` boş olmayan bir sözlük (en az bir çözümleyici, saniye değeriyle).
- **H4 (kayıt tutarlılığı, 8 / 8):** `adim_sureleri`'nin her anahtarı `karadul/ghidra/headless.py`'deki sabit listede (`GHIDRA_ADIMLARI`); değerler ≥ 0; değerlerin toplamı ≤ `duration_seconds` + 0,01 sn (adımlar köprü süresinin içinde ve ayrık; pay yalnız üç basamaklı yuvarlama için); `decompile_parcalari.parca_sayisi` ≥ 1.
- **Ek satır (kabule girmez):** `static/ghidra_output/pcode.jsonl` bayt eşitliği.

## Hariç tutulan alanlar (zaman ve mutlak yol; taban çıktısında tarandı)

JSON kıyasında (kökten noktalı yol; dosyadan bağımsız):

| Alan | Tür | Görüldüğü dosya |
|---|---|---|
| `duration_seconds` | zaman | `decompiled.json`, `ghidra_decompiled.json` |
| `decompiled_dir` | mutlak yol | `decompiled.json`, `ghidra_decompiled.json` |
| `jsonl_path` | mutlak yol | `pcode.json`, `ghidra_pcode.json` |
| `query_duration` | zaman | `bsim_matches.json`, `ghidra_bsim.json` |
| `timestamp` | zaman | `bsim_shadow.json` |
| `bsim_detail.lock_wait_s`, `bsim_detail.ingest_s`, `bsim_detail.query_s` | zaman | `bsim_matches.json`, `bsim_shadow.json`, `ghidra_bsim.json` |

`ghidra_status.json`'da: `duration_seconds` (zaman), `project.path` (mutlak yol); yeni alanlar `analysis`, `adim_sureleri`, `decompile_parcalari` H2'de ayrıca sayılır.

## Tutmazsa

- H1 / H2'de fark çıkarsa: farklı dosya ve alan yazılır; kodun o alana dokunup dokunmadığı incelenir; "tuttu" yazılmaz. Taban tek koşu olduğu için koşudan koşuya kararsızlık ile bu paketin etkisi ayrılamıyorsa bu da "ayrılamadı" diye yazılır; hariç alan listesi genişletilmez.
- H3 tutmazsa: `analysis.analyzer_times_error` metni yazılır; kayıt kancası doğru ama Ghidra'nın süre metni okunamıyor demektir.

## Süre oranı (plan kabulü "≤ 1,01")

Gündüz, makine yüklüyken ölçülmez (ORTAK_D0 §3). Bu pakette "yapı gereği" yazılır: eklenen iş yalnız `time.monotonic()` çağrıları ve küçük sözlük yazımıdır; sayı ölçülmez, uydurulmaz. Ölçüm gece HZ-0 / ÖLÇ-1 koşusunda.

## Ek (2026-11-20 08:35; kod commit'inden sonra, hiçbir karşılaştırma yapılmadan önce)

Ana oturum tabanın A/A tekrarını koşuyor: aynı ağaç (`urun-b6aceb9`), aynı komut ve sıra, kök `~/karadul_olcum/runs/dalga0-2026-11-20/s8_taban_b6aceb9_AA/`. Bu ek yalnız sınıflamayı belirler; beklentiler, eşikler ve hariç alan listesi değişmez.

- `s8_esitlik.py` iki ayrı tablo yazar: **T-AA** = taban ↔ A/A (koşudan koşuya belirlenimsizlik; kodun etkisi değil), **T-HZ1** = taban ↔ sonra.
- Fark birimi: JSON dosyalarında (dosya, noktalı alan yolu; liste sırası `[]` ile genellenir), `.c` ve `naming_map.json`'da dosya.
- T-HZ1'deki bir fark T-AA'da da (aynı ikili, aynı birim) görülüyorsa "belirlenimsizlik kümesinde" diye ayrı satırda adıyla yazılır; T-AA'da görülmeyen fark "HZ-1'e yüklenebilir" sayılır.
- H1 / H2 hükmü: "HZ-1'e yüklenebilir" fark yoksa tuttu; belirlenimsizlik kümesindeki farklar da ayrıca sayılır ve adıyla raporlanır (hariç listesine eklenmez). Belirlenimsizlik kümesindeki bir alan HZ-1'in de etkileyebileceği bir alansa bu ayrıca yazılır (ayrılamadı).
