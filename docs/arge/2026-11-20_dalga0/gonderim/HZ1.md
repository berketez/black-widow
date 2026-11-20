# HZ1 — HZ-1 ölçüm kancaları (çıktıyı değiştirmez)

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md`.

**Plan.** `docs/arge/2026-11-19_mythos/hiz/PLAN.md` "HZ-1" (adımlar 1–6, kabul, ön kayıt), §1 (S8, çıktı eşitliği), §5 (`headless.py` sırası: HZ-1 önce, ÖL-1 sonra gelecek ve senin zaman noktalarını kullanacak). Dosya:satır atıfları ana oturumca denetlendi, tutuyor: `karadul/ghidra/headless.py:267` `_analyze_pyghidra`, `:713` `analyzer_times`, `:1185` `_parallel_decompile_java_threads`; `karadul/analyzers/macho.py:1103` `_record_ghidra_outcome`. İlerleme olayı sözleşmesi `olcek/PLAN.md` §1 (olayları ÖL-1 ekleyecek; sen ekleme, ama adım adlarını o sözleşmeyle aynı seç: `ghidra.otomatik_analiz`, `ghidra.decompile`, `ghidra.xref`, `ghidra.cfg`, `ghidra.bsim` …).

**Yazabileceğin dosyalar.** `karadul/ghidra/headless.py`, `karadul/analyzers/macho.py`, yeni `tests/test_hz1_olcum_kancasi.py`, yeni `scripts/measurement/mutation_specs_hz1.json`, var olan `scripts/measurement/mutation_specs_{macho,p16a,p16c,p16d}.json` (yalnız senin değişikliğinle bayatlayan `find` güncellemesi), belgeler `docs/arge/2026-11-19_mythos/hiz/{on_kayit_hz1.md, HZ1.md}`. İlerleme dosyası `hiz/HZ1.md`.
**Dokunma.** Adımların gövdeleri (yalnız zaman ölçümü ve kayıt eklenir), `ghidra_output/*.json` içerikleri, `pipeline_result.json` şeması, `karadul/config.py` (bayrak gerekmez).

## Kalemler

1. **Ön kayıt** (`on_kayit_hz1.md`, koddan önce commit): planın "S8 8 / 8 çıktı eşit; `analyzer_times` 8 / 8 dolu."
2. **Kod** — planın adım 2–4'ü. `adim_sureleri` anahtarları tek yerde sabit bir listeden gelsin (ÖL-1 onu içe aktaracak; ad sözleşmesi yukarıda).
3. **Testler** — planın adım 5'i (sahte program / sahte JVM; `tests/test_p16c_analiz_suresi.py` kalıbı); alanlar dışında `ghidra_status.json` aynı.
4. **Mutasyon** — planın adım 6'sı (3–4 mutant) + var olan `macho`, `p16a`, `p16c`, `p16d` tanımlarını koş: hepsi öldü / hata 0.
5. **S8 çıktı eşitliği.** "Önce" kolu ana oturumun S8 tabanıdır: `~/karadul_olcum/runs/dalga0-2026-11-20/s8_taban_b6aceb9/` (ORTAK_D0 §6; tabanı sen koşma; 8 alt dizinin hepsinde `BITTI` yoksa bekle). "Sonra" kolu: kendi dalının son kod commit'inden ürün ağacı (ORTAK_D0 §3) ve ORTAK_D0 §6'daki AYNI komut, kök `~/karadul_olcum/runs/dalga0-2026-11-20/HZ1/s8_sonra_<kısa-hash>/`. Karşılaştırma: `ghidra_output/*.json` JSON eşitliği (zaman ve mutlak yol alanları hariç; hariç tutulan alan listesini yaz), `decompiled/*.c` bayt, `naming_map.json` bayt; `ghidra_status.json`'da yalnız yeni alanlar fark. Karşılaştırmayı küçük bir betikle yap (`scripts/arge/hiz/s8_esitlik.py`, yeni; dosya listene ekli say) ki sonraki paketler de kullansın.
6. **Süre oranı ≤ 1,01** yük altında ölçülemez: "yapı gereği (yalnız `time.monotonic()` çağrıları); ölçüm gece HZ-0'da" diye yaz; sayı uydurma.

## Kabul

Planınki: S8'de 8 / 8 çıktı eşit, `analyzer_times` 8 / 8 dolu; mutantlar öldü; `tests/test_p16a_ghidra_sonuc.py`, `tests/test_p16c_analiz_suresi.py` ve yeni testler yeşil; tam takım 0 hata. Ürün ağacı worktree'sini silme. Süre: kod 45–60 dk; S8 "sonra" kolu kuyrukta 1–2 sa.
