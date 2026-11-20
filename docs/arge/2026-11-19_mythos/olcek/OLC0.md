# ÖLÇ-0 — gösteri koşusunun bitmiş ölçümü (salt okur; 2026-11-20)

Plan: `olcek/PLAN.md` ÖLÇ-0. Ghidra koşusu yok; gösteri dizinine yazılmadı.

## Kaynak ve komutlar

- Koşu: `~/karadul_olcum/runs/gosteri-2026-11-19/ollama/` (Ollama 0.40.3 arm64 dilimi; commit `b4be6f3`; ayar `gosteri.yaml`: "Objective-C Message Analyzer" kapalı). `BASLADI` 2026-11-19 11:10:50, `BITTI` 13:20:12, `CIKIS` = 3 (kısmi: evrensel ikilideki Go dilimi analiz edilmedi; `kosu.log` son satırları). **Yük altında** koşuldu (HIZ BULGULAR: yük ortalaması 40–60).
- Okuma (adım 2): `PYTHONDONTWRITEBYTECODE=1 python scripts/arge/olcek/gosteri_oku.py --gosteri ~/karadul_olcum/runs/gosteri-2026-11-19/ollama --cikti ~/karadul_olcum/runs/arge-2026-11-19/olcek/gosteri_son.json` (2026-11-20 08:31; `kosu_suruyor: false`).
- `out/` diski `gosteri_oku.py`'de yok; aynı `_disk` işleviyle (`scripts/arge/olcek/olcek_topla.py`, ayrılan bayt = `st_blocks × 512`; örneklem modeliyle aynı tanım, `olcek_egri.py:82-84`) ayrıca okundu. Bitişten (`BITTI`) sonra çalışma alanında ve `out/`'ta değişen dosya: 0 / 0 (ölçüm koşunun kendi çıktısı).

## Uçtan uca sayılar (gözlenen)

| Kalem | Değer | Kaynak |
|---|---|---|
| Toplam (`pipeline_result.total_duration`) | 7 729,1 sn | `gosteri_son.json` `pipeline_result` |
| `time -l` gerçek / kullanıcı / sistem | 7 761,62 / 8 050,11 / 447,04 sn | `deneme2_time` (`kosu.log` sonu) |
| Azami RSS / tepe bellek ayak izi | 4 680 646 656 B (4,68 GB) / 5 827 663 560 B (5,83 GB) | `deneme2_time` |
| Aşamalar: identify / static / deobfuscate / reconstruct / report | 0,0 / 4 712,3 / 663,5 / 2 353,1 / 0,06 sn | `pipeline_result.stages` |
| ↳ Ghidra köprüsü | 3 815,4 sn (13 559 fonksiyon) | `ghidra_status.json` |
| ↳ statik aşamanın köprü dışı kısmı | 912,0 sn | `static_kopru_disi_sn` |
| Ghidra adımları (dosya zamanı) | ilk adım 320,6; dizgi 2,6; çağrı grafiği 55,6; decompile 523,9; tip 6,7; xref 348,7; P-code 3,1; CFG 600,9; FunctionID 0,1; BSim 1 951,9 sn | `ghidra_adim_sn_mtime` |
| Çalışma alanı diski (ayrılan) / dosya | 2 164 350 976 B (2,16 GB) / 135 329 | `disk_calisma_alani` |
| `out/` diski (ayrılan) / dosya | 145 985 536 B (146,0 MB) / 13 272 | `_disk(out)` |
| `decompiled/` `.c` | 13 554 | `decompiled_c_dosya` |
| reconstruct `timing_*` kalemi | 37 (iç içe; toplamları aşama süresine eklenmez) | `pipeline_result.stages.reconstruct.stats` |

1. denemenin (ObjC çözümleyicisi açık; otomatik analizde 22+ dk takılı, SIGTERM) `time -l`'i: gerçek 1 687,88 sn, azami RSS 6 401 507 328 B, tepe ayak izi 7 379 524 304 B (`deneme1_time`).

## Ön kayıtla kıyas (ön kayıt 2026-11-19 12:38, `olcek/PLAN.md` ÖLÇ-0; model değiştirilmedi)

Ölçü birimleri ön kayıttaki gibi ondalık (GB = 10⁹ B, MB = 10⁶ B). Hüküm: gözlenen değer p5–p95 aralığının içinde mi.

| Ölçü | Eksen | Öngörü [p5; p95] | Gözlenen | Hüküm |
|---|---|---|---|---|
| reconstruct süresi | fonksiyon | 466 [315; 732] sn | 2 353,1 sn | **tutmadı** (üst sınırın 3,2 katı) |
| reconstruct süresi | kod baytı | 464 [326; 710] sn | 2 353,1 sn | **tutmadı** (3,3 kat) |
| çalışma alanı diski | fonksiyon | 1,95 [1,55; 2,66] GB | 2,16 GB | tuttu |
| çalışma alanı diski | kod baytı | 1,61 [1,38; 2,12] GB | 2,16 GB | **tutmadı** (üst sınırın %2,1 üstü) |
| çalışma alanı dosya sayısı | fonksiyon | 161 700 [159 700; 164 000] | 135 329 | **tutmadı** (alt sınırın %15,3 altı) |
| çalışma alanı dosya sayısı | kod baytı | 114 500 [75 450; 207 200] | 135 329 | tuttu |
| `out/` diski | fonksiyon | 117,7 [97,4; 160,4] MB | 146,0 MB | tuttu |
| `out/` diski | kod baytı | 96,2 [77,8; 144,2] MB | 146,0 MB | **tutmadı** (üst sınırın %1,2 üstü) |
| toplam süre | fonksiyon | 1 108 [727; 1 632] sn | 7 729,1 sn | **tutmadı** (koşu bitmeden belliydi; PLAN) |
| toplam süre | kod baytı | 1 199 [763; 1 827] sn | 7 729,1 sn | **tutmadı** |

Özet: 10 satırın 3'ü tuttu, 7'si tutmadı. Disk ve dosya sayısı modeli eksenlerden birinde tutuyor, öbüründe sınırda kaçırıyor (sapma %1–15); süre modeli örneklem dışında çöküyor (reconstruct 3,2–3,3 kat, toplam 4,2–4,7 kat). Bu, BULGULAR §3.3'ün "örneklemden büyük ikiliye düz dış değerleme yanıltıcıdır" bulgusunu reconstruct ve toplam için de doğruluyor. Ayrım yapılamayan etken: koşu yük altındaydı (yük 40–60); 119'luk örneklem de yük altında ama başka düzeyde (3 paralel + 5–7 ajan).

**Dosya sayısının fonksiyon ekseninde tutmaması:** örneklemde fonksiyon başına ≈ 12,2 dosya (BULGULAR §3.2); gösteride 135 329 / 13 559 = 9,98. Gösteride reconstruct'ın fonksiyon başına daha az kopya yazdığı mı, yoksa 13 559 fonksiyonun bir kısmının (5 fonksiyon `decompiled/`'a girmedi: 13 554) bazı kopya dizinlerine girmediği mi bu okumayla ayrılamadı (dizin başına sayım yapılmadı; ölçülmedi).

## Dürüst sınır cümlesinin güncellenmesi (BULGULAR §5'teki cümlenin yerine)

"Karadul'un uçtan uca ölçülmüş en büyük tek ikili girdisi 26,6 MB'lık bir uygulama dilimidir (Ollama 0.40.3 arm64; 5,5 MB kod, 13 559 fonksiyon): 7 729 sn (2 sa 9 dk), azami RSS 4,68 GB; Ghidra aşaması 63,6 dk (yarısı sonuç üretmeyen BSim); koşu yük altındaydı, Objective-C mesaj çözümleyicisi kapatılmıştı ve çıkış kısmiydi (Go dilimi analiz edilmedi). 100 MB ve üstü tek ikili ile çok bileşenli paket hiç uçtan uca koşulmadı." Boş makine sayıları ÖLÇ-1 + HZ-0 gece koşusundan gelecek (`GECE_PLANI.md`).
