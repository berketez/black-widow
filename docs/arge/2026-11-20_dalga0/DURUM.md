# Dalga 0 — durum (2026-11-20)

Yaşayan kayıt: hangi paket kimde, ne main'e girdi, hangi karar verildi. Oturum yarıda kalırsa buradan sürdürülür.

## Kurallar (bu oturum)

- Berke (2026-11-20 07:5x): "argeyi yapmaya başlatalım … aynı anda 5 ajan olacak şekilde başlayalım."
- Dalga 0 toplam **9 ajan** (aynı anda en çok 5): BAYRAK, OLCUM, OK5, OLCEK, HZ1 (ilk 5); MUTBAKIM, HEDEF, KIMLIK, OL10 (yer açıldıkça). Takılan olursa yerine açılacak ajan sayıya dahildir; aşılırsa Berke'ye sorulur (CLAUDE.md §26).
- Bütün ajanlar Opus 5.5, effort xhigh, kendi worktree'si. Ortak brif `ORTAK_D0.md`; paket metinleri `gonderim/`.
- Ghidra kuyruğu: makinede aynı anda tek koşu; `~/karadul_olcum/ghidra_kuyruk.sh` (kilit `ghidra_kuyruk.lock`, kayıt `ghidra_kuyruk.log`).

## Ana oturum

| Saat | İş | Sonuç |
|---|---|---|
| 07:54–08:02 | Tam takım, main `b6aceb9` | **10 289 geçti / 11 atlandı / 0 kaldı** (475 sn); kayıt `~/karadul_olcum/runs/dalga0-2026-11-20/tam_takim/` |
| 08:03– | Son doğrulama mutasyonları (p18, p20b, lm_kesif, lm_oturum, p20, p09, p16d) — ayrı ağaç `.claude/worktrees/dogrulama-d0` | sürüyor; kayıt `~/karadul_olcum/runs/dalga0-2026-11-20/son_dogrulama/` |
| 08:05– | S8 tabanı (main `b6aceb9`, ağaç `~/karadul_olcum/urun-b6aceb9`) | sürüyor; kök `~/karadul_olcum/runs/dalga0-2026-11-20/s8_taban_b6aceb9/` |
| — | HIZ planı dosya yolu denetimi (`scripts/arge/hiz/plan_yol_denetimi.py`) | yok / beklenmeyen 0, satır aşımı 0; HZ-1 atıfları elle de doğrulandı (`headless.py:267, :713, :1185`; `macho.py:1103`). Kabul ölçütleri denetimi gece koşusundan önce |
| — | Hüküm: `AD_ESIGI = L / (L + 1)` kesirle (A-13'teki "0,909" yuvarlanmış yazım) | BAYRAK paketine yazıldı |

## Paketler

| Paket | Ajan | Durum | Not |
|---|---|---|---|
| BAYRAK | — | gönderilecek | |
| OLCUM | — | gönderilecek | |
| OK5 | — | gönderilecek | |
| OLCEK | — | gönderilecek | |
| HZ1 | — | gönderilecek | |
| MUTBAKIM | — | sırada | son doğrulama koşusu bitince |
| HEDEF | — | sırada | |
| KIMLIK | — | sırada | PK-11 için V5 indirmesi Berke'ye soruluyor |
| OL10 | — | sırada | model sorusu Berke'de (Opus mimar önerildi) |

## Berke'ye sorulanlar / bekleyenler

- V5 indirmesi (PK-11): `libzstd1_1.5.7+dfsg-1_arm64.deb` (266 052 B) ve `libzstd1-dbgsym_1.5.7+dfsg-1_arm64.deb` (1 834 508 B), deb.debian.org (trixie / trixie-debug); sha256 dizinden.
- A-12: Go derleyicisi (133 MB) ve kaynaktan derleme izni.
- Gece koşusu (ÖLÇ-1 + HZ-0, boş makine) ve Avast dışlaması.
- ÖL-10 tasarım turunu kim yapacak.
- Push: son doğrulama mutasyonlarından sonra sorulacak.
