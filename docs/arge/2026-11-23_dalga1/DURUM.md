# Uygulama oturumu 2 — durum (2026-11-23)

Yaşayan kayıt: hangi paket kimde, ne main'e girdi, hangi karar verildi. Oturum yarıda kalırsa buradan sürdürülür. Önceki oturumun kaydı `docs/arge/2026-11-20_dalga0/DURUM.md`; plan `docs/arge/2026-11-19_mythos/SONRAKI_OTURUM.md` §8.

## Kurallar (bu oturum)

- Berke (08:0x): "planlamalar Mythos'ta olacak, kodu yazanların hepsi Opus olacak; max 4 ajan yollayabilirsin, max 1 tane Mythos."
- Ana oturum Mythos 5.2: plan, gönderim metni, birleştirme, bağımsız doğrulama. Kod yazmaz.
- Ajanlar: Opus 5.5 xhigh, kendi worktree'si; Mythos ajanı yalnız tasarım belgesi (ÖL-10; A-24).
- **İlk dilim 8 ajan** (aynı anda en çok 4): PUV6a, P16e, PUV3, OL10 (08:1x'te gönderildi); yer açıldıkça PUV5, OL1, PUV4, PUV7. Takılan ajanın yerine açılan sayıya dahildir. Dilim bitince sonraki dilim ayrıca ilan edilir (CLAUDE.md §26).
- Ortak brif `ORTAK_D1.md`; gönderim metinleri `gonderim/`; yamalar `yamalar/`; koşu kökü `~/karadul_olcum/runs/dalga1-2026-11-23/`.

## Sıra mantığı: üç zincir + serbest paketler

Aynı dosyaya yazan paketler sıralı gider (`karsi/CAKISMA.md` §1). Kalan işin kritik yolu iki uzun zincirdir; her zincire bir yuva ayrıldı, öbür yuvalar yalnız yeni dosya yazan paketlere.

| Zincir | Ortak dosya | Sıra |
|---|---|---|
| Ad bağlama | `_feedback_naming_*.py`, `naming_labels.py`, `stages.py`, `baglama.py` | **PUV6a** → PUV5 (`stages.py`) → PK-1 → PK-5 → PK-4 → PK-7 → P-ÜV6b (Swift, RTTI, Go tutarlılık damgası, `main` bayrağı) |
| Ghidra köprüsü | `karadul/ghidra/headless.py` (+ `bsim.py`) | **P16e** → ÖL-1 → ÖL-2 → HZ-2 → ÖL-3 + HZ-4a → HZ-3 → ÖL-6 → ÖL-10 alt paketleri |
| `c_namer` | `karadul/reconstruction/c_namer.py` | P12d → ÖK-1 (aynı ajan; A-20) → ÖK-2 (R1 %79,8 ile yeniden ele alınacak; A-29) |
| Serbest (yalnız yeni dosya ya da ayrık dosya) | — | **PUV3**, PUV4, PUV7, OKUMA, MUTBAKIM-2, ÖL-4, D1, D4, P24, P18, PK-2 → PK-3, P03b / P08b / P10b, ÖL-5a, D2 → ÖL-3b → HZ-6, HZ-7a |

P-ÜV6 ikiye bölündü (ana oturum kararı): plan P-ÜV6'yı altı okuyucu main'deyken tek paket sayıyordu; bugün yalnız Go ve ObjC okuyucuları main'de ve gerçek uygulamadaki en büyük kazanç onlarda (Ollama 10 600 + 151 ad). PUV6a onları bağlar ve ortak altyapıyı kurar; P-ÜV6b kalan kanalları aynı kalıpla ekler.

## Ana oturum

| Saat | İş | Sonuç |
|---|---|---|
| 08:00–08:10 | Durum doğrulaması | main = origin/main = `9c9b2d4`, ağaç temiz; yük 3,3; boş alan 191,8 GB (kullanılan 774,3 GB); Ghidra kuyruğu boş; açık başka oturum: karadelik (ayrı proje) |
| 08:10 | Bu dalganın belgeleri | `ORTAK_D1.md`, `gonderim/{PUV6a,P16e,PUV3,OL10}.md`, bu dosya |

## Paketler

| Paket | Ajan | Model | Durum | Not |
|---|---|---|---|---|
| PUV6a | — | Opus | gönderiliyor | sert son 11:45; ilerleme `docs/arge/2026-11-19_mythos/ustveri/P-UV6a.md` |
| P16e | — | Opus | gönderiliyor | sert son 10:45; ilerleme `docs/arge/2026-11-19_mythos/hiz/P16e.md` |
| PUV3 | — | Opus | gönderiliyor | sert son 11:30; ilerleme `docs/arge/2026-11-19_mythos/ustveri/P-UV3.md` |
| OL10 | — | Mythos | gönderiliyor | sert son 10:45; çıktı `docs/arge/2026-11-19_mythos/olcek/OL10_TASARIM.md` |
| PUV5 | — | Opus | sırada (PUV6a main'e girince; `stages.py`) | metin `docs/arge/2026-11-20_dalga0/gonderim/PUV5.md` (saatler güncellenecek) |
| OL1 | — | Opus | sırada (P16e main'e girince; `headless.py`) | `olcek/PLAN.md` ÖL-1 |
| PUV4 | — | Opus | sırada (yer açılınca) | `ustveri/PLAN.md` P-ÜV4 |
| PUV7 | — | Opus | sırada (yer açılınca) | `ustveri/PLAN.md` P-ÜV7 |

## Açık kararlar ve bekleyenler

- **Üst veri bayraklarının öntanımda açılması (K-4):** A-14 kanal başına en az 3 bağımsız program ister; bugün Go'da 2, ObjC'de 2 GT'li program var. Üçüncü programlar: Go için P-ÜV9 kalem 3 (Go derleyicisiyle sembollü + soyulmuş derleme çifti; A-23 izni var), ObjC için hedef setine üçüncü sembollü ObjC ikilisi. PUV6a main'e girince küçük bir "açılış ölçümü" paketiyle kapatılacak; o zamana kadar adlar yalnız bayrak açıkken yazılır.
- Ollama'nın uçtan uca ürün koşusu (bayraklar açık): PUV6a main'e girince ana oturum kuyruğa koyar (2 saatten uzun).
- Gece koşusu (HZ-0 + ÖLÇ-1; A-26) ve KIMLIK'in kalan 35 çifti: Berke'nin izniyle.
- Push: oturum sonunda sorulur.
- Disk: kullanılan alan 13 Ekim'de 568 GB'tı, bugün 774 GB. `.claude/worktrees` 4,0 GB (70 ağaç). Nereye gittiği ölçülecek; silme kalem kalem Berke'nin onayıyla.
