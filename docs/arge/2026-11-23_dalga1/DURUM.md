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
| 08:10 | Bu dalganın belgeleri | `ORTAK_D1.md`, `gonderim/{PUV6a,P16e,PUV3,OL10}.md`, bu dosya (`f2b0db5`) |
| 08:11 | İlk dört ajan gönderildi; bekçi kuruldu | `bekci_d0.py` (Monitor, 30 dk'da bir yeniden); OL10 için "model düşmesi" satırı beklenen (Mythos ajanı) |
| 08:2x | Sıradaki dört paketin metni | `gonderim/{OL1,PUV4,PUV5,PUV7}.md` |

## Paketler

| Paket | Ajan | Model | Durum | Not |
|---|---|---|---|---|
| PUV6a | a42e3d495be90379d | Opus | çalışıyor (08:11) | sert son 11:45; ilerleme `docs/arge/2026-11-19_mythos/ustveri/P-UV6a.md` |
| P16e | a55c97e3a05c70d6f | Opus | çalışıyor (08:11) | sert son 10:45; ilerleme `docs/arge/2026-11-19_mythos/hiz/P16e.md` |
| PUV3 | a14ae2562cbc29126 | Opus | çalışıyor (08:11) | sert son 11:30; ilerleme `docs/arge/2026-11-19_mythos/ustveri/P-UV3.md` |
| OL10 | a8420740e5db17ed4 | Mythos | **bitti 08:55; main'de** (`2cc31dc..15013bb`, 8 commit, yalnız belge) | `olcek/OL10_TASARIM.md` 896 satır: üç katman (K0 Ghidra'sız, K1 çözümleme, K2 seçilenlerin decompile'ı), seçim kuralı, ad kanalı sözleşmesi, 10 alt paket (OL10-A … J). Ollama'da kendiliğinden seçilebilen küme 4 619 / 13 160; gösterinin 17 adının 17'si ilk 4 028'de; xref dökümü K1'in iki dosyasından türetilebiliyor (13 559 / 13 559 aynı). **Bağımsız denetim (ana oturum):** tam yollu 39 atıfta dosya yok 0, satır aşımı 0; 8 işlev adı çapası 8 / 8 tuttu. Kararlar A-33 |
| PUV5 | — | Opus | sırada (PUV6a main'e girince; `stages.py`) | metin hazır: `gonderim/PUV5.md` |
| OL1 | — | Opus | sırada (P16e main'e girince; `headless.py`) | metin hazır: `gonderim/OL1.md` |
| PUV4 | — | Opus | sırada (yer açılınca) | metin hazır: `gonderim/PUV4.md` |
| PUV7 | ade3c0e98c5bfe6e0 | Opus | çalışıyor (08:57) | sert son 11:30; ilerleme `docs/arge/2026-11-19_mythos/ustveri/P-UV7.md` |
| PK1 | — | Opus | sırada (PUV6a main'e girince; ikinci dilim) | metin hazır: `gonderim/PK1.md` |
| OK1 | — | Opus | sırada (PUV6a main'e girince; `alt_kanal.py`; ikinci dilim) | metin hazır: `gonderim/OK1.md` (P12d + ÖK-1) |
| OL10A | — | Opus | sırada (yer açılınca; yalnız yeni dosya; ikinci dilim) | metin hazır: `gonderim/OL10A.md` |

## Açık kararlar ve bekleyenler

- **Üst veri bayraklarının öntanımda açılması (K-4):** A-14 kanal başına en az 3 bağımsız program ister; bugün Go'da 2, ObjC'de 2 GT'li program var. Üçüncü programlar: Go için P-ÜV9 kalem 3 (Go derleyicisiyle sembollü + soyulmuş derleme çifti; A-23 izni var), ObjC için hedef setine üçüncü sembollü ObjC ikilisi. PUV6a main'e girince küçük bir "açılış ölçümü" paketiyle kapatılacak; o zamana kadar adlar yalnız bayrak açıkken yazılır.
- Ollama'nın uçtan uca ürün koşusu (bayraklar açık): PUV6a main'e girince ana oturum kuyruğa koyar (2 saatten uzun).
- Gece koşusu (HZ-0 + ÖLÇ-1; A-26) ve KIMLIK'in kalan 35 çifti: Berke'nin izniyle.
- Push: oturum sonunda sorulur.
- **Disk temizliği (08:15–08:40; Berke: "100 GB kadarını sil" → liste sunuldu → "onları sil, gerisi kalsın şimdilik"):** kullanılan alan 774,2 → **698,4 GB** (75,8 GB açıldı; boş 267,7 GB). Ölçüm `diskutil` + `~/.claude/scripts/disk/tara.py`. 13 Ekim'den beri büyüme: `~/karadul_olcum` +103 GB (her onarım paketi 119 ikilinin çalışma alanlarını saklamış), `~/HRMA-wt` +69, `~/HRMA-calisma` +43, `~/Library` +51.
  - Silinen (Berke'nin onayıyla): **A** `~/karadul_olcum/runs/onarim-2026-11-18/{P-S3,P12a,P12b,P13a,P13b,P15b,P15c,P16a,P16b,P16c,P07,P-S1,P-S2}` ve `onarim-2026-11-19/{P12c,P-S4,P16d}` (main'e girmiş paketlerin koşu çıktıları; sayıları raporlarda); **C** 72 eski ajan / doğrulama worktree'si (77 dalın hepsi duruyor; kalan ağaçlar: bugünkü dört ajan + P12d `agent-a733cb2eb8bc2b9fd`); **D** HRMA `v307/` altı onarım ağacı; **E** HRMA `v306-bakim` + `yayin/3.0.7-paket` (dallar ve `v3.0.7` etiketi duruyor); **H** Homebrew indirme önbelleği.
  - Kalan, karar bekleyen: **B** `~/karadul_olcum/ozkod_nufus/runs` 8,7 GB (kör nüfus önbelleği); **F** HRMA harita indirilenleri 10,4 GB; **G** HRMA eski çalışma dizinleri 15,7 GB; **I** Claude masaüstü `vm_bundles` 12,2 GB.
  - Saklananlar (bekleyen işler okuyor): `onarim-2026-11-18/{P-S3b,P10,P00,ana,…}`, `onarim-2026-11-19/{P12d,P18,OLCUM}`, `urun-onarim-a62f15e`, `urun-yeni2-f30ac9a`, `urun-yeni-93a2956` (yerleşim betikleri), `dalga0-2026-11-20`, `arge-2026-11-19`, `gosteri-2026-11-19`.
  - Doğrulama ağaçları (`dogrulama-d0`, `-d0b`, `-aksam`) silindi; bağımsız doğrulama için yenisi açılacak.
  - Ders: koşu çıktısı üreten paketin metnine "main'e girince çalışma alanlarını sil, yalnız ölçüm özetini sakla" satırı yazılacak.
