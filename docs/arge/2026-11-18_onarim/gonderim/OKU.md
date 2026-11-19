# Hazır gönderim metinleri (onarım, 2026-11-18)

Ana oturumun ajanlara verdiği paket metinleri. Oturuma özel geçici dizin silinebileceği için buraya kopyalandı; ertesi gün buradan sürdürülür. Canlı durum `../DURUM.md`'dedir; çelişkide DURUM.md geçerlidir.

## Gönderilmiş (kayıt için)
- `PS3.md` — P-S3, 2026-11-18 12:4x'te gönderildi.
- **Akşam 1. dalga (18:06):** `P22b.md`, `P22d.md`, `P13a.md`, `P20.md`, `P15b.md` (istemde dosyaya işaret + akşam ek notları: tabanın bugünkü main olması, paralel paketler, "P22e / P-S4 için" başlıkları; P15b'ye P13a yamalarını uygulamaması ve batch `Config.load` kalemi; imza DB adsız adları P15c'ye).

- **Akşam 2. dalga:** `P16c.md` (18:52), `PS3b.md` (19:04), `P22e.md` (19:05), `P13b.md` (19:18), `P12b.md` (19:20), `P15c.md` (19:22). Berke 19:4x: "ajanların hepsi bitince bi duralım bakalım" → başka gönderim yok.

## DURUŞ (2026-11-18 20:3x) — sonraki oturum buradan
**main'de (akşam):** P20, P22d, P22b, P13a (+ c_namer yaması), P16c, P15b (+ P13a / P20 / P16c / P15b yamaları), P-S3b (+ stages.py yaması), P22e, P13b (+ config yaması), P12b (+ arayüz yamaları), P15c (bkz. DURUM). Her birinde ana oturum: ilgili testler main'de + bağımsız mutasyon main koduyla.

**Gönderilmeyen paketler (sıra önerisi):**
1. Birleşik ölçümden ÖNCE (ad / tip / belirlenimcilik): `P16d.md` (Ghidra döküm sırası; küçük), `P12c` (YAZILMADI: `c_namer._extract_function_bodies` iki satırlı imzanın gövdesini almıyor — 14 ikilide 697 / 13 832 fonksiyon görünmez; ad değişir → ön kayıtlı ölçüm), `P05c.md` (+ kalem 5 n-gram kökeni), `P18.md` (`undefined8` tip kararı), `P08b.md` (FLIRT seçici VT; K-2), `P10b.md` (K-1 yeniden yazım + MaxSMT).
2. Tespit / akış: `P02b.md`, `P03b.md`, `PS4.md` (+ `P20__stages.py.patch`; RTTI üretici adımı P13b'den; `_collect_all_algorithms` silme), `P20b.md`.
3. KaradulLM / arayüz: `P22c.md` (c1 → c2); `P22h` (YAZILMADI: keşif sorusu görevinin ajana bağlanması, oturum bloğunun isteme girmesi, `get_name_provenance`'ın `string_roles`'u okuması — P22e / P12b notları).
4. Son: `P23.md`, kapanış denetimi (137 bulgu + 105 küçük kalem için durum tablosu; 2 salt okur ajan önerilir), birleşik 119 ölçümü (ön kayıt + `urun_kos --paralel 3`, ayrı ağaç `~/karadul_olcum/urun-<commit>` + `signatures.lmdb` bağı), ARGE listesinin son hâli → Mythos.

**Berke'nin kararını bekleyenler:**
- Eski deobfuscation zincirinin `beautify` / `babel_transforms` adımları (P20: A, kopya; `babel_transforms` 5/5 girdide hiç çalışmıyor) silinsin mi? (`synchrony` bayrak arkasında bağlandı.)
- K-2 sonuçları: `kebap_ad` (P12b) ve AD-02 'rol + öğe' için ölçülmüş bir ad kuralı kurulamadı → kanal ad vermiyor, kanıt satırı yazıyor (yanlış ad havuzu %44,7 → %21,1). Kabul mü, yoksa `get_<seçenek>` / `<eylem>_<nesne>` biçimleri bağımsız sınama nüfusu bulunarak (tmux dışı kebap dizgili programlar) araştırılmaya devam mı?
- K-10 ölü kod (eski füzyon, `_collect_all_algorithms`, VF2 süreç yolu): Berke "herhalde hepsi" dedi; ana oturum önerisi silinmesi (P-S4 / P23'te). İtiraz yok sayılmadı, sorulacak.
- Silme onayı: `~/karadul_olcum/runs/onarim-2026-11-18/` bugün 28 GB (akşam paketleri: P12b 4,0 GB, P13a 2,4 GB, P15c 2,2 GB, P15b 1,4 GB, P13b 0,9 GB, P16c 0,5 GB, P-S3b 0,4 GB). Öneri: yalnız kod / ağaç kopyaları ve önbellekler silinsin, koşu çıktıları (raporların kanıtı) kalsın. Genel tarama koşusu 2,0 GB onaylı, ajanlar bittiği için silinebilir. Boş alan 243 GB.
- `sigs/ngram_name_db` uygulama paketine girsin mi (bugün uygulamada n-gram `veri_yok`)? K-5'e benzer.
- Push.

**Atanmamış yeni bulgular (akşam):** gcat'te `close_stdout` yanlış adı (P-S3b'nin ön kayıtlı önerisi P-S3b.md'de); Ghidra `\'` kaçışı dizgiyi kaynak metinle karşılaştıran öbür kanalları da bozuyor olabilir; Mach-O'da `main` kurtarılmıyor; `string_intel` alt kanalı ayrı ölçüm ister (K-2); P13a'dan devreden iki kalan (c_namer kapalıyken ön ad 0,85; FID `caseD_N` yer tutucuları); RTTI üretici adımı ve parametre adı yayılımının uygulanması (`stages.py` + ölçüm); PDB / Go kanalı gerçek Ghidra koşusunda ölçülmedi; decompile işçi sayısı boş makinede ölçülmedi (P16c); KaradulLM gerçek model duman listeleri P21 / P22b / P22e.md'de.

## Akşam yazılanlar (2026-11-18 18:1x)
| Metin | Paket | Önkoşul |
|---|---|---|
| `PS3b.md` | gnulib kanalı: platformdan bağımsız varlık kanıtı, `usage`, `full_write`, LTO'suz iç adlar, aday kaydının rapora taşınması | — (stages.py yaması → P-S4) |
| `P15c.md` | İmza veritabanının adsız fonksiyonlara verdiği adlar (K-2) | P15b (`signature_db.py`) |
| `P10b.md` | Yeniden yazımın açılma kararı (K-1 ad kaynağı ölçümü) + MaxSMT CAST / PTRSUB | — (config yaması → P15b sonrası) |
| `P13b.md` | Bağlı olmayan ad kanalları (K-4) + parametre adı yayılımı | P13a |
| `PS4.md` | `stages.py` 4. tur + bekleyen stages yamaları + `_collect_all_algorithms` silme | P13a, P20, P-S3b (P13b yaması varsa o da) |
| `P22e.md` | KaradulLM oturum / kipler / izin / repl / defter | P22b, P22d |
| `P22c.md` | KaradulLM arayüzü: c1 sunucu → c2 sayfa | P22e |
| `P23.md` | Test, CI, düzen + onaylı ölü kod silme (eski füzyon, VF2 süreç yolu) | dosya sahibi paketler |

## Gönderime hazır
| Metin | Paket | Önkoşul (bitmiş olmalı) | Göndermeden önce |
|---|---|---|---|
| `P18.md` | Çıktı ağacı (ARAYUZ-09, B-B1/B8, `undefined8`, thunk `.c`, `types_candidates`) | — | P12a'nın dosya adı belirlenimciliği sonucu (P12a.md) metne not olarak eklenebilir |
| `P20.md` | JS hattı (BICIM-01/03/11/12, JS ad yardımcıları, eski deobf zinciri A/B kanıtı) | — | — |
| `P13a.md` | Ad yan yolları (AD-04/05/06/09/11/12, B-C6, K-3 A5 silme, bekletilen `808a7f8`) | P12a | P12a'nın `yamalar/P12a__binary_name_extractor*.patch` yaması önce main'e alınır (dosya P13a'nın); P12a.md'deki ön ad güveni metne işlenir; P17 bittiyse "P17 bitti" ifadesi doğrulanır |
| `P12b.md` | K-2 araştırması: `kebap_ad` (AD-01) | P12a | — |
| `P15b.md` | Veri kökü (GHIDRA-14), yeni imza veritabanı (K-5), CLI / ayar kalanları | P14 | P13a'nın config / cli yamaları varsa metne yazılır |
| `P16c.md` | Ghidra hızlandırma (otomatik analiz süre sınırı, çözümleyici profili, toplu BSim) | P11 | P11.md'deki Ghidra betiği değişikliği metne eklenir |
| `P22b.md` | KaradulLM görevler + aşağıdan yukarı özet | P22a | P22d ile aynı anda gönderilebilir |
| `P22d.md` | KaradulLM araç kaydı v2 | P22a | P22b ile aynı anda |
| `P02b.md` | Anti-debug / paketleyici kalanları | — | — |
| `P03b.md` | capa süre / bellek sınırı, kural süzgeci, CRT ayrımı | — | — |
| `P05c.md` | Parametre adları: kanıtsız genel adlar (K-2) | — | P12b ile aynı anda olabilir (dosyalar ayrık) |

## Henüz yazılmadı
- **P-S4** (`stages.py` 4. tur: BICIM-02, 09, 10, 13, BORU-08 + MEK-09 (c) evrensel Mach-O dilimleri, P-S1'in "Analyzer bulunamadi" / "Hedef türü tanınmadı" notu, P13a'nın olası `stages.py` yaması, P14 notu: üç `except RuntimeError` dalı `reconstruct_status: basarisiz` + neden yazsın): P-S3 ve P20'den sonra (BICIM-13 ProjectReconstructor BICIM-01'e bağlı). Dosyalar: `stages.py`, `analyzers/app_bundle.py`, `core/target.py`, `analyzers/python_binary.py`.
- **P13b** (bağlı olmayan ad kanalları, K-4): P13a'dan sonra.
- **P22e** (oturum, kipler, izin, terminal ayrıştırıcısı): P22b + P22d'den sonra. **P22c** (arayüz, c1 sunucu → c2 sayfa): P17 + P22e'den sonra. **P22g** ölçüm ön kaydı.
- **P23** (test, CI, düzen): en son.

## Onarım bitince (sıra, Berke 2026-11-18)
1. Bütün paketler biter (yukarıdakiler + P-S4, P13b, P22e, P22c, P23).
2. Birleşik ürün ölçümü (119 ikili; ayrı `KARADUL_CACHE_DIR`, `PYTHONHASHSEED=0`; yeni imza veritabanı devreye alındıysa onunla).
3. ARGE soru listesi (`docs/arge/2026-11-18_arge_soru_listesi.md`, şu an ARA SÜRÜM) bu sayılarla yeniden güncellenir.
4. Sonra Mythos devreye girer.

## Sürüm
1.24.1 yapıldı (197e416, 2026-11-18 15:0x; tam takım 9 653 / 0). Push yapılmadı; Berke'ye sorulur. `surum_yukselt.py` / `changelog_1241_taslak.md` kayıt için duruyor.

## Bekçi
`bekci.py` — CLAUDE.md §27 takılma bekçisi: `python3 bekci.py P18=<ajan_id> P20=<ajan_id> …`, Monitor ile (30 dk'da bir yeniden kurulur). Alt ajan transcript dizini oturuma özeldir: `BEKCI_OTURUM_DIZINI` verilmezse en son değişen oturumun `subagents` dizini alınır.

## Atanmamış bulgular (gönderimden önce bir pakete yazılacak)
- **Ölçüm araçları (OLCUM ön kaydı, 2026-11-19; `docs/arge/2026-11-19_birlesik_olcum/on_kayit.md` "araç kusurları"):** (1) `ks1_olc.debian_elfleri` `BITTI` içeriğine bakmıyor → kısmi koşu (`3`) `urun_olc`'a bitmiş diye giriyor; (2) `ks1_olc.mac_elfleri` `BITTI`'ye hiç bakmıyor (yalnız `ws/`); (3) `urun_kos` künyesi `KARADUL_CACHE_DIR`'ı ve imza VT şemasını yazmıyor; (4) `urun_olc` ad sınıflayıcısını betiğin ağacından alıyor, ürünle aynı sürüm olduğunu denetlemiyor (gün içinde ad çekirdeğine paket girerse ölçüm ürün ağacından koşulmalı); (5) `kol_butunlugu.py` düzen varsayımı; (6) `urun_olc` `on_ad:gnulib`'i karar nedenine göre ayırmıyor. Aday paket: P23 (ölçüm betikleri) ya da ayrı küçük ölçüm paketi. (1)–(3) birleşik ölçümde `butunluk.py` ile elle denetleniyor.
- **P-S3b (yeni izleme, P-S3'ten):** gnulib ön ad kanalı Mac'te / gnulib 2024+'ta varlığı tanımıyor (Homebrew `gcat`: kanıt 1/2, kanal susuyor; 1 doğru `usage` kayıp). Sürümden ve platformdan bağımsız işaretler (getopt.c metinleri, version-etc'nin ayrı fonksiyonları, error.c) yeni ön kayıtla; doğrulama geliştirme seti dışı Mach-O gnulib programlarıyla (Homebrew m4, gettext araçları). Ayrıca: `usage` gelenek kanalı (zstd + gcat `usage` kaybı), `sort`'ta `full_write` yanlışı (`_exit` dışlaması), LTO'suz yapıda iç adlar (`version_etc_arn`, `safe_write`; K-2), `static/gnulib_candidates.json` adaylarının fonksiyon kartına / rapora taşınması (P07 / arayüz). Dosyalar: `analyzers/gnulib_fingerprints.py`, `stages.py` (P-S4 ile sıralı).
- **gnulib güven satırı** (`naming_labels.MEASURED_PRE_NAME_PRECISION`, 0,706) P-S3'ten sonra bayat: birleşik ölçümde yenilenir.
- **`tarif/evidence.py:80-85`** (P22a yan bulgusu): çağrı argümanındaki dizgi sabitinde geçen `FUN_…` metni geri çağrı sayılıyor; gerçek veride 891 kayıtta 0, ama düşman ikili kanıt paketine sahte geri çağrı ilişkisi sokabilir. Onarım pilotun kanıtını da değiştirir → P12b'ye (tarif/** onun), ölçümle.
- **P22b'ye:** yeni görev türleri `gorev_turu`'yu sabit `TASK_NAME` ile yazan satırı değiştirmeli (P22a notu). **P22d'ye:** yeni adres alanı gelirse `events.TOUCH_*` kuralı (events.py P22a'nın; yama). **P22e'ye:** `iptal` olayını oturum yaysın (ajan yaymıyor).
- **İmza veritabanının adsız fonksiyonlara verdiği adlar** (P11 ölçümü): `call_pattern` 0 / 76, `string_ref` 0 / 132 doğru (12 Debian ikilisi); `read_env_var`, `verify_certificate` gibi betimleyici tahminler, güven 0,56–0,86. Ad haritasına girip girmediği, raporda / arayüzde / `signature_matches.json`'da nasıl göründüğü bakılmadı. K-2: kanal susturulmaz, düzeltilir. Dosya `analyzers/signature_db.py` → P15b'ye eklenebilir (o paketin dosyası) ya da ayrı paket.
- **P15b'ye:** `batch.py` `Config.load` / `--config` (P14 dokunmadı; satır 203-204).
- **MaxSMT kapsamı** (P11): `binary_reconstruction.pcode_selective_ops`'a `CAST` / `PTRSUB` eklemek erişimlerin %37'sini çözülebilir kılar ama P-code'un öbür tüketicilerini etkiler → ayrı ön kayıtlı ölçüm (`config.py` P15b'nin).
- **Silme onayı bekleyenler (Berke):** `stages.py` `_collect_all_algorithms` (P-S2), `vf2_matcher._vf2_worker` / `_serialize_graph` ve eski `computation/fusion/{fuser,model,features,calibration}.py` (P11), ölçüm kopyaları `~/karadul_olcum/runs/onarim-2026-11-18/P-S2/taban_agac/`, `P14/{agac_taban,agac_sonra,yama_dogrulama,kollar}/` (~320 MB).
