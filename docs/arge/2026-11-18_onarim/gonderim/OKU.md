# Hazır gönderim metinleri (onarım, 2026-11-18)

Ana oturumun ajanlara verdiği paket metinleri. Oturuma özel geçici dizin silinebileceği için buraya kopyalandı; ertesi gün buradan sürdürülür. Canlı durum `../DURUM.md`'dedir; çelişkide DURUM.md geçerlidir.

## Gönderilmiş (kayıt için)
- `PS3.md` — P-S3, 2026-11-18 12:4x'te gönderildi.

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

## Bekçi
`bekci.py` — CLAUDE.md §27 takılma bekçisi: `python3 bekci.py P18=<ajan_id> P20=<ajan_id> …`, Monitor ile (30 dk'da bir yeniden kurulur). Alt ajan transcript dizini oturuma özeldir: `BEKCI_OTURUM_DIZINI` verilmezse en son değişen oturumun `subagents` dizini alınır.

## Atanmamış bulgular (gönderimden önce bir pakete yazılacak)
- **İmza veritabanının adsız fonksiyonlara verdiği adlar** (P11 ölçümü): `call_pattern` 0 / 76, `string_ref` 0 / 132 doğru (12 Debian ikilisi); `read_env_var`, `verify_certificate` gibi betimleyici tahminler, güven 0,56–0,86. Ad haritasına girip girmediği, raporda / arayüzde / `signature_matches.json`'da nasıl göründüğü bakılmadı. K-2: kanal susturulmaz, düzeltilir. Dosya `analyzers/signature_db.py` → P15b'ye eklenebilir (o paketin dosyası) ya da ayrı paket.
- **P15b'ye:** `batch.py` `Config.load` / `--config` (P14 dokunmadı; satır 203-204).
- **MaxSMT kapsamı** (P11): `binary_reconstruction.pcode_selective_ops`'a `CAST` / `PTRSUB` eklemek erişimlerin %37'sini çözülebilir kılar ama P-code'un öbür tüketicilerini etkiler → ayrı ön kayıtlı ölçüm (`config.py` P15b'nin).
- **Silme onayı bekleyenler (Berke):** `stages.py` `_collect_all_algorithms` (P-S2), `vf2_matcher._vf2_worker` / `_serialize_graph` ve eski `computation/fusion/{fuser,model,features,calibration}.py` (P11), ölçüm kopyaları `~/karadul_olcum/runs/onarim-2026-11-18/P-S2/taban_agac/`, `P14/{agac_taban,agac_sonra,yama_dogrulama,kollar}/` (~320 MB).
