# ADR 0007 Ek Karar: Faz A-DELETE v1.13'e Ertelendi

**Durum:** Karar verildi (2026-05-07)
**Bağlı ADR:** [0007 — signature_db.py Dismantle Planı](0007_signature_db_dismantle_plan.md)
**Karar verici:** Berke (nihai), Codex (öneri sahibi 2026-05-07), Architect (plan sahibi)
**Sürüm bağlamı:** v1.12 dalga 2 sonu

---

## Karar

ADR 0007 Faz A-DELETE (legacy `_*_SIGNATURES` dict'lerinin `signature_db.py`'dan silinmesi), **v1.12 sonunda kısmen yapılmayacak**, **bütün olarak v1.13'e ertelenmiştir**.

v1.12 dalga 2 itibarıyla 7/18 kategori migrate edilmiş durumda (crypto, compression, network, pe_runtime, windows_gui, logging, languages). Kalan 11 kategori legacy dict olarak `signature_db.py` içinde kalmaya devam edecek; v1.13–v1.15 arasında migrate edildikten **sonra** tek seferlik A-DELETE uygulanacak.

---

## Gerekçe

### Codex önerisi (2026-05-07)

> "v1.12 dalga 2'de partial A-DELETE riskli — sadece 7/18 kategori migrate edilmiş durumda. Override pattern aktifken bazı dict'leri silip bazılarını silmemek karışık bir kod tabanı yaratır: override+silme matrisi, audit yükü, davranış belirsizliği. Tek seferlik temiz A-DELETE (tüm kategoriler migrate olduktan sonra) daha güvenli."

### Risk Analizi: (a) v1.12 sonu partial A-DELETE vs (b) v1.13 tam A-DELETE

| Boyut | (a) v1.12 sonu partial | (b) v1.13 tam A-DELETE |
|---|---|---|
| Kapsam | 7 kategori dict silinir, 11 kategori legacy kalır | 18 kategori dict aynı anda silinir |
| Kod karmaşası | Yüksek — override+silme karma durumu | Düşük — tek tip durum |
| Audit yükü | Yüksek — her PR'da "bu kategori migrate mi, silindi mi?" sorusu | Düşük — sürüm sınırında net geçiş |
| Rollback | Karmaşık — silinen 7'si farklı, kalan 11'i farklı revert prosedürü | Tek commit revert |
| LOC kazancı | ~2 200 satır (kısmi) | ~6 500+ satır (toplu) |
| Parity test maliyeti | 7 ayrı identity + coverage seti | 1 tam set, daha kolay yönetilir |
| ADR 0007 tutarlılığı | "Önce override, sonra silme — 1 sürüm bekle" pattern'i bozulur | Pattern korunur |

**Seçim: (b)**. Ana motivasyon: ADR 0007 §2'deki "önce override, sonra silme; 1 sürüm boyunca legacy in-place" temel ilkesinin korunması ve audit/rollback maliyetinin minimize edilmesi.

---

## Giriş Kriterleri (v1.13 başlamadan önce sağlanmalı)

A-DELETE PR'ı v1.13 sürüm penceresinde **ancak şu koşullar gerçekleştiğinde** açılır:

1. **Tüm kategoriler migrate edilmiş:** 18/18 kategori `karadul/analyzers/sigdb_builtin/<kategori>.py` modülüne taşınmış, override try/except blokları aktif. Kalan 11 kategori (POSIX system, Linux system, macOS Apple, Windows API, runtimes, database, graphics_media, event_utils, game_ml, strings_module, calls) v1.13–v1.15 arasında migrate edilmiş olmalı.
2. **Override stabilite süresi:** Her kategori en az **1 sürüm** boyunca override pattern altında çalışmış olmalı (legacy fallback aktivasyon riski bilinmeli).
3. **Parity test yeşili:** Her migrate edilmiş kategori için `tests/test_sigdb_<alan>_migration.py` testleri PASS — identity, coverage, no_duplicate_keys.
4. **Full suite:** `pytest tests/ -x --tb=short` 4 100+ PASS, 0 FAIL.
5. **Benchmark stabil:** `SignatureDB` cold init < 1.5s, warm init < 0.05s — son 3 sürümde regresyon yok.
6. **LMDB schema versiyon bump planı hazır:** ADR-003 kapsamında schema_version artırma kararı netleştirilmiş, release note draft mevcut.

---

## Çıkış Kriterleri (A-DELETE PR'ı kabul edilmesi için)

A-DELETE PR'ı (v1.13 hedef sürümünde) **ancak şu koşullar sağlandığında** merge edilir:

1. `signature_db.py` LOC: **10 639 → ≤ 1 500** (Faz A sonu hedefi). `grep -c "^_.*_SIGNATURES" karadul/analyzers/signature_db.py` == 0 olmalı.
2. Override try/except blokları → doğrudan import ifadeleri (rollback gerekirse git revert tek commit'lik).
3. `_load_builtin_signatures` daraltılmış (tek `_merged_builtin_all()` helper).
4. **Match parity:** sample binary üzerinde `match_all()` çıktısı hash karşılaştırması başarılı (önceki sürümle bit-bit aynı).
5. **Test sayısı korundu:** v1.12 sonu PASS sayısı (4 147+) artmış veya aynı, hiçbir test silinmedi.
6. **Release notes:** "LMDB cache rebuild zorunlu" uyarısı + rollback prosedürü dokümante edildi.

---

## Rollback Stratejisi

A-DELETE merge'den **sonra** kritik regresyon tespit edilirse:

1. **v1.13.x patch:** `git revert <a_delete_commit>` — legacy dict'ler tamamen geri yüklenir, override pattern devreye döner.
2. LMDB cache stale ise: `karadul sigdb rebuild` CLI komutu (ADR-003 rebuild path).
3. Patch sürüm release notes'unda: "v1.13 A-DELETE geri alındı, override pattern aktif, v1.13.1 ile düzelt."

Bu sebeple **A-DELETE commit'i atomik olmalı** (tek PR, tek commit, mixed başka değişiklik yok).

---

## Bağlı Güncellemeler

- ADR 0007 §10 madde 2 → karar olarak işaretlendi (bu dosyaya referans verildi).
- ADR 0007 başına "Güncelleme 2026-05-07" kutusu eklendi (v1.12 dalga 2 ilerleme + bu karar özeti).
- ADR 0008 (kalan kategoriler) ile koordineli: A1–A13 sıralaması v1.13–v1.15 arası dağıtılacak; bunun detay tablosu ADR 0008'de güncellenmeli (ayrı görev).

---

## Onay

- [x] Codex önerisi (2026-05-07)
- [ ] Berke onayı
- [ ] Architect plan sahibi onayı
- [ ] Reviewer
