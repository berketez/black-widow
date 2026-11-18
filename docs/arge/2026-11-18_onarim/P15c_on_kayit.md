# P15c — ön kayıt (kod değişmeden önce)

- **Tarih:** 2026-11-18 akşam. **Taban:** `main` = 6a74da0 (P15b dahil; şema 2 veritabanı veri kökünden). Dondurulmuş taban ağacı: `~/karadul_olcum/runs/onarim-2026-11-18/P15c/agac_T` (`git archive` 6a74da0 + çalışma zamanı bağları; `signatures.lmdb` → `~/karadul_olcum/sigdb/s2-20261118/`).
- **Ölçüm kökü:** `~/karadul_olcum/runs/onarim-2026-11-18/P15c/`; betik `p15c_olc.py` (`oynat` = Ghidra'sız `SignatureDB.match_all` yeniden oynatması, ürünle aynı girdi yolları; `tuketici` = ürün çıktısında tüketici sayımı; `ozellik` = kanıt özellikleri).
- **Nüfus:** Ghidra'nın adsız bıraktığı (`FUN_`) fonksiyonlara imza veritabanının `string_ref` / `call_pattern` yoluyla verdiği adlar.

## Setler (geliştirme ↔ kabul ayrı ikililer)
- **Geliştirme:** genel taramanın 14 ikilisi (`genel-tarama-2026-11-18`: 12 Debian + mac htop / tmux). Taban yeniden oynatmasıyla 236 kayıt (P11'in 208'i + Mac 28; ikili başına sayılar 1.23.1 çıktısıyla aynı). Tasarım kararları yalnız bu setle verildi.
- **Kabul (Ghidra'sız):** 119'luk setin geri kalan 105 ikilisi (`urun-yeni2-f30ac9a` Ghidra çıktıları üstünde yeniden oynatma): taban 123 kayıt (`oynat_tam119_T.json`).
- **Ürün koşusu (`kol_kos.py`, `--paralel 1`, `PYTHONHASHSEED=0`, kol başına ayrı `KARADUL_CACHE_DIR`):** geliştirmeden `debian/coreutils/ls`, `debian/tree/tree`, `debian/htop/htop`, `debian/zstd/pzstd`; kabulden `debian/redis-tools/redis-check-aof`, `debian/coreutils/cp`. Kol T = taban ağacı; kol Y = bu paketin son commit'i + bu paketin yamaları uygulanmış dondurulmuş ağaç.

## Gevşek etiket (geliştirme seti; kod değişmeden önce)
- `etiket_gelistirme.json` (sha256 `974bb953…dd2e6`): rubrik v2, **gerçek adın gösterildiği kip** (protokolün cömertlik kipi), tek etiketçi (bu ajan), kör DEĞİL — çift (aday ad, GT adı) birimi; 220 çiftin her biri okundu, `dogru_tarif` / `yalniz_alan` olanlar gerekçeli, kalanlar `yanlis`. "Doğru" = `tam` + `dogru_tarif` (tam ad hiç yok).
- **Sonuç (taban):** `call_pattern` 83 kayıt: doğru_tarif 19, yalnız_alan 30, yanlış 34 → doğru oranı Wilson %95 alt sınırı **0,152**; `string_ref` 153: 5 / 14 / 134 → **0,014**. İmza başına en yüksek alt sınır `connect_by_hostname` 2/2 → 0,342; 0,35'i geçen imza yok.

## Onarım tasarımı (bu kayıttan sonra yazılacak)
1. `SignatureMatch` iddia türü taşır: `symbol` / `byte_pattern` → `kimlik`; `string_ref` / `call_pattern` → `davranis` (yerleşik 246 + 98 imzanın adları betimleyicidir; 337 adın 8'i dışa aktarılmış bir simgeyle rastlantısal aynı). Davranış kaydı kanıt satırlarını taşır (eşleşen dizgiler / çağrılan API'ler) ve `confidence` = yöntemin ölçülmüş gevşek doğru oranının Wilson alt sınırı (`measured_precision.py`, yeni bölüm; eski tam-ad kaydı silinmez). Ham eşleşme puanı ayrı alanda (`match_score`) kalır.
2. Ad (`matched_name`) değişmez: kanal susturulmaz (K-2); kanıt daraltma bu pakette YAPILMAZ (geliştirme setinde ölçüldü: sözcük sınırı + harf duyarlılığı dizgi yanlışını 134 → 50 indiriyor ama doğruyu 5 → 2; çağrı kapsaması doğruyu yanlıştan ayırmıyor — kayıtta, sonraki paket adayı).
3. Tüketiciler (rapor, SARIF; ad haritası ve `signature_matches.json` yamayla) etiketi gösterir: `signature_db:kimlik` ↔ `signature_db:davranis`.

## Beklentiler (kabul ölçütleri)
| # | Ölçüt | Ölçüm | Eşik |
|---|---|---|---|
| H1 | Analistin gördüğü yanlış kimlik iddiası (tam ad yanlış + kimlik etiketi; tabanda etiket olmadığından `signature_db` kaynaklı her kayıt kimlik sayılır) | kabul seti yeniden oynatma (105 ikili) + ürün koşusu (`signature_matches.json` ve ad haritası) | tabandan en az **%90** düşüş |
| H2 | Gevşek doğru ad sayısı | yeniden oynatma: adres başına ad aynı mı; değişen kayıtlar (yalnız aynı fonksiyonda iki yöntem birden eşleşince seçim değişebilir) gevşek etiketlenir | tabandan düşmez |
| H3 | Başka kanalların adı değişmez | ürün koşusu T ↔ Y: ad haritası `mappings` (imza dışı kaynaklar) ve köken kaydı `per_function` | fark **0** (değişirse gerekçe + GT'ye göre yön) |
| H4 | Rapor / SARIF etiketi | ürün koşusu Y: davranış kaydı raporda "kimlik" gibi sunulmuyor; künye, şema ve veri kökü raporda | 6/6 ikili |
