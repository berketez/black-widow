# P11 ön kayıt — hesaplama kolları (CFG-iso, füzyon, MaxSMT)

Yazıldığı an: hiçbir "sonra" ölçümü koşulmadan (yalnız bulgu metinleri ve taban çıktıları okundu). Taban kod: b7c0872 (dondurulmuş kopya `~/karadul_olcum/runs/onarim-2026-11-18/P11/taban_agac/`). Ölçüm betiği: `scripts/measurement/p11_olc.py`.

## 0. K-1 ve öntanım davranışı
- Üç kolun hiçbirinin çıktısı öntanımda ad haritasına ya da koda girmez. MaxSMT bayrağı (`computation.enable_computation_struct_recovery`) kapalı kalır; P10'un `StructRecoveryEngine.APPLY_REWRITES = False`'u değişmez. Füzyonun ad kanalına tüketimi yeni bir bayrağa bağlanır (öntanım kapalı).
- **Öntanımda değişmesi beklenen tek şey:** `pipeline_result.json` istatistiklerinde üç yeni anahtar (`kol_cfg_iso`, `kol_fuzyon`, `kol_maxsmt`), CFG-iso / füzyon sayaçlarının anlamı (aşağıda) ve `cfg.json`'da blok başına komut adı listesi. Ad haritası ve `out/` kaynak ağacı bu paketten değişmez (gerekçe: üç kolun çıktısını okuyan etkin adım yok; test ile kilitlenir).

## 1. MaxSMT (TIP-03) — Ghidra'sız, var olan P-code üstünde
**Set:** DWARF tip tabanı olan 22 Debian ikilisi (`~/karadul_olcum/runs/t0b-1acba60/hizalama/` adres eşlemesi + `~/karadul_olcum/runs/t0c-a10fde3/dwarf/` yapı yerleşimi), P-code `~/karadul_olcum/runs/urun-yeni2-f30ac9a/` (aynı ikili; sha256 hizalama belgesiyle denetlenir, tutmayan ikili ölçüm dışı ve listelenir).
**Ölçüler:**
- M1 (kusur): LOAD/STORE erişimlerinde ofsetin `input0`'dan (adres alanı kimliği) gelme oranı. Taban: ≥ %99 (bulgu: 27 251 / 27 251). **Sonra: 0** (yapısal; birim testiyle kilitli). Ayrıca kabul edilen erişimlerde ofseti 433 olanların payı < %1.
- M2 (birincil, DWARF): kök varnode'u DWARF'ta `struct S *` olan bir parametrenin giriş yazmacı (AArch64 `x0`–`x7` = `register 0x4000 + 8k`, fonksiyonda tanımı yok) olan tekil (fonksiyon, parametre, ofset, genişlik) erişimleri. Hüküm: B1 `0 ≤ ofset` ve `ofset + genişlik ≤ sizeof(S)`; B2 ofset bir üye başlangıcı; B3 B2 ve genişlik ≤ üye aralığı (sonraki üyenin ofseti − bu ofset; son üyede sizeof − ofset). **Eşik: B2 ≥ 0,80 ve B1 ≥ 0,90 → tuttu.** Altındaysa çıkarıcı adaya veri vermeye uygun sayılmaz (yine de kayıt).
- M3: çözücünün (Z3, fonksiyon başına, sıralı) aynı parametre ailesine verdiği aday alanlarda B2 ≥ 0,80.
- Rapor (eşiksiz): kapsam = en az bir erişimi bulunan DWARF yapı işaretçisi parametresi / bütün yapı işaretçisi parametreleri; düşme nedenleri dağılımı; taban kodun aynı parametre kümesindeki B2'si (taban kodda kök kimliği yok: fonksiyon başına tek değişken; hesaplanabildiği kadar).
- Tehlike (önceden yazılan): JSONL'de CAST / PTRSUB / MULTIEQUAL kaydedilmiyor (`binary_reconstruction.pcode_selective_ops`); bunlarla tanımlanan işaretçiler çözülemez → kapsam düşük olabilir. Kapsam bu paketin eşiği değil; `pcode_selective_ops`'a ekleme `config.py` (P15a) ve P-code'un öbür tüketicileri (fonksiyon sınıflaması → ad adayları) yüzünden yalnız yama + ayrı ölçümle önerilir.

## 2. CFG-iso (TIP-01)
**Ürün koşusu:** 5 ikili, `PYTHONHASHSEED=0`, `--paralel 1`: `debian/coreutils/cat`, `debian/coreutils/ls`, `debian/coreutils/sort`, `debian/coreutils/expr`, `debian/tree/tree`.
- C1: yeni `cfg.json`'da `instruction_count > 0` olan her blokta komut adı listesinin uzunluğu `instruction_count`'a eşit: **%100**.
- C2: öntanımlı şablon bankası (8 elle yazılmış + 307 JSON) gerçek komut adlı AArch64 sorgularında: beklenen eşleşme **0** (banka x86 komut adlarıyla elle / sentetik yazılmış). Adım bu durumda `desteklenmiyor` + neden yazar (sorgu ile bankanın komut sözlüğü kesişmiyor); "çalıştı, 0" yazmaz. Eski kodda sorgu `{"instr": N}` olduğu için 14 HEAD ikilisinin hepsinde LSH adayı 0 (yeniden gösterilir).
- C3 (fizibilite deneyi, ürün değil): şablon = A ikilisinde GT adı olan, en az 5 bloklu fonksiyonun gerçek CFG'si + blok komut histogramı; sorgu = B ikilisinin fonksiyonları (aynı araç zinciri). Çiftler: cat → ls, cat → sort, cat → expr (gnulib ortak). Ölçü: eşleşen (≥ `cfg_iso_min_confidence`) sorgularda kesinlik = GT adı şablon adıyla aynı / eşleşen; duyarlılık = A ve B'de aynı GT adlı (≥ 5 blok) çiftlerden bulunan. **Tahmin: en az 1 doğru eşleşme; kesinlik ≥ 0,90.** Kesinlik < 0,90 ise gerçek koddan banka ad kaynağı olarak kullanılamaz (kayıt).
- C4: VF2 süreç bombası: aday döndüğünde adım ikili başına ≤ 60 sn (5 ikili). VF2 artık süreç başlatmıyor (süreç içi süre sınırı); birim testiyle kilitli.

## 3. Füzyon (TIP-02 + BORU-03)
- F1: imza ve CFG kanıtının anahtarı. Taban: imza `original_name`, CFG adres → kesişim **0** (yapısal). Sonra: ikisi de adres; aynı adresin kanıtları TEK adayda birleşir (ad başına). İki kaynaklı anahtar sayısı raporlanır (öntanımlı bankayla 0 beklenir — C2).
- F2: kabul olasılığı sabit ağırlık / sigmoid (−1,5 → 0,182) yerine kaynağın **ölçülmüş kesinliği**: geliştirme setinde (119 ikili, Ghidra'sız, `urun-yeni2-f30ac9a`), Ghidra'nın adsız bıraktığı (`FUN_`) fonksiyonlarda imza eşleşme yöntemi başına GT kesinliği, Wilson %95 alt sınırı. Tek kaynak: o kaynağın alt sınırı. Aynı adı veren iki kaynak: alt sınırların büyüğü (bağımsızlık varsayılmaz). Ölçülmemiş kaynak (ör. öntanımlı CFG bankası): olasılık yok, karar `abstain` + neden. Kabul eşiği 0,90 (değişmez). Ölçüm tablosu kodla birlikte depoda (köken: set, tarih, n).
- F3: `fused_matches`'i öntanımda okuyan adım yok (test); kabul edilen adlar aday yapıtına yazılır. Ad kanalına tüketim bayrakla (öntanım kapalı); ad kanalının dosyası bu paketin değil → yama.
- `cfg_hash_similarity` totolojisi (şablon adı kendisiyle) kalkar.

## 4. Durum kaydı
Her kol `ctx.stats["kol_<kol>"] = {durum, neden, cikti, sayaçlar}`; `durum` ∈ {`kapali`, `calisti`, `desteklenmiyor`, `hata`}; `cikti` ∈ {`bagli_degil`, `fuzyon_girdisi`, `yapi_adayi`, `ad_adayi`}. Hatada sayaç yazılmaz.

## 5. Değiştirilmeyecek
Eşikler (B2 0,80, B1 0,90, C3 0,90, kabul 0,90) sonuç görüldükten sonra değiştirilmez; tutmayan madde "tutmadı" yazılır.
