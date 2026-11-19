# P12d ön kayıt — `string_context`: susan adayın kalan adayı örtmesi (erken dönüş ve klasik kanıt seçimi)

- **Tarih:** 2026-11-19. **Durum:** KESİN; ürün kodu değişikliğinden ve yeniden oynatma ölçümünden ÖNCE commit'lenir. Taban `2381dce` (yerel `main` ucu).
- **Önce yapılan (bu belgenin dayanağı):** `P12d.md` Kalem 0. Tanı betikleri (`tani.py`, `tani2.py`, `tani3.py`, `tani3b.py`) ürünün yükleyicileri ve `_strategy_string_context`'iyle a62f15e girdilerinde çalıştı; ad haritası üretmedi, GT'ye bakmadı. Aşağıdaki beklentilerin sayıları oradan.

## 1. Kapsam sapması (yazılı gerekçe)

Paket metni yalnız (a)'yı istiyor: agresif erken dönüş. Tanı:
- 27 kayıp anahtarın hiçbirinde erken dönüş tetiklenmiyor (en yüksek agresif güven 0,65).
- Kayıp, klasik aşamanın kanıt seçiminde. GHIDRA-16'dan sonra dizgi bağları dizgi adresi sırasıyla yükleniyor. Aynı adı aynı puanla veren iki dizgiden önce geleni kanıt oluyor; dosya yolu ya da hata iletisi önde olunca aday susuyor.

Bu yüzden iki değişiklik var, iki ayrı commit:
- **D1** (paketin istediği): erken dönüşü onarır.
- **D2** (kusurun asıl yeri): klasik kanıt seçimini onarır.

D2 aynı fonksiyonda ve aynı K-2 ilkesinde, ama paket metninin kapsam cümlesinin dışında. Ana oturum D2'yi almayabilir; D1 ve belgeler ondan bağımsız.

Kapsam dışı (b) (P12c önerisi, ÖZ KOD hattı) bu değişikliklere girmez:
- birden çok fonksiyonda geçen öz-ad dizgisi;
- öz-ad dizgisinin büyük/küçük harfi.

## 2. Değişiklikler (ölçümden önce tanımlı)

| | Değişiklik | Yer |
|---|---|---|
| D1 | Agresif aday güveni ≥ 0,75 olunca strateji yalnız bu aday susmayacaksa döner. Susacaksa (`_string_sub_channel` susan kümede) klasik aşama da koşar. Susturma kapalıyken davranış aynı. | `c_namer._strategy_string_context` |
| D2 | Klasik aşama dizgileri puana göre sıralar (eşitlikte görülme sırası). Susturma açıkken seçilen dizginin adayı susuyorsa, AYNI puanı ve AYNI adı veren dizgiler arasında susmayan alt kanala düşen ilki kanıt olur. Ad ve güven değişmez; yalnız kanıt, kanıt kaynağı ve alt kanal değişir. Farklı ad veren dizgiye ve daha düşük puanlı dizgiye geçilmez. Susturma kapalıyken davranış aynı. | `c_namer._classic_evidence` (yeni), `_strategy_string_context` |
| D1 + D2 ortak | İşçi süreçler susan kümeyi alır (`_init_heuristic_worker` yeni isteğe bağlı argüman, `initargs` sonuna eklenir). Şu an işçi ad çözücüsü `__new__` ile kuruluyor ve kümeyi görmüyor; bu olmadan iki değişiklik de süreç havuzunda ölü kalır. Aday listesi işçide süzülmez; süzgeç yine ana süreçte. | `c_namer._init_heuristic_worker`, `analyze_and_rename` |

## 3. Kollar ve girdi

- **Girdi:** `urun-onarim-a62f15e`'nin 119 çalışma alanı. SALT OKUR; `yeniden.py` kopyalar, `reconstructed/` ve `reports/` hariç.
- **Yöntem:** yalnız `ReconstructionStage`, Ghidra'sız (P12a / P12c yöntemi).
  - `PYTHONHASHSEED=0`, `PYTHONDONTWRITEBYTECODE=1`, ikili başına ayrı `KARADUL_CACHE_DIR`.
  - Ağaçlar `git archive` ile dışa aktarılır; çalışma zamanı verisi symlink: `sigs`, `vendor`, `signatures*.json`, `signatures.lmdb`, `scripts/node_modules`.
- **Kollar:**
  - taban: `2381dce` (`P12d/agac_taban`) → `P12d/yeniden_taban/`;
  - sonra: D1 + D2'nin son commit'i (`P12d/agac_sonra`) → `P12d/yeniden_sonra/`.
- **Ölçüm:**
  - `urun_olc.py olc` (iki kol, 119; `--mac-veri /Users/apple/Black_Widow/workspaces/olcum_mac`) ve `urun_olc.py karsilastir`;
  - anahtar düzeyinde fark: `ad_fark.py` (P12c'den; kanal / alt kanal kırılımı);
  - köken kaydındaki `silencing.candidates_dropped` toplamları.
- Bütün betikler ölçüm kökünde (depo dışı).

## 4. Hipotezler

Sayılar tanı sayımından (`tani3_taban_ozet.json`, `tani3b_E.json`).

| # | Ölçü | Beklenti (eşik) |
|---|---|---|
| T1 | Tabanda 27 kayıp anahtar (`kayip27.json`) | 27 / 27 adsız (bugünkü `main` kusuru taşıyor) |
| T2 | Taban toplamı ↔ `sonuc.md` (a62f15e) | Yalnız bilgi. a62f15e'den sonra `main`'e P12c ve P05c girdi; fark yazılır, hüküm yok |
| H1 | Kaybedilen 19 doğrudan sonra kolunda yine doğru adı alan | **17** (eşik: tam 17). Paket hedefi 19 / 19: **tutmayacak** (2'sinde öz-ad dizgisi farklı ad veriyor; D2 farklı ada geçmez) |
| H2 | Kaybedilen 8 yanlıştan sonra kolunda ad alan | **0** (eşik: 0) |
| H3 | Tabanda adsız olup sonra kolunda ad alan, 27 dışı anahtar (yeni ad) | **4**: D1'den 1 (zstd), D2'den 3 (debian/tmux 1, mac/tmux 1, zstd 1). `tani3b` E dalında D2 kuralıyla ek çıkarırsa o sayı eklenir (§6'ya yazılır, ölçümden önce). Eşik: tam beklenen sayı |
| H4 | Yeni yanlış (`karsilastir` `yeni_yanlis`) | Paket hedefi 0. **Beklentim 2–4**: zstd'deki 2 yeni ad büyük harfli bir öz-ad dizgisinden (`_sanitize_c_name` küçük harfe çeviriyor) geliyor; tam eşitlikte yanlış sayılır. tmux'taki 2'si bilinmiyor. Hüküm: yeni yanlış = 0 ise "paket hedefi tuttu", değilse "tutmadı" |
| H5 | Öbür kanallar (`string_context/oz_ad` dışındaki her kanal): ad / doğru / yanlış | Fark 0 (eşik: 0) |
| H6 | Değişen genel anahtarlar | Yalnız tanı listesindekiler: B_ayni_ad (20), E_kalan (1) ve §6'daki ek. Hepsi adsız → adlı. Liste dışı değişen genel anahtar: 0. Yerel ad farkı: 0 |
| H7 | Susturulan `agresif` aday sayısı (`silencing.candidates_dropped.agresif`, 119 toplamı) | Değişmez (eşik: tam eşit) |
| H8 | Susturulan klasik aday sayısı (öbür alt kanalların toplamı) | D2: 20 azalır. D1: erken dönüşün kalktığı 26 fonksiyonda klasik adaylar eklenir; bunların 25'i susar, 1'i (E_kalan) kalır. Beklenen net: +25 − 20 = **+5** (± `tani3b` eki). Yalnız bilgi; hüküm yok (aday sayımı yükleme ayrıntısına duyarlı) |

## 5. Önceden yazılan kararlar

- H1, H2 ya da H6 tutmazsa tanı ile ürün ayrışıyor demektir. Ayrışan anahtar tek tek dökülür. Kural değiştirilmez, sonuç "tutmadı" yazılır.
- H4'te yeni yanlış > 0 çıkarsa kural gevşetilmez ya da sıkılaştırılmaz; sonuç ve kaynağı (D1 / D2, ikili) yazılır, karar ana oturumun.
- H5 tutmazsa D1 / D2 başka bir kanala sızıyor demektir. Bu durumda commit'ler geri alınmaz, ama ana oturuma "alma" önerisiyle bildirilir.
- **Aykırı öncül (yazılı):** "Eşitlikte ilk görüleni seçmek tarafsızdır" öncülü doğru olsaydı dizgi sırası adın susmasını belirlemezdi. Tanıda 27 / 27 anahtarda yalnız sıra değişti ve ad sustu. Yani eşitlik kuralı tarafsız değil, yükleme sırasına bağlı. D2 yalnız aynı adı veren eşitlikleri çözer. Farklı adlı eşitlik (23 fonksiyon, 8 yanlışın 8'i dahil) sıraya bağlı kalır. Onu çözmek bir dizginin ad olup olmadığı sorusudur: ÖZ KOD hattı.
- **[seçim]** D1'in biçimi: "susan aday erken dönüşü tetiklemez". "Klasik her durumda koşar" seçilmedi: susturma kapalıyken (testler, ablasyon) davranışı değiştirirdi ve bu kolda kanıt yok.

## 6. Ölçümden önce eklenen tanı sonucu

**Ne yapıldı:** `tani3b.py`, yani `tani3`'ün E dalında D2 kuralını da uygulayan biçimi. Erken dönüşün tetiklendiği 6 ikilide koştu:
- sqlite3, zstd, redis-check-aof, redis-check-rdb, openssl, pzstd;
- E = 26 fonksiyonun hepsi bu ikililerde.

**Sonuç:** E_kalan **1** (zstd, aynı fonksiyon). D2 kuralı E dalına ek ad katmıyor.

**H3 beklentisi kesinleşti:** 27 dışı yeni ad **4**:
- D1'den 1 (zstd);
- D2'den 3 (debian/tmux, mac/tmux, zstd).

pzstd C++ olduğu için ölçü dışı; orada E_kalan zaten 0. Bu ek, D1 commit'inden (`190ddb1`) sonra ama sonra kolunun yeniden oynatmasından ÖNCE yazıldı. §4'teki beklenti ve eşikler değişmedi.
