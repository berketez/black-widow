# BAYRAK — bayrak ön paketi (KARARLAR A-19 a, A-13)

Önce oku: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md`.

**Plan kaynakları.** Alan listesi `docs/arge/2026-11-19_mythos/karsi/CAKISMA.md` §2.1. Alanların tanımı her hattın planında: `kimlik/PLAN.md` (PK-4, PK-5, PK-7), `ozkod/PLAN.md` (ÖK-1, ÖK-2, ÖK-3, ÖK-4b, ÖK-6), `ustveri/PLAN.md` (P-ÜV6), `olcek/PLAN.md` (ÖL-1, ÖL-2, ÖL-5a, ÖL-6, ÖL-7 `reconstruct.ara_kopyalar`, ÖL-9, ÖL-10, ÖL-11), `hiz/PLAN.md` (HZ-5 donanım künyesi; HZ-2, HZ-3, HZ-7a, HZ-7b, HZ-7c, HZ-7d bayrakları). Hepsi `docs/arge/2026-11-19_mythos/` altında.

**Amaç.** Sonraki paketlerin `karadul/config.py`'ye sırayla yazmasını kaldırmak: bütün planların yeni alanları tek pakette, hepsi okunmayan (etkisiz) alan olarak `INERT_SETTINGS`'te kayıtlı; ad eşiği sabiti tek yerde.

**Yazabileceğin dosyalar.** `karadul/config.py`; `karadul/core/naming_labels.py` (yalnız yeni sabitler `MALIYET_ORANI_L`, `AD_ESIGI`; var olan satırlara — `MEASURED_PRE_NAME_PRECISION` dahil — dokunma); yeni `tests/test_bayrak_on_paketi.py`; yeni `scripts/measurement/mutation_specs_bayrak.json`; ilerleme `docs/arge/2026-11-20_dalga0/BAYRAK.md`. Alan listesi başka bir dosyada da tutuluyorsa (örnek ayar dosyası, ayar belgesi, şema): yazma, yama bırak.
**Dokunma.** Başka her şey; `tests/test_p15a_etkisiz.py` dahil (yalnız koş). Ghidra koşusu yok.

## Kalemler

1. **Envanter** (commit). CAKISMA §2.1'deki ve planlardaki her yeni `config.py` alanı için: tam yol (bölüm.alan), tür, öntanım, anlamı, bağlayacak paket, planın satırı. A-19 a "bütün planların" der: CAKISMA §2.1'in saymadığı ama bir planın eklediği alanlar da (HIZ bayrakları, ÖL-* bütçe alanları) bu pakete girer. Planda tanımı olmayan / çelişen alanı ayrı listele: uydurma; en dar güvenli tanımı seç, gerekçesini yaz.
   - Öntanım kuralı: yeni yöntem bayrakları **kapalı**; sayısal bütçe / eşik alanlarında öntanım bugünkü davranışı aynen korur (ör. "sınır yok" anlamına gelen değer). Alanlar bu pakette okunmaz; davranış değişmez.
   - Var olan bir alanın değerini ya da davranışını değiştiren işler (HZ-5'in işçi / JVM yığını formülleri, ÖL-1 / ÖL-2'nin var olan `Timeouts` değerleri) bu paketin işi DEĞİL; yalnız yeni alan eklenir.
2. **Alanları ekle.** Var olan bölüm (dataclass) yapısına uy; yeni bölüm gerekiyorsa planın adıyla. YAML'dan yükleme, tür denetimi, bilinmeyen anahtar davranışı var olan mekanizmayla çalışsın. Her alanın yanında tek satır Türkçe açıklama ve `# ETKİSİZ: <paket> bağlayacak (INERT_SETTINGS)`.
3. **`INERT_SETTINGS`.** Her yeni alanı kaydet. Bağlayan paket bu satırı silmek zorunda kalacak ama `config.py`'ye yazmayacak (satır silme yamasını ana oturum uygular): bunu en az çakışan biçimde düzenle (ör. yeni alanlar tek blokta, alan başına tek satır) ve ilerleme dosyasına "alan → bağlayacak paket → dalga → silinecek INERT satırı" tablosunu yaz.
4. **`naming_labels.py`.** `MALIYET_ORANI_L = 10` ve `AD_ESIGI = MALIYET_ORANI_L / (MALIYET_ORANI_L + 1)` (= 0,90909…). Ana oturum hükmü (2026-11-20): KARARLAR A-13'teki "0,909" bu kesrin yuvarlanmış yazımıdır; sabit kesirle tanımlanır. Belge dizgisinde A-2 / A-13 / A-14 kuralı ("Wilson alt sınırı ≥ AD_ESIGI, örnek düzeyi, yön başına, en az 3 bağımsız programda ölçülmüş"). Depoda bu eşiği başka yerde tanımlayan kod varsa (`grep -rn "0\.909\|AD_ESIGI" karadul scripts`) listele, değiştirme.
5. **Testler** (`tests/test_bayrak_on_paketi.py`): (a) her yeni alan var; türü ve öntanımı envanterdeki gibi (tablo güdümlü); (b) her yeni alan `INERT_SETTINGS`'te; (c) boş YAML ile ve depodaki örnek ayar dosyalarıyla yüklenen `Config`'in yeni alanlar dışındaki içeriği değişmedi (var olan dışa aktarma / karşılaştırma mekanizmasını bul ve kullan); (d) YAML'da her yeni bölüm için bir değer verilince alan değişiyor; (e) `AD_ESIGI` ↔ `MALIYET_ORANI_L` ilişkisi.
6. **Davranış değişmedi kanıtı.** `tests/test_p15a_etkisiz.py`, config testleri, tam takım. Yeni alanların hiçbir yerde okunmadığını `grep` ile göster.
7. **Mutasyon** (`mutation_specs_bayrak.json`, en az 5): bir bayrağın öntanımını aç; bir alanı INERT kaydından çıkar; bir alanın türünü değiştir; `AD_ESIGI` formülünü boz (`+ 1` → `+ 2`); YAML okuyucusunda yeni bir bölümü atla. Hepsi ölmeli.

## Kabul

Envanterdeki her alan dalında; öntanımlı davranış aynı (tam takım 0 hata, `test_p15a_etkisiz` yeşil); mutantlar öldü; bağlama tablosu ilerleme dosyasında. Süre hedefi 60–90 dk.
