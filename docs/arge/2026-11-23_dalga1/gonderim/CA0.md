# CA0 — ÇA-0: çıktı ağacı tasarım turu (dosya adı ve dizin kurtarılan addan)

Bu bir TASARIM turudur: ürün kodu yazılmaz. Çıktın tek bir tasarım belgesi + onu besleyen kuru sayım betiğidir (ÖL-10 tasarım turunun düzeni: `docs/arge/2026-11-19_mythos/olcek/OL10_TASARIM.md`'ye biçim örneği olarak bak).

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md` (§5, §6), `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-7, A-8, A-10, A-17, A-27, A-28, A-32, A-39 ve "Berke'nin sözleri"), `docs/arge/2026-11-23_dalga1/DURUM.md`'nin "Ollama uçtan uca koşusu 2" bölümü, `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/ollama_ba_kapali/ozet/OZET.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV6a.md` (üst veri adlarının çıktıya nasıl girdiği; `ozgun_ad`), `docs/arge/2026-11-18_onarim/P18.md` varsa (alt sistem başlıklarındaki çelişkili bildirimler).

## Neden

Dünkü Ollama koşusunda çıktıya 10 626 üst veri adı girdi; ama `out/src`'deki 13 159 `.c` dosyasının 12 486'sı hâlâ `FUN_<adres>.c` adında ve 9 448'i tek dizinde (`src/subsystem_group_0`). Ad dosyanın içinde ve başlığında var; dosya adında ve dizin yapısında yok. Go adları paket yolunu (`net/http`, `crypto/ecdsa` …), ObjC adları sınıfı, Swift adları modül ve tipi taşıyor: çıktı ağacı bu bilgiyi kullanmıyor. Analist 13 000 dosyalık düz bir dizinde aradığını bulamaz. Berke (2026-11-24): öneriyi onayladı (A-39) — dosya adı kurtarılan addan, dizin dilin kendi hiyerarşisinden kurulsun.

Dikkat çekici ipucu: aynı çıktıda `main` için `main.c` dosyası var (PUV5 koşularında da). Yani dosya adının addan geldiği bir yol bugün de var; hangi adların o yola girdiğini bulmak tasarımın ilk işi.

## Cevaplanacak sorular (belgenin bölümleri)

1. **Bugünkü akış (kod okuması, dosya:işlev atıflarıyla):** `out/src` ağacını kim kuruyor, dosya adına ve dizine kim karar veriyor (`karadul/core/output_formatter.py`, proje kurma adımı, alt sistem kümeleme), `main.c` neden o adı alıyor, birleştiricinin (`üst veriden`, `c_namer`) adları neden dosya adına yansımıyor. Çalışma alanındaki ara ağaçlar (`reconstructed/{src,merged,typed,commented,annotated,…}`) dosya adını nereden alıyor.
2. **Tüketiciler (tam envanter):** dosya yolunu ya da `FUN_<adres>` dosya adını varsayan her okuyucu — `ui/server.py` (kod görünümü, fonksiyon listesi, köken rozeti), `ui/index.html`, `karadul/lm/` araçları, raporlar (`report.json` / `.md` / `.html`, SARIF: dosya yolları), `naming_map.json`, `naming_provenance.json`, `dependency_graph.json`, `.vscode/` dosyaları, kurulan projenin derleme dosyaları ve `#include` ilişkileri, ölçüm araçları (`urun_olc.py`, `ks1_olc.py`, `ustveri_urun.py`, S8 eşitlik aracı), testler. Her biri için: neyi varsayıyor, yeni düzende ne değişmeli.
3. **Yol türetme kuralı (dil başına, belirlenimci):** Go (`ozgun_ad`'dan paket yolu → dizin; alıcı tip → dosya mı alt dizin mi; kapanışlar `func1`; generics; `vendor/` ve modül yolu; standart kitaplık ↔ üçüncü taraf ↔ kendi kod ayrımı — OL10A'nın sınıfları KENDI / BAGIMLILIK / STANDART kullanılabilir mi), ObjC (sınıf → dosya, kategori), Swift (modül / tip), C++ (RTTI yalnız kanıt satırı: dizine girer mi? ölçülmüş kesinlikle), C (hiyerarşi yok: bugünkü alt sistem kümeleri; `c_namer` adı dosya adına girer mi — etiketi `doğrulanmadı` olan ad dosya adı olur mu?). Adsız fonksiyonlar nerede durur.
4. **Güven ve etiket:** dosya adı da bir iddiadır. Hangi etiketteki ad dosya adına / dizine girebilir (`kesin`, `üst veriden`, `doğrulandı`, `doğrulanmadı`)? Öneri ve gerekçe; yanlış adın dosya adına girmesinin maliyeti (analist yanlış dosyaya bakar) ↔ `FUN_` adının maliyeti.
5. **Çakışma ve dosya sistemi:** macOS öntanımda büyük / küçük harfe DUYARSIZ (`Foo.c` ↔ `foo.c`), yol uzunluğu sınırı, yasak karakterler (Go adlarındaki `(*T)`, `/`, `.`, `[`, boşluk; ObjC `-[A b:c:]`), aynı ada inen iki fonksiyon, Windows'ta ayrılmış adlar. Kural yazılı ve tersinir olmalı.
6. **Adres ↔ dosya eşlemesi tek kaynaktan:** dizin dosyası (şema önerisi), tüketicilerin oradan okuması; eski `FUN_<adres>.c` yolunu varsayanlar için geçiş.
7. **Kararlılık:** aynı ikilinin iki koşusunda aynı ağaç; ad kümesi değişince (bayrak açık ↔ kapalı) ağacın ne kadarının değiştiği; S8 eşitlik denetimlerinin bu değişiklikten sonra neyi kıyaslayacağı.
8. **Bayrak ve öntanım:** yeni düzen bayrak arkasında başlar; öntanımda açma kararı hangi ölçümle verilir. Eski düzen kaldırılmaz (kapsam küçültülmez).
9. **Uygulama planı:** alt paketler (ÇA-A …), her birinin dokunduğu dosyalar, hangi zincire girdiği (`output_formatter.py` bugün PUV6b'de; `ui/server.py` OL4 → GS-1; `karadul/lm/`), sırası, kabul ölçütü ve ön kayıt metni, Ghidra gerekip gerekmediği. Paket başına en çok 5–8 kalem ve kesişmeyen dosya kümesi.
10. **Riskler ve açık kararlar:** Berke / ana oturum için numaralı karar listesi (öneriyle).

## Kuru sayım (tasarımın sayıları; Ghidra yok, ürün kodu değişmez)

`scripts/arge/cikti/kuru_agac.py` (yeni): var olan çıktılar üstünde önerdiğin kuralı uygula ve say — dünkü Ollama çıktısı (`~/karadul_olcum/runs/dalga1-2026-11-23/ANA/ollama_ba_kapali/out` ve `ws`; salt okur), terminal-notifier ve bir Mach-O C ikilisi (`~/karadul_olcum/runs/dalga1-2026-11-23/PUV5/urun/acik/mac/{terminal-notifier,tmux}`), bir ELF C ikilisi (S8 tabanı `ANA/s8_taban_534e252b`'den zstd). Raporla: dizin sayısı, dizin başına dosya dağılımı (en büyük 10; bugün 9 448), adı addan gelen dosya oranı (bugün Ollama'da 673 / 13 159), çakışma sayısı (harf duyarsız dahil), en uzun yol, yasak karakter dönüşümü gereken ad sayısı, sınıf dağılımı (kendi / bağımlılık / standart). Sahte veri yok: ölçmediğini "ölçülmedi" yaz.

## Ana oturumun çerçeve hükümleri

1. Adres ↔ dosya eşlemesi her zaman kurulabilir kalır; hiçbir fonksiyon çıktıda kaybolmaz.
2. Yalnız etiketi ölçülmüş bir kesinliğe dayanan ad dizin yapısını belirler; sorunun cevabını (4) ölçümle gerekçelendir.
3. Arayüz ve KaradulLM yeni düzende çalışmaya devam eder; geçiş sırasında iki düzen birlikte desteklenir.
4. Uydurma hiyerarşi yok: dilin kendi verdiği yapı (paket, sınıf, modül) dışında dizin uydurulmaz; C için bugünkü kümeleme kalır.

## Yazabileceğin dosyalar

`docs/arge/2026-11-19_mythos/cikti/CIKTI_AGACI_TASARIM.md` (yeni dizin), `scripts/arge/cikti/kuru_agac.py`. Başka hiçbir dosyaya yazma.

## Sert son

Gönderim iletisinde yazılı. Belgenin son satırı tam olarak `## PAKET BİTTİ`.

## Dönüş mesajı

İlk satır kuru sayımın sayısı: Ollama'da önerdiğin kuralla dizin sayısı, en kalabalık dizindeki dosya sayısı (bugün 9 448), adı addan gelen dosya oranı (bugün 673 / 13 159), çakışma sayısı. Sonra: bugünkü akışın özeti (`main.c` neden var), tüketici envanterinin sayısı, alt paket listesi, Berke / ana oturum için karar listesi, atıf doğrulaman (belgede geçen dosya:işlev atıflarının kaçı `grep` ile doğrulandı).
