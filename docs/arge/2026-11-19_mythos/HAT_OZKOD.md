# Hat: ÖZ KOD (A5, I1, A6, H2, B1) — tur 1

Hat dizinin: `docs/arge/2026-11-19_mythos/ozkod/`, betikler `scripts/arge/ozkod/`, veri `~/karadul_olcum/runs/arge-2026-11-19/ozkod/`. Önce `ORTAK_BRIF.md`.

## Soru

Programın yalnız kendisinde bulunan koda (hiçbir kitaplıkta olmayan fonksiyonlara) yalnız ikilideki kanıttan hangi adlar **hesaplanabilir**? Tavan nedir; hangi mekanizma ölçülmüş kesinlikle ad verir?

Berke'nin hipotezinin ikinci ve üçüncü kolu budur: "kütüphane bilgisinden rol, programın dizgisinden öğe" (liste I1).

## Bilinenler (üstüne kur)

- Fiil tavanı düşük: Mac tmux ≤ %11,1, Mac htop ≤ %20,6; tablo yuvası kanıtı tmux'ta ≤ %10,6 (`docs/arge/2026-11-10_n4/`, `2026-11-11_n4_v2/`).
- Kebap dizgisini ad yapmak: 239 adda 0 doğru; ad kuralı kurulamadı; en iyi sınıf 5 / 49 (`docs/arge/2026-11-18_onarim/P12b.md`).
- "Benzer imzalı fonksiyonun adı": 0 / 208; gevşek ölçütte 19 / 83 ve 5 / 153 (P11, P15c).
- `string_context/oz_ad`: 197 ad, 93 doğru (%47,2); kalan 119 yanlışın 104'ü buradan; zstd 46, sqlite3 7 yanlış (`sonuc.md` §2, §5).
- Yeni kusur: `c_namer._strategy_string_context` erken dönüşü 19 doğru adı düşürüyor. Onarımı ayrı paket (P12d); sen onu onarmıyorsun.

## Yasak cevap (literatürün beklediği)

- "Dizgilerden anahtar sözcük çıkar, fiil + nesne kur." Ölçüldü, tutmadı.
- "Dil modeli kullan."

## Aykırı öncüller (sına)

1. **Kanıt, adlandırılan fonksiyonun içinde değil, onu kaydeden yerdedir.** Ad taşıyan dizgi çoğu kez fonksiyonun gövdesinde geçmez; fonksiyonun adresiyle **yan yana** durur: komut tablosu, seçenek tablosu, `{ "ad", işlev }` kayıtları, kayıt çağrıları (`…_register("ad", işlev)`, `sqlite3_create_function`, `g_signal_connect(w, "olay", işlev)`, `PyMethodDef`, `luaL_Reg`). Rolü tablonun ya da kayıt çağrısının türü, öğeyi dizgi, **hedefi işaretçi** verir. Kebap adı belki yanlış fonksiyona verildiği için 0 / 239 çıktı (dizgiyi anan fonksiyon ≠ dizgiyle kaydedilen fonksiyon). Bunu say.
2. **"Uygulama adlarının çoğu ikilide hiçbir kanıt taşımaz."** Belirteç düzeyinde say: GT adının belirteçleri (modül öneki, fiil, nesne ayrı ayrı) hangi kanıt kaynağında geçiyor? Kaynaklar: fonksiyonun doğrudan andığı dizgiler; derinlik 1–2'deki çağrılanların dizgileri; kayıt çifti dizgisi; çağrılan içe aktarım adları; çağıran ya da çağrılanın bilinen adı; assert / dosya yolu dizgileri. Tavan kaynak başına ve birleşik.
3. **Liste I1'in kendi aykırı öncülü:** "Rolü veren kitaplık çağrısı çoğu kez adlandırılan fonksiyonda değil, ortak bir sarmalayıcıdadır." Rolün hangi çağrı derinliğinde durduğunu say.

## Bölme

Keşif birimleri ve sınama birimlerini sayılara bakmadan önce deftere yaz. Coreutils tek birim. Öneri: keşif = debian/tmux, openssl, coreutils; sınama = mac/tmux hariç (aynı kaynak) sqlite3, redis-tools, zstd, htop, tree. İstersen değiştir, ama önce yaz.

## Bu turun kalemleri (sırayla)

1. **`oz_ad` ayrımı.** 197 adın doğru / yanlış ayrımını hangi kanıt özelliği yapıyor (dizgi türü, dizginin kaç fonksiyonda geçtiği, adın dizgideki konumu, çağıran / çağrılan ilişkisi)? Keşif birimlerinde oku, sınama birimlerinde say. Çıktı: ayrımcı kural adayı + ön kayıt taslağı.
2. **Kayıt çifti tavanı** (aykırı öncül 1). Geliştirme setinde: veri bölümünde fonksiyon adresine komşu dizgiler; çağrı yerinde birlikte geçen dizgi sabiti ve fonksiyon işaretçisi. Kaç fonksiyon böyle bir çifte sahip; çiftteki dizgi ile GT adı arasındaki ilişki (tam / basit kuralla tam / belirteç örtüşmesi / ilgisiz). N4'ün "tablo yuvası ≤ %10,6" sonucuyla aynı şeyi mi ölçüyorsun, farkı yaz.
3. **Belirteç tavanı** (aykırı öncül 2). Olgu tablosu hazır olunca tam sette; o zamana kadar 2–3 birimde kendi küçük çıkarımınla.
4. **Rol derinliği** (aykırı öncül 3).
5. **A6:** modül öneki yayılımının tavanı (GT'de aynı öneki taşıyan fonksiyonlar çağrı grafiğinde ya da adres sırasında komşu mu).
6. **Bağımsız sınama nüfusu önerisi:** kayıt çiftinin yoğun olduğu yazılım türleri (GTK / GLib, Python C uzantıları, Lua modülleri, …). İndirme listesi: ad, kaynak, boyut. İndirme yapma.

## Çakışma notları

- P12d (`oz_ad` erken dönüşü) ve P05c (parametre adları) onarım işleri; onlara girme.
- "Yakın ad" sayarken ölçüyü kendin uydurma: tam eşitliği ve belirteç kesinliği / duyarlılığını ayrı ayrı yaz; hangi ölçünün insan yargısıyla uyuştuğu ÖLÇÜ hattının işi.
- Ürün kodunu değiştirme; ürüne girecek her şey `PLAN.md`'de Opus paketi olarak yazılır.
