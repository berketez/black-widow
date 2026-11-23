# Ön kayıt — P-ÜV4 (C++ RTTI sembolsüz tarama + `rtti_recovery` üretici adımı), 2026-11-23

Bu metin koddan ve ölçümden ÖNCE commit'lenir. Tutmayan beklenti silinmez; eşik sonradan değişmez.
Paket metni `docs/arge/2026-11-23_dalga1/gonderim/PUV4.md`; plan `ustveri/PLAN.md` "P-ÜV4"; kararlar A-10, A-13,
A-14, A-27, A-32 (yuva = kanıt satırı, P-ÜV6b), A-34 (`config.py` yaması ajan ağacında uygulanmaz).
Taban commit: `bcbc183` (main; `git merge --ff-only main`).

**Bu kayıttan önce görülenler (dürüstlük notu):**
- Araştırma tarayıcısı `scripts/arge/ustveri/cpp_rtti_tara.py` (kaynak kod) ve `BULGULAR.md` §0 / §4 / §6.1 tabloları.
  §4 tablosu sınama ikililerinin (llama-server, iTerm2) **toplu** sembol karşılaştırma sonuçlarını içeriyor
  (1 994 / 1 994, 1 317 / 1 317, 7 023 / 9 / 21; iTerm2 18 / 10 / 63 / 1 / 0); bunlar belgede yazılı sayılar, GT
  dosyası açılmadı.
- `$V/rtti/btop.json` (`$V` = `~/karadul_olcum/runs/arge-2026-11-19/ustveri`) bütünüyle (btop keşif ikilisi; sembol
  karşılaştırması dahil). `$V/rtti/llama-server.arm64.json`, `iTerm2.arm64.json`, `Ollama.*.json` **açılmadı**;
  H1 karşılaştırması onların yalnız sayım alanlarını (`typeinfo`, `vtable`, `ayrik_islev`) okuyan betikle yapılacak.
- pzstd (Debian 13 arm64) ikilisinin ve dbgsym dosyasının yolu (`file` çıktısı); içerikleri açılmadı.

## 1. Hipotezler (plan + gönderim metni, aynen)

> **H0 (keşif, yerel örnekler):** sembollü kopyada her `_ZTI` sembolü için typeinfo bulunur, adı sembolle aynı; her
> `_ZTV` için vtable adresi sembolle aynı; yuva işlevlerinin sembolü sınıfın ya da tabanının adını taşır (saf sanal ve
> içe aktarım yuvası hariç). Soyulmuş kopyada çıktı sembollüyle aynı (fark 0). arm64 ve x86_64'te sınıf kümesi aynı.
>
> **H1:** 5 Mach-O hedefinde üç sayı başvuruyla aynı.
>
> **H2 (SINAMA, bir kez; tarayıcı dondurulduktan sonra):** llama-server + iTerm2 + btop'ta typeinfo adı 2 028 / 2 028,
> vtable 1 328 / 1 328 sembolle aynı; yuva → sınıf bağı ≥ 7 098 / 7 119. Tutmazsa tarayıcı sınama sonucuna göre YENİDEN
> AYARLANMAZ; hangi sınıf türlerinde (şablon, sanal kalıtım, adsız ad alanı, öbür) kaç yanlış olduğu yazılır.
>
> **H3:** Ollama arm64 ve x86_64 dilimleri aynı sayıyı verir (19 / 8 / 68); zayıf bağ çözümünü kaldıran mutant x86_64'te
> ≤ 4 typeinfo bulur.
>
> **H4:** bulanık girdide istisna 0, süre aşımı 0.
>
> **H5:** ELF `pzstd`'de en az 1 vtable bulunur ve sınıf adı eşleşmesi ≥ %99 (ilk ölçüm; tutmazsa ELF yolu
> `desteklenmiyor` kalır).
>
> **H6 (beklenen sınır):** yuvadan yöntem adı çıkmaz; aday `Sınıf_vfunc_N` biçimindedir ve doğruluğu "tam eşitlik"
> ölçüsünde 0'dır → bu adaylar ad olarak değil kanıt satırı olarak yazılmalıdır (karar P-ÜV6).

Kabul ölçütü (plan): sayılar `$V/rtti/<ad>.json` ile aynı: btop 42 typeinfo / 36 vtable / 84 işlev; iTerm2 arm64
18 / 10 / 64; llama-server arm64 1 994 / 1 317 / 7 053; Ollama arm64 ve x86_64 19 / 8 / 68. Sembollü ikililerde
typeinfo adı 2 028 / 2 028, vtable 1 328 / 1 328 sembolle aynı; yuva işlevinin sembolü sınıfın ya da tabanının adını
taşıyor ≥ 7 098 / 7 119 (Wilson alt sınırı ≥ 0,99). ELF `pzstd`: bulunan sınıf adlarının dbgsym'deki `_ZTI`
sembolleriyle eşleşmesi ≥ %99.

## 2. İşlem tanımları (ölçümden önce sabitlenir)

- **Girdi:** `$V/hedef/` araştırma kopyaları (`btop`, `iTerm2.arm64`, `llama-server.arm64`, `Ollama.arm64`,
  `Ollama.x86_64`); pzstd `~/karadul_olcum/downloads/debian13/x_zstd_1.5.7+dfsg-1_arm64/usr/bin/pzstd`, GT
  `…/x_zstd-dbgsym_1.5.7+dfsg-1_arm64/usr/lib/debug/.build-id/7e/170a7ec030c257c2a884cc2bcc4b459ebdad4e.debug`
  (`.symtab`, P-ÜV0 ELF görüntüsüyle okunur). Tarayıcı P-ÜV0 `Goruntu` üstünden çalışır, sembol tablosuna yalnız zayıf
  bağ adını yerel adrese çevirmek için bakar. Hiçbir ikili çalıştırılmaz.
- **Üç sayı (H1, H3):** `typeinfo` = bulunan typeinfo nesnesi; `vtable` = bulunan vtable kaydı (birincil + ikincil;
  yuvası olmayan aday sayılmaz); `işlev` = yuvalardaki ayrık yerel kod adresi (içe aktarım yuvası hariç). Başvurunun
  alanları: `typeinfo`, `vtable`, `ayrik_islev`. Hüküm: üçü de eşit.
- **typeinfo adı eşitliği (H0, H2, H5):** adresinde tanımlı `_ZTI…` sembolü olan typeinfo kayıtlarında sembol =
  `_ZTI` + ad dizgisi (Mach-O'da baştaki `_` fazlası soyulur; GCC'nin yerel ad işareti `*` adın parçası sayılmaz).
  Pay: aynı; payda: adresinde `_ZTI` sembolü olan kayıt. Ayrıca yazılır: tanımlı `_ZTI` sembolü olup kayıt bulunmayan
  adres sayısı (kaçan).
- **vtable eşitliği (H0, H2):** başvurunun tanımı: birincil vtable (tepeye uzaklık 0) kaydının adresi (tepeye uzaklık
  sözcüğü) bir `_ZTV…` sembolünün adresiyse sembol = `_ZTV` + sınıf adı mı. Pay / payda bu kayıtlar. Ayrıca yazılır:
  tanımlı `_ZTV` sembolü olup o adreste birincil vtable kaydı olmayan sayısı (H0'da sanal tabanlı sınıfta vtable
  grubu sanal taban ofsetleriyle başlar: bu durumda kayıt sembolden sonra gelir; kaçan diye ayrı satırda, sınıf
  türüyle yazılır).
- **Yuva → sınıf bağı (H0, H2):** iki satır.
  (a) **Başvuru kuralı** (planın 7 098 / 7 119'u): ayrık yuva işlevi başına, adresinde kod sembolü varsa; sembol
  `_ZTh` / `_ZTv` / `_ZTc` ise "thunk" (paydaya girmez); değilse sembol, işlevin göründüğü sınıflardan birinin ya da
  onların (geçişli) tabanlarından birinin ad gövdesini (`N…E` sarmalı soyulmuş typeinfo adı) içeriyorsa doğru. Payda:
  doğru + yanlış.
  (b) **Ürün bağı** (kalem 4): tarayıcının işleve bağladığı tek sınıf (`belirsiz` olanlar hariç); sembol o sınıfın ya da
  geçişli tabanlarından birinin ad gövdesini içeriyorsa doğru. `belirsiz` sayısı ayrıca yazılır. Eşik: (a) için plan
  (≥ 7 098 / 7 119 ve Wilson alt ≥ 0,99); (b) için Wilson alt ≥ 0,99.
- **H2 kapsamı:** 2 028 = btop 1 + iTerm2 18 + llama-server 1 994 + Ollama x86_64 15 (BULGULAR §0 satırı dört ikiliyi
  sayar); vtable 1 328 ve yuva 7 119 = btop + iTerm2 + llama-server. Ollama x86_64'ün `_ZTI` karşılaştırması da bu tek
  ölçümde yapılır (keşifte Ollama yalnız sayı).
- **Fark 0 (H0):** sembollü ve `/usr/bin/strip` ile soyulmuş kopyada tarayıcının tam çıktısı (typeinfo listesi,
  vtable listesi, `rtti_classes`, işlev bağları) JSON olarak aynı.
- **Sınıf kümesi aynı (H0):** arm64 ve x86_64 derlemelerinde (aynı kaynak, aynı `-O`) çözülmüş sınıf adı kümesi aynı.
- **H3 mutantı:** "zayıf bağ adı yerel adrese çevrilmez" (ürün kodunda tek satır) geçici uygulanır, Ollama x86_64'te
  typeinfo sayısı ≤ 4; ardından geri alınır (`git diff` temiz).
- **H4:** btop'un (keşif) kopyasında typeinfo ve vtable'ların bulunduğu veri bölümünün içinde 200 deneme; her denemede
  tohumlu üreteçle 200 rastgele bayt bozulur, tarayıcı 10 sn sınırla koşar. Hüküm: istisna 0, süre aşımı 0 (200 / 200).
- **H5:** pzstd'de vtable ≥ 1 ve typeinfo adı eşitliği (yukarıdaki tanım, GT dbgsym `.symtab`) ≥ %99.
- **H6:** yerel örneklerde ve btop'ta `rtti_classes` yuvalarından kurulan `Sınıf_vfunc_N` adayının GT adıyla (çözülmüş
  sembol ya da ham sembol) tam eşitliği sayılır; beklenen 0.

## 3. Tutmazsa

Fark yazılır (hangi hedef, hangi sayı, kaç kayıt; sınıf türü: şablon / sanal kalıtım / adsız ad alanı / öbür).
H1'de başvuru betiği de denetlenir (hata iki yanda da olabilir; bilerek yapılan ayrılıklar ilerleme dosyasında
gerekçesiyle). H2 tarayıcı dondurulduktan sonra bir kez ölçülür; sonuca göre tarayıcı değiştirilmez. H5 tutmazsa ELF
yolu `desteklenmiyor` kalır.
