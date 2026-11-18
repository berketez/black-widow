# P16b — ön kayıt: BSim deposunda kilit, sızıntı, atomik dizin

- **Tarih:** 2026-11-18. **Durum:** KESİN (ürün kodu değişmeden önce commit'lendi; taban commit `b82c6e9`).
- **Şablon:** `docs/arge/2026-11-10_n1_adim3/urun_olcumu_onkayit_taslak.md` (kısaltılmış: BSim öntanımlı ayarda gölge kipte, ad kanalına bağlı değil; soru "değişiklik adları bozuyor mu" ve "BSim adayları dürüst mü").
- **Kapsam:** GHIDRA-01 (eşzamanlı koşuda H2 kilidi → sessiz yedeğe düşüş), GHIDRA-02 (ortak depoda kendisi ve aynı yapının sembollü kopyası aday oluyor), GHIDRA-03 (lite dizini atomik değil), GHIDRA-12 (`bsim.py` tarafı: doğru depoyu dışa açan API).
- Bu belgede fonksiyon adı geçmez.

## 1. Değişiklikler ve neden ada dokunabilecekleri

1. **Süreçler arası kilit + bekleme + açık durum (GHIDRA-01).** Depo dizininde veritabanı başına bir kilit dosyası (`fcntl.flock`). BSim oturumu (ingest + sorgu) kilidi alır; alamazsa sınırlı süre bekler. Kilit sonrası H2 yine "in use" derse (kilidi bilmeyen eski sürüm ya da başka araç) sınırlı süre yeniden dener. Süre dolarsa BSim **atlanır** ve bu durum yazılır; kilit / meşgul durumunda lite yedeğine düşülmez. Öbür yerel hatalarda lite yedeği kalır, ama neden ve kip sonuç kaydına yazılır. H2 istemcisi oturum başına bir kez açılır (bugün her fonksiyon sorgusunda yeniden açılıyor).
2. **Aday kaynağı ve dışlama (GHIDRA-02).** İngest edilen her ikilinin kimliği (md5, sha256, ELF build-id / Mach-O LC_UUID, ad) depoda bir kaynak kaydına yazılır. Sorguda (a) kendi md5'i, (b) aynı sha256, (c) aynı build-id / UUID taşıyan ikililerden gelen aday dışlanır; dışlanan sayı sonuç kaydına yazılır. Kalan her adaya kaynağı (md5, sha256, kaynak kaydı var / yok) eklenir. Lite kipte dışlama addan değil kimlikten yapılır (bugün aynı adlı bütün programlar dışlanıyor).
3. **Lite dizini (GHIDRA-03).** Yazım kilit altında: diskteki son hâl yeniden okunur, bu koşunun kaydı birleştirilir, geçici dosya + `os.replace`. Okunamayan dizin ezilmez, yedeği bırakılır. `close()` yalnız değişiklik varsa yazar.
4. **API (GHIDRA-12, `bsim.py` tarafı).** `query_all_functions` / `query_similar` veritabanı adını parametre olarak alır; `list_databases` kipten bağımsız olarak hem native `.mv.db` dosyalarını hem lite dizinini salt okur listeler. CLI tarafı (`cli.py`, P15a) yama olarak bırakılır.

**Ada dokunma yolu:** öntanımlı ayarda (`bsim.shadow_mode=True`, `use_bsim_fusion=False`) BSim adayı ad haritasına girmez. Arayüz teşhis kartı ve `bsim_shadow.json` adayı gösterir (analiste görünen yüzey). Dolaylı etki: lite yedeğinin kalkması Ghidra oturumunda decompile sayısını değiştirir; ad çıktısını değiştirmesi beklenmez.

## 2. Ölçüm düzeni

- **Kollar:**
  - *önce*: taban commit `b82c6e9`'un ayrı bir kopyası (`~/karadul_olcum/runs/onarim-2026-11-18/P16b/agac-once`, `git clone --shared` + checkout).
  - *sonra*: P16b dalının son commit'i + `yamalar/P16b__headless.py.patch` (durum alanlarını `bsim_matches.json`'a yazan çağıran tarafı) uygulanmış ikinci kopya (`agac-sonra`). Commit'ler ilerleme dosyasına yazılır.
- **Ortam:** iki kolda `PYTHONHASHSEED=0`; BSim deposu kol başına boş bir dizin (`KARADUL_CACHE_DIR=<kök>/<kol>/<deney>/cache`; `resolve_cache_root()` yalnız BSim tarafından kullanılıyor, öbür önbellekler etkilenmez). Ortak depo `~/.cache/karadul/bsim/` okunmaz, yazılmaz.
- **Deney E (eşzamanlılık):** `urun_kos.py --paralel 3 --yalniz debian/coreutils/cat --yalniz debian/coreutils/expr --yalniz debian/coreutils/sort --yalniz debian/tree/tree` (4 ikili, kilitli liste); boş depo.
- **Deney S (sızıntı):** boş depoya önce Mac htop'un sembollü özgünü (`workspaces/2026-10-15_oturum_scratchpad/macho/orig/htop`, sha256 `29449bae…`) `python -m karadul analyze` ile koşulur (tohum); sonra aynı depoyla soyulmuş Mac htop (`--yalniz mac/htop`, `--paralel 1`). İkisinin LC_UUID'si aynı (`otool -l`, 0BAB9353-…).
- **Deney L (lite dizini, Ghidra'sız):** `_BSimLiteIndex` üstünde iki süreç aynı dizine aynı anda farklı program yazar; bozuk JSON'lu dizinle bir süreç açılıp kapatılır. Betik `~/karadul_olcum/runs/onarim-2026-11-18/P16b/lite_yaris.py`.
- **Deney C (API, Ghidra'sız):** JVM'siz süreçte (lite kip) native `.mv.db` dosyası bulunan depoda `list_databases()`; ardından lite dizininin mtime'ı.
- **Ad ölçüsü:** `urun_olc.py olc` her iki kolun E + S koşuları için; `karsilastir` önce ↔ sonra. Kanal kırılımında BSim kaynaklı ad sayısı.
- **BSim aday ölçüsü (GT'siz):** `bsim_matches.json` / `bsim_shadow.json` üstünden: eşleşme sayısı, kendisiyle eşleşme (önce kolda `matched_program` = kendi program adı ve `matched_function` = sorgu fonksiyonu; sonra kolda ek olarak md5 eşitliği), soyulmuş Mac htop'ta FUN_/DAT_ olmayan adayı olan fonksiyon sayısı ve bu adayların tohumdan (sembollü htop) gelenleri. Sayım betiği `~/karadul_olcum/runs/onarim-2026-11-18/P16b/bsim_say.py`.
- **Bilinen gürültü:** `PYTHONHASHSEED` sabit; Ghidra'nın aynı adlı fonksiyonlara dosya adı dağıtımı P16a'dan sonra adres sıralı. Yerel ad soneklerindeki fark BSim etkisi sayılmaz. Deney E'de çakışmanın olup olmaması zamanlamaya bağlıdır; önce kolda çakışma çıkmazsa deney bir kez daha koşulur ve bu yazılır.

## 3. Beklentiler (ölçümden önce)

| # | Ölçü | Beklenti | "Tutmadı" denir, eğer |
|---|---|---|---|
| H1 | E: günlükte "Database already in use" ve lite'a düşüş | önce ≥ 1 / 4; sonra kilit kaynaklı düşüş 0 / 4 | sonra kolda kilit / meşgul nedeniyle lite'a düşen ya da durumu yazılmamış ikili > 0 |
| H2 | E + S: `bsim_matches.json`'da kip ve durum alanı | sonra 5 / 5 ikilide var (önce 0 / 5) | sonra kolda eksik |
| H3 | E + S: kendisiyle eşleşen aday (sonra: md5 eşitliği) | sonra 0 | > 0 |
| H4 | S: soyulmuş Mac htop'ta tohumdan (aynı UUID) gelen FUN_/DAT_ olmayan aday taşıyan fonksiyon | önce ≥ 100 (Ghidra fonksiyon sayısının çoğu; önce kol native koşarsa); sonra 0 | sonra > 0 |
| H5 | S: sonra kolda kalan adayların her birinde kaynak (md5 + kaynak kaydı var/yok) | %100 | eksik aday > 0 |
| H6 | Ad: alt kümede (E + S) doğru ve yanlış ad sayısı, önce ↔ sonra | aynı ya da her biri en çok ±%1 (BSim ad kanalına bağlı değil) | farkın BSim'e bağlanabilen bir kısmı varsa; ya da ±%1 aşılırsa fark ikili ikili yazılır |
| H7 | Ad: BSim kaynaklı ad (kanal kırılımı) | iki kolda 0 | > 0 |
| H8 | L: eşzamanlı iki yazıcıdan sonra dizindeki program sayısı | önce < 2 (son yazan kazanır; zamanlamaya bağlı), sonra 2 | sonra < 2 |
| H9 | L: bozuk JSON'lu dizin açılıp kapatıldıktan sonra özgün baytlar | önce ezilir; sonra yedekte bayt bayt aynı | sonra yedek yok ya da farklı |
| H10 | C: lite kipteki süreçte native `.mv.db` listede; liste sonrası lite dizini mtime | önce listede yok, mtime değişir; sonra listede, mtime aynı | sonra tutmazsa |

- H6 tutmazsa değişiklik geri alınmaz; fark kanal kanal ve ikili ikili yazılır, ana oturuma bildirilir.
- H4'ün önce kolu tohumun native koşmasına bağlı (lite'ta dışlama addan olduğu için tohum zaten dışlanır); önce kol S koşusu lite'a düşerse bu yazılır ve H4 önce kolu "bakılamadı" olur.
