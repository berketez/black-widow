# Dalga 0 — ortak brif (2026-11-20)

Bağlayıcılık sırası (çelişkide üstteki geçerli): `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-1 … A-20) → bu brif → `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md` → hat planı (`docs/arge/2026-11-19_mythos/<hat>/PLAN.md`) → ajan tanımın.

## 1. Ne yapılıyor

- Karadul uygulama oturumu, **Dalga 0** (`docs/arge/2026-11-19_mythos/SONRAKI_OTURUM.md` §3): zemin ve "önce" sayıları. Ürün davranışı bu dalgada DEĞİŞMEZ (bayrak ön paketi yalnız okunmayan alan ekler; HZ-1 yalnız süre kaydı ekler).
- Senin paketin: `docs/arge/2026-11-20_dalga0/gonderim/<PAKET>.md`. Paketin ayrıntısı hat planındadır; gönderim metni hangi bölümü okuyacağını söyler. Planı ilgili bölümüyle baştan sona oku: kabul ölçütü ve ön kayıt metni orada.
- Bütün yollar mutlak verilir; belgeleri ana ağaçtan (`/Users/apple/Black_Widow/…`) okuyabilirsin, yazamazsın.

## 2. Ortam

- ONARIM_BRIF §2 aynen: kendi worktree'n; dalında commit yokken ilk iş `git merge --ff-only main` (sonra `git log --oneline -1` = `git rev-parse main`); komutlar worktree kökünden `python -m …`; `python -c "import karadul; print(karadul.__file__)"` worktree yolunu göstermeli; ana ağaca YAZMA; git'in izlemediği çalışma verisi gerekiyorsa symlink (`sigs`, `vendor`, `signatures_homebrew*.json`, `sigs_macos_system.json`, `signatures.lmdb`, `scripts/node_modules`; asla commit'leme); Python `/opt/anaconda3/bin/python`; paket kurma ve ağa çıkma YASAK; `PYTHONDONTWRITEBYTECODE=1`.
- Makine: Apple M4 Max, 14 çekirdek, 36 GB bellek. Aynı anda 5 ajan + ana oturumun koşuları var; yük yüksek olabilir.
- Kabuk zsh: komutu ya da listeyi değişkende tutma (`${=VAR}` ya da fonksiyon).
- **Scratchpad bütün alt ajanlar arasında ORTAK** (2026-11-20 08:5x'te iki ajanın `tam_takim.log`'u birbirine karıştı). Geçici dosyalarını (tam takım günlüğü dahil) yalnız kendi alt dizininde tut: `~/karadul_olcum/runs/dalga0-2026-11-20/<PAKET>/` ya da `<scratchpad>/<PAKET>/`. Ortak bir dosya adından sonuç okuma.
- `codex`, `gemini` ya da başka model CLI'ı çağırma; alt ajan açma.

## 3. Ghidra kuyruğu (yeni, zorunlu)

- Makinede aynı anda **tek** Ghidra koşusu. Ghidra başlatan her komutu (`python -m karadul analyze`, `scripts/measurement/urun_kos.py`, pyghidra kullanan her betik) şu sarmalayıcıyla çalıştır:

  `~/karadul_olcum/ghidra_kuyruk.sh <PAKET> <etiket> <komut> [arg ...]`

  Sarmalayıcı kilidi (`~/karadul_olcum/ghidra_kuyruk.lock`) bekler, komutu çalıştırır, `~/karadul_olcum/ghidra_kuyruk.log`'a `bekliyor / basladi / bitti` satırı yazar; çıkış kodu komutunkidir. Kuyrukta kim var: `tail ~/karadul_olcum/ghidra_kuyruk.log`.
- Kilidi tek bir uzun komutla saatlerce tutma: her ikiliyi ayrı çağrıyla sar (başka paketler de sırada).
- Uzun koşuyu arka planda başlat (Bash `run_in_background`) ve bitişini kısa aralıklı bir bekleme döngüsüyle izle. Her koşuya süre sınırı ver (`urun_kos.py --zaman-asimi`, ya da `timeout`); süresiz bekleme yok.
- `PYTHONHASHSEED=0`; koşuya özel `KARADUL_CACHE_DIR`; gerekirse `GHIDRA_INSTALL_DIR=$HOME/Library/BlackWidowBuild/ghidra_12.1.2_PUBLIC`.
- **Süre ölçümü gündüz yapılmaz** (makine yüklü). Bir süre yazıyorsan "yük altında" etiketi ve `uptime` künyesi. Boş makine ölçümleri (ÖLÇ-1, HZ-0) gece ana oturumca koşulur.
- **Sabit ürün ağacı:** bugünkü ürünü (main `b6aceb9`) koşman gerekiyorsa kendi worktree'ni değil `~/karadul_olcum/urun-b6aceb9`'u kullan (temiz, çalışma verisi bağlı; `urun_kos.agac_kunyesi` ile denetlenir). Kendi dalının ürününü koşman gerekiyorsa: `git -C /Users/apple/Black_Widow worktree add --detach ~/karadul_olcum/urun-<kısa-hash> <hash>` + aynı altı bağ (`ls -la ~/karadul_olcum/urun-b6aceb9 | grep -- '->'`). Bu ağaçları silme (ana oturum siler).

## 4. Paketler ve dosya sahipliği (Dalga 0; kümeler ayrık)

| Paket | Yazabileceği dosyalar (özet; tam liste gönderim metninde) |
|---|---|
| BAYRAK | `karadul/config.py`, `karadul/core/naming_labels.py` (yalnız yeni sabitler), `tests/test_bayrak_on_paketi.py`, `scripts/measurement/mutation_specs_bayrak.json` |
| OLCUM | `scripts/measurement/{ad_bicimi,urun_olc,ks1_olc,masum_kapi,saglamlik_denetle,function_f1,urun_kos}.py`, `tests/test_ad_bicimi.py`, `tests/test_olcum_araci_d0.py`, bu betiklerin testlerine ek, `mutation_specs_{po1,olcum_araci,urun_olc,ks1,function_f1}.json` |
| OK5 | `scripts/measurement/{ozkod_olc,ozkod_nufus_kur}.py`, `tests/test_ozkod_olc.py`, `mutation_specs_ozkod_olc.json`, `docs/…/ozkod/{NUFUS,on_kayit_OK5,OK5}.md` |
| OLCEK | `scripts/measurement/olcek_kos.py`, `tests/test_olcek_kos.py`, `mutation_specs_olcek_kos.json`, `scripts/arge/hiz/{hz0_ek,zaman_cizelgesi}.py`, `scripts/arge/olcek/gece_kosusu.py`, `docs/…/olcek/{OLC0,on_kayit_olc1,GECE_PLANI}.md`, `docs/…/hiz/on_kayit_hz0.md` |
| HZ1 | `karadul/ghidra/headless.py`, `karadul/analyzers/macho.py`, `tests/test_hz1_olcum_kancasi.py`, `mutation_specs_{hz1,macho,p16a,p16c,p16d}.json`, `scripts/arge/hiz/s8_esitlik.py`, `docs/…/hiz/{on_kayit_hz1,HZ1}.md` |
| MUTBAKIM | `mutation_specs_{p20,ps1,adim3_hat,p13a,p12a,ad_gecerliligi,adim3_c_namer,p05,adim3_ui}.json`, `tests/test_mutbakim_*.py` |
| HEDEF | `scripts/measurement/{ustveri_set,ustveri_olc}.py`, `tests/test_puv8_olcum.py`, `mutation_specs_puv8.json`, `scripts/arge/ustveri/acik_*.py`, `docs/…/ustveri/{olcum,acik_olcum}/` |
| KIMLIK | `scripts/measurement/kimlik_ciftler.py`, `scripts/arge/kimlik/d0_*.py`, `docs/…/kimlik/{PK-6_on_kayit,PK-6,PK-11_on_kayit,PK-11}.md` |
| OL10 | `docs/…/olcek/OL10_TASARIM.md` (yalnız belge) |

- `docs/…` = `docs/arge/2026-11-19_mythos`. İlerleme dosyaları ayrıca `docs/arge/2026-11-20_dalga0/<PAKET>.md` olabilir (gönderim metni hangisi olduğunu söyler).
- Listende olmayan bir dosyada değişiklik gerekiyorsa DEĞİŞTİRME: `docs/arge/2026-11-20_dalga0/yamalar/<PAKET>__<dosya_adı>.patch` olarak yama bırak, gerekçesini ilerleme dosyana yaz; ana oturum uygular.
- `karadul/config.py`'ye BAYRAK dışında kimse yazmaz (KARARLAR A-19). Bayrak gerekiyorsa alan adı `karsi/CAKISMA.md` §2.1'de; BAYRAK ekliyor.

## 5. Commit, ön kayıt, mutasyon, tam takım

- **Commit:** kendi dalında, iş kalemi başına bir commit (ONARIM_BRIF §4e: dosyalar adıyla stage, `git diff --cached --name-only` ile doğrula, Türkçe `Kategori: başlık`, gövdede sorun → onarım → doğrulama). Hat planlarındaki "commit'i ana oturum atar" satırı bu oturumda geçersizdir: sen kendi dalına commit'lersin, ana oturum main'e alır. `Co-Authored-By` satırı YOK. push / merge / rebase YOK (başlangıçtaki `--ff-only main` hariç).
- **Ön kayıt** ölçümden önce kendi dalında ayrı commit; hash'ini ilerleme dosyasına ve dönüş mesajına yaz. Tutmayan beklenti silinmez; eşik sonradan değişmez.
- **Mutasyon:** `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_<ad>.json`. `find` metni dosyada tekil, `replace` farklı uzunlukta; aynı worktree'de eşzamanlı mutasyon koşusu yok; bitince `git diff` temiz.
- **Tam takım** sonda bir kez, worktree kökünden: `PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider`. Main `b6aceb9`'da 2026-11-20 08:02'de: 10 289 geçti / 11 atlandı / 0 kaldı (475 sn, boş makinede). Yüklü makinede 10–20 dk sürebilir. Kalan test varsa senin değişikliğinden mi değil mi ayır.

## 6. Veri

- Kilitli setler (`targets/test_seti`, `targets/dogrulama_seti`) açılmaz, listelenmez. ÖK-V'nin "kör" tarafı (`ozkod/NUFUS.md`) yalnız OK5 paketinin kör sayımında, adsız sayılarla kullanılır.
- Hazır çıktılar SALT OKUR: `~/karadul_olcum/runs/urun-onarim-a62f15e/` (119'luk birleşik ölçüm, a62f15e), `~/karadul_olcum/runs/urun-yeni2-f30ac9a/`, `~/karadul_olcum/runs/gosteri-2026-11-19/`, `~/karadul_olcum/runs/arge-2026-11-19/`, `~/karadul_olcum/n1_debian13/`, `~/karadul_olcum/n2_tabaka/`, `~/karadul_olcum/ozkod_nufus/` (OK5 hariç).
- **S8 tabanı** (bugünkü main `b6aceb9`; ana oturum koşuyor; `BITTI` dosyası olan alt dizin bitmiştir): `~/karadul_olcum/runs/dalga0-2026-11-20/s8_taban_b6aceb9/`. Komut (ikili başına bir çağrı, bu sırayla; "sonra" kolunda aynısını kendi ağacın ve kökünle kullan):

  ```
  K=<kök>; mkdir -p $K/cache
  for a in debian/coreutils/cat debian/coreutils/sort debian/tree/tree debian/sqlite3/sqlite3 debian/htop/htop debian/tmux/tmux debian/zstd/zstd mac/tmux; do
    PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 KARADUL_CACHE_DIR=$K/cache \
    ~/karadul_olcum/ghidra_kuyruk.sh <PAKET> S8:$a python scripts/measurement/urun_kos.py \
      --agac <ürün ağacı> --kok $K --paralel 1 \
      --taban-debian ~/karadul_olcum/runs/urun-onarim-a62f15e/debian \
      --taban-mac ~/karadul_olcum/runs/urun-onarim-a62f15e/mac --yalniz $a >> $K/kos.log 2>&1
  done
  ```

  (komut ana ağacın `scripts/measurement/urun_kos.py`'siyle, ana ağaç kökünden koşuldu.)
- Kendi koşu çıktın: `~/karadul_olcum/runs/dalga0-2026-11-20/<PAKET>/`. `~/karadul_olcum` altında başka şeyi değiştirme / silme.
- Disk: büyük veri üretmeden önce ve sonra `diskutil info /System/Volumes/Data | grep "Volume Used"`; 20 GB'ı aşacaksan dur, bildir. Boş alan 08:00'de 217 GB.
- **Depo herkese açık:** üçüncü taraf ikili, çıkarılmış ad listesi, GT adı commit'lenmez (yalnız sayı ve sha256).

## 7. İlerleme dosyası ve dönüş

- Gönderim metnindeki ilerleme dosyası: işe başlar başlamaz oluştur, her kalem bitince büyüt ve commit'le (yarıda kesilirsen sonraki ajan oradan sürdürür). 20 dakikadan uzun sürecek bir adıma (Ghidra kuyruğu dahil) girmeden önce "şu an şunu bekliyorum, tahmini bitiş" satırı yaz ve commit'le. Son satır tam olarak: `## PAKET BİTTİ`.
- Dönüş mesajı ONARIM_BRIF §6 biçiminde: kalem kalem durum, önce → sonra sayıları, test ve mutant sayıları, commit listesi (kısa hash + başlık), bıraktığın yamalar, riskler.
- **Sahte veri yok:** veri yoksa "veri yok / ölçülmedi / izin bekliyor" yazılır; 0 ya da boş yazılmaz; tahmin "TAHMİN" etiketli ve aralıklı.
- Türkçe yaz, Türkçe karakterleri doğru kullan; kod simgeleri İngilizce.

## 8. Dalga 0'a özgü notlar

- Ölçüm araçları (`urun_olc.py`, `ks1_olc.py`, `urun_kos.py` …) OLCUM paketinde değişiyor; sen kendi worktree'ndeki sürümü kullanırsın. `urun_kos.agac_kunyesi`'nin imzası geriye uyumlu kalacak.
- HZ-1 (`headless.py` / `macho.py`) `ghidra_status.json`'a `adim_sureleri` / `analysis` alanı ekliyor; bu alanları okuyan araç, alan yoksa eski yola düşmeli.
- Takılma bekçisi ana oturumda çalışıyor (CLAUDE.md §27): 20 dk boyunca ne commit ne dosya değişikliği ne transcript etkinliği olursa takıldı sayılırsın.
