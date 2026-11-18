# Karadul onarımı (2026-11-18) — bütün paketler için ortak brif

Bu brif bağlayıcıdır; ajan tanımındaki genel talimatlarla çelişirse bu brif geçerlidir.

- **Depo:** `/Users/apple/Black_Widow` (dal `main`, sürüm 1.23.1). Sen ana ağaçta DEĞİL, kendi git worktree'nde çalışıyorsun (çalışma dizinin).
- **İş emri:** `/Users/apple/Black_Widow/docs/arge/2026-11-18_genel_tarama/RAPOR.md` (§3 temalar, §5 plan) ve bulguların tam metni kulvar dosyalarında (`kulvar_<AD>.md`, aynı dizin). Bulgu kimliği (ör. `IMZA-05`) hangi dosyada olduğunu söyler. Bu dosyaları mutlak yoldan oku.
- **Aynı anda başka paketlerin ajanları da çalışıyor.** Dosya kümeleri ayrık; senin listen paket isteminde.

## 1. Ürün ve ölçüt
Karadul (Black Widow) bir tersine mühendislik aracıdır: derlenmiş ikiliyi (ELF, Mach-O, PE; ayrıca JS/Electron, Java/APK, .NET, Python paketleri) alır, Ghidra çıktısı üstünde hesaplamayla (motor LLM kullanmaz) ad, tip, yapı, ilişki kurtarır; analist için kaynak ağacı ve rapor üretir. Hedef kullanıcı: bir yazılımın zararlı olup olmadığını anlamaya çalışan güvenlik analisti. **Ölçüt: analisti yanıltmamak.** Yanlış ad, sahte iddia, sahte güven değeri, "başarılı" görünen boş çıktı, yalan sayaç en ağır kusurlardır.

**Berke'nin kararı (2026-11-18):** Karadul küçültülmez. Yanlış iddia üreten bir katman silinmez ya da bayrağı kalıcı kapatılmaz; **onarılır ve ölçülür** (kanıta bağlanır). Yeni özellik eklenmez; var olan düzeltilir. Ölü kod silme yalnız paket isteminde açıkça yazıyorsa.

## 2. Ortam (ilk komutların)
1. `pwd` → `…/.claude/worktrees/agent-…` gibi bir yol olmalı. `git log --oneline -1` → taban commit'i not et.
2. `python -c "import karadul; print(karadul.__file__)"` worktree yolunu göstermeli. `karadul` paketi ana ağaca editable kurulu: komutları HER ZAMAN worktree kökünden `python -m …` ile koş (`python -m pytest`, `python -m karadul`). Kabuk komutu `karadul …` ana ağacın kodunu yükler: KULLANMA.
3. **Ana ağaca (`/Users/apple/Black_Widow/…`) YAZMA.** Orada ana oturum ve başka ajanlar çalışıyor. Okumak serbest.
4. Git'in izlemediği çalışma zamanı verisi worktree'de yok: `scripts/node_modules`, `sigs/`, `vendor/`, `signatures_homebrew*.json`, `sigs_macos_system.json`. Bir test ya da ölçüm gerektirirse worktree'de symlink kur: `ln -s /Users/apple/Black_Widow/<ad> <ad>` (bunlar `.gitignore`'da; asla commit'leme).
5. Python: `/opt/anaconda3/bin/python` (3.12). Paket kurma (pip/npm/brew/conda) YASAK. Ağa çıkma YASAK (indirme, `npx`, `curl`).
6. Mutasyon ya da deneme için dosyayı geçici değiştirdiysen geri aldığından emin ol (`git diff` temiz olmalı); `.pyc` tuzağı yüzünden `PYTHONDONTWRITEBYTECODE=1` kullan.

## 3. Kesin kurallar
1. **Dosya sahipliği.** Yalnız paket istemindeki "Yazabileceğin dosyalar" listesini, kendi yeni test dosyalarını ve kendi ilerleme dosyanı yazarsın. Başka bir dosyada değişiklik gerekiyorsa DEĞİŞTİRME: `docs/arge/2026-11-18_onarim/yamalar/<PAKET>__<dosya_adı>.patch` olarak yama bırak, gerekçesini ilerleme dosyasına yaz. Ana oturum uygular.
2. **Alt ajan açma.** `codex`, `gemini` ya da başka bir model CLI'ını çağırma (ajan tanımında yazsa bile YASAK).
3. Ghidra koşusu ve tam ürün koşusu (`urun_kos.py`, gerçek ikiliyle `python -m karadul analyze`) yalnız paket istemi izin veriyorsa.
4. **Hazır gerçek çıktılar SALT OKUR:**
   - `~/karadul_olcum/runs/urun-yeni2-f30ac9a/` — 119 ikilinin 1.22.1 çıktısı (ad davranışı bugünküyle aynı).
   - `~/karadul_olcum/runs/genel-tarama-2026-11-18/` — 14 ikilinin HEAD (1.23.1) çıktısı.
   - Ham ikililer (geliştirme seti, 119): `scripts/measurement/urun_kos.py` → `isleri_topla(TABAN_DEBIAN, TABAN_MAC)` her iş için girdi yolu ve sha256 verir.
   - Kendi ölçüm çıktın: `~/karadul_olcum/runs/onarim-2026-11-18/<PAKET>/` (oluştur). `~/karadul_olcum` altında başka hiçbir şeyi değiştirme, silme.
5. Gizli dosyalara (`~/.ssh`, `.env`, anahtarlar) dokunma.
6. Türkçe yaz, Türkçe karakterleri doğru kullan (ç ğ ı İ ö ş ü). Kod simgeleri (değişken, fonksiyon) İngilizce kalır.
7. **Sahte veri yok.** Rapor, sayaç, güven değeri gerçek veriden gelir; veri yoksa "veri yok / bakılmadı / araç yok" yazılır, 0 ya da boş yazılmaz.
8. Sürüm numarasına dokunma (ana oturum sonda yükseltir).

## 4. Yöntem (her kalem için)
- **a. Göster.** Kulvar dosyasındaki "Kanıt" ve "Nasıl sınanır" ile kusuru gerçek çıktıda ya da gerçek ikilide SAY. Sayı rapordakiyle belirgin biçimde tutmuyorsa o kalemi onarma; ilerleme dosyasına yaz, ana oturuma bildir.
- **b. Onar.** Kök nedeni onar. Tespit/iddia katmanlarında tek kanıtla hüküm yok: deseni biçime, mimariye, bölüme bağla; sözcük sınırı ve harf duyarlılığı; en az iki bağımsız kanıt ya da tek ama ayırt edici güçlü kanıt. (Örnek düzen: `ab986da` sabit katmanı: tam belirteç + en az iki ayırt edici kanıt.)
- **c. Yeniden say.** Aynı sayımı onarımdan sonra yinele. **Masum set** (yanlış iddia düşmeli) ve **gerçek pozitif set** (doğru tespit kalmalı) birlikte. Önce/sonra sayılarını ilerleme dosyasına tablo olarak yaz.
- **d. Test.** Onarımı kilitleyen test: eski kodda KIRMIZI, yeni kodda yeşil olmalı. Mutasyon: `scripts/measurement/mutation_specs_<paket>.json` (biçim örneği `scripts/measurement/mutation_specs_kripto.json`); koşum `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec <dosya>`. Her mutant öldürülmeli; mutant metninin uzunluğu özgününden farklı olsun (`.pyc` tuzağı). Bu depoda yeşil test tek başına kanıt değildir.
- **e. Commit.** Kendi dalında, iş kalemi başına bir commit. Dosyaları adıyla stage et (`git add -A` / `git add .` YASAK), `git diff --cached --name-only` ile doğrula. Mesaj Türkçe, biçim `Kategori: başlık` (Güvenlik / Bug / Test / Ölçüm / Belge); gövdede sorun (bulgu kimliği + önce sayısı) → onarım → doğrulama (sonra sayısı, test sayısı, mutant x/x). **`Co-Authored-By` satırı YOK.** Push, merge, rebase YOK; başka dala ve başka worktree'ye dokunma.
- **f. Tam takım.** Sonda bir kez, worktree kökünden: `PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider` (birkaç dakika). Kalan test varsa senin değişikliğinden mi değil mi ayır ve yaz. Ara adımlarda yalnız ilgili test dosyalarını koş.

## 5. İlerleme dosyası (zorunlu, parça parça)
- `docs/arge/2026-11-18_onarim/<PAKET>.md` (kendi worktree'nde). İşe başlar başlamaz oluştur; her kalem bitince büyüt: önce sayısı → onarım (dosya:satır) → sonra sayısı → test / mutant → commit kısa hash.
- Ajan yarıda kesilirse yazdıkların kalır; sonraki ajan oradan sürdürür. Bu yüzden her kalemi bitirince commit'le, işi sona biriktirme.
- Bitince dosyanın son satırı tam şu olsun: `## PAKET BİTTİ`. Bu dosya da commit'lenir.
- Hedef süre 60–90 dk. Daha uzun sürecekse önce en ağır kalemleri bitir ve commit'le.

## 6. Dönüş mesajın
Kısa: kalem kalem durum (onarıldı / onarılmadı + neden), önce → sonra sayıları, test ve mutant sayıları, commit listesi (kısa hash + başlık), bıraktığın yamalar, ana oturumun bilmesi gereken riskler. Ayrıntı ilerleme dosyasında; mesajda yineleme.
