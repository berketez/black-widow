# HZ-7a ön kaydı (düzenli ifade deseni önbelleği ve satır ön süzgeci)

- Yazıldı: 2026-11-27 22:3x; HZ-7a kodundan ve bütün ölçümlerden ÖNCE, ayrı commit.
- Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/HZ7a.md`; plan `hiz/PLAN.md` HZ-7a; sayılar ana oturumun (gönderim metni "Ön kayıt").
- Taban: main `c59d3c0e` (ürün kodu `ed28e36b`; sabit ürün ağacı `~/karadul_olcum/urun-ed28e36b`).
- Koşu kökü: `~/karadul_olcum/runs/dalga1-2026-11-23/HZ7a/`.

## Beklentiler (eşikler bu commit'ten sonra değişmez; tutmayan silinmez)

> **H1 (eşitlik):** S8'in 8 ikilisinde ve Ollama çalışma alanında `naming_map.json`, `naming_provenance.json` ve `reconstructed/src/` önce ↔ sonra bayt eşit (9 / 9).
>
> **H2 (süre, Ollama yeniden oynatması, yük altında, art arda):** `c_naming` adımı sonra / önce oranı ≤ 0,6.
>
> **H3 (süre, S8'in en büyük iki ikilisi: sqlite3, mac/tmux):** `c_naming` oranı ≤ 0,5.
>
> **H4 (profil):** seri profilde (plandaki `profil_yeniden.py` ya da eşdeğeri, bir ikili) `re._compile` kümülatif payı ≤ %5 (BULGULAR'da %50,5).
>
> **H5:** ön süzgeç koşulunu sağlamayan desen sayısı — yön bildirilmez, ilk ölçüm.

## Yöntem (ölçümden önce sabit)

- **Kollar.** "Önce" = `~/karadul_olcum/urun-ed28e36b` (main'in ürün kodu). "Sonra" = bu dalın ürün kodu: `urun-ed28e36b`'nin koşu kökünde kopyası (`HZ7a/agac_sonra`) + bu dalın `karadul/reconstruction/c_namer.py` ve `karadul/reconstruction/api_param_db.py` dosyaları; `diff -rq` ile dalın `karadul/`'u ile aynı olduğu denetlenir. Her koşunun günlüğü yüklenen `karadul/__init__.py` yolunu yazar.
- **Düzenek.** Ghidra'sız yeniden oynatma, OK1'in `yeniden.py` / `kos1.sh`'si koşu köküne kopyalanıp uyarlanır (yalnız `ReconstructionStage`; ek: `ctx.stats`'taki `timing_*` alanları `sureler.json`'a yazılır; Ollama için isteğe bağlı ayar dosyası). `PYTHONHASHSEED=0`, `PYTHONDONTWRITEBYTECODE=1`, koşuya özel `KARADUL_CACHE_DIR`.
- **Girdiler (salt okur).** S8: `~/karadul_olcum/runs/urun-onarim-a62f15e/<ikili>/ws/workspaces/*/*` (debian/coreutils/cat, debian/coreutils/sort, debian/tree/tree, debian/sqlite3/sqlite3, debian/htop/htop, debian/tmux/tmux, debian/zstd/zstd, mac/tmux). Ollama: `~/karadul_olcum/runs/dalga1-2026-11-23/ANA/ollama_ba_kapali/ws/workspaces/*/*`; ayar o koşunun `bayraklar.yaml`'ı (koşu köküne kopya; üst veri bayrakları açık, blok açıklama ve BSim kapalı) — iki kolda aynı.
- **Eşitlik (H1).** `reconstructed/src/naming_map.json`, `reconstructed/src/naming_provenance.json` sha256 ve `reconstructed/src/` ağacının dosya dosya bayt karşılaştırması (`diff -rq`); ikili başına "eşit / farklı".
- **Süre (H2, H3).** `c_naming` = `ctx.stats`'taki `timing_c_naming_iter<k>` alanlarının toplamı (koşan turların hepsi). Oran = sonra / önce. Bütün süreler **yük altında** (üç ajan aynı anda; ana oturumun S8 tabanı Ghidra'da): her koşunun başında ve sonunda `uptime`. Kollar art arda: önce kolu kod yazılırken, sonra kolu kod ve testler bitince; aynı ikili kümesi aynı eşzamanlılıkla (Ollama ∥ S8 dizisi) koşulur.
- **Profil (H4).** `scripts/arge/hiz/profil_yeniden.py --seri` (ya da eşdeğeri) sonra kolunda bir ikilide (mac/tmux; süre yetmezse daha küçük bir ikili, adı yazılır); `re/__init__.py:_compile` kümülatif süresi / C aşaması toplamı.
- **H5.** İki desen listesinin (`_PARAM_USAGE_PATTERNS`, `_LOCAL_VAR_USAGE_PATTERNS`) her öğesi için "`PARAM` tam bir kez ve zorunlu konumda" koşulu ürün kodundaki denetimle sayılır; koşulu sağlamayan öğe sayısı (liste başına) yazılır.
- **Bilinen risk (ölçümden önce yazıldı).** `feedback_loop` bir turun süresi `pipeline_iteration_timeout`'u (600 sn) aşınca kalan turları atlar: Ollama'nın özgün koşusunda 1. tur 1 790 sn sürdü ve 2. tur koşmadı. Sonra kolunda tur süresi 600 sn'nin altına inerse 2. tur koşar ve çıktı süre yüzünden (kodun ad kararından değil) farklılaşabilir. Böyle olursa fark bu nedene göre ayrıştırılır ve ayrıca yazılır; H1 hükmü değişmez.
