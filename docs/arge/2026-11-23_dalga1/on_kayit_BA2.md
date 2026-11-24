# BA2 — ön kayıt (ölçümden önce; sayılar ana oturumun, değiştirilmez)

- Gönderim: `docs/arge/2026-11-23_dalga1/gonderim/BA2.md`
- Taban: main `cfe93cef` (ürün kodu `534e252b` ile aynı; aradaki fark yalnız belge)
- Yazılma: 2026-11-24 13:20, ölçümden önce; ayrı commit.

> H1: İki bilinen kalıbın BA-1'deki düşmanca girdileri onarımdan sonra ≤ 0,1 sn'de sonuçlanır (önce: 28 tekrarda 5 sn'de bitmedi; 30 karakterde 1,13 sn).
> H2 (eşdeğerlik): geliştirme setinin çalışma alanlarından (`~/karadul_olcum/runs/urun-onarim-a62f15e/`, salt okur) ve Ollama çalışma alanından toplanan gerçek girdilerde eski ↔ yeni kalıp aynı sonucu verir; farklı 0 (girdi sayısı ilk ölçüm; her kalıp için en az 200 gerçek girdi ya da "bu kalıp gerçek veride N kez denendi").
> H3 (ad haritası): `c_namer`'ın Ghidra'sız yeniden oynatmasında (OK1 / P12d'nin yöntemi; S8'in 8 ikilisi) ad haritası onarımdan önce ↔ sonra bayt eşit 8 / 8.
> H4: 39 adaydan üstel çıkan sayısı: yön bildirilmez, ilk ölçüm.
> H5: genişletilmiş taramada (`karadul/` tamamı + `ui/server.py`) yeni üstel kalıp sayısı: yön bildirilmez, ilk ölçüm.
> H6: kapı testi ≤ 60 sn; istisna listesi boş.

Ölçüm yöntemi (ön kayıtla birlikte sabitlenir):

- Süre ölçen her deneme ayrı çocuk süreçte, `subprocess.run(timeout=…)` (süre dolunca SIGKILL). Yük altında (makinede başka ajanlar var); `uptime` künyesi ilerleme dosyasında.
- "Aynı sonuç": `re.match` / `search` için eşleşme yok ↔ yok ya da aynı span + aynı gruplar; `finditer` için aynı eşleşme dizisi (her biri span + adlı gruplar).
- H3: S8'in 8 ikilisi (`debian/coreutils/cat`, `debian/coreutils/sort`, `debian/tree/tree`, `debian/sqlite3/sqlite3`, `debian/htop/htop`, `debian/tmux/tmux`, `debian/zstd/zstd`, `mac/tmux`), kaynak `~/karadul_olcum/runs/urun-onarim-a62f15e/<ikili>/ws/workspaces/*/*`; önce kolu ürün ağacı `~/karadul_olcum/urun-534e252b`, sonra kolu bu dalın ürün ağacı; `reconstructed/src/naming_map.json` bayt karşılaştırması.
