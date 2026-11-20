# HEDEF — P-ÜV8 kalem 1–4 (hedef seti, GT, "önce" sayısı) ║ P-ÜV9 kalem 1

Paket metni: `docs/arge/2026-11-20_dalga0/gonderim/HEDEF.md`. Ortak brif: `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`.

- Başlangıç: 2026-11-20 09:2x. Taban commit: `233f199` (main; `git merge --ff-only main` ile).
- `karadul.__file__` worktree yolunu gösteriyor (doğrulandı).
- Veri kökü: `~/karadul_olcum/ustveri_set/` (set), `~/karadul_olcum/runs/dalga0-2026-11-20/HEDEF/` (koşular).
- **Ön kayıt:** `on_kayit_HEDEF.md`, commit `bbda937` (ölçümden önce).

## Durum

| Kalem | Durum |
|---|---|
| 1 set + GT + bölme | bitti (aşağıda) |
| 2 ad eşitliği | bekliyor |
| 3 kanal ölçümü | bekliyor |
| 4 bütçe + ürün "önce" sayısı | bekliyor |
| 5 P-ÜV9 kalem 1 | yön ön kaydı commit'li (`bbda937`, §5) |
| 6 test + mutasyon | bekliyor |

## Koşu listesi (Ghidra kuyruğu) ve TAHMİNİ süre

Ayrıntı ve dayanak: `on_kayit_HEDEF.md` §4 (güç yasası üssü 2,14; tmux 223 sn, gösteri 7 762 sn).

| İkili | TAHMİN | Karar |
|---|---|---|
| terminal-notifier (soyulmuş) | 1–5 dk (yük altında) | koşulur: `ghidra_kuyruk.sh HEDEF urun:terminal-notifier …`, süre sınırı 3 600 sn |
| llama-server arm64 | 164–215 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| docker-cli | 334–983 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| docker-compose | 859–7 378 dk | ölçülmedi: süre — gece kuyruğuna önerildi |
| iTerm2 arm64 | 1 046–11 219 dk | ölçülmedi: süre — gece kuyruğuna önerildi |

## Kalem 1 — set, GT, bölme (`scripts/measurement/ustveri_set.py hazirla`)

Veri: `~/karadul_olcum/ustveri_set/<ad>/{orig,bin,gt}`, künye `~/karadul_olcum/ustveri_set/manifest.json` (araç künyesi: `/usr/bin/strip` → CLT 27.2, sha256 `719f0aeb…`; `/usr/bin/nm` llvm-nm 21.0.0). Kilitli test setiyle kesişim 0. Süre 5,7 sn.

| Ad | Bölme | Dilim | Özgün dilim sha256 | Soyulmuş sha256 | Soyma temiz | GT fonksiyon adresi / ad | Ad türü (adres): objc / swift / cxx / diğer | GT RTTI adresi (typeinfo / vtable adı) |
|---|---|---|---|---|---|---|---|---|
| terminal-notifier | keşif | ince | `eaec53d59e9ed9ba56841379f6b54904092ba01ad5747c4add5305a64c77e91e` | `d352c10594f241191b344e48e6607bce73a5b5095722bb3b2216640d74f2cd03` | evet | 92 / 93 | 42 / 0 / 0 / 50 | 0 |
| docker-cli | keşif | ince | `1b2b4029ea6ba83b320faa14dbd2044b1bd05a9a9bea0921b10c39575e7ce717` | `4b6b084536de5c22fc7fd8a19f4b2d3b10ad8a6e1816da211a546fc8bacefe12` | evet | 35 050 / 35 051 | 0 / 0 / 0 / 35 050 | 0 |
| docker-compose | sınama | ince | `fc9b9e22a1134f55500699f703e790cda16b7ba56d9894ef9a80ddb3f5732bd9` | `9f39c96629894866376e5352c9bc1947dfe916ba8d21ad2e95b568e2ce2aebf4` | evet | 90 257 / 90 258 | 0 / 0 / 0 / 90 257 | 0 |
| iTerm2 | sınama | arm64 (kaynak `53b9badb…0d29`) | `9fc127adb7d2f18c669f6954a2850a0dd153f2af666cd7d820f1cc715269aa65` | `4c3e96a2593d00e69f9e32cdde9f59ee0cd093cc5125565042dac4797d98febe` | **hayır**: 5 dışa aktarım + 1 fonksiyon sembolü kaldı | 108 776 / 131 876 | 34 605 / 60 771 / 314 / 13 096 | 28 (18 / 10) |
| llama-server | sınama | arm64 (kaynak `3efd976f…58d4`) | `89a52344cd014129a1d849079730810a6190eec5eec6ff8547027a91ec9d7321` | `6ae2d57c0dae9715aa245bf8b41c1ce8e4481f0f3cdf93cc725bc915c67c782f` | **hayır**: 151 dışa aktarım + 63 fonksiyon sembolü kaldı | 17 210 / 19 601 | 0 / 0 / 14 878 / 2 333 | 3 323 (2 006 / 1 317) |

- Dilimler araştırma kopyalarıyla (`$V/hedef/iTerm2.arm64`, `llama-server.arm64`) aynı sha256.
- GT adres sayıları araştırma envanteriyle tutarlı: docker-cli 35 050 (= `ayrik_adres`), iTerm2 108 776 ve llama-server 17 210 (= sembollü başlangıç).
- **HS tutmadı (2 / 5):** `/usr/bin/strip` öntanımı, ikilinin dışa açtığı sembolleri bırakıyor (iTerm2 5, llama-server 151 dışa aktarım; 1 ve 63 `T` sembolü). Kanal ölçümü sembol okumaz (RTTI taramasının zayıf bağ çözümü hariç; H1 bunu sınar). Ürün koşusu bu iki ikilide zaten yok (süre); gece kuyruğunda koşulursa bu adlar Ghidra'ya sızar: ya kalan sembollerin adresleri ölçümden çıkarılmalı ya da `strip -x` değil, dışa aktarım bırakmayan bir yol aranmalı (karar ana oturumda).
