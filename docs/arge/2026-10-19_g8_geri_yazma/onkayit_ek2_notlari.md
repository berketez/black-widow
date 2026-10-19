# G8 ek 2: ön kayıt notları

`onkayit_ek2.md` ölçümden sonra değiştirilmedi. Mühür `workspaces/2026-10-19_g8/veri/onkayit_ek2_muhur.txt`'de: 2026-10-19T13:12:30+0300, SHA-256 `6a27a7c2c9ecb6337de602c22f13435eeea5f3f8a5f85f832b40140681815056`. K4 ve K4' bu mühürden sonra koşuldu (ölçüm kayıtları 13:13:52 ve 13:13:58). Aşağıdakiler ön kaydın sustuğu yerlerdir; hiçbiri ölçütü, eşiği ya da okumaları değiştirmedi.

| # | Yer | Not | Sonuca etkisi |
|---|---|---|---|
| 1 | §2 K4 | Ghidra'nın gördüğü parametrelerin hepsi (48/48) kaynak adıyla adlandırıldı. Kaynakta 51 parametre var. İki fonksiyonda Ghidra daha az parametre görüyor: `window_pane_send_resize` 1/3 (`sx`, `sy` decompile edilen gövdede yok) ve `window_pane_set_prompt` 9/10. Eşlenemeyen ve kaynakta karşılığı olmayan parametre yok; hata yok. | Yok |
| 2 | §2 K4' | 22 parametreye ve 3 dönüş tipine (`window_pane_find_up/down`, `cmd_swap_pane_prev_tiled_pane`) `window_pane *` yazıldı. `window_pane` programda 1760 bayt, 75 alan; `timeval` ve `termios` tabanda vardı. | Yok |
| 3 | §2 ısınma | Isınma turu `projeler/K0` kopyasında yapıldı. Bu kopya tabanla aynıdır, değiştirilmedi ve kaydedilmedi. | Yok |
| 4 | — (gözlem) | `commitParamsToDatabase` çağrı kuralını da decompiler'ın modelinden yazıyor. Bu yüzden K4 ve K4' çıktılarında C2-C4'teki "Unknown calling convention" uyarı yorumu yok. Yorumlar ölçüte girmiyor. | Yok |
| 5 | §5 R1 | K4'te hedeflerin metni C0'dan yalnız adlarda ayrılıyor. U, P1 ve C her fonksiyonda aynı; satır toplamı aynı (622). R1'in değeri tam 0. | Yok |
| 6 | — (süre) | K4 ve K4' ölçülürken makinenin yük ortalaması 31-35'ti (başka ajanlar ve yerel model). Decompile süreleri önceki koşulların 2-3 katı çıktı (K4: hedefler 157 ms, çağıranlar 3700 ms). Bu fark yükten geliyor. Bu tur için süre **ölçülemedi** sayılır ve yorumlanmaz. | Süre raporlanmaz |
