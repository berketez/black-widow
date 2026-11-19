# ÖLÇÜ hattı — Berke için özet (2026-11-19)

1. **Ne soruldu:** "Ad birebir aynı değil ama amacı doğru anlatıyor" durumunu bir hesapla sayabilir miyiz, ve bu hesap insanın yargısıyla uyuşuyor mu?
2. **İlk bulgu:** elimizde hiç insan etiketi yok. Bugüne kadarki 1 319 "doğru tarif / yanlış" hükmünün hepsini yapay zekâ ajanları vermiş. Bu yüzden ölçtüğüm şey "hesap ↔ ajan hükmü" uyumudur; insan uyumu hâlâ bilinmiyor.
3. **Ana sonuç:** ad benzerliğini sözcük sözcük karşılaştıran hiçbir hesap (literatürün önerdiği "belirteç F1" dahil; belirteç = adın `_` ile ayrılan parçası) "amacı doğru"yu sayamıyor. O hesabın "yakın" dediği adların yalnız %23–%35'i gerçekten doğru tarif; beşte biri ile dörtte biri arası yanıltıcı. Sebep: `window_pane_add` ile `window_pane_add_ref` neredeyse aynı yazılıyor ama farklı iş yapıyor; fonksiyonların dörtte üçünün böyle bir "ikizi" var.
4. **İyi haber, hesapla sayılabilen bir şey çıktı:** bugün "yanlış" saydığımız 119 adın 40'ı aslında doğru ad, yalnız harfleri küçük yazılmış (çoğu zstd'de: `FSE_buildDTable` yerine `fse_builddtable`). Bunları doğru sayınca yanlış oranı %6,6 → %4,4; program ortalaması %31,0 → %19,1. Hedef (≤ %10) yine tutmuyor.
5. **Geriye 79 belirsiz ad kalıyor** (tekrarlar çıkınca 73). Bunların kaçının "amacı doğru" olduğunu ancak insan söyleyebilir.
6. **Uyarı:** 1 800 adın yalnız 535'i birbirinden farklı ad (aynı gnulib kodu 106 programda tekrar ediyor). "733'te 733 doğru" görünen kanal aslında 10 farklı adda sınandı; başka programlarda ölçmeden güvenemeyiz.
7. **Ad mı, ipucu mu:** "yanlış ≤ %10" hedefi, yanlış adı eksik adın 10 katı kötü saymak demek. Bu ölçüyle gnulib, program başlangıcı ve `main` kanalları ad vermeye devam eder; dizgiden ad çıkaran kanal (`oz_ad`) ad değil ipucu satırı yazmalı. O kanalın kendine biçtiği güven (%83) gerçekleşenin (%47) çok üstünde.

**Senden beklenen kararlar:**
- İki insan değerlendirici (C okuyabilen). Paket hazırlanacak: 302 ad, kişi başı süre ilk 50 adla ölçülecek. Bu olmadan "yakın ad" sayısı yayımlanamaz.
- Yanlış ad, eksik adın kaç katı kötü? (Öneri: 10; bugünkü hedefle aynı.)
- İndirme onayı: önce aynı programların x86-64 sürümleri (7,3 MB + hata ayıklama paketleri), sonra kurayla seçilecek 10 yeni program.
- Küçük harf farkı "doğru" sayılsın mı? (İnsanlar da onaylarsa önerim evet.)
