# KİMLİK hattı — Berke için özet (2026-11-19)

**Ne soruldu:** Adını bilmediğimiz bir fonksiyonu, aynı kodun adları bilinen başka bir derlemesinde ("başvuru": aynı programın başka derleyiciyle ya da başka sürümle derlenmiş, adları duran hâli) bulup adını oradan alabilir miyiz? Ne kadar doğru, ne kadarını?

**Ne bulundu (hepsi ölçüm; yapay zekâ ve öğrenme yok):**
1. **Evet, başvuru aynı sürümse.** Yöntem: önce yalnız tek bir fonksiyonda geçen yazıları eşle ("çapa"), sonra onları çağıran / onların çağırdığı ve aynı tabloda duran komşulara yayıl; emin değilsen ad verme. tmux 3.8'i GCC ile kendim derleyip Homebrew'un clang derlemesinden tanıttım (önceden yazılmış eşiklerle, hiç görülmemiş ikilide): ad bekleyen fonksiyonların **%80–88'ine** ad verdi, **%99'u doğru** (4 281 doğru, 36 yanlış). Bugünkü ürün aynı programda %8.
2. **Başvuru başka sürümse doğruluk %93,5'e iniyor** (tmux 3.5a ↔ 3.8: 2 276 doğru, 158 yanlış). Yanlışların çoğu yanlış fonksiyon değil: yeni sürümde adı değişmiş fonksiyonlar (`notify_pane` → `events_fire_pane`). Sürüm farkı, derleyici farkından daha pahalı çıktı.
3. Kalan gerçek hata: derleyici küçük fonksiyonu çağıranın içine gömünce ("satır içine alma") kanıt bir basamak kayıyor. Bunu işaretleyen bir denetim buldum; işaretlileri ad yerine not olarak yazarsak doğruluk %99,7'ye çıkıyor, kapsam 3 puan düşüyor.
4. Hazır yöntemler aynı sınavda çöküyor: BSim %61, CFG bankası hiç eşleşmiyor.
5. **Üründe bugün duran "başvuru ikilisi ver" özelliği yanlış ad yazıyor:** tmux'ta 328 doğruya karşı 174 yanlış; içindeki "boyut benzerliği" yöntemi 118 addan 2'sini bildi. Öntanımda kapalı olduğu için ölçümlerde görünmüyordu. Yayından önce düzeltilmeli (planın ilk paketi).
6. En ucuz yol üründe hiç yok: Linux dağıtımından çıkan soyulmuş bir ikili, kimlik numarasıyla ("build-id") kendi hata ayıklama dosyasını birebir gösterir; ad oradan doğrudan okunur.

**Ne anlama geliyor:** "İmzalı olandan tanı" fikrin doğru; ama işe yarayan şey hazır imza kütüphanesi değil, **aynı kaynağın aynı sürümünün adları duran bir derlemesi**. Asıl iş artık eşleştirmek değil, doğru sürümü bulmak. Sınır: sonuç iki programda (tmux, htop) ölçüldü; başka programlarda yinelenmeli. Kapalı kaynak programın kendi kodunda bu yol yok.

**Senden karar (ana oturum soracak):**
- Başka programlarda yinelemek için birkaç kaynak paketi ve bir kitaplık paketi (libzstd) indirilsin mi? (Verdiğin indirme onayının kapsamına giriyorsa ek onay gerekmez.)
- Analist hata ayıklama dosyasını kendisi verdiğinde adları oradan almak öntanımlı açık olsun mu (PDB'de böyle)?
- Başvuru başka sürümse ürün adı yazıp "başvurunun sürümündeki ad" diye işaretlesin mi, yoksa yalnız not mu düşsün? (Önerim: ad + işaret.)
