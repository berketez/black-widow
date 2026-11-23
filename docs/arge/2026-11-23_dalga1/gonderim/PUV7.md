# PUV7 — P-ÜV7: Go tutarlılık denetimi (I4)

Önce oku (sırayla, baştan sona): `docs/arge/2026-11-23_dalga1/ORTAK_D1.md`, `docs/arge/2026-11-20_dalga0/ORTAK_D0.md`, `docs/arge/2026-11-18_onarim/ONARIM_BRIF.md`, `docs/arge/2026-11-19_mythos/KARARLAR.md` (A-10, A-13, A-14, A-23, A-27), `docs/arge/2026-11-19_mythos/ustveri/PLAN.md` §0 ve "P-ÜV7" (biçim, kalemler 1–7, kabul, sınama ve mutasyon: aynen uygula), `docs/arge/2026-11-19_mythos/ustveri/BULGULAR.md` §6 (bozma deneyi), `docs/arge/2026-11-19_mythos/ustveri/P-UV1.md` (Go okuyucusunun raporu; K denetimleri, `pcsp_kapsama`, E türü bozma).

Kod başvuruları: `karadul/analyzers/ustveri/go_pclntab.py` (içe aktar; DEĞİŞTİRME — eksik alan gerekiyorsa ilerleme dosyana yaz), `karadul/analyzers/ustveri/goruntu.py`, araştırma betikleri `scripts/arge/ustveri/go_tip.py`, `go_tutarlilik.py`, `dusman_deney.py` (çalışan başvuru; yeniden yazılır, kopyalanmaz).

## Neden

Go `pclntab` adı derleyicinin yazdığı hâliyle doğrudur ama ad metni çalışma için zorunlu olmadığından değiştirilebilir (bozma deneyi: tutarlı sahtecilikte yakalanan 0 / 86, 0 / 451). Analist zararlı yazılım incelerken ad tahrifatı gerçek bir tehdittir. Bu paket adı, çalışma için zorunlu ikinci bir yapıyla (itab, yöntem tabloları, `funcID`) karşılaştırır ve fonksiyon başına `cift_kaynak` / `tek_kaynak` / `tutarsiz` damgası üretir. Denetim adın gerçekliğini kanıtlamaz; ucuz tahrifatı ve bozuk üst veriyi yakalar. Damganın ad kanalına bağlanması P-ÜV6b'de.

## Ana oturumun hükümleri (plan metninin önüne geçer)

1. **Üretici adım yok, bağlama yok:** bu paket yalnız kitaplık (`go_tip.py`, `tutarlilik.py`) + ölçüm betiği (`ustveri_bozma.py`). `go_metadata_recovery` adımına ve ad kanalına dokunma. `enable_go_metadata_integrity` bayrağını okuma (P-ÜV6b bağlar; INERT'te kalır, yama yok).
2. **Hedef seti:** `gh` ve `limactl` (Homebrew, soyulmuş) plandaki başvuru ikilileridir ve keşifte serbesttir (GT'leri yok; ölçüt araştırma çıktısıyla eşitlik + bozma deneyi). docker-cli keşif, docker-compose SINAMA: H3'ün docker-compose kolu denetimler dondurulduktan sonra BİR kez.
3. **Kalem 6 (K10 içerik denetimi) koşulludur:** önce ölç (bozulmamış ikilide `pcsp` ↔ giriş bölümü yığın ayarlaması uyumu); ≥ %99 tutuyorsa ekle, tutmuyorsa "neden olmadı"yı yaz ve ekleme. İki sonuç da geçerli bir teslimdir.
4. Bozma deneyi özgün dosyayı değiştirmez; bozuk kopya bellekte ya da `~/karadul_olcum/runs/dalga1-2026-11-23/PUV7/` altında. Hiçbir ikili çalıştırılmaz.
5. Damga sözlüğü (`cift_kaynak`, `tek_kaynak`, `tutarsiz`) ve ikili düzeyi karar (`ust_veri_supheli`; eşik ilk ölçümle ön kayıtlı) modülde adlandırılmış sabit; P-ÜV6b içe aktaracak.

## Yazabileceğin dosyalar (hepsi yeni)

`karadul/analyzers/ustveri/go_tip.py`; `karadul/analyzers/ustveri/tutarlilik.py`; `scripts/measurement/ustveri_bozma.py`; `tests/test_puv7_tutarlilik.py`; `scripts/measurement/mutation_specs_puv7.json`; `docs/arge/2026-11-19_mythos/ustveri/on_kayit_PUV7.md`, `docs/arge/2026-11-19_mythos/ustveri/P-UV7.md` (ilerleme dosyası).

**Dokunma:** var olan bütün dosyalar (`go_pclntab.py`, `goruntu.py`, `go_metadata_recovery.py`, `stages.py`, `config.py`). Ghidra koşusu YOK.

## Ön kayıt (`on_kayit_PUV7.md`; ölçümden önce commit)

Plandaki H1–H6 aynen. Ek:
> H3-sınama (bir kez; denetimler dondurulduktan sonra): docker-compose'da (Go 1.23.8) bozulmamış hâlde T1 ve T2 uyumu ≥ %99,9; tutmazsa o sürüm için `desteklenmiyor`.
> H7 (ikili düzeyi eşik): bozulmamış 11 dilimde güçlü işaretli fonksiyon oranının en büyüğü ölçülür; `ust_veri_supheli` eşiği (%1) bu en büyük değerin en az 10 katıysa eşik kalır, değilse eşik ön kayıtta yazılı kuralla yükseltilmez — bulgu olarak yazılır ve karar ana oturuma bırakılır.

## Sıra

1. Ön kayıt → commit. 2. Tip verisi okuyucu (itab, tipler, yöntem tabloları; 1.27 ve ≤ 1.26 yerleşimi) + sentetik testler. 3. Denetimler T1, T2, T2p, T5, T6 (güçlü); T3, T4 (zayıf, ayrı). 4. Damga + ikili özeti. 5. Bozma deneyi betiği (A–E; tohum 20261119; tür başına 200). 6. Kalem 6 ölçümü ve kararı. 7. Mutasyon (≥ 8). 8. Kabul ölçümü (H1, H2, H4, H6, H7; ek ikililer). 9. Dondur → H3-sınama. 10. Tam takım.

## Sert son

Gönderim iletisinde yazılı.

## Dönüş mesajı

İlk satır gerçek uygulama sayıları: Ollama arm64'te 10 600 adın kaçı `cift_kaynak` / `tek_kaynak` / `tutarsiz`; docker-cli'de aynı döküm; bozma deneyinde tür başına yakalanan (A–E). Sonra H1–H7, K10 kararı, test / mutant sayıları, dondurma commit'i, commit listesi, P-ÜV6b'ye notlar (içe aktarılacak adlar; `go_pclntab.py`'de eksik bulduğun alan).
