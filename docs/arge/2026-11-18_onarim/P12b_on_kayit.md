# P12b ön kaydı — `kebap_ad` (AD-01), rol kanıtı; `tarif/evidence.py` dizgi içi `FUN_` (kalem 6)

- **Tarih:** 2026-11-18 (akşam). Ürün kodu değişmeden ÖNCE commit'lenir.
- **Taban ağaç:** yerel `main` ucu `80be454` (P13a ve c_namer yaması dahil).
- **Şablon:** `docs/arge/2026-11-10_n1_adim3/urun_olcumu_onkayit_taslak.md` (kısaltılmış).
- **Ölçüm kökü:** `~/karadul_olcum/runs/onarim-2026-11-18/P12b/`.

## 1. Görülen veri (değişiklikten önce; araştırma, kalem 1)

Geliştirme seti `urun-yeni2-f30ac9a` (119 ikili) köken kayıtlarında `kebap_ad` alt kanallı genel ad: **239** (Mac tmux 135, Debian tmux 101, openssl 2, sqlite3 1); tam eşitlikte doğru **0**. Rol çıkarımı (`kebap_topla.py`, `rol_say.py`, ölçüm kökünde; tanım §3) ve N0b'nin kör L1 etiketleri (`docs/arge/2026-10-19_g4_etiketleme/veri/etiket_L1_tmux385.jsonl`; Mac tmux, 76 kebap öğesi; `n0b_kebap_rol.py`) birlikte okundu:

| Rol sınıfı (Mac tmux, L1 etiketli) | n | tam | doğru tarif | yalnız alan | yanlış |
|---|---|---|---|---|---|
| `anahtar_erisimi` (kebap anahtar alan erişimci) | 49 | 0 | 5 | 40 | 4 |
| `olay_yayar` (çok yayan) | 6 | 0 | 0 | 6 | 0 |
| `olay_yayar` (ikilide tek yayan) | 6 | 0 | 1 | 4 | 1 |
| `cagri_disi` | 6 | 0 | 0 | 2 | 4 |
| `az_ornekli_cagri` | 2 | 0 | 0 | 2 | 0 |
| rol yok (urun-yeni2'de aynı adreste kebap kaydı yok) | 7 | 0 | 0 | 6 | 1 |
| **Toplam** | **76** | **0** | **6** | **60** | **10** |

Gevşek ölçütte (amacı doğru anlatan ad başarıdır: tam + doğru tarif + yakın) başarı **6 / 76**; hiçbir rol sınıfında başarı oranının Wilson %95 alt sınırı ürün eşiğine (0,7) yaklaşmıyor (en iyisi `anahtar_erisimi` 5 / 49). Kebap dizgisi fonksiyonun OKUDUĞU seçeneğin ya da YAYDIĞI olayın adıdır; fonksiyonun amacı dizgide yok (GT örnekleri: `monitor-silence` → `alerts_check_silence`, `pane-border-status` → `window_pane_find_up` / `layout_fix_panes` / … 10 ayrı fonksiyon, `window-layout-changed` → 16 yayan). Bu yüzden **bu pakette rol + nesne ad kuralı EKLENMEZ** (ölçülmüş kesinliği olmayan ad, sahte güvenle yayımlanmış olur); rol kanıt satırı olur.

## 2. Değişiklik (ön kayıtla sabit)

1. `tarif/alt_kanal.py`: `kebap_ad` kararı `belirsiz` → `zayif` (yeni ölçüm kaydı `kesinlik_tablosu.json` → `sonraki_kararlar`; eski `ana_kararlar` silinmez). Sonuç: `kebap_ad` adayı genel adlarda susturma süzgecinde düşer ve `silencing.candidates_dropped.kebap_ad` sayılır.
2. `c_namer.py`: her genel anahtarın `kebap_ad` alt kanallı `string_context` adayı için **dizgi rolü kanıtı** `naming_provenance.json` → `string_roles` (`{anahtar: [{string, role, api, arg_index, api_distinct_strings, emitters, function_kebab_strings}]}`), susturmadan önce, susturma açık da kapalı da. Ad seçimi değişmez (yalnız kayıt).
3. Kanıt düşmez ve seçim değişmez: susan dizginin yerine bir sonraki dizgiye geçilmez (N0b kuralı aynen).

## 3. Rol tanımı (sürüm 1)

Gövdedeki her `"<kebap>"` literali için sarmalayan çağrı (çağrılan ad, derinlik-0 argüman sırası). İkili genelinde aynı (çağrılan, sıra) çiftine verilen farklı kebap literalleri `D`.
- `karsilastirma`: çağrılan `strcmp` / `strcasecmp` / `strncmp` / `strncasecmp` (baştaki `_` soyulur).
- `olay_yayar`: |D| ≥ 2 ve D'deki her dizginin son parçası `-ed` ile biter.
- `anahtar_erisimi`: |D| ≥ 3 (öbür koşullar tutmadı).
- `az_ornekli_cagri`: çağrı var, yukarıdakilerin hiçbiri değil.
- `cagri_disi`: literal bir çağrı argümanı değil ya da gövdede literal yok.
`emitters`: aynı dizgiyi aynı (çağrılan, sıra)'ya veren fonksiyon sayısı.

## 4. Kollar ve girdi

Ghidra'sız yeniden oynatma (P12a aracı `yeniden.py`), `genel-tarama-2026-11-18` çalışma alanları; taban = `80be454` (`git archive`), sonra = P12b ağacı; `PYTHONHASHSEED=0`, ayrı `KARADUL_CACHE_DIR`.
- **Geliştirme:** `debian/tmux/tmux`, `mac/tmux` (rol tanımı bunlarda okundu).
- **Sınama (kuralın görmediği):** `debian/openssl/openssl`, `debian/sqlite3/sqlite3` (119'luk sette tmux dışında kebap adı taşıyan yalnız bu ikisi; toplam 3 ad). Daha geniş bağımsız kebap nüfusu bu sette YOK.
- **Yan etki denetimi:** aynı 14 çalışma alanından kalan 10'u (kebap adı yok).
- Ürün koşusu (Ghidra dahil): en çok 2 ikili (Debian tmux, sqlite3), süre izin verirse; yoksa açıkça yazılır.

## 5. Hipotezler

| # | Hipotez | Beklenti |
|---|---|---|
| H1 (kabul) | `kebap_ad` alt kanallı genel ad, 4 ikili: sonra ≤ %20 × taban | 0 (taban ≈ 239) |
| H2 (kabul) | Ad haritası (`global`) farkı yalnız tabanda `kebap_ad` adı taşıyan anahtarlarda; öbür bütün anahtarlar (14 ikili) aynı | tutar |
| H3 | Kebap anahtarında sonra başka kanaldan ad (ikinci aday ürün eşiğini geçti): sayılır, raporlanır | ≤ 5 (karar ölçütü değil) |
| H4 | `silencing.candidates_dropped.kebap_ad` = tabandaki kebap adı sayısı (ikili başına) | tutar |
| H5 | `string_roles` anahtar sayısı = tabandaki kebap adı sayısı (ikili başına); her satırda `role` §3 kümesinden | tutar |
| H6 (kabul) | Kaybedilen doğru ad (tam eşitlik, `urun_olc karsilastir`, C ikilileri) | 0 |
| H7 | Gevşek doğru kebap adı | 0 (ad verilmiyor); neden: §1 tablosu ve GT örnekleri |

## 6. Kalem 6 — `tarif/evidence.py` dizgi içi `FUN_`

- **Kusur:** `build_evidence` geri çağrı kaydını çağrı argümanlarının HAM metninden çıkarıyor; argümandaki dizgi sabitinde geçen `FUN_<hex>` / `LAB_<hex>` geri çağrı sayılıyor.
- **Onarım:** argüman metninde dizgi ve karakter sabitleri (`"…"`, `'…'`, kaçışlar dahil) aranmadan önce boşaltılır.
- **H8:** sentetik gövdede (`foo(“FUN_00401000”)`) kayıt önce 1 → sonra 0; gerçek koddaki argüman başvurusu (`foo(FUN_00401000)`) önce 1 → sonra 1.
- **H9 (önce / sonra sayım):** 14 genel tarama çalışma alanının `callback_registrations` toplamı ve `registered_as_callback` toplamı: fark yalnız dizgi içi başvurulardan; beklenti 0 fark (P22a: gerçek veride 891'de 0).

## 7. AD-02 "rol + öğe" (kalem 5)

`naming_provenance.json` `role_evidence` satırlarında (sonra kolu, 14 ikili) öğe kanıtı kaynakları sayılır: (a) çağıranın adı `FUN_` değil, (b) aynı API'ye verilen öbür geri çağrıların adlı olanı, (c) karşılaştırıcının gövdesinde çağrılan adlı fonksiyon. Ölçülmeden ad kuralı eklenmez; sayı ve GT örnekleri `P12b.md`'ye yazılır.
