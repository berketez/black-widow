# Arayüz onarımı: çağrı kenarları ve "imza eşleşmesi yok" cümlesi (2026-11-11)

Envanterin (`envanter.md` §2, §5.2) ölçtüğü iki arayüz hatasının onarımı. Kapsam yalnız bu iki hata. Hesaplama füzyonu satırı, BSim adayları, "otomatik isimlenebilir" metinleri ve `deriveRole` etiketlerine dokunulmadı.

## 1. Onarım A: çağrı kenarları Ghidra çağrı grafiğinden

**Kök neden.** Eski `ui/server.py` `build_model` (onarım öncesi satır 244) her fonksiyonun decompile metnindeki bütün `FUN_…` adlarını çağrı sayıyordu: `callees = set(_FUN_RE.findall(text)) & addr_set`. Adresi yalnız alınan fonksiyon (geri çağrı kaydı, tablo, karşılaştırma) "çağıran" görünüyordu.

**Değişiklik.**
- `_load_call_graph` ve `_call_graph_edges` (`ui/server.py:218-292`). Kenarlar `static/ghidra_call_graph.json`'dan kuruluyor. Önce decompile dizininin üstündeki `static/` aranıyor, çalışma alanının dışına çıkılmıyor; bulunamazsa `_read_static_json` ile aranıyor.
  - Grafik adrese anahtarlı. `edges[].from/to` okunuyor; kenar listesi yoksa `nodes[adres].callees[].address` okunuyor.
  - Adres `FUN_<adres>` dosya adına çevriliyor. Yalnız iki ucu da `FUN_*.c` olan kenarlar tutuluyor; ithaller ve Ghidra'nın adlandırdığı fonksiyonlar eskisi gibi düğüm değil.
- `build_model` (`ui/server.py:308-331`):
  - Metinde adı geçip grafikte kenarı olmayan başvurular yeni `addr_refs` alanına gidiyor (`{fonksiyon: [başvurduğu FUN_…]}`). Bunlar `calls`, `out`, `in` sayılarına girmiyor.
  - Grafikte olup metinde adı geçmeyen kenar çağrı sayılıyor. Grafik kaynaktır.
  - Kendine kenar eskisi gibi atılıyor. Dört çalışma alanında grafikte kendine kenar 0.
- **Geri düşüş açık.** Grafik yoksa, JSON bozuksa, biçim beklenen değilse ya da grafiğin düğümleri bu decompile dizininin fonksiyonlarıyla hiç örtüşmüyorsa (başka koşunun grafiği) eski metin yöntemi kullanılıyor. Bu durumda model `calls_source: "text"` ve `addr_refs: null` taşıyor. Grafik kullanıldığında `calls_source: "ghidra_call_graph"`.
- `_evidence` kanıt paketine `calls_source` eklendi (`ui/server.py:786`).
- `ui/index.html`, yalnız metin kipinde değişen iki etiket:
  - Harita merkezi (`:977-980`): "◀ N metninde adı geçen · M adının geçtiği ▶".
  - Kanıt kartı (`:1280-1288`): başlık "⇄ METİNDE ADI GEÇENLER (çağrı grafiği yok)", satır öneki "adının geçtiği: ".
  - Grafik varken metinler eskisiyle aynı. `addr_refs` bugün arayüzde gösterilmiyor; kartta ileride "adresini kullananlar" satırı olacak.

**Davranışı değişen yerler** (hepsi `calls` ya da `out`/`in` üzerinden; ayrı kod değişikliği gerekmedi):

| Yer | Değişen |
|---|---|
| `build_model` `functions[].out` / `in` | Yalnız gerçek çağrı |
| `build_model` `entry` (en çok çağıran = ilk odak) | Gerçek çağrıdan. Mac tmux'ta değişti (tablo) |
| `_evidence` `callers` / `callees` | Gerçek çağrıdan |
| `index.html` `buildList` sıralaması ve `.deg` sayıları (`N↗ M↘`) | Gerçek çağrıdan; sıra değişebilir |
| `index.html` `drawRadial`: ışınlar (sol: çağırdıkları, sağ: çağıranları), merkez sayacı, `tgCount`, `fEdges` | Gerçek çağrıdan; metin kipinde merkez etiketi değişiyor |
| `index.html` kanıt kartı "ÇAĞRI BAĞLAMI" | Gerçek çağrıdan; metin kipinde başlık ve önek değişiyor |
| `_naming_diagnosis`, süzgeçler (`passFilter`), isimli/zayıf/isimsiz sayımları | `calls` kullanmıyor; değişmedi |

## 2. Onarım B: "imza eşleşmesi yok" yalnız aday yokken

**Kök neden.** Eski `_naming_diagnosis` (onarım öncesi satır 596-599) adsız her fonksiyona sabit "Uygulanabilir imza/parmak izi eşleşmesi yok" cümlesini yazıyordu. İmza eşleşme kaydına hiç bakmıyordu.

**Değişiklik.**
- `_signature_candidates` (`ui/server.py:647`) `reconstructed/signature_matches.json`'daki `original` adlarını okuyor. Kayıt yoksa ya da okunamıyorsa None döndürüyor ("aday yok" bilinmiyor).
- `_naming_diagnosis` (`ui/server.py:706-715`):
  - Cümle yalnız kayıt okunup fonksiyonun Ghidra adı (`FUN_…`) aday listesinde yoksa yazılıyor.
  - Aday varsa ya da kayıt okunamıyorsa cümle yazılmıyor; yerine yeni iddia konmadı.
  - Zayıf adlı fonksiyonda aynı kural geçerli: aday varsa "— kesin imza eşleşmesi yok" eki düşüyor, "Yalnızca zayıf/adres-sonekli isim" kalıyor.
- `verdict` ve `reason` mantığına dokunulmadı; test bunu sınıyor.

## 3. Önce/sonra sayımı (GT'siz)

**Komut.** Önce: `git show 1c73026:ui/server.py` (onarımdan önceki sürüm). Sonra: `a8bcaac` sürümü. Betik scratchpad'te; arayüzün `build_model` ve `_naming_diagnosis` işlevlerini içe aktarıp çağırıyor:

```
PYTHONDONTWRITEBYTECODE=1 python3 sayim.py server_old.py ui/server.py
PYTHONDONTWRITEBYTECODE=1 python3 sayim_ek.py ui/server.py
```

- **Çalışma alanları** (salt okunur), `~/karadul_olcum/runs/urun-yeni-93a2956/` altında:
  - `debian/tree/tree/ws/workspaces/tree/20261111_050850/`
  - `debian/tmux/tmux/ws/workspaces/tmux/20261111_052758/`
  - `mac/tmux/ws/workspaces/tmux/20261111_054109/`
  - `mac/htop/ws/workspaces/htop/20261111_055521/`
- **"Grafikle örtüşen":** modeldeki kenarın, Ghidra grafiğindeki iki ucu da `FUN_*.c` olan kenarlar arasında bulunması.
- **"İmza çelişkisi":** adsız fonksiyonda "imza eşleşmesi yok" yazılırken fonksiyonun `FUN_` adının `signature_matches.json`'da `original` olarak bulunması (envanterdeki tanım).
- Ölçüm düzeninde temiz harita (`clean/naming_map.json`) bulunmadığı için teşhis `cmap = {}` ile çağrıldı. İmza cümlesi `cmap`'e bağlı değil.

| | Debian tree | Debian tmux | Mac tmux | Mac htop |
|---|---|---|---|---|
| Fonksiyon (`FUN_*.c`) | 115 | 1 916 | 2 587 | 597 |
| Kenar, önce → sonra | 263 → 135 | 9 790 → 6 282 | 13 350 → 8 574 | 2 089 → 1 210 |
| Grafikle örtüşen kenar oranı, önce → sonra | 0,5095 → 1,0 | 0,6415 → 1,0 | 0,6422 → 1,0 | 0,5792 → 1,0 |
| Grafikte olup modelde olmayan kenar, önce → sonra | 1 → 0 | 2 → 0 | 1 → 0 | 0 → 0 |
| `addr_refs` (başvuru / fonksiyon) | 129 / 62 | 3 510 / 1 314 | 4 777 / 1 852 | 879 / 389 |
| Hiç çağıranı olmayan, önce → sonra | 34 → 53 | 233 → 632 | 312 → 794 | 53 → 217 |
| Bunlardan Ghidra'da yalnız `FUN_` dışı çağıranı olan (sonra) | 3 | 3 | 7 | 1 |
| İlk odak (`entry`), önce → sonra | aynı | aynı | `FUN_100072604` → `FUN_10001bc5c` | aynı |
| Adsızda "imza eşleşmesi yok" yazılan, önce → sonra | 112 → 108 | 1 623 → 1 615 | 2 192 → 2 178 | 597 → 587 |
| İmza çelişkisi, önce → sonra | 4 → 0 | 8 → 0 | 14 → 0 | 10 → 0 |

**Okuma.**
- `addr_refs` sayıları envanterin "fazla kenar" sayılarıyla aynı: Debian tmux 3 510, Mac tmux 4 777, Mac htop 879.
- "İmza eşleşmesi yok" yazılan fonksiyon sayısındaki düşüş, çelişki sayısına eşit. Cümle yalnız çelişkili fonksiyonlardan kalktı.
- Sonradan "çağıranı 0" görünen fonksiyonların çoğu Ghidra'da da çağıransız. Az bir kısmı yalnız ithal ya da Ghidra'nın adlandırdığı fonksiyonlardan (`entry`, `_DT_INIT` gibi) çağrılıyor; bunlar arayüzde düğüm değil. Bu sınır onarımdan önce de vardı.

## 4. Testler ve mutantlar

- `tests/test_ui_cagri_kenari.py`: 16 test. Onarım A için 11, onarım B için 5.
- **Mutantlar:** `PYTHONDONTWRITEBYTECODE=1 python scripts/mutation_probe.py --spec scripts/measurement/mutation_specs_ui_cagri_kenari.json`. Sonuç: **13 killed, 0 survived, 0 error**.
- **Takımlar:** `python -m pytest tests -q -p no:cacheprovider -k "ui"` → 538 passed, 5 skipped. Bu koşu onarım A ve onun 11 testiyle, onarım B'den önce yapıldı.
- **Tam takım** (iki onarımdan sonra): `python -m pytest tests -q -p no:cacheprovider` → 7 859 passed, 56 skipped, 4 failed (638 sn).
  - Dört düşme ortam kaynaklı: `test_deobfuscator.py` (3) ve `test_pipeline.py::TestPipelineExecution::test_identify_and_static`.
  - Hata: `ERR_MODULE_NOT_FOUND`, `js-beautify` ve `@babel/parser` bulunamadı. Git dışı `scripts/node_modules` ana ağaçta var, bu worktree'de yok.
  - Arayüz koduyla ilgileri yok.

## 5. Doğrulanmayanlar

- Arayüz tarayıcıda açılmadı. Harita ve kanıt kartındaki yeni etiketlerin görünümü gözle denetlenmedi.
  - `index.html` için tek test, metin kipindeki etiket dizgilerinin dosyada bulunmasını sınıyor; JS davranışı koşturulmadı.
  - Yalnız sözdizimi denetlendi: betik bloğu ayıklanıp `node --check` ile sınandı, hata yok.
- `app_wrapper` kararının gerekçe metni ("eşleşecek imza yok") değişmedi. Karar metinleri kullanıcının kararına bırakıldı. Bu metin de imza adayı olan fonksiyonda çelişebilir; sayılmadı.
- Kenarlar Ghidra çağrı grafiği kadar doğru. Metinde çağrı sözdizimiyle geçip grafikte kenarı olmayan başvurular (envanter: Mac tmux'ta 63 yalnız çağrı sözdizimi, 5 ikisi birden) da artık `addr_refs`'te. Bunların hangisinin gerçek çağrı olduğu ayrıca denetlenmedi.
