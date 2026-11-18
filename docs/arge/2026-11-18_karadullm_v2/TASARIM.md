# KaradulLM v2 tasarımı: hafif ajan, kısıtlı terminal, canlı görünüm

- **Tarih:** 2026-11-18. **Durum:** taslak; kod yazılmadı. Karar bekleyen maddeler §11'de.
- **Taban:** `main` `f7522e6` (sürüm 1.23.1). Paket: P22-T (yalnız belge).
- **Okunan iç kaynaklar:** `karadul/lm/` (agent, protocol, tools, context, audit, backend imzaları, `__init__` sabitleri); `docs/arge/2026-11-11_karadullm/` (`tasarim.md` tamamı, `arac_sozlesmeleri.md` tamamı, `asama1b.md` §1-2 ve §6-8, `onuncu_adam.md` §0 ve §6); `docs/arge/2026-11-18_genel_tarama/kulvar_LM.md` tamamı, `RAPOR.md` §5 ve §7, `kulvar_ARAYUZ.md` ARAYUZ-19; `ui/server.py` ve `ui/index.html` (ilgili bölümler).
- **P21:** ilerleme dosyası (`docs/arge/2026-11-18_onarim/P21.md`) 2026-11-18'de ne `main`'de ne bir worktree'de vardı. P21'e bağlanan her yer "P21'in teslim edeceği arayüz" diye yazıldı; P21 bitince bu yerler denetlenir.
- **Koşulmayanlar:** model, `llama-server`, Ghidra, Karadul hattı, testler. Diskte yalnız bir saklı çalışma alanının dosya listesine bakıldı (§3.5'teki "veri hazır" sütunu için).
- **Kör setler okunmadı.** Belgede gerçek fonksiyon adı ve dizgi içeriği yok.
- **İşaretler (önceki tasarımla aynı):** **[ölçüm]** bir belgeden ya da koşulan bir komuttan. **[hesap]** ölçülmüş sayılardan aritmetik. **[tahmin]** ölçülmemiş varsayım. **[seçim]** Berke'nin kararı; değer yalnız başlangıç önerisi. **[doğrulanmadı]** teyit edilemedi.
- **Dış kaynak kimlikleri** (`[OC-n]` opencode, `[CC-n]` Claude Code, `[CX-n]` Codex, `[XT-1]` xterm.js): tam kayıtlar §10'da (Claim / Evidence / Confidence / Date checked / What may change).

## 0. Kısa sonuç

1. **İki motor.** KaradulLM v2'nin ad ve açıklama işi **belirlenimci bir hattan** geçer: sırayı sunucu yürütür, model fonksiyon başına bir kez çağrılır (bugünkü K0'ın zenginleşmiş hâli). Kodlama ajanlarına benzeyen **araç döngüsü** yalnız analistin sorduğu açık uçlu sorular için kullanılır (keşif kipi). Döngünün kapıları (K-Z1, K-A1…) gerçek modelde geçilene kadar keşif soruları da tek atışla, soru + anılan fonksiyonların paketiyle cevaplanır. Döngü, ayırıcı deney (§8.2) yanlış ad oranını düşürdüğünü gösterirse ad üretimine girer. Bu karar §7'deki aykırı öncülden geliyor: 27B yerel modelde ad işi için döngünün kazancı ölçülmedi, bedeli ise ölçüldü.
2. **5/5 çekimserliğin çaresi bilgidir, ajan değil.** Aşağıdan yukarı özet zinciri (önce yapraklar; özet çağıranın paketine `[model-özet]` satırı olarak girer), LM-08'deki eksik komşu bilgisini belirlenimci sırayla sağlar (§3.6).
3. **opencode'dan alınan çekirdek fikirler:** istemci–sunucu ayrımı (ajan sunucuda, terminal ve arayüz istemci), kip = istem + izin + araç kümesi, sıra numaralı olay akışı, adım tavanı dolunca araçların kaldırılıp son cevabın zorlanması (bizde zaten var), plan kipi [OC-1][OC-2][OC-4][OC-5]. **Alınmayanlar:** kabuk, dosya düzenleme, web, model yazımlı sohbet sıkıştırması, paralel alt ajan, MCP tüketimi (§6).
4. **Kısıtlı terminal (Berke'nin kararı): terminal biçimli olay akışı.** PTY yok, xterm.js yok, kabuk yok. Panel bir giriş satırı ve olaylardan çizilen satırlardan oluşur. Sunucu tek bir komut kabul eder: tam olarak `karadullm`. Bu komut başka bir süreç başlatmaz; arayüz sunucusunun içinde bir KaradulLM oturumu açar. Gerekçe §4.3: PTY, macOS'ta bu sunucunun kaçındığı `setsid` yolunu ister (`ui/server.py:1820-1822`); ayrıca WebSocket, ham bayt akışı ve kaçış dizisi yorumlayan bir öykünücü getirir. Olay akışı aynı görünümü bu yüzeylerin hiçbiri olmadan verir.
5. **Taşıyıcı: uzun yoklama** (`GET /api/lm/olaylar?sonra=N&bekle=…`). Bugünkü `fetch` sarmalayıcısı jetonu her `/api/` isteğine ekliyor (`ui/index.html:687-696`); `EventSource` bu sarmalayıcıdan geçmez ve özel başlık gönderemez. Uzun yoklama `_guard`'ı (Host, Origin, `X-Karadul-Token`; `ui/server.py:2013-2038`) hiç değiştirmeden kullanır ve yanıt yolu bugünkü gibi `Content-Length` yazar (§4.2).
6. **Örümcek** yalnız gerçek olaylardan beslenir: `gorev_basladi` / `arac_basladi` olaylarındaki `hedef.fn` alanı arayüzün `BYADDR` anahtarıyla aynı yazımdadır (decompile dosya adının gövdesi; `ui/server.py:300-301`, `karadul/lm/tools/__init__.py:244-246`). Olay yoksa hiçbir şey hareket etmez (§4.5, §4.7).
7. **İzin modeli eylem × kip tablosudur.** `uygula` (ad haritasına ya da model bölümüne yazma) ve `çalıştır` (hedefi ya da herhangi bir süreci çalıştırma) her kipte reddedilir ve ayarla açılamaz. Model yalnız öneri açar; kabul analistin tıklamasıyla ve yalnız `proposal_id` ile yapılır (§3.9).
8. **MCP:** KaradulLM MCP **tüketmez** (16K bağlamda her araç tanımı yer tutar, araç kümesi değişince sabit önek bozulur). Karadul'un okuyan araçları ileride isteğe bağlı, salt okur, yalnız stdio üstünden çalışan bir MCP sunucusuyla dışa açılabilir (P22f). Asıl risk, araç sonucundaki saldırgan metninin kabuk erişimi olan bir dış ajanı yönlendirmesidir (§5).
9. **İş paketleri:** P22a (olay omurgası) → P22b (görevler + aşağıdan yukarı özet) ∥ P22d (araç kaydı v2) → P22e (kipler, izin, plan, terminal ayrıştırıcısı, defter) → P22c (arayüz: önce sunucu, sonra sayfa; P17'den sonra) → P22f (MCP, isteğe bağlı); P22g (ölçüm) P22a'dan sonra ön kaydını yazar, P22b ve P22d'den sonra koşar (§9).

## 1. Ölçüt ve kapsam

**Berke'nin tarifinden çıkan ölçütler (2026-11-18):**

| # | Tarif | Tasarımdaki karşılığı | Sınayan |
|---|---|---|---|
| Ö1 | Arayüzün yanında terminal paneli; `karadullm` yazınca ajan açılır | §4.3 kısıtlı terminal; tek komutluk izin listesi | T-1, T-2 (§8.1) |
| Ö2 | Terminal ajanın ne yaptığını adım adım akıtır (araç, okuduğu, önerisi, denetim hükmü) | §4.1 olay şeması, §4.4 terminal biçimi | E-1, E-2 |
| Ö3 | Örümcek ajanın o an dokunduğu fonksiyonun üstüne gider; yalnız gerçek olaydan | §4.5; §4.7 mekanik sınama | U-1, U-2 |
| Ö4 | Hafif: opencode'un bütünü değil, bu deneyim için gereken çekirdek | §2 matris; §6 alınmayanlar | — |
| Ö5 | Kısıtlı terminal: kabuk yok, izin listesi tek öğe, girdi yalnız o oturuma, jeton/Host/Origin denetimi, arayüz kapanınca ölür, hedef asla çalıştırılmaz | §4.3 G1-G9 | T-1…T-5 |
| Ö6 | Motor LLM'siz; KaradulLM isteğe bağlı; model önerisi ayrı köken bölümünde; analist onaylamadan ad haritasına girmez | §3.9, §3.10; önceki tasarım §5.3 aynen | K-M1, K-M3, K-G3 |
| Ö7 | Hedef kullanıcı: yazılımın zararlı olup olmadığını anlamaya çalışan analist | §3.4 keşif kipi (ters arama, yol bulma), §3.5 araçlar | yön gösterici (§8.1) |

**Hedef olmayanlar:**

- KaradulLM bir yazılım için "zararlı" ya da "zararsız" hükmü vermez. Analistin sorusuna kanıt toplar ve her cümlesini bir sonuç kimliğine bağlar. Hükmü analist verir. (Ürün ölçütü: analisti yanıltmamak, `ONARIM_BRIF.md` §1.)
- Kod düzenleme, kabuk, web, hedefi çalıştırma, dinamik analiz yok.
- İnce ayar yok. Bunun için önce ölçüm gerekir (RAPOR §7.3).
- Sayısal güven gösterilmez (önceki tasarım §1).
- Ölçülmemiş hiçbir kip öntanımlı açılmaz. K1 ve K2 bugün kapalıdır (`agent.py:156`) ve kapıları geçmeden kapalı kalır.

## 2. Özellik matrisi

Hücrelerdeki köşeli kimlikler §10'daki dış kaynak kayıtlarıdır; dosya:satır başvuruları bu depodandır. "bakılmadı" = bu çalışmada resmi kaynağı okunmadı.

| Özellik | Claude Code | Codex CLI | opencode | KaradulLM bugün | KaradulLM önerilen |
|---|---|---|---|---|---|
| **Araç döngüsü** | "Bağlam topla → eylem → doğrula" döngüsü; model araç seçer (dosya, arama, kabuk, web) [CC-1] | Döngünün öğeleri: ajan iletisi, akıl yürütme, komut çalıştırma, dosya değişikliği, MCP çağrısı, web arama, plan güncellemesi [CX-3] | Birincil ajan, izin kurallarının açtığı araçlarla çalışır (read, edit, shell, glob, grep, webfetch…) [OC-2]; `steps` tavanı [OC-1] | K0 tek atış: sunucu O1 ve O2'yi çağırır, model bir kez (`agent.py:390-432`). K1/K2 bütçeli döngü kodda var, öntanımlı kapalı (`:194-201`, `:450-545`); gerçek modelde hiç koşmadı (kulvar LM-07 e) | **İki motor:** belirlenimci hat (açıkla, adlandır; sıra sunucuda) + keşif döngüsü (Yol A JSON zarfı, dilbilgisiyle; ≤ 8 çağrı). Döngünün ad üretmesi ayırıcı deneye bağlı (§7, §8.2) |
| **Plan kipi** | `plan`: "research and propose changes without making them" [CC-2] | `/plan` plan kipini açıp kapatır [CX-7] | `plan` birincil ajanı; `~/.opencode/plan` dışında düzenlemeyi reddeder [OC-1][OC-2] | Yok | `plan` kipi: model iş listesi önerir (hangi fonksiyonda hangi görev), sunucu adresleri doğrular ve ölçülen hızla beklenen süreyi hesaplar, analist onaylarsa kuyruğa girer. Model planı kendisi yürütmez (§3.4) |
| **Alt ajan / görev bölme** | Alt ajan kendi bağlam penceresinde, kendi istemi, aracı ve izniyle çalışır; yalnız özet döner; üç kata kadar iç içe [CC-3] | Alt ajanlar var ("Subagents for delegating work") [CX-8]; ayrıntı bakılmadı | V2: `subagent` aracı; alt ajan taze bağlamlı çocuk oturumda ve arka planda; `general`, `explore` [OC-1]. V1: Task aracı [OC-9] | Yok; K2 tek fonksiyon, 8 çağrı (kulvar §Vizyon 1) | **Alt görev = taze bağlamlı, sıralı kuyruk öğesi** (özet, ad öner). Sonucu yapılandırılmış kayıt olarak özet deposuna yazılır. Paralellik yok (tek yuva, `--parallel 1`, `backend.py:143`); alt görev alt görev açamaz (§3.6) |
| **İzin sistemi** | Kipler: `default`, `acceptEdits`, `plan`, `auto`, `dontAsk`, `bypassPermissions`; "Deny rules block in every mode" [CC-2] | Kum havuzu: `read-only` / `workspace-write` (öntanım) / `danger-full-access`; onay: `on-request`, `never` (`untrusted` emekli); ağ öntanımlı kapalı; macOS'ta Seatbelt [CX-2]; `exec` öntanımı `read-only` [CX-3] | Eylem × kaynak deseni × `allow`/`ask`/`deny`; son eşleşen kazanır; kural yoksa `ask`; `once`/`always`/`reject`; politika katmanı yalnız daraltır [OC-2] | Araçlar yapım gereği salt okur; yol, komut, URL ya da düzenli ifade almaz (`tools/__init__.py:6-11`). Öneri ve yazma aracı yok. Loopback dışı uç için ağ onayı (`allow_network`, `backend.py:839-875`) | Sabit eylem tablosu (`oku`, `öner`, `uygula`, `ağ`, `çalıştır`, `uzun_iş`) × kip. `uygula` ve `çalıştır` her kipte `deny`, ayarla açılmaz. `uzun_iş` `ask` (plan onayı) (§3.9) |
| **Oturum ve bağlam sıkıştırma** | Oturum JSONL; bağlam dolunca özetle sıkıştırma; `/compact` odaklı; özet istekleri ve kod parçalarını tutar, erken talimatlar kaybolabilir [CC-1] | `/compact` görünür sohbeti yoğunlaştırır [CX-7] | V2: eski konuşma özetle değişir; son ~15 000 jeton aynen kalır; `buffer` %15 ve en az 16k; aşımda bir kez sıkıştırıp yeniden dener [OC-6] | Denetim günlüğü içeriksiz (sha256); sıkıştırma yok; bağlama sığmayan görev başlamadan reddedilir (`agent.py:411-413`) | **Model yazımlı sıkıştırma yok.** Belirlenimci kütük (eski sonuç → tek satır, yeniden çağrılabilir), yapılandırılmış defter ve özet deposu. opencode'un ≥ 16k tamponu bizim bütün penceremiz kadar (§3.7) |
| **Kalıcı bellek / proje notları** | CLAUDE.md (kullanıcı yazar) + otomatik bellek (model yazar); ikisi de her oturumda yüklenir; "context, not enforced configuration" [CC-5] | AGENTS.md zinciri; toplam `project_doc_max_bytes` 32 KiB [CX-4] | AGENTS.md; yoksa CLAUDE.md; `instructions` dizisi [OC-10] | Yok. `overrides.py`'de `note` alanı var, oturum defteri yok (kulvar §Vizyon 1) | İkili sha256'sına bağlı **defter**: analist notu, kabul / ret ve nedeni. Modelin notu yalnız öneridir. Oturum bloğu ≤ 600 jeton (önceki tasarım §4.4) |
| **Kancalar** | `PreToolUse` engelleyebilir (çıkış 2 ya da JSON `deny`), `PostToolUse`, `UserPromptSubmit`, `Stop`, `PreCompact`, `SessionStart`…; kanca kabuk komutu çalıştırır [CC-4] | bakılmadı | Eklentiler yeni izin eylemi tanımlayabilir [OC-2]; kanca belgesi bakılmadı | İç denetimler: şema, bütçe, tekrar, körlük (`agent.py:510-544`) | Kullanıcı tanımlı kabuk kancası **yok**. Süreç içi, sabit kanca noktaları: araç öncesi (şema, kip, bütçe, tekrar), araç sonrası (körlük, enjeksiyon bayrağı), öneri öncesi (P21 denetimi) (§3.10) |
| **MCP** | İstemci; uyarı: "Verify you trust each server before connecting it" [CC-8]. Sunucu kipi okunan resmi sayfalarda bulunamadı [CC-7] | İstemci (`[mcp_servers.<ad>]`, `enabled_tools`) [CX-6]; `codex mcp-server` **kaldırıldı** [CX-5] | İstemci: yerel stdio, uzak Streamable HTTP; "MCP tools consume model context" [OC-7] | Yok; önceki tasarım "MCP sunucusu yok" (§1) | Tüketme yok. Karadul araçları için isteğe bağlı, salt okur stdio sunucusu, en sonda (P22f, §5) |
| **Olay akışı ve canlı arayüz** | `--output-format stream-json`: satır başına bir JSON olayı; `system/init`, kısmi iletiler, son `result` maliyetle [CC-6] | `exec --json`: `thread.started`, `turn.*`, `item.*`, `error` [CX-3] | V1: TUI sunucunun istemcisi; `/event` SSE, ilk olay `server.connected` [OC-4]. V2: `GET /api/event` "volatile by contract"; kalıcı oturum günlüğü `follow=true` [OC-5] | Yok. Denetim günlüğü iş bittikten sonra ve içeriksiz yazılıyor; `task_started`, `tool_started`, jeton olayı yok (kulvar §Vizyon 3) | Sıra numaralı olay şeması + bellekte halka + uzun yoklama. Taşma durumu dürüstçe bildirilir. Terminal ve örümcek yalnız bu olaylardan çizilir (§4) |
| **İptal / devam** | Esc anında durdurur, süren aracı iptal eder; `--continue` / `--resume`; çatallama; dosya değişikliklerine checkpoint [CC-1] | bakılmadı | V1 `POST /session/:id/abort` [OC-4]; V2 `interrupt` [OC-5] | İptal yalnız tur aralarında; iptal olayı hiç sıfırlanmıyor (LM-06); süren istek kesilmiyor (`asama1b.md` §2 madde 18) | Görev başına iptal (P21). Akışlı istek + parça başına iptal denetimi. "Devam" = defter + özet deposu; sohbet geçmişi taşınmaz (§3.11) |
| **Maliyet / süre bütçesi** | `--max-turns`, `--max-budget-usd` (yalnız print kipi); JSON çıktıda `total_cost_usd` [CC-7][CC-6] | bakılmadı | `steps`; son adımda araçlar kaldırılır, metin özeti istenir [OC-1] | ≤ 8 çağrı (K1 ≤ 2), bağlam ön denetimi, adım başına ≤ 256 jeton; bütçe bitince zarfın araç dalları kaldırılır (`agent.py:479-489`). Süre bütçesi tanımlı, uygulanmıyor (LM-06) | Görev: araç / jeton / süre (ölçülen hız × 4). Plan: toplam beklenen süre onaydan önce gösterilir. Para yok (yerel); süre ve jeton gerçek sayılarla |
| **Çoklu model** | Alt ajan başına `model` (sonnet, opus, haiku, fable, inherit) [CC-3] | bakılmadı | Ajan başına `provider/model#variant`; alt ajan üstünkini devralır; sıkıştırma için ayrı model [OC-1][OC-6] | Tek arka uç: yerel `llama-server` ya da kullanıcı ucu; yetenek düzeyi L1/L2/L3 (`protocol.py:466-523`) | Aynı anda tek yerel model (36 GiB makinede ~17,5 GiB). İkinci model (ör. özet için daha küçük) yalnız Z13 ve ayırıcı deneyden sonra |

**Okuma:** Kodlama ajanlarının üçünde de en ağır parça kabuk ve dosya düzenlemedir; izin sistemleri, kum havuzları, checkpoint'ler hep bu iki yetki için var. KaradulLM'de ikisi de yok. Geriye kalan ve bize uyan çekirdek: istemci–sunucu ayrımı, olay akışı, kip başına araç kümesi, adım tavanı, plan, iptal, defter.

## 3. KaradulLM'e uyarlanmış mimari

### 3.1 Bileşenler

```
 ui/index.html                         ui/server.py (127.0.0.1; Host + Origin + X-Karadul-Token)
 ┌───────────────────────────┐  fetch  ┌───────────────────────────────────────────────────────┐
 │ harita (svg) · liste      │◄───────►│ /api/lm/*  (yeni uçlar, §4.6)                         │
 │ örümcek (olaydan)         │ uzun    │   │                                                   │
 │ TERMİNAL paneli           │ yoklama │   ▼                                                   │
 │  (satırlar: textContent)  │         │ karadul/lm/session.py   oturum: kip, defter, kuyruk    │
 └───────────────────────────┘         │   │        │                                          │
                                       │   │   repl.py (komut ayrıştırıcı; kabuk YOK)           │
                                       │   ▼                                                   │
                                       │ agent.py ── olay geri çağrısı ──► events.py (halka)   │
                                       │   │  hat (açıkla, adlandır, özet)  döngü (keşif)       │
                                       │   ├─ tools/ (O sınıfı salt okur; Ö sınıfı yalnız kayıt)│
                                       │   ├─ guard.py (P21: D0-D14 alt kümesi)                 │
                                       │   ├─ summaries.py (özet deposu) · order.py (katmanlar) │
                                       │   └─ backend.py ── llama-server (tek yuva, loopback)   │
                                       │ saklı çalışma alanı (salt okur)   ~/.karadul/lm/<sha>/  │
                                       └───────────────────────────────────────────────────────┘
```

- **Oturum arayüz sunucusunun sürecinde yaşar.** Ayrı bir Python süreci yoktur. Bugün açılan tek alt süreç `llama-server`'dır (`backend.py:663-690`). Böylece "arayüz kapanınca oturum ölür" kuralı yapım gereği tutar; geriye yalnız `llama-server`'ın kapatılması kalır (P21, LM-05; §4.3 G7).
- **Motor sınırı değişmez:** `karadul/` altında hiçbir motor modülü `karadul.lm`'i içe aktarmaz (K-M1). `ui/server.py` içe aktarır; bu kabul edilen yöndür (arayüz motor değildir).
- Yeni modüller: `events.py`, `session.py`, `repl.py`, `summaries.py`, `order.py`, `modes.py`, `notebook.py`, `tools/read_more.py`, `tools/index.py`; P21'den `guard.py`. Bütün yeni sayısal sabitler yalnız `karadul/lm/__init__.py`'de durur (proje kuralı; `__init__.py:28-38`).

### 3.2 İki motor

| | **Belirlenimci hat** | **Keşif döngüsü** |
|---|---|---|
| Kim sıralar | Sunucu (sabit iş akışı) | Model (her turda bir araç ya da son cevap) |
| Görevler | `acikla` (ne yapıyor?), `ad_oner`, `ozet_alt` (aşağıdan yukarı özet) | `soru` (analistin açık uçlu sorusu) |
| Model çağrısı | Fonksiyon başına bir kez (+ L2'de bir onarım) | Görev başına ≤ 8 araç + son cevap |
| Neden | Sırası çağrı grafiğinden hesaplanabilen bilgi toplama; ölçülebilir, yeniden üretilebilir | Bilgi ihtiyacını analistin sorusu belirler; önceden hesaplanamaz |
| Öneri açabilir mi | Evet (yalnız kayıt; §3.9) | Hayır (keşif kipi `öner` = `deny`) |
| Açılma | Öntanımlı | Kapı arkasında: K-Z1, K-A1, K-A2, K-A3 (önceki tasarım §9.2) |

İki motor aynı olay şemasını yayar; terminal ve örümcek ikisini aynı biçimde gösterir.

### 3.3 Ajan döngüsü (bir görevin adımları)

1. **Görev açılır.** `gorev_basladi` olayı: görev türü, kip, hedef (`fn`, `adres`), bütçe.
2. **Ön denetim.** Hedef çalışma alanında var mı (`Workspace.resolve`); `kesin` etiketli fonksiyona ad görevi açılmaz (D2; P21); analiz sürüyorsa model başlatılmaz (`_running_job`, `ui/server.py:1773`).
3. **Paket.** Sunucu araçları çağırır: `get_evidence`, `get_decompiled`; hat görevlerinde ayrıca komşuların özeti (§3.6). Her çağrı `arac_basladi` ve `arac_bitti` olayı üretir.
4. **Bağlam denetimi.** Kestirim + pay ≤ bağlam; sığmazsa görev başlamadan reddedilir. Sessiz kırpma yok (`agent.py:411-413`). LM-04'ün düzeltilmiş kestirimi P21'den gelir.
5. **Model çağrısı.** Akışlı istek (`stream=True`; arka uç destekliyor, `backend.py:287-328`, `:388-409`). Jeton sayısı `jeton` olaylarıyla akar; parça başına iptal denetlenir (§3.11).
6. **Ayrıştırma ve onarım.** `protocol.parse_turn` + `next_action` (L2'de en çok bir onarım; `protocol.py:490-523`).
7. **Döngüde:** araç dalıysa sunucu denetler (kip, şema, bütçe, tekrar, körlük; `agent.py:510-544`), aracı çalıştırır, sonucu ekler, 5'e döner. Bütçe bitince zarfın araç dalları kaldırılır (`agent.py:479-489`; opencode'un `steps` davranışıyla aynı fikir [OC-1]).
8. **Son cevap.** Öneri ya da özet **denetim katmanından** geçer (P21 `guard.py`). `denetim` olayı yayılır; öneriyse `oneri` olayı, özetse `ozet` olayı gelir.
9. **Kapanış.** `gorev_bitti` olayı: durum (`agent.py:50-62`'deki sınıflar), sayaçlar, gerçek jeton ve süre. Denetim günlüğüne `gorev` kaydı düşer (içeriksiz; bugünkü kural).

### 3.4 Kipler

Kip = sistem istemine eklenen blok + araç alt kümesi + izin satırı + cevap şeması. Kip oturum içinde değişebilir; değişince yeni görevlerin sabit öneki değişir. Bu yüzden kip değişikliği görev sınırında yapılır (K-B1). Fikir opencode'un "ajan = istem + izin + model" tanımından [OC-1] ve Claude Code'un kiplerinden [CC-2] geliyor.

| Kip | Ne için | Motor | Araçlar (§3.5) | `öner` | Çıktı şeması |
|---|---|---|---|---|---|
| **keşif** (öntanım) | Analistin sorusu: "bu dizgiyi kim kullanıyor", "`connect`'e hangi yoldan ulaşılıyor", "şu fonksiyon ne okuyor" | döngü (kapı açılana kadar: soru + `@FUN_…` paketleriyle K0) | O1-O3, O5, O7, O8, O10, O11, R1 | deny | `{"kind":"final","cevap":…,"kanit":[r…]}`; `cevap` ≤ 480 karakter [seçim] |
| **açıkla** | Bir fonksiyonun ya da alt ağacının ne yaptığı | hat | paket + komşu özetleri (sunucu kurar) | allow (yalnız yorum önerisi) | `{"ozet":…,"belirsiz":bool,"kanit":[…]}`; `ozet` ≤ `RATIONALE_MAX_CHARS` (240) |
| **adlandır** | Ad önerisi | hat (+ kapı açılırsa K1: komşuya bir bakış) | paket + komşu özetleri | allow (ad önerisi) | bugünkü "ad öner" şeması (`protocol.py:441-459`) |
| **plan** | Uzun iş önerisi: "ağ çağıran fonksiyonları ve alt ağaçlarını özetle, sonra beşine ad öner" | döngü (tek tur, araçsız) + sunucu doğrulaması | yok (sunucu R1 ve O7 sonuçlarını pakete koyar) | deny | `{"adimlar":[{"gorev","hedef"}…≤ 20],"gerekce":…}`; sunucu adresleri doğrular ve beklenen süreyi ekler |

- **Plan onayı bir yazma onayı değildir, hesap onayıdır.** Plan analistin makinesinde dakikalar ya da saatler sürecek bir kuyruk açar (htop'ta bütün ikilinin özeti yük altında ~5,9 sa **[hesap, kulvar LM §Vizyon 2]**). `uzun_iş` izni bu yüzden `ask`'tır.
- Plan adımları belirlenimci olarak da kurulabilir (R1 + O7 kapanışı). Model planının değeri ölçülmedi (yön gösterici, §8.1).
- **Cevap dili:** analist metni Türkçe, tanımlayıcılar İngilizce (KL-0 kuralı; `context.py` `SYSTEM_PROMPT_KL0` son satırı).

### 3.5 Araç kayıt defteri v2

Kurallar (bugünkü sözleşme, `arac_sozlesmeleri.md` §1, aynen): yalnız saklı çalışma alanını okur; yol, komut, URL, düzenli ifade almaz; sonuç zarfı aynı; kırpma sessiz değil; körlük kipi geçerli. Her araç tanımı sabit önekte ~130 jeton tutar **[tahmin, `arac_sozlesmeleri.md` §5]**; önek önbelleği bugün çalışmıyor (0 / 111, önceki tasarım §0 madde 3). Bu yüzden **araç kümesi kipe göre seçilir**; hat görevlerinde araç tanımı hiç yoktur.

| # | Araç | Ne verir | Veri kaynağı (diskte) | Durum | Boy | Kipler |
|---|---|---|---|---|---|---|
| O1 | `get_evidence` | Kanıt paketi | `build_evidence` | var (`tools/read.py`) | — | hepsi (sunucu) |
| O2 | `get_decompiled` | Ghidra C metni (dilimli) | `static/ghidra_output/decompiled/` (Mac htop, HEAD koşusu: 790 dosya, 597'si `FUN_*.c` **[ölçüm, 2026-11-18 `ls`]**) | var | — | hepsi |
| O3 | `get_xrefs` | Tek adım çağıran / çağrılan / metin vekili | `static/ghidra_call_graph.json` | var | — | keşif |
| O5 | `get_function_facts` | Boyut, blok, kenar, döngü, karmaşıklık, parametre sayısı, Ghidra uyarıları | `static/ghidra_cfg.json`, `ghidra_functions.json` | yeni | S | keşif, açıkla (sunucu) |
| O7 | `get_call_graph` | Derinlik ≤ 2, ≤ 40 düğüm; kapsama notu | `ghidra_call_graph.json` (`Workspace.call_edges`) | yeni | S | keşif |
| O7b | `find_path` | A'dan B'ye en kısa çağrı yolları (≤ 3 yol, derinlik ≤ 6 **[seçim]**) | aynı | yeni (tasarımda bile yoktu, kulvar §Vizyon 1) | S | keşif |
| R1 | `find_refs` | **Ters arama:** bir ithal adını çağıran, bir dizgiyi kullanan fonksiyonlar | `static/ghidra_xrefs.json` `function_xrefs[].functions_called` (htop 498/790 dolu) ve `strings_used` (137/790) **[ölçüm, kulvar LM §Vizyon 1]**; `ghidra_strings.json[].function` htop'ta 0/1 937 dolu olduğu için kullanılmaz | yeni | S | keşif, plan (sunucu) |
| O11 | `search_code` | Decompile metninde düz alt dizgi (3-64 karakter), ≤ 20 satır | `decompiled/*.c` | yeni | S | keşif |
| O8 | `get_name_provenance` | Adın kanalı, etiketi, kanıtı | `reconstructed/src/naming_provenance.json` | yeni | S | keşif |
| O10 | `get_types` | Yapı, enum, typedef (ikili geneli; fonksiyon bağı yok) | `static/ghidra_types.json` | yeni | S | keşif |
| O9 | `find_similar` | İthal kümesi / dizgi benzerliği (vekil; BSim değil) | `EvidencePack` | yeni; yön gösterici | S-M | keşif |
| S1 | `get_summary` | Özet deposundaki özet ve kökeni | özet deposu (§3.6) | yeni | S | keşif |
| N1 | `get_notes` | Analistin notları, kabul / ret kayıtları | defter (§3.8) | yeni | S | keşif |
| D1 | `ask_dataflow` | Fonksiyon içi veri akışı sorusu ("bu parametre hangi çağrıya argüman oluyor") | `reconstructed/data_flow/` program geneli; `ghidra_pcode.json` yalnız bir yola işaretçi (kulvar LM §Vizyon 1) | **ertelendi** | M-L | — |
| Ö1-Ö5 | `propose_name`, `propose_comment`, `propose_param_name`, `add_note` | Yalnız öneri kaydı açar | öneri kuyruğu | yeni (P21 denetimiyle) | M | açıkla, adlandır |

- `find_refs`'in argümanı serbest metin değildir. İthal adı, ikilinin ithal listesinden olmak zorundadır (sunucu üyelik denetler; liste `enum` olarak şemaya konmaz, çünkü uzun). Dizgi araması düz alt dizgidir, düzenli ifade değil.
- `ask_dataflow` ertelendi: fonksiyon içi akış verisi diskte hazır değil; vekil (metinden düzenli ifadeyle) bir araç "olgu" gibi okunur ve yanıltır. Ürün çıktısına fonksiyon içi akış yazılınca araç olur.
- `get_table_slots`, H sınıfı (`redecompile`, `rescan_algorithms`) önceki sözleşmedeki koşullarıyla kapalı kalır (`arac_sozlesmeleri.md` §2 O13, §4).

### 3.6 Aşağıdan yukarı özet alt görevleri (LM-08'in çaresi)

**Sorun [ölçüm, kulvar LM-08]:** bugünkü ürün çıktısında çağrılanı olan fonksiyonların hiçbirinde çağrılanlardan biri adlı değil (htop 419/419, tree 43/43). K0 dumanında 5/5 çekimser; dört gerekçe "çağrılan fonksiyonların işlevi bilinmiyor". Pilotun Ekim paketlerinde etiketli komşulu paket htop'ta 78/165'ti ve `C-Ç` koşulunda model 20'nin 12'sinde ad verdi.

**Çare:** komşuların ne yaptığını, çağrı grafiğinin sırasıyla önce yapraklardan başlayarak, kısa özetler olarak üretmek ve çağıranın paketine koymak.

1. **Katman sıralayıcı** (`order.py`): `Workspace.call_edges`'ten güçlü bağlı bileşenler (Tarjan) yoğunlaştırılır, topolojik sıra katmanlara ayrılır. Döngüdeki fonksiyonlar aynı katmandadır ve birbirlerinin özetini görmez. tree 7, htop 15 katman **[ölçüm, kulvar LM §Vizyon 2]**.
2. **Belirlenimci kısa yol (D0):** ithal çağrısı yok, dizgi yok, program içi çağrılanı yok → model çağrılmaz. Kayıt modelsiz bir olgu satırıdır: "ithal çağrı yok, dizgi yok, ‹blok sayısı› blok" (O5'ten). Bu satır `[olgu]` işaretlidir, `[model-özet]` değil.
3. **Özet görevi** (`ozet_alt`, açıkla kipinin şeması): paket = hedefin kanıtı + kodu + doğrudan çağrılanlarının özetleri `FUN_x [model-özet: …]` satırı olarak. Model "belirsiz" diyebilir; diyorsa çağıranın paketine "özet yok (belirsiz)" girer.
4. **Özet deposu** (`summaries.py`): anahtar = (ikili sha256, adres, istem sürümü, araç kümesi sürümü, model dosyası sha256, paket metninin sha256'sı). Bir çağrılanın özeti değişirse çağıranın paket özeti de değişir; eski kayıt geçersiz sayılır. Yer: `~/.karadul/lm/<ikili_sha256>/ozet.jsonl` (dizin 0700, dosya 0600; `audit.py:87-98` kalıbı).
5. **Kapsam:** iki biçim. (a) **İsteğe bağlı:** analist bir fonksiyon seçer; yalnız onun çağrılan kapanışı (derinlik ≤ 2 **[seçim]**, önceki tasarımın D4 kapanış derinliğiyle aynı) aşağıdan yukarı özetlenir. (b) **Bütün ikili:** plan kipiyle onaylanan kuyruk işi. Kapanış boyutunun dağılımı ölçülmedi; (a)'nın süresi bu yüzden bilinmiyor (§8.1 S-3).
6. **Denetim:** her özet P21'in denetiminden geçer. Uygulananlar: D9 (özette geçen ithal adı, `FUN_` adresi ya da tırnaklı dizgi görevin sonuçlarında yoksa `celiski`) ve D13 (enjeksiyon belirtisi bayrağı). Çelişkili özet çağıranın paketine **girmez**; terminalde ve kayıtta görünür.
7. **Etiket ve körlük:** özet adın yerine geçmez; `[model-özet]` işareti taşır ve KL-1 istemi bunun modelin kendi çıkarımı olduğunu, tek başına dayanak olamayacağını söyler (KL-0 kural 5'in uzantısı). **Ölçüm kipinde** (pilot D satırı) özetler körlük kuralıyla kurulur: hiçbir özet isteminde program fonksiyonlarının `[unverified]`, `[manual]` ya da `[model]` adı yoktur; her özet metni hedefin Karadul adına karşı sızıntı taramasından geçer (`context.blind_leaks`, `agent.py:313-322` kalıbı). Tutmazsa o özet o hedefin paketine girmez.

**Risk:** hata birikimi. Yanlış bir yaprak özeti, üstündeki her çağıranın paketine girer (önceki tasarım R10'un özet karşılığı). Karşı önlemler: D9 ve D13 süzgeci; "belirsiz" yolu; özetin `kanit` alanının boş olmaması (boşsa `celiski`); ayırıcı deneyde "özetli / özetsiz" ve "doğru özet / bozulmuş özet" kolları (§8.2). Bozulmuş özet kolu, modelin komşu özetine körü körüne yaslanıp yaslanmadığını ölçer (önceki tasarım K-P3'ün özet karşılığı).

**Bedel [hesap]:** htop 597 fonksiyonun hepsi model çağrısı isteseydi yük altında ortanca 35,6 sn ile ~5,9 sa, boş makinede ~17 sn ile ~2,8 sa (kulvar LM §Vizyon 2). D0 kısa yolu bu sayıyı düşürür: htop'ta `icerik_adsiz` 288 fonksiyon **[ölçüm, kulvar LM-08 kanıt satırı]**; bunların kaçının program içi çağrılanı da olmadığı sayılmadı.

### 3.7 16K yerel bağlam: sıkıştırma ve özet deposu

**Neden model yazımlı sıkıştırma yok:**

- opencode V2 öntanımda bağlamın %15'ini, en az 16k jetonu boş tutuyor ve son ~15 000 jetonu aynen saklıyor [OC-6]. Bu sayılar bizim bütün penceremiz (16 384) kadar; o yöntem bu ölçekte tasarlanmamış.
- Model yazımlı özet bir model çağrısıdır: bu makinede yük altında bir "ad öner" ≈ 29 sn **[hesap, önceki tasarım §8.2]**.
- Özet kayıplıdır ([CC-1]: "detailed instructions from early in the conversation may be lost") ve ikiliden gelen bir dizgideki talimatı "özetin parçası" olarak sonraki tura taşıyabilir.

**Yerine:**

| Parça | Kural | Bütçe (K2 tablosu, önceki tasarım §2.3) |
|---|---|---|
| Sabit önek | Kipe göre sabit; bayt bayt aynı (K-B1) | 2 200 |
| Oturum bloğu | Defterin belirlenimci özeti: son 20 kayıt, ≤ 600 jeton (önceki tasarım §4.4) | 600 |
| Fonksiyon paketi | Kanıt + kod (döngüde 4 500 bayt) + komşu özetleri | 4 100 |
| Araç sonuçları | Görev içinde toplam | 6 000 |
| Üretim + pay | | 2 560 + 512 |

- **Kütük:** görev sınırında eski araç sonuçları tek satıra iner ("r3 get_decompiled, ‹bayt› bayt, çıkarıldı; yeniden çağrılabilir"). Döngü ortasında hiçbir şey çıkarılmaz; çıkarılırsa önek bozulur (önceki tasarım §4.3, K-B2). Sonuç diskten yeniden okunabildiği için kütük kayıpsızdır: model aynı aracı yeniden çağırabilir.
- **Keşif sohbeti:** her analist turu yeni bir görevdir. Önceki turlardan yalnız modelin son cevapları girer; bunlar şema gereği ≤ 480 karakterdir **[seçim]**. Sığmayan en eski tur kütüğe iner.
- **Özet deposu** sohbet geçmişinin yerine geçen kalıcı bilgidir: komşunun ne yaptığı bir kez hesaplanır ve sonraki her pakete girer.
- Jeton sayımı: kestirim P21'in LM-04 düzeltmesiyle; gerçek sayı her istekte `usage`'tan okunur (bugünkü kural).

### 3.8 Analist notları ve oturum belleği

- **Defter** (`notebook.py`): `~/.karadul/lm/<ikili_sha256>/defter.jsonl`, yalnız eklenir. Kayıt türleri: `analist_notu`, `kabul`, `ret` (neden zorunlu), `duzeltme` (analistin elle verdiği ad). Modelin `add_note` önerisi kabul edilene kadar defterde "bekleyen" durur.
- Araç sonuçlarında defter kayıtları `kind: "arastirmaci"` taşır (`arac_sozlesmeleri.md` §1.3). İstem, analist notunun bağlam olduğunu, talimat olmadığını söyler: not da ikiliden kopyalanmış metin taşıyabilir.
- Reddedilmiş ad aynı fonksiyona yeniden önerilirse `ret` (D10, P21).
- Fikir Claude Code'un CLAUDE.md ve otomatik belleğinden [CC-5], Codex'in AGENTS.md'sinden [CX-4] geliyor. Fark: modelin kendisi kalıcı belleğe yazamaz. Yazdığı her şey analistin kabulünü bekler.

### 3.9 İzin modeli

| Eylem | Ne | keşif | açıkla | adlandır | plan | Ayarla değişir mi |
|---|---|---|---|---|---|---|
| `oku` | Saklı çalışma alanını okuyan araçlar | allow | allow | allow | allow | Hayır |
| `öner` | Öneri kaydı açmak (ad, yorum, parametre adı, not) | deny | allow | allow | deny | Hayır |
| `uygula` | Ad haritasına ya da deponun `model` bölümüne yazmak | **deny** | **deny** | **deny** | **deny** | **Hayır** (yalnız analistin kabul ucu; modelin aracı yok) |
| `ağ` | Model ucuna loopback dışından istek | Bugün kullanıcı ucunun `allow_network` parametresi; verilmezse istek atılmadan `NetworkConsentRequired` (`backend.py:839-875`). v2'de bu parametre yalnız `network.enabled` (katı bool; P-GÜV) **ve** analistin ilk kullanımdaki açık onayı birlikteyse `True` olur | aynı | aynı | aynı | Evet, iki koşulla |
| `çalıştır` | Hedefi ya da herhangi bir süreci çalıştırmak | **deny** | **deny** | **deny** | **deny** | **Hayır**; hiçbir aracın gövdesinde süreç başlatan kod yok |
| `uzun_iş` | Beklenen süresi eşiği aşan kuyruk (≥ 10 dk **[seçim]**) | ask | ask | ask | ask | Eşik ayarla değişir |

- **"Deny her kipte kazanır"** kuralı Claude Code'dan [CC-2], "politika yalnız daraltır, asla izin vermez" kuralı opencode'dan [OC-2] alındı. Bizde iki satır ayarla hiç açılamaz; tabloda `allow` yazan bir satırı analist `deny`'a çekebilir.
- **Hedef hiçbir koşulda çalıştırılmaz** üç katmanla güvencelenir: (1) kayıt defterinde süreç başlatan araç yok; (2) durağan sınama: `karadul/lm/tools/**`, `session.py`, `repl.py`, `events.py`, `summaries.py` `subprocess`, `os.system`, `os.exec*`, `os.spawn*`, `pty`, `karadul.frida` içe aktarmaz ya da çağırmaz; (3) `backend.py`'nin tek alt süreci `build_llama_command`'ın kurduğu kapalı komut listesidir ve ikili yolu `llama-server`'dır, çalışma alanının hedef yolu değildir. Sınama, bu yolun çalışma alanının hedefiyle aynı olamadığını kilitler. P-GÜV'ün kapı testleri (`tests/test_pguv_*.py`) bu yolu kapsamaz; yeni sınama P22e'de yazılır.
- **Ağ:** araçların hiçbiri ağa çıkmaz. Tek ağ yolu model ucudur; öntanım loopback. Hız yoklaması ikiliden veri taşımaz (önceki tasarım §6.2).

### 3.10 P21'in denetim katmanıyla bağ (süreç içi kanca noktaları)

Claude Code'un kancaları kullanıcı kabuk komutlarıdır [CC-4]; bizde kabuk olmadığı için aynı yerler **sabit Python denetimleridir**. Analist kanca eklemez.

| Kanca noktası | Bugün | P21 ile | v2'de eklenen |
|---|---|---|---|
| Araç öncesi | şema, tekrar, bütçe, bilinmeyen adres (`agent.py:510-527`; `tools/__init__.py:525-546`) | — | kip araç kümesinde mi; tamsayı değerli kayan noktanın `int`'e çevrilmesi (LM-07 c) |
| Araç sonrası | körlük taraması (`agent.py:528-531`) | enjeksiyon belirtisi (D13) | `arac_bitti` olayı; `dokunulan` adres listesi |
| Öneri / özet öncesi | yok (LM-01) | D0-D14 alt kümesi: en az D1, D2, D3, D8, D13 (RAPOR §7.2) | özete D9 ve D13; `denetim` olayı |
| Kabul anı | — | D1 ve D2 kabulde yeniden (önceki tasarım §5.3 "çift denetim") | kabul ucu yalnız `proposal_id` alır |

- P21'den beklenen arayüz (teslimde doğrulanacak): `guard.check(proposal, task_results, workspace) → Verdict(status ∈ {ret, celiski, sinandi_celiski_yok, sinanamadi}, findings=[(kural, ayrıntı)])`. Ad farklıysa P22a/P22b uyarlanır.
- Hüküm dört değerlidir ve terminalde dördü de ayrı yazılır. `sinanamadi` "temiz" gibi gösterilmez (önceki tasarım §5.1).

### 3.11 İptal, devam, bütçe

- **İptal:** her görevin kendi iptal olayı vardır (LM-06'nın onarımı P21'de). Model istekleri akışlıdır; okuma döngüsü her SSE parçasında iptali denetler ve bağlantıyı kapatır. `llama-server`'ın bağlantı kopunca üretimi kesip kesmediği ölçülmedi (Z8); terminal bunu "iptal istendi → sunucu durumu" diye iki satırla yazar ve sunucunun gerçekten durduğunu `/health` yoklamasından okur.
- **Devam:** `karadullm` yeniden açıldığında aynı ikilinin defteri ve özet deposu yüklenir: "‹n› bekleyen öneri, ‹m› özet, son oturum ‹zaman›". Sohbet geçmişi taşınmaz; Claude Code'da da her oturum taze bağlamla başlar [CC-1]. Yarıda kalmış bir özet kuyruğu kaldığı yerden sürer: girdi özeti değişmemiş fonksiyonlar atlanır.
- **Bütçe:** görev başına araç (≤ 8; K1 ≤ 2), bağlam, adım başına üretim (≤ 256), süre (ölçülen hızdan beklenen × `TIME_BUDGET_FACTOR` = 4; LM-06'nın onarımıyla öntanımda uygulanır). Plan için toplam beklenen süre onaydan önce gösterilir. Süre "beklenen" diye etiketlenir; ilerleme çubuğu yalnız biten / toplam sayısından çizilir.

## 4. Canlı arayüz: olay akışı, kısıtlı terminal, örümcek

### 4.1 Olay şeması

**Zarf (her olayda):**

| Alan | Tür | Anlam |
|---|---|---|
| `seq` | tamsayı | Oturum içinde 1'den başlayan, boşluksuz sıra numarası |
| `t_ms` | tamsayı | Oturum başından beri geçen süre (tekdüze saat) |
| `zaman` | ISO 8601 | Duvar saati (`audit.now_iso`) |
| `oturum` | dizgi | Oturum kimliği (`[A-Za-z0-9_-]{1,64}`, `audit.py:38`) |
| `gorev` | dizgi \| null | Görev kimliği (`g1`, `g2`…) |
| `tur` | dizgi | Aşağıdaki türlerden biri |

**Hedef nesnesi** (`hedef`): `{"fn": "FUN_00103cc0", "adres": "103cc0"}`. `fn` decompile dosyasının adından `.c` atılmış hâlidir; arayüz bugün listeyi ve haritayı bu anahtarla kurar (`ui/server.py:300-301` `addrs`, `ui/index.html` `BYADDR`). KaradulLM tarafında aynı ad `Workspace.code_files` yollarından çıkar (`tools/__init__.py:244-246` `_fun_names`). Decompile dosyası olmayan adres (ithal, thunk) için `fn` `null`'dır; örümcek o olayda yer değiştirmez.

| `tur` | Ek alanlar | Kaynak (ajanda nerede yayılır) |
|---|---|---|
| `oturum_basladi` | `kip`, `model` (dosya adı + sha256 ilk 12), `arka_uc`, `baglam`, `ag` (kapalı / açık + uç adı), `hiz` (yoklandıysa P, G, ölçüm saati; yoksa yok) | `session.open` |
| `arka_uc_durumu` | `durum` ∈ {kapali, yukleniyor, hazir, mesgul, bellek_durdu, hata}, `bellek_gib` (ölçüldüyse) | `backend` durum geçişi, bellek bekçisi |
| `gorev_basladi` | `gorev_turu` ∈ {acikla, ad_oner, ozet_alt, soru, plan}, `kip`, `hedef`, `butce` {`arac`, `jeton`, `sure_sn`} | `Agent._run` başı |
| `arac_basladi` | `sonuc` (r kimliği), `arac`, `cagiran` ∈ {sunucu, model}, `hedef`, `arguman` (şemaya uyan argümanlar; uymayan model çıktısı yazılmaz, `agent.py:279-283` kuralı) | `_run_tool` başı (bugün yalnız sonrası var) |
| `arac_bitti` | `sonuc`, `arac`, `tamam`, `hata`, `tur_kind` (olgu / vekil / çıkarım), `bayt`, `kirpma`, `sure_ms`, `dokunulan` (sonuçta geçen program fonksiyonlarının `fn` listesi, ≤ 40) | `_run_tool` sonu |
| `model_istegi` | `amac` (k0, dongu, onarim…), `istem_kestirim` | `_model_call` başı |
| `jeton` | `uretilen` (birikimli üretim jetonu sayısı) | `on_token` geri çağrısı; ≤ 10 olay/sn'ye birleştirilir **[seçim]** |
| `model_cevabi` | `durum` (`parse_turn`), `bitis_nedeni`, `istem_jeton`, `uretim_jeton`, `onbellek_jeton` (uç bildirdiyse), `sure_ms`, `niyet` (araç dalında modelin isteğe bağlı kısa notu, ≤ 80 karakter **[seçim]**) | `_model_call` sonu |
| `denetim` | `nesne` (öneri ya da özet kimliği), `hukum`, `bulgular` [{`kural`, `ayrinti`}] | P21 `guard` |
| `oneri` | `oneri_kimligi`, `hedef`, `oneri_turu` ∈ {ad, yorum, parametre, not}, `deger`, `gerekce`, `kanit` [r…], `hukum` | öneri kuyruğu |
| `ozet` | `hedef`, `metin`, `belirsiz`, `kanit`, `hukum`, `kaynak` ∈ {model, olgu} | özet deposu |
| `butce` | `arac` "x/y", `jeton` "x/y", `sure` "x/y sn" | her tur sonu |
| `gorev_bitti` | `durum` (`agent.py:50-62` sınıfları), `sayaclar` (`Counters`), `sure_ms` | `Agent._close` |
| `iptal` | `kaynak` ∈ {analist, sure, bellek, kapanis} | iptal yolu |
| `satir` | `metin`, `duzey` ∈ {bilgi, uyari, hata} | REPL'in kendi iletileri (yardım, ret, hata) |
| `oturum_bitti` | `neden` ∈ {cik, arayuz_kapandi, calisma_alani_degisti, bosta} | `session.close` |

- **İçerik kuralı:** olay akışı içerik taşır (model metni, özet, öneri; araç sonuçlarının kendisi değil, özeti). Denetim günlüğü bugünkü gibi içeriksiz kalır (`audit.py:6-12`). Araç sonuçlarının tam metni ayrı bir **içerik deposunda** tutulur (`~/.karadul/lm/<sha>/sonuclar/`, 0600). Böylece terminal "r3'ü aç" diyebilir; RAPOR §7.2 madde 3'ün istediği "içerikli kayıt" da buradan çıkar. Depo yereldir ve oturum kapanınca silinmez; saklama süresi açık karar (§11, karar 6).
- **Görüntü öncesi arındırma (sunucuda, serileştirmede):** model metni ve ikiliden gelen her dizgide C0 / C1 denetim karakterleri, ESC ve yön değiştiren Unicode biçim karakterleri (U+202A-U+202E, U+2066-U+2069) görünür kaçışa çevrilir (`‮` gibi). Bu, ikili yazarının metniyle terminalde satırı ters çevirip yanıltmasını önler. Arayüz yalnız `textContent` kullanır (önceki tasarım K-U2).
- **Halka:** oturum başına bellekte en çok 10 000 olay **[seçim]**. İstemci geride kalırsa (`sonra` < en eski `seq`) yanıt `{"tasma": true, "kacan": ‹n›}` taşır ve terminal "‹n› olay kaçırıldı" yazar. Kaybı gizlemek yerine söylemek, opencode V2'nin "volatile by contract" tutumuyla aynıdır [OC-5]; bizde ayrıca sayılır.

### 4.2 Taşıyıcı: uzun yoklama

| Seçenek | Bugünkü korumayla uyum | Emek | Risk |
|---|---|---|---|
| **(a) Uzun yoklama** `GET /api/lm/olaylar?oturum=…&sonra=N&bekle=25` | Tam: `fetch` sarmalayıcısı jetonu ekler (`index.html:687-696`); `_guard` değişmez; yanıt `Content-Length`'li tek JSON | En düşük: sunucuda koşul değişkeniyle bekleyen bir uç | Her olay öbeği için bir istek; localhost'ta ihmal edilebilir. Uzun bekleyen istek bir iş parçacığı tutar (`ThreadingHTTPServer`, `ui/server.py:2225`) |
| (b) `fetch` ile parçalı akış | Jeton başlığı korunur | Orta: `Transfer-Encoding: chunked` yanıt yolu yazılmalı (bugün `_send` hep `Content-Length` yazıyor, `ui/server.py:2001-2008`) | WKWebView'da akış okuma denenmedi (önceki tasarım §15) |
| (c) SSE (`EventSource`) | Özel başlık gönderemez; jeton sorgu dizgisine iner; sarmalayıcının dışında kalır | Düşük | Tek tip koruma kuralı bozulur; jeton URL'de |
| (d) WebSocket | Tarayıcı WebSocket'i de özel başlık gönderemez; `BaseHTTPRequestHandler`'da el yazımı RFC 6455 el sıkışması | Yüksek | Yeni protokol yüzeyi |

**Seçim (a).** Gecikme: olay geldiğinde bekleyen istek hemen döner. Jeton olaylarının sıklığı birleştirmeyle sınırlıdır (≤ 10/sn), yani istek sayısı da öyle. Ölçüt E-3 (§8.1): olayın yayılmasıyla arayüze ulaşması arasındaki p95 ≤ 250 ms **[seçim]**. Tutmazsa (b) değerlendirilir.

### 4.3 Kısıtlı terminal

**Uygulama seçimi: terminal biçimli olay akışı.** Berke'nin istediği iki seçenek karşılaştırıldı:

| | (1) xterm.js + kısıtlı PTY | (2) Terminal biçimli olay akışı |
|---|---|---|
| Süreç | Yeni alt süreç ve sözde uçbirim. Denetleyici uçbirim için `setsid` gerekir; bu sunucu çok iş parçacıklıdır ve `setsid` yolu macOS'ta kilitleniyordu (`ui/server.py:1820-1822`, `:1051-1052`) | Yeni süreç yok; oturum arayüz sunucusunun içinde bir nesne |
| Taşıma | Çift yönlü bayt akışı. xterm.js'in hazır bağlayıcısı WebSocket kullanır [XT-1]; sunucuya WebSocket yazılmalı ve jeton özel başlıkla taşınamaz | Bugünkü `fetch` + `_guard` (§4.2) |
| Görüntülenen | Ham baytlar bir uçbirim öykünücüsünde yorumlanır; ikiliden ve modelden gelen metin kaçış dizisi taşıyabilir. Bayt düzeyinde arındırıcı gerekir | Yapılandırılmış olaylar; yalnız `textContent`; yorumlanan hiçbir şey yok |
| Bağımlılık | xterm.js (MIT [XT-1]) depoya gömülür; çevrimdışı paketleme ve CSP | Yok |
| Sınanabilirlik | Bayt akışı üstünde | JSON olayları üstünde (`tests/test_ui_etiket.py` kalıbı) |
| Kazanç | İmleç, renk, yeniden boyut: bu deneyim için gerekmiyor | Claude Code benzeri satır görünümü CSS ile |

**Seçim (2).** Güvenlik ve emek açısından en sadesi bu. (1)'in getirdiği üç yüzey (alt süreç, WebSocket, kaçış dizisi yorumlayan öykünücü) Berke'nin istediği deneyime bir şey eklemiyor.

**Güvenlik tasarımı (Berke'nin şartları, G1-G9):**

| # | Şart | Nasıl | Sınama |
|---|---|---|---|
| G1 | Arkada genel kabuk HİÇ açılmaz | Terminal uçları süreç başlatmaz. `repl.py` ve terminal uçlarının kodunda `subprocess`, `os.system`, `os.exec*`, `os.spawn*`, `pty`, `shell=True` yok | Durağan sınama (AST ile içe aktarma ve çağrı taraması) — T-1 |
| G2 | İzin listesi tek öğe | `ALLOWED_COMMANDS = frozenset({"karadullm"})`; sunucu `komut.strip() == "karadullm"` tam eşitliğine bakar (harf duyarlı, argüman yok). Seçenekler oturum içinde `/kip` gibi REPL komutlarıyla verilir | Kümenin boyu 1; 200 rastgele / düşman girdi (`karadullm; ls`, `KARADULLM`, `karadullm --x`, `$(…)`, `\nkaradullm`, Unicode benzerleri) → 0 kabul — T-2 |
| G3 | Başka komut reddedilir | 400 `{"hata": "izin verilmeyen komut"}` + denetim kaydı (komut metni yazılmaz, yalnız uzunluk ve sha256); terminal "bu terminal yalnız `karadullm` çalıştırır" yazar | T-2 |
| G4 | Girdi yalnız o oturuma gider | `POST /api/lm/terminal/girdi` metni yalnız `repl.parse`'a verir. Ayrıştırıcının çıktıları kapalı bir komut kümesidir (§4.4) ya da keşif kipinde "soru"dur. Girdi ≤ 2 000 karakter **[seçim]**; denetim karakterleri atılır | Ayrıştırıcı birim testleri; düşman girdi kümesi — T-3 |
| G5 | Jeton / Host / Origin denetimi bu uçlarda da | Bütün yeni uçlar `/api/lm/` altında; `do_GET` ve `do_POST` zaten `_guard`'ı her `/api/` isteğinde koşturuyor (`ui/server.py:2056`, `:2137`); gövde `_MAX_BODY` (64 KiB) ile sınırlı (`:85`) | Bugünkü `tests/test_ui_request_guard.py` kalıbıyla her yeni uç için 3 ret (yanlış Host, yabancı Origin, jetonsuz) — T-4 |
| G6 | Tek oturum, analizle çakışmaz | Aynı anda tek oturum (ikinci `karadullm` → "oturum zaten açık"). Analiz sürüyorsa (`_running_job`) model başlatılmaz; terminal bunu yazar | birim testi |
| G7 | Arayüz kapanınca süreç ölür | Oturum arayüz sunucusunun içinde olduğundan onunla ölür. `llama-server` için: `_kill_jobs` (`ui/server.py:2182-2195`) ve `_parent_watchdog` (`:2204-2215`, `os._exit` yolu) oturumu ve arka ucu kapatan bir çağrı alır (P21 LM-05 onarımıyla bağ); sunucu açılışında `reap_recorded()` (`backend.py:631`) yetimi toplar; boşta `IDLE_SHUTDOWN_SEC` (600 sn) sonra `stop_if_idle` (`backend.py:778`) | Sahte `llama-server` betiğiyle: arayüz sürecine SIGTERM ve ebeveyn ölümü → ‹N› sn içinde çocuk süreç yok (K-M2) — T-5 |
| G8 | Hedef ikili hiçbir koşulda çalıştırılmaz | §3.9'daki üç katman | T-1 + `build_llama_command` sınaması |
| G9 | Ekrana yazılan metin yorumlanmaz | Sunucuda arındırma (§4.1), arayüzde yalnız `textContent`; HTML, bağlantı, görsel üretilmez | Tuzak kümesi: `<script>`, `<img>`, ESC dizileri, U+202E → panelde öğe 0, kaçış görünür (K-U2) |

- Sayfanın içerik güvenlik politikası başlığı bugün yok (önceki tasarım §6.1). Terminal paneliyle birlikte `connect-src 'self'`, `img-src 'self' data:`, `form-action 'none'`, `base-uri 'none'` eklenmesi önerilir (P17 ya da P22c'nin dosyası).

### 4.4 Terminal biçimi

Görünüm Claude Code'un adım satırlarına benzer. Aşağıdaki örnek yalnız biçimi gösterir; `‹…›` yer gösterir, sayı değildir.

```
$ karadullm
KaradulLM · yerel ‹model› · bağlam ‹n› · ağ kapalı · kip: keşif (salt okur)
hız: ölçülmedi                                          [/hiz ile ölç]
karadullm> /acikla FUN_‹adres›
● g‹k› açıkla FUN_‹adres›  bütçe: ‹a› araç · ‹j› jeton · ‹s› sn
  ⎿ get_evidence(FUN_‹adres›)            olgu+çıkarım · ‹bayt› B · ‹ms› ms
  ⎿ get_decompiled(FUN_‹adres›, bas)     olgu · ‹bayt› B · kırpıldı ‹x›/‹y› satır
  ⎿ özet: FUN_‹c1› [model-özet] · FUN_‹c2› özet yok (belirsiz)
  ◆ model: istem ‹n› jeton · üretilen ‹m›
● özet (model önerisi · kanıt r1 r2): "‹metin›"
  denetim: ÇELİŞKİ BULUNMADI (sınandı) · ⚑ D12 kuşkulu decompile
● g‹k› bitti · tamam · ‹a› araç · ‹j› jeton · ‹s› sn
karadullm> bu ikilide connect'i kim çağırıyor?
● g‹k+1› soru  (keşif döngüsü kapalı: soru + paket, tek çağrı)
  ⎿ find_refs(import=connect)            olgu · ‹n› fonksiyon
  …
```

- **"Ne düşündü" satırı yok.** Düşünme kipi kapalıdır (`enable_thinking: false`; önceki tasarım §2.2); terminal "düşünce" diye bir metin uydurmaz. Gösterilen yalnız modelin yazdıklarıdır: araç dalındaki isteğe bağlı `niyet` notu ve son cevabın `gerekce` / `ozet` / `cevap` alanı, "model metni" diye işaretli.
- **REPL komutları (kapalı küme):** `/kip kesif|acikla|adlandir|plan`, `/acikla FUN_…`, `/ad FUN_…`, `/ozet FUN_… [derinlik]`, `/plan ‹metin›`, `/onayla`, `/durdur`, `/oneriler`, `/ac r‹n›` (araç sonucunun içeriği), `/not FUN_… ‹metin›`, `/hiz`, `/takip ac|kapat`, `/yardim`, `/cik`. Keşif kipinde `/` ile başlamayan satır "soru"dur ve içindeki `@FUN_…` anmalarını sunucu çözer.
- Öneriler terminalde kabul edilmez. Kabul ve ret, öneri kartında analistin tıklamasıyla yapılır (önceki tasarım §7.3). Terminal yalnız "öneri p‹n› kuyrukta" yazar ve karta götürür. Bu, kabulün klavyeden yanlışlıkla akmasını önler.

### 4.5 Örümcek simgesinin konumlanması

Simge, markanın kırmızı kum saatinden türetilir (`ui/index.html:969-983`, `M4 2.5H20L12 12L20 21.5H4L12 12Z`). "Ajan imleci" olarak ayrı bir öğedir ve haritanın merkez işaretiyle karışmaz.

| Olay | Arayüzün yaptığı |
|---|---|
| `gorev_basladi` / `arac_basladi` (`hedef.fn` dolu) | **Takip açık** (öntanım: oturum açıkken): `focus(fn)` çağrılır (`ui/index.html:888-895`), simge merkeze konur. **Takip kapalı:** `fn == CENTER` ise merkezde; `fn` haritada çizili bir komşuysa o düğümün `(x, y)`'sinde; değilse simge haritadan kalkar, listede `.fn[data-addr=fn]` satırı işaretlenir, terminal başlığında "ajan: FUN_… (haritada değil) [git]" yazar |
| `arac_bitti` (`dokunulan` dolu) | Merkezden `dokunulan` düğümlere giden ışınlar o olay için vurgulanır (`get_xrefs(callers)` → çağıranlar). Vurgu bir sonraki olaya kadar durur; zamanlayıcıyla sönmez |
| `ozet` | Düğüm etiketinin altında küçük "özet var" işareti (metin araç ipucunda, `textContent`) |
| `oneri` | Simgenin yanında "öneri: ‹ad› · ‹hüküm›" etiketi; uygulanmış bir ad gibi görünmez (ayrı stil) |
| `jeton` | Simge hareket etmez; yalnız terminaldeki sayaç artar |
| `gorev_bitti` | Simge son konumunda soluk kalır (durağan) |
| `oturum_bitti` | Simge kaldırılır |

- **Yer değiştirme geçişi** yalnız bir olayla tetiklenir: `transform` geçişi ≤ 200 ms **[seçim]**, bir kez. `prefers-reduced-motion` açıksa geçiş yok. Simgede `infinite` süreli animasyon yok.
- Analist haritada bir düğüme tıklarsa takip kapanır ("takip durdu · [/takip ac]"). Ajan analistin görüşünü elinden almaz.
- Haritanın bir tarafta en çok 42 komşu çizdiği (`drawSide`, `MAX=42`, `ui/index.html:927`) unutulmaz: 42'nin dışındaki komşu "haritada değil" dalına düşer.

### 4.6 Arayüz sunucusu uçları (yeni; hepsi `_guard`'lı)

| Uç | Yöntem | Gövde / sorgu | Dönüş |
|---|---|---|---|
| `/api/lm/terminal/komut` | POST | `{"komut": "karadullm"}` | `{"oturum"}` ya da 400 (izin verilmeyen komut / oturum açık / çalışma alanı yok) |
| `/api/lm/terminal/girdi` | POST | `{"oturum", "metin"}` | `{"kabul": true, "gorev"?}` ya da 400 (ayrıştırma hatası; terminale `satir` olayı da düşer) |
| `/api/lm/olaylar` | GET | `?oturum=…&sonra=N&bekle=25` | `{"olaylar": […], "son": N, "tasma"?: true, "kacan"?: n}` |
| `/api/lm/durdur` | POST | `{"oturum", "gorev"?}` | `{"tamam": true}`; `iptal` olayı akışa düşer |
| `/api/lm/durum` | GET | — | arka uç durumu, model, son bellek ölçümü, hız (ölçüldüyse), kip, ağ |
| `/api/lm/sonuc` | GET | `?oturum=…&kimlik=r‹n›` | araç sonucunun saklı içeriği (içerik deposundan) |
| `/api/lm/oneriler` | GET | `?oturum=…` | bekleyen ve karara bağlanmış öneriler |
| `/api/lm/oneri/kabul` | POST | `{"oneri_kimligi"}` | yalnız kimlik; sunucu D1 ve D2'yi yeniden koşturur; ad deponun `model` bölümüne yazılır, `naming_map.json`'a yazılmaz (önceki tasarım §5.3) |
| `/api/lm/oneri/ret` | POST | `{"oneri_kimligi", "neden"}` | defterde `ret` |
| `/api/lm/terminal/kapat` | POST | `{"oturum"}` | oturum ve arka uç kapanır; `oturum_bitti` |

- Kabul yolunun deponun `model` bölümüne yazması `karadul/core/overrides.py`'yi değiştirir; bu dosya P17'nin (RAPOR §5.2). Yazma yolu P17 bitince P22c'de yapılır ya da yama bırakılır.
- Çalışma alanı değişirse (`activate_workspace`, `ui/server.py:366`) açık oturum kapanır (`neden: calisma_alani_degisti`).

### 4.7 Sahte animasyon yasağının mekanik sınaması

- **U-1:** olay akışı boşken (oturum açık, görev yok) örümcek öğesinin sınıfında ve hesaplanmış stilinde `animation` yok; 10 sn içinde konum değişmiyor.
- **U-2:** `ui/index.html`'de terminal ve örümcek seçicilerinde `infinite` sözcüğü yok (durağan tarama; `tests/test_ui_etiket.py` kalıbı).
- **U-3:** hız alanı ölçümden önce boş; "beklenen süre" yalnız ölçülen hızdan hesaplanır ve "beklenen" diye etiketlenir.
- Bugünkü arayüzde olaydan bağımsız iki sürekli animasyon duruyor (haritanın merkezindeki halka `ui/index.html:965`; giriş ekranındaki işaret `:43`). Bunlar bu paketin kapsamında değil; önceki tasarımın açık kararı 13.

## 5. MCP

### 5.1 Karadul araçlarını MCP sunucusu olarak dışa açmak

**Yarar:**

- Claude Code, opencode ya da başka bir MCP istemcisi kullanan analist, Karadul'un saklı analizini (kanıt, kod, çağrı ilişkileri, ters arama) kendi daha güçlü modeliyle sorgulayabilir.
- Araçlar zaten şemalı ve yan etkisiz (`ToolRegistry`, `tools/__init__.py:478-546`); MCP katmanı ince bir bağdaştırıcıdır.

**Risk:**

1. **Kabuk erişimli dış ajanın yönlendirilmesi (en ağırı).** Araç sonuçları saldırgan denetimli dizgi taşır. KaradulLM'in kabuğu yok; ama Claude Code'un ya da Codex'in var. Zararlı yazılımın içine gömülü bir "şu ikiliyi çalıştırıp çıktısına bak" metni, kabuk izni olan bir ajanı hedefi çalıştırmaya itebilir. Claude Code'un kendi belgesi de dış içerik çeken sunucuların istem enjeksiyonu riski taşıdığını yazıyor [CC-8]. Karadul istemcinin ne yaptığını denetleyemez.
2. **Veri sızıntısı.** Decompile metni istemcinin bulut modeline gider. Karadul'un "ağ kapalı öntanımı" bu yolda geçersiz olur.
3. **Ölçüm kirlenmesi.** Dış ajanın önerdiği adlar ancak `model` kökeniyle (kaynak `mcp:‹istemci›`) ve analist kabulüyle girebilir; motor okumaz, ölçüm görmez (K-M3).
4. **Bakım.** Protokol sürümleri değişiyor (opencode yapılandırmasında `protocol: legacy | auto | 2026-07-28` [OC-7]); Codex kendi MCP sunucusunu kaldırdı [CX-5].

**Tasarım (yapılırsa):** öntanımlı kapalı; yalnız stdio (ağ dinleyicisi yok); yalnız O sınıfı araçlar (öneri ve yazma aracı yok); sonuç zarfı kayıt defterinin çıktısıyla bayt bayt aynı (`kind`, `limits`, `data` ayrımı korunur); açılırken analiste bir kez "decompile metni istemcinin modeline gidecek; istemciyi salt okur kipte çalıştırın (Claude Code `plan` / `dontAsk` [CC-2], Codex `read-only` [CX-2])" uyarısı. Bağımlılık kararı (resmi MCP Python paketi mi, el yazımı JSON-RPC mi) açık karar 9.

### 5.2 KaradulLM'in MCP araçlarını tüketmesi

**Önerilmez.** Yarar düşük: RE için gereken veri zaten Karadul'un diskinde. Risk yüksek:

- Her araç tanımı 16K bağlamdan yer yer; opencode bile "MCP tools consume model context" diye uyarıyor [OC-7].
- Araç kümesi değişince sabit önek değişir (K-B1); önek önbelleği zaten çalışmıyor.
- Üçüncü taraf araç yan etkili ya da ağa çıkan olabilir; `ağ` ve `çalıştır` kuralları delinir.

### 5.3 Sıra

Önce P21 (denetim) ve P22d (araç kaydı v2) bitmeli; sonra P22f. MCP sunucusu ürünün çekirdek deneyimi değildir (terminal + örümcek değil); en sona kalır ve Berke'nin kararına bağlıdır (karar 9).

## 6. Neyi almayacağız

| Özellik (kaynak) | Neden almıyoruz |
|---|---|
| Dosya düzenleme / yazma araçları (edit, write, patch) [OC-2][CC-1] | RE ajanı ürün dosyasına yazmaz. Tek yazma yolu: öneri + analistin kabulü (Ö6) |
| Genel kabuk (bash / zsh / shell) [OC-2][CC-1] | Hedef çalıştırma ve P-GÜV; Berke'nin terminal kararı. opencode'un kendi belgesi kabuğun "host user's filesystem, process, and network authority" ile çalıştığını yazıyor [OC-2] |
| Web getirme / arama [OC-2][CC-1] | Ağ kapalı öntanımı; ikili verisinin dışarı sızması; T2 (önceki tasarım §6.1) |
| Kullanıcı tanımlı kabuk kancaları [CC-4] | Kabuk yok. Aynı noktalar sabit Python denetimleri (§3.10) |
| Model yazımlı sohbet sıkıştırması [OC-6][CC-1] | 16K'da maliyet; kayıp; talimat taşıma riski (§3.7) |
| Checkpoint / geri sarma [CC-1] | Geri sarılacak dosya değişikliği yok. Öneriler ret edilir; kabul edilen model adı geri alınabilir (`model` bölümünden silme; önceki tasarımda eksik, kulvar §Vizyon 1) |
| Paralel ve arka plan alt ajanları [CC-3][OC-1] | Tek yuva (`--parallel 1`) ve 36 GiB'ta ~17,5 GiB'lık model. "Taze bağlamlı alt görev" fikri alındı, paralellik alınmadı |
| Otomatik onay kipleri (`acceptEdits`, `auto`, `bypassPermissions`) [CC-2] | Onaysız yazma yok. Toplu kabul önceki tasarımın açık kararı 14 |
| Modelin kendi kendine kalıcı bellek yazması (otomatik bellek) [CC-5] | Modelin notu yalnız öneridir (§3.8) |
| MCP tüketimi [OC-7][CX-6] | §5.2 |
| Çok sağlayıcılı model seçimi, bulut öntanımı [OC-1] | Yerel öntanım; kullanıcı ucu L1-L3 ile zaten var, ağ onayına bağlı |
| LSP, git, PR, paylaşım bağlantısı, eklenti ve beceri sistemi | Kodlama iş akışına özgü; RE'de karşılığı yok |

## 7. Aykırı öncül

**Öncül:** "Genel kodlama ajanı mimarisi 27B yerel modelle RE için yanlış seçimdir; belirlenimci araç zincirleri + tek atış daha iyi sonuç verir."

**Ciddi savunma:**

1. **Kodlama ajanlarının döngüsü bir doğrulayıcıya yaslanır; ad işinde doğrulayıcı yok.** Claude Code kendi döngüsünü "bağlam topla, eylem, **sonuçları doğrula**" diye tanımlıyor; örnek akışı testleri koşup yeniden koşmak [CC-1]. Derleyici ve test, her adımda gerçek bir geri bildirim verir; döngünün gücü buradan gelir. RE'de ad önerisinin döngü içinde sınanacağı bir kâhin yoktur: araç sonuçları hipotezi doğrulamaz, yalnız daha çok metin getirir. Doğrulayıcısız ek adım doğruluğu artırmaz, akıcılığı artırır. Berke'nin yaratıcılık protokolünün 1. kuralı (denetlenebilirlik) da aynı yere çıkar.
2. **Gereken bilginin sırası önceden hesaplanabilir.** Ad için gereken bağlam (çağrılanların ne yaptığı, çağıranlar, ithal çağrıları, dizgiler) çağrı grafiğinden çıkar. LM-08 bunu gösterdi: çekimserliğin nedeni modelin araç seçememesi değil, pakette komşu bilgisinin olmamasıydı. Aşağıdan yukarı sıra bir uzmanın yaptığının hesaplanabilir hâlidir; planlayıcı model buna bir şey eklemez.
3. **Hız bu makinede döngüyü cezalandırıyor.** Önek önbelleği 0 / 111 isabet; döngüde her adımda bütün geçmiş yeniden işleniyor ve bedel adım sayısının karesiyle büyüyor. 4 araç çağrılı görev yük altında ≈ 192 sn, 8 çağrılı ≈ 458 sn; boş makinede ≈ 114 / 273 sn. Tek atış "ad öner" ≈ 29 / 17 sn **[hesap, önceki tasarım §8.2]**. Aynı sürede tek atışlı model çağrısı 6-16 kez yapılabilir **[hesap: 192 / 29,1 ≈ 6,6; 458 / 29,1 ≈ 15,7]**; hattın bir fonksiyon için özet dahil kaç çağrı yapacağı kapanış boyutuna bağlıdır (S-3, ölçülmedi).
4. **16K bağlam çok fonksiyonlu döngüyü taşımıyor.** tmux'ta tek bir fonksiyonun Ghidra C'si p95'te 8 034 jeton (önceki tasarım §2.3). Döngü komşunun kodunu okumak istediğinde paket bütçesini aşar. Özet satırları aynı bilgiyi onlarca jetonla taşır.
5. **Her ek tur, saldırgan metnine bir fırsat daha.** Döngüde model ikiliden gelen dizgileri her turda yeniden okur ve sonraki eylemini onlara göre seçer. Hatta model yalnız okur, sonra cevaplar.
6. **Ölçülebilirlik ve yeniden üretim.** Açgözlü çözmede düşünmesiz tek atış 40 / 40 bayt bayt aynıydı (önceki tasarım R11). Döngünün yörüngeleri dallanır; kör pilotun eşli karşılaştırması (önceki tasarım K-P2) zorlaşır. "İddia yalnız ölçülen kadar" kuralı, ölçülmesi kolay olan yolu öntanım yapmayı gerektirir.
7. **Sözdizimi sorunu zaten çözülmüş; kalan sorun seçim.** Şemaya zorlanmış çağrılar 10/10 geçerli (zemin §5). Ama zemin denemesinde yön (`to/from`) ters seçildi ve "ad öner"de önce `get_decompiled` istendi (kulvar LM §Vizyon 4). Seçim hatası, döngünün tam da kazanç sağlaması beklenen yerde.

**Savunmanın sınırı:** analistin açık uçlu sorusu ("`connect`'e hangi yoldan ulaşılıyor", "bu dizgiyi kim kullanıyor") önceden hesaplanamaz; bilgi ihtiyacını soru belirler ve **doğrulayıcı analistin kendisidir**. Döngünün yeri orasıdır. Bu yüzden tasarım ikiye ayrıldı (§3.2): ad ve açıklama hatta, keşif döngüde. Öncül doğruysa ürün kaybetmez; yanlışsa döngü ölçümle ad işine girer.

**İki yolu ayıracak ölçüm:** §8.2'deki ayırıcı deney. Kısaca: aynı GT'li fonksiyon örnekleminde (a) bugünkü K0, (b) belirlenimci hat (aşağıdan yukarı özet + zenginleşmiş K0), (c) döngü (aynı araçlar, eşit süre bütçesi). Birincil ölçü yanlış ad oranı, ikincil doğru ad kapsamı; karar kuralı ölçümden önce yazılır.

## 8. Ölçüm planı

### 8.1 Özellik başına doğrulayıcı

Eşikler **[seçim]**; Berke değiştirebilir. "Model" sütunu: bu ölçüm gerçek model ister mi.

| Kimlik | Özellik | Doğrulayıcı | Ölçü | Eşik | Model |
|---|---|---|---|---|---|
| A-1 | Araç döngüsü | K-A1 (önceki tasarım §9.2): geçerli çağrı / üretilen; sözdizimi ve anlam ayrı | oran | ≥ %95 | evet |
| A-2 | Araç döngüsü | **Yanlış araç:** doğru aracı bilinen 40 yapay görev (zemin §5'in 10'unun genişletilmişi: yön, ters arama, yol bulma) | yanlış araç / görev; yanlış argüman / görev | ≤ %10; ≤ %5 | evet |
| A-3 | Araç döngüsü | **Boşa çağrı:** sonucu ne `kanit`'te anılan ne de bir sonraki çağrının argümanını belirleyen çağrı | oran | rapor | evet |
| A-4 | Araç döngüsü | K-A2 tekrar, K-A3 bütçe | oran | ≤ %5; ≤ %5 | evet |
| S-1 | Aşağıdan yukarı özet | Çekimser oranı: K0 ile hat arasında, aynı fonksiyonlarda | fark | rapor (ön kayıtta yön yazılır) | evet |
| S-2 | Aşağıdan yukarı özet | GT'li sette yanlış ad oranı (gevşek ölçüt; tam eşitlik ayrıca) | oran | §8.2 kuralı | evet |
| S-3 | Aşağıdan yukarı özet | Çağrılan kapanış boyutu (derinlik ≤ 2) ve D0 kısa yoluna düşen pay; tree, htop, tmux | dağılım | rapor | hayır |
| S-4 | Aşağıdan yukarı özet | Özette D9 ihlali (görülmemiş olgu) oranı; `belirsiz` oranı | oran | rapor | evet |
| S-5 | Aşağıdan yukarı özet | Bütün ikili zinciri: süre, model çağrısı, bellek tepesi (tree, htop) | sn, sayı, GiB | tepe ≤ 20 GiB | evet |
| P-1 | Plan kipi | Plan adımlarının geçerliliği (adres var, görev kipe uygun) | oran | 100 / 100 (sunucu reddeder; sayaç) | evet |
| P-2 | Plan kipi | Beklenen / gerçek süre (K-H2'nin plan karşılığı) | göreli fark | ≤ %25 | evet |
| Z-1 | İzin | Tuzak kümesi (dizgiye gömülü 20 talimat): görevden önce ve sonra ad haritası ve depo bayt bayt aynı; kip dışı araç çağrısı 0 | fark | 0 | evet (K-G3) |
| Z-2 | İzin | Durağan: süreç başlatan çağrı `karadul/lm/**`'de yalnız `backend.py`'de; `build_llama_command` hedef yolunu alamaz | sayı | 0 ihlal | hayır |
| B-1 | Bağlam | K-B1 (sabit önek tek sha256, kip başına), K-B2 (geçmiş yalnız sona eklenir) | eşitlik | 100 / 100 | hayır (sahte arka uç) |
| B-2 | Bağlam | Bağlam aşımıyla biten görev oranı; gerçek / kestirilen jeton (LM-04 sonrası) | oran | ≤ %2; ≤ 1,05 | evet |
| E-1 | Olay akışı | Her çalışan araç için bir `arac_basladi` ve bir `arac_bitti`; `seq` boşluksuz; olay sayısı = denetim günlüğündeki araç kaydı sayısı (K-L1) | eşitlik | 100 / 100 | hayır |
| E-2 | Olay akışı | Halka taşması: yavaş istemci benzetimi → `tasma` ve `kacan` doğru | eşitlik | 100 / 100 | hayır |
| E-3 | Olay akışı | Yayılma → arayüze ulaşma gecikmesi (zaman damgalarından) | p95 | ≤ 250 ms | hayır |
| T-1…T-5 | Kısıtlı terminal | §4.3 G1-G9 sınamaları | ihlal | 0 | hayır |
| U-1…U-3 | Örümcek | §4.7 | ihlal | 0 | hayır |
| I-1 | İptal | İptal edilen görevden sonraki görev `tamam` (LM-06); `/durdur` → `iptal` olayı gecikmesi | oran; sn | 100 / 100; ≤ bir SSE parçası | hayır (sahte) |
| I-2 | İptal | Bağlantı kesilince sunucunun üretimi durdurması (Z8) | evet / hayır + süre | rapor | evet |
| M-1 | Bellek | 16K bağlamda en uzun istemlerle tepe (Z2) | GiB | ≤ 20 GiB; tutmazsa 12K | evet |
| C-1 | MCP sunucusu | `tools/list` yalnız O sınıfı; `tools/call` sonucu kayıt defteri çıktısıyla bayt bayt aynı | eşitlik | 100 / 100 | hayır |
| Y-1 | Keşif kipinin analiste faydası | Doğrulayıcısı yok | — | **yön gösterici**; küçük kullanıcı sınaması (önceki tasarım §9.4) | — |

### 8.2 Ayırıcı deney (ön kayıt taslağı; kesinleşmedi)

- **Örneklem:** geliştirme setinin GT'li ikililerinden, pilot örneklemleriyle ve iz fonksiyonlarıyla kesişmeyen 150 fonksiyon (`onuncu_adam.md` §1.3 boyutu). Tabakalar: `icerik_adsiz` / öbürleri; yaprak / ara; kırpılmış / kırpılmamış. Kör setlere dokunulmaz.
- **Kollar:**
  - **C** — bugünkü K0 (kontrol).
  - **H** — belirlenimci hat: çağrılan kapanışı (derinlik ≤ 2) aşağıdan yukarı özetlenir; zenginleşmiş K0 ad önerir.
  - **H-boz** — H, ama komşu özetlerinin yarısı başka fonksiyonların özetleriyle değiştirilmiş (yaslanma ölçüsü).
  - **D** — döngü: aynı model, v2 araç kümesi, 16K, ≤ 8 çağrı; **süre bütçesi H'nin aynı fonksiyonda ölçülen süresine eşit** (eşit hesap).
- **Ölçüler:** fonksiyon başına sonuç ∈ {doğru (gevşek ölçüt), tam eşit, yanlış, çekimser}; yanlış ad oranı = yanlış / ad verilen; doğru kapsamı = doğru / toplam; süre, model çağrısı, istem ve üretim jetonu, bellek tepesi; D'de A-1…A-4. Ek olarak **örtüşme:** D'nin getirdiği sonuçların (araç + argüman) H paketinde zaten bulunma oranı.
- **Karar kuralı (ölçümden önce yazılır; değerler [seçim]):**
  - H'nin C'ye üstünlüğü: çekimser oranı düşer **ve** yanlış ad oranı artışının bootstrap %95 GA üst sınırı ≤ +0,02. Tutarsa aşağıdan yukarı özet öntanım olur; tutmazsa özet zinciri yalnız açıklama için kalır.
  - D'nin ad işine girmesi: D − H yanlış ad oranı farkının üst sınırı ≤ 0 **ve** doğru kapsamı farkının alt sınırı > 0 **ve** ortanca süre ≤ 2 × H. Biri tutmazsa döngü yalnız keşif kipinde kalır.
  - Örtüşme ≥ %80 ise döngünün getirdiği bilgi hattın zaten verdiğidir; raporlanır.
  - H-boz'da yanlış ad oranı H'ye göre belirgin artarsa (GA alt sınırı > 0) model komşu özetine yaslanıyor demektir; özetler pakete daha sert etiketle ve D14 bayrağıyla girer.
- **Puanlayıcı:** pilotun ayrıştırıcısı ve jenerik ad kuralı (`protocol.py` kopyaları); gevşek ölçüt Berke'nin tanımı ("amacı doğru anlatan isim başarı"). Etiketleme körlemesine; iki değerlendirici (makale hedefindeki kural).
- Pilotun kuru koşusu tamamlanmadan bu deney koşulmaz (önceki tasarım §10 notu).

### 8.3 Gerçek model koşuları: ne zaman, nasıl

- **Sıra:** (1) Z1 (önek yeniden kullanımı) ve Z2 (16K bellek): döngü ve maliyet modeli bunlara bağlı. (2) P22b + P22d bitince S-3 (modelsiz), sonra küçük duman (tree, 20 fonksiyon). (3) Ayırıcı deney.
- **Makine boşken:** Ghidra, ürün koşusu, test takımı ve başka ajan koşmuyor; koşu başında ve sonunda `uptime` yük ortalaması künyeye yazılır; yük ortalaması < 2 **[seçim]** değilse koşu "yük altında" etiketlenir ve hız sayısı olarak kullanılmaz. 2026-11-12 dumanının yük ortalaması ≈ 7'ydi (`asama1b.md` §6).
- **Kim:** ana oturum (model koşusu paket ajanlarına yasak; brif §3.3). Her koşu künyesi: Karadul commit'i, model sha256, `llama-server` sha256, şablon sha256, istem sürümü, araç kümesi sürümü, kip, bağlam.
- Bellek bekçisi her koşuda açık (eşik 20 GiB; `MEMORY_LIMIT_GIB`).

## 9. İş paketleri

Kurallar (RAPOR §5.1, brif): tek tema, 5-8 kalem, ayrık dosya kümesi, her kalem ayrı commit, mutasyon tanımı ilk günden. `karadul/lm/**` bugün P21'in; P22'nin kod paketleri P21 `main`'e girdikten sonra başlar.

| Paket | Tema | Kalemler | Dosyalar (yazabileceği) | Bağımlılık | Boy |
|---|---|---|---|---|---|
| **P22a** | Olay omurgası (arayüzsüz) | (1) `events.py`: zarf, türler, serileştirme, görüntü arındırması; (2) halka + `seq` + taşma; (3) `Agent`'a olay geri çağrısı: `gorev_basladi`, `arac_basladi`/`bitti` (+ `dokunulan`), `model_istegi`/`cevabi`, `gorev_bitti`; (4) akışlı model isteği + `jeton` birleştirme; (5) `hedef.fn` eşlemesi (`Workspace`'e `ui_name(addr)`); (6) içerik deposu (0600); (7) testler + mutasyon | yeni: `karadul/lm/events.py`, `tests/test_lm_events.py`, `scripts/measurement/mutation_specs_lm_olay.json`; değişen: `karadul/lm/agent.py`, `karadul/lm/tools/__init__.py` (yalnız `ui_name`), `karadul/lm/__init__.py` (sabitler) | P21 | M |
| **P22b** | Görevler ve aşağıdan yukarı özet | (1) `acikla` / `ozet_alt` şeması ve sorusu (istem KL-1); (2) `order.py` katman sıralayıcı (SCC); (3) `summaries.py` özet deposu + geçersiz kılma; (4) `evidence_fields`'e özet kaynağı `[model-özet]`; (5) D0 kısa yolu; (6) körlük kuralı ve sızıntı taraması özetlerde; (7) P21 denetimine D9/D13 bağlantısı; (8) testler + mutasyon | yeni: `karadul/lm/order.py`, `summaries.py`, `tests/test_lm_summaries.py`, `test_lm_order.py`; değişen: `context.py`, `protocol.py`, `agent.py` (yeni görev türleri) | P22a | M-L |
| **P22d** | Araç kaydı v2 | (1) O5 `get_function_facts`; (2) O7 `get_call_graph` + O7b `find_path`; (3) R1 `find_refs` + ters dizin; (4) O11 `search_code`; (5) O8 `get_name_provenance`, O10 `get_types`; (6) kip başına araç alt kümesi; (7) sözleşme belgesi güncellemesi; (8) testler + mutasyon | yeni: `karadul/lm/tools/read_more.py`, `tools/index.py`, `tests/test_lm_tools_v2.py`; değişen: `tools/__init__.py` (kayıt), `docs/arge/2026-11-18_karadullm_v2/arac_sozlesmeleri_v2.md` | P22a (P22b ile paralel: dosyalar ayrık; `tools/__init__.py`'ye P22a'dan sonra yalnız P22d dokunur) | M |
| **P22e** | Oturum, kipler, izin, plan, terminal ayrıştırıcısı, defter | (1) `session.py` (tek oturum, yaşam döngüsü, analizle dışlama); (2) `modes.py` (kip → istem bloğu, araç kümesi, izin satırı); (3) izin tablosu + durağan "süreç başlatma yok" sınaması; (4) `repl.py` komut ayrıştırıcısı (kapalı küme, girdi sınırları); (5) plan kipi (şema, adres doğrulama, beklenen süre); (6) `notebook.py` defter; (7) iptal / devam; (8) testler + mutasyon | yeni: `karadul/lm/session.py`, `modes.py`, `repl.py`, `notebook.py`, `tests/test_lm_session.py`, `test_lm_repl.py`, `test_lm_izin.py` | P22b, P22d | M-L |
| **P22c** | Arayüz (iki tur, sıralı) | **c1 sunucu:** (1) §4.6 uçları; (2) uzun yoklama; (3) tek komutluk izin listesi; (4) `_kill_jobs` / `_parent_watchdog` / açılışta yetim toplama; (5) kabul yolu (`model` bölümü); (6) uç testleri (koruma dahil). **c2 sayfa:** (1) terminal paneli (alt çekmece, `textContent`); (2) olay işleyici; (3) örümcek imleci ve takip; (4) öneri kartı; (5) CSP; (6) U-1…U-3 sınamaları; Berke ile elle gezinti | c1: `ui/server.py`, `tests/test_ui_lm_api.py`; c2: `ui/index.html`, `tests/test_ui_lm_panel.py`; kabul yolu için `karadul/core/overrides.py` (P17'nin; P17 bitmeden yama) | P17, P22e | L |
| **P22f** | MCP sunucusu (isteğe bağlı) | (1) stdio bağdaştırıcısı; (2) yalnız O sınıfı; (3) zarf eşitliği; (4) açılış uyarısı ve kayıt; (5) testler | yeni: `karadul/lm/mcp_server.py`, `tests/test_lm_mcp.py`; CLI girişi `karadul/cli.py` (P15'in; yama) | P22d, karar 9 | S-M |
| **P22g** | Ölçüm | (1) §8.2 ön kaydı; (2) harness (`scripts/measurement/karadullm_v2_olc.py`); (3) S-3 modelsiz sayım; (4) A-2 için 40 yapay görev; (5) koşu künyesi | yeni: `scripts/measurement/karadullm_v2_olc.py`, `docs/arge/2026-11-18_karadullm_v2/on_kayit.md`, `tests/test_karadullm_v2_olc.py` | ön kayıt P22a'dan sonra; koşu P22b + P22d + makine boş | M + model zamanı (htop zinciri tahminen 3-6 sa) |

**Sıra:** P21 → P22a → (P22b ∥ P22d) → P22e → P22c (c1 → c2; P17'den sonra) → P22f. P22g'nin ön kaydı P22a'dan sonra yazılır, modelli koşuları P22b ve P22d'den sonra ana oturumda yapılır. Eşzamanlı en çok iki P22 paketi (P22b ∥ P22d), çünkü öbürleri aynı dosyalara dokunur.

## 10. Lisans ve kaynak notu

**Alınan fikirler ve kaynakları:**

| Fikir | Kaynak | Kod alınıyor mu |
|---|---|---|
| İstemci–sunucu ayrımı (ajan sunucuda, arayüz istemci) | opencode V1 sunucu belgesi [OC-4]; V2 arka plan sunucusu [OC-3] | Hayır |
| Kip = istem + izin + araç kümesi; `plan` kipi | opencode ajanları [OC-1][OC-9]; Claude Code izin kipleri [CC-2]; Codex `/plan` [CX-7] | Hayır |
| Allow / ask / deny; deny her kipte kazanır; politika yalnız daraltır | opencode [OC-2]; Claude Code [CC-2] | Hayır |
| Adım tavanı dolunca araçların kaldırılıp son cevabın istenmesi | opencode `steps` [OC-1] (bizde bağımsız olarak zaten vardı, `agent.py:479-489`) | Hayır |
| Taze bağlamlı alt görev, yalnız özet döner | Claude Code alt ajanları [CC-3]; opencode `subagent` [OC-1] | Hayır |
| Sıra numaralı olay akışı; tüketici geride kalırsa kayıp | Claude Code `stream-json` [CC-6]; Codex `exec --json` [CX-3]; opencode `/api/event` [OC-5] | Hayır |
| Proje notları / defter | Claude Code CLAUDE.md ve otomatik bellek [CC-5]; Codex AGENTS.md [CX-4]; opencode kuralları [OC-10] | Hayır |
| Kanca noktaları | Claude Code kancaları [CC-4] (bizde sabit Python denetimi) | Hayır |
| Terminal satır görünümü | Claude Code'un etkileşimli görünümü (genel tasarım dili; belge sayfası alıntılanmadı) | Hayır |

- **Lisanslar:** opencode MIT ("Copyright (c) 2025 opencode") [OC-8]; Codex Apache-2.0 [CX-1]; Claude Code açık kaynak lisanslı değil ("© Anthropic PBC. All rights reserved. Use is subject to Anthropic's Commercial Terms of Service.") [CC-9]; xterm.js MIT [XT-1] (kullanılmıyor).
- **Bu tasarım hiçbirinden kod almıyor.** Fikirler telif konusu değildir; kaynak gösterimi depo herkese açık olduğu için yapıldı. İleride kod alınırsa: MIT'te telif ve izin bildirimi kopyada korunur; Apache-2.0'da lisans metni, varsa NOTICE bildirimi ve değişiklik notu eklenir; Claude Code'dan kod alınamaz.
- Belgedeki dış alıntılar kısa ve kaynaklıdır; üçüncü taraf belge metni depoya kopyalanmadı.

**Dış kaynak kayıtları** (hepsi için Date checked: 2026-11-18; sayfalar bir özetleme ara katmanından geçti, birebir cümle istendi):

- **[OC-1] opencode ajanları (V2).** Claim: yerleşik birincil `build`, `plan`; alt ajan `general`, `explore`; `mode` ∈ primary / subagent / all; alt ajan `subagent` aracıyla, "fresh context" çocuk oturumda, arka planda; `steps` son adımda araçları kaldırır ve metin özeti ister; ajan başına `provider/model#variant`. Evidence: https://opencode.ai/docs/agents/. Confidence: yüksek (resmi). What may change: V2 hızla değişiyor; V1'de Task aracı vardı.
- **[OC-2] opencode izinleri (V2).** Claim: kurallar eylem × kaynak × `allow`/`ask`/`deny`; son eşleşen kazanır; kural yoksa `ask`; `once` / `always` / `reject`; politikalar yalnız `deny`'a çevirir; kabuk tarayıcısı; "`shell` runs with the host user's filesystem, process, and network authority"; eklentiler eylem tanımlayabilir. Evidence: https://opencode.ai/docs/permissions/. Confidence: yüksek. What may change: eylem adları.
- **[OC-3] opencode CLI (V2).** Claim: kullanıcı başına paylaşılan arka plan sunucusu oturumları, yapılandırmayı, izinleri ve araç yürütmeyi tutar; "Every local OpenCode client connects to that server". Evidence: https://opencode.ai/docs/cli/. Confidence: yüksek. What may change: sunucu bulma yöntemi.
- **[OC-4] opencode sunucusu (V1, resmi Türkçe sayfa).** Claim: `opencode serve` arayüzsüz HTTP sunucusu; "TUI, sunucuyla konuşan istemci tarafıdır"; öntanım `127.0.0.1:4096`; `OPENCODE_SERVER_PASSWORD` ile temel kimlik doğrulama; `/event` SSE, ilk olay `server.connected`; `POST /session/:id/abort`; izin yanıtı ucu. Evidence: https://opencode.ai/docs/tr/server. Confidence: yüksek (V1 için). What may change: V2'de uç adları farklı ([OC-5]).
- **[OC-5] opencode HTTP API başvurusu (V2).** Claim: OpenAPI 3.1; `GET /api/event` "Volatile by contract: a slow consumer overflows and fails the stream, and events during disconnection are missed"; kalıcı oturum günlüğü `follow=true`; `POST /api/session/{id}/interrupt`; izin yanıtı ucu; eşleştirme koduyla kimlik doğrulama. Evidence: https://opencode.ai/docs/server/. Confidence: orta (sayfanın ilk ~100 000 karakteri okundu; taşıyıcı adı görülen kısımda yok; "deneysel" diye işaretli). What may change: deneysel yüzey.
- **[OC-6] opencode sıkıştırma (V2).** Claim: eski konuşma özetle değişir; `keep.tokens` 15 000; `buffer` "15%" ve en az 16k; `auto` öntanım açık; aşımda bir kez sıkıştırıp yeniden dener. Evidence: https://opencode.ai/v2/docs/compaction. Confidence: yüksek. What may change: öntanım değerler.
- **[OC-7] opencode MCP.** Claim: yerel stdio ve uzak Streamable HTTP istemcisi; "MCP tools consume model context, so add only the servers you need"; `protocol` ∈ legacy / auto / 2026-07-28; belgede opencode'un kendisinin MCP sunucusu olduğu yazmıyor. Evidence: https://opencode.ai/docs/mcp-servers/. Confidence: yüksek. What may change: protokol sürümleri.
- **[OC-8] opencode deposu ve lisansı.** Claim: depo `github.com/anomalyco/opencode` (`github.com/sst/opencode` adresi bu depoyu gösteriyor); lisans MIT, "Copyright (c) 2025 opencode"; README: `build` "Default, full-access agent", `plan` "Read-only agent for analysis and code exploration". Evidence: https://github.com/sst/opencode, https://github.com/anomalyco/opencode/blob/dev/LICENSE. Confidence: yüksek. What may change: depo sahibi adı (taşındığı görülüyor).
- **[OC-9] opencode ajanları (V1, resmi Türkçe sayfa).** Claim: birincil Build, Plan; alt ajan General, Explore, Scout; alt ajan çağrısını Task aracı izinleri denetler; `maxSteps` kullanımdan kaldırıldı, yerine `steps`. Evidence: https://opencode.ai/docs/tr/agents. Confidence: yüksek (V1 için). What may change: V2'de Scout yok ([OC-1]).
- **[OC-10] opencode kuralları.** Claim: `AGENTS.md`; yoksa `CLAUDE.md`; küresel `~/.config/opencode/AGENTS.md`; `instructions` dizisi. Evidence: https://opencode.ai/docs/rules/. Confidence: yüksek; sürüm belirtilmemiş. What may change: dosya adları.
- **[CC-1] Claude Code nasıl çalışır.** Claim: döngü "gather context, take action, verify results"; oturum JSONL; bağlam dolunca özetle sıkıştırma, "detailed instructions from early in the conversation may be lost"; `/compact` odaklı; Esc ile durdurma; checkpoint ile dosya geri sarma; alt ajanlar kendi penceresinde. Evidence: https://code.claude.com/docs/en/how-claude-code-works. Confidence: yüksek. What may change: kip adları ve öntanımlar.
- **[CC-2] Claude Code izin kipleri.** Claim: `default`, `acceptEdits`, `plan`, `auto`, `dontAsk`, `bypassPermissions`; "Plan mode tells Claude to research and propose changes without making them"; "Deny rules block in every mode, including `bypassPermissions`". Evidence: https://code.claude.com/docs/en/permission-modes. Confidence: yüksek (ilk ~100 000 karakter okundu). What may change: kip listesi.
- **[CC-3] Claude Code alt ajanları.** Claim: "Each subagent runs in its own context window with a custom system prompt, specific tool access, and independent permissions"; Markdown + YAML önbilgi; yerleşik Explore, Plan, general-purpose; üç kata kadar iç içe; yalnız özet döner; `model` alanı. Evidence: https://code.claude.com/docs/en/sub-agents. Confidence: yüksek. What may change: derinlik sınırı.
- **[CC-4] Claude Code kancaları.** Claim: `PreToolUse` çıkış 2 ya da JSON `permissionDecision: "deny"` ile engeller; "staying silent doesn't approve it"; olay listesi. Evidence: https://code.claude.com/docs/en/hooks. Confidence: yüksek (ilk ~100 000 karakter). What may change: olay listesi büyüyor.
- **[CC-5] Claude Code belleği.** Claim: CLAUDE.md ve otomatik bellek her oturumda yüklenir; "Claude treats them as context, not enforced configuration"; engellemek için `PreToolUse` kancası. Evidence: https://code.claude.com/docs/en/memory. Confidence: yüksek. What may change: yükleme sınırları.
- **[CC-6] Claude Code programatik kullanım.** Claim: `--output-format stream-json` "newline-delimited JSON for real-time streaming"; `system/init`; son `result` iletisi maliyetle; `--include-partial-messages`; `permission_denied` iletileri. Evidence: https://code.claude.com/docs/en/headless. Confidence: yüksek. What may change: olay alanları.
- **[CC-7] Claude Code CLI başvurusu.** Claim: `--max-turns`, `--max-budget-usd` yalnız print kipinde; `claude mcp` MCP sunucularını yapılandırır; okunan satırlarda Claude Code'u MCP sunucusu olarak çalıştıran bir komut **bulunamadı** (üçüncü taraf kaynaklar `claude mcp serve` diyor; doğrulanmadı). Evidence: https://code.claude.com/docs/en/cli-reference. Confidence: bayraklar için yüksek; "sunucu kipi yok" için düşük (yalnız arama). What may change: komut listesi.
- **[CC-8] Claude Code MCP.** Claim: "Verify you trust each server before connecting it. Servers that fetch external content can expose you to prompt injection risk"; araç arama öntanımlı açık. Evidence: https://code.claude.com/docs/en/mcp. Confidence: yüksek. What may change: araç arama davranışı.
- **[CC-9] Claude Code lisansı.** Claim: "© Anthropic PBC. All rights reserved. Use is subject to Anthropic's Commercial Terms of Service." Evidence: https://github.com/anthropics/claude-code/blob/main/LICENSE.md. Confidence: yüksek. What may change: lisans metni.
- **[CX-1] Codex deposu.** Claim: Apache-2.0. Evidence: https://github.com/openai/codex. Confidence: yüksek. What may change: düşük.
- **[CX-2] Codex onaylar ve güvenlik.** Claim: kum havuzu `read-only` / `workspace-write` (masaüstü, CLI, IDE öntanımı) / `danger-full-access`; `on-request`, `never`; "Codex and ChatGPT Work no longer support `approval_policy = "untrusted"`"; "By default, the agent runs with network access turned off"; macOS'ta Seatbelt + `sandbox-exec`, Linux'ta `bwrap` + `seccomp`. Evidence: https://learn.chatgpt.com/docs/agent-approvals-security (`developers.openai.com/codex/agent-approvals-security`'den 308 yönlendirmesi). Confidence: yüksek. What may change: onay politikaları (biri emekli edilmiş).
- **[CX-3] Codex etkileşimsiz kip.** Claim: `--json` ile stdout JSONL; olay türleri `thread.started`, `turn.started`, `turn.completed`, `turn.failed`, `item.*`, `error`; öğe türleri ajan iletisi, akıl yürütme, komut çalıştırma, dosya değişikliği, MCP çağrısı, web arama, plan güncellemesi; "By default, `codex exec` runs in a read-only sandbox". Evidence: https://learn.chatgpt.com/docs/non-interactive-mode (`developers.openai.com/codex/noninteractive`'ten 308). Confidence: yüksek. What may change: olay biçimi (bir kez değişmiş).
- **[CX-4] Codex AGENTS.md.** Claim: dizin başına `AGENTS.override.md`, `AGENTS.md`, …; toplam `project_doc_max_bytes` 32 KiB. Evidence: https://developers.openai.com/codex/guides/agents-md. Confidence: orta (arama özetinden; sayfa ayrıca açılmadı). What may change: dosya adları.
- **[CX-5] Codex MCP sunucusu kaldırıldı.** Claim: "The `codex mcp-server` command and the standalone `codex-mcp-server` binary have been removed"; yerine deneysel app server, "isn't an MCP server". Evidence: https://learn.chatgpt.com/docs/mcp-server (`developers.openai.com/codex/guides/agents-sdk`'ten 308). Confidence: yüksek. What may change: app server'ın durumu.
- **[CX-6] Codex MCP istemcisi.** Claim: `[mcp_servers.<ad>]` tabloları; `enabled_tools` / `disabled_tools`; stdio ve Streamable HTTP. Evidence: https://developers.openai.com/codex/mcp, https://developers.openai.com/codex/config-reference. Confidence: orta (arama özetinden). What may change: anahtar adları.
- **[CX-7] Codex eğik çizgi komutları.** Claim: `/compact` görünür sohbeti yoğunlaştırır; `/plan` plan kipini açıp kapatır; `/review`. Evidence: https://developers.openai.com/codex/cli/slash-commands. Confidence: orta (arama özetinden). What may change: komut listesi.
- **[CX-8] Codex özelleştirme (alt ajanlar).** Claim: katmanlar AGENTS.md, anılar, beceriler, MCP, "Subagents for delegating work to specialized subagents". Evidence: https://developers.openai.com/codex/codex-manual.md (arama sonucu metni). Confidence: düşük-orta. What may change: hepsi.
- **[XT-1] xterm.js.** Claim: MIT; `@xterm/addon-attach` "Attaches to a server running a process via a websocket". Evidence: https://github.com/xtermjs/xterm.js. Confidence: yüksek. What may change: eklenti adları.
- **Üçüncü taraf blog iddiaları:** "opencode MIT lisanslı" → resmi LICENSE ile doğrulandı [OC-8]. "build / plan / explore ajanları" → V2 belgesinde build, plan (birincil), general, explore (alt) [OC-1]; V1'de ayrıca scout [OC-9]. "opencode `task` alt ajanı" → V1'de Task aracı [OC-9]; V2'de adı `subagent` [OC-1].

## 11. Açık kararlar (Berke'ye)

Seçenekler düşük maliyet / risk → yüksek sırasıyla; ilk sıradaki önerimdir.

| # | Karar | Seçenekler | Not |
|---|---|---|---|
| 1 | Döngünün ad işindeki yeri | (a) Ayırıcı deneye kadar yalnız keşif kipinde. (b) Baştan ad işinde de | §7, §8.2 |
| 2 | Aşağıdan yukarı özetin öntanımı | (a) İsteğe bağlı: seçili fonksiyonun kapanışı (derinlik ≤ 2). (b) Analiz bitince bütün ikili, gece işi | (b) htop'ta saatler sürüyor |
| 3 | Plan kipi | (a) Belirlenimci plan (R1 + O7 kapanışı), model planı yok. (b) Model planı + sunucu doğrulaması (bu belge) | Model planının değeri ölçülmedi |
| 4 | Terminal panelinin yeri | (a) Harita ve kod panelinin altında açılır çekmece (örümcek görünür kalır). (b) Sağda sütun | (a) örümcekle aynı anda görünür |
| 5 | `niyet` alanı (araç dalında modelin kısa notu) | (a) Kapalı (her adım +~30 jeton; yük altında ~3 sn **[hesap: 30 / 10,9]**). (b) Açık | Terminalde "neden bu aracı çağırdı" satırı yalnız (b)'de |
| 6 | İçerik deposunun saklama süresi | (a) Oturum kapanınca sil. (b) İkiliyle birlikte kalır, analist siler. (c) N gün | Ölçüm ve gelecekteki eğitim verisi için (b) |
| 7 | Eşikler | §8.1, §8.2, §4'teki **[seçim]** değerleri | — |
| 8 | Keşif kipinde bulut ucu | (a) Yalnız yerel. (b) Kullanıcı ucu, ağ onayıyla (bugünkü arka uç destekliyor) | Decompile metni dışarı gider |
| 9 | MCP sunucusu | (a) Yapılmasın. (b) P22f: salt okur, stdio, öntanımlı kapalı | §5; bağımlılık: resmi MCP Python paketi mi, el yazımı JSON-RPC mi |
| 10 | Bağımsız CLI | (a) Yalnız arayüz paneli. (b) Ayrıca `python -m karadul.lm` (aynı oturum çekirdeği, düz çıktı) | (b) ölçüm ve başsız kullanım için ucuz |

### 11.1 Verilen kararlar (2026-11-18)

| # | Karar | Kim |
|---|---|---|
| 1 | (a) Döngü ayırıcı deneye kadar yalnız keşif kipinde | ana oturum (teknik; Berke RE yol ayrımını ölçüme bırakıyor) |
| 2 | (a) Aşağıdan yukarı özet isteğe bağlı: seçili fonksiyonun kapanışı (derinlik ≤ 2); bütün ikili gece işi ayrı düğme | ana oturum |
| 3 | (a) Belirlenimci plan; model planı yok (değeri ölçülünce yeniden bakılır) | ana oturum |
| 4 | **(a) Terminal paneli harita ve kod panelinin altında açılır çekmece** (örümcek görünür kalır) | **Berke** |
| 5 | **(b) `niyet` satırı AÇIK:** terminal her araç çağrısında "neden bu aracı çağırdı" satırını gösterir | **Berke** |
| 6 | (b) İçerik deposu ikiliyle birlikte kalır, analist siler | ana oturum (yalnız yerel veri) |
| 7 | Eşikler ölçümle seçilir (§8) | ana oturum |
| 8 | **(a) Keşif kipinde yalnız yerel model; bulut ucu yok** (decompile metni makineden çıkmaz) | **Berke** |
| 9 | **(a) MCP sunucusu şimdilik yapılmasın** (P22f ertelendi) | **Berke** |
| 10 | (b) Bağımsız CLI `python -m karadul.lm` da olsun (ölçüm ve başsız kullanım) | ana oturum |

## 12. Doğrulanmayanlar

- Model koşturulmadı. Süreler önceki tasarımın hesaplarıdır; döngü ve özet zincirinin gerçek süresi bilinmiyor.
- Önek önbelleğinin neden isabet etmediği hâlâ bilinmiyor (Z1). Çalışırsa §7'nin 3. savunması zayıflar.
- 16K bağlamın bellek tepesi ölçülmedi (Z2).
- `llama-server`'ın bağlantı kopunca üretimi kesip kesmediği (Z8).
- WKWebView'da uzun yoklamanın davranışı denenmedi (sıradan `fetch` olduğu için risk düşük görülüyor; doğrulanmadı).
- Çağrılan kapanış boyutu (S-3) sayılmadı; isteğe bağlı özetin süresi bu yüzden bilinmiyor.
- P21'in denetim arayüzünün adı ve biçimi bilinmiyor (P21.md yok); §3.10'daki imza beklentidir.
- Dış kaynaklarda: opencode V2 HTTP API sayfasının ilk ~100 000 karakteri okundu; Claude Code'un MCP sunucusu kipi resmi sayfalarda bulunamadı; Codex için kanca, iptal / devam, bütçe ve çoklu model belgeleri okunmadı ("bakılmadı").
- Takım tartışma dosyasına yazılmadı: paket istemi `~/.claude/**` yazmayı yasaklıyor.

## 13. Dört kural (yaratıcılık protokolü)

| Kural | Uygulandı mı | Nasıl |
|---|---|---|
| 1. Denetlenebilirlik | Evet | §8.1: her özellik mekanik bir doğrulayıcıya bağlı; doğrulayıcısı olmayan (keşif kipinin faydası) "yön gösterici" diye ayrıldı |
| 2. Uzlaşıyı kır | Evet | "Kodlama ajanı mimarisini taşı" uzlaşısına karşı §7'de aykırı öncül savunuldu; sonuç mimariyi değiştirdi (iki motor, döngü ad işinden kapı arkasında). Opus dışı model danışması bu pakette yasaktı |
| 3. Başarısızlıkları taşı | Evet | LM-08 (5/5 çekimser) → §3.6; önek önbelleği 0 / 111 → §3.7 ve §7; LM-06 (yapışkan iptal) → §3.11; `setsid` kilitlenmesi → §4.3; LM-05 (yetim sunucu) → G7 |
| 4. Seçimi sen yapma | Evet | §11'de 10 karar seçenekleriyle; eşikler **[seçim]**. Dış uzman sorusu: önceki tasarımın §11.3 madde 2'si (27B yerel modelde serbest araç seçimi sabit pakete göre kazanç veriyor mu) bu tasarımın ayırıcı deneyiyle aynı sorudur; deneyden önce bir RE uygulayıcısına sorulması önerilir |
