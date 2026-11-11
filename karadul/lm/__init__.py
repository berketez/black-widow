"""KaradulLM: arayüzün içinde çalışan, isteğe bağlı yerel model ajanının çekirdeği.

Tasarım: ``docs/arge/2026-11-11_karadullm/tasarim.md`` (§2.1, §2.2, §3.1, §5.4, §8.3).
Aşama 1a notu: ``docs/arge/2026-11-11_karadullm/asama1a.md``.

Motor LLM'siz kalır: ``karadul/`` altındaki hiçbir motor modülü bu paketi içe aktarmaz (K-M1).
Bu paket motor modüllerinden okuyabilir; tersi yasaktır.

Aşama 1b notu: ``docs/arge/2026-11-11_karadullm/asama1b.md``.

Modüller:

- ``backend``: arka uç soyutlaması; yerel yalın ``llama-server``, kullanıcının OpenAI uyumlu ucu,
  testler için betikli sahte arka uç.
- ``probe``: hız yoklaması (P, G, önek yeniden kullanımı) ve arayüz kipi kuralı.
- ``memory_guard``: ``llama-server`` için RSS + footprint ölçümü ve eşik.
- ``protocol``: tur şeması (düz ``anyOf`` zarfı), şema doğrulayıcı, cevap ayrıştırma, onarım kuralı.
- ``audit``: denetim günlüğü (anahtar ve ham ikili verisi yazılmaz).
- ``context``: sabit önek (sistem istemi KL-0 + araç tanımları), kanıt paketi metni (pilot biçimi),
  veri / talimat ayrımı (kaçışlama, sarmalama), kod kırpma, bağlam bütçesi.
- ``tools``: araç kaydı, saklı çalışma alanının salt okunur görünümü ve üç okuyan araç
  (``get_evidence``, ``get_decompiled``, ``get_xrefs``).
- ``agent``: K0 iş akışı ve bütçeli döngü (K1 / K2 öntanımlı kapalı).

İçe aktarma yan etkisizdir: sunucu başlatılmaz, ağ açılmaz, dosya yazılmaz. Alt modüller burada
içe aktarılmaz; yalnız sabitler tanımlıdır.

Sabitler
--------
Paketin bütün sayısal sabitleri yalnız burada tanımlıdır (proje kuralı: aynı sayı birden çok yerde
yazılmaz). Hepsi ileride ``karadul/config.py``'ye taşınacak (asama1a.md "config'e taşınacaklar").

Kökler:
- **pilot**: ``scripts/measurement/llm_pilot.py``'deki değerin kopyası; eşitliği testle kilitli
  (``tests/test_lm_backend.py``). Pilot ön kayıtlıdır ve değişmez; ürün onu içe aktaramaz.
- **tasarım**: tasarım belgesinin tanımı (ölçüm ya da hesap).
- **[seçim]**: tasarımda Berke'nin kararına bırakılmış değer; önerilen başlangıç noktası.
- **[bu iş]**: tasarımda yazmayan, bu işte konmuş eşik; asama1a.md'de gerekçesiyle listelidir.
"""
from __future__ import annotations

# --- Pilot kopyaları (llm_pilot.py) ---------------------------------------------------------
CONTEXT_TOKENS = 10240          # llm_pilot.py:166 BAGLAM; K0 bağlamı (tasarım §2.3)
MODEL_SEED = 20261019           # llm_pilot.py:50 MODEL_TOHUMU; --seed ve istek gövdesi
MAX_TOKENS_STEP = 256           # llm_pilot.py:63 MAX_TOKENS; adım başına üretim (tasarım §2.3)
MEMORY_LIMIT_GIB = 20.0         # llm_pilot.py:65 BELLEK_ESIGI_GB; RSS + footprint üst sınırı
REQUEST_TIMEOUT_SEC = 900       # llm_pilot.py:66 CAGRI_ZAMAN_ASIMI; tek model isteği
READY_TIMEOUT_SEC = 900         # llm_pilot.py:756; llama-server hazır olma beklemesi
HEALTH_POLL_SEC = 2.0           # llm_pilot.py:765; /health yoklama aralığı
HEALTH_REQUEST_TIMEOUT_SEC = 5  # llm_pilot.py:760; tek /health isteği
STOP_WAIT_SEC = 60              # llm_pilot.py:772; terminate sonrası bekleme

# --- Tasarım seçimleri [seçim] --------------------------------------------------------------
MAX_TOKENS_CHAT = 512           # §2.3 sohbet cevabı
INTERACTIVE_TAU_SEC = 10.0      # §8.3 τ: T̂ ≤ τ ise etkileşimli kip
MODE_BAND = 0.20                # §8.3 kip değişimi ancak τ'nun %20 altı / üstü geçilince
FIRST_TOKEN_TARGET_SEC = 3.0    # §8.3 ikincil gösterge: ilk jetona kadar süre
ROLLING_WINDOW = 5              # §2.2 hızın kayan medyanı: son 5 gözlem
IDLE_SHUTDOWN_SEC = 600.0       # §2.2 boşta 10 dk sonra durdurma
MEMORY_POLL_SEC = 10.0          # §2.2 boşta bellek ölçüm aralığı

# --- Tasarım tanımları ----------------------------------------------------------------------
REF_PROMPT_TOKENS = 2500            # §8.3 N_yeni: K0 "ad öner" başvuru istemi
REF_PROMPT_TOKENS_PREFILLED = 30    # §8.3 N_yeni: önek yeniden kullanılıyor + seçimde ön işleme
REF_OUTPUT_TOKENS = 80              # §8.3 M: "ad öner" cevabı
PROBE_PROMPT_TOKENS_TARGET = 1000   # §2.2 yoklama 1: ~1.000 jetonluk istem
PROBE_FIRST_MAX_TOKENS = 1          # §2.2 yoklama 1: 1 jeton üretim
PROBE_GEN_TOKENS = 64               # §2.2 yoklama 2: 64 jeton üretim
PROBE_REUSE_FRACTION = 0.95         # §9.2 K-Z1: cache_n ≥ ortak önekin %95'i → yeniden kullanım var
RATIONALE_MAX_CHARS = 240           # §8.4 madde 5: "ad öner" gerekçesi ≤ 240 karakter
MEMORY_ROUND_DIGITS = 3             # llm_pilot.py:630-631: bellek GiB değerleri 3 basamağa yuvarlanır

# --- Bu işin eşikleri [bu iş] ---------------------------------------------------------------
# Yoklama metninin sözcük sayısı. Zemin önbellek yoklamasında 1.200 sözcüklük aynı biçimli metin +
# kısa soru 2.594 jeton tuttu (onbellek_a.json r1); ≈ 2,16 jeton/sözcük → 1.000 / 2,16 ≈ 463.
# Gerçek jeton sayısı her zaman ucun `usage` alanından okunur; bu yalnız hedef boyuttur.
PROBE_WORDS = 460
# Önek hızı (P) yalnız en az bu kadar jetonun işlendiği istemden (ya da iki istem arasındaki
# işlenen jeton farkından) hesaplanır; daha azında ağ ve ölçüm gürültüsü baskındır.
PROBE_MIN_PREFILL_TOKENS = 256
# Üretim hızı (G) yalnız en az bu kadar jeton üretilmişse hesaplanır.
PROBE_MIN_GEN_TOKENS = 8
# Yetenek yoklamasında (L1/L2/L3) tek isteğin üretim tavanı.
CAPABILITY_PROBE_MAX_TOKENS = 32
# Hata iletisine alınan uç cevabı parçasının en büyük uzunluğu (karakter).
ERROR_EXCERPT_CHARS = 300

# ============================================================================================
# Aşama 1b: bağlam, okuyan araçlar, K0 iş akışı ve bütçeli döngü (asama1b.md)
# ============================================================================================

# --- Pilot kopyaları (llm_pilot.py; eşitliği tests/test_lm_context.py ile kilitli) ------------
CODE_LIMIT_BYTES = 9000         # llm_pilot.py:60 KOD_SINIR; tek atış kipinde kod tavanı
CODE_HEAD_BYTES = 7000          # llm_pilot.py:61 KOD_BAS
CODE_TAIL_BYTES = 2000          # llm_pilot.py:62 KOD_SON
EVIDENCE_MAX_CALLEES = 40       # llm_pilot.py:463
EVIDENCE_MAX_CALLERS = 30       # llm_pilot.py:464
EVIDENCE_MAX_CALLBACKS = 20     # llm_pilot.py:465-466
EVIDENCE_MAX_STRINGS = 40       # llm_pilot.py:467
EVIDENCE_STRING_CHARS = 120     # llm_pilot.py:460
EVIDENCE_MAX_CONSTANTS = 20     # llm_pilot.py:468
EVIDENCE_API_LIMIT = 10**6      # llm_pilot.py:462: kütüphane çağrıları listesi fiilen sınırsız

# --- Tasarım tanımları -----------------------------------------------------------------------
MAX_TOOL_CALLS = 8              # §2.3 araç çağrısı / görev (pilot_protokolu.md §15)
MAX_TOOL_CALLS_K1 = 2           # §2.3 K1: en çok 2 ek bakış
CONTEXT_TOKENS_K2 = 16384       # §2.3 K2 bağlamı
CONTEXT_TOKENS_K2_FALLBACK = 12288  # §2.3 bellek kapısı tutmazsa
XREFS_MAX_ROWS = 30             # arac_sozlesmeleri.md O3: limit ≤ 30
# §2.3 bağlam bütçesi dilimleri (K2, jeton). Toplam 15.972 (testle kilitli).
BUDGET_PREFIX_TOKENS = 2200
BUDGET_SESSION_TOKENS = 600
BUDGET_PACKAGE_TOKENS = 4100
BUDGET_TOOL_RESULTS_TOKENS = 6000
BUDGET_OUTPUT_TOKENS = 2560
BUDGET_MARGIN_TOKENS = 512
# Jeton kestirimi [tahmin]: gerçek sayı her zaman ucun `usage` alanından okunur (§2.3).
BYTES_PER_TOKEN_CODE = 1.5      # arac_sozlesmeleri.md §2: kod, 9.000 bayt ≈ 6.000 jeton
BYTES_PER_TOKEN_TEXT = 4.294    # tasarım §4.1: sistem_ortak.txt 1.331 bayt = 310 jeton

# --- Tasarım seçimleri [seçim] ---------------------------------------------------------------
LOOP_CODE_LIMIT_BYTES = 4500    # §4.3, arac_sozlesmeleri.md O2: döngü kipinde çağrı başına kod
TIME_BUDGET_FACTOR = 4.0        # §2.3 süre / görev: beklenen sürenin 4 katı

# --- Bu işin eşikleri [bu iş] (asama1b.md §2) ------------------------------------------------
# `kanit` dizisinin üst sınırı: bir görevde en çok MAX_TOOL_CALLS araç sonucu + paketin iki sonucu
# (get_evidence, get_decompiled) olabilir. Gerçek sınır istek başına verilen kimlik sayısıdır;
# bu değer onun tavanıdır.
REFS_MAX_ITEMS = MAX_TOOL_CALLS + 2
# Araç sonucunun (serileştirilmiş zarf) bayt tavanı; sözleşme get_evidence için sayı sınırı veriyor,
# bayt sınırı vermiyor. Sayı sınırlarıyla en kötü durum kestirimi bu tavanın altında kalmazsa liste
# sınırları yarılanır ve `truncated` dolar (sessiz kesme yok).
EVIDENCE_RESULT_MAX_BYTES = 16000
# get_evidence boyut hesabında zarfın veri dışı alanları (id, tool, ok, kind, source) için pay.
ENVELOPE_OVERHEAD_BYTES = 256
# get_xrefs: satır başına en çok ~190 bayt (FUN_ + 16 basamak + etiketli 128 karakterlik ad) × 30
# satır + zarf.
XREFS_RESULT_MAX_BYTES = 8000
# get_decompiled: kod en çok CODE_LIMIT_BYTES (+ kırpma satırı). JSON kaçışı bir baytı en çok altı
# bayta çıkarır (\uXXXX); tavan bu en kötü durumun üstündedir, yani yalnız araç hatasında tetiklenir.
DECOMPILED_RESULT_MAX_BYTES = 6 * (CODE_LIMIT_BYTES + 200) + 4096
# get_decompiled.ghidra_warnings: en çok bu kadar ayrı uyarı, her biri en çok bu kadar karakter.
WARNINGS_MAX_ITEMS = 8
WARNING_MAX_CHARS = 160
# Kanıt paketine giren adın en büyük uzunluğu; daha uzun ya da tanımlayıcı olmayan ad gösterilmez.
NAME_TAG_MAX_CHARS = 128
# get_decompiled satır numarası argümanlarının şema tavanı.
LINE_NUMBER_MAX = 999999

__all__: list[str] = []
