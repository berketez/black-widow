"""KaradulLM: arayüzün içinde çalışan, isteğe bağlı yerel model ajanının çekirdeği.

Tasarım: ``docs/arge/2026-11-11_karadullm/tasarim.md`` (§2.1, §2.2, §3.1, §5.4, §8.3).
Aşama 1a notu: ``docs/arge/2026-11-11_karadullm/asama1a.md``.

Motor LLM'siz kalır: ``karadul/`` altındaki hiçbir motor modülü bu paketi içe aktarmaz (K-M1).
Bu paket motor modüllerinden okuyabilir; tersi yasaktır.

Modüller (bu aşamada):

- ``backend``: arka uç soyutlaması; yerel yalın ``llama-server``, kullanıcının OpenAI uyumlu ucu,
  testler için betikli sahte arka uç.
- ``probe``: hız yoklaması (P, G, önek yeniden kullanımı) ve arayüz kipi kuralı.
- ``memory_guard``: ``llama-server`` için RSS + footprint ölçümü ve eşik.
- ``protocol``: tur şeması (düz ``anyOf`` zarfı), şema doğrulayıcı, cevap ayrıştırma, onarım kuralı.
- ``audit``: denetim günlüğü (anahtar ve ham ikili verisi yazılmaz).

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

# --- Tasarım tanımları -----------------------------------------------------------------------
MAX_TOOL_CALLS = 8              # §2.3 araç çağrısı / görev (pilot_protokolu.md §15)

# --- Bu işin eşikleri [bu iş] (asama1b.md §2) ------------------------------------------------
# `kanit` dizisinin üst sınırı: bir görevde en çok MAX_TOOL_CALLS araç sonucu + paketin iki sonucu
# (get_evidence, get_decompiled) olabilir. Gerçek sınır istek başına verilen kimlik sayısıdır;
# bu değer onun tavanıdır.
REFS_MAX_ITEMS = MAX_TOOL_CALLS + 2

__all__: list[str] = []
