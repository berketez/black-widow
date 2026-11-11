"""Hız yoklaması ve arayüz kipi kuralı (tasarım §2.2 "Hız yoklaması", §8.3).

**Yoklama (iki istek; tamamen yapay metin, ikiliden veri yok):**

- İstek 1: ~1.000 jetonluk yapay metin, 1 jeton üretim → önek hızı P.
- İstek 2: istek 1'in konuşması + istek 1'in cevabı (asistan turu) + kısa bir kullanıcı eki, 64 jeton
  üretim → üretim hızı G ve önek yeniden kullanımı ö (1 ya da 0).

İstek 2 konuşmanın **sonuna eklenir** ("ek" deseni, ajan döngüsünün büyüyen konuşması). Bu seçim
zemin ölçümünden geliyor (``zemin/zemin_olcumu.md`` §4): karma mimarili Qwen3.8'de pilotun yalın
bayraklarıyla önek yalnız bu desende kullanıldı; kullanıcı iletisinin içine ek yapmak geri sarma
ister ve aynı yapılandırmada 0 verirdi. Metnin ilk satırı her yoklamada yeni bir rastgele etiket
taşır; böylece "yeniden ölç" bir önceki yoklamanın önbelleğine çarpmaz.

**İki hesap yolu** (hangisinin kullanılacağına veri karar verir, arka ucun türü değil):

- ``timings`` (iki istekte de ``timings`` var; yerel ``llama-server``): P = istek 1
  ``prompt_per_second``, G = istek 2 ``predicted_per_second``, ö = istek 2 ``cache_n`` ≥ ortak önekin
  %95'i (K-Z1).
- ``akis`` (``timings`` yok): G = (üretilen − 1) / (t_son − t_ilk) akışın zaman damgalarından;
  ö = ``usage.prompt_tokens_details.cached_tokens`` ≥ ortak önekin %95'i; P = (N₂ − N₁) / (t_ilk₂ −
  t_ilk₁), N = gerçekten işlenen istem jetonu (``prompt_tokens − cached_tokens``). Sabit ağ gecikmesi
  farkta düşer. Uç önbellek bilgisini vermiyorsa işlenen jeton bilinemez ve P boş kalır.

Her değer yalnız geçerlilik koşulu tutarsa dolar; tutmazsa ``None`` kalır ve nedeni ``notes``'a
yazılır. Ölçülmemiş hız, kip ya da süre için öntanımlı "makul" değer yoktur.

**Kip kuralı** (§8.3): T̂ = N_yeni / P + M / G; T̂ ≤ τ ise etkileşimli, değilse kuyruk. Kip değişimi
ancak T̂ bandın dışına çıkınca olur: etkileşimliden kuyruğa T̂ > τ·(1 + bant), kuyruktan
etkileşimliye T̂ ≤ τ·(1 − bant). τ ve bant ``karadul/lm/__init__.py``'de tek yerde.
"""
from __future__ import annotations

import math
import random
import secrets
import statistics
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from karadul.lm import (
    FIRST_TOKEN_TARGET_SEC, INTERACTIVE_TAU_SEC, MODE_BAND, PROBE_FIRST_MAX_TOKENS, PROBE_GEN_TOKENS,
    PROBE_MIN_GEN_TOKENS, PROBE_MIN_PREFILL_TOKENS, PROBE_REUSE_FRACTION, PROBE_WORDS, REF_OUTPUT_TOKENS,
    REF_PROMPT_TOKENS, REF_PROMPT_TOKENS_PREFILLED, ROLLING_WINDOW,
)
from karadul.lm.audit import AuditLog, now_iso
from karadul.lm.backend import Backend, ChatResult

MODE_INTERACTIVE = "etkilesimli"
MODE_QUEUE = "kuyruk"
PATH_TIMINGS = "timings"
PATH_STREAM = "akis"

# Yapay sözcük listesi (zemin önbellek yoklamasıyla aynı biçim, onbellek_yoklamasi.py:60-64).
_WORDS = ("register stack frame pointer offset buffer length index table entry handler callback symbol "
          "section segment header field value flag mask count size limit cursor parser token stream reader "
          "writer encoder decoder checksum digest key cipher block state context session socket packet queue "
          "worker thread mutex lock signal timer event loop dispatch route config option argument result "
          "error status code string array list map node tree graph edge vertex path file directory archive").split()
_WORDS_PER_LINE = 12
_PROBE_QUESTION = "Reply with the word OK."
_PROBE_SUFFIX = "Now write the next five numbered lines of the list."


def probe_text(nonce: str, words: int = PROBE_WORDS) -> str:
    """Yoklama metni: ilk satırda etiket, sonra numaralı yapay sözcük satırları. Aynı etiket aynı
    metni verir; metin ikiliden veri taşımaz."""
    rnd = random.Random(f"karadullm-yoklama-{nonce}")
    lines = [f"Probe {nonce}."]
    for i in range(0, words, _WORDS_PER_LINE):
        s = " ".join(rnd.choice(_WORDS) for _ in range(_WORDS_PER_LINE))
        lines.append(f"{i // _WORDS_PER_LINE + 1:04d}. {s} {rnd.randint(0, 65535):#06x}.")
    return "\n".join(lines)


def probe_messages(nonce: str, words: int = PROBE_WORDS) -> list[dict[str, str]]:
    return [{"role": "system", "content": probe_text(nonce, words)},
            {"role": "user", "content": _PROBE_QUESTION}]


def extension_messages(first: list[dict[str, str]], first_reply: str) -> list[dict[str, str]]:
    """İstek 2: istek 1'in iletileri aynen + asistan cevabı + kullanıcı eki (yalnız sona ekleme)."""
    return [*first, {"role": "assistant", "content": first_reply}, {"role": "user", "content": _PROBE_SUFFIX}]


# ---------------------------------------------------------------------------------------------
# Aritmetik (saf işlevler; sınır değerleri testte)


def _positive(x: Any) -> Optional[float]:
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return None
    x = float(x)
    return x if math.isfinite(x) and x > 0 else None


def _count(x: Any) -> Optional[int]:
    return x if isinstance(x, int) and not isinstance(x, bool) and x >= 0 else None


def prefill_from_timings(timings: Optional[dict]) -> Optional[float]:
    """P: ``prompt_per_second``; yalnız en az ``PROBE_MIN_PREFILL_TOKENS`` jeton işlendiyse."""
    if not isinstance(timings, dict):
        return None
    n = _count(timings.get("prompt_n"))
    if n is None or n < PROBE_MIN_PREFILL_TOKENS:
        return None
    return _positive(timings.get("prompt_per_second"))


def gen_from_timings(timings: Optional[dict]) -> Optional[float]:
    """G: ``predicted_per_second``; yalnız en az ``PROBE_MIN_GEN_TOKENS`` jeton üretildiyse."""
    if not isinstance(timings, dict):
        return None
    n = _count(timings.get("predicted_n"))
    if n is None or n < PROBE_MIN_GEN_TOKENS:
        return None
    return _positive(timings.get("predicted_per_second"))


def gen_from_stream(generated: Optional[int], t_first: Optional[float], t_last: Optional[float]) -> Optional[float]:
    """G = (üretilen − 1) / (t_son − t_ilk); ilk jetonun süresi istem işlemeye aittir."""
    n = _count(generated)
    if n is None or n < PROBE_MIN_GEN_TOKENS or t_first is None or t_last is None:
        return None
    dt = t_last - t_first
    return (n - 1) / dt if dt > 0 else None


def prefill_from_first_token(n1: Optional[int], t1: Optional[float], n2: Optional[int],
                             t2: Optional[float]) -> Optional[float]:
    """P = (N₂ − N₁) / (t_ilk₂ − t_ilk₁). İşlenen jeton farkı en az ``PROBE_MIN_PREFILL_TOKENS`` ve
    süre farkıyla aynı işaretli olmalı; değilse ölçüm gürültüdür → ``None``."""
    if None in (n1, n2, t1, t2):
        return None
    dn, dt = n2 - n1, t2 - t1
    if abs(dn) < PROBE_MIN_PREFILL_TOKENS or dt == 0 or (dn > 0) != (dt > 0):
        return None
    return dn / dt


def reuse_flag(cached: Optional[int], common_prefix: Optional[int]) -> Optional[int]:
    """ö: önekten gelen jeton ≥ ortak önekin ``PROBE_REUSE_FRACTION``'ı ise 1, değilse 0; bilinmiyorsa
    ``None``."""
    c, p = _count(cached), _count(common_prefix)
    if c is None or p is None or p == 0:
        return None
    return 1 if c >= PROBE_REUSE_FRACTION * p else 0


def _processed(r: ChatResult) -> Optional[int]:
    """Gerçekten işlenen istem jetonu; önbellek bilgisi yoksa bilinemez."""
    if r.prompt_tokens is None or r.cached_tokens is None:
        return None
    return r.prompt_tokens - r.cached_tokens


# ---------------------------------------------------------------------------------------------
# Sonuç


@dataclass
class ProbeResult:
    """Yoklama sonucu. Bütün ölçüm alanları ölçülmeden önce ``None``'dır."""

    measured_at: Optional[str] = None
    path: Optional[str] = None
    prefill_tps: Optional[float] = None         # P
    gen_tps: Optional[float] = None             # G
    prefix_reuse: Optional[int] = None          # ö
    cached_tokens: Optional[int] = None
    common_prefix_tokens: Optional[int] = None
    duration_sec: Optional[float] = None
    requests: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _request_summary(r: ChatResult) -> dict[str, Any]:
    return {"istem_jeton": r.prompt_tokens, "uretilen_jeton": r.completion_tokens, "onbellek_jeton": r.cached_tokens,
            "ilk_jeton_sn": r.first_token_sec, "son_jeton_sn": r.last_token_sec, "sure_sn": r.duration_sec,
            "bitis": r.finish_reason, "timings_var": isinstance(r.timings, dict)}


def compute_probe(r1: ChatResult, r2: ChatResult, measured_at: Optional[str] = None) -> ProbeResult:
    """İki yoklama isteğinden P, G ve ö (saf hesap)."""
    res = ProbeResult(measured_at=measured_at or now_iso(), requests=[_request_summary(r1), _request_summary(r2)],
                      duration_sec=r1.duration_sec + r2.duration_sec)
    if isinstance(r1.timings, dict) and isinstance(r2.timings, dict):
        res.path = PATH_TIMINGS
        res.prefill_tps = prefill_from_timings(r1.timings)
        res.gen_tps = gen_from_timings(r2.timings)
        res.cached_tokens = _count(r2.timings.get("cache_n"))
        common = r1.prompt_tokens
        if common is None:
            n, c = _count(r1.timings.get("prompt_n")), _count(r1.timings.get("cache_n"))
            common = n + c if n is not None and c is not None else None
        res.common_prefix_tokens = common
        if res.prefill_tps is None:
            res.notes.append(f"P yok: istek 1'de işlenen jeton < {PROBE_MIN_PREFILL_TOKENS} ya da hız alanı geçersiz")
        if res.gen_tps is None:
            res.notes.append(f"G yok: istek 2'de üretilen jeton < {PROBE_MIN_GEN_TOKENS} ya da hız alanı geçersiz")
    else:
        res.path = PATH_STREAM
        res.gen_tps = gen_from_stream(r2.completion_tokens, r2.first_token_sec, r2.last_token_sec)
        res.cached_tokens = r2.cached_tokens
        res.common_prefix_tokens = r1.prompt_tokens
        res.prefill_tps = prefill_from_first_token(_processed(r1), r1.first_token_sec,
                                                   _processed(r2), r2.first_token_sec)
        if res.gen_tps is None:
            res.notes.append("G yok: üretilen jeton sayısı (usage) ya da akış zaman damgaları eksik / yetersiz")
        if res.prefill_tps is None:
            if _processed(r1) is None or _processed(r2) is None:
                res.notes.append("P yok: uç önbellek bilgisi (cached_tokens) vermiyor; işlenen jeton bilinemez")
            else:
                res.notes.append(f"P yok: işlenen jeton farkı < {PROBE_MIN_PREFILL_TOKENS} ya da süre farkı tutarsız")
    res.prefix_reuse = reuse_flag(res.cached_tokens, res.common_prefix_tokens)
    if res.prefix_reuse is None:
        res.notes.append("ö yok: önek yeniden kullanımı bildirilmedi")
    return res


def run_probe(backend: Backend, *, nonce: Optional[str] = None, audit: Optional[AuditLog] = None) -> ProbeResult:
    """İki yoklama isteğini atar ve sonucu hesaplar. İsteklerin kendisi arka ucun denetim kaydına
    ``yoklama-1`` / ``yoklama-2`` amacıyla düşer; sonuç ``yoklama`` olayı olarak yazılır."""
    tag = nonce or secrets.token_hex(4)
    m1 = probe_messages(tag)
    r1 = backend.chat(m1, stream=True, max_tokens=PROBE_FIRST_MAX_TOKENS, purpose="yoklama-1")
    r2 = backend.chat(extension_messages(m1, r1.content), stream=True, max_tokens=PROBE_GEN_TOKENS,
                      purpose="yoklama-2")
    res = compute_probe(r1, r2)
    if audit is not None:
        audit.write("yoklama", arka_uc=backend.identity(), sonuc=res.as_dict())
    return res


# ---------------------------------------------------------------------------------------------
# Kip kuralı


def expected_name_suggest_sec(prefill_tps: Optional[float], gen_tps: Optional[float],
                              prefix_reuse: Optional[int] = None, prefill_on_select: bool = False) -> Optional[float]:
    """T̂ = N_yeni / P + M / G (§8.3). N_yeni = 30 yalnız önek yeniden kullanımı ölçülmüş (ö = 1) ve
    seçimde ön işleme açıksa; aksi hâlde 2.500. P ya da G yoksa ``None``."""
    p, g = _positive(prefill_tps), _positive(gen_tps)
    if p is None or g is None:
        return None
    n_new = REF_PROMPT_TOKENS_PREFILLED if (prefix_reuse == 1 and prefill_on_select) else REF_PROMPT_TOKENS
    return n_new / p + REF_OUTPUT_TOKENS / g


def first_token_sec(prefill_tps: Optional[float], prefix_reuse: Optional[int] = None,
                    prefill_on_select: bool = False) -> Optional[float]:
    """İkincil gösterge (§8.3): ilk jetona kadar süre N_yeni / P."""
    p = _positive(prefill_tps)
    if p is None:
        return None
    n_new = REF_PROMPT_TOKENS_PREFILLED if (prefix_reuse == 1 and prefill_on_select) else REF_PROMPT_TOKENS
    return n_new / p


def decide_mode(t_hat: Optional[float], previous: Optional[str] = None, *, tau: float = INTERACTIVE_TAU_SEC,
                band: float = MODE_BAND) -> Optional[str]:
    """Arayüz kipi. T̂ yoksa ``None`` (ölçülmedi; kip uydurulmaz). İlk kararda T̂ ≤ τ etkileşimli;
    sonrasında bant: etkileşimliden çıkmak için T̂ > τ·(1+bant), kuyruktan çıkmak için T̂ ≤ τ·(1−bant)."""
    if t_hat is None:
        return None
    if previous == MODE_INTERACTIVE:
        return MODE_QUEUE if t_hat > tau * (1 + band) else MODE_INTERACTIVE
    if previous == MODE_QUEUE:
        return MODE_INTERACTIVE if t_hat <= tau * (1 - band) else MODE_QUEUE
    if previous is not None:
        raise ValueError(f"bilinmeyen kip: {previous!r}")
    return MODE_INTERACTIVE if t_hat <= tau else MODE_QUEUE


@dataclass(frozen=True)
class ModeDecision:
    mode: Optional[str]
    t_hat_sec: Optional[float]
    first_token_sec: Optional[float]
    first_token_ok: Optional[bool]
    prefill_tps: Optional[float]
    gen_tps: Optional[float]
    prefix_reuse: Optional[int]
    prefill_on_select: bool


class SpeedTracker:
    """Hızın kayan medyanı (§2.2 "Güncelleme"): yoklamanın P ve G'si ilk gözlemdir; gerçek görevlerin
    gözlemleri eklendikçe son ``window`` gözlemin medyanı kullanılır. Kip durumu burada tutulur ki
    bant kuralı önceki kipe göre işlesin."""

    def __init__(self, window: int = ROLLING_WINDOW):
        self._p: deque[float] = deque(maxlen=window)
        self._g: deque[float] = deque(maxlen=window)
        self.prefix_reuse: Optional[int] = None
        self.mode: Optional[str] = None

    def seed_from_probe(self, result: ProbeResult) -> None:
        self.observe(result.prefill_tps, result.gen_tps)
        self.prefix_reuse = result.prefix_reuse

    def observe(self, prefill_tps: Optional[float] = None, gen_tps: Optional[float] = None) -> None:
        p, g = _positive(prefill_tps), _positive(gen_tps)
        if p is not None:
            self._p.append(p)
        if g is not None:
            self._g.append(g)

    def current(self) -> tuple[Optional[float], Optional[float]]:
        p = statistics.median(self._p) if self._p else None
        g = statistics.median(self._g) if self._g else None
        return p, g

    def decide(self, prefill_on_select: bool = False) -> ModeDecision:
        p, g = self.current()
        t_hat = expected_name_suggest_sec(p, g, self.prefix_reuse, prefill_on_select)
        self.mode = decide_mode(t_hat, self.mode)
        ft = first_token_sec(p, self.prefix_reuse, prefill_on_select)
        return ModeDecision(mode=self.mode, t_hat_sec=t_hat, first_token_sec=ft,
                            first_token_ok=None if ft is None else ft <= FIRST_TOKEN_TARGET_SEC,
                            prefill_tps=p, gen_tps=g, prefix_reuse=self.prefix_reuse,
                            prefill_on_select=prefill_on_select)
