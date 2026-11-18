"""KaradulLM ajanı: K0 iş akışı ve genel bütçeli döngü (tasarım §2.3, §4.3, §5.4, §6).

**K0 (öntanımlı, tek açık kip):** sırayı sunucu yürütür. Paket kurulur (sunucu ``get_evidence`` ve
``get_decompiled`` araçlarını çağırır), model TEK kez çağrılır (yalnız L2 ucunda bir onarım turu,
tasarım §2.2), cevap ayrıştırılır, sonuç nesnesi döner. Model araç çağıramaz.

**Döngü (K1 güdümlü, K2 serbest):** model her turda ya bir araç çağrısı ya da son cevabı yazar
(tasarım §3.1 Yol A zarfı). Sunucu denetler: bütçe (K2 ≤ 8, K1 ≤ 2 çağrı), tekrar (aynı araç ve
argüman ikinci kez çalışmaz), geçersiz çağrı (bilinmeyen adres, anlamsız argüman), bağlam (istem +
üretim + pay ≤ bağlam; araç sonuçları dilimi), iptal ve süre. Bütçe bitince model yalnız son cevabı
verebilir: zarfın araç dalları kaldırılır. **K1 ve K2 öntanımlı KAPALIDIR**; kapıları (tasarım §9.2
K-Z1, K-A1…) geçmeden açılmaz ve ``enabled_modes`` ile açıkça etkinleştirilmeden ``run_loop``
``ModeDisabled`` yükseltir, arka uca hiç dokunmaz.

Güvenlik: araç sonucu ve ikili içeriği talimat değildir (``context.wrap_result``); model çıktısı da
veridir (geçmişe ``context.safe_assistant_content`` ile yazılır, onarım iletisi modelin değerini
yansıtmaz). Körlük kipinde (``blind_target=True``) hedefin Karadul adı hiçbir sonuca girmez; sızıntı
taraması tutmazsa istem gönderilmez.

Tutarlılık: her model çağrısı denetim günlüğüne düşer (``Backend.chat``); çalıştırılan her araç ve
her görev de birer kayıttır (K-L1). Her model çağrısından sonra bellek bekçisi denetlenir; bellek
nedeniyle durmuş sunucuya yeni istek atılmaz (kendiliğinden yeniden başlatma yok). Arka uç hatası
(``LMError``) görevi ``arka_uc_hatasi`` ile bitirir, ajan yeni göreve hazır kalır. Beklenmeyen her
hata ve kesmede arka uç ``hata`` nedeniyle durdurulur (yetim süreç kalmaz) ve hata yükselir.
"""
from __future__ import annotations

import re
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Iterator, Mapping, Optional

from karadul.lm import (
    BUDGET_TOOL_RESULTS_TOKENS, CONTEXT_TOKENS, CONTEXT_TOKENS_K2, EVENT_TOKEN_MIN_INTERVAL_SEC, EVENT_TOUCHED_MAX,
    MAX_TOKENS_STEP, MODEL_RETRY_MAX, TASK_TIME_BUDGET_FALLBACK_SEC, TIME_BUDGET_FACTOR, guard, protocol,
)
from karadul.lm.audit import AuditLog, canonical_json, sha256_text
from karadul.lm.backend import STATE_ERROR, STATE_MEMORY_STOPPED, Backend, BackendError, ChatResult, LMError
from karadul.lm.context import (
    MODE_K0, MODE_K1, MODE_K2, MODES, PROMPT_VERSION, ContextBudget, blind_leaks, estimate_result_tokens,
    estimate_text_tokens, fixed_prefix, max_calls_for, name_question, safe_assistant_content, user_message,
)
from karadul.lm.events import CALLER_MODEL, CALLER_SERVER, ContentStore, touched_refs
from karadul.lm.memory_guard import MemoryGuard
from karadul.lm.tools import (
    ADDR_PATTERN, ERR_BUDGET, ERR_REPEAT, ERR_TOOL_CLOSED, INVALID_CALL_ERRORS, ToolContext, ToolRegistry,
    ToolResult, Workspace, WorkspaceError, default_registry, error_result, normalize_args,
)

# --- Görev durumları -------------------------------------------------------------------------
STATUS_DONE = "tamam"                         # geçerli son cevap (ad ya da çekimser)
STATUS_UNKNOWN_ADDRESS = "bilinmeyen_adres"  # hedef adres çalışma alanında yok; model çağrılmadı
STATUS_PACKAGE_ERROR = "paket_hatasi"       # paket kurulamadı (decompile metni yok vb.); model çağrılmadı
STATUS_BLIND_LEAK = "korluk_ihlali"         # körlük taraması tutmadı; istem gönderilmedi
STATUS_CONTEXT = "baglam_asimi"             # istem bağlama sığmıyor; görev başlamadan reddedildi
STATUS_LEVEL_UNKNOWN = "yetenek_bilinmiyor"  # ucun yetenek düzeyi yoklanmamış; model çağrılmadı
STATUS_BACKEND_ERROR = "arka_uc_hatasi"     # model isteği hata verdi
STATUS_MEMORY = "bellek_durdu"              # bellek bekçisi sunucuyu durdurdu
STATUS_CANCELLED = "iptal"                  # araştırmacı durdurdu
STATUS_TIMEOUT = "sure_asimi"               # süre bütçesi doldu
STATUS_BUDGET = "butce_asildi"              # araç ya da bağlam bütçesi bitti ve model son cevabı vermedi
STATUS_UNEXPECTED = "beklenmeyen_hata"      # beklenmeyen hata ya da kesme; arka uç durduruldu, hata yükseldi
STATUS_PROTECTED = "korunan_ad"             # D2: hedefin adı kesin ya da elle verilmiş; model çağrılmadı
# Ayrıca protocol.parse_turn durumları: gecersiz, sema_ihlali, butce_asimi (üretim tavanı), ret.

TASK_NAME = "ad_oner"
# CALLER_SERVER ("sunucu"), CALLER_MODEL ("model"): ``karadul.lm.events``'te tanımlı (olay şemasının
# kapalı kümesi); denetim günlüğü ve olaylar aynı değeri yazar.
# Körlük taramasına giren kanıt alanları: ad taşıyabilenler. Dizgi alanı girmez (pilot §12 madde 4:
# aynı adın dizgi sabiti olarak geçmesi meşru kanıttır).
_BLIND_SCANNED = ("apis", "callees", "callers", "callbacks_given", "callback_of")
_ADDR_RE = re.compile(ADDR_PATTERN)


class ModeDisabled(LMError):
    """K1 / K2 açıkça etkinleştirilmeden çalıştırılmak istendi."""


class AgentBusy(LMError):
    """Ajan başka bir görev yürütürken ikinci görev istendi (tek yuva, tasarım §2.3 "Sıra")."""


class _StreamStop(Exception):
    """Akış parçası gelirken iptal ya da süre dolması (KaradulLM v2 §3.11): akış okuma döngüsünden
    çıkılır, arka uç bağlantıyı kapatır. ``LMError`` değildir: yinelenmez, arka uç hatası sayılmaz."""

    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


class _TokenSink:
    """Akışlı isteğin parça geri çağrısı (KaradulLM v2 §3.3 adım 5, §3.11, §4.1 ``jeton``).

    - Her parçadan ÖNCE iptal ve süre bütçesi denetlenir; biri tutarsa ``_StreamStop`` (süren istek
      artık soket zaman aşımını beklemeden kesilir; sunucunun üretimi kesip kesmediği ölçülmedi, Z8).
    - ``jeton`` olayları birleştirilir: ilk parça hemen, sonrakiler en erken
      ``EVENT_TOKEN_MIN_INTERVAL_SEC`` aralıkla; akış bitince (ya da kesilince) yayılmamış birikim
      ``flush`` ile bir kez yayılır. Olay yalnız gerçekten gelen parçadan doğar; parça yoksa olay yok.
      Sayılan: içerik parçası ve karakter (jeton sayısı değil; o ``model_cevabi``'nda, uçtan)."""

    def __init__(self, agent: "Agent", task: "_Task"):
        self.agent = agent
        self.task = task
        self.parts = 0
        self.chars = 0
        self.emitted = 0
        self.last: Optional[float] = None

    def on_token(self, piece: str) -> None:
        a = self.agent
        if a.cancel.is_set():
            raise _StreamStop(STATUS_CANCELLED)
        now = a._clock()
        if self.task.deadline is not None and now > self.task.deadline:
            raise _StreamStop(STATUS_TIMEOUT)
        self.parts += 1
        self.chars += len(piece)
        if self.last is None or now - self.last >= EVENT_TOKEN_MIN_INTERVAL_SEC:
            self.last = now
            self.emitted = self.parts
            a._emit("jeton", self.task, parca=self.parts, karakter=self.chars)

    def flush(self) -> None:
        if self.parts > self.emitted:
            self.emitted = self.parts
            self.agent._emit("jeton", self.task, parca=self.parts, karakter=self.chars)


def time_budget_sec(expected_sec: float) -> float:
    """Görevin süre bütçesi: ölçülen hızdan beklenen sürenin katı (tasarım §2.3 [seçim])."""
    return TIME_BUDGET_FACTOR * expected_sec


@dataclass
class Counters:
    """Görev sayaçları (tasarım §2.4 "Sayaçlar")."""

    model_calls: int = 0            # modele atılan istek (onarım turları dahil)
    package_calls: int = 0          # sunucunun paket için çalıştırdığı araç
    call_requests: int = 0          # modelin istediği araç çağrısı (çalışmayanlar dahil)
    tool_calls: int = 0             # modelin isteğiyle gerçekten çalışan araç
    invalid_calls: int = 0          # bilinmeyen adres / anlamsız argüman
    repeats: int = 0                # aynı (araç, argüman) yinelemesi
    budget_exceeded: int = 0        # araç bütçesinden sonra gelen çağrı
    context_exceeded: int = 0       # bağlama sığmadığı için verilmeyen sonuç
    blind_blocked: int = 0          # körlük taramasına takıldığı için verilmeyen sonuç
    repairs: int = 0                # onarım turu
    retries: int = 0                # geçici arka uç hatasından sonra yinelenen istek (LM-02)
    prompt_tokens: int = 0          # uçtan gelen gerçek sayıların toplamı
    completion_tokens: int = 0


@dataclass
class TaskResult:
    """Bir görevin sonucu. ``answer`` yalnız ``status == "tamam"`` iken doludur.

    ``answer`` modelin ÖNERİSİDİR, doğrulanmış ad değildir: araştırmacıya gösterilmeden önce ``verdict``
    okunur (denetim katmanı, ``guard``; tasarım §5.1). ``ret`` kabul edilemez; ``celiski`` uyarı
    rozetiyle ve toplu kabul dışında; ``guard["toplu_kabul"]`` toplu kabule girip giremeyeceğini söyler.
    """

    task_id: str
    mode: str
    task: str
    addr: Optional[str]
    status: str
    answer: Optional[dict[str, Any]] = None
    name_status: Optional[str] = None       # pilotun durum sınıfı (gecerli / jenerik / cekimser …)
    result_ids: tuple[str, ...] = ()        # modele verilen sonuç kimlikleri
    truncated_ids: tuple[str, ...] = ()     # kırpılmış sonuçlar ("kırpılmış" katmanı, pilot §10.5)
    code_clipped: bool = False              # paketin kodu kırpıldı mı
    empty_content: bool = False             # ithal çağrı yok ve dizgi yok (D0, envanter icerik_adsiz)
    blind: bool = False
    est_prompt_tokens: Optional[int] = None  # ön denetimin kestirimi [tahmin]
    prompt_tokens: Optional[int] = None      # son isteğin gerçek istem jetonu (uç bildirdiyse)
    completion_tokens: Optional[int] = None
    finish_reason: Optional[str] = None
    counters: Counters = field(default_factory=Counters)
    duration_sec: float = 0.0
    memory: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    verdict: Optional[str] = None            # denetim hükmü (guard.VERDICTS); denetlenecek cevap yoksa None
    time_budget_sec: Optional[float] = None  # uygulanan süre bütçesi (LM-06)
    guard: Optional[dict[str, Any]] = None   # GuardReport.as_dict(): bulgular, bayraklar, toplu kabul

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class _Task:
    """Yürüyen görevin iç durumu."""

    result: TaskResult
    results: list[ToolResult] = field(default_factory=list)
    seen: set[tuple[str, str]] = field(default_factory=set)
    done: bool = False
    deadline: Optional[float] = None    # süre bütçesinin bittiği an (saat değeri); yoksa sınırsız
    # Olaylar (P22a): çalışan aracın ölçülen süresi (sonuç kimliği → ms) ve son model isteğinin amacı
    # ile süresi (``model_cevabi`` olayı ayrıştırmadan sonra yayılır).
    tool_ms: dict[str, int] = field(default_factory=dict)
    reply_meta: Optional[tuple[str, int]] = None

    def finish(self, status: str, error: Optional[str] = None, *, override: bool = False) -> None:
        if self.done and not override:
            return
        self.done = True
        self.result.status = status
        if error is not None:
            self.result.error = error


class Agent:
    """Tek çalışma alanı ve tek arka uç için görev yürütücü. Aynı anda tek görev çalışır."""

    def __init__(self, backend: Backend, workspace: Workspace, *, registry: Optional[ToolRegistry] = None,
                 audit: Optional[AuditLog] = None, memory_guard: Optional[MemoryGuard] = None,
                 enabled_modes: Iterable[str] = (MODE_K0,), blind_target: bool = False,
                 context_tokens: int = CONTEXT_TOKENS, loop_context_tokens: int = CONTEXT_TOKENS_K2,
                 clock: Callable[[], float] = time.monotonic, cancel: Optional[threading.Event] = None,
                 rejected_names: Optional[Mapping[str, Iterable[str]]] = None,
                 expected_task_sec: Optional[float] = None,
                 on_event: Optional[Callable[..., Any]] = None, stream: Optional[bool] = None,
                 content_store: Optional[ContentStore] = None):
        modes = frozenset(enabled_modes)
        if not modes <= frozenset(MODES):
            raise ValueError(f"bilinmeyen ajan kipi: {sorted(modes - frozenset(MODES))}")
        self.backend = backend
        self.workspace = workspace
        self.registry = registry if registry is not None else default_registry()
        self.audit = audit if audit is not None else backend.audit
        self.memory_guard = memory_guard
        self.enabled_modes = modes
        self.blind_target = bool(blind_target)
        self.context_tokens = context_tokens
        self.loop_context_tokens = loop_context_tokens
        # İptal görev başınadır (LM-06): her görevin başında temizlenir; görev yürürken kurulursa o görev
        # tur arasında "iptal" ile biter. Görev yokken kurulan iptal sonraki görevi etkilemez.
        self.cancel = cancel if cancel is not None else threading.Event()
        # Hız yoklamasından beklenen tek model turunun süresi (``probe.expected_name_suggest_sec``); verilirse
        # süre bütçesi TIME_BUDGET_FACTOR × beklenen süredir, verilmezse TASK_TIME_BUDGET_FALLBACK_SEC.
        self.expected_task_sec = expected_task_sec
        self._running = False
        self._clock = clock
        self._lock = threading.Lock()
        self._result_seq = 0
        self._task_seq = 0
        # Denetim (guard) oturum belleği: D10 araştırmacının reddettiği adlar (adres → adlar; arayüz
        # doldurur), D11 bu oturumda önerilmiş adlar (küçük harfli ad → adres).
        self.rejected_names: dict[str, set[str]] = {}
        for k, v in (rejected_names or {}).items():
            a = workspace.resolve(k) if isinstance(k, str) else None
            if a is not None:
                self.rejected_names.setdefault(a, set()).update(x for x in v if isinstance(x, str))
        self._session_names: dict[str, str] = {}
        # Olay geri çağrısı (KaradulLM v2 §3.3, §4.1): ``on_event(tur, gorev=<görev kimliği>, **alanlar)``;
        # ``events.EventStream.emit`` bu imzadadır. Olay yalnız gerçekten olan bir şey için çağrılır.
        # Geri çağrının hatası programlama hatasıdır: görev sürerken olursa görev ``beklenmeyen_hata`` ile
        # biter ve arka uç durur; kapanışta olursa görevin denetim kayıtları zaten yazılmıştır (olaylar
        # kayıtlardan sonra yayılır). İki durumda da hata yükselir; hata yolunda yayılan olayların hatası
        # asıl hatayı örtmez.
        self.on_event = on_event
        # Akışlı model isteği (§3.3 adım 5): öntanım olay geri çağrısı varken açık (canlı görünüm),
        # yokken kapalı (ölçüm ve pilot eşitliği: pilot ``stream: false`` istiyor, istek gövdesi aynı kalır).
        self.stream = (on_event is not None) if stream is None else bool(stream)
        # İçerik deposu (§4.1 "İçerik kuralı"): modelin gördüğü her araç sonucunun tam zarfı. Olaydan
        # bağımsızdır (olay geri çağrısı yokken de yazar). Yazılamazsa görev sürer; ``arac_bitti``
        # ``icerik_saklandi: false`` der.
        self.content_store = content_store

    # --- olaylar (P22a) -----------------------------------------------------------------------

    def _emit(self, tur: str, task: Optional[_Task], **fields: Any) -> None:
        if self.on_event is not None:
            self.on_event(tur, gorev=task.result.task_id if task is not None else None, **fields)

    def _target(self, a: Optional[str]) -> dict[str, Optional[str]]:
        """Olayın ``hedef`` nesnesi: ``fn`` arayüzün düğüm anahtarı (decompile dosyası yoksa ``None``),
        ``adres`` çalışma alanı yazımı."""
        return {"fn": self.workspace.ui_name(a) if a is not None else None, "adres": a}

    def _args_target(self, tool: str, args: Any) -> Optional[dict[str, Optional[str]]]:
        """Çağrının hedefi: argümanlar şemaya uyuyor ve ``addr`` çalışma alanında varsa; yoksa ``None``."""
        shown = self._shown_args(tool, args)
        a = self.workspace.resolve(shown.get("addr")) if shown is not None else None
        return self._target(a) if a is not None else None

    def _shown_args(self, tool: str, args: Any) -> Optional[dict[str, Any]]:
        """Olaya yazılabilen argümanlar: yalnız şemaya uyanlar (uymayan model çıktısı veridir;
        denetim günlüğüyle aynı kural, ``_log_tool``)."""
        spec = self.registry.spec(tool)
        if spec is None or not isinstance(args, dict) or protocol.validate(args, spec.args_schema):
            return None
        return dict(args)

    def _tool_started(self, task: _Task, rid: str, tool: str, args: Any, caller: str, *, runs: bool) -> None:
        """``arac_basladi``: sunucu bir araç çağrısını ele aldı (denetim günlüğünde bir ``arac_cagrisi``
        kaydı doğacak). Çalıştırılmadan reddedilen çağrıda (bütçe, tekrar) ``hedef`` ``None``'dır:
        örümcek yalnız gerçekten okunan fonksiyona gider."""
        self._emit("arac_basladi", task, sonuc=rid, arac=str(tool)[:64], cagiran=caller,
                   hedef=self._args_target(tool, args) if runs else None, arguman=self._shown_args(tool, args))

    def _tool_done(self, task: _Task, result: ToolResult) -> None:
        """Modelin (ya da paketin) gördüğü sonuç: içerik deposuna tam zarf; ``arac_bitti`` olayına özeti
        ve dokunulan fonksiyonlar."""
        saved: Optional[bool] = None
        if self.content_store is not None:
            try:
                self.content_store.put(result.id, result.envelope())
                saved = True
            except (OSError, ValueError):
                saved = False
        if self.on_event is None:
            return
        ws = self.workspace
        own = ws.ui_name(ws.resolve((result.data or {}).get("addr"))) if result.ok else None
        fns: list[str] = []
        for ref in touched_refs(result.envelope()):
            fn = ws.ui_name(ws.resolve(ref))
            if fn is not None and fn != own and fn not in fns:
                fns.append(fn)
        self._emit("arac_bitti", task, sonuc=result.id, arac=result.tool, tamam=result.ok, hata=result.error,
                   calistirildi=result.executed, tur_kind=result.kind, bayt=result.size_bytes(),
                   kirpma=result.truncated, sure_ms=task.tool_ms.get(result.id),
                   dokunulan=fns[:EVENT_TOUCHED_MAX], dokunulan_toplam=len(fns), icerik_saklandi=saved)

    def _reply_done(self, task: _Task, reply: ChatResult, status: str, obj: Optional[Mapping[str, Any]]) -> None:
        """``model_cevabi`` (başarılı istek): ayrıştırma durumu, ucun gerçek jeton sayıları ve süre.
        ``niyet`` yalnız şemaya uyan araç dalında modelin yazdığı not."""
        amac, sure_ms = task.reply_meta or (None, None)
        niyet = None
        if status == "gecerli" and isinstance(obj, Mapping) and obj.get("kind") == "call":
            niyet = obj.get("niyet") if isinstance(obj.get("niyet"), str) else None
        self._emit("model_cevabi", task, amac=amac, durum=status, bitis_nedeni=reply.finish_reason,
                   istem_jeton=reply.prompt_tokens, uretim_jeton=reply.completion_tokens,
                   onbellek_jeton=reply.cached_tokens, sure_ms=sure_ms, niyet=niyet, hata=None)

    def _reply_failed(self, task: _Task, amac: str, sure_ms: int, status: str, error: Optional[str],
                      reply: Optional[ChatResult] = None) -> None:
        """``model_cevabi`` (cevap ayrıştırılmadan biten istek: arka uç hatası, iptal, bellek)."""
        self._emit("model_cevabi", task, amac=amac, durum=status,
                   bitis_nedeni=reply.finish_reason if reply is not None else None,
                   istem_jeton=reply.prompt_tokens if reply is not None else None,
                   uretim_jeton=reply.completion_tokens if reply is not None else None,
                   onbellek_jeton=reply.cached_tokens if reply is not None else None,
                   sure_ms=sure_ms, niyet=None, hata=error)

    # --- sabit önek ---------------------------------------------------------------------------

    def prefix(self, mode: str) -> str:
        """Kipin sabit öneki (sistem iletisi)."""
        return fixed_prefix(mode, self.registry.definition_lines())

    def prefix_sha256(self, mode: str) -> str:
        return sha256_text(self.prefix(mode))

    # --- dış arayüz ---------------------------------------------------------------------------

    def suggest_name(self, addr: str, *, abstain_allowed: bool = True,
                     deadline_sec: Optional[float] = None) -> TaskResult:
        """K0 "ad öner": paket kur → model tek çağrı → ayrıştır → sonuç. ``deadline_sec`` verilmezse
        öntanımlı süre bütçesi (``default_time_budget_sec``)."""
        if MODE_K0 not in self.enabled_modes:
            raise ModeDisabled("K0 bu ajanda etkin değil")
        return self._run(MODE_K0, addr, abstain_allowed, deadline_sec)

    def default_time_budget_sec(self, mode: str) -> float:
        """Öntanımlı süre bütçesi (LM-06): hız ölçüldüyse TIME_BUDGET_FACTOR × beklenen süre × model
        turu sayısı (K0: 1; döngü: araç bütçesi + son cevap), ölçülmediyse TASK_TIME_BUDGET_FALLBACK_SEC."""
        e = self.expected_task_sec
        if isinstance(e, (int, float)) and not isinstance(e, bool) and e > 0:
            turns = 1 if mode == MODE_K0 else max_calls_for(mode) + 1
            return time_budget_sec(float(e) * turns)
        return TASK_TIME_BUDGET_FALLBACK_SEC

    def cancel_current(self) -> bool:
        """Yürüyen görevi iptal eder (tur arasında biter). Görev yoksa hiçbir şey yapmaz, ``False``."""
        if not self._running:
            return False
        self.cancel.set()
        return True

    def run_loop(self, addr: str, *, mode: str = MODE_K2, abstain_allowed: bool = True,
                 deadline_sec: Optional[float] = None) -> TaskResult:
        """Bütçeli döngüyle "ad öner" (K1 / K2). Kip açıkça etkinleştirilmemişse ``ModeDisabled``."""
        if mode not in (MODE_K1, MODE_K2):
            raise ValueError("döngü yalnız K1 ya da K2 kipinde çalışır")
        if mode not in self.enabled_modes:
            raise ModeDisabled(f"{mode} kapalı: kapıları geçilmeden ve açıkça etkinleştirilmeden çalışmaz")
        return self._run(mode, addr, abstain_allowed, deadline_sec)

    # --- yürütme çatısı -----------------------------------------------------------------------

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        if not self._lock.acquire(blocking=False):
            raise AgentBusy("ajan başka bir görev yürütüyor")
        try:
            yield
        finally:
            self._lock.release()

    def _run(self, mode: str, addr: str, abstain_allowed: bool, deadline_sec: Optional[float]) -> TaskResult:
        with self._exclusive():
            self._task_seq += 1
            # İptal görev başınadır: önceki görevin (ya da görev yokken kurulmuş) iptali bu görevi bitirmez.
            self.cancel.clear()
            self._running = True
            t0 = self._clock()
            if deadline_sec is None:
                deadline_sec = self.default_time_budget_sec(mode)
            # Adres alanına yalnız biçimi doğrulanmış değer yazılır (çağıranın verdiği ham dizgi değil).
            shown = addr if isinstance(addr, str) and _ADDR_RE.fullmatch(addr) else None
            task = _Task(TaskResult(task_id=f"g{self._task_seq}", mode=mode, task=TASK_NAME, addr=shown,
                                    status="", blind=self.blind_target, time_budget_sec=deadline_sec),
                         deadline=t0 + deadline_sec)
            try:
                try:
                    # Olay: görev açıldı (tasarım v2 §3.3 adım 1). Hedef çözülemiyorsa adres ve fn None.
                    self._emit("gorev_basladi", task, gorev_turu=TASK_NAME, kip=mode,
                               hedef=self._target(self.workspace.resolve(addr)),
                               butce={"arac": max_calls_for(mode), "sure_sn": deadline_sec,
                                      "jeton": self.context_tokens if mode == MODE_K0 else self.loop_context_tokens})
                    if mode == MODE_K0:
                        self._execute_k0(task, addr, abstain_allowed)
                    else:
                        self._execute_loop(task, mode, addr, abstain_allowed)
                except WorkspaceError as e:
                    task.finish(STATUS_PACKAGE_ERROR, str(e), override=True)
            except BaseException as e:
                # Beklenmeyen hata ya da kesme: sunucu açık kalmasın (tasarım §2.2 "her hata yolunda").
                # Kapatma ve kayıt hataları asıl hatayı örtmez.
                task.finish(STATUS_UNEXPECTED, type(e).__name__, override=True)
                for step in (lambda: self.backend.stop("hata"), lambda: self._close(task, t0)):
                    try:
                        step()
                    except Exception:  # noqa: BLE001
                        pass
                raise
            finally:
                self._running = False
            self._close(task, t0)
            return task.result

    def _close(self, task: _Task, t0: float) -> None:
        r = task.result
        r.duration_sec = round(self._clock() - t0, 3)
        r.result_ids = tuple(x.id for x in task.results)
        r.truncated_ids = tuple(x.id for x in task.results if x.truncated is not None)
        if self.audit is not None and r.guard is not None:
            # Tasarım §5.4 "Denetim": kural bulguları ve hüküm. Ad, gerekçe ve ikili metni yazılmaz.
            self.audit.write("denetim", gorev=r.task_id, hukum=r.verdict, bulgular=r.guard["bulgular"],
                             bayraklar=r.guard["bayraklar"], toplu_kabul=r.guard["toplu_kabul"],
                             sinanmayan=r.guard["sinanmayan"])
        if self.audit is not None:
            self.audit.write("gorev", kimlik=r.task_id, kip=r.mode, tur=r.task, adres=r.addr, durum=r.status,
                             ad_durumu=r.name_status, hata=r.error, sayaclar=asdict(r.counters),
                             kestirim_istem_jetonu=r.est_prompt_tokens, kod_kirpildi=r.code_clipped,
                             kirpilan_sonuclar=list(r.truncated_ids), icerik_adsiz=r.empty_content,
                             kor=r.blind, sure_sn=r.duration_sec, sure_butcesi_sn=r.time_budget_sec,
                             istem_surumu=PROMPT_VERSION, hukum=r.verdict,
                             arac_kumesi=self.registry.version(), onek_sha256=self.prefix_sha256(r.mode))
        # Olaylar, denetim günlüğünden SONRA (geri çağrının hatası kaydı yarım bırakmaz). Denetim olayı
        # dört değerli hükmü ve koşmayan kuralları (``sinanmayan``) taşır: ``sinanamadi`` temiz gösterilmez.
        if r.guard is not None:
            self._emit("denetim", task, nesne=r.task_id, **{k: r.guard[k] for k in (
                "hukum", "bulgular", "bayraklar", "toplu_kabul", "sinanan", "sinanmayan")})
        self._emit("gorev_bitti", task, durum=r.status, hata=r.error, ad_durumu=r.name_status, cevap=r.answer,
                   hukum=r.verdict, toplu_kabul=r.guard["toplu_kabul"] if r.guard is not None else None,
                   sayaclar=asdict(r.counters), sure_ms=int(round(r.duration_sec * 1000)))

    # --- araçlar ------------------------------------------------------------------------------

    def _new_result_id(self) -> str:
        self._result_seq += 1
        return f"r{self._result_seq}"

    def _call_key(self, tool: str, args: Any) -> tuple[str, str]:
        """Tekrar tespitinin anahtarı: araç + öntanımları doldurulmuş, adresi tek yazıma çevrilmiş
        argümanlar. ``FUN_1000`` ile ``FUN_00001000`` aynı çağrıdır."""
        spec = self.registry.spec(tool)
        norm = dict(spec.defaults) if spec is not None else {}
        if isinstance(args, dict):
            # ``2.0`` ile ``2`` aynı çağrıdır (LM-07; araç da aynı biçime çevirir).
            norm.update(normalize_args(args, spec.args_schema) if spec is not None else args)
            a = self.workspace.resolve(norm.get("addr"))
            if a is not None:
                norm["addr"] = f"FUN_{a}"
        return tool, canonical_json(norm)

    def _log_tool(self, task: _Task, result: ToolResult, args: Any, caller: str, duration: float) -> None:
        if self.audit is None:
            return
        spec = self.registry.spec(result.tool)
        valid = spec is not None and isinstance(args, dict) and not protocol.validate(args, spec.args_schema)
        # Şemaya uymayan argüman model çıktısıdır (veri); kayda girmez.
        self.audit.write("arac_cagrisi", gorev=task.result.task_id, cagiran=caller,
                         argumanlar=args if valid else None, gecerli=valid, sure_sn=round(duration, 4),
                         **result.audit_fields())

    def _run_tool(self, task: _Task, tool: str, args: Any, ctx: ToolContext, caller: str) -> ToolResult:
        """Aracı çalıştırır, denetim kaydını yazar. ``arac_basladi`` olayı burada; ``arac_bitti`` çağıran
        sonucun son hâline (körlük / bağlam kararından sonra) karar verince yayılır (``_tool_done``)."""
        rid = self._new_result_id()
        self._tool_started(task, rid, tool, args, caller, runs=True)
        t = self._clock()
        result = self.registry.call(self.workspace, tool, args, result_id=rid, ctx=ctx)
        duration = self._clock() - t
        task.tool_ms[rid] = int(round(duration * 1000))
        self._log_tool(task, result, args, caller, duration)
        return result

    def _build_package(self, task: _Task, a: str, *, single_shot: bool) -> Optional[list[ToolResult]]:
        """Fonksiyon paketi: kanıt + kod (tasarım §4.3). Kurulamazsa görev biter ve ``None`` döner."""
        ctx = ToolContext(single_shot=single_shot, blind_target=a if self.blind_target else None)
        package: list[ToolResult] = []
        for tool, args in (("get_evidence", {"addr": f"FUN_{a}"}),
                           ("get_decompiled", {"addr": f"FUN_{a}", "part": "bas"})):
            result = self._run_tool(task, tool, args, ctx, CALLER_SERVER)
            self._tool_done(task, result)
            task.result.counters.package_calls += 1
            task.seen.add(self._call_key(tool, args))
            if not result.ok:
                task.finish(STATUS_PACKAGE_ERROR, f"{tool}:{result.error}")
                return None
            package.append(result)
        evidence, code = package
        task.results.extend(package)
        task.result.code_clipped = code.truncated is not None
        task.result.empty_content = evidence.data["apis"] == "none" and evidence.data["strings"] == "none"
        if self.blind_target and self._blind_leak(evidence, a):
            task.finish(STATUS_BLIND_LEAK)
            return None
        return package

    def _blind_leak(self, result: ToolResult, a: str) -> bool:
        """Körlük taraması (K-K1): sonucun ad taşıyabilen alanlarında hedefin Karadul adı tam sözcük
        olarak geçiyor mu? Dizgi ve kod alanları taranmaz (pilot_protokolu.md §12 madde 3-4)."""
        hidden = self.workspace.raw_name(a)
        if not hidden or not result.ok:
            return False
        data = result.data or {}
        texts = [data[k] for k in _BLIND_SCANNED if isinstance(data.get(k), str)]
        texts += [x.get("name_tag") or "" for x in data.get("items", []) if isinstance(x, dict)]
        return blind_leaks(texts, [hidden]) > 0

    # --- model çağrısı ------------------------------------------------------------------------

    def _memory_stopped(self) -> bool:
        tripped = self.memory_guard is not None and self.memory_guard.tripped is not None
        return tripped or self.backend.state == STATE_MEMORY_STOPPED

    def _check_memory(self, task: _Task) -> None:
        if self.memory_guard is not None:
            sample = self.memory_guard.check()
            if sample is not None:
                task.result.memory = sample.as_dict()
            if self.memory_guard.tripped is not None:
                task.result.memory = self.memory_guard.tripped.as_dict()
                task.finish(STATUS_MEMORY, override=True)
        if self.backend.state == STATE_MEMORY_STOPPED:
            task.finish(STATUS_MEMORY, override=True)

    def _model_call(self, task: _Task, messages: list[dict[str, str]], schema: dict[str, Any],
                    purpose: str, est: Optional[int] = None) -> Optional[ChatResult]:
        """Tek model isteği; ardından bellek bekçisi. Arka uç hatasında görev biter, ``None`` döner.

        Olaylar: her istek denemesi bir ``model_istegi`` ve bir ``model_cevabi`` üretir. Cevap gelip
        görev sürüyorsa ``model_cevabi`` çağıran ayrıştırdıktan sonra yayılır (``_reply_done``); hata,
        iptal ve bellek durumunda burada. ``est`` ajanın istem kestirimidir (gerçek sayı cevaptadır)."""
        if self._memory_stopped():
            # Bellek nedeniyle durmuş sunucu kendiliğinden yeniden başlatılmaz: istek atılmaz. Yeniden
            # denemek için arka uç açıkça başlatılır ve yeni bir bekçi kurulur.
            task.finish(STATUS_MEMORY)
            return None
        # İptal ve süre her model isteğinden önce bakılır (K0'ın ilk isteği ve onarım turu dahil; LM-06).
        # Süren istek kesilmez: tek sınırı isteğin soket zaman aşımıdır.
        if self.cancel.is_set():
            task.finish(STATUS_CANCELLED)
            return None
        if task.deadline is not None and self._clock() > task.deadline:
            task.finish(STATUS_TIMEOUT)
            return None
        c = task.result.counters
        reply: Optional[ChatResult] = None
        attempt = 0
        while True:
            c.model_calls += 1
            amac = purpose if attempt == 0 else f"{purpose}_yineleme"
            self._emit("model_istegi", task, amac=amac, istem_kestirim=est)
            sink = _TokenSink(self, task) if self.stream else None
            t = self._clock()
            try:
                # Arka uca listenin kopyası gider: geçmiş sonradan uzasa da gönderilen istek değişmez.
                reply = self.backend.chat(list(messages), schema=schema, max_tokens=MAX_TOKENS_STEP,
                                          purpose=amac, stream=self.stream,
                                          on_token=sink.on_token if sink is not None else None)
            except _StreamStop as stop:
                # Parça başına iptal / süre: akış kesildi, bağlantı kapandı; cevap yok.
                sure_ms = int(round((self._clock() - t) * 1000))
                sink.flush()
                task.finish(stop.status)
                self._reply_failed(task, amac, sure_ms, stop.status, None)
            except LMError as e:
                sure_ms = int(round((self._clock() - t) * 1000))
                if sink is not None:
                    sink.flush()
                if self._may_retry(task, e, attempt):
                    shown = f"{type(e).__name__}: {e}"
                    self._reply_failed(task, amac, sure_ms, STATUS_BACKEND_ERROR,
                                       self.audit.redact(shown) if self.audit is not None else shown)
                    attempt += 1
                    c.retries += 1
                    continue
                text = f"{type(e).__name__}: {e}"
                if attempt:
                    text += f" (yineleme {attempt}/{MODEL_RETRY_MAX} sonrası)"
                task.finish(STATUS_BACKEND_ERROR, self.audit.redact(text) if self.audit is not None else text)
                self._reply_failed(task, amac, sure_ms, STATUS_BACKEND_ERROR, task.result.error)
            except BaseException as e:
                # Beklenmeyen hata / kesme: istek olayı eşsiz kalmasın. Olay yayımının hatası asıl hatayı
                # örtmez (``_run`` arka ucu durdurur ve hatayı yükseltir).
                try:
                    if sink is not None:
                        sink.flush()
                    self._reply_failed(task, amac, int(round((self._clock() - t) * 1000)), STATUS_UNEXPECTED,
                                       type(e).__name__)
                except Exception:  # noqa: BLE001
                    pass
                raise
            if reply is not None and sink is not None:
                sink.flush()
            break
        sure_ms = int(round((self._clock() - t) * 1000))
        self._check_memory(task)
        if reply is None:
            return None
        task.result.finish_reason = reply.finish_reason
        task.result.prompt_tokens = reply.prompt_tokens
        task.result.completion_tokens = reply.completion_tokens
        c.prompt_tokens += reply.prompt_tokens or 0
        c.completion_tokens += reply.completion_tokens or 0
        if task.done:
            # Cevap geldi ama bellek bekçisi görevi bitirdi: cevap ayrıştırılmaz.
            self._reply_failed(task, amac, sure_ms, task.result.status, None, reply)
            return None
        task.reply_meta = (amac, sure_ms)
        return reply

    def _may_retry(self, task: _Task, error: LMError, attempt: int) -> bool:
        """Geçici arka uç hatasından sonra istek yinelenir mi (LM-02)? Yalnız bağlantı kopması / okuma
        zaman aşımı / kesik akışta, bütçe kalmışsa, sunucu hata ya da bellek nedeniyle durmamışsa (ölmüş
        yerel sunucu kendiliğinden yeniden yüklenmez), iptal yoksa ve süre bütçesi dolmamışsa."""
        if not (isinstance(error, BackendError) and error.transient) or attempt >= MODEL_RETRY_MAX:
            return False
        if self.backend.state in (STATE_ERROR, STATE_MEMORY_STOPPED) or self._memory_stopped():
            return False
        if self.cancel.is_set():
            return False
        return task.deadline is None or self._clock() <= task.deadline

    def _level(self, task: _Task) -> Optional[str]:
        level = self.backend.capabilities().level
        if level not in protocol.CAPABILITY_LEVELS:
            task.finish(STATUS_LEVEL_UNKNOWN)
            return None
        return level

    def _accept(self, task: _Task, obj: dict[str, Any], reply: ChatResult, abstain_allowed: bool, a: str) -> None:
        refs: list[str] = []
        for i in obj["kanit"]:
            if i not in refs:
                refs.append(i)
        task.result.answer = {"isim": obj["isim"], "gerekce": obj["gerekce"], "cekimser": obj["cekimser"],
                              "kanit": refs}
        # Pilotun puanlayıcısının göreceği durum sınıfı (K-P1: aynı ayrıştırıcı).
        task.result.name_status = protocol.parse_name_answer(
            reply.content, reply.finish_reason, abstain_allowed=abstain_allowed, address=a)["durum"]
        self._audit_answer(task, a)
        task.finish(STATUS_DONE)

    # --- denetim katmanı (tasarım §5) -----------------------------------------------------------

    def _audit_answer(self, task: _Task, a: str) -> None:
        """Cevabı model dışı denetimden geçirir; hüküm ve bulgular sonuca yazılır (LM-01, LM-03)."""
        answer = task.result.answer or {}
        ws = self.workspace
        related = [x[4:] for x in self._neighbours(a)]
        report = guard.check_proposal(
            answer, [r.envelope() for r in task.results], target=a, target_tag=ws.name_tag(a),
            existing_functions=ws.existing_function_names(), own_ghidra_name=ws.ghidra_name(a),
            assigned_names=ws.assigned_names(), related=related, empty_content=task.result.empty_content,
            session_names=self._session_names, rejected=self.rejected_names.get(a, ()))
        task.result.verdict = report.verdict
        task.result.guard = report.as_dict()
        name = answer.get("isim")
        if isinstance(name, str) and not answer.get("cekimser") and report.acceptable:
            self._session_names.setdefault(name.casefold(), a)

    def _protected(self, task: _Task, a: str) -> bool:
        """D2 ön denetimi: hedefin adı ``kesin`` ya da elle verilmişse model çağrılmaz. Körlük kipinde
        (ölçüm) uygulanmaz: hedefin adı orada sunucu tarafında bile örneklemi değiştirmemeli; cevap yine
        denetlenir ve D2 ``ret`` hükmü sonuca yazılır."""
        if self.blind_target:
            return False
        tag = self.workspace.name_tag(a)
        if tag is None or tag[1] not in guard.PROTECTED_TAGS:
            return False
        report = guard.protected_report(tag[1])
        task.result.verdict = report.verdict
        task.result.guard = report.as_dict()
        task.finish(STATUS_PROTECTED, f"D2: hedefin adı '{tag[1]}' etiketli; öneri istenmez")
        return True

    # --- K0 -----------------------------------------------------------------------------------

    def _execute_k0(self, task: _Task, addr: str, abstain_allowed: bool) -> None:
        a = self.workspace.resolve(addr)
        if a is None:
            return task.finish(STATUS_UNKNOWN_ADDRESS)
        task.result.addr = f"FUN_{a}"
        if self._protected(task, a):
            return None
        level = self._level(task)
        if level is None:
            return None
        package = self._build_package(task, a, single_shot=True)
        if package is None:
            return None
        # D0 (tasarım §5.2): paket boşsa (ithal çağrı yok, dizgi yok) çekimser eki kullanılır.
        abstain_allowed = abstain_allowed or task.result.empty_content
        ids = [r.id for r in package]
        system = self.prefix(MODE_K0)
        question = name_question(f"FUN_{a}", ids, abstain_allowed=abstain_allowed)
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": user_message([r.wrapped() for r in package], question)}]
        est = (estimate_text_tokens(system) + estimate_text_tokens(question)
               + sum(estimate_result_tokens(r.envelope()) for r in package))
        task.result.est_prompt_tokens = est
        if not ContextBudget(self.context_tokens, MAX_TOKENS_STEP).fits(est):
            # Sessiz kırpma yok: görev başlamadan reddedilir (tasarım §2.3 "Bağlam").
            return task.finish(STATUS_CONTEXT)
        # İptal ve süre model isteğinden hemen önce bakılır (``_model_call``; LM-06).
        schema = protocol.build_name_answer_schema(ids, abstain_allowed=abstain_allowed)
        repairs = 0
        while True:
            reply = self._model_call(task, messages, schema, "k0" if repairs == 0 else "k0_onarim", est)
            if reply is None:
                return None
            parsed = protocol.parse_turn(reply.content, reply.finish_reason, schema)
            self._reply_done(task, reply, parsed.status, parsed.obj)
            action = protocol.next_action(level, parsed, repairs)
            if action == protocol.ACTION_ACCEPT:
                return self._accept(task, parsed.obj, reply, abstain_allowed, a)
            if action != protocol.ACTION_REPAIR:
                return task.finish(parsed.status)
            repairs += 1
            task.result.counters.repairs += 1
            messages = messages + [
                {"role": "assistant", "content": safe_assistant_content(reply.content, parsed.obj)},
                protocol.repair_message(parsed)]

    # --- döngü (K1 / K2) ----------------------------------------------------------------------

    def _neighbours(self, a: str) -> list[str]:
        """K1'in kapalı adres listesi: hedef ve paketindeki komşular (tasarım §2.3)."""
        pack = self.workspace.packs.get(a)
        found = {a}
        if pack is not None:
            raw = list(pack.internal_callees) + list(pack.callers)
            raw += [r.get("target") for r in pack.callback_registrations]
            raw += [r.get("registrar") for r in pack.registered_as_callback]
            for x in raw:
                c = self.workspace.resolve(f"FUN_{x}") if isinstance(x, str) else None
                if c is not None:
                    found.add(c)
        return [f"FUN_{x}" for x in sorted(found, key=lambda x: int(x, 16))]

    def _execute_loop(self, task: _Task, mode: str, addr: str, abstain_allowed: bool) -> None:
        a = self.workspace.resolve(addr)
        if a is None:
            return task.finish(STATUS_UNKNOWN_ADDRESS)
        task.result.addr = f"FUN_{a}"
        if self._protected(task, a):
            return None
        level = self._level(task)
        if level is None:
            return None
        package = self._build_package(task, a, single_shot=False)
        if package is None:
            return None
        abstain_allowed = abstain_allowed or task.result.empty_content
        tool_schemas = self.registry.schemas(self._neighbours(a) if mode == MODE_K1 else None)
        max_calls = max_calls_for(mode)
        ctx = ToolContext(single_shot=False, blind_target=a if self.blind_target else None)
        system = self.prefix(mode)
        question = name_question(f"FUN_{a}", [r.id for r in package], abstain_allowed=abstain_allowed,
                                 final_kind=True)
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": user_message([r.wrapped() for r in package], question)}]
        prompt_est = (estimate_text_tokens(system) + estimate_text_tokens(question)
                      + sum(estimate_result_tokens(r.envelope()) for r in package))
        task.result.est_prompt_tokens = prompt_est
        budget = ContextBudget(self.loop_context_tokens, MAX_TOKENS_STEP)
        if not budget.fits(prompt_est):
            return task.finish(STATUS_CONTEXT)
        c = task.result.counters
        tool_tokens = 0             # araç sonuçları dilimi (paket hariç)
        forced_final = False        # bütçe bitti: model yalnız son cevabı verebilir
        repairs = 0
        while True:
            # İptal ve süre her turun model isteğinden önce ``_model_call``'da bakılır (LM-06).
            finals = protocol.name_answer_branches([r.id for r in task.results if r.ok],
                                                   abstain_allowed=abstain_allowed)
            schema = protocol.build_task_envelope({} if forced_final else tool_schemas, finals,
                                                  protocol.NAME_ANSWER_REQUIRED)
            reply = self._model_call(task, messages, schema, "dongu" if repairs == 0 else "dongu_onarim",
                                     prompt_est)
            if reply is None:
                return None
            parsed = protocol.parse_turn(reply.content, reply.finish_reason, schema)
            self._reply_done(task, reply, parsed.status, parsed.obj)
            action = protocol.next_action(level, parsed, repairs)
            if action == protocol.ACTION_REPAIR:
                repairs += 1
                c.repairs += 1
                messages.append({"role": "assistant", "content": safe_assistant_content(reply.content, parsed.obj)})
                messages.append(protocol.repair_message(parsed))
                continue
            if action != protocol.ACTION_ACCEPT:
                # Bütçe bittikten sonra son cevap gelmediyse görev bütçeyle bitmiştir (K-A3).
                return task.finish(STATUS_BUDGET if forced_final else parsed.status)
            repairs = 0
            obj = parsed.obj
            messages.append({"role": "assistant", "content": safe_assistant_content(reply.content, obj)})
            if obj["kind"] == "final":
                return self._accept(task, obj, reply, abstain_allowed, a)
            # --- araç çağrısı ---
            tool, args = obj["tool"], obj["args"]
            c.call_requests += 1
            key = self._call_key(tool, args)
            if c.call_requests > max_calls:
                result = error_result(self._new_result_id(), tool, ERR_BUDGET)
                self._tool_started(task, result.id, tool, args, CALLER_MODEL, runs=False)
                c.budget_exceeded += 1
                forced_final = True
                self._log_tool(task, result, args, CALLER_MODEL, 0.0)
            elif key in task.seen:
                result = error_result(self._new_result_id(), tool, ERR_REPEAT)
                self._tool_started(task, result.id, tool, args, CALLER_MODEL, runs=False)
                c.repeats += 1
                self._log_tool(task, result, args, CALLER_MODEL, 0.0)
            else:
                task.seen.add(key)
                result = self._run_tool(task, tool, args, ctx, CALLER_MODEL)
                c.tool_calls += 1
                if result.error in INVALID_CALL_ERRORS:
                    c.invalid_calls += 1
                if self.blind_target and self._blind_leak(result, a):
                    # Körlük: hedefin adını taşıyan sonuç modele verilmez.
                    result = error_result(result.id, tool, ERR_TOOL_CLOSED, executed=True)
                    c.blind_blocked += 1
                cost = estimate_result_tokens(result.envelope())
                real = (reply.prompt_tokens + reply.completion_tokens
                        if reply.prompt_tokens is not None and reply.completion_tokens is not None else None)
                # Uç gerçek sayıyı verdiyse o şişirilmez; yalnız kestirilen kısım paylanır (B-E2).
                fits = budget.fits(cost, real) if real is not None else budget.fits(prompt_est + cost)
                if tool_tokens + cost > BUDGET_TOOL_RESULTS_TOKENS or not fits:
                    # Sonuç bağlama sığmıyor: sessizce kırpılmaz, verilmez; model son cevabı verir.
                    result = error_result(result.id, tool, ERR_BUDGET, executed=True)
                    c.context_exceeded += 1
                    forced_final = True
                else:
                    tool_tokens += cost
            # Olay: modelin gördüğü sonuç (körlük / bağlam kararından sonraki hâli).
            self._tool_done(task, result)
            task.results.append(result)
            messages.append({"role": "user", "content": result.wrapped()})
            prompt_est += estimate_text_tokens(reply.content) + estimate_result_tokens(result.envelope())
