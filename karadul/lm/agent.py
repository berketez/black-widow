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
her görev de birer kayıttır (K-L1). Her model çağrısından sonra bellek bekçisi denetlenir. Arka uç
hatası (``LMError``) görevi ``arka_uc_hatasi`` ile bitirir, ajan yeni göreve hazır kalır. Beklenmeyen
her hata ve kesmede arka uç ``hata`` nedeniyle durdurulur (yetim süreç kalmaz) ve hata yükselir.
"""
from __future__ import annotations

import re
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Iterator, Optional

from karadul.lm import (
    BUDGET_TOOL_RESULTS_TOKENS, CONTEXT_TOKENS, CONTEXT_TOKENS_K2, MAX_TOKENS_STEP, TIME_BUDGET_FACTOR, protocol,
)
from karadul.lm.audit import AuditLog, canonical_json, sha256_text
from karadul.lm.backend import STATE_MEMORY_STOPPED, Backend, ChatResult, LMError
from karadul.lm.context import (
    MODE_K0, MODE_K1, MODE_K2, MODES, PROMPT_VERSION, ContextBudget, blind_leaks, estimate_result_tokens,
    estimate_text_tokens, fixed_prefix, max_calls_for, name_question, safe_assistant_content, user_message,
)
from karadul.lm.memory_guard import MemoryGuard
from karadul.lm.tools import (
    ADDR_PATTERN, ERR_BUDGET, ERR_REPEAT, ERR_TOOL_CLOSED, INVALID_CALL_ERRORS, ToolContext, ToolRegistry,
    ToolResult, Workspace, WorkspaceError, default_registry, error_result,
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
# Ayrıca protocol.parse_turn durumları: gecersiz, sema_ihlali, butce_asimi (üretim tavanı), ret.

TASK_NAME = "ad_oner"
CALLER_SERVER, CALLER_MODEL = "sunucu", "model"
# Körlük taramasına giren kanıt alanları: ad taşıyabilenler. Dizgi alanı girmez (pilot §12 madde 4:
# aynı adın dizgi sabiti olarak geçmesi meşru kanıttır).
_BLIND_SCANNED = ("apis", "callees", "callers", "callbacks_given", "callback_of")
_ADDR_RE = re.compile(ADDR_PATTERN)


class ModeDisabled(LMError):
    """K1 / K2 açıkça etkinleştirilmeden çalıştırılmak istendi."""


class AgentBusy(LMError):
    """Ajan başka bir görev yürütürken ikinci görev istendi (tek yuva, tasarım §2.3 "Sıra")."""


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
    prompt_tokens: int = 0          # uçtan gelen gerçek sayıların toplamı
    completion_tokens: int = 0


@dataclass
class TaskResult:
    """Bir görevin sonucu. ``answer`` yalnız ``status == "tamam"`` iken doludur."""

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

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class _Task:
    """Yürüyen görevin iç durumu."""

    result: TaskResult
    results: list[ToolResult] = field(default_factory=list)
    seen: set[tuple[str, str]] = field(default_factory=set)
    done: bool = False

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
                 clock: Callable[[], float] = time.monotonic, cancel: Optional[threading.Event] = None):
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
        self.cancel = cancel if cancel is not None else threading.Event()
        self._clock = clock
        self._lock = threading.Lock()
        self._result_seq = 0
        self._task_seq = 0

    # --- sabit önek ---------------------------------------------------------------------------

    def prefix(self, mode: str) -> str:
        """Kipin sabit öneki (sistem iletisi)."""
        return fixed_prefix(mode, self.registry.definition_lines())

    def prefix_sha256(self, mode: str) -> str:
        return sha256_text(self.prefix(mode))

    # --- dış arayüz ---------------------------------------------------------------------------

    def suggest_name(self, addr: str, *, abstain_allowed: bool = True) -> TaskResult:
        """K0 "ad öner": paket kur → model tek çağrı → ayrıştır → sonuç."""
        if MODE_K0 not in self.enabled_modes:
            raise ModeDisabled("K0 bu ajanda etkin değil")
        return self._run(MODE_K0, addr, abstain_allowed, None)

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
            t0 = self._clock()
            # Adres alanına yalnız biçimi doğrulanmış değer yazılır (çağıranın verdiği ham dizgi değil).
            shown = addr if isinstance(addr, str) and _ADDR_RE.fullmatch(addr) else None
            task = _Task(TaskResult(task_id=f"g{self._task_seq}", mode=mode, task=TASK_NAME, addr=shown,
                                    status="", blind=self.blind_target))
            try:
                try:
                    if mode == MODE_K0:
                        self._execute_k0(task, addr, abstain_allowed)
                    else:
                        self._execute_loop(task, mode, addr, abstain_allowed,
                                           None if deadline_sec is None else t0 + deadline_sec)
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
            self._close(task, t0)
            return task.result

    def _close(self, task: _Task, t0: float) -> None:
        r = task.result
        r.duration_sec = round(self._clock() - t0, 3)
        r.result_ids = tuple(x.id for x in task.results)
        r.truncated_ids = tuple(x.id for x in task.results if x.truncated is not None)
        if self.audit is not None:
            self.audit.write("gorev", kimlik=r.task_id, kip=r.mode, tur=r.task, adres=r.addr, durum=r.status,
                             ad_durumu=r.name_status, hata=r.error, sayaclar=asdict(r.counters),
                             kestirim_istem_jetonu=r.est_prompt_tokens, kod_kirpildi=r.code_clipped,
                             kirpilan_sonuclar=list(r.truncated_ids), icerik_adsiz=r.empty_content,
                             kor=r.blind, sure_sn=r.duration_sec, istem_surumu=PROMPT_VERSION,
                             arac_kumesi=self.registry.version(), onek_sha256=self.prefix_sha256(r.mode))

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
            norm.update(args)
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
        t = self._clock()
        result = self.registry.call(self.workspace, tool, args, result_id=self._new_result_id(), ctx=ctx)
        self._log_tool(task, result, args, caller, self._clock() - t)
        return result

    def _build_package(self, task: _Task, a: str, *, single_shot: bool) -> Optional[list[ToolResult]]:
        """Fonksiyon paketi: kanıt + kod (tasarım §4.3). Kurulamazsa görev biter ve ``None`` döner."""
        ctx = ToolContext(single_shot=single_shot, blind_target=a if self.blind_target else None)
        package: list[ToolResult] = []
        for tool, args in (("get_evidence", {"addr": f"FUN_{a}"}),
                           ("get_decompiled", {"addr": f"FUN_{a}", "part": "bas"})):
            result = self._run_tool(task, tool, args, ctx, CALLER_SERVER)
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
                    purpose: str) -> Optional[ChatResult]:
        """Tek model isteği; ardından bellek bekçisi. Arka uç hatasında görev biter, ``None`` döner."""
        c = task.result.counters
        c.model_calls += 1
        reply: Optional[ChatResult] = None
        try:
            # Arka uca listenin kopyası gider: geçmiş sonradan uzasa da gönderilen istek değişmez.
            reply = self.backend.chat(list(messages), schema=schema, max_tokens=MAX_TOKENS_STEP,
                                      purpose=purpose)
        except LMError as e:
            text = f"{type(e).__name__}: {e}"
            task.finish(STATUS_BACKEND_ERROR, self.audit.redact(text) if self.audit is not None else text)
        self._check_memory(task)
        if reply is None:
            return None
        task.result.finish_reason = reply.finish_reason
        task.result.prompt_tokens = reply.prompt_tokens
        task.result.completion_tokens = reply.completion_tokens
        c.prompt_tokens += reply.prompt_tokens or 0
        c.completion_tokens += reply.completion_tokens or 0
        return None if task.done else reply

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
        task.finish(STATUS_DONE)

    # --- K0 -----------------------------------------------------------------------------------

    def _execute_k0(self, task: _Task, addr: str, abstain_allowed: bool) -> None:
        a = self.workspace.resolve(addr)
        if a is None:
            return task.finish(STATUS_UNKNOWN_ADDRESS)
        task.result.addr = f"FUN_{a}"
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
        if self.cancel.is_set():
            return task.finish(STATUS_CANCELLED)
        schema = protocol.build_name_answer_schema(ids, abstain_allowed=abstain_allowed)
        repairs = 0
        while True:
            reply = self._model_call(task, messages, schema, "k0" if repairs == 0 else "k0_onarim")
            if reply is None:
                return None
            parsed = protocol.parse_turn(reply.content, reply.finish_reason, schema)
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

    def _execute_loop(self, task: _Task, mode: str, addr: str, abstain_allowed: bool,
                      deadline: Optional[float]) -> None:
        a = self.workspace.resolve(addr)
        if a is None:
            return task.finish(STATUS_UNKNOWN_ADDRESS)
        task.result.addr = f"FUN_{a}"
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
            if self.cancel.is_set():
                return task.finish(STATUS_CANCELLED)
            if deadline is not None and self._clock() > deadline:
                return task.finish(STATUS_TIMEOUT)
            finals = protocol.name_answer_branches([r.id for r in task.results if r.ok],
                                                   abstain_allowed=abstain_allowed)
            schema = protocol.build_task_envelope({} if forced_final else tool_schemas, finals,
                                                  protocol.NAME_ANSWER_REQUIRED)
            reply = self._model_call(task, messages, schema, "dongu" if repairs == 0 else "dongu_onarim")
            if reply is None:
                return None
            parsed = protocol.parse_turn(reply.content, reply.finish_reason, schema)
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
                c.budget_exceeded += 1
                forced_final = True
                self._log_tool(task, result, args, CALLER_MODEL, 0.0)
            elif key in task.seen:
                result = error_result(self._new_result_id(), tool, ERR_REPEAT)
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
                now = real if real is not None else prompt_est
                if tool_tokens + cost > BUDGET_TOOL_RESULTS_TOKENS or not budget.fits(now + cost):
                    # Sonuç bağlama sığmıyor: sessizce kırpılmaz, verilmez; model son cevabı verir.
                    result = error_result(result.id, tool, ERR_BUDGET, executed=True)
                    c.context_exceeded += 1
                    forced_final = True
                else:
                    tool_tokens += cost
            task.results.append(result)
            messages.append({"role": "user", "content": result.wrapped()})
            prompt_est += estimate_text_tokens(reply.content) + estimate_result_tokens(result.envelope())
