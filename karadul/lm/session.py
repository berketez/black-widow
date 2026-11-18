"""KaradulLM oturumu: yaşam döngüsü, kipler, izin, kuyruk, iptal / devam (KaradulLM v2 tasarımı §3.4, §3.8, §3.9,
§3.11, §4.3 G6; P22e kalem 1 ve 7).

**Tek oturum.** Süreçte aynı anda tek oturum vardır (``open_session``; ikincisi ``SessionExists``: "oturum zaten
açık"). Oturum arayüz sunucusunun sürecinde bir nesnedir; yeni süreç açmaz (tek alt süreç, arka ucun
``llama-server``'ıdır ve ``modes.check_server_binary``'den geçmiş bir yolla kurulur). Arayüz kapanınca oturum
onunla ölür; ``close`` arka ucu da durdurur.

**Yaşam döngüsü:** ``open_session`` → ``oturum_basladi`` olayı + devam satırı (defter ve özet deposundan
gerçek sayılar) → ``submit(satır)`` (terminal girdisi; ``repl.parse``'ın kapalı kümesi) → işler sıralı bir
kuyrukta, tek iş parçacığında yürür (tek yuva) → ``cancel`` (``/durdur``) → ``close(neden)`` → ``oturum_bitti``.

**Analizle dışlama** (G6; paket kalemi 1): ``analysis_running()`` doğru dönerken (aynı çalışma alanında analiz
sürüyor; arayüzün ``_running_job``'ı) oturum **model başlatmaz ve yazma yapmaz**: model işleri, not, öneri
kaydı ve karar reddedilir; kuyruktaki iş başlamadan önce de yeniden bakılır. Okuma komutları (yardım,
öneriler, sonuç açma, plan kurma) çalışır.

**İptal** (§3.11; P21 görev başına iptal, P22b zincir iptali): ``cancel`` kuyruğu ve onay bekleyen işi
boşaltır, süren görevi ``Agent.cancel_current`` ile durdurur (zincirin kalanı da açılmaz; planın kalan
adımları da). ``iptal`` olayını OTURUM yayar (ajan yaymaz; P22a kuralı): kaynak ``analist`` ya da ``kapanis``.
İptal edilen işten sonra arka ucun durumu ``health()``'ten okunup yazılır (sunucunun gerçekten durup
durmadığı ölçülmedi, Z8).

**Devam** (§3.11): sohbet geçmişi taşınmaz. Aynı ikilinin defteri (bekleyen öneriler, reddedilen adlar →
D10) ve özet deposu (anahtarı aynı özet yeniden hesaplanmaz; yarıda kalmış zincir yeniden açılınca bitmiş
düğümler depodan gelir) yüklenir.

**Öneriler**: model yalnız öneri açar; kip izin vermiyorsa (``PermissionPolicy.may_propose``) açılmaz. Öneri
deftere ``oneri`` kaydıyla (bekleyen) yazılır ve ``oneri`` olayı yayılır. Kabul / ret terminalden değil, öneri
kartından ve yalnız öneri kimliğiyle gelir (``decide``); kabulde D1 ve D2 yeniden koşar. Ad haritasına ya da
deponun model bölümüne yazmak (``uygula``) bu modülün işi değildir (P22c, P17).

Bu modül süreç başlatmaz (durağan sınama ``tests/test_lm_izin.py``); dosya yalnız ``~/.karadul/lm/<sha>/``
altında, defter / özet / içerik depoları üstünden yazılır.
"""
from __future__ import annotations

import json
import secrets
import threading
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from karadul.lm import guard, probe
from karadul.lm.agent import STATUS_DONE, Agent, ExplainRun, TaskResult
from karadul.lm.audit import _HEX64, _SESSION_ID, now_iso, sha256_text
from karadul.lm.backend import Backend
from karadul.lm.events import ContentStore, EventStream
from karadul.lm.modes import (
    DEFAULT_MODE, LONG_JOB_ASK, LONG_JOB_DENIED, PROPOSAL_COMMENT, PROPOSAL_NAME, SESSION_MODES, PermissionPolicy,
    Plan, PlanError, build_plan, mode_spec, validate_plan,
)
from karadul.lm.notebook import REC_ACCEPT, REC_PROPOSAL, REC_REJECT, Notebook, NotebookError, NoteRecord
from karadul.lm.order import bottom_up_layers
from karadul.lm.repl import (
    CMD_APPROVE, CMD_EXIT, CMD_EXPLAIN, CMD_FOLLOW, CMD_HELP, CMD_MODE, CMD_NAME, CMD_NOTE, CMD_OPEN, CMD_PLAN,
    CMD_PROPOSALS, CMD_QUESTION, CMD_SPEED, CMD_STOP, CMD_SUMMARY, HELP_LINES, PLAN_TASK_EXPLAIN, Command, InputError,
    check_text, parse,
)
from karadul.lm.summaries import SummaryStore
from karadul.lm.tools import MODE_EXPLAIN, MODE_NAME, MODE_PLAN, Workspace, WorkspaceError

# Kapanışta yürüyen işin bitmesi için beklenen en uzun süre (sn) [bu iş]. Akışlı istek iptali her parçada
# denetler (P22a); parça gelmiyorsa arka uç ``stop`` ile kapatılır ve istek hata ile biter.
CLOSE_JOIN_SEC = 30.0
JOB_EXPLAIN, JOB_SUMMARY, JOB_NAME, JOB_PLAN, JOB_SPEED = "acikla", "ozet", "ad", "plan", "hiz"
CANCEL_ANALYST, CANCEL_CLOSING = "analist", "kapanis"
CLOSE_EXIT, CLOSE_UI, CLOSE_WORKSPACE, CLOSE_IDLE = "cik", "arayuz_kapandi", "calisma_alani_degisti", "bosta"
DECIDE_ACCEPT, DECIDE_REJECT = "kabul", "ret"
_REASON_ANALYSIS = "analiz sürüyor: oturum model başlatmaz ve yazma yapmaz"


class SessionError(RuntimeError):
    """Oturum açılamadı ya da istek oturum kuralına uymuyor (ileti Türkçe)."""


class SessionExists(SessionError):
    """Süreçte zaten açık bir oturum var (tek oturum; §4.3 G6)."""


_SLOT_LOCK = threading.Lock()
_ACTIVE: Optional["Session"] = None


def current_session() -> Optional["Session"]:
    with _SLOT_LOCK:
        return _ACTIVE if _ACTIVE is not None and not _ACTIVE.closed else None


def new_session_id() -> str:
    return "o" + secrets.token_hex(6)


def workspace_binary_sha256(root: Path) -> Optional[str]:
    """Çalışma alanının KENDİ kaydındaki ikili özeti (``ui/server.py::_workspace_target_hash`` ile aynı sıra:
    ``reports/report.json`` → ``target.hash``; ``raw/target_info.json`` → ``file_hash``; ``raw/`` altındaki tek
    ikilinin sha256'sı). Defter ve depoların dizini bu özettir: arayüz ve CLI aynı dizini kullanmalı.
    Bulunamazsa ``None`` (uydurulmaz)."""
    import hashlib
    base = Path(root)

    def field_(p: Path, *keys: str) -> Optional[str]:
        try:
            v: Any = json.loads(p.read_text(encoding="utf-8"))
            for k in keys:
                v = v[k]
            return v if isinstance(v, str) and v else None
        except (OSError, ValueError, KeyError, TypeError):
            return None

    h = field_(base / "reports" / "report.json", "target", "hash") or field_(base / "raw" / "target_info.json",
                                                                             "file_hash")
    if not h:
        raw = base / "raw"
        bins = [p for p in raw.iterdir() if p.is_file() and p.name != "target_info.json"] if raw.is_dir() else []
        if len(bins) == 1:
            hh = hashlib.sha256()
            try:
                with open(bins[0], "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        hh.update(chunk)
                h = hh.hexdigest()
            except OSError:
                h = None
    h = h.lower() if isinstance(h, str) else None
    return h if h is not None and _HEX64.fullmatch(h) else None


@dataclass
class _Job:
    """Kuyruktaki iş. ``kip``: izinlerin değerlendirildiği kip (öneri türü buradan)."""

    kimlik: str
    tur: str
    kip: str
    hedef: Optional[str] = None
    derinlik: Optional[int] = None
    plan: Optional[Plan] = None


def open_session(workspace_root: Path, *, backend: Optional[Backend], binary_sha256: str,
                 **kwargs: Any) -> "Session":
    """Tek oturumu açar. Süreçte açık bir oturum varsa ``SessionExists``. Argümanlar ``Session``'ınkiler."""
    global _ACTIVE
    with _SLOT_LOCK:
        if _ACTIVE is not None and not _ACTIVE.closed:
            raise SessionExists("oturum zaten açık")
        s = Session(workspace_root, backend=backend, binary_sha256=binary_sha256, **kwargs)
        _ACTIVE = s
    try:
        s._start()
    except BaseException:
        s.close(CLOSE_EXIT)
        raise
    return s


class Session:
    """Bir KaradulLM oturumu (``open_session`` ile açılır). İş parçacığı güvenlidir: ``submit``, ``cancel``,
    ``decide``, ``close`` arayüzün istek iş parçacıklarından çağrılabilir; işler tek bir iç iş parçacığında
    sırayla yürür."""

    def __init__(self, workspace_root: Path, *, backend: Optional[Backend], binary_sha256: str,
                 session_id: Optional[str] = None, mode: str = DEFAULT_MODE,
                 policy: Optional[PermissionPolicy] = None,
                 analysis_running: Optional[Callable[[], bool]] = None, store_root: Optional[Path] = None,
                 expected_task_sec: Optional[float] = None, network_enabled: bool = False,
                 network_consent: bool = False):
        if not isinstance(binary_sha256, str) or not _HEX64.fullmatch(binary_sha256):
            raise SessionError("geçersiz ikili sha256 (64 küçük harfli onaltılık basamak beklenir)")
        sid = session_id if session_id is not None else new_session_id()
        if not isinstance(sid, str) or not _SESSION_ID.fullmatch(sid):
            raise SessionError("geçersiz oturum kimliği")
        if mode not in SESSION_MODES:
            raise SessionError(f"bilinmeyen kip: {mode!r}")
        try:
            self.workspace = Workspace(Path(workspace_root))
        except WorkspaceError as e:
            raise SessionError(f"çalışma alanı açılamadı: {e}") from None
        self.workspace_root = Path(workspace_root)
        self.id = sid
        self.binary_sha256 = binary_sha256
        self.mode = mode
        self.policy = policy if policy is not None else PermissionPolicy()
        self._analysis_running = analysis_running if analysis_running is not None else (lambda: False)
        self.network_enabled = network_enabled
        self.network_consent = network_consent
        self.stream = EventStream(sid)
        self.notebook = Notebook(binary_sha256, root=store_root)
        self.summary_store = SummaryStore(binary_sha256, root=store_root)
        self.content_store = ContentStore(binary_sha256, sid, root=store_root)
        self.backend = backend
        self.audit = backend.audit if backend is not None else None
        self.agent: Optional[Agent] = None
        if backend is not None:
            self.agent = Agent(backend, self.workspace, on_event=self._agent_event, content_store=self.content_store,
                               summary_store=self.summary_store, expected_task_sec=expected_task_sec)
        self.follow = True
        self.speed: Optional[dict[str, Any]] = None
        self._cond = threading.Condition()
        self._jobs: deque[_Job] = deque()
        self._pending: Optional[_Job] = None
        self._current: Optional[_Job] = None
        self._stop = threading.Event()
        self._closed = False
        self._job_seq = 0
        self._worker: Optional[threading.Thread] = None
        self._backend_state: Optional[str] = None
        # Defter yazımları (öneri, not, karar) tek kilit altında: aynı öneriye iki istekten aynı anda
        # karar yazılamasın, öneri kimliği yinelenmesin (istek iş parçacıkları + iş parçacığı).
        self._nb_lock = threading.Lock()

    # --- olaylar ------------------------------------------------------------------------------

    @property
    def closed(self) -> bool:
        with self._cond:
            return self._closed

    def _agent_event(self, tur: str, /, gorev: Optional[str] = None, **fields: Any) -> None:
        self.stream.emit(tur, gorev=gorev, **fields)

    def _emit(self, tur: str, gorev: Optional[str] = None, **fields: Any) -> None:
        if not self.stream.closed:
            self.stream.emit(tur, gorev=gorev, **fields)

    def _line(self, text: str, level: str = "bilgi") -> None:
        self._emit("satir", metin=text, duzey=level)

    def _target(self, a: Optional[str]) -> Optional[dict[str, Optional[str]]]:
        return None if a is None else {"fn": self.workspace.ui_name(a), "adres": a}

    def _uses_network(self) -> bool:
        return getattr(self.backend, "loopback", True) is False

    def _backend_state_event(self) -> None:
        if self.backend is None:
            return
        st = self.backend.state
        if st != self._backend_state:
            self._backend_state = st
            self._emit("arka_uc_durumu", durum=st, bellek_gib=None)

    def _audit(self, event: str, **fields: Any) -> None:
        if self.audit is not None:
            self.audit.write(event, oturum=self.id, **fields)

    # --- açılış / kapanış ---------------------------------------------------------------------

    def _model_label(self) -> Optional[str]:
        if self.backend is None:
            return None
        ident = self.backend.identity()
        name = ident.get("model")
        if not isinstance(name, str) or not name:
            return None
        sha = ident.get("model_sha256")
        return Path(name).name + (f" · {sha[:12]}" if isinstance(sha, str) and sha else "")

    def _start(self) -> None:
        self._emit("oturum_basladi", kip=self.mode, model=self._model_label(),
                   arka_uc=self.backend.kind if self.backend is not None else "yok",
                   baglam=self.agent.context_tokens if self.agent is not None else None,
                   ag="açık" if self._uses_network() else "kapalı", hiz=None)
        self._line(self.policy.line(self.mode))
        self._backend_state_event()
        self._audit("oturum_acildi", kip=self.mode)
        if self.backend is None:
            self._line("model yok (arka uç verilmedi): yalnız plan, not, öneri listesi ve sonuç açma çalışır",
                       "uyari")
        self._resume_line()
        self._worker = threading.Thread(target=self._work, name=f"karadullm-{self.id}", daemon=True)
        self._worker.start()

    def _resume_line(self) -> None:
        try:
            recs = self.notebook.records()
            pending = len(self.notebook.pending())
            sums = len(self.summary_store.records())
        except OSError as e:
            self._line(f"defter ya da özet deposu okunamadı: {e}", "hata")
            return
        if self.agent is not None:
            for a, names in self.notebook.rejected_names().items():
                self.agent.rejected_names.setdefault(a, set()).update(names)
        if not recs and not sums:
            self._line("bu ikili için defter ve özet deposu boş")
        else:
            last = self.notebook.last_time()
            self._line(f"devam: {pending} bekleyen öneri, {sums} özet kaydı, {len(recs)} defter kaydı"
                       + (f", son defter kaydı {last}" if last else ""))
        bad = (self.notebook.corrupt_lines, self.summary_store.corrupt_lines)
        if any(bad):
            self._line(f"bozuk satır atlandı: defter {bad[0]}, özet deposu {bad[1]}", "uyari")

    def close(self, neden: str = CLOSE_EXIT) -> None:
        """Oturumu kapatır: kuyruk boşalır, süren iş iptal edilir (``iptal`` kaynak ``kapanis``), arka uç
        durur, ``oturum_bitti`` yayılır, akış kapanır. İkinci çağrı etkisizdir."""
        global _ACTIVE
        with self._cond:
            if self._closed:
                return
            running = self._current is not None
            self._closed = True
            self._jobs.clear()
            self._pending = None
            self._stop.set()
            self._cond.notify_all()
        if running:
            self._emit("iptal", kaynak=CANCEL_CLOSING)
            if self.agent is not None:
                self.agent.cancel_current()
        w = self._worker
        if w is not None and w is not threading.current_thread():
            w.join(CLOSE_JOIN_SEC)
        if self.backend is not None:
            try:
                self.backend.stop("cikis")
            except Exception:  # noqa: BLE001 — kapanış hatası oturumun kapanmasını engellemez
                self._line("arka uç durdurulurken hata", "hata")
            self._backend_state_event()
        self._audit("oturum_kapandi", neden=neden)
        self._emit("oturum_bitti", neden=neden)
        self.stream.close()
        with _SLOT_LOCK:
            if _ACTIVE is self:
                _ACTIVE = None

    # --- girdi --------------------------------------------------------------------------------

    def submit(self, text: Any) -> dict[str, Any]:
        """Terminal satırı. Dönüş: ``{"kabul": bool, "is": iş kimliği | None, "hata": ileti | None}``.
        Reddedilen satır terminale de ``satir`` olayı (hata) olarak düşer."""
        if self.closed:
            return {"kabul": False, "is": None, "hata": "oturum kapalı"}
        try:
            cmd = parse(text, self.mode)
        except InputError as e:
            self._audit("girdi", komut=None, gecerli=False, uzunluk=len(text) if isinstance(text, str) else None,
                        sha256=sha256_text(text) if isinstance(text, str) else None)
            return self._refuse(str(e))
        self._audit("girdi", komut=cmd.ad, gecerli=True, uzunluk=len(text), sha256=sha256_text(text))
        handler = getattr(self, f"_cmd_{cmd.ad}")
        return handler(cmd)

    def _refuse(self, msg: str, level: str = "hata") -> dict[str, Any]:
        self._line(msg, level)
        return {"kabul": False, "is": None, "hata": msg}

    def _ok(self, job: Optional[str] = None) -> dict[str, Any]:
        return {"kabul": True, "is": job, "hata": None}

    def _busy(self) -> bool:
        with self._cond:
            return self._current is not None or bool(self._jobs)

    def _model_refusal(self, task_mode: str) -> Optional[str]:
        if self.agent is None:
            return "model yok (arka uç verilmedi)"
        if self._analysis_running():
            return _REASON_ANALYSIS
        if self._uses_network() and not self.policy.network_allowed(task_mode, enabled=self.network_enabled,
                                                                   consent=self.network_consent):
            return f"bu kipte ağ üstündeki model ucu kullanılamaz ({self.policy.decide('ag', task_mode)})"
        return None

    def _new_job(self, tur: str, kip: str, **kw: Any) -> _Job:
        with self._cond:
            self._job_seq += 1
            return _Job(f"i{self._job_seq}", tur, kip, **kw)

    def _enqueue(self, job: _Job) -> dict[str, Any]:
        with self._cond:
            if self._closed:
                return {"kabul": False, "is": None, "hata": "oturum kapalı"}
            self._jobs.append(job)
            waiting = len(self._jobs) - 1 + (1 if self._current is not None else 0)
            self._cond.notify_all()
        self._line(f"iş {job.kimlik} kuyrukta" + (f" (önünde {waiting} iş)" if waiting else ""))
        return self._ok(job.kimlik)

    def _cmd_yardim(self, cmd: Command) -> dict[str, Any]:
        for s in HELP_LINES:
            self._line(s)
        self._line(self.policy.line(self.mode))
        return self._ok()

    def _cmd_kip(self, cmd: Command) -> dict[str, Any]:
        if self._busy():
            return self._refuse("görev sürerken kip değişmez (önce /durdur ya da bitmesini bekleyin)", "uyari")
        assert cmd.kip in SESSION_MODES
        self.mode = cmd.kip
        self._line(self.policy.line(self.mode))
        return self._ok()

    def _resolve(self, hedef: Optional[str]) -> Optional[str]:
        return self.workspace.resolve(hedef)

    def _task_job(self, cmd: Command, tur: str) -> dict[str, Any]:
        if self.mode == MODE_PLAN:
            return self._refuse("plan kipinde işler /plan ve /onayla ile açılır", "uyari")
        if tur == JOB_NAME and self.mode != MODE_NAME:
            return self._refuse("ad önerisi adlandır kipinde: /kip adlandir", "uyari")
        task_mode = MODE_NAME if tur == JOB_NAME else self.mode
        why = self._model_refusal(task_mode)
        if why is not None:
            return self._refuse(why, "uyari")
        a = self._resolve(cmd.hedef)
        if a is None:
            return self._refuse(f"{cmd.hedef}: çalışma alanında böyle bir fonksiyon yok")
        job = self._new_job(tur, task_mode, hedef=f"FUN_{a}", derinlik=cmd.derinlik)
        if tur == JOB_NAME:
            return self._enqueue(job)
        n = sum(len(layer) for layer in bottom_up_layers(self.workspace.call_edges, a, cmd.derinlik or 0))
        if n <= 1:
            return self._enqueue(job)
        return self._gate_long(job, n)

    def _expected(self, tasks: int) -> Optional[float]:
        e = self.agent.expected_task_sec if self.agent is not None else None
        return tasks * float(e) if isinstance(e, (int, float)) and not isinstance(e, bool) and e > 0 else None

    def _gate_long(self, job: _Job, tasks: int, *, always_ask: bool = False) -> dict[str, Any]:
        expected = self._expected(tasks)
        decision = self.policy.long_job(job.kip, expected)
        if decision == LONG_JOB_DENIED:
            return self._refuse("uzun iş bu kipte kapalı (izin politikası)", "uyari")
        if decision == LONG_JOB_ASK or always_ask:
            with self._cond:
                self._pending = job
            sure = f"beklenen süre en çok ≈ {expected:.0f} sn" if expected is not None else \
                "hız ölçülmedi: beklenen süre yok (/hiz)"
            self._line(f"iş {job.kimlik} en çok {tasks} görev açabilir; {sure}. Başlatmak için /onayla", "uyari")
            return self._ok(job.kimlik)
        return self._enqueue(job)

    def _cmd_acikla(self, cmd: Command) -> dict[str, Any]:
        return self._task_job(cmd, JOB_EXPLAIN)

    def _cmd_ozet(self, cmd: Command) -> dict[str, Any]:
        return self._task_job(cmd, JOB_SUMMARY)

    def _cmd_ad(self, cmd: Command) -> dict[str, Any]:
        return self._task_job(cmd, JOB_NAME)

    def _cmd_plan(self, cmd: Command) -> dict[str, Any]:
        if self.mode != MODE_PLAN:
            return self._refuse("plan plan kipinde kurulur: /kip plan", "uyari")
        if self._busy():
            return self._refuse("görev sürerken yeni plan kurulmaz", "uyari")
        e = self.agent.expected_task_sec if self.agent is not None else None
        try:
            plan = build_plan(self.workspace, cmd.plan_turu or "", cmd.metin or "", cmd.plan_gorevi or "",
                              expected_task_sec=e)
        except PlanError as err:
            return self._refuse(f"plan kurulamadı: {err}")
        errs = validate_plan(plan.as_dict(), self.workspace)
        if errs:
            return self._refuse("plan doğrulanamadı: " + "; ".join(errs))
        self._line(f"plan: {plan.gerekce}")
        for i, s in enumerate(plan.adimlar, 1):
            self._line(f"  {i}. {'açıkla' if s['gorev'] == PLAN_TASK_EXPLAIN else 'ad öner'} {s['hedef']}"
                       f" (en çok {s['gorev_ust_siniri']} görev)")
        self._line(f"toplam: {len(plan.adimlar)} adım, en çok {plan.gorev_ust_siniri} görev, "
                   f"{plan.ayrik_fonksiyon} ayrık fonksiyon")
        job = self._new_job(JOB_PLAN, MODE_PLAN, plan=plan)
        return self._gate_long(job, plan.gorev_ust_siniri, always_ask=True)

    def _cmd_onayla(self, cmd: Command) -> dict[str, Any]:
        with self._cond:
            job = self._pending
        if job is None:
            return self._refuse("onay bekleyen iş yok", "uyari")
        modes = ({MODE_NAME if s["gorev"] != PLAN_TASK_EXPLAIN else MODE_EXPLAIN for s in job.plan.adimlar}
                 if job.plan is not None else {job.kip})
        for m in sorted(modes):
            why = self._model_refusal(m)
            if why is not None:
                return self._refuse(why, "uyari")
        with self._cond:
            self._pending = None
        self._audit("onay", is_kimligi=job.kimlik, tur=job.tur)
        return self._enqueue(job)

    def _cmd_durdur(self, cmd: Command) -> dict[str, Any]:
        self.cancel(CANCEL_ANALYST)
        return self._ok()

    def _cmd_oneriler(self, cmd: Command) -> dict[str, Any]:
        try:
            props = self.notebook.proposals()
        except OSError as e:
            return self._refuse(f"defter okunamadı: {e}")
        if not props:
            self._line("öneri yok")
        for p in props:
            self._line(f"{p['oneri_kimligi']} {p['durum']} · {p['oneri_turu']} FUN_{p['adres']} → \"{p['deger']}\""
                       f" · denetim {p.get('hukum')}" + (f" · neden: {p['neden']}" if p.get("neden") else ""))
        return self._ok()

    def _cmd_ac(self, cmd: Command) -> dict[str, Any]:
        try:
            obj = self.content_store.get_display(cmd.sonuc or "")
        except (OSError, ValueError) as e:
            return self._refuse(f"{cmd.sonuc} açılamadı: {e}")
        if obj is None:
            return self._refuse(f"{cmd.sonuc} bu oturumun içerik deposunda yok", "uyari")
        self._line(json.dumps(obj, ensure_ascii=False, sort_keys=True))
        return self._ok()

    def _cmd_not(self, cmd: Command) -> dict[str, Any]:
        if self._analysis_running():
            return self._refuse(_REASON_ANALYSIS, "uyari")
        a = self._resolve(cmd.hedef)
        if a is None:
            return self._refuse(f"{cmd.hedef}: çalışma alanında böyle bir fonksiyon yok")
        try:
            with self._nb_lock:
                self.notebook.note(self.id, a, cmd.metin or "")
        except (NotebookError, OSError) as e:
            return self._refuse(f"not yazılamadı: {e}")
        self._line(f"not deftere yazıldı: FUN_{a}")
        return self._ok()

    def _cmd_hiz(self, cmd: Command) -> dict[str, Any]:
        why = self._model_refusal(self.mode if self.mode != MODE_PLAN else MODE_EXPLAIN)
        if why is not None:
            return self._refuse(why, "uyari")
        return self._enqueue(self._new_job(JOB_SPEED, self.mode))

    def _cmd_takip(self, cmd: Command) -> dict[str, Any]:
        self.follow = bool(cmd.takip)
        self._line("takip açık" if self.follow else "takip kapalı")
        return self._ok()

    def _cmd_cik(self, cmd: Command) -> dict[str, Any]:
        self.close(CLOSE_EXIT)
        return self._ok()

    def _cmd_soru(self, cmd: Command) -> dict[str, Any]:
        return self._refuse("keşif sorusu görevi henüz bağlı değil (ajanda soru görevi yok); /acikla, /ozet, "
                            "/ad ya da /plan kullanın", "uyari")

    # --- iptal --------------------------------------------------------------------------------

    def cancel(self, kaynak: str = CANCEL_ANALYST) -> bool:
        """Süren işi ve kuyruğu durdurur; ``iptal`` olayını yayar. Durdurulacak bir şey yoksa ``False``."""
        with self._cond:
            if self._closed:
                return False
            dropped = len(self._jobs)
            self._jobs.clear()
            pending = self._pending is not None
            self._pending = None
            running = self._current is not None
            if running:
                self._stop.set()
        if running and self.agent is not None:
            self.agent.cancel_current()
        if not (running or dropped or pending):
            self._line("durdurulacak iş yok")
            return False
        self._emit("iptal", kaynak=kaynak)
        self._line(f"durduruldu: süren iş {'var' if running else 'yok'}, kuyruktan düşen {dropped}, "
                   f"onay bekleyen {1 if pending else 0}")
        return True

    # --- iş parçacığı -------------------------------------------------------------------------

    def _work(self) -> None:
        while True:
            with self._cond:
                while not self._jobs and not self._closed:
                    self._cond.wait()
                if self._closed:
                    return
                job = self._jobs.popleft()
                self._current = job
                self._stop.clear()
            try:
                self._run_job(job)
            except BaseException as e:  # noqa: BLE001 — iş hatası oturumu öldürmez; analiste yazılır
                try:
                    self._line(f"iş {job.kimlik} beklenmeyen hatayla bitti: {type(e).__name__}", "hata")
                except Exception:  # noqa: BLE001
                    pass
            finally:
                with self._cond:
                    self._current = None
                    self._cond.notify_all()
                try:
                    self._backend_state_event()
                except Exception:  # noqa: BLE001
                    pass

    def wait_idle(self, timeout: Optional[float] = None) -> bool:
        """Kuyruk boşalıp süren iş bitene kadar bekler (CLI ve testler). Zaman aşımında ``False``."""
        with self._cond:
            return self._cond.wait_for(lambda: self._closed or (self._current is None and not self._jobs), timeout)

    def _run_job(self, job: _Job) -> None:
        why = self._model_refusal(job.kip if job.kip != MODE_PLAN else MODE_EXPLAIN)
        if why is not None:
            self._line(f"iş {job.kimlik} başlatılmadı: {why}", "uyari")
            return
        assert self.agent is not None
        if job.tur == JOB_SPEED:
            return self._run_speed()
        if job.tur == JOB_PLAN:
            assert job.plan is not None
            n = len(job.plan.adimlar)
            for i, step in enumerate(job.plan.adimlar, 1):
                if self._stop.is_set() or self.closed:
                    self._line(f"plan durdu: {i - 1}/{n} adım bitti", "uyari")
                    return
                if self._analysis_running():
                    self._line(f"plan durdu ({_REASON_ANALYSIS}): {i - 1}/{n} adım bitti", "uyari")
                    return
                self._line(f"plan adımı {i}/{n}: {step['hedef']}")
                if step["gorev"] == PLAN_TASK_EXPLAIN:
                    self._run_explain(step["hedef"], step["derinlik"], MODE_EXPLAIN, propose=True)
                else:
                    self._run_name(step["hedef"], MODE_NAME)
            self._line(f"plan bitti: {n}/{n} adım")
            return
        if job.tur == JOB_NAME:
            return self._run_name(job.hedef or "", job.kip)
        self._run_explain(job.hedef or "", job.derinlik or 0, job.kip, propose=job.tur == JOB_EXPLAIN)

    def _after(self, stopped: Optional[str]) -> None:
        if stopped == "iptal" and self.backend is not None:
            try:
                h = self.backend.health()
                self._line(f"iptal sonrası sunucu durumu: {h.get('durum')}")
            except Exception as e:  # noqa: BLE001
                self._line(f"iptal sonrası sunucu durumu okunamadı: {type(e).__name__}", "uyari")

    def _run_explain(self, hedef: str, depth: int, task_mode: str, *, propose: bool) -> None:
        assert self.agent is not None
        run: ExplainRun = self.agent.explain(hedef, depth=depth)
        root = run.root_result
        if propose and root is not None and root.status == STATUS_DONE and root.summary is not None:
            s = root.summary
            if s.get("kaynak") == "model" and not s.get("belirsiz") and s.get("pakete_girer"):
                self._file_proposal(PROPOSAL_COMMENT, task_mode, root, s["metin"], None, list(s.get("kanit") or ()),
                                    s.get("hukum"))
            else:
                self._line("yorum önerisi açılmadı: özet belirsiz, modelsiz ya da denetimden geçmedi")
        self._after(run.stopped)

    def _run_name(self, hedef: str, task_mode: str) -> None:
        assert self.agent is not None
        r = self.agent.suggest_name(hedef)
        ans = r.answer or {}
        if r.status == STATUS_DONE and isinstance(ans.get("isim"), str) and not ans.get("cekimser"):
            if r.verdict == guard.VERDICT_REJECT:
                self._line("ad önerisi açılmadı: denetim RET", "uyari")
            else:
                self._file_proposal(PROPOSAL_NAME, task_mode, r, ans["isim"], ans.get("gerekce"),
                                    list(ans.get("kanit") or ()), r.verdict)
        self._after(r.status if r.status == "iptal" else None)

    def _file_proposal(self, kind: str, task_mode: str, r: TaskResult, value: str, reason: Optional[str],
                       refs: list[str], verdict: Optional[str]) -> None:
        with self._nb_lock:
            self._file_proposal_locked(kind, task_mode, r, value, reason, refs, verdict)

    def _file_proposal_locked(self, kind: str, task_mode: str, r: TaskResult, value: str,
                              reason: Optional[str], refs: list[str], verdict: Optional[str]) -> None:
        if not self.policy.may_propose(task_mode, kind):
            self._line(f"öneri açılmadı: {mode_spec(task_mode).label} kipinde {kind} önerisi yok")
            return
        if self._analysis_running():
            self._line(f"öneri deftere yazılmadı: {_REASON_ANALYSIS}", "uyari")
            return
        a = self.workspace.resolve(r.addr)
        if a is None:
            return
        try:
            pid = self.notebook.next_proposal_id()
            self.notebook.append(NoteRecord(REC_PROPOSAL, now_iso(), self.id, adres=a, oneri_kimligi=pid,
                                            oneri_turu=kind, deger=value, gerekce=reason, hukum=verdict,
                                            gorev=r.task_id))
        except (NotebookError, OSError) as e:
            self._line(f"öneri deftere yazılamadı: {e}", "uyari")
            return
        self._emit("oneri", gorev=r.task_id, oneri_kimligi=pid, hedef=self._target(a), oneri_turu=kind,
                   deger=value, gerekce=reason, kanit=refs, hukum=verdict)

    def _run_speed(self) -> None:
        assert self.backend is not None and self.agent is not None
        res = probe.run_probe(self.backend, audit=self.audit)
        t_hat = probe.expected_name_suggest_sec(res.prefill_tps, res.gen_tps, res.prefix_reuse)
        self.speed = {"P": res.prefill_tps, "G": res.gen_tps, "T": t_hat, "zaman": res.measured_at}
        if t_hat is None:
            self._line("hız ölçülemedi (uç P ya da G bildirmedi); beklenen süre hesaplanmaz", "uyari")
            return
        self.agent.expected_task_sec = t_hat
        self._line(f"hız: önek {res.prefill_tps:.1f} jeton/sn · üretim {res.gen_tps:.1f} jeton/sn · beklenen "
                   f"görev süresi ≈ {t_hat:.1f} sn ({res.measured_at})")

    # --- kararlar (öneri kartı; P22c) -----------------------------------------------------------

    def decide(self, proposal_id: str, decision: str, reason: Optional[str] = None) -> dict[str, Any]:
        """Analistin öneri kararı; ``_decide_locked``'u defter kilidi altında çağırır."""
        with self._nb_lock:
            return self._decide_locked(proposal_id, decision, reason)

    def _decide_locked(self, proposal_id: str, decision: str, reason: Optional[str]) -> dict[str, Any]:
        """Analistin öneri kararı (yalnız kimlikle). ``ret`` neden ister. ``kabul``de ad önerisi için D1 ve D2
        bugünkü çalışma alanıyla yeniden koşar (çift denetim); tutmazsa kabul yazılmaz. Dönüş:
        ``{"tamam": bool, "hata": ileti | None, "oneri": öneri kaydı | None}``. Ad haritasına / model
        bölümüne yazma burada YOK (P22c)."""
        def fail(msg: str) -> dict[str, Any]:
            return {"tamam": False, "hata": msg, "oneri": None}

        if self.closed:
            return fail("oturum kapalı")
        if self._analysis_running():
            return fail(_REASON_ANALYSIS)
        if decision not in (DECIDE_ACCEPT, DECIDE_REJECT):
            return fail("karar kabul ya da ret olmalı")
        try:
            p = self.notebook.proposal(proposal_id) if isinstance(proposal_id, str) else None
        except OSError as e:
            return fail(f"defter okunamadı: {e}")
        if p is None:
            return fail("böyle bir öneri yok")
        if p["durum"] != "bekleyen":
            return fail(f"öneri zaten karara bağlanmış: {p['durum']}")
        if decision == DECIDE_REJECT:
            try:
                check_text(reason if isinstance(reason, str) else "")
            except InputError as e:
                return fail(f"neden: {e}")
            if not isinstance(reason, str) or not reason.strip(" "):
                return fail("ret için neden zorunlu")
        else:
            findings = self._recheck(p)
            if findings:
                return fail("kabulde yeniden denetim: " + ", ".join(findings))
        try:
            self.notebook.append(NoteRecord(REC_ACCEPT if decision == DECIDE_ACCEPT else REC_REJECT, now_iso(),
                                            self.id, oneri_kimligi=proposal_id,
                                            neden=reason if decision == DECIDE_REJECT else None))
        except (NotebookError, OSError) as e:
            return fail(f"karar yazılamadı: {e}")
        if decision == DECIDE_REJECT and p["oneri_turu"] == PROPOSAL_NAME and self.agent is not None:
            self.agent.rejected_names.setdefault(p["adres"], set()).add(p["deger"])
        self._line(f"{proposal_id} {'kabul edildi' if decision == DECIDE_ACCEPT else 'reddedildi'}")
        return {"tamam": True, "hata": None, "oneri": self.notebook.proposal(proposal_id)}

    def _recheck(self, p: Mapping[str, Any]) -> list[str]:
        if p["oneri_turu"] != PROPOSAL_NAME:
            return []
        ws, a = self.workspace, p["adres"]
        rep = guard.check_proposal({"isim": p["deger"], "gerekce": p.get("gerekce") or "", "cekimser": False,
                                    "kanit": []}, [], target=a, target_tag=ws.name_tag(a),
                                   existing_functions=ws.existing_function_names(), own_ghidra_name=ws.ghidra_name(a),
                                   assigned_names=ws.assigned_names(), related=[a], empty_content=False,
                                   use_library=False)
        return [f"{f.rule} {f.code}" for f in rep.findings if f.rule in ("D1", "D2")]

    # --- durum (arayüz) -------------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        with self._cond:
            cur = self._current
            queued = len(self._jobs)
            pending = self._pending
        return {"oturum": self.id, "kip": self.mode, "kip_satiri": self.policy.line(self.mode),
                "arka_uc": self.backend.state if self.backend is not None else None, "model": self._model_label(),
                "hiz": self.speed, "ag": "açık" if self._uses_network() else "kapalı", "takip": self.follow,
                "calisan": None if cur is None else {"is": cur.kimlik, "tur": cur.tur, "hedef": cur.hedef},
                "kuyruk": queued, "onay_bekleyen": None if pending is None else {"is": pending.kimlik,
                                                                                  "tur": pending.tur},
                "kapali": self.closed, "son_olay": self.stream.last_seq}

    def result_content(self, result_id: str) -> Optional[dict[str, Any]]:
        """``/api/lm/sonuc``: araç sonucunun saklı içeriği (arındırılmış, kesilmemiş); yoksa ``None``."""
        return self.content_store.get_display(result_id)
