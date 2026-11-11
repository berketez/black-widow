"""KaradulLM arka uç soyutlaması (tasarım §2.1, §2.2, §6).

Arayüz (``Backend``): ``start``, ``stop``, ``health``, ``chat(messages, schema, stream)``,
``capabilities``, ``identity``. Üç gerçekleme:

- ``LlamaServerBackend``: yerel yalın ``llama-server``. Bayraklar pilotun komutudur
  (``scripts/measurement/llm_pilot.py:725-734``; eşitliği testle kilitli) + ``--api-key <rastgele>``;
  kapı boş bir loopback kapısıdır, sunucu yalnız ``127.0.0.1``'e bağlanır. Süreç ``process_group=0``
  ile açılır; ``start_new_session`` KULLANILMAZ: çok iş parçacıklı süreçte ``setsid`` yolu
  ``posix_spawn`` dışına düşüp macOS'ta ``fork`` kilitlenmesine yol açıyordu
  (``ui/server.py:1812-1818``). PID dosyası yazılır; her hata yolunda süreç kapatılır ve PID dosyası
  silinir. Başlatmada ikilinin ve sohbet şablonunun sha256'sı künyeye yazılır.
- ``OpenAIEndpointBackend``: kullanıcının OpenAI uyumlu ucu. Yetenek düzeyi (L1 / L2 / L3, tasarım
  §2.2) yoklamayla belirlenir; yoklanmadan şemalı istek atılmaz. Uç loopback değilse açık ağ onayı
  (``allow_network=True``) olmadan HİÇBİR istek atılmaz (tasarım §6.2 "Ağ kapalı öntanımı").
- ``FakeBackend``: testler için betikli sahte arka uç; gerçek model gerekmeden cevap, gecikme ve
  hata oynatır. Sonuç nesnesini ve denetim kaydını gerçek arka uçlarla aynı kod kurar.

Güvenlik: API anahtarı denetim günlüğüne, hata iletisine ve istisna metnine girmez (anahtar
``AuditLog.add_secret`` ile kaydedilir; hata metinleri ``_redact``'tan geçer). Loopback isteklerinde
vekil sunucu kullanılmaz; yönlendirme hiçbir istekte izlenmez (yönlendirme onay denetimini aşabilirdi).

Bu modül içe aktarıldığında süreç açmaz, ağa bağlanmaz.
"""
from __future__ import annotations

import atexit
import hashlib
import ipaddress
import json
import os
import secrets as _secrets
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Optional, Sequence

from karadul.lm import (
    CAPABILITY_PROBE_MAX_TOKENS, CONTEXT_TOKENS, ERROR_EXCERPT_CHARS, HEALTH_POLL_SEC,
    HEALTH_REQUEST_TIMEOUT_SEC, IDLE_SHUTDOWN_SEC, MAX_TOKENS_STEP, MODEL_SEED, READY_TIMEOUT_SEC,
    REQUEST_TIMEOUT_SEC, STOP_WAIT_SEC,
)
from karadul.lm import protocol
from karadul.lm.audit import REDACTED, AuditLog, canonical_json, now_iso, redact_text, redact_url, sha256_text

# Arka uç durumları (tasarım §7.6 /api/lm/status).
STATE_OFF = "kapali"
STATE_LOADING = "yukleniyor"
STATE_READY = "hazir"
STATE_BUSY = "mesgul"
STATE_MEMORY_STOPPED = "bellek_durdu"
STATE_ERROR = "hata"

# Durdurma nedenleri → son durum.
_STOP_STATE = {"bellek": STATE_MEMORY_STOPPED, "hata": STATE_ERROR}

_PID_FILE_NAME = "llama_server.pid"
_LOG_FILE_NAME = "llama_server.log"
_VERSION_TIMEOUT_SEC = 30
_KEY_BYTES = 32
_HASH_BLOCK = 1 << 22


class LMError(RuntimeError):
    """KaradulLM arka uç hatası (iletisi her zaman anahtardan arındırılmış)."""


class BackendError(LMError):
    pass


class HttpStatusError(BackendError):
    def __init__(self, status: int, excerpt: str):
        super().__init__(f"uç HTTP {status} döndü: {excerpt}")
        self.status = status
        self.excerpt = excerpt


class NetworkConsentRequired(LMError):
    """Loopback olmayan uca açık onay olmadan istek atılmak istendi."""


class CapabilityUnknown(LMError):
    """Yetenek düzeyi yoklanmadan şemalı istek atılmak istendi."""


# ---------------------------------------------------------------------------------------------
# Yardımcılar


def is_loopback_host(host: Optional[str]) -> bool:
    """Yalnız gerçek dönüş adresleri: ``127.0.0.0/8``, ``::1`` ve ``localhost``.

    Ad çözümlemesi yapılmaz: ``127.0.0.1.ornek.com`` gibi adlar loopback sayılmaz.
    """
    if not host:
        return False
    h = host.strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def find_free_port(host: str = "127.0.0.1") -> int:
    """Çekirdeğin verdiği boş bir loopback kapısı (soket hemen kapatılır)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


def new_api_key() -> str:
    """Her başlatmada yeni rastgele anahtar."""
    return _secrets.token_hex(_KEY_BYTES)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(_HASH_BLOCK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def build_llama_command(binary: Path, model_path: Path, port: int, api_key: str, *,
                        template_path: Optional[Path] = None, ctx_size: int = CONTEXT_TOKENS) -> list[str]:
    """Yerel sunucunun komutu: pilotun yalın bayrakları (``llm_pilot.LlamaSunucu.komut``,
    ``llm_pilot.py:725-734``; aynı sıra) ve sonunda ``--api-key``. Kapı ``127.0.0.1``'dedir."""
    k = [str(binary), "--model", str(model_path), "--host", "127.0.0.1",
         "--port", str(port), "--ctx-size", str(ctx_size), "--n-gpu-layers", "999", "--parallel", "1",
         "--jinja", "--flash-attn", "on", "--cache-ram", "0", "--ctx-checkpoints", "0",
         "--batch-size", "2048", "--ubatch-size", "512", "--threads", "10", "--cache-type-k", "f16",
         "--cache-type-v", "f16", "--load-mode", "mmap+mlock", "--reasoning-format", "deepseek",
         "--no-webui", "--seed", str(MODEL_SEED)]
    if template_path is not None:
        k += ["--chat-template-file", str(template_path)]
    return k + ["--api-key", api_key]


def redact_command(cmd: Sequence[str], api_key: Optional[str]) -> list[str]:
    return [REDACTED if (api_key and part == api_key) else part for part in cmd]


def _int_or_none(v: Any) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _check_messages(messages: Any) -> list[dict[str, Any]]:
    if not isinstance(messages, list) or not messages:
        raise ValueError("iletiler boş olmayan liste olmalı")
    for m in messages:
        if not isinstance(m, dict) or not isinstance(m.get("role"), str) or not isinstance(m.get("content"), str):
            raise ValueError("her ileti {'role': str, 'content': str} olmalı")
    return messages


# ---------------------------------------------------------------------------------------------
# Sonuç ve yetenek


@dataclass(frozen=True)
class Capabilities:
    level: Optional[str]            # "L1" | "L2" | "L3" | None (yoklanmadı)
    level_source: Optional[str]     # düzeyin nereden bilindiği
    streaming: bool
    local_process: bool             # süreç bu arka uç tarafından başlatılıp durduruluyor mu
    memory_guard: bool              # bellek bekçisi uygulanır mı
    network: bool                   # uç loopback dışında mı

    def as_dict(self) -> dict[str, Any]:
        return {"duzey": self.level, "duzey_kaynagi": self.level_source, "akis": self.streaming,
                "yerel_surec": self.local_process, "bellek_bekcisi": self.memory_guard, "ag": self.network}


@dataclass
class ChatResult:
    """Bir model isteğinin sonucu. Süreler saniye; ilk / son jeton zamanı isteğin başlangıcına göre
    (yalnız akışta ve en az bir içerik parçası geldiyse dolu)."""

    content: str
    finish_reason: Optional[str]
    usage: Optional[dict]
    timings: Optional[dict]
    duration_sec: float
    first_token_sec: Optional[float]
    last_token_sec: Optional[float]
    content_events: int
    stream: bool
    request_meta: dict
    messages_sha256: str
    messages_bytes: int
    started_at: str = field(default_factory=now_iso)

    @property
    def prompt_tokens(self) -> Optional[int]:
        return _int_or_none((self.usage or {}).get("prompt_tokens"))

    @property
    def completion_tokens(self) -> Optional[int]:
        return _int_or_none((self.usage or {}).get("completion_tokens"))

    @property
    def cached_tokens(self) -> Optional[int]:
        """``usage.prompt_tokens_details.cached_tokens``; uç bildirmiyorsa ``None``."""
        details = (self.usage or {}).get("prompt_tokens_details")
        return _int_or_none(details.get("cached_tokens")) if isinstance(details, dict) else None

    def audit_fields(self) -> dict[str, Any]:
        """Denetim kaydı: içerik değil, özetleri (tasarım §5.4)."""
        body = self.content.encode("utf-8")
        return {"istek": self.request_meta, "iletiler_sha256": self.messages_sha256,
                "iletiler_bayt": self.messages_bytes, "usage": self.usage, "timings": self.timings,
                "bitis": self.finish_reason, "sure_sn": round(self.duration_sec, 3),
                "ilk_jeton_sn": self.first_token_sec, "son_jeton_sn": self.last_token_sec,
                "akis": self.stream, "icerik_parca": self.content_events,
                "cevap_sha256": hashlib.sha256(body).hexdigest(), "cevap_bayt": len(body),
                "baslangic": self.started_at}


def messages_digest(messages: list[dict[str, Any]]) -> tuple[str, int]:
    """İletilerin kanonik JSON özeti ve bayt uzunluğu (iletilerin kendisi kayda girmez)."""
    text = canonical_json(messages)
    return sha256_text(text), len(text.encode("utf-8"))


# ---------------------------------------------------------------------------------------------
# HTTP katmanı (standart kitaplık)


@dataclass
class HttpResponse:
    status: int
    lines: Iterator[bytes]
    read: Callable[[], bytes]
    close: Callable[[], None]


Transport = Callable[[str, str, Mapping[str, str], Optional[bytes], float], HttpResponse]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Yönlendirme izlenmez: loopback ucun uzak bir makineye yönlendirmesi onay denetimini aşardı."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401, ANN001
        raise urllib.error.HTTPError(req.full_url, code, "yönlendirme izlenmez", headers, fp)


def _opener(loopback: bool) -> urllib.request.OpenerDirector:
    handlers: list[Any] = [_NoRedirect()]
    if loopback:
        handlers.append(urllib.request.ProxyHandler({}))   # loopback isteği vekile gitmez
    return urllib.request.build_opener(*handlers)


def urllib_transport(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes],
                     timeout: float) -> HttpResponse:
    host = urllib.parse.urlsplit(url).hostname
    req = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    try:
        resp = _opener(is_loopback_host(host)).open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        try:
            excerpt = e.read(ERROR_EXCERPT_CHARS * 4).decode("utf-8", "replace")[:ERROR_EXCERPT_CHARS]
        except (OSError, AttributeError):
            excerpt = ""
        raise HttpStatusError(e.code, excerpt) from None
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", None)
        raise BackendError(f"uca bağlanılamadı ({type(e).__name__}: {reason if reason is not None else e})") from None
    return HttpResponse(status=resp.status, lines=iter(resp), read=resp.read, close=resp.close)


def read_sse(lines: Iterable[bytes], clock: Callable[[], float], t0: float,
             on_token: Optional[Callable[[str], None]] = None) -> dict[str, Any]:
    """OpenAI uyumlu akışı (``data: {...}`` satırları, ``data: [DONE]`` sonu) okur.

    İçerik parçalarının geldiği an ``clock``'la ölçülür; ilk ve son içerik parçasının ``t0``'a göre
    süresi döner. ``usage`` ve ``timings`` hangi parçada gelirse alınır (genelde sonuncusu).
    """
    pieces: list[str] = []
    out: dict[str, Any] = {"finish_reason": None, "usage": None, "timings": None,
                           "first": None, "last": None, "events": 0}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(b":") or not line.startswith(b"data:"):
            continue
        data = line[5:].strip()
        if data == b"[DONE]":
            break
        try:
            chunk = json.loads(data)
        except json.JSONDecodeError:
            raise BackendError("akış parçası çözülemedi") from None
        if not isinstance(chunk, dict):
            raise BackendError("akış parçası nesne değil")
        if "error" in chunk:
            raise BackendError(f"uç akışta hata bildirdi: {str(chunk['error'])[:ERROR_EXCERPT_CHARS]}")
        if isinstance(chunk.get("usage"), dict):
            out["usage"] = chunk["usage"]
        if isinstance(chunk.get("timings"), dict):
            out["timings"] = chunk["timings"]
        choices = chunk.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            continue
        delta = choices[0].get("delta") or {}
        piece = delta.get("content") if isinstance(delta, dict) else None
        if isinstance(piece, str) and piece:
            now = clock() - t0
            if out["first"] is None:
                out["first"] = now
            out["last"] = now
            out["events"] += 1
            pieces.append(piece)
            if on_token is not None:
                on_token(piece)
        if choices[0].get("finish_reason"):
            out["finish_reason"] = choices[0]["finish_reason"]
    out["content"] = "".join(pieces)
    return out


def parse_completion(body: bytes) -> dict[str, Any]:
    """Akışsız cevap: ``choices[0].message.content``, bitiş nedeni, ``usage``, ``timings``."""
    try:
        d = json.loads(body)
    except json.JSONDecodeError:
        raise BackendError("uç cevabı JSON değil") from None
    if not isinstance(d, dict):
        raise BackendError("uç cevabı nesne değil")
    if "error" in d:
        raise BackendError(f"uç hata bildirdi: {str(d['error'])[:ERROR_EXCERPT_CHARS]}")
    choice = (d.get("choices") or [{}])[0]
    msg = choice.get("message") if isinstance(choice, dict) else None
    content = msg.get("content") if isinstance(msg, dict) else None
    return {"content": content if isinstance(content, str) else "",
            "finish_reason": choice.get("finish_reason") if isinstance(choice, dict) else None,
            "usage": d.get("usage") if isinstance(d.get("usage"), dict) else None,
            "timings": d.get("timings") if isinstance(d.get("timings"), dict) else None}


class _OpenAIClient:
    """OpenAI uyumlu ``/chat/completions`` istemcisi (yerel ve kullanıcı ucu ortak)."""

    def __init__(self, chat_url: str, api_key: Optional[str], model_name: str, transport: Transport,
                 redact: Callable[[str], str], *, thinking_control: bool,
                 clock: Callable[[], float] = time.monotonic):
        self.chat_url = chat_url
        self.api_key = api_key
        self.model_name = model_name
        self.transport = transport
        self.redact = redact
        self.thinking_control = thinking_control
        self.clock = clock

    def headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def build_body(self, messages: list[dict[str, Any]], response_format: Optional[dict], stream: bool,
                   max_tokens: int) -> dict[str, Any]:
        """Çözme ayarları pilotun düşünmesiz gövdesiyle aynı (``llm_pilot.LlamaSunucu.govde``,
        ``llm_pilot.py:737-747``): sıcaklık 0, tohum, üretim tavanı, düşünme kapalı."""
        body: dict[str, Any] = {"model": self.model_name, "messages": messages, "temperature": 0,
                                "seed": MODEL_SEED, "max_tokens": max_tokens, "stream": stream}
        if self.thinking_control:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        if stream:
            body["stream_options"] = {"include_usage": True}
        if response_format is not None:
            body["response_format"] = response_format
        return body

    def chat(self, messages: list[dict[str, Any]], response_format: Optional[dict], stream: bool,
             max_tokens: int, on_token: Optional[Callable[[str], None]], timeout: float) -> ChatResult:
        body = self.build_body(messages, response_format, stream, max_tokens)
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        meta = {k: v for k, v in body.items() if k != "messages"}
        digest, nbytes = messages_digest(messages)
        started = now_iso()
        t0 = self.clock()
        # Hatalar ``except`` bloğunun DIŞINDA yükseltilir: içeride yükseltilen istisna özgün istisnayı
        # ``__context__`` olarak taşır ve özgün ileti (ör. ucun yankıladığı anahtar) orada kalırdı.
        err: Optional[LMError] = None
        try:
            resp = self.transport("POST", self.chat_url, self.headers(), payload, timeout)
        except HttpStatusError as e:
            err = HttpStatusError(e.status, self.redact(e.excerpt))
        except LMError as e:
            err = BackendError(self.redact(str(e)))
        if err is not None:
            raise err
        try:
            if stream:
                parts = read_sse(resp.lines, self.clock, t0, on_token)
            else:
                parts = parse_completion(resp.read())
                parts.update({"first": None, "last": None, "events": 0})
        except LMError as e:
            err = BackendError(self.redact(str(e)))
        finally:
            resp.close()
        if err is not None:
            raise err
        return ChatResult(content=parts["content"], finish_reason=parts["finish_reason"], usage=parts["usage"],
                          timings=parts["timings"], duration_sec=self.clock() - t0,
                          first_token_sec=parts["first"], last_token_sec=parts["last"],
                          content_events=parts["events"], stream=stream, request_meta=meta,
                          messages_sha256=digest, messages_bytes=nbytes, started_at=started)


# ---------------------------------------------------------------------------------------------
# Soyut arka uç


class Backend(ABC):
    kind: str = "soyut"

    def __init__(self, audit: Optional[AuditLog] = None):
        self.audit = audit
        self._state = STATE_OFF
        self._chat_lock = threading.Lock()

    @property
    def state(self) -> str:
        return self._state

    @property
    def pid(self) -> Optional[int]:
        """Bellek bekçisinin ölçeceği süreç; yerel süreç yoksa ``None``."""
        return None

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def stop(self, reason: str = "istek") -> None: ...

    @abstractmethod
    def health(self) -> dict[str, Any]: ...

    @abstractmethod
    def capabilities(self) -> Capabilities: ...

    @abstractmethod
    def identity(self) -> dict[str, Any]:
        """Künye (tasarım §5.4): anahtar ve ham veri içermez."""

    @abstractmethod
    def _chat(self, messages: list[dict[str, Any]], schema: Optional[Mapping[str, Any]], stream: bool,
              max_tokens: int, on_token: Optional[Callable[[str], None]]) -> ChatResult: ...

    def _secrets(self) -> tuple[str, ...]:
        return ()

    def _redact(self, text: str) -> str:
        return redact_text(text, self._secrets())

    def chat(self, messages: list[dict[str, Any]], schema: Optional[Mapping[str, Any]] = None,
             stream: bool = False, *, max_tokens: int = MAX_TOKENS_STEP,
             on_token: Optional[Callable[[str], None]] = None, purpose: str = "gorev") -> ChatResult:
        """Tek model isteği. İstekler sıradan geçer (tek yuva, ``--parallel 1``). Her istek —
        başarılı ya da hatalı — denetim günlüğüne bir kayıt yazar (K-L1)."""
        messages = _check_messages(messages)
        with self._chat_lock:
            try:
                result = self._chat(messages, schema, stream, max_tokens, on_token)
            except BaseException as e:
                if self.audit is not None:
                    digest, nbytes = messages_digest(messages)
                    self.audit.write("model_istegi", amac=purpose, arka_uc=self._audit_backend(),
                                     iletiler_sha256=digest, iletiler_bayt=nbytes,
                                     hata=self._redact(f"{type(e).__name__}: {e}"))
                raise
            if self.audit is not None:
                self.audit.write("model_istegi", amac=purpose, arka_uc=self._audit_backend(),
                                 **result.audit_fields())
            return result

    def _audit_backend(self) -> dict[str, Any]:
        return {"tur": self.kind}

    def __enter__(self) -> "Backend":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop("hata" if exc and exc[0] is not None else "istek")


# ---------------------------------------------------------------------------------------------
# Yerel llama-server


Popen = Callable[..., Any]
Runner = Callable[..., Any]


class LlamaServerBackend(Backend):
    """Yerel yalın ``llama-server`` (tasarım §2.2 "Yerel sunucu").

    Bağımlılıklar (``popen``, ``transport``, ``run``, ``kill``, ``clock``, ``sleep``, ``port_finder``,
    ``key_factory``) testte sahteleriyle değiştirilir; testler süreç açmaz.
    """

    kind = "yerel_llama_server"

    def __init__(self, binary: Path, model_path: Path, state_dir: Path, *, template_path: Optional[Path] = None,
                 ctx_size: int = CONTEXT_TOKENS, model_name: str = "karadullm", audit: Optional[AuditLog] = None,
                 popen: Popen = subprocess.Popen, transport: Transport = urllib_transport, run: Runner = subprocess.run,
                 kill: Callable[[int, int], None] = os.kill, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep, port_finder: Callable[[], int] = find_free_port,
                 key_factory: Callable[[], str] = new_api_key, ready_timeout: float = READY_TIMEOUT_SEC,
                 idle_shutdown_sec: float = IDLE_SHUTDOWN_SEC, request_timeout: float = REQUEST_TIMEOUT_SEC):
        super().__init__(audit)
        self.binary = Path(binary)
        self.model_path = Path(model_path)
        self.template_path = Path(template_path) if template_path is not None else None
        self.state_dir = Path(state_dir)
        self.ctx_size = ctx_size
        self.model_name = model_name
        self._popen, self._transport, self._run, self._kill = popen, transport, run, kill
        self._clock, self._sleep = clock, sleep
        self._port_finder, self._key_factory = port_finder, key_factory
        self.ready_timeout = ready_timeout
        self.idle_shutdown_sec = idle_shutdown_sec
        self.request_timeout = request_timeout
        self._proc: Any = None
        self._port: Optional[int] = None
        self._key: Optional[str] = None
        self._log: Any = None
        self._client: Optional[_OpenAIClient] = None
        self._identity: dict[str, Any] = {}
        self._last_activity: Optional[float] = None
        self._lock = threading.RLock()
        self._atexit_registered = False

    # --- yollar ---------------------------------------------------------------------------
    @property
    def pid_file(self) -> Path:
        return self.state_dir / _PID_FILE_NAME

    @property
    def log_file(self) -> Path:
        return self.state_dir / _LOG_FILE_NAME

    @property
    def pid(self) -> Optional[int]:
        p = self._proc
        return p.pid if p is not None and p.poll() is None else None

    @property
    def port(self) -> Optional[int]:
        return self._port

    def _secrets(self) -> tuple[str, ...]:
        return (self._key,) if self._key else ()

    def _root_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    # --- künye ----------------------------------------------------------------------------
    def _version(self) -> Optional[str]:
        try:
            r = self._run([str(self.binary), "--version"], capture_output=True, text=True,
                          timeout=_VERSION_TIMEOUT_SEC)
        except (OSError, subprocess.TimeoutExpired):
            return None
        lines = [s for s in ((r.stdout or "") + (r.stderr or "")).splitlines() if s.startswith(("version", "built"))]
        return " | ".join(lines) or None

    def _static_identity(self) -> dict[str, Any]:
        if not self.binary.is_file():
            raise BackendError(f"llama-server ikilisi yok: {self.binary}")
        if not self.model_path.is_file():
            raise BackendError(f"model dosyası yok: {self.model_path}")
        st = self.model_path.stat()
        return {"tur": self.kind, "ikili": str(self.binary), "ikili_sha256": sha256_file(self.binary),
                "surum": self._version(),
                "sablon": None if self.template_path is None else str(self.template_path),
                "sablon_sha256": None if self.template_path is None else sha256_file(self.template_path),
                "model": str(self.model_path), "model_bayt": st.st_size,
                # 16 GiB'lık dosyayı her başlatmada özetlemek ≈ 8+ sn; ölçülmeden doldurulmaz.
                "model_sha256": None, "baglam": self.ctx_size}

    def identity(self) -> dict[str, Any]:
        return dict(self._identity) if self._identity else {"tur": self.kind, "ikili": str(self.binary),
                                                            "model": str(self.model_path)}

    def _audit_backend(self) -> dict[str, Any]:
        return {"tur": self.kind, "ikili_sha256": self._identity.get("ikili_sha256"), "port": self._port}

    # --- PID dosyası ve yetim ---------------------------------------------------------------
    def _write_pid_file(self, pid: int, port: int) -> None:
        self.pid_file.write_text(json.dumps({"pid": pid, "port": port, "ikili": str(self.binary)}),
                                 encoding="utf-8")

    def _recorded_pid(self) -> Optional[int]:
        """PID dosyasındaki süreç hâlâ bizim llama-server'ımız mı (ikili yolu ve kapı eşleşmeli)?
        Pilotun ``_kayitli_pid`` denetimi (``llm_pilot.py:711-723``); kapı burada dosyadan okunur.
        ``ps`` çıktısı anahtarı da taşır; yalnız alt dizgi denetiminde kullanılır, hiçbir yere yazılmaz."""
        try:
            rec = json.loads(self.pid_file.read_text(encoding="utf-8"))
            pid, port = int(rec["pid"]), int(rec["port"])
        except (OSError, ValueError, KeyError, TypeError):
            return None
        try:
            r = self._run(["ps", "-o", "args=", "-p", str(pid)], capture_output=True, text=True,
                          timeout=_VERSION_TIMEOUT_SEC)
        except (OSError, subprocess.TimeoutExpired):
            return None
        args = (r.stdout or "").strip()
        if str(self.binary) in args and f"--port {port}" in args:
            return pid
        return None

    def reap_recorded(self) -> bool:
        """PID dosyasında kalmış (önceki çökmeden yetim) sunucuyu kapatır; dosyayı siler.
        Pilotun kapatma yolu (``llm_pilot.py:777-788``): SIGTERM, en çok ``STOP_WAIT_SEC`` bekleme,
        sonra SIGKILL. Kapatılan süreç varsa ``True``."""
        killed = False
        pid = self._recorded_pid()
        if pid is not None:
            try:
                self._kill(pid, signal.SIGTERM)
                for _ in range(STOP_WAIT_SEC):
                    if self._recorded_pid() is None:
                        break
                    self._sleep(1)
                else:
                    self._kill(pid, signal.SIGKILL)
                killed = True
            except ProcessLookupError:
                killed = True
        try:
            self.pid_file.unlink()
        except FileNotFoundError:
            pass
        return killed

    # --- yaşam döngüsü ----------------------------------------------------------------------
    def command(self) -> list[str]:
        """Bu başlatmanın komutu (anahtar dahil; kayda yalnız ``redact_command`` ile girer)."""
        if self._port is None or self._key is None:
            raise BackendError("komut yalnız başlatma sırasında kurulur")
        return build_llama_command(self.binary, self.model_path, self._port, self._key,
                                   template_path=self.template_path, ctx_size=self.ctx_size)

    def start(self) -> None:
        """Sunucuyu başlatır ve ``/health`` 200 dönene kadar bekler. Herhangi bir hatada süreç
        kapatılır, PID dosyası silinir ve anahtardan arındırılmış ``BackendError`` yükselir."""
        with self._lock:
            if self.pid is not None:
                return
            self._state = STATE_LOADING
            failure: Optional[str] = None
            try:
                self.state_dir.mkdir(parents=True, exist_ok=True)
                self.reap_recorded()
                ident = self._static_identity()
                self._port = self._port_finder()
                self._key = self._key_factory()
                if self.audit is not None:
                    self.audit.add_secret(self._key)
                cmd = self.command()
                self._log = open(self.log_file, "ab")
                self._proc = self._popen(cmd, stdout=self._log, stderr=subprocess.STDOUT,
                                         stdin=subprocess.DEVNULL, process_group=0)
                self._write_pid_file(self._proc.pid, self._port)
                self._client = _OpenAIClient(self._root_url() + "/v1/chat/completions", self._key,
                                             self.model_name, self._transport, self._redact,
                                             thinking_control=True, clock=self._clock)
                self._wait_ready()
                if not self._atexit_registered:
                    atexit.register(self._atexit_stop)
                    self._atexit_registered = True
            except BaseException as e:
                msg = self._redact(f"{type(e).__name__}: {e}")
                self._shutdown("hata")
                if self.audit is not None:
                    self.audit.write("baslatma_hatasi", arka_uc={"tur": self.kind}, hata=msg)
                if isinstance(e, (KeyboardInterrupt, SystemExit)):
                    raise
                failure = f"llama-server başlatılamadı: {msg}"
            if failure is not None:
                # except bloğunun dışında: özgün istisna (anahtarlı komut taşıyabilir) bağlama girmez.
                raise BackendError(failure)
            self._identity = {**ident, "bayraklar": redact_command(cmd[1:], self._key), "host": "127.0.0.1",
                              "port": self._port, "pid": self._proc.pid, "baslangic": now_iso()}
            self._state = STATE_READY
            self._last_activity = self._clock()
            if self.audit is not None:
                self.audit.write("kunye", arka_uc=self._identity, yetenek=self.capabilities().as_dict())

    def _health_ok(self) -> bool:
        resp = self._transport("GET", self._root_url() + "/health", {"Authorization": f"Bearer {self._key}"},
                               None, HEALTH_REQUEST_TIMEOUT_SEC)
        try:
            return resp.status == 200
        finally:
            resp.close()

    def _wait_ready(self) -> None:
        t0 = self._clock()
        while self._clock() - t0 < self.ready_timeout:
            if self._proc.poll() is not None:
                raise BackendError(f"llama-server erken çıktı (kod {self._proc.returncode})")
            try:
                if self._health_ok():
                    return
            except LMError:
                pass
            self._sleep(HEALTH_POLL_SEC)
        raise BackendError(f"llama-server {self.ready_timeout:.0f} saniyede hazır olmadı")

    def _shutdown(self, reason: str) -> None:
        """Süreci kapatır (SIGTERM → bekle → SIGKILL), PID dosyasını siler, anahtarı unutur.
        Her adım ayrı korunur: biri hata verse de sonrakiler yapılır."""
        proc, self._proc = self._proc, None
        try:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=STOP_WAIT_SEC)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=STOP_WAIT_SEC)
                    except subprocess.TimeoutExpired:
                        pass
        finally:
            try:
                self.reap_recorded()
            finally:
                try:
                    self.pid_file.unlink()
                except FileNotFoundError:
                    pass
                if self._log is not None:
                    try:
                        self._log.close()
                    except OSError:
                        pass
                self._log = None
                self._client = None
                self._key = None
                self._port = None
                self._state = _STOP_STATE.get(reason, STATE_OFF)

    def stop(self, reason: str = "istek") -> None:
        """Sunucuyu durdurur. ``reason``: ``istek`` | ``bosta`` | ``analiz`` | ``bellek`` | ``hata``."""
        with self._lock:
            was_running = self._proc is not None
            self._shutdown(reason)
        if was_running and self.audit is not None:
            self.audit.write("durdurma", arka_uc={"tur": self.kind}, neden=reason, durum=self._state)

    def _atexit_stop(self) -> None:
        try:
            self.stop("cikis")
        except Exception:  # noqa: BLE001 — çıkışta son çare; hata yutulur, süreç yine de sonlanır
            pass

    def stop_if_idle(self) -> bool:
        """Boşta ``idle_shutdown_sec`` geçtiyse durdurur (tasarım §2.2 [seçim: 10 dk])."""
        with self._lock:
            if self._state != STATE_READY or self._last_activity is None:
                return False
            if self._clock() - self._last_activity < self.idle_shutdown_sec:
                return False
        self.stop("bosta")
        return True

    def health(self) -> dict[str, Any]:
        out: dict[str, Any] = {"durum": self._state, "pid": self.pid, "port": self._port, "hazir": False}
        if self.pid is not None:
            try:
                out["hazir"] = self._health_ok()
            except LMError:
                out["hazir"] = False
        return out

    def capabilities(self) -> Capabilities:
        return Capabilities(level="L3",
                            level_source="yerel llama-server: json_schema response_format "
                                         "(zemin_olcumu.md §5, düz anyOf zarfı 10/10)",
                            streaming=True, local_process=True, memory_guard=True, network=False)

    def _chat(self, messages: list[dict[str, Any]], schema: Optional[Mapping[str, Any]], stream: bool,
              max_tokens: int, on_token: Optional[Callable[[str], None]]) -> ChatResult:
        if self.pid is None:
            self.start()
        self._state = STATE_BUSY
        try:
            assert self._client is not None
            return self._client.chat(messages, protocol.response_format_for("L3", schema), stream, max_tokens,
                                     on_token, self.request_timeout)
        except BaseException:
            if self._proc is not None and self._proc.poll() is not None:
                self.stop("hata")
            raise
        finally:
            self._last_activity = self._clock()
            if self._state == STATE_BUSY:
                self._state = STATE_READY if self.pid is not None else STATE_OFF


# ---------------------------------------------------------------------------------------------
# Kullanıcının OpenAI uyumlu ucu


# Yetenek yoklaması: tamamen yapay; ikiliden veri yok (tasarım §2.2). L3 isteminde şema anlatılmaz,
# böylece şemaya uyan çıktı ancak ucun zorlamasıyla gelir.
_LEVEL_PROBE_SCHEMA = {"type": "object", "properties": {"kind": {"const": "probe"}, "n": {"enum": [7]}},
                       "required": ["kind", "n"], "additionalProperties": False}
_LEVEL_PROBE_L3_MESSAGES = [{"role": "user", "content": "Say hello."}]
_LEVEL_PROBE_L2_MESSAGES = [{"role": "user", "content": "Say hello. Reply in JSON."}]
# Ucun "bu özelliği desteklemiyorum" anlamına gelen cevapları; başka HTTP hataları düzeyi belirlemez.
_UNSUPPORTED_STATUS = frozenset({400, 404, 415, 422, 501})


class OpenAIEndpointBackend(Backend):
    """Kullanıcının OpenAI uyumlu ucu (``…/v1`` taban adresi; istek ``<taban>/chat/completions``).

    ``allow_network`` loopback olmayan uç için açık onaydır; verilmemişse ``start``, ``health``,
    ``probe_level`` ve ``chat`` istek atmadan ``NetworkConsentRequired`` yükseltir.
    ``thinking_control``: ``chat_template_kwargs.enable_thinking=false`` gönderilsin mi (modele ve
    sunucuya özgü; standart OpenAI ucu bilinmeyen alanı reddedebilir, öntanım kapalı).
    """

    kind = "kullanici_ucu"

    def __init__(self, base_url: str, *, model_name: str, api_key: Optional[str] = None,
                 allow_network: bool = False, thinking_control: bool = False, audit: Optional[AuditLog] = None,
                 transport: Transport = urllib_transport, clock: Callable[[], float] = time.monotonic,
                 request_timeout: float = REQUEST_TIMEOUT_SEC):
        super().__init__(audit)
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("uç adresi http(s)://makine[:kapı]/yol biçiminde olmalı")
        if parts.username is not None or parts.password is not None:
            raise ValueError("uç adresinde kullanıcı bilgisi kabul edilmez; anahtarı ayrı verin")
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self._api_key = api_key or None
        self.allow_network = bool(allow_network)
        self.loopback = is_loopback_host(parts.hostname)
        self._transport = transport
        self.request_timeout = request_timeout
        self._level: Optional[str] = None
        self._level_source: Optional[str] = None
        if audit is not None:
            audit.add_secret(self._api_key)
        self._client = _OpenAIClient(self.base_url + "/chat/completions", self._api_key, model_name, transport,
                                     self._redact, thinking_control=thinking_control, clock=clock)

    def _secrets(self) -> tuple[str, ...]:
        return (self._api_key,) if self._api_key else ()

    def _require_consent(self) -> None:
        if not self.loopback and not self.allow_network:
            raise NetworkConsentRequired(
                f"loopback olmayan uç ({redact_url(self.base_url)}) için ağ onayı verilmedi; istek atılmadı")

    def identity(self) -> dict[str, Any]:
        return {"tur": self.kind, "uc": redact_url(self.base_url), "model": self.model_name,
                "ag": not self.loopback, "ag_onayi": self.allow_network, "duzey": self._level,
                "anahtar_var": self._api_key is not None}

    def _audit_backend(self) -> dict[str, Any]:
        return {"tur": self.kind, "uc": redact_url(self.base_url), "model": self.model_name}

    def start(self) -> None:
        self._require_consent()
        self._state = STATE_READY
        if self.audit is not None:
            self.audit.write("kunye", arka_uc=self.identity(), yetenek=self.capabilities().as_dict())

    def stop(self, reason: str = "istek") -> None:
        self._state = _STOP_STATE.get(reason, STATE_OFF)

    def health(self) -> dict[str, Any]:
        self._require_consent()
        try:
            resp = self._transport("GET", self.base_url + "/models", self._client.headers(), None,
                                   HEALTH_REQUEST_TIMEOUT_SEC)
        except LMError as e:
            return {"durum": self._state, "hazir": False, "hata": self._redact(str(e))}
        try:
            return {"durum": self._state, "hazir": resp.status == 200}
        finally:
            resp.close()

    def capabilities(self) -> Capabilities:
        return Capabilities(level=self._level, level_source=self._level_source, streaming=True,
                            local_process=False, memory_guard=False, network=not self.loopback)

    def _try(self, messages: list[dict[str, Any]], response_format: Optional[dict]) -> Optional[ChatResult]:
        """Yoklama isteği; uç özelliği reddederse ``None``, başka hata yükselir."""
        try:
            return self._client.chat(messages, response_format, False, CAPABILITY_PROBE_MAX_TOKENS, None,
                                     self.request_timeout)
        except HttpStatusError as e:
            if e.status in _UNSUPPORTED_STATUS:
                return None
            raise

    def probe_level(self) -> str:
        """Yetenek düzeyini yoklar (tasarım §2.2): önce L3 (``json_schema``; çıktı şemaya uymalı), sonra
        L2 (``json_object``; çıktı bütünüyle bir JSON nesnesi olmalı), yoksa L1. Uç hiçbir isteği
        kabul etmiyorsa düzey belirlenmez ve hata yükselir. En çok üç istek; her biri denetim
        günlüğünde."""
        self._require_consent()
        attempts: list[dict[str, Any]] = []
        level: Optional[str] = None
        source = ""
        with self._chat_lock:
            r3 = self._try(_LEVEL_PROBE_L3_MESSAGES, protocol.response_format_for("L3", _LEVEL_PROBE_SCHEMA))
            attempts.append(self._attempt_record("L3", r3))
            if r3 is not None and protocol.parse_turn(r3.content, r3.finish_reason,
                                                      _LEVEL_PROBE_SCHEMA).status == "gecerli":
                level, source = "L3", "yoklama: json_schema kabul edildi, çıktı şemaya uydu"
            if level is None:
                r2 = self._try(_LEVEL_PROBE_L2_MESSAGES, {"type": "json_object"})
                attempts.append(self._attempt_record("L2", r2))
                if r2 is not None and _is_whole_json_object(r2.content):
                    level, source = "L2", "yoklama: json_object kabul edildi, çıktı JSON nesnesi"
                elif r2 is not None:
                    level, source = "L1", "yoklama: json_object yanıtı JSON nesnesi değil"
            if level is None:
                r1 = self._try(_LEVEL_PROBE_L3_MESSAGES, None)
                attempts.append(self._attempt_record("L1", r1))
                if r1 is None:
                    raise BackendError("uç düz sohbet isteğini de reddetti; yetenek düzeyi belirlenemedi")
                level, source = "L1", "yoklama: yalnız düz metin"
        self._level, self._level_source = level, source
        if self.audit is not None:
            self.audit.write("yetenek_yoklamasi", arka_uc=self._audit_backend(), duzey=level, kaynak=source,
                             denemeler=attempts)
        return level

    @staticmethod
    def _attempt_record(level: str, r: Optional[ChatResult]) -> dict[str, Any]:
        if r is None:
            return {"denenen": level, "kabul": False}
        return {"denenen": level, "kabul": True, **r.audit_fields()}

    def _chat(self, messages: list[dict[str, Any]], schema: Optional[Mapping[str, Any]], stream: bool,
              max_tokens: int, on_token: Optional[Callable[[str], None]]) -> ChatResult:
        self._require_consent()
        if schema is not None and self._level is None:
            raise CapabilityUnknown("yetenek düzeyi yoklanmadı; şemalı istek atılmadı")
        rf = protocol.response_format_for(self._level, schema) if schema is not None else None
        return self._client.chat(messages, rf, stream, max_tokens, on_token, self.request_timeout)


def _is_whole_json_object(content: str) -> bool:
    text = content[protocol.think_end(content):].strip()
    try:
        return isinstance(json.loads(text), dict)
    except json.JSONDecodeError:
        return False


# ---------------------------------------------------------------------------------------------
# Betikli sahte arka uç (testler için)


@dataclass
class FakeReply:
    """Sahte arka ucun bir cevabı. ``error`` doluysa istek o hatayla biter; ``delay_sec`` kadar
    gerçekten beklenir; süreler betikteki değerlerdir (ölçülmez)."""

    content: str = ""
    finish_reason: Optional[str] = "stop"
    usage: Optional[dict] = None
    timings: Optional[dict] = None
    chunks: Optional[list[str]] = None
    first_token_sec: Optional[float] = None
    last_token_sec: Optional[float] = None
    duration_sec: float = 0.0
    delay_sec: float = 0.0
    error: Optional[BaseException] = None


class FakeBackend(Backend):
    kind = "sahte"

    def __init__(self, replies: Iterable[FakeReply] = (), *, level: Optional[str] = "L3",
                 health_ok: bool = True, start_error: Optional[str] = None, pid: Optional[int] = None,
                 memory_guard: bool = False, audit: Optional[AuditLog] = None,
                 sleep: Callable[[float], None] = time.sleep):
        super().__init__(audit)
        self.replies = list(replies)
        self.level = level
        self.health_ok = health_ok
        self.start_error = start_error
        self._pid = pid
        self._memory_guard = memory_guard
        self._sleep = sleep
        self.calls: list[dict[str, Any]] = []
        self.starts = 0
        self.stops: list[str] = []

    @property
    def pid(self) -> Optional[int]:
        return self._pid if self._state in (STATE_READY, STATE_BUSY) else None

    def start(self) -> None:
        self.starts += 1
        if self.start_error is not None:
            self._state = STATE_ERROR
            raise BackendError(self.start_error)
        self._state = STATE_READY

    def stop(self, reason: str = "istek") -> None:
        self.stops.append(reason)
        self._state = _STOP_STATE.get(reason, STATE_OFF)

    def health(self) -> dict[str, Any]:
        return {"durum": self._state, "hazir": self.health_ok and self._state == STATE_READY}

    def capabilities(self) -> Capabilities:
        return Capabilities(level=self.level, level_source="sahte arka uç (betik)", streaming=True,
                            local_process=False, memory_guard=self._memory_guard, network=False)

    def identity(self) -> dict[str, Any]:
        return {"tur": self.kind, "betik_uzunlugu": len(self.replies) + len(self.calls)}

    def _chat(self, messages: list[dict[str, Any]], schema: Optional[Mapping[str, Any]], stream: bool,
              max_tokens: int, on_token: Optional[Callable[[str], None]]) -> ChatResult:
        if self._state not in (STATE_READY, STATE_BUSY):
            self.start()
        self.calls.append({"messages": messages, "schema": schema, "stream": stream, "max_tokens": max_tokens})
        if not self.replies:
            raise BackendError("sahte arka uç: betik bitti")
        r = self.replies.pop(0)
        if r.delay_sec:
            self._sleep(r.delay_sec)
        if r.error is not None:
            raise r.error
        rf = protocol.response_format_for(self.level, schema) if schema is not None else None
        meta = {"model": "sahte", "temperature": 0, "seed": MODEL_SEED, "max_tokens": max_tokens,
                "stream": stream, **({"response_format": rf} if rf is not None else {})}
        pieces = r.chunks if r.chunks is not None else ([r.content] if r.content else [])
        if stream and on_token is not None:
            for p in pieces:
                on_token(p)
        digest, nbytes = messages_digest(messages)
        return ChatResult(content="".join(pieces) if r.chunks is not None else r.content,
                          finish_reason=r.finish_reason, usage=r.usage, timings=r.timings,
                          duration_sec=r.duration_sec, first_token_sec=r.first_token_sec if stream else None,
                          last_token_sec=r.last_token_sec if stream else None,
                          content_events=len(pieces) if stream else 0, stream=stream, request_meta=meta,
                          messages_sha256=digest, messages_bytes=nbytes)
