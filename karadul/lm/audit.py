"""KaradulLM denetim günlüğü (tasarım §5.4, §2.4).

Her model çağrısı, her hız yoklaması ve arka ucun her başlatma / durdurma olayı tek satırlık bir JSON
kaydıdır (JSONL). Kayıt alanları: olay türü, zaman, süre, jeton sayıları, arka uç künyesi.

Yazılmayanlar (yapım gereği, testle kilitli):

- **API anahtarı**: kayda eklenen her gizli değer (``add_secret``) serileştirilmiş satırda ``<gizli>``
  ile değiştirilir; ``FORBIDDEN_KEYS`` adlı alanların değeri hiç yazılmaz.
- **Ham ikili verisi**: iletiler (decompile metni, dizgiler) kayda girmez, yalnız sha256'ları ve bayt
  uzunlukları girer. ``bytes`` değerleri ``{"sha256", "bayt"}`` özetine çevrilir.
- Tanınmayan nesne türleri ``repr`` ile yazılmaz (``repr`` gizli alan taşıyabilir); yalnız tür adı.

Oturum dosyasının yeri ``~/.karadul/lm/<ikili_sha256>/oturum-<kimlik>.jsonl`` (tasarım §2.4; dizin
kalıbı ``karadul/core/overrides.py:62-78``). Yol kurmak dosya ya da dizin açmaz; dizin ilk yazmada
0700, dosya 0600 izniyle açılır.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import re
import threading
import urllib.parse
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

REDACTED = "<gizli>"
# Değeri hiçbir koşulda yazılmayan alan adları (küçük harfle karşılaştırılır).
FORBIDDEN_KEYS = frozenset({"api_key", "apikey", "authorization", "headers", "messages", "password",
                            "secret", "token"})
# Bundan kısa dizgiler gizli değer olarak kaydedilmez: kısa dizgiyi her yerde silmek kaydı bozar.
_MIN_SECRET_LEN = 8
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def now_iso() -> str:
    """Yerel saat dilimiyle ISO 8601 zaman (saniye çözünürlüğü)."""
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def canonical_json(obj: Any) -> str:
    """Özet almak için kanonik JSON: anahtarlar sıralı, boşluksuz, UTF-8 karakterler korunur."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_json(obj: Any) -> str:
    return sha256_text(canonical_json(obj))


def redact_text(text: str, secrets: Iterable[str]) -> str:
    """Metindeki her gizli değeri ``<gizli>`` ile değiştirir (hata iletileri ve kayıt satırları için)."""
    out = text
    for s in secrets:
        if s and len(s) >= _MIN_SECRET_LEN:
            out = out.replace(s, REDACTED)
    return out


def redact_url(url: str) -> str:
    """URL'nin kayda yazılabilir biçimi: şema, makine, kapı ve yol. Kullanıcı bilgisi, sorgu ve
    parça atılır (sorgu dizgisi anahtar taşıyabilir)."""
    p = urllib.parse.urlsplit(url)
    host = p.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = p.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port is not None else host
    return urllib.parse.urlunsplit((p.scheme, netloc, p.path, "", ""))


def session_log_path(binary_sha256: str, session_id: str, root: Optional[Path] = None) -> Path:
    """Oturum günlüğünün yolu; dosya ya da dizin oluşturmaz.

    ``binary_sha256`` 64 küçük harfli onaltılık basamak, ``session_id`` ``[A-Za-z0-9_-]{1,64}`` olmalı;
    değilse ``ValueError`` (yol aşımı koruması).
    """
    if not isinstance(binary_sha256, str) or not _HEX64.fullmatch(binary_sha256):
        raise ValueError("geçersiz ikili sha256 (64 küçük harfli onaltılık basamak beklenir)")
    if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
        raise ValueError("geçersiz oturum kimliği ([A-Za-z0-9_-]{1,64} beklenir)")
    base = root if root is not None else Path.home() / ".karadul" / "lm"
    return base / binary_sha256 / f"oturum-{session_id}.jsonl"


def _summarize_bytes(data: bytes) -> dict[str, Any]:
    return {"sha256": sha256_bytes(data), "bayt": len(data)}


def scrub(value: Any) -> Any:
    """Değeri kayda yazılabilir JSON yapısına çevirir; yasak alanları ve ham baytları ayıklar."""
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            out[key] = REDACTED if key.lower() in FORBIDDEN_KEYS else scrub(v)
        return out
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _summarize_bytes(bytes(value))
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=repr) if isinstance(value, (set, frozenset)) else value
        return [scrub(v) for v in items]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return scrub(dataclasses.asdict(value))
    return f"<{type(value).__name__}>"


class AuditLog:
    """Satır satır eklenen denetim günlüğü.

    ``path`` verilmezse kayıtlar yalnız bellekte tutulur (``records``); verilirse dosyaya da eklenir.
    Her ``write`` tek satırdır ve kilit altında yazılır.
    """

    def __init__(self, path: Optional[Path] = None, *, keep_in_memory: Optional[bool] = None):
        self.path = Path(path) if path is not None else None
        self.keep_in_memory = (path is None) if keep_in_memory is None else keep_in_memory
        self.records: list[dict[str, Any]] = []
        self.count = 0
        self._secrets: set[str] = set()
        self._lock = threading.Lock()

    def add_secret(self, value: Optional[str]) -> None:
        """Kayıtta asla görünmeyecek bir değer ekler (API anahtarı vb.)."""
        if value and len(value) >= _MIN_SECRET_LEN:
            with self._lock:
                self._secrets.add(value)

    def redact(self, text: str) -> str:
        with self._lock:
            secrets = tuple(self._secrets)
        return redact_text(text, secrets)

    def _open_append(self) -> int:
        assert self.path is not None
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        """Bir olay kaydı ekler; yazılan (ayıklanmış) kaydı döndürür."""
        record = {"olay": event, "zaman": now_iso(), **scrub(fields)}
        with self._lock:
            line = redact_text(json.dumps(record, ensure_ascii=False, sort_keys=True), self._secrets)
            if self.path is not None:
                fd = self._open_append()
                try:
                    os.write(fd, (line + "\n").encode("utf-8"))
                finally:
                    os.close(fd)
            written = json.loads(line)
            if self.keep_in_memory:
                self.records.append(written)
            self.count += 1
        return written

    def read_records(self) -> list[dict[str, Any]]:
        """Dosyadaki bütün kayıtlar (dosya yoksa bellektekiler)."""
        if self.path is None or not self.path.is_file():
            return list(self.records)
        return [json.loads(s) for s in self.path.read_text(encoding="utf-8").splitlines() if s.strip()]
