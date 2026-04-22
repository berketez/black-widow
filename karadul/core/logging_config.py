"""Karadul logging konfigurasyonu.

Iki format destekli: 'text' (insan-okunabilir) ve 'json' (structured,
tool-parseable). Idempotent -- tekrar setup_logging cagrilirsa eski
handler'lar temizlenir, tek handler kalir.

Ornek:
    >>> from karadul.core.logging_config import setup_logging
    >>> setup_logging(level="INFO", format="json")
    >>> import logging; logging.getLogger("foo").info("hi", extra={"user": "berke"})
    {"timestamp": "...", "level": "INFO", "logger": "foo", "message": "hi", "user": "berke"}
"""

from __future__ import annotations

import json
import logging
from typing import Any


# LogRecord'un her zaman sahip oldugu standart alanlar -- JSON'a eklemeyiz.
_STANDARD_LOG_ATTRS: frozenset[str] = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
})


class JsonFormatter(logging.Formatter):
    """LogRecord'u tek satir JSON olarak formatlar.

    Ek alanlar (`logger.info(..., extra={"user": "berke"})`) otomatik
    JSON objesine dahil edilir. `default=str` sayesinde Path, datetime
    vb. serialize edilebilir tipler string'e donusur.
    """

    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            data["exc_info"] = self.formatException(record.exc_info)
        for key, value in record.__dict__.items():
            if key not in _STANDARD_LOG_ATTRS and not key.startswith("_"):
                data[key] = value
        return json.dumps(data, default=str, ensure_ascii=False)


def setup_logging(level: str = "INFO", format: str = "text") -> None:
    """Karadul root logger'i konfigure et.

    Idempotent: tekrar cagrilirsa eski handler'lar temizlenir. Boylece
    test suite'inde veya CLI'de guvenle birden fazla kez cagrilabilir.

    Args:
        level: DEBUG/INFO/WARNING/ERROR/CRITICAL. Kucuk/buyuk harf
               duyarsiz; tanimsiz ise INFO'ya dusulur.
        format: 'text' (insan-okunabilir) veya 'json' (structured).
    """
    level_num = getattr(logging, level.upper(), logging.INFO)

    handler: logging.Handler = logging.StreamHandler()
    if format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        ))

    root = logging.getLogger()
    root.setLevel(level_num)
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)


__all__ = ["setup_logging", "JsonFormatter"]
