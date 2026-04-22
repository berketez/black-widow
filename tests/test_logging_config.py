"""karadul.core.logging_config testleri (Batch 5C-1)."""
from __future__ import annotations

import json
import logging

import pytest

from karadul.core.logging_config import JsonFormatter, setup_logging


@pytest.fixture(autouse=True)
def _reset_root() -> None:
    """Her test sonrasi root logger'i sifirla (globals test'ten test'e
    sizmasin)."""
    yield
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.setLevel(logging.WARNING)


class TestJsonFormatter:
    def test_basic_format(self) -> None:
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test.module",
            level=logging.INFO,
            pathname="f.py",
            lineno=1,
            msg="hello %s",
            args=("world",),
            exc_info=None,
        )
        out = fmt.format(record)
        data = json.loads(out)
        assert data["message"] == "hello world"
        assert data["level"] == "INFO"
        assert data["logger"] == "test.module"
        assert "timestamp" in data

    def test_extra_fields_included(self) -> None:
        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="f.py",
            lineno=1,
            msg="warn",
            args=(),
            exc_info=None,
        )
        record.user = "berke"  # type: ignore[attr-defined]
        record.binary = "/bin/ls"  # type: ignore[attr-defined]
        out = fmt.format(record)
        data = json.loads(out)
        assert data["user"] == "berke"
        assert data["binary"] == "/bin/ls"

    def test_exc_info_included(self) -> None:
        fmt = JsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="f.py",
                lineno=1,
                msg="error",
                args=(),
                exc_info=sys.exc_info(),
            )
            out = fmt.format(record)
            data = json.loads(out)
            assert "exc_info" in data
            assert "ValueError" in data["exc_info"]
            assert "boom" in data["exc_info"]


class TestSetupLogging:
    def test_text_format_installs_handler(self) -> None:
        setup_logging(level="DEBUG", format="text")
        root = logging.getLogger()
        assert len(root.handlers) == 1
        assert root.level == logging.DEBUG

    def test_json_format_uses_json_formatter(self) -> None:
        setup_logging(level="INFO", format="json")
        root = logging.getLogger()
        assert isinstance(root.handlers[0].formatter, JsonFormatter)

    def test_idempotent_single_handler(self) -> None:
        setup_logging("INFO", "text")
        setup_logging("DEBUG", "text")
        setup_logging("WARNING", "json")
        root = logging.getLogger()
        # Tekrar cagrildigi halde tek handler kalmali
        assert len(root.handlers) == 1
        assert root.level == logging.WARNING

    def test_invalid_level_falls_back_to_info(self) -> None:
        setup_logging(level="NOTALEVEL", format="text")
        root = logging.getLogger()
        assert root.level == logging.INFO

    def test_case_insensitive_level(self) -> None:
        setup_logging(level="debug", format="text")
        root = logging.getLogger()
        assert root.level == logging.DEBUG
