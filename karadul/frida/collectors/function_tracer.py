"""Frida mesajlarindan fonksiyon cagri izi olustur.

FridaSession.messages listesini isleyerek:
- Zaman sirali cagri sekansini cikarir
- Benzersiz modulleri tespit eder
- API/network cagrilarini filtreler
- Dosya erisimlerini filtreler
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Network ile ilgili mesaj tipleri
_NET_TYPES = frozenset({
    "net_connect", "net_send", "net_recv", "net_request",
})

# Dosya erisimi ile ilgili mesaj tipleri
_FS_TYPES = frozenset({
    "fs_open", "fs_read", "fs_write", "fs_stat",
    "fs_listdir", "fs_exists", "fs_read_file", "fs_create_file",
})

# Syscall olarak network
_SYSCALL_NET_NAMES = frozenset({
    "connect", "send", "recv",
})

# Syscall olarak dosya
_SYSCALL_FS_NAMES = frozenset({
    "open", "read", "write", "stat", "access", "unlink", "close",
})

# Crypto ile ilgili mesaj tipleri
_CRYPTO_TYPES = frozenset({
    "crypto_encrypt", "crypto_decrypt", "crypto_hash",
    "crypto_sign", "crypto_dlopen",
})

# Process ile ilgili mesaj tipleri
_PROCESS_TYPES = frozenset({
    "process_exec", "process_spawn", "process_fork",
})


class FunctionTracer:
    """Frida mesajlarindan fonksiyon cagri izi olusturur.

    Kullanim:
        tracer = FunctionTracer()
        tracer.process_messages(session.messages)
        calls = tracer.get_call_sequence()
        modules = tracer.get_unique_modules()
        api_calls = tracer.get_api_calls()
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def process_messages(self, messages: list[dict]) -> None:
        """Frida mesajlarini isle ve cagri listesine ekle.

        Hook mesajlari (hook_loaded gibi meta mesajlar) filtrelenir.
        Her mesaj bir cagri kaydi olarak islenir.

        Args:
            messages: FridaSession.messages listesi.
        """
        for msg in messages:
            if not isinstance(msg, dict):
                continue

            msg_type = msg.get("type", "")

            # Meta mesajlari atla
            if msg_type in ("hook_loaded", "hook_error"):
                continue

            # Cagri kaydina donustur
            call_record = self._message_to_call(msg)
            if call_record:
                self.calls.append(call_record)

        logger.info("FunctionTracer: %d mesaj islendi, %d cagri kaydi", len(messages), len(self.calls))

    def _message_to_call(self, msg: dict) -> dict | None:
        """Tek bir Frida mesajini normalize edilmis cagri kaydina donustur."""
        msg_type = msg.get("type", "")
        timestamp = msg.get("timestamp", 0)

        if msg_type == "syscall":
            # Generic hooks formati: { type: 'syscall', name: '...', args: {...}, retval: ... }
            syscall_name = msg.get("name", "unknown")
            return {
                "type": "syscall",
                "name": syscall_name,
                "category": self._categorize_syscall(syscall_name),
                "args": msg.get("args", {}),
                "retval": msg.get("retval"),
                "timestamp": timestamp,
            }
        else:
            # Ozel hook formati: { type: 'fs_open', path: '...', ... }
            category = self._categorize_type(msg_type)
            record = {
                "type": msg_type,
                "name": msg_type,
                "category": category,
                "timestamp": timestamp,
            }
            # Ek alanlari kopyala (type ve timestamp haric)
            for key, value in msg.items():
                if key not in ("type", "timestamp"):
                    record[key] = value
            return record

    @staticmethod
    def _categorize_type(msg_type: str) -> str:
        """Mesaj tipinden kategori belirle."""
        if msg_type in _NET_TYPES:
            return "network"
        elif msg_type in _FS_TYPES:
            return "filesystem"
        elif msg_type in _CRYPTO_TYPES:
            return "crypto"
        elif msg_type in _PROCESS_TYPES:
            return "process"
        elif msg_type.startswith("env_"):
            return "environment"
        elif msg_type.startswith("defaults_"):
            return "preferences"
        elif msg_type.startswith("bundle_"):
            return "bundle"
        return "other"

    @staticmethod
    def _categorize_syscall(name: str) -> str:
        """Syscall adından kategori belirle."""
        if name in _SYSCALL_NET_NAMES:
            return "network"
        elif name in _SYSCALL_FS_NAMES:
            return "filesystem"
        elif name == "mmap":
            return "memory"
        elif name == "dlopen":
            return "library"
        return "other"

    def get_call_sequence(self) -> list[dict]:
        """Zaman sirasina gore cagri listesi.

        Returns:
            Timestamp'e gore siralanmis cagri kayitlari.
        """
        return sorted(self.calls, key=lambda c: c.get("timestamp", 0))

    def get_unique_modules(self) -> set[str]:
        """Kullanilan benzersiz moduller / kutuphane isimleri.

        dlopen cagrilarindan ve require mesajlarindan modul isimlerini toplar.

        Returns:
            Benzersiz modul isimleri seti.
        """
        modules: set[str] = set()
        for call in self.calls:
            # dlopen syscall
            if call.get("name") == "dlopen":
                args = call.get("args", {})
                path = args.get("path", "")
                if path:
                    # Kutuphane adini cikar (sadece dosya adi)
                    modules.add(Path(path).name)

            # require hook
            if call.get("type") == "require":
                module = call.get("module", "")
                if module:
                    modules.add(module)

            # crypto_dlopen
            if call.get("type") == "crypto_dlopen":
                lib = call.get("library", "")
                if lib:
                    modules.add(Path(lib).name)

        return modules

    def get_api_calls(self) -> list[dict]:
        """Sadece network/API cagrilarini dondur.

        Returns:
            Network kategorisindeki cagri kayitlari.
        """
        return [
            call for call in self.get_call_sequence()
            if call.get("category") == "network"
        ]

    def get_file_accesses(self) -> list[dict]:
        """Dosya erisimleri.

        Returns:
            Filesystem kategorisindeki cagri kayitlari.
        """
        return [
            call for call in self.get_call_sequence()
            if call.get("category") == "filesystem"
        ]

    def get_crypto_operations(self) -> list[dict]:
        """Kriptografi islemleri.

        Returns:
            Crypto kategorisindeki cagri kayitlari.
        """
        return [
            call for call in self.get_call_sequence()
            if call.get("category") == "crypto"
        ]

    def get_process_operations(self) -> list[dict]:
        """Process islemleri (exec, spawn, fork).

        Returns:
            Process kategorisindeki cagri kayitlari.
        """
        return [
            call for call in self.get_call_sequence()
            if call.get("category") == "process"
        ]

    def get_env_accesses(self) -> list[dict]:
        """Ortam degiskeni erisimleri.

        Returns:
            Environment kategorisindeki cagri kayitlari.
        """
        return [
            call for call in self.get_call_sequence()
            if call.get("category") == "environment"
        ]

    def get_stats(self) -> dict[str, int]:
        """Kategori bazli istatistikler.

        Returns:
            Her kategori icin cagri sayisi.
        """
        stats: dict[str, int] = {}
        for call in self.calls:
            cat = call.get("category", "other")
            stats[cat] = stats.get(cat, 0) + 1
        return stats

    def to_json(self) -> dict:
        """JSON rapor.

        Returns:
            Tam cagri raporu (sekans, moduller, istatistikler).
        """
        sequence = self.get_call_sequence()
        return {
            "total_calls": len(sequence),
            "unique_modules": sorted(self.get_unique_modules()),
            "stats": self.get_stats(),
            "api_calls": self.get_api_calls(),
            "file_accesses": self.get_file_accesses(),
            "crypto_operations": self.get_crypto_operations(),
            "process_operations": self.get_process_operations(),
            "env_accesses": self.get_env_accesses(),
            "call_sequence": sequence,
        }

    def save_report(self, output_path: Path) -> None:
        """Raporu JSON dosyasina kaydet.

        Args:
            output_path: Cikti dosyasi yolu.
        """
        report = self.to_json()
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        logger.info("FunctionTracer raporu kaydedildi: %s", output_path)

    def clear(self) -> None:
        """Tum cagri kayitlarini temizle."""
        self.calls.clear()
