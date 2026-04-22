"""v1.10.0 M2 T10 — Decompiler backend abstraction.

Protocol + dataclass tanimlari. Tum backend'ler (Ghidra, angr, ileride
BinaryNinja/IDA) ayni arayuze uymali.

Tasarim ilkeleri:
    - Backend-agnostic sonuc formati (DecompileResult).
    - `backend_specific` dict escape hatch'i — ozgun veriler kaybolmasin.
    - Protocol runtime_checkable; isinstance ile tip kontrolu yapilabilir.
    - Dataclass'lar frozen DEGIL — reporting/merge step'leri alan
      ekleyebilsin diye.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable


@dataclass
class DecompiledFunction:
    """Tek bir fonksiyonun decompile edilmis gosterimi.

    Args:
        address: Fonksiyon giris adresi (hex string, ornegin "0x100003abc").
        name: Fonksiyon adi (sembol yoksa Ghidra/angr varsayilani).
        pseudocode: Decompiler'in uretti C benzeri pseudocode metni.
        calls: Bu fonksiyondan cagrilan diger fonksiyon adresleri (hex).
        backend_specific: Backend-ozgu ek metadata (type info, pcode, stack
            frame vb.). Konsumer backend_name'i kontrol ederek okumali.
    """

    address: str
    name: str
    pseudocode: str
    calls: list[str] = field(default_factory=list)
    backend_specific: dict | None = None


@dataclass
class DecompileResult:
    """Tum binary icin decompile cikisinin standart formati.

    Args:
        functions: Decompile edilen fonksiyonlar.
        call_graph: Address -> called address listesi. Fonksiyon bulunamayan
            cagrilar (external, indirect) dahil olabilir.
        strings: Tanimli string tablolari. Her entry en az `addr` ve `value`
            icerir; `encoding` alani backend'e gore degisebilir.
        errors: Analiz sirasinda olusan non-fatal hatalar (backend cokmez ama
            bazi fonksiyonlar kayip).
        backend_name: "ghidra" | "angr" | ...
        duration_seconds: Toplam analiz suresi (wall-clock).
    """

    functions: list[DecompiledFunction]
    call_graph: dict[str, list[str]]
    strings: list[dict]
    errors: list[str]
    backend_name: str
    duration_seconds: float


@runtime_checkable
class DecompilerBackend(Protocol):
    """Decompiler backend arayuzu.

    Tum backend'ler bu Protocol'e uymali. Runtime check mumkun:
        isinstance(obj, DecompilerBackend) -> True ise uygun.

    Not: Protocol Python'da "structural subtyping" -- ad + signature
    eslesmesi yeterli, explicit inherit gerekmiyor. Ama runtime_checkable
    yalnizca method varligina bakar, signature'a degil; test'lerde
    integration-level kontrol gerekir.
    """

    name: str

    def is_available(self) -> bool:
        """Backend kullanilabilir mi? (Ghidra install var mi, angr import
        edilebiliyor mu vb.)"""
        ...

    def decompile(
        self,
        binary: Path,
        output_dir: Path,
        timeout: float = 3600.0,
    ) -> DecompileResult:
        """Binary'i decompile et.

        Args:
            binary: Girdi binary dosyasi.
            output_dir: Backend ara/nihai ciktilari buraya yazar.
            timeout: Toplam analiz zaman asimi (saniye).

        Returns:
            Standart DecompileResult.

        Raises:
            RuntimeError: Backend kullanilamazsa veya kritik hata.
        """
        ...

    def supports_platform(self, platform: str) -> bool:
        """Verilen platform icin destek var mi?

        Args:
            platform: "macho" | "elf" | "pe" | "raw".

        Returns:
            Platform destekleniyorsa True.
        """
        ...
