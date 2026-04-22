"""TypeForge adapter -- binary/LLVM IR'den struct rekonstruksiyonu.

TypeForge (S&P 2025, Java/Ghidra Extension) opsiyonel harici CLI'dir.
Kurulu degilse ``is_available()`` False doner, pipeline sessiz devam eder.

TypeForge, Rust CLI degil -- Ghidra headless wrapper'i olarak calisir.
Kurulum: ``scripts/setup_typeforge.sh`` (Ghidra 11+, Java 17+, Gradle gerekli)

CLI arayuzu beklentisi (wrapper'in urettigi format):
    typeforge --binary <path> [--llvm-ir <path>] --output-dir <dir>
    stdout: {"structs": [...]}

Tasarim:
    - Subprocess cagrisi ``_run_subprocess``'te izole; monkeypatch ile mock'lanir.
    - Her hata ``TypeForgeResult.errors``'a dusurulur, exception sizmaz.
    - Magic number yok: timeout/min_conf ``BinaryReconstructionConfig``'ten.
    - Yol onceligi: KARADUL_TYPEFORGE_PATH env var > config.typeforge_path > PATH.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclass'lar -- JSON uyumlu sade yapi
# ---------------------------------------------------------------------------


@dataclass
class TypeForgeStruct:
    """TypeForge'dan gelen bir struct tanimi (name/size/fields/confidence)."""

    name: str
    size: int
    fields: list[dict[str, Any]]
    confidence: float


@dataclass
class TypeForgeResult:
    """TypeForge subprocess sonucu (structs + errors + duration_seconds)."""

    structs: list[TypeForgeStruct] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    backend: str = "typeforge"


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class TypeForgeAdapter:
    """TypeForge CLI sarmalayici.

    Args:
        config: Karadul ``Config`` nesnesi. ``config.binary_reconstruction``
            uzerinden feature flag ve TypeForge yolu okunur.
        timeout: Subprocess icin max sure (saniye). ``None`` verilirse
            ``config.binary_reconstruction.typeforge_timeout`` kullanilir.
    """

    def __init__(self, config: Any, timeout: float | None = None) -> None:
        self.config = config
        br = getattr(config, "binary_reconstruction", None)
        # Timeout secimi: arg > config > default 600s
        if timeout is not None:
            self.timeout = float(timeout)
        elif br is not None and getattr(br, "typeforge_timeout", None) is not None:
            self.timeout = float(br.typeforge_timeout)
        else:
            self.timeout = 600.0

        # Availability lazy cache: None = kontrol edilmedi, True/False = cached.
        self._available_cache: bool | None = None
        self._typeforge_path: str | None = self._find_typeforge()

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def _find_typeforge(self) -> str | None:
        """TypeForge CLI yolu -- oncelik sirasi: env var > config > PATH.

        Oncelik:
            1. ``KARADUL_TYPEFORGE_PATH`` cevre degiskeni (setup_typeforge.sh'in yazdigi yol)
            2. ``config.binary_reconstruction.typeforge_path``
            3. ``shutil.which("typeforge")`` -- PATH uzerindeki herhangi bir wrapper

        Hicbiri yoksa ``None`` doner; ``is_available()`` False uretir ve
        pipeline sessiz devam eder. Kullaniciya ``scripts/setup_typeforge.sh``
        calistirmasi onerilir.
        """
        # 1) Cevre degiskeni (en yuksek oncelik)
        env_path = os.environ.get("KARADUL_TYPEFORGE_PATH")
        if env_path:
            p = Path(env_path).expanduser()
            if p.exists() and p.is_file():
                logger.debug("TypeForge env var'dan alindi: %s", p)
                return str(p)
            logger.warning(
                "KARADUL_TYPEFORGE_PATH tanimli ama dosya yok: %s -- "
                "scripts/setup_typeforge.sh ile yeniden kurun.",
                env_path,
            )

        # 2) Config'deki yol
        br = getattr(self.config, "binary_reconstruction", None)
        if br is not None:
            configured = getattr(br, "typeforge_path", None)
            if configured:
                p = Path(configured).expanduser()
                if p.exists() and p.is_file():
                    logger.debug("TypeForge config'den alindi: %s", p)
                    return str(p)
                logger.debug(
                    "Config typeforge_path mevcut degil: %s", configured,
                )

        # 3) PATH uzerinden ara
        which = shutil.which("typeforge")
        if which:
            logger.debug("TypeForge PATH'te bulundu: %s", which)
        return which

    def is_available(self) -> bool:
        """TypeForge sistemde kullanilabilir mi?"""
        if self._available_cache is not None:
            return self._available_cache
        self._available_cache = self._typeforge_path is not None
        if not self._available_cache:
            logger.debug(
                "TypeForge CLI bulunamadi. Kurulum icin: "
                "bash scripts/setup_typeforge.sh  "
                "(Ghidra 11+, Java 17+, Gradle gerekli). "
                "Kurulumdan sonra: export KARADUL_TYPEFORGE_PATH=~/.karadul/typeforge/typeforge",
            )
        else:
            logger.debug("TypeForge bulundu: %s", self._typeforge_path)
        return self._available_cache

    # ------------------------------------------------------------------
    # Public: binary analizi
    # ------------------------------------------------------------------

    def analyze_binary(
        self,
        binary: Path,
        llvm_ir: Path | None = None,
    ) -> TypeForgeResult:
        """Binary'den (veya LLVM IR'den) struct cikar -- graceful hata yolu."""
        start = time.perf_counter()
        result = TypeForgeResult()

        if not self.is_available():
            result.errors.append(
                "TypeForge kurulu degil -- 'bash scripts/setup_typeforge.sh' calistirin "
                "veya KARADUL_TYPEFORGE_PATH env var'i tanimlayin.",
            )
            result.duration_seconds = time.perf_counter() - start
            return result

        binary = Path(binary)
        if not binary.exists():
            result.errors.append(f"Binary bulunamadi: {binary}")
            result.duration_seconds = time.perf_counter() - start
            return result

        # Subprocess arg listesi
        cmd: list[str] = [
            str(self._typeforge_path),
            "--json",
            "--binary", str(binary),
        ]
        if llvm_ir is not None:
            cmd.extend(["--llvm-ir", str(llvm_ir)])

        # Cagri izolasyonu: exception varsa error listesine dusur
        try:
            payload = self._run_subprocess(cmd)
        except FileNotFoundError as exc:
            result.errors.append(f"TypeForge binary cagrilamadi: {exc}")
            result.duration_seconds = time.perf_counter() - start
            return result
        except subprocess.TimeoutExpired:
            result.errors.append(
                f"TypeForge timeout ({self.timeout}s) asildi",
            )
            result.duration_seconds = time.perf_counter() - start
            return result
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "")[:500] if isinstance(exc.stderr, str) else ""
            result.errors.append(
                f"TypeForge non-zero exit ({exc.returncode}): {stderr}",
            )
            result.duration_seconds = time.perf_counter() - start
            return result
        except OSError as exc:
            result.errors.append(f"TypeForge cagrisi basarisiz: {exc}")
            result.duration_seconds = time.perf_counter() - start
            return result
        except ValueError as exc:
            # _run_subprocess JSON parse hatasinda ValueError firlatir.
            result.errors.append(f"TypeForge stdout JSON parse hatasi: {exc}")
            result.duration_seconds = time.perf_counter() - start
            return result

        # JSON payload -> TypeForgeStruct listesi
        try:
            structs = self._parse_typeforge_json(payload)
        except ValueError as exc:
            result.errors.append(f"TypeForge JSON parse hatasi: {exc}")
            result.duration_seconds = time.perf_counter() - start
            return result

        result.structs = structs
        result.duration_seconds = time.perf_counter() - start
        logger.info(
            "TypeForge: %d struct (%.2fs)", len(structs), result.duration_seconds,
        )
        return result

    # ------------------------------------------------------------------
    # Internals -- test edilebilir parcalar
    # ------------------------------------------------------------------

    def _run_subprocess(self, cmd: list[str]) -> dict[str, Any]:
        """TypeForge CLI'yi calistir, stdout JSON'u dict olarak don."""
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=True,
        )
        stdout = proc.stdout or ""
        if not stdout.strip():
            return {}
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ValueError(f"stdout JSON degil: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(
                f"TypeForge JSON dict bekleniyor, {type(data).__name__} geldi",
            )
        return data

    def _parse_typeforge_json(self, data: dict[str, Any]) -> list[TypeForgeStruct]:
        """TypeForge JSON'u -> TypeForgeStruct listesi.

        Beklenen sema: {"structs": [{"name", "size", "fields":[{"name","offset","type"}],
        "confidence"}, ...]}. Malformed girdiler atlanir, gecerli olanlar doner.
        """
        if not isinstance(data, dict):
            raise ValueError(f"dict bekleniyor, {type(data).__name__}")
        raw_structs = data.get("structs", [])
        if not isinstance(raw_structs, list):
            raise ValueError(
                f"'structs' alan list olmali, {type(raw_structs).__name__}",
            )

        out: list[TypeForgeStruct] = []
        for idx, raw in enumerate(raw_structs):
            if not isinstance(raw, dict):
                logger.debug(
                    "TypeForge struct[%d] dict degil, atlaniyor: %r", idx, raw,
                )
                continue
            name = raw.get("name")
            size = raw.get("size")
            fields = raw.get("fields", [])
            conf = raw.get("confidence")
            # Zorunlu alanlar
            if not isinstance(name, str) or not name:
                logger.debug("TypeForge struct[%d] name gecersiz, atlaniyor", idx)
                continue
            if not isinstance(size, int) or size < 0:
                logger.debug(
                    "TypeForge struct '%s' size gecersiz (%r), atlaniyor",
                    name, size,
                )
                continue
            if not isinstance(fields, list):
                logger.debug(
                    "TypeForge struct '%s' fields list degil, atlaniyor", name,
                )
                continue
            if not isinstance(conf, (int, float)):
                logger.debug(
                    "TypeForge struct '%s' confidence gecersiz, 0.0 atanir", name,
                )
                conf = 0.0
            conf = float(conf)
            # Clamp [0, 1]
            if conf < 0.0:
                conf = 0.0
            elif conf > 1.0:
                conf = 1.0
            # Field dogrulamasi hafif: dict icinde offset int olmali
            normalized_fields: list[dict[str, Any]] = []
            for f in fields:
                if not isinstance(f, dict):
                    continue
                off = f.get("offset")
                if not isinstance(off, int):
                    continue
                normalized_fields.append(dict(f))
            out.append(
                TypeForgeStruct(
                    name=name,
                    size=int(size),
                    fields=normalized_fields,
                    confidence=conf,
                )
            )
        return out


__all__ = ["TypeForgeStruct", "TypeForgeResult", "TypeForgeAdapter"]
