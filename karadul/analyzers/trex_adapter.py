"""TRex adapter -- Ghidra PCode'dan struct rekonstruksiyonu (USENIX'25).

TRex (Bosamiya, Woo, Parno -- USENIX Security 2025) BSD-3 lisansli, deductive
type reconstruction aracidir. ``vendor/trex/`` altinda Rust kaynak kodu olarak
bulunur; calistirmak icin ``cargo build --release`` ile binary uretilmesi
gerekir. Mac uzerinde Rust toolchain'i kurulu degilse adapter sessizce
``is_available() == False`` doner ve pipeline devam eder.

Kullanim akisi (vendor/trex/README.md):
    1. Stripped binary -> Ghidra headless -> ``foo.lifted`` (PCode export)
    2. (Opsiyonel) Unstripped binary -> ``foo.vars`` (variable subset)
    3. ``trex from-ghidra foo.lifted foo.vars`` -> stdout: C-like struct'lar

Adapter sadece adim 3'u sarar; .lifted/.vars dosyalarinin uretimi pipeline'da
ayri Ghidra adimi olacak (v1.13.x veya v1.14 entegrasyonu).

Tasarim:
    - Subprocess izole: ``_run_subprocess`` monkeypatch'lenebilir.
    - Binary yoksa ``is_available() == False``, ``analyze()`` ``RuntimeError``.
    - Yol onceligi: ``binary_path`` arg > ``KARADUL_TREX_PATH`` env >
      ``vendor/trex/trex/target/release/trex`` > PATH (``shutil.which``).
    - Cikti parse: regex ile ``struct <name> { ... };`` bloklari ayiklanir,
      her field tipi/offset'i/adi cikarilir.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_VENDOR_TREX_BIN = _REPO_ROOT / "vendor" / "trex" / "trex" / "target" / "release" / "trex"

# struct <name> { <body> };  --  body'de yorum satirlari ve fieldlar olabilir
_STRUCT_RE = re.compile(
    r"struct\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{(?P<body>[^}]*)\};",
    re.DOTALL,
)
# Field satiri:  <type>  <name>;   (offset opsiyonel, comment olabilir)
# Ornekler:
#   int32_t field_0;
#   t1* field_8;
#   /* offset 0x10 */ int64_t count;
_FIELD_RE = re.compile(
    r"^\s*"
    r"(?:/\*\s*offset\s+(?P<offset>0x[0-9a-fA-F]+|\d+)\s*\*/\s*)?"
    r"(?P<type>[A-Za-z_][\w\s\*]*?)\s+"
    r"(?P<fname>[A-Za-z_]\w*)\s*;"
    r"\s*(?:/\*[^*]*\*/)?\s*$",
)
# `// var@func@addr : type` yorum satirlari -- variable annotation
_VAR_COMMENT_RE = re.compile(
    r"//\s*(?P<var>\w+)@(?P<func>\w+)@(?P<addr>[0-9a-fA-Fx]+)\s*:\s*(?P<type>.+)",
)


# ---------------------------------------------------------------------------
# Dataclass'lar
# ---------------------------------------------------------------------------


@dataclass
class TRexStruct:
    """TRex'in cikardigi struct yapisi.

    fields formati: ``[{"offset": "0x0", "type": "int32_t", "name": "field_0"}, ...]``.
    Offset, kaynak ciktida verilmediyse field index'ten turetilir (``field_<N>``
    isimlerinden veya satir sirasindan).
    """

    name: str
    fields: list[dict[str, str]] = field(default_factory=list)
    function: str | None = None
    raw_output: str = ""


@dataclass
class TRexResult:
    """TRex subprocess sonucu (struct'lar + raw stdout/stderr + meta)."""

    structs: list[TRexStruct] = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""
    return_code: int = 0
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class TRexAdapter:
    """TRex CLI sarmalayici -- ``from-ghidra`` modu.

    Args:
        binary_path: TRex binary yolu. None verilirse oncelik sirasiyla
            env var ``KARADUL_TREX_PATH``, ``vendor/trex/trex/target/release/trex``
            ve PATH uzerindeki ``trex`` aranir.
        timeout: Subprocess icin max sure (saniye). Default 300.
    """

    def __init__(
        self,
        binary_path: Path | str | None = None,
        timeout: int = 300,
    ) -> None:
        self.timeout = int(timeout)
        # Availability lazy cache: None = kontrol edilmedi, str = bulundu, "" = yok
        self._binary_path: str | None = self._resolve_binary(binary_path)

    # ------------------------------------------------------------------
    # Binary cozumleme
    # ------------------------------------------------------------------

    def _resolve_binary(self, override: Path | str | None) -> str | None:
        """TRex binary yolunu cozumle -- arg > env > vendor > PATH."""
        # 1) Explicit argument
        if override is not None:
            p = Path(override).expanduser()
            if p.exists() and p.is_file():
                logger.debug("TRex binary arg'tan alindi: %s", p)
                return str(p)
            logger.warning(
                "TRex binary_path verildi ama dosya yok: %s -- "
                "vendor/trex/BUILD_INSTRUCTIONS.md ile kurun.",
                override,
            )
            return None

        # 2) Environment variable
        env_path = os.environ.get("KARADUL_TREX_PATH")
        if env_path:
            p = Path(env_path).expanduser()
            if p.exists() and p.is_file():
                logger.debug("TRex env var'dan alindi: %s", p)
                return str(p)
            logger.warning(
                "KARADUL_TREX_PATH tanimli ama dosya yok: %s",
                env_path,
            )

        # 3) Vendor build location
        if _VENDOR_TREX_BIN.exists() and _VENDOR_TREX_BIN.is_file():
            logger.debug("TRex vendor build'den alindi: %s", _VENDOR_TREX_BIN)
            return str(_VENDOR_TREX_BIN)

        # 4) PATH
        which = shutil.which("trex")
        if which:
            logger.debug("TRex PATH'te bulundu: %s", which)
            return which

        logger.debug(
            "TRex binary bulunamadi. Kurulum: bash ile "
            "vendor/trex/BUILD_INSTRUCTIONS.md adimlarini izleyin "
            "(Rust toolchain + cargo build --release).",
        )
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """TRex binary kurulmus (build edilmis) mu?"""
        return self._binary_path is not None

    def get_version(self) -> str | None:
        """``trex --version`` cikti string'i. Binary yoksa None."""
        if self._binary_path is None:
            return None
        try:
            proc = subprocess.run(
                [self._binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("TRex --version cagrisi basarisiz: %s", exc)
            return None
        out = (proc.stdout or proc.stderr or "").strip()
        return out or None

    def analyze(
        self,
        lifted_path: Path | str,
        vars_path: Path | str | None = None,
    ) -> TRexResult:
        """``trex from-ghidra <lifted> [<vars>]`` cagrir, sonucu parse eder.

        Args:
            lifted_path: Ghidra PCode export (.lifted) dosyasi.
            vars_path: Opsiyonel variable subset (.vars).

        Returns:
            ``TRexResult`` (structs + raw stdout/stderr + return_code + duration_ms).

        Raises:
            RuntimeError: Binary kurulu degilse veya .lifted dosyasi yoksa.
        """
        if self._binary_path is None:
            raise RuntimeError(
                "trex binary not available -- "
                "vendor/trex/BUILD_INSTRUCTIONS.md ile kurun "
                "veya KARADUL_TREX_PATH env var'i tanimlayin.",
            )

        lifted = Path(lifted_path)
        if not lifted.exists():
            raise RuntimeError(f"trex .lifted dosyasi yok: {lifted}")

        cmd: list[str] = [self._binary_path, "from-ghidra", str(lifted)]
        if vars_path is not None:
            vars_p = Path(vars_path)
            if not vars_p.exists():
                logger.warning(
                    "TRex .vars dosyasi yok, parametresiz devam: %s", vars_p,
                )
            else:
                cmd.append(str(vars_p))

        start = time.perf_counter()
        try:
            proc = self._run_subprocess(cmd)
        except subprocess.TimeoutExpired:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return TRexResult(
                raw_stderr=f"trex timeout ({self.timeout}s) asildi",
                return_code=-1,
                duration_ms=duration_ms,
            )
        except (OSError, FileNotFoundError) as exc:
            duration_ms = (time.perf_counter() - start) * 1000.0
            return TRexResult(
                raw_stderr=f"trex cagrisi basarisiz: {exc}",
                return_code=-1,
                duration_ms=duration_ms,
            )

        duration_ms = (time.perf_counter() - start) * 1000.0
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        rc = proc.returncode

        if rc != 0:
            logger.warning(
                "TRex non-zero exit (%d): %s", rc, stderr[:200],
            )
            return TRexResult(
                raw_stdout=stdout,
                raw_stderr=stderr,
                return_code=rc,
                duration_ms=duration_ms,
            )

        try:
            structs = self.parse_output(stdout)
        except (ValueError, re.error) as exc:
            logger.warning("TRex stdout parse hatasi: %s", exc)
            structs = []

        logger.info(
            "TRex: %d struct (%.1fms)", len(structs), duration_ms,
        )
        return TRexResult(
            structs=structs,
            raw_stdout=stdout,
            raw_stderr=stderr,
            return_code=rc,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Cikti parse (testlerde dogrudan cagrilabilir)
    # ------------------------------------------------------------------

    def parse_output(self, stdout: str) -> list[TRexStruct]:
        """C-like struct ciktisini ``TRexStruct`` listesine cevir.

        Beklenen format (vendor/trex/README.md ornek):
            // n@getlast@00100000 : t1*
            // nxt@getlast@00100000 : t1*

            struct t1 {
              int32_t field_0;
              t1* field_8;
            };

        Yorum satirlarindaki ``var@func@addr`` annotation'lari toplanir,
        ardindan gelen struct'in ``function`` alanina (varsa) yazilir.
        """
        if not stdout:
            return []

        # Variable comment'lerinden son fonksiyon adini takip et.
        last_function: str | None = None
        for line in stdout.splitlines():
            m = _VAR_COMMENT_RE.search(line)
            if m:
                last_function = m.group("func")

        out: list[TRexStruct] = []
        for match in _STRUCT_RE.finditer(stdout):
            name = match.group("name")
            body = match.group("body")
            fields = self._parse_struct_body(body)
            out.append(
                TRexStruct(
                    name=name,
                    fields=fields,
                    function=last_function,
                    raw_output=match.group(0),
                )
            )
        return out

    @staticmethod
    def _parse_struct_body(body: str) -> list[dict[str, str]]:
        """Struct govdesinden field listesi cikar."""
        fields: list[dict[str, str]] = []
        idx = 0
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue
            m = _FIELD_RE.match(line)
            if not m:
                continue
            ftype = m.group("type").strip()
            fname = m.group("fname")
            offset_raw = m.group("offset")
            if offset_raw:
                # 0x... veya decimal -> normalize "0x..."
                if offset_raw.startswith("0x") or offset_raw.startswith("0X"):
                    offset = offset_raw.lower()
                else:
                    offset = hex(int(offset_raw))
            elif fname.startswith("field_"):
                # field_8 -> 0x8 (TRex konvansiyonu: byte offset)
                tail = fname[len("field_"):]
                try:
                    offset = hex(int(tail))
                except ValueError:
                    offset = hex(idx)
            else:
                offset = hex(idx)
            fields.append({"offset": offset, "type": ftype, "name": fname})
            idx += 1
        return fields

    # ------------------------------------------------------------------
    # Subprocess izolasyonu (test mock noktasi)
    # ------------------------------------------------------------------

    def _run_subprocess(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        """TRex'i calistir; CompletedProcess (stdout/stderr/returncode) don."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,  # rc != 0 durumu adapter tarafinda raporlanir
        )


__all__ = ["TRexStruct", "TRexResult", "TRexAdapter"]
