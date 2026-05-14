"""PDB (Microsoft Program Database) sembol/tip yukleyici -- llvm-pdbutil sarmalayici.

Karadul'da PDB native parser yok; bunun yerine LLVM toolkit'inin
``llvm-pdbutil`` aracini subprocess ile cagiririz (BSD-3 / Apache lisansli,
upstream'de bakimi suren tek acik kaynak PDB parser). Pattern olarak
``trex_adapter`` ve ``typeforge_adapter`` ile birebir ortusur:

    - Binary yoksa ``is_available() == False``, ``extract_*()`` ``RuntimeError``.
    - Subprocess izole edilmis (``_run_subprocess``), test mock noktasi.
    - Yol cozumu oncelik sirasi: arg > env (``KARADUL_LLVM_PDBUTIL``) >
      Homebrew LLVM (``/opt/homebrew/opt/llvm/bin/llvm-pdbutil``) >
      ``/usr/local/opt/llvm/bin/llvm-pdbutil`` > PATH.
    - 3rd-party Python yok (sadece subprocess + regex).

Kullanim:
    >>> from karadul.analyzers.pdb_parser import PDBAdapter
    >>> a = PDBAdapter(pdb_path=Path("foo.pdb"))
    >>> if a.is_available():
    ...     result = a.extract_all()
    ...     for s in result.symbols:
    ...         print(s.name, hex(s.address or 0))

llvm-pdbutil dump cikti format ornegi (--symbols):
    Symbols
    ============================================================
      Mod 0000 | `C:\\proj\\foo.obj`:
            4 | S_GPROC32 [size = 44] `MyFunction`
                parent = 0, addr = 0001:00010, code size = 64
                debug start = 4, debug end = 60
                flags = none
                type = 0x1003 (int (int))
        52 | S_END

llvm-pdbutil dump --globals ornegi:
    Global Symbols
    ============================================================
            0 | S_GDATA32 [size = 28] `g_counter`
                type = 0x0074 (int), addr = 0002:00100

llvm-pdbutil dump --types ornegi (TPI):
    Types (TPI Stream)
    ============================================================
      0x1003 | LF_PROCEDURE [size = 16]
              return type = 0x0074 (int), # args = 1, param list = 0x1002
              calling conv = near c, options = None
      0x1004 | LF_STRUCTURE [size = 64] `Foo`
              unique name: `.?AUFoo@@`
              vtable: <no type>, base list: <no type>, field list: 0x1005
              options: forward ref | has unique name, sizeof 24

Parser bu formati saturlik regex'lerle isler; ham cikti ``raw_stdout``
alaninda saklanir, gelecek surumlerde format degisirse fallback mumkundur.
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

from karadul.exceptions import AnalysisError
# B21: cikplak subprocess.run yerine safe_run (LD_PRELOAD/DYLD koruma).
# _binary_path adapter init'inde absolute path; env temizligi yeterli.
from karadul.core.safe_subprocess import safe_run

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

# Homebrew LLVM lokasyonlari (Mac/Linuxbrew)
_BREW_LOCATIONS: tuple[Path, ...] = (
    Path("/opt/homebrew/opt/llvm/bin/llvm-pdbutil"),
    Path("/usr/local/opt/llvm/bin/llvm-pdbutil"),
    Path("/home/linuxbrew/.linuxbrew/opt/llvm/bin/llvm-pdbutil"),
)

# Cikti banner ayraci
_BANNER_RE = re.compile(r"^=+\s*$")

# S_GPROC32 / S_LPROC32 / S_GPROC32_ID / S_LPROC32_ID / S_THUNK32
# Ornek satir: "      4 | S_GPROC32 [size = 44] `MyFunction`"
_PROC_RE = re.compile(
    r"^\s*\d+\s*\|\s*"
    r"S_(?P<kind>[GL]PROC32(?:_ID)?|THUNK32)"
    r"(?:\s*\[size\s*=\s*\d+\])?"
    r"\s*`(?P<name>[^`]+)`",
)

# S_GDATA32 / S_LDATA32 / S_GTHREAD32 / S_LTHREAD32 -- data symbols
# Ornek: "      0 | S_GDATA32 [size = 28] `g_counter`"
_DATA_RE = re.compile(
    r"^\s*\d+\s*\|\s*"
    r"S_(?P<kind>G|L)(?P<storage>DATA32|THREAD32)"
    r"(?:\s*\[size\s*=\s*\d+\])?"
    r"\s*`(?P<name>[^`]+)`",
)

# S_PUB32 -- public symbols (linker-emitted)
# Ornek: "      4 | S_PUB32 [size = 24] `?foo@@YAHH@Z`"
_PUB_RE = re.compile(
    r"^\s*\d+\s*\|\s*S_PUB32"
    r"(?:\s*\[size\s*=\s*\d+\])?"
    r"\s*`(?P<name>[^`]+)`",
)

# Detay satiri: "addr = 0001:00010" / "addr = [0001:00010, ...]"
_ADDR_RE = re.compile(
    r"addr\s*=\s*\[?(?P<sec>[0-9a-fA-F]+):(?P<off>[0-9a-fA-F]+)",
)

# code size = 64
_CODE_SIZE_RE = re.compile(r"code\s+size\s*=\s*(?P<size>\d+)")

# type = 0x1003 (...)
_TYPE_REF_RE = re.compile(r"type\s*=\s*0x(?P<tid>[0-9a-fA-F]+)")

# Type record bas satiri:
# "  0x1004 | LF_STRUCTURE [size = 64] `Foo`"
# "  0x1003 | LF_PROCEDURE [size = 16]"
_TYPE_HEAD_RE = re.compile(
    r"^\s*0x(?P<tid>[0-9a-fA-F]+)\s*\|\s*"
    r"LF_(?P<kind>[A-Z_]+)"
    r"(?:\s*\[size\s*=\s*\d+\])?"
    r"(?:\s*`(?P<name>[^`]+)`)?",
)

# sizeof 24  (LF_STRUCTURE / LF_CLASS detay satirlari icinde)
_SIZEOF_RE = re.compile(r"\bsizeof\s+(?P<sz>\d+)")

# Field list listing entry (LF_FIELDLIST altinda olur)
# Ornek: "- LF_MEMBER [name = `m_x`, Type = 0x0074 (int), offset = 0]"
_MEMBER_RE = re.compile(
    r"LF_MEMBER\s*\[\s*"
    r"name\s*=\s*`(?P<name>[^`]+)`,\s*"
    r"Type\s*=\s*0x(?P<tid>[0-9a-fA-F]+)"
    r"(?:\s*\([^)]*\))?,\s*"
    r"offset\s*=\s*(?P<off>\d+)",
)

# PDB version (Summary bolumunde): "  Signature: ..." veya "  Age: 1"
# Yaygin: "PDB Version: 20000404"
_PDB_VER_RE = re.compile(
    r"PDB\s+Version[:\s]+(?P<ver>\S+)", re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Yardimcilar
# ---------------------------------------------------------------------------


_PROC_KIND_MAP = {
    "GPROC32": "function",
    "GPROC32_ID": "function",
    "LPROC32": "function",
    "LPROC32_ID": "function",
    "THUNK32": "thunk",
}


def _parse_addr(line: str) -> tuple[int | None, int | None]:
    """``addr = SSSS:OOOOOOOO`` -> (section, offset) -- ikisi de int."""
    m = _ADDR_RE.search(line)
    if not m:
        return None, None
    try:
        sec = int(m.group("sec"), 16)
        off = int(m.group("off"), 16)
        return sec, off
    except ValueError:
        return None, None


# ---------------------------------------------------------------------------
# Dataclass'lar
# ---------------------------------------------------------------------------


@dataclass
class PDBSymbol:
    """PDB sembolu (function / global / static / thread / public)."""

    name: str
    address: int | None = None  # RVA (section:offset offset kismi -- relative)
    size: int | None = None     # bytes (S_GPROC32: code size)
    section: int | None = None  # PE section index (1-based)
    kind: str = "unknown"       # "function" | "global" | "static" | "thread" | "public" | "thunk"
    type_index: int | None = None  # CodeView type ID (None: bilinmiyor)


@dataclass
class PDBType:
    """PDB CodeView tip kaydi (Class / Struct / Union / Enum / Procedure / ...)."""

    type_id: int                              # CodeView type index
    kind: str                                 # "Class" | "Struct" | "Union" | "Enum" | "Procedure" | ...
    name: str | None = None                   # type name (varsa, LF_STRUCTURE/LF_CLASS icin)
    size: int | None = None                   # bytes (sizeof)
    fields: list[dict[str, object]] = field(default_factory=list)  # [{name, type_id, offset}]
    raw: str = ""                             # ham CodeView bloku


@dataclass
class PDBResult:
    """``llvm-pdbutil dump`` toplu sonucu."""

    symbols: list[PDBSymbol] = field(default_factory=list)
    types: list[PDBType] = field(default_factory=list)
    pdb_path: Path | None = None
    pdb_version: str | None = None
    raw_stdout: str = ""
    return_code: int = 0
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class PDBAdapter:
    """``llvm-pdbutil`` CLI sarmalayici -- PDB symbol/type yukleyici.

    Args:
        pdb_path: Hedef ``.pdb`` dosyasi yolu.
        llvm_pdbutil_path: Binary yolu (None: otomatik cozumle).
        timeout: Subprocess max sure (saniye). Default 300.
    """

    def __init__(
        self,
        pdb_path: Path | str,
        llvm_pdbutil_path: Path | str | None = None,
        timeout: int = 300,
    ) -> None:
        self.pdb_path: Path = Path(pdb_path)
        self.timeout: int = int(timeout)
        self._binary_path: str | None = self._resolve_binary(llvm_pdbutil_path)

    # ------------------------------------------------------------------
    # Binary cozumleme
    # ------------------------------------------------------------------

    def _resolve_binary(self, override: Path | str | None) -> str | None:
        """``llvm-pdbutil`` yolunu coz -- arg > env > brew > PATH."""
        # 1) Explicit argument
        if override is not None:
            p = Path(override).expanduser()
            if p.exists() and p.is_file():
                logger.debug("llvm-pdbutil arg'tan alindi: %s", p)
                return str(p)
            logger.warning(
                "llvm-pdbutil yolu verildi ama dosya yok: %s -- "
                "brew install llvm veya apt install llvm.",
                override,
            )
            return None

        # 2) Environment variable
        env_path = os.environ.get("KARADUL_LLVM_PDBUTIL")
        if env_path:
            p = Path(env_path).expanduser()
            if p.exists() and p.is_file():
                logger.debug("llvm-pdbutil env'den alindi: %s", p)
                return str(p)
            logger.warning(
                "KARADUL_LLVM_PDBUTIL tanimli ama dosya yok: %s",
                env_path,
            )

        # 3) Homebrew / Linuxbrew lokasyonlari
        for cand in _BREW_LOCATIONS:
            if cand.exists() and cand.is_file():
                logger.debug("llvm-pdbutil brew'den alindi: %s", cand)
                return str(cand)

        # 4) PATH
        which = shutil.which("llvm-pdbutil")
        if which:
            logger.debug("llvm-pdbutil PATH'te bulundu: %s", which)
            return which

        logger.debug(
            "llvm-pdbutil bulunamadi -- "
            "brew install llvm (Mac) veya apt install llvm (Linux).",
        )
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """``llvm-pdbutil`` kuruluymus mu?"""
        return self._binary_path is not None

    def get_version(self) -> str | None:
        """``llvm-pdbutil --version`` cikti string'i. Binary yoksa None."""
        if self._binary_path is None:
            return None
        try:
            # B21: safe_run -- LD_PRELOAD/DYLD env temizligi.
            proc = safe_run(
                [self._binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            logger.warning("llvm-pdbutil --version cagrisi basarisiz: %s", exc)
            return None
        out = (proc.stdout or proc.stderr or "").strip()
        return out or None

    def extract_symbols(self) -> list[PDBSymbol]:
        """``llvm-pdbutil dump --symbols --globals --publics`` cagir, sembolleri don."""
        result = self._run_dump(symbols=True, types=False)
        symbols, _types = self.parse_dump(result.stdout)
        return symbols

    def extract_types(self) -> list[PDBType]:
        """``llvm-pdbutil dump --types --ids`` cagir, CodeView tipleri don."""
        result = self._run_dump(symbols=False, types=True)
        _syms, types = self.parse_dump(result.stdout)
        return types

    def extract_all(self) -> PDBResult:
        """Tam dump (symbols + types + globals + publics) -- tek cagri.

        Returns:
            ``PDBResult`` (symbols, types, raw_stdout, return_code, duration_ms,
            pdb_path, pdb_version).

        Raises:
            RuntimeError: Binary kurulu degilse veya .pdb dosyasi yoksa.
        """
        start = time.perf_counter()
        proc = self._run_dump(symbols=True, types=True)
        duration_ms = (time.perf_counter() - start) * 1000.0

        symbols, types = self.parse_dump(proc.stdout)
        pdb_version: str | None = None
        m = _PDB_VER_RE.search(proc.stdout)
        if m:
            pdb_version = m.group("ver")

        logger.info(
            "PDB: %d sembol, %d tip (%.1fms)",
            len(symbols), len(types), duration_ms,
        )
        return PDBResult(
            symbols=symbols,
            types=types,
            pdb_path=self.pdb_path,
            pdb_version=pdb_version,
            raw_stdout=proc.stdout,
            return_code=proc.returncode,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # Subprocess + parser
    # ------------------------------------------------------------------

    def _run_dump(
        self, *, symbols: bool, types: bool,
    ) -> subprocess.CompletedProcess[str]:
        """``llvm-pdbutil dump`` cagir; flags symbols/types arg'larina gore."""
        if self._binary_path is None:
            raise AnalysisError(
                "llvm-pdbutil not available -- "
                "brew install llvm or apt-get install llvm",
            )
        if not self.pdb_path.exists():
            raise AnalysisError(f"PDB dosyasi yok: {self.pdb_path}")

        cmd: list[str] = [self._binary_path, "dump"]
        if symbols:
            cmd.extend(["--symbols", "--globals", "--publics"])
        if types:
            cmd.extend(["--types", "--ids"])
        cmd.append(str(self.pdb_path))

        try:
            proc = self._run_subprocess(cmd)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(
                cmd, -1,
                stdout="",
                stderr=f"llvm-pdbutil timeout ({self.timeout}s) asildi",
            )
        except (OSError, FileNotFoundError) as exc:
            return subprocess.CompletedProcess(
                cmd, -1,
                stdout="",
                stderr=f"llvm-pdbutil cagrisi basarisiz: {exc}",
            )

        if proc.returncode != 0:
            logger.warning(
                "llvm-pdbutil non-zero exit (%d): %s",
                proc.returncode, (proc.stderr or "")[:200],
            )
        return proc

    def parse_dump(
        self, stdout: str,
    ) -> tuple[list[PDBSymbol], list[PDBType]]:
        """``llvm-pdbutil dump`` ciktisini PDBSymbol/PDBType listelerine cevir.

        Parser saturlik gezinti yapar; yeni bir symbol/type bas satiri
        gorulduğunde onceki kaydi finalize eder, sonraki detay satirlari
        bu kayda baglanir. Banner ('====') satirlari yok sayilir.
        """
        if not stdout:
            return [], []

        symbols: list[PDBSymbol] = []
        types: list[PDBType] = []

        cur_sym: PDBSymbol | None = None
        cur_type: PDBType | None = None
        cur_type_lines: list[str] = []

        for raw_line in stdout.splitlines():
            line = raw_line.rstrip()

            # Banner satirlari: yok say
            if _BANNER_RE.match(line):
                continue

            # 1) Type record bas satiri?
            tm = _TYPE_HEAD_RE.match(line)
            if tm:
                # Onceki tipi finalize
                if cur_type is not None:
                    cur_type.raw = "\n".join(cur_type_lines)
                    self._finalize_type(cur_type, cur_type_lines)
                    types.append(cur_type)

                # Onceki sembolu finalize (varsa)
                if cur_sym is not None:
                    symbols.append(cur_sym)
                    cur_sym = None

                kind_raw = tm.group("kind")
                cur_type = PDBType(
                    type_id=int(tm.group("tid"), 16),
                    kind=self._normalize_type_kind(kind_raw),
                    name=tm.group("name"),
                )
                cur_type_lines = [line]
                continue

            # 2) Symbol bas satiri (proc / data / pub)?
            for regex, kind_resolver in (
                (_PROC_RE, self._proc_kind),
                (_DATA_RE, self._data_kind),
                (_PUB_RE, lambda _m: "public"),
            ):
                sm = regex.match(line)
                if sm:
                    # Onceki sembolu finalize
                    if cur_sym is not None:
                        symbols.append(cur_sym)
                    # Onceki tipi finalize
                    if cur_type is not None:
                        cur_type.raw = "\n".join(cur_type_lines)
                        self._finalize_type(cur_type, cur_type_lines)
                        types.append(cur_type)
                        cur_type = None
                        cur_type_lines = []

                    cur_sym = PDBSymbol(
                        name=sm.group("name"),
                        kind=kind_resolver(sm),
                    )
                    break
            else:
                # Hicbir bas satiri eslesmedi -- detay satiri olabilir.
                if cur_type is not None:
                    cur_type_lines.append(line)
                if cur_sym is not None:
                    self._enrich_symbol(cur_sym, line)

        # Donus -- son aktif kaydi da kapat.
        if cur_type is not None:
            cur_type.raw = "\n".join(cur_type_lines)
            self._finalize_type(cur_type, cur_type_lines)
            types.append(cur_type)
        if cur_sym is not None:
            symbols.append(cur_sym)

        return symbols, types

    # ------------------------------------------------------------------
    # Yardimci kind/finalizer'lar
    # ------------------------------------------------------------------

    @staticmethod
    def _proc_kind(m: re.Match[str]) -> str:
        kind = m.group("kind")
        return _PROC_KIND_MAP.get(kind, "function")

    @staticmethod
    def _data_kind(m: re.Match[str]) -> str:
        # GDATA32 -> global, LDATA32 -> static, *THREAD32 -> thread
        storage = m.group("storage")
        scope = m.group("kind")  # "G" | "L"
        if storage == "THREAD32":
            return "thread"
        return "global" if scope == "G" else "static"

    @staticmethod
    def _normalize_type_kind(raw: str) -> str:
        """``LF_STRUCTURE`` -> ``Struct``, ``LF_CLASS`` -> ``Class``, vs."""
        mapping = {
            "STRUCTURE": "Struct",
            "STRUCT": "Struct",
            "CLASS": "Class",
            "UNION": "Union",
            "ENUM": "Enum",
            "PROCEDURE": "Procedure",
            "MFUNCTION": "MemberFunction",
            "POINTER": "Pointer",
            "ARRAY": "Array",
            "MODIFIER": "Modifier",
            "FIELDLIST": "FieldList",
            "ARGLIST": "ArgList",
            "BITFIELD": "Bitfield",
            "VTSHAPE": "VTShape",
            "TYPESERVER2": "TypeServer2",
        }
        return mapping.get(raw, raw.title())

    @staticmethod
    def _enrich_symbol(sym: PDBSymbol, line: str) -> None:
        """Detay satirini sembole ekle (addr / code size / type)."""
        sec, off = _parse_addr(line)
        if sec is not None and sym.section is None:
            sym.section = sec
            sym.address = off
        cm = _CODE_SIZE_RE.search(line)
        if cm and sym.size is None:
            try:
                sym.size = int(cm.group("size"))
            except ValueError:
                pass
        tm = _TYPE_REF_RE.search(line)
        if tm and sym.type_index is None:
            try:
                sym.type_index = int(tm.group("tid"), 16)
            except ValueError:
                pass

    @staticmethod
    def _finalize_type(t: PDBType, lines: list[str]) -> None:
        """Tip detay satirlarinda sizeof + member alanlarini topla."""
        for ln in lines:
            sm = _SIZEOF_RE.search(ln)
            if sm and t.size is None:
                try:
                    t.size = int(sm.group("sz"))
                except ValueError:
                    pass
            mm = _MEMBER_RE.search(ln)
            if mm:
                try:
                    t.fields.append({
                        "name": mm.group("name"),
                        "type_id": int(mm.group("tid"), 16),
                        "offset": int(mm.group("off")),
                    })
                except ValueError:
                    continue

    # ------------------------------------------------------------------
    # Subprocess izolasyon noktasi (test mock)
    # ------------------------------------------------------------------

    def _run_subprocess(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        """``llvm-pdbutil``'i calistir; CompletedProcess don."""
        # B21: safe_run -- LD_PRELOAD/DYLD env temizligi.
        return safe_run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )


__all__ = ["PDBSymbol", "PDBType", "PDBResult", "PDBAdapter"]


# ---------------------------------------------------------------------------
# Pipeline entegrasyonu plani (v1.15)
# ---------------------------------------------------------------------------
#
# Yeni stage: ``karadul/pipeline/steps/pdb_symbol_recovery.py``
#   - Input:  PDB yolu (CLI flag ``--pdb`` veya workspace metadata).
#   - Output: ``static/pdb_symbols.json``, ``static/pdb_types.json``.
#   - Akis:
#       1. PDBAdapter(pdb_path).is_available() ? -> graceful skip.
#       2. extract_all() -> PDBResult.
#       3. function naming fusion (Bayesian source):
#          - PDB symbol'ler "high-confidence" prior (ger$ot{c}ek symbol).
#          - sigdb / FLIRT / TRex sonuclari ile bayes posterior'da kombine.
#       4. Workspace JSON yaz (atomicity: tmp -> rename).
#
# Sigorta: Bu adapter sadece I/O sarici; pipeline kodu v1.15'te eklenecek.

