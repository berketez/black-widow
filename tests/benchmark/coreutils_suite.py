"""Coreutils multi-binary benchmark suite (v1.15-A).

30 GNU coreutils Linux ELF binary'sinin (Ubuntu 24.04 apt) stripped
versiyonlari icin ground truth ve aggregate benchmark altyapisi.

Tasarim notu:
    - Ubuntu apt'tan gelen coreutils ZATEN stripped (lokal sembol yok).
      Ground truth = ``nm -D`` dynamic symbol set (libc imports + binary
      exports). Bu HARD MODE -- gercek dunya stripped binary senaryosu.
    - Easy mode (kaynak build, debug info) v1.15.5'e ertelendi.
    - Aggregate metrik: per-binary F1 ortalamasi (macro) + tum function
      pool'da F1 (micro) ikisi de hesaplanir.

Kullanim:
    >>> suite = CoreutilsSuite.discover(
    ...     fixtures_dir=Path("tests/fixtures/coreutils/binaries/stripped"),
    ... )
    >>> for entry in suite.entries:
    ...     gt = suite.ground_truth(entry)
    ...     print(entry.name, gt.symbol_count)
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    # v1.15.5: PATH hijack korumalı tool resolution (varsa).
    from karadul.core.safe_subprocess import resolve_tool as _resolve_tool
except Exception:  # pragma: no cover - karadul paketsiz test ortamı
    _resolve_tool = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def _find_nm_tool(nm_path: Optional[str] = None) -> tuple[Optional[str], bool]:
    """Platform-aware nm aracı bul.

    v1.15.5: macOS sistem ``nm`` ``-D`` bayrağını DESTEKLEMEZ
    ("invalid argument -D"). Coreutils ground truth Linux ELF dynamic
    sembol seti içindir, dolayısıyla ``-D`` destekleyen bir araç gerekir.

    Arama sırası (mümkünse PATH hijack korumalı resolve_tool ile):
      - Linux: nm (binutils, -D destekler)
      - macOS: llvm-nm → gnm (GNU binutils) → objdump
      - nm_path override edildiyse onu kullan.

    Returns:
        (tool_path, supports_dash_D). Bulunamazsa (None, False).
    """
    def _which(name: str) -> Optional[str]:
        if _resolve_tool is not None:
            found = _resolve_tool(name)
            if found:
                return found
        return shutil.which(name)

    if nm_path:
        # Kullanıcı override etti: -D varsayımı platforma göre.
        return nm_path, (sys.platform != "darwin")

    if sys.platform == "darwin":
        # macOS sistem nm -D'yi desteklemez; -D destekleyen alternatifler.
        for cand in ("llvm-nm", "gnm"):
            found = _which(cand)
            if found:
                return found, True
        # objdump fallback (-T ile dynamic sembol); -D desteği farklı yolla.
        objdump = _which("objdump")
        if objdump:
            return objdump, False
        # Son çare: sistem nm (-D olmadan, defined-only).
        return _which("nm"), False

    # Linux ve diğerleri: binutils nm -D destekler.
    return _which("nm") or _which("gnm"), True


# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CoreutilsEntry:
    """Suite icindeki tek binary kaydi."""

    name: str          # "ls", "cat", "cp"
    path: Path         # absolute binary path
    size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": str(self.path),
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class CoreutilsSymbol:
    """``nm -D`` cikti satirindan parse edilmis tek dynamic symbol."""

    name: str            # demangled name (varsa); aksi halde mangled
    raw_name: str        # nm cikti satirindaki ham isim
    symbol_type: str     # "T" (text), "U" (undefined), "W" (weak), ...
    address: Optional[str] = None  # hex string veya None (U/W icin)
    binding: str = "GLOBAL"        # GLOBAL/WEAK
    glibc_version: Optional[str] = None  # "@GLIBC_2.17" varsa


@dataclass
class CoreutilsBinaryGroundTruth:
    """Tek bir coreutils binary icin ground truth (dynamic symbols)."""

    binary_name: str                                # "ls"
    binary_path: str
    binary_sha256: str
    symbols: list[CoreutilsSymbol] = field(default_factory=list)

    @property
    def symbol_count(self) -> int:
        return len(self.symbols)

    @property
    def export_count(self) -> int:
        """T (defined text/code) tipindeki sembol sayisi."""
        return sum(1 for s in self.symbols if s.symbol_type.upper() == "T")

    @property
    def import_count(self) -> int:
        """U (undefined, libc import) tipindeki sembol sayisi."""
        return sum(1 for s in self.symbols if s.symbol_type.upper() == "U")

    def name_set(self) -> set[str]:
        return {s.name for s in self.symbols}

    def imports_set(self) -> set[str]:
        return {s.name for s in self.symbols if s.symbol_type.upper() == "U"}

    def to_dict(self) -> dict[str, object]:
        return {
            "binary_name": self.binary_name,
            "binary_path": self.binary_path,
            "binary_sha256": self.binary_sha256,
            "symbol_count": self.symbol_count,
            "export_count": self.export_count,
            "import_count": self.import_count,
            "symbols": [
                {
                    "name": s.name,
                    "raw_name": s.raw_name,
                    "type": s.symbol_type,
                    "address": s.address,
                    "binding": s.binding,
                    "glibc_version": s.glibc_version,
                }
                for s in self.symbols
            ],
        }


@dataclass
class CoreutilsSuite:
    """N binary'lik benchmark suite. v1.15-A coreutils setinde N=30."""

    entries: list[CoreutilsEntry] = field(default_factory=list)
    fixtures_dir: Optional[Path] = None

    # --- Discovery -----------------------------------------------------

    @classmethod
    def discover(
        cls,
        fixtures_dir: Path,
        whitelist: Optional[list[str]] = None,
    ) -> "CoreutilsSuite":
        """Fixture dizinini tara, executable dosyalari topla.

        Args:
            fixtures_dir: ``stripped/`` ya da benzer dizin.
            whitelist: Sadece bu isimlerdekileri al (None: hepsini).

        Returns:
            CoreutilsSuite, alfabetik siralanmis entries ile.
        """
        if not fixtures_dir.is_dir():
            raise FileNotFoundError(
                f"Coreutils fixtures dizini bulunamadi: {fixtures_dir}",
            )
        entries: list[CoreutilsEntry] = []
        for p in sorted(fixtures_dir.iterdir()):
            if not p.is_file():
                continue
            if whitelist is not None and p.name not in whitelist:
                continue
            try:
                size = p.stat().st_size
            except OSError as exc:
                logger.warning("stat hatasi %s: %s", p, exc)
                continue
            entries.append(CoreutilsEntry(name=p.name, path=p, size_bytes=size))
        return cls(entries=entries, fixtures_dir=fixtures_dir)

    @property
    def count(self) -> int:
        return len(self.entries)

    @property
    def total_size_bytes(self) -> int:
        return sum(e.size_bytes for e in self.entries)

    def names(self) -> list[str]:
        return [e.name for e in self.entries]

    def find(self, name: str) -> Optional[CoreutilsEntry]:
        for e in self.entries:
            if e.name == name:
                return e
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "fixtures_dir": str(self.fixtures_dir) if self.fixtures_dir else None,
            "count": self.count,
            "total_size_bytes": self.total_size_bytes,
            "entries": [e.to_dict() for e in self.entries],
        }


# ---------------------------------------------------------------------------
# Dynamic symbol cikartici (nm -D)
# ---------------------------------------------------------------------------


# nm cikti satir formati:
#   "0000000000001234 T symbol_name"          # defined
#   "                 U undefined_name"         # undefined
#   "                 w weak_symbol"            # weak
# GLIBC version suffix: "symbol@GLIBC_2.17"
_NM_LINE_RE = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F]+)?\s+(?P<type>[A-Za-z])\s+(?P<rest>.+)$",
)
_GLIBC_SUFFIX_RE = re.compile(r"@+(?P<v>GLIBC_[\d.]+)$")


def parse_nm_dynamic_output(output: str) -> list[CoreutilsSymbol]:
    """``nm -D <binary>`` cikti string'ini ayrist.

    Args:
        output: Tam nm cikti metni.

    Returns:
        CoreutilsSymbol listesi, sira korunmus.
    """
    symbols: list[CoreutilsSymbol] = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        m = _NM_LINE_RE.match(line)
        if m is None:
            continue
        addr = m.group("addr")
        sym_type = m.group("type")
        rest = m.group("rest").strip()
        # GLIBC version suffix'i ayikla
        raw_name = rest
        glibc = None
        gm = _GLIBC_SUFFIX_RE.search(rest)
        if gm is not None:
            glibc = gm.group("v")
            raw_name = rest[: gm.start()]
        # Lowercase = LOCAL/WEAK (genellikle), uppercase = GLOBAL
        binding = "WEAK" if sym_type.islower() else "GLOBAL"
        symbols.append(
            CoreutilsSymbol(
                name=raw_name.strip(),
                raw_name=rest,
                symbol_type=sym_type.upper(),  # T/U/W canonicalize
                address=("0x" + addr.lower()) if addr else None,
                binding=binding,
                glibc_version=glibc,
            )
        )
    return symbols


def _sha256_file(path: Path) -> str:
    """SHA-256 hex digest (deterministic ground truth icin)."""
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_ground_truth(
    entry: CoreutilsEntry,
    nm_path: Optional[str] = None,
) -> CoreutilsBinaryGroundTruth:
    """Bir binary'den dynamic symbol ground truth cikar.

    Linux'ta yerel ``nm`` (binutils) tercih edilir. Mac'te brew
    ``binutils`` (gnm) gerekir; yoksa hata firlatir.

    Args:
        entry: Suite entry.
        nm_path: Override (default: PATH'te ``nm`` veya ``gnm``).

    Returns:
        CoreutilsBinaryGroundTruth, sembol listesiyle.

    Raises:
        FileNotFoundError: nm bulunamazsa.
        RuntimeError: nm cagrisi basarisiz olursa.
    """
    # v1.15.5: Platform-aware araç seçimi. macOS sistem nm -D'yi desteklemez;
    # llvm-nm/gnm/objdump'a düşülür. Linux'ta binutils nm -D kullanılır.
    nm_bin, supports_dash_d = _find_nm_tool(nm_path)
    if nm_bin is None:
        raise FileNotFoundError(
            "nm/llvm-nm/objdump (dynamic symbol araci) bulunamadi. Mac'te "
            "'brew install binutils' ya da Xcode CLT (llvm-nm) gerekir; "
            "veya nm_path argumani saglayin.",
        )

    tool_name = Path(nm_bin).name
    if "objdump" in tool_name:
        # objdump -T: dynamic symbol table (nm -D karsiligi).
        cmd = [nm_bin, "-T", str(entry.path)]
    elif supports_dash_d:
        cmd = [nm_bin, "-D", "--no-demangle", str(entry.path)]
    else:
        # -D desteklenmiyor: defined-only (Mach-O / fallback). nm -D yerine
        # en azindan defined sembolleri al; --no-demangle olmayabilir.
        cmd = [nm_bin, str(entry.path)]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"nm cagrisi basarisiz ({entry.name}, arac={tool_name}): "
            f"rc={proc.returncode}, stderr={proc.stderr.strip()}",
        )
    symbols = parse_nm_dynamic_output(proc.stdout)
    return CoreutilsBinaryGroundTruth(
        binary_name=entry.name,
        binary_path=str(entry.path),
        binary_sha256=_sha256_file(entry.path),
        symbols=symbols,
    )


def extract_suite_ground_truths(
    suite: CoreutilsSuite,
    output_dir: Optional[Path] = None,
    nm_path: Optional[str] = None,
) -> list[CoreutilsBinaryGroundTruth]:
    """Tum suite icin ground truth cikar; isteniyorsa JSON'a kaydet.

    Args:
        suite: Discovered suite.
        output_dir: Verilirse her binary icin
            ``<output_dir>/<name>.json`` yazar + ``suite_index.json``.
        nm_path: Override.

    Returns:
        CoreutilsBinaryGroundTruth listesi (suite siralamasiyla).
    """
    results: list[CoreutilsBinaryGroundTruth] = []
    for entry in suite.entries:
        try:
            gt = extract_ground_truth(entry, nm_path=nm_path)
        except (FileNotFoundError, RuntimeError) as exc:
            logger.warning("Ground truth atlandi (%s): %s", entry.name, exc)
            continue
        results.append(gt)
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / f"{entry.name}.json").write_text(
                json.dumps(gt.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
    if output_dir is not None and results:
        index = {
            "suite": suite.to_dict(),
            "ground_truths": [
                {
                    "binary": gt.binary_name,
                    "symbol_count": gt.symbol_count,
                    "export_count": gt.export_count,
                    "import_count": gt.import_count,
                    "sha256": gt.binary_sha256,
                }
                for gt in results
            ],
        }
        (output_dir / "suite_index.json").write_text(
            json.dumps(index, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    return results


# ---------------------------------------------------------------------------
# Aggregate metrikler (basit; v1.15-E icin extend edilebilir)
# ---------------------------------------------------------------------------


@dataclass
class SuiteAggregate:
    """Tum suite icin toplam istatistikler."""

    binary_count: int
    total_symbols: int
    total_exports: int
    total_imports: int
    avg_symbols_per_binary: float
    min_symbols: int
    max_symbols: int

    @classmethod
    def from_ground_truths(
        cls, ground_truths: list[CoreutilsBinaryGroundTruth],
    ) -> "SuiteAggregate":
        if not ground_truths:
            return cls(0, 0, 0, 0, 0.0, 0, 0)
        counts = [gt.symbol_count for gt in ground_truths]
        return cls(
            binary_count=len(ground_truths),
            total_symbols=sum(counts),
            total_exports=sum(gt.export_count for gt in ground_truths),
            total_imports=sum(gt.import_count for gt in ground_truths),
            avg_symbols_per_binary=sum(counts) / len(counts),
            min_symbols=min(counts),
            max_symbols=max(counts),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "binary_count": self.binary_count,
            "total_symbols": self.total_symbols,
            "total_exports": self.total_exports,
            "total_imports": self.total_imports,
            "avg_symbols_per_binary": round(self.avg_symbols_per_binary, 2),
            "min_symbols": self.min_symbols,
            "max_symbols": self.max_symbols,
        }
