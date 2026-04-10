"""Ghidra ProgramDiff wrapper -- iki binary arasindaki farklari tespit eder.

Iki binary versiyonunu Ghidra ile acarak fonksiyon, tip ve veri
degisikliklerini karsilastirir. Patch analizi, guncelleme tespiti
ve guvenlik denetimi icin kullanilir.

Iki mod destekler:
  1. PyGhidra native: pyghidra.open_program ile iki binary acilir,
     FunctionManager'lar karsilastirilir.
  2. JSON fallback: Onceden uretilmis ghidra_functions.json dosyalari
     karsilastirilir (Ghidra gerektirmez).

Kullanim:
    differ = GhidraProgramDiff(config)
    report = differ.diff(Path("v1.bin"), Path("v2.bin"))
    print(f"{report.summary.functions_added} yeni, {report.summary.functions_modified} degisik")

    # JSON fallback:
    report = differ.diff_from_json(Path("v1_funcs.json"), Path("v2_funcs.json"))
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from karadul.config import Config

if TYPE_CHECKING:
    pass  # Ghidra type'lari runtime'da import edilir

logger = logging.getLogger(__name__)

# PyGhidra kontrol
_PYGHIDRA_AVAILABLE: bool | None = None


def _check_pyghidra() -> bool:
    """PyGhidra modulu mevcut mu kontrol et (lazy, tek seferlik)."""
    global _PYGHIDRA_AVAILABLE
    if _PYGHIDRA_AVAILABLE is None:
        try:
            import pyghidra  # noqa: F401
            _PYGHIDRA_AVAILABLE = True
        except ImportError:
            _PYGHIDRA_AVAILABLE = False
    return _PYGHIDRA_AVAILABLE


# ---------------------------------------------------------------------------
# Veri siniflari
# ---------------------------------------------------------------------------

@dataclass
class FunctionDiff:
    """Tek bir fonksiyonun diff bilgisi.

    Attributes:
        name: Fonksiyon adi.
        address1: Birinci binary'deki adres (added ise None).
        address2: Ikinci binary'deki adres (removed ise None).
        status: Degisiklik durumu -- "added", "removed", "modified", "unchanged".
        size_change: Boyut farki (byte). Pozitif = buyudu, negatif = kuculdu.
        instruction_diff: Instruction sayisi farki. None = hesaplanamadi.
    """
    name: str
    address1: str | None
    address2: str | None
    status: str  # "added" | "removed" | "modified" | "unchanged"
    size_change: int = 0
    instruction_diff: int | None = None

    def __post_init__(self) -> None:
        valid = {"added", "removed", "modified", "unchanged"}
        if self.status not in valid:
            raise ValueError(f"Gecersiz status: {self.status!r}, beklenen: {valid}")


@dataclass
class DiffSummary:
    """Diff isleminin ozet istatistikleri.

    Attributes:
        functions_added: Yeni eklenen fonksiyon sayisi.
        functions_removed: Silinen fonksiyon sayisi.
        functions_modified: Degistirilen fonksiyon sayisi.
        functions_unchanged: Degismeyen fonksiyon sayisi.
        total_functions_1: Birinci binary'deki toplam fonksiyon sayisi.
        total_functions_2: Ikinci binary'deki toplam fonksiyon sayisi.
    """
    functions_added: int = 0
    functions_removed: int = 0
    functions_modified: int = 0
    functions_unchanged: int = 0
    total_functions_1: int = 0
    total_functions_2: int = 0

    @property
    def change_rate(self) -> float:
        """Degisim orani (0.0 - 1.0). Toplam fonksiyon yoksa 0."""
        total = self.total_functions_1 + self.total_functions_2
        if total == 0:
            return 0.0
        changed = self.functions_added + self.functions_removed + self.functions_modified
        return changed / max(self.total_functions_1, self.total_functions_2, 1)


@dataclass
class DiffReport:
    """Tam diff raporu.

    Attributes:
        binary1_name: Birinci binary dosya adi.
        binary2_name: Ikinci binary dosya adi.
        summary: Ozet istatistikler.
        function_diffs: Fonksiyon bazinda diff listesi.
        duration_seconds: Islem suresi (saniye).
    """
    binary1_name: str
    binary2_name: str
    summary: DiffSummary
    function_diffs: list[FunctionDiff] = field(default_factory=list)
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Dahili veri yapilari (fonksiyon eslestirme icin)
# ---------------------------------------------------------------------------

@dataclass
class _FuncInfo:
    """Bir fonksiyonun karsilastirma bilgileri (dahili)."""
    name: str
    address: str
    size: int
    instruction_count: int = 0


# ---------------------------------------------------------------------------
# Ana sinif
# ---------------------------------------------------------------------------

class GhidraProgramDiff:
    """Iki binary arasindaki farklari tespit eden diff motoru.

    PyGhidra mevcut ise gercek Ghidra API kullanir.
    Degilse onceden uretilmis JSON'lar uzerinden calisir.

    Args:
        config: Merkezi konfigurasyon.
    """

    def __init__(self, config: Config) -> None:
        self.config = config

    # ----- PyGhidra-based diff -----

    def diff(
        self,
        binary1: Path,
        binary2: Path,
        output_dir: Path | None = None,
    ) -> DiffReport:
        """Iki binary'yi PyGhidra ile acip karsilastirir.

        Her binary ayri bir Ghidra projesinde acilir.
        FunctionManager'lar karsilastirilir: isim eslestirme + adres yakinligi.

        Args:
            binary1: Birinci (eski) binary dosyasi.
            binary2: Ikinci (yeni) binary dosyasi.
            output_dir: Rapor cikti dizini. None ise binary1'in yanina yazar.

        Returns:
            DiffReport: Karsilastirma raporu.

        Raises:
            RuntimeError: PyGhidra bulunamazsa.
            FileNotFoundError: Binary dosyasi bulunamazsa.
        """
        if not _check_pyghidra():
            raise RuntimeError(
                "PyGhidra bulunamadi. PyGhidra yukleyin veya "
                "diff_from_json() ile onceden uretilmis JSON'lari kullanin."
            )

        binary1 = Path(binary1).resolve()
        binary2 = Path(binary2).resolve()

        if not binary1.exists():
            raise FileNotFoundError(f"Binary bulunamadi: {binary1}")
        if not binary2.exists():
            raise FileNotFoundError(f"Binary bulunamadi: {binary2}")

        effective_output = output_dir or binary1.parent
        effective_output = Path(effective_output).resolve()
        effective_output.mkdir(parents=True, exist_ok=True)

        t0 = time.monotonic()

        # PyGhidra JVM'i baslat
        from karadul.ghidra.headless import _ensure_pyghidra_started
        ghidra_install = self.config.tools.ghidra_install
        _ensure_pyghidra_started(ghidra_install)

        import pyghidra

        # Her binary icin ayri proje olustur
        funcs1 = self._extract_functions_pyghidra(
            pyghidra, binary1, project_name="diff_prog1",
        )
        funcs2 = self._extract_functions_pyghidra(
            pyghidra, binary2, project_name="diff_prog2",
        )

        # Eslestirme ve karsilastirma
        matched, added, removed = self._match_functions(funcs1, funcs2)

        # Diff listesi olustur
        function_diffs: list[FunctionDiff] = []

        # Eslesen fonksiyonlar
        for f1, f2 in matched:
            size_change = f2.size - f1.size
            instr_diff = (f2.instruction_count - f1.instruction_count
                          if f1.instruction_count and f2.instruction_count
                          else None)
            status = "unchanged" if (size_change == 0 and instr_diff in (None, 0)) else "modified"
            function_diffs.append(FunctionDiff(
                name=f1.name,
                address1=f1.address,
                address2=f2.address,
                status=status,
                size_change=size_change,
                instruction_diff=instr_diff,
            ))

        # Eklenen fonksiyonlar
        for f in added:
            function_diffs.append(FunctionDiff(
                name=f.name,
                address1=None,
                address2=f.address,
                status="added",
                size_change=f.size,
            ))

        # Silinen fonksiyonlar
        for f in removed:
            function_diffs.append(FunctionDiff(
                name=f.name,
                address1=f.address,
                address2=None,
                status="removed",
                size_change=-f.size,
            ))

        # Ozet hesapla
        n_unchanged = sum(1 for d in function_diffs if d.status == "unchanged")
        n_modified = sum(1 for d in function_diffs if d.status == "modified")
        n_added = sum(1 for d in function_diffs if d.status == "added")
        n_removed = sum(1 for d in function_diffs if d.status == "removed")

        summary = DiffSummary(
            functions_added=n_added,
            functions_removed=n_removed,
            functions_modified=n_modified,
            functions_unchanged=n_unchanged,
            total_functions_1=len(funcs1),
            total_functions_2=len(funcs2),
        )

        duration = time.monotonic() - t0

        report = DiffReport(
            binary1_name=binary1.name,
            binary2_name=binary2.name,
            summary=summary,
            function_diffs=function_diffs,
            duration_seconds=round(duration, 3),
        )

        # JSON rapor
        self._generate_json_report(report, effective_output)

        logger.info(
            "ProgramDiff tamamlandi: %s vs %s -- "
            "+%d -%d ~%d =%d (%.1fs)",
            binary1.name, binary2.name,
            n_added, n_removed, n_modified, n_unchanged, duration,
        )

        return report

    def _extract_functions_pyghidra(
        self,
        pyghidra_mod: Any,
        binary_path: Path,
        project_name: str,
    ) -> list[_FuncInfo]:
        """PyGhidra ile binary'den fonksiyon bilgilerini cikarir.

        Args:
            pyghidra_mod: pyghidra modulu (import edilmis).
            binary_path: Binary dosya yolu.
            project_name: Ghidra proje adi (cakismamasi icin farkli olmali).

        Returns:
            list[_FuncInfo]: Fonksiyon listesi.
        """
        funcs: list[_FuncInfo] = []
        try:
            with pyghidra_mod.open_program(
                str(binary_path),
                project_name=project_name,
                analyze=True,
            ) as flat_api:
                program = flat_api.getCurrentProgram()
                func_manager = program.getFunctionManager()
                func_iter = func_manager.getFunctions(True)  # Forward iterator

                while func_iter.hasNext():
                    func = func_iter.next()
                    name = func.getName()
                    addr = str(func.getEntryPoint())
                    body = func.getBody()
                    size = int(body.getNumAddresses()) if body else 0

                    # Instruction sayisi
                    instr_count = 0
                    try:
                        listing = program.getListing()
                        if body:
                            instr_iter = listing.getInstructions(body, True)
                            while instr_iter.hasNext():
                                instr_iter.next()
                                instr_count += 1
                    except Exception:
                        logger.debug("Instruction sayimi basarisiz -- devam", exc_info=True)

                    funcs.append(_FuncInfo(
                        name=name,
                        address=addr,
                        size=size,
                        instruction_count=instr_count,
                    ))

        except Exception as exc:
            logger.error("PyGhidra fonksiyon cikarma hatasi (%s): %s", binary_path, exc)
            raise

        logger.info(
            "PyGhidra: %s -- %d fonksiyon cikarildi",
            binary_path.name, len(funcs),
        )
        return funcs

    # ----- JSON-based diff (fallback) -----

    def diff_from_json(
        self,
        functions_json_1: Path,
        functions_json_2: Path,
        output_dir: Path | None = None,
    ) -> DiffReport:
        """Onceden uretilmis ghidra_functions.json dosyalarini karsilastirir.

        PyGhidra gerektirmez. Ghidra analiz ciktisi olan JSON dosyalarini
        okuyarak fonksiyon karsilastirmasi yapar.

        Beklenen JSON formati:
            [
                {
                    "name": "main",
                    "entry_point": "0x100000",
                    "size": 256,
                    "instruction_count": 42  // opsiyonel
                },
                ...
            ]

        Alternatif format (dict anahtarli):
            {
                "functions": [...]
            }

        Args:
            functions_json_1: Birinci binary'nin fonksiyon JSON'u.
            functions_json_2: Ikinci binary'nin fonksiyon JSON'u.
            output_dir: Rapor cikti dizini.

        Returns:
            DiffReport: Karsilastirma raporu.
        """
        t0 = time.monotonic()

        functions_json_1 = Path(functions_json_1).resolve()
        functions_json_2 = Path(functions_json_2).resolve()

        if not functions_json_1.exists():
            raise FileNotFoundError(f"JSON bulunamadi: {functions_json_1}")
        if not functions_json_2.exists():
            raise FileNotFoundError(f"JSON bulunamadi: {functions_json_2}")

        funcs1 = self._parse_functions_json(functions_json_1)
        funcs2 = self._parse_functions_json(functions_json_2)

        # Eslestirme
        matched, added, removed = self._match_functions(funcs1, funcs2)

        # Diff listesi
        function_diffs: list[FunctionDiff] = []

        for f1, f2 in matched:
            size_change = f2.size - f1.size
            instr_diff = (f2.instruction_count - f1.instruction_count
                          if f1.instruction_count and f2.instruction_count
                          else None)
            status = "unchanged" if (size_change == 0 and instr_diff in (None, 0)) else "modified"
            function_diffs.append(FunctionDiff(
                name=f1.name,
                address1=f1.address,
                address2=f2.address,
                status=status,
                size_change=size_change,
                instruction_diff=instr_diff,
            ))

        for f in added:
            function_diffs.append(FunctionDiff(
                name=f.name,
                address1=None,
                address2=f.address,
                status="added",
                size_change=f.size,
            ))

        for f in removed:
            function_diffs.append(FunctionDiff(
                name=f.name,
                address1=f.address,
                address2=None,
                status="removed",
                size_change=-f.size,
            ))

        n_unchanged = sum(1 for d in function_diffs if d.status == "unchanged")
        n_modified = sum(1 for d in function_diffs if d.status == "modified")
        n_added = sum(1 for d in function_diffs if d.status == "added")
        n_removed = sum(1 for d in function_diffs if d.status == "removed")

        summary = DiffSummary(
            functions_added=n_added,
            functions_removed=n_removed,
            functions_modified=n_modified,
            functions_unchanged=n_unchanged,
            total_functions_1=len(funcs1),
            total_functions_2=len(funcs2),
        )

        duration = time.monotonic() - t0

        report = DiffReport(
            binary1_name=functions_json_1.stem,
            binary2_name=functions_json_2.stem,
            summary=summary,
            function_diffs=function_diffs,
            duration_seconds=round(duration, 3),
        )

        # JSON rapor
        if output_dir:
            output_dir = Path(output_dir).resolve()
            output_dir.mkdir(parents=True, exist_ok=True)
            self._generate_json_report(report, output_dir)

        logger.info(
            "JSON diff tamamlandi: %s vs %s -- +%d -%d ~%d =%d (%.3fs)",
            functions_json_1.name, functions_json_2.name,
            n_added, n_removed, n_modified, n_unchanged, duration,
        )

        return report

    def _parse_functions_json(self, json_path: Path) -> list[_FuncInfo]:
        """JSON dosyasindan fonksiyon listesi okur.

        Desteklenen formatlar:
          - Liste: [{"name": ..., "entry_point": ..., "size": ...}, ...]
          - Dict: {"functions": [...]}

        Args:
            json_path: JSON dosya yolu.

        Returns:
            list[_FuncInfo]: Fonksiyon bilgileri.
        """
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.error("JSON parse hatasi (%s): %s", json_path, exc)
            return []

        # Format tespiti
        if isinstance(raw, dict):
            func_list = raw.get("functions", [])
        elif isinstance(raw, list):
            func_list = raw
        else:
            logger.warning("Beklenmeyen JSON yapisi: %s", type(raw).__name__)
            return []

        funcs: list[_FuncInfo] = []
        for item in func_list:
            if not isinstance(item, dict):
                continue
            name = item.get("name", item.get("function_name", ""))
            address = item.get("entry_point", item.get("address", ""))
            size = item.get("size", item.get("body_size", 0))
            instr = item.get("instruction_count", item.get("instr_count", 0))

            if not name:
                continue

            funcs.append(_FuncInfo(
                name=str(name),
                address=str(address),
                size=int(size) if size else 0,
                instruction_count=int(instr) if instr else 0,
            ))

        return funcs

    # ----- Fonksiyon eslestirme -----

    @staticmethod
    def _match_functions(
        funcs1: list[_FuncInfo],
        funcs2: list[_FuncInfo],
    ) -> tuple[list[tuple[_FuncInfo, _FuncInfo]], list[_FuncInfo], list[_FuncInfo]]:
        """Iki fonksiyon listesini eslestirir.

        Eslestirme stratejisi:
        1. Isim eslestirme: ayni isme sahip fonksiyonlar eslestirilir.
        2. Adres yakinligi: isim eslesmeyen fonksiyonlar icin adres
           yakinligina gore eslestirme denenir.

        Args:
            funcs1: Birinci binary'nin fonksiyonlari.
            funcs2: Ikinci binary'nin fonksiyonlari.

        Returns:
            tuple:
                matched -- eslesen ciftler [(f1, f2), ...]
                added   -- sadece funcs2'de olan fonksiyonlar
                removed -- sadece funcs1'de olan fonksiyonlar
        """
        matched: list[tuple[_FuncInfo, _FuncInfo]] = []
        added: list[_FuncInfo] = []
        removed: list[_FuncInfo] = []

        # Isim tabanlari index
        name_to_f1: dict[str, _FuncInfo] = {f.name: f for f in funcs1}
        name_to_f2: dict[str, _FuncInfo] = {f.name: f for f in funcs2}

        # 1. Isim eslestirme
        matched_names: set[str] = set()

        for name, f2 in name_to_f2.items():
            f1 = name_to_f1.get(name)
            if f1 is not None:
                matched.append((f1, f2))
                matched_names.add(name)

        # Eslesmeyenler
        unmatched_f1 = [f for f in funcs1 if f.name not in matched_names]
        unmatched_f2 = [f for f in funcs2 if f.name not in matched_names]

        # 2. Adres yakinligi ile eslestirme
        # Adres'leri integer'a cevir (hex parse)
        def _addr_int(addr_str: str) -> int | None:
            """Adres stringini integer'a cevir."""
            if not addr_str:
                return None
            try:
                cleaned = addr_str.lower().replace("0x", "").lstrip("0") or "0"
                return int(cleaned, 16)
            except (ValueError, TypeError):
                return None

        # Adres tabanlari eslestirme -- her eslesmeyen f1 icin en yakin f2'yi bul
        if unmatched_f1 and unmatched_f2:
            f2_addrs = [(f, _addr_int(f.address)) for f in unmatched_f2]
            f2_addrs = [(f, a) for f, a in f2_addrs if a is not None]

            addr_matched_f2: set[str] = set()  # Zaten eslesmis f2 adresleri

            remaining_f1: list[_FuncInfo] = []
            for f1 in unmatched_f1:
                a1 = _addr_int(f1.address)
                if a1 is None:
                    remaining_f1.append(f1)
                    continue

                # En yakin f2'yi bul (threshold: 256 byte)
                best_f2: _FuncInfo | None = None
                best_dist = 256  # Maksimum adres farki

                for f2, a2 in f2_addrs:
                    if f2.address in addr_matched_f2:
                        continue
                    dist = abs(a1 - a2)
                    if dist < best_dist:
                        best_dist = dist
                        best_f2 = f2

                if best_f2 is not None:
                    matched.append((f1, best_f2))
                    addr_matched_f2.add(best_f2.address)
                else:
                    remaining_f1.append(f1)

            # Kalan eslesmeyenler
            removed = remaining_f1
            added = [f for f in unmatched_f2 if f.address not in addr_matched_f2]
        else:
            removed = unmatched_f1
            added = unmatched_f2

        return matched, added, removed

    # ----- Rapor uretimi -----

    @staticmethod
    def _generate_json_report(report: DiffReport, output_dir: Path) -> Path:
        """Diff raporunu JSON dosyasina yazar.

        Args:
            report: Diff raporu.
            output_dir: Cikti dizini.

        Returns:
            Path: Yazilan JSON dosyasinin yolu.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        report_path = output_dir / "diff_report.json"

        data = {
            "binary1": report.binary1_name,
            "binary2": report.binary2_name,
            "duration_seconds": report.duration_seconds,
            "summary": asdict(report.summary),
            "change_rate": report.summary.change_rate,
            "function_diffs": [asdict(fd) for fd in report.function_diffs],
        }

        report_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        logger.info("Diff raporu yazildi: %s", report_path)
        return report_path
