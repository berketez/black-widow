"""Python packed binary analyzer.

PyInstaller, cx_Freeze, Nuitka ile paketlenmis Python uygulamalarini analiz eder:
- PyInstaller: PYZ magic bytes, MEIPASS marker, PKG/TOC yapisi
- cx_Freeze: frozen module detection, cx_Freeze marker strings
- Nuitka: nuitka-version string, _nuitka marker
- Python versiyonu tespiti (.pyc magic number'dan)
- Embedded .pyc dosyalarinin listesini cikarma

Strateji:
1. Magic bytes ve string pattern'lerle paketleyici tespit et
2. Binary icindeki .pyc referanslarini bul
3. Python versiyonu tespit et (.pyc magic -> versiyon eslesmesi)
4. Embedded modul listesini cikar
"""

from __future__ import annotations

import json
import logging
import re
import struct
import time
from pathlib import Path
from typing import Any

from karadul.analyzers import register_analyzer
from karadul.analyzers.base import BaseAnalyzer
from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.subprocess_runner import SubprocessRunner
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace
from karadul.analyzers.pyc_decompiler import (
    _PYC_MAGIC_TO_VERSION,
    decompile_pyc,
    pycdc_available,
    repair_pyc_header,
    version_from_pyc_bytes,
)
from karadul.analyzers.packed_binary import (
    _MAX_PYINSTALLER_DECOMPRESS,
    _PYZ_MAX_NAME_BYTES,
    _is_safe_pyz_module_name,
    _is_windows_reserved,
    _write_pyz_member,
    PYZ_MAGIC,
    PyInstallerExtractor,
    PyzFormatError,
    classify_pyz_module,
    locate_pyinstaller_archive,
    parse_pyz,
    pyinstaller_python_version,
    select_decompile_chain,
    unique_casefold_name,
)
from karadul.core.safe_subprocess import safe_zlib_decompress

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# PyInstaller magic bytes & markers
# --------------------------------------------------------------------------

# PyInstaller archive cookie (end-of-archive marker)
# "MEI\014\013\012\013\016" — 8 byte magic
_PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"

# PyInstaller bootloader MEIPASS marker
_MEIPASS_MARKER = b"_MEIPASS"

# PYZ archive magic bytes (used inside PyInstaller archives)
# "PYZ\0" header -- tek kaynak packed_binary.PYZ_MAGIC (PYZ okuyucusu orada).
_PYZ_MAGIC = PYZ_MAGIC

# --------------------------------------------------------------------------
# cx_Freeze markers
# --------------------------------------------------------------------------

_CXFREEZE_MARKERS = [
    b"cx_Freeze",
    b"cx_freeze",
    b"__cxfreeze__",
    b"frozen_modules",
    b"initscript",
]

# --------------------------------------------------------------------------
# Nuitka markers
# --------------------------------------------------------------------------

_NUITKA_MARKERS = [
    b"nuitka-version:",
    b"Nuitka",
    b"_nuitka",
    b"__nuitka_binary",
    b"onefile_bootstrap",
]

# --------------------------------------------------------------------------
# .pyc magic number -> Python versiyon tablosu artik pyc_decompiler.py'de
# TEK KAYNAK (CLAUDE.md #11). Yukarida import edildi; re-export burada tutulur
# (geriye donuk: bu modulden import eden kod calismaya devam eder).

# Python versiyon string pattern'leri (binary string'lerde)
_PYTHON_VERSION_PATTERN = re.compile(
    r"Python\s+(\d+\.\d+(?:\.\d+)?)"
)
_PYTHON_VERSION_SHORT_PATTERN = re.compile(
    r"python(\d)\.(\d{1,2})"
)

# .pyc/.pyo dosya referans pattern'i (embedded modullerin isimleri)
_PYC_MODULE_PATTERN = re.compile(
    r"([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\.pyc?"
)


# Decompile üst sınırı aşıldığında atlanan .pyc'lerin listesi (manifest'le aynı dizinde).
_DECOMPILE_SKIPPED_FILE = "decompile_skipped.json"
_DECOMPILE_LIMIT_POLICY = (
    "Zincirdeki .pyc sayısı security.max_python_decompile_modules'u aşarsa üst düzey "
    "paketi az modüllü olanlar önce işlenir (uygulama betikleri/kendi modülleri önce, "
    "büyük üçüncü parti paketler sona); eşitlikte arşiv sırası. Atlananlar çıkarılmış "
    ".pyc olarak durur, yalnız decompile edilmez."
)


def _pyinstaller_note(summary: dict[str, Any]) -> str:
    """PyInstaller manifest notu -- decompile sonucuna gore dinamik ve DURUST.

    "Python %100" iddia edilmez; ne decompile edildi, ne disassembly'de kaldi
    acikca yazilir (bkz. pyc_decompiler bilgisel tavan notu).
    """
    skipped = (summary or {}).get("skipped_by_limit", 0)
    if not summary or (summary.get("total_pyc", 0) == 0 and not skipped):
        return (
            "Paket acildi ama islenecek .pyc bulunamadi "
            "(native .so/derlenmis, sifreli, veya dagitim dizini eksik olabilir)."
        )
    total = summary.get("total_pyc", 0)
    dec = summary.get("decompiled", 0)
    part = summary.get("partial", 0)
    dis = summary.get("disasm", 0)
    failed = summary.get("failed", 0)
    parts = [f"{total} .pyc işlendi"]
    if skipped:
        parts.append(
            f"{skipped} .pyc decompile üst sınırı ({summary.get('limit')}) nedeniyle "
            f"İŞLENMEDİ (liste: {summary.get('skipped_list', _DECOMPILE_SKIPPED_FILE)}; "
            "sınır: security.max_python_decompile_modules)"
        )
    if dec:
        parts.append(f"{dec} tanesi doğrulanmış kaynak (.py) olarak decompile edildi")
    if part:
        parts.append(
            f"{part} tanesinde pycdc yalnız kısmi/geçersiz kaynak verdi "
            "(.partial.py, nedeni dosya başında; varsa yanında .disasm.txt)"
        )
    if dis:
        msg = f"{dis} tanesi yalnız bytecode disassembly olarak kurtarıldı"
        # pycdc zaten kuruluysa "kurun" demek yanıltıcı (3.12+ tavanı araç eksikliği değil).
        if not summary.get("pycdc_available", False):
            msg += " (daha iyi sonuç için pycdc kurun: scripts/setup_pycdc.sh)"
        parts.append(msg)
    if failed:
        parts.append(f"{failed} tanesi çözülemedi")
    return "; ".join(parts) + "."


# PYZ decompile politikası (manifest'te aynen görünür). Sınıflandırma:
# packed_binary.classify_pyz_module.
_PYZ_POLICY = (
    "PYZ modülleri hedef Python sürümüne göre sınıflanır: stdlib "
    "(sys.stdlib_module_names + sürüm farkı tablosu) ve PyInstaller iç modülleri "
    "(pyimod*/pyiboot*/pyi_*/_pyi_*) yalnız çıkarılır ve listelenir; geri kalan "
    "her modül (uygulama + üçüncü parti) decompile zincirine girer "
    "(üst sınır: security.max_python_decompile_modules)."
)
_PYZ_MODULES_FILE = "pyz_modules.json"


def _pyz_summary(extracted_files: list, output_dir: Path) -> dict[str, Any]:
    """PYZ açma sonucunu manifest için özetle; tam modül listesini dosyaya yaz.

    Raporlar ``PyInstallerExtractor`` tarafından PYZ blobunun ExtractedFile
    metadata'sına (``"pyz"``) konur; modüllerin kategorisi ``pyz_category``'dedir.
    PYZ yoksa boş dict.
    """
    archives = [
        ef.metadata["pyz"] for ef in extracted_files
        if isinstance((getattr(ef, "metadata", None) or {}).get("pyz"), dict)
    ]
    if not archives:
        return {}
    members = [
        ef for ef in extracted_files
        if (getattr(ef, "metadata", None) or {}).get("pyz_module")
    ]
    by_category: dict[str, int] = {}
    listing: list[dict[str, Any]] = []
    for ef in members:
        cat = ef.metadata.get("pyz_category", "user")
        by_category[cat] = by_category.get(cat, 0) + 1
        try:
            rel = str(ef.path.relative_to(output_dir))
        except ValueError:
            rel = str(ef.path)
        listing.append({
            "name": ef.original_name,
            "category": cat,
            "archive": ef.metadata.get("pyz_archive"),
            "typecode": ef.metadata.get("pyz_typecode"),
            "is_package": ef.metadata.get("is_package", False),
            "path": rel,
            "size": ef.size,
        })
    (output_dir / _PYZ_MODULES_FILE).write_text(
        json.dumps({"archives": archives, "modules": listing}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    rejected: dict[str, int] = {}
    for rep in archives:
        for reason, n in (rep.get("rejected") or {}).items():
            rejected[reason] = rejected.get(reason, 0) + n
    versions = {rep.get("python_version") for rep in archives if rep.get("python_version")}
    return {
        "policy": _PYZ_POLICY,
        "python_version": versions.pop() if len(versions) == 1 else None,
        "modules_extracted": len(members),
        "decompile_chain": by_category.get("user", 0),
        "skipped_stdlib": by_category.get("stdlib", 0),
        "skipped_pyinstaller": by_category.get("pyinstaller", 0),
        "rejected": rejected,
        "encrypted": any(rep.get("encrypted") for rep in archives),
        # Şifreli arşivin ad listesi manifest'i şişirmesin: yalnız dosyada.
        "archives": [
            {k: v for k, v in rep.items() if k != "encrypted_module_names"}
            for rep in archives
        ],
        "modules_list": _PYZ_MODULES_FILE,
    }


def _pyz_note(pyz: dict[str, Any]) -> str:
    """Manifest notuna PYZ cümlesi (PYZ yoksa boş)."""
    if not pyz:
        return ""
    if pyz.get("encrypted"):
        return (
            "PYZ şifreli (PyInstaller <6.0 bytecode şifrelemesi): modül adları "
            f"{_PYZ_MODULES_FILE} içinde, içerik çözülmedi."
        )
    if all(rep.get("error") for rep in pyz.get("archives", [])):
        return "PYZ okunamadı (ayrıntı extraction_errors içinde)."
    msg = (
        f"PYZ: {pyz['modules_extracted']} modül çıkarıldı; "
        f"{pyz['decompile_chain']} tanesi decompile zincirine girdi, "
        f"{pyz['skipped_stdlib']} stdlib ve {pyz['skipped_pyinstaller']} PyInstaller "
        f"iç modülü yalnız listelendi ({_PYZ_MODULES_FILE})."
    )
    n_rejected = sum(pyz.get("rejected", {}).values())
    if n_rejected:
        msg += f" {n_rejected} PYZ girdisi reddedildi (nedenleri manifest'te)."
    return msg


def _module_inventory(
    modules: list[dict[str, Any]], *, source: str, python_version: str | None,
) -> dict[str, Any]:
    """python_modules.json biçimi: kategori sayıları + (ilk 5000) modül listesi.

    ``source``: ``"pyinstaller_toc"`` (CArchive + PYZ TOC'leri; gerçek envanter) ya da
    ``"string_scan"`` (binary'deki ``ad.py[c]`` dizgeleri; yalnız sezgi).
    """
    counts: dict[str, int] = {}
    for m in modules:
        counts[m["type"]] = counts.get(m["type"], 0) + 1
    return {
        "source": source,
        "python_version": python_version,
        "total": len(modules),
        "user_count": counts.get("user", 0),
        "stdlib_count": counts.get("stdlib", 0),
        "pyinstaller_count": counts.get("pyinstaller", 0),
        "modules": modules[:5000],  # max 5000 modul
    }


def _cxfreeze_module_name(rel_path: str) -> tuple[str, bool]:
    """cx_Freeze içindeki .pyc yolu -> (noktalı modül adı, paket mi).

    ``pkg/__init__.pyc`` -> (``pkg``, True); ``a/b_c.pyc`` -> ``a.b_c``;
    ``pkg/__pycache__/m.cpython-312.pyc`` -> ``pkg.m``. Bileşenleri Python
    tanımlayıcısı olmayan (``..``, ``-`` vb.) ad tek bileşene düzleştirilir; güvenlik
    ölçütü PYZ üyeleriyle aynıdır (``_is_safe_pyz_module_name``).
    """
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p]
    if parts and parts[-1].endswith(".pyc"):
        parts[-1] = parts[-1][:-4]
    if len(parts) >= 2 and parts[-2] == "__pycache__":
        parts = parts[:-2] + [parts[-1].split(".", 1)[0]]
    is_package = len(parts) > 1 and parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    name = ".".join(parts)
    if _is_safe_pyz_module_name(name):
        return name, is_package
    flat = re.sub(r"[^0-9A-Za-z_]+", "_", "_".join(parts)).strip("_") or "unnamed"
    flat = flat[:_PYZ_MAX_NAME_BYTES - 16]
    if _is_windows_reserved(flat + ".pyc"):
        flat = "_" + flat
    return flat, is_package


def _vendor_tool_paths() -> list[str] | None:
    """setup_pycdc.sh'ın pycdc VE pycdas kurduğu vendor/pycdc dizini (yoksa None).

    python_binary.py -> parents[0]=analyzers, [1]=karadul, [2]=depo kökü; editable
    kurulumda cwd'den bağımsızdır. Testler için ayrı fonksiyon (monkeypatch).
    """
    vendor_pycdc = Path(__file__).resolve().parents[2] / "vendor" / "pycdc"
    return [str(vendor_pycdc)] if vendor_pycdc.is_dir() else None


@register_analyzer(TargetType.PYTHON_PACKED)
class PythonBinaryAnalyzer(BaseAnalyzer):
    """Python packed binary analyzer.

    PyInstaller, cx_Freeze, Nuitka ile paketlenmis Python
    uygulamalarini analiz eder. Paketleyici tespiti, Python
    versiyon tespiti ve embedded modul listesini cikarir.
    """

    supported_types = [TargetType.PYTHON_PACKED]

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.runner = SubprocessRunner(config)

    # ------------------------------------------------------------------
    # Public interface (BaseAnalyzer)
    # ------------------------------------------------------------------

    @staticmethod
    def can_handle(target_info: TargetInfo) -> bool:
        """Python packed binary mi kontrol et.

        Binary icindeki PyInstaller, cx_Freeze veya Nuitka
        marker'larina bakar.
        """
        try:
            with open(target_info.path, "rb") as f:
                data = f.read(2 * 1024 * 1024)  # Ilk 2MB
        except OSError:
            return False

        # PyInstaller: MEIPASS marker veya MEI magic
        if _MEIPASS_MARKER in data:
            return True
        if _PYINSTALLER_MAGIC in data:
            return True
        if _PYZ_MAGIC in data:
            return True

        # cx_Freeze markers
        for marker in _CXFREEZE_MARKERS:
            if marker in data:
                return True

        # Nuitka markers
        for marker in _NUITKA_MARKERS:
            if marker in data:
                return True

        return False

    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Python packed binary statik analizi.

        Siralama:
        1. Paketleyici tipi tespiti (PyInstaller/cx_Freeze/Nuitka)
        2. Python versiyon tespiti
        3. Embedded .pyc modul listesi cikarma
        4. PyInstaller TOC (Table of Contents) parse
        5. String extraction

        Args:
            target: Hedef bilgileri.
            workspace: Calisma dizini.

        Returns:
            StageResult: Statik analiz sonucu.
        """
        start = time.monotonic()
        artifacts: dict[str, Path] = {}
        errors: list[str] = []
        stats: dict[str, Any] = {
            "analyzer": "python_binary",
        }

        binary_path = target.path

        # Binary verisini oku (analiz boyunca kullanilacak)
        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()
        except OSError as exc:
            errors.append(f"Binary okunamadi: {exc}")
            return StageResult(
                stage_name="static",
                success=False,
                duration_seconds=time.monotonic() - start,
                errors=errors,
            )

        # 1. Paketleyici tespiti
        packer_info = self._detect_packer(binary_data)
        stats["packer"] = packer_info["packer"]
        stats["packer_confidence"] = packer_info["confidence"]
        if packer_info.get("details"):
            packer_path = workspace.save_json("static", "python_packer", packer_info)
            artifacts["python_packer"] = packer_path

        # 2. Python versiyon tespiti
        python_version = self._detect_python_version(binary_data)
        stats["python_version"] = python_version or "unknown"
        # reconstruct icin sakla: PyInstaller .pyc header'lari genelde SIYRILMIS oldugundan
        # decompile asamasi surumu buradan ogrenir (header'dan okuyamaz).
        if python_version:
            workspace.save_json("static", "python_version", {"version": python_version})

        # 3. Modül envanteri. PyInstaller: CArchive + PYZ TOC'leri (reconstruct'taki
        #    çıkarıcıyla aynı veri, tek sınıflandırıcı). TOC okunamaz/boşsa ya da başka
        #    paketleyicide yalnız string taraması kalır (source="string_scan").
        modules = None
        if packer_info["packer"] == "pyinstaller":
            modules = self._pyinstaller_module_inventory(binary_data, python_version)
        if not modules or modules["total"] == 0:
            modules = self._extract_embedded_modules(binary_data, python_version)
        if modules:
            mod_path = workspace.save_json("static", "python_modules", modules)
            artifacts["python_modules"] = mod_path
            stats["module_count"] = modules["total"]
            stats["stdlib_modules"] = modules.get("stdlib_count", 0)
            stats["user_modules"] = modules.get("user_count", 0)
            stats["pyinstaller_modules"] = modules.get("pyinstaller_count", 0)
            stats["module_source"] = modules.get("source", "string_scan")

        # "Functions recovered" (cli.py) proxy'si: kurtarilan Python modul sayisi.
        # JVM'de metot, .NET'te CIL metodu; Python'da modul = kurtarilan kod birimi.
        # Set edilmezse packed binary "0 fonksiyon" gorunur (kapsam bug'i, misroute deseni).
        _recovered_modules = stats.get("module_count", 0)
        stats["functions"] = _recovered_modules
        stats["functions_found"] = _recovered_modules

        # 4. PyInstaller TOC (varsa)
        if packer_info["packer"] == "pyinstaller":
            toc = self._parse_pyinstaller_toc(binary_data)
            if toc:
                toc_path = workspace.save_json("static", "pyinstaller_toc", toc)
                artifacts["pyinstaller_toc"] = toc_path
                stats["toc_entry_count"] = toc.get("total", 0)

        # 5. String extraction
        string_list = self.runner.run_strings(binary_path)
        if string_list:
            # Python-ilgili stringleri filtrele
            py_strings = self._filter_python_strings(string_list)
            strings_data = {
                "total": len(string_list),
                "python_related": len(py_strings),
                "strings": string_list[:10000],
                "python_strings": py_strings[:2000],
            }
            str_path = workspace.save_json("static", "strings_raw", strings_data)
            artifacts["strings_raw"] = str_path
            stats["string_count"] = len(string_list)
            stats["python_string_count"] = len(py_strings)

        duration = time.monotonic() - start
        stats["total_duration"] = round(duration, 3)

        return StageResult(
            stage_name="static",
            success=packer_info["packer"] != "unknown" or len(artifacts) > 0,
            duration_seconds=duration,
            artifacts=artifacts,
            stats=stats,
            errors=errors,
        )

    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Python packed binary deobfuscation.

        Python packed binary'ler icin deobfuscation:
        - Modul listesini deobfuscated dizinine tasi
        - Packer bilgisini raporla
        """
        start = time.monotonic()
        artifacts: dict[str, Path] = {}
        errors: list[str] = []

        # Packer bilgisini tasi
        packer_info = workspace.load_json("static", "python_packer")
        if packer_info:
            deobf_path = workspace.save_json("deobfuscated", "python_packer", packer_info)
            artifacts["python_packer"] = deobf_path

        # Modul listesini tasi
        modules = workspace.load_json("static", "python_modules")
        if modules:
            mod_path = workspace.save_json("deobfuscated", "python_modules", modules)
            artifacts["python_modules"] = mod_path
        else:
            errors.append("Embedded modul listesi bulunamadi")

        return StageResult(
            stage_name="deobfuscate",
            success=len(errors) == 0 or len(artifacts) > 0,
            duration_seconds=time.monotonic() - start,
            artifacts=artifacts,
            errors=errors,
        )

    def reconstruct(self, target: TargetInfo, workspace: Workspace) -> StageResult | None:
        """Python paketinden proje iskeleti olustur.

        Native binary DEGIL: Ghidra/JS yerine paketleyiciye ozel kurtarma. PyInstaller
        icin `packed_binary.PyInstallerExtractor` ile GERCEK CArchive extraction yapilir
        (pipeline'a bagli olmayan gercek unpacker'i burada wire eder) -> cikarilmis
        .pyc/.py dosyalari + manifest. Static analiz kosmadiysa (packer/modul JSON'u yok)
        None doner -> ReconstructionStage bunu graceful fail'e cevirir.

        Ciktı: reconstructed/python_project/ (extracted/ + manifest.json).
        """
        start = time.monotonic()

        # Static analiz kosmus olmali (packer + modul bilgisi icin)
        packer_info = workspace.load_json("static", "python_packer")
        modules = workspace.load_json("static", "python_modules")
        if not packer_info and not modules:
            return None

        output_dir = workspace.get_stage_dir("reconstructed") / "python_project"
        output_dir.mkdir(parents=True, exist_ok=True)

        packer = (packer_info or {}).get("packer", "unknown")
        extracted_count = 0
        extract_errors: list[str] = []
        decompile_summary: dict[str, Any] = {}
        pyz: dict[str, Any] = {}

        # Surum static asamada tespit edildi (paketleyiciler .pyc header'ini siyirabilir).
        pv_info = workspace.load_json("static", "python_version")
        detected_version = (pv_info or {}).get("version")

        # PyInstaller: gercek CArchive extraction (packed_binary unpacker'i wire et)
        if packer == "pyinstaller":
            try:
                from karadul.analyzers.packed_binary import PyInstallerExtractor
                unpack = PyInstallerExtractor(self.config).extract(
                    target.path, output_dir / "extracted",
                )
                extracted_count = len(unpack.extracted_files)
                extract_errors = list(unpack.errors)
                pyz = _pyz_summary(unpack.extracted_files, output_dir)
                # PYZ başlığındaki bytecode magic derleyen yorumlayıcının kendisidir;
                # static aşamanın sezgisel tespitinden önce gelir.
                py_version = pyz.get("python_version") or detected_version
                # Politika: PYZ'nin stdlib/PyInstaller modülleri zincire girmez.
                chain = [
                    ef for ef in unpack.extracted_files
                    if (getattr(ef, "metadata", None) or {}).get("pyz_category", "user") == "user"
                ]
                # .pyc -> .py: header onar + deterministik decompile (LLM'siz zincir).
                decompile_summary = self._decompile_pyc_files(
                    chain, output_dir, py_version=py_version,
                )
            except Exception as exc:
                logger.debug("PyInstaller extraction basarisiz: %s", exc, exc_info=True)
                extract_errors.append(f"{type(exc).__name__}: {exc}")

        # cx_Freeze: lib/library.zip (standart ZIP) + lib/ altindaki serbest .pyc'ler
        elif packer == "cx_freeze":
            try:
                extracted = self._extract_cxfreeze(target.path, output_dir / "extracted")
                extracted_count = len(extracted)
                if not extracted:
                    extract_errors.append(
                        "cx_Freeze: library.zip / lib/ bulunamadi "
                        "(binary tek basina verildi, dagitim dizini eksik olabilir)"
                    )
                decompile_summary = self._decompile_pyc_files(
                    extracted, output_dir, py_version=detected_version,
                )
            except Exception as exc:
                logger.debug("cx_Freeze extraction basarisiz: %s", exc, exc_info=True)
                extract_errors.append(f"{type(exc).__name__}: {exc}")

        # Manifest: kurtarilan yapinin ozeti (extraction basarisiz olsa da yazilir)
        manifest = {
            "packer": packer,
            "native_format": target.metadata.get("native_format"),
            # Static envanter (PyInstaller'da iki TOC; bkz. _pyinstaller_module_inventory).
            "module_summary": {
                "source": (modules or {}).get("source", "string_scan"),
                "total": (modules or {}).get("total", 0),
                "user": (modules or {}).get("user_count", 0),
                "stdlib": (modules or {}).get("stdlib_count", 0),
                "pyinstaller": (modules or {}).get("pyinstaller_count", 0),
            },
            "extracted_count": extracted_count,
            "decompile": decompile_summary,
            "pyz": pyz,
            "extraction_errors": extract_errors,
            "note": (
                " ".join(filter(None, (_pyinstaller_note(decompile_summary), _pyz_note(pyz))))
                if packer in ("pyinstaller", "cx_freeze") else
                f"Paketleyici '{packer}': .pyc extraction yalnizca PyInstaller ve cx_Freeze "
                "icin destekli (Nuitka native derler -> .pyc yok, decompile edilemez)."
            ),
        }
        (output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, default=str)
        )

        return StageResult(
            stage_name="reconstruct",
            success=True,
            duration_seconds=time.monotonic() - start,
            artifacts={"python_project": output_dir},
            stats={
                "reconstructed": True,
                "extracted_count": extracted_count,
                "decompiled_count": decompile_summary.get("decompiled", 0),
                "partial_count": decompile_summary.get("partial", 0),
                "disasm_count": decompile_summary.get("disasm", 0),
            },
            errors=extract_errors,
        )

    def _extract_cxfreeze(self, binary_path: Path, output_dir: Path) -> list:
        """cx_Freeze dagitimindan .pyc'leri topla (çıktı dizinine kopyalayarak).

        cx_Freeze tek dosya DEGIL dizin dagitimi yapar: executable + ``lib/library.zip``
        (standart ZIP) + ``lib/`` altinda paket .pyc'leri. İkisindeki her .pyc noktalı
        modül adıyla (``pkg/__init__.pyc`` -> ``pkg``) ``output_dir``'e TEK düzlemde
        yazılır; çakışan ad (harf duyarsız dahil) ``~N`` eki alır. Hedefin dizinine
        hiçbir şey yazılmaz (onarım kopyaları da çıktıda oluşur); lib/ dışına çıkan
        symlink izlenmez. Cikti: ExtractedFile listesi (original_name = modül adı).
        Dagitim dizini yoksa bos liste (graceful).

        Eskiden zip yolu "/" -> "_" ile düzleştiriliyordu: ``a/b_c.pyc`` ile
        ``a_b/c.pyc`` (ve ``Foo``/``foo``) aynı dosyaya yazılıp biri kayboluyordu;
        lib/'deki ``__init__.pyc``'ler paket adını kaybediyordu.
        """
        import zipfile
        from karadul.analyzers.packed_binary import ExtractedFile

        output_dir.mkdir(parents=True, exist_ok=True)
        results: list = []
        used: set[str] = set()
        base = binary_path.parent

        def add(rel_path: str, data: bytes, origin: str) -> None:
            module, is_package = _cxfreeze_module_name(rel_path)
            filename = unique_casefold_name(module, used) + ".pyc"
            out = _write_pyz_member(output_dir, filename, data)
            if out is None:
                return
            results.append(ExtractedFile(
                path=out, original_name=module, file_type="pyc", size=len(data),
                metadata={
                    "cxfreeze_origin": origin,
                    "archive_path": rel_path,
                    "is_package": is_package,
                },
            ))

        # library.zip aday konumlari (surumler/platformlar arasi farklar)
        zip_candidates = [
            base / "lib" / "library.zip",
            base / "library.zip",
            binary_path.with_suffix("") / "lib" / "library.zip",
        ]
        for zpath in zip_candidates:
            if not zpath.is_file():
                continue
            try:
                with zipfile.ZipFile(zpath) as zf:
                    for name in zf.namelist():
                        if not name.endswith(".pyc"):
                            continue
                        try:
                            data = zf.read(name)
                        except Exception:
                            continue
                        add(name, data, "library.zip")
            except zipfile.BadZipFile:
                logger.debug("cx_Freeze library.zip bozuk: %s", zpath)
            break  # ilk gecerli library.zip yeterli

        # lib/ altindaki serbest .pyc dosyalari (library.zip disindaki paketler):
        # yerinde işlenmez, çıktıya kopyalanır.
        lib_dir = base / "lib"
        if lib_dir.is_dir():
            lib_root = lib_dir.resolve()
            for pyc in sorted(lib_dir.rglob("*.pyc")):
                try:
                    if not pyc.resolve().is_relative_to(lib_root) or not pyc.is_file():
                        logger.debug("cx_Freeze lib/ disina cikan yol atlandi: %s", pyc)
                        continue
                    data = pyc.read_bytes()
                except OSError:
                    continue
                add(pyc.relative_to(lib_dir).as_posix(), data, "lib")

        return results

    def _decompile_pyc_files(
        self, extracted_files: list, output_dir: Path,
        py_version: str | None = None,
    ) -> dict[str, Any]:
        """Extract edilmis .pyc'leri header-onar + deterministik decompile.

        Cikti: ``output_dir/source/`` altina ``.py`` (basari) veya
        ``.disasm.txt`` (kismi kurtarma). Zincir: pycdc -> decompyle3/uncompyle6
        -> disassembly (bkz. pyc_decompiler). LLM/ML KULLANILMAZ.

        Args:
            extracted_files: PyInstallerExtractor ciktisi (ExtractedFile listesi).
            output_dir: reconstructed/python_project dizini.
            py_version: Static asamada tespit edilen Python surumu. PyInstaller
                .pyc header'larini siyirdigi icin surum genelde .pyc'den okunamaz;
                header onarimi bu degere dayanir.

        Returns:
            Ozet dict: total_pyc, decompiled, partial, disasm, failed, methods{},
            pycdc_available, limit, skipped_by_limit (+ skipped_list dosya adı;
            atlananlar total_pyc'ye dahil DEĞİL). Sınıflar ayrıktır (toplamları total_pyc):
            decompiled = doğrulanmış kaynak; partial = pycdc kısmi .partial.py
            (+ varsa disasm); disasm = yalnız disassembly; failed = hiçbiri.
        """
        candidates = [
            ef for ef in extracted_files
            if getattr(ef, "file_type", "") == "pyc" and ef.path.exists()
        ]
        # Üst sınır (SecurityConfig.max_python_decompile_modules): aşılırsa küçük üst
        # düzey paketler önce; atlananlar sayılır ve dosyaya listelenir.
        limit = int(self.config.security.max_python_decompile_modules)
        pyc_files, skipped = select_decompile_chain(candidates, limit)
        summary: dict[str, Any] = {
            "total_pyc": len(pyc_files),
            "decompiled": 0,
            "partial": 0,
            "disasm": 0,
            "failed": 0,
            "methods": {},
            "limit": limit,
            "skipped_by_limit": len(skipped),
        }
        if skipped:
            logger.warning(
                "Python decompile: %d .pyc üst sınır (%d) nedeniyle atlandı (%s)",
                len(skipped), limit, _DECOMPILE_SKIPPED_FILE,
            )
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / _DECOMPILE_SKIPPED_FILE).write_text(json.dumps({
                "limit": limit,
                "policy": _DECOMPILE_LIMIT_POLICY,
                "skipped": [
                    {"name": ef.original_name, "size": ef.size} for ef in skipped
                ],
            }, indent=2, ensure_ascii=False), encoding="utf-8")
            summary["skipped_list"] = _DECOMPILE_SKIPPED_FILE
        if not pyc_files:
            return summary

        source_dir = output_dir / "source"
        source_dir.mkdir(parents=True, exist_ok=True)

        # Global surum: once header tasiyan bir .pyc'den oku; hicbiri header tasimiyorsa
        # (PyInstaller tipik olarak siyirir) static asamada tespit edilen surume dus.
        global_version: str | None = None
        for ef in pyc_files:
            try:
                v = version_from_pyc_bytes(ef.path.read_bytes())
            except OSError:
                v = None
            if v:
                global_version = v
                break
        if global_version is None:
            global_version = py_version

        # pycdc VE pycdas icin vendor/pycdc dizini (setup_pycdc.sh ikisini de buraya kurar).
        extra = _vendor_tool_paths()
        summary["pycdc_available"] = pycdc_available(extra)
        timeout = float(getattr(self.config.timeouts, "subprocess", 120.0))

        # Farklı dizinlerden gelen aynı adlı .pyc'ler (CArchive betiği "app" ile PYZ
        # modülü "app"; harf duyarsız FS'de "Foo"/"foo") source/ altında birbirini ezmesin.
        used_stems: set[str] = set()
        for ef in pyc_files:
            try:
                body = ef.path.read_bytes()
            except OSError:
                summary["failed"] += 1
                continue

            # Çıktı adı kökü: PyInstaller TOC girdileri uzantısız ("hello"; noktalı
            # modül adı da olabilir), cx_Freeze'inkiler ".pyc". Path.stem/with_suffix
            # "pkg.a"yı "pkg"ye indirir -> iki modül aynı dosyaya yazılır ve ".fixed"
            # çıktı adına sızar. Yalnız ".pyc" soyulur.
            name = ef.path.name
            out_stem = name[:-4] if name.endswith(".pyc") and len(name) > 4 else name
            out_stem = unique_casefold_name(out_stem, used_stems)

            repaired = repair_pyc_header(body, global_version)
            if repaired is not None and repaired != body:
                # Header onarildi -> onarilmis kopyayi diske yaz, onu decompile et.
                fixed = ef.path.with_name(out_stem + ".fixed.pyc")
                try:
                    fixed.write_bytes(repaired)
                    target_pyc = fixed
                except OSError:
                    target_pyc = ef.path
            else:
                target_pyc = ef.path

            try:
                res = decompile_pyc(
                    target_pyc, source_dir,
                    py_version=global_version, timeout=timeout, extra_paths=extra,
                    out_stem=out_stem,
                )
            except OSError as exc:
                # Tek dosyanın yazma hatası (ör. ad uzunluğu) kalan .pyc'leri düşürmesin.
                logger.debug("decompile yazma hatasi (%s): %s", ef.path.name, exc)
                summary["failed"] += 1
                continue
            summary["methods"][res.method] = summary["methods"].get(res.method, 0) + 1
            if res.success:
                summary["decompiled"] += 1
            elif res.partial_path is not None:
                summary["partial"] += 1
            elif res.is_disassembly:
                summary["disasm"] += 1
            else:
                summary["failed"] += 1

        return summary

    # ------------------------------------------------------------------
    # Packer detection
    # ------------------------------------------------------------------

    def _detect_packer(self, data: bytes) -> dict[str, Any]:
        """Paketleyici tipini tespit et.

        Binary verisi icindeki magic byte ve marker string'lerle
        PyInstaller, cx_Freeze veya Nuitka tespiti yapar.

        Returns:
            dict: packer (str), confidence (str), details (dict)
        """
        details: dict[str, Any] = {}
        scores: dict[str, int] = {
            "pyinstaller": 0,
            "cx_freeze": 0,
            "nuitka": 0,
        }

        # --- PyInstaller ---
        if _PYINSTALLER_MAGIC in data:
            scores["pyinstaller"] += 3
            details["pyinstaller_magic"] = True

        if _MEIPASS_MARKER in data:
            scores["pyinstaller"] += 3
            details["meipass_marker"] = True

        if _PYZ_MAGIC in data:
            scores["pyinstaller"] += 2
            details["pyz_magic"] = True

        # PyInstaller bootloader string'leri
        pyinstaller_strings = [
            b"pyi-runtime",
            b"_pyi_main_co",
            b"PYTHONINSPECT",
            b"_PYI_PROCNAME",
        ]
        for marker in pyinstaller_strings:
            if marker in data:
                scores["pyinstaller"] += 1
                details.setdefault("pyinstaller_strings", []).append(
                    marker.decode("ascii", errors="replace")
                )

        # --- cx_Freeze ---
        for marker in _CXFREEZE_MARKERS:
            if marker in data:
                scores["cx_freeze"] += 2
                details.setdefault("cx_freeze_markers", []).append(
                    marker.decode("ascii", errors="replace")
                )

        # --- Nuitka ---
        for marker in _NUITKA_MARKERS:
            if marker in data:
                scores["nuitka"] += 2
                details.setdefault("nuitka_markers", []).append(
                    marker.decode("ascii", errors="replace")
                )

        # Nuitka-spesifik: compiled module pattern
        if b".cpython-" in data and b".so" in data:
            scores["nuitka"] += 1
        if b"__compiled__" in data:
            scores["nuitka"] += 2

        # En yuksek skoru sec
        max_packer = max(scores, key=lambda k: scores[k])
        max_score = scores[max_packer]

        if max_score == 0:
            return {"packer": "unknown", "confidence": "none", "details": {}}

        confidence = "low"
        if max_score >= 3:
            confidence = "medium"
        if max_score >= 5:
            confidence = "high"

        return {
            "packer": max_packer,
            "confidence": confidence,
            "scores": scores,
            "details": details,
        }

    # ------------------------------------------------------------------
    # Python version detection
    # ------------------------------------------------------------------

    def _detect_python_version(self, data: bytes) -> str | None:
        """Binary'den Python versiyonunu tespit et.

        Stratejiler:
        1. .pyc magic number'dan versiyon haritasi
        2. "Python X.Y.Z" string pattern'i
        3. "pythonX.Y" kisa format
        """
        # Strateji 1: .pyc magic number ara
        version = self._version_from_pyc_magic(data)
        if version:
            return version

        # Strateji 2: "Python X.Y.Z" string pattern
        text = data.decode("ascii", errors="replace")
        match = _PYTHON_VERSION_PATTERN.search(text)
        if match:
            return match.group(1)

        # Strateji 3: "pythonX.Y" (orn: "python3.11", "libpython3.10.so")
        match = _PYTHON_VERSION_SHORT_PATTERN.search(text)
        if match:
            return f"{match.group(1)}.{match.group(2)}"

        return None

    def _version_from_pyc_magic(self, data: bytes) -> str | None:
        """Binary icindeki .pyc magic number'lardan Python versiyonu bul.

        .pyc dosyalari 4-byte little-endian magic number ile baslar.
        Bu magic number Python surumune ozgudur.

        Binary icinde gomulu .pyc dosyalarinin magic number'larini
        arar ve bilinen versiyonlarla eslestirir.
        """
        # .pyc magic number pattern: 2-byte versiyon + \\r\\n (0x0D0A)
        # Ornek: Python 3.11 -> 0xa70d (little-endian) + 0x0d0a
        # Binary icinde \\r\\n\\r\\n pattern'i ara (pyc header)
        pyc_header_pattern = re.compile(rb"(..\r\n)")

        found_versions: dict[str, int] = {}

        for match in pyc_header_pattern.finditer(data):
            pos = match.start()
            if pos + 4 > len(data):
                continue

            # 2-byte little-endian magic number oku
            try:
                magic_num = struct.unpack("<H", data[pos:pos + 2])[0]
            except struct.error:
                continue

            version = _PYC_MAGIC_TO_VERSION.get(magic_num)
            if version:
                found_versions[version] = found_versions.get(version, 0) + 1

        if not found_versions:
            return None

        # En cok bulunan versiyon
        return max(found_versions, key=lambda k: found_versions[k])

    # ------------------------------------------------------------------
    # Embedded module extraction
    # ------------------------------------------------------------------

    def _extract_embedded_modules(
        self, data: bytes, python_version: str | None = None,
    ) -> dict[str, Any] | None:
        """Binary icindeki embedded Python modullerini cikar (string taraması; sezgi).

        .pyc dosya referanslarini ve modul isimlerini bulur. Sınıflandırma tek
        kaynaktan: ``classify_pyz_module`` (PYZ/CArchive envanteriyle aynı; hedef
        sürüm ``python_version``).
        """
        text = data.decode("ascii", errors="replace")

        modules: list[dict[str, str]] = []
        seen: set[str] = set()

        # Python modulu olabilecek string'leri bul
        for match in _PYC_MODULE_PATTERN.finditer(text):
            module_name = match.group(1)

            # Cok kisa veya cok uzun isimleri filtrele
            if len(module_name) < 2 or len(module_name) > 200:
                continue

            # Zaten gorulmus mu
            if module_name in seen:
                continue
            seen.add(module_name)

            # False positive filtreleme
            # Buyuk harfle baslayan, sayi ile baslayan vb. filtrele
            if not module_name[0].isalpha() and module_name[0] != "_":
                continue

            modules.append({
                "name": module_name,
                "type": classify_pyz_module(module_name, python_version),
            })

        if not modules:
            return None

        return _module_inventory(modules, source="string_scan", python_version=python_version)

    # ------------------------------------------------------------------
    # PyInstaller TOC parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _read_pyinstaller_archive(
        data: bytes,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        """Cookie + CArchive TOC: reconstruct'taki çıkarıcıyla AYNI kod (tek kaynak).

        ``packed_binary.locate_pyinstaller_archive`` (big-endian cookie, son MEI
        magic'i) + ``PyInstallerExtractor._parse_toc`` (DoS sınırlı TOC okuyucu).
        Dosya çıkarmaz. Magic yoksa ya da cookie kısaysa None.
        """
        try:
            info = locate_pyinstaller_archive(data)
        except struct.error:
            return None
        if info is None:
            return None
        return info, PyInstallerExtractor._parse_toc(data, info["toc_start"], info["toc_length"])

    def _pyinstaller_module_inventory(
        self, data: bytes, fallback_version: str | None,
    ) -> dict[str, Any] | None:
        """PyInstaller modül envanteri: CArchive'deki code girdileri + PYZ TOC'si.

        Tek doğru kaynak: reconstruct'taki çıkarıcının okuduğu iki TOC ve tek
        sınıflandırıcı (``classify_pyz_module``). Dosya çıkarılmaz, PYZ gövdeleri
        açılmaz (yalnız TOC; kısıtlı ayrıştırıcı). Eskiden sayı string taramasından
        geliyordu: TOC'deki tip baytı + ad ("z" + "PYZ.pyz") "zPYZ" modülü sayılıyordu.
        Cookie okunamıyorsa None.
        """
        archive = self._read_pyinstaller_archive(data)
        if archive is None:
            return None
        info, toc = archive
        carchive = [e for e in toc if e["type_name"] in PyInstallerExtractor.CODE_TYPE_NAMES]
        pyz_names: list[str] = []
        pyz_version: str | None = None
        for e in toc:
            if e["type_name"] != "ZIPFILE":
                continue
            start = info["pkg_start"] + e["entry_offset"]
            end = start + e["data_length"]
            if e["data_length"] <= 0 or end > len(data):
                continue
            raw_entry = data[start:end]
            blob = (
                safe_zlib_decompress(raw_entry, max_size=_MAX_PYINSTALLER_DECOMPRESS)
                if e["is_compressed"] else raw_entry
            )
            if not blob or not blob.startswith(PYZ_MAGIC):
                continue
            try:
                pyz = parse_pyz(blob)
            except PyzFormatError as exc:
                logger.debug("static: PYZ TOC okunamadi (%s): %s", e["name"], exc)
                continue
            pyz_version = pyz_version or pyz.python_version
            pyz_names.extend(entry.name for entry in pyz.entries)
        version = (
            pyz_version or pyinstaller_python_version(info["python_version"]) or fallback_version
        )
        modules = [
            {"name": e["name"], "type": classify_pyz_module(e["name"], version),
             "origin": "carchive"}
            for e in carchive
        ] + [
            {"name": n, "type": classify_pyz_module(n, version), "origin": "pyz"}
            for n in pyz_names
        ]
        return _module_inventory(modules, source="pyinstaller_toc", python_version=version)

    def _parse_pyinstaller_toc(self, data: bytes) -> dict[str, Any] | None:
        """PyInstaller CArchive TOC'sinin özeti (static aşama; dosya çıkarmaz).

        Eski kopya cookie'yi little-endian okuyordu: gerçek binary'lerde
        python_version "9395896.32" ve 0 girdi. Artık okuma ``_read_pyinstaller_archive``.
        """
        archive = self._read_pyinstaller_archive(data)
        if archive is None:
            return None
        info, toc = archive
        entries = [
            {
                "name": e["name"],
                "type": chr(e["type_flag"]) if 32 <= e["type_flag"] < 127 else "?",
                "compressed": e["is_compressed"],
            }
            for e in toc
        ]
        py_version = pyinstaller_python_version(info["python_version"])
        if not entries and py_version is None:
            return None

        result: dict[str, Any] = {
            "total": len(entries),
            "entries": entries[:5000],
        }
        if py_version:
            result["python_version"] = py_version
        if info["package_length"]:
            result["package_length"] = info["package_length"]

        return result

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _filter_python_strings(strings: list[str]) -> list[str]:
        """String listesinden Python-ilgili olanlari filtrele."""
        python_indicators = [
            "import ", "from ", "def ", "class ",
            ".py", ".pyc", ".pyo", ".pyd",
            "Traceback", "Exception", "Error",
            "Python", "python", "PyObject",
            "__init__", "__main__", "__name__",
            "site-packages", "dist-packages",
            "pip", "setuptools", "pkg_resources",
            "MEIPASS", "PyInstaller", "cx_Freeze", "Nuitka",
        ]
        result = []
        for s in strings:
            if not isinstance(s, str):
                continue
            if any(indicator in s for indicator in python_indicators):
                result.append(s[:500])  # max 500 karakter
        return result
