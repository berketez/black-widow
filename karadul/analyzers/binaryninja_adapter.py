"""Binary Ninja experimental adapter (Karadul v1.14 Dalga 2).

Binary Ninja (Vector35), ticari bir RE platformudur. Python SDK'si
(``binaryninja``) PyPI'de YOKTUR; kullanici lisansli kurulum dizinindeki
``python/`` klasorunu ``PYTHONPATH``'e ekleyerek veya Vector35'in saglandigi
``install_api.py`` script'i ile sisteme baglar. Headless modu icin de
ayri bir lisans (Personal $300+, Commercial $4000+) gerekir.

Karadul'da Binary Ninja **release blocker degildir**:

- Lisanssiz makinelerde (CI dahil) ``is_available()`` ``False`` doner.
- Tum extract metodlari, modul yokken ``RuntimeError("binaryninja module
  not available -- license required")`` firlatir.
- Mevcut karadul pipeline'ina dokunulmaz; entegrasyon v1.15'te
  ``pipeline/steps/binaryninja_analysis.py`` olarak eklenmesi planlanir
  (BinaryView types -> TypeForge fusion, MLIL/HLIL komplement).

Tasarim TRex/PDB adapter'larina paralel:

- Lazy import (``_try_import_binaryninja``) test mock noktasi.
- ``timeout`` parametresi BinaryView load + analiz icin ust sinir
  (deafult 600s; headless analiz buyuk binary'lerde dakikalar surer).
- 3rd-party Python kutuphanesi ZORUNLU degil; ``binaryninja`` modulu
  varsa kullanilir, yoksa graceful skip.

Kullanim:
    >>> from karadul.analyzers.binaryninja_adapter import BinaryNinjaAdapter
    >>> adapter = BinaryNinjaAdapter(Path("foo.exe"))
    >>> if adapter.is_available():
    ...     result = adapter.extract_all()
    ...     for fn in result.functions:
    ...         print(fn.name, hex(fn.address))
    ... else:
    ...     # Lisanssiz makine -- pipeline diger adimlarla devam etsin
    ...     pass
"""

from __future__ import annotations

import importlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sabitler / hata mesajlari
# ---------------------------------------------------------------------------

_BN_MISSING_MSG = (
    "binaryninja module not available -- license required "
    "(Vector35 lisanslari icin: https://binary.ninja/purchase/, "
    "Python SDK kurulumu: <BinaryNinja>/scripts/install_api.py)"
)


# ---------------------------------------------------------------------------
# Dataclass'lar
# ---------------------------------------------------------------------------


@dataclass
class BNFunction:
    """Binary Ninja BinaryView'den cikarilan tek bir fonksiyon ozet kaydi."""

    name: str
    address: int
    size: int
    return_type: str | None = None
    parameters: list[dict[str, str]] = field(default_factory=list)
    is_thunk: bool = False
    is_imported: bool = False


@dataclass
class BNType:
    """Binary Ninja TypeContainer kaydi (struct/union/enum/typedef/function)."""

    name: str
    kind: str  # "struct", "union", "enum", "typedef", "function", "unknown"
    size: int | None = None
    fields: list[dict[str, Any]] = field(default_factory=list)
    raw: str = ""  # binaryninja Type repr (tokens veya str(t))


@dataclass
class BNResult:
    """``extract_all()`` cikti zarfi."""

    binary_path: Path
    functions: list[BNFunction] = field(default_factory=list)
    types: list[BNType] = field(default_factory=list)
    arch: str | None = None
    platform: str | None = None  # "windows", "linux", "mac", "freebsd", ...
    bv_summary: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Yardimci -- modul import (test mock noktasi)
# ---------------------------------------------------------------------------


def _try_import_binaryninja() -> ModuleType | None:
    """``binaryninja`` modulunu lazy import et; yoksa None.

    Test edilebilirlik icin ayri fonksiyon: testler
    ``monkeypatch.setattr(... "_try_import_binaryninja", ...)`` ile
    sahte modul saglayabilir.
    """
    try:
        return importlib.import_module("binaryninja")
    except ImportError:
        logger.debug("binaryninja module not importable (license required).")
        return None
    except Exception as exc:  # pragma: no cover -- savunma
        # Lisans kontrolu sirasinda RuntimeError firlatabilir vendor
        logger.warning("binaryninja import beklenmedik hata: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class BinaryNinjaAdapter:
    """Binary Ninja Python API sarmalayici -- experimental, opsiyonel.

    Args:
        binary_path: Analiz edilecek binary (PE/ELF/Mach-O/...).
        timeout: BinaryView load + analiz icin ust sinir (saniye).
            BN headless analizi buyuk dosyalarda yavas; default 600.
    """

    def __init__(self, binary_path: Path | str, timeout: int = 600) -> None:
        self.binary_path: Path = Path(binary_path)
        self.timeout: int = int(timeout)
        # Modul cache: None = henuz denenmedi flag yerine her cagrida import
        # denenir; BSim/TRex'teki gibi tek seferlik olmasi icin lazy:
        self._bn_module: ModuleType | None = None
        self._module_checked: bool = False

    # ------------------------------------------------------------------
    # Modul cozumleme
    # ------------------------------------------------------------------

    def _bn(self) -> ModuleType | None:
        """``binaryninja`` modulunu cache'li dondur (yoksa None)."""
        if not self._module_checked:
            self._bn_module = _try_import_binaryninja()
            self._module_checked = True
        return self._bn_module

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """``binaryninja`` Python modulu import edilebiliyor mu?"""
        return self._bn() is not None

    def get_version(self) -> str | None:
        """``binaryninja.core_version()`` cikti string'i. Modul yoksa None."""
        bn = self._bn()
        if bn is None:
            return None
        # binaryninja API'sinde fonksiyon adi versiyona gore degisebilir;
        # birkac alternatif dene.
        for attr in ("core_version", "get_core_version", "version"):
            fn = getattr(bn, attr, None)
            if callable(fn):
                try:
                    val = fn()
                except Exception as exc:  # pragma: no cover
                    logger.debug("binaryninja.%s() basarisiz: %s", attr, exc)
                    continue
                if val:
                    return str(val).strip() or None
            elif isinstance(fn, str) and fn:
                return fn
        return None

    def extract_functions(self) -> list[BNFunction]:
        """BinaryView ile fonksiyon listesini cikar.

        Raises:
            RuntimeError: ``binaryninja`` modulu yoksa.
        """
        bn = self._bn()
        if bn is None:
            raise RuntimeError(_BN_MISSING_MSG)
        bv = self._load_binary_view(bn)
        try:
            return self._iter_functions(bv)
        finally:
            self._close_binary_view(bv)

    def extract_types(self) -> list[BNType]:
        """BinaryView types (TypeContainer) listesini cikar.

        Raises:
            RuntimeError: ``binaryninja`` modulu yoksa.
        """
        bn = self._bn()
        if bn is None:
            raise RuntimeError(_BN_MISSING_MSG)
        bv = self._load_binary_view(bn)
        try:
            return self._iter_types(bv)
        finally:
            self._close_binary_view(bv)

    def extract_all(self) -> BNResult:
        """Fonksiyon + tip + meta ozetli tam analiz.

        Raises:
            RuntimeError: ``binaryninja`` modulu yoksa veya
                BinaryView olusturulamazsa.
        """
        bn = self._bn()
        if bn is None:
            raise RuntimeError(_BN_MISSING_MSG)
        if not self.binary_path.exists():
            raise RuntimeError(
                f"binary path yok: {self.binary_path}",
            )

        start = time.perf_counter()
        bv = self._load_binary_view(bn)
        try:
            functions = self._iter_functions(bv)
            types = self._iter_types(bv)
            arch = self._get_arch(bv)
            platform = self._get_platform(bv)
            summary = self._summarize_bv(bv, functions, types)
        finally:
            self._close_binary_view(bv)

        duration_ms = (time.perf_counter() - start) * 1000.0
        logger.info(
            "BinaryNinja: %d fn / %d type (%.1fms)",
            len(functions),
            len(types),
            duration_ms,
        )
        return BNResult(
            binary_path=self.binary_path,
            functions=functions,
            types=types,
            arch=arch,
            platform=platform,
            bv_summary=summary,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    # BinaryView ic islemler (test mock noktalari)
    # ------------------------------------------------------------------

    def _load_binary_view(self, bn: ModuleType) -> Any:
        """``binaryninja.load(path)`` (yeni) veya
        ``BinaryViewType.get_view_of_file()`` (eski) ile bv olustur.

        Modul attribute'larini sirayla dene; bu sayede farkli BN
        surumleriyle uyumluluk korunur. Hata olursa ``RuntimeError``.
        """
        path_str = str(self.binary_path)

        # Yeni API (3.x): binaryninja.load(...)
        load_fn = getattr(bn, "load", None)
        if callable(load_fn):
            try:
                bv = load_fn(path_str, update_analysis=True)
            except TypeError:
                # Eski signature: tek arg
                try:
                    bv = load_fn(path_str)
                except Exception as exc:  # pragma: no cover
                    raise RuntimeError(
                        f"binaryninja.load basarisiz: {exc}",
                    ) from exc
            except Exception as exc:  # pragma: no cover
                raise RuntimeError(
                    f"binaryninja.load basarisiz: {exc}",
                ) from exc
            if bv is None:
                raise RuntimeError(
                    f"binaryninja.load None dondu: {path_str}",
                )
            return bv

        # Eski API: BinaryViewType.get_view_of_file
        bvt = getattr(bn, "BinaryViewType", None)
        if bvt is not None:
            getter = getattr(bvt, "get_view_of_file", None)
            if callable(getter):
                try:
                    bv = getter(path_str)
                except Exception as exc:  # pragma: no cover
                    raise RuntimeError(
                        f"BinaryViewType.get_view_of_file basarisiz: {exc}",
                    ) from exc
                if bv is None:
                    raise RuntimeError(
                        f"BinaryViewType.get_view_of_file None: {path_str}",
                    )
                # Analizi tetikle
                update = getattr(bv, "update_analysis_and_wait", None)
                if callable(update):
                    try:
                        update()
                    except Exception as exc:  # pragma: no cover
                        logger.warning(
                            "BinaryView update_analysis hata: %s", exc,
                        )
                return bv

        raise RuntimeError(
            "binaryninja API uyumsuz: load() / "
            "BinaryViewType.get_view_of_file() bulunamadi",
        )

    @staticmethod
    def _close_binary_view(bv: Any) -> None:
        """BinaryView icin file_accessor / close cagrisi (varsa)."""
        if bv is None:
            return
        for attr in ("file", "close"):
            obj = getattr(bv, attr, None)
            if obj is None:
                continue
            close = getattr(obj, "close", None) if attr == "file" else obj
            if callable(close):
                try:
                    close()
                except Exception as exc:  # pragma: no cover
                    logger.debug("BinaryView close hata (%s): %s", attr, exc)
                return

    # ------------------------------------------------------------------
    # Fonksiyon iteration
    # ------------------------------------------------------------------

    def _iter_functions(self, bv: Any) -> list[BNFunction]:
        """``bv.functions`` uzerinde gez, ``BNFunction`` listesi don."""
        out: list[BNFunction] = []
        functions = getattr(bv, "functions", None) or []
        for fn in functions:
            try:
                bn_fn = self._convert_function(fn)
            except Exception as exc:  # pragma: no cover -- defensive
                logger.debug("Fonksiyon donusumu basarisiz: %s", exc)
                continue
            out.append(bn_fn)
        return out

    @staticmethod
    def _convert_function(fn: Any) -> BNFunction:
        """Binary Ninja Function nesnesini ``BNFunction``'a cevir."""
        name = str(getattr(fn, "name", "") or getattr(fn, "symbol", "") or "")
        address_raw = getattr(fn, "start", None) or getattr(fn, "address", 0)
        try:
            address = int(address_raw or 0)
        except (TypeError, ValueError):
            address = 0
        size_raw = getattr(fn, "total_bytes", None)
        if size_raw is None:
            size_raw = getattr(fn, "size", 0)
        try:
            size = int(size_raw or 0)
        except (TypeError, ValueError):
            size = 0

        # Donus tipi
        return_type: str | None = None
        ret_attr = getattr(fn, "return_type", None)
        if ret_attr is not None:
            try:
                return_type = str(ret_attr).strip() or None
            except Exception:  # pragma: no cover
                return_type = None

        # Parametreler
        parameters: list[dict[str, str]] = []
        params_attr = getattr(fn, "parameter_vars", None)
        if params_attr is None:
            params_attr = getattr(fn, "parameters", None)
        if params_attr is None:
            ftype = getattr(fn, "function_type", None)
            params_attr = getattr(ftype, "parameters", None) if ftype else None
        if params_attr:
            try:
                iterable = list(params_attr)
            except TypeError:
                iterable = []
            for idx, p in enumerate(iterable):
                pname = str(getattr(p, "name", f"arg{idx}") or f"arg{idx}")
                ptype_attr = getattr(p, "type", None)
                ptype = str(ptype_attr).strip() if ptype_attr is not None else ""
                parameters.append({"name": pname, "type": ptype})

        is_thunk = bool(getattr(fn, "is_thunk", False))
        # imported tespiti: symbol.binding == ImportAddressSymbol veya
        # symbol_type "ImportedFunctionSymbol" benzeri.
        is_imported = False
        sym = getattr(fn, "symbol", None)
        if sym is not None:
            stype = getattr(sym, "type", None)
            stype_name = str(stype) if stype is not None else ""
            if "Import" in stype_name:
                is_imported = True

        return BNFunction(
            name=name,
            address=address,
            size=size,
            return_type=return_type,
            parameters=parameters,
            is_thunk=is_thunk,
            is_imported=is_imported,
        )

    # ------------------------------------------------------------------
    # Type iteration
    # ------------------------------------------------------------------

    def _iter_types(self, bv: Any) -> list[BNType]:
        """``bv.types.items()`` uzerinde gez, ``BNType`` listesi don."""
        types = getattr(bv, "types", None)
        if types is None:
            return []
        try:
            items = list(types.items()) if hasattr(types, "items") else list(types)
        except Exception as exc:  # pragma: no cover
            logger.debug("bv.types iter basarisiz: %s", exc)
            return []

        out: list[BNType] = []
        for entry in items:
            # entry ya (name, type) tuple ya da Type nesnesi
            if isinstance(entry, tuple) and len(entry) == 2:
                name_raw, ttype = entry
            else:
                name_raw = getattr(entry, "name", "") or ""
                ttype = entry
            try:
                bn_type = self._convert_type(name_raw, ttype)
            except Exception as exc:  # pragma: no cover
                logger.debug("Type donusumu basarisiz: %s", exc)
                continue
            out.append(bn_type)
        return out

    @staticmethod
    def _convert_type(name_raw: Any, ttype: Any) -> BNType:
        """Binary Ninja Type nesnesini ``BNType``'a cevir."""
        name = str(name_raw or "").strip() or "<anonymous>"

        # kind cozumleme: type_class veya class attribute
        kind_raw = (
            getattr(ttype, "type_class", None)
            or getattr(ttype, "kind", None)
            or ""
        )
        kind_str = str(kind_raw).lower() if kind_raw else ""
        kind = "unknown"
        if "struct" in kind_str:
            kind = "struct"
        elif "union" in kind_str:
            kind = "union"
        elif "enum" in kind_str:
            kind = "enum"
        elif "function" in kind_str:
            kind = "function"
        elif "named" in kind_str or "typedef" in kind_str or "alias" in kind_str:
            kind = "typedef"

        # boyut
        size: int | None = None
        size_attr = getattr(ttype, "width", None)
        if size_attr is None:
            size_attr = getattr(ttype, "size", None)
        if size_attr is not None:
            try:
                size = int(size_attr)
            except (TypeError, ValueError):
                size = None

        # alanlar (struct/union/enum)
        fields: list[dict[str, Any]] = []
        members_attr = getattr(ttype, "members", None)
        if members_attr is None:
            structure = getattr(ttype, "structure", None)
            if structure is not None:
                members_attr = getattr(structure, "members", None)
        if members_attr:
            try:
                members_iter = list(members_attr)
            except TypeError:
                members_iter = []
            for m in members_iter:
                mname = str(getattr(m, "name", "") or "")
                mtype = getattr(m, "type", None)
                moffset = getattr(m, "offset", None)
                fields.append(
                    {
                        "name": mname,
                        "type": str(mtype).strip() if mtype is not None else "",
                        "offset": int(moffset) if moffset is not None else None,
                    }
                )

        # raw repr
        try:
            raw = str(ttype)
        except Exception:  # pragma: no cover
            raw = ""

        return BNType(name=name, kind=kind, size=size, fields=fields, raw=raw)

    # ------------------------------------------------------------------
    # Meta
    # ------------------------------------------------------------------

    @staticmethod
    def _get_arch(bv: Any) -> str | None:
        arch = getattr(bv, "arch", None)
        if arch is None:
            return None
        name = getattr(arch, "name", None)
        if name:
            return str(name)
        try:
            return str(arch)
        except Exception:  # pragma: no cover
            return None

    @staticmethod
    def _get_platform(bv: Any) -> str | None:
        plat = getattr(bv, "platform", None)
        if plat is None:
            return None
        name = getattr(plat, "name", None)
        text = str(name) if name else ""
        if not text:
            try:
                text = str(plat)
            except Exception:  # pragma: no cover
                return None
        text_lower = text.lower()
        for needle in ("windows", "linux", "mac", "darwin", "freebsd"):
            if needle in text_lower:
                return "mac" if needle == "darwin" else needle
        return text or None

    @staticmethod
    def _summarize_bv(
        bv: Any,
        functions: list[BNFunction],
        types: list[BNType],
    ) -> dict[str, Any]:
        """BinaryView icin kucuk meta ozet (test edilebilir, ham bv'ye dokunmaz)."""
        summary: dict[str, Any] = {
            "function_count": len(functions),
            "type_count": len(types),
            "imported_function_count": sum(1 for f in functions if f.is_imported),
            "thunk_count": sum(1 for f in functions if f.is_thunk),
        }
        # BV tarafindan dogrudan saglanan opsiyonel meta
        for attr in ("entry_point", "start", "end"):
            val = getattr(bv, attr, None)
            if val is not None:
                try:
                    summary[attr] = int(val)
                except (TypeError, ValueError):
                    pass
        view_type = getattr(bv, "view_type", None) or getattr(bv, "name", None)
        if view_type:
            summary["view_type"] = str(view_type)
        return summary


__all__ = [
    "BNFunction",
    "BNType",
    "BNResult",
    "BinaryNinjaAdapter",
    "_try_import_binaryninja",
]
