"""Feedback loop — NameMerger candidate toplayicilari.

stages.py L2663-2846. Her kaynaktan (binary_extractor, c_namer, BinDiff,
ReferenceDiffer, FunctionID, Computation Recovery, P-Code) NamingCandidate
uret, tek bir {sembol: [candidate, ...]} dict'te topla.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from karadul.reconstruction.name_merger import NamingCandidate
except ImportError:
    NamingCandidate = None  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)


def collect_candidates(
    *,
    extracted_names: dict[str, str],
    naming_result: Any,
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    refdiff_naming: dict[str, str],
    fid_json: Path,
    computation_result: Any,
    pcode_naming_candidates: list[dict[str, Any]],
    iter_index: int,
    stats: dict[str, Any],
    bsim_shadow: dict[str, Any] | None = None,
    bsim_fusion_min_similarity: float = 0.7,
    bsim_fusion_max_candidates: int = 3,
    # P13b / K-4: DWARF, PDB, BN, TRex, Rust / Go, RTTI kanalları (``add_k4_channels``).
    # ``k4``: ``run_name_merger``'in kurduğu girdiler (bayraklar, Ghidra dizini, üretici
    # listeleri); ``None`` → kanallar çalışmaz (durumları da yazılmaz).
    k4: dict[str, Any] | None = None,
    # 2026-05-14 v1.21: Engineering algorithm fusion -- constant/API/formula
    # tabanli naming kanallari. Decompiled C dizini + functions_json varsa
    # EngineeringAlgorithmAnalyzer + FormulaReconstructor calistirilir.
    decompiled_dir: Path | None = None,
    functions_json: Path | None = None,
    # P13a / AD-04: c_namer koştuysa ön adları o zaten işledi (aynı kanıt). True iken
    # ön adlar (``binary_extractor``) ve c_namer'ın kendi adları birleştiriciye aday
    # olarak GİRMEZ: c_namer'ın ad verdiği anahtarın kararı c_namer'ındır.
    pre_names_via_c_namer: bool = False,
) -> dict[str, list[Any]]:
    """Tum kaynaklardan candidates_by_symbol sozlugu olustur.

    bsim_shadow: v1.11.0 BSim kopru. None ise BSim evidence eklenmez
    (shadow mode davranisi). Dict verildiginde ``matches`` alanindaki
    BSim eslemeleri source="bsim" ile eklenir. Caller (run_name_merger),
    shadow_mode=False AND use_bsim_fusion=True oldugunda dict gonderir.
    """
    candidates_by_symbol: dict[str, list[Any]] = {}

    if not pre_names_via_c_namer:
        _add_binary_extractor(extracted_names, candidates_by_symbol)
        _add_c_namer(naming_result, candidates_by_symbol, stats)
    _add_bindiff(bindiff_confidence_map, candidates_by_symbol)
    _add_refdiff(refdiff_naming, candidates_by_symbol)
    _add_fid(fid_json, candidates_by_symbol)

    if computation_result and computation_result.success:
        _add_computation(
            computation_result, candidates_by_symbol, iter_index, stats,
        )

    if pcode_naming_candidates:
        _add_pcode(pcode_naming_candidates, candidates_by_symbol)

    if bsim_shadow:
        _add_bsim(
            bsim_shadow=bsim_shadow,
            candidates=candidates_by_symbol,
            min_similarity=bsim_fusion_min_similarity,
            max_per_function=bsim_fusion_max_candidates,
            stats=stats,
        )

    # P13b / K-4: hata ayıklama bilgisi / ayrıştırılmış simge / harici araç kanalları
    if k4 is not None:
        add_k4_channels(**k4, candidates=candidates_by_symbol, stats=stats)

    # 2026-05-14 v1.21: Engineering fusion -- constant/API/formula naming.
    # Tek bir EngineeringAlgorithmAnalyzer.identify() cagrisi ile 3 sinyal
    # ayni AlgorithmMatch listesinden uretilir. Cache fonksiyon disinda
    # tutulmaz; her iter feedback dongusunde yeniden cagrilir (idempotent).
    if (
        decompiled_dir is not None
        and decompiled_dir.exists()
        and functions_json is not None
        and functions_json.exists()
    ):
        _add_engineering_naming(
            decompiled_dir=decompiled_dir,
            functions_json=functions_json,
            candidates=candidates_by_symbol,
            stats=stats,
        )

    return candidates_by_symbol


def _addr_to_fun_key(addr: int | str) -> str:
    """Adres → FUN_<lowercase hex> (Ghidra/BSim ile ayni format)."""
    if isinstance(addr, str):
        try:
            addr_int = int(addr, 16) if addr.startswith("0x") else int(addr)
        except ValueError:
            return ""
    else:
        addr_int = int(addr)
    # KANONIK: 8-hane zero-padded (Ghidra FUN_00101234). :x paddingsizdi ->
    # DWARF/Rust/Go/PDB/BN/TRex kanallari FUN_101234 uretip Ghidra'nin
    # FUN_00101234'uyle eslesemiyor, sessizce dusuyordu. :08x cli.py:938 /
    # quick_f1_eval.py:121 / benchmark_runner ile hizali (yuksek adres >8 hane
    # oldugu gibi korunur).
    return f"FUN_{addr_int:08x}"


def _make_candidate(name: str, source: str, confidence: float, reason: str) -> Any:
    """NamingCandidate wrapper. NamingCandidate yoksa dict dondur (test mock)."""
    if NamingCandidate is None:
        return {"name": name, "source": source, "confidence": confidence, "reason": reason}
    return NamingCandidate(
        name=name, source=source, confidence=confidence, reason=reason,
    )


# ---------------------------------------------------------------------------
# P13b / K-4: hata ayıklama bilgisi, ayrıştırılmış simge ve harici araç kanalları
#
# Eskiden (IMZA-13 / BORU-14 a) tek çağıran bu kanalların girdisini hiç geçirmiyordu; açılsalardı
# da anahtarları Ghidra'nın adıyla tutmazdı: PDB adresi bölüm İÇİ ofsetti, DWARF / nm adresi
# ikilinin bağlama adresiydi (PIE ELF'te Ghidra 0x100000'e taşır), TRex ``related_functions``
# arıyordu (üretici ``function`` yazar), C++ ``_ZN…`` simgeleri Rust kanalına düşüyordu ve
# çözülmüş ad (``a::b``) C tanımlayıcısı değildi. Şimdi:
# - her kanal kendi bayrağıyla açılır (``K4_CHANNEL_FLAGS``; öntanımda hepsi kapalı: doğrulukları
#   ölçülmedi, K-4); kapalı kanal iş yapmaz;
# - adres → Ghidra fonksiyonu: ``GhidraFunctionIndex`` (Ghidra'nın fonksiyon listesi + görüntü
#   tabanı farkı); yalnız Ghidra'da o adreste ADSIZ (``FUN_`` …) bir fonksiyon varsa aday olur,
#   anahtar Ghidra'nın adıdır; tutmayan / Ghidra'nın zaten adlandırdığı sayılır;
# - ad C tanımlayıcısına çevrilir (``c_identifier``), özgün ad adayın gerekçesinde;
# - kanal başına durum ve sayılar ``stats["naming_channels"]``'ta (P-S1 durum sözlüğü:
#   ``calisti`` / ``veri_yok`` / ``arac_yok`` / ``desteklenmiyor`` / ``kapali`` / ``hata``).
# Bu kanalların güveni ölçülmedi: birleştiricinin köken kaydında güvenleri ``null``
# (``UNMEASURED_SOURCES``; P12a kuralı).
# ---------------------------------------------------------------------------

K4_CHANNEL_FLAGS: dict[str, str] = {
    "pdb": "enable_pdb_naming",
    "dwarf": "enable_dwarf_naming",
    "rust_demangler": "enable_rust_naming",
    "go_demangler": "enable_go_naming",
    "bn_symbol": "enable_binaryninja_naming",
    "trex_struct": "enable_trex_naming",
    "rtti": "enable_rtti_naming",
}
UNMEASURED_SOURCES: frozenset[str] = frozenset(K4_CHANNEL_FLAGS)

CH_RAN = "calisti"
CH_NO_DATA = "veri_yok"
CH_NO_TOOL = "arac_yok"
CH_UNSUPPORTED = "desteklenmiyor"
CH_DISABLED = "kapali"
CH_ERROR = "hata"

# Rust legacy adı: ``_ZN`` … ``17h<16 onaltılık>E`` (+ isteğe bağlı ``.llvm.N`` gibi son ek).
# C++ Itanium adları ``E``'den sonra parametre türü taşır ya da karma bileşeni yoktur.
_RUST_LEGACY_RE = re.compile(r"^_{1,2}ZN.*17h[0-9a-f]{16}E(?:\.[A-Za-z0-9_.$]+)?$")
_RUST_V0_RE = re.compile(r"^_{1,2}R[A-Za-z0-9_]")


def c_identifier(qualified: str) -> str | None:
    """Nitelikli adı (``a::b<c>``) C tanımlayıcısına çevir; çevrilemezse ``None``."""
    if not isinstance(qualified, str):
        return None
    s = re.sub(r"[^A-Za-z0-9_]+", "_", qualified)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s or s[0].isdigit():
        return None
    return s


@dataclass
class GhidraFunctionIndex:
    """Ghidra'nın fonksiyon listesi: adres → ad; ``delta`` = Ghidra adresi − ikili adresi."""

    by_addr: dict[int, str]
    names: frozenset[str]
    delta: int = 0

    def key_for(self, addr: int) -> tuple[str | None, str]:
        """İkili adresinin Ghidra anahtarı. Dönen: (anahtar ya da None, sonuç)."""
        name = self.by_addr.get(int(addr) + self.delta)
        if name is None:
            return None, "ghidra_fonksiyonu_yok"
        if not _is_unnamed(name):
            return None, "ghidra_adli"
        return name, "tuttu"

    def key_for_name(self, symbol: str) -> tuple[str | None, str]:
        """Ghidra fonksiyonu simgenin kendi (ayrıştırılmamış) adını taşıyorsa o ad anahtardır."""
        for cand in (symbol, symbol[1:] if symbol.startswith("__") else None):
            if cand and cand in self.names:
                return cand, "tuttu"
        return None, "ghidra_fonksiyonu_yok"


def load_ghidra_index(
    functions_json: Path | None, *, binary_path: Path | None = None,
    ghidra_image_base: int | None = None,
) -> GhidraFunctionIndex | None:
    """``ghidra_functions.json``'dan dizin; ``delta`` Ghidra görüntü tabanı ile ikilinin bağlama
    tabanı farkıdır (PIE ELF: 0x100000 − 0). Taban okunamazsa ``delta`` 0 (adresler tutmazsa
    sayaçlar bunu ``ghidra_fonksiyonu_yok`` olarak gösterir)."""
    if functions_json is None or not Path(functions_json).is_file():
        return None
    try:
        data = json.loads(Path(functions_json).read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    funcs = data.get("functions", []) if isinstance(data, dict) else data
    by_addr: dict[int, str] = {}
    names: set[str] = set()
    for f in funcs if isinstance(funcs, list) else []:
        if not isinstance(f, dict) or not isinstance(f.get("name"), str):
            continue
        if f.get("is_external"):
            continue
        names.add(f["name"])
        try:
            by_addr.setdefault(int(str(f.get("address", "")), 16), f["name"])
        except ValueError:
            continue
    delta = 0
    link_base = _binary_link_base(binary_path) if binary_path is not None else None
    if ghidra_image_base is not None and link_base is not None:
        delta = int(ghidra_image_base) - int(link_base)
    return GhidraFunctionIndex(by_addr=by_addr, names=frozenset(names), delta=delta)


def _binary_link_base(binary_path: Path | None) -> int | None:
    """İkilinin bağlama tabanı: ELF en küçük PT_LOAD adresi (sayfaya hizalı), Mach-O ``__TEXT``,
    PE ``ImageBase``. Okunamazsa ``None``."""
    if binary_path is None or not Path(binary_path).is_file():
        return None
    try:
        import lief  # noqa: PLC0415 — isteğe bağlı bağımlılık
        lief.logging.disable()
        binary = lief.parse(str(binary_path))
    except Exception:  # lief yok ya da biçim tanınmadı
        return None
    if binary is None:
        return None
    try:
        if isinstance(binary, lief.ELF.Binary):
            loads = [s.virtual_address for s in binary.segments
                     if s.type == lief.ELF.Segment.TYPE.LOAD]
            return (min(loads) & ~0xFFF) if loads else None
        if isinstance(binary, lief.MachO.Binary):
            seg = binary.get_segment("__TEXT")
            return int(seg.virtual_address) if seg is not None else None
        if isinstance(binary, lief.PE.Binary):
            return int(binary.optional_header.imagebase)
    except Exception:
        return None
    return None


def pe_section_rvas(binary_path: Path | None) -> list[int] | None:
    """PE bölümlerinin RVA'ları (PDB ``bölüm:ofset`` → RVA için; bölüm 1'den sayılır)."""
    if binary_path is None or not Path(binary_path).is_file():
        return None
    try:
        import lief  # noqa: PLC0415
        lief.logging.disable()
        binary = lief.parse(str(binary_path))
        if not isinstance(binary, lief.PE.Binary):
            return None
        return [int(s.virtual_address) for s in binary.sections]
    except Exception:
        return None


def _channel(stats: dict[str, Any], source: str) -> dict[str, Any]:
    return stats.setdefault("naming_channels", {}).setdefault(source, {})


def _set_status(stats: dict[str, Any], source: str, status: str, reason: str = "") -> None:
    ch = _channel(stats, source)
    ch["durum"] = status
    if reason:
        ch["neden"] = reason


def _add_resolved(
    *,
    source: str,
    addr: int | None,
    symbol: str | None,
    qualified: str,
    confidence: float,
    reason: str,
    index: GhidraFunctionIndex,
    candidates: dict[str, list[Any]],
    stats: dict[str, Any],
) -> bool:
    """Adresi (ya da ayrıştırılmamış simge adını) Ghidra anahtarına çevirip aday ekle."""
    ch = _channel(stats, source)
    key, outcome = (None, "ghidra_fonksiyonu_yok")
    if addr is not None:
        key, outcome = index.key_for(addr)
    if key is None and symbol:
        key2, outcome2 = index.key_for_name(symbol)
        if key2 is not None:
            key, outcome = key2, outcome2
    ch[outcome] = ch.get(outcome, 0) + 1
    if key is None:
        return False
    name = c_identifier(qualified)
    if name is None:
        ch["gecersiz_ad"] = ch.get("gecersiz_ad", 0) + 1
        return False
    candidates.setdefault(key, []).append(_make_candidate(
        name=name, source=source, confidence=confidence,
        reason=f"{reason}: {qualified}" if qualified != name else reason,
    ))
    ch["aday"] = ch.get("aday", 0) + 1
    return True


def add_k4_channels(
    *,
    flags: dict[str, bool],
    index: GhidraFunctionIndex | None,
    binary_path: Path | None,
    pdb_symbols: list[dict[str, Any]] | None,
    pdb_status: str | None,
    bn_functions: list[dict[str, Any]] | None,
    bn_status: str | None,
    trex_structs: list[dict[str, Any]] | None,
    trex_status: str | None,
    rtti_classes: list[dict[str, Any]] | None = None,
    rtti_status: tuple[str, str] | None = None,
    candidates: dict[str, list[Any]],
    stats: dict[str, Any],
) -> None:
    """Bayrağı açık K-4 kanallarını çalıştır; her kanalın durumunu yaz (kapalılar dahil)."""
    for source in K4_CHANNEL_FLAGS:
        if not flags.get(source):
            _set_status(stats, source, CH_DISABLED, f"{K4_CHANNEL_FLAGS[source]} kapalı (ölçülmedi)")
    active = [s for s in K4_CHANNEL_FLAGS if flags.get(s)]
    if not active:
        return
    if index is None:
        for source in active:
            _set_status(stats, source, CH_NO_DATA, "Ghidra fonksiyon listesi yok")
        return
    if flags.get("dwarf"):
        _add_dwarf(binary_path, index, candidates, stats)
    if flags.get("rust_demangler") or flags.get("go_demangler"):
        syms = _extract_binary_symbols(binary_path) if binary_path is not None else []
        if flags.get("rust_demangler"):
            _add_rust_demangler(syms, index, candidates, stats)
        if flags.get("go_demangler"):
            _add_go_demangler(syms, index, candidates, stats)
    if flags.get("pdb"):
        _add_pdb_symbols(pdb_symbols or [], pdb_status, binary_path, index, candidates, stats)
    if flags.get("bn_symbol"):
        _add_bn_symbols(bn_functions or [], bn_status, index, candidates, stats)
    if flags.get("trex_struct"):
        _add_trex_structs(trex_structs or [], trex_status, index, candidates, stats)
    if flags.get("rtti"):
        _add_rtti(rtti_classes or [], rtti_status, index, candidates, stats)


def _add_dwarf(
    binary_path: Path | None,
    index: GhidraFunctionIndex,
    candidates: dict[str, list[Any]],
    stats: dict[str, Any],
) -> None:
    """DWARF ``.debug_info`` (ikilinin kendisinde ya da yanındaki ``.dSYM``'de) fonksiyon adları."""
    if binary_path is None or not Path(binary_path).exists():
        _set_status(stats, "dwarf", CH_NO_DATA, "ikili yolu yok")
        return
    try:
        from karadul.analyzers.dwarf_extractor import DwarfExtractor
    except ImportError:
        _set_status(stats, "dwarf", CH_NO_TOOL, "dwarf_extractor yüklenemedi")
        return
    try:
        funcs = DwarfExtractor(binary_path).extract_functions()
    except Exception as exc:
        logger.debug("DWARF extract basarisiz: %s", exc, exc_info=True)
        _set_status(stats, "dwarf", CH_ERROR, type(exc).__name__)
        return
    if not funcs:
        _set_status(stats, "dwarf", CH_NO_DATA, "hata ayıklama bilgisi yok (ikili ve .dSYM)")
        return
    for fn in funcs:
        name = getattr(fn, "name", None)
        addr = getattr(fn, "address", None)
        if not name or not addr:
            continue
        _add_resolved(
            source="dwarf", addr=int(addr), symbol=None, qualified=str(name),
            confidence=0.95, index=index, candidates=candidates, stats=stats,
            reason=(f"DWARF .debug_info ({getattr(fn, 'source_file', '?')}:"
                    f"{getattr(fn, 'line_number', '?')})"),
        )
    _set_status(stats, "dwarf", CH_RAN)


def _extract_binary_symbols(binary_path: Path | None) -> list[tuple[str, int]]:
    """nm -P ile (name, addr) sembol cifti listesi cek. macOS+Linux uyumlu."""
    if binary_path is None:
        return []
    try:
        from karadul.core.safe_subprocess import resolve_tool, safe_run
    except ImportError:
        try:
            from karadul.core.safe_subprocess import safe_run
            resolve_tool = None  # type: ignore[assignment]
        except ImportError:
            return []
    nm_path = resolve_tool("nm") if resolve_tool is not None else "nm"
    if nm_path is None:
        return []
    try:
        result = safe_run([str(nm_path), "-P", str(binary_path)], timeout=30.0, capture_output=True)
    except Exception:
        return []
    if result.returncode != 0:
        return []
    syms: list[tuple[str, int]] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        if parts[1] in ("U", "w", "v"):  # tanımsız / zayıf başvuru: ikilide gövde yok
            continue
        try:
            addr = int(parts[2], 16)
        except (ValueError, IndexError):
            continue
        if addr == 0:
            continue
        syms.append((name, addr))
    return syms


def is_rust_symbol(symbol: str) -> bool:
    """Rust adı mı (legacy karma bileşeniyle ya da v0)? C++ ``_ZN…`` adları değil."""
    return bool(_RUST_LEGACY_RE.match(symbol) or _RUST_V0_RE.match(symbol))


def _add_rust_demangler(
    syms: list[tuple[str, int]],
    index: GhidraFunctionIndex,
    candidates: dict[str, list[Any]],
    stats: dict[str, Any],
) -> None:
    """Rust simgeleri (legacy / v0) ayrıştırılıp Ghidra'nın adsız fonksiyonuna ya da ayrıştırılmamış
    adı taşıyan fonksiyonuna aday olur. C++ Itanium adları bu kanala girmez."""
    try:
        from karadul.analyzers.rust_demangler import demangle as rust_demangle
    except ImportError:
        _set_status(stats, "rust_demangler", CH_NO_TOOL, "rust_demangler yüklenemedi")
        return
    if not syms:
        _set_status(stats, "rust_demangler", CH_NO_DATA, "ikilide simge yok (soyulmuş)")
        return
    ch = _channel(stats, "rust_demangler")
    seen = 0
    for name, addr in syms:
        if not is_rust_symbol(name):
            continue
        seen += 1
        try:
            demangled = rust_demangle(name)
        except Exception:
            demangled = None
        if not demangled or demangled == name:
            ch["cozulemedi"] = ch.get("cozulemedi", 0) + 1
            continue
        _add_resolved(
            source="rust_demangler", addr=addr, symbol=name, qualified=demangled,
            confidence=0.95, reason="Rust ad ayrıştırma", index=index,
            candidates=candidates, stats=stats,
        )
    ch["rust_simge"] = seen
    _set_status(stats, "rust_demangler", CH_RAN if seen else CH_NO_DATA,
                "" if seen else "Rust simgesi yok")


def _add_go_demangler(
    syms: list[tuple[str, int]],
    index: GhidraFunctionIndex,
    candidates: dict[str, list[Any]],
    stats: dict[str, Any],
) -> None:
    """Go simgeleri (``paket.Fonksiyon``) ayrıştırılıp aday olur."""
    try:
        from karadul.analyzers.go_demangler import (
            demangle as go_demangle,
            is_go_symbol,
        )
    except ImportError:
        _set_status(stats, "go_demangler", CH_NO_TOOL, "go_demangler yüklenemedi")
        return
    if not syms:
        _set_status(stats, "go_demangler", CH_NO_DATA, "ikilide simge yok (soyulmuş)")
        return
    ch = _channel(stats, "go_demangler")
    seen = 0
    for name, addr in syms:
        try:
            if not is_go_symbol(name):
                continue
            demangled = go_demangle(name)
        except Exception:
            continue
        seen += 1
        if not demangled:
            ch["cozulemedi"] = ch.get("cozulemedi", 0) + 1
            continue
        _add_resolved(
            source="go_demangler", addr=addr, symbol=name, qualified=demangled,
            confidence=0.90, reason="Go ad ayrıştırma", index=index,
            candidates=candidates, stats=stats,
        )
    ch["go_simge"] = seen
    _set_status(stats, "go_demangler", CH_RAN if seen else CH_NO_DATA,
                "" if seen else "Go simgesi yok")


# PDB simge türlerinden fonksiyon gövdesi olanlar (pdb_parser ``kind``)
_PDB_FUNCTION_KINDS = frozenset({"function"})


def _add_pdb_symbols(
    pdb_symbols: list[dict[str, Any]],
    pdb_status: str | None,
    binary_path: Path | None,
    index: GhidraFunctionIndex,
    candidates: dict[str, list[Any]],
    stats: dict[str, Any],
) -> None:
    """PDB fonksiyon simgeleri: ``bölüm:ofset`` → VA (görüntü tabanı + bölüm RVA + ofset)."""
    if not pdb_symbols:
        if pdb_status in ("tool_missing", "module_missing"):
            _set_status(stats, "pdb", CH_NO_TOOL, "llvm-pdbutil bulunamadı")
        elif pdb_status == "not_pe_target":
            _set_status(stats, "pdb", CH_UNSUPPORTED, "PE değil")
        else:
            _set_status(stats, "pdb", CH_NO_DATA, f"PDB simgesi yok ({pdb_status})")
        return
    rvas = pe_section_rvas(binary_path)
    image_base = _binary_link_base(binary_path)
    if not rvas or image_base is None:
        _set_status(stats, "pdb", CH_ERROR, "PE bölüm tablosu okunamadı (bölüm:ofset → VA yok)")
        return
    for sym in pdb_symbols:
        if sym.get("kind") not in _PDB_FUNCTION_KINDS:
            continue
        name, sec, off = sym.get("name"), sym.get("section"), sym.get("address")
        if not name or not isinstance(sec, int) or not isinstance(off, int):
            continue
        if not 1 <= sec <= len(rvas):
            ch = _channel(stats, "pdb")
            ch["bolum_disi"] = ch.get("bolum_disi", 0) + 1
            continue
        _add_resolved(
            source="pdb", addr=image_base + rvas[sec - 1] + off, symbol=None,
            qualified=str(name), confidence=0.95, reason="PDB simgesi", index=index,
            candidates=candidates, stats=stats,
        )
    _set_status(stats, "pdb", CH_RAN)


def _add_bn_symbols(
    bn_functions: list[dict[str, Any]],
    bn_status: str | None,
    index: GhidraFunctionIndex,
    candidates: dict[str, list[Any]],
    stats: dict[str, Any],
) -> None:
    """Binary Ninja fonksiyon adları (araç ve lisans varsa)."""
    if not bn_functions:
        if bn_status in ("arac_yok", "not_available", "module_missing"):
            _set_status(stats, "bn_symbol", CH_NO_TOOL, "Binary Ninja Python API yok")
        elif bn_status == "disabled":
            _set_status(stats, "bn_symbol", CH_DISABLED,
                        "üretici kapalı (binary_reconstruction.enable_binaryninja)")
        else:
            _set_status(stats, "bn_symbol", CH_NO_DATA, f"BN fonksiyonu yok ({bn_status})")
        return
    for fn in bn_functions:
        name, addr = fn.get("name"), fn.get("address")
        if not name or addr is None or fn.get("is_thunk") or fn.get("is_imported"):
            continue
        if name.startswith(("sub_", "FUN_", "thunk_")):  # BN'in öntanımlı adları
            continue
        try:
            addr_int = int(addr) if not isinstance(addr, str) else int(addr, 16)
        except ValueError:
            continue
        _add_resolved(
            source="bn_symbol", addr=addr_int, symbol=None, qualified=str(name),
            confidence=0.85, reason="Binary Ninja", index=index,
            candidates=candidates, stats=stats,
        )
    _set_status(stats, "bn_symbol", CH_RAN)


def _struct_name_to_func_hint(struct_name: str) -> str:
    """CamelCase struct → snake_case fonksiyon ipucu."""
    s = re.sub(r"(?<!^)([A-Z])", r"_\1", struct_name).lower()
    return s


def _add_trex_structs(
    trex_structs: list[dict[str, Any]],
    trex_status: str | None,
    index: GhidraFunctionIndex,
    candidates: dict[str, list[Any]],
    stats: dict[str, Any],
) -> None:
    """TRex yapı çıkarımından fonksiyon ipucu (üretici ``function`` ya da ``related_functions``)."""
    if not trex_structs:
        if trex_status == CH_UNSUPPORTED:
            _set_status(stats, "trex_struct", CH_UNSUPPORTED,
                        "ghidra_lifted_il_path üreten adım yok")
        elif trex_status == CH_NO_TOOL:
            _set_status(stats, "trex_struct", CH_NO_TOOL, "TRex ikilisi yok")
        else:
            _set_status(stats, "trex_struct", CH_NO_DATA, f"TRex yapısı yok ({trex_status})")
        return
    for st in trex_structs:
        struct_name = st.get("name")
        funcs = list(st.get("related_functions") or [])
        if st.get("function"):
            funcs.append(st["function"])
        if not struct_name or not funcs:
            continue
        hint = _struct_name_to_func_hint(struct_name)
        for ref in funcs:
            addr: int | None = None
            symbol: str | None = None
            if isinstance(ref, str) and ref.startswith("FUN_"):
                symbol = ref
            else:
                try:
                    addr = int(ref, 16) if isinstance(ref, str) else int(ref)
                except (TypeError, ValueError):
                    continue
            _add_resolved(
                source="trex_struct", addr=addr, symbol=symbol, qualified=hint,
                confidence=0.75, reason=f"TRex yapısı {struct_name}", index=index,
                candidates=candidates, stats=stats,
            )
    _set_status(stats, "trex_struct", CH_RAN)


def _add_rtti(
    rtti_classes: list[dict[str, Any]],
    rtti_status: tuple[str, str] | None,
    index: GhidraFunctionIndex,
    candidates: dict[str, list[Any]],
    stats: dict[str, Any],
) -> None:
    """C++ RTTI: vtable yuvasındaki adsız fonksiyona ``Sinif_vfunc_N`` adayı (IMZA-16).

    ``rtti_classes``: ``{"name": sınıf, "methods": [adres, …]}``. Yuvanın gerçek yöntem adı RTTI'de
    yoktur; aday yalnız sınıf + yuva sırasıdır (ad doğruluğu ölçülmedi, bayrak arkasında).
    """
    if rtti_status is None:
        # P13b kalem 4 yapılmadı: RTTI kurtarmayı (analyzers/cpp_rtti.py) analiz akışında koşturan
        # üretici yok; "sınıf bulunamadı" demek yalan olur (hiç aranmadı).
        _set_status(stats, "rtti", CH_UNSUPPORTED,
                    "RTTI kurtarma analiz akışına bağlı değil (üretici yok)")
        return
    if rtti_status[0] != CH_RAN:
        _set_status(stats, "rtti", rtti_status[0], rtti_status[1])
        return
    if not rtti_classes:
        _set_status(stats, "rtti", CH_NO_DATA, "RTTI sınıfı bulunamadı")
        return
    for cls in rtti_classes:
        cname = cls.get("name")
        if not cname:
            continue
        for slot, addr in enumerate(cls.get("methods") or []):
            if not isinstance(addr, int) or addr <= 0:
                continue
            _add_resolved(
                source="rtti", addr=addr, symbol=None, qualified=f"{cname}_vfunc_{slot}",
                confidence=0.6, reason=f"RTTI vtable {cname}[{slot}]", index=index,
                candidates=candidates, stats=stats,
            )
    _set_status(stats, "rtti", CH_RAN)

# ---------------------------------------------------------------------------
# Per-source helper'lari
# ---------------------------------------------------------------------------


def _add_binary_extractor(
    extracted_names: dict[str, str],
    candidates: dict[str, list[Any]],
) -> None:
    for old_name, new_name in extracted_names.items():
        if not old_name or len(old_name) < 2 or not new_name:
            continue
        candidates.setdefault(old_name, []).append(
            NamingCandidate(new_name, 0.85, "binary_extractor"),
        )


def _add_c_namer(
    naming_result: Any, candidates: dict[str, list[Any]],
    stats: dict[str, Any] | None = None,
) -> None:
    """c_namer'ın adları (yalnız c_namer koşmuş sayılmadığında çağrılır; bkz. collect_candidates).

    Güveni ``confidence_map``'te olmayan ad (ölçülmemiş kanaldaki ön ad: Faz 1, elle) aday
    olmaz: eskiden 0,70 uyduruluyordu (P12a / AD-07 notu; P13a). Sayısı
    ``name_merger_c_namer_unmeasured`` istatistiğinde.
    """
    if naming_result is None or not hasattr(naming_result, "naming_map"):
        return
    # FIX (2026-07-12): sabit 0.70 yerine c_namer'in gercek per-isim
    # confidence'ini kullan. Zayif yapisal stratejileri (call_graph/callee_based
    # -> helper_<adr>, dispatcher_<adr> gibi adres-gomulu uydurmalar) ayri
    # dusuk-agirlik source'a (c_namer_structural, weight 0.35) etiketle ki
    # tek-kaynak olduklarinda NameMerger'in UNK esigi altinda kalip FUN_xxx
    # olarak birakilsinlar. Korroborasyon (byte-sig/cfg_iso) varsa isim verilir.
    conf_map = getattr(naming_result, "confidence_map", None) or {}
    strat_map = getattr(naming_result, "strategy_map", None) or {}
    for old_name, new_name in naming_result.naming_map.items():
        if not old_name or len(old_name) < 2 or not new_name:
            continue
        strat = strat_map.get(old_name, "")
        if strat in ("call_graph", "callee_based"):
            # Adres-gomulu yapisal uydurma (helper_<adr>, dispatcher_<adr>) --
            # gercek bilgi ~0. Confidence'i UNK esigi (0.30) altina sabitle ki
            # tek-kaynak oldugunda merger FUN_xxx biraksin; korroborasyon varsa gecer.
            candidates.setdefault(old_name, []).append(
                NamingCandidate(new_name, 0.25, "c_namer_structural"),
            )
        else:
            conf = conf_map.get(old_name)
            if not isinstance(conf, (int, float)) or isinstance(conf, bool):
                if stats is not None:
                    stats["name_merger_c_namer_unmeasured"] = (
                        stats.get("name_merger_c_namer_unmeasured", 0) + 1)
                continue
            candidates.setdefault(old_name, []).append(
                NamingCandidate(new_name, float(conf), "c_namer"),
            )


def _add_bindiff(
    bindiff_confidence_map: dict[str, tuple[str, float, str]],
    candidates: dict[str, list[Any]],
) -> None:
    if not bindiff_confidence_map:
        return
    for old_name, (new_name, conf, method) in bindiff_confidence_map.items():
        if not old_name or len(old_name) < 2 or not new_name:
            continue
        candidates.setdefault(old_name, []).append(
            NamingCandidate(new_name, conf, f"bindiff_{method}"),
        )
    logger.debug(
        "BinDiff: %d candidate (per-match confidence) Name Merger'a eklendi",
        len(bindiff_confidence_map),
    )


def _add_refdiff(
    refdiff_naming: dict[str, str], candidates: dict[str, list[Any]],
) -> None:
    if not refdiff_naming:
        return
    for old_name, new_name in refdiff_naming.items():
        if not old_name or len(old_name) < 2 or not new_name:
            continue
        candidates.setdefault(old_name, []).append(
            NamingCandidate(new_name, 0.95, "reference_differ"),
        )
    logger.debug(
        "ReferenceDiffer: %d candidate Name Merger'a eklendi",
        len(refdiff_naming),
    )


def _add_fid(fid_json: Path, candidates: dict[str, list[Any]]) -> None:
    if not (fid_json and fid_json.exists()):
        return
    try:
        fid_data = json.loads(
            fid_json.read_text(encoding="utf-8", errors="replace"),
        )
        for m in fid_data.get("matches", []):
            fid_name = m.get("name", "")
            fid_addr = m.get("address", "")
            if not fid_name or not fid_addr:
                continue
            # KANONIK key: int(hex) -> FUN_00101234. Eski lstrip("0x") bir
            # KARAKTER-SETI ("0" ve "x") stripliyor + padding yok -> FID library
            # candidate'lari Ghidra sembolleriyle eslesemiyordu.
            try:
                fun_key = f"FUN_{int(str(fid_addr), 16):08x}"
            except (ValueError, TypeError):
                continue
            if len(fun_key) >= 2:
                candidates.setdefault(fun_key, []).append(
                    NamingCandidate(fid_name, 0.95, "function_id"),
                )
        logger.debug(
            "FunctionID: %d candidate eklendi",
            fid_data.get("total_matches", 0),
        )
    except Exception as exc:
        logger.debug("FunctionID candidate yuklenemedi: %s", exc)


def _add_computation(
    computation_result: Any,
    candidates: dict[str, list[Any]],
    iter_index: int,
    stats: dict[str, Any],
) -> None:
    """Computation Recovery + cross-binary transfer."""
    comp_added = 0
    for nc in computation_result.naming_candidates:
        func_name = nc.get("function_name", "")
        cand_name = nc.get("candidate_name", "")
        cand_conf = nc.get("confidence", 0.0)
        cand_src = nc.get("source", "computation_recovery")
        if not func_name or len(func_name) < 2 or not cand_name:
            continue
        if not _is_unnamed(func_name):
            continue
        if cand_src == "signature_fusion" and cand_conf < 0.40:
            continue
        if cand_src == "callee_profile" and cand_conf < 0.30:
            continue
        candidates.setdefault(func_name, []).append(
            NamingCandidate(cand_name, cand_conf, cand_src),
        )
        comp_added += 1
    if comp_added:
        logger.debug(
            "Computation Recovery: %d naming candidate eklendi", comp_added,
        )

    cross_matches = computation_result.layer_results.get(
        "cross_binary_matches", [],
    )
    if cross_matches and iter_index == 0:
        cross_added = 0
        for cm in cross_matches:
            cm_func = cm.get("func_name", "")
            cm_name = cm.get("matched_name", "")
            cm_conf = cm.get("confidence", 0.0)
            if not cm_func or not cm_name:
                continue
            if not _is_unnamed(cm_func, include_unnamed=False):
                continue
            candidates.setdefault(cm_func, []).append(
                NamingCandidate(
                    cm_name, cm_conf, "cross_binary_transfer",
                    reason="CFG fingerprint match from cached binary %s" % (
                        cm.get("source_binary", "?"),
                    ),
                ),
            )
            cross_added += 1
        if cross_added:
            logger.info(
                "Cross-binary transfer: %d naming candidate eklendi",
                cross_added,
            )
            stats["cross_binary_candidates"] = cross_added


def _add_pcode(
    pcode_naming_candidates: list[dict[str, Any]], candidates: dict[str, list[Any]],
) -> None:
    pcode_added = 0
    for nc in pcode_naming_candidates:
        func_name = nc.get("function_name", "")
        cand_name = nc.get("candidate_name", "")
        cand_conf = nc.get("confidence", 0.0)
        cand_src = nc.get("source", "pcode_dataflow")
        if not cand_name or not func_name:
            continue
        if not _is_unnamed(func_name):
            continue
        candidates.setdefault(func_name, []).append(
            NamingCandidate(
                cand_name, cand_conf, cand_src, reason=nc.get("reason", ""),
            ),
        )
        pcode_added += 1
    if pcode_added > 0:
        logger.info("P-Code naming: %d candidate eklendi", pcode_added)


def _add_bsim(
    *,
    bsim_shadow: dict[str, Any],
    candidates: dict[str, list[Any]],
    min_similarity: float,
    max_per_function: int,
    stats: dict[str, Any],
) -> None:
    """BSim kopru (v1.11.0 Hafta 2): shadow payload -> NamingCandidate.

    Shadow payload formati ``bsim_match.BSimMatchStep._build_shadow_payload``
    tarafindan uretilir:

        {
          "version": "1",
          "mode": "shadow" | "live-dump-only",
          "matches": [
            {"function_addr": "0x...", "function_name": "FUN_xxx",
             "bsim_candidates": [
                {"name": str, "similarity": float, "binary": str}, ...
             ]}
          ]
        }

    Confidence olarak BSim similarity skorunu dogrudan kullaniyoruz.
    Source-bazli weight (``NameMergerConfig.source_weights["bsim"] = 0.85``)
    NameMerger'in kendi Bayesian log-odds fusion'inda uygulanir;
    burada ayrica kesrin carpilmasi double-damping olur.
    """
    matches = bsim_shadow.get("matches") or []
    if not isinstance(matches, list) or not matches:
        return

    added = 0
    skipped_unnamed = 0
    skipped_low_sim = 0
    skipped_no_key = 0
    for entry in matches:
        if not isinstance(entry, dict):
            continue
        func_name = str(entry.get("function_name", "") or "")
        func_addr = str(entry.get("function_addr", "") or "")

        # Hedef sembol anahtari: once function_name (Ghidra FUN_xxx),
        # yoksa function_addr'den FUN_XXX uret.
        old_key = func_name.strip()
        if not old_key and func_addr:
            # "0x004012a0" -> "FUN_004012a0" (kanonik 8-hane). Eski
            # lstrip("0x") karakter-seti stripliyor + padding yoktu ->
            # BSim adres-fallback candidate'lari eslesemiyordu.
            try:
                old_key = f"FUN_{int(func_addr, 16):08x}"
            except (ValueError, TypeError):
                old_key = ""
        if not old_key or len(old_key) < 2:
            skipped_no_key += 1
            continue

        # Sadece adlandirilmamis fonksiyonlar icin oneri uret
        if not _is_unnamed(old_key):
            skipped_unnamed += 1
            continue

        bsim_cands = entry.get("bsim_candidates") or []
        if not isinstance(bsim_cands, list):
            continue

        # top-N similarity desc (shadow payload zaten sortli ama
        # defansif olarak yeniden sortla)
        ranked = sorted(
            (c for c in bsim_cands if isinstance(c, dict)),
            key=lambda c: float(c.get("similarity", 0.0) or 0.0),
            reverse=True,
        )[:max_per_function]

        for cand in ranked:
            cand_name = str(cand.get("name", "") or "").strip()
            if not cand_name:
                continue
            try:
                sim = float(cand.get("similarity", 0.0) or 0.0)
            except (TypeError, ValueError):
                sim = 0.0
            if sim < min_similarity:
                skipped_low_sim += 1
                continue
            binary = str(cand.get("binary", "") or "")
            candidates.setdefault(old_key, []).append(
                NamingCandidate(
                    cand_name,
                    sim,
                    "bsim",
                    reason=f"BSim match (sim={sim:.3f}, binary={binary})",
                ),
            )
            added += 1

    if added:
        logger.info(
            "BSim fusion: %d naming candidate eklendi (skip: %d unnamed, "
            "%d low-sim, %d no-key)",
            added, skipped_unnamed, skipped_low_sim, skipped_no_key,
        )
        stats["bsim_fusion_candidates"] = added
    else:
        logger.debug(
            "BSim fusion: 0 candidate (skip: %d unnamed, %d low-sim, "
            "%d no-key)",
            skipped_unnamed, skipped_low_sim, skipped_no_key,
        )


def _is_unnamed(name: str, *, include_unnamed: bool = True) -> bool:
    """FUN_/sub_/thunk_/_unnamed_ prefix kontrolu."""
    if (
        name.startswith("FUN_")
        or name.startswith("sub_")
        or name.startswith("thunk_")
    ):
        return True
    if include_unnamed and name.startswith("_unnamed_"):
        return True
    return False


# ---------------------------------------------------------------------------
# v1.21 Engineering Fusion helpers (2026-05-14)
#
# karadul/reconstruction/engineering paketinin pipeline'a entegrasyonu.
# Tek dispatcher _add_engineering_naming() ucu da uretir:
#   * engineering_constant  -- IEEE-754 sabit eslestirmesi (Gauss, k-eps vb.)
#   * engineering_api       -- BLAS/LAPACK/FFTW/PETSc cagrilari
#   * engineering_formula   -- FormulaReconstructor template match
#
# Hepsi tek EngineeringAlgorithmAnalyzer.identify() ciktisindan turetilir,
# ekstra decompile gerektirmez. Modul yoksa veya hata olursa GRACEFUL SKIP.
# ---------------------------------------------------------------------------


_ALGO_NAME_TO_FUNC_HINT_OVERRIDES: dict[str, str] = {
    # Sik gecen algoritma adi -> daha okunabilir fonksiyon ipucu.
    # Yoksa _sanitize_algo_to_func_name fallback yapilir.
    "matrix_multiply": "matrix_multiply",
    "dot_product": "vector_dot",
    "axpy": "vector_axpy",
    "lu_factorization": "lu_factorize",
    "cholesky_factorization": "cholesky_factorize",
    "qr_factorization": "qr_factorize",
    "svd": "svd_decompose",
    "eigenvalue_decomposition": "eigen_decompose",
    "fft": "fft_transform",
    "ifft": "ifft_transform",
    "gauss_quadrature_1pt": "gauss_quad_1pt",
    "gauss_quadrature_2pt": "gauss_quad_2pt",
    "gauss_quadrature_3pt": "gauss_quad_3pt",
    "k_epsilon_turbulence": "turb_k_epsilon",
    "black_scholes": "black_scholes_price",
    "monte_carlo": "monte_carlo_simulate",
}


def _sanitize_algo_to_func_name(algo_name: str) -> str:
    """Algoritma adini valid C fonksiyon adina cevir.

    "AES-256-CBC" -> "aes_256_cbc"
    "Gauss Legendre 3pt" -> "gauss_legendre_3pt"
    "matrix_multiply" -> "matrix_multiply" (degisim yok)
    """
    import re as _re
    s = algo_name.strip().lower()
    s = _re.sub(r"[^a-z0-9_]+", "_", s)
    s = _re.sub(r"_+", "_", s).strip("_")
    if not s or s[0].isdigit():
        s = f"algo_{s}" if s else "algo_unknown"
    return s


def _algo_name_to_func_hint(algo_name: str) -> str:
    """Algoritma adi -> fonksiyon adi ipucu (override + sanitize)."""
    key = algo_name.strip().lower()
    if key in _ALGO_NAME_TO_FUNC_HINT_OVERRIDES:
        return _ALGO_NAME_TO_FUNC_HINT_OVERRIDES[key]
    return _sanitize_algo_to_func_name(algo_name)


def _add_engineering_naming(
    *,
    decompiled_dir: Path,
    functions_json: Path,
    candidates: dict[str, list[Any]],
    stats: dict[str, Any],
) -> None:
    """v1.21: Engineering analyzer ciktisindan 3 naming kanali.

    EngineeringAlgorithmAnalyzer.identify() tek seferde calistirilir;
    sonuc detection_method'a gore 3 alt-helper'a dagitilir:
      * constant -> engineering_constant
      * api      -> engineering_api
      * structural / yapisal -> engineering_constant (constant grubuna sayilir)

    Ek olarak FormulaReconstructor calistirilarak formula template match'leri
    ayni AlgorithmMatch listesinden uretilir (engineering_formula).
    """
    try:
        from karadul.reconstruction.engineering import (
            EngineeringAlgorithmAnalyzer,
            FormulaReconstructor,
        )
    except ImportError as exc:
        logger.debug("Engineering analyzer import basarisiz: %s", exc)
        stats["engineering_naming_status"] = "no-module"
        return

    try:
        analyzer = EngineeringAlgorithmAnalyzer()
        result = analyzer.identify(decompiled_dir, functions_json)
    except Exception as exc:
        logger.debug("Engineering identify hata: %s", exc, exc_info=True)
        stats["engineering_naming_status"] = "identify-error"
        return

    if not result.success or not result.algorithms:
        stats["engineering_naming_status"] = "no-matches"
        stats["engineering_candidates_added"] = 0
        return

    const_added = _add_engineering_constant_naming(
        algorithms=result.algorithms, candidates=candidates,
    )
    api_added = _add_engineering_api_naming(
        algorithms=result.algorithms, candidates=candidates,
    )

    formula_added = 0
    try:
        reconstructor = FormulaReconstructor()
        formulas = reconstructor.reconstruct(result.algorithms)
        formula_added = _add_engineering_formula_naming(
            algorithms=result.algorithms,
            formulas=formulas,
            candidates=candidates,
        )
    except Exception as exc:
        logger.debug("FormulaReconstructor hata: %s", exc, exc_info=True)
        stats["engineering_formula_status"] = "reconstruct-error"

    total = const_added + api_added + formula_added
    stats["engineering_naming_status"] = "active" if total else "no-candidates"
    stats["engineering_const_candidates"] = const_added
    stats["engineering_api_candidates"] = api_added
    stats["engineering_formula_candidates"] = formula_added
    stats["engineering_candidates_added"] = total

    if total:
        logger.info(
            "Engineering naming: %d candidate eklendi (const=%d, api=%d, "
            "formula=%d)",
            total, const_added, api_added, formula_added,
        )


def _add_engineering_constant_naming(
    *,
    algorithms: list[Any],
    candidates: dict[str, list[Any]],
) -> int:
    """IEEE-754 sabit ve yapisal pattern tabanli naming.

    AlgorithmMatch.detection_method in {"constant", "structural"} olanlari
    engineering_constant source ile candidate'a cevirir. function_name FUN_xxx
    veya benzeri 'unnamed' formdaysa eklenir; aksi halde atlanir (zaten
    ismi olan fonksiyona zayif evidence basmayalim).
    """
    added = 0
    for m in algorithms:
        method = getattr(m, "detection_method", "")
        if method not in ("constant", "structural", "yapisal"):
            continue
        fname = getattr(m, "function_name", "") or ""
        algo = getattr(m, "name", "") or ""
        conf = float(getattr(m, "confidence", 0.0) or 0.0)
        if not fname or not algo:
            continue
        # Sadece adlandirilmamis fonksiyonlara oneri (mevcut adlari ezme).
        if not _is_unnamed(fname):
            continue
        hint = _algo_name_to_func_hint(algo)
        if not hint or len(hint) < 2:
            continue
        # Confidence floor: structural-only bulgular zaten 0.50 capped
        # (bkz analyzer._STRUCTURAL_ONLY_CAP); biz de min 0.40 alalim.
        if conf < 0.40:
            continue
        cand = _make_candidate(
            name=hint,
            source="engineering_constant",
            confidence=min(conf, 0.95),
            reason=f"{method}: {algo}",
        )
        candidates.setdefault(fname, []).append(cand)
        added += 1
    return added


def _add_engineering_api_naming(
    *,
    algorithms: list[Any],
    candidates: dict[str, list[Any]],
) -> int:
    """BLAS/LAPACK/FFTW/PETSc API cagrisi tabanli naming.

    AlgorithmMatch.detection_method == "api" olanlari engineering_api source ile
    candidate'a cevirir. API match'leri yuksek-precision oldugu icin confidence
    floor 0.50.
    """
    added = 0
    for m in algorithms:
        if getattr(m, "detection_method", "") != "api":
            continue
        fname = getattr(m, "function_name", "") or ""
        algo = getattr(m, "name", "") or ""
        conf = float(getattr(m, "confidence", 0.0) or 0.0)
        if not fname or not algo:
            continue
        if not _is_unnamed(fname):
            continue
        if conf < 0.50:
            continue
        hint = _algo_name_to_func_hint(algo)
        if not hint or len(hint) < 2:
            continue
        # API kaynaklarinda evidence listesinde kutuphane bilgisi olabilir.
        evidence = getattr(m, "evidence", None) or []
        ev_summary = (
            ", ".join(str(e) for e in evidence[:3]) if evidence else algo
        )
        cand = _make_candidate(
            name=hint,
            source="engineering_api",
            confidence=min(conf, 0.95),
            reason=f"api call: {ev_summary}",
        )
        candidates.setdefault(fname, []).append(cand)
        added += 1
    return added


# Formül adayıyla AYNI eşleşmeden (AlgorithmMatch) doğan kaynaklar
_SAME_MATCH_SOURCES = frozenset({"engineering_constant", "engineering_api"})


def _add_engineering_formula_naming(
    *,
    algorithms: list[Any],
    formulas: list[Any],
    candidates: dict[str, list[Any]],
) -> int:
    """FormulaReconstructor template match tabanli naming.

    FormulaReconstructor.reconstruct() dedup'lu FormulaInfo listesi doner;
    bu liste algorithms uzerinden uretildigi icin algoritma -> fonksiyon
    eslemesini AlgorithmMatch'lerden alip formula template eslesmesi olanlara
    engineering_formula source verir.
    """
    if not formulas:
        return 0
    # MUH-12 (P04b): formül, kendisini doğuran (tespit adı, fonksiyon) çiftlerini
    # taşır (FormulaInfo.detected_as / functions). Alt dizgi eşleşmesi yok: "Password-
    # based key derivation (PBKDF2, scrypt)" başka bir fonksiyonun PBKDF2 formülünden
    # ad almaz.
    # Kaynak taşımayan (eski biçim) formülde yalnız ad TAM eşitliği.
    formula_sources: set[tuple[str, str]] = set()
    exact_names: set[str] = set()
    for f in formulas:
        names = [n.strip().lower() for n in (getattr(f, "detected_as", None) or [])]
        funcs = list(getattr(f, "functions", None) or [])
        if names and funcs:
            for n in names:
                for fn in funcs:
                    formula_sources.add((n, fn))
        else:
            algo_name = (getattr(f, "algorithm", "") or "").strip().lower()
            if algo_name:
                exact_names.add(algo_name)
    if not formula_sources and not exact_names:
        return 0

    added = 0
    for m in algorithms:
        algo = (getattr(m, "name", "") or "").strip().lower()
        fname = getattr(m, "function_name", "") or ""
        conf = float(getattr(m, "confidence", 0.0) or 0.0)
        if not algo or not fname:
            continue
        if (algo, fname) not in formula_sources and algo not in exact_names:
            continue
        if not _is_unnamed(fname):
            continue
        if conf < 0.45:
            continue
        hint = _algo_name_to_func_hint(algo)
        if not hint or len(hint) < 2:
            continue
        # P13a: formül aynı AlgorithmMatch'ten doğar. Aynı fonksiyona aynı adı o eşleşme
        # zaten (sabit / API) verdiyse ikinci bir bağımsız kaynak DEĞİLDİR; birleştiricide iki
        # kaynak sayılıp güveni şişirmesin (kulvar AD "Küçükler": 0,60 → 0,709).
        if any(getattr(c, "name", None) == hint
               and getattr(c, "source", "") in _SAME_MATCH_SOURCES
               for c in candidates.get(fname, ())):
            continue
        cand = _make_candidate(
            name=hint,
            source="engineering_formula",
            confidence=min(conf + 0.05, 0.95),  # template match boost
            reason=f"formula template: {algo}",
        )
        candidates.setdefault(fname, []).append(cand)
        added += 1
    return added
