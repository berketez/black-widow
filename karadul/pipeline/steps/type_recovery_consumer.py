"""TypeRecoveryConsumerStep — type/sembol kurtarma artifact birlestirici.

v1.15-B7 (2026-05-13): re-analyst-binary audit bulgusu kapatildi.

Onceki halde ``trex_struct_recovery``, ``pdb_symbol_recovery`` ve
``binaryninja_analysis`` step'leri JSON artifact'leri uretiyordu:

    static/trex_structs.json     -- list[dict] TRexStruct
    static/pdb_symbols.json      -- list[dict] PDBSymbol
    static/pdb_types.json        -- list[dict] PDBType
    static/bn_functions.json     -- list[dict] BNFunction
    static/bn_types.json         -- list[dict] BNType

ama bu artifact'leri okuyup pipeline'daki naming/reconstruction'a baglayan
**hicbir tuketici yoktu** -- "dead pipeline" durumu.

Bu step:
    - 5 artifact'i okur (hepsi opsiyonel; biri/birkaci/hicbiri yoksa
      graceful skip)
    - Adres -> tip_info ve adres -> sembol_adi map'leri uretir
    - Cakisma durumunda oncelik PDB > BN > TRex (PDB compiler-emitted
      ground truth)
    - 2 yeni artifact yayinlar:

        consumed_symbols: dict[str, dict[str, Any]]
            Key = ``FUN_<hex>``
            Value = {"name": str, "source": "pdb"|"bn"|"trex",
                     "confidence": float, "address": int,
                     "extra": dict}

        consumed_types: dict[str, dict[str, Any]]
            Key = tip ismi (PDBType.name, BNType.name vb.)
            Value = {"source": str, "kind": str, "size": int,
                     "fields": list, "confidence": float}

    - ``_feedback_naming_merger`` ve ``c_type_recoverer`` bu artifact'leri
      okur ve heuristic'ten ONCE uygular.

Tasarim notu:
    - Step idempotent (ayni girdi -> ayni cikti).
    - Hicbir artifact yoksa stats["type_recovery_consumer_status"] = "no-data"
      ve bos dict'ler doner; pipeline kirilmaz.
    - ``requires`` listesinde sadece her zaman var olan ``binary_for_byte_match``
      var; opsiyonel artifact'ler ``ctx.artifacts.get()`` ile okunur. DAG
      kontrolu opsiyonelleri zorlamaz.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


@register_step(
    name="type_recovery_consumer",
    requires=[
        # Pipeline'in baska bir adimi tarafindan zaten urteilmis olan
        # baz artifact. Opsiyonel type-recovery artifact'leri requires'a
        # KOYULMAZ -- yoksa runner RuntimeError firlatir; bizim
        # tuketicimiz graceful skip yapiyor.
        "binary_for_byte_match",
    ],
    produces=[
        "consumed_symbols",       # dict[str, dict] -- FUN_xxx -> sym info
        "consumed_types",         # dict[str, dict] -- type_name -> tip info
        "type_recovery_status",   # str
    ],
    parallelizable_with=[
        "anti_debug",
        "packer_fingerprint",
        # Bu step uretici step'lerin (trex/pdb/bn) ARDINDAN calismali --
        # paralel degil. Stages.py listesinde sirali yer alir.
    ],
)
class TypeRecoveryConsumerStep(Step):
    """trex/pdb/bn artifact'lerini ortak symbol/type map'lerine birlestir."""

    # Oncelik sirasi: PDB > BN > TRex.
    # Ayni adrese birden fazla kaynak isim verirse PDB kazanir; PDB yoksa
    # BN; yoksa TRex. (Bu sadece consumed_symbols icin -- NameMerger'a
    # paralel candidate olarak HEPSI eklenir, Bayesian fusion'a karar
    # verdirilir.)
    _SOURCE_PRIORITY: dict[str, int] = {
        "pdb": 3,
        "bn": 2,
        "trex": 1,
    }

    def run(self, ctx: StepContext) -> dict[str, Any]:
        step_start = time.monotonic()

        empty: dict[str, Any] = {
            "consumed_symbols": {},
            "consumed_types": {},
            "type_recovery_status": "no-data",
        }

        # 1) Opsiyonel artifact'leri topla
        a = ctx.artifacts
        pdb_symbols = self._as_list(a.get("pdb_symbols"))
        pdb_types = self._as_list(a.get("pdb_types"))
        bn_functions = self._as_list(a.get("bn_functions"))
        bn_types = self._as_list(a.get("bn_types"))
        trex_structs = self._as_list(a.get("trex_structs"))

        total_inputs = (
            len(pdb_symbols) + len(pdb_types)
            + len(bn_functions) + len(bn_types)
            + len(trex_structs)
        )
        if total_inputs == 0:
            ctx.stats["type_recovery_consumer_status"] = "no-data"
            ctx.stats["timing_type_recovery_consumer"] = round(
                time.monotonic() - step_start, 3,
            )
            return empty

        # 2) consumed_symbols: adres -> sembol
        consumed_symbols: dict[str, dict[str, Any]] = {}
        self._merge_pdb_symbols(pdb_symbols, consumed_symbols)
        self._merge_bn_functions(bn_functions, consumed_symbols)
        self._merge_trex_structs(trex_structs, consumed_symbols)

        # 3) consumed_types: tip adi -> tip info
        consumed_types: dict[str, dict[str, Any]] = {}
        self._merge_pdb_types(pdb_types, consumed_types)
        self._merge_bn_types(bn_types, consumed_types)
        self._merge_trex_struct_types(trex_structs, consumed_types)

        # 4) Stat'lar
        ctx.stats["consumed_symbols_total"] = len(consumed_symbols)
        ctx.stats["consumed_types_total"] = len(consumed_types)
        ctx.stats["consumed_symbols_pdb"] = sum(
            1 for v in consumed_symbols.values() if v.get("source") == "pdb"
        )
        ctx.stats["consumed_symbols_bn"] = sum(
            1 for v in consumed_symbols.values() if v.get("source") == "bn"
        )
        ctx.stats["consumed_symbols_trex"] = sum(
            1 for v in consumed_symbols.values() if v.get("source") == "trex"
        )

        status = "active" if (consumed_symbols or consumed_types) else "empty"
        ctx.stats["type_recovery_consumer_status"] = status
        ctx.stats["timing_type_recovery_consumer"] = round(
            time.monotonic() - step_start, 3,
        )

        if consumed_symbols or consumed_types:
            logger.info(
                "type_recovery_consumer: %d sembol + %d tip birlestirildi "
                "(PDB=%d, BN=%d, TRex=%d)",
                len(consumed_symbols), len(consumed_types),
                ctx.stats["consumed_symbols_pdb"],
                ctx.stats["consumed_symbols_bn"],
                ctx.stats["consumed_symbols_trex"],
            )

        return {
            "consumed_symbols": consumed_symbols,
            "consumed_types": consumed_types,
            "type_recovery_status": status,
        }

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    @staticmethod
    def _as_list(value: Any) -> list[dict[str, Any]]:
        """Artifact degerini list[dict]'e normalize et (defansif)."""
        if value is None:
            return []
        if isinstance(value, list):
            return [v for v in value if isinstance(v, dict)]
        return []

    def _maybe_set_symbol(
        self,
        consumed: dict[str, dict[str, Any]],
        key: str,
        new_entry: dict[str, Any],
    ) -> None:
        """Oncelik karsilastirmasi ile sembolu ekle/uzerine yaz.

        Eski entry varsa: yeni kaynak daha yuksek priority -> uzerine yaz;
        daha dusuk priority -> es gec; esit -> ilki kazanir (deterministic).
        """
        if not key:
            return
        existing = consumed.get(key)
        if existing is None:
            consumed[key] = new_entry
            return
        new_pri = self._SOURCE_PRIORITY.get(new_entry.get("source", ""), 0)
        old_pri = self._SOURCE_PRIORITY.get(existing.get("source", ""), 0)
        if new_pri > old_pri:
            consumed[key] = new_entry

    def _merge_pdb_symbols(
        self,
        pdb_symbols: list[dict[str, Any]],
        consumed: dict[str, dict[str, Any]],
    ) -> None:
        for sym in pdb_symbols:
            name = str(sym.get("name", "") or "").strip()
            if not name:
                continue
            addr = self._coerce_addr(sym.get("address"))
            if addr is None or addr <= 0:
                continue
            key = f"FUN_{format(addr, 'x').lstrip('0')}"
            self._maybe_set_symbol(consumed, key, {
                "name": name,
                "source": "pdb",
                "confidence": 0.95,
                "address": addr,
                "extra": {
                    "kind": sym.get("kind"),
                    "section": sym.get("section"),
                    "size": sym.get("size"),
                    "type_index": sym.get("type_index"),
                },
            })

    def _merge_bn_functions(
        self,
        bn_functions: list[dict[str, Any]],
        consumed: dict[str, dict[str, Any]],
    ) -> None:
        for fn in bn_functions:
            if bool(fn.get("is_thunk", False)):
                continue
            if bool(fn.get("is_imported", False)):
                continue
            name = str(fn.get("name", "") or "").strip()
            if not name:
                continue
            lower = name.lower()
            if lower.startswith("sub_") or lower.startswith("fun_"):
                continue
            addr = self._coerce_addr(fn.get("address"))
            if addr is None or addr <= 0:
                continue
            key = f"FUN_{format(addr, 'x').lstrip('0')}"
            self._maybe_set_symbol(consumed, key, {
                "name": name,
                "source": "bn",
                "confidence": 0.85,
                "address": addr,
                "extra": {
                    "return_type": fn.get("return_type"),
                    "parameters": fn.get("parameters"),
                    "size": fn.get("size"),
                },
            })

    def _merge_trex_structs(
        self,
        trex_structs: list[dict[str, Any]],
        consumed: dict[str, dict[str, Any]],
    ) -> None:
        """TRex struct -> indirect symbol map.

        TRex direkt fonksiyon adi vermez; struct adi (`FooHandler`) verir.
        Bu birlesim consumed_symbols'a "indirekt" giris ekler -- BN/PDB
        zaten daha guvenilir bir sembol vermisse onlar kazanir.
        """
        for s in trex_structs:
            struct_name = str(s.get("name", "") or "").strip()
            if not struct_name:
                continue
            func_ref = s.get("function")
            if not func_ref:
                continue
            if isinstance(func_ref, str) and func_ref.startswith("FUN_"):
                key = func_ref
                addr = self._coerce_addr(func_ref[4:])
            else:
                addr = self._coerce_addr(func_ref)
                if addr is None or addr <= 0:
                    continue
                key = f"FUN_{format(addr, 'x').lstrip('0')}"
            self._maybe_set_symbol(consumed, key, {
                "name": _camel_to_snake(struct_name),
                "source": "trex",
                "confidence": 0.75,
                "address": addr or 0,
                "extra": {
                    "struct_name": struct_name,
                    "fields": s.get("fields"),
                },
            })

    def _merge_pdb_types(
        self,
        pdb_types: list[dict[str, Any]],
        consumed: dict[str, dict[str, Any]],
    ) -> None:
        for t in pdb_types:
            name = str(t.get("name", "") or "").strip()
            if not name:
                continue
            if name not in consumed:
                consumed[name] = {
                    "source": "pdb",
                    "kind": t.get("kind"),
                    "size": t.get("size"),
                    "fields": t.get("fields") or [],
                    "confidence": 0.95,
                    "type_id": t.get("type_id"),
                }

    def _merge_bn_types(
        self,
        bn_types: list[dict[str, Any]],
        consumed: dict[str, dict[str, Any]],
    ) -> None:
        for t in bn_types:
            name = str(t.get("name", "") or "").strip()
            if not name:
                continue
            # PDB onceligi: zaten varsa BN uzerine yazma
            if name in consumed and consumed[name].get("source") == "pdb":
                continue
            consumed[name] = {
                "source": "bn",
                "kind": t.get("kind"),
                "size": t.get("size"),
                "fields": t.get("fields") or [],
                "confidence": 0.85,
            }

    def _merge_trex_struct_types(
        self,
        trex_structs: list[dict[str, Any]],
        consumed: dict[str, dict[str, Any]],
    ) -> None:
        for s in trex_structs:
            name = str(s.get("name", "") or "").strip()
            if not name:
                continue
            # PDB/BN onceligi
            if name in consumed and consumed[name].get("source") in (
                "pdb", "bn",
            ):
                continue
            consumed[name] = {
                "source": "trex",
                "kind": "struct",
                "size": None,
                "fields": s.get("fields") or [],
                "confidence": 0.75,
                "function": s.get("function"),
            }

    @staticmethod
    def _coerce_addr(value: Any) -> int | None:
        """Adres degerini int'e cevir (hex string veya int kabul eder)."""
        if value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            s = value.strip().lower()
            if s.startswith("0x"):
                s = s[2:]
            if not s:
                return None
            try:
                return int(s, 16)
            except ValueError:
                try:
                    return int(s, 10)
                except ValueError:
                    return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


def _camel_to_snake(name: str) -> str:
    """``FooHandler`` -> ``foo_handler``; ``ARGB32`` -> ``argb32``."""
    if not name:
        return ""
    out: list[str] = []
    for i, ch in enumerate(name):
        if ch.isupper() and i > 0 and not name[i - 1].isupper():
            out.append("_")
        out.append(ch.lower())
    return "".join(out).strip("_")
