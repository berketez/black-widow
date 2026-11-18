"""TypeRecoveryConsumerStep — PDB / Binary Ninja / TRex üreticilerinin çıktı sayımı.

P13b / BORU-14 (b): adım eskiden yalnız ``binary_for_byte_match``'i ``requires`` ediyordu;
koşucu onu üreticileriyle (``pdb_symbol_recovery``, ``binaryninja_analysis``,
``trex_struct_recovery``) AYNI paralel düzeye koyuyordu ve öntanımlı paralel kipte düzey
bitmeden yapıtlar yazılmadığı için üreticilerin çıktısını hiç göremiyordu (``no-data``
119 / 119). Sıralı kipte görüyordu: sonuç kipe bağlıydı. Şimdi üreticilerin bütün yapıtlarını
``requires`` eder (onlar her dönüş yolunda yapıtlarını — boş liste ve durum — üretir), yani her
kipte onlardan SONRA koşar.

Eskiden ürettiği ``consumed_symbols`` / ``consumed_types`` yapıtlarını depoda okuyan yoktu
(belgedeki "birleştirici ve c_type_recoverer okur" cümlesi yanlıştı). Üretimleri kaldırıldı:
- adlar: üreticilerin listeleri ad birleştiricisine (``_feedback_naming_merger.run_name_merger``
  → ``collect_candidates``) doğrudan, her kaynak ayrı kanıt olarak gider (öncelik seçimi değil,
  birleştiricinin kendi füzyonu; aynı kanıtı iki yoldan saymamak için tek yol);
- tipler: PDB / BN tiplerini koda uygulayan bir tüketici yok (yazmak yeni özellik olur; ölçülmedi).

Adım artık yalnız hangi üreticinin ne getirdiğini dürüstçe sayar
(``stats["type_recovery_inputs"]``) ve ``type_recovery_status`` üretir.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

# Üreticilerin her dönüş yolunda ürettiği yapıtlar (P13b / BORU-14 b): tüketici bunları
# ``requires`` eder ki koşucu onu üreticilerden SONRAKİ düzeye koysun.
PRODUCER_ARTIFACTS: tuple[str, ...] = (
    "pdb_symbols", "pdb_types", "pdb_status",
    "bn_functions", "bn_types", "bn_status",
    "trex_structs", "trex_status",
)


@register_step(
    name="type_recovery_consumer",
    requires=["binary_for_byte_match", *PRODUCER_ARTIFACTS],
    produces=[
        "type_recovery_status",   # str: "active" (en az bir üretici veri getirdi) / "no-data"
    ],
    parallelizable_with=[
        "anti_debug",
        "packer_fingerprint",
    ],
)
class TypeRecoveryConsumerStep(Step):
    """PDB / BN / TRex üreticilerinin getirdiğini say (adlar birleştiricide aday olur)."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        step_start = time.monotonic()
        a = ctx.artifacts
        inputs = {
            "pdb": {
                "status": _status(a.get("pdb_status")),
                "symbols": len(_as_list(a.get("pdb_symbols"))),
                "types": len(_as_list(a.get("pdb_types"))),
            },
            "bn": {
                "status": _status(a.get("bn_status")),
                "functions": len(_as_list(a.get("bn_functions"))),
                "types": len(_as_list(a.get("bn_types"))),
            },
            "trex": {
                "status": _status(a.get("trex_status")),
                "structs": len(_as_list(a.get("trex_structs"))),
            },
        }
        total = sum(v for src in inputs.values() for k, v in src.items() if k != "status")
        status = "active" if total else "no-data"
        ctx.stats["type_recovery_inputs"] = inputs
        ctx.stats["type_recovery_consumer_status"] = status
        ctx.stats["timing_type_recovery_consumer"] = round(time.monotonic() - step_start, 3)
        if total:
            logger.info(
                "type_recovery_consumer: PDB %d sembol / %d tip, BN %d fonksiyon / %d tip, "
                "TRex %d yapı (adlar birleştiricide aday olur)",
                inputs["pdb"]["symbols"], inputs["pdb"]["types"],
                inputs["bn"]["functions"], inputs["bn"]["types"], inputs["trex"]["structs"],
            )
        return {"type_recovery_status": status}


def _as_list(value: Any) -> list[dict[str, Any]]:
    """Yapıt değerini list[dict]'e indir (savunmacı)."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _status(value: Any) -> str | None:
    return value if isinstance(value, str) else None
