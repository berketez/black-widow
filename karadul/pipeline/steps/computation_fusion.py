"""ComputationFusionStep -- log-odds signature fusion step'i.

v1.10.0 M4 entegrasyonu: ``karadul.computation.fusion`` paketini pipeline'a
bagliyor. Feature flag ``ComputationConfig.enable_computation_fusion`` True
ise:

    byte signature matches (sig_matches)         --+
    CFG isomorphism matches (cfg_iso_matches)    --+--> SignatureFuser --> FusedMatch
                                                  |                         (per function)
    (gelecek: proto/context sinyalleri)          --+

Cikti:
    fused_matches: dict[str, list[FusedMatch]]  -- fn key -> aday listesi.

fn key olarak tercihen fonksiyon adresi kullanilir (CFG iso'dan gelen);
sig_matches liste halinde `original_name` uzerinden key'lenir. Her iki
kaynaktan da gelen fonksiyon varsa her iki candidate fuse edilir.

Eski Dempster-Shafer fusion (`ComputationRecoveryConfig.enable_signature_fusion`)
DEPRECATED; double-counting riski nedeniyle. Bu step o yola dokunmaz,
ayri bir evidence hatti saglar.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)


def _sig_match_to_candidate(sm: Any) -> Any:
    """SignatureMatch -> SignatureCandidate (byte kanitli)."""
    from karadul.computation.fusion import SignatureCandidate

    return SignatureCandidate(
        symbol_name=getattr(sm, "matched_name", "") or getattr(sm, "original_name", ""),
        byte_score=float(getattr(sm, "confidence", 0.0) or 0.0),
        cfg_hash="",
        func_size=0,
        compiler_bucket="unknown",
    )


def _cfg_match_to_candidate(cm: Any, fn_addr: str) -> Any:
    """CFGMatch -> SignatureCandidate (CFG hash + shape kanitli)."""
    from karadul.computation.fusion import SignatureCandidate

    return SignatureCandidate(
        symbol_name=getattr(cm, "template_name", "") or f"cfg_{fn_addr}",
        byte_score=0.0,
        cfg_hash=getattr(cm, "template_name", ""),  # template adi hash yerine (pratik).
        func_size=0,
        compiler_bucket="unknown",
        # Reference CFG hash'i set ederek shape feature aktif olur
        reference_cfg_hash=getattr(cm, "template_name", ""),
        # CFG confidence'i decompiler_conf'a bindir (proto ailesi) —
        # log-odds ensemble'da ek kanıt.
        decompiler_conf=float(getattr(cm, "confidence", 0.0) or 0.0),
    )


@register_step(
    name="computation_fusion",
    requires=["sig_matches", "cfg_iso_matches"],
    produces=["fused_matches", "timing_computation_fusion"],
)
class ComputationFusionStep(Step):
    """Log-odds ensemble fusion -- byte + CFG sinyallerini birlestir."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        cfg_computation = getattr(pc.config, "computation", None)

        step_start = time.monotonic()
        empty_result = {
            "fused_matches": {},
            "timing_computation_fusion": 0.0,
        }

        if cfg_computation is None or not getattr(
            cfg_computation, "enable_computation_fusion", False,
        ):
            empty_result["timing_computation_fusion"] = round(
                time.monotonic() - step_start, 3,
            )
            return empty_result

        sig_matches = ctx.artifacts.get("sig_matches") or []
        cfg_matches = ctx.artifacts.get("cfg_iso_matches") or {}
        if not sig_matches and not cfg_matches:
            empty_result["timing_computation_fusion"] = round(
                time.monotonic() - step_start, 3,
            )
            return empty_result

        try:
            from karadul.computation.fusion import SignatureFuser

            fuser = SignatureFuser.from_computation_config(cfg_computation)

            # SignatureMatch listesini original_name -> match dict'ine cevir.
            # Eger ayni key icin birden fazla match varsa en yuksek
            # confidence'liyi tut.
            sig_by_key: dict[str, Any] = {}
            for sm in sig_matches:
                key = getattr(sm, "original_name", None)
                if not key:
                    continue
                prev = sig_by_key.get(key)
                if prev is None or getattr(sm, "confidence", 0.0) > getattr(
                    prev, "confidence", 0.0,
                ):
                    sig_by_key[key] = sm

            fused_by_key: dict[str, list] = {}
            # Tum key'ler (sig dokum + cfg'den).
            all_keys = set(sig_by_key.keys()) | set(cfg_matches.keys())
            for key in all_keys:
                candidates = []
                if key in sig_by_key:
                    candidates.append(_sig_match_to_candidate(sig_by_key[key]))
                if key in cfg_matches:
                    candidates.append(
                        _cfg_match_to_candidate(cfg_matches[key], key),
                    )
                if not candidates:
                    continue
                fused = fuser.fuse(candidates)
                if fused:
                    fused_by_key[key] = fused

            # Stats
            n_accepted = sum(
                1 for flist in fused_by_key.values()
                for fm in flist if getattr(fm, "decision", "") == "accept"
            )
            ctx.stats["computation_fusion_matches"] = len(fused_by_key)
            ctx.stats["computation_fusion_accepted"] = n_accepted
            logger.info(
                "Computation fusion: %d fonksiyon fuse edildi, %d accept",
                len(fused_by_key), n_accepted,
            )

            timing = round(time.monotonic() - step_start, 3)
            ctx.stats["timing_computation_fusion"] = timing
            return {
                "fused_matches": fused_by_key,
                "timing_computation_fusion": timing,
            }
        except ImportError as exc:
            logger.debug(
                "computation_fusion import hatasi: %s", exc,
            )
        except Exception as exc:
            logger.warning(
                "computation_fusion hatasi (atlaniyor): %s", exc,
            )
            ctx.errors.append(f"computation_fusion: {exc}")

        empty_result["timing_computation_fusion"] = round(
            time.monotonic() - step_start, 3,
        )
        return empty_result
