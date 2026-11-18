"""ComputationFusionStep -- imza + CFG-iso kanıtlarının adres başına füzyonu.

``ComputationConfig.enable_computation_fusion`` açıksa:

    imza eşleşmeleri (sig_matches)      --+
                                          +--> adres başına kanıt --> FusedName
    CFG-iso eşleşmeleri (cfg_iso_matches) -+   (ad başına tek aday)

TIP-02 + BORU-03 (P11): eskiden imza kanıtı ``original_name`` (ad), CFG kanıtı
adresle anahtarlanıyordu (kesişim 0), her aday ayrı puanlanıyordu ve tek
kanıtlı en iyi aday sabit ağırlıklarla 0,182 olasılık alıyordu (kabul 0,90);
CFG adayında ``cfg_hash`` = ``reference_cfg_hash`` = şablon adıydı (benzerlik
kendisiyle, hep 1,0). Şimdi:

- Anahtar fonksiyon ADRESİDİR (iki kaynak da). Yalnız Ghidra'nın adsız
  bıraktığı (``FUN_``) fonksiyonların imza kanıtı alınır; adı olanlar ad
  adayı değildir.
- Olasılık kaynağın ölçülmüş kesinliğidir (``karadul.computation.fusion.
  measured``); ölçülmemiş kaynakta olasılık yok, karar ``abstain``.
- Çıktı (K-1): ``fused_matches`` ({adres: [FusedName]}) ve aday dosyası
  ``reconstructed/computation_fusion_candidates.json``. Kabul edilen adlar ad
  kanalına (``fusion_name_candidates``) yalnız
  ``computation.enable_fusion_naming`` açıkken verilir (öntanım kapalı); o
  yapıtı okuyan ad adımı ayrı yamayla bağlanır.

Durum: ``ctx.stats["kol_fuzyon"]`` (``karadul.computation.kol_durumu``).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

CANDIDATES_FILE = "computation_fusion_candidates.json"
_GENERIC_PREFIXES = ("FUN_",)


def _norm_address(addr: Any) -> str:
    """``0x104000`` / ``00104000`` → ``00104000`` (Ghidra biçimi, en az 8 hane)."""
    text = str(addr or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    try:
        return format(int(text, 16), "08x")
    except ValueError:
        return ""


def collect_evidence(sig_matches: Any, cfg_matches: Any) -> dict[str, list[Any]]:
    """İki kaynağın kanıtını adres anahtarında topla.

    İmza: yalnız ``original_name`` jenerik (``FUN_``) ve adresi olan eşleşme;
    kaynak ``imza:<yöntem>``. CFG-iso: ``{adres: CFGMatch}``; kaynak
    ``cfg_iso:<şablon kaynağı>``.
    """
    from karadul.computation.fusion.measured import Evidence

    out: dict[str, list[Any]] = {}
    for sm in sig_matches or []:
        original = str(getattr(sm, "original_name", "") or "")
        name = str(getattr(sm, "matched_name", "") or "")
        address = _norm_address(getattr(sm, "address", ""))
        if not name or not address or not original.startswith(_GENERIC_PREFIXES):
            continue
        method = str(getattr(sm, "match_method", "") or "bilinmiyor")
        out.setdefault(address, []).append(Evidence(
            source=f"imza:{method}", name=name,
            raw_score=float(getattr(sm, "confidence", 0.0) or 0.0),
        ))
    for addr, cm in (cfg_matches or {}).items():
        address = _norm_address(addr)
        name = str(getattr(cm, "template_name", "") or "")
        if not address or not name:
            continue
        src = str(getattr(cm, "template_source", "") or "bilinmiyor")
        out.setdefault(address, []).append(Evidence(
            source=f"cfg_iso:{src}", name=name,
            raw_score=float(getattr(cm, "confidence", 0.0) or 0.0),
        ))
    return out


def _write_candidates(ctx: StepContext, fused: dict[str, list[Any]], bagli: bool) -> None:
    pc = ctx.pipeline_context
    try:
        target_dir = Path(pc.workspace.get_stage_dir("reconstructed"))
    except Exception:
        return
    if not target_dir.is_dir():
        return
    from karadul.computation.fusion.measured import load_measured_precision_document
    kayit = {
        "ad_kanalina_bagli": bagli,
        "olcum": load_measured_precision_document().get("_kaynak", {}),
        "adaylar": [
            {"adres": f.address, "ad": f.name, "kaynaklar": f.sources,
             "olasilik": f.probability, "karar": f.decision, "neden": f.reason}
            for flist in fused.values() for f in flist
        ],
    }
    (target_dir / CANDIDATES_FILE).write_text(
        json.dumps(kayit, ensure_ascii=False, indent=1), encoding="utf-8")


@register_step(
    name="computation_fusion",
    requires=["sig_matches", "cfg_iso_matches"],
    produces=["fused_matches", "fusion_name_candidates", "timing_computation_fusion"],
)
class ComputationFusionStep(Step):
    """Adres başına kanıt füzyonu -- ölçülmüş kesinlikle."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        from karadul.computation.kol_durumu import (
            AD_ADAYI, BAGLI_DEGIL, CALISTI, HATA, KAPALI, STAT_FUZYON, kol_durumu,
        )

        pc = ctx.pipeline_context
        cfg_computation = getattr(pc.config, "computation", None)
        step_start = time.monotonic()
        naming_on = bool(getattr(cfg_computation, "enable_fusion_naming", False))
        cikti = AD_ADAYI if naming_on else BAGLI_DEGIL

        def _bitir(durum: str, neden: str, fused: dict, names: list, **sayac: Any):
            ctx.stats[STAT_FUZYON] = kol_durumu(durum, neden, cikti, **sayac)
            timing = round(time.monotonic() - step_start, 3)
            if durum == CALISTI:
                ctx.stats["timing_computation_fusion"] = timing
            return {"fused_matches": fused, "fusion_name_candidates": names,
                    "timing_computation_fusion": timing}

        if cfg_computation is None or not getattr(
            cfg_computation, "enable_computation_fusion", False,
        ):
            return _bitir(KAPALI, "bayrak kapalı (computation.enable_computation_fusion)", {}, [])

        try:
            from karadul.computation.fusion import measured as fm

            evidence = collect_evidence(
                ctx.artifacts.get("sig_matches") or [],
                ctx.artifacts.get("cfg_iso_matches") or {},
            )
            table = fm.load_measured_precision()
            fused = fm.fuse_by_address(
                evidence, table,
                accept_threshold=float(cfg_computation.fusion_accept_threshold),
                reject_threshold=float(cfg_computation.fusion_reject_threshold),
            )
            kararlar = [f.decision for fl in fused.values() for f in fl]
            accepted = [f for fl in fused.values() for f in fl if f.decision == fm.ACCEPT]
            names = [
                {"address": f.address, "name": f.name, "probability": f.probability,
                 "sources": f.sources}
                for f in accepted
            ] if naming_on else []
            _write_candidates(ctx, fused, naming_on)
            kaynaklar: dict[str, int] = {}
            for evs in evidence.values():
                for e in evs:
                    kaynaklar[e.source] = kaynaklar.get(e.source, 0) + 1
            iki_kaynak = sum(
                1 for evs in evidence.values()
                if len({e.source.split(":", 1)[0] for e in evs}) > 1
            )
            ctx.stats["computation_fusion_matches"] = len(fused)
            ctx.stats["computation_fusion_accepted"] = len(accepted)
            return _bitir(
                CALISTI, "", fused, names,
                adres=len(evidence), kanit=kaynaklar, iki_kaynakli_adres=iki_kaynak,
                kabul=kararlar.count(fm.ACCEPT), red=kararlar.count(fm.REJECT),
                cekimser=kararlar.count(fm.ABSTAIN),
                olculmemis_kaynak=sorted({s for s in kaynaklar if s not in table}),
            )
        except Exception as exc:
            logger.warning("computation_fusion hatasi (atlaniyor): %s", exc)
            ctx.errors.append(f"computation_fusion: {exc}")
            return _bitir(HATA, f"{type(exc).__name__}: {exc}", {}, [])
