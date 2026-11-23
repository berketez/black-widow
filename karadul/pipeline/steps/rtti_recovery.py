"""RttiRecoveryStep — C++ (Itanium) RTTI / vtable üretici adımı (P-ÜV4; ÜST VERİ hattı; IMZA-16).

Ürünün ``binary_for_byte_match`` yapıtındaki ince dosyayı P-ÜV0 görüntüsüyle açar, sembol tablosuna bakmadan
typeinfo nesnelerini, vtable'ları ve yuva işlevlerini tarar (``karadul.analyzers.ustveri.cpp_rtti_tara``) ve
``static/rtti_classes.json``'a yazar.

Akış:
    1. Bayrak: ``binary_reconstruction.enable_rtti_recovery`` tam olarak ``True`` değilse adım iş yapmaz; durum
       ``kapali``, dosya yazılmaz.
    2. Görüntü: ``binary_for_byte_match`` (yoksa hedef yolu) ``goruntu.ac`` ile açılır. Açılamazsa görüntünün
       bildirdiği durum (``desteklenmiyor`` / ``veri_yok`` / ``hata``) + neden.
    3. Tarama: ``cpp_rtti_tara.tara`` (yuva üst sınırı ``binary_reconstruction.rtti_max_vtable_entries``); istisna
       atmaz. Durum ``calisti`` / ``veri_yok`` (Itanium typeinfo yok) / ``desteklenmiyor`` / ``hata``.
    4. Çıktı: ``rtti_classes`` (``_feedback_naming_candidates._add_rtti``'nin beklediği biçim), ``rtti_status``
       (``(durum, neden)`` demeti), ``static/rtti_classes.json`` (sınıflar, vtable'lar, işlev → sınıf bağları).

Adım ad yazmaz. Yuva adayı (``Sınıf_vfunc_N``) ad değildir, kanıt satırıdır (A-32); ad kanalına bağlama,
etiket ve güven kuralı P-ÜV6b'dedir (``enable_rtti_naming``). Adım Faz 1 adım listesine ve
``steps/__init__.py``'ye bu pakette eklenmez (P-ÜV6b ekler).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Optional

from karadul.analyzers.ustveri import cpp_rtti_tara as rtti
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

RTTI_RECOVERY_FLAG = "enable_rtti_recovery"
RTTI_LIMIT_FIELD = "rtti_max_vtable_entries"
RTTI_OUTPUT_STAGE = "static"
RTTI_OUTPUT_NAME = "rtti_classes"
RTTI_SCHEMA = "karadul.rtti_classes.v1"

RTTI_ART_CLASSES = "rtti_classes"
RTTI_ART_STATUS = "rtti_status"
RTTI_ART_CLASSES_PATH = "rtti_classes_path"

RTTI_STAT_STATUS = "rtti_status"
RTTI_STAT_DETAIL = "rtti_detail"
RTTI_STAT_CLASSES = "rtti_class_count"
RTTI_STAT_VTABLES = "rtti_vtable_count"
RTTI_STAT_TIMING = "timing_rtti_recovery"


def rtti_recovery_enabled(config: Any) -> bool:
    """Adım bayrağı açık mı (yalnız ``True``; doğruluk değeri yetmez)."""
    recon = getattr(config, "binary_reconstruction", None)
    return getattr(recon, "enable_rtti_recovery", False) is True


def rtti_slot_limit(config: Any) -> int:
    """Yuva üst sınırı (``rtti_max_vtable_entries``); geçersizse ``config.py`` öntanımı."""
    recon = getattr(config, "binary_reconstruction", None)
    deger = getattr(recon, "rtti_max_vtable_entries", rtti.YUVA_AZAMI_ONTANIM)
    if isinstance(deger, bool) or not isinstance(deger, int) or deger <= 0:
        return rtti.YUVA_AZAMI_ONTANIM
    return deger


def _goruntu_ac(yol: Path) -> Any:
    """P-ÜV0 görüntüsü (testler bu işlevi sahte görüntüyle değiştirir)."""
    from karadul.analyzers.ustveri import goruntu

    return goruntu.ac(yol)


@register_step(
    name="rtti_recovery",
    requires=[
        "binary_for_byte_match",
    ],
    produces=[
        RTTI_ART_CLASSES,        # list[dict] — {"name", "mangled", "methods", "bases", "vtable", "typeinfo"}
        RTTI_ART_STATUS,         # tuple[str, str|None] — (durum, neden)
        RTTI_ART_CLASSES_PATH,   # Path | None — static/rtti_classes.json
    ],
    parallelizable_with=[],
)
class RttiRecoveryStep(Step):
    """C++ RTTI / vtable üst verisini tarar; ad yazmaz."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        baslangic = time.monotonic()
        config = getattr(pc, "config", None)

        if not rtti_recovery_enabled(config):
            ctx.stats[RTTI_STAT_STATUS] = rtti.DURUM_KAPALI
            return {RTTI_ART_CLASSES: [], RTTI_ART_STATUS: (rtti.DURUM_KAPALI, "bayrak kapalı"),
                    RTTI_ART_CLASSES_PATH: None}

        yol = self._ikili_yolu(ctx)
        if yol is None:
            sonuc = rtti.RttiSonuc(rtti.DURUM_HATA, "ikili yolu çözülemedi (binary_for_byte_match yok)")
        else:
            sonuc = self._tara(yol, rtti_slot_limit(config))

        if sonuc.durum == rtti.DURUM_HATA:
            ctx.errors.append(f"rtti_recovery: {sonuc.neden}")
        siniflar = sonuc.rtti_classes()
        durum = (sonuc.durum, sonuc.neden)
        yol_json = self._yaz(ctx, yol, sonuc, siniflar)

        ctx.stats[RTTI_STAT_STATUS] = sonuc.durum
        if sonuc.neden:
            ctx.stats[RTTI_STAT_DETAIL] = sonuc.neden
        ctx.stats[RTTI_STAT_CLASSES] = len(siniflar)
        ctx.stats[RTTI_STAT_VTABLES] = len(sonuc.vtablelar)
        ctx.stats[RTTI_STAT_TIMING] = round(time.monotonic() - baslangic, 3)
        logger.info("C++ RTTI: durum %s, %d sınıf, %d vtable", sonuc.durum, len(siniflar), len(sonuc.vtablelar))
        return {RTTI_ART_CLASSES: siniflar, RTTI_ART_STATUS: durum, RTTI_ART_CLASSES_PATH: yol_json}

    # --- iç işler -----------------------------------------------------------------------
    @staticmethod
    def _ikili_yolu(ctx: StepContext) -> Optional[Path]:
        bpm = ctx.artifacts.get("binary_for_byte_match")
        if isinstance(bpm, (str, Path)) and str(bpm):
            return Path(bpm)
        hedef = getattr(getattr(ctx.pipeline_context, "target", None), "path", None)
        if isinstance(hedef, (str, Path)) and str(hedef):
            return Path(hedef)
        return None

    @staticmethod
    def _tara(yol: Path, azami_yuva: int) -> rtti.RttiSonuc:
        try:
            g = _goruntu_ac(yol)
        except Exception as exc:
            # GoruntuHatasi kendi durumunu taşır (biçim tanınmadı → desteklenmiyor); öbürleri hata
            durum = getattr(exc, "durum", rtti.DURUM_HATA)
            neden = getattr(exc, "neden", None) or f"{type(exc).__name__}: {exc}"
            if durum not in (rtti.DURUM_DESTEKLENMIYOR, rtti.DURUM_VERI_YOK, rtti.DURUM_HATA):
                durum = rtti.DURUM_HATA
            return rtti.RttiSonuc(durum, f"görüntü açılamadı: {neden}")
        return rtti.tara(g, azami_yuva=azami_yuva)

    @staticmethod
    def _yaz(ctx: StepContext, yol: Optional[Path], sonuc: rtti.RttiSonuc,
             siniflar: list[dict[str, Any]]) -> Optional[Path]:
        ti = sonuc.ti_sozlugu()
        try:
            p = ctx.pipeline_context.workspace.save_json(RTTI_OUTPUT_STAGE, RTTI_OUTPUT_NAME, {
                "schema": RTTI_SCHEMA, "ikili": str(yol) if yol else None,
                "durum": sonuc.durum, "neden": sonuc.neden, "ozet": sonuc.ozet(),
                "siniflar": siniflar,
                "typeinfolar": [t.as_dict() for t in sonuc.typeinfolar],
                "vtablelar": [v.as_dict() for v in sonuc.vtablelar],
                "islevler": [i.as_dict(ti) for i in sonuc.islevler],
            })
            ctx.produce_artifact(RTTI_ART_CLASSES_PATH, p)
            return p
        except Exception as exc:
            logger.warning("rtti_classes.json yazılamadı: %s", exc)
            ctx.errors.append(f"rtti_recovery: rtti_classes.json yazılamadı: {exc}")
            return None
