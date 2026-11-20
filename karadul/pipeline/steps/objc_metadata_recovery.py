"""ObjcMetadataRecoveryStep — Objective-C yöntem listesi üretici adımı (P-ÜV2; ÜST VERİ hattı).

Ürünün ``binary_for_byte_match`` yapıtındaki ince dosyayı P-ÜV0 görüntüsüyle açar, ObjC sınıf / kategori
yöntem listelerinden uygulama adresi → tam ad (``-[Sınıf seçici]`` / ``+[Sınıf seçici]``) ve seçiciyi
(ayrı alan; A-28: P-ÜV6 seçiciyi Ghidra adıyla karşılaştırır) okur ve ``static/objc_methods.json``'a yazar.

Akış:
    1. Bayrak: ``binary_reconstruction.enable_objc_metadata_recovery`` tam olarak ``True`` değilse adım iş
       yapmaz; durum ``kapali``, dosya yazılmaz.
    2. Görüntü: ``binary_for_byte_match`` (yoksa hedef yolu) ``goruntu.ac`` ile açılır. Açılamazsa
       görüntünün bildirdiği durum (``desteklenmiyor`` / ``hata``) + neden.
    3. Okuma: ``objc.oku``; istisna atmaz. Durum ``calisti`` / ``veri_yok`` (ObjC yok) / ``desteklenmiyor`` /
       ``tutarsiz`` (yapı ihlali: ad listesi üretilmez, yalnız kanıt) / ``hata``.
    4. Çıktı: ``static/objc_methods.json`` (durum, neden, özet sayılar, sınıflar, yöntemler).

Adım ad yazmaz; adların ad kanalına bağlanması, etiket ve güven kuralı P-ÜV6'dadır (``enable_objc_metadata_naming``).
Adım Faz 1 adım listesine bu pakette eklenmez (P-ÜV6 ekler).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Optional

from karadul.analyzers.ustveri import objc
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

OBJC_RECOVERY_FLAG = "enable_objc_metadata_recovery"
OBJC_OUTPUT_STAGE = "static"
OBJC_OUTPUT_NAME = "objc_methods"
OBJC_SCHEMA = "karadul.objc_methods.v1"

ART_METHODS = "objc_methods"
ART_CLASSES = "objc_classes"
ART_STATUS = "objc_status"
ART_METHODS_PATH = "objc_methods_path"

STAT_STATUS = "objc_status"
STAT_DETAIL = "objc_detail"
STAT_METHODS = "objc_method_count"
STAT_TIMING = "timing_objc_metadata_recovery"


def objc_recovery_enabled(config: Any) -> bool:
    """Adım bayrağı açık mı (yalnız ``True``; doğruluk değeri yetmez)."""
    recon = getattr(config, "binary_reconstruction", None)
    return getattr(recon, "enable_objc_metadata_recovery", False) is True


def _goruntu_ac(yol: Path) -> Any:
    """P-ÜV0 görüntüsü (testler bu işlevi sahte görüntüyle değiştirir)."""
    from karadul.analyzers.ustveri import goruntu

    return goruntu.ac(yol)


def _durum(durum: str, neden: Optional[str]) -> dict[str, Any]:
    return {"durum": durum, "neden": neden}


@register_step(
    name="objc_metadata_recovery",
    requires=[
        "binary_for_byte_match",
    ],
    produces=[
        ART_METHODS,        # list[dict] — yöntem kayıtları (tam ad + seçici ayrı alan)
        ART_CLASSES,        # list[dict] — sınıflar
        ART_STATUS,         # dict — {"durum", "neden", ...özet}
        ART_METHODS_PATH,   # Path | None — static/objc_methods.json
    ],
    parallelizable_with=[],
)
class ObjcMetadataRecoveryStep(Step):
    """ObjC üst verisinden yöntem adlarını okur; ad yazmaz."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        baslangic = time.monotonic()

        if not objc_recovery_enabled(getattr(pc, "config", None)):
            ctx.stats[STAT_STATUS] = objc.DURUM_KAPALI
            return self._bos(objc.DURUM_KAPALI, "bayrak kapalı")

        yol = self._ikili_yolu(ctx)
        if yol is None:
            sonuc = objc.ObjcSonuc(objc.DURUM_HATA, "ikili yolu çözülemedi (binary_for_byte_match yok)")
        else:
            sonuc = self._oku(yol)

        if sonuc.durum == objc.DURUM_HATA:
            ctx.errors.append(f"objc_metadata_recovery: {sonuc.neden}")
        yontemler = [] if sonuc.durum == objc.DURUM_TUTARSIZ else [y.as_dict() for y in sonuc.yontemler]
        siniflar = [s.as_dict() for s in sonuc.siniflar]
        durum = {**_durum(sonuc.durum, sonuc.neden), "ozet": sonuc.ozet()}

        yol_json = self._yaz(ctx, yol, durum, siniflar, yontemler)

        ctx.stats[STAT_STATUS] = sonuc.durum
        if sonuc.neden:
            ctx.stats[STAT_DETAIL] = sonuc.neden
        ctx.stats[STAT_METHODS] = len(yontemler)
        ctx.stats[STAT_TIMING] = round(time.monotonic() - baslangic, 3)
        logger.info("ObjC üst verisi: durum %s, %d yöntem kaydı", sonuc.durum, len(yontemler))
        return {
            ART_METHODS: yontemler,
            ART_CLASSES: siniflar,
            ART_STATUS: durum,
            ART_METHODS_PATH: yol_json,
        }

    # --- iç işler -----------------------------------------------------------------------
    @staticmethod
    def _bos(durum: str, neden: str) -> dict[str, Any]:
        return {ART_METHODS: [], ART_CLASSES: [], ART_STATUS: _durum(durum, neden), ART_METHODS_PATH: None}

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
    def _oku(yol: Path) -> objc.ObjcSonuc:
        try:
            g = _goruntu_ac(yol)
        except Exception as exc:
            # GoruntuHatasi kendi durumunu taşır (biçim tanınmadı → desteklenmiyor); öbürleri hata
            durum = getattr(exc, "durum", objc.DURUM_HATA)
            neden = getattr(exc, "neden", None) or f"{type(exc).__name__}: {exc}"
            if durum not in (objc.DURUM_DESTEKLENMIYOR, objc.DURUM_VERI_YOK, objc.DURUM_HATA):
                durum = objc.DURUM_HATA
            return objc.ObjcSonuc(durum, f"görüntü açılamadı: {neden}")
        return objc.oku(g)

    @staticmethod
    def _yaz(ctx: StepContext, yol: Optional[Path], durum: dict[str, Any],
             siniflar: list[dict[str, Any]], yontemler: list[dict[str, Any]]) -> Optional[Path]:
        try:
            p = ctx.pipeline_context.workspace.save_json(OBJC_OUTPUT_STAGE, OBJC_OUTPUT_NAME, {
                "schema": OBJC_SCHEMA, "ikili": str(yol) if yol else None, **durum,
                "siniflar": siniflar, "yontemler": yontemler,
            })
            ctx.produce_artifact(ART_METHODS_PATH, p)
            return p
        except Exception as exc:
            logger.warning("objc_methods.json yazılamadı: %s", exc)
            ctx.errors.append(f"objc_metadata_recovery: objc_methods.json yazılamadı: {exc}")
            return None
