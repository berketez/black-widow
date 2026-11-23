"""SwiftMetadataRecoveryStep — Swift tip üst verisi üretici adımı (P-ÜV3; ÜST VERİ hattı).

Ürünün ``binary_for_byte_match`` yapıtındaki ince dosyayı P-ÜV0 görüntüsüyle açar; Swift tip betimleyicilerinden
tip adları ve tip başına erişim fonksiyonunu (``type metadata accessor for <Tip>``), vtable / geçersiz kılma /
tanık tablosu yuvalarını okur ve ``static/swift_metadata.json``'a yazar.

Akış:
    1. Bayrak: ``binary_reconstruction.enable_swift_metadata_recovery`` tam olarak ``True`` değilse adım iş
       yapmaz; durum ``kapali``, dosya yazılmaz.
    2. Görüntü: ``binary_for_byte_match`` (yoksa hedef yolu) ``goruntu.ac`` ile açılır. Açılamazsa görüntünün
       bildirdiği durum (``desteklenmiyor`` / ``veri_yok`` / ``hata``) + neden.
    3. Okuma: ``swift.oku``; istisna atmaz. Durum ``calisti`` / ``veri_yok`` (Swift yok) / ``desteklenmiyor`` /
       ``tutarsiz`` (yapı ihlali: ad listesi üretilmez, yalnız kanıt) / ``hata``.
    4. Çıktı: ``swift_types`` (ad verilebilen erişim fonksiyonları; ad kanalının girdisi) ve ``swift_slots``
       (vtable / geçersiz kılma / tanık yuvaları: tip + tür + sıra + adres). **``swift_slots`` ad adayı değildir**:
       kayıtlarında ad alanı yoktur; rapor ve KaradulLM için kanıt satırıdır.

Adım ad yazmaz; adların ad kanalına bağlanması, etiket ve güven kuralı P-ÜV6'dadır (``enable_swift_metadata_naming``).
Adım Faz 1 adım listesine bu pakette eklenmez (P-ÜV6 ekler).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Optional

from karadul.analyzers.ustveri import swift
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

SWIFT_RECOVERY_FLAG = "enable_swift_metadata_recovery"
SWIFT_OUTPUT_STAGE = "static"
SWIFT_OUTPUT_NAME = "swift_metadata"
SWIFT_SCHEMA = "karadul.swift_metadata.v1"

ART_TYPES = "swift_types"
ART_SLOTS = "swift_slots"
ART_STATUS = "swift_status"
ART_TYPES_PATH = "swift_types_path"

STAT_STATUS = "swift_status"
STAT_DETAIL = "swift_detail"
STAT_TYPES = "swift_type_count"
STAT_SLOTS = "swift_slot_count"
STAT_TIMING = "timing_swift_metadata_recovery"


def swift_recovery_enabled(config: Any) -> bool:
    """Adım bayrağı açık mı (yalnız ``True``; doğruluk değeri yetmez)."""
    recon = getattr(config, "binary_reconstruction", None)
    return getattr(recon, "enable_swift_metadata_recovery", False) is True


def _goruntu_ac(yol: Path) -> Any:
    """P-ÜV0 görüntüsü (testler bu işlevi sahte görüntüyle değiştirir)."""
    from karadul.analyzers.ustveri import goruntu

    return goruntu.ac(yol)


def _durum(durum: str, neden: Optional[str]) -> dict[str, Any]:
    return {"durum": durum, "neden": neden}


@register_step(
    name="swift_metadata_recovery",
    requires=[
        "binary_for_byte_match",
    ],
    produces=[
        ART_TYPES,       # list[dict] — erişim fonksiyonları (ad verilebilir: "type metadata accessor for <Tip>")
        ART_SLOTS,       # list[dict] — vtable / geçersiz kılma / tanık yuvaları (kanıt; ad adayı DEĞİL)
        ART_STATUS,      # dict — {"durum", "neden", "ozet"}
        ART_TYPES_PATH,  # Path | None — static/swift_metadata.json
    ],
    parallelizable_with=[],
)
class SwiftMetadataRecoveryStep(Step):
    """Swift üst verisinden tip adlarını ve yuvaları okur; ad yazmaz."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        baslangic = time.monotonic()

        if not swift_recovery_enabled(getattr(pc, "config", None)):
            ctx.stats[STAT_STATUS] = swift.DURUM_KAPALI
            return self._bos(swift.DURUM_KAPALI, "bayrak kapalı")

        yol = self._ikili_yolu(ctx)
        if yol is None:
            sonuc = swift.SwiftSonuc(swift.DURUM_HATA, "ikili yolu çözülemedi (binary_for_byte_match yok)")
        else:
            sonuc = self._oku(yol)

        if sonuc.durum == swift.DURUM_HATA:
            ctx.errors.append(f"swift_metadata_recovery: {sonuc.neden}")
        if sonuc.durum == swift.DURUM_TUTARSIZ:
            tipler: list[dict[str, Any]] = []
            yuvalar: list[dict[str, Any]] = []
        else:
            tipler = sonuc.swift_types()
            yuvalar = sonuc.swift_slots()
        durum = {**_durum(sonuc.durum, sonuc.neden), "ozet": sonuc.ozet()}

        yol_json = self._yaz(ctx, yol, durum, tipler, yuvalar)

        ctx.stats[STAT_STATUS] = sonuc.durum
        if sonuc.neden:
            ctx.stats[STAT_DETAIL] = sonuc.neden
        ctx.stats[STAT_TYPES] = len(tipler)
        ctx.stats[STAT_SLOTS] = len(yuvalar)
        ctx.stats[STAT_TIMING] = round(time.monotonic() - baslangic, 3)
        logger.info("Swift üst verisi: durum %s, %d tip, %d yuva", sonuc.durum, len(tipler), len(yuvalar))
        return {
            ART_TYPES: tipler,
            ART_SLOTS: yuvalar,
            ART_STATUS: durum,
            ART_TYPES_PATH: yol_json,
        }

    # --- iç işler -----------------------------------------------------------------------
    @staticmethod
    def _bos(durum: str, neden: str) -> dict[str, Any]:
        return {ART_TYPES: [], ART_SLOTS: [], ART_STATUS: _durum(durum, neden), ART_TYPES_PATH: None}

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
    def _oku(yol: Path) -> swift.SwiftSonuc:
        try:
            g = _goruntu_ac(yol)
        except Exception as exc:
            # GoruntuHatasi kendi durumunu taşır (biçim tanınmadı → desteklenmiyor); öbürleri hata
            durum = getattr(exc, "durum", swift.DURUM_HATA)
            neden = getattr(exc, "neden", None) or f"{type(exc).__name__}: {exc}"
            if durum not in (swift.DURUM_DESTEKLENMIYOR, swift.DURUM_VERI_YOK, swift.DURUM_HATA):
                durum = swift.DURUM_HATA
            return swift.SwiftSonuc(durum, f"görüntü açılamadı: {neden}")
        return swift.oku(g)

    @staticmethod
    def _yaz(ctx: StepContext, yol: Optional[Path], durum: dict[str, Any],
             tipler: list[dict[str, Any]], yuvalar: list[dict[str, Any]]) -> Optional[Path]:
        try:
            p = ctx.pipeline_context.workspace.save_json(SWIFT_OUTPUT_STAGE, SWIFT_OUTPUT_NAME, {
                "schema": SWIFT_SCHEMA, "ikili": str(yol) if yol else None, **durum,
                "swift_types": tipler, "swift_slots": yuvalar,
            })
            ctx.produce_artifact(ART_TYPES_PATH, p)
            return p
        except Exception as exc:
            logger.warning("swift_metadata.json yazılamadı: %s", exc)
            ctx.errors.append(f"swift_metadata_recovery: swift_metadata.json yazılamadı: {exc}")
            return None
