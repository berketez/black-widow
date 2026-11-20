"""GoMetadataRecoveryStep — Go ``pclntab`` üretici adımı (P-ÜV1; ÜST VERİ hattı).

Soyulmuş Go ikilisinin ``pclntab``'ından fonksiyon adresi → tam ad, kaynak dosya, paket sınıfı;
``__go_buildinfo``'dan Go sürümü ve modül; yapı denetimleri (K0–K9). Okuyucu
``karadul/analyzers/ustveri/go_pclntab.py``, ikili görüntü P-ÜV0 ``goruntu.ac``. Ghidra'sız,
ikili çalıştırılmaz.

Akış:
    1. Bayrak: ``binary_reconstruction.enable_go_metadata_recovery`` yalnız gerçek ``True`` ise
       çalışır; değilse ``kapali``, yapıt boş, dosya yazılmaz.
    2. ``binary_for_byte_match`` (ürünün seçtiği ince dilim) görüntü olarak açılır.
    3. Okuyucu durumu: ``calisti`` / ``veri_yok`` (Go değil) / ``desteklenmiyor`` / ``tutarsiz``
       (yapı denetimi tuttu değil: ad listesi YOK, yalnız kanıt) / ``hata``; her biri neden ile.
    4. ``static/go_functions.json`` yazılır (kapalı dışındaki her durumda; ad listesi yalnız
       ``calisti``'da dolu).

Bu adım ad yazmaz; adları ad haritasına bağlayan kanal ``enable_go_pclntab_naming`` (P-ÜV6).
Faz 1 adım listesine ekleme de P-ÜV6'dadır.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from karadul.analyzers.ustveri import go_pclntab
from karadul.pipeline.context import StepContext
from karadul.pipeline.registry import Step, register_step

logger = logging.getLogger(__name__)

CIKTI_ASAMA = "static"
CIKTI_AD = "go_functions"
SEMA = "karadul-go-functions/1"


def _goruntu_ac(yol: Path) -> Any:
    """P-ÜV0 görüntüsünü aç (``GoruntuHatasi`` ``durum`` / ``neden`` taşır).

    ``binary_for_byte_match`` normalde ürünün kestiği ince dilimdir; evrensel dosya gelirse ürünün
    seçeceği dilim (``goruntu.urun_dilimi``) açılır, başka dilim değil.
    """
    from karadul.analyzers.ustveri import goruntu

    veri = Path(yol).read_bytes()
    return goruntu.baytlardan(veri, goruntu.urun_dilimi(veri), kaynak=str(yol))


def go_metadata_enabled(cfg: Any) -> bool:
    """Bayrak yalnız gerçek ``True`` ise açık (``"true"``, 1, sahte nesne açmaz)."""
    recon = getattr(cfg, "binary_reconstruction", None)
    return getattr(recon, "enable_go_metadata_recovery", False) is True


@register_step(
    name="go_metadata_recovery",
    requires=["binary_for_byte_match"],
    produces=[
        "go_functions",        # list[dict] — GoFonksiyon.kayit(); yalnız "calisti"da dolu
        "go_buildinfo",        # dict | None
        "go_integrity",        # dict — K0–K9 + satır içi ad sayacı (bakılan / ihlal)
        "go_status",           # {"durum": …, "neden": …}
        "go_functions_path",   # Path | None
    ],
)
class GoMetadataRecoveryStep(Step):
    """Go ``pclntab`` okuyucusunu ürünün ince dilimi üstünde koşar."""

    def run(self, ctx: StepContext) -> dict[str, Any]:
        pc = ctx.pipeline_context
        t0 = time.monotonic()

        if not go_metadata_enabled(pc.config):
            return self._bitir(ctx, t0, go_pclntab.DURUM_KAPALI, "bayrak kapalı", yaz=False)

        yol = ctx.artifacts.get("binary_for_byte_match")
        if yol is None or not Path(yol).is_file():
            return self._bitir(ctx, t0, go_pclntab.DURUM_HATA,
                               f"binary_for_byte_match yok ya da dosya değil: {yol}")
        try:
            g = _goruntu_ac(Path(yol))
        except Exception as exc:  # noqa: BLE001 - görüntü kurulamazsa adım düşmez
            durum = getattr(exc, "durum", None)
            if durum not in go_pclntab.DURUMLAR:
                durum = go_pclntab.DURUM_HATA
            neden = getattr(exc, "neden", None) or f"{type(exc).__name__}: {exc}"
            if durum == go_pclntab.DURUM_HATA:
                ctx.errors.append(f"go_metadata_recovery: görüntü açılamadı: {neden}")
            return self._bitir(ctx, t0, durum, f"görüntü: {neden}")

        sonuc = go_pclntab.oku(g)
        if sonuc.durum == go_pclntab.DURUM_HATA:
            ctx.errors.append(f"go_metadata_recovery: {sonuc.neden}")
        return self._bitir(ctx, t0, sonuc.durum, sonuc.neden, sonuc=sonuc)

    # ------------------------------------------------------------------
    def _bitir(self, ctx: StepContext, t0: float, durum: str, neden: str, *,
               sonuc: go_pclntab.GoSonuc | None = None, yaz: bool = True) -> dict[str, Any]:
        fonksiyonlar = ([f.kayit() for f in sonuc.fonksiyonlar]
                        if sonuc is not None and durum == go_pclntab.DURUM_CALISTI else [])
        buildinfo = sonuc.buildinfo if sonuc is not None else None
        butunluk = dict(sonuc.butunluk) if sonuc is not None else {}
        status = {"durum": durum, "neden": neden}
        yol: Path | None = None
        if yaz:
            payload = {
                "sema": SEMA,
                "durum": status,
                "pclntab": sonuc.pclntab if sonuc is not None else {},
                "buildinfo": buildinfo,
                "butunluk": butunluk,
                "sayim": sonuc.sayim if sonuc is not None else {},
                "okuma_suresi_sn": sonuc.sure_sn if sonuc is not None else None,
                "fonksiyon_sayisi": len(fonksiyonlar),
                "fonksiyonlar": fonksiyonlar,
            }
            try:
                yol = ctx.pipeline_context.workspace.save_json(CIKTI_ASAMA, CIKTI_AD, payload)
                ctx.produce_artifact("go_functions_path", yol)
            except Exception as exc:  # noqa: BLE001 - yazılamazsa adım düşmez, hata kaydı
                logger.warning("go_functions.json yazılamadı: %s", exc)
                ctx.errors.append(f"go_metadata_recovery yapıt yazımı: {exc}")
                yol = None
        ctx.stats["go_status"] = durum
        ctx.stats["go_function_count"] = len(fonksiyonlar)
        ctx.stats["timing_go_metadata_recovery"] = round(time.monotonic() - t0, 3)
        if durum != go_pclntab.DURUM_KAPALI:
            logger.info("Go pclntab: %s (%d fonksiyon)%s", durum, len(fonksiyonlar),
                        f" — {neden}" if neden else "")
        return {
            "go_functions": fonksiyonlar,
            "go_buildinfo": buildinfo,
            "go_integrity": butunluk,
            "go_status": status,
            "go_functions_path": yol,
        }
