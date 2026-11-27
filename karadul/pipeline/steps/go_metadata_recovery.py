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

P-ÜV6c (tutarlılık damgası; bayrak ``binary_reconstruction.enable_go_metadata_integrity``, yalnız
gerçek ``True`` açar): ``calisti`` sonucunda P-ÜV7'nin denetimi (``tutarlilik.denetle``) okuyucu
nesnesiyle (``GoSonuc.pcln``) koşar; her fonksiyon kaydına ``dogrulama`` (``cift_kaynak`` /
``tek_kaynak`` / ``tutarsiz``) ve ``tutarsiz``'da ``dogrulama_isaretleri`` yazılır; durum sözlüğüne
ikili düzeyi özet (``tutarlilik``: karar, güçlü işaret sayısı, hangi denetim). Bayrak kapalıyken
kayıtlar, durum ve ``go_functions.json`` bugünküyle bayt bayt aynı (damga yok = ``olculmedi``).

P-ÜV6c hüküm 5: okuyucu aynı koşuda ``calisti`` verdiyse statik aşamanın evrensel ikili iletisi
("eski Go çözümleyicisi şişman dosyayı açmıyor") aşama hatası olmaktan çıkar, bilgi satırına iner
(``_eski_evrensel_iletiyi_indir``). Okuyucu kapalıysa ya da okuyamadıysa ileti hata olarak kalır.
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


def go_integrity_enabled(cfg: Any) -> bool:
    """Tutarlılık damgası bayrağı (P-ÜV6c); yalnız gerçek ``True`` açar."""
    recon = getattr(cfg, "binary_reconstruction", None)
    return getattr(recon, "enable_go_metadata_integrity", False) is True


# İkili düzeyi özetin taşıdığı alanlar (rapor uyarısı bunları okur; gerçek sayılar, puan yok).
TUTARLILIK_OZET_ALANLARI = ("fonksiyon", "adli", "guclu_isaretli_fonksiyon", "cift_kaynakli_fonksiyon",
                            "K4_uyumsuz_fonksiyon", "K10_ihlal_fonksiyon", "damga", "adli_damga",
                            "K_karari")


def tutarlilik_ozeti(ts: Any) -> dict[str, Any]:
    """``TutarlilikSonucu`` → durum sözlüğüne giren ikili düzeyi özet (JSON'a yazılabilir)."""
    from karadul.analyzers.ustveri import tutarlilik

    ozet = {"durum": ts.durum, "neden": ts.neden, "karar": ts.karar,
            "karar_nedeni": ts.karar_nedeni}
    if ts.durum == go_pclntab.DURUM_CALISTI:
        o = ts.ozet or {}
        ozet.update({k: o.get(k) for k in TUTARLILIK_OZET_ALANLARI})
        # hangi güçlü denetim kaç fonksiyonda işaret verdi (T3 / T4 zayıf: karara girmez)
        ozet["guclu_isaret_dagilimi"] = {
            k: v for k, v in sorted((o.get("isaret_dagilimi") or {}).items())
            if k in tutarlilik.GUCLU_DENETIMLER}
    return ozet


def damgala(kayitlar: list[dict[str, Any]], sonuc: go_pclntab.GoSonuc, ts: Any) -> None:
    """Fonksiyon kayıtlarına damga yaz (yerinde). ``kayitlar`` ``sonuc.fonksiyonlar`` sırasıyla."""
    from karadul.analyzers.ustveri import tutarlilik

    if ts.durum != go_pclntab.DURUM_CALISTI:
        return
    for f, k in zip(sonuc.fonksiyonlar, kayitlar):
        damga = ts.damga(f.giris)
        if damga is None:
            continue
        k["dogrulama"] = damga
        if damga == tutarlilik.DAMGA_TUTARSIZ:
            k["dogrulama_isaretleri"] = sorted(
                i for i in ts.isaretler.get(f.giris, ())
                if i in tutarlilik.GUCLU_DENETIMLER or i in tutarlilik.YAPISAL_ISARETLER)


# Statik aşamanın evrensel ikili iletisi (``stages._note_universal_special_slices``) hata olmaktan
# çıkınca yazılan bilgi satırı (P-ÜV6c hüküm 5).
EVRENSEL_BILGI = ("eski çözümleyici evrensel dosyayı açmıyor; ad ve fonksiyon bilgisi yeni "
                  "okuyucudan (go_metadata_recovery, ürün dilimi)")
EVRENSEL_DURUM_BILGI = "bilgi"


def _eski_evrensel_iletiyi_indir(pc: Any) -> bool:
    """Statik aşamanın Go evrensel ikili hatasını bilgi satırına indir; indirildiyse True.

    İleti ``stages._note_universal_special_slices`` tarafından yazılır ve hata dizgisinin kendisi
    ``go_hatti_error`` istatistiğinde tutulur: yalnız o dizgi (birebir) hata listesinden çıkar.
    """
    results = getattr(pc, "results", None)
    static = results.get("static") if isinstance(results, dict) else None
    stats = getattr(static, "stats", None)
    errors = getattr(static, "errors", None)
    if not isinstance(stats, dict) or not isinstance(errors, list):
        return False
    hata = stats.get("go_hatti_error")
    if not isinstance(hata, str) or hata not in errors:
        return False
    errors[:] = [e for e in errors if e != hata]
    stats["go_hatti_status"] = EVRENSEL_DURUM_BILGI
    stats["go_hatti_bilgi"] = EVRENSEL_BILGI
    stats["go_hatti_eski_ileti"] = stats.pop("go_hatti_error")
    return True


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
        ts = None
        if sonuc.durum == go_pclntab.DURUM_CALISTI:
            if _eski_evrensel_iletiyi_indir(pc):
                ctx.stats["go_universal_note"] = EVRENSEL_DURUM_BILGI
            if go_integrity_enabled(pc.config):
                from karadul.analyzers.ustveri import tutarlilik

                t1 = time.monotonic()
                ts = tutarlilik.denetle(g, sonuc=sonuc)
                ctx.stats["timing_go_metadata_integrity"] = round(time.monotonic() - t1, 3)
        return self._bitir(ctx, t0, sonuc.durum, sonuc.neden, sonuc=sonuc, ts=ts)

    # ------------------------------------------------------------------
    def _bitir(self, ctx: StepContext, t0: float, durum: str, neden: str, *,
               sonuc: go_pclntab.GoSonuc | None = None, yaz: bool = True,
               ts: Any = None) -> dict[str, Any]:
        fonksiyonlar = ([f.kayit() for f in sonuc.fonksiyonlar]
                        if sonuc is not None and durum == go_pclntab.DURUM_CALISTI else [])
        buildinfo = sonuc.buildinfo if sonuc is not None else None
        butunluk = dict(sonuc.butunluk) if sonuc is not None else {}
        status: dict[str, Any] = {"durum": durum, "neden": neden}
        if ts is not None and sonuc is not None:
            # P-ÜV6c: damga + ikili düzeyi özet (yalnız bayrak açıkken; kapalıyken alan yok).
            damgala(fonksiyonlar, sonuc, ts)
            status["tutarlilik"] = tutarlilik_ozeti(ts)
            ctx.stats["go_metadata_integrity"] = status["tutarlilik"]
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
