"""
karadul.cli_common -- CLI ortak yardimcilar (B17 refactor).

Bu modul `karadul/cli.py` (Click tabanlı klasik CLI) ve
`karadul/hacker_cli.py` (Rich Live tabanlı hacker dashboard) arasında
*tekrar eden* iki parcayi merkezilestirir:

1. `format_size(size)` -- byte -> insanca okunabilir string. Onceden
   her iki dosyada birebir kopya olarak (`_format_size`) yasiyordu;
   yeni stage eklenince iki yer guncellemek gerekiyordu.
2. `build_pipeline(config, ...)` -- Pipeline kurulumu ve stage register
   mantigi. Onceden cli.py:577-589 ve hacker_cli.py:1091-1103 ayri ayri
   yapiyordu. Yeni stage eklendiginde tek yerden eklenmesi yeterli.

Tasarim notlari:
- `build_pipeline` esnek kullanilabilir: cli.py karmasik filtreleme
  (--stage stop_after + --skip-dynamic) için `stages=` parametresi ile
  cagirir; hacker_cli.py default davranis (tüm stage'ler) için
  parametresiz cagirir.
- ReconstructionStage opsiyonel (ImportError tolere edilir).
- `format_size` public (underscore yok) -- iki tarafdan da
  `from karadul.cli_common import format_size` ile import edilir.

B17 sprint, 2026-05-14.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, Optional

if TYPE_CHECKING:
    from karadul.config import Config
    from karadul.core.pipeline import Pipeline
    from rich.progress import Progress, TaskID

logger = logging.getLogger("karadul")


# ---------------------------------------------------------------------------
# Stage isimleri -- pipeline sirasina gore. cli.py'daki STAGES listesinin
# kanonik kopyasi. Yeni stage eklendiginde BURAYA eklenmeli (cli.py icin
# ayrica STAGES degiskeni Click choice icin lazim ama ondan da bu
# modulden referans veriliyor).
# ---------------------------------------------------------------------------
DEFAULT_STAGE_ORDER: tuple[str, ...] = (
    "identify",
    "static",
    "dynamic",
    "deobfuscate",
    "reconstruct",
    "report",
)


def format_size(size: int) -> str:
    """Byte degerini insanca okunabilir formata cevir.

    Args:
        size: Byte cinsinden boyut (>= 0).

    Returns:
        "423 B", "12.3 KB", "1.5 MB", "2.10 GB" gibi formatlanmis string.

    Ornekler:
        >>> format_size(512)
        '512 B'
        >>> format_size(2048)
        '2.0 KB'
        >>> format_size(1572864)
        '1.5 MB'
    """
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


def _resolve_stage_classes(requested: Iterable[str]) -> list:
    """Istenen stage isim listesini somut stage sinif INSTANCE'larina cevir.

    ReconstructionStage opsiyonel (ImportError tolere edilir). Diger
    stage'ler `karadul.stages` paketinde her zaman bulunmalidir.

    Args:
        requested: Stage isimleri ("identify", "static", "dynamic",
                   "deobfuscate", "reconstruct", "report").

    Returns:
        Instantiate edilmiş stage objeleri listesi (`requested` sirasinda).
        Bilinmeyen veya ImportError olan stage'ler atlanir.
    """
    from karadul.stages import (
        IdentifyStage,
        StaticAnalysisStage,
        DeobfuscationStage,
        DynamicAnalysisStage,
        ReportStage,
    )

    stage_map: dict[str, type] = {
        "identify": IdentifyStage,
        "static": StaticAnalysisStage,
        "dynamic": DynamicAnalysisStage,
        "deobfuscate": DeobfuscationStage,
        "report": ReportStage,
    }

    # ReconstructionStage opsiyonel (LLM/ML bagimliliklari yoksa atlar).
    try:
        from karadul.stages import ReconstructionStage
        stage_map["reconstruct"] = ReconstructionStage
    except ImportError as exc:
        logger.warning("ReconstructionStage yüklenemedi, atlanıyor: %s", exc)

    instances = []
    for name in requested:
        cls = stage_map.get(name)
        if cls is not None:
            instances.append(cls())
        else:
            logger.debug("Bilinmeyen stage atlandi: %s", name)
    return instances


def filter_stages(
    *,
    stop_after: Optional[str] = None,
    skip_dynamic: bool = False,
) -> list[str]:
    """Default sira üzerinde filtre uygulayarak aktif stage isim listesini dondur.

    Args:
        stop_after: Bu stage'den sonrasini at (dahil bu stage). None ise
                    tumu.
        skip_dynamic: True ise "dynamic" stage'i listeden çıkar.

    Returns:
        Filtre uygulanmis stage isim listesi (DEFAULT_STAGE_ORDER sirasinda).
    """
    stages = list(DEFAULT_STAGE_ORDER)

    if skip_dynamic and "dynamic" in stages:
        stages.remove("dynamic")

    if stop_after:
        try:
            idx = stages.index(stop_after)
            stages = stages[: idx + 1]
        except ValueError:
            # Bilinmeyen stop_after -> tum stage'ler kalir
            pass

    return stages


def build_pipeline(
    config: "Config",
    *,
    stages: Optional[Iterable[str]] = None,
    stop_after: Optional[str] = None,
    skip_dynamic: bool = False,
) -> "Pipeline":
    """Pipeline olustur, istenen stage'leri register et ve geri dondur.

    İki kullanim sekli vardir:

    1. Filtre uygulama (cli.py klasik mod):
        ``build_pipeline(cfg, stop_after="static", skip_dynamic=True)``
        -> DEFAULT_STAGE_ORDER'dan filtrelenmis liste register edilir.

    2. Explicit stage listesi (gelistirici / hacker_cli.py varyant):
        ``build_pipeline(cfg, stages=["identify", "static", "report"])``
        -> Tam o sira ile register edilir.

    Eger her ikisi de None ise tüm default stage'ler register edilir.

    Args:
        config: `karadul.config.Config` instance.
        stages: Explicit stage isim listesi. Verilirse `stop_after` ve
                `skip_dynamic` parametreleri yok sayilir.
        stop_after: Bu stage'de dur (dahil). Sadece `stages` None ise
                    kullanılır.
        skip_dynamic: "dynamic" stage'i atla. Sadece `stages` None ise
                      kullanılır.

    Returns:
        Stage'leri register edilmiş `Pipeline` instance.

    Raises:
        Caglir tarafa hicbir exception yumuselendir-MIYOR. Pipeline'in
        kendi `__init__`'i veya stage import'lari hata uretirse yukseltir.
    """
    from karadul.core.pipeline import Pipeline

    if stages is None:
        stage_names = filter_stages(
            stop_after=stop_after, skip_dynamic=skip_dynamic,
        )
    else:
        stage_names = list(stages)

    pipeline = Pipeline(config)
    stage_instances = _resolve_stage_classes(stage_names)
    for stage in stage_instances:
        pipeline.register_stage(stage)

    return pipeline


def make_progress_callbacks(
    progress: "Progress",
    task_id: "TaskID",
    stage_labels: Optional[dict[str, str]] = None,
) -> tuple[
    Callable[[str, int, int], None],
    Callable[[str, Any, int, int], None],
    Callable[[str, str, float], None],
]:
    """Tek satırlık `rich.progress.Progress` bar için pipeline callback'leri üret.

    `karadul.core.pipeline.Pipeline.run` uc opsiyonel callback kabul eder
    (`on_stage_start`, `on_stage_complete`, `on_progress`). Bu helper onlari
    verilen `progress` bar / `task_id` uzerine baglar. `hacker_cli.py`'nin tam
    Live dashboard'i DEĞİL -- sade tek satir ilerleme cubugu (cli.py analyze).

    Bar'in `total`'i pipeline stage sayisina esit olmalidir; her stage bitince
    `advance=1` ile ilerler. Alt-ilerleme (`on_progress`) sadece aciklama
    metnini gunceller (bar konumunu degil), boylece uzun Ghidra decompile
    sirasinda ekran sessiz kalmaz.

    Args:
        progress: Aktif (context icinde acilmis) Rich Progress instance'i.
        task_id: `progress.add_task(...)` ile olusturulmus task kimligi.
        stage_labels: Stage adı -> insanca etiket eslemesi (opsiyonel). Yoksa
                      stage adı Title Case yapilir.

    Returns:
        `(on_stage_start, on_stage_complete, on_progress)` uclusu. Dogrudan
        `pipeline.run(..., on_stage_start=..., ...)` icine gecirilebilir.
    """
    labels = stage_labels or {}

    def _label(name: str) -> str:
        return labels.get(name, name.replace("_", " ").title())

    def on_stage_start(stage_name: str, index: int, total: int) -> None:
        progress.update(
            task_id,
            description=f"[cyan]{_label(stage_name)}[/cyan]",
        )

    def on_stage_complete(
        stage_name: str, result: Any, index: int, total: int,
    ) -> None:
        # result.success yoksa (savunmaci) yine de ilerlet. Atlanan asama
        # (skipped) HATA degil; success=False tasidigi icin "!" gorunuyordu.
        if getattr(result, "skipped", False):
            marker = "[dim]SKIP[/dim]"
        else:
            ok = getattr(result, "success", True)
            marker = "[green]OK[/green]" if ok else "[yellow]![/yellow]"
        progress.update(
            task_id,
            advance=1,
            description=f"{marker} [dim]{_label(stage_name)}[/dim]",
        )

    def on_progress(stage_name: str, message: str, fraction: float) -> None:
        desc = f"[cyan]{_label(stage_name)}[/cyan]"
        if message:
            desc += f" [dim]{message}[/dim]"
        progress.update(task_id, description=desc)

    return on_stage_start, on_stage_complete, on_progress


# ---------------------------------------------------------------------------
# ÖL-4: ``karadul.ilerleme`` olaylarının ``analyze``'da gösterimi.
#
# Olayı ÖL-1 üretir (``karadul/ghidra/headless.py``); burada yalnız gösterilir. Ayrıştırıcı tek:
# ``karadul.core.ilerleme.ilerleme_ayristir`` (arayüz sunucusu da onu kullanır). Kipler:
#   yok   -> işleyici kurulmaz: ``--quiet`` / ``--json`` (olay basılmaz) ve ``--verbose`` (kök
#            işleyici satırı zaten yazıyor; ayrı işleyici satırı iki kez bastırırdı).
#   cubuk -> stderr terminal ve çubuk terminalde çiziliyor: satır basılmaz, çubuğun açıklaması
#            son olayın ``adim`` + ``islenen/toplam`` + ``gecen_sn``'si.
#   satir -> öbür durumlar (stderr dosya / boru, ya da çubuk çizilmiyor): her olay stderr'e tek
#            satır, sözleşme biçiminde; çubuk varsa açıklaması da güncellenir. stdout'a hiç yazılmaz.
# Olay yoksa gösterilecek bir şey yoktur: zamanlayıcıyla satır / açıklama üretilmez.
# ---------------------------------------------------------------------------
ILERLEME_KIP_YOK = "yok"
ILERLEME_KIP_CUBUK = "cubuk"
ILERLEME_KIP_SATIR = "satir"


def akim_tty(akim: Any) -> bool:
    """Akım bir terminal mi (kapalı / sahte akımda ``False``)."""
    try:
        return bool(akim.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def ilerleme_kipi(*, quiet: bool, verbose: bool, stderr_tty: bool, cubuk_cizilir: bool) -> str:
    """``analyze``'ın ilerleme gösterim kipi (yukarıdaki tablo)."""
    if quiet or verbose:
        return ILERLEME_KIP_YOK
    if stderr_tty and cubuk_cizilir:
        return ILERLEME_KIP_CUBUK
    return ILERLEME_KIP_SATIR


def ilerleme_aciklamasi(
    olay: dict[str, Any], stage_labels: Optional[dict[str, str]] = None,
) -> str:
    """Çubuk açıklaması: aşama etiketi + ``adim`` [+ ``islenen[/toplam]``] [+ ``gecen_sn``].

    Yalnız olayda geçen alanlar yazılır (alan uydurulmaz); değerler Rich biçimlemesinden kaçırılır.
    """
    from rich.markup import escape

    labels = stage_labels or {}
    asama = str(olay.get("asama", ""))
    parcalar = [escape(str(olay["adim"]))]
    if olay.get("islenen") is not None:
        parcalar.append(
            f"{olay['islenen']}/{olay['toplam']}" if olay.get("toplam") is not None
            else str(olay["islenen"]))
    if olay.get("gecen_sn") is not None:
        parcalar.append(f"{olay['gecen_sn']:.1f} sn")
    etiket = labels.get(asama, asama.replace("_", " ").title())
    return f"[cyan]{escape(etiket)}[/cyan] [dim]{' '.join(parcalar)}[/dim]"


class IlerlemeGosterici(logging.Handler):
    """``karadul.ilerleme`` kayıtlarını satır olarak yazar ve / ya da çubuk açıklamasına koyar."""

    def __init__(
        self,
        *,
        akim: Any = None,
        progress: "Optional[Progress]" = None,
        task_id: "Optional[TaskID]" = None,
        stage_labels: Optional[dict[str, str]] = None,
    ) -> None:
        super().__init__(level=logging.INFO)
        self._akim = akim
        self._progress = progress
        self._task_id = task_id
        self._labels = stage_labels

    def emit(self, record: logging.LogRecord) -> None:
        try:
            mesaj = record.getMessage()
            if self._akim is not None:
                self._akim.write(mesaj + "\n")
                self._akim.flush()
            if self._progress is not None:
                from karadul.core.ilerleme import ilerleme_ayristir

                olay = ilerleme_ayristir(mesaj)
                if olay is not None:
                    self._progress.update(
                        self._task_id, description=ilerleme_aciklamasi(olay, self._labels))
        except Exception:  # günlük işleyicisi analizi düşürmez (logging sözleşmesi)
            self.handleError(record)


@contextlib.contextmanager
def ilerleme_gosterimi(
    kip: str,
    *,
    akim: Any,
    progress: "Optional[Progress]" = None,
    task_id: "Optional[TaskID]" = None,
    stage_labels: Optional[dict[str, str]] = None,
) -> Iterator[Optional[IlerlemeGosterici]]:
    """Kipe göre ``karadul.ilerleme`` işleyicisini kur; çıkışta günlükçüyü eski hâline getir.

    ``akim`` çağıran tarafça çubuk açılmadan ÖNCE alınmış ``sys.stderr`` olmalı: Rich ``Live``
    terminalde ``sys.stderr``'i konsola (stdout) yönlendirir. Günlükçü düzeyi INFO'ya çekilir ve
    yayılım kapatılır: kökte (önceki bir koşudan kalan) işleyici varsa satır iki kez çıkmaz.
    """
    if kip == ILERLEME_KIP_YOK:
        yield None
        return
    from karadul.core.ilerleme import ILERLEME_GUNLUKCU

    gunlukcu = logging.getLogger(ILERLEME_GUNLUKCU)
    isleyici = IlerlemeGosterici(
        akim=akim if kip == ILERLEME_KIP_SATIR else None,
        progress=progress, task_id=task_id, stage_labels=stage_labels,
    )
    eski_duzey, eski_yayilim = gunlukcu.level, gunlukcu.propagate
    gunlukcu.addHandler(isleyici)
    gunlukcu.setLevel(logging.INFO)
    gunlukcu.propagate = False
    try:
        yield isleyici
    finally:
        gunlukcu.removeHandler(isleyici)
        gunlukcu.setLevel(eski_duzey)
        gunlukcu.propagate = eski_yayilim


__all__ = [
    "DEFAULT_STAGE_ORDER",
    "format_size",
    "filter_stages",
    "build_pipeline",
    "make_progress_callbacks",
    "ILERLEME_KIP_YOK",
    "ILERLEME_KIP_CUBUK",
    "ILERLEME_KIP_SATIR",
    "akim_tty",
    "ilerleme_kipi",
    "ilerleme_aciklamasi",
    "IlerlemeGosterici",
    "ilerleme_gosterimi",
]
