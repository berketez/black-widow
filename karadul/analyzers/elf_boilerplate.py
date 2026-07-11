"""ELF/CRT boilerplate fonksiyon tanima (call-shape, hesaplama — FIX-3, 2026-07-12).

Amac
----
Her ELF binary'sinde derleyici+linker'in urettigi sabit "boilerplate"
fonksiyonlari bulunur: ``_start``, ``register_tm_clones``,
``deregister_tm_clones``, ``__do_global_dtors_aux``, ``frame_dummy``,
``call_weak_fn`` ... Bunlar kaynak koddan gelmez; C runtime (crt1.o/crti.o
/crtbegin.o) ve linker tarafindan enjekte edilir. Stripped binary'de isimsiz
``FUN_`` olurlar, ama **davranislari (call-shape) evrenseldir ve kaynak-
bagimsizdir** -> deterministik olarak hesaplanabilir.

Yontem
------
Bu stub'lari benzersiz kilan sey, cagirdiklari ayirt-edici runtime
sembolleridir. ``_ITM_registerTMCloneTable`` / ``_ITM_deregisterTMCloneTable``
(transactional-memory clone tablolari) ve ``__cxa_finalize`` linker-uretimi
CRT stub'lari DISINDA pratikte hicbir yerde cagrilmaz. Bu callee'ler stripped
binary'de bile PLT/dinamik-sembol tablosundan isimli cozulur (gnulib
call-shape [FIX-2b] ile ayni prensip).

``_start`` ayri ele alinir: ``stages._recover_main_from_entry``, main'i
``__libc_start_main(main, ...)`` cagrisindan bulurken bu cagriyi iceren
DOSYANIN kendisi zaten ``_start``/entry fonksiyonudur -> o kurtarma noktasinda
isaretlenir (burada degil).

Precision
---------
``__gmon_start__`` cagrisi genelde IKI fonksiyonda gorunur (``call_weak_fn``
ve bir PLT/wrapper) -> unique-in-binary kisitini gececek tek aday olmadigi
icin ``call_weak_fn`` bilincli DISARIDA birakildi (kabul edilen sinir; yanlis
isim vermektense bos birakmak -> precision sozlesmesi). Atama, cagiran tarafta
(``stages._recover_elf_boilerplate``) **unique-in-binary** kisiti ile yapilir.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BoilerplateShape:
    """Bir ELF/CRT boilerplate fonksiyonunun call-shape imzasi.

    Args:
        name: GT ile eslesecek kanonik ad (``register_tm_clones`` vb.).
        required_callees: fonksiyonun cagirmasi GEREKEN ayirt-edici runtime
            sembolleri (AND). Hepsi callee-set'te bulunmali.
        min_fanout: alt sinir. ``fout=1`` PLT thunk'larini gercek stub'tan ayirir
            (ornegin ``__cxa_finalize`` thunk'i cc=1, ``__do_global_dtors_aux``
            cc>=2).
        max_fanout: opsiyonel ust sinir; kucuk stub'lari buyuk fonksiyonlardan ayirir.
        note: kisa aciklama.
    """

    name: str
    required_callees: tuple[str, ...]
    min_fanout: int = 1
    max_fanout: int | None = None
    note: str = ""


# Curated set. Her required_callee, linker/CRT-uretimi bir sembol olup coreutils
# gibi normal kaynak kodda hicbir yerde cagrilmaz -> son derece ayirt-edici.
ELF_BOILERPLATE_SHAPES: tuple[BoilerplateShape, ...] = (
    BoilerplateShape(
        "register_tm_clones", ("_ITM_registerTMCloneTable",),
        min_fanout=1, max_fanout=3,
        note="TM-clone tablosu kaydi -- _ITM_registerTMCloneTable yalniz burada",
    ),
    BoilerplateShape(
        "deregister_tm_clones", ("_ITM_deregisterTMCloneTable",),
        min_fanout=1, max_fanout=3,
        note="TM-clone tablosu iptali -- _ITM_deregisterTMCloneTable yalniz burada",
    ),
    BoilerplateShape(
        "__do_global_dtors_aux", ("__cxa_finalize",),
        min_fanout=2, max_fanout=5,
        note="global dtor aux -- __cxa_finalize + ic callee (cc>=2); "
             "salt __cxa_finalize PLT thunk'i (cc=1) min_fanout ile elenir",
    ),
    BoilerplateShape(
        "_start", ("__libc_start_main",),
        min_fanout=2, max_fanout=4,
        note="program giris noktasi -- __libc_start_main'i main+abort/hlt ile "
             "cagirir (cc>=2); salt-cagri PLT thunk'i (cc=1) min_fanout ile elenir",
    ),
)


def match_boilerplate(callee_names: set[str], fanout: int) -> str | None:
    """Bir fonksiyonun callee-set'i hangi ELF boilerplate stub'una uyar?

    TUM ``required_callees`` (AND) callee-set'te bulunan ve
    ``min_fanout <= fanout <= max_fanout`` araligindaki ILK shape'in adini
    dondurur; eslesme yoksa ``None``. unique-in-binary kisiti cagiran tarafta
    (``stages._recover_elf_boilerplate``) uygulanir.
    """
    if not callee_names:
        return None
    for bp in ELF_BOILERPLATE_SHAPES:
        if fanout < bp.min_fanout:
            continue
        if bp.max_fanout is not None and fanout > bp.max_fanout:
            continue
        if all(c in callee_names for c in bp.required_callees):
            return bp.name
    return None
