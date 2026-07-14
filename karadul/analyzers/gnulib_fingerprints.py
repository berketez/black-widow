"""gnulib fonksiyon string-anchor fingerprint DB (FIX-2, 2026-07-08).

Amac
----
coreutils stripped-ELF'te gnulib kutuphane fonksiyonlari (``xalloc_die``,
``close_stdout``, ``version_etc`` ...) GCC ``.constprop``/``.isra`` ile
inline+specialize edildigi icin byte-imza backbone'u OLU: hicbir FLIRT/byte
DB'sinde pattern'leri yok. Geriye kalan tek ayirt-edici sinyal, bu
fonksiyonlarin referansladigi sabit hata/surum mesaji string'leridir
(ornegin ``xalloc_die`` -> ``"memory exhausted"``).

Bu modul her hedef gnulib fonksiyonu icin ayirt-edici string anchor(lar)ini
tanimlar. Fonksiyon->isim eslemesi **gnulib upstream kaynagindan** turetilir
(``vendor/gnulib-ref/lib/*.c``), test binary'lerinin ``.rodata``'sindan
DEGIL -- bu, GT-leakage'i (test setine overfit) onler. Her anchor'in ilgili
kaynak dosyada birebir gectigi ``tests/test_gnulib_fingerprints.py`` ile
denetlenir.

Precision
---------
Bazi anchor'lar birden fazla fonksiyonda gorunebilir (ornegin ``"write
error"`` hem ``close_stdout`` hem ``close_stream``'de). Bu yuzden eslesme
CAGIRAN tarafta (``stages._recover_gnulib_from_fingerprints``)
**unique-in-binary** kisiti ile uygulanir: bir isim yalniz TEK ``FUN_`` ile
eslesirse atanir; birden fazla aday varsa belirsiz kabul edilip call-shape
katmanina (FIX-2b) birakilir.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# VENDOR PIN -- leakage-oracle surum sabitlemesi (olcum hijyeni, 2026-07-14)
# ---------------------------------------------------------------------------
# String-anchor / call-shape'lerin "leakage-safe" iddiasi, oracle kaynaginin
# (vendor/gnulib-ref) OLCUM BINARY'lerinin (coreutils 9.4) gnulib surumuyle AYNI
# cagda olmasina baglidir. Asagidaki commit, coreutils v9.4 tag'inin gnulib
# submodule pointer'idir (2023-08). vendor .gitignore'da; yeniden getirme:
#     scripts/fetch_gnulib_ref.sh
# Drift-guard: tests/test_gnulib_fingerprints.py bu commit'i vendor HEAD ile
# karsilastirir -> yanlislikla master'a fetch edilirse test kirilir.
GNULIB_REF_COMMIT = "bb5bb43a1ebb9f502b5ce38c0b8c8778d13b9f6e"
EXPECTED_COREUTILS = "9.4"


@dataclass(frozen=True)
class GnulibFingerprint:
    """Bir gnulib fonksiyonunun string-anchor imzasi.

    Args:
        name: gnulib fonksiyon adi (ground truth ile eslesecek kanonik ad).
        anchors: TUM bu substring'ler fonksiyonun string'lerinde gecmeli (AND).
            Format-specifier'siz (``%s`` vb. haric) guvenli parcalar secilir.
        source: anchor'larin turetildigi gnulib ``lib/`` kaynak dosyasi
            (leakage denetimi icin; GT nm ciktisi degil).
        note: kisa aciklama.
    """

    name: str
    anchors: tuple[str, ...]
    source: str
    note: str = ""


# Curated set: coreutils'te yaygin, ayirt-edici string sabitli gnulib
# fonksiyonlari. Her anchor gnulib lib/<source>'da birebir gecer (dogrulandi).
GNULIB_FINGERPRINTS: tuple[GnulibFingerprint, ...] = (
    GnulibFingerprint(
        "version_etc", ("Written by",), "version-etc.c",
        "surum/yazar ciktisi -- her coreutils binary'sinde tam 1 fonksiyon",
    ),
    GnulibFingerprint(
        "xalloc_die", ("memory exhausted",), "xalloc-die.c",
        "bellek tukenme handler (bazen xmalloc/xrealloc'a inline -> unique-kisit)",
    ),
    GnulibFingerprint(
        "close_stdout", ("write error",), "closeout.c",
        "stdout flush+close (close_stream ile string paylasir -> unique-kisit)",
    ),
    # NOT: emit_ancillary_info / emit_bug_reporting_address curated setten
    # bilincli CIKARILDI: coreutils'te usage() ve emit_* zinciri sik sik main'e
    # inline oluyor -> string'leri main'in govdesine tasiniyor -> bu anchor'lar
    # main'e (FUN_) yanlis atanip FP uretiyor. FIX-1 main'i kurtardiginda guard
    # korur, ama FIX-1'in main'i bulamadigi binary'de main'i bozarlardi. Net
    # kazanc dusuk, FP riski yuksek. (Ayri fonksiyon kaldiklarinda call-shape
    # [FIX-2b] ile yakalanabilirler.)
    GnulibFingerprint(
        "argmatch", ("ambiguous argument", "Valid arguments"), "argmatch.c",
        "enum arg secenegi eslestirme",
    ),
    GnulibFingerprint(
        "xstrtol_error", ("invalid suffix in",), "xstrtol-error.c",
        "sayisal (--lines vb.) arg ayristirma hatasi",
    ),
    GnulibFingerprint(
        "close_stdin", ("error closing file",), "closein.c",
        "stdin kapatma hata handler'i -- close_stdout 'write error' ile cakismaz",
    ),
    GnulibFingerprint(
        "usage", ("Usage: %s",), "argmatch.c",
        "coreutils usage() ekrani. Teknik olarak program-ozgu (src/<prog>.c) bir "
        "fonksiyondur, gnulib degil; ama 'Usage: %s' string prefiksi TUM coreutils "
        "binary'lerinde evrenseldir ve argmatch.c'de bagimsiz gecer (leakage-safe "
        "anchor). unique-in-binary korur; 'Written by' (version_etc) icermez -> "
        "cakismaz. Karadul aksi halde --version/--help satirlarindan yaniltilip "
        "'version_*' atiyordu (FP).",
    ),
)

# Decompiled C string literal cikarici: "..." icini yakalar, kacislar ham kalir.
_STR_LIT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def extract_string_literals(c_source: str) -> list[str]:
    """Ghidra decompiled C metninden string literal'leri cikar.

    Escape dizileri (``\\n`` vb.) ham metin olarak korunur -- anchor'lar
    format-specifier'siz secildigi icin bu yeterli.
    """
    return _STR_LIT_RE.findall(c_source)


def match_function(strings: list[str]) -> str | None:
    """Bir fonksiyonun string seti hangi gnulib fingerprint'e uyar?

    TUM anchor'lari (AND) fonksiyonun string blob'unda substring olarak
    bulunan ILK fingerprint'in adini dondurur; eslesme yoksa ``None``.
    unique-in-binary kisiti burada UYGULANMAZ (cagiran tarafta).
    """
    if not strings:
        return None
    blob = "\n".join(strings)
    for fp in GNULIB_FINGERPRINTS:
        if all(anchor in blob for anchor in fp.anchors):
            return fp.name
    return None


# ---------------------------------------------------------------------------
# FIX-2b: CALL-SHAPE fingerprint
# ---------------------------------------------------------------------------
# String sabiti olmayan (ya da paylasan) gnulib fonksiyonlari icin ikinci
# kanal: fonksiyonun cagirdigi AYIRT-EDICI libc/PLT fonksiyonlari. Ornegin
# ``close_stream`` her zaman ``__fpending`` cagirir, ``gettext_quote`` ise
# ``nl_langinfo``. Bu cagrilar gnulib fonksiyonunun DAVRANISIDIR ve ilgili
# gnulib kaynagi (lib/<source>) icinde birebir gecer -> GT-leakage yok
# (test_gnulib_fingerprints.py::TestNoGroundTruthLeakage denetler).
#
# libc callee isimleri Ghidra tarafindan PLT'den cozulur (dinamik link), o
# yuzden fonksiyonun kendisi isimsiz FUN_ olsa bile callee'ler isimlidir.


@dataclass(frozen=True)
class GnulibCallShape:
    """Bir gnulib fonksiyonunun call-shape (cagri-imzasi) fingerprint'i.

    Args:
        name: gnulib fonksiyon adi.
        required_callees: fonksiyonun cagirmasi GEREKEN ayirt-edici libc/PLT
            isimleri (AND). Hepsi callee-set'te bulunmali.
        source: davranisi dogrulayan gnulib ``lib/`` kaynak dosyasi.
        max_fanout: opsiyonel ust sinir. Kucuk wrapper'lari (ornegin
            ``full_write``) daha buyuk fonksiyonlardan ayirmak icin.
        note: kisa aciklama.
    """

    name: str
    required_callees: tuple[str, ...]
    source: str
    min_fanout: int = 2
    max_fanout: int | None = None
    note: str = ""


# Curated call-shape set. Her required_callee ilgili gnulib kaynaginda gecer.
#
# KRITIK: bir ayirt-edici libc callee'yi (ornegin ``__fpending``) genelde IKI
# fonksiyon cagirir: (1) ``fout=1`` bir PLT thunk / tek-satir wrapper (GT'de
# YOK, olcume girmez) ve (2) gercek gnulib fonksiyonu (``fout>=2``). Bu yuzden
# ``min_fanout=2`` thunk'lari eler ve gnulib fonksiyonunu tek aday birakir.
# ``gettext_quote`` bilinen bir istisnadir (kendisi de ``fout=1``, thunk ve
# ``proper_name_lite`` ile karisir) -> call-shape kanalindan CIKARILDI; string
# sabiti olmadigi icin bu fonksiyon simdilik yakalanamaz (kabul edilen sinir).
GNULIB_CALL_SHAPES: tuple[GnulibCallShape, ...] = (
    GnulibCallShape(
        "close_stream", ("__fpending",), "close-stream.c",
        min_fanout=2, max_fanout=6,
        note="stdout durumunu __fpending ile denetler",
    ),
    GnulibCallShape(
        "hard_locale", ("setlocale",), "hard-locale.c",
        min_fanout=2, max_fanout=6,
        note="aktif locale 'C'/'POSIX' disinda mi -- KUCUK fonksiyon (cc<=6); "
             "usage() de setlocale cagirir ama cc>=8, max_fanout ile ayrilir",
    ),
    GnulibCallShape(
        "full_write", ("write",), "full-write.c",
        min_fanout=2, max_fanout=4,
        note="kismi yazmalari toparlayan write wrapper'i",
    ),
    # KALDIRILDI: quotearg_buffer_restyled call-shape'i (eski anchor: iswprint).
    # 2026-07-14 vendor pin sonrasi drift-guard yakaladi: 2026 kaynaginda bu fonksiyon
    # iswprint cagiriyordu, ama OLCUM HEDEFI (coreutils 9.4 / 2023 gnulib) quotearg.c'de
    # iswprint YOK -> isprint + mbrtoc32 + mbsinit kullaniyor. 2023'te
    # quotearg_buffer_restyled ile mbslen call-shape acisindan AYIRT EDILEMEZ (ikisi de
    # isprint/mbrtoc32/mbsinit/MB_CUR_MAX cagirir); tek fark c32isprint, o da gnulib-ic
    # (stripped binary'de isimsiz FUN_, anchor olamaz). Yani iswprint anchor'i olculen
    # 2023 binary'lerinde HIC eslesmiyordu (~0 gercek TP); 2026-oracle bu hatayi
    # maskeliyordu. Durust olcum icin kaldirildi (naming denetimi 2026-07-13 / pin 07-14).
    GnulibCallShape(
        "rpl_fclose", ("fclose", "__freading"), "fclose.c",
        min_fanout=3, max_fanout=10,
        note="gnulib fclose replacement -- __freading ile buffer durum denetimi",
    ),
    GnulibCallShape(
        "parse_long_options", ("getopt_long",), "long-options.c",
        min_fanout=2, max_fanout=12,
        note="--help/--version isleyen long-opt parser -- getopt_long yalniz burada",
    ),
    GnulibCallShape(
        "rpl_mbrtoc32", ("mbrtoc32",), "mbrtoc32.c",
        min_fanout=2, max_fanout=4,
        note="gnulib mbrtoc32 replacement -- sistem mbrtoc32'yi cagirir",
    ),
    GnulibCallShape(
        "mbslen", ("mbsinit",), "mbswidth.c",
        min_fanout=2, max_fanout=10,
        note="cok-baytli string uzunlugu -- mbsinit ile mbstate sifirlama denetimi",
    ),
    # NOT: proper_name_lite call-shape ILE KURTARILAMIYOR (2023'e pin sonrasi da).
    # 2023 propername-lite.c dogrudan c_strcasecmp + locale_charset + gettext cagiriyor.
    # nl_langinfo, proper_name_lite'in DOGRUDAN callee'si DEGIL -- locale_charset'in
    # (localcharset.c) callee'si, yani iki kademe asagida. proper_name_lite'in dogrudan
    # ayirt-edici callee'leri (c_strcasecmp, locale_charset) gnulib-ic fonksiyonlar ->
    # stripped binary'de isimsiz FUN_ -> call-shape anchor'i OLAMAZ. Bu yuzden vendor'i
    # 2023'e pin'lemek oracle'i olcum hedefiyle hizalar (olcum durustlugu + drift-guard)
    # AMA proper_name_lite'i kurtarmaz. Beklenen F1 kazanci ~0; pin'in degeri saf
    # olcum hijyeni (naming denetimi 2026-07-13, pin 2026-07-14).
)


def match_call_shape(callee_names: set[str], fanout: int) -> str | None:
    """Bir fonksiyonun callee-set'i hangi gnulib call-shape'e uyar?

    TUM ``required_callees`` (AND) callee-set'te bulunan ve
    ``min_fanout <= fanout <= max_fanout`` araligindaki ILK shape'in adini
    dondurur. ``min_fanout`` fout=1 PLT thunk'larini eler. unique-in-binary
    kisiti cagiran tarafta uygulanir.
    """
    if not callee_names:
        return None
    for cs in GNULIB_CALL_SHAPES:
        if fanout < cs.min_fanout:
            continue
        if cs.max_fanout is not None and fanout > cs.max_fanout:
            continue
        if all(c in callee_names for c in cs.required_callees):
            return cs.name
    return None


# ---------------------------------------------------------------------------
# DISAMBIGUATION (2026-07-14): string-anchor paylasan gnulib adlari
# ---------------------------------------------------------------------------
# Bir string anchor birden fazla fonksiyonda gecince (ornegin ``"write error"``
# hem ``close_stdout`` hem ``write_error``'de) match_function unique-in-binary
# kisitiyla ismi ATLAR (belirsiz). Bu katman, dogru adayi fonksiyonlarin
# ayirt-edici callee davranisindan secer -- call-shape (FIX-2b) ile ayni ilke,
# ama sadece belirsiz string-fp adaylari uzerinde calisir.


@dataclass(frozen=True)
class GnulibDisambiguator:
    """String-anchor'i paylasan (belirsiz) bir gnulib adini call-shape'le ayikla.

    Args:
        name: ayirt edilecek gnulib fonksiyon adi (belirsiz string-fp adi).
        require_callees: dogru adayin cagirmasi GEREKEN callee'ler (AND).
        exclude_callees: dogru adayin cagirMAMASI gereken callee'ler (NOR).
        source: davranisi dogrulayan gnulib ``lib/`` kaynak dosyasi.
            ``require_callees`` davranislari BURADA gecer, ``exclude_callees``
            davranislari GECMEZ -> leakage-safe (GT'den degil, kaynaktan turer;
            tests/test_gnulib_fingerprints.py denetler).
    """

    name: str
    require_callees: tuple[str, ...]
    exclude_callees: tuple[str, ...]
    source: str


# Curated disambiguator set. Her kural leakage-safe (asagidaki kaynak
# dogrulamasiyla). Simdilik tek gercek belirsiz vaka mevcut.
GNULIB_DISAMBIGUATORS: tuple[GnulibDisambiguator, ...] = (
    # close_stdout vs write_error: ikisi de "write error" string'ini tasir
    # (closeout.c:121 -- `char const *write_error = _("write error");`), bu yuzden
    # match_function ikisini de "close_stdout" adayi gorup ATLIYOR. Ayirt-edici:
    # close_stdout `_exit` cagirir (closeout.c:128,134) ve buffer'i asla
    # __fpurge/clearerr_unlocked ile ELLEMEZ; write_error tersine davranir
    # (__fpurge/clearerr_unlocked VAR, _exit YOK). cat/cut/paste/split/tail/tr'de
    # gozlemlendi. Leakage-safe: closeout.c'de _exit VAR, fpurge/clearerr YOK.
    GnulibDisambiguator(
        "close_stdout",
        require_callees=("_exit",),
        exclude_callees=("__fpurge", "clearerr_unlocked"),
        source="closeout.c",
    ),
)


def disambiguate(name: str, candidates: dict[str, set[str]]) -> str | None:
    """Belirsiz bir gnulib adi icin dogru ``FUN_`` adayini call-shape'le sec.

    Args:
        name: string-fp'nin birden fazla ``FUN_``'a esledigi belirsiz ad.
        candidates: ``{fun_key: callee_set}`` -- adaylarin callee kumeleri.

    Returns:
        require (AND) + exclude (NOR) filtresinden GECEN TEK ``fun_key``; 0 veya
        >1 hayatta kalan varsa ``None`` (belirsizlik korunur, yanlis atama yok).
    """
    rule = next((d for d in GNULIB_DISAMBIGUATORS if d.name == name), None)
    if rule is None or not candidates:
        return None
    survivors = [
        fk
        for fk, callees in candidates.items()
        if all(r in callees for r in rule.require_callees)
        and not any(x in callees for x in rule.exclude_callees)
    ]
    return survivors[0] if len(survivors) == 1 else None
