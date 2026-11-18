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
# Yalnız oracle'ın (vendor pin) kimliği; ürün bunu DENETLEMEZ, denetlemesi de gerekmez
# (P-S3, 2026-11-18, GT ile): geliştirme seti coreutils 9.7 (gnulib 2025) ve buradaki yedi
# girdi orada doğru ad veriyor; doğruluğu değişen üç girdi (version_etc, hard_locale,
# full_write) AYNI sürümde (9.4) LTO'ya göre değişiyor (Debian 9.4 0/11, Ubuntu 9.4 14/14).
# Ayrım sürümle değil yerleşimle: bkz. LAYOUT_DEPENDENT_NAMES / lto_less_layout.
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
    # NOT (2026-11-11): version_etc yapıya bağlı. LTO'lu Ubuntu 9.4'te 6/6 doğru; LTO'suz
    # Debian 9.4'te 0/5 (GT'ye göre "Written by" version_etc_arn'da kalıyor, ad onu çağıranın),
    # geliştirme setinde 0/104. Kural gereği çıkarılmadı; öneri
    # docs/arge/2026-11-11_on_ad_onarimi/sonuc.md'de.
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
    # NOT: xstrtol_error ("invalid suffix in") 2026-11-11'de ÇIKARILDI. Baktığımız her GT'li
    # korpusta 0 doğru: geliştirme seti (Debian 13) 0/9, Debian 9.4 ve Ubuntu 9.4 coreutils
    # (5'er ikili) ateşlenme yok, Ubuntu 9.4 od/pr 0/2. xstrtol-error.c'deki static
    # xstrtol_error çağıranına (xstrtol_fatal) satır içine alınıyor; dizgiyi taşıyan fonksiyonun
    # GT adı xstrtol_error değil. Kanıt ve komutlar: docs/arge/2026-11-11_on_ad_onarimi/sonuc.md.
    # Girdi silindiği için sonraki girdilerin sıra numarası bir azaldı (close_stdin 5 -> 4,
    # usage 6 -> 5); 2026-11-10 dökümündeki numaralar eski sıradır.
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
# NOT (2026-11-11): hard_locale ve full_write yapıya bağlı. LTO'lu Ubuntu 9.4'te hard_locale
# 7/7, full_write 1/1 doğru; LTO'suz Debian 9.4'te 0/5 ve 0/1 (GT'ye göre setlocale ve write'ı
# doğrudan çağıran iç fonksiyon setlocale_null_r / safe_write, ad onu çağıranın), geliştirme
# setinde 0/104 ve 0/11. Kural gereği çıkarılmadı; öneri docs/arge/2026-11-11_on_ad_onarimi/sonuc.md.
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


# ---------------------------------------------------------------------------
# P-S3 (AD-03, 2026-11-18): gnulib VARLIK kanıtı
# ---------------------------------------------------------------------------
# Yukarıdaki parmak izleri "bu fonksiyon hangi gnulib fonksiyonu?" sorusunu cevaplar; ikilinin
# gnulib içerip içermediğini sormaz. Sorulmadığı için `write` çağıran 2-4 dallı tek fonksiyon her
# programda `full_write`, "write error" taşıyan tek fonksiyon `close_stdout` oluyordu (tmux, Mach-O
# tmux, redis-cli, openssl, zstd). Kanal artık yalnız ikilide en az MIN_PRESENCE_MODULES BAĞIMSIZ
# gnulib modülünün işareti varsa ad yazar. Tek dizgi yetmez; platform (ELF / Mach-O) koşul değildir
# (Homebrew'un GNU araçları Mach-O'da da gnulib içerir).
#
# İşaretler gnulib UPSTREAM kaynağından seçildi (leakage-safe; her biri vendor/gnulib-ref/lib/
# <source>'da birebir geçer, testle denetlenir) ve gnulib'e özgü kod metnidir. Genel dizgiler
# ("write error", "memory exhausted", "Usage: %s") bilerek YOK: bison ve başka programlar da taşır.
# Çağrı işaretleri, gnulib'in glibc'de çağırdığı ve başka kodun pek çağırmadığı stdio_ext
# fonksiyonlarıdır (close-stream: __fpending, freading: __freading).

PRESENCE_KIND_STRING = "dizgi"
PRESENCE_KIND_CALL = "cagri"
MIN_PRESENCE_MODULES = 2

# P-S3b (2026-11-18): Ghidra decompile çıktısında dizgi değişmezindeki tırnakları kaçırır
# ("Try \'%s --help\' ..."). İşaretler kaynaktaki metinle yazıldığı için karşılaştırma kaçışı
# çözülmüş metinde yapılır; yoksa tek tırnaklı işaret (xstrtol-error, getopt) hiç eşleşmez
# (geliştirme setinde xstrtol-error: ham 0, çözülmüş 8 coreutils ikilisi).
_GHIDRA_QUOTE_ESCAPES = (("\\'", "'"), ('\\"', '"'))


def unescape_ghidra_quotes(text: str) -> str:
    """Ghidra'nın dizgi değişmezindeki tırnak kaçışlarını (``\\'``, ``\\"``) çöz."""
    for kacis, karakter in _GHIDRA_QUOTE_ESCAPES:
        text = text.replace(kacis, karakter)
    return text


@dataclass(frozen=True)
class GnulibPresenceMarker:
    """Bir gnulib modülünün ikilideki izi.

    Args:
        module: gnulib modülü (kanıt satırında görünen ad).
        source: işaretin birebir geçtiği gnulib ``lib/`` kaynak dosyası.
        kind: ``dizgi`` (ikilinin dizgi değişmezlerinde alt dizgi) ya da ``cagri`` (çağrı
            çizgesinde çağrılan ad, tam eşitlik).
        anchors: herhangi biri (OR) bulunursa modül var sayılır.
        glibc_shared: işaretin metni glibc'nin kendi kaynağında da aynı (getopt.c, error.c).
            Glibc'li Linux'ta dinamik bağlı programda bu metin libc.so'da kalır, macOS'ta gnulib
            onu ikiliye derler; ama statik glibc'li gnulib'siz bir program da taşıyabilir. Bu
            yüzden yalnız böyle modüllerden oluşan kanıt yetmez (``presence_evidence``).
    """

    module: str
    source: str
    kind: str
    anchors: tuple[str, ...]
    glibc_shared: bool = False


GNULIB_PRESENCE_MARKERS: tuple[GnulibPresenceMarker, ...] = (
    GnulibPresenceMarker(
        "progname", "progname.c", PRESENCE_KIND_STRING,
        ("A NULL argv[0] was passed through an exec system call",),
    ),
    # "Written by %s, %s, and %s." version_etc_arn'ın dizgisi (P-S3b): emit_bug_reporting_address
    # olmayan programda da version-etc'yi tanır. Aynı modül; modül sayısı değişmez.
    GnulibPresenceMarker(
        "version-etc", "version-etc.c", PRESENCE_KIND_STRING,
        ("General help using GNU software",
         "License GPLv3+: GNU GPL version 3 or later <%s>",
         "Packaged by %s",
         "Written by %s, %s, and %s."),
    ),
    GnulibPresenceMarker(
        "argmatch", "argmatch.c", PRESENCE_KIND_STRING,
        ("invalid argument %s for %s", "ambiguous argument %s for %s", "Valid arguments are:"),
    ),
    GnulibPresenceMarker(
        "closein", "closein.c", PRESENCE_KIND_STRING, ("error closing file",),
    ),
    GnulibPresenceMarker(
        "xstrtol-error", "xstrtol-error.c", PRESENCE_KIND_STRING,
        ("invalid suffix in %s%s argument '%s'", "%s%s argument '%s' too large"),
    ),
    GnulibPresenceMarker(
        "close-stream", "close-stream.c", PRESENCE_KIND_CALL, ("__fpending",),
    ),
    GnulibPresenceMarker(
        "freading", "freading.h", PRESENCE_KIND_CALL, ("__freading",),
    ),
    # P-S3b (2026-11-18): sürümden ve platformdan bağımsız işaretler. P-S3'ün işaretleri Homebrew
    # coreutils 9.12'de (Mach-O, gnulib 2024+) yalnız 1 modül buldu: progname iletisi yeni gnulib'de
    # yok, __fpending / __freading macOS'ta gnulib'in kendi (adsız) fonksiyonu. getopt (uzun seçenek
    # iletilerinin '%s%s' biçimi, 2017+) ve error modülleri macOS'ta ikiliye derlenir. Dağılım
    # (P-S3b ön kaydı): geliştirme setinin 13 gnulib'siz programında ve /usr/bin'in 640 Mach-O
    # dosyasında 0. Metin glibc'yle ortak -> glibc_shared.
    GnulibPresenceMarker(
        "getopt", "getopt.c", PRESENCE_KIND_STRING,
        ("%s: option '%s%s' doesn't allow an argument",
         "%s: unrecognized option '%s%s'",
         "%s: option '%s%s' requires an argument",
         "%s: option '%s%s' is ambiguous"),
        glibc_shared=True,
    ),
    GnulibPresenceMarker(
        "error", "error.c", PRESENCE_KIND_STRING, ("Unknown system error",),
        glibc_shared=True,
    ),
)


@dataclass(frozen=True)
class GnulibPresence:
    """İkilideki gnulib varlık kanıtı.

    ``found``: bulunan her modül için ``(module, source, kind, eşleşen işaret)``, katalog sırasıyla.
    ``sufficient``: en az ``MIN_PRESENCE_MODULES`` modül bulundu VE en az biri glibc ile ortak
    olmayan (gnulib'e özgü) modül.
    ``glibc_shared_modules``: bulunanlardan metni glibc'yle ortak olanlar.
    """

    found: tuple[tuple[str, str, str, str], ...]
    sufficient: bool
    glibc_shared_modules: tuple[str, ...] = ()

    def evidence_line(self) -> str:
        """Kanıt satırı (insan okur; ``static/gnulib_candidates.json`` ve günlük)."""
        if not self.found:
            return f"gnulib varlık kanıtı yok (gereken {MIN_PRESENCE_MODULES} bağımsız modül)"
        parcalar = "; ".join(f"{m} ({src}, {k}: '{a}')" for m, src, k, a in self.found)
        hukum = "yeterli" if self.sufficient else "yetersiz"
        ek = ""
        if (not self.sufficient and len(self.found) >= MIN_PRESENCE_MODULES
                and len(self.glibc_shared_modules) == len(self.found)):
            ek = " (hepsi glibc ile ortak; gnulib'e özgü modül yok)"
        return (f"gnulib varlık kanıtı {hukum}: {len(self.found)} / {MIN_PRESENCE_MODULES} "
                f"bağımsız modül{ek} — {parcalar}")


def presence_evidence(literals, callee_names) -> GnulibPresence:
    """İkilinin dizgi değişmezleri ve çağrılan adlarından gnulib varlık kanıtı.

    Dizgi işaretleri, değişmezlerin Ghidra tırnak kaçışları çözülmüş metninde aranır.
    Yeterlilik: en az ``MIN_PRESENCE_MODULES`` bağımsız modül ve bunlardan en az biri glibc ile
    ortak olmayan modül (yalnız getopt + error: statik glibc'li gnulib'siz program da taşır).

    Args:
        literals: ikilinin decompile edilmiş bütün fonksiyonlarındaki dizgi değişmezleri.
        callee_names: çağrı çizgesinde çağrılan bütün adlar.
    """
    blob = unescape_ghidra_quotes("\n".join(sorted(set(literals or ()))))
    callees = set(callee_names or ())
    found: list[tuple[str, str, str, str]] = []
    shared: list[str] = []
    for marker in GNULIB_PRESENCE_MARKERS:
        for anchor in marker.anchors:
            hit = (anchor in blob) if marker.kind == PRESENCE_KIND_STRING else (anchor in callees)
            if hit:
                found.append((marker.module, marker.source, marker.kind, anchor))
                if marker.glibc_shared:
                    shared.append(marker.module)
                break
    sufficient = len(found) >= MIN_PRESENCE_MODULES and len(shared) < len(found)
    return GnulibPresence(tuple(found), sufficient, tuple(shared))


# ---------------------------------------------------------------------------
# P-S3 (B-A3, 2026-11-18): yerleşime bağlı girdiler
# ---------------------------------------------------------------------------
# version_etc ("Written by"), hard_locale (setlocale) ve full_write (write) LTO'lu yapıda doğru
# fonksiyonda ateşlenir (iç fonksiyon dışarıdakine satır içine alınır); LTO'suz yapıda dizgi /
# çağrı İÇ fonksiyonda (version_etc_arn, setlocale_null_r, safe_write) kalır, dış ad onu çağıran
# ince sarmalayıcınındır. GT: Debian 9.4 (LTO'suz) 0/11, Ubuntu 9.4 (LTO'lu) 14/14, geliştirme seti
# (Debian 13, LTO'suz) 0/217 (docs/arge/2026-11-11_on_ad_onarimi/sonuc.md, P-S3.md).
# GT'siz ayırt edici: LTO'suz yapıda ateşlenen fonksiyonun BÜTÜN çağıranları ince sarmalayıcıdır
# (en çok THIN_CALLER_MAX_CALLEES fonksiyon çağırır); LTO'lu yapıda çağıran main gibi geniş bir
# fonksiyondur. Kural yalnız bu üç girdiye uygulanır; çağıranı olmayan ateşlemede karar verilemez.
# İç ad (version_etc_arn ...) burada üretilmez: gnulib sürümüne bağlı (setlocale_null_r ↔
# setlocale_null_r_unlocked) ve ayrı ölçüm ister.

LAYOUT_DEPENDENT_NAMES = frozenset({"version_etc", "hard_locale", "full_write"})
THIN_CALLER_MAX_CALLEES = 2


def lto_less_layout(caller_callee_counts) -> bool:
    """Ateşlenen fonksiyonun bütün çağıranları ince sarmalayıcı mı (LTO'suz yerleşim)?

    ``caller_callee_counts``: çağıranların çağırdığı fonksiyon sayıları. Çağıran yoksa ``False``
    (yerleşim kanıtı yok; eski davranış).
    """
    counts = list(caller_callee_counts or ())
    return bool(counts) and all(c <= THIN_CALLER_MAX_CALLEES for c in counts)
