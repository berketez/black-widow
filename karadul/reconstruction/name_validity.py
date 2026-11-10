"""Ad geçerliliği: verilen her ad geçerli bir C tanımlayıcısı ve ikili içinde tek anlamlı olsun.

Kanıt: ``docs/arge/2026-11-10_cikti_saglamligi/rapor.md`` bulgu 8 ve bulgu 9'un ad kısmı.
c_namer ``break``, ``continue``, ``long`` (C anahtar sözcüğü), ``undefined`` (Ghidra tip
sözcüğü) ve ``write``, ``read`` (ikilide zaten başka bir fonksiyonun adı) gibi adlar
verebiliyordu. ``continue(status_208,lVar8);`` C değildir; ``write`` adlı iki ayrı fonksiyon
olunca çağrının hangisine gittiği okunamaz.

Bu modül listelerin ve kararın TEK yeridir: yalnız standart kitaplık kullanır, c_namer'ı içe
aktarmaz. Adayı listeden çıkarmak, saymak ve köken kaydına yazmak c_namer'ın işidir.

Kurallar (ilk tutan neden kazanır; sıra :data:`REJECT_REASONS`)
----------------------------------------------------------------
1. ``invalid_c_identifier``: ad ``[A-Za-z_][A-Za-z0-9_]*`` biçiminde değil (boş, rakamla
   başlıyor, ``$`` ya da boşluk taşıyor, dizgi değil).
2. ``invalid_c_keyword``: ad bir C anahtar sözcüğü (:data:`C_KEYWORDS`).
3. ``invalid_type_name``: ad bir C/stdint tip adı ya da Ghidra tip sözcüğü
   (:data:`FILE_SCOPE_TYPE_NAMES`; yerel adda :data:`BODY_TYPE_NAMES`).
4. ``collides_with_existing_function``: ad ikilide BAŞKA bir fonksiyonun adı (ithal, export ya
   da Ghidra'nın verdiği ad; kaynak ``ghidra_functions.json``). Yalnız ikili kapsamlı adda
   sorulur. İthal fonksiyon (thunk ya da dış) baştaki tek ``_`` soyulmuş adıyla da sayılır:
   Mach-O'da Ghidra ithal adını ``_gettimeofday`` diye verir, C'deki adı ``gettimeofday``'dir
   (:func:`existing_function_names`). Fonksiyon kendi adıyla çakışmaz: anahtar adresten kurulmuş
   bir yer tutucuysa (``FUN_<adres>``) c_namer "kendi adı" olarak o adresteki fonksiyonun Ghidra
   adını verir.

Kapsam
------
- İkili kapsamlı ad (fonksiyon, genel veri; c_namer'ın genel anahtarları ve kendi adını
  değiştiren fonksiyon): dört kural da geçerli. Bu adlar çıktı projesinde dosya kapsamındadır;
  tip adı ``types.h``'deki typedef'le, var olan fonksiyon adı o fonksiyonla çakışır.
- Yerel ad (parametre, yerel değişken): 1-3 geçerli, 4 sorulmaz. Yerel bir değişkenin bir
  fonksiyonla aynı adı taşıması C'de geçerli gölgelemedir (``time``, ``index``, ``error``
  gerçek kaynakta da yerel addır). Kural 3 yerelde yalnız fonksiyon GÖVDESİNDE tip olarak geçen
  sözcükleri reddeder: ``byte`` adlı bir yerel aynı gövdedeki ``(byte)x`` cast'ini bozar.
  ``addr`` ve ``uaddr`` (çıktının ``types.h``'sindeki, gövdelerde hiç geçmeyen typedef'ler)
  yerelde serbesttir: ``addr`` yaygın ve doğru bir yerel addır.

Aynı yeni adı iki anahtar isterse (karar c_namer'da; burada belgelenir)
-----------------------------------------------------------------------
- Ön adlar (``pre_names``): öncelik sırasıyla (elle > ``main`` girişi > KS-1 > kalanlar; öbek
  içinde sözlük sırası) ilk gelen adı alır; sonraki ad ALMAZ (``pre_names_dropped_duplicate``)
  ve aday listesine kalır.
- Aday listesinden gelen adlar: aday anahtarlarının sırasıyla (fonksiyonların
  ``ghidra_functions.json`` sırası) ilk gelen adı olduğu gibi alır; sonraki ``_2``, ``_3`` …
  ekini alır (köken kaydında ``proposed_name`` eksiz adı taşır). Ek, bu koşuda verilmiş adları
  ve ikili kapsamlı adda var olan fonksiyon adlarını atlar (:func:`unique_name`). Sıra
  belirlenimlidir (plan v2.2 G9).
- Ad var olan bir fonksiyonunsa hiç verilmez (kural 4), ek de eklenmez: ``write_2`` adı
  ``write``'ın bir türevi gibi okunur. Aday bu fonksiyonun ``write`` olduğunu söylüyordu; ikili
  ``write``'ın başka bir fonksiyon olduğunu söylüyor. Ön adlar için de aynıdır (elle verilen ad
  dahil): var olan simgenin adı en güçlü kanıttır ve ön adların kendi aralarındaki kuralla
  (ikinci gelen ad almaz) tutarlıdır.

Listelerin kaynağı (tanım sürümü 1)
-----------------------------------
- :data:`C11_KEYWORDS`: ISO/IEC 9899:2011 §6.4.1, 44 sözcük.
- :data:`C23_KEYWORDS`: ISO/IEC 9899:2024 §6.4.1'in eklediği sözcükler. ``bool``, ``true``,
  ``false`` C11 çıktısında da ad olamaz: ``types.h`` ``<stdbool.h>``'yi içerir
  (``c_project_builder._build_types_h``) ve Ghidra ``while( true )`` yazar (taramada ``true``
  6 555 geçiş / 116 ikili, ``false`` 3 334 / 116).
- :data:`GNU_KEYWORDS`: GCC ve Clang'in öntanımlı (``gnu``) kipinde anahtar sözcük olan uzantılar
  (GCC el kitabı, "Alternate Keywords").
- :data:`GHIDRA_TYPE_WORDS`: Ghidra'nın decompile çıktısında GERÇEKTEN görülen yerleşik tip
  sözcükleri. Tarama (2026-11-10): Debian 13 arm64 geliştirme setinin saklı koşularındaki ham
  Ghidra çıktısı, 117 ikili, 63 367 ``.c`` dosyası; üç yer: ``static/ghidra_functions.json``
  dönüş ve parametre tipleri, ``static/ghidra_output/decompiled/*.c`` bildirim satırlarının tip
  sözcükleri ve tek sözcüklü cast'ler. Betik ve sayılar:
  ``~/karadul_olcum/runs/ad-gecerliligi-2026-11-10/tip_sozcugu_taramasi.{py,json}``.
  Görülenler (bildirimde geçiş sayısı / ikili sayısı): ``undefined8`` 31 083/117,
  ``undefined1`` 6 884/116, ``undefined4`` 6 505/116, ``undefined`` 3 120/116, ``undefined2``
  454/38, ``undefined6`` 137/6, ``undefined7`` 47/5, ``undefined5`` 12/6, ``undefined3`` 8/5;
  ``ulong`` 19 573/116, ``uint`` 16 321/116, ``byte`` 6 790/116, ``bool`` 2 870/116, ``code``
  1 735/49, ``ushort`` 1 271/116, ``uchar`` 156/7, ``uint6`` 61/6, ``uint3`` 7/5, ``longlong``
  4/2, ``uint7`` 4/2, ``uint5`` 1/1, ``float2`` 1/1; yalnız cast'te: ``int3`` 9/5, ``int5`` 1/1.
  Ghidra'nın bu taramada HİÇ görülmeyen yerleşik tip adları (``sbyte``, ``ulonglong``,
  ``word``, ``dword``, ``qword``, ``float10``, ``string``, ``pointer`` …) listeye alınmadı:
  ``word`` ve ``string`` gibi sözcükler meşru fonksiyon adıdır. Başka bir platformun çıktısında
  görülürlerse tarama yinelenir ve tanım sürümü artar.
- :data:`KARADUL_TYPEDEF_NAMES`: çıktı projesinin ``types.h`` dosyasında tanımlanan, Ghidra'nın
  olmayan adlar (``c_project_builder._build_types_h``).
- :data:`STD_TYPE_NAMES`: ``types.h``'nin içerdiği ``<stdint.h>`` (C11 §7.20) ve ``<stddef.h>``
  (C11 §7.19) başlıklarının tanımladığı tip adları ve POSIX ``ssize_t`` (taramada 272/39). Tip
  kurtarmanın yazdığı adlar (``c_type_recoverer``: ``uint8_t`` … ``uint64_t``, ``int32_t``) bu
  kümenin içindedir.

Bilinen sınırlar
----------------
- Programa özgü tip adları (``ghidra_types.json``: ``stat``, ``sigaction``, ``FILE`` …) listede
  YOKTUR: Ghidra'nın kendi çıktısı aynı adı hem tip hem fonksiyon olarak kullanır (``stat``,
  ``sigaction``), ve bu adları taşıyan gerçek fonksiyonlar vardır.
- İkilinin dosya biçimi c_namer'a verilmez; bu yüzden ``_`` soyma kuralı biçime bakmadan her
  ithal ada uygulanır. ELF'te ``_exit`` ithal eden bir ikilide başka bir fonksiyona ``exit`` adı
  verilmez (2026-11-10 sayımı: 117 Debian ikilisinde bu yüzden reddedilen ad yok; Mac tmux'ta 6
  ad grubu: ``gettimeofday``, ``sigaction``, ``socketpair``, ``time`` …). Mach-O'da ithal OLMAYAN
  simgeli fonksiyonun (``_usage``) ``_``'siz hâli çakışma sayılmaz.
- ``symbols.json`` (``nm`` simgeleri) c_namer'a verilmez. Sayımda 117 Debian ikilisinde boş. Mac
  tmux / htop'ta 233 / 203 simge var, biri dışında hepsi ithal (``U``); 11 / 18'i
  ``ghidra_functions.json``'da fonksiyon adı değil (ne oldukları doğrulanmadı) ve süzgeç onları
  görmez.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping

from karadul.core.naming_labels import EXACT_NAME_PATTERN

DEFINITION_VERSION = 1

# ---------------------------------------------------------------------------
# Ret nedenleri (köken kaydına ve sayaçlara bu yazımla girer)
# ---------------------------------------------------------------------------

REASON_NOT_IDENTIFIER = "invalid_c_identifier"
REASON_KEYWORD = "invalid_c_keyword"
REASON_TYPE_NAME = "invalid_type_name"
REASON_COLLISION = "collides_with_existing_function"
# Sınama sırası: ilk tutan neden kazanır
REJECT_REASONS = (REASON_NOT_IDENTIFIER, REASON_KEYWORD, REASON_TYPE_NAME, REASON_COLLISION)

# ---------------------------------------------------------------------------
# C anahtar sözcükleri
# ---------------------------------------------------------------------------

# ISO/IEC 9899:2011 §6.4.1
C11_KEYWORDS: frozenset[str] = frozenset("""
    auto break case char const continue default do double else enum extern float for goto if
    inline int long register restrict return short signed sizeof static struct switch typedef
    union unsigned void volatile while
    _Alignas _Alignof _Atomic _Bool _Complex _Generic _Imaginary _Noreturn _Static_assert
    _Thread_local
""".split())

# ISO/IEC 9899:2024 §6.4.1'in eklediği sözcükler
C23_KEYWORDS: frozenset[str] = frozenset("""
    alignas alignof bool constexpr false nullptr static_assert thread_local true typeof
    typeof_unqual _BitInt _Decimal32 _Decimal64 _Decimal128
""".split())

# GCC / Clang'in öntanımlı gnu kipinde anahtar sözcük olan uzantılar (``typeof`` C23'te de var)
GNU_KEYWORDS: frozenset[str] = frozenset({"asm", "typeof"})

C_KEYWORDS: frozenset[str] = C11_KEYWORDS | C23_KEYWORDS | GNU_KEYWORDS

# ---------------------------------------------------------------------------
# Tip adları
# ---------------------------------------------------------------------------

# Ghidra'nın ``Undefined`` tipi ve boyut ekli adları (undefined1 … undefined8: hepsi görüldü)
_GHIDRA_UNDEFINED_SIZES = range(1, 9)
GHIDRA_UNDEFINED_WORDS: frozenset[str] = frozenset(
    {"undefined"} | {f"undefined{size}" for size in _GHIDRA_UNDEFINED_SIZES}
)

# Ham Ghidra decompile çıktısında görülen öbür yerleşik tip sözcükleri (kaynak ve sayılar:
# modül belgesi). C anahtar sözcüğü olanlar (``int``, ``long``, ``char`` …) burada yinelenmez;
# ``bool`` hem burada hem C23 listesindedir (neden sırası gereği ``invalid_c_keyword`` çıkar).
GHIDRA_BUILTIN_TYPE_WORDS: frozenset[str] = frozenset("""
    byte bool code uchar ushort uint ulong longlong
    uint3 uint5 uint6 uint7 int3 int5 float2
""".split())

GHIDRA_TYPE_WORDS: frozenset[str] = GHIDRA_UNDEFINED_WORDS | GHIDRA_BUILTIN_TYPE_WORDS

# Çıktı projesinin ``types.h`` dosyasındaki, Ghidra'nın olmayan typedef adları
KARADUL_TYPEDEF_NAMES: frozenset[str] = frozenset({"addr", "uaddr"})

# <stdint.h> (C11 §7.20) ve <stddef.h> (C11 §7.19) tip adları, POSIX ``ssize_t``
_STDINT_WIDTHS = (8, 16, 32, 64)
STD_TYPE_NAMES: frozenset[str] = frozenset(
    {f"{sign}int{kind}{width}_t"
     for sign in ("", "u") for kind in ("", "_least", "_fast") for width in _STDINT_WIDTHS}
    | {"intptr_t", "uintptr_t", "intmax_t", "uintmax_t"}
    | {"size_t", "ptrdiff_t", "wchar_t", "max_align_t"}
    | {"ssize_t"}
)

# Fonksiyon gövdesinde tip olarak geçen sözcükler: yerel ad olamazlar
BODY_TYPE_NAMES: frozenset[str] = GHIDRA_TYPE_WORDS | STD_TYPE_NAMES
# Dosya kapsamında görünen bütün tip adları: fonksiyon ve genel veri adı olamazlar
FILE_SCOPE_TYPE_NAMES: frozenset[str] = BODY_TYPE_NAMES | KARADUL_TYPEDEF_NAMES

_IDENTIFIER_RE = re.compile(EXACT_NAME_PATTERN)

# Çakışma ekinin ilk değeri: adı ilk alan eksiz kalır, ikincisi ``_2`` olur
FIRST_COLLISION_SUFFIX = 2


# ---------------------------------------------------------------------------
# Karar
# ---------------------------------------------------------------------------


def is_c_identifier(name: object) -> bool:
    """``name`` biçimce bir C tanımlayıcısı mı (anahtar sözcük olup olmadığına bakmaz)."""
    return isinstance(name, str) and _IDENTIFIER_RE.fullmatch(name) is not None


def lexical_reject_reason(name: object, *, local: bool = False) -> str | None:
    """Adın yalnız sözcüğüne bakan ret nedeni (kural 1-3); ad geçerliyse ``None``.

    ``local``: ad bir parametre ya da yerel değişken adı mı. Yerelde tip adı sınaması yalnız
    gövdede geçen tip sözcüklerine bakar (:data:`BODY_TYPE_NAMES`).
    """
    if not is_c_identifier(name):
        return REASON_NOT_IDENTIFIER
    if name in C_KEYWORDS:
        return REASON_KEYWORD
    if name in (BODY_TYPE_NAMES if local else FILE_SCOPE_TYPE_NAMES):
        return REASON_TYPE_NAME
    return None


def import_alias(name: str) -> str | None:
    """İthal adının baştaki tek ``_`` soyulmuş hâli (Mach-O'da C'deki ad); yoksa ``None``."""
    if len(name) > 1 and name.startswith("_"):
        return name[1:]
    return None


def existing_function_names(functions: Iterable[tuple[str, bool]]) -> dict[str, str]:
    """İkilide var olan fonksiyon adları: ad → o adın sahibi fonksiyonun Ghidra adı.

    ``functions``: ``(Ghidra adı, ithal mi)`` çiftleri, ``ghidra_functions.json`` sırasıyla
    (ithal: ``is_thunk`` ya da ``is_external``). Her fonksiyon kendi adıyla girer; ithal fonksiyon
    ayrıca :func:`import_alias` adıyla girer. Tam ad her zaman önce gelir: ``_exit`` ithal
    edilirken ``exit`` adlı bir fonksiyon da varsa ``exit`` adının sahibi odur.
    """
    names: dict[str, str] = {}
    aliases: dict[str, str] = {}
    for name, is_import in functions:
        if not name:
            continue
        names.setdefault(name, name)
        alias = import_alias(name) if is_import else None
        if alias is not None:
            aliases.setdefault(alias, name)
    for alias, owner in aliases.items():
        names.setdefault(alias, owner)
    return names


def reject_reason(
    name: object,
    *,
    local: bool = False,
    existing_functions: Mapping[str, str] | None = None,
    own_name: str = "",
) -> str | None:
    """Adın ret nedeni (kural 1-4); ad verilebilirse ``None``.

    ``existing_functions``: :func:`existing_function_names` sözlüğü (ad → sahibinin Ghidra adı).
    Yerel adda (``local=True``) çakışma sorulmaz.
    ``own_name``: adlandırılan simgenin bugünkü adı. Adın sahibi bu simgeyse çakışma sayılmaz:
    fonksiyon kendi adıyla çakışmaz (özdeş eşleme çıktıyı değiştirmez).
    """
    reason = lexical_reject_reason(name, local=local)
    if reason is not None:
        return reason
    if not local and existing_functions and isinstance(name, str):
        owner = existing_functions.get(name)
        if owner is not None and owner != own_name:
            return REASON_COLLISION
    return None


def unique_name(base: str, used: Collection[str], reserved: Collection[str] = frozenset()) -> str:
    """``base`` kullanılmışsa ``_2``, ``_3`` … ekli ilk boş ad; değilse ``base``.

    ``used``: bu koşuda verilmiş adlar. ``reserved``: ek aranırken ayrıca atlanacak adlar (ikili
    kapsamlı adda var olan fonksiyon adları). ``base``'in kendisi ``reserved``'e karşı sınanmaz:
    o sınama ret kuralıdır (:func:`reject_reason`), ek kuralı değil.
    """
    if base not in used:
        return base
    suffix = FIRST_COLLISION_SUFFIX
    while f"{base}_{suffix}" in used or f"{base}_{suffix}" in reserved:
        suffix += 1
    return f"{base}_{suffix}"
