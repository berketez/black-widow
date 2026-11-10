"""string_context alt kanalları: ürün sınıflayıcısı ve susturma karar tablosu.

Plan v2.2 N1 adım 3 (tasarım: ``docs/arge/2026-11-10_n1_adim3``, §3.1-§3.2). Belirlenimci ve
LLM'siz; yalnız standart kitaplık. Bu modül c_namer'ı ve ``scripts/`` altını içe aktarmaz.

Ne işe yarar
------------
c_namer'ın ``string_context`` stratejisi fonksiyon adını bir dizgiden kurar. N0b (plan v2.2) bu
adayları kod yolundan ve kanıt dizgisinin biçiminden kurulan 11 ayrık alt kanala böldü ve her
birinin yanlış oranını ölçtü. Sonuç: yalnız ``oz_ad`` ve ``kebap_ad`` ad vermeyi sürdürür
("doğrulanmadı" etiketiyle), öbür dokuzu susar. Bu modül o kararın üründeki karşılığıdır:

- :func:`classify`: bir ``string_context`` adayının alt kanalı;
- :data:`SUBCHANNEL_DECISIONS`: alt kanal → N0b kararı;
- :data:`SILENCED_SUBCHANNELS`, :func:`is_silenced`, :func:`label_for`: susan küme ve kalan
  alt kanalın güven etiketi.

Modül yalnız sınıflar ve kararı söyler. Adayı listeden çıkarmak c_namer'ın işidir.

Tanımın kaynağı (tanım sürümü 1)
--------------------------------
Sürüm 1'in başvuru kopyası ölçüm betiğidir: ``scripts/measurement/alt_kanal.py``. O betik donuktur
(N0b ve N2 ön kayıtları sha256'sını denetler) ve ürün onu içe aktaramaz. Bu yüzden sabitler,
yüklemler ve öncelik sırası buraya kopyalandı. İki kopyanın aynı olduğunu
``tests/test_tarif_alt_kanal.py`` kilitler: sabitler tek tek, sınıflama ise sentetik dizgilerde ve
N0b'nin depodaki atamalarında karşılaştırılır. Tanım değişecekse sürüm 2 burada yazılır ve yeni
ölçüm betiği bu modülü içe aktarır (ölçüm üründen alabilir, ürün ölçümden alamaz).

Anahtar sözcük çıkarımı c_namer'ın klasik yolunun kopyasıdır
(``c_namer._extract_keywords_from_string``); aynı test onunla da karşılaştırır.

Alt kanallar
------------
Gösterim: ``e`` kanıt dizgisinin baştaki ve sondaki boşlukları atılmış hâli; ``ad`` önerilen ad
(çakışma eki eklenmeden önce); ``k`` klasik yolun kanıttan çıkardığı anahtar sözcük sayısı (0-4).
İlk tutan yüklem kazanır; ``diger`` her adayı tutar. Böylece her aday tam bir alt kanala düşer.

1. ``agresif``: kod yolu ``aggressive``.
2. ``kod_parcasi``: kanıt gövde literali (``body_literal``) ama gerçek bir C dizgi literali değil:
   ham satır sonu ya da Ghidra'nın kendiliğinden verdiği bir ad (``FUN_…``, ``param_2``,
   ``local_28``, ``undefined4`` …) taşıyor.
3. ``bicim_parcasi``: adı kuran anahtar sözcüklerden (ilk üç) biri bir printf dönüşüm belirtecinin
   (``%%`` hariç) içine taşıyor: ``%lld`` → ``lld``.
4. ``oz_ad``: ``e`` alt çizgili tek bir C tanımlayıcısı, en az bir küçük harf taşıyor ve ``ad``
   onun küçük harfli hâline eşit.
5. ``tek_sozcuk``: ``k == 1``.
6. ``tanimlayici``: ``e`` alt çizgili tek bir C tanımlayıcısı ama 4'e girmedi (ad dizgiden farklı
   ya da tanımlayıcının tamamı büyük harf).
7. ``kebap_ad``: ``e`` küçük harfli, tireyle bağlanmış tek belirteç (``monitor-activity``).
8. ``hata_iletisi``: kanıtta hata ya da kullanım iletisi belirteci var.
9. ``bicim_dizgisi``: kanıtta printf dönüşüm belirteci (``%%`` hariç) ya da şablon yer tutucusu var.
10. ``duz_metin``: ``e`` boşlukla ayrılmış birden çok parça ve C işleci taşımıyor.
11. ``diger``: kalanlar.

Karar
-----
N0b adım 2 (``docs/arge/2026-10-21_g10_n0b/kesinlik_tablosu.md``; makine okur hâli
``kesinlik_tablosu.json``, ``ana_kararlar``). Kural "yalnız zayıflar": yanlış oranının Wilson %95
alt sınırı %10'un üstünde olan (``zayif``) ve hiç ölçülemeyen (``olculemedi``) alt kanal susar;
``belirsiz`` ve ``dogrulandi`` kalır. Karar bir ölçüm sonucudur, kullanıcı ayarı değildir: tablo
burada sabittir ve aynı test onu ``kesinlik_tablosu.json`` ile karşılaştırır.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any, NamedTuple, Optional

from karadul.core.naming_labels import LABEL_UNVERIFIED, LABEL_VERIFIED

# Tanım sürümü: ölçüm betiğindeki ``TANIM_SURUMU`` ile aynı. Köken kaydına yazılır.
DEFINITION_VERSION = 1

# Sınıflamanın geçerli olduğu strateji. Başka stratejinin adayı sınıflanmaz (çağıran denetler).
STRATEGY = "string_context"
# c_namer'ın aday nesnesindeki ``code_path`` değerleri (``STRING_CONTEXT_CODE_PATHS``)
PATH_AGGRESSIVE = "aggressive"
PATH_CLASSIC = "classic"
# Kanıt decompile gövdesindeki ``"..."`` literalinden okundu (``STRING_CONTEXT_EVIDENCE_ORIGINS``)
ORIGIN_BODY_LITERAL = "body_literal"

# --- Klasik yolun anahtar sözcük çıkarımı (c_namer._extract_keywords_from_string kopyası)
KEYWORD_RE = re.compile(r"[a-zA-Z]{3,}")
STOP_WORDS = frozenset({
    "the", "and", "for", "not", "but", "has", "had", "was", "are",
    "can", "did", "does", "with", "from", "that", "this", "will",
    "you", "your", "all", "been", "have", "its", "may", "our",
    "too", "use", "way", "who", "how", "let", "put",
    "say", "she", "his", "her", "him", "get", "got", "set",
    "try", "yes", "yet", "than", "into", "just", "also",
    "failed", "error", "success", "warning", "info", "debug",
    "true", "false", "null", "none", "invalid", "unknown",
    "opt", "usr", "lib", "bin", "var", "tmp", "etc",
    "build", "buildbot", "buildworker", "hotfix",
    "release", "client", "server", "public",
    "src", "include", "framework", "frameworks",
    "system", "library", "versions", "darwin",
})
MIN_STRING_LENGTH = 3   # bundan kısa dizgiden anahtar sözcük çıkmaz
MAX_KEYWORDS = 4        # klasik yol en çok dört anahtar sözcük tutar (güveni belirler)
NAME_PARTS = 3          # ad ilk üç anahtar sözcükten kurulur

# --- Biçim yüklemleri
# printf dönüşüm belirteci. "%%" ayrı bir seçenek olarak eşlenir ki "%%u" yanlışlıkla "%u"
# sayılmasın. Boşluk bayrağı alınmaz: düz metindeki "50% done" belirteç sayılmasın.
FORMAT_SPEC_RE = re.compile(
    r"%(?:(?:\d+\$)?[-+#0']*(?:\d+|\*)?(?:\.(?:\d+|\*)?)?(?:hh|h|ll|l|L|q|j|z|t)?"
    r"[diouxXeEfFgGaAcspnmCS@]|%)")
ESCAPED_PERCENT = "%%"
TEMPLATE_PLACEHOLDERS = ("#{", "#[", "${", "{{")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
KEBAB_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$")
C_OPERATOR_RE = re.compile(r"->|==|!=|<=|>=|&&|\|\|")
# Ghidra'nın kendiliğinden verdiği adlar. Gerçek bir literaldeki İngilizce sözcüğe uymasın diye
# rakamsız "undefined" ve "in_…" alınmaz (Ghidra kodunda bunlar zaten başka adlarla birlikte geçer).
GHIDRA_AUTO_NAME_RE = re.compile(
    r"\b(?:(?:FUN|DAT|PTR|LAB|SUB|UNK|thunk_FUN)_[0-9a-fA-F]+|param_\d+|local_[0-9a-fA-F]+"
    r"|[a-z]{1,3}Var\d+|a[a-z]{0,2}Stack_[0-9a-fA-F]+|(?:extraout|unaff)_[A-Za-z0-9]+"
    r"|undefined\d+)\b")
ERROR_RE = re.compile(
    r"\b(?:errors?|fail(?:s|ed|ure)?|fatal|invalid|illegal|bad|wrong|unknown|unsupported"
    r"|unexpected|unrecogni[sz]ed|cannot|can'?t|could\s+not|couldn'?t|unable|not\s+able"
    r"|missing|no\s+such|not\s+found|not\s+allowed|denied|refused"
    r"|too\s+(?:many|few|long|big|large|small)|overflow|out\s+of|usage|must|expected)\b",
    re.IGNORECASE)

# --- Alt kanal adları. Değerler ölçümdekiyle aynıdır: köken kaydına (``sub_channel``) yazılır ve
# donuk sınıflayıcının çıktısıyla karşılaştırılır.
SUB_AGGRESSIVE = "agresif"
SUB_CODE_FRAGMENT = "kod_parcasi"
SUB_FORMAT_FRAGMENT = "bicim_parcasi"
SUB_OWN_NAME = "oz_ad"
SUB_SINGLE_WORD = "tek_sozcuk"
SUB_IDENTIFIER = "tanimlayici"
SUB_KEBAB_NAME = "kebap_ad"
SUB_ERROR_MESSAGE = "hata_iletisi"
SUB_FORMAT_STRING = "bicim_dizgisi"
SUB_PLAIN_TEXT = "duz_metin"
SUB_OTHER = "diger"

# --- Karar sözlüğü (N0b ön kaydı; ölçüm betiğindeki ``KARARLAR`` ile aynı değerler)
DECISION_VERIFIED = "dogrulandi"     # Wilson üst sınırı <= %10
DECISION_WEAK = "zayif"              # Wilson alt sınırı > %10
DECISION_UNCERTAIN = "belirsiz"      # aralık %10'u içeriyor
DECISION_UNMEASURED = "olculemedi"   # etiketli öğe yok
DECISIONS = (DECISION_VERIFIED, DECISION_WEAK, DECISION_UNCERTAIN, DECISION_UNMEASURED)
# "Yalnız zayıflar": doğrulanan ve belirsiz kalan alt kanal ad vermeyi sürdürür.
KEPT_DECISIONS = frozenset({DECISION_VERIFIED, DECISION_UNCERTAIN})

# --- Güven etiketleri (kullanıcıya gösterilen yazım; N0b'nin sözlüğüyle aynı)
# Etiket sözlüğü tek yerde: karadul.core.naming_labels (LABEL_VERIFIED, LABEL_UNVERIFIED)
DECISION_LABELS: Mapping[str, str] = {
    DECISION_VERIFIED: LABEL_VERIFIED,
    DECISION_UNCERTAIN: LABEL_UNVERIFIED,
}

# --- Karar tablosu: N0b adım 2'nin birleşik (tmux + htop) kararı, alt kanal sırasıyla.
# Kaynak: docs/arge/2026-10-21_g10_n0b/kesinlik_tablosu.json, "ana_kararlar".
SUBCHANNEL_DECISIONS: Mapping[str, str] = {
    SUB_AGGRESSIVE: DECISION_UNMEASURED,
    SUB_CODE_FRAGMENT: DECISION_WEAK,
    SUB_FORMAT_FRAGMENT: DECISION_WEAK,
    SUB_OWN_NAME: DECISION_UNCERTAIN,
    SUB_SINGLE_WORD: DECISION_WEAK,
    SUB_IDENTIFIER: DECISION_WEAK,
    SUB_KEBAB_NAME: DECISION_UNCERTAIN,
    SUB_ERROR_MESSAGE: DECISION_WEAK,
    SUB_FORMAT_STRING: DECISION_WEAK,
    SUB_PLAIN_TEXT: DECISION_WEAK,
    SUB_OTHER: DECISION_WEAK,
}


# --------------------------------------------------------------------------------------------
# Girdi


class ClassifierInput(NamedTuple):
    """Yüklemlerin okuduğu alanlar. :func:`build_input` kurar."""

    code_path: str
    evidence_origin: str
    evidence: str
    stripped: str
    name: str
    keywords: list[tuple[str, int, int]]

    @property
    def k(self) -> int:
        """Klasik yolun kanıttan çıkardığı anahtar sözcük sayısı."""
        return len(self.keywords)


def extract_keywords(s: str) -> list[tuple[str, int, int]]:
    """Klasik yolun anahtar sözcükleri, dizgideki konumlarıyla: ``[(sözcük, başlangıç, bitiş)]``.

    Sözcükler küçük harfe çevrilir; durak sözcükler atılır; en çok :data:`MAX_KEYWORDS` sözcük
    döner. Sözcük dizisi ``c_namer._extract_keywords_from_string`` çıktısıyla aynıdır.
    """
    if len(s) < MIN_STRING_LENGTH:
        return []
    out: list[tuple[str, int, int]] = []
    for m in KEYWORD_RE.finditer(s):
        word = m.group(0).lower()
        if word not in STOP_WORDS:
            out.append((word, m.start(), m.end()))
    return out[:MAX_KEYWORDS]


def format_specs(s: str) -> list[tuple[int, int]]:
    """``%%`` dışındaki printf dönüşüm belirteçlerinin ``[başlangıç, bitiş)`` aralıkları."""
    return [(m.start(), m.end()) for m in FORMAT_SPEC_RE.finditer(s)
            if m.group(0) != ESCAPED_PERCENT]


def build_input(*, evidence: str, name: str, code_path: str,
                evidence_origin: str) -> ClassifierInput:
    """Adayın dört alanından sınıflayıcı girdisi.

    ``name`` çakışma eki (``_2``) eklenmeden önceki addır: c_namer adayında ``new_name``, köken
    kaydında ``proposed_name`` (yoksa ``new_name``).
    """
    return ClassifierInput(code_path=code_path, evidence_origin=evidence_origin,
                           evidence=evidence, stripped=evidence.strip(), name=name,
                           keywords=extract_keywords(evidence))


# --------------------------------------------------------------------------------------------
# Yüklemler


def _is_aggressive(inp: ClassifierInput) -> bool:
    return inp.code_path == PATH_AGGRESSIVE


def _is_code_fragment(inp: ClassifierInput) -> bool:
    return inp.evidence_origin == ORIGIN_BODY_LITERAL and (
        "\n" in inp.evidence or bool(GHIDRA_AUTO_NAME_RE.search(inp.evidence)))


def _is_format_fragment(inp: ClassifierInput) -> bool:
    specs = format_specs(inp.evidence)
    return any(start < spec_end and spec_start < end
               for _, start, end in inp.keywords[:NAME_PARTS] for spec_start, spec_end in specs)


def _is_underscored_identifier(stripped: str) -> bool:
    return bool(IDENTIFIER_RE.match(stripped)) and "_" in stripped


def _is_own_name(inp: ClassifierInput) -> bool:
    return (_is_underscored_identifier(inp.stripped) and any(c.islower() for c in inp.stripped)
            and inp.name == inp.stripped.lower())


def _is_single_word(inp: ClassifierInput) -> bool:
    return inp.k == 1


def _is_identifier(inp: ClassifierInput) -> bool:
    return _is_underscored_identifier(inp.stripped)


def _is_kebab_name(inp: ClassifierInput) -> bool:
    return bool(KEBAB_RE.match(inp.stripped))


def _is_error_message(inp: ClassifierInput) -> bool:
    return bool(ERROR_RE.search(inp.evidence))


def _is_format_string(inp: ClassifierInput) -> bool:
    return bool(format_specs(inp.evidence)) or any(p in inp.evidence
                                                   for p in TEMPLATE_PLACEHOLDERS)


def _is_plain_text(inp: ClassifierInput) -> bool:
    return len(inp.stripped.split()) > 1 and not C_OPERATOR_RE.search(inp.stripped)


def _is_other(inp: ClassifierInput) -> bool:
    return True


class SubChannel(NamedTuple):
    name: str
    predicate: Callable[[ClassifierInput], bool]


# Öncelik sırası: ilk tutan yüklem kazanır. Sıra tanımın parçasıdır.
SUBCHANNELS: tuple[SubChannel, ...] = (
    SubChannel(SUB_AGGRESSIVE, _is_aggressive),
    SubChannel(SUB_CODE_FRAGMENT, _is_code_fragment),
    SubChannel(SUB_FORMAT_FRAGMENT, _is_format_fragment),
    SubChannel(SUB_OWN_NAME, _is_own_name),
    SubChannel(SUB_SINGLE_WORD, _is_single_word),
    SubChannel(SUB_IDENTIFIER, _is_identifier),
    SubChannel(SUB_KEBAB_NAME, _is_kebab_name),
    SubChannel(SUB_ERROR_MESSAGE, _is_error_message),
    SubChannel(SUB_FORMAT_STRING, _is_format_string),
    SubChannel(SUB_PLAIN_TEXT, _is_plain_text),
    SubChannel(SUB_OTHER, _is_other),
)
SUBCHANNEL_NAMES: tuple[str, ...] = tuple(sub.name for sub in SUBCHANNELS)


# --------------------------------------------------------------------------------------------
# Sınıflama


def predicate_values(inp: ClassifierInput) -> dict[str, bool]:
    """Her yüklemin tek başına değeri, öncelik sırasıyla (şeffaflık ve eşitlik denetimi için)."""
    return {sub.name: bool(sub.predicate(inp)) for sub in SUBCHANNELS}


def classify_input(inp: ClassifierInput) -> str:
    """Öncelik sırasında ilk tutan yüklemin alt kanalı."""
    for sub in SUBCHANNELS:
        if sub.predicate(inp):
            return sub.name
    return SUB_OTHER  # erişilmez: son yüklem her girdiyi tutar


def classify(*, evidence: str, name: str, code_path: str, evidence_origin: str) -> str:
    """Bir ``string_context`` adayının alt kanalı (:data:`SUBCHANNEL_NAMES` içinden).

    Dört alan c_namer adayının aynı adlı alanlarıdır (``name`` = ``new_name``); köken kaydına da
    bunlar yazılır. Stratejiye bakılmaz: yalnız ``strategy == STRATEGY`` olan aday için çağrılır.
    """
    return classify_input(build_input(evidence=evidence, name=name, code_path=code_path,
                                      evidence_origin=evidence_origin))


def record_input(record: Mapping[str, Any]) -> ClassifierInput:
    """Köken kaydından (``naming_provenance.json`` kaydı ya da rakip aday girdisi) girdi.

    Ad, çakışma ekinden önceki addır: ``proposed_name``, yoksa ``new_name``. Eksik ya da boş alan
    boş dizgi sayılır.
    """
    return build_input(
        evidence=str(record.get("evidence") or ""),
        name=str(record.get("proposed_name") or record.get("new_name") or ""),
        code_path=str(record.get("code_path") or ""),
        evidence_origin=str(record.get("evidence_origin") or ""))


def classify_record(record: Mapping[str, Any]) -> str:
    """Köken kaydındaki bir ``string_context`` kaydının alt kanalı. Stratejiye bakılmaz."""
    return classify_input(record_input(record))


# --------------------------------------------------------------------------------------------
# Karar


def silenced_from(decisions: Mapping[str, str]) -> frozenset[str]:
    """Karar tablosundan susan alt kanallar.

    Kararı :data:`KEPT_DECISIONS` içinde olmayan her alt kanal susar. Tabloda hiç geçmeyen ya da
    tanınmayan bir karar taşıyan alt kanal da susar: ölçülmemiş kanal ad vermez.
    """
    return frozenset(name for name in SUBCHANNEL_NAMES
                     if decisions.get(name) not in KEPT_DECISIONS)


# Susan ve kalan alt kanallar (N0b: 9 susar, 2 kalır). Kalanlar öncelik sırasıyla.
SILENCED_SUBCHANNELS: frozenset[str] = silenced_from(SUBCHANNEL_DECISIONS)
KEPT_SUBCHANNELS: tuple[str, ...] = tuple(
    name for name in SUBCHANNEL_NAMES if name not in SILENCED_SUBCHANNELS)


def _require_known(sub_channel: str) -> None:
    if sub_channel not in SUBCHANNEL_NAMES:
        raise ValueError(f"bilinmeyen alt kanal: {sub_channel!r}")


def is_silenced(sub_channel: str) -> bool:
    """Alt kanal üründe susuyor mu. Bilinmeyen ad ``ValueError`` verir."""
    _require_known(sub_channel)
    return sub_channel in SILENCED_SUBCHANNELS


def label_for(sub_channel: str) -> Optional[str]:
    """Kalan alt kanalın adlarına yazılacak güven etiketi; susan alt kanalda ``None``.

    Bilinmeyen ad ``ValueError`` verir.
    """
    if is_silenced(sub_channel):
        return None
    return DECISION_LABELS[SUBCHANNEL_DECISIONS[sub_channel]]
