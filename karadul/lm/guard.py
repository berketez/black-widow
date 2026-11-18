"""KaradulLM model dışı denetim katmanı (tasarım §5.1-5.2, §6.2; bulgular LM-01, LM-03).

Her "ad öner" cevabı araştırmacıya gösterilmeden önce buradan geçer. Katman belirlenimcidir:
modeli çağırmaz, ağa çıkmaz, dosya yazmaz. Girdisi modelin cevabı, o görevde modele verilen araç
sonuçları ve çalışma alanının ad bilgisidir.

Hüküm (tasarım §5.1)
--------------------
- ``ret``: öneri uygulanamaz (kabul düğmesi yok; neden yazılı).
- ``celiski``: en az bir kural kanıtla çelişki buldu (uyarı rozeti; toplu kabule girmez).
- ``sinandi_celiski_yok``: sınanabilir kurallar koştu, çelişki çıkmadı (doğru demek DEĞİLDİR).
- ``sinanamadi``: fonksiyonda sınanacak kanıt yok (D0) ve hiçbir kural çelişki bulmadı.

Kurallar (tasarım §5.2). Kodlananlar:
- D0 kanıt yeterliliği (paket boş: ithal çağrı yok, dizgi yok) → ``sinanamadi``.
- D1 ad geçerliliği → ``ret``: C tanımlayıcısı değil; C'nin ayrılmış adı (``_`` + büyük harf, ``__``);
  C anahtar sözcüğü ya da tip adı (``name_validity.lexical_reject_reason``); ikilide başka bir
  fonksiyonun Ghidra adı ya da ithal adı (``name_validity.reject_reason``, ``existing_function_names``);
  Karadul'un başka bir fonksiyona verdiği ad (``naming_map.json``; ör. ``main``).
- D2 ``kesin`` ya da elle verilmiş ad ezilmez → ``ret`` (ajan bu hedefte modeli hiç çağırmaz).
- D3 yer tutucu → ``ret``: ``protocol.is_placeholder_name``, ``tarif.kesin.is_generic_name`` ve istem
  kuralı 6'daki sözcükler (``func``, ``handler``, ``helper`` …) yalnız başına ya da rakamla.
- D6 dizgiden / simgeden ad → ``celiski`` (LM-03): adın sözcükleri, o görevde modele verilen TEK bir
  dizginin (kanıt dizgisi, koddaki dizgi sabiti, Ghidra'nın ``s_…`` dizgi etiketi) sözcüklerinin alt
  kümesi; ya da ad, sonuçlardaki ikili kökenli bir simge adının (kod tanımlayıcısı, ithal adı, komşu
  adı) birebir kopyası.
- D7 kütüphane adı → ``celiski``: ad bilinen bir C çalışma zamanı fonksiyonunun adı (ikilide ithal
  olmasa da). Sözlük ürünün imza verisinden okunur (``library_names``); okunamazsa kural koşmaz ve
  ``sinanmayan`` listesine yazılır.
- D8 kanıt atfı → ``celiski``: ``kanit`` boş (kanıtsız öneri), bu görevde verilmemiş kimlik, ya da
  gösterilen sonuçların hepsi hedefle ve komşularıyla ilgisiz bir adrese ait.
- D9 görülmemiş olgu → ``celiski``: gerekçede geçen ``FUN_`` adresi, tırnaklı metin ya da çağrı
  biçimli ad (``ad(``) bu görevin sonuçlarının hiçbirinde yok.
- D10 reddedilmiş ad → ``ret`` (araştırmacının bu fonksiyon için reddettiği ad; liste ajana verilir).
- D11 oturum içi çakışma → ``celiski`` (ad bu oturumda başka bir fonksiyona önerildi).
- D12 kuşkulu decompile → bayrak (hükmü değiştirmez).
- D13 enjeksiyon belirtisi → bayrak; öneri toplu kabule girmez (LM-03).
- D14 model adına yaslanma → bayrak (gösterilen sonuçlardaki adlı komşuların hepsi ``[model]``).

Kodlanmayanlar (``sinanmayan`` alanında her raporda yazılı): D4 (alan çelişkisi) ve D5 (fiil
çelişkisi). İkisi de geliştirme setinden türetilecek, kökeni kayda geçen bir aile sözlüğü ister
(tasarım §5.2 son maddeler); sözlük ölçümle kurulmadan kural uydurulmaz.

Kanıt alanlarının ayrımı (LM-03)
--------------------------------
Araç sonucunun ``data`` alanları iki sınıftır: **ikili kökenli** (dizgi, simge adı, kod, Ghidra
uyarısı; adı ikiliden türemiş olabilen komşu etiketleri) ve **yapı** (Karadul'un yazdığı adres, sayı,
yön). ``HOSTILE_FIELDS`` ve ``STRUCTURE_FIELDS`` her aracın her alanını tam bir kez sınıflar; testle
kilitlidir. Tanınmayan araç ya da alan güvenli tarafa düşer: ikili kökenli sayılır.

Denetim kaydı ikili verisi ve model metni taşımaz: bulgular yalnız kural, kod, etki ve sonuç
kimliği + alan adı (``r1.strings``) yazar.
"""
from __future__ import annotations

import functools
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional, Sequence

from karadul.lm import protocol

# --- Hüküm ve etki --------------------------------------------------------------------------
VERDICT_REJECT = "ret"
VERDICT_CONFLICT = "celiski"
VERDICT_CLEAR = "sinandi_celiski_yok"
VERDICT_UNTESTABLE = "sinanamadi"
VERDICTS = (VERDICT_REJECT, VERDICT_CONFLICT, VERDICT_CLEAR, VERDICT_UNTESTABLE)

EFFECT_REJECT, EFFECT_CONFLICT, EFFECT_FLAG = "ret", "celiski", "bayrak"

# --- Bulgu kodları --------------------------------------------------------------------------
CODE_NOT_IDENTIFIER = "gecersiz_tanimlayici"
CODE_RESERVED = "ayrilmis_ad"
CODE_COLLISION_ASSIGNED = "baska_fonksiyonun_adi"     # Karadul'un başka fonksiyona verdiği ad
CODE_PROTECTED_CERTAIN = "kesin_ad_ezilmez"
CODE_PROTECTED_MANUAL = "elle_ad_ezilmez"
CODE_PLACEHOLDER = "yer_tutucu"
CODE_FROM_STRING = "dizgiden_ad"
CODE_SYMBOL_COPY = "simge_kopyasi"
CODE_LIBRARY = "kutuphane_adi"
CODE_NO_REFS = "kanitsiz_oneri"
CODE_UNKNOWN_REF = "verilmemis_kanit"
CODE_UNRELATED_REFS = "ilgisiz_kanit"
CODE_UNSEEN_ADDRESS = "gorulmemis_adres"
CODE_UNSEEN_QUOTE = "gorulmemis_dizgi"
CODE_UNSEEN_CALL = "gorulmemis_cagri"
CODE_REJECTED_BEFORE = "reddedilmis_ad"
CODE_SESSION_DUPLICATE = "oturumda_baska_fonksiyona_onerildi"
CODE_SUSPICIOUS_DECOMPILE = "kuskulu_decompile"
CODE_INJECTION = "enjeksiyon_belirtisi"
CODE_MODEL_ONLY = "yalniz_model_adlari"

# Kodlanmayan kurallar ve nedeni (raporda her zaman yazılır).
NOT_IMPLEMENTED = {
    "D4": "aile sözlüğü yok (geliştirme setinden ölçülerek kurulmadı)",
    "D5": "fiil sözlüğü yok (geliştirme setinden ölçülerek kurulmadı)",
}

# D2: korunan etiketler (tools.name_tag etiketi). ``proven`` = naming_labels.LABEL_CERTAIN.
TAG_PROVEN, TAG_MANUAL, TAG_MODEL = "proven", "manual", "model"
PROTECTED_TAGS = {TAG_PROVEN: CODE_PROTECTED_CERTAIN, TAG_MANUAL: CODE_PROTECTED_MANUAL}

# D3: istem kuralı 6'nın yer tutucu sözcükleri (``context.SYSTEM_PROMPT_KL0`` kural 6: "FUN_..., sub_...,
# func, handler, helper"); ``function`` / ``fun`` aynı sözcüğün açık ve kısa yazımı.
PLACEHOLDER_WORDS = frozenset({"func", "function", "fun", "sub", "handler", "helper"})

# D7: C çalışma zamanı kütüphaneleri (imza verisindeki ``lib`` alanı). ``_``-önekli Mach-O yazımının
# C adı (``_malloc`` → ``malloc``) yalnız Unix kütüphanelerinde türetilir; msvcrt'nin ``_beginthread``
# gibi adları zaten alt çizgiyle başlar.
C_RUNTIME_LIBS = frozenset({"libc", "libm", "libpthread", "libdl", "librt", "libSystem", "msvcrt", "ucrt"})
_MACHO_ALIAS_LIBS = frozenset({"libc", "libm", "libpthread", "libdl", "librt", "libSystem"})

# --- Kanıt alanlarının ayrımı (LM-03) -------------------------------------------------------
FIELD_STRINGS = "dizgi_listesi"     # pilot biçimli JSON dizgi listesi ("a", "b", ... and N more)
FIELD_NAMES = "ad_listesi"          # ithal adları ya da "FUN_x [etiket: ad]" listesi
FIELD_CODE = "kod"                  # decompile metni
FIELD_TEXT = "metin"                # serbest metin (sabitler, Ghidra uyarıları, tanınmayan alan)
FIELD_TAG_ITEMS = "etiket_ogeleri"  # get_xrefs items[].name_tag
HOSTILE_FIELDS: dict[str, dict[str, str]] = {
    "get_evidence": {"apis": FIELD_NAMES, "callees": FIELD_NAMES, "callers": FIELD_NAMES,
                     "callbacks_given": FIELD_NAMES, "callback_of": FIELD_NAMES, "strings": FIELD_STRINGS,
                     "constants": FIELD_TEXT},
    "get_decompiled": {"code": FIELD_CODE, "ghidra_warnings": FIELD_TEXT},
    "get_xrefs": {"items": FIELD_TAG_ITEMS},
}
STRUCTURE_FIELDS: dict[str, frozenset[str]] = {
    "get_evidence": frozenset({"addr", "lines"}),
    "get_decompiled": frozenset({"addr", "total_lines", "line_from", "line_to", "ghidra_warning_total"}),
    "get_xrefs": frozenset({"addr", "direction", "total", "offset"}),
}

# D13: talimat kalıbı ya da sohbet şablonu işareti. Kalıplar dar tutulur (HTML'deki ``</div>`` ya da
# biçim dizgisindeki ``{"kind":`` işaretlenmez); bayrak hükmü değiştirmez, toplu kabulü kapatır.
INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<\|[A-Za-z_][A-Za-z0-9_]{0,30}\|?>|<[A-Za-z_]{1,30}\|>"),
    re.compile(r"</?\s*(?:tool_response|tool_call|tool_calls|think|system|assistant|user|function_call"
               r"|im_start|im_end|start_of_turn|end_of_turn)\s*>", re.I),
    re.compile(r"\[/?INST\]|<</?SYS>>", re.I),
    re.compile(r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?\b(?:instructions?|rules?|prompts?"
               r"|directions?|guidelines?)\b", re.I),
    re.compile(r"\b(?:name|call|rename|label)\s+(?:this|the|that)\s+(?:function|routine|method|procedure)\b", re.I),
    re.compile(r"\byou\s+(?:are|must|should|will)\s+(?:now\s+)?(?:an?\s+|the\s+)?(?:ai|assistant|model"
               r"|language\s+model|llm|karadul\w*)\b", re.I),
    re.compile(r"\b(?:system|developer)\s+prompt\b", re.I),
    re.compile(r"\"(?:isim|kanit|cekimser)\"\s*:|\"kind\"\s*:\s*\"(?:final|call)\"", re.I),
    re.compile(r"\b(?:önceki|yukarıdaki)\s+(?:talimat|kural)", re.I),
    re.compile(r"\bbu\s+fonksiyon\w*\s+(?:\w+\s+){0,3}ad(?:ı|ını|landır)", re.I),
)

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WORD_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_JSON_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_C_STRING_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_TAG_RE = re.compile(r"\[([a-z]+): ([A-Za-z_][A-Za-z0-9_]*)\]")
_GHIDRA_STRING_LABEL_RE = re.compile(r"^[su]_(.+?)(?:_[0-9a-fA-F]{4,16})?$")
_FUN_HEX_RE = re.compile(r"\bFUN_([0-9a-fA-F]{1,16})\b")
_QUOTED_RE = re.compile(r"[\"“”«»']([^\"“”«»'\n]{3,120})[\"“”«»']")
_CALL_LIKE_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,63})\s*\(")
_RESERVED_RE = re.compile(r"^(?:__|_[A-Z])")


def words(text: str) -> list[str]:
    """Metnin küçük harfli sözcükleri: alt çizgi ve büyük-küçük harf geçişinde bölünür
    (``parseHTTPHeader`` → parse, http, header; ``safe_init`` → safe, init)."""
    return [m.group(0).lower() for m in _WORD_RE.finditer(text)]


@dataclass(frozen=True)
class HostileText:
    """Sonuçlardaki ikili kökenli bir metin parçası. ``kind``: ``dizgi`` | ``ad`` | ``kod`` | ``metin``."""

    result_id: str
    field: str
    kind: str
    text: str

    @property
    def ref(self) -> str:
        return f"{self.result_id}.{self.field}"


def _decode_json_strings(listing: str) -> list[str]:
    out: list[str] = []
    for m in _JSON_STRING_RE.finditer(listing):
        try:
            v = json.loads(m.group(0))
        except ValueError:
            continue
        if isinstance(v, str):
            out.append(v)
    return out


# Ad listelerinde Karadul'un yazdığı biçim sözcükleri: etiketler, "by", "... and N more", "none", "x3".
_LISTING_WORDS = frozenset({"proven", "verified", "unverified", "manual", "model", "by", "and", "more", "none"})
_COUNT_RE = re.compile(r"^x[0-9]+$")


def _listed_names(listing: str) -> list[str]:
    """Pilot biçimli ad listesindeki adlar (ithal adı, etiketli komşu adı, geri çağrı API'si);
    ``FUN_`` adresleri ve listenin biçim sözcükleri atılır."""
    out: list[str] = []
    for m in _IDENT_RE.finditer(listing):
        t = m.group(0)
        if t in _LISTING_WORDS or _COUNT_RE.fullmatch(t) or protocol.is_placeholder_name(t):
            continue
        out.append(t)
    return out


def _flatten(value: Any) -> list[str]:
    """Bilinmeyen alanın bütün dizgi değerleri (güvenli taraf: hepsi ikili kökenli sayılır)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [s for v in value.values() for s in _flatten(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _flatten(v)]
    return []


def hostile_texts(envelope: Mapping[str, Any]) -> list[HostileText]:
    """Bir sonuç zarfının ikili kökenli metinleri (alan sınıfı ``HOSTILE_FIELDS``'ten).

    Dizgi listesinden her dizgi ayrı öğe; koddan kodun tamamı (``kod``) ve her dizgi sabiti
    (``dizgi``); ad listelerinden her tanımlayıcı (``ad``); öbür alanlar ``metin``. Yapı alanları
    (``STRUCTURE_FIELDS``) atlanır; tanınmayan alan ``metin`` sayılır."""
    if not envelope.get("ok") or not isinstance(envelope.get("data"), Mapping):
        return []
    rid, tool, data = str(envelope.get("id")), str(envelope.get("tool")), envelope["data"]
    classes = HOSTILE_FIELDS.get(tool, {})
    structure = STRUCTURE_FIELDS.get(tool, frozenset())
    out: list[HostileText] = []
    for key, value in data.items():
        if key in structure:
            continue
        cls = classes.get(key, FIELD_TEXT)
        if cls == FIELD_STRINGS and isinstance(value, str):
            out += [HostileText(rid, key, "dizgi", s) for s in _decode_json_strings(value)]
        elif cls == FIELD_CODE and isinstance(value, str):
            out.append(HostileText(rid, key, "kod", value))
            out += [HostileText(rid, key, "dizgi", m.group(1)) for m in _C_STRING_RE.finditer(value)]
        elif cls == FIELD_NAMES and isinstance(value, str):
            out += [HostileText(rid, key, "ad", n) for n in _listed_names(value)]
        elif cls == FIELD_TAG_ITEMS and isinstance(value, list):
            for item in value:
                tag = item.get("name_tag") if isinstance(item, Mapping) else None
                if isinstance(tag, str):
                    out += [HostileText(rid, key, "ad", m.group(2)) for m in _TAG_RE.finditer(tag)]
        else:
            out += [HostileText(rid, key, "metin", s) for s in _flatten(value)]
    return out


def injection_hits(texts: Iterable[HostileText]) -> list[str]:
    """D13: talimat kalıbı ya da şablon işareti taşıyan metinlerin başvuruları (``r1.strings``)."""
    refs: list[str] = []
    for t in texts:
        if any(p.search(t.text) for p in INJECTION_PATTERNS) and t.ref not in refs:
            refs.append(t.ref)
    return refs


@functools.lru_cache(maxsize=1)
def library_names() -> Optional[frozenset[str]]:
    """D7 sözlüğü: imza verisindeki C çalışma zamanı fonksiyonlarının C adları; okunamazsa ``None``.

    Kaynak ``karadul.analyzers.sigdb_builtin`` (kategori başına ``SIGNATURES``; girişin ``lib``
    alanı ``C_RUNTIME_LIBS``'te). Sözlük kopyalanmaz: tek kaynak ürünün imza verisidir."""
    try:
        from karadul.analyzers.sigdb_builtin import get_category, list_categories
        names: set[str] = set()
        for cat in list_categories():
            for table in get_category(cat).values():
                if not isinstance(table, Mapping):
                    continue
                for name, entry in table.items():
                    lib = entry.get("lib") if isinstance(entry, Mapping) else None
                    if lib not in C_RUNTIME_LIBS or not isinstance(name, str):
                        continue
                    names.add(name)
                    if lib in _MACHO_ALIAS_LIBS and len(name) > 1 and name[0] == "_" and name[1] != "_":
                        names.add(name[1:])
    except Exception:  # noqa: BLE001 — sözlük yoksa kural koşmaz ve bu raporda yazılır (uydurma yok)
        return None
    return frozenset(names) if names else None


@dataclass(frozen=True)
class Finding:
    """Bir kural bulgusu. ``ref``: dayanağın sonuç kimliği + alanı; ikili ya da model metni taşımaz."""

    rule: str
    code: str
    effect: str
    ref: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return {"kural": self.rule, "kod": self.code, "etki": self.effect, "dayanak": self.ref}


@dataclass(frozen=True)
class GuardReport:
    verdict: str
    findings: tuple[Finding, ...]
    tested: tuple[str, ...]
    not_tested: dict[str, str] = field(default_factory=dict)

    @property
    def flags(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(f.code for f in self.findings if f.effect == EFFECT_FLAG))

    @property
    def bulk_accept(self) -> bool:
        """Toplu kabule girer mi: yalnız çelişkisiz hüküm ve enjeksiyon belirtisi yoksa."""
        return self.verdict == VERDICT_CLEAR and CODE_INJECTION not in self.flags

    @property
    def acceptable(self) -> bool:
        """Tek tek kabul edilebilir mi (``ret`` değil)."""
        return self.verdict != VERDICT_REJECT

    def codes(self) -> list[str]:
        return [f.code for f in self.findings]

    def as_dict(self) -> dict[str, Any]:
        return {"hukum": self.verdict, "bulgular": [f.as_dict() for f in self.findings],
                "bayraklar": list(self.flags), "toplu_kabul": self.bulk_accept,
                "sinanan": list(self.tested), "sinanmayan": dict(self.not_tested)}


def _verdict(findings: Sequence[Finding], untestable: bool) -> str:
    effects = {f.effect for f in findings}
    if EFFECT_REJECT in effects:
        return VERDICT_REJECT
    if EFFECT_CONFLICT in effects:
        return VERDICT_CONFLICT
    return VERDICT_UNTESTABLE if untestable else VERDICT_CLEAR


def protected_report(tag: str) -> GuardReport:
    """D2 ön denetimi: hedefin adı korunuyor; model çağrılmadan verilen hüküm."""
    return GuardReport(VERDICT_REJECT, (Finding("D2", PROTECTED_TAGS[tag], EFFECT_REJECT),), ("D2",),
                       dict(NOT_IMPLEMENTED))


_all_strings = _flatten


def check_proposal(answer: Mapping[str, Any], envelopes: Sequence[Mapping[str, Any]], *, target: str,
                   target_tag: Optional[tuple[str, str]], existing_functions: Mapping[str, str],
                   own_ghidra_name: str, assigned_names: Mapping[str, str], related: Iterable[str],
                   empty_content: bool, session_names: Mapping[str, str] = {},
                   rejected: Iterable[str] = (), library: Optional[frozenset[str]] = None,
                   use_library: bool = True) -> GuardReport:
    """Bir "ad öner" cevabının denetimi.

    ``answer``: ``{isim, gerekce, cekimser, kanit}``. ``envelopes``: bu görevde modele verilen sonuç
    zarfları (hata zarfları dahil). ``target``: hedefin çalışma alanı adresi (onaltılık, ``0x``'siz).
    ``target_tag``: ``Workspace.name_tag(target)``. ``existing_functions``:
    ``name_validity.existing_function_names`` sözlüğü; ``own_ghidra_name`` hedefin Ghidra adı.
    ``assigned_names``: Karadul'un ad haritası (ad → adres). ``related``: hedef ve komşularının
    adresleri. ``session_names``: bu oturumda önerilmiş adlar (küçük harfli ad → adres). ``rejected``:
    araştırmacının bu fonksiyon için reddettiği adlar. ``library``: D7 sözlüğü (verilmezse
    ``library_names()``)."""
    findings: list[Finding] = []
    tested: list[str] = []
    not_tested = dict(NOT_IMPLEMENTED)

    def add(rule: str, code: str, effect: str, ref: Optional[str] = None) -> None:
        f = Finding(rule, code, effect, ref)
        if f not in findings:
            findings.append(f)

    name = answer.get("isim")
    named = not answer.get("cekimser") and isinstance(name, str)
    ok_envs = [e for e in envelopes if e.get("ok")]
    texts = [t for e in envelopes for t in hostile_texts(e)]
    target_int = int(target, 16)

    # D2: korunan ad (ad verilmiş olsun ya da olmasın; çekimser cevapta öneri yok).
    if named:
        tested.append("D2")
        if target_tag is not None and target_tag[1] in PROTECTED_TAGS:
            add("D2", PROTECTED_TAGS[target_tag[1]], EFFECT_REJECT)

    if named:
        from karadul.reconstruction import name_validity as nv
        # D1
        tested.append("D1")
        if nv.is_c_identifier(name) and _RESERVED_RE.match(name):
            add("D1", CODE_RESERVED, EFFECT_REJECT)
        elif not protocol.NAME_RE.fullmatch(name) or not nv.is_c_identifier(name):
            add("D1", CODE_NOT_IDENTIFIER, EFFECT_REJECT)
        else:
            reason = nv.reject_reason(name, existing_functions=existing_functions, own_name=own_ghidra_name)
            if reason is not None:
                add("D1", reason, EFFECT_REJECT)
            owner = assigned_names.get(name)
            if owner is not None and int(owner, 16) != target_int:
                add("D1", CODE_COLLISION_ASSIGNED, EFFECT_REJECT)
        # D3
        tested.append("D3")
        from karadul.reconstruction.tarif.kesin import is_generic_name
        letters = [w for w in words(name) if not w.isdigit()]
        if (protocol.is_placeholder_name(name, [target_int]) or is_generic_name(name)
                or (letters and all(w in PLACEHOLDER_WORDS for w in letters))):
            add("D3", CODE_PLACEHOLDER, EFFECT_REJECT)
        # D10
        tested.append("D10")
        if name.casefold() in {r.casefold() for r in rejected if isinstance(r, str)}:
            add("D10", CODE_REJECTED_BEFORE, EFFECT_REJECT)
        # D11
        tested.append("D11")
        other = session_names.get(name.casefold())
        if other is not None and int(other, 16) != target_int:
            add("D11", CODE_SESSION_DUPLICATE, EFFECT_CONFLICT)
        # D6: dizgiden ya da ikili kökenli simgeden ad
        tested.append("D6")
        name_words = words(name)
        name_set = set(name_words)
        for t in texts:
            if t.kind == "dizgi" and name_set and name_set <= set(words(t.text)):
                add("D6", CODE_FROM_STRING, EFFECT_CONFLICT, t.ref)
            elif t.kind == "metin" and name_set and name_set <= set(words(t.text)):
                add("D6", CODE_FROM_STRING, EFFECT_CONFLICT, t.ref)
            elif t.kind in ("kod", "ad"):
                for ident in ({t.text} if t.kind == "ad" else set(_IDENT_RE.findall(t.text))):
                    label = _GHIDRA_STRING_LABEL_RE.match(ident)
                    if label and name_set and name_set <= set(words(label.group(1))):
                        add("D6", CODE_FROM_STRING, EFFECT_CONFLICT, t.ref)
                    elif ident.casefold() == name.casefold():
                        add("D6", CODE_SYMBOL_COPY, EFFECT_CONFLICT, t.ref)
        # D7: kütüphane adı (D1'de ithal adı olarak zaten reddedilmediyse)
        lib = library if library is not None else (library_names() if use_library else None)
        if lib is None:
            not_tested["D7"] = "kütüphane sözlüğü okunamadı"
        else:
            tested.append("D7")
            if name in lib and not any(f.code == nv.REASON_COLLISION for f in findings):
                add("D7", CODE_LIBRARY, EFFECT_CONFLICT)
        # D8: kanıt atfı
        tested.append("D8")
        refs = [r for r in (answer.get("kanit") or []) if isinstance(r, str)]
        by_id = {str(e.get("id")): e for e in ok_envs}
        if not refs:
            add("D8", CODE_NO_REFS, EFFECT_CONFLICT)
        else:
            unknown = [r for r in refs if r not in by_id]
            for r in unknown:
                add("D8", CODE_UNKNOWN_REF, EFFECT_CONFLICT, r)
            rel = {int(x, 16) for x in related} | {target_int}
            cited = [by_id[r] for r in refs if r in by_id]
            addrs = [_env_addr(e) for e in cited]
            if cited and all(a is not None and a not in rel for a in addrs):
                add("D8", CODE_UNRELATED_REFS, EFFECT_CONFLICT, ",".join(r for r in refs if r in by_id))
        # D14: gösterilen sonuçlardaki adlı komşuların hepsi model kökenli
        tested.append("D14")
        cited_ids = set(refs)
        tags: list[str] = []
        for e in ok_envs:
            if str(e.get("id")) in cited_ids:
                for s in _all_strings(e.get("data")):
                    tags += [m.group(1) for m in _TAG_RE.finditer(s)]
        if tags and all(tg == TAG_MODEL for tg in tags):
            add("D14", CODE_MODEL_ONLY, EFFECT_FLAG)

    # D9: gerekçedeki görülmemiş olgu (ad veren ve çekimser cevapta)
    rationale = answer.get("gerekce")
    if isinstance(rationale, str) and rationale:
        tested.append("D9")
        seen_values = [s for e in ok_envs for s in _all_strings(e.get("data"))]
        seen_ints = {target_int}
        for s in seen_values:
            seen_ints |= {int(h, 16) for h in _FUN_HEX_RE.findall(s)}
        for h in _FUN_HEX_RE.findall(rationale):
            if int(h, 16) not in seen_ints:
                add("D9", CODE_UNSEEN_ADDRESS, EFFECT_CONFLICT)
        folded = [s.casefold() for s in seen_values]
        for m in _QUOTED_RE.finditer(rationale):
            q = m.group(1).strip().casefold()
            if q and not any(q in s for s in folded):
                add("D9", CODE_UNSEEN_QUOTE, EFFECT_CONFLICT)
        idents = {i for s in seen_values for i in _IDENT_RE.findall(s)}
        for m in _CALL_LIKE_RE.finditer(rationale):
            if m.group(1) not in idents:
                add("D9", CODE_UNSEEN_CALL, EFFECT_CONFLICT)

    # D12: kuşkulu decompile (hedefin kodunda Ghidra uyarısı)
    tested.append("D12")
    for e in ok_envs:
        d = e.get("data")
        if e.get("tool") == "get_decompiled" and isinstance(d, Mapping) and _env_addr(e) == target_int \
                and isinstance(d.get("ghidra_warning_total"), int) and d["ghidra_warning_total"] > 0:
            add("D12", CODE_SUSPICIOUS_DECOMPILE, EFFECT_FLAG, f"{e.get('id')}.ghidra_warnings")
            break

    # D13: enjeksiyon belirtisi (görevin bütün sonuçlarında)
    tested.append("D13")
    for ref in injection_hits(texts):
        add("D13", CODE_INJECTION, EFFECT_FLAG, ref)

    # D0: kanıt yeterliliği. Yalnız hiçbir kural çelişki bulmadıysa hükmü belirler.
    tested.insert(0, "D0")
    return GuardReport(_verdict(findings, empty_content), tuple(findings), tuple(dict.fromkeys(tested)),
                       not_tested)


def _env_addr(envelope: Mapping[str, Any]) -> Optional[int]:
    d = envelope.get("data")
    a = d.get("addr") if isinstance(d, Mapping) else None
    if isinstance(a, str) and a.startswith("FUN_"):
        try:
            return int(a[4:], 16)
        except ValueError:
            return None
    return None
