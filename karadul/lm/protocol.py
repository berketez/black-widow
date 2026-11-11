"""KaradulLM tur protokolü: şema, doğrulama, ayrıştırma ve onarım kuralı (tasarım §3.1, §2.2).

Üç parça:

1. **Pilot kopyası** (``scripts/measurement/llm_pilot.py:498-557``): düşünme bloğu ayıklama
   (``think_end``), ilk dengeli JSON nesnesi (``first_json``) ve "ad öner" cevabının ön kayıtlı durum
   sınıfları (``parse_name_answer``). Jenerik ad kuralı ``scripts/measurement/function_f1.py:136-164``
   ve ``tests/benchmark/metrics.py:647-663`` kopyasıdır (``is_placeholder_name``). Ürün ölçüm
   betiğini içe aktaramaz (kural: ``karadul/reconstruction/tarif/alt_kanal.py:20-27``); iki kopyanın
   eşitliği ``tests/test_lm_protocol.py`` ile kilitlidir. Pilot değişmez; kopyalar da değişmez.
2. **Şema**: tasarım §3.1 Yol A'nın düz ``anyOf`` zarfı (araç başına bir nesne + ``final``; ortak
   ``properties`` yok) ve "ad öner" cevap şeması. Şemalar yalnız ``SUPPORTED_KEYWORDS`` alt kümesini
   kullanabilir: llama.cpp desteklemediği özelliği sessizce atlıyor (tasarım §3.1, [K-D1]); burada
   bilinmeyen anahtar sözcük hata verir. Doğrulayıcı kendi yazılmıştır (zorunlu bağımlılık yok).
3. **Yetenek düzeyine göre kural** (tasarım §2.2): L3 şemayı ``response_format`` ile zorlar; L2 yalnız
   ``json_object`` alır, şema sunucu tarafında doğrulanır ve **bir kez** onarım turu açılır; L1 düz
   metindir, ilk dengeli JSON nesnesi okunur, yeniden deneme yoktur.

Model çıktısı veridir: onarım iletisi modelin yazdığı değeri geri yansıtmaz, yalnız alan yolu ve
kuralın adı gider.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

from karadul.lm import RATIONALE_MAX_CHARS

# ============================================================================================
# 1. Pilot kopyası (llm_pilot.py:498-557). DEĞİŞTİRME: eşitlik testi pilotla karşılaştırır.
# ============================================================================================

# Qwen ``<think>…</think>``, Gemma 4 ``<|channel>thought…<channel|>``; kapanmamış blok metnin sonuna
# kadar sürer (model düşünürken bütçe bitti, cevap yok). llm_pilot.py:500 ``_DUSUNME_BLOKU``.
THINK_BLOCK_RE = re.compile(r"<think>.*?(?:</think>|\Z)|<\|channel>.*?(?:<channel\|>|\Z)", re.S)
# llm_pilot.py:68-69 ``RET_KALIPLARI``
REFUSAL_PATTERNS = ("i can't", "i cannot", "i won't", "unable to assist", "not able to help",
                    "against policy", "malicious")
# llm_pilot.py:72 ``_ISIM``
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def think_end(text: str) -> int:
    """Son düşünme bloğunun bittiği konum (blok yoksa 0); cevap bu konumdan sonra aranır.
    Kopya: ``llm_pilot.dusunme_sonu``."""
    end = 0
    for m in THINK_BLOCK_RE.finditer(text):
        end = m.end()
    return end


def first_json(text: str, start: int = 0) -> tuple[Optional[dict], int, int]:
    """``start``'tan sonraki ilk dengeli JSON nesnesi ve ham metindeki konumları.
    Kopya: ``llm_pilot.ilk_json``."""
    dec = json.JSONDecoder()
    i = text.find("{", start)
    while i != -1:
        try:
            obj, end = dec.raw_decode(text, i)
            if isinstance(obj, dict):
                return obj, i, end
        except json.JSONDecodeError:
            pass
        i = text.find("{", i + 1)
    return None, -1, -1


def parse_name_answer(content: Optional[str], finish_reason: Optional[str], *, abstain_allowed: bool,
                      address: Any) -> dict[str, Any]:
    """"Ad öner" cevabının ön kayıtlı durum sınıfları (``pilot_protokolu.md`` §5).

    Kopya: ``llm_pilot.ayristir``. Pilotun ``kosul`` argümanı yerine ``abstain_allowed``: pilotta ek
    ``cekimser`` olan koşullar ``True``, ``zorunlu`` olanlar ``False``. ``address`` fonksiyonun adresidir
    (``0x…``, ``FUN_…`` ya da tamsayı); jenerik ad kuralı kendi adresini taşıyan adı yakalamak için
    kullanır. Dönen sözlük pilotunkiyle aynı anahtarları taşır.
    """
    metin = content or ""
    cevap_bas = think_end(metin)
    obj, bas, son = first_json(metin, cevap_bas)
    sonuc: dict[str, Any] = {"durum": "gecersiz", "isim": None, "gerekce": None, "cekimser": None,
                             "json_bas": bas, "json_son": son}
    if obj is None:
        if finish_reason == "length":
            sonuc["durum"] = "butce_asimi"
        elif any(k in metin[cevap_bas:].lower() for k in REFUSAL_PATTERNS):
            sonuc["durum"] = "ret"
        return sonuc
    if not {"isim", "gerekce", "cekimser"} <= set(obj) or not isinstance(obj["cekimser"], bool):
        return sonuc
    sonuc["gerekce"] = obj["gerekce"] if isinstance(obj["gerekce"], str) else None
    sonuc["cekimser"] = obj["cekimser"]
    if obj["cekimser"]:
        if not abstain_allowed:
            sonuc["durum"] = "zorunluyken_cekimser"
        elif obj["isim"] is None:
            sonuc["durum"] = "cekimser"
        return sonuc
    isim = obj["isim"]
    if not isinstance(isim, str) or not NAME_RE.match(isim):
        return sonuc
    sonuc["isim"] = isim
    sonuc["durum"] = "jenerik" if is_placeholder_name(isim, [address_to_int(address)]) else "gecerli"
    return sonuc


def address_to_int(address: Any) -> int:
    """``0x100012340``, ``100012340``, ``FUN_100012340`` ya da tamsayı → tamsayı adres."""
    if isinstance(address, bool):
        raise ValueError("adres mantıksal değer olamaz")
    if isinstance(address, int):
        return address
    s = str(address)
    if s.startswith("FUN_"):
        s = s[4:]
    return int(s, 16)


# --- Jenerik ad kuralı: function_f1.is_generic_name (+ metrics._UNNAMED_PATTERNS) kopyası ------

# tests/benchmark/metrics.py:647-657 ``AccuracyCalculator._UNNAMED_PATTERNS``
_UNNAMED_PATTERNS = (
    re.compile(r"^FUN_[0-9a-fA-F]+$"),
    re.compile(r"^sub_[0-9a-fA-F]+$"),
    re.compile(r"^var_[0-9a-fA-F]+$"),
    re.compile(r"^local_[0-9a-fA-F]+$"),
    re.compile(r"^param_\d+$"),
    re.compile(r"^DAT_[0-9a-fA-F]+$"),
    re.compile(r"^field_0x[0-9a-fA-F]+$"),
    re.compile(r"^PTR_[0-9a-fA-F]+$"),
    re.compile(r"^[a-z]Var\d+$"),
)
# scripts/measurement/function_f1.py:102-108 ``_EXTRA_GENERIC_PATTERNS``
_EXTRA_GENERIC_PATTERNS = (
    re.compile(r"^thunk_FUN_[0-9a-fA-F]+$"),
    re.compile(r"^(?:LAB|caseD|switchD)_[0-9a-fA-F]+"),
    re.compile(r"^_(?:INIT|FINI)_\d+$"),
    re.compile(r"^_DT_(?:INIT|FINI)$"),
    re.compile(r"^entry$"),
)
# function_f1.py:109 ``_HEX_TOKEN_RE``
_HEX_TOKEN_RE = re.compile(r"^[0-9a-f]{4,}$")


def _embeds_own_address(name: str, addresses: Iterable[int]) -> bool:
    """Ad fonksiyonun kendi adresinin son onaltılık basamaklarını sözcük olarak taşıyor mu?
    Kopya: ``function_f1._embeds_own_address``."""
    hexes = [f"{a:x}" for a in addresses if a]
    if not hexes:
        return False
    for tok in re.split(r"[_.]", name.lower()):
        if not _HEX_TOKEN_RE.match(tok):
            continue
        for h in hexes:
            if h.zfill(len(tok)).endswith(tok):
                return True
    return False


def is_placeholder_name(name: Optional[str], addresses: Iterable[int] = ()) -> bool:
    """Ad bir kimlik iddiası değil mi (yer tutucu / oto-ad / adres etiketi)?
    Kopya: ``function_f1.is_generic_name``."""
    if not name or not name.strip():
        return True
    if any(p.match(name) for p in _UNNAMED_PATTERNS):
        return True
    if any(p.match(name) for p in _EXTRA_GENERIC_PATTERNS):
        return True
    return _embeds_own_address(name, addresses)


# ============================================================================================
# 2. Şema: desteklenen alt küme, doğrulayıcı, zarf
# ============================================================================================

SUPPORTED_KEYWORDS = frozenset({
    "type", "const", "enum", "pattern", "minLength", "maxLength", "minimum", "maximum",
    "properties", "required", "additionalProperties", "items", "minItems", "maxItems", "anyOf",
    "description",
})
_JSON_TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})


class SchemaError(ValueError):
    """Şema, desteklenen alt kümenin dışında."""


@dataclass(frozen=True)
class Issue:
    """Doğrulama bulgusu: alanın yolu ve çiğnenen kural. Modelin yazdığı değeri taşımaz."""

    path: str
    rule: str

    def describe(self) -> str:
        """Modele gidecek İngilizce açıklama (sistem istemi İngilizce, tasarım §4.1)."""
        return f"{self.path}: violates '{self.rule}'"


def check_schema(schema: Any, path: str = "$") -> None:
    """Şemanın desteklenen alt kümede kaldığını denetler; değilse ``SchemaError``.

    Kurallar (tasarım §3.1, [K-D1]): bilinmeyen anahtar sözcük yok; ``$ref`` yok; ``pattern`` ``^…$``
    biçiminde; aynı düzeyde ``properties`` ile ``anyOf`` birlikte yok; ``properties`` taşıyan her
    nesne ``additionalProperties``'i açıkça yazar (llama.cpp öntanımı ile JSON Schema öntanımı farklı).
    """
    problems: list[str] = []
    _check(schema, path, problems)
    if problems:
        raise SchemaError("; ".join(problems))


def _check(s: Any, path: str, problems: list[str]) -> None:
    if not isinstance(s, Mapping):
        problems.append(f"{path}: şema nesne olmalı")
        return
    for k in s:
        if k not in SUPPORTED_KEYWORDS:
            problems.append(f"{path}: desteklenmeyen anahtar sözcük {k!r}")
    t = s.get("type")
    for tt in (t if isinstance(t, list) else [t] if t is not None else []):
        if tt not in _JSON_TYPES:
            problems.append(f"{path}: bilinmeyen tip {tt!r}")
    if "pattern" in s:
        p = s["pattern"]
        if not isinstance(p, str) or not (p.startswith("^") and p.endswith("$")):
            problems.append(f"{path}: pattern ^…$ biçiminde olmalı")
        else:
            try:
                re.compile(p)
            except re.error:
                problems.append(f"{path}: pattern derlenemedi")
    if "properties" in s and "anyOf" in s:
        problems.append(f"{path}: properties ile anyOf aynı düzeyde")
    if "properties" in s:
        if "additionalProperties" not in s:
            problems.append(f"{path}: additionalProperties açıkça yazılmalı")
        props = s["properties"]
        if not isinstance(props, Mapping):
            problems.append(f"{path}.properties: nesne olmalı")
        else:
            for name, sub in props.items():
                _check(sub, f"{path}.{name}", problems)
        for r in s.get("required", []):
            if not isinstance(props, Mapping) or r not in props:
                problems.append(f"{path}: required {r!r} properties içinde yok")
    ap = s.get("additionalProperties")
    if isinstance(ap, Mapping):
        _check(ap, f"{path}.*", problems)
    elif ap is not None and not isinstance(ap, bool):
        problems.append(f"{path}: additionalProperties mantıksal ya da şema olmalı")
    if "items" in s:
        _check(s["items"], f"{path}[]", problems)
    if "anyOf" in s:
        branches = s["anyOf"]
        if not isinstance(branches, list) or not branches:
            problems.append(f"{path}: anyOf boş olmayan liste olmalı")
        else:
            for i, b in enumerate(branches):
                _check(b, f"{path}|{i}", problems)
    if "enum" in s and (not isinstance(s["enum"], list) or not s["enum"]):
        problems.append(f"{path}: enum boş olmayan liste olmalı")


def json_equal(a: Any, b: Any) -> bool:
    """JSON değer eşitliği: ``true`` ile ``1`` ve ``false`` ile ``0`` eşit DEĞİL (Python'da eşit)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


def _type_ok(value: Any, t: str) -> bool:
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "null":
        return value is None
    if t == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (
            isinstance(value, float) and value.is_integer())
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def validate(value: Any, schema: Mapping[str, Any], path: str = "$") -> list[Issue]:
    """Değeri şemayla denetler; bulgu listesi (boşsa geçerli). Şema önceden ``check_schema``'dan
    geçmiş sayılır."""
    issues: list[Issue] = []
    if "anyOf" in schema:
        best: Optional[list[Issue]] = None
        for branch in schema["anyOf"]:
            sub = validate(value, branch, path)
            if not sub:
                best = []
                break
            if best is None or len(sub) < len(best):
                best = sub
        if best:
            issues.append(Issue(path, "anyOf"))
            issues.extend(best)
    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_type_ok(value, tt) for tt in types):
            return issues + [Issue(path, "type")]
    if "const" in schema and not json_equal(value, schema["const"]):
        issues.append(Issue(path, "const"))
    if "enum" in schema and not any(json_equal(value, e) for e in schema["enum"]):
        issues.append(Issue(path, "enum"))
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            issues.append(Issue(path, "pattern"))
        if "minLength" in schema and len(value) < schema["minLength"]:
            issues.append(Issue(path, "minLength"))
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            issues.append(Issue(path, "maxLength"))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            issues.append(Issue(path, "minimum"))
        if "maximum" in schema and value > schema["maximum"]:
            issues.append(Issue(path, "maximum"))
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for r in schema.get("required", []):
            if r not in value:
                issues.append(Issue(f"{path}.{r}", "required"))
        ap = schema.get("additionalProperties", True)
        for k, v in value.items():
            if k in props:
                issues.extend(validate(v, props[k], f"{path}.{k}"))
            elif ap is False:
                issues.append(Issue(f"{path}.{k}", "additionalProperties"))
            elif isinstance(ap, Mapping):
                issues.extend(validate(v, ap, f"{path}.{k}"))
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            issues.append(Issue(path, "minItems"))
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            issues.append(Issue(path, "maxItems"))
        if "items" in schema:
            for i, v in enumerate(value):
                issues.extend(validate(v, schema["items"], f"{path}[{i}]"))
    return issues


def matching_branches(value: Any, schema: Mapping[str, Any]) -> list[int]:
    """Üst düzey ``anyOf`` dallarından değerin uyduklarının sıra numaraları."""
    return [i for i, b in enumerate(schema.get("anyOf", [])) if not validate(value, b)]


def call_branch(tool: str, args_schema: Mapping[str, Any]) -> dict[str, Any]:
    """Zarfın bir araç dalı: ``{"kind": "call", "tool": <ad>, "args": {...}}``."""
    return {"type": "object",
            "properties": {"kind": {"const": "call"}, "tool": {"const": tool}, "args": dict(args_schema)},
            "required": ["kind", "tool", "args"], "additionalProperties": False}


def final_branch(properties: Mapping[str, Any], required: Sequence[str]) -> dict[str, Any]:
    """Zarfın ``final`` dalı: ``{"kind": "final", ...}``."""
    props = {"kind": {"const": "final"}, **dict(properties)}
    return {"type": "object", "properties": props, "required": ["kind", *required],
            "additionalProperties": False}


def build_envelope(tools: Mapping[str, Mapping[str, Any]], final_properties: Mapping[str, Any],
                   final_required: Sequence[str]) -> dict[str, Any]:
    """Tasarım §3.1 Yol A zarfı: en üstte ``anyOf`` ile araç başına bir nesne ve bir ``final``;
    ortak ``properties`` yok. Araç adları benzersiz olmalı (``dict`` anahtarları)."""
    if not tools:
        raise SchemaError("zarf en az bir araç ister")
    envelope = {"anyOf": [*(call_branch(name, args) for name, args in tools.items()),
                          final_branch(final_properties, final_required)]}
    check_schema(envelope)
    return envelope


# "Ad öner" cevabı (tasarım §3.1 son madde): pilotun {isim, gerekce, cekimser} şeması + kanit (sonuç
# kimlikleri, arac_sozlesmeleri.md §1.3 "r7" biçimi). İki düz dal: ad veren ve çekimser.
RESULT_ID_PATTERN = "^r[0-9]{1,9}$"
_RATIONALE = {"type": "string", "maxLength": RATIONALE_MAX_CHARS}
_REFS = {"type": "array", "items": {"type": "string", "pattern": RESULT_ID_PATTERN}}
NAME_ANSWER_SCHEMA: dict[str, Any] = {"anyOf": [
    {"type": "object",
     "properties": {"isim": {"type": "string", "pattern": NAME_RE.pattern}, "gerekce": _RATIONALE,
                    "cekimser": {"const": False}, "kanit": _REFS},
     "required": ["isim", "gerekce", "cekimser", "kanit"], "additionalProperties": False},
    {"type": "object",
     "properties": {"isim": {"type": "null"}, "gerekce": _RATIONALE, "cekimser": {"const": True},
                    "kanit": _REFS},
     "required": ["isim", "gerekce", "cekimser", "kanit"], "additionalProperties": False},
]}


# ============================================================================================
# 3. Tur ayrıştırma ve yetenek düzeyine göre kural
# ============================================================================================

CAPABILITY_LEVELS = ("L1", "L2", "L3")
# Düzey başına izin verilen onarım turu sayısı (tasarım §2.2): yalnız L2'de bir kez.
MAX_REPAIRS = {"L1": 0, "L2": 1, "L3": 0}
# Onarım yalnız biçim hatasında: JSON yok ya da şemaya uymuyor. Bütçe aşımı ve ret onarılmaz.
REPAIRABLE = frozenset({"gecersiz", "sema_ihlali"})
ACTION_ACCEPT, ACTION_REPAIR, ACTION_GIVE_UP = "kabul", "onar", "vazgec"


@dataclass(frozen=True)
class TurnParse:
    """Bir model turunun ayrıştırma sonucu.

    ``status``: ``gecerli`` | ``sema_ihlali`` (JSON var, şemaya uymuyor) | ``gecersiz`` (JSON yok) |
    ``butce_asimi`` (JSON yok, üretim tavanına çarptı) | ``ret`` (reddetme kalıbı).
    """

    status: str
    obj: Optional[dict]
    branch: Optional[int]
    issues: tuple[Issue, ...]
    json_start: int
    json_end: int


def parse_turn(content: Optional[str], finish_reason: Optional[str], schema: Mapping[str, Any]) -> TurnParse:
    """Model turunu ayrıştırır: düşünme bloğu atılır, ilk dengeli JSON nesnesi okunur
    (``llm_pilot.py:511``), şemayla denetlenir. Her düzeyde aynı yol; düzey yalnız sonraki eylemi
    değiştirir (``next_action``)."""
    text = content or ""
    start = think_end(text)
    obj, b, e = first_json(text, start)
    if obj is None:
        if finish_reason == "length":
            status = "butce_asimi"
        elif any(k in text[start:].lower() for k in REFUSAL_PATTERNS):
            status = "ret"
        else:
            status = "gecersiz"
        return TurnParse(status, None, None, (), b, e)
    issues = tuple(validate(obj, schema))
    branches = matching_branches(obj, schema) if "anyOf" in schema else []
    branch = branches[0] if len(branches) == 1 else None
    return TurnParse("sema_ihlali" if issues else "gecerli", obj, branch, issues, b, e)


def next_action(level: str, parsed: TurnParse, repairs_done: int) -> str:
    """Tek onarım turu kuralı: ``kabul`` | ``onar`` | ``vazgec``.

    L2'de biçim hatası ilk kez görülürse ``onar``; L1'de yeniden deneme yok; L3'te şema dilbilgisiyle
    zorlandığı için onarım yok. Bütçe aşımı ve ret hiçbir düzeyde onarılmaz.
    """
    if level not in MAX_REPAIRS:
        raise ValueError(f"bilinmeyen yetenek düzeyi: {level!r}")
    if parsed.status == "gecerli":
        return ACTION_ACCEPT
    if parsed.status in REPAIRABLE and repairs_done < MAX_REPAIRS[level]:
        return ACTION_REPAIR
    return ACTION_GIVE_UP


def repair_message(parsed: TurnParse) -> dict[str, str]:
    """Onarım turunun kullanıcı iletisi. Modelin yazdığı değer geri gönderilmez; yalnız alan yolu ve
    kural adı (model çıktısı veridir, tasarım §6)."""
    if parsed.status == "gecersiz":
        reason = "it did not contain a JSON object"
    else:
        reason = "it did not match the required schema: " + "; ".join(i.describe() for i in parsed.issues)
    return {"role": "user",
            "content": f"Your previous reply was rejected because {reason}. "
                       "Reply again with exactly one JSON object that matches the schema, and nothing else."}


def response_format_for(level: Optional[str], schema: Optional[Mapping[str, Any]],
                        name: str = "zarf") -> Optional[dict[str, Any]]:
    """İstek gövdesinin ``response_format`` alanı: L3 şema (zemin denemesindeki biçim:
    ``json_schema`` + ``strict``), L2 ``json_object``, L1 yok."""
    if schema is None or level == "L1":
        return None
    if level == "L3":
        check_schema(schema)
        return {"type": "json_schema", "json_schema": {"name": name, "strict": True, "schema": dict(schema)}}
    if level == "L2":
        return {"type": "json_object"}
    raise ValueError(f"bilinmeyen yetenek düzeyi: {level!r}")
