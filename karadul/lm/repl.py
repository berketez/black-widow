"""KaradulLM kısıtlı terminali: komut ayrıştırıcısı ve satır biçimi (KaradulLM v2 tasarımı §4.3, §4.4; P22e kalem 4).

**Terminal kabuk değildir.** Arayüzün terminal paneli tek bir komut kabul eder: tam olarak ``karadullm``
(``is_allowed_command``; izin listesi tek öğe, harf duyarlı, argümansız). Bu komut süreç başlatmaz;
arayüz sunucusunun içinde bir KaradulLM oturumu açar (``session.open_session``). Oturum açıkken girilen
her satır yalnız ``parse``'a verilir; ``parse``'ın çıktısı kapalı bir komut kümesidir (``COMMANDS``) ya da
keşif kipinde "soru"dur. Hiçbir girdi kabuğa, ``eval``'e ya da süreç çağrısına ulaşmaz (durağan sınama:
``tests/test_lm_izin.py``).

**Girdi sınırları** (``check_text``; §4.3 G4): en çok ``INPUT_MAX_CHARS`` (2 000) karakter; denetim
karakterleri (C0, C1, DEL; satır sonu ve sekme dahil), biçim karakterleri (yön değiştiren U+202A-E,
U+2066-9, sıfır genişlikliler, BOM), vekil ve özel kullanım alanı, atanmamış kod noktaları, satır / paragraf
ayırıcıları, U+0020 dışındaki boşluklar ve görünmez dolgu harfleri REDDEDİLİR. Atılıp sessizce devam
edilmez: ``kara\\u200bdullm`` gibi bir girdinin anlamı değişmesin, analist ne yazdığını görsün.

**Satır biçimi** (``render``; §4.4): olaylardan terminal satırları. Olaylar sunucuda zaten arındırılmıştır
(``events.display_text``); arayüz yine yalnız ``textContent`` kullanır. "Ne düşündü" satırı yoktur: gösterilen
yalnız modelin yazdıklarıdır (``niyet``, cevap alanları) ve sayılar olaylardaki gerçek değerlerdir.

Bu modül süreç başlatmaz, ağa çıkmaz, dosya yazmaz.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from karadul.lm import DISPLAY_TEXT_MAX_CHARS
from karadul.lm.audit import sha256_text
from karadul.lm.order import DEFAULT_CLOSURE_DEPTH
from karadul.lm.protocol import RESULT_ID_PATTERN
from karadul.lm.tools import ADDR_PATTERN, IMPORT_NAME_MAX_CHARS, SEARCH_TEXT_MAX_CHARS, SEARCH_TEXT_MIN_CHARS

# --- İzin listesi (§4.3 G2) -------------------------------------------------------------------------
TERMINAL_COMMAND = "karadullm"
ALLOWED_COMMANDS = frozenset({TERMINAL_COMMAND})
# Terminal girdisinin tavanı (§4.3 G4 [seçim] 2 000). Olay metninin görüntü tavanıyla aynı sayıdır ve
# ``karadul/lm/__init__.py``'de o adla tanımlıdır (tek kaynak).
INPUT_MAX_CHARS = DISPLAY_TEXT_MAX_CHARS

# U+0020 dışında görünmeyen ya da boşluk gibi görünen, kategorisi Cf / Cc olmayan kod noktaları (dolgu
# harfleri, değişke seçicileri, birleştirici yerleştirici). Hepsi reddedilir.
_INVISIBLE = frozenset({0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0, *range(0x180B, 0x1810),
                        *range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)})
_REJECTED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


class InputError(ValueError):
    """Terminal girdisi kabul edilmedi; ileti analiste gösterilir (Türkçe)."""


def _bad_char(ch: str) -> Optional[str]:
    cat = unicodedata.category(ch)
    if cat in _REJECTED_CATEGORIES or ord(ch) in _INVISIBLE or (cat == "Zs" and ch != " "):
        return f"U+{ord(ch):04X}"
    return None


def check_text(text: Any, max_chars: int = INPUT_MAX_CHARS) -> str:
    """Girdiyi denetler, olduğu gibi döndürür; uymazsa ``InputError`` (hangi karakter, kaçıncı konum)."""
    if not isinstance(text, str):
        raise InputError("girdi metin olmalı")
    if len(text) > max_chars:
        raise InputError(f"girdi çok uzun: {len(text)} karakter (en çok {max_chars})")
    for i, ch in enumerate(text):
        bad = _bad_char(ch)
        if bad is not None:
            raise InputError(f"girdide izin verilmeyen karakter: {bad} ({i + 1}. konum); satır reddedildi")
    return text


def is_allowed_command(text: Any) -> bool:
    """Terminalin başlatma komutu mu: yalnız ``karadullm`` (baştaki / sondaki U+0020 boşluklar dışında hiçbir
    ek yok; harf duyarlı; denetim ya da görünmez karakterli girdi hayır)."""
    try:
        check_text(text)
    except InputError:
        return False
    return text.strip(" ") in ALLOWED_COMMANDS


def command_audit_fields(text: Any) -> dict[str, Any]:
    """Reddedilen komutun denetim kaydı alanları: metin yazılmaz, yalnız uzunluk ve sha256 (§4.3 G3)."""
    s = text if isinstance(text, str) else repr(type(text).__name__)
    return {"uzunluk": len(s), "sha256": sha256_text(s)}


# --- Komutlar (§4.4 kapalı küme) ------------------------------------------------------------------
CMD_MODE, CMD_EXPLAIN, CMD_NAME, CMD_SUMMARY, CMD_PLAN = "kip", "acikla", "ad", "ozet", "plan"
CMD_APPROVE, CMD_STOP, CMD_PROPOSALS, CMD_OPEN, CMD_NOTE = "onayla", "durdur", "oneriler", "ac", "not"
CMD_SPEED, CMD_FOLLOW, CMD_HELP, CMD_EXIT, CMD_QUESTION = "hiz", "takip", "yardim", "cik", "soru"
COMMANDS = (CMD_MODE, CMD_EXPLAIN, CMD_NAME, CMD_SUMMARY, CMD_PLAN, CMD_APPROVE, CMD_STOP, CMD_PROPOSALS,
            CMD_OPEN, CMD_NOTE, CMD_SPEED, CMD_FOLLOW, CMD_HELP, CMD_EXIT)
# Yazım biçimleri (Türkçe harfli ve ASCII); ikisi de aynı komuta gider. Liste kapalıdır.
_ALIASES = {**{f"/{c}": c for c in COMMANDS}, "/açıkla": CMD_EXPLAIN, "/özet": CMD_SUMMARY,
            "/öneriler": CMD_PROPOSALS, "/aç": CMD_OPEN, "/hız": CMD_SPEED, "/yardım": CMD_HELP, "/çık": CMD_EXIT}
_MODE_ALIASES = {"kesif": "kesif", "keşif": "kesif", "acikla": "acikla", "açıkla": "acikla",
                 "adlandir": "adlandir", "adlandır": "adlandir", "plan": "plan"}
_FOLLOW_ALIASES = {"ac": True, "aç": True, "kapat": False}
PLAN_IMPORT, PLAN_STRING = "ithal", "dizgi"
PLAN_TASK_EXPLAIN, PLAN_TASK_NAME = "acikla", "ad_oner"
_PLAN_TASKS = {"acikla": PLAN_TASK_EXPLAIN, "açıkla": PLAN_TASK_EXPLAIN, "ad": PLAN_TASK_NAME}
_ADDR = re.compile(ADDR_PATTERN)
_RID = re.compile(RESULT_ID_PATTERN)
_IMPORT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$@]*$")
_MENTION = re.compile(r"@(FUN_[0-9a-fA-F]{3,16})(?![0-9A-Za-z_])")
_SHOWN_NAME_MAX = 32   # hata iletisinde gösterilen bilinmeyen komut adının tavanı


@dataclass(frozen=True)
class Command:
    """Ayrıştırılmış satır. ``ad`` ``COMMANDS`` ya da ``soru``; alanlar komuta göre dolar."""

    ad: str
    hedef: Optional[str] = None          # FUN_<adres> (yazıldığı gibi; çözümü oturum yapar)
    derinlik: Optional[int] = None
    metin: Optional[str] = None          # not metni, soru, plan dizgisi
    kip: Optional[str] = None
    sonuc: Optional[str] = None          # /ac r<n>
    takip: Optional[bool] = None
    plan_turu: Optional[str] = None      # ithal | dizgi
    plan_gorevi: Optional[str] = None    # acikla | ad_oner
    anmalar: tuple[str, ...] = field(default_factory=tuple)   # soru içindeki @FUN_… anmaları


def _fun(tok: str, cmd: str) -> str:
    if not _ADDR.fullmatch(tok):
        raise InputError(f"/{cmd}: hedef FUN_<adres> biçiminde olmalı")
    return tok


def _depth(tok: str, cmd: str) -> int:
    if not tok.isascii() or not tok.isdigit() or int(tok) > DEFAULT_CLOSURE_DEPTH:
        raise InputError(f"/{cmd}: derinlik 0-{DEFAULT_CLOSURE_DEPTH} arası bir tamsayı olmalı")
    return int(tok)


def _arity(args: list[str], lo: int, hi: int, cmd: str, usage: str) -> None:
    if not lo <= len(args) <= hi:
        raise InputError(f"kullanım: {usage}")


def parse(line: Any, mode: str) -> Command:
    """Bir terminal satırını ayrıştırır. ``mode``: oturumun kipi (keşif dışında serbest metin soru değildir).
    Uymayan satır ``InputError`` (ileti Türkçe, analiste gösterilir); hiçbir satır kabuğa gitmez."""
    text = check_text(line).strip(" ")
    if not text:
        raise InputError("boş satır")
    if not text.startswith("/"):
        if mode != "kesif":
            raise InputError("serbest metin yalnız keşif kipinde soru sayılır; komutlar için /yardim")
        return Command(CMD_QUESTION, metin=text, anmalar=tuple(dict.fromkeys(_MENTION.findall(text))))
    head, _, rest = text.partition(" ")
    cmd = _ALIASES.get(head)
    if cmd is None:
        shown = head if len(head) <= _SHOWN_NAME_MAX else head[:_SHOWN_NAME_MAX] + "…"
        raise InputError(f"bilinmeyen komut: {shown} (/yardim)")
    args = [t for t in rest.split(" ") if t]
    if cmd == CMD_MODE:
        _arity(args, 1, 1, cmd, "/kip kesif|acikla|adlandir|plan")
        if args[0] not in _MODE_ALIASES:
            raise InputError("kip: kesif, acikla, adlandir ya da plan")
        return Command(cmd, kip=_MODE_ALIASES[args[0]])
    if cmd in (CMD_EXPLAIN, CMD_SUMMARY):
        _arity(args, 1, 2, cmd, f"/{cmd} FUN_<adres> [derinlik 0-{DEFAULT_CLOSURE_DEPTH}]")
        return Command(cmd, hedef=_fun(args[0], cmd),
                       derinlik=_depth(args[1], cmd) if len(args) == 2 else DEFAULT_CLOSURE_DEPTH)
    if cmd == CMD_NAME:
        _arity(args, 1, 1, cmd, "/ad FUN_<adres>")
        return Command(cmd, hedef=_fun(args[0], cmd))
    if cmd == CMD_NOTE:
        if len(args) < 2:
            raise InputError("kullanım: /not FUN_<adres> <metin>")
        body = rest.lstrip(" ")[len(args[0]):].strip(" ")
        return Command(cmd, hedef=_fun(args[0], cmd), metin=body)
    if cmd == CMD_OPEN:
        _arity(args, 1, 1, cmd, "/ac r<sayı>")
        if not _RID.fullmatch(args[0]):
            raise InputError("/ac: sonuç kimliği r<sayı> biçiminde olmalı")
        return Command(cmd, sonuc=args[0])
    if cmd == CMD_FOLLOW:
        _arity(args, 1, 1, cmd, "/takip ac|kapat")
        if args[0] not in _FOLLOW_ALIASES:
            raise InputError("kullanım: /takip ac|kapat")
        return Command(cmd, takip=_FOLLOW_ALIASES[args[0]])
    if cmd == CMD_PLAN:
        return _parse_plan(args, rest)
    _arity(args, 0, 0, cmd, f"/{cmd} (argümansız)")
    return Command(cmd)


def _parse_plan(args: list[str], rest: str) -> Command:
    usage = "/plan [acikla|ad] ithal <ad> | /plan [acikla|ad] dizgi <metin>"
    task = PLAN_TASK_EXPLAIN
    if args and args[0] in _PLAN_TASKS:
        task = _PLAN_TASKS[args[0]]
        rest = rest.lstrip(" ")[len(args[0]):]
        args = args[1:]
    if len(args) < 2 or args[0] not in (PLAN_IMPORT, PLAN_STRING):
        raise InputError(f"kullanım: {usage}")
    if args[0] == PLAN_IMPORT:
        if len(args) != 2 or len(args[1]) > IMPORT_NAME_MAX_CHARS or not _IMPORT_NAME.fullmatch(args[1]):
            raise InputError(f"/plan ithal: tek bir ithal adı (en çok {IMPORT_NAME_MAX_CHARS} karakter)")
        return Command(CMD_PLAN, metin=args[1], plan_turu=PLAN_IMPORT, plan_gorevi=task)
    value = rest.lstrip(" ")[len(PLAN_STRING):].strip(" ")
    if not SEARCH_TEXT_MIN_CHARS <= len(value) <= SEARCH_TEXT_MAX_CHARS:
        raise InputError(f"/plan dizgi: metin {SEARCH_TEXT_MIN_CHARS}-{SEARCH_TEXT_MAX_CHARS} karakter olmalı")
    return Command(CMD_PLAN, metin=value, plan_turu=PLAN_STRING, plan_gorevi=task)


HELP_LINES = (
    "KaradulLM terminali: kabuk değildir; yalnız aşağıdaki komutlar vardır. Hedef ikili hiçbir koşulda çalıştırılmaz.",
    "/kip kesif|acikla|adlandir|plan   kipi değiştirir (yalnız görev yokken)",
    f"/acikla FUN_<adres> [0-{DEFAULT_CLOSURE_DEPTH}]       fonksiyonun ne yaptığı; çağrılanları aşağıdan yukarı özetlenir",
    f"/ozet FUN_<adres> [0-{DEFAULT_CLOSURE_DEPTH}]         yalnız özet zinciri (öneri açmaz)",
    "/ad FUN_<adres>                   ad önerisi (adlandır kipinde)",
    "/plan [acikla|ad] ithal <ad>      o kütüphane fonksiyonunu çağıranlar için iş planı (model kullanılmaz)",
    "/plan [acikla|ad] dizgi <metin>   o metni kullananlar için iş planı",
    "/onayla                           bekleyen planı ya da uzun işi başlatır",
    "/durdur                           süren görevi ve kuyruğu durdurur",
    "/oneriler                         öneriler ve durumları (kabul / ret öneri kartında yapılır)",
    "/ac r<sayı>                       bir araç sonucunun saklı içeriği",
    "/not FUN_<adres> <metin>          deftere analist notu",
    "/hiz                              model hızını ölçer (iki kısa istek)",
    "/takip ac|kapat                   ajan imlecinin haritayı izlemesi",
    "/yardim                           bu metin",
    "/cik                              oturumu kapatır",
    "Keşif kipinde / ile başlamayan satır sorudur; @FUN_<adres> ile en çok 3 fonksiyon anılabilir; araç "
    "döngüsü kapalıyken (öntanım) en az bir anma gerekir. Cevabın kanıta bağlı olup olmadığını denetim yazar.",
)


# --- Satır biçimi (§4.4) -----------------------------------------------------------------------------
VERDICT_LABELS = {"ret": "RET", "celiski": "ÇELİŞKİ", "sinandi_celiski_yok": "ÇELİŞKİ BULUNMADI (sınandı)",
                  "sinanamadi": "SINANAMADI (kanıt yok)"}
TASK_LABELS = {"acikla": "açıkla", "ad_oner": "ad öner", "ozet_alt": "özet", "soru": "soru", "plan": "plan"}


def _fn(hedef: Any) -> str:
    if isinstance(hedef, Mapping):
        if hedef.get("fn"):
            return str(hedef["fn"])
        if hedef.get("adres"):
            return f"adres {hedef['adres']}"
    return "-"


def _num(v: Any, unit: str) -> str:
    return f"{v} {unit}" if v is not None else f"? {unit}"


def render(event: Mapping[str, Any]) -> list[str]:
    """Bir olayın terminal satırları (boş liste: terminalde satırı yok, ör. ``jeton``; sayaç arayüzde)."""
    t = event.get("tur")
    g = event.get("gorev")
    if t == "oturum_basladi":
        hiz = event.get("hiz")
        baglam = event.get("baglam")
        return [f"KaradulLM · {event.get('arka_uc')} · model {event.get('model') or 'bilinmiyor'} · bağlam "
                f"{'-' if baglam is None else baglam} · ağ {event.get('ag')} · {event.get('kip')}",
                "hız: ölçülmedi  [/hiz ile ölç]" if not hiz else f"hız: {hiz}"]
    if t == "arka_uc_durumu":
        b = event.get("bellek_gib")
        return [f"arka uç: {event.get('durum')}" + (f" · bellek {b} GiB" if b is not None else "")]
    if t == "gorev_basladi":
        b = event.get("butce") or {}
        return [f"● {g} {TASK_LABELS.get(event.get('gorev_turu'), event.get('gorev_turu'))} {_fn(event.get('hedef'))}"
                f"  bütçe: {b.get('arac')} araç · {b.get('jeton')} jeton · {b.get('sure_sn')} sn"]
    if t == "arac_bitti":
        durum = (event.get("tur_kind") or "") if event.get("tamam") else f"hata: {event.get('hata')}"
        kirp = " · kırpıldı" if event.get("kirpma") else ""
        return [f"  ⎿ {event.get('sonuc')} {event.get('arac')}  {durum} · {_num(event.get('bayt'), 'B')} · "
                f"{_num(event.get('sure_ms'), 'ms')}{kirp}"]
    if t == "model_cevabi":
        out = []
        if event.get("niyet"):
            out.append(f"  ⋯ niyet (model metni): {event['niyet']}")
        if event.get("hata"):
            return out + [f"  ◆ model: {event.get('durum')} · {event['hata']}"]
        return out + [f"  ◆ model: istem {_num(event.get('istem_jeton'), 'jeton')} · üretilen "
                      f"{_num(event.get('uretim_jeton'), 'jeton')} · {event.get('durum')}"]
    if t == "denetim":
        out = [f"  denetim: {VERDICT_LABELS.get(event.get('hukum'), event.get('hukum'))}"]
        for f in event.get("bulgular") or []:
            out.append(f"    {f.get('kural')} {f.get('kod')} ({f.get('etki')})")
        if event.get("sinanmayan"):
            out.append(f"    sınanmayan: {', '.join(sorted(event['sinanmayan']))}")
        return out
    if t == "ozet":
        kaynak = "model önerisi" if event.get("kaynak") == "model" else "olgu (modelsiz)"
        kanit = " ".join(event.get("kanit") or []) or "yok"
        bel = " · belirsiz" if event.get("belirsiz") else ""
        return [f"● özet {_fn(event.get('hedef'))} ({kaynak} · kanıt {kanit}{bel}): \"{event.get('metin')}\""]
    if t == "oneri":
        return [f"● öneri {event.get('oneri_kimligi')} kuyrukta: {event.get('oneri_turu')} {_fn(event.get('hedef'))} → "
                f"\"{event.get('deger')}\" · denetim {VERDICT_LABELS.get(event.get('hukum'), event.get('hukum'))} "
                "(kabul / ret öneri kartında)"]
    if t == "gorev_bitti":
        s = event.get("sayaclar") or {}
        return [f"● {g} bitti · {event.get('durum')} · {s.get('tool_calls', 0)} araç · {s.get('model_calls', 0)} model "
                f"çağrısı · {_num(event.get('sure_ms'), 'ms')}" + (f" · {event['hata']}" if event.get("hata") else "")]
    if t == "iptal":
        return [f"■ iptal istendi ({event.get('kaynak')})"]
    if t == "satir":
        prefix = {"uyari": "! ", "hata": "✗ "}.get(event.get("duzey"), "")
        return [f"{prefix}{event.get('metin')}"]
    if t == "oturum_bitti":
        return [f"oturum kapandı ({event.get('neden')})"]
    return []
