"""KaradulLM olay omurgası: olay zarfı, türler, serileştirme ve görüntü arındırması.

Tasarım: ``docs/arge/2026-11-18_karadullm_v2/TASARIM.md`` §4.1 (olay şeması), §4.3 G9 (ekrana yazılan
metin yorumlanmaz), §3.3 (bir görevin adımları). Terminal paneli ve örümcek simgesi YALNIZ bu
olaylardan çizilir (P22c); olay yalnız gerçekten olan bir şey için üretilir, alanlar gerçek değer taşır.
Bilinmeyen değer ``None`` yazılır; uydurma sayı, süre ya da ilerleme yoktur.

**Zarf** (her olayda): ``seq`` (oturumda 1'den başlayan boşluksuz sıra), ``t_ms`` (oturum başından
tekdüze saatle geçen süre), ``zaman`` (duvar saati), ``oturum``, ``gorev`` (görev kimliği ya da
``None``), ``tur``. Türlerin ek alanları ``EVENT_FIELDS``'tedir; her alan her olayda bulunur (eksik ya
da fazla alan programlama hatasıdır, ``EventError``).

**Görüntü arındırması** (``display_text``, ``sanitize``): analiz edilen ikiliden ya da modelden gelen
metin terminale ham basılmaz. C0 / C1 denetim karakterleri (ESC dahil: ANSI kaçışları etkisiz kalır),
satır ve paragraf ayırıcıları, biçim karakterleri (yön değiştiren U+202A-U+202E, U+2066-U+2069 ve sıfır
genişlikli karakterler) görünür kaçışa (``\\x1b``, ``\\u202e``) çevrilir. Ters bölü OLDUĞU GİBİ kalır:
Ghidra dizgileri zaten C kaçışıyla yazıyor (gerçek koşularda dizgilerin bir kısmı ``\\n`` metnini
taşıyor, ham satır sonu taşıyan 0; P22a.md kalem 1), ikilemek bunları "ikilide ters bölü var" diye
yanlış gösterirdi. Bedeli: ikiliden gelen düz ``\\u202e`` metni gerçek U+202E'nin kaçışıyla aynı
görünür; ikisi de yorumlanmaz, ham metin içerik deposundadır. Çok uzun metin ``DISPLAY_TEXT_MAX_CHARS``'ta kesilir
ve kesilen karakter sayısı ekte yazılır. Arındırma olay kurulurken yapılır: halkada ve serileştirmede
yalnız arındırılmış değer vardır (tasarım "sunucuda, serileştirmede"). Arayüz yine yalnız
``textContent`` kullanır (K-U2).

Bu modül süreç başlatmaz, ağa çıkmaz; içe aktarılınca dosya yazmaz.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Mapping, Optional

from karadul.lm import DISPLAY_TEXT_MAX_CHARS
from karadul.lm.audit import _SESSION_ID

# --- Zarf ve türler (tasarım §4.1) -------------------------------------------------------------
ENVELOPE_KEYS = ("seq", "t_ms", "zaman", "oturum", "gorev", "tur")

# Türlerin ek alanları. Tasarım tablosundan; P22a'da eklenenler "[P22a]" notlu (P22a.md "Şema").
EVENT_FIELDS: dict[str, tuple[str, ...]] = {
    # Oturum (P22e yayar)
    "oturum_basladi": ("kip", "model", "arka_uc", "baglam", "ag", "hiz"),
    "arka_uc_durumu": ("durum", "bellek_gib"),
    # Görev (ajan yayar)
    "gorev_basladi": ("gorev_turu", "kip", "hedef", "butce"),
    "arac_basladi": ("sonuc", "arac", "cagiran", "hedef", "arguman"),
    # [P22a] calistirildi, dokunulan_toplam, icerik_saklandi
    "arac_bitti": ("sonuc", "arac", "tamam", "hata", "calistirildi", "tur_kind", "bayt", "kirpma", "sure_ms",
                   "dokunulan", "dokunulan_toplam", "icerik_saklandi"),
    "model_istegi": ("amac", "istem_kestirim"),
    # [P22a] tasarımdaki "uretilen" yerine: parca (akışta gelen içerik parçası) ve karakter. Parça sayısı
    # jeton sayısı değildir (uç parça başına bir jeton gönderir ama bu doğrulanmadı); gerçek üretim jetonu
    # model_cevabi.uretim_jeton'dadır (ucun usage alanı).
    "jeton": ("parca", "karakter"),
    # [P22a] amac (isteği eşlemek için), hata
    "model_cevabi": ("amac", "durum", "bitis_nedeni", "istem_jeton", "uretim_jeton", "onbellek_jeton", "sure_ms",
                     "niyet", "hata"),
    # [P22a] bayraklar, toplu_kabul, sinanan, sinanmayan (P21 GuardReport.as_dict ile aynı adlar)
    "denetim": ("nesne", "hukum", "bulgular", "bayraklar", "toplu_kabul", "sinanan", "sinanmayan"),
    "oneri": ("oneri_kimligi", "hedef", "oneri_turu", "deger", "gerekce", "kanit", "hukum"),
    "ozet": ("hedef", "metin", "belirsiz", "kanit", "hukum", "kaynak"),
    "butce": ("arac", "jeton", "sure"),
    # [P22a] hata, ad_durumu, cevap, hukum, toplu_kabul
    "gorev_bitti": ("durum", "hata", "ad_durumu", "cevap", "hukum", "toplu_kabul", "sayaclar", "sure_ms"),
    "iptal": ("kaynak",),
    "satir": ("metin", "duzey"),
    "oturum_bitti": ("neden",),
}
EVENT_TYPES = frozenset(EVENT_FIELDS)

CALLER_SERVER, CALLER_MODEL = "sunucu", "model"
# Kapalı değer kümeleri (tasarım §4.1). ``None`` yalnız ayrıca izin verilen alanlarda.
FIELD_CHOICES: dict[tuple[str, str], frozenset[Any]] = {
    ("gorev_basladi", "gorev_turu"): frozenset({"acikla", "ad_oner", "ozet_alt", "soru", "plan"}),
    ("arac_basladi", "cagiran"): frozenset({CALLER_SERVER, CALLER_MODEL}),
    ("arka_uc_durumu", "durum"): frozenset({"kapali", "yukleniyor", "hazir", "mesgul", "bellek_durdu", "hata"}),
    ("oneri", "oneri_turu"): frozenset({"ad", "yorum", "parametre", "not"}),
    ("ozet", "kaynak"): frozenset({"model", "olgu"}),
    ("iptal", "kaynak"): frozenset({"analist", "sure", "bellek", "kapanis"}),
    ("satir", "duzey"): frozenset({"bilgi", "uyari", "hata"}),
    ("oturum_bitti", "neden"): frozenset({"cik", "arayuz_kapandi", "calisma_alani_degisti", "bosta"}),
}
# ``hedef`` nesnesi: ``fn`` arayüzün düğüm anahtarı (``Workspace.ui_name``; decompile dosyası yoksa
# ``None``), ``adres`` çalışma alanındaki adres yazımı. Hedefi olmayan olayda alan ``None``'dır.
TARGET_KEYS = ("fn", "adres")


class EventError(ValueError):
    """Olay şemaya uymuyor (programlama hatası): bilinmeyen tür, eksik / fazla alan, kapalı kümede
    olmayan değer, JSON'a çevrilemeyen değer."""


# --- Görüntü arındırması --------------------------------------------------------------------
# Görünür kaçışa çevrilen Unicode kategorileri: Cc (C0, DEL, C1), Cf (biçim: yön değiştirenler, sıfır
# genişlikliler, BOM), Cs (eşsiz vekil), Zl / Zp (satır ve paragraf ayırıcısı: satırı böler).
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
_NAMED_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
# Hızlı yol: yalnız basılabilir ASCII metin değişmez.
_PLAIN_ASCII = re.compile(r"[\x20-\x7e]*")
TRUNCATION_SUFFIX = "… [+{n} karakter]"


def _escape_char(ch: str) -> str:
    named = _NAMED_ESCAPES.get(ch)
    if named is not None:
        return named
    if unicodedata.category(ch) not in _ESCAPED_CATEGORIES:
        return ch
    o = ord(ch)
    if o < 0x100:
        return f"\\x{o:02x}"
    return f"\\u{o:04x}" if o <= 0xFFFF else f"\\U{o:08x}"


def display_text(text: str, max_chars: int = DISPLAY_TEXT_MAX_CHARS) -> str:
    """Metnin görüntülenebilir biçimi: denetim / biçim karakterleri görünür kaçış, uzunluk tavanlı.

    Tavan kaçışlanmış metne uygulanır ve bir kaçış dizisi ortadan bölünmez; kesilirse kalan özgün
    karakter sayısı ``… [+N karakter]`` ekiyle yazılır."""
    if not isinstance(text, str):
        raise TypeError("display_text yalnız str alır")
    if len(text) <= max_chars and _PLAIN_ASCII.fullmatch(text):
        return text
    out: list[str] = []
    used = 0
    for i, ch in enumerate(text):
        piece = _escape_char(ch)
        if used + len(piece) > max_chars:
            return "".join(out) + TRUNCATION_SUFFIX.format(n=len(text) - i)
        out.append(piece)
        used += len(piece)
    return "".join(out)


def sanitize(value: Any, max_chars: int = DISPLAY_TEXT_MAX_CHARS) -> Any:
    """Değerin görüntülenebilir kopyası: her dizgi (sözlük anahtarları dahil) ``display_text``'ten geçer;
    demet liste olur. Sayı, mantıksal değer ve ``None`` değişmez. Başka tür ``EventError``."""
    if isinstance(value, str):
        return display_text(value, max_chars)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise EventError("olay değeri sonlu sayı olmalı")
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise EventError("olay sözlüğünün anahtarı dizgi olmalı")
            out[display_text(k, max_chars)] = sanitize(v, max_chars)
        return out
    if isinstance(value, (list, tuple)):
        return [sanitize(v, max_chars) for v in value]
    raise EventError(f"olaya yazılamayan değer türü: {type(value).__name__}")


# --- Olay kurma ve serileştirme ---------------------------------------------------------------


def _check_target(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, Mapping) or set(value) != set(TARGET_KEYS):
        raise EventError("hedef {'fn', 'adres'} nesnesi ya da None olmalı")
    for k in TARGET_KEYS:
        if value[k] is not None and not isinstance(value[k], str):
            raise EventError(f"hedef.{k} dizgi ya da None olmalı")


def build_event(tur: str, fields: Mapping[str, Any], *, seq: int, t_ms: int, zaman: str, oturum: str,
                gorev: Optional[str]) -> dict[str, Any]:
    """Şemayı denetleyip arındırılmış olay sözlüğünü kurar (zarf + türün alanları, bu sırayla)."""
    if tur not in EVENT_FIELDS:
        raise EventError(f"bilinmeyen olay türü: {tur!r}")
    expected = EVENT_FIELDS[tur]
    got = set(fields)
    if got != set(expected):
        missing, extra = sorted(set(expected) - got), sorted(got - set(expected))
        raise EventError(f"{tur}: eksik alan {missing}, fazla alan {extra}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise EventError("seq 1'den başlayan tamsayı olmalı")
    if not isinstance(t_ms, int) or isinstance(t_ms, bool) or t_ms < 0:
        raise EventError("t_ms eksi olmayan tamsayı olmalı")
    if not isinstance(zaman, str):
        raise EventError("zaman ISO 8601 dizgisi olmalı")
    if not isinstance(oturum, str) or not _SESSION_ID.fullmatch(oturum):
        raise EventError("oturum kimliği [A-Za-z0-9_-]{1,64} olmalı")
    if gorev is not None and (not isinstance(gorev, str) or not _SESSION_ID.fullmatch(gorev)):
        raise EventError("görev kimliği [A-Za-z0-9_-]{1,64} ya da None olmalı")
    for name in expected:
        choices = FIELD_CHOICES.get((tur, name))
        if choices is not None and fields[name] not in choices:
            raise EventError(f"{tur}.{name}: izin verilmeyen değer")
    if "hedef" in fields:
        _check_target(fields["hedef"])
    event: dict[str, Any] = {"seq": seq, "t_ms": t_ms, "zaman": display_text(zaman), "oturum": oturum,
                             "gorev": gorev, "tur": tur}
    for name in expected:
        value = fields[name]
        if name == "hedef" and value is not None:
            value = {k: value[k] for k in TARGET_KEYS}       # alan sırası sabit: fn, adres
        event[name] = sanitize(value)
    return event


def serialize(event: Mapping[str, Any]) -> str:
    """Olayın tek satırlık JSON metni (NaN / sonsuz yok). Olay ``build_event``'ten geldiyse metin
    zaten arındırılmıştır; JSON kaçışı yalnız sözdizimi içindir."""
    try:
        return json.dumps(event, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError) as e:
        raise EventError(f"olay JSON'a çevrilemedi: {type(e).__name__}") from None
