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
import os
import re
import sys
import threading
import time
import unicodedata
from collections import deque
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from karadul.lm import DISPLAY_TEXT_MAX_CHARS, EVENT_RING_CAPACITY
from karadul.lm.audit import _HEX64, _SESSION_ID, now_iso
from karadul.lm.protocol import RESULT_ID_PATTERN

# --- Zarf ve türler (tasarım §4.1) -------------------------------------------------------------
ENVELOPE_KEYS = ("seq", "t_ms", "zaman", "oturum", "gorev", "tur")

# Türlerin ek alanları. Tasarım tablosundan; P22a'da eklenenler "[P22a]" notlu (gerekçe: P22a.md kalem 1).
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
# Kapalı değer kümeleri (tasarım §4.1); bu alanlarda ``None`` da kabul edilmez.
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


# ``arac_bitti.dokunulan``: araç sonucunda geçen program fonksiyonları. Yalnız Karadul'un yazdığı adres
# alanları okunur; ikili kökenli metin (dizgi, sabit, ithal adı, Ghidra uyarısı) taranmaz: ikilinin
# içine gömülü bir "FUN_…" dizgisi örümceği oynatamasın. Alan adına göre (araçtan bağımsız) kural:
# - liste alanları (``callees`` …): ``FUN_x [etiket: ad]`` / ``api(FUN_x)`` / ``api by FUN_x`` biçimli
#   metin; etiketteki ad tanımlayıcıdır ve yer tutucu (``FUN_…``) ad gösterilmez (``Workspace.name_tag``),
# - ``items``: ``{"addr": "FUN_x", …}`` öğeleri,
# - ``code``: decompile metni; dizgi ve karakter sabitleri atılarak (sabit içi metin ikiliden gelir).
# Sonucun kendi hedefi (``data.addr``) dokunulan sayılmaz. Yeni bir araç başka bir adres alanı
# taşırsa kural buraya eklenir (P22d).
TOUCH_LISTING_FIELDS = ("callees", "callers", "callbacks_given", "callback_of")
TOUCH_ITEM_FIELDS = ("items",)
TOUCH_CODE_FIELDS = ("code",)
_FUN_TOKEN = re.compile(r"\bFUN_[0-9a-fA-F]{3,16}\b")
_C_LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')


def touched_refs(envelope: Mapping[str, Any]) -> list[str]:
    """Araç sonucu zarfındaki program fonksiyonu başvuruları (``FUN_<adres>``), ilk geçiş sırasıyla,
    yinelenmesiz; sonucun kendi hedefi hariç. Hata zarfında boş liste."""
    data = envelope.get("data") if envelope.get("ok") else None
    if not isinstance(data, Mapping):
        return []
    own = data.get("addr")
    found: list[str] = []
    for key, value in data.items():
        tokens: list[str] = []
        if key in TOUCH_LISTING_FIELDS and isinstance(value, str):
            tokens = _FUN_TOKEN.findall(value)
        elif key in TOUCH_ITEM_FIELDS and isinstance(value, list):
            tokens = [x["addr"] for x in value
                      if isinstance(x, Mapping) and isinstance(x.get("addr"), str) and _FUN_TOKEN.fullmatch(x["addr"])]
        elif key in TOUCH_CODE_FIELDS and isinstance(value, str):
            tokens = _FUN_TOKEN.findall(_C_LITERAL.sub('""', value))
        for t in tokens:
            if t != own and t not in found:
                found.append(t)
    return found


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


# --- Halka ve uzun yoklama (tasarım §4.1 "Halka", §4.2) ---------------------------------------


class EventStream:
    """Bir oturumun olay akışı: sıra numarası, bellekte halka, uzun yoklama.

    - ``emit`` olayı kurar (şema + arındırma), ``seq``'i verir ve halkaya ekler. Şemaya uymayan olay
      sıra numarası TÜKETMEZ: ``seq`` boşluksuzdur.
    - Halka ``capacity`` olay tutar; dolunca en eski olay düşer ve ``dropped`` sayacı artar.
    - ``since(sonra)`` ``seq > sonra`` olan olayları verir. İstemci geride kaldıysa (istediği olaylar
      halkadan düşmüşse) cevap ``tasma: True`` ve ``kacan: <düşen ve hiç verilmemiş olay sayısı>``
      taşır; kayıp gizlenmez (tasarım §4.1, opencode'un "volatile by contract" tutumu + sayım).
    - ``timeout > 0`` ise yeni olay gelene, akış kapanana ya da süre dolana kadar bekler (uzun
      yoklama). Olay yoksa boş döner: beklerken hiçbir şey üretilmez.

    Halkada olayın JSON metni saklanır; ``since`` her çağrıda yeni sözlükler döndürür (okuyan, öbür
    okuyanların gördüğünü değiştiremez). İş parçacığı güvenlidir.
    """

    def __init__(self, session_id: str, *, capacity: int = EVENT_RING_CAPACITY,
                 clock: Callable[[], float] = time.monotonic, wall: Callable[[], str] = now_iso):
        if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
            raise ValueError("oturum kimliği [A-Za-z0-9_-]{1,64} olmalı")
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 1:
            raise ValueError("halka boyu artı tamsayı olmalı")
        self.session_id = session_id
        self.capacity = capacity
        self._ring: deque[tuple[int, str]] = deque(maxlen=capacity)
        self._seq = 0
        self._dropped = 0
        self._closed = False
        self._clock = clock
        self._wall = wall
        self._t0 = clock()
        self._cond = threading.Condition()

    @property
    def last_seq(self) -> int:
        """Son yayılan olayın sırası (hiç olay yoksa 0)."""
        with self._cond:
            return self._seq

    @property
    def dropped(self) -> int:
        """Halka dolduğu için düşen olayların toplamı."""
        with self._cond:
            return self._dropped

    @property
    def closed(self) -> bool:
        with self._cond:
            return self._closed

    def emit(self, tur: str, /, gorev: Optional[str] = None, **fields: Any) -> dict[str, Any]:
        """Olayı yayar; kurulan (arındırılmış) olayı döndürür. Şema dışı olay ``EventError``."""
        with self._cond:
            if self._closed:
                raise EventError("akış kapalı: olay yayılamaz")
            t_ms = max(0, int((self._clock() - self._t0) * 1000))
            event = build_event(tur, fields, seq=self._seq + 1, t_ms=t_ms, zaman=self._wall(),
                                oturum=self.session_id, gorev=gorev)
            text = serialize(event)
            if len(self._ring) == self.capacity:
                self._dropped += 1
            self._ring.append((event["seq"], text))
            self._seq = event["seq"]
            self._cond.notify_all()
            return event

    def since(self, after: int, *, timeout: float = 0.0, limit: Optional[int] = None) -> dict[str, Any]:
        """``seq > after`` olayları: ``{"olaylar", "son", "tasma", "kacan", "kapali"}``.

        ``son``: verilen son olayın sırası (olay yoksa ``after``); istemci bir sonraki istekte bunu
        verir. ``kacan``: ``after``'dan sonra gelip halkadan düşmüş, bu cevapta da verilemeyen olay
        sayısı. ``kapali``: akış kapandı ve verilecek olay kalmadı. ``after`` akışın son sırasından
        büyükse (başka oturumun sırası) ``ValueError``."""
        if not isinstance(after, int) or isinstance(after, bool) or after < 0:
            raise ValueError("sonra eksi olmayan tamsayı olmalı")
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
            raise ValueError("limit artı tamsayı olmalı")
        with self._cond:
            if after > self._seq:
                raise ValueError("istenen sıra akışın ilerisinde (başka oturumun sırası olabilir)")
            if timeout > 0:
                self._cond.wait_for(lambda: self._seq > after or self._closed, timeout)
            oldest = self._seq - len(self._ring) + 1          # halkadaki ilk olayın sırası
            missed = max(0, oldest - 1 - after)
            texts = [t for s, t in self._ring if s > after]
            if limit is not None:
                texts = texts[:limit]
            events = [json.loads(t) for t in texts]
            last = events[-1]["seq"] if events else after
            return {"olaylar": events, "son": last, "tasma": missed > 0, "kacan": missed,
                    "kapali": self._closed and last == self._seq}

    def close(self) -> None:
        """Akışı kapatır: yeni olay yayılamaz, bekleyen yoklamalar hemen döner."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()


# --- İçerik deposu (tasarım §4.1 "İçerik kuralı"; karar 6 (b)) -------------------------------

CONTENT_DIR_NAME = "sonuclar"
_RESULT_ID = re.compile(RESULT_ID_PATTERN)


class ContentStore:
    """Araç sonuçlarının tam metni: ``~/.karadul/lm/<ikili_sha256>/sonuclar/<oturum>/r<n>.json``.

    Olay akışı araç sonucunun yalnız özetini taşır; terminalin "r3'ü aç" demesi ve "her araç çağrısı
    içeriğiyle birlikte kayda geçer" (RAPOR §7.2 madde 3) buradan. Denetim günlüğü içeriksiz kalır.

    - Kayıt modelin gördüğü zarfın kendisidir (ham; görüntü için ``get_display`` arındırır).
    - Dizinler 0700, dosya 0600 (``audit.py`` kalıbı); yalnız yeni dosya açılır (``O_EXCL``): aynı
      kimlik ikinci kez yazılmaz, var olan içerik ezilmez; dosya ya da oturum dizini sembolik bağsa
      yazılmaz.
    - Saklama: Berke kararı 6 (b) — ikiliyle birlikte kalır, oturum kapanınca silinmez; silmeyi
      analist yapar. Bu sınıf hiçbir şey silmez.
    - Yol yalnız doğrulanmış parçalardan kurulur: ikili sha256 (64 küçük onaltılık), oturum kimliği
      (``[A-Za-z0-9_-]{1,64}``), sonuç kimliği (``r<sayı>``); değilse ``ValueError`` (yol aşımı yok).
    Nesne kurmak dosya ya da dizin açmaz.
    """

    def __init__(self, binary_sha256: str, session_id: str, *, root: Optional[Path] = None):
        if not isinstance(binary_sha256, str) or not _HEX64.fullmatch(binary_sha256):
            raise ValueError("geçersiz ikili sha256 (64 küçük harfli onaltılık basamak beklenir)")
        if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
            raise ValueError("geçersiz oturum kimliği ([A-Za-z0-9_-]{1,64} beklenir)")
        base = Path(root) if root is not None else Path.home() / ".karadul" / "lm"
        self.dir = base / binary_sha256 / CONTENT_DIR_NAME / session_id

    def path_for(self, result_id: str) -> Path:
        if not isinstance(result_id, str) or not _RESULT_ID.fullmatch(result_id):
            raise ValueError("geçersiz sonuç kimliği (r<sayı> beklenir)")
        return self.dir / f"{result_id}.json"

    def _ensure_dir(self) -> None:
        missing: list[Path] = []
        p = self.dir
        while not p.exists() and not p.is_symlink():
            missing.append(p)
            p = p.parent
        for d in reversed(missing):
            try:
                d.mkdir(mode=0o700)
            except FileExistsError:
                pass
        if self.dir.is_symlink() or not self.dir.is_dir():
            raise OSError(f"içerik dizini dizin değil ya da sembolik bağ: {self.dir}")

    def put(self, result_id: str, envelope: Mapping[str, Any]) -> Path:
        """Zarfı yazar ve yolunu döndürür. Yazılamazsa ``OSError`` (var olan dosya dahil)."""
        path = self.path_for(result_id)
        data = json.dumps(envelope, ensure_ascii=True, sort_keys=True).encode("ascii")
        self._ensure_dir()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
        return path

    def get(self, result_id: str) -> Optional[dict[str, Any]]:
        """Saklı zarf (ham); yoksa ``None``. Sembolik bağ ya da bozuk içerik ``OSError`` / ``ValueError``."""
        path = self.path_for(result_id)
        if path.is_symlink():
            raise OSError(f"içerik dosyası sembolik bağ: {path}")
        try:
            text = path.read_text(encoding="ascii")
        except FileNotFoundError:
            return None
        obj = json.loads(text)
        if not isinstance(obj, dict):
            raise ValueError("içerik dosyası bir zarf değil")
        return obj

    def get_display(self, result_id: str) -> Optional[dict[str, Any]]:
        """Saklı zarfın görüntülenebilir kopyası: terminale / arayüze bu verilir. Karakterler olaydaki
        kuralla kaçışlanır; uzunluk kesilmez (analist tam metni açmak istiyor; zarf zaten aracın sonuç
        tavanıyla sınırlı)."""
        obj = self.get(result_id)
        return None if obj is None else sanitize(obj, sys.maxsize)
