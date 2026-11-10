"""KS-1 bağlama: kesin çapaları ürünün ön ad kanalına (``pre_names``) hazırlayan saf mantık.

Plan v2.2 N1 adım 3. Tasarım: ``docs/arge/2026-11-10_n1_adim3/baglama_tasarimi_taslak.md`` §2, §4.1.
Çıkarıcı ``kesin.py``'dir ve değişmez (sha256'sı ön kayıtla sabit); bu modül onun çıktısını alır,
ürünün karar tablosuna göre "ad verir mi, hangi etiketle" sorusunu cevaplar ve adı köken
künyesiyle (``pre_name_meta``) birlikte ön ad sözlüğüne yazar. Yalnız standart kitaplık kullanır.

Akış (hat adımı ve ``stages.py`` yalnız çağırır):

    binding = bind_static(static_dir)                     # çıkarım + karar; hata fırlatmaz
    apply_binding(extracted_names, binding, meta, stats)  # tohum sırasında, ``main``'den sonra
    binding.as_dict()                                     # yan çıktı: kesin_capalar.json

Kurallar:

- Anahtar: çapanın adresindeki Ghidra fonksiyon adı. Yalnız ``FUN_<onaltılık>`` anahtarlı çapa ad
  alır; ``entry`` gibi sözcüklerin genel değişimi dizgi literallerini bozar (§2.2).
- Satır: çapanın karar satırları ölçümdeki ``ks1_olc.gorunum`` ile aynı tanımdan (§2.5). Parça
  çapası ad almaz ve satır hesabına girmez; yan çıktıya yazılır (§2.6). ``export`` çapası ad almaz,
  yalnız sayılır (§2.7).
- Satır durumu ``ROW_STATUS`` tablosundadır: ``kesin`` | ``dogrulanmadi`` | ``sus``. Tablo, adım 2
  ölçümünün sayılarına ``row_status_from_measurement`` uygulanarak doldurulur; doldurulana kadar
  dört satır da ``sus``'tur (KS-1 ad vermez).
- Etiket: satırlardan en az biri ``kesin`` ise "kesin", değilse en az biri ``dogrulanmadi`` ise
  "doğrulanmadı"; hepsi ``sus`` ise ad verilmez. C++ ikilide "kesin" hiç verilmez (ölçüm C++
  ikilileri kesinlik dışında tuttu).
- Öncelik (§2.8): elle > ``main`` girişi > KS-1 > Faz 1 > gnulib > ELF önyükü. KS-1, elle ve
  ``main`` girişi künyeli anahtara yazamaz, ``main`` adını ikinci bir anahtara veremez; öbür
  türlerin adını ezer ve ezdiğini sayar.

"kesin" etiketine giden tek yol: ölçüm kararı ``kesin`` (n > 0) → satır durumu ``kesin`` → o satırı
taşıyan, C++ olmayan ikilideki çapa. Ölçülmemiş satır ``sus``'tur.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from karadul.core.naming_labels import LABEL_CERTAIN as LABEL_KESIN
from karadul.core.naming_labels import LABEL_UNVERIFIED
from karadul.core.naming_labels import PRE_NAME_KIND_KS1 as KIND_KS1
from karadul.core.naming_labels import PRE_NAME_KIND_MAIN as KIND_MAIN
from karadul.core.naming_labels import PRE_NAME_KIND_MANUAL as KIND_MANUAL
from karadul.reconstruction.tarif import kesin as K

BINDING_SCHEMA = "karadul.ks1_baglama"
BINDING_VERSION = 1

# ---- Etiket sözlüğü (§4.1); yazım N0b'ninkiyle aynı (``alt_kanal.GUVEN_ETIKETLERI``) ----
# Etiket yazımı ve ortak ön ad türleri tek yerde: karadul.core.naming_labels
LABELS = (LABEL_KESIN, LABEL_UNVERIFIED)

# ---- Ön ad türleri (``pre_name_meta[anahtar]["kind"]``, §2.3) ----
# KIND_KS1 ("ks1"), KIND_MAIN ("main_giris": ``__libc_start_main``'in ilk argümanı) ve
# KIND_MANUAL ("elle") çekirdek sözlükten gelir.
KIND_GNULIB = "gnulib"
KIND_ELF_BOILERPLATE = "elf_onyuk"
KIND_PHASE1 = "faz1"              # BinaryNameExtractor, byte pattern, CAPA
# Öncelik sırası, yüksekten düşüğe (§2.8)
KIND_PRIORITY = (KIND_MANUAL, KIND_MAIN, KIND_KS1, KIND_PHASE1, KIND_GNULIB, KIND_ELF_BOILERPLATE)
# c_namer'ın ön adları işleme sırası; kalanlar özgün sözlük sırasıyla arkadan gelir (§2.4)
PRE_NAME_ORDER = (KIND_MANUAL, KIND_MAIN, KIND_KS1)
# Adı temizlenmeden, olduğu gibi yazılan türler (§2.4 tuzak 1)
EXACT_KINDS = frozenset({KIND_KS1, KIND_MANUAL})
# KS-1'in üzerine yazamadığı türler
PROTECTED_KINDS = frozenset({KIND_MANUAL, KIND_MAIN})
MAIN_NAME = "main"

# ---- Karar satırları (``ks1_olc.KARAR_SATIRLARI`` ile aynı adlar ve sıra) ----
ROW_ASSERT = "assert"             # assert türlü, rolü ``kendi``
ROW_ASSERT_LIFTED = "assert_ust"  # rolü ``ust``: parçadan üst fonksiyona kaldırılmış
ROW_FUNC = "func_kalibi"
ROW_FORWARD = "func_aktarma"
DECISION_ROWS = (ROW_ASSERT, ROW_ASSERT_LIFTED, ROW_FUNC, ROW_FORWARD)

# ---- Satır durumu ----
STATUS_KESIN = "kesin"                # ad verir, etiket "kesin"
STATUS_UNVERIFIED = "dogrulanmadi"    # ad verir, etiket "doğrulanmadı"
STATUS_SILENT = "sus"                 # ad vermez
ROW_STATUSES = (STATUS_KESIN, STATUS_UNVERIFIED, STATUS_SILENT)
# Ürünün satır tablosu. "Aç" commit'ine kadar dört satır da susar; o commit tabloyu
# ``row_status_table``'ın adım 2 sayılarına uygulanmasıyla doldurur ve testle kilitler.
ROW_STATUS: Mapping[str, str] = MappingProxyType({row: STATUS_SILENT for row in DECISION_ROWS})

# ---- Adım 2 kararından satır durumuna geçiş (§2.5) ----
DECISION_KESIN = "kesin"
DECISION_NOT_KESIN = "kesin_degil"
DECISION_INSUFFICIENT = "yetersiz"
MEASUREMENT_DECISIONS = (DECISION_KESIN, DECISION_NOT_KESIN, DECISION_INSUFFICIENT)
WRONG_RATE_TARGET = 0.10   # yanlış oranı hedefi; N0b'nin susturma eşiğiyle aynı
WILSON_Z = 1.96            # %95

# ---- C++ ikili işareti (``ks1_olc.CPP_ISARETLERI`` ile aynı; eşitlik testle kilitli) ----
CPP_MARKERS = ("_Z", "__gxx_personality", "__cxa_begin_catch", "__cxa_end_catch", "__cxa_throw",
               "__cxa_rethrow")

# ---- Çıkarımın durumu (``stats["ks1_status"]``, §2.1) ----
RUN_OK = "ok"
RUN_DISABLED = "kapali"
RUN_INPUT_MISSING = "girdi_eksik"
RUN_UNSUPPORTED = "desteklenmeyen_platform"
RUN_ERROR = "hata"
RUN_STATUSES = (RUN_OK, RUN_DISABLED, RUN_INPUT_MISSING, RUN_UNSUPPORTED, RUN_ERROR)
# Çıkarımın okuduğu dosyalar; biri yoksa çıkarım denenmez
FUNCTIONS_FILE = "ghidra_functions.json"
REQUIRED_FILES = (FUNCTIONS_FILE, "ghidra_strings.json", "ghidra_xrefs.json",
                  "ghidra_combined_results.json")

# ---- Ad vermeme nedenleri (``stats["ks1_skipped"]``) ----
SKIP_FRAGMENT = "parca"                 # üst fonksiyonun adını taşır; aynı ad iki fonksiyona verilmez
SKIP_KEY = "anahtar_fun_degil"          # Ghidra adı ``FUN_<onaltılık>`` değil
SKIP_NAME_FORM = "ad_bicimi"            # ad C tanımlayıcısı değil (olduğu gibi yazılamaz)
SKIP_SILENT_ROW = "satir_sus"           # bütün satırları susuyor
SKIP_PROTECTED = "korunan_anahtar"      # anahtar elle ya da ``main`` girişi adı taşıyor
SKIP_MAIN_TAKEN = "ad_main_dolu"        # ``main`` adı başka bir anahtarda
SKIP_REASONS = (SKIP_FRAGMENT, SKIP_KEY, SKIP_NAME_FORM, SKIP_SILENT_ROW, SKIP_PROTECTED,
                SKIP_MAIN_TAKEN)

# ``pre_names`` anahtarı: Ghidra'nın yer tutucu fonksiyon adı (c_namer'ın tanıdığı biçim)
FUN_KEY_RE = re.compile(r"^FUN_[0-9a-fA-F]+$")


# --------------------------------------------------------------------------------------------
# Geçiş kuralı: adım 2 ölçümü → satır durumu


def wilson(k: int, n: int, z: float = WILSON_Z) -> tuple[float, float]:
    """k/n oranının Wilson skor aralığı (yuvarlamasız). n == 0 için (0, 1)."""
    if n <= 0:
        return 0.0, 1.0
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return max(0.0, center - half), min(1.0, center + half)


def row_status_from_measurement(decision: str, n: int, wrong: int, *,
                                target: float = WRONG_RATE_TARGET, z: float = WILSON_Z) -> str:
    """Bir karar satırının adım 2 sonucundan ürün durumu.

    ``decision``: ``ks1_olc`` satır kararı. ``n`` ve ``wrong``: satırın havuzlanmış tekil öğe sayısı
    ve tam ada eşit olmayanların sayısı (yanlış oranı = 1 − tam ad kesinliği).

    - n == 0: ``sus`` (ölçülmemiş satır ad vermez; karar ne olursa olsun);
    - karar ``kesin``: ``kesin``;
    - karar ``kesin_degil`` ya da ``yetersiz``: yanlış oranının Wilson %95 alt sınırı L ile
      L > hedef ise ``sus``, değilse ``dogrulanmadi``.
    """
    if decision not in MEASUREMENT_DECISIONS:
        raise ValueError(f"bilinmeyen ölçüm kararı: {decision!r}")
    if n < 0 or wrong < 0 or wrong > n:
        raise ValueError(f"geçersiz sayılar: n={n}, yanlış={wrong}")
    if n == 0:
        return STATUS_SILENT
    if decision == DECISION_KESIN:
        return STATUS_KESIN
    low, _ = wilson(wrong, n, z)
    return STATUS_SILENT if low > target else STATUS_UNVERIFIED


def row_status_table(measurements: Mapping[str, tuple[str, int, int]]) -> dict[str, str]:
    """Satır → (karar, n, yanlış) sözlüğünden bütün karar satırlarının durum tablosu.

    Ölçümde hiç geçmeyen karar satırı ``sus``'tur. Karar satırı olmayan anahtar hatadır.
    """
    unknown = sorted(set(measurements) - set(DECISION_ROWS))
    if unknown:
        raise ValueError(f"karar satırı değil: {unknown}")
    table = {}
    for row in DECISION_ROWS:
        if row in measurements:
            decision, n, wrong = measurements[row]
            table[row] = row_status_from_measurement(decision, n, wrong)
        else:
            table[row] = STATUS_SILENT
    return table


# --------------------------------------------------------------------------------------------
# Satır, etiket, C++ işareti, anahtar


def anchor_rows(types: Iterable[str], role: str) -> tuple[str, ...]:
    """Çapanın karar satırları, ``DECISION_ROWS`` sırasıyla (``ks1_olc.gorunum`` ile aynı tanım).

    Parça çapası üründe ad almadığı için satır taşımaz; ölçüm onu ``assert_ust`` görünümünde
    yalnız ayrı sayar.
    """
    if role == K.ROLE_FRAGMENT:
        return ()
    have = set(types)
    member = {
        ROW_ASSERT: K.TYPE_ASSERT in have and role == K.ROLE_OWN,
        ROW_ASSERT_LIFTED: role == K.ROLE_LIFTED,
        ROW_FUNC: K.TYPE_FUNC in have,
        ROW_FORWARD: K.TYPE_FORWARD in have,
    }
    return tuple(row for row in DECISION_ROWS if member[row])


def anchor_label(rows: Iterable[str], *, cpp: bool,
                 row_status: Mapping[str, str] = ROW_STATUS) -> str | None:
    """Çapanın etiketi; ``None``: ad verilmez (fonksiyon c_namer'ın olağan yoluna kalır).

    En iyi satır belirler: birbirini doğrulayan iki kanıt tek kanıttan zayıf olamaz. Tabloda
    olmayan satır ``sus`` sayılır. C++ ikilide ``kesin`` satır da "doğrulanmadı" etiketi verir.
    """
    statuses = {row_status.get(row, STATUS_SILENT) for row in rows}
    if STATUS_KESIN in statuses:
        return LABEL_UNVERIFIED if cpp else LABEL_KESIN
    if STATUS_UNVERIFIED in statuses:
        return LABEL_UNVERIFIED
    return None


def is_macho(executable_format: str) -> bool:
    """Dosya biçimi Mach-O mu (``kesin.detect_abi`` ile aynı sınama)."""
    return "mach-o" in executable_format.lower()


def is_cpp_binary(functions: Iterable[Mapping[str, Any]], *, macho: bool) -> bool:
    """İçe aktarılan (thunk ya da dış) adlardan biri C++ çalışma zamanına ait mi.

    ``functions``: ``ghidra_functions.json``'ın ``functions`` listesi (ölçümün okuduğu ham kayıtlar).
    Mach-O'da Ghidra içe aktarılan adı baştaki ``_`` ile verir; işaret tek ``_`` soyulduktan sonra
    aranır (soyulmasa ``_ZSTD_…`` gibi C adları ``_Z`` sayılırdı).
    """
    for f in functions:
        if not (f.get("is_thunk") or f.get("is_external")):
            continue
        name = str(f.get("name") or "")
        if macho and name.startswith("_"):
            name = name[1:]
        if name.startswith(CPP_MARKERS):
            return True
    return False


def pre_name_key(function_name: str | None) -> str:
    """Ghidra fonksiyon adı ``pre_names`` anahtarı olabiliyorsa kendisi, olamıyorsa boş dizgi."""
    if function_name and FUN_KEY_RE.match(function_name):
        return function_name
    return ""


def _check_row_status(row_status: Mapping[str, str]) -> None:
    bad = sorted(k for k, v in row_status.items() if k not in DECISION_ROWS or v not in ROW_STATUSES)
    if bad:
        raise ValueError(f"geçersiz satır durumu: {bad}")


# --------------------------------------------------------------------------------------------
# Künye (``pre_name_meta``)


def make_meta(kind: str, name: str) -> dict[str, Any]:
    """KS-1 dışı bir ön adın künyesi. Etiket yazılmaz; c_namer ``entry_label``'ı kullanır."""
    if kind not in KIND_PRIORITY:
        raise ValueError(f"bilinmeyen ön ad türü: {kind!r}")
    return {"kind": kind, "name": name, "exact": kind in EXACT_KINDS}


def mark_changed(meta: dict[str, dict[str, Any]], before: Mapping[str, str],
                 after: Mapping[str, str], kind: str) -> list[str]:
    """Bir tohumun eklediği ya da değiştirdiği anahtarlara türünü yaz; yazılan anahtarları döndür.

    Tohum fonksiyonlarının imzası değişmesin diye tür, sözlüğün önceki ve sonraki hâli
    karşılaştırılarak bulunur. Değişen anahtarın eski künyesi (KS-1 dahil) silinir.
    """
    changed = [key for key, name in after.items() if before.get(key) != name]
    for key in changed:
        meta[key] = make_meta(kind, after[key])
    return changed


def meta_for(meta: Mapping[str, Any] | None, key: str, name: str) -> dict[str, Any] | None:
    """Anahtarın geçerli künyesi. Künyedeki ad sözlükteki adla aynı değilse künye yok sayılır
    (ad künyeden sonra başka bir kaynakça ezilmiştir); "kesin" etiketi yanlış ada geçmez."""
    entry = (meta or {}).get(key)
    if not isinstance(entry, dict) or entry.get("name") != name:
        return None
    if entry.get("kind") not in KIND_PRIORITY:
        return None
    return entry


def entry_label(entry: Mapping[str, Any] | None) -> str | None:
    """Ön adın etiketi: KS-1'de künyedeki etiket, elle adda etiket yok, kalan her ad (künyesiz
    olan da) "doğrulanmadı". KS-1 dışı bir tür künyesinde ne yazarsa yazsın "kesin" alamaz."""
    if entry is None:
        return LABEL_UNVERIFIED
    kind = entry.get("kind")
    if kind == KIND_MANUAL:
        return None
    if kind == KIND_KS1 and entry.get("label") == LABEL_KESIN:
        return LABEL_KESIN
    return LABEL_UNVERIFIED


def is_exact(entry: Mapping[str, Any] | None) -> bool:
    """Ad temizlenmeden yazılsın mı: yalnız ``EXACT_KINDS`` türünde ve künye öyle diyorsa."""
    return entry is not None and entry.get("kind") in EXACT_KINDS and entry.get("exact") is True


def ordered_pre_names(pre_names: Mapping[str, str],
                      meta: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    """Ön adlar c_namer'ın işleyeceği sırayla: elle, ``main`` girişi, KS-1, sonra kalanlar.

    Aynı ad iki anahtarda ise ikincisi düşer; sıra, düşenin düşük öncelikli olmasını sağlar. Her
    öbeğin içinde özgün sözlük sırası korunur.
    """
    last = len(PRE_NAME_ORDER)

    def rank(item: tuple[str, str]) -> int:
        entry = meta_for(meta, item[0], item[1])
        kind = entry["kind"] if entry else None
        return PRE_NAME_ORDER.index(kind) if kind in PRE_NAME_ORDER else last

    return sorted(pre_names.items(), key=rank)


# --------------------------------------------------------------------------------------------
# Bağlama


@dataclass(frozen=True)
class BoundAnchor:
    """Bir dizgi türü çapası ve ürün kararı. ``skip`` doluysa ad verilmez."""

    address: str                 # Ghidra biçimi: küçük harf onaltılık, 0x'siz
    key: str                     # ``pre_names`` anahtarı; Ghidra adı ``FUN_`` değilse boş
    function_name: str           # çapanın adresindeki Ghidra adı
    name: str
    types: tuple[str, ...]
    role: str
    rows: tuple[str, ...]
    label: str | None
    skip: str | None
    evidence: tuple[dict[str, Any], ...]

    def meta(self) -> dict[str, Any]:
        """``pre_name_meta`` girdisi (§2.3)."""
        return {"kind": KIND_KS1, "name": self.name, "exact": True, "label": self.label,
                "ks1": {"adres": self.address, "turler": list(self.types), "rol": self.role,
                        "satirlar": list(self.rows), "kanitlar": [dict(e) for e in self.evidence]}}

    def as_dict(self) -> dict[str, Any]:
        return {"adres": self.address, "anahtar": self.key or None, "ghidra_adi": self.function_name,
                "ad": self.name, "turler": list(self.types), "rol": self.role,
                "satirlar": list(self.rows), "etiket": self.label, "atlama": self.skip,
                "kanitlar": [dict(e) for e in self.evidence]}


@dataclass
class Binding:
    """Bir ikilinin KS-1 bağlaması: çapalar, kararlar ve çıkarımın durumu."""

    status: str
    detail: str = ""
    program: str = ""
    abi: str | None = None
    cpp: bool = False
    row_status: dict[str, str] = field(default_factory=lambda: dict(ROW_STATUS))
    anchors: list[BoundAnchor] = field(default_factory=list)   # export dışı, adrese göre sıralı
    export_count: int = 0
    counts: dict[str, int] = field(default_factory=dict)       # çıkarıcının huni sayaçları

    def named(self) -> list[BoundAnchor]:
        return [a for a in self.anchors if a.skip is None]

    def skipped(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for a in self.anchors:
            if a.skip is not None:
                out[a.skip] = out.get(a.skip, 0) + 1
        return dict(sorted(out.items()))

    def fragments(self) -> list[dict[str, str]]:
        """Parça çapaları: ``{adres, ust_ad}`` (arayüz "X'in soğuk parçası" notunu buradan alır)."""
        return [{"adres": a.address, "ust_ad": a.name} for a in self.anchors
                if a.role == K.ROLE_FRAGMENT]

    def as_dict(self) -> dict[str, Any]:
        """Yan çıktı (``reconstructed/kesin_capalar.json``). GT değil; ürünün kendi kanıt dökümü."""
        return {
            "sema": BINDING_SCHEMA, "surum": BINDING_VERSION, "ks1_surumu": K.KS1_VERSION,
            "durum": self.status, "ayrinti": self.detail, "program": self.program,
            "abi": self.abi, "cpp": self.cpp, "satir_durumu": dict(self.row_status),
            "capalar": [a.as_dict() for a in self.anchors if a.role != K.ROLE_FRAGMENT],
            "parcalar": self.fragments(), "export": self.export_count,
            "ad_veren": len(self.named()), "atlanan": self.skipped(),
            "sayaclar": dict(self.counts),
        }


def disabled() -> Binding:
    """Bayrak kapalıyken adımın çıktısı."""
    return Binding(status=RUN_DISABLED)


def _skip_reason(anchor: K.Anchor, key: str, label: str | None) -> str | None:
    if anchor.role == K.ROLE_FRAGMENT:
        return SKIP_FRAGMENT
    if not key:
        return SKIP_KEY
    if not K.name_candidate(anchor.name):
        return SKIP_NAME_FORM
    if label is None:
        return SKIP_SILENT_ROW
    return None


def bind(result: K.Ks1Result, functions: Mapping[int, K.Function], *, cpp: bool,
         row_status: Mapping[str, str] = ROW_STATUS, status: str = RUN_OK,
         detail: str = "") -> Binding:
    """Çıkarım sonucundan bağlama (saf; dosya okumaz).

    ``functions``: adres → Ghidra fonksiyonu (``StaticInput.functions``); anahtar buradan okunur.
    Adresten ``FUN_%08x`` kurulmaz: Ghidra'nın adlandırdığı fonksiyonda o anahtar metinde geçmez.
    """
    _check_row_status(row_status)
    bound: list[BoundAnchor] = []
    exports = 0
    for address in sorted(result.anchors, key=lambda a: int(a, 16)):
        anchor = result.anchors[address]
        if not set(anchor.types) & set(K.STRING_TYPES):
            exports += 1   # yalnız ``export``: ad zaten Ghidra'nın, etiket verilmez
            continue
        function = functions.get(int(address, 16))
        function_name = function.name if function is not None else ""
        key = pre_name_key(function_name)
        rows = anchor_rows(anchor.types, anchor.role)
        label = anchor_label(rows, cpp=cpp, row_status=row_status)
        bound.append(BoundAnchor(
            address=address, key=key, function_name=function_name, name=anchor.name,
            types=tuple(anchor.types), role=anchor.role, rows=rows, label=label,
            skip=_skip_reason(anchor, key, label),
            evidence=tuple(e.as_dict() for e in anchor.evidence)))
    return Binding(status=status, detail=detail, program=result.program, abi=result.abi, cpp=cpp,
                   row_status={row: row_status.get(row, STATUS_SILENT) for row in DECISION_ROWS},
                   anchors=bound, export_count=exports, counts=dict(result.counts))


def bind_static(static_dir: Path | str | None, *,
                row_status: Mapping[str, str] = ROW_STATUS) -> Binding:
    """``static/`` dizininden bağlama. Hat düşmesin diye hata fırlatmaz; durum ``status``'tadır.

    - ``girdi_eksik``: dizin ya da ``REQUIRED_FILES``'tan biri yok; ya da hiçbir fonksiyonun gömülü
      disassembly'si okunamadı;
    - ``desteklenmeyen_platform``: çağrı kuralı bilinmiyor (AArch64 dışı); dizgi türleri çıkmaz;
    - ``hata``: girdi bozuk ya da çıkarım hata verdi (ayrıntı ``detail``'de).

    Türler daraltılmaz: daraltılırsa K3 başka sonuç verir ve çapa kümesi ölçülenden ayrılır.
    """
    _check_row_status(row_status)
    table = {row: row_status.get(row, STATUS_SILENT) for row in DECISION_ROWS}
    if static_dir is None or not Path(static_dir).is_dir():
        return Binding(status=RUN_INPUT_MISSING, detail="static dizini yok", row_status=table)
    root = Path(static_dir)
    missing = [name for name in REQUIRED_FILES if not (root / name).is_file()]
    if missing:
        return Binding(status=RUN_INPUT_MISSING, detail="eksik dosya: " + ", ".join(missing),
                       row_status=table)
    try:
        inp = K.load_static(root)
        result = K.extract(inp)
        raw = json.loads((root / FUNCTIONS_FILE).read_text(encoding="utf-8"))
        cpp = is_cpp_binary(raw.get("functions", []), macho=is_macho(inp.executable_format))
    except Exception as exc:   # girdi ürünün dışından gelir; her hata durum koduna çevrilir
        return Binding(status=RUN_ERROR, detail=f"{type(exc).__name__}: {exc}", row_status=table)
    if result.abi is None:
        return bind(result, inp.functions, cpp=cpp, row_status=row_status, status=RUN_UNSUPPORTED,
                    detail=f"{inp.processor or '?'} / {inp.executable_format or '?'}")
    if not inp.code:
        return Binding(status=RUN_INPUT_MISSING, detail="gömülü disassembly yok",
                       program=inp.program, abi=result.abi, cpp=cpp, row_status=table)
    return bind(result, inp.functions, cpp=cpp, row_status=row_status)


# --------------------------------------------------------------------------------------------
# Ön ad sözlüğüne yazma


def apply_binding(extracted_names: dict[str, str], binding: Binding | None,
                  meta: dict[str, dict[str, Any]],
                  stats: dict[str, Any] | None = None) -> dict[str, Any]:
    """KS-1 adlarını ön ad sözlüğüne, künyelerini ``meta``'ya yazar; özet döndürür.

    Çağrı sırası: ``main`` tohumundan sonra, gnulib ve ELF önyükü tohumlarından önce; elle adlar en
    sonda (KS-1'i ezer, ``mark_changed`` künyeyi ``elle`` yapar). Kurallar:

    - anahtar elle ya da ``main`` girişi künyesi taşıyorsa, ya da adı ``main`` ise: dokunulmaz;
    - çapanın adı ``main`` ve bu ad başka bir anahtardaysa: yazılmaz;
    - anahtarda başka bir ad varsa ezilir ve ezilen ad türüne göre sayılır (künyesiz ad Faz 1'dir).

    Yeniden çağrılabilir: aynı girdilerle ikinci çağrı hiçbir şeyi değiştirmez (``written`` 0).
    ``binding`` yoksa (KS-1 yapıtı üretilmediyse) hiçbir şey yapılmaz.

    ``stats`` verilirse şu anahtarlar yazılır: ``ks1_status``, ``ks1_anchors`` (export dışı çapa),
    ``ks1_export``, ``ks1_named`` (şu an KS-1 adını taşıyan anahtar), ``ks1_kesin``,
    ``ks1_skipped`` (neden → sayı) ve ``ks1_overrode`` (ezilen ad türü → sayı; çağrılar boyunca
    birikir). Her çağrıda ``ks1_anchors == ks1_named + Σ ks1_skipped`` tutar.
    """
    summary: dict[str, Any] = {"written": 0, "named": 0, "kesin": 0, "skipped": {}, "overrode": {}}
    if binding is None:
        return summary
    skipped = dict(binding.skipped())
    overrode: dict[str, int] = {}

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    for anchor in binding.named():
        key = anchor.key
        current = extracted_names.get(key)
        kind: str | None = None   # anahtardaki adın türü; künyesiz ad Faz 1'dir
        if current is not None:
            entry = meta_for(meta, key, current)
            kind = str(entry["kind"]) if entry else KIND_PHASE1
        if kind in PROTECTED_KINDS or current == MAIN_NAME:
            skip(SKIP_PROTECTED)
            continue
        # buraya gelen anahtarın adı ``main`` değildir: ``main`` varsa başka bir anahtardadır
        if anchor.name == MAIN_NAME and MAIN_NAME in extracted_names.values():
            skip(SKIP_MAIN_TAKEN)
            continue
        new_entry = anchor.meta()
        if current != anchor.name or meta.get(key) != new_entry:
            if kind is not None and current != anchor.name:
                overrode[kind] = overrode.get(kind, 0) + 1
            extracted_names[key] = anchor.name
            meta[key] = new_entry
            summary["written"] += 1
        summary["named"] += 1
        if anchor.label == LABEL_KESIN:
            summary["kesin"] += 1
    summary["skipped"] = dict(sorted(skipped.items()))
    summary["overrode"] = dict(sorted(overrode.items()))
    if stats is not None:
        total = dict(stats.get("ks1_overrode") or {})
        for kind_, count in overrode.items():
            total[kind_] = total.get(kind_, 0) + count
        stats["ks1_status"] = binding.status
        stats["ks1_anchors"] = len(binding.anchors)
        stats["ks1_export"] = binding.export_count
        stats["ks1_named"] = summary["named"]
        stats["ks1_kesin"] = summary["kesin"]
        stats["ks1_skipped"] = summary["skipped"]
        stats["ks1_overrode"] = dict(sorted(total.items()))
    return summary
