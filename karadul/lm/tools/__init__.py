"""KaradulLM araç kaydı ve saklı çalışma alanının salt okunur görünümü.

Sözleşme: ``docs/arge/2026-11-11_karadullm/arac_sozlesmeleri.md`` §1 (ortak kurallar) ve §5 (ilk
dilimin araç kümesi: O1 ``get_evidence``, O2 ``get_decompiled``, O3 ``get_xrefs``; ``read.py``).

Kurallar (sözleşme §1.1-1.5, tasarım §6.2):

- Araçlar yalnız etkin çalışma alanının saklı dosyalarını OKUR; canlı Ghidra istemez, dosya yazmaz,
  ağa çıkmaz, hedefi çalıştırmaz. Hiçbir araç dosya yolu, kabuk komutu, URL ya da düzenli ifade
  almaz: çalışma alanının kökünü sunucu verir, model yalnız ``FUN_<adres>`` ve kapalı seçenekler yazar.
- Argüman şemaları ``protocol.check_schema``'dan geçer (bilinmeyen anahtar reddedilir).
- Her sonuç aynı zarfı taşır: ``id``, ``tool``, ``ok``, ``data``, ``kind``, ``source``, ``limits``,
  ``truncated``. ``limits`` sözleşmenin yazdığı sabit sınırlama notudur; model uydurmaz.
- Sonuç boyut tavanını aşamaz. Kırpma sessiz değildir: atılan kısım ``truncated`` ile bildirilir
  (K-A4). Tavanı aşan bir sonuç hiçbir koşulda isteme girmez (``ic_hata`` döner).
- Körlük kipinde (``ToolContext.blind_target``) hedef fonksiyonun Karadul adı hiçbir sonuca girmez;
  elle ve model kökenli komşu adları da girmez (sözleşme §1.5).

Çağrı kenarlarının kaynağı arayüzle aynıdır: ``static/ghidra_call_graph.json``
(``ui/server.py::_call_graph_edges``). Ürün ``ui/``'yi içe aktarmaz; mantık buraya kopyalandı ve
eşitliği ``tests/test_lm_tools.py`` ile kilitli.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from karadul.core.naming_labels import (
    LABEL_CERTAIN, LABEL_UNVERIFIED, LABEL_VERIFIED, NAMING_PROVENANCE_FILE, PROVENANCE_GLOBAL, provenance_label,
)
from karadul.lm import NAME_TAG_MAX_CHARS, protocol
from karadul.lm.audit import sha256_text
from karadul.lm.context import NameLookup, escape_json, wrap_result

# --- Sonuç türleri (sözleşme §1.3) ----------------------------------------------------------
KIND_FACT = "olgu"              # Ghidra'nın ya da ikilinin doğrudan söylediği
KIND_PROXY = "vekil"            # decompile metninden düzenli ifadeyle çıkarılan
KIND_INFERENCE = "cikarim"      # Karadul'un etiketli adı
KIND_FACT_AND_INFERENCE = f"{KIND_FACT}+{KIND_INFERENCE}"

# --- Hata kodları ---------------------------------------------------------------------------
# Sözleşme §1.3'teki beş kod:
ERR_UNKNOWN_ADDRESS = "bilinmeyen_adres"
ERR_BUDGET = "butce_asildi"
ERR_REPEAT = "tekrar"
ERR_TOOL_CLOSED = "arac_kapali"
ERR_INTERNAL = "ic_hata"
# Bu işte eklenen iki kod (sözleşmede karşılığı yok; asama1b.md §2):
ERR_NO_DATA = "veri_yok"                # adres biliniyor ama istenen saklı dosya yok
ERR_BAD_ARGUMENT = "gecersiz_arguman"   # şemaya uymayan ya da anlamsız argüman birleşimi
# Geçersiz çağrı sayılan hatalar (K-A1'in "anlam" payı).
INVALID_CALL_ERRORS = frozenset({ERR_UNKNOWN_ADDRESS, ERR_BAD_ARGUMENT, ERR_TOOL_CLOSED})

# --- Ad etiketleri (sözleşme §1.6) ----------------------------------------------------------
TAG_PROVEN, TAG_VERIFIED, TAG_UNVERIFIED = "proven", "verified", "unverified"
TAG_MANUAL, TAG_MODEL = "manual", "model"
LABEL_TAGS = {LABEL_CERTAIN: TAG_PROVEN, LABEL_VERIFIED: TAG_VERIFIED, LABEL_UNVERIFIED: TAG_UNVERIFIED}
# Körlük kipinde sonuçlara girmeyen etiketler (sözleşme §1.5; tasarım §5.3 "Ölçüm kipi").
BLIND_HIDDEN_TAGS = frozenset({TAG_MANUAL, TAG_MODEL})

# Sözleşme §1.2: adres argümanı.
ADDR_PATTERN = "^FUN_[0-9a-fA-F]{3,16}$"
_ADDR_RE = re.compile(ADDR_PATTERN)
_FUN_FILE_RE = re.compile(r"^FUN_([0-9a-fA-F]+)\.c$")
# ui/server.py:74 ``_FUN_RE``
_FUN_RE = re.compile(r"FUN_[0-9a-fA-F]+")
# Kanıt paketine giren ad düz bir C tanımlayıcısı olmalı: köşeli ayraç, boşluk ya da noktalama
# taşıyan bir "ad" etiket biçimini (``FUN_x [etiket: ad]``) bozabilirdi.
_NAME_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class WorkspaceError(Exception):
    """Çalışma alanı okunamıyor ya da beklenen dosya yok."""


class ToolError(Exception):
    """Aracın bildirdiği hata; ``code`` zarfın ``error`` alanına yazılır."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _hex_int(text: Any) -> Optional[int]:
    """``0x00103cc0`` / ``00103CC0`` → tamsayı; onaltılık değilse ``None``."""
    if not isinstance(text, str):
        return None
    s = text.lower()
    if s.startswith("0x"):
        s = s[2:]
    try:
        return int(s, 16)
    except ValueError:
        return None


def _read_json(path: Path) -> Any:
    """JSON dosyası; yoksa ya da bozuksa ``None`` (uydurma yok)."""
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def call_graph_edges(data: Any, addr_set: set[str]) -> Optional[dict[str, set[str]]]:
    """Ghidra çağrı grafiğinden ``FUN_`` düğümleri arasındaki çağrı kenarları: ``{çağıran: {çağrılan}}``.

    Kopya: ``ui/server.py::_call_graph_edges``'in veri kısmı (dosya arama hariç). Grafik adrese
    anahtarlıdır (``edges[].from/to`` ya da ``nodes[adres].callees[].address``); adres ``addr_set``'teki
    ``FUN_<adres>`` adına çevrilir. Yalnız iki ucu da ``addr_set``'te olan kenarlar tutulur. Biçim
    beklenen değilse ya da grafiğin düğümleri ``addr_set`` ile hiç örtüşmüyorsa (başka koşunun
    grafiği) ``None``.
    """
    if not isinstance(data, dict):
        return None
    by_hex = {a[4:].lower(): a for a in addr_set}

    def fun(address: Any) -> Optional[str]:
        if not isinstance(address, str):
            return None
        h = address.lower()
        if h.startswith("0x"):
            h = h[2:]
        return by_hex.get(h)

    pairs: list[tuple] = []
    nodes = data.get("nodes")
    edges = data.get("edges")
    if isinstance(edges, list):
        pairs = [(e.get("from"), e.get("to")) for e in edges if isinstance(e, dict)]
    elif isinstance(nodes, dict):
        pairs = [(a, c.get("address")) for a, n in nodes.items() if isinstance(n, dict)
                 for c in (n.get("callees") or []) if isinstance(c, dict)]
    else:
        return None
    if isinstance(nodes, dict):
        known = {fun(a) for a in nodes}
    else:
        known = {fun(x) for pair in pairs for x in pair}
    known.discard(None)
    if addr_set and not known:
        return None
    out: dict[str, set[str]] = {}
    for src, dst in pairs:
        s, d = fun(src), fun(dst)
        if s and d:
            out.setdefault(s, set()).add(d)
    return out


class Workspace:
    """Saklı bir Karadul çalışma alanının (``…/workspaces/<ad>/<zaman>/``) salt okunur görünümü.

    Adresler içeride ``ghidra_functions.json``'daki yazımıyla (küçük harf, ``0x``'siz) taşınır;
    ``resolve`` modelin yazdığı ``FUN_<adres>``'i sayı değeri üzerinden bu yazıma çevirir. Dizinler
    ilk kullanımda kurulur ve nesne ömrünce saklanır; çalışma alanı bu sırada değişmez sayılır.
    """

    def __init__(self, root: Path):
        self.root = Path(root)
        self.static_dir = self.root / "static"
        self.code_dir = self.static_dir / "ghidra_output" / "decompiled"
        data = _read_json(self.static_dir / "ghidra_functions.json")
        funcs = data.get("functions") if isinstance(data, dict) else None
        if not isinstance(funcs, list):
            raise WorkspaceError("static/ghidra_functions.json okunamadı ya da 'functions' listesi yok")
        self._functions: dict[int, str] = {}
        for f in funcs:
            n = _hex_int(f.get("address")) if isinstance(f, dict) else None
            if n is not None:
                self._functions.setdefault(n, f"{f['address']}".lower().removeprefix("0x"))
        self._cache: dict[str, Any] = {}

    # --- adresler -----------------------------------------------------------------------------

    def resolve(self, addr: Any) -> Optional[str]:
        """``FUN_<adres>`` → çalışma alanındaki yazımıyla adres; biçim bozuksa ya da adres
        ``ghidra_functions.json``'da yoksa ``None`` (sözleşme §1.2)."""
        if not isinstance(addr, str) or not _ADDR_RE.fullmatch(addr):
            return None
        return self._functions.get(int(addr[4:], 16))

    def function_count(self) -> int:
        return len(self._functions)

    def _canon(self, hexaddr: Any) -> Optional[str]:
        n = _hex_int(hexaddr)
        return None if n is None else self._functions.get(n)

    # --- decompile metni ----------------------------------------------------------------------

    @property
    def code_files(self) -> dict[str, Path]:
        """Decompile dosyası olan program fonksiyonları: adres → ``FUN_<adres>.c`` yolu."""
        if "code_files" not in self._cache:
            out: dict[str, Path] = {}
            if self.code_dir.is_dir():
                for p in sorted(self.code_dir.glob("FUN_*.c")):
                    m = _FUN_FILE_RE.match(p.name)
                    a = self._canon(m.group(1)) if m else None
                    if a is not None:
                        out.setdefault(a, p)
            self._cache["code_files"] = out
        return self._cache["code_files"]

    def program_addresses(self) -> list[str]:
        """Decompile dosyası olan program fonksiyonlarının adresleri (adrese göre artan)."""
        return sorted(self.code_files, key=lambda a: int(a, 16))

    def read_code(self, hexaddr: str) -> Optional[str]:
        """Fonksiyonun ham decompile metni; dosya yoksa ya da okunamıyorsa ``None``."""
        p = self.code_files.get(hexaddr)
        if p is None:
            return None
        try:
            return p.read_text(errors="replace")
        except OSError:
            return None

    # --- kanıt paketleri ----------------------------------------------------------------------

    @property
    def packs(self) -> dict[str, Any]:
        """``build_evidence`` paketleri, çalışma alanı adres yazımıyla anahtarlı."""
        if "packs" not in self._cache:
            from karadul.reconstruction.tarif.evidence import build_evidence
            try:
                raw = build_evidence(self.static_dir)
            except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
                raise WorkspaceError(f"kanıt paketleri kurulamadı: {type(e).__name__}") from e
            out: dict[str, Any] = {}
            for k, p in raw.items():
                a = self._canon(k)
                if a is not None:
                    out.setdefault(a, p)
            self._cache["packs"] = out
        return self._cache["packs"]

    # --- çağrı kenarları ----------------------------------------------------------------------

    def _fun_names(self) -> dict[str, str]:
        """Arayüzün düğüm adı (dosya adı, uzantısız) → adres."""
        return {p.name[:-2]: a for a, p in self.code_files.items()}

    @property
    def call_edges(self) -> Optional[dict[str, set[str]]]:
        """Program fonksiyonları arasındaki çağrı kenarları (adres → çağırdığı adresler); çağrı
        grafiği yoksa, bozuksa ya da bu çalışma alanına ait değilse ``None``."""
        if "call_edges" not in self._cache:
            names = self._fun_names()
            raw = call_graph_edges(_read_json(self.static_dir / "ghidra_call_graph.json"), set(names))
            self._cache["call_edges"] = None if raw is None else {
                names[s]: {names[d] for d in ds} for s, ds in raw.items()}
        return self._cache["call_edges"]

    def callees(self, hexaddr: str) -> Optional[list[str]]:
        """``hexaddr``'in ÇAĞIRDIĞI program fonksiyonları (kendisi hariç); grafik yoksa ``None``."""
        edges = self.call_edges
        if edges is None:
            return None
        return sorted(edges.get(hexaddr, set()) - {hexaddr}, key=lambda a: int(a, 16))

    def callers(self, hexaddr: str) -> Optional[list[str]]:
        """``hexaddr``'i ÇAĞIRAN program fonksiyonları (kendisi hariç); grafik yoksa ``None``."""
        edges = self.call_edges
        if edges is None:
            return None
        return sorted((s for s, ds in edges.items() if hexaddr in ds and s != hexaddr), key=lambda a: int(a, 16))

    @property
    def _address_refs(self) -> Optional[dict[str, set[str]]]:
        """Metin vekili (``ui/server.py::build_model`` ``addr_refs``): fonksiyon → metninde adı geçip
        çağrı kenarı olmayan program fonksiyonları."""
        if "address_refs" not in self._cache:
            edges = self.call_edges
            if edges is None:
                self._cache["address_refs"] = None
            else:
                names = self._fun_names()
                refs: dict[str, set[str]] = {}
                for a in self.code_files:
                    text = self.read_code(a) or ""
                    mentioned = {names[m] for m in set(_FUN_RE.findall(text)) if m in names}
                    mentioned.discard(a)
                    extra = mentioned - edges.get(a, set())
                    if extra:
                        refs[a] = extra
                self._cache["address_refs"] = refs
        return self._cache["address_refs"]

    def address_refs_from(self, hexaddr: str) -> Optional[list[str]]:
        """``hexaddr``'in metninde adı geçip çağırmadığı program fonksiyonları."""
        refs = self._address_refs
        return None if refs is None else sorted(refs.get(hexaddr, set()), key=lambda a: int(a, 16))

    def address_refs_to(self, hexaddr: str) -> Optional[list[str]]:
        """Metninde ``hexaddr``'in adı geçip onu çağırmayan program fonksiyonları."""
        refs = self._address_refs
        if refs is None:
            return None
        return sorted((s for s, ds in refs.items() if hexaddr in ds), key=lambda a: int(a, 16))

    # --- adlar --------------------------------------------------------------------------------

    def _fun_keyed(self, key: str, path: Path, section: str) -> dict[str, Any]:
        if key not in self._cache:
            data = _read_json(path)
            table = data.get(section) if isinstance(data, dict) else None
            out: dict[str, Any] = {}
            if isinstance(table, dict):
                for k, v in table.items():
                    a = self._canon(k[4:]) if isinstance(k, str) and k.startswith("FUN_") else None
                    if a is not None:
                        out.setdefault(a, v)
            self._cache[key] = out
        return self._cache[key]

    @property
    def _names(self) -> dict[str, Any]:
        return self._fun_keyed("names", self.root / "reconstructed" / "src" / "naming_map.json", "global")

    @property
    def _provenance(self) -> dict[str, Any]:
        return self._fun_keyed("provenance", self.root / "reconstructed" / "src" / NAMING_PROVENANCE_FILE,
                               PROVENANCE_GLOBAL)

    def raw_name(self, hexaddr: str) -> Optional[str]:
        """Ad haritasında bu fonksiyon için yazılı ad (süzülmemiş); yoksa ``None``."""
        name = self._names.get(hexaddr)
        return name if isinstance(name, str) and name else None

    def name_tag(self, hexaddr: str) -> Optional[tuple[str, str]]:
        """Fonksiyonun gösterilebilir adı ve etiketi (sözleşme §1.6); ad yoksa ``None``.

        Gösterilmeyenler: yer tutucu / oto-ad, düz tanımlayıcı olmayan ya da çok uzun ad. Etiket köken
        kaydından okunur: kayıt o anki adı anlatıyorsa kaydın etiketi (elle verilen ad ``manual``);
        kayıt başka bir adı anlatıyorsa ad sonradan elle verilmiştir (``manual``;
        ``ui/server.py::_provenance`` kuralı); kayıt hiç yoksa ``unverified``.
        """
        name = self.raw_name(hexaddr)
        if name is None or len(name) > NAME_TAG_MAX_CHARS or not _NAME_OK.fullmatch(name):
            return None
        if protocol.is_placeholder_name(name, [int(hexaddr, 16)]):
            return None
        rec = self._provenance.get(hexaddr)
        if not isinstance(rec, dict):
            return name, TAG_UNVERIFIED
        if rec.get("new_name") != name:
            return name, TAG_MANUAL
        return name, LABEL_TAGS.get(provenance_label(rec), TAG_MANUAL)

    def _has_engine_record(self, hexaddr: str, name: str) -> bool:
        rec = self._provenance.get(hexaddr)
        return isinstance(rec, dict) and rec.get("new_name") == name

    def name_lookup(self, blind_target: Optional[str] = None) -> NameLookup:
        """Kanıt paketinin komşu adı işlevi (``llm_pilot.kanit_alanlari``'nin ``ad_bul``'u).

        ``blind_target`` verilirse (körlük kipi): o adresin adı; onunla aynı adı taşıyan komşular;
        ``manual`` / ``model`` etiketli adlar; köken kaydı o anki adı anlatmayan adlar gösterilmez.
        """
        if blind_target is None:
            return lambda a: self.name_tag(self._canon(a) or a)
        hidden = self.raw_name(blind_target)

        def lookup(a: str) -> Optional[tuple[str, str]]:
            a = self._canon(a) or a
            if a == blind_target:
                return None
            r = self.name_tag(a)
            if r is None or r[1] in BLIND_HIDDEN_TAGS or r[0] == hidden:
                return None
            return r if self._has_engine_record(a, r[0]) else None

        return lookup


def format_tag(name_tag: Optional[tuple[str, str]]) -> Optional[str]:
    """``(ad, etiket)`` → ``[etiket: ad]`` (pilot biçimindeki köşeli ayraç); ad yoksa ``None``."""
    return None if name_tag is None else f"[{name_tag[1]}: {name_tag[0]}]"


# ---------------------------------------------------------------------------------------------
# Sonuç zarfı ve araç kaydı


@dataclass(frozen=True)
class ToolContext:
    """Çağrının sunucu tarafındaki bağlamı; model göremez ve değiştiremez.

    ``single_shot``: K0'da paketi sunucu kurar; ``get_decompiled`` pilotun tek atış kırpmasını
    (9.000 bayt, baştan 7.000 + sondan 2.000) uygular. ``blind_target``: körlük kipinde hedef
    fonksiyonun adresi (çalışma alanı yazımıyla).
    """

    single_shot: bool = False
    blind_target: Optional[str] = None


@dataclass(frozen=True)
class ToolOutput:
    """Bir aracın başarılı çıktısı (zarfın ``id`` ve ``tool`` dışındaki alanları)."""

    data: dict[str, Any]
    kind: str
    source: str
    limits: tuple[str, ...]
    truncated: Optional[dict[str, Any]] = None


@dataclass(frozen=True)
class ToolResult:
    """Sonuç zarfı (sözleşme §1.3)."""

    id: str
    tool: str
    ok: bool
    data: Optional[dict[str, Any]] = None
    kind: Optional[str] = None
    source: Optional[str] = None
    limits: tuple[str, ...] = ()
    truncated: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    executed: bool = False      # araç işlevi gerçekten çalıştı mı (denetim günlüğü, K-L1)

    def envelope(self) -> dict[str, Any]:
        """Modele giden nesne. Hata: ``{"id", "tool", "ok": false, "error"}``."""
        if not self.ok:
            return {"id": self.id, "tool": self.tool, "ok": False, "error": self.error}
        out: dict[str, Any] = {"id": self.id, "tool": self.tool, "ok": True, "data": self.data,
                               "kind": self.kind, "source": self.source, "limits": list(self.limits)}
        if self.truncated is not None:
            out["truncated"] = self.truncated
        return out

    def wrapped(self) -> str:
        return wrap_result(self.envelope())

    def size_bytes(self) -> int:
        """Serileştirilmiş (kaçışlanmış) zarfın bayt uzunluğu."""
        return len(escape_json(self.envelope()).encode("utf-8"))

    def audit_fields(self) -> dict[str, Any]:
        """Denetim kaydı: sonuç metni değil özeti (tasarım §5.4 "Araç çağrısı")."""
        text = escape_json(self.envelope())
        return {"kimlik": self.id, "arac": self.tool, "tamam": self.ok, "hata": self.error,
                "calistirildi": self.executed, "sonuc_sha256": sha256_text(text),
                "sonuc_bayt": len(text.encode("utf-8")), "kirpma": self.truncated}


def error_result(result_id: str, tool: str, code: str, *, executed: bool = False) -> ToolResult:
    return ToolResult(id=result_id, tool=tool, ok=False, error=code, executed=executed)


ToolFunc = Callable[[Workspace, Mapping[str, Any], ToolContext], ToolOutput]


@dataclass(frozen=True)
class ToolSpec:
    """Kayıtlı bir araç: ad, argüman şeması, sonuç boyut sınırı, istemdeki tanımı ve işlevi."""

    name: str
    cls: str                        # sözleşme §1.1: "O" | "Ö" | "H"
    signature: str                  # istemdeki çağrı biçimi: ad(argümanlar)
    description: str                # istemdeki tek satırlık tanım (İngilizce; yön adları açık)
    args_schema: Mapping[str, Any]
    max_result_bytes: int
    func: ToolFunc = field(repr=False, compare=False)
    # Yazılmayan isteğe bağlı argümanların değeri; tekrar tespitinde aynı çağrıyı aynı anahtara indirir.
    defaults: Mapping[str, Any] = field(default_factory=dict)

    def definition_line(self) -> str:
        return f"{self.signature}: {self.description}"


class ToolRegistry:
    """Araç kaydı. Küme oturum boyunca sabittir (sözleşme §5): araç eklemek sabit öneki değiştirir."""

    def __init__(self, specs: Iterable[ToolSpec]):
        self._specs: dict[str, ToolSpec] = {}
        for s in specs:
            if s.name in self._specs:
                raise ValueError(f"araç adı yineleniyor: {s.name}")
            if "\n" in s.signature or "\n" in s.description:
                raise ValueError(f"{s.name}: tanım tek satır olmalı")
            if s.max_result_bytes <= 0:
                raise ValueError(f"{s.name}: sonuç boyut sınırı artı olmalı")
            protocol.check_schema(s.args_schema)
            if s.args_schema.get("type") != "object" or s.args_schema.get("additionalProperties") is not False:
                raise ValueError(f"{s.name}: argüman şeması kapalı bir nesne olmalı")
            self._specs[s.name] = s
        if not self._specs:
            raise ValueError("araç kaydı boş olamaz")

    def names(self) -> tuple[str, ...]:
        return tuple(self._specs)

    def spec(self, name: str) -> Optional[ToolSpec]:
        return self._specs.get(name)

    def definition_lines(self) -> tuple[str, ...]:
        """Sabit önekteki araç tanım satırları (kayıt sırasıyla)."""
        return tuple(s.definition_line() for s in self._specs.values())

    def version(self) -> str:
        """Araç kümesi sürümü: tanım satırlarının ve argüman şemalarının özeti (künye, §5.4)."""
        return sha256_text(escape_json([[s.name, s.definition_line(), s.args_schema, s.max_result_bytes]
                                        for s in self._specs.values()]))[:16]

    def schemas(self, addr_enum: Optional[Sequence[str]] = None) -> dict[str, dict[str, Any]]:
        """Zarfın araç dalları için argüman şemaları. ``addr_enum`` verilirse (K1) ``addr`` yalnız o
        kapalı listeden seçilebilir: geçersiz adres yapısal olarak üretilemez (tasarım §2.3)."""
        out: dict[str, dict[str, Any]] = {}
        for name, s in self._specs.items():
            schema = {**s.args_schema, "properties": dict(s.args_schema.get("properties", {}))}
            if addr_enum is not None and "addr" in schema["properties"]:
                if not addr_enum:
                    raise ValueError("kapalı adres listesi boş olamaz")
                schema["properties"]["addr"] = {"type": "string", "enum": list(addr_enum)}
            out[name] = schema
        return out

    def call(self, workspace: Workspace, name: str, args: Any, *, result_id: str,
             ctx: ToolContext = ToolContext()) -> ToolResult:
        """Aracı çalıştırır; her durumda bir zarf döner (istisna yükseltmez).

        Sıra: araç kayıtlı mı (``arac_kapali``) → argümanlar şemaya uyuyor mu (``gecersiz_arguman``)
        → araç (``ToolError`` kodu; beklenmeyen hata ``ic_hata``) → boyut tavanı (``ic_hata``)."""
        spec = self._specs.get(name)
        if spec is None:
            return error_result(result_id, str(name)[:64], ERR_TOOL_CLOSED)
        if not isinstance(args, dict) or protocol.validate(args, spec.args_schema):
            return error_result(result_id, name, ERR_BAD_ARGUMENT)
        try:
            out = spec.func(workspace, args, ctx)
        except ToolError as e:
            return error_result(result_id, name, e.code, executed=True)
        except Exception:  # noqa: BLE001 — araç hatası görevi düşürmez; model sabit bir kod görür
            return error_result(result_id, name, ERR_INTERNAL, executed=True)
        result = ToolResult(id=result_id, tool=name, ok=True, data=out.data, kind=out.kind, source=out.source,
                            limits=tuple(out.limits), truncated=out.truncated, executed=True)
        if result.size_bytes() > spec.max_result_bytes:
            return error_result(result_id, name, ERR_INTERNAL, executed=True)
        return result


def default_registry() -> ToolRegistry:
    """İlk dilimin araç kümesi (sözleşme §5): O1, O2, O3."""
    from karadul.lm.tools import read
    return ToolRegistry(read.READ_TOOLS)
