"""KS-1 kesin çapalar: fonksiyonun tam adını ikilinin kendisinden okuyan kaynaklar.

Plan v2.2 N1 (v2.1 3.2). Ön kayıt: ``docs/arge/2026-10-21_g11_n1/ks1_onkayit.md``.
Belirlenimci ve LLM'siz. Girdi yalnız Karadul'un ``static/`` çıktısıdır:

- ``ghidra_functions.json``: adres, ad, thunk/dış, ad kaynağı (``source``);
- ``ghidra_strings.json``: dizgi adresi → değer;
- ``ghidra_xrefs.json``: fonksiyonun başvurduğu dizgiler ve çağıranları;
- ``ghidra_combined_results.json``: işlemci ve dosya biçimi (çağrı kuralı buna göre seçilir);
- ``ghidra_output/decompiled/*.c``: başlıktaki adres ve dosya sonundaki gömülü disassembly.

Türler (tam tanımlar ön kayıt §3):

``assert``
    Darwin ``__assert_rtn(fonksiyon, dosya, satır, ifade)``: 1. argüman.
    glibc ``__assert_fail`` / ``__assert_perror_fail(ifade, dosya, satır, fonksiyon)``: 4. argüman.
``func_kalibi``
    Bir çağrıda tek bir argüman ``%s:`` ya da ``%s()`` ile başlayan biçim dizgisidir; o ilk ``%s``'e
    hizalı argüman (biçimden sonraki ilk değişken argüman) tanımlayıcı biçimli sabit dizgidir.
``func_aktarma``
    Fonksiyonun bir parametresi ``func_kalibi`` hizasına (ya da başka bir aktarıcının aynı
    parametresine) gidiyorsa fonksiyon o parametrenin aktarıcısıdır. Aktarıcıya o parametrede
    tanımlayıcı biçimli sabit dizgi geçiren çağrı yeri bu türden kanıttır.
``export``
    Ghidra'nın ikilinin kendi simge tablosundan (``source == IMPORTED``) adlandırdığı, thunk ve dış
    olmayan fonksiyon. KS-1 yalnız işaretler; kesinlik ölçüsünü şişirmemesi için ayrı türdür.

Neden disassembly: Darwin arm64'te değişken sayılı argümanlar yığında geçer; Ghidra'nın C çıktısı
``log("%s: ...", __func__)`` çağrısını ``FUN_x("%s: ...")`` diye gösterir, ``__func__``
görünmez. Argümanlar bu yüzden disassembly üzerinde, fonksiyon içi ileri veri akışıyla okunur;
birleşme noktasında yalnız bütün gelen yollarda aynı olan değerler tutulur.

İnline koruması (ön kayıt §5), sırasıyla:

- K0 başlık dosyası: dosya argümanı başlık (``.h`` …) olan assert yuvası çapa vermez; başlıkta
  tanımlı fonksiyon başka gövdelere inline edilmiş olabilir. Bu adlar K3'te gövde adı sayılmaz.
- K1 saf başvuru: dizgiye başvuran her fonksiyon onu bir ad yuvasında kullanır (ya da yalnız assert
  yuvasında tüketilen bir yükleyicidir); başka türlü başvuru varsa dizgi çapa vermez.
- K2 tek sahip: dizginin yuva kullanıcıları (assert parçaları üst fonksiyona kaldırılarak) tek bir
  fonksiyona iner; inmezse çapa yok.
- K3 gövdede tek ad: bir fonksiyonun ad yuvalarında (elenmiş dizgiler dahil) birden çok farklı ad
  varsa çapa yok. Türler arası çelişki de buraya düşer.
- K4 ad tekliği: aynı ad birden çok fonksiyona çapalanıyorsa hiçbirine çapa yok.
- K5 zaten adlı: Ghidra fonksiyonu kendisi adlandırmışsa dizgi türlerinden çapa yazılmaz.

Çıktı adrese göre sıralıdır; bütün küme dolaşımları sıralıdır (belirlenimcilik).
"""

from __future__ import annotations

import heapq
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

KS1_VERSION = 1

TYPE_ASSERT = "assert"
TYPE_FUNC = "func_kalibi"
TYPE_FORWARD = "func_aktarma"
TYPE_EXPORT = "export"
STRING_TYPES = (TYPE_ASSERT, TYPE_FUNC, TYPE_FORWARD)
ALL_TYPES = STRING_TYPES + (TYPE_EXPORT,)

ROLE_OWN = "kendi"       # yuva fonksiyonun kendi gövdesinde
ROLE_LIFTED = "ust"      # yuva bir assert parçasında; çapa parçanın tek üst fonksiyonuna
ROLE_FRAGMENT = "parca"  # assert parçasının kendisi: üst fonksiyonun adını taşır, ayrı raporlanır

ABI_DARWIN = "darwin"    # Apple arm64: değişken argümanlar yığında, [sp, #0]'dan başlayarak
ABI_AAPCS = "aapcs"      # AAPCS64 (ELF): değişken argümanlar sabit argümanlar gibi x0-x7'de

# Assert işlevi (baştaki alt çizgiler atılmış ad) → fonksiyon adı argümanının sırası (0 tabanlı)
ASSERT_FUNCTIONS: Mapping[str, int] = {"assert_rtn": 0, "assert_fail": 3, "assert_perror_fail": 3}
# Üçünde de dosya adı 2. argümandır (x1)
ASSERT_FILE_ARG = 1
# Başlık dosyası: assert'i yazan fonksiyon başlıkta tanımlı (inline edilen yardımcı) sayılır (K0)
HEADER_FILE_RE = re.compile(r"\.(?:h|hh|hpp|hxx|h\+\+|inl|inc|def|tcc)$", re.I)

# Ad yuvasındaki dizgi: C tanımlayıcısı, en az iki karakter
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]+$")
# Biçim dizgisi: ``%s`` ile başlar, hemen ardından ``:`` ya da ``()`` gelir
FORMAT_RE = re.compile(r"^%s(?::|\(\))")
ARG_REGS = 8

# Ghidra'nın yer tutucu ya da kendiliğinden verdiği adlar: fonksiyon "ad bekliyor"
GENERIC_NAME_RE = re.compile(
    r"^(?:(?:thunk_)?FUN_[0-9A-Fa-f]+|LAB_[0-9A-Fa-f]+|SUB_[0-9A-Fa-f]+|sub_[0-9A-Fa-f]+"
    r"|entry|_(?:INIT|FINI)_\d+)$")
# Ghidra'nın simge tablosu dışından (giriş noktası, .init/.fini, dinamik bölüm) koyduğu adlar
NOT_EXPORT_NAMES = frozenset({
    "entry", "_start", "_init", "_fini", "_DT_INIT", "_DT_FINI", "__libc_csu_init",
    "__libc_csu_fini", "_mh_execute_header", "__mh_execute_header",
})
SOURCE_IMPORTED = "IMPORTED"

# Koruma kuralları ve eleme nedenleri (ön kayıt §5)
DROP_HEADER = "K0_baslik_dosyasi"
DROP_IMPURE = "K1_yuva_disi_basvuru"
DROP_NO_OWNER = "K2_sahipsiz"
DROP_MULTI_OWNER = "K2_cok_sahip"
DROP_BODY_MULTI = "K3_govdede_cok_ad"
DROP_NAME_MULTI = "K4_ad_cok_fonksiyonda"
DROP_NAMED = "K5_zaten_adli"
DROP_REASONS = (DROP_HEADER, DROP_IMPURE, DROP_NO_OWNER, DROP_MULTI_OWNER, DROP_BODY_MULTI,
                DROP_NAME_MULTI, DROP_NAMED)
# Huni aşamaları (her tür için ayrı sayılır; ön kayıt §5)
FUNNEL = ("1_yuva", "2_dizgi", "3_K0_sonrasi", "4_K1_sonrasi", "5_K2_sonrasi", "6_aday_fonksiyon",
          "7_K3_sonrasi", "8_K4_sonrasi", "9_capa")

_DISASM_HEADER = "// --- DISASSEMBLY"
_ADDRESS_HEADER = re.compile(r"^// Address:\s+([0-9A-Fa-f]+)\s*$", re.M)
_INSN_LINE = re.compile(r"^// ([0-9A-Fa-f]+)  (\S+)(?:\s+(.*?))?\s*$")
_XREG = re.compile(r"^[xw](\d+)$")
_COND_BRANCH = re.compile(r"^b\.[a-z]{2}$")
_MEM_SP = re.compile(r"^\[sp(?:,\s*#(-?(?:0x[0-9a-fA-F]+|\d+)))?\](!?)$")

_STORE_MNEMONICS = frozenset({
    "str", "strb", "strh", "stur", "sturb", "sturh", "stp", "stnp", "stlr", "stlrb", "stlrh",
    "stllr", "stllrb", "stllrh", "stlur", "stlurb", "stlurh", "st1", "st2", "st3", "st4",
})
_BYTE_STORES = {"strb": 1, "sturb": 1, "stlrb": 1, "stllrb": 1, "stlurb": 1,
                "strh": 2, "sturh": 2, "stlrh": 2, "stllrh": 2, "stlurh": 2}
# Yazmaç yazmayan komutlar (ilk işlenen kaynak ya da yok)
_NO_WRITE_MNEMONICS = _STORE_MNEMONICS | frozenset({
    "cmp", "cmn", "tst", "ccmp", "ccmn", "fcmp", "fcmpe", "fccmp", "fccmpe", "prfm", "prfum",
    "nop", "dmb", "dsb", "isb", "hint", "msr", "svc", "clrex", "yield", "bti", "csdb", "sev",
    "sevl", "wfe", "wfi",
})
_PAIR_LOADS = frozenset({"ldp", "ldnp", "ldpsw", "ldxp", "ldaxp"})
_ATOMIC_PREFIXES = ("ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin",
                    "swp", "cas")
_CALLER_SAVED = tuple(range(19)) + (30,)
_REG_WIDTH = {"x": 8, "w": 4, "q": 16, "d": 8, "s": 4, "h": 2, "b": 1}
_MAX_ROUNDS = 64   # blok başına en çok yeniden değerlendirme (güvenlik sınırı)

# Değer: (tür, sayı, köken). Köken: yükleyici özetinden geldiyse yükleyicinin adresi, yoksa -1.
PAGE = "sayfa"   # adrp sayfası
CONST = "sabit"  # adres sabiti
PARAM = "param"  # fonksiyon girişindeki x0-x7
Value = tuple[str, int, int]
NO_ORIGIN = -1


# --------------------------------------------------------------------------------------------
# Girdi


@dataclass(frozen=True)
class Function:
    address: int
    name: str
    is_thunk: bool
    is_external: bool
    source: str
    size: int


@dataclass(frozen=True)
class Insn:
    pc: int
    mnemonic: str
    operands: tuple[str, ...]


@dataclass
class StaticInput:
    """``static/`` dizininden okunan, KS-1'in kullandığı her şey."""

    program: str
    processor: str
    executable_format: str
    functions: dict[int, Function]
    strings: dict[int, str]
    string_refs: dict[int, set[int]]   # dizgi adresi → ona kod içinden başvuran fonksiyonlar
    callers: dict[int, set[int]]       # fonksiyon → çağıranlar (kendisi hariç)
    code: dict[int, list[Insn]]        # fonksiyon → komutlar (gömülü disassembly)


_HEX_ADDRESS = re.compile(r"^(?:0x)?([0-9a-f]+)$")


def _hex(text: object) -> int | None:
    """Ghidra adresi → sayı. Yüklenmeyen bölümlerin adresleri (``.shstrtab::00000001``) None."""
    m = _HEX_ADDRESS.match(str(text).strip().lower())
    return int(m.group(1), 16) if m else None


def split_operands(text: str) -> tuple[str, ...]:
    """Virgülle ayır; köşeli ayraç içindeki virgüller bölmez."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return tuple(parts)


def parse_disassembly(text: str) -> list[Insn]:
    """``.c`` dosyasının sonundaki ``// <adres>  <komut> <işlenenler>`` satırları."""
    i = text.find(_DISASM_HEADER)
    if i < 0:
        return []
    out: list[Insn] = []
    for line in text[i:].splitlines()[1:]:
        m = _INSN_LINE.match(line)
        if m:
            out.append(Insn(int(m.group(1), 16), m.group(2).lower(),
                            split_operands(m.group(3) or "")))
    return out


def load_static(static_dir: Path) -> StaticInput:
    static_dir = Path(static_dir)
    fdoc = json.loads((static_dir / "ghidra_functions.json").read_text(encoding="utf-8"))
    functions: dict[int, Function] = {}
    for f in fdoc.get("functions", []):
        a = _hex(f.get("address", ""))
        if a is None:
            continue
        functions.setdefault(a, Function(
            address=a, name=str(f.get("name") or ""), is_thunk=bool(f.get("is_thunk")),
            is_external=bool(f.get("is_external")), source=str(f.get("source") or ""),
            size=int(f.get("size") or 0)))
    sdoc = json.loads((static_dir / "ghidra_strings.json").read_text(encoding="utf-8"))
    strings: dict[int, str] = {}
    for s in sdoc.get("strings", []):
        a = _hex(s.get("address", ""))
        if a is not None and isinstance(s.get("value"), str):
            strings.setdefault(a, s["value"])
    xdoc = json.loads((static_dir / "ghidra_xrefs.json").read_text(encoding="utf-8"))
    string_refs: dict[int, set[int]] = {}
    callers: dict[int, set[int]] = {}
    for key, x in sorted(xdoc.get("function_xrefs", {}).items()):
        fa = _hex(x.get("address") or key)
        if fa is None:
            continue
        for s in x.get("strings_used", []):
            sa = _hex(s.get("address", ""))
            if sa is None:
                continue
            string_refs.setdefault(sa, set()).add(fa)
            if isinstance(s.get("value"), str):
                strings.setdefault(sa, s["value"])
        ups = {_hex(c.get("address", "")) for c in x.get("called_by", [])}
        callers[fa] = {u for u in ups if u is not None} - {fa}
    info: dict = {}
    combined = static_dir / "ghidra_combined_results.json"
    if combined.is_file():
        info = json.loads(combined.read_text(encoding="utf-8")).get("program_info") or {}
    code: dict[int, list[Insn]] = {}
    dec = static_dir / "ghidra_output" / "decompiled"
    for path in (sorted(dec.glob("*.c")) if dec.is_dir() else []):
        text = path.read_text(encoding="utf-8", errors="replace")
        m = _ADDRESS_HEADER.search(text[:2000])
        if not m:
            continue
        insns = parse_disassembly(text)
        if insns:
            code.setdefault(int(m.group(1), 16), insns)
    return StaticInput(
        program=str(fdoc.get("program") or info.get("name") or ""),
        processor=str(info.get("processor") or ""),
        executable_format=str(info.get("executable_format") or ""),
        functions=functions, strings=strings, string_refs=string_refs, callers=callers, code=code)


def detect_abi(inp: StaticInput) -> str | None:
    """Çağrı kuralı. Yalnız AArch64 desteklenir: Mach-O → Darwin, ELF → AAPCS64; başkası None."""
    if inp.processor.upper() != "AARCH64":
        return None
    fmt = inp.executable_format.lower()
    if "mach-o" in fmt:
        return ABI_DARWIN
    if "elf" in fmt or "executable and linking" in fmt:
        return ABI_AAPCS
    return None


# --------------------------------------------------------------------------------------------
# Fonksiyon içi veri akışı


def _imm(text: str) -> int | None:
    t = text.strip()
    if t.startswith("#"):
        t = t[1:]
    try:
        return int(t, 0)
    except ValueError:
        return None


def _reg(text: str) -> int | None:
    m = _XREG.match(text.strip())
    return int(m.group(1)) if m else None


def _is_sp(text: str) -> bool:
    return text.strip() in ("sp", "wsp")


def _branch(insn: Insn) -> tuple[str, int | None]:
    """('call'|'jump'|'cond'|'icall'|'end'|'none', hedef)."""
    m, ops = insn.mnemonic, insn.operands
    if m == "bl":
        return "call", _imm(ops[0]) if ops else None
    if m == "b":
        return "jump", _imm(ops[0]) if ops else None
    if _COND_BRANCH.match(m):
        return "cond", _imm(ops[0]) if ops else None
    if m in ("cbz", "cbnz"):
        return "cond", _imm(ops[1]) if len(ops) > 1 else None
    if m in ("tbz", "tbnz"):
        return "cond", _imm(ops[2]) if len(ops) > 2 else None
    if m.startswith("blr"):
        return "icall", None
    if m.startswith(("ret", "br", "eret")) or m in ("brk", "udf", "hlt"):
        return "end", None
    return "none", None


@dataclass(frozen=True)
class CallSite:
    """Bir çağrı yeri (``bl``, ``blr`` ya da fonksiyon dışına ``b``) ve o andaki bilinen değerler."""

    function: int
    pc: int
    target: int | None
    regs: tuple[tuple[int, Value], ...]    # x0-x7
    stack: tuple[tuple[int, Value], ...]   # [sp, #ofset]; yalnız son çağrıdan sonra yazılmış yuvalar
    tail: bool = False

    def reg(self, n: int) -> Value | None:
        for k, v in self.regs:
            if k == n:
                return v
        return None

    def slot(self, off: int) -> Value | None:
        for k, v in self.stack:
            if k == off:
                return v
        return None


@dataclass
class _State:
    """Yazmaçlar (x0-x30) ve [sp, #ofset] yuvaları. Yuva: (değer, taze). Taze = son çağrıdan sonra
    yazıldı; çağrıda bütün yuvalar bayatlar ama değer korunur (geri yüklemeler için)."""

    regs: dict[int, Value] = field(default_factory=dict)
    stack: dict[int, tuple[Value, bool]] = field(default_factory=dict)

    def copy(self) -> _State:
        return _State(dict(self.regs), dict(self.stack))

    def same(self, other: _State) -> bool:
        return self.regs == other.regs and self.stack == other.stack


def _meet(states: list[_State]) -> _State:
    """Birleşme: yalnız bütün öncüllerde aynı olan değerler kalır; yuva tazeliği VE ile birleşir."""
    first, *rest = states
    regs = {k: v for k, v in first.regs.items() if all(s.regs.get(k) == v for s in rest)}
    stack = {}
    for k, (v, fresh) in first.stack.items():
        others = [s.stack.get(k) for s in rest]
        if all(o is not None and o[0] == v for o in others):
            stack[k] = (v, fresh and all(o[1] for o in others))
    return _State(regs, stack)


def _kill(st: _State, n: int | None) -> None:
    if n is not None:
        st.regs.pop(n, None)


def _store(st: _State, insn: Insn) -> None:
    """Saklama komutu. [sp]'ye yazanlar yığın yuvalarını günceller; sp değişirse harita silinir."""
    ops = insn.operands
    mem_i = next((i for i, o in enumerate(ops) if o.startswith("[")), None)
    if mem_i is None:
        return
    mem = ops[mem_i]
    writeback = mem.endswith("!") or mem_i + 1 < len(ops)
    if not mem.startswith("[sp"):
        if writeback:
            _kill(st, _reg(mem.strip("[]!").split(",")[0]))
        return
    m = _MEM_SP.match(mem)
    if m is None or writeback:
        st.stack.clear()   # yazmaç ofsetli biçim ya da sp değişiyor: eski ofsetler geçersiz
        return
    off = int(m.group(1), 0) if m.group(1) else 0
    srcs = ops[:mem_i]
    if insn.mnemonic.startswith(("stxr", "stlxr", "stxp", "stlxp")):
        srcs = srcs[1:]
    width = 8
    if srcs:
        width = _BYTE_STORES.get(insn.mnemonic) or _REG_WIDTH.get(srcs[0].strip()[:1], 8)
    for k, src in enumerate(srcs):
        lo = off + k * width
        hi = lo + width
        for slot in [s for s in st.stack if s < hi and s + 8 > lo]:
            del st.stack[slot]
        n = _reg(src)
        if width == 8 and n is not None and src.strip().startswith("x") and n in st.regs:
            st.stack[lo] = (st.regs[n], True)


def _load_sp(st: _State, insn: Insn) -> bool:
    """[sp, #ofset]'ten (geri yazmasız) x yazmacına geri yükleme; değer yuvadan gelir."""
    ops = insn.operands
    mem_i = next((i for i, o in enumerate(ops) if o.startswith("[")), None)
    if mem_i is None or mem_i + 1 < len(ops):
        return False
    m = _MEM_SP.match(ops[mem_i])
    if m is None or m.group(2) == "!":
        return False
    off = int(m.group(1), 0) if m.group(1) else 0
    dsts = ops[:mem_i]
    if not dsts or not all(d.strip().startswith("x") for d in dsts):
        return False
    for k, d in enumerate(dsts):
        n = _reg(d)
        slot = st.stack.get(off + 8 * k)
        if n is None:
            continue
        if slot is None:
            st.regs.pop(n, None)
        else:
            st.regs[n] = slot[0]
    return True


def _transfer(st: _State, insn: Insn) -> None:
    """Dallanma ve çağrı dışı bir komutun durum üzerindeki etkisi."""
    m, ops = insn.mnemonic, insn.operands
    if m == "adrp" and len(ops) == 2:
        n, v = _reg(ops[0]), _imm(ops[1])
        if n is not None and v is not None:
            st.regs[n] = (PAGE, v, NO_ORIGIN)
            return
    if m == "adr" and len(ops) == 2:
        n, v = _reg(ops[0]), _imm(ops[1])
        if n is not None and v is not None:
            st.regs[n] = (CONST, v, NO_ORIGIN)
            return
    if m == "add" and len(ops) == 3 and ops[0].startswith("x"):
        # adrp + add; ya da bölüm çapası + ofset (GCC: add x1, x19, #0x18)
        n, s, v = _reg(ops[0]), _reg(ops[1]), _imm(ops[2])
        src = st.regs.get(s) if s is not None and ops[1].startswith("x") else None
        if n is not None and v is not None and src is not None and src[0] in (PAGE, CONST):
            st.regs[n] = (CONST, src[1] + v, src[2] if src[0] == CONST else NO_ORIGIN)
            return
    if m in ("ldr", "ldur", "ldp", "ldnp") and ops and _load_sp(st, insn):
        return
    if m == "mov" and len(ops) == 2 and ops[0].startswith("x") and ops[1].startswith("x"):
        n, s = _reg(ops[0]), _reg(ops[1])
        if n is not None and s is not None and s in st.regs:
            st.regs[n] = st.regs[s]
            return
    if ops and _is_sp(ops[0]):
        st.stack.clear()   # sp'ye yazma (sub/add/mov sp)
        return
    if m in _STORE_MNEMONICS or m.startswith(("stxr", "stlxr", "stxp", "stlxp")):
        _store(st, insn)
        if m.startswith(("stxr", "stlxr", "stxp", "stlxp")):
            _kill(st, _reg(ops[0]) if ops else None)   # durum yazmacı
        return
    if m in _NO_WRITE_MNEMONICS:
        return
    if m in _PAIR_LOADS or m.startswith(_ATOMIC_PREFIXES):
        _kill(st, _reg(ops[0]) if ops else None)
        _kill(st, _reg(ops[1]) if len(ops) > 1 else None)
    elif ops:
        _kill(st, _reg(ops[0]))
    for i, o in enumerate(ops):   # geri yazmalı yükleme: taban yazmacı (ya da sp) değişir
        if o.startswith("["):
            if o.endswith("!") or i + 1 < len(ops):
                base = o.strip("[]!").split(",")[0].strip()
                if _is_sp(base):
                    st.stack.clear()
                else:
                    _kill(st, _reg(base))
            break


@dataclass
class FunctionFlow:
    """Bir fonksiyonun çağrı yerleri, işlev dışına dallanmaları ve dönüş bilgisi."""

    calls: list[CallSite]
    jumps_out: list[int]                 # işlev dışı dallanma hedefleri (kuyruk çağrısı dahil)
    has_return: bool                     # ``ret`` ya da dolaylı dallanma var
    exit_regs: dict[int, Value] | None   # bütün ``ret``'lerde ortak x0-x7
    call_targets: list[int]              # ``bl`` ve kuyruk çağrısı hedefleri


def _blocks(insns: list[Insn]) -> tuple[list[int], dict[int, list[Insn]], dict[int, list[int]]]:
    pcs = [i.pc for i in insns]
    index = {pc: k for k, pc in enumerate(pcs)}
    body = set(pcs)
    leaders = {pcs[0]}
    for k, ins in enumerate(insns):
        kind, tgt = _branch(ins)
        if kind in ("jump", "cond") and tgt in body:
            leaders.add(tgt)
        nxt = pcs[k + 1] if k + 1 < len(pcs) else None
        if nxt is not None and (kind in ("jump", "cond", "end") or nxt != ins.pc + 4):
            leaders.add(nxt)
    starts = sorted(leaders)
    blocks: dict[int, list[Insn]] = {}
    for b, start in enumerate(starts):
        end = index[starts[b + 1]] if b + 1 < len(starts) else len(insns)
        blocks[start] = insns[index[start]:end]
    succ: dict[int, list[int]] = {}
    for start, blk in blocks.items():
        last = blk[-1]
        kind, tgt = _branch(last)
        k = index[last.pc]
        nxt = pcs[k + 1] if k + 1 < len(pcs) and pcs[k + 1] == last.pc + 4 else None
        out = []
        if kind in ("jump", "cond") and tgt in body:
            out.append(tgt)
        if kind not in ("jump", "end") and nxt is not None:
            out.append(nxt)
        succ[start] = sorted(set(out))
    return starts, blocks, succ


def _run_block(addr: int, st: _State, blk: list[Insn], body: set[int],
               summaries: Mapping[int, Mapping[int, Value]], flow: FunctionFlow | None) -> _State:
    st = st.copy()
    for ins in blk:
        kind, tgt = _branch(ins)
        is_call = kind in ("call", "icall") or (kind == "jump" and tgt not in body)
        if is_call:
            if flow is not None:
                flow.calls.append(CallSite(
                    function=addr, pc=ins.pc, target=None if kind == "icall" else tgt,
                    regs=tuple(sorted((n, v) for n, v in st.regs.items() if n < ARG_REGS)),
                    stack=tuple(sorted((k, v) for k, (v, fresh) in st.stack.items() if fresh)),
                    tail=(kind == "jump")))
                if kind != "icall" and tgt is not None:
                    flow.call_targets.append(tgt)
                if kind == "jump" and tgt is not None:
                    flow.jumps_out.append(tgt)
            for n in _CALLER_SAVED:
                st.regs.pop(n, None)
            st.stack = {k: (v, False) for k, (v, _) in st.stack.items()}
            if kind == "call" and tgt in summaries:
                st.regs.update(summaries[tgt])
        elif kind == "cond":
            if flow is not None and tgt is not None and tgt not in body:
                flow.jumps_out.append(tgt)
        elif kind == "end":
            # tuzak komutları (brk, udf, hlt) dönüş değildir; dolaylı dallanma dönüş sayılır
            if flow is not None and _may_return(ins.mnemonic):
                flow.has_return = True
                if ins.mnemonic.startswith("ret"):
                    flow.exit_regs = _merge_exit(flow.exit_regs, st)
        elif kind != "jump":
            _transfer(st, ins)
    return st


def _may_return(mnemonic: str) -> bool:
    return mnemonic.startswith(("ret", "eret")) or (mnemonic.startswith("br") and mnemonic != "brk")


def _merge_exit(prev: dict[int, Value] | None, st: _State) -> dict[int, Value]:
    cur = {n: v for n, v in st.regs.items() if n < ARG_REGS}
    if prev is None:
        return cur
    return {k: v for k, v in prev.items() if cur.get(k) == v}


def analyze_function(addr: int, insns: list[Insn],
                     summaries: Mapping[int, Mapping[int, Value]] | None = None) -> FunctionFlow:
    """İleri veri akışı (sabit nokta), sonra çağrı yerlerinin ve dönüş durumunun toplanması."""
    summaries = summaries or {}
    flow = FunctionFlow([], [], False, None, [])
    if not insns:
        return flow
    starts, blocks, succ = _blocks(insns)
    body = {i.pc for i in insns}
    entry = _State({n: (PARAM, n, NO_ORIGIN) for n in range(ARG_REGS)}, {})
    preds: dict[int, list[int]] = {s: [] for s in starts}
    for s in starts:
        for t in succ[s]:
            preds[t].append(s)
    in_state: dict[int, _State] = {}
    out_state: dict[int, _State] = {}
    rounds: dict[int, int] = {}
    heap = [starts[0]]
    queued = {starts[0]}
    while heap:
        b = heapq.heappop(heap)
        queued.discard(b)
        reached = [out_state[p] for p in sorted(preds[b]) if p in out_state]
        if b == starts[0]:
            new_in = _meet([entry] + reached)
        elif reached:
            new_in = _meet(reached)
        else:
            continue
        old = in_state.get(b)
        if old is not None and old.same(new_in):
            continue
        rounds[b] = rounds.get(b, 0) + 1
        if rounds[b] > _MAX_ROUNDS:
            new_in = _State()   # sınır aşıldı: en tutucu durum (hiçbir değer bilinmiyor)
            if old is not None and old.same(new_in):
                continue
        in_state[b] = new_in
        out_state[b] = _run_block(addr, new_in, blocks[b], body, summaries, None)
        for t in succ[b]:
            if t not in queued:
                heapq.heappush(heap, t)
                queued.add(t)
    for start in starts:
        if start in in_state:
            _run_block(addr, in_state[start], blocks[start], body, summaries, flow)
    flow.calls.sort(key=lambda c: c.pc)
    flow.jumps_out = sorted(set(flow.jumps_out))
    flow.call_targets = sorted(set(flow.call_targets))
    return flow


# --------------------------------------------------------------------------------------------
# Yuvalar ve çapalar


@dataclass(frozen=True)
class Evidence:
    """Bir ad yuvası kullanımı: hangi çağrı yerinde, hangi dizgi, hangi türden."""

    type: str
    string_address: int | None
    site_function: int
    pc: int | None
    callee: str
    role: str

    def as_dict(self) -> dict:
        return {"tur": self.type,
                "dizgi_adresi": None if self.string_address is None else f"{self.string_address:x}",
                "cagri_fonksiyonu": f"{self.site_function:x}",
                "cagri_yeri": None if self.pc is None else f"{self.pc:x}",
                "cagrilan": self.callee, "rol": self.role}


@dataclass(frozen=True)
class Anchor:
    address: str              # Ghidra biçimi: küçük harf onaltılık, 0x'siz
    name: str
    types: tuple[str, ...]
    role: str
    evidence: tuple[Evidence, ...]

    def as_dict(self) -> dict:
        return {"adres": self.address, "ad": self.name, "turler": list(self.types),
                "rol": self.role, "kanitlar": [e.as_dict() for e in self.evidence]}


@dataclass
class Ks1Result:
    program: str
    abi: str | None
    types: tuple[str, ...]
    anchors: dict[str, Anchor]   # adrese göre sıralı
    counts: dict[str, int]       # huni ve tanı sayaçları (ad içermez)
    dropped: list[dict]          # elenenler: neden, türler, adres ya da dizgi adresi (ad içermez)


def is_generic_name(name: str) -> bool:
    return not name or bool(GENERIC_NAME_RE.match(name))


def name_candidate(value: str | None, program: str) -> bool:
    """Ad yuvasındaki dizgi aday mı: tanımlayıcı biçimi ve ikilinin kendi adı değil."""
    if value is None or not IDENT_RE.match(value):
        return False
    return value != program


def assert_arg_index(name: str) -> int | None:
    return ASSERT_FUNCTIONS.get(name.lstrip("_"))


def format_register(cs: CallSite, strings: Mapping[int, str]) -> int | None:
    """x0-x7 arasında FORMAT_RE'ye uyan tek biçim dizgisi; yoksa ya da birden çoksa None."""
    hits = [n for n, v in cs.regs if v[0] == CONST and FORMAT_RE.match(strings.get(v[1]) or "")]
    return hits[0] if len(hits) == 1 else None


def aligned_value(cs: CallSite, fmt_reg: int, abi: str) -> Value | None:
    """Biçim dizgisinden sonraki ilk değişken argüman: Darwin'de [sp, #0], AAPCS64'te x(biçim+1)."""
    if abi == ABI_DARWIN:
        return cs.slot(0)
    if fmt_reg + 1 < ARG_REGS:
        return cs.reg(fmt_reg + 1)
    return cs.slot(0)


@dataclass(frozen=True)
class _Slot:
    type: str
    string: int
    site: int          # yuvanın bulunduğu fonksiyon
    pc: int
    callee: int | None
    loader: int        # değer bir yükleyici özetinden geldiyse onun adresi, yoksa -1
    header: bool = False   # assert'in dosya argümanı başlık dosyası (K0)


def _loader_summaries(inp: StaticInput) -> dict[int, dict[int, Value]]:
    """Yükleyici: çağrı yapmayan, dönen fonksiyon; dönüşte x0-x7'de ortak adres sabitleri."""
    out: dict[int, dict[int, Value]] = {}
    for a in sorted(inp.code):
        f = inp.functions.get(a)
        if f is not None and (f.is_thunk or f.is_external):
            continue
        if any(_branch(i)[0] in ("call", "icall") for i in inp.code[a]):
            continue
        fl = analyze_function(a, inp.code[a])
        if fl.calls or not fl.exit_regs:
            continue
        consts = {n: (CONST, v[1], a) for n, v in sorted(fl.exit_regs.items())
                  if v[0] == CONST and v[2] == NO_ORIGIN}
        if consts:
            out[a] = consts
    return out


def extract(inp: StaticInput, *, types: Iterable[str] = ALL_TYPES,
            abi: str | None = None) -> Ks1Result:
    """KS-1 çapaları. ``types`` dışındaki türler hiç çıkarılmaz (koruma kurallarına da girmez)."""
    wanted = set(types)
    enabled = tuple(t for t in ALL_TYPES if t in wanted)
    abi = abi or detect_abi(inp)
    counts: dict[str, int] = {f"{stage}:{t}": 0 for t in STRING_TYPES if t in enabled
                              for stage in FUNNEL}
    dropped: list[dict] = []
    anchors: dict[int, Anchor] = {}
    string_types = [t for t in STRING_TYPES if t in enabled]
    if string_types and abi is not None:
        summaries = _loader_summaries(inp)
        flows: dict[int, FunctionFlow] = {}
        for a in sorted(inp.code):
            f = inp.functions.get(a)
            if f is not None and (f.is_thunk or f.is_external):
                continue
            flows[a] = analyze_function(a, inp.code[a], summaries)
        anchors.update(_string_anchors(inp, flows, summaries, string_types, abi, counts, dropped))
    elif string_types:
        counts["desteklenmeyen_platform"] = 1
    if TYPE_EXPORT in enabled:
        n_export = 0
        for a in sorted(inp.functions):
            f = inp.functions[a]
            if f.is_thunk or f.is_external or f.source != SOURCE_IMPORTED or a in anchors:
                continue
            if is_generic_name(f.name) or f.name in NOT_EXPORT_NAMES:
                continue
            anchors[a] = Anchor(f"{a:x}", f.name, (TYPE_EXPORT,), ROLE_OWN,
                                (Evidence(TYPE_EXPORT, None, a, None, "", ROLE_OWN),))
            n_export += 1
        counts[f"9_capa:{TYPE_EXPORT}"] = n_export
    return Ks1Result(program=inp.program, abi=abi, types=enabled,
                     anchors={f"{a:x}": anchors[a] for a in sorted(anchors)},
                     counts=dict(sorted(counts.items())), dropped=dropped)


def _string_anchors(inp: StaticInput, flows: Mapping[int, FunctionFlow],
                    summaries: Mapping[int, Mapping[int, Value]], types: list[str], abi: str,
                    counts: dict[str, int], dropped: list[dict]) -> dict[int, Anchor]:
    strings, funcs = inp.strings, inp.functions
    names = {a: f.name for a, f in funcs.items()}

    def bump(key: str, n: int = 1) -> None:
        counts[key] = counts.get(key, 0) + n

    def drop(reason: str, ts: Iterable[str], **where) -> None:
        ts = sorted(set(ts))
        dropped.append({"neden": reason, "turler": ts, **where})
        for t in ts:
            bump(f"eleme:{reason}:{t}")

    def candidate(v: Value | None, allow_loader: bool) -> bool:
        return (v is not None and v[0] == CONST and (allow_loader or v[2] == NO_ORIGIN)
                and name_candidate(strings.get(v[1]), inp.program))

    # 1. Doğrudan yuvalar: assert ve func_kalibi; func_kalibi hizasında parametre → aktarıcı
    slots: list[_Slot] = []
    forwarders: dict[int, set[int]] = {}
    for a in sorted(flows):
        for cs in flows[a].calls:
            if cs.target is None:
                continue
            ai = assert_arg_index(names.get(cs.target, ""))
            if ai is not None:
                v = cs.reg(ai)
                if TYPE_ASSERT in types and candidate(v, allow_loader=True):
                    fv = cs.reg(ASSERT_FILE_ARG)
                    path = strings.get(fv[1]) if fv is not None and fv[0] == CONST else None
                    slots.append(_Slot(TYPE_ASSERT, v[1], a, cs.pc, cs.target, v[2],
                                       bool(path and HEADER_FILE_RE.search(path))))
                continue
            fr = format_register(cs, strings)
            if fr is None:
                continue
            v = aligned_value(cs, fr, abi)
            if TYPE_FUNC in types and candidate(v, allow_loader=False):
                slots.append(_Slot(TYPE_FUNC, v[1], a, cs.pc, cs.target, NO_ORIGIN))
            elif v is not None and v[0] == PARAM:
                forwarders.setdefault(a, set()).add(v[1])

    # 2. Aktarıcıların sabit noktası (aktarıcının aktarıcısı) ve aktarma yuvaları
    if TYPE_FORWARD in types:
        changed = True
        while changed:
            changed = False
            for a in sorted(flows):
                for cs in flows[a].calls:
                    for j in sorted(forwarders.get(cs.target, ())):
                        v = cs.reg(j)
                        if v is not None and v[0] == PARAM and v[1] not in forwarders.get(a, set()):
                            forwarders.setdefault(a, set()).add(v[1])
                            changed = True
        for a in sorted(flows):
            for cs in flows[a].calls:
                for j in sorted(forwarders.get(cs.target, ())):
                    v = cs.reg(j)
                    if candidate(v, allow_loader=False):
                        slots.append(_Slot(TYPE_FORWARD, v[1], a, cs.pc, cs.target, NO_ORIGIN))
    counts["aktarici_fonksiyon"] = len(forwarders)
    for s in slots:
        bump(f"1_yuva:{s.type}")

    # 3. Assert parçaları ve kaldırma: dönmeyen, yalnız assert (ve yükleyici) çağıran fonksiyon
    assert_targets = {a for a, n in names.items() if assert_arg_index(n) is not None}
    edges_in: dict[int, set[int]] = {a: set(inp.callers.get(a, set())) for a in flows}
    for a in sorted(flows):
        for t in flows[a].jumps_out:
            if t in flows and t != a:
                edges_in.setdefault(t, set()).add(a)
    stubs: set[int] = set()
    for a in sorted(flows):
        tg = set(flows[a].call_targets)
        if not flows[a].has_return and tg & assert_targets and tg <= assert_targets | set(summaries):
            stubs.add(a)
    counts["assert_parcasi"] = len(stubs)
    lifted: dict[int, int | None] = {}

    def lift(f: int, seen: frozenset[int] = frozenset()) -> int | None:
        """Parçanın tek sahibi (parça değilse kendisi); belirsiz ya da sahipsizse None."""
        if f not in stubs:
            return f
        if f in lifted:
            return lifted[f]
        if f in seen:
            return None
        ups = {lift(u, seen | {f}) for u in sorted(edges_in.get(f, set()))}
        res = next(iter(ups)) if len(ups) == 1 else None
        lifted[f] = res
        return res

    # 4. Dizgi başına: başlık dosyası (K0), saflık (K1) ve tek sahip (K2)
    by_string: dict[int, list[_Slot]] = {}
    for s in slots:
        by_string.setdefault(s.string, []).append(s)
    body_names: dict[int, set[str]] = {}
    owned: dict[int, list[int]] = {}   # sahip → dizgiler
    for sa in sorted(by_string):
        sl = by_string[sa]
        ts = {s.type for s in sl}
        for t in ts:
            bump(f"2_dizgi:{t}")
        if any(s.header for s in sl):
            drop(DROP_HEADER, ts, dizgi=f"{sa:x}")
            continue
        for t in ts:
            bump(f"3_K0_sonrasi:{t}")
        owners = {lift(s.site) for s in sl}
        for o in sorted(o for o in owners if o is not None):
            body_names.setdefault(o, set()).add(strings[sa])
        users = {s.site for s in sl}
        loaders = {s.loader for s in sl if s.loader != NO_ORIGIN}
        impure = [r for r in sorted(inp.string_refs.get(sa, set())) if r not in users | loaders]
        impure += [ld for ld in sorted(loaders) if not inp.callers.get(ld, set()) <= users]
        if impure:
            drop(DROP_IMPURE, ts, dizgi=f"{sa:x}")
            continue
        for t in ts:
            bump(f"4_K1_sonrasi:{t}")
        if None in owners:
            drop(DROP_NO_OWNER, ts, dizgi=f"{sa:x}")
            continue
        if len(owners) != 1:
            drop(DROP_MULTI_OWNER, ts, dizgi=f"{sa:x}", sahip_sayisi=len(owners))
            continue
        for t in ts:
            bump(f"5_K2_sonrasi:{t}")
        owned.setdefault(next(iter(owners)), []).append(sa)

    # 5. Gövdede tek ad (K3), 6. ad tekliği (K4), 7. zaten adlı (K5)
    def slots_of(o: int) -> list[_Slot]:
        return [s for sa in owned[o] for s in by_string[sa]]

    def types_of(o: int) -> tuple[str, ...]:
        have = {s.type for s in slots_of(o)}
        return tuple(t for t in STRING_TYPES if t in have)

    for o in sorted(owned):
        for t in types_of(o):
            bump(f"6_aday_fonksiyon:{t}")
    k3 = []
    for o in sorted(owned):
        if len(body_names.get(o, set())) > 1:
            drop(DROP_BODY_MULTI, types_of(o), adres=f"{o:x}", ad_sayisi=len(body_names[o]))
            continue
        k3.append(o)
        for t in types_of(o):
            bump(f"7_K3_sonrasi:{t}")
    owners_of_name: dict[str, list[int]] = {}
    for o in k3:
        owners_of_name.setdefault(strings[owned[o][0]], []).append(o)
    result: dict[int, Anchor] = {}
    fragments: dict[int, tuple[str, list[_Slot]]] = {}
    for o in k3:
        name = strings[owned[o][0]]
        ts = types_of(o)
        if len(owners_of_name[name]) > 1:
            drop(DROP_NAME_MULTI, ts, adres=f"{o:x}")
            continue
        for t in ts:
            bump(f"8_K4_sonrasi:{t}")
        f = funcs.get(o)
        if f is None or not is_generic_name(f.name):
            drop(DROP_NAMED, ts, adres=f"{o:x}")
            continue
        sl = slots_of(o)
        ev = tuple(sorted(
            (Evidence(s.type, s.string, s.site, s.pc, names.get(s.callee, "") if s.callee else "",
                      ROLE_OWN if s.site == o else ROLE_LIFTED) for s in sl),
            key=lambda e: (e.site_function, e.pc or 0, e.type, e.string_address or 0)))
        role = ROLE_OWN if any(s.site == o for s in sl) else ROLE_LIFTED
        result[o] = Anchor(f"{o:x}", name, ts, role, ev)
        for t in ts:
            bump(f"9_capa:{t}")
        for s in sl:
            if s.site != o and s.site in stubs and len(edges_in.get(s.site, set())) == 1:
                fragments.setdefault(s.site, (name, []))[1].append(s)

    # 8. Parça çapaları: üst fonksiyonu çapalanan, tek girişli assert parçaları (ayrı raporlanır)
    n_frag = 0
    for fa in sorted(fragments):
        f = funcs.get(fa)
        if fa in result or f is None or not is_generic_name(f.name):
            continue
        name, sl = fragments[fa]
        ts = tuple(t for t in STRING_TYPES if t in {s.type for s in sl})
        ev = tuple(sorted((Evidence(s.type, s.string, s.site, s.pc,
                                    names.get(s.callee, "") if s.callee else "", ROLE_FRAGMENT)
                           for s in sl), key=lambda e: (e.pc or 0, e.type)))
        result[fa] = Anchor(f"{fa:x}", name, ts, ROLE_FRAGMENT, ev)
        n_frag += 1
    counts["capa_parca"] = n_frag
    return result


def extract_anchors(static_dir: Path, *, types: Iterable[str] = ALL_TYPES,
                    abi: str | None = None) -> Ks1Result:
    """``static/`` dizininden KS-1 çapaları."""
    return extract(load_static(Path(static_dir)), types=types, abi=abi)


def kesin_mapping(result: Ks1Result, types: Iterable[str] = STRING_TYPES,
                  include_fragments: bool = False) -> dict[str, str]:
    """``run_tarif``'in ``kesin`` girdisi biçiminde adres → ad (bu adımda ürüne bağlı değil)."""
    wanted = set(types)
    return {a: c.name for a, c in result.anchors.items()
            if wanted & set(c.types) and (include_fragments or c.role != ROLE_FRAGMENT)}
