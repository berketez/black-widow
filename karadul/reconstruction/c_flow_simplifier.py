"""Ghidra decompile çıktısındaki goto/etiket kalıplarını sadeleştirir.

Geçişler (sırayla):

1. ``cascade``        — ``L: goto M;`` zincirleri: ``goto L`` -> ``goto M``.
2. ``ifelse``         — ``if (k) goto E; A; goto S; E: B; S:`` -> if/else.
3. ``early_return``   — ``goto L`` (``L: return x;``) -> ``return x;``.
4. ``break_continue`` — döngünün hemen ardındaki/önündeki etikete giden
   goto -> ``break`` / ``continue``.
5. ``inline``         — küçük temizlik bloğunun goto yerine konması (tek ya
   da çok hedefli).
6. ``rename``         — kalan ``LAB_`` etiketlerine anlamlı ad.

Güvence (2026-11-10 onarımı)
----------------------------
Eski sürüm metni satır satır ve düzenli ifadeyle işliyordu: ayraç
derinliğine bakmıyor, ayraçsız ``if`` altına çok deyimli blok koyuyor,
düşerek ulaşılan etiketin bloğunu siliyordu. 119 ikilinin 117'sinde kod
bozuldu (docs/arge/2026-11-10_cikti_saglamligi/rapor.md, kusur 1).

Bu sürümde:

* Yorumlar ve dizgi/karakter sabitleri maskelenir; yapı kararı yalnız
  maskeli metinden verilir.
* Her fonksiyon gövdesi deyim ağacına ayrıştırılır. Dönüşümler ağaç
  üzerinde, tam deyim sınırlarıyla çalışır. Ayrıştırılamayan fonksiyona
  dokunulmaz.
* Fonksiyona uygulanan dönüşümlerin sonunda **ard koşullar** denetlenir
  (``_postcondition_violation``): ayraç dengesi, goto/etiket tutarlılığı,
  çağrı çoklu kümesi, ``return`` kümesi ve denetim akış grafının özgün
  grafla eşdeğerliği. Biri tutmazsa fonksiyonun **özgün metni** yazılır ve
  ``functions_reverted`` sayacı artar. Yanlış kod göstermektense Ghidra'nın
  ham akışı kalır.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


def _replace_whole_word(text: str, old: str, new: str) -> str:
    """str.replace gibi hizli ama sadece tam kelime eslesir (word boundary).

    re.sub(r'\\b...\\b') buyuk dosyalarda catastrophic backtracking yapar.
    Bu fonksiyon O(n) garanti eder.
    """
    old_len = len(old)
    if not old_len:
        return text
    result: list[str] = []
    start = 0
    while True:
        idx = text.find(old, start)
        if idx == -1:
            result.append(text[start:])
            break
        # Sol sinir kontrolu: basinda mi veya onceki karakter identifier degil mi
        if idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            result.append(text[start : idx + old_len])
            start = idx + old_len
            continue
        # Sag sinir kontrolu
        end = idx + old_len
        if end < len(text) and (text[end].isalnum() or text[end] == "_"):
            result.append(text[start : idx + old_len])
            start = idx + old_len
            continue
        # Tam eslesme — degistir
        result.append(text[start:idx])
        result.append(new)
        start = end
    return "".join(result)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sabitler ve düzenli ifadeler
# ---------------------------------------------------------------------------

# goto LAB_xxx;  (ön eleme; maskeli metinde aranır)
_GOTO_RE = re.compile(r"\bgoto\s+(LAB_[0-9a-fA-F]+)\s*;")

# LAB_xxx:  (ön eleme; maskeli metinde aranır)
_LABEL_RE = re.compile(r"^(\s*)(LAB_[0-9a-fA-F]+)\s*:", re.MULTILINE)

# Dönüşümlerin dokunduğu etiket adları. Ghidra'nın öbür etiketleri
# (code_r0x…, joined_r0x…, switchD_…) olduğu gibi kalır.
_LAB_NAME_RE = re.compile(r"LAB_[0-9a-fA-F]+\Z")

# Cleanup API'leri (error cleanup tespiti icin)
_CLEANUP_APIS = frozenset({
    "free", "close", "fclose", "munmap", "release",
    "destroy", "cleanup", "dispose", "dealloc",
    "SSL_free", "BIO_free", "EVP_CIPHER_CTX_free",
    "EVP_MD_CTX_free", "OPENSSL_free", "sk_pop_free",
})

# Return pattern (cleanup block sonu)
_RETURN_RE = re.compile(r"\breturn\b\s*[^;]*;")

# Etiket sınıflama sezgisinin görmemesi gerekenler: goto hedefleri, etiket
# tanımı satırları ve yığın koruması çağrısının adı
_HEURISTIC_NOISE_RE = re.compile(
    r"\bgoto\s+[A-Za-z_][\w:]*|^[ \t]*[A-Za-z_][\w:]*[ \t]*:(?!:)[ \t]*$"
    r"|\b_*stack_chk_fail\b",
    re.MULTILINE,
)

# Yorum, dizgi sabiti ve karakter sabiti (C kurallarıyla, tek geçişte)
_LEX_RE = re.compile(
    r"/\*.*?\*/|//[^\n]*|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S
)
# Maskeleme sonrasında bunlardan biri kaldıysa sözcük çözümü güvenilmezdir
# (kapanmamış yorum ya da dizgi; gövde içinde ön işlemci satırı ya da satır
# devamı); o fonksiyona dokunulmaz.
_LEX_DOUBT_RE = re.compile(r"/\*|\*/|[\"'\\]|^[ \t]*#", re.MULTILINE)

# Yapı sözcükleri: sözcük/sayı, "::" ve yapı ayraçları. İşleçler atlanır.
_TOK_RE = re.compile(r"\w+|::|[{}()\[\];:?]")
_OPENERS = frozenset("([{")
_CLOSERS = frozenset(")]}")
_CONTROL_WORDS = frozenset({
    "if", "else", "while", "for", "do", "switch", "case", "default",
    "goto", "return", "break", "continue",
})
_JUMP_KINDS = frozenset({"goto", "return", "break", "continue"})
_LOOP_KINDS = frozenset({"while", "do", "for"})

# Çağrı sayımı (ard koşul): "ad(" biçimi; denetim sözcükleri hariç
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_NOT_A_CALL = frozenset({
    "if", "while", "for", "switch", "return", "sizeof", "do", "else",
    "case", "goto",
})
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_BRACE_RE = re.compile(r"[{}]")
_BRACKET_RE = re.compile(r"[{}()\[\]]")

# Bildirim sezgisi: "tip [tip…] [*…] ad" ya da "tip (*ad)" ve ardından
# ; = [ , ya da ). İhtiyatlıdır: "a * b;" de bildirim sayılır (yalnız
# dönüşümü engeller). "f (a, b);" çağrısı bildirim sayılmaz.
_DECL_RE = re.compile(
    r"\s*(?:[A-Za-z_]\w*[\s\*]+)+(?:\(\s*\*[\s\*]*)?[A-Za-z_]\w*\s*(?:\)|\[|=|;|,)"
)

# Deyim metni karşılaştırması: sabitlerin içi korunur, boşluk dizileri teklenir
_NORM_RE = re.compile(
    r"(\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*')|\s+"
)
_LITERAL_OR_PAREN_RE = re.compile(
    r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|[()]"
)
# Her zaman doğru koşullar: grafikte düğüm üretmez (``do {…} while( true );``)
_ALWAYS_TRUE = frozenset({"true", "1"})

# Satır içine alma sınırları (eski davranışla aynı)
_MAX_MULTI_TARGETS = 10
_MAX_MULTI_BLOCK_NEWLINES = 5
_MAX_SINGLE_INLINES = 50
_MAX_IFELSE = 30
_MAX_IFELSE_BLOCK_NEWLINES = 20
_MAX_RETURN_LEN = 120

# Blok return ile bitmese de verilebilen etiket adları
_CLEANUP_LABEL_NAMES = frozenset({"error_cleanup", "cleanup_and_return"})

_STAT_KEYS = (
    "eliminated", "renamed", "inlined", "cascading_collapsed",
    "ifelse_restructured", "early_returns", "breaks_continues",
    "multi_target_inlined", "functions_changed", "functions_reverted",
    "functions_skipped",
)

_ALL_PASSES = (
    "cascade", "ifelse", "early_return", "break_continue", "inline", "rename",
)


@dataclass
class SimplifyResult:
    """Simplifikasyon sonucu."""
    total_files: int = 0
    gotos_eliminated: int = 0
    labels_renamed: int = 0
    labels_inlined: int = 0
    files_modified: int = 0
    early_returns: int = 0
    breaks_continues: int = 0
    ifelse_restructured: int = 0
    cascading_collapsed: int = 0
    multi_target_inlined: int = 0
    # Ard koşul tutmadığı için özgün metni yazılan fonksiyon sayısı
    functions_reverted: int = 0
    # Ayrıştırılamadığı için hiç dokunulmayan fonksiyon sayısı
    functions_skipped: int = 0
    # İşlenirken beklenmeyen hata veren (ve değiştirilmeyen) dosya sayısı
    files_failed: int = 0


# ---------------------------------------------------------------------------
# Sözcük düzeyi: maskeleme
# ---------------------------------------------------------------------------


def _blank(s: str) -> str:
    """Satır sonları dışındaki her karakteri boşluk yapar (uzunluk korunur)."""
    if "\n" not in s:
        return " " * len(s)
    return "".join("\n" if c == "\n" else " " for c in s)


def _mask(text: str) -> tuple[str, str]:
    """Metnin iki maskeli kopyasını döndürür; ikisi de özgünle aynı uzunlukta.

    * ``code``: yorumlar, dizgi ve karakter sabitleri boşluk. Yapı (ayraç,
      goto, etiket) yalnız bundan okunur.
    * ``nocomment``: yalnız yorumlar boşluk. Deyim metinlerinin
      karşılaştırmasında kullanılır (sabitlerin içeriği önemlidir).
    """
    code = _LEX_RE.sub(lambda m: _blank(m.group(0)), text)
    nocomment = _LEX_RE.sub(
        lambda m: _blank(m.group(0)) if m.group(0)[0] == "/" else m.group(0),
        text,
    )
    return code, nocomment


def _function_bodies(code: str) -> list[tuple[int, int]] | None:
    """Maskeli metindeki üst düzey ``{…}`` aralıkları: ``[(baş, son), …]``.

    Ayraçlar dengesizse ``None`` (dosyaya dokunulmaz).
    """
    out: list[tuple[int, int]] = []
    depth = 0
    start = 0
    for m in _BRACE_RE.finditer(code):
        if m.group() == "{":
            if depth == 0:
                start = m.start()
            depth += 1
        else:
            depth -= 1
            if depth < 0:
                return None
            if depth == 0:
                out.append((start, m.end()))
    if depth != 0:
        return None
    return out


def _brackets_balanced(code: str) -> bool:
    """Maskeli metinde ``{} () []`` doğru iç içe ve dengeli mi?"""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for m in _BRACKET_RE.finditer(code):
        c = m.group()
        if c in pairs:
            if not stack or stack.pop() != pairs[c]:
                return False
        else:
            stack.append(c)
    return not stack


def _call_counts(code: str) -> Counter:
    """Maskeli metindeki çağrı adlarının çoklu kümesi."""
    return Counter(n for n in _CALL_RE.findall(code) if n not in _NOT_A_CALL)


def _norm(s: str) -> str:
    """Deyim metnini karşılaştırma biçimine getirir (sabitlerin içi korunur)."""
    return _NORM_RE.sub(lambda m: m.group(1) or " ", s).strip()


def _line_start(s: str, pos: int) -> int:
    return s.rfind("\n", 0, pos) + 1


def _line_end(s: str, pos: int) -> int:
    e = s.find("\n", pos)
    return len(s) if e < 0 else e


def _indent_at(text: str, line_start: int) -> str:
    """``line_start``'ta başlayan satırın baştaki boşluk/sekme dizisi."""
    e = line_start
    n = len(text)
    while e < n and text[e] in " \t":
        e += 1
    return text[line_start:e]


def _starts_line(code: str, pos: int) -> bool:
    """``pos`` kendi satırının ilk boşluk olmayan karakteri mi?"""
    return not code[_line_start(code, pos):pos].strip()


def _ends_line(code: str, pos: int) -> bool:
    """``pos``'tan satır sonuna kadar (maskeli metinde) yalnız boşluk mu?"""
    return not code[pos:_line_end(code, pos)].strip()


def _reindent(src: str, indent: str) -> str:
    """Satırların ortak girintisini ``indent`` ile değiştirir; boş satırları
    atar. Göreli girinti korunur."""
    lines = [ln for ln in src.split("\n") if ln.strip()]
    if not lines:
        return ""
    common: str | None = None
    for ln in lines:
        lead = ln[: len(ln) - len(ln.lstrip())]
        if common is None:
            common = lead
            continue
        n = 0
        for a, b in zip(common, lead):
            if a != b:
                break
            n += 1
        common = common[:n]
    cut = len(common or "")
    return "\n".join(indent + ln[cut:] for ln in lines)


# ---------------------------------------------------------------------------
# Deyim ağacı
# ---------------------------------------------------------------------------


class _ParseError(Exception):
    """Fonksiyon gövdesi güvenle ayrıştırılamadı (dokunulmaz)."""


class _Node:
    """Deyim ağacı düğümü. ``start``/``end`` fonksiyon metnindeki konumlar.

    kind: block, if, while, do, for, switch, label, case, goto, return,
    break, continue, expr, empty.
    """

    __slots__ = (
        "kind", "start", "end", "name", "name_span", "cond", "body",
        "orelse", "items", "parent", "index", "brk", "loop",
    )

    def __init__(self, kind: str, start: int, end: int = 0):
        self.kind = kind
        self.start = start
        self.end = end
        self.name: str | None = None          # etiket adı / goto hedefi
        self.name_span: tuple[int, int] | None = None
        self.cond: tuple[int, int] | None = None   # koşul / for başlığı / case metni
        self.body: _Node | None = None
        self.orelse: _Node | None = None
        self.items: list[_Node] | None = None  # yalnız block
        self.parent: _Node | None = None
        self.index = -1                        # üst bloktaki sıra (block öğesiyse)
        self.brk: _Node | None = None          # en içteki döngü ya da switch
        self.loop: _Node | None = None         # en içteki döngü


class _Parser:
    """Maskeli fonksiyon gövdesini deyim ağacına çevirir.

    Tam bir C ayrıştırıcısı değildir: deyim sınırlarını ve denetim
    yapılarını tanır, ifadelerin içine girmez. Tanımadığı her biçimde
    ``_ParseError`` verir.
    """

    def __init__(self, code: str):
        self.code = code
        toks: list[str] = []
        starts: list[int] = []
        ends: list[int] = []
        for m in _TOK_RE.finditer(code):
            toks.append(m.group())
            starts.append(m.start())
            ends.append(m.end())
        self.t = toks
        self.s = starts
        self.e = ends
        self.n = len(toks)
        self.i = 0

    def parse(self) -> _Node:
        if not self.n or self.t[0] != "{":
            raise _ParseError("gövde '{' ile başlamıyor")
        root = self._block()
        if self.i != self.n:
            raise _ParseError("gövdeden sonra artık sözcük")
        return root

    # -- yardımcılar --------------------------------------------------

    def _tok(self, i: int) -> str:
        if i >= self.n:
            raise _ParseError("beklenmeyen son")
        return self.t[i]

    def _gap_blank(self, i: int) -> bool:
        """i. ve (i+1). sözcük arasında yalnız boşluk mu?"""
        return not self.code[self.e[i]:self.s[i + 1]].strip()

    def _is_ident(self, i: int) -> bool:
        t = self._tok(i)
        return (t[0].isalpha() or t[0] == "_") and t not in _CONTROL_WORDS

    def _qualified_name(self, i: int) -> int:
        """``a::b::c`` biçimli adın son sözcük sırasını döndürür."""
        j = i
        while (
            j + 2 < self.n
            and self.t[j + 1] == "::"
            and self._is_ident(j + 2)
            and self.e[j] == self.s[j + 1]
            and self.e[j + 1] == self.s[j + 2]
        ):
            j += 2
        return j

    def _paren(self, allow_semicolon: bool) -> tuple[int, int]:
        """``(`` üzerindeyken eşine kadar ilerler; iç aralığı döndürür."""
        i = self.i
        if self._tok(i) != "(":
            raise _ParseError("'(' bekleniyordu")
        depth = 0
        j = i
        while True:
            t = self._tok(j)
            if t == "(" or t == "[":
                depth += 1
            elif t == ")" or t == "]":
                depth -= 1
                if depth == 0:
                    break
                if depth < 0:
                    raise _ParseError("parantez dengesiz")
            elif t == "{" or t == "}":
                raise _ParseError("parantez içinde ayraç")
            elif t == ";" and not allow_semicolon:
                raise _ParseError("parantez içinde ';'")
            j += 1
        if self.t[j] != ")":
            raise _ParseError("parantez dengesiz")
        self.i = j + 1
        return self.e[i], self.s[j]

    def _scan_semicolon(self, i: int) -> int:
        """i'den başlayan ifadenin bitiş ``;`` sözcüğünün sırası."""
        depth = 0
        j = i
        while j < self.n:
            t = self.t[j]
            if t in _OPENERS:
                depth += 1
            elif t in _CLOSERS:
                depth -= 1
                if depth < 0:
                    raise _ParseError("ifade kapanmadan blok bitti")
            elif t == ";":
                if depth == 0:
                    return j
            elif t in _CONTROL_WORDS:
                raise _ParseError("ifade içinde denetim sözcüğü")
            j += 1
        raise _ParseError("';' bulunamadı")

    # -- deyimler -----------------------------------------------------

    def _block(self) -> _Node:
        i = self.i
        node = _Node("block", self.s[i])
        items: list[_Node] = []
        self.i = i + 1
        while True:
            if self._tok(self.i) == "}":
                break
            item = self._stmt()
            item.parent = node
            item.index = len(items)
            items.append(item)
        node.items = items
        node.end = self.e[self.i]
        self.i += 1
        return node

    def _child(self, parent: _Node) -> _Node:
        node = self._stmt()
        if node.kind == "label" or node.kind == "case":
            raise _ParseError("ayraçsız alt deyim olarak etiket")
        node.parent = parent
        return node

    def _stmt(self) -> _Node:
        i = self.i
        t = self._tok(i)
        s, e = self.s, self.e
        if t == "{":
            return self._block()
        if t == ";":
            self.i = i + 1
            return _Node("empty", s[i], e[i])
        if t == "if":
            node = _Node("if", s[i])
            self.i = i + 1
            node.cond = self._paren(False)
            node.body = self._child(node)
            if self.i < self.n and self.t[self.i] == "else":
                self.i += 1
                node.orelse = self._child(node)
                node.end = node.orelse.end
            else:
                node.end = node.body.end
            return node
        if t == "while" or t == "switch" or t == "for":
            node = _Node(t, s[i])
            self.i = i + 1
            node.cond = self._paren(t == "for")
            node.body = self._child(node)
            node.end = node.body.end
            return node
        if t == "do":
            node = _Node("do", s[i])
            self.i = i + 1
            node.body = self._child(node)
            if self._tok(self.i) != "while":
                raise _ParseError("do sonrasında while yok")
            self.i += 1
            node.cond = self._paren(False)
            if self._tok(self.i) != ";":
                raise _ParseError("do-while sonunda ';' yok")
            node.end = e[self.i]
            self.i += 1
            return node
        if t == "goto":
            a = i + 1
            if not self._is_ident(a) or not self._gap_blank(i):
                raise _ParseError("goto hedefi ad değil")
            b = self._qualified_name(a)
            if self._tok(b + 1) != ";" or not self._gap_blank(b):
                raise _ParseError("goto sonunda ';' yok")
            node = _Node("goto", s[i], e[b + 1])
            node.name = self.code[s[a]:e[b]]
            node.name_span = (s[a], e[b])
            self.i = b + 2
            return node
        if t == "return":
            j = self._scan_semicolon(i + 1)
            self.i = j + 1
            return _Node("return", s[i], e[j])
        if t == "break" or t == "continue":
            if self._tok(i + 1) != ";" or not self._gap_blank(i):
                raise _ParseError("%s sonunda ';' yok" % t)
            self.i = i + 2
            return _Node(t, s[i], e[i + 1])
        if t == "case":
            depth = 0
            ternary = 0
            j = i + 1
            while True:
                u = self._tok(j)
                if u == "(" or u == "[":
                    depth += 1
                elif u == ")" or u == "]":
                    depth -= 1
                    if depth < 0:
                        raise _ParseError("case ifadesi dengesiz")
                elif u == "{" or u == "}" or u == ";":
                    raise _ParseError("case ifadesinde beklenmeyen sözcük")
                elif depth == 0 and u == "?":
                    ternary += 1
                elif depth == 0 and u == ":":
                    if ternary == 0:
                        break
                    ternary -= 1
                j += 1
            node = _Node("case", s[i], e[j])
            node.cond = (s[i], s[j])
            self.i = j + 1
            return node
        if t == "default":
            if self._tok(i + 1) != ":":
                raise _ParseError("default sonrasında ':' yok")
            node = _Node("case", s[i], e[i + 1])
            node.cond = (s[i], e[i])
            self.i = i + 2
            return node
        if t == "else" or t in _CLOSERS or t == ":" or t == "?" or t == "::":
            raise _ParseError("deyim başında beklenmeyen sözcük: %s" % t)
        if self._is_ident(i):
            b = self._qualified_name(i)
            if b + 1 < self.n and self.t[b + 1] == ":" and self._gap_blank(b):
                node = _Node("label", s[i], e[b + 1])
                node.name = self.code[s[i]:e[b]]
                node.name_span = (s[i], e[b])
                self.i = b + 2
                return node
        j = self._scan_semicolon(i)
        self.i = j + 1
        return _Node("expr", s[i], e[j])


def _subtree(node: _Node):
    """Düğümü ve altındakileri kaynak sırasıyla verir (özyinelemesiz)."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        if n.items is not None:
            stack.extend(reversed(n.items))
        else:
            if n.orelse is not None:
                stack.append(n.orelse)
            if n.body is not None:
                stack.append(n.body)


class _Analysis:
    """Tek fonksiyon gövdesinin maskeli metni, deyim ağacı ve envanteri."""

    def __init__(self, text: str):
        self.text = text
        self.code, self.nocomment = _mask(text)
        if _LEX_DOUBT_RE.search(self.code):
            raise _ParseError("kapanmamış yorum/dizgi ya da ön işlemci satırı")
        self.root = _Parser(self.code).parse()
        self.nodes: list[_Node] = []
        self.blocks: list[_Node] = []
        self.labels: dict[str, _Node] = {}
        self.gotos: dict[str, list[_Node]] = {}
        self.duplicate_labels = False
        self._late_declared: frozenset[str] | None = None
        self._unit: str | None = None
        self._walk()

    def _walk(self) -> None:
        stack: list[tuple[_Node, _Node | None, _Node | None]] = [
            (self.root, None, None)
        ]
        while stack:
            node, brk, loop = stack.pop()
            node.brk = brk
            node.loop = loop
            self.nodes.append(node)
            kind = node.kind
            if kind == "block":
                self.blocks.append(node)
                for it in reversed(node.items):
                    stack.append((it, brk, loop))
            elif kind == "label":
                if node.name in self.labels:
                    self.duplicate_labels = True
                else:
                    self.labels[node.name] = node
            elif kind == "goto":
                self.gotos.setdefault(node.name, []).append(node)
            elif kind == "if":
                if node.orelse is not None:
                    stack.append((node.orelse, brk, loop))
                stack.append((node.body, brk, loop))
            elif kind in _LOOP_KINDS:
                stack.append((node.body, node, node))
            elif kind == "switch":
                stack.append((node.body, node, loop))

    # -- sorgular -----------------------------------------------------

    def next_real(self, label: _Node) -> _Node | None:
        """Etiketten sonraki, etiket olmayan ilk kardeş deyim."""
        parent = label.parent
        if parent is None or parent.items is None:
            return None
        items = parent.items
        j = label.index + 1
        while j < len(items) and items[j].kind == "label":
            j += 1
        return items[j] if j < len(items) else None

    def no_fallthrough(self, label: _Node) -> bool:
        """Etikete düşerek ulaşılamıyor mu?

        Yalnız en kesin biçim kabul edilir: etiketin aynı bloktaki bir
        önceki deyimi koşulsuz bir atlamadır (goto/return/break/continue),
        tek satırdadır ve o satırda başka kod yoktur; etiket de kendi
        satırının başındadır. Dönmeyen çağrılara (exit, abort) güvenilmez.
        """
        parent = label.parent
        if parent is None or parent.items is None or label.index == 0:
            return False
        prev = parent.items[label.index - 1]
        if prev.kind not in _JUMP_KINDS:
            return False
        code = self.code
        if "\n" in code[prev.start:prev.end]:
            return False
        return (
            _starts_line(code, prev.start)
            and _ends_line(code, prev.end)
            and _starts_line(code, label.start)
        )

    @property
    def late_declared(self) -> frozenset[str]:
        """Fonksiyonun baştaki bildirim öbeği dışında bildirilen adlar.

        Bu adlardan birini anan metin başka bir konuma taşınmaz (kapsam
        değişebilir). Ghidra bütün yerelleri başta bildirdiği için kümesi
        çoğunlukla boştur.
        """
        if self._late_declared is None:
            names: set[str] = set()
            prefix: set[int] = set()
            for it in self.root.items:
                if it.kind == "expr" and _looks_like_decl(self.code[it.start:it.end]):
                    prefix.add(id(it))
                else:
                    break
            for node in self.nodes:
                if node.kind != "expr" or id(node) in prefix:
                    continue
                stmt = self.code[node.start:node.end]
                if _looks_like_decl(stmt):
                    names.update(_IDENT_RE.findall(stmt))
            self._late_declared = frozenset(names)
        return self._late_declared

    def mentions_late_declared(self, start: int, end: int) -> bool:
        late = self.late_declared
        if not late:
            return False
        return any(w in late for w in _IDENT_RE.findall(self.code[start:end]))

    @property
    def unit(self) -> str:
        """Bir girinti adımı (gövdenin ilk satırının girintisi; yoksa 2 boşluk)."""
        if self._unit is None:
            unit = "  "
            for it in self.root.items:
                ls = _line_start(self.text, it.start)
                lead = self.text[ls:it.start]
                if ls > 0 and lead and not lead.strip() and len(lead) <= 8:
                    unit = lead
                break
            self._unit = unit
        return self._unit


def _looks_like_decl(stmt_code: str) -> bool:
    m = _DECL_RE.match(stmt_code)
    if not m:
        return False
    first = _IDENT_RE.match(stmt_code.lstrip())
    return bool(first) and first.group() not in ("sizeof", "typeof")


# ---------------------------------------------------------------------------
# Denetim akış grafı ve eşdeğerlik
# ---------------------------------------------------------------------------


def _strip_negation(text: str) -> tuple[str, bool]:
    """``!(X)`` -> (``X``, True). Dış parantez bütün ifadeyi sarmalıdır."""
    negated = False
    while text.startswith("!"):
        rest = text[1:].lstrip()
        if not rest.startswith("("):
            break
        depth = 0
        close = -1
        for m in _LITERAL_OR_PAREN_RE.finditer(rest):
            c = m.group()
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    close = m.start()
                    break
        if close != len(rest) - 1:
            break
        text = rest[1:-1].strip()
        negated = not negated
    return text, negated


class _Cfg:
    """Fonksiyonun denetim akış grafı.

    Düğüm etiketi ``None`` ise düğüm geçirgendir (etiket, sabit-doğru
    koşul); ``resolve`` geçirgen zincirleri atlar. Düğüm etiketleri deyim
    metinleridir; iki grafın eşdeğerliği için metinler ve dallar birebir
    örtüşmelidir. Etiket adları grafa girmez.
    """

    def __init__(self, an: _Analysis):
        self.an = an
        self.labels: list[tuple | None] = []
        self.succ: list[list[int]] = []
        self.end = self._new(("son",))
        self.spin = self._new(("sonsuz-boş-döngü",))
        self._label_nodes: dict[str, int] = {}
        self._resolved: dict[int, int] = {}
        self.entry = self._build(an.root, self.end, None, None, None)

    def _new(self, label: tuple | None, succ: tuple[int, ...] = ()) -> int:
        self.labels.append(label)
        self.succ.append(list(succ))
        return len(self.labels) - 1

    def _text(self, span: tuple[int, int]) -> str:
        return _norm(self.an.nocomment[span[0]:span[1]])

    def _label_node(self, name: str) -> int:
        n = self._label_nodes.get(name)
        if n is None:
            n = self._label_nodes[name] = self._new(None)
        return n

    def _cond_node(self, node_id: int, text: str, true_to: int, false_to: int) -> None:
        text, negated = _strip_negation(text)
        if negated:
            true_to, false_to = false_to, true_to
        if text in _ALWAYS_TRUE:
            self.succ[node_id] = [true_to]
            return
        self.labels[node_id] = ("koşul", text)
        self.succ[node_id] = [true_to, false_to]

    def _build(self, node: _Node, nxt: int, brk, cont, cases) -> int:
        kind = node.kind
        if kind == "block":
            for it in reversed(node.items):
                nxt = self._build(it, nxt, brk, cont, cases)
            return nxt
        if kind == "expr":
            return self._new(("ifade", self._text((node.start, node.end))), (nxt,))
        if kind == "empty":
            return nxt
        if kind == "return":
            return self._new(("return", self._text((node.start, node.end))))
        if kind == "goto":
            if node.name in self.an.labels:
                return self._label_node(node.name)
            # Fonksiyonda tanımı olmayan hedef (Ghidra: code_r0x…): çıkış
            return self._new(("dış-goto", node.name))
        if kind == "label":
            n = self._label_node(node.name)
            self.succ[n] = [nxt]
            return n
        if kind == "case":
            if cases is None:
                raise _ParseError("switch dışında case")
            n = self._new(None, (nxt,))
            cases.append((self._text(node.cond), n))
            return n
        if kind == "break":
            if brk is None:
                raise _ParseError("döngü/switch dışında break")
            return brk
        if kind == "continue":
            if cont is None:
                raise _ParseError("döngü dışında continue")
            return cont
        if kind == "if":
            then_to = self._build(node.body, nxt, brk, cont, cases)
            else_to = (
                self._build(node.orelse, nxt, brk, cont, cases)
                if node.orelse is not None else nxt
            )
            c = self._new(None)
            self._cond_node(c, self._text(node.cond), then_to, else_to)
            return c
        if kind == "while":
            c = self._new(None)
            body = self._build(node.body, c, nxt, c, cases)
            self._cond_node(c, self._text(node.cond), body, nxt)
            return c
        if kind == "do":
            c = self._new(None)
            body = self._build(node.body, c, nxt, c, cases)
            self._cond_node(c, self._text(node.cond), body, nxt)
            return body
        if kind == "for":
            parts = self._for_parts(node.cond)
            c = self._new(None)
            step = self._new(("ifade", parts[2] + ";"), (c,)) if parts[2] else c
            body = self._build(node.body, step, nxt, step, cases)
            if parts[1]:
                self._cond_node(c, parts[1], body, nxt)
            else:
                self.succ[c] = [body]
            if parts[0]:
                return self._new(("ifade", parts[0] + ";"), (c,))
            return c
        if kind == "switch":
            mine: list[tuple[str, int]] = []
            self._build(node.body, nxt, nxt, cont, mine)
            mine.sort()
            names = [t for t, _ in mine]
            if len(set(names)) != len(names):
                raise _ParseError("yinelenen case")
            targets = [n for _, n in mine]
            if "default" not in names:
                names.append("<default yok>")
                targets.append(nxt)
            return self._new(
                ("switch", self._text(node.cond), tuple(names)), tuple(targets)
            )
        raise _ParseError("bilinmeyen deyim türü: %s" % kind)

    def _for_parts(self, span: tuple[int, int]) -> list[str]:
        code = self.an.code
        cuts: list[int] = []
        depth = 0
        for pos in range(span[0], span[1]):
            c = code[pos]
            if c == "(" or c == "[":
                depth += 1
            elif c == ")" or c == "]":
                depth -= 1
            elif c == ";" and depth == 0:
                cuts.append(pos)
        if len(cuts) != 2:
            raise _ParseError("for başlığı üç parça değil")
        return [
            self._text((span[0], cuts[0])),
            self._text((cuts[0] + 1, cuts[1])),
            self._text((cuts[1] + 1, span[1])),
        ]

    def resolve(self, n: int) -> int:
        """Geçirgen düğümleri atlayarak ilk gerçek düğümü döndürür."""
        r = self._resolved.get(n)
        if r is not None:
            return r
        path: list[int] = []
        seen: set[int] = set()
        cur = n
        while True:
            known = self._resolved.get(cur)
            if known is not None:
                r = known
                break
            if self.labels[cur] is not None:
                r = cur
                break
            if cur in seen:
                r = self.spin          # yalnız etiketlerden oluşan döngü
                break
            seen.add(cur)
            path.append(cur)
            nxt = self.succ[cur]
            if len(nxt) != 1:
                raise _ParseError("geçirgen düğümün ardılı yok")
            cur = nxt[0]
        for p in path:
            self._resolved[p] = r
        self._resolved[n] = r
        return r


def _cfg_equivalent(a: _Cfg, b: _Cfg) -> bool:
    """İki graf, girişlerinden başlayarak ikili benzer mi (bisimülasyon)?

    Graflar belirlenimlidir (her düğümün sıralı ardılları var); bu yüzden
    Hopcroft–Karp'ın otomat eşdeğerliği yöntemi yeter: düğüm çiftleri
    birleştirilir, her birleştirmede etiketler ve ardıl sayısı aynı olmalı.
    Erişilemeyen düğümler karşılaştırmaya girmez.
    """
    parent: dict[tuple[int, int], tuple[int, int]] = {}

    def find(x: tuple[int, int]) -> tuple[int, int]:
        root = x
        while True:
            p = parent.get(root)
            if p is None:
                break
            root = p
        while x != root:
            nxt = parent[x]
            parent[x] = root
            x = nxt
        return root

    stack = [(a.resolve(a.entry), b.resolve(b.entry))]
    while stack:
        x, y = stack.pop()
        rx, ry = find((0, x)), find((1, y))
        if rx == ry:
            continue
        sx, sy = a.succ[x], b.succ[y]
        if a.labels[x] != b.labels[y] or len(sx) != len(sy):
            return False
        parent[rx] = ry
        for u, v in zip(sx, sy):
            stack.append((a.resolve(u), b.resolve(v)))
    return True


def _return_set(an: _Analysis) -> frozenset[str]:
    return frozenset(
        _norm(an.nocomment[n.start:n.end]) for n in an.nodes if n.kind == "return"
    )


def _statement_set(an: _Analysis) -> frozenset:
    """Fonksiyondaki ifade deyimlerinin ve koşulların metin kümesi.

    Erişilemeyen kod da girer: akış grafı yalnız erişilen kodu karşılaştırır;
    bu küme, silinen bloğun yerinde kalan artık parçayı (``1;``) ve kaybolan
    deyimi de yakalar. ``!(k)`` ile ``k`` aynı koşul sayılır.
    """
    out: set = set()
    text = an.nocomment
    for n in an.nodes:
        kind = n.kind
        if kind == "expr":
            out.add(_norm(text[n.start:n.end]))
        elif kind in ("if", "while", "do", "switch"):
            out.add((kind == "switch", _strip_negation(_norm(text[n.cond[0]:n.cond[1]]))[0]))
        elif kind == "for" or kind == "case":
            out.add((kind, _norm(text[n.cond[0]:n.cond[1]])))
    return frozenset(out)


def _postcondition_violation(
    old_text: str,
    new_text: str,
    call_delta: Counter | None = None,
    _old: _Analysis | None = None,
    _new: _Analysis | None = None,
) -> str | None:
    """Dönüşümün ard koşullarını denetler; ilk ihlalin adını döndürür.

    ``None`` dönerse ``new_text`` özgün fonksiyon gövdesinin yerine
    yazılabilir. Denetlenenler (yorum ve dizgi sabitleri dışında):

    * ``denge``   — ``{} () []`` doğru iç içe ve dengeli.
    * ``ayrıştırma`` — yeni metin deyim ağacına ayrışıyor.
    * ``etiket``  — her etiket en çok bir kez tanımlı (özgün metin de
      öyleyse; Ghidra'nın kendisi nadiren aynı etiketi iki kez yazar ve o
      fonksiyonlara zaten dokunulmaz).
    * ``goto``    — etiketi olmayan goto kümesi büyümüyor (özgün metinde
      zaten fonksiyon dışına atlayanlar hariç her goto'nun etiketi var).
    * ``çağrı``   — çağrı adlarının çoklu kümesi = özgün + ``call_delta``
      (dönüşümlerin bildirdiği kopya farkı). ``call_delta`` ``None`` ise
      yalnız çağrı kaybı aranır.
    * ``return``  — ``return`` deyimlerinin kümesi aynı.
    * ``deyim``   — ifade deyimlerinin ve koşulların kümesi aynı (erişilemeyen
      kod dahil; artık parça ya da kayıp deyim yok).
    * ``akış``    — denetim akış grafı özgün grafla eşdeğer.
    * ``girdi``   — özgün metnin akış grafı kurulamıyor (geçersiz C);
      eşdeğerlik gösterilemediği için yeni metin kabul edilmez.
    """
    try:
        old = _old if _old is not None else _Analysis(old_text)
    except (_ParseError, RecursionError):
        return "ayrıştırma"
    new_code = _mask(new_text)[0] if _new is None else _new.code
    if not _brackets_balanced(new_code):
        return "denge"
    try:
        new = _new if _new is not None else _Analysis(new_text)
    except (_ParseError, RecursionError):
        return "ayrıştırma"
    if new.duplicate_labels and not old.duplicate_labels:
        return "etiket"
    dangling_old = {n for n in old.gotos if n not in old.labels}
    dangling_new = {n for n in new.gotos if n not in new.labels}
    if not dangling_new <= dangling_old:
        return "goto"
    calls_old = _call_counts(old.code)
    calls_new = _call_counts(new.code)
    if call_delta is None:
        if calls_old - calls_new:
            return "çağrı"
    else:
        expected = Counter(calls_old)
        expected.update(call_delta)
        if {k: v for k, v in expected.items() if v} != dict(calls_new):
            return "çağrı"
    if _return_set(old) != _return_set(new):
        return "return"
    if _statement_set(old) != _statement_set(new):
        return "deyim"
    try:
        old_cfg = _Cfg(old)
    except (_ParseError, RecursionError):
        # Özgün metnin akışı kurulamıyor (ör. döngü dışında break):
        # eşdeğerlik gösterilemez.
        return "girdi"
    try:
        if not _cfg_equivalent(old_cfg, _Cfg(new)):
            return "akış"
    except (_ParseError, RecursionError):
        return "akış"
    return None


# ---------------------------------------------------------------------------
# Düzenleme yardımcıları
# ---------------------------------------------------------------------------

_Edit = tuple[int, int, str]


def _apply_edits(text: str, edits: list[_Edit]) -> str:
    """Çakışmayan düzenlemeleri uygular. Çakışma varsa ``_ParseError``."""
    out: list[str] = []
    cursor = 0
    for start, end, repl in sorted(edits, key=lambda x: (x[0], x[1])):
        if start < cursor or end < start:
            raise _ParseError("çakışan düzenleme")
        out.append(text[cursor:start])
        out.append(repl)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def _label_removal(an: _Analysis, label: _Node) -> _Edit:
    """Artık hedef olmayan etiketin silinmesi (ardındaki kod kalır)."""
    text, code = an.text, an.code
    ls = _line_start(code, label.start)
    le = _line_end(code, label.end)
    if not code[ls:label.start].strip() and not code[label.end:le].strip():
        return (ls, min(len(text), le + 1), "")
    e = label.end
    while e < le and text[e] in " \t":
        e += 1
    return (label.start, e, "")


def _dead_removal(an: _Analysis, label: _Node, stmt: _Node) -> _Edit | None:
    """Etiketi ve ardındaki (artık erişilemeyen) deyimi satırlarıyla siler.

    Yalnız etiket kendi satırındaysa ve deyim kendi satırlarını tümüyle
    kaplıyorsa; değilse ``None`` (çağıran yalnız etiketi siler).
    """
    text, code = an.text, an.code
    if not (
        _starts_line(code, label.start)
        and _ends_line(code, label.end)
        and _starts_line(code, stmt.start)
        and _ends_line(code, stmt.end)
    ):
        return None
    return (
        _line_start(code, label.start),
        min(len(text), _line_end(code, stmt.end) + 1),
        "",
    )


class _FileContext:
    """Bir dosyanın fonksiyonları arasında paylaşılan ad durumu."""

    __slots__ = ("taken", "name_counts")

    def __init__(self, code: str):
        self.taken: set[str] = set(_IDENT_RE.findall(code))
        self.name_counts: Counter[str] = Counter()


def _goto_positions(code: str) -> dict[str, list[int]]:
    """Maskeli metinde ``goto LAB_x;`` konumları: tam etiket adı -> konumlar."""
    out: dict[str, list[int]] = {}
    for m in _GOTO_RE.finditer(code):
        out.setdefault(m.group(1), []).append(m.start())
    return out


# ---------------------------------------------------------------------------
# Sadeleştirici
# ---------------------------------------------------------------------------


class CFlowSimplifier:
    """Ghidra goto/label pattern'lerini sadeler.

    Ghidra decompiler ciktilarinda cok sayida ``goto LAB_xxx`` pattern'i
    bulunur.  Bu sinif:

    * Düşerek ulaşılmayan küçük temizlik bloklarını goto yerine koyar.
    * ``return``'e giden goto'ları ``return`` yapar; döngü çıkışına giden
      goto'ları ``break`` yapar.
    * Kalan etiketleri anlamsallık bazlı yeniden adlandırır.
    * Her fonksiyonda ard koşulları denetler; tutmazsa özgün metni bırakır.

    Tum islemler *in-place* veya ayri bir output dizinine yazilabilir.
    """

    def __init__(self, config=None):
        self._max_inline_lines: int = 15
        self._enabled: bool = True
        self._passes: tuple[str, ...] = _ALL_PASSES
        if config and hasattr(config, "binary_reconstruction"):
            br = config.binary_reconstruction
            self._max_inline_lines = getattr(br, "goto_max_inline_lines", 15)
            self._enabled = getattr(br, "enable_flow_simplification", True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def simplify_directory(
        self,
        input_dir: Path,
        output_dir: Path | None = None,
    ) -> SimplifyResult:
        """Dizindeki tum C dosyalarini sadeler.

        *output_dir* ``None`` ise **input_dir uzerinde in-place** degisiklik
        yapar.  Farkli bir *output_dir* verilirse once dizin kopyalanir.
        """
        result = SimplifyResult()

        if not self._enabled:
            logger.debug("Flow simplification devre disi, atlaniyor")
            return result

        if output_dir and output_dir != input_dir:
            import shutil

            if output_dir.exists():
                shutil.rmtree(output_dir)
            shutil.copytree(input_dir, output_dir)
            target_dir = output_dir
        else:
            target_dir = input_dir

        c_files = sorted(target_dir.glob("*.c"))
        result.total_files = len(c_files)

        for c_file in c_files:
            try:
                content = c_file.read_text(encoding="utf-8", errors="replace")
                new_content, stats = self._simplify_content(content)
                if new_content != content:
                    c_file.write_text(new_content, encoding="utf-8")
                    result.files_modified += 1
                result.gotos_eliminated += stats.get("eliminated", 0)
                result.labels_renamed += stats.get("renamed", 0)
                result.labels_inlined += stats.get("inlined", 0)
                result.early_returns += stats.get("early_returns", 0)
                result.breaks_continues += stats.get("breaks_continues", 0)
                result.ifelse_restructured += stats.get("ifelse_restructured", 0)
                result.cascading_collapsed += stats.get("cascading_collapsed", 0)
                result.multi_target_inlined += stats.get("multi_target_inlined", 0)
                result.functions_reverted += stats.get("functions_reverted", 0)
                result.functions_skipped += stats.get("functions_skipped", 0)
            except Exception as exc:
                # Dosya değişmeden kalır; hata sessizce yutulmaz.
                result.files_failed += 1
                logger.warning("Flow simplify hatasi %s: %s", c_file.name, exc)

        logger.info(
            "Flow simplify: %d dosya, %d goto eliminated, %d label renamed, "
            "%d inlined, %d early_ret, %d break/cont, %d if-else, %d cascade, "
            "%d multi; ard kosul: %d fonksiyon ozgun metne dondu, %d "
            "ayristirilamadi, %d dosya hata",
            result.total_files,
            result.gotos_eliminated,
            result.labels_renamed,
            result.labels_inlined,
            result.early_returns,
            result.breaks_continues,
            result.ifelse_restructured,
            result.cascading_collapsed,
            result.multi_target_inlined,
            result.functions_reverted,
            result.functions_skipped,
            result.files_failed,
        )
        return result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _simplify_content(self, content: str) -> tuple[str, dict]:
        """Tek bir C dosyasinin icerigini sadeler.

        Donus: ``(yeni_icerik, istatistik_dict)``

        Dosya, maskeli metindeki üst düzey ``{…}`` aralıklarına (fonksiyon
        gövdeleri) bölünür; her gövde bağımsız işlenir ve ard koşulu
        tutmayan gövdenin özgün metni korunur. Gövdelerin dışındaki metne
        (künye yorumu, ``// --- DISASSEMBLY`` eki) hiç dokunulmaz.
        """
        stats: dict[str, int] = dict.fromkeys(_STAT_KEYS, 0)

        if "goto" not in content:
            return content, stats

        code = _mask(content)[0]
        bodies = _function_bodies(code)
        if bodies is None:
            # Üst düzey ayraçlar dengesiz: fonksiyon sınırı bilinmiyor.
            stats["functions_skipped"] += 1
            return content, stats

        # v1.6.4: Buyuk icerik korumasi — 500K+ karakter iceriklerde
        # sadece rename yap (maliyet/fayda orani dusuk).
        skip_inline = len(content) > 500_000

        file_ctx: _FileContext | None = None
        parts: list[str] = []
        cursor = 0
        for start, end in bodies:
            body_code = code[start:end]
            # Ön eleme: gövdede, aynı gövdedeki bir goto'nun hedefi olan en
            # az bir LAB_ etiketi olmalı. Eşleşme tam adladır (sözlük
            # anahtarı); LAB_00a ile LAB_00ab karışmaz.
            goto_positions = _goto_positions(body_code)
            if not goto_positions:
                continue
            if not any(
                goto_positions.get(label_name)
                for _indent, label_name in _LABEL_RE.findall(body_code)
            ):
                continue
            if file_ctx is None:
                file_ctx = _FileContext(code)
            body = content[start:end]
            new_body, fstats = self._simplify_function(body, file_ctx, skip_inline)
            for key, value in fstats.items():
                stats[key] = stats.get(key, 0) + value
            if new_body != body:
                parts.append(content[cursor:start])
                parts.append(new_body)
                cursor = end

        if not parts:
            return content, stats
        parts.append(content[cursor:])
        return "".join(parts), stats

    def _simplify_function(
        self, text: str, file_ctx: _FileContext, skip_inline: bool = False
    ) -> tuple[str, dict[str, int]]:
        """Tek fonksiyon gövdesini (``{`` … ``}``) sadeleştirir.

        Dönüş: ``(yeni_gövde, istatistik)``. Ard koşul tutmazsa özgün gövde
        ve ``{"functions_reverted": 1, "reverted_<ihlal>": 1}`` döner.
        """
        try:
            original = _Analysis(text)
        except (_ParseError, RecursionError):
            return text, {"functions_skipped": 1}
        if original.duplicate_labels:
            return text, {"functions_skipped": 1}

        an = original
        stats: Counter[str] = Counter()
        call_delta: Counter[str] = Counter()
        for name in self._passes:
            if skip_inline and name != "rename":
                continue
            edits, pstats, pdelta = getattr(self, "_pass_" + name)(an, file_ctx)
            if not edits:
                continue
            try:
                an = _Analysis(_apply_edits(an.text, edits))
            except (_ParseError, RecursionError):
                # Geçişin ürettiği metin ayrıştırılamıyor: ard koşul ihlali.
                return text, {"functions_reverted": 1, "reverted_ayrıştırma": 1}
            stats.update(pstats)
            call_delta.update(pdelta)

        if an.text == text:
            return text, {}

        violation = _postcondition_violation(
            text, an.text, call_delta, _old=original, _new=an
        )
        if violation == "girdi":
            # Kusur dönüşümde değil girdide: ayrıştırılamayanlarla sayılır.
            return text, {"functions_skipped": 1}
        if violation is not None:
            logger.debug("Flow simplify: ard kosul ihlali (%s), ozgun metin korundu", violation)
            return text, {"functions_reverted": 1, "reverted_" + violation: 1}
        stats["functions_changed"] += 1
        return an.text, dict(stats)

    # ------------------------------------------------------------------
    # Etiket sınıflama sezgileri (yalnız adlandırma ve aday seçimi)
    # ------------------------------------------------------------------

    def _extract_label_block(self, content: str, start_pos: int) -> str:
        """Etiketten sonraki düz bloğu çıkarır (return/break/goto'ya kadar).

        Yalnız sınıflama sezgisinin girdisidir; hiçbir dönüşüm bu metinle
        taşıma ya da silme yapmaz. Etiketin bulunduğu bloğu kapatan ``}``
        aşılmaz ve bitiş deyimi yalnız etiketin kendi derinliğinde aranır
        (eski sürüm ayraç derinliğine bakmıyordu).
        """
        return self._label_block(content, start_pos)[0]

    def _label_block(self, content: str, start_pos: int) -> tuple[str, str]:
        """``(blok, bitiş)``: bitiş ``"return"``, ``"goto"``, ``"break"`` ya
        da (blok bir atlamayla bitmeden pencere/blok sonuna gelindiyse) ``""``.
        """
        window = content[start_pos : start_pos + 2000]
        code = _mask(window)[0]
        lines = window.split("\n")
        code_lines = code.split("\n")
        block_lines: list[str] = []
        depth = 0
        terminator = ""
        for line, code_line in zip(
            lines[: self._max_inline_lines + 5], code_lines
        ):
            if not line.strip():
                continue
            closed_enclosing = False
            for ch in code_line:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth < 0:
                        closed_enclosing = True
                        break
            if closed_enclosing:
                break
            block_lines.append(line)
            stripped = code_line.strip()
            if depth == 0:
                if stripped.startswith("return ") or stripped == "return;":
                    terminator = "return"
                elif stripped.startswith("break;"):
                    terminator = "break"
                elif stripped.startswith("goto "):
                    terminator = "goto"
                if terminator:
                    break
        return "\n".join(block_lines), terminator

    @staticmethod
    def _has_cleanup_call(block: str) -> bool:
        """Blokta adı bir temizlik API'sini içeren çağrı var mı?

        Yalnız çağrılan fonksiyon adlarına bakılır (maskeli metinde
        ``ad(``). Eski sürüm bütün metinde alt dizgi arıyordu; etiket adı
        (``goto error_cleanup_2;``), dizgi ya da yorum da eşleşiyordu.
        """
        callees = set(_CALL_RE.findall(_mask(block)[0])) - _NOT_A_CALL
        return any(api in callee for callee in sorted(callees) for api in _CLEANUP_APIS)

    def _is_cleanup_block(self, block: str) -> bool:
        """Block cleanup pattern'i mi? (free/close/return iceriyor mu)"""
        has_return = bool(_RETURN_RE.search(block))
        return self._has_cleanup_call(block) or has_return

    def _classify_label(self, label_name: str, block: str) -> str:
        """Label'in amacini belirle ve anlamli isim ver."""
        has_cleanup = self._has_cleanup_call(block)
        # Sezgi metni: etiket adları ve yığın koruması çağrısı çıkarılır;
        # yoksa "goto error_exit;" ya da "__stack_chk_fail" kendi başına
        # "error"/"fail" sayılır ve ad, uygulama sayısına bağlı olur.
        block = _HEURISTIC_NOISE_RE.sub(" ", block)
        block_lower = block.lower()

        # Cleanup pattern: free/close + return
        if has_cleanup:
            if re.search(r"\breturn\b", block):
                return "cleanup_and_return"
            return "error_cleanup"

        # Basarili donus: return 0 / return result
        if re.search(
            r"\breturn\s+0\s*;|\breturn\s+result\s*;|\breturn\s+\w+\s*;", block
        ):
            return "exit_function"

        # Hata donusu: return -1 / "error" / "fail"
        if re.search(r"\breturn\s*-", block) or "error" in block_lower or "fail" in block_lower:
            return "error_exit"

        # Siniflandirilamadi -> oldugu gibi birak
        return label_name

    @staticmethod
    def _indent_block(block: str, base_indent: str) -> str:
        """Block'u verilen indent seviyesine getir."""
        return _reindent(block, base_indent)

    # ==================================================================
    # Geçiş 1: goto zinciri
    # ==================================================================

    def _pass_cascade(self, an: _Analysis, file_ctx=None):
        """``goto A; … A: goto B;`` -> ``goto B;`` (zincir boyunca).

        ``A`` etiketi hedef olmaktan çıkınca silinir. Ardındaki ``goto B;``
        yalnız ``A``'ya düşerek ulaşılamıyorsa silinir; aksi hâlde düşen
        yol için yerinde kalır.
        """
        redirect: dict[str, str] = {}
        for name, label in an.labels.items():
            if not _LAB_NAME_RE.match(name) or not an.gotos.get(name):
                continue
            nxt = an.next_real(label)
            if (
                nxt is not None
                and nxt.kind == "goto"
                and nxt.name != name
                and nxt.name in an.labels
            ):
                redirect[name] = nxt.name
        if not redirect:
            return [], {}, {}

        resolved: dict[str, str] = {}
        for name, target in redirect.items():
            visited = {name}
            while target in redirect and target not in visited:
                visited.add(target)
                target = redirect[target]
            if target not in visited:
                resolved[name] = target
        if not resolved:
            return [], {}, {}

        edits: list[_Edit] = []
        dead: set[int] = set()
        removed = 0
        for name in resolved:
            label = an.labels[name]
            follower = label.parent.items[label.index + 1]
            cut = None
            if follower.kind == "goto" and an.no_fallthrough(label):
                cut = _dead_removal(an, label, follower)
            if cut is not None:
                dead.add(id(follower))
                removed += 1
                edits.append(cut)
            else:
                edits.append(_label_removal(an, label))

        count = 0
        for name, target in resolved.items():
            for g in an.gotos[name]:
                if id(g) in dead:
                    continue
                edits.append((g.name_span[0], g.name_span[1], target))
                count += 1
        return edits, {"cascading_collapsed": count, "eliminated": removed}, {}

    # ==================================================================
    # Geçiş 2: if-else
    # ==================================================================

    def _pass_ifelse(self, an: _Analysis, file_ctx=None):
        """``if (k) goto E; A; goto S; E: B; S:`` -> ``if (!(k)) {A} else {B}``.

        Altı öğe de aynı blokta ardışık kardeş olmalıdır; ``E`` yalnız bu
        ``if``'in hedefidir; A ve B içinde etiket, goto ya da (blok
        kapsamına girecek) bildirim yoktur.
        """
        edits: list[_Edit] = []
        count = 0
        for block in an.blocks:
            items = block.items
            i = 0
            while i < len(items) and count < _MAX_IFELSE:
                hit = self._match_ifelse(an, items, i)
                if hit is None:
                    i += 1
                    continue
                edit, i = hit
                edits.append(edit)
                count += 1
        if not count:
            return [], {}, {}
        return edits, {"ifelse_restructured": count, "eliminated": 2 * count}, {}

    def _match_ifelse(self, an: _Analysis, items: list[_Node], i: int):
        head = items[i]
        if head.kind != "if" or head.orelse is not None or head.body.kind != "goto":
            return None
        else_name = head.body.name
        else_label = an.labels.get(else_name)
        if (
            else_label is None
            or not _LAB_NAME_RE.match(else_name)
            or else_label.parent is not head.parent
            or else_label.index < i + 3
            or len(an.gotos.get(else_name, ())) != 1
        ):
            return None
        le = else_label.index
        end_goto = items[le - 1]
        if end_goto.kind != "goto" or end_goto.name == else_name:
            return None
        end_name = end_goto.name
        end_label = an.labels.get(end_name)
        if (
            end_label is None
            or not _LAB_NAME_RE.match(end_name)
            or end_label.parent is not head.parent
            or end_label.index < le + 2
        ):
            return None
        k = end_label.index
        then_items = items[i + 1 : le - 1]
        else_items = items[le + 1 : k]
        code, text = an.code, an.text
        for part in (then_items, else_items):
            for top in part:
                if top.kind == "case":
                    return None
                if top.kind == "expr" and _looks_like_decl(code[top.start:top.end]):
                    return None
                for node in _subtree(top):      # top'un kendisi dahil
                    if node.kind == "label" or node.kind == "goto":
                        return None
        # Her parça kendi satır(lar)ında olmalı; satır bazında taşınır.
        for node in (head, then_items[0], end_goto, else_label, else_items[0], end_label):
            if not _starts_line(code, node.start):
                return None
        for node in (head, then_items[-1], end_goto, else_label, else_items[-1]):
            if not _ends_line(code, node.end):
                return None

        then_src = text[_line_end(text, head.end) + 1 : _line_start(text, end_goto.start)]
        between = text[_line_end(text, end_goto.end) + 1 : _line_start(text, else_label.start)]
        else_src = text[_line_end(text, else_label.end) + 1 : _line_start(text, end_label.start)]
        if between.strip():
            else_src = between + else_src
        if (
            then_src.count("\n") > _MAX_IFELSE_BLOCK_NEWLINES
            or else_src.count("\n") > _MAX_IFELSE_BLOCK_NEWLINES
        ):
            return None

        start = _line_start(text, head.start)
        indent = text[start:head.start]
        inner = indent + an.unit
        cond_src = text[head.cond[0]:head.cond[1]]
        new = (
            "%sif (!(%s)) {\n%s\n%s} else {\n%s\n%s}"
            % (indent, cond_src, _reindent(then_src, inner), indent,
               _reindent(else_src, inner), indent)
        )
        if len(an.gotos.get(end_name, ())) > 1:
            # Bitiş etiketine başka yerden de atlanıyor: etiket kalır.
            stop = _line_start(text, end_label.start)
            new += "\n"
        elif _ends_line(code, end_label.end):
            stop = min(len(text), _line_end(text, end_label.end) + 1)
            new += "\n"
        else:
            stop = end_label.end
            while stop < len(text) and text[stop] in " \t":
                stop += 1
            new += "\n" + text[_line_start(text, end_label.start):end_label.start]
        return (start, stop, new), k

    # ==================================================================
    # Geçiş 3: erken dönüş
    # ==================================================================

    def _pass_early_return(self, an: _Analysis, file_ctx=None):
        """``goto L;`` -> ``return x;`` (``L:`` hemen ardından ``return x;``).

        goto tek bir deyimdir ve yerine tek bir deyim konur; bu yüzden
        ayraçsız ``if``/``else`` altında da geçerlidir. Etiket hedef
        olmaktan çıkınca silinir; ardındaki ``return`` yalnız etikete
        düşerek ulaşılamıyorsa silinir.
        """
        edits: list[_Edit] = []
        delta: Counter[str] = Counter()
        count = 0
        for name, label in an.labels.items():
            sites = an.gotos.get(name)
            if not sites or not _LAB_NAME_RE.match(name):
                continue
            ret = an.next_real(label)
            if ret is None or ret.kind != "return":
                continue
            ret_src = an.text[ret.start:ret.end]
            if "\n" in ret_src or len(ret_src) >= _MAX_RETURN_LEN:
                continue
            if an.mentions_late_declared(ret.start, ret.end):
                continue
            for g in sites:
                edits.append((g.start, g.end, ret_src))
            count += len(sites)
            cut = None
            if label.parent.items[label.index + 1] is ret and an.no_fallthrough(label):
                cut = _dead_removal(an, label, ret)
            if cut is not None:
                edits.append(cut)
                copies = len(sites) - 1
            else:
                edits.append(_label_removal(an, label))
                copies = len(sites)
            for callee, n in _call_counts(an.code[ret.start:ret.end]).items():
                delta[callee] += n * copies
        if not count:
            return [], {}, {}
        return edits, {"early_returns": count, "eliminated": count}, delta

    # ==================================================================
    # Geçiş 4: break / continue
    # ==================================================================

    def _pass_break_continue(self, an: _Analysis, file_ctx=None):
        """Döngü içindeki goto -> ``break`` / ``continue``.

        * ``break``: etiket döngünün hemen ardındaki kardeş deyimdir ve
          goto'yu saran en içteki döngü/switch o döngüdür.
        * ``continue``: etiket döngünün hemen önündeki kardeş deyimdir,
          goto'yu saran en içteki döngü o döngüdür ve döngü ``while (k)``
          ya da ``do {…} while (true)`` biçimindedir (başa atlamak ile
          koşula atlamak yalnız bu ikisinde aynıdır).
        """
        edits: list[_Edit] = []
        replaced: Counter[str] = Counter()
        count = 0
        for name, sites in an.gotos.items():
            label = an.labels.get(name)
            if label is None or not _LAB_NAME_RE.match(name):
                continue
            parent = label.parent
            for g in sites:
                word = None
                brk = g.brk
                if (
                    brk is not None
                    and brk.kind in _LOOP_KINDS
                    and brk.body.kind == "block"
                    and brk.parent is parent
                    and label.index == brk.index + 1
                ):
                    word = "break;"
                else:
                    loop = g.loop
                    if (
                        loop is not None
                        and loop.body.kind == "block"
                        and loop.parent is parent
                        and label.index == loop.index - 1
                        and (
                            loop.kind == "while"
                            or (
                                loop.kind == "do"
                                and _norm(an.code[loop.cond[0]:loop.cond[1]])
                                in _ALWAYS_TRUE
                            )
                        )
                    ):
                        word = "continue;"
                if word is not None:
                    edits.append((g.start, g.end, word))
                    replaced[name] += 1
                    count += 1
        if not count:
            return [], {}, {}
        for name, n in replaced.items():
            if n == len(an.gotos[name]):
                edits.append(_label_removal(an, an.labels[name]))
        return edits, {"breaks_continues": count, "eliminated": count}, {}

    # ==================================================================
    # Geçiş 5: temizlik bloğunu goto yerine koyma
    # ==================================================================

    def _pass_inline(self, an: _Analysis, file_ctx=None):
        """Küçük temizlik bloğunu goto'ların yerine koyar, özgününü siler.

        Koşullar (hepsi):

        * Etikete düşerek ulaşılamıyor (``no_fallthrough``); aksi hâlde
          blok o yol için de gereklidir ve silinemez.
        * Blok, etiketin kendi bloğunda ardışık **tam** deyimlerdir ve
          koşulsuz ``return`` ya da ``goto`` ile biter. İçinde etiket,
          ``case``, ``break`` ya da ``continue`` yoktur; baştaki bildirim
          öbeği dışında bildirilen bir adı (kendi bildirimi dahil) anmaz.
        * goto bir deyim listesinin öğesi değilse (``if (k) goto L;``)
          blok ``{ }`` ile sarılır; koşul bütün bloğu kapsar.
        """
        text, code = an.text, an.code
        edits: list[_Edit] = []
        delta: Counter[str] = Counter()
        taken: list[tuple[int, int]] = []
        stats: Counter[str] = Counter()
        singles = 0
        for name, label in an.labels.items():
            sites = an.gotos.get(name)
            if not sites or len(sites) > _MAX_MULTI_TARGETS:
                continue
            if not _LAB_NAME_RE.match(name):
                continue
            single = len(sites) == 1
            if single and singles >= _MAX_SINGLE_INLINES:
                continue
            block = self._inline_block(an, label, single)
            if block is None:
                continue
            first, term = block
            src_start = _line_end(text, label.end) + 1
            block_src = text[src_start:term.end]
            cut = (_line_start(text, label.start),
                   min(len(text), _line_end(text, term.end) + 1))
            if any(cut[0] <= g.start < cut[1] for g in sites):
                continue      # blok kendi etiketine atlıyor (döngü)
            if any(g is label.parent.items[label.index - 1] for g in sites):
                continue      # "goto L; L:" — taşınacak bir şey yok
            spans = [cut] + [(g.start, g.end) for g in sites]
            if any(s < te and ts < e for s, e in spans for ts, te in taken):
                continue      # başka bir adayın dokunduğu aralıkla çakışıyor
            taken.extend(spans)

            comment = (
                "/* error cleanup (inlined from %s) */" if single
                else "/* cleanup (inlined from %s) */"
            ) % name
            for g in sites:
                line = _line_start(text, g.start)
                lead = text[line:g.start]
                if g.parent.kind == "block" and not lead.strip():
                    # Deyim listesinde, satır başında: blok olduğu gibi girer.
                    edits.append((
                        line, g.end,
                        "%s%s\n%s" % (lead, comment, _reindent(block_src, lead)),
                    ))
                    continue
                # Ayraçsız alt deyim (if/else/döngü gövdesi) ya da satır
                # ortası: tek deyimin yerine tek bir bileşik deyim.
                p = g.start - 1
                while p >= 0 and code[p] in " \t\n":
                    p -= 1
                base = _indent_at(text, _line_start(text, max(p, 0)))
                inner = base + an.unit
                start, opener = g.start, "{"
                if p >= 0 and "\n" in text[p + 1:g.start] and not text[p + 1:g.start].strip():
                    # goto kendi satırında: ayraç koşulun satırına alınır
                    start, opener = p + 1, " {"
                edits.append((
                    start, g.end,
                    "%s\n%s%s\n%s\n%s}" % (opener, inner, comment, _reindent(block_src, inner), base),
                ))
            edits.append((cut[0], cut[1], ""))

            copies = len(sites) - 1
            if copies:
                for callee, n in _call_counts(code[first.start:term.end]).items():
                    delta[callee] += n * copies
            if single:
                singles += 1
                stats["inlined"] += 1
            else:
                stats["multi_target_inlined"] += len(sites)
            stats["eliminated"] += len(sites)
        if not edits:
            return [], {}, {}
        return edits, dict(stats), delta

    def _inline_block(self, an: _Analysis, label: _Node, single: bool):
        """Etiketin satır içine alınabilir bloğu: ``(ilk_deyim, bitiş_deyimi)``."""
        parent = label.parent
        if parent is None or parent.items is None:
            return None
        if not an.no_fallthrough(label) or not _ends_line(an.code, label.end):
            return None
        items = parent.items
        code = an.code
        j = label.index + 1
        term = None
        while j < len(items):
            it = items[j]
            kind = it.kind
            if kind == "return" or kind == "goto":
                term = it
                break
            # Alt ağaç düğümün kendisini de içerir: üst düzey etiket, case,
            # break ve continue de burada elenir.
            for node in _subtree(it):
                if node.kind in ("label", "case", "break", "continue"):
                    return None
            j += 1
        if term is None:
            return None
        if term.kind == "goto" and term.name == label.name:
            return None
        if not _ends_line(code, term.end):
            return None
        first = items[label.index + 1]
        block_src = an.text[_line_end(an.text, label.end) + 1 : term.end]
        newlines = block_src.count("\n")
        if single:
            if newlines > self._max_inline_lines:
                return None
        elif newlines > _MAX_MULTI_BLOCK_NEWLINES:
            return None
        if not self._is_cleanup_block(block_src):
            return None
        if an.mentions_late_declared(first.start, term.end):
            return None
        return first, term

    # ==================================================================
    # Geçiş 6: etiket adlandırma
    # ==================================================================

    def _pass_rename(self, an: _Analysis, file_ctx: _FileContext | None = None):
        """Kalan ``LAB_`` etiketlerine sezgisel ad verir.

        Yalnız etiket tanımı ve goto hedefi sözcükleri değişir (yorumlar,
        dizgiler ve DISASSEMBLY eki değişmez). Yeni ad dosyadaki hiçbir
        tanımlayıcıyla çakışmaz.
        """
        if file_ctx is None:
            file_ctx = _FileContext(an.code)
        edits: list[_Edit] = []
        count = 0
        for name, label in an.labels.items():
            if not _LAB_NAME_RE.match(name):
                continue
            block, terminator = self._label_block(an.text, label.end)
            if not block or not terminator:
                # Düz blok bir atlamayla bitmiyor (döngü başı, uzun gövde):
                # etiketin amacı bu pencereden okunamaz; ad verilmez.
                continue
            base = self._classify_label(name, block)
            if base == name:
                continue
            if terminator != "return" and base not in _CLEANUP_LABEL_NAMES:
                # "exit"/"error_exit" yalnız blok return ile bitiyorsa doğru
                continue
            while True:
                file_ctx.name_counts[base] += 1
                n = file_ctx.name_counts[base]
                new_name = base if n == 1 else "%s_%d" % (base, n)
                if new_name not in file_ctx.taken:
                    break
            file_ctx.taken.add(new_name)
            edits.append((label.name_span[0], label.name_span[1], new_name))
            for g in an.gotos.get(name, ()):
                edits.append((g.name_span[0], g.name_span[1], new_name))
            count += 1
        if not count:
            return [], {}, {}
        return edits, {"renamed": count}, {}
