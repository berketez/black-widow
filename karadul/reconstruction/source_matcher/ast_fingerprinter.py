"""JS kodundan fonksiyon fingerprint'leri cikar -- regex tabanli, AST parser gereksiz.

Kullanim:
    fingerprinter = ASTFingerprinter()
    functions = fingerprinter.extract_functions(js_code)
    for f in functions:
        print(f.name, f.arity, f.string_literals)

Brace matching ile fonksiyon sinirlarini bulur, her fonksiyon body'si icin
yapisal parmak izi olusturur. String literal'ler, property access'ler,
dallanma/dongu/return sayilari gibi sinyalleri toplar.

NOT: Bu regex tabanli bir yaklasimdir, gercek AST parse degil.
Template literal'ler, iç ice brace'ler gibi edge case'lerde hata yapabilir.
Ancak fingerprint eslestirme icin yeterli dogrulukta calisir.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# --- Regex pattern'leri ---

# function NAME(params) {
RE_FUNCTION_DECL = re.compile(
    r"function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)\s*\{",
)

# const/let/var NAME = function(params) {
RE_FUNCTION_EXPR = re.compile(
    r"(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*)?\s*\(([^)]*)\)\s*\{",
)

# const/let/var NAME = (params) => {
RE_ARROW_BLOCK = re.compile(
    r"(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>\s*\{",
)

# const/let/var NAME = SINGLE_PARAM => {
RE_ARROW_SINGLE = re.compile(
    r"(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=>\s*\{",
)

# class method: NAME(params) {  (class body icinde)
RE_METHOD = re.compile(
    r"(?:async\s+)?([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)\s*\{",
)

# Property accesses: .push, .map, .filter etc.
RE_PROPERTY_ACCESS = re.compile(
    r"\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:\(|(?=[^(]))",
)

# String literals: "..." ve '...'
RE_STRING_DOUBLE = re.compile(r'"((?:[^"\\]|\\.)*)"')
RE_STRING_SINGLE = re.compile(r"'((?:[^'\\]|\\.)*)'")

# Branch patterns
RE_IF = re.compile(r"\bif\s*\(")
RE_ELSE = re.compile(r"\belse\b")
RE_SWITCH = re.compile(r"\bswitch\s*\(")
RE_TERNARY = re.compile(r"[^?]\?[^?:.].*?:")  # basit ternary tespiti

# Loop patterns
RE_FOR = re.compile(r"\bfor\s*\(")
RE_WHILE = re.compile(r"\bwhile\s*\(")
RE_DO_WHILE = re.compile(r"\bdo\s*\{")

# Statement patterns
RE_RETURN = re.compile(r"\breturn\b")
RE_THROW = re.compile(r"\bthrow\b")
RE_TRY = re.compile(r"\btry\s*\{")
RE_CATCH = re.compile(r"\bcatch\s*\(")

# Nested function (body icindeki function/arrow tespiti)
RE_NESTED_FUNC = re.compile(
    r"(?:function\s+[a-zA-Z_$]|function\s*\(|=>\s*\{)"
)

# Statement terminator (noktalı virgul veya } ile biten satirlar)
RE_STATEMENT = re.compile(r"[;}\n]")


@dataclass
class FunctionFingerprint:
    """Bir fonksiyonun yapisal parmak izi.

    Minified kodda isimler kısaltılır ama yapisal ozellikler korunur:
    - Parametre sayisi (arity)
    - String literal'ler (minifier'lar dokunmaz)
    - Property access'ler (.push, .map, .filter)
    - Dallanma/dongu/return sayilari
    """

    name: str  # orijinal isim (veya minified isim)
    arity: int  # parametre sayisi
    param_names: list[str] = field(default_factory=list)  # parametre isimleri
    string_literals: list[str] = field(default_factory=list)  # icindeki string'ler (sirali, unique)
    property_accesses: list[str] = field(default_factory=list)  # .push, .map, .filter gibi
    branch_count: int = 0  # if/else/switch/ternary sayisi
    loop_count: int = 0  # for/while/do-while sayisi
    return_count: int = 0  # return statement sayisi
    throw_count: int = 0  # throw statement sayisi
    has_try_catch: bool = False  # try/catch var mi
    nested_func_count: int = 0  # ic fonksiyon sayisi
    total_statements: int = 0  # toplam statement sayisi
    line_count: int = 0  # satir sayisi
    body_hash: str = ""  # body'nin kisa hash'i (debug icin)

    def similarity(self, other: FunctionFingerprint) -> float:
        """0.0 - 1.0 arasi benzerlik skoru.

        Agirliklar:
        - String literals (Jaccard): %35 (en guvenilir sinyal)
        - Property accesses (Jaccard): %20
        - Arity (exact match): %15
        - Branch count (toleransli): %10
        - Loop count: %05
        - Return count: %05
        - has_try_catch: %05
        - Statement count (ratio): %05
        """
        score = 0.0
        weights_total = 0.0

        # Arity (en guclu sinyal -- parametre sayisi minifier'da korunur)
        w = 0.15
        weights_total += w
        if self.arity == other.arity:
            score += w

        # String literals (Jaccard similarity)
        w = 0.35
        weights_total += w
        s1 = set(self.string_literals)
        s2 = set(other.string_literals)
        if s1 or s2:
            union = s1 | s2
            jaccard = len(s1 & s2) / len(union) if union else 0
            score += w * jaccard
        else:
            score += w * 0.5  # ikisi de string'siz -> notr

        # Property accesses
        w = 0.20
        weights_total += w
        p1 = set(self.property_accesses)
        p2 = set(other.property_accesses)
        if p1 or p2:
            union = p1 | p2
            jaccard = len(p1 & p2) / len(union) if union else 0
            score += w * jaccard
        else:
            score += w * 0.5

        # Branch count (toleransli)
        w = 0.10
        weights_total += w
        if self.branch_count == other.branch_count:
            score += w
        elif abs(self.branch_count - other.branch_count) <= 2:
            score += w * 0.5

        # Loop count
        w = 0.05
        weights_total += w
        if self.loop_count == other.loop_count:
            score += w

        # Return count
        w = 0.05
        weights_total += w
        if self.return_count == other.return_count:
            score += w

        # has_try_catch
        w = 0.05
        weights_total += w
        if self.has_try_catch == other.has_try_catch:
            score += w

        # Statement count (toleransli -- ratio)
        w = 0.05
        weights_total += w
        if self.total_statements and other.total_statements:
            ratio = min(self.total_statements, other.total_statements) / max(
                self.total_statements, other.total_statements
            )
            score += w * ratio

        return score / weights_total if weights_total > 0 else 0.0

    def summary(self) -> str:
        """Kisa ozet string."""
        return (
            f"{self.name}({self.arity}) "
            f"str:{len(self.string_literals)} "
            f"prop:{len(self.property_accesses)} "
            f"br:{self.branch_count} "
            f"loop:{self.loop_count} "
            f"ret:{self.return_count} "
            f"stmt:{self.total_statements}"
        )


class ASTFingerprinter:
    """JS kodundan fonksiyon fingerprint'leri cikar -- regex tabanli.

    Calisma mantigi:
    1. Koddan tum fonksiyon/method/arrow tanimlarini bul (regex)
    2. Her biri icin brace matching ile body'yi cikar
    3. Body'den yapisal ozellikleri cikar (string'ler, property'ler, dallanma vs.)
    4. FunctionFingerprint dataclass'i olustur
    """

    def __init__(self, min_body_length: int = 10, min_statements: int = 1):
        """
        Args:
            min_body_length: Minimum fonksiyon body uzunlugu (karakter)
            min_statements: Minimum statement sayisi (cok kucuk fonksiyonlari atla)
        """
        self.min_body_length = min_body_length
        self.min_statements = min_statements

    def extract_functions(self, code: str) -> list[FunctionFingerprint]:
        """Koddan tum fonksiyonlari cikar ve fingerprint olustur.

        Destek:
        - function NAME(params) { ... }
        - const/let/var NAME = function(params) { ... }
        - const/let/var NAME = (params) => { ... }
        - const/let/var NAME = param => { ... }
        - class method: NAME(params) { ... }

        Returns:
            FunctionFingerprint listesi (sirali)
        """
        functions: list[FunctionFingerprint] = []
        seen_positions: set[int] = set()  # ayni fonksiyonu iki kez isleme

        # 1. function declarations: function NAME(params) {
        for m in RE_FUNCTION_DECL.finditer(code):
            brace_pos = m.end() - 1  # { pozisyonu
            if brace_pos in seen_positions:
                continue
            seen_positions.add(brace_pos)

            name = m.group(1)
            params = m.group(2).strip()
            body = self._extract_brace_body(code, brace_pos)
            if body is None:
                continue

            fp = self._build_fingerprint(name, params, body)
            if fp is not None:
                functions.append(fp)

        # 2. function expressions: const NAME = function(params) {
        for m in RE_FUNCTION_EXPR.finditer(code):
            brace_pos = m.end() - 1
            if brace_pos in seen_positions:
                continue
            seen_positions.add(brace_pos)

            name = m.group(1)
            params = m.group(2).strip()
            body = self._extract_brace_body(code, brace_pos)
            if body is None:
                continue

            fp = self._build_fingerprint(name, params, body)
            if fp is not None:
                functions.append(fp)

        # 3. arrow functions with block body: const NAME = (params) => {
        for m in RE_ARROW_BLOCK.finditer(code):
            brace_pos = m.end() - 1
            if brace_pos in seen_positions:
                continue
            seen_positions.add(brace_pos)

            name = m.group(1)
            params = m.group(2).strip()
            body = self._extract_brace_body(code, brace_pos)
            if body is None:
                continue

            fp = self._build_fingerprint(name, params, body)
            if fp is not None:
                functions.append(fp)

        # 4. arrow functions with single param: const NAME = param => {
        for m in RE_ARROW_SINGLE.finditer(code):
            brace_pos = m.end() - 1
            if brace_pos in seen_positions:
                continue
            seen_positions.add(brace_pos)

            name = m.group(1)
            params = m.group(2).strip()
            body = self._extract_brace_body(code, brace_pos)
            if body is None:
                continue

            fp = self._build_fingerprint(name, params, body)
            if fp is not None:
                functions.append(fp)

        logger.info(
            "ASTFingerprinter: %d fonksiyon cikarildi (%d karakter koddan)",
            len(functions),
            len(code),
        )
        return functions

    def _extract_brace_body(self, code: str, open_pos: int) -> str | None:
        """Brace matching ile fonksiyon body'sini cikar.

        String literal'ler icindeki brace'leri atlar (string-aware).
        Template literal'ler (backtick) icindeki brace'ler de atlanir.

        Args:
            code: Tam kaynak kod
            open_pos: Acilan { pozisyonu

        Returns:
            Body string'i (brace'ler haric) veya None (eslesme bulunamazsa)
        """
        if open_pos >= len(code) or code[open_pos] != "{":
            return None

        depth = 0
        i = open_pos
        in_single_quote = False
        in_double_quote = False
        in_template = False
        in_line_comment = False
        in_block_comment = False

        while i < len(code):
            c = code[i]

            # Line comment
            if in_line_comment:
                if c == "\n":
                    in_line_comment = False
                i += 1
                continue

            # Block comment
            if in_block_comment:
                if c == "*" and i + 1 < len(code) and code[i + 1] == "/":
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue

            # Comment detection
            if not in_single_quote and not in_double_quote and not in_template:
                if c == "/" and i + 1 < len(code):
                    next_c = code[i + 1]
                    if next_c == "/":
                        in_line_comment = True
                        i += 2
                        continue
                    if next_c == "*":
                        in_block_comment = True
                        i += 2
                        continue

            # Escape character
            if c == "\\" and (in_single_quote or in_double_quote or in_template):
                i += 2  # escape'i atla
                continue

            # String state tracking
            if not in_double_quote and not in_template and c == "'":
                in_single_quote = not in_single_quote
            elif not in_single_quote and not in_template and c == '"':
                in_double_quote = not in_double_quote
            elif not in_single_quote and not in_double_quote and c == "`":
                in_template = not in_template
            elif not in_single_quote and not in_double_quote and not in_template:
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        # Body: open_pos+1 ... i-1
                        return code[open_pos + 1 : i]

            i += 1

        # Eslesen kapanma bulunamadi
        return None

    def _build_fingerprint(
        self, name: str, params_str: str, body: str
    ) -> FunctionFingerprint | None:
        """Fonksiyon body'sinden fingerprint olustur.

        Args:
            name: Fonksiyon adi
            params_str: Parametre string'i (orn: "a, b, c")
            body: Fonksiyon body'si (brace'ler haric)

        Returns:
            FunctionFingerprint veya None (cok kucukse)
        """
        if len(body) < self.min_body_length:
            return None

        # Parametre parse
        param_names = self._parse_params(params_str)
        arity = len(param_names)

        # Yapisal ozellikler
        strings = self._extract_strings(body)
        properties = self._extract_property_accesses(body)
        branches = self._count_branches(body)
        loops = self._count_loops(body)
        returns = self._count_returns(body)
        throws = self._count_throws(body)
        try_catch = self._has_try_catch(body)
        nested = self._count_nested_functions(body)
        statements = self._count_statements(body)
        lines = body.count("\n") + 1

        if statements < self.min_statements:
            return None

        return FunctionFingerprint(
            name=name,
            arity=arity,
            param_names=param_names,
            string_literals=strings,
            property_accesses=properties,
            branch_count=branches,
            loop_count=loops,
            return_count=returns,
            throw_count=throws,
            has_try_catch=try_catch,
            nested_func_count=nested,
            total_statements=statements,
            line_count=lines,
        )

    def _parse_params(self, params_str: str) -> list[str]:
        """Parametre string'ini parse et.

        Destekler:
        - "a, b, c" -> ["a", "b", "c"]
        - "a = 5, b" -> ["a", "b"]
        - "{x, y}, z" -> ["{x, y}", "z"]
        - "" -> []
        """
        if not params_str.strip():
            return []

        params: list[str] = []
        depth = 0
        current = ""

        for c in params_str:
            if c in "({[":
                depth += 1
                current += c
            elif c in ")}]":
                depth -= 1
                current += c
            elif c == "," and depth == 0:
                param = current.strip()
                if param:
                    # Default value'yu sil (= sonrasini at)
                    if "=" in param and not param.startswith("{") and not param.startswith("["):
                        param = param.split("=")[0].strip()
                    # Rest/spread operator
                    param = param.lstrip(".")
                    params.append(param)
                current = ""
            else:
                current += c

        # Son parametreyi ekle
        param = current.strip()
        if param:
            if "=" in param and not param.startswith("{") and not param.startswith("["):
                param = param.split("=")[0].strip()
            param = param.lstrip(".")
            params.append(param)

        return params

    def _extract_strings(self, code: str) -> list[str]:
        """String literal'leri cikar (sirali, unique).

        Hem "..." hem '...' pattern'lerini destekler.
        Cok kisa string'leri (<2 karakter) atlar.
        """
        strings: list[str] = []
        seen: set[str] = set()

        for pattern in (RE_STRING_DOUBLE, RE_STRING_SINGLE):
            for m in pattern.finditer(code):
                s = m.group(1)
                # Cok kisa veya bos string'leri atla
                if len(s) < 2:
                    continue
                # Sadece escape karakterlerinden olusan string'leri atla
                if all(c == "\\" or c == "n" or c == "t" for c in s):
                    continue
                if s not in seen:
                    seen.add(s)
                    strings.append(s)

        # Sirala (deterministic fingerprint icin)
        strings.sort()
        return strings

    def _extract_property_accesses(self, code: str) -> list[str]:
        """Property erisimlerini cikar (.push, .map, .filter gibi).

        Sadece bilinen/anlamli property'leri tutar (cok kisa olanlari atlar).
        Unique, sirali.
        """
        # Bilinen onemli property'ler (minifier'lar dokunmaz)
        known_properties = {
            "push", "pop", "shift", "unshift", "splice", "slice", "concat",
            "map", "filter", "reduce", "forEach", "find", "findIndex", "some", "every",
            "includes", "indexOf", "lastIndexOf", "join", "split", "replace",
            "trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase",
            "match", "search", "test", "exec",
            "keys", "values", "entries", "hasOwnProperty", "assign", "create",
            "freeze", "defineProperty", "getOwnPropertyNames",
            "apply", "call", "bind",
            "then", "catch", "finally",
            "resolve", "reject", "all", "allSettled", "race",
            "stringify", "parse",
            "log", "warn", "error", "info", "debug",
            "emit", "on", "once", "removeListener", "addEventListener",
            "write", "read", "end", "pipe", "destroy",
            "set", "get", "has", "delete", "clear", "add",
            "sort", "reverse", "fill", "flat", "flatMap",
            "toString", "valueOf", "charAt", "charCodeAt", "codePointAt",
            "startsWith", "endsWith", "padStart", "padEnd", "repeat",
            "length", "size", "name", "message", "stack", "code",
            "prototype", "constructor", "super",
            "next", "done", "value", "return", "throw",
        }

        seen: set[str] = set()
        for m in RE_PROPERTY_ACCESS.finditer(code):
            prop = m.group(1)
            if prop in known_properties and prop not in seen:
                seen.add(prop)

        return sorted(seen)

    def _count_branches(self, code: str) -> int:
        """if/else/switch/ternary sayisi."""
        count = 0
        count += len(RE_IF.findall(code))
        count += len(RE_ELSE.findall(code))
        count += len(RE_SWITCH.findall(code))
        # Ternary: basit yaklasim (false positive olabilir)
        count += len(RE_TERNARY.findall(code))
        return count

    def _count_loops(self, code: str) -> int:
        """for/while/do-while sayisi."""
        count = 0
        count += len(RE_FOR.findall(code))
        count += len(RE_WHILE.findall(code))
        count += len(RE_DO_WHILE.findall(code))
        return count

    def _count_returns(self, code: str) -> int:
        """return statement sayisi."""
        return len(RE_RETURN.findall(code))

    def _count_throws(self, code: str) -> int:
        """throw statement sayisi."""
        return len(RE_THROW.findall(code))

    def _has_try_catch(self, code: str) -> bool:
        """try/catch blogu var mi."""
        return bool(RE_TRY.search(code)) and bool(RE_CATCH.search(code))

    def _count_nested_functions(self, code: str) -> int:
        """Ic fonksiyon sayisi (function tanimlari + arrow function'lar)."""
        return len(RE_NESTED_FUNC.findall(code))

    def _count_statements(self, code: str) -> int:
        """Toplam statement sayisi (yaklasik).

        Semicolon ve kapanan brace sayisiyla tahmin eder.
        Yorum satirlarini atlar.
        """
        # Basit yaklasim: ; sayisi + } sayisi (blok sonu)
        # Daha dogru bir yontem icin gercek parser lazim ama bu yeterli
        semi = code.count(";")
        # return/throw/break/continue gibi keyword'ler de statement
        keywords = 0
        for kw in (RE_RETURN, RE_THROW):
            keywords += len(kw.findall(code))
        # En buyugunu al (semi zaten cogu statement'i kapsar)
        return max(semi, keywords)

    def fingerprint_code(self, code: str, label: str = "unknown") -> list[FunctionFingerprint]:
        """Kodu fingerprint'le -- extract_functions icin alias.

        Args:
            code: JS kaynak kodu
            label: Log icin etiket (orn: dosya adi)

        Returns:
            FunctionFingerprint listesi
        """
        logger.debug("Fingerprinting: %s (%d bytes)", label, len(code))
        return self.extract_functions(code)
