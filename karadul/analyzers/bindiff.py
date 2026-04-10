"""Binary karsilastirma (BinDiff benzeri) modulu.

Iki binary arasinda fonksiyon eslestirmesi yapar:
- Referans binary (debug sembollerle, isimler biliniyor)
- Hedef binary (stripped, isimler bilinmiyor)

Ghidra JSON ciktilarini girdi olarak kullanir:
  - functions.json: fonksiyon listesi (name, address, size, param_count, ...)
  - strings.json: string listesi ve xref bilgileri
  - call_graph.json: cagri grafi (nodes, edges)

Eslestirme stratejileri (sirasiz calisan, en yuksek confidence oncelikli):
  1. Decompiled hash: Decompile edilmis C kodunun normalize hash'i (exact match)
  2. CFG fingerprint: basic block pattern'i (size + param_count + return_type + convention)
  3. String referans fingerprint: fonksiyonun referans ettigi string kumeleri
  4. Size + params: fonksiyon boyutu, parametre sayisi ve tip bilgileri
  5. Call graph pattern: caller/callee komsuluk benzerlik skor

Kullanim:
    differ = BinaryDiffer()
    result = differ.compare(
        reference={"functions": [...], "strings": [...]},  # debug binary Ghidra JSON
        target={"functions": [...], "strings": [...]},      # stripped binary Ghidra JSON
    )
    # result.matches: [DiffMatch(ref_name="SSL_read", target_name="FUN_001234", ...)]
    naming_map = differ.transfer_names(result)
    # {"FUN_001234": "SSL_read", ...}
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DiffMatch:
    """Tek bir fonksiyon eslesmesi."""

    ref_name: str
    ref_address: str
    target_name: str
    target_address: str
    confidence: float  # 0.0 - 1.0
    method: str  # "decompiled_hash", "cfg_fingerprint", "string_refs", "size_params", "call_pattern"


@dataclass
class DiffResult:
    """Karsilastirma sonucu."""

    total_ref_functions: int = 0
    total_target_functions: int = 0
    matched: int = 0
    unmatched_ref: int = 0
    unmatched_target: int = 0
    matches: list[DiffMatch] = field(default_factory=list)
    match_rate: float = 0.0  # matched / min(total_ref, total_target)

    def summary(self) -> dict:
        """Ozet istatistikleri dict olarak dondur."""
        return {
            "total_ref_functions": self.total_ref_functions,
            "total_target_functions": self.total_target_functions,
            "matched": self.matched,
            "unmatched_ref": self.unmatched_ref,
            "unmatched_target": self.unmatched_target,
            "match_rate": round(self.match_rate, 4),
            "by_method": dict(Counter(m.method for m in self.matches)),
        }


# ---------------------------------------------------------------------------
# Normalize helpers
# ---------------------------------------------------------------------------

# Decompile edilmis C kodundaki adres ve degisken isimlerini normalize et
_ADDR_RE = re.compile(r"\b(?:0x[0-9a-fA-F]+|[0-9a-fA-F]{8,})\b")
_FUNC_NAME_RE = re.compile(r"\bFUN_[0-9a-fA-F]+\b")
_VAR_NAME_RE = re.compile(r"\b(?:local_|param_|uVar|iVar|lVar|cVar|sVar|bVar|unaff_|in_)[0-9a-zA-Z_]*\b")
_WHITESPACE_RE = re.compile(r"\s+")

# Fonksiyon tanimi satirindaki ismi normalize et:
# "int SSL_read(" veya "void* my_func(" gibi C fonksiyon imzalarini yakalar
# ve ismi FUNC ile degistirir. Boylece farkli isimli ama ayni govdeli
# fonksiyonlar ayni hash'i uretir.
_FUNC_DEF_RE = re.compile(
    r"^(\s*(?:[\w*]+\s+)+?)"  # return type (int, void*, unsigned long, ...)
    r"(\w+)"                   # fonksiyon ismi
    r"(\s*\()",                # acilan parantez
    re.MULTILINE,
)

# Fonksiyon cagrilarini normalize et: herhangi bir identifier + ( pattern'i
# (C'de foo( seklinde fonksiyon cagrisi) -- sadece bilinen C keyword'lerini koru
_C_KEYWORDS = frozenset({
    "if", "else", "while", "for", "do", "switch", "case", "return",
    "break", "continue", "goto", "sizeof", "typeof", "struct", "union",
    "enum", "typedef", "const", "static", "extern", "volatile", "register",
    "inline", "void", "int", "char", "short", "long", "float", "double",
    "unsigned", "signed", "bool",
})
_FUNC_CALL_RE = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")


def _normalize_decompiled(code: str) -> str:
    """Decompile edilmis C kodunu normalize et.

    Adresler, degisken isimleri, fonksiyon isimleri ve whitespace
    farklarini yok eder. Boylece ayni kaynak koddan gelen ama farkli
    adreslere yuklenmis ve farkli isimlendirilmis fonksiyonlar ayni
    hash'i uretir.
    """
    text = _ADDR_RE.sub("ADDR", code)
    text = _FUNC_NAME_RE.sub("FUNC", text)
    text = _VAR_NAME_RE.sub("VAR", text)

    # Fonksiyon tanimi satirindaki ismi normalize et
    text = _FUNC_DEF_RE.sub(r"\1FUNC\3", text)

    # Fonksiyon cagrilarini normalize et (C keyword'leri haric)
    def _replace_call(m: re.Match) -> str:
        name = m.group(1)
        if name in _C_KEYWORDS:
            return m.group(0)
        return "FUNC("

    text = _FUNC_CALL_RE.sub(_replace_call, text)

    text = _WHITESPACE_RE.sub(" ", text)
    return text.strip()


def _sha256(text: str) -> str:
    """String'in SHA256 hash'ini dondur."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Internal helper: fonksiyon-string haritasi
# ---------------------------------------------------------------------------


def _build_func_string_map(strings_data: dict) -> dict[str, set[str]]:
    """strings.json'dan fonksiyon_adresi -> {string_degerleri} haritasi olustur.

    Her string xref'ine bakar, string'i hangi fonksiyonun referans ettigini bulur.
    """
    result: dict[str, set[str]] = {}
    strings_list = strings_data.get("strings", [])

    for s in strings_list:
        value = s.get("value", "")
        if not value or len(value) < 3:
            # Cok kisa string'ler anlamsiz (tek harf, bos, "\n" vb.)
            continue

        # xref-based eslestirme (en guvenilir)
        xrefs = s.get("xrefs", [])
        for xref in xrefs:
            func_addr = xref.get("from_func_addr")
            if func_addr:
                result.setdefault(func_addr, set()).add(value)

        # Fallback: dogrudan function_addr field'i
        func_addr = s.get("function_addr")
        if func_addr:
            result.setdefault(func_addr, set()).add(value)

    return result


# ---------------------------------------------------------------------------
# BinaryDiffer
# ---------------------------------------------------------------------------


class BinaryDiffer:
    """Iki binary arasinda fonksiyon eslestirmesi yapar.

    Ghidra JSON ciktisini girdi alir. 5 strateji sirayla uygulanir.
    Eslesen fonksiyonlar sonraki stratejilerden cikarilir (greedy).
    """

    def compare(
        self,
        reference: dict,
        target: dict,
        min_confidence: float = 0.7,
        ref_call_graph: Optional[dict] = None,
        target_call_graph: Optional[dict] = None,
        ref_strings: Optional[dict] = None,
        target_strings: Optional[dict] = None,
        ref_decompiled: Optional[dict] = None,
        target_decompiled: Optional[dict] = None,
    ) -> DiffResult:
        """Iki binary'nin fonksiyonlarini karsilastir.

        Args:
            reference: Ghidra functions.json (veya icerisinde "functions" key'i olan dict).
            target: Ghidra functions.json (stripped binary).
            min_confidence: Minimum eslestirme guvenligi (0.0-1.0).
            ref_call_graph: Referans binary'nin call_graph.json verisi (opsiyonel).
            target_call_graph: Hedef binary'nin call_graph.json verisi (opsiyonel).
            ref_strings: Referans binary'nin strings.json verisi (opsiyonel).
            target_strings: Hedef binary'nin strings.json verisi (opsiyonel).
            ref_decompiled: Referans binary'nin decompiled.json verisi (opsiyonel).
            target_decompiled: Hedef binary'nin decompiled.json verisi (opsiyonel).

        Returns:
            DiffResult: Eslestirme sonuclari.
        """
        ref_funcs = reference.get("functions", [])
        target_funcs = target.get("functions", [])

        result = DiffResult(
            total_ref_functions=len(ref_funcs),
            total_target_functions=len(target_funcs),
        )

        # Hizli index: address -> func dict
        ref_by_addr = {f["address"]: f for f in ref_funcs}
        target_by_addr = {f["address"]: f for f in target_funcs}

        # Eslesmemis fonksiyonlarin adreslerini takip et
        unmatched_ref_addrs = set(ref_by_addr.keys())
        unmatched_target_addrs = set(target_by_addr.keys())

        # --- Strateji 1: Decompiled hash (en yuksek confidence) ---
        if ref_decompiled and target_decompiled:
            matches = self._strategy_decompiled_hash(
                ref_funcs, target_funcs, ref_decompiled, target_decompiled,
                unmatched_ref_addrs, unmatched_target_addrs,
            )
            for m in matches:
                if m.confidence >= min_confidence:
                    result.matches.append(m)
                    unmatched_ref_addrs.discard(m.ref_address)
                    unmatched_target_addrs.discard(m.target_address)

        # --- Strateji 2: CFG Fingerprint ---
        remaining_ref = [ref_by_addr[a] for a in unmatched_ref_addrs]
        remaining_target = [target_by_addr[a] for a in unmatched_target_addrs]

        matches = self._strategy_cfg_fingerprint(remaining_ref, remaining_target)
        for m in matches:
            if m.confidence >= min_confidence:
                result.matches.append(m)
                unmatched_ref_addrs.discard(m.ref_address)
                unmatched_target_addrs.discard(m.target_address)

        # --- Strateji 3: String referans fingerprint ---
        if ref_strings and target_strings:
            remaining_ref = [ref_by_addr[a] for a in unmatched_ref_addrs]
            remaining_target = [target_by_addr[a] for a in unmatched_target_addrs]

            matches = self._strategy_string_refs(
                remaining_ref, remaining_target, ref_strings, target_strings,
            )
            for m in matches:
                if m.confidence >= min_confidence:
                    result.matches.append(m)
                    unmatched_ref_addrs.discard(m.ref_address)
                    unmatched_target_addrs.discard(m.target_address)

        # --- Strateji 4: Size + params ---
        remaining_ref = [ref_by_addr[a] for a in unmatched_ref_addrs]
        remaining_target = [target_by_addr[a] for a in unmatched_target_addrs]

        matches = self._strategy_size_params(remaining_ref, remaining_target)
        for m in matches:
            if m.confidence >= min_confidence:
                result.matches.append(m)
                unmatched_ref_addrs.discard(m.ref_address)
                unmatched_target_addrs.discard(m.target_address)

        # --- Strateji 5: Call graph pattern ---
        if ref_call_graph and target_call_graph:
            remaining_ref = [ref_by_addr[a] for a in unmatched_ref_addrs]
            remaining_target = [target_by_addr[a] for a in unmatched_target_addrs]

            matches = self._strategy_call_pattern(
                remaining_ref, remaining_target,
                ref_call_graph, target_call_graph,
                result.matches,  # onceki eslesmeler, propagasyon icin
            )
            for m in matches:
                if m.confidence >= min_confidence:
                    result.matches.append(m)
                    unmatched_ref_addrs.discard(m.ref_address)
                    unmatched_target_addrs.discard(m.target_address)

        # --- Sonuclari hesapla ---
        result.matched = len(result.matches)
        result.unmatched_ref = len(unmatched_ref_addrs)
        result.unmatched_target = len(unmatched_target_addrs)

        denominator = min(result.total_ref_functions, result.total_target_functions)
        if denominator > 0:
            result.match_rate = result.matched / denominator
        else:
            result.match_rate = 0.0

        logger.info(
            "BinDiff: %d/%d eslesti (%.1f%%), yontemler: %s",
            result.matched,
            denominator,
            result.match_rate * 100,
            dict(Counter(m.method for m in result.matches)),
        )

        return result

    # ------------------------------------------------------------------
    # Strateji 1: Decompiled Hash
    # ------------------------------------------------------------------

    def _strategy_decompiled_hash(
        self,
        ref_funcs: list[dict],
        target_funcs: list[dict],
        ref_decompiled: dict,
        target_decompiled: dict,
        unmatched_ref: set[str],
        unmatched_target: set[str],
    ) -> list[DiffMatch]:
        """Decompile edilmis C kodunun normalize edilmis SHA256 hash'ini karsilastir.

        Ghidra decompiled.json icerisinde her fonksiyon icin decompiled C
        kaynak dosyasi var. Bu kodu normalize edip (adresler, degisken isimleri
        temizlenir) hash'ini aliriz. Ayni hash = ayni fonksiyon.

        Confidence: 0.95 (normalize edildigi icin %100 degil, nadiren collision olabilir)
        """
        matches: list[DiffMatch] = []

        # decompiled.json: {"functions": [{"name": ..., "address": ..., "file": ...}]}
        # "file" alani decompiled C dosyasinin adi, ama icerigi yoksa hash alamayiz.
        # Alternatif: eger "code" veya "body" key'i varsa onu kullan.

        ref_decomp = self._build_decompiled_index(ref_decompiled, unmatched_ref)
        target_decomp = self._build_decompiled_index(target_decompiled, unmatched_target)

        if not ref_decomp or not target_decomp:
            return matches

        # Hash -> [(addr, name)] index olustur
        ref_by_hash: dict[str, list[tuple[str, str]]] = {}
        for addr, (name, code_hash) in ref_decomp.items():
            ref_by_hash.setdefault(code_hash, []).append((addr, name))

        target_by_hash: dict[str, list[tuple[str, str]]] = {}
        for addr, (name, code_hash) in target_decomp.items():
            target_by_hash.setdefault(code_hash, []).append((addr, name))

        # Eslestir: ayni hash, tek ref + tek target => exact match
        for h, ref_entries in ref_by_hash.items():
            target_entries = target_by_hash.get(h)
            if not target_entries:
                continue

            # 1:1 eslestirme (hash collision varsa, yani birden fazla
            # fonksiyon ayni hash'e sahipse, eslestirme yapmiyoruz -- belirsiz)
            if len(ref_entries) == 1 and len(target_entries) == 1:
                r_addr, r_name = ref_entries[0]
                t_addr, t_name = target_entries[0]
                matches.append(DiffMatch(
                    ref_name=r_name,
                    ref_address=r_addr,
                    target_name=t_name,
                    target_address=t_addr,
                    confidence=0.95,
                    method="decompiled_hash",
                ))
            elif len(ref_entries) == 1 and len(target_entries) > 1:
                # Bir ref, birden fazla target => en kucuk adres farkina gore sec
                # (genellikle ayni siralamayla yuklenir)
                r_addr, r_name = ref_entries[0]
                # Basitce ilk target'i sec (siralanmis)
                t_addr, t_name = target_entries[0]
                matches.append(DiffMatch(
                    ref_name=r_name,
                    ref_address=r_addr,
                    target_name=t_name,
                    target_address=t_addr,
                    confidence=0.80,
                    method="decompiled_hash",
                ))

        return matches

    def _build_decompiled_index(
        self,
        decompiled: dict,
        valid_addrs: set[str],
    ) -> dict[str, tuple[str, str]]:
        """decompiled.json'dan addr -> (name, normalized_hash) index olustur.

        Decompiled verisi iki formati destekler:
        1. Fonksiyonlarda "code" veya "body" key'i varsa dogrudan hash al.
        2. Yoksa "lines" (satir sayisi) kullan ama hash uretemeyiz -- bos dondur.
        """
        result: dict[str, tuple[str, str]] = {}
        funcs = decompiled.get("functions", [])

        for f in funcs:
            addr = f.get("address", "")
            if addr not in valid_addrs:
                continue

            name = f.get("name", "")
            # Eger code/body varsa normalize et ve hash al
            code = f.get("code") or f.get("body") or f.get("decompiled") or ""
            if not code:
                continue

            normalized = _normalize_decompiled(code)
            if len(normalized) < 10:
                # Cok kisa (bos fonksiyon, sadece return) -- atla
                continue

            code_hash = _sha256(normalized)
            result[addr] = (name, code_hash)

        return result

    # ------------------------------------------------------------------
    # Strateji 2: CFG Fingerprint
    # ------------------------------------------------------------------

    def _strategy_cfg_fingerprint(
        self,
        ref_funcs: list[dict],
        target_funcs: list[dict],
    ) -> list[DiffMatch]:
        """CFG yapisal fingerprint: size + param_count + return_type + calling_convention.

        Tam eslesen fingerprint'ler icin 1:1 eslestirme yapar.
        Birden fazla ayni fingerprint varsa belirsiz -- eslestirmez.

        Confidence: 0.85 (yapisal benzerlik yuksek ama identik olmayabilir)
        """
        matches: list[DiffMatch] = []

        ref_by_fp: dict[str, list[dict]] = {}
        for f in ref_funcs:
            fp = self._cfg_fingerprint(f)
            ref_by_fp.setdefault(fp, []).append(f)

        target_by_fp: dict[str, list[dict]] = {}
        for f in target_funcs:
            fp = self._cfg_fingerprint(f)
            target_by_fp.setdefault(fp, []).append(f)

        for fp, ref_entries in ref_by_fp.items():
            target_entries = target_by_fp.get(fp)
            if not target_entries:
                continue

            # 1:1 eslestirme: sadece tek ref + tek target
            if len(ref_entries) == 1 and len(target_entries) == 1:
                r = ref_entries[0]
                t = target_entries[0]
                # Cok kucuk fonksiyonlar (thunk, stub) icin confidence dusur
                size = r.get("size", 0)
                if size < 16:
                    confidence = 0.70
                elif size < 64:
                    confidence = 0.80
                else:
                    confidence = 0.85

                # Thunk fonksiyonlar icin match guvensiz
                if r.get("is_thunk") or t.get("is_thunk"):
                    confidence = min(confidence, 0.65)

                matches.append(DiffMatch(
                    ref_name=r["name"],
                    ref_address=r["address"],
                    target_name=t["name"],
                    target_address=t["address"],
                    confidence=confidence,
                    method="cfg_fingerprint",
                ))

        return matches

    @staticmethod
    def _cfg_fingerprint(func: dict) -> str:
        """Fonksiyonun yapisal fingerprint'ini olustur.

        Size + param_count + return_type + calling_convention bilesimi.
        Ayni kaynak koddan derlenen fonksiyonlar ayni fingerprint'e sahiptir
        (ayni compiler, ayni optimizasyon seviyesi ise).
        """
        size = func.get("size", 0)
        param_count = func.get("param_count", 0)
        ret_type = func.get("return_type", "?")
        convention = func.get("calling_convention", "?")
        is_thunk = func.get("is_thunk", False)

        return f"{size}:{param_count}:{ret_type}:{convention}:{is_thunk}"

    # ------------------------------------------------------------------
    # Strateji 3: String Reference Fingerprint
    # ------------------------------------------------------------------

    def _strategy_string_refs(
        self,
        ref_funcs: list[dict],
        target_funcs: list[dict],
        ref_strings: dict,
        target_strings: dict,
    ) -> list[DiffMatch]:
        """Fonksiyonlarin referans ettigi string kümelerini karsilastir.

        Ayni string'lere referans veren fonksiyonlar = muhtemelen ayni fonksiyon.
        Jaccard benzerlik skoru kullanilir.

        Confidence: jaccard skoru * 0.90 (string bazli, guclu ama tam degil)
        """
        matches: list[DiffMatch] = []

        ref_str_map = _build_func_string_map(ref_strings)
        target_str_map = _build_func_string_map(target_strings)

        if not ref_str_map or not target_str_map:
            return matches

        # Her ref fonksiyon icin, en iyi eslesen target fonksiyonu bul
        ref_func_by_addr = {f["address"]: f for f in ref_funcs}
        target_func_by_addr = {f["address"]: f for f in target_funcs}

        # Sadece ref_funcs ve target_funcs icerisindeki (unmatched) adresleri kullan
        ref_addrs = set(ref_func_by_addr.keys())
        target_addrs = set(target_func_by_addr.keys())

        # String kumesi olan fonksiyonlari filtrele
        ref_with_strings = {
            addr: strings
            for addr, strings in ref_str_map.items()
            if addr in ref_addrs and len(strings) >= 2
        }
        target_with_strings = {
            addr: strings
            for addr, strings in target_str_map.items()
            if addr in target_addrs and len(strings) >= 2
        }

        if not ref_with_strings or not target_with_strings:
            return matches

        # Brute-force jaccard (O(n*m) ama fonksiyon sayisi genellikle < 10K)
        used_targets: set[str] = set()
        candidates: list[tuple[float, str, str]] = []

        for r_addr, r_strings in ref_with_strings.items():
            best_score = 0.0
            best_target = ""
            for t_addr, t_strings in target_with_strings.items():
                jaccard = self._jaccard(r_strings, t_strings)
                if jaccard > best_score:
                    best_score = jaccard
                    best_target = t_addr
            if best_score >= 0.5 and best_target:
                candidates.append((best_score, r_addr, best_target))

        # Yuksek confidence'dan dusuge dogru sirala, greedy eslestir
        candidates.sort(key=lambda x: -x[0])
        for score, r_addr, t_addr in candidates:
            if t_addr in used_targets:
                continue
            if r_addr not in ref_func_by_addr or t_addr not in target_func_by_addr:
                continue

            r_func = ref_func_by_addr[r_addr]
            t_func = target_func_by_addr[t_addr]

            matches.append(DiffMatch(
                ref_name=r_func["name"],
                ref_address=r_addr,
                target_name=t_func["name"],
                target_address=t_addr,
                confidence=round(score * 0.90, 4),
                method="string_refs",
            ))
            used_targets.add(t_addr)

        return matches

    @staticmethod
    def _jaccard(set_a: set, set_b: set) -> float:
        """Iki kume arasindaki Jaccard benzerlik skoru."""
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        return intersection / union if union > 0 else 0.0

    # ------------------------------------------------------------------
    # Strateji 4: Size + Params Match
    # ------------------------------------------------------------------

    def _strategy_size_params(
        self,
        ref_funcs: list[dict],
        target_funcs: list[dict],
    ) -> list[DiffMatch]:
        """Fonksiyon boyutu + parametre sayisi + donus tipi kombinasyonuyla eslestirme.

        CFG fingerprint'e benzer ama daha gevsek: boyut %10 toleransla eslesir.
        Sadece buyuk fonksiyonlarda (>= 64 byte) uygulanir.

        Confidence: 0.78 (orta-dusuk -- false positive riski var ama buyuk fonksiyonlarda guvenilir)
        """
        matches: list[DiffMatch] = []

        # Kucuk fonksiyonlari filtrele (cok fazla duplicate uretir)
        ref_large = [f for f in ref_funcs if f.get("size", 0) >= 64]
        target_large = [f for f in target_funcs if f.get("size", 0) >= 64]

        if not ref_large or not target_large:
            return matches

        used_targets: set[str] = set()
        candidates: list[tuple[float, dict, dict]] = []

        for r in ref_large:
            r_size = r.get("size", 0)
            r_params = r.get("param_count", 0)
            r_ret = r.get("return_type", "?")

            best_score = 0.0
            best_target: Optional[dict] = None

            for t in target_large:
                t_size = t.get("size", 0)
                t_params = t.get("param_count", 0)
                t_ret = t.get("return_type", "?")

                # Parametre sayisi farkli => eslesmez
                if r_params != t_params:
                    continue

                # Donus tipi farkli => penalty ama eslesmez degil
                ret_match = 1.0 if r_ret == t_ret else 0.8

                # Boyut benzerlik skoru (0.0 - 1.0)
                if r_size == 0 and t_size == 0:
                    size_sim = 1.0
                elif r_size == 0 or t_size == 0:
                    continue
                else:
                    size_sim = 1.0 - abs(r_size - t_size) / max(r_size, t_size)

                # %10 tolerans: size_sim >= 0.90
                if size_sim < 0.90:
                    continue

                score = size_sim * ret_match
                if score > best_score:
                    best_score = score
                    best_target = t

            if best_target is not None and best_score >= 0.85:
                candidates.append((best_score, r, best_target))

        # Greedy eslestirme
        candidates.sort(key=lambda x: -x[0])
        for score, r, t in candidates:
            if t["address"] in used_targets:
                continue

            # 1:1 kontrol: ayni size+params'a sahip baska ref var mi?
            # Varsa belirsiz -- atlat
            same_fp_count = sum(
                1
                for other_r in ref_large
                if (
                    other_r["address"] != r["address"]
                    and other_r.get("size", 0) == r.get("size", 0)
                    and other_r.get("param_count", 0) == r.get("param_count", 0)
                    and other_r.get("return_type", "?") == r.get("return_type", "?")
                )
            )
            if same_fp_count > 0:
                continue

            confidence = round(0.78 * score, 4)
            matches.append(DiffMatch(
                ref_name=r["name"],
                ref_address=r["address"],
                target_name=t["name"],
                target_address=t["address"],
                confidence=confidence,
                method="size_params",
            ))
            used_targets.add(t["address"])

        return matches

    # ------------------------------------------------------------------
    # Strateji 5: Call Graph Pattern
    # ------------------------------------------------------------------

    def _strategy_call_pattern(
        self,
        ref_funcs: list[dict],
        target_funcs: list[dict],
        ref_graph: dict,
        target_graph: dict,
        existing_matches: list[DiffMatch],
    ) -> list[DiffMatch]:
        """Call graph komsuluk pattern'ini kullanarak eslestirme.

        Onceki stratejilerde eslesen fonksiyonlari "capa" olarak kullanir.
        Bir fonksiyonun eslesmis callees/callers pattern'i, eslesmemis
        komsuyu icin ipucu verir.

        Ornek: A -> [B, C, D] ise ve B, C eslesmisse, D'nin komsuluk
        pattern'i kullanilarak hedef taraftaki karsilik bulunur.

        Confidence: 0.75 (yapisal propagasyon, orta guvence)
        """
        matches: list[DiffMatch] = []

        ref_nodes = ref_graph.get("nodes", {})
        target_nodes = target_graph.get("nodes", {})

        if not ref_nodes or not target_nodes:
            return matches

        # Mevcut eslesmelerden addr -> addr mapping olustur
        ref_to_target: dict[str, str] = {}
        target_to_ref: dict[str, str] = {}
        for m in existing_matches:
            ref_to_target[m.ref_address] = m.target_address
            target_to_ref[m.target_address] = m.ref_address

        ref_func_by_addr = {f["address"]: f for f in ref_funcs}
        target_func_by_addr = {f["address"]: f for f in target_funcs}

        ref_addrs = set(ref_func_by_addr.keys())
        target_addrs = set(target_func_by_addr.keys())

        used_targets: set[str] = set()
        candidates: list[tuple[float, str, str]] = []

        for r_addr in ref_addrs:
            r_node = ref_nodes.get(r_addr)
            if not r_node:
                continue

            # Bu ref fonksiyonun eslesmis caller ve callee'lerini bul
            r_callees = [c["address"] for c in r_node.get("callees", [])]
            r_callers = [c["address"] for c in r_node.get("callers", [])]

            # Eslesmis komsularin target karsiliklari
            matched_callee_targets = set()
            for rc in r_callees:
                if rc in ref_to_target:
                    matched_callee_targets.add(ref_to_target[rc])
            matched_caller_targets = set()
            for rc in r_callers:
                if rc in ref_to_target:
                    matched_caller_targets.add(ref_to_target[rc])

            # Eslesmis komsu sayisi < 2 ise yeterli bilgi yok
            total_matched_neighbors = len(matched_callee_targets) + len(matched_caller_targets)
            if total_matched_neighbors < 2:
                continue

            # Target tarafinda, ayni eslesmis komsulari paylasan fonksiyonu bul
            best_score = 0.0
            best_target = ""

            for t_addr in target_addrs:
                t_node = target_nodes.get(t_addr)
                if not t_node:
                    continue

                t_callees = {c["address"] for c in t_node.get("callees", [])}
                t_callers = {c["address"] for c in t_node.get("callers", [])}

                # Eslesmis callee'lerin target tarafindaki karsiliklari
                # t_callees icinde olmali
                callee_overlap = len(matched_callee_targets & t_callees)
                caller_overlap = len(matched_caller_targets & t_callers)

                total_overlap = callee_overlap + caller_overlap
                if total_overlap == 0:
                    continue

                # Skor: overlap / toplam eslesmis komsu sayisi
                score = total_overlap / total_matched_neighbors
                if score > best_score:
                    best_score = score
                    best_target = t_addr

            if best_score >= 0.5 and best_target:
                candidates.append((best_score, r_addr, best_target))

        # Greedy eslestirme
        candidates.sort(key=lambda x: -x[0])
        for score, r_addr, t_addr in candidates:
            if t_addr in used_targets:
                continue
            if r_addr not in ref_func_by_addr or t_addr not in target_func_by_addr:
                continue

            r_func = ref_func_by_addr[r_addr]
            t_func = target_func_by_addr[t_addr]

            confidence = round(0.75 * score, 4)
            matches.append(DiffMatch(
                ref_name=r_func["name"],
                ref_address=r_addr,
                target_name=t_func["name"],
                target_address=t_addr,
                confidence=confidence,
                method="call_pattern",
            ))
            used_targets.add(t_addr)

        return matches

    # ------------------------------------------------------------------
    # Sonuc kullanimi
    # ------------------------------------------------------------------

    def transfer_names(
        self,
        diff_result: DiffResult,
        min_confidence: float = 0.7,
    ) -> dict[str, str]:
        """DiffResult'tan naming map cikar: target_name -> ref_name.

        Ayni target_name birden fazla eslesmisse en yuksek confidence'li olanini al.

        Args:
            diff_result: compare() sonucu.
            min_confidence: Minimum eslestirme guvenligi.

        Returns:
            dict: target_name -> ref_name mapping.
        """
        best: dict[str, tuple[float, str]] = {}  # target_name -> (confidence, ref_name)
        for m in diff_result.matches:
            if m.confidence < min_confidence:
                continue
            existing = best.get(m.target_name)
            if existing is None or m.confidence > existing[0]:
                best[m.target_name] = (m.confidence, m.ref_name)

        return {t_name: ref_name for t_name, (_, ref_name) in best.items()}

    def transfer_names_with_confidence(
        self,
        diff_result: DiffResult,
        min_confidence: float = 0.7,
    ) -> dict[str, tuple[str, float, str]]:
        """DiffResult'tan naming map cikar: target_name -> (ref_name, confidence, method).

        Name Merger'a per-match confidence aktarmak icin kullanilir.
        Ayni target_name birden fazla eslesmisse en yuksek confidence'li olanini al.

        Args:
            diff_result: compare() sonucu.
            min_confidence: Minimum eslestirme guvenligi.

        Returns:
            dict: target_name -> (ref_name, confidence, method) mapping.
        """
        best: dict[str, tuple[float, str, str]] = {}  # target -> (conf, ref_name, method)
        for m in diff_result.matches:
            if m.confidence < min_confidence:
                continue
            existing = best.get(m.target_name)
            if existing is None or m.confidence > existing[0]:
                best[m.target_name] = (m.confidence, m.ref_name, m.method)

        return {
            t_name: (ref_name, conf, method)
            for t_name, (conf, ref_name, method) in best.items()
        }

    def transfer_names_by_address(
        self,
        diff_result: DiffResult,
        min_confidence: float = 0.7,
    ) -> dict[str, str]:
        """DiffResult'tan address bazli naming map: target_address -> ref_name.

        Bu format c_namer gibi downstream tool'lar icin daha kullanisli.

        Args:
            diff_result: compare() sonucu.
            min_confidence: Minimum eslestirme guvenligi.

        Returns:
            dict: target_address -> ref_name mapping.
        """
        best: dict[str, tuple[float, str]] = {}
        for m in diff_result.matches:
            if m.confidence < min_confidence:
                continue
            existing = best.get(m.target_address)
            if existing is None or m.confidence > existing[0]:
                best[m.target_address] = (m.confidence, m.ref_name)

        return {t_addr: ref_name for t_addr, (_, ref_name) in best.items()}
