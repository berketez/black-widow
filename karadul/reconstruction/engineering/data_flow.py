"""Inter-procedural data flow tracker -- Karadul v1.1.5 Module 2.

Fonksiyonlar arasi veri akisini izler: hangi fonksiyon bir degeri uretir,
hangisi tuketir.  Sonuc olarak algoritma pipeline'larini ortaya cikarir:

    assemble_stiffness() produces K_global
      -> newton_solve(K_global, f) consumes K_global
        -> dgetrs_(K_factored, rhs) consumes factored K

    GPStartVPNTunnel() creates NEVPNManager
      -> calls startVPNTunnelWithOptions: passing config
        -> calls NEPacketTunnelProvider with encryption params

Yaklasim: Pragmatic pattern matching (regex-based) decompile edilmis C uzerinde.
Symbolic execution veya abstract interpretation DEGiL.  Yaygin %80 pattern'leri
yakalar, kusursuz olma iddiasi yok.

4 Pattern:
  1. Parameter Passthrough  -- caller arg'i callee arg'ina akar
  2. Return-to-Argument     -- fonksiyon return degeri baska fonksiyona arg olarak gecer
  3. Struct/Global Mediation -- struct field'a yaz, baska fonksiyondan oku
  4. Allocation Chain        -- malloc -> fill -> use -> free

v1.6.5: Batch analysis.
  - Cross-func struct field confidence scoring: writer-reader cift matrisinde
    call-graph iliskisini batch hesapla.
  - xrefs validation: confidence bonus'lari batch uygula.
  - Pipeline detection: sparse adjacency + longest-path DP.
  - Edge deduplication: batch dedup with max-confidence selection.

Kullanim:
    from karadul.reconstruction.engineering.data_flow import InterProceduralDataFlow

    tracker = InterProceduralDataFlow(config)
    result = tracker.analyze(
        decompiled_dir=Path("decompiled"),
        functions_json=Path("functions.json"),
        call_graph_json=Path("call_graph.json"),
        xrefs_json=Path("xrefs.json"),
        output_dir=Path("data_flow_out"),
    )
"""
from __future__ import annotations

import json
import logging
import re
import threading
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karadul.config import CPU_PERF_CORES, Config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Batch helper fonksiyonlari (pure-Python)
# ---------------------------------------------------------------------------


def _batch_struct_confidence(
    w_callers_mat: list[list[int]],
    r_callers_mat: list[list[int]],
    w_callees_mat: list[list[int]],
    r_callees_mat: list[list[int]],
    pair_w_idx: list[int],
    pair_r_idx: list[int],
) -> list[float]:
    """Writer-reader ciftleri icin struct-field confidence hesapla.

    Mantik: Ortak caller var mi (matmul > 0 -> 0.15 bonus),
    writer callee'leri arasinda reader var mi (0.20 bonus),
    reader callee'leri arasinda writer var mi (0.10 bonus).
    Base confidence: 0.45.
    """
    base = 0.45
    result: list[float] = []
    for wi, ri in zip(pair_w_idx, pair_r_idx):
        conf = base
        # Ortak caller kontrolu: w_callers_mat[wi] . r_callers_mat[ri]^T
        w_row = w_callers_mat[wi]
        r_row = r_callers_mat[ri]
        dot = sum(a * b for a, b in zip(w_row, r_row))
        if dot > 0:
            conf += 0.15
        # Writer -> reader cagiriyor mu?
        if w_callees_mat[wi][ri]:
            conf += 0.20
        # Reader -> writer cagiriyor mu?
        if r_callees_mat[ri][wi]:
            conf += 0.10
        result.append(min(conf, 1.0))
    return result


def _pipeline_longest_path(
    adj: dict[str, set[str]],
    relevant_nodes: set[str],
) -> tuple[dict[str, int], dict[str, str | None]]:
    """DAG uzerinde en uzun yol hesapla (topolojik siralama + DP).

    Returns:
        (dist, pred) -- her node icin en uzun mesafe ve predecessor.
    """
    # In-degree hesapla
    in_deg: dict[str, int] = {n: 0 for n in relevant_nodes}
    for u in relevant_nodes:
        for v in adj.get(u, set()):
            if v in relevant_nodes:
                in_deg[v] = in_deg.get(v, 0) + 1

    # Topolojik siralama (Kahn)
    queue = deque(n for n in relevant_nodes if in_deg.get(n, 0) == 0)
    topo_order: list[str] = []
    while queue:
        u = queue.popleft()
        topo_order.append(u)
        for v in adj.get(u, set()):
            if v not in relevant_nodes:
                continue
            in_deg[v] -= 1
            if in_deg[v] == 0:
                queue.append(v)

    # Cycle varsa kalan node'lari da ekle (deterministik siralama)
    if len(topo_order) < len(relevant_nodes):
        remaining = sorted(relevant_nodes - set(topo_order))
        topo_order.extend(remaining)

    # DP: en uzun yol
    dist: dict[str, int] = {n: 0 for n in relevant_nodes}
    pred: dict[str, str | None] = {n: None for n in relevant_nodes}

    for u in topo_order:
        for v in adj.get(u, set()):
            if v not in relevant_nodes:
                continue
            if dist[u] + 1 > dist[v]:
                dist[v] = dist[u] + 1
                pred[v] = u

    return dist, pred


def _batch_confidence_update(
    old_confidences: list[float],
    bonuses: list[float],
) -> list[float]:
    """Confidence degerlerini bonus ile guncelle, [0, 1] araliginda tut."""
    return [min(max(o + b, 0.0), 1.0) for o, b in zip(old_confidences, bonuses)]


def _batch_dedup_edges(
    edge_keys: list[tuple[str, str, str, str]],
    confidences: list[float],
) -> list[int]:
    """Ayni key'e sahip edge'lerden en yuksek confidence'li olanin index'ini sec."""
    best: dict[tuple[str, str, str, str], tuple[float, int]] = {}
    for i, (key, conf) in enumerate(zip(edge_keys, confidences)):
        if key not in best or conf > best[key][0]:
            best[key] = (conf, i)
    return [idx for _, idx in best.values()]


# ---------------------------------------------------------------------------
# Veri Yapilari
# ---------------------------------------------------------------------------


@dataclass
class PropagatedParamName:
    """Inter-procedural parametre isim yayilimi sonucu.

    Fonksiyon A, fonksiyon B'yi cagirir ve B'nin parametre isimleri biliniyorsa,
    A'nin o pozisyondaki degiskenine B'nin parametre ismi yayilir (backward).
    Veya A'nin parametresi biliniyorsa ve B'ye geciriyorsa, B'ye yayilir (forward).

    Attributes:
        function_name: Isim yayilan fonksiyon (ismin atandigi yer).
        original_name: Degiskenin orijinal ismi (param_1, local_48 vb.).
        propagated_name: Yayilan yeni isim (dest, src, n vb.).
        confidence: Guven skoru (0.0-1.0), hop basina 0.90 decay.
        direction: "backward" (callee -> caller) veya "forward" (caller -> callee).
        hop_count: Kac hop uzaktan yayildi (1 = dogrudan, 2+ = transitif).
        source_function: Ismin orijinal kaynagi olan fonksiyon.
        source_param_idx: Kaynak fonksiyondaki parametre pozisyonu.
        evidence: Kanit aciklamasi.
    """

    function_name: str
    original_name: str
    propagated_name: str
    confidence: float
    direction: str          # "backward" | "forward"
    hop_count: int
    source_function: str
    source_param_idx: int
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "original_name": self.original_name,
            "propagated_name": self.propagated_name,
            "confidence": round(self.confidence, 3),
            "direction": self.direction,
            "hop_count": self.hop_count,
            "source_function": self.source_function,
            "source_param_idx": self.source_param_idx,
            "evidence": self.evidence,
        }


@dataclass
class DataFlowEdge:
    """Fonksiyonlar arasi tek bir veri akisi kenar.

    Attributes:
        source_func: Ureticti fonksiyon (producer).
        target_func: Tuketici fonksiyon (consumer).
        data_name: Tanimlayici isim ("K_global", "encryption_key", "config").
        flow_type: Akis turu -- param_passthrough, return_to_arg,
                   struct_field, allocation_chain.
        source_param_idx: Kaynak parametresi veya -1 (return degeri).
        target_param_idx: Hedef parametresi.
        confidence: Guven skoru (0.0-1.0).
        evidence: Tespit kaniti (regex match, kod satiri vb.).
    """

    source_func: str
    target_func: str
    data_name: str
    flow_type: str
    source_param_idx: int
    target_param_idx: int
    confidence: float
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_func": self.source_func,
            "target_func": self.target_func,
            "data_name": self.data_name,
            "flow_type": self.flow_type,
            "source_param_idx": self.source_param_idx,
            "target_param_idx": self.target_param_idx,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
        }


@dataclass
class DataFlowGraph:
    """Tum veri akisi grafigi.

    Attributes:
        edges: DataFlowEdge listesi.
        nodes: Tum katilan fonksiyon isimleri.
        data_objects: data_name -> [func1, func2, ...] yasam dongusu.
    """

    edges: list[DataFlowEdge] = field(default_factory=list)
    nodes: set[str] = field(default_factory=set)
    data_objects: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_edges": len(self.edges),
            "total_nodes": len(self.nodes),
            "edges": [e.to_dict() for e in self.edges],
            "nodes": sorted(self.nodes),
            "data_objects": {k: v for k, v in sorted(self.data_objects.items())},
        }


@dataclass
class DataFlowResult:
    """Analiz sonucu.

    Attributes:
        success: Basarili mi.
        graph: Veri akisi grafigi.
        pipelines: Tespit edilen dogrusal zincirler [func1, func2, func3, ...].
        total_edges: Toplam kenar sayisi.
        total_data_objects: Toplam veri nesnesi sayisi.
        errors: Hata mesajlari.
    """

    success: bool
    graph: DataFlowGraph = field(default_factory=DataFlowGraph)
    pipelines: list[list[str]] = field(default_factory=list)
    total_edges: int = 0
    total_data_objects: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "total_edges": self.total_edges,
            "total_data_objects": self.total_data_objects,
            "pipeline_count": len(self.pipelines),
            "pipelines": self.pipelines,
            "graph": self.graph.to_dict(),
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Regex pattern'leri -- decompile edilmis C icin
# ---------------------------------------------------------------------------

# Fonksiyon tanimini yakalama (Ghidra decompile formati)
_FUNC_DEF_RE = re.compile(
    r"^(?:(?:void|int|uint|long|ulong|char|uchar|short|ushort|byte|bool|float|double|"
    r"size_t|ssize_t|undefined\d?|code\s*\*|undefined\s*\*|typedef\s+\w+\s+\w+|"
    r"\w+\s*\*+)\s+)"
    r"(\w+)\s*\(([^)]*)\)\s*\{",
    re.MULTILINE,
)

# Fonksiyon cagrisi yakalama -- callee(arg1, arg2, ...)
# Ghidra ciktisinda: func_name(expr, expr, ...)
_CALL_RE = re.compile(
    r"(\w+)\s*\(([^;]*?)\)(?:\s*;|\s*\))",
)

# Daha siki fonksiyon cagrisi -- atama ile birlikte
# var = func(args);
_ASSIGN_CALL_RE = re.compile(
    r"(\w+)\s*=\s*(\w+)\s*\(([^;]*?)\)\s*;",
)

# Obj-C mesaj gonderme -- _objc_msgSend(obj, "selector", arg1, arg2)
_OBJC_MSG_RE = re.compile(
    r"_objc_msgSend\w*\s*\(([^,]+),\s*\"([^\"]+)\"(?:,\s*([^)]*))?\)",
)

# Obj-C retain/autorelease donus -- sonraki satirdaki retainAutoreleasedReturnValue
_OBJC_RETAIN_RETURN_RE = re.compile(
    r"(\w+)\s*=\s*_objc_retainAutoreleasedReturnValue\s*\(\s*\)",
)

# malloc/calloc/realloc tespiti
_ALLOC_RE = re.compile(
    r"(\w+)\s*=\s*(?:_?(?:malloc|calloc|realloc|_Znwm|_Znam|operator_new))\s*\(([^)]*)\)\s*;",
)

# malloc/calloc/realloc tespiti -- cast'li Ghidra formati
# Ghidra ciktisi: var = (type *)malloc(size);
_ALLOC_CAST_RE = re.compile(
    r"(\w+)\s*=\s*\([^)]*\)\s*(?:_?(?:malloc|calloc|realloc|_Znwm|_Znam|operator_new))\s*\(([^)]*)\)\s*;",
)

# Pointer free/dealloc
_FREE_RE = re.compile(
    r"(?:_?(?:free|_ZdlPv|_ZdaPv|operator_delete))\s*\(([^)]*)\)\s*;",
)

# Struct/global field yazma -- context->field = expr; veya *(type *)(ptr + offset) = expr;
_STRUCT_WRITE_RE = re.compile(
    r"(?:"
    r"(\w+)->(\w+)\s*=\s*([^;]+)"  # ptr->field = val
    r"|"
    r"(\w+)\.(\w+)\s*=\s*([^;]+)"  # struct.field = val
    r"|"
    r"\*\s*\([^)]*\)\s*\((\w+)\s*\+\s*(?:0x)?([0-9a-fA-F]+)\)\s*=\s*([^;]+)"  # *(type*)(ptr + off) = val
    r")\s*;",
)

# Struct/global field okuma -- var = context->field; veya var = *(type *)(ptr + offset);
_STRUCT_READ_RE = re.compile(
    r"(\w+)\s*=\s*(?:"
    r"(\w+)->(\w+)"  # var = ptr->field
    r"|"
    r"(\w+)\.(\w+)"  # var = struct.field
    r"|"
    r"\*\s*\([^)]*\)\s*\((\w+)\s*\+\s*(?:0x)?([0-9a-fA-F]+)\)"  # var = *(type*)(ptr + off)
    r")\s*;",
)

# Ghidra param isimleri
_PARAM_NAME_RE = re.compile(r"param_(\d+)")

# Return statement
_RETURN_RE = re.compile(r"return\s+(\w+)\s*;")

# Ghidra auto-generated fonksiyon isimleri (FUN_XXXX, _FUN_XXXX)
_AUTO_FUNC_RE = re.compile(r"^_?FUN_([0-9a-fA-F]+)$")

# Yaygin ObjC tipler -- VPN/security baglami icin
_OBJC_TYPE_INDICATORS = frozenset({
    "NEVPNManager", "NEVPNConnection", "NEVPNProtocol",
    "NETransparentProxyManager", "NEAppProxyProviderManager",
    "NEFilterManager", "NEDNSProxyManager",
    "NSDictionary", "NSString", "NSError", "NSData",
    "SecKeyRef", "SecCertificateRef", "SecIdentityRef",
    "CCCryptorRef",
})

# Bilinen allocation fonksiyonlari
_ALLOC_FUNCS = frozenset({
    "malloc", "calloc", "realloc", "strdup", "strndup",
    "_malloc", "_calloc", "_realloc",
    "_Znwm", "_Znam",  # C++ new/new[]
    "operator_new",
})

# Bilinen free fonksiyonlari
_FREE_FUNCS = frozenset({
    "free", "_free", "_ZdlPv", "_ZdaPv", "operator_delete",
})

# Runtime/boilerplate -- akis analizinde skip edilecek fonksiyonlar
_SKIP_FUNCS = frozenset({
    "_objc_retain", "_objc_release", "_objc_autorelease",
    "_objc_retainAutoreleasedReturnValue", "_objc_autoreleaseReturnValue",
    "_objc_alloc", "_objc_alloc_init", "_objc_opt_class",
    "_objc_opt_isKindOfClass", "_objc_msgSendSuper2",
    "__Block_object_dispose", "__Block_object_copy",
    "___Block_byref_object_copy_", "___Block_byref_object_dispose_",
    "_dispatch_group_create", "_dispatch_group_enter",
    "_dispatch_group_wait", "_dispatch_time",
    "_dispatch_async", "_dispatch_queue_create",
    "_NSLog", "___pan_cfprint", "printf", "fprintf", "puts",
    "memset", "memcpy", "memmove", "bzero", "strlen", "strcmp",
    "strcpy", "strncpy", "strcat", "strncat",
})


# ---------------------------------------------------------------------------
# Yardimci: Decompile edilmis C'den fonksiyon body cikarma
# ---------------------------------------------------------------------------


def _extract_body(content: str, brace_pos: int, max_len: int = 8000) -> str:
    """Suslu parantez eslestirme ile body cikar.

    max_len: En fazla kac karakter okunacak.  Data flow icin 8KB yeterli
    (analyzer'daki 5KB'den biraz fazla -- parametre gecirgenligi icin
    fonksiyon giris kismi onemli).
    """
    if brace_pos >= len(content) or content[brace_pos] != "{":
        return ""
    depth = 0
    limit = min(brace_pos + max_len, len(content))
    for i in range(brace_pos, limit):
        ch = content[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[brace_pos: i + 1]
    return content[brace_pos:limit]


def _parse_args_string(args_str: str) -> list[str]:
    """Fonksiyon cagrisi arguman string'ini parcala.

    Nested parantez ve virgulleri dogru isler:
        "K, f, n"          -> ["K", "f", "n"]
        "func(a,b), c"     -> ["func(a,b)", "c"]
        ""                  -> []
    """
    if not args_str or not args_str.strip():
        return []

    args: list[str] = []
    depth = 0
    current: list[str] = []

    for ch in args_str:
        if ch == "(" or ch == "[":
            depth += 1
            current.append(ch)
        elif ch == ")" or ch == "]":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            arg = "".join(current).strip()
            if arg:
                args.append(arg)
            current = []
        else:
            current.append(ch)

    last = "".join(current).strip()
    if last:
        args.append(last)
    return args


def _extract_base_var(expr: str) -> str:
    """Ifadeden temel degisken adini cikar.

    "*(double *)param_3"     -> "param_3"
    "(long)local_a8"         -> "local_a8"
    "&local_d8"              -> "local_d8"
    "uVar5"                  -> "uVar5"
    "param_1 + 0x10"         -> "param_1"
    """
    # Cast ve dereference kaldir
    cleaned = re.sub(r"\([^)]*\)", "", expr)
    cleaned = cleaned.replace("*", "").replace("&", "").strip()
    # Aritmetik ifadeden ilk token'i al
    m = re.match(r"(\w+)", cleaned)
    return m.group(1) if m else expr.strip()


# ---------------------------------------------------------------------------
# Veri nesnesi isimlendirme rehberi
# ---------------------------------------------------------------------------

# Parametre tip + pozisyon -> olasi isim (FEA/CFD/VPN konteksti)
_TYPE_NAME_HINTS: dict[str, dict[int, str]] = {
    # FEA / Linear Algebra
    "double *": {
        0: "matrix",
        1: "rhs_vector",
        2: "solution_vector",
    },
    "int": {
        0: "dimension",
        1: "n_rows",
        2: "n_cols",
    },
    # VPN / Networking
    "NEVPNManager *": {0: "vpn_manager"},
    "NSDictionary *": {0: "options_dict", 1: "vpn_options"},
    "NEFilterManager *": {0: "filter_manager"},
    "NSError *": {0: "error"},
    "NSString *": {0: "config_string"},
}

# Fonksiyon adi alt-stringleri -> uretilen verinin adi
_FUNC_OUTPUT_NAMES: dict[str, str] = {
    "malloc": "allocated_buffer",
    "calloc": "allocated_buffer",
    "assemble": "assembled_matrix",
    "stiffness": "K_global",
    "compute": "computed_result",
    "create": "new_object",
    "alloc": "allocated_object",
    "init": "initialized_object",
    "load": "loaded_data",
    "read": "read_data",
    "encrypt": "ciphertext",
    "decrypt": "plaintext",
    "hash": "hash_digest",
    "sign": "signature",
    "connect": "connection",
    "solve": "solution",
    "factor": "factored_matrix",
    "decompos": "decomposition",
    "invert": "inverse_matrix",
    "transpose": "transposed_matrix",
    "transform": "transformed_data",
    "filter": "filtered_data",
    "config": "configuration",
    "start": "started_session",
    "save": "saved_state",
    "download": "downloaded_data",
}


def _guess_data_name(
    func_name: str,
    param_idx: int,
    param_type: str = "",
    flow_type: str = "",
) -> str:
    """Veri nesnesine anlamli bir isim ver.

    Oncelik sirasi:
      1. Fonksiyon adi + parametre tipi
      2. Fonksiyon alt-string eslesmesi
      3. Parametre tipi + pozisyon
      4. Genel fallback
    """
    fn_lower = func_name.lower()

    # 1. Bilinen fonksiyon alt-string'leri icin cikti isimleri
    if param_idx == -1:  # return degeri
        for substr, name in _FUNC_OUTPUT_NAMES.items():
            if substr in fn_lower:
                return name
        return f"result_of_{func_name}"

    # 2. Tip bazli isimlendirme
    if param_type:
        type_clean = param_type.strip()
        hints = _TYPE_NAME_HINTS.get(type_clean)
        if hints:
            if param_idx in hints:
                return hints[param_idx]
            # En yakin pozisyon
            if hints:
                closest = min(hints.keys(), key=lambda k: abs(k - param_idx))
                return hints[closest]

    # 3. Genel fallback
    if param_idx == 0:
        return f"input_to_{func_name}"
    return f"arg{param_idx}_of_{func_name}"


# ---------------------------------------------------------------------------
# Fonksiyon ismi normalizasyonu
# ---------------------------------------------------------------------------


def _normalize_func_name(
    name: str, func_info: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Ghidra auto-generated isimlerini normalize et.

    FUN_XXXX formatindaki isimler adres bazli eslesme icin hex adrese
    donusturulur.  func_info varsa ve o adreste gercek bir isim
    biliniyorsa, o isim kullanilir.

    Ornekler:
        FUN_00401234  -> "sub_00401234"  (func_info'da yoksa)
        FUN_00401234  -> "compute_stiffness"  (func_info'da varsa)
        my_func       -> "my_func"  (degismez)
    """
    m = _AUTO_FUNC_RE.match(name)
    if not m:
        return name

    addr_hex = m.group(1).lower()

    # func_info'dan gercek isim aransin
    if func_info:
        # Adres eslesmeleri: hex addr -> func_info entry
        for finfo in func_info.values():
            entry_addr = str(finfo.get("address", "")).lower().replace("0x", "")
            if entry_addr == addr_hex:
                real_name = finfo.get("name", "")
                # Eger kendisi de FUN_xxx ise donguye girme
                if real_name and not _AUTO_FUNC_RE.match(real_name):
                    return real_name

    # Gercek isim bulunamadi -- standart prefix ile dondur
    return f"sub_{addr_hex}"


# ---------------------------------------------------------------------------
# Batch helper functions
# ---------------------------------------------------------------------------


def _batch_confidence_update(  # type: ignore[no-redef]  # v1.4.3 yeni imza eski 149'u override eder
    confidences: list[float],
    bonuses: list[float],
    max_val: float = 1.0,
) -> list[float]:
    """Confidence degerlerine bonus ekle.

    Args:
        confidences: Mevcut confidence degerleri.
        bonuses: Her edge icin bonus miktari (0.0 = degisiklik yok).
        max_val: Confidence ust siniri (1.0).

    Returns:
        Guncelenmis confidence listesi.
    """
    if not confidences:
        return []
    return [min(c + b, max_val) for c, b in zip(confidences, bonuses)]


def _batch_struct_confidence(  # type: ignore[no-redef]  # v1.4.3 yeni imza eski 65'i override eder
    writer_callers_matrix: list[list[int]],
    reader_callers_matrix: list[list[int]],
    writer_callees_matrix: list[list[int]],
    reader_callees_matrix: list[list[int]],
    writer_idx_per_pair: list[int],
    reader_idx_per_pair: list[int],
    base_confidence: float = 0.45,
) -> list[float]:
    """Cross-func struct field confidence'larini hesapla.

    Her (writer, reader) cifti icin:
      - Ortak caller varsa: 0.60
      - Writer, reader'i cagiriyorsa: 0.70
      - Reader, writer'i cagiriyorsa: 0.65
      - Hicbiri: base_confidence (0.45)

    Args:
        writer_callers_matrix: (num_writers, max_callers) -- 0/1 sparse adjacency.
        reader_callers_matrix: (num_readers, max_callers) -- 0/1 sparse adjacency.
        writer_callees_matrix: (num_writers, num_readers) -- writer[i] calls reader[j]?
        reader_callees_matrix: (num_readers, num_writers) -- reader[j] calls writer[i]?
        writer_idx_per_pair: Flat list -- her cift icin writer index.
        reader_idx_per_pair: Flat list -- her cift icin reader index.
        base_confidence: Varsayilan confidence (hicbir iliski yoksa).

    Returns:
        Her cift icin confidence degeri.
    """
    n_pairs = len(writer_idx_per_pair)
    if n_pairs == 0:
        return []

    result: list[float] = []
    for wi, ri in zip(writer_idx_per_pair, reader_idx_per_pair):
        confidence = base_confidence
        # Ortak caller
        w_cal = writer_callers_matrix[wi]
        r_cal = reader_callers_matrix[ri]
        if any(a and b for a, b in zip(w_cal, r_cal)):
            confidence = 0.60
        # Reader calls writer
        if reader_callees_matrix[ri][wi] > 0:
            confidence = 0.65
        # Writer calls reader (en yuksek oncelik)
        if writer_callees_matrix[wi][ri] > 0:
            confidence = 0.70
        result.append(confidence)
    return result


def _dedup_edges(
    edge_keys: list[tuple[str, str, str, str]],
    confidences: list[float],
) -> list[int]:
    """Ayni key'e sahip edge'lerden en yuksek confidence'li olanin index'ini sec.

    Args:
        edge_keys: (source, target, flow_type, data_name) tuples.
        confidences: Her edge'in confidence degeri.

    Returns:
        Secilen edge index'leri (orijinal listedeki pozisyonlar).
    """
    if not edge_keys:
        return []
    best: dict[tuple[str, str, str, str], tuple[int, float]] = {}
    for i, (k, c) in enumerate(zip(edge_keys, confidences)):
        if k not in best or c > best[k][1]:
            best[k] = (i, c)
    return sorted(idx for idx, _ in best.values())


def _pipeline_longest_path(  # type: ignore[no-redef]  # v1.4.3 yeni imza eski 100'u override eder
    adj: dict[str, set[str]],
    relevant_nodes: set[str],
) -> tuple[dict[str, int], dict[str, str | None]]:
    """Topolojik siralama + DP ile en uzun yol.

    Args:
        adj: node -> set(neighbors) adjacency list.
        relevant_nodes: Tum relevant node'lar.

    Returns:
        (dist, pred) -- dist[node] = en uzun mesafe, pred[node] = onceki node.
    """
    nodes = sorted(relevant_nodes)
    relevant_nodes = set(nodes)
    in_degree: dict[str, int] = defaultdict(int)
    for node in relevant_nodes:
        in_degree.setdefault(node, 0)
    for src, targets in adj.items():
        for t in targets:
            if t in relevant_nodes:
                in_degree[t] = in_degree.get(t, 0) + 1

    # Kahn's algorithm
    queue = deque([n for n in relevant_nodes if in_degree.get(n, 0) == 0])
    topo_order: list[str] = []
    while queue:
        node = queue.popleft()
        topo_order.append(node)
        for neighbor in adj.get(node, set()):
            if neighbor in relevant_nodes:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

    remaining = relevant_nodes - set(topo_order)
    topo_order.extend(sorted(remaining))

    dist: dict[str, int] = {n: 0 for n in topo_order}
    pred: dict[str, str | None] = {n: None for n in topo_order}
    for node in topo_order:
        for neighbor in adj.get(node, set()):
            if neighbor in relevant_nodes and dist.get(neighbor, 0) < dist[node] + 1:
                dist[neighbor] = dist[node] + 1
                pred[neighbor] = node

    return dist, pred


# ---------------------------------------------------------------------------
# Ana sinif
# ---------------------------------------------------------------------------


class InterProceduralDataFlow:
    """Fonksiyonlar arasi veri akisi izleyici.

    Decompile edilmis C kodunu regex ile tarar ve 4 temel pattern'i yakalar:
      1. Parameter Passthrough  -- caller arg -> callee arg
      2. Return-to-Argument     -- func() return -> baska func()'a arg
      3. Struct/Global Mediation -- field'a yaz / baska yerden oku
      4. Allocation Chain        -- alloc -> use -> ... -> free

    Thread-safe, paralel dosya analizi yapar.
    """

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or Config()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        decompiled_dir: Path,
        functions_json: Path,
        call_graph_json: Path,
        xrefs_json: Path | None = None,
        output_dir: Path | None = None,
    ) -> DataFlowResult:
        """Inter-procedural data flow grafigi olustur.

        Args:
            decompiled_dir: Ghidra decompile ciktisi (.c dosyalari).
            functions_json: Fonksiyon metadata (adres, parametreler, return tipi).
            call_graph_json: Call graph (caller/callee iliskileri).
            xrefs_json: Cross reference'lar (opsiyonel, string xref'leri icin).
            output_dir: Sonuclarin yazilacagi dizin (opsiyonel).

        Returns:
            DataFlowResult: Basari/basarisizlik, graph, pipeline'lar.
        """
        errors: list[str] = []

        # Metadata yukle
        func_meta = self._load_json(functions_json, errors)
        call_graph = self._load_json(call_graph_json, errors)
        xrefs = self._load_json(xrefs_json, errors) if xrefs_json else {}

        # Call graph normalize et -- farkli JSON yapilari icin
        cg_nodes = self._normalize_call_graph(call_graph)

        # Fonksiyon metadata'sini normalize et
        func_info = self._normalize_functions(func_meta)

        # C dosyalarini topla
        c_files = self._collect_c_files(decompiled_dir, errors)
        if not c_files:
            return DataFlowResult(
                success=False,
                errors=errors or ["No C files found"],
            )

        logger.info(
            "InterProceduralDataFlow: %d files, %d call graph nodes",
            len(c_files), len(cg_nodes),
        )

        # Faz 1: Her dosyadan lokal veri akisi bilgisi cikar (paralel)
        file_edges: list[DataFlowEdge] = []
        all_func_code: dict[str, str] = {}  # func_name -> code body
        edges_lock = threading.Lock()
        code_lock = threading.Lock()

        with ThreadPoolExecutor(max_workers=CPU_PERF_CORES) as pool:
            futures = {
                pool.submit(
                    self._analyze_file, f, func_info, cg_nodes,
                ): f
                for f in c_files
            }
            processed = 0
            for future in as_completed(futures):
                processed += 1
                try:
                    edges, func_codes = future.result()
                    with edges_lock:
                        file_edges.extend(edges)
                    with code_lock:
                        all_func_code.update(func_codes)
                except Exception as exc:
                    cf = futures[future]
                    errors.append(f"Data flow analysis failed for {cf.name}: {exc}")
                if processed % 500 == 0:
                    logger.info(
                        "  Data flow scan: %d/%d (%.0f%%)",
                        processed, len(c_files),
                        100.0 * processed / len(c_files),
                    )

        # Faz 2: Cross-function struct field akisi
        struct_edges = self._extract_cross_func_struct_flows(
            all_func_code, cg_nodes, func_info,
        )
        file_edges.extend(struct_edges)

        # Faz 3: Allocation chain tespiti (cross-function)
        alloc_edges = self._extract_cross_func_alloc_chains(
            all_func_code, cg_nodes, func_info,
        )
        file_edges.extend(alloc_edges)

        # Faz 4: Fonksiyon isimlerini normalize et (FUN_xxx -> gercek isim)
        file_edges = self._normalize_edge_names(file_edges, func_info)

        # Faz 5: xrefs ile dogrulama ve confidence bonus
        if xrefs:
            file_edges = self._apply_xrefs_validation(file_edges, xrefs, func_info)

        # Tekillesttirme
        deduped = self._deduplicate_edges(file_edges)

        # Graph olustur
        graph = DataFlowGraph()
        graph.edges = deduped
        for e in deduped:
            graph.nodes.add(e.source_func)
            graph.nodes.add(e.target_func)

        # Data object lifecycle
        graph.data_objects = self._build_data_objects(deduped)

        # Pipeline tespit
        pipelines = self._detect_pipelines(graph)

        result = DataFlowResult(
            success=True,
            graph=graph,
            pipelines=pipelines,
            total_edges=len(deduped),
            total_data_objects=len(graph.data_objects),
            errors=errors,
        )

        logger.info(
            "InterProceduralDataFlow: %d edges, %d data objects, %d pipelines",
            result.total_edges, result.total_data_objects, len(pipelines),
        )

        # Ciktilari yaz
        if output_dir:
            self._write_output(result, output_dir)

        return result

    # ------------------------------------------------------------------
    # Inter-Procedural Parameter Name Propagation (Technique 2)
    # ------------------------------------------------------------------

    # Confidence decay per hop: base * decay^(hop-1)
    _PROP_BASE_CONFIDENCE = 0.85
    _PROP_DECAY = 0.90
    _PROP_MAX_ROUNDS = 5

    def propagate_param_names(
        self,
        decompiled_dir: Path,
        functions_json: Path,
        call_graph_json: Path,
        known_names: dict[str, dict[str, str]] | None = None,
        signature_matches: list[Any] | None = None,
    ) -> list[PropagatedParamName]:
        """Inter-procedural parametre isim yayilimi.

        Fonksiyon A, B'yi cagirir ve B'nin parametreleri biliniyorsa,
        A'nin o pozisyondaki degiskenlerine B'nin parametre isimleri yayilir.
        Ayni mantik tersi yonde de calisir.

        Iteratif: Her turda bulunan yeni isimler sonraki turun seed'i olur.
        Max 5 tur veya convergence'a kadar.

        Args:
            decompiled_dir: Ghidra decompile C dosyalari dizini.
            functions_json: Fonksiyon metadata JSON.
            call_graph_json: Call graph JSON.
            known_names: Onceden bilinen param isimleri.
                {func_name: {param_name: semantic_name}} formati.
                Ornegin: {"memcpy": {"param_1": "dest", "param_2": "src", "param_3": "n"}}
                None ise APIParamDB'den yuklenmeye calisilir.
            signature_matches: Opsiyonel signature DB match listesi.
                Her eleman .original_name, .matched_name, .confidence
                attribute'larina (veya ayni key'lere sahip dict) sahip olmali.
                Confidence >= 0.70 olanlar: matched_name ile APIParamDB'de
                eslestirme yapilir, bulunursa pos_db'ye seed olarak eklenir.

        Returns:
            PropagatedParamName listesi -- name_merger'a beslenecek.
        """
        errors: list[str] = []

        # Metadata yukle
        func_meta = self._load_json(functions_json, errors)
        call_graph = self._load_json(call_graph_json, errors)
        cg_nodes = self._normalize_call_graph(call_graph)
        func_info = self._normalize_functions(func_meta)

        # C dosyalarini topla ve parse et
        c_files = self._collect_c_files(decompiled_dir, errors)
        if not c_files:
            logger.warning("propagate_param_names: no C files found")
            return []

        # Tum fonksiyonlarin kodunu topla
        all_func_code: dict[str, str] = {}
        for f in c_files:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            functions = self._extract_functions(content, func_info, f.stem)
            for func_name, func_body in functions:
                all_func_code[func_name] = func_body

        # Call-argument graph: her (caller, callee, arg_idx) icin
        # caller'in hangi degiskeni gecirdigi
        # Struct: {caller: [(callee, [(arg_idx, caller_var_name)])]}
        call_arg_map = self._build_call_argument_graph(
            all_func_code, func_info, cg_nodes,
        )

        # Bilinen parametre isimlerini baslat -- pozisyon bazli
        # {func_name: {param_position: semantic_name}}
        pos_db: dict[str, dict[int, str]] = {}

        # Fonksiyonlarin param listelerini cache'le
        param_cache: dict[str, list[dict[str, Any]]] = {}
        for func_name, code in all_func_code.items():
            params = self._get_func_params(func_name, code, func_info)
            if params:
                param_cache[func_name] = params

        # 1. Kullanici verdiyse (param_name -> semantic_name, pozisyona cevir)
        if known_names:
            for fn, mapping in known_names.items():
                params = param_cache.get(fn, [])
                for orig_name, sem_name in mapping.items():
                    # Isme gore pozisyon bul
                    found = False
                    for p in params:
                        if p["name"] == orig_name:
                            pos_db.setdefault(fn, {})[p["ordinal"]] = sem_name
                            found = True
                            break
                    if not found:
                        # param_N formatinda ise pozisyonu cikar
                        pm = re.match(r"param_(\d+)", orig_name)
                        if pm:
                            # Ghidra param_1 = ordinal 0 (1-indexed)
                            idx = int(pm.group(1)) - 1
                            pos_db.setdefault(fn, {})[idx] = sem_name

        # 2. APIParamDB'den bilinen fonksiyonlari ekle
        _api_db = None
        try:
            from karadul.reconstruction.api_param_db import APIParamDB
            _api_db = APIParamDB()
            for func_name in all_func_code:
                api_names = _api_db.get_param_names(func_name)
                if api_names:
                    for i, api_name in enumerate(api_names):
                        pos_db.setdefault(func_name, {})[i] = api_name
        except ImportError:
            logger.debug("APIParamDB import edilemedi, sadece known_names kullanilacak")

        # 2.5. Signature DB match'lerinden ek seed ekle
        _sig_seed_count = 0
        if signature_matches and _api_db is not None:
            for m in signature_matches:
                # SignatureMatch objesi veya dict olabilir
                if isinstance(m, dict):
                    orig = m.get("original_name", m.get("original", ""))
                    matched = m.get("matched_name", m.get("matched", ""))
                    conf = m.get("confidence", 0.0)
                else:
                    orig = getattr(m, "original_name", "")
                    matched = getattr(m, "matched_name", "")
                    conf = getattr(m, "confidence", 0.0)

                if not orig or not matched or conf < 0.70:
                    continue
                # Zaten pos_db'de varsa atla
                if orig in pos_db:
                    continue

                # matched_name ile APIParamDB'de eslestirme yap
                api_names = _api_db.get_param_names(matched)
                if not api_names:
                    # Underscore prefix ile dene
                    api_names = _api_db.get_param_names(f"_{matched}")
                if not api_names:
                    # matched_name tam eslesmedi, strip edip dene
                    _clean = matched.lstrip("_").rstrip("_")
                    api_names = _api_db.get_param_names(_clean)
                if api_names:
                    for i, api_name in enumerate(api_names):
                        pos_db.setdefault(orig, {})[i] = api_name
                    _sig_seed_count += 1

            if _sig_seed_count:
                logger.info(
                    "propagate_param_names: %d ek seed signature_matches'ten "
                    "(APIParamDB eslesmesi ile) eklendi",
                    _sig_seed_count,
                )

        # 3. func_info / koddan mevcut anlamli isimleri ekle
        for func_name, params in param_cache.items():
            for p in params:
                pname = p["name"]
                ordinal = p["ordinal"]
                # Zaten anlamli bir ismi varsa (auto-gen degil)
                if not re.match(r"^(?:param_\d+|local_[0-9a-fA-F]+|[a-z]Var\d+|in_\w+)$", pname):
                    pos_db.setdefault(func_name, {})[ordinal] = pname

        if not pos_db:
            logger.info("propagate_param_names: no known names to propagate")
            return []

        logger.info(
            "propagate_param_names: starting with %d functions having known names",
            len(pos_db),
        )

        # Iteratif yayilim
        all_propagated: list[PropagatedParamName] = []
        # Zaten isimlendirilmis: (func, orig_param_name) -> True
        already_named: set[tuple[str, str]] = set()
        for fn, pos_map in pos_db.items():
            params = param_cache.get(fn, [])
            for pos in pos_map:
                for p in params:
                    if p["ordinal"] == pos:
                        already_named.add((fn, p["name"]))
                        break

        for round_num in range(1, self._PROP_MAX_ROUNDS + 1):
            new_in_round: list[PropagatedParamName] = []

            # Backward propagation: callee'nin bilinen param isimlerini caller'a yay
            backward = self._propagate_backward(
                call_arg_map, pos_db, param_cache, func_info, all_func_code,
                already_named, round_num,
            )
            new_in_round.extend(backward)

            # Forward propagation: caller'in bilinen param isimlerini callee'ye yay
            forward = self._propagate_forward(
                call_arg_map, pos_db, param_cache, func_info, all_func_code,
                already_named, round_num,
            )
            new_in_round.extend(forward)

            if not new_in_round:
                logger.info(
                    "propagate_param_names: converged at round %d", round_num,
                )
                break

            # Yeni isimleri pos_db'ye ekle (sonraki tur icin seed)
            for prop in new_in_round:
                # Propagated name'in pozisyonunu bul
                params = param_cache.get(prop.function_name, [])
                for p in params:
                    if p["name"] == prop.original_name:
                        pos_db.setdefault(prop.function_name, {})[p["ordinal"]] = prop.propagated_name
                        break
                already_named.add((prop.function_name, prop.original_name))

            all_propagated.extend(new_in_round)
            logger.info(
                "propagate_param_names: round %d -> %d new names (%d total)",
                round_num, len(new_in_round), len(all_propagated),
            )

        logger.info(
            "propagate_param_names: %d total propagated names", len(all_propagated),
        )
        return all_propagated

    def _build_call_argument_graph(
        self,
        all_func_code: dict[str, str],
        func_info: dict[str, dict[str, Any]],
        cg_nodes: dict[str, dict[str, Any]],
    ) -> dict[str, list[tuple[str, list[tuple[int, str]]]]]:
        """Call-argument graph olustur.

        Returns:
            {caller: [(callee, [(arg_idx, caller_var_name), ...]), ...]}

        Her caller icin, cagirdigi callee'ler ve her cagrida hangi
        arguman pozisyonuna caller'in hangi degiskenini gecirdigi.

        NOT: _SKIP_FUNCS burada atlanMAZ -- data_flow edge analizi
        icin skip olan fonksiyonlar (memcpy, strlen vb.) isim propagasyonu
        icin ONEMLI cunku bilinen param isimleri var.
        Sadece ObjC runtime ve loglama fonksiyonlari atlanir.
        """
        # Isim propagasyonunda ATLANMAMASI gereken fonksiyonlar --
        # bunlar bilinen API'ler, param isimleri propagasyon kaynagi.
        _PROP_SKIP = frozenset({
            "_objc_retain", "_objc_release", "_objc_autorelease",
            "_objc_retainAutoreleasedReturnValue", "_objc_autoreleaseReturnValue",
            "_objc_alloc", "_objc_alloc_init", "_objc_opt_class",
            "_objc_opt_isKindOfClass", "_objc_msgSendSuper2",
            "__Block_object_dispose", "__Block_object_copy",
            "___Block_byref_object_copy_", "___Block_byref_object_dispose_",
            "_dispatch_group_create", "_dispatch_group_enter",
            "_dispatch_group_wait", "_dispatch_time",
            "_dispatch_async", "_dispatch_queue_create",
            "_NSLog", "___pan_cfprint", "printf", "fprintf", "puts",
        })

        result: dict[str, list[tuple[str, list[tuple[int, str]]]]] = {}

        for caller_name, caller_code in all_func_code.items():
            caller_entries: list[tuple[str, list[tuple[int, str]]]] = []

            for m in _CALL_RE.finditer(caller_code):
                callee_name = m.group(1)

                # Skip: ObjC runtime/loglama, recursive, control-flow keywords
                if callee_name in _PROP_SKIP:
                    continue
                if callee_name == caller_name:
                    continue
                if callee_name in ("if", "while", "for", "switch", "return", "sizeof"):
                    continue

                args_str = m.group(2)
                call_args = _parse_args_string(args_str)
                if not call_args:
                    continue

                arg_mappings: list[tuple[int, str]] = []
                for arg_idx, arg_expr in enumerate(call_args):
                    base_var = _extract_base_var(arg_expr)
                    # Sadece degisken isimlerini al (sabitler, literaller degil)
                    if base_var and re.match(r"^[a-zA-Z_]\w*$", base_var):
                        arg_mappings.append((arg_idx, base_var))

                if arg_mappings:
                    caller_entries.append((callee_name, arg_mappings))

            if caller_entries:
                result[caller_name] = caller_entries

        return result

    def _propagate_backward(
        self,
        call_arg_map: dict[str, list[tuple[str, list[tuple[int, str]]]]],
        pos_db: dict[str, dict[int, str]],
        param_cache: dict[str, list[dict[str, Any]]],
        func_info: dict[str, dict[str, Any]],
        all_func_code: dict[str, str],
        already_named: set[tuple[str, str]],
        round_num: int,
    ) -> list[PropagatedParamName]:
        """Backward propagation: callee'nin bilinen parametre isimlerini
        caller'in degiskenlerine yay.

        Ornek:
            memcpy(param_1, param_2, param_3) -> callee memcpy biliniyor:
            param_1 -> dest, param_2 -> src, param_3 -> n

        pos_db pozisyon bazli: {func: {idx: semantic_name}}.
        """
        results: list[PropagatedParamName] = []
        _auto_re = re.compile(r"^(?:param_\d+|local_[0-9a-fA-F]+|[a-z]Var\d+|in_\w+)$")

        for caller_name, call_entries in call_arg_map.items():
            for callee_name, arg_mappings in call_entries:
                # Callee'nin pozisyon bazli bilinen isimleri
                callee_pos_known = pos_db.get(callee_name, {})
                if not callee_pos_known:
                    continue

                for arg_idx, caller_var in arg_mappings:
                    # Bu caller degiskeni zaten isimlendirilmis mi?
                    if (caller_name, caller_var) in already_named:
                        continue

                    # Callee'nin bu pozisyondaki isim biliniyor mu?
                    semantic_name = callee_pos_known.get(arg_idx)
                    if not semantic_name:
                        continue

                    # Caller'in degiskeni otomatik-gen isim mi? Sadece bunlari degistir
                    if not _auto_re.match(caller_var):
                        continue

                    confidence = self._PROP_BASE_CONFIDENCE * (self._PROP_DECAY ** (round_num - 1))

                    results.append(PropagatedParamName(
                        function_name=caller_name,
                        original_name=caller_var,
                        propagated_name=semantic_name,
                        confidence=round(confidence, 3),
                        direction="backward",
                        hop_count=round_num,
                        source_function=callee_name,
                        source_param_idx=arg_idx,
                        evidence=(
                            f"{caller_var} passed as arg{arg_idx} to "
                            f"{callee_name}(pos{arg_idx}={semantic_name}) "
                            f"[round {round_num}]"
                        ),
                    ))

        return results

    def _propagate_forward(
        self,
        call_arg_map: dict[str, list[tuple[str, list[tuple[int, str]]]]],
        pos_db: dict[str, dict[int, str]],
        param_cache: dict[str, list[dict[str, Any]]],
        func_info: dict[str, dict[str, Any]],
        all_func_code: dict[str, str],
        already_named: set[tuple[str, str]],
        round_num: int,
    ) -> list[PropagatedParamName]:
        """Forward propagation: caller'in bilinen degisken isimlerini
        callee'nin parametrelerine yay.

        Ornek:
            void known_func(double *K_global, double *f_load) {
                FUN_xxx(K_global, f_load, n);
            }
            -> FUN_xxx'in param_1 = K_global, param_2 = f_load
        """
        results: list[PropagatedParamName] = []
        _auto_re = re.compile(r"^(?:param_\d+|local_[0-9a-fA-F]+|[a-z]Var\d+|in_\w+)$")

        for caller_name, call_entries in call_arg_map.items():
            # Caller'in pozisyon bazli bilinen isimleri
            caller_pos_known = pos_db.get(caller_name, {})
            if not caller_pos_known:
                continue

            # caller'in param listesini al
            caller_params = param_cache.get(caller_name, [])
            if not caller_params:
                continue

            # param_name -> pozisyon -> semantic_name mapping
            caller_var_to_sem: dict[str, str] = {}
            for p in caller_params:
                ordinal = p["ordinal"]
                if ordinal in caller_pos_known:
                    caller_var_to_sem[p["name"]] = caller_pos_known[ordinal]
                elif not _auto_re.match(p["name"]):
                    # Param ismi zaten anlamli ise onu da kullan
                    caller_var_to_sem[p["name"]] = p["name"]

            if not caller_var_to_sem:
                continue

            for callee_name, arg_mappings in call_entries:
                callee_params = param_cache.get(callee_name, [])
                if not callee_params:
                    continue

                for arg_idx, caller_var in arg_mappings:
                    # Caller'in bu degiskeni biliniyor mu?
                    if caller_var not in caller_var_to_sem:
                        continue

                    semantic_name = caller_var_to_sem[caller_var]

                    # Callee'nin bu pozisyondaki param'i auto-gen isim mi?
                    if arg_idx >= len(callee_params):
                        continue
                    callee_param_name = callee_params[arg_idx]["name"]

                    if (callee_name, callee_param_name) in already_named:
                        continue

                    # Sadece auto-gen isimleri degistir
                    if not _auto_re.match(callee_param_name):
                        continue

                    # Forward propagation biraz daha dusuk confidence
                    confidence = (self._PROP_BASE_CONFIDENCE - 0.05) * (self._PROP_DECAY ** (round_num - 1))

                    results.append(PropagatedParamName(
                        function_name=callee_name,
                        original_name=callee_param_name,
                        propagated_name=semantic_name,
                        confidence=round(confidence, 3),
                        direction="forward",
                        hop_count=round_num,
                        source_function=caller_name,
                        source_param_idx=arg_idx,
                        evidence=(
                            f"{caller_name} passes {caller_var}={semantic_name} "
                            f"as arg{arg_idx} to {callee_name}({callee_param_name}) "
                            f"[round {round_num}]"
                        ),
                    ))

        return results

    # ------------------------------------------------------------------
    # Faz 1: Dosya bazli analiz (paralel calisir)
    # ------------------------------------------------------------------

    def _analyze_file(
        self,
        filepath: Path,
        func_info: dict[str, dict[str, Any]],
        cg_nodes: dict[str, dict[str, Any]],
    ) -> tuple[list[DataFlowEdge], dict[str, str]]:
        """Tek bir C dosyasini analiz et.

        Returns:
            (edges, func_codes) -- kenarlar ve fonksiyon kodlari (sonra cross-func icin lazim).
        """
        edges: list[DataFlowEdge] = []
        func_codes: dict[str, str] = {}

        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return edges, func_codes

        # Dosyadaki fonksiyonlari cikar
        functions = self._extract_functions(content, func_info, filepath.stem)

        for func_name, func_body in functions:
            func_codes[func_name] = func_body

            # Her fonksiyon icindeki call site'lari bul
            callees_in_cg = set()
            cg_entry = cg_nodes.get(func_name)
            if cg_entry:
                callees_in_cg = {
                    c["name"] for c in cg_entry.get("callees", [])
                }

            # Pattern 1: Parameter passthrough
            param_edges = self._extract_param_flows(
                func_name, func_body, callees_in_cg, func_info,
            )
            edges.extend(param_edges)

            # Pattern 2: Return-to-argument
            ret_edges = self._extract_return_flows(
                func_name, func_body, callees_in_cg, func_info,
            )
            edges.extend(ret_edges)

            # Pattern 3: Struct field flows (intra-function)
            struct_edges = self._extract_intra_struct_flows(
                func_name, func_body, callees_in_cg,
            )
            edges.extend(struct_edges)

            # Pattern 4: Allocation chains (intra-function)
            alloc_edges = self._extract_intra_alloc_chains(
                func_name, func_body, callees_in_cg,
            )
            edges.extend(alloc_edges)

        return edges, func_codes

    # ------------------------------------------------------------------
    # Pattern 1: Parameter Passthrough
    # ------------------------------------------------------------------

    def _extract_param_flows(
        self,
        caller_name: str,
        caller_code: str,
        callees: set[str],
        func_info: dict[str, dict[str, Any]],
    ) -> list[DataFlowEdge]:
        """Caller parametresi callee parametresine akiyor mu?

        Ornek:
            void caller(double *K, double *f) {
                callee(K, f, n);  // K: caller.param_0 -> callee.param_0
            }

        Ghidra ciktisinda:
            void FUN_xxx(long param_1, long param_2) {
                FUN_yyy(param_1, param_2, local_10);
            }
        """
        edges: list[DataFlowEdge] = []

        # Caller'in parametrelerini cikar
        caller_params = self._get_func_params(caller_name, caller_code, func_info)
        if not caller_params:
            return edges

        # Caller param adlarini set olarak tut -- hizli lookup
        param_names = {p["name"] for p in caller_params}

        # Tum fonksiyon cagrilarini bul
        for m in _CALL_RE.finditer(caller_code):
            callee_name = m.group(1)

            # Skip: boilerplate fonksiyonlari
            if callee_name in _SKIP_FUNCS:
                continue
            # Skip: caller'in kendisi (recursive cagri)
            if callee_name == caller_name:
                continue

            args_str = m.group(2)
            call_args = _parse_args_string(args_str)

            for target_idx, arg_expr in enumerate(call_args):
                base_var = _extract_base_var(arg_expr)
                if base_var in param_names:
                    # Bu parametre caller'dan geliyor
                    source_idx = next(
                        (p["ordinal"] for p in caller_params if p["name"] == base_var),
                        -1,
                    )
                    if source_idx < 0:
                        continue

                    # Callee'nin param tipi (varsa)
                    callee_params = self._get_func_params(
                        callee_name, "", func_info,
                    )
                    param_type = ""
                    if callee_params and target_idx < len(callee_params):
                        param_type = callee_params[target_idx].get("type", "")

                    data_name = _guess_data_name(
                        callee_name, target_idx, param_type, "param_passthrough",
                    )

                    confidence = 0.75
                    # Call graph'ta dogrulama -- callee gercekten cagriliyorsa
                    # confidence arttir
                    if callee_name in callees:
                        confidence = 0.85

                    edges.append(DataFlowEdge(
                        source_func=caller_name,
                        target_func=callee_name,
                        data_name=data_name,
                        flow_type="param_passthrough",
                        source_param_idx=source_idx,
                        target_param_idx=target_idx,
                        confidence=confidence,
                        evidence=f"{base_var} passed from {caller_name} arg{source_idx} to {callee_name} arg{target_idx}",
                    ))

        return edges

    # ------------------------------------------------------------------
    # Pattern 2: Return-to-Argument
    # ------------------------------------------------------------------

    def _extract_return_flows(
        self,
        func_name: str,
        func_code: str,
        callees: set[str],
        func_info: dict[str, dict[str, Any]],
    ) -> list[DataFlowEdge]:
        """Return degeri baska fonksiyona arg olarak gidiyor mu?

        Ornek:
            void *result = produce_data();
            consume_data(result);
            // produce_data return -> consume_data arg0

        Ghidra ciktisi:
            uVar5 = FUN_xxx();
            FUN_yyy(uVar5, param_2);

        ObjC:
            uVar4 = _objc_retainAutoreleasedReturnValue();
            _objc_msgSend(uVar4, "startVPNTunnelWithOptions:", ...);
        """
        edges: list[DataFlowEdge] = []

        # 1. Standart C: var = callee(args); ... other_func(var, ...)
        return_vars: dict[str, str] = {}  # var_name -> producing_func

        for m in _ASSIGN_CALL_RE.finditer(func_code):
            var_name = m.group(1)
            callee_name = m.group(2)

            if callee_name in _SKIP_FUNCS:
                continue
            if callee_name == func_name:
                continue

            return_vars[var_name] = callee_name

        # 2. ObjC: _objc_msgSend ardindan retainAutoreleasedReturnValue
        # Ghidra pattern: _objc_msgSend(obj, "sel"); uVar = _objc_retainAutoreleasedReturnValue();
        for m in _OBJC_RETAIN_RETURN_RE.finditer(func_code):
            var_name = m.group(1)
            # Bir onceki _objc_msgSend'i bul
            pos = m.start()
            # Geri git ve en yakin msgSend'i bul
            preceding = func_code[max(0, pos - 500):pos]
            msg_matches = list(_OBJC_MSG_RE.finditer(preceding))
            if msg_matches:
                last_msg = msg_matches[-1]
                selector = last_msg.group(2)
                # Selector'dan anlamli fonksiyon ismi cikar
                producer = selector.rstrip(":")
                return_vars[var_name] = producer

        # Simdi bu degiskenlerin baska fonksiyona arg olarak gectigini bul
        for m in _CALL_RE.finditer(func_code):
            consumer_name = m.group(1)
            if consumer_name in _SKIP_FUNCS:
                continue
            if consumer_name == func_name:
                continue

            args_str = m.group(2)
            call_args = _parse_args_string(args_str)

            for target_idx, arg_expr in enumerate(call_args):
                base_var = _extract_base_var(arg_expr)
                if base_var in return_vars:
                    producer = return_vars[base_var]
                    data_name = _guess_data_name(
                        producer, -1, "", "return_to_arg",
                    )

                    confidence = 0.75
                    if consumer_name in callees:
                        confidence = 0.85

                    edges.append(DataFlowEdge(
                        source_func=producer,
                        target_func=consumer_name,
                        data_name=data_name,
                        flow_type="return_to_arg",
                        source_param_idx=-1,
                        target_param_idx=target_idx,
                        confidence=confidence,
                        evidence=(
                            f"{base_var} = {producer}() then passed to "
                            f"{consumer_name}() arg{target_idx} in {func_name}"
                        ),
                    ))

        # 3. ObjC msgSend zincirleri -- obj.method1() -> obj.method2(result)
        for m in _OBJC_MSG_RE.finditer(func_code):
            obj_var = m.group(1).strip()
            selector = m.group(2)
            extra_args = m.group(3)

            if not extra_args:
                continue

            args = _parse_args_string(extra_args)
            for arg_idx, arg_expr in enumerate(args):
                base_var = _extract_base_var(arg_expr)
                if base_var in return_vars:
                    producer = return_vars[base_var]
                    consumer = selector.rstrip(":")

                    edges.append(DataFlowEdge(
                        source_func=producer,
                        target_func=consumer,
                        data_name=_guess_data_name(producer, -1),
                        flow_type="return_to_arg",
                        source_param_idx=-1,
                        target_param_idx=arg_idx,
                        confidence=0.75,
                        evidence=(
                            f"{base_var} = {producer}() then passed to "
                            f"[obj {selector}] arg{arg_idx} in {func_name}"
                        ),
                    ))

        return edges

    # ------------------------------------------------------------------
    # Pattern 3: Struct/Global Field Mediation (intra-function)
    # ------------------------------------------------------------------

    def _extract_intra_struct_flows(
        self,
        func_name: str,
        func_code: str,
        callees: set[str],
    ) -> list[DataFlowEdge]:
        """Fonksiyon icinde struct field uzerinden veri akisi.

        Ornek:
            context->K = compute_stiffness();
            solve(context->K, rhs);
        """
        edges: list[DataFlowEdge] = []

        # Struct field yazmalari topla
        # field_key -> (writer_func_or_expr, evidence)
        writes: dict[str, tuple[str, str]] = {}

        for m in _STRUCT_WRITE_RE.finditer(func_code):
            if m.group(1) and m.group(2):
                # ptr->field = val
                ptr, fld, val = m.group(1), m.group(2), m.group(3)
                field_key = f"{ptr}->{fld}"
            elif m.group(4) and m.group(5):
                # struct.field = val
                st, fld, val = m.group(4), m.group(5), m.group(6)
                field_key = f"{st}.{fld}"
            elif m.group(7):
                # *(type*)(ptr + offset) = val
                ptr, offset, val = m.group(7), m.group(8), m.group(9)
                field_key = f"{ptr}+0x{offset}"
            else:
                continue

            # val tarafinda fonksiyon cagrisi var mi?
            val_clean = val.strip()
            call_in_val = _ASSIGN_CALL_RE.search(val_clean + ";")
            if not call_in_val:
                # Dogrudan func() olabilir
                simple_call = re.match(r"(\w+)\s*\(", val_clean)
                if simple_call:
                    writer_func = simple_call.group(1)
                    if writer_func not in _SKIP_FUNCS:
                        writes[field_key] = (
                            writer_func,
                            f"{field_key} = {writer_func}()",
                        )
                else:
                    writes[field_key] = ("direct_assign", f"{field_key} = {val_clean[:60]}")
            else:
                writer_func = call_in_val.group(2)
                if writer_func not in _SKIP_FUNCS:
                    writes[field_key] = (writer_func, f"{field_key} = {writer_func}()")

        # Struct field okumalari ve bu degerin fonksiyona arg olarak gecisini bul
        for m in _STRUCT_READ_RE.finditer(func_code):
            var = m.group(1)
            if m.group(2) and m.group(3):
                field_key = f"{m.group(2)}->{m.group(3)}"
            elif m.group(4) and m.group(5):
                field_key = f"{m.group(4)}.{m.group(5)}"
            elif m.group(6):
                field_key = f"{m.group(6)}+0x{m.group(7)}"
            else:
                continue

            if field_key not in writes:
                continue

            writer_func, write_evidence = writes[field_key]

            # Bu degisken sonra bir fonksiyona arg olarak geciyor mu?
            # var kullanimlarini bul
            # v1.6.1: [^)]*\b...\b[^)]*  catastrophic backtracking yapar.
            # Buyuk body'lerde str.find ile on-filtre, kucuklerde regex.
            _remaining = func_code[m.end():]
            if len(_remaining) > 50_000 or var not in _remaining:
                continue  # Buyuk body veya var yok — atla
            use_pattern = re.compile(
                r"(\w+)\s*\([^)]*\b" + re.escape(var) + r"\b[^)]*\)\s*;",
            )
            for um in use_pattern.finditer(_remaining):
                consumer = um.group(1)
                if consumer in _SKIP_FUNCS or consumer == func_name:
                    continue

                data_name = field_key.replace("->", "_").replace(".", "_").replace("+", "_off")
                if writer_func != "direct_assign":
                    data_name = _guess_data_name(writer_func, -1)

                edges.append(DataFlowEdge(
                    source_func=writer_func if writer_func != "direct_assign" else func_name,
                    target_func=consumer,
                    data_name=data_name,
                    flow_type="struct_field",
                    source_param_idx=-1,
                    target_param_idx=0,
                    confidence=0.60,
                    evidence=f"struct mediation: {write_evidence} -> {var} -> {consumer}() in {func_name}",
                ))

        return edges

    # ------------------------------------------------------------------
    # Pattern 3b: Cross-function struct field akisi
    # ------------------------------------------------------------------

    def _extract_cross_func_struct_flows(
        self,
        all_func_code: dict[str, str],
        cg_nodes: dict[str, dict[str, Any]],
        func_info: dict[str, dict[str, Any]],
    ) -> list[DataFlowEdge]:
        """Farkli fonksiyonlarda ayni struct field'a yazma/okuma.

        Ornek:
            // fonksiyon A:
            context->K = compute_stiffness();

            // fonksiyon B:
            solve(context->K, rhs);

        Basit yaklasim: ayni field_key'e birden fazla fonksiyondan
        erisim varsa, yazici -> okuyucu kenar olustur.
        """
        edges: list[DataFlowEdge] = []

        # Global field erisimleri topla
        # field_key -> { "writers": [(func_name, evidence)], "readers": [(func_name, evidence)] }
        field_access: dict[str, dict[str, list[tuple[str, str]]]] = defaultdict(
            lambda: {"writers": [], "readers": []},
        )

        for func_name, code in all_func_code.items():
            # Yazmalar
            for m in _STRUCT_WRITE_RE.finditer(code):
                if m.group(1) and m.group(2):
                    field_key = f"{m.group(2)}"  # Sadece field adi -- ptr degisebilir
                elif m.group(4) and m.group(5):
                    field_key = f"{m.group(5)}"
                elif m.group(7):
                    field_key = f"offset_0x{m.group(8)}"
                else:
                    continue
                field_access[field_key]["writers"].append(
                    (func_name, m.group(0)[:80]),
                )

            # Okumalar
            for m in _STRUCT_READ_RE.finditer(code):
                if m.group(2) and m.group(3):
                    field_key = f"{m.group(3)}"
                elif m.group(4) and m.group(5):
                    field_key = f"{m.group(5)}"
                elif m.group(6):
                    field_key = f"offset_0x{m.group(7)}"
                else:
                    continue
                field_access[field_key]["readers"].append(
                    (func_name, m.group(0)[:80]),
                )

        # v1.6.5: Yazici -> okuyucu kenarlar olustur (batch confidence)
        # Ilk pass: tum ciftleri topla, confidence hesabini batch yap
        pending_pairs: list[tuple[str, str, str, str, str]] = []
        # (field_key, writer_func, w_ev, reader_func, r_ev)

        for field_key, access in field_access.items():
            writers = access["writers"]
            readers = access["readers"]

            if not writers or not readers:
                continue

            # Cok genel field'lari (her yerde kullanilan) atla
            if len(writers) + len(readers) > 500:
                continue

            for writer_func, w_ev in writers:
                for reader_func, r_ev in readers:
                    if writer_func == reader_func:
                        continue  # Ayni fonksiyon -- intra-func zaten islendi
                    pending_pairs.append(
                        (field_key, writer_func, w_ev, reader_func, r_ev),
                    )

        if not pending_pairs:
            return edges

        # v1.6.5: Batch confidence hesapla
        # Unik writer/reader fonksiyonlari index'le
        all_writers_uniq: list[str] = []
        all_readers_uniq: list[str] = []
        writer_name_to_idx: dict[str, int] = {}
        reader_name_to_idx: dict[str, int] = {}

        for _, wf, _, rf, _ in pending_pairs:
            if wf not in writer_name_to_idx:
                writer_name_to_idx[wf] = len(all_writers_uniq)
                all_writers_uniq.append(wf)
            if rf not in reader_name_to_idx:
                reader_name_to_idx[rf] = len(all_readers_uniq)
                all_readers_uniq.append(rf)

        n_w = len(all_writers_uniq)
        n_r = len(all_readers_uniq)

        # Tum caller isimlerini topla (global index)  # v1.6.5
        all_caller_names: set[str] = set()
        for wf in all_writers_uniq:
            for c in cg_nodes.get(wf, {}).get("callers", []):
                all_caller_names.add(c["name"])
        for rf in all_readers_uniq:
            for c in cg_nodes.get(rf, {}).get("callers", []):
                all_caller_names.add(c["name"])

        caller_list = sorted(all_caller_names)
        caller_to_idx = {name: i for i, name in enumerate(caller_list)}
        n_callers = len(caller_list)

        # Matrisler olustur  # v1.6.5
        w_callers_mat = [[0] * n_callers for _ in range(n_w)]
        r_callers_mat = [[0] * n_callers for _ in range(n_r)]
        w_callees_mat = [[0] * n_r for _ in range(n_w)]  # writer calls reader?
        r_callees_mat = [[0] * n_w for _ in range(n_r)]  # reader calls writer?

        for wi, wf in enumerate(all_writers_uniq):
            w_entry = cg_nodes.get(wf, {})
            for c in w_entry.get("callers", []):
                ci = caller_to_idx.get(c["name"])
                if ci is not None:
                    w_callers_mat[wi][ci] = 1
            w_callees = {c["name"] for c in w_entry.get("callees", [])}
            for ri, rf in enumerate(all_readers_uniq):
                if rf in w_callees:
                    w_callees_mat[wi][ri] = 1

        for ri, rf in enumerate(all_readers_uniq):
            r_entry = cg_nodes.get(rf, {})
            for c in r_entry.get("callers", []):
                ci = caller_to_idx.get(c["name"])
                if ci is not None:
                    r_callers_mat[ri][ci] = 1
            r_callees = {c["name"] for c in r_entry.get("callees", [])}
            for wi, wf in enumerate(all_writers_uniq):
                if wf in r_callees:
                    r_callees_mat[ri][wi] = 1

        # Pair index'leri  # v1.6.5
        pair_w_idx = [writer_name_to_idx[wf] for _, wf, _, _, _ in pending_pairs]
        pair_r_idx = [reader_name_to_idx[rf] for _, _, _, rf, _ in pending_pairs]

        # Batch confidence hesapla  # v1.6.5
        confidences = _batch_struct_confidence(
            w_callers_mat, r_callers_mat,
            w_callees_mat, r_callees_mat,
            pair_w_idx, pair_r_idx,
        )

        # Edge'leri olustur  # v1.6.5
        for i, (field_key, writer_func, _, reader_func, _) in enumerate(pending_pairs):
            edges.append(DataFlowEdge(
                source_func=writer_func,
                target_func=reader_func,
                data_name=f"field_{field_key}",
                flow_type="struct_field",
                source_param_idx=-1,
                target_param_idx=0,
                confidence=confidences[i],
                evidence=f"cross-func field '{field_key}': write in {writer_func}, read in {reader_func}",
            ))

        return edges

    # ------------------------------------------------------------------
    # Pattern 4: Allocation Chain (intra-function)
    # ------------------------------------------------------------------

    def _extract_intra_alloc_chains(
        self,
        func_name: str,
        func_code: str,
        callees: set[str],
    ) -> list[DataFlowEdge]:
        """Fonksiyon icinde allocation -> kullanim -> free zinciri.

        Ornek:
            K = malloc(n * n * sizeof(double));
            fill_matrix(K);
            factorize(K);
            solve_with(K, b);
            free(K);
        """
        edges: list[DataFlowEdge] = []

        # Allocation'lari bul (cast'li ve cast'siz formlar)
        alloc_vars: dict[str, int] = {}  # var_name -> position_in_code

        for m in _ALLOC_RE.finditer(func_code):
            var_name = m.group(1)
            alloc_vars[var_name] = m.start()

        # Cast'li alloc: var = (type *)malloc(size);
        for m in _ALLOC_CAST_RE.finditer(func_code):
            var_name = m.group(1)
            if var_name not in alloc_vars:  # Cift sayma onle
                alloc_vars[var_name] = m.start()

        if not alloc_vars:
            return edges

        # Her alloc'd degiskenin kullanimlarini izle
        for alloc_var, alloc_pos in alloc_vars.items():
            users: list[tuple[str, int, int]] = []  # (callee, arg_idx, position)

            # Bu degiskeni arg olarak alan fonksiyonlari bul
            for m in _CALL_RE.finditer(func_code[alloc_pos:]):
                callee_name = m.group(1)
                if callee_name in _SKIP_FUNCS or callee_name == func_name:
                    continue

                args = _parse_args_string(m.group(2))
                for arg_idx, arg_expr in enumerate(args):
                    if _extract_base_var(arg_expr) == alloc_var:
                        users.append((callee_name, arg_idx, alloc_pos + m.start()))
                        break

            # Allocation -> ilk kullanici, her kullanici -> sonraki kullanici
            if not users:
                continue

            # alloc -> first_user
            first_user, first_idx, _ = users[0]
            edges.append(DataFlowEdge(
                source_func=func_name,
                target_func=first_user,
                data_name=f"alloc_{alloc_var}",
                flow_type="allocation_chain",
                source_param_idx=-1,
                target_param_idx=first_idx,
                confidence=0.75,
                evidence=f"{alloc_var} = malloc/calloc() -> {first_user}({alloc_var}) in {func_name}",
            ))

            # user[i] -> user[i+1]
            for i in range(len(users) - 1):
                prev_func, _, _ = users[i]
                next_func, next_idx, _ = users[i + 1]
                if prev_func == next_func:
                    continue

                edges.append(DataFlowEdge(
                    source_func=prev_func,
                    target_func=next_func,
                    data_name=f"alloc_{alloc_var}",
                    flow_type="allocation_chain",
                    source_param_idx=-1,
                    target_param_idx=next_idx,
                    confidence=0.70,
                    evidence=f"allocation chain: {prev_func}({alloc_var}) -> {next_func}({alloc_var}) in {func_name}",
                ))

        return edges

    # ------------------------------------------------------------------
    # Pattern 4b: Cross-function allocation chains
    # ------------------------------------------------------------------

    def _extract_cross_func_alloc_chains(
        self,
        all_func_code: dict[str, str],
        cg_nodes: dict[str, dict[str, Any]],
        func_info: dict[str, dict[str, Any]],
    ) -> list[DataFlowEdge]:
        """Farkli fonksiyonlarda ayni pointer'i allocate/use/free.

        Caller allocate eder, callee'ye param olarak gecirir, callee kullanir.
        Bu pattern Parameter Passthrough ile kapanir ama allocation
        semantigini ekler.

        Burada sadece ek edge'ler yaratiyoruz: allocator fonksiyon ile
        callee arasinda "allocation_chain" tipi bir kenar.
        """
        edges: list[DataFlowEdge] = []

        # Allocation yapan fonksiyonlari bul (cast'li ve cast'siz)
        allocating_funcs: dict[str, set[str]] = {}  # func -> set of alloc'd var names

        for func_name, code in all_func_code.items():
            for m in _ALLOC_RE.finditer(code):
                allocating_funcs.setdefault(func_name, set()).add(m.group(1))
            for m in _ALLOC_CAST_RE.finditer(code):
                allocating_funcs.setdefault(func_name, set()).add(m.group(1))

        if not allocating_funcs:
            return edges

        # Free yapan fonksiyonlari bul
        freeing_funcs: dict[str, set[str]] = {}  # func -> set of free'd var names

        for func_name, code in all_func_code.items():
            for m in _FREE_RE.finditer(code):
                freed_var = _extract_base_var(m.group(1))
                freeing_funcs.setdefault(func_name, set()).add(freed_var)

        # Alloc yapan fonksiyonun callee'lerini bul
        # ve alloc'd pointer'i param olarak geciren kenarlar olustur
        for alloc_func, alloc_vars in allocating_funcs.items():
            cg_entry = cg_nodes.get(alloc_func, {})
            callees_list = cg_entry.get("callees", [])

            for callee_info in callees_list:
                callee_name = callee_info.get("name", "")
                if callee_name in _SKIP_FUNCS:
                    continue

                # callee free yapiyor mu?
                if callee_name in freeing_funcs:
                    # alloc -> ... -> free iliskisi
                    for var in alloc_vars:
                        edges.append(DataFlowEdge(
                            source_func=alloc_func,
                            target_func=callee_name,
                            data_name=f"alloc_{var}_lifecycle",
                            flow_type="allocation_chain",
                            source_param_idx=-1,
                            target_param_idx=0,
                            confidence=0.55,
                            evidence=f"cross-func alloc: {alloc_func} allocates, {callee_name} frees",
                        ))

        return edges

    # ------------------------------------------------------------------
    # Pipeline tespiti -- topolojik siralama + en uzun yollar
    # ------------------------------------------------------------------

    def _detect_pipelines(self, graph: DataFlowGraph) -> list[list[str]]:
        """Veri akis grafiginde dogrusal pipeline'lari tespit et.  # v1.6.5

        Topolojik siralama + en uzun yol algoritmasi.
        Sadece yuksek guvenli (>= 0.6) kenarlar kullanilir.

        v1.6.5: Longest path via topological sort + DP.

        Returns:
            En uzun pipeline'lardan kisaya dogru siralanmis liste.
            Her pipeline [func1, func2, func3, ...] seklinde.
        """
        # Yuksek guvenli kenarlardan adjacency list olustur  # v1.6.5
        min_conf = 0.60
        adj: dict[str, set[str]] = defaultdict(set)

        relevant_nodes: set[str] = set()
        for e in graph.edges:
            if e.confidence < min_conf:
                continue
            adj[e.source_func].add(e.target_func)
            relevant_nodes.add(e.source_func)
            relevant_nodes.add(e.target_func)

        if not relevant_nodes:
            return []

        # v1.6.5: en uzun yol hesapla
        dist, pred = _pipeline_longest_path(adj, relevant_nodes)

        # En uzun yollardan pipeline'lar cikar  # v1.6.5
        # Sink'lerden (out-degree 0) geriye dogru git
        out_nodes = {
            n for n in relevant_nodes
            if not adj.get(n) or all(t not in relevant_nodes for t in adj.get(n, set()))
        }
        if not out_nodes:
            # Cycle -- en yuksek dist'li node'u kullan
            out_nodes = {max(dist, key=lambda n: dist[n])} if dist else set()

        pipelines: list[list[str]] = []
        for sink in out_nodes:
            if dist.get(sink, 0) < 2:
                continue  # En az 3 node'luk pipeline

            # Yolu geri izle
            path: list[str] = [sink]
            current = sink
            visited: set[str] = {sink}  # Sonsuz dongu korumasai
            while pred.get(current) is not None and pred[current] not in visited:
                current = pred[current]  # type: ignore[assignment]
                path.append(current)
                visited.add(current)
            path.reverse()
            pipelines.append(path)

        # Uzunluga gore sirala (uzundan kisaya)
        pipelines.sort(key=len, reverse=True)

        # En fazla 500 pipeline rapor et  # v1.6.5
        return pipelines[:500]

    # ------------------------------------------------------------------
    # Fonksiyon ismi normalizasyonu (FUN_xxx -> gercek isim)
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_edge_names(
        edges: list[DataFlowEdge],
        func_info: dict[str, dict[str, Any]],
    ) -> list[DataFlowEdge]:
        """Edge'lerdeki FUN_xxx formatindaki fonksiyon isimlerini normalize et.

        Ghidra, analiz edemedigi fonksiyonlara FUN_XXXX isimleri verir.
        func_info'da adres eslemesi varsa gercek isimle degistir.
        Yoksa sub_XXXX formatina donustur (adres-bazli eslesme icin
        tutarli olsun).

        Ayrica ayni fonksiyon ciftinin farkli FUN_xxx isimlerine sahip
        oldugu durumu ele alir (ornek: FUN_00401234 ve _FUN_00401234
        ayni sey).
        """
        # Cache: bir kere cevrilmis isimleri tekrar hesaplama
        name_cache: dict[str, str] = {}

        def resolve(name: str) -> str:
            if name in name_cache:
                return name_cache[name]
            resolved = _normalize_func_name(name, func_info)
            name_cache[name] = resolved
            return resolved

        result: list[DataFlowEdge] = []
        for e in edges:
            new_src = resolve(e.source_func)
            new_tgt = resolve(e.target_func)

            # Normalizasyon sonrasi source == target olabilir (FUN_xxx
            # ve _FUN_xxx ayni fonksiyona cozulurse) -- self-edge atla
            if new_src == new_tgt:
                continue

            # data_name icindeki FUN_xxx referanslarini da normalize et
            # Ornek: "result_of_FUN_00404000" -> "result_of_factorize_lu"
            # _AUTO_FUNC_RE anchor'lu (^) oldugu icin inline arama yapamaz;
            # ayri bir non-anchored pattern kullaniyoruz.
            new_data_name = e.data_name
            # data_name icinde FUN_xxx referanslarini bul ve normalize et.
            # Dikkat: "_of_FUN_xxx" gibi durumlarda sadece "FUN_xxx"
            # kismini degistirmek lazim (onceki _ ayirici).
            for fun_match in re.finditer(r"(?:^|(?<=_))(_?FUN_[0-9a-fA-F]+)", new_data_name):
                old_fun = fun_match.group(1)
                new_fun = resolve(old_fun)
                if old_fun != new_fun:
                    new_data_name = new_data_name.replace(old_fun, new_fun)

            result.append(DataFlowEdge(
                source_func=new_src,
                target_func=new_tgt,
                data_name=new_data_name,
                flow_type=e.flow_type,
                source_param_idx=e.source_param_idx,
                target_param_idx=e.target_param_idx,
                confidence=e.confidence,
                evidence=e.evidence,
            ))

        return result

    # ------------------------------------------------------------------
    # xrefs_json dogrulama ve confidence bonus
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_xrefs_validation(
        edges: list[DataFlowEdge],
        xrefs: dict[str, Any],
        func_info: dict[str, dict[str, Any]] | None = None,
    ) -> list[DataFlowEdge]:
        """Cross-reference verileriyle edge'leri dogrula.

        xrefs_json yapisi (Ghidra ciktisi):
          {
            "addr_hex": {
              "name": "func_or_data",
              "type": "DATA" | "CODE",
              "refs_to": [{"addr": "...", "type": "READ|WRITE|CALL", "from_func": "..."}],
              "refs_from": [{"addr": "...", "type": "READ|WRITE|CALL", "to_func": "..."}]
            }
          }

        veya basitlestirilmis format:
          {
            "func_name": {
              "references": [{"from": "caller", "to": "callee", "type": "CALL|DATA"}]
            }
          }

        Dogrulama kurallari:
          1. xrefs'te bir edge'in source->target CALL referansi varsa: +0.10 bonus
          2. struct_field edge'leri icin ayni global DATA ref varsa: +0.10 bonus
          3. Bonus uygulandiktan sonra confidence 1.0'i gecemez
        """
        # xrefs'teki FUN_xxx isimlerini normalize et (edge'ler zaten normalize)
        def _norm(name: str) -> str:
            return _normalize_func_name(name, func_info)

        # xrefs'ten hizli lookup icin iki index olustur:
        #   call_pairs: (caller, callee) -> True
        #   data_refs: func_name -> set of referenced data/global names
        call_pairs: set[tuple[str, str]] = set()
        data_refs: dict[str, set[str]] = defaultdict(set)

        for key, entry in xrefs.items():
            if not isinstance(entry, dict):
                continue

            entry_name = _norm(entry.get("name", key))

            # Format 1: refs_to / refs_from
            for ref in entry.get("refs_to", []):
                if not isinstance(ref, dict):
                    continue
                ref_type = ref.get("type", "")
                from_func = _norm(ref.get("from_func", ""))
                if "CALL" in ref_type.upper() and from_func:
                    call_pairs.add((from_func, entry_name))
                elif ref_type.upper() in ("READ", "WRITE", "DATA"):
                    if from_func:
                        data_refs[from_func].add(entry_name)

            for ref in entry.get("refs_from", []):
                if not isinstance(ref, dict):
                    continue
                ref_type = ref.get("type", "")
                to_func = _norm(ref.get("to_func", ref.get("to", "")))
                if "CALL" in ref_type.upper() and to_func:
                    call_pairs.add((entry_name, to_func))
                elif ref_type.upper() in ("READ", "WRITE", "DATA"):
                    if to_func:
                        data_refs[entry_name].add(to_func)

            # Format 2: references listesi
            for ref in entry.get("references", []):
                if not isinstance(ref, dict):
                    continue
                ref_from = _norm(ref.get("from", ""))
                ref_to = _norm(ref.get("to", ""))
                ref_type = ref.get("type", "")
                if "CALL" in ref_type.upper():
                    if ref_from and ref_to:
                        call_pairs.add((ref_from, ref_to))
                elif ref_type.upper() in ("DATA", "READ", "WRITE"):
                    if ref_from:
                        data_refs[ref_from].add(ref_to or entry_name)

        if not call_pairs and not data_refs:
            return edges

        # v1.6.5: Bonus degerlerini topla, sonra batch uygula
        xref_bonus = 0.10
        bonuses: list[float] = []

        for e in edges:
            bonus = 0.0

            # Kural 1: CALL referansi ile dogrulama
            if (e.source_func, e.target_func) in call_pairs:
                bonus = xref_bonus

            # Kural 2: struct_field edge'leri icin ortak DATA referansi
            if e.flow_type == "struct_field" and bonus == 0.0:
                src_data = data_refs.get(e.source_func, set())
                tgt_data = data_refs.get(e.target_func, set())
                if src_data & tgt_data:
                    # Ortak global/data referansi var -- struct mediation dogrulanmis
                    bonus = xref_bonus

            bonuses.append(bonus)

        # v1.6.5: Batch confidence update
        old_confidences = [e.confidence for e in edges]
        new_confidences = _batch_confidence_update(old_confidences, bonuses)

        result: list[DataFlowEdge] = []
        for i, e in enumerate(edges):
            new_evidence = e.evidence
            if bonuses[i] > 0:
                new_evidence = e.evidence + " [xref-validated]"

            result.append(DataFlowEdge(
                source_func=e.source_func,
                target_func=e.target_func,
                data_name=e.data_name,
                flow_type=e.flow_type,
                source_param_idx=e.source_param_idx,
                target_param_idx=e.target_param_idx,
                confidence=new_confidences[i],
                evidence=new_evidence,
            ))

        validated_count = sum(1 for e in result if "[xref-validated]" in e.evidence)
        if validated_count:
            logger.info(
                "xrefs validation: %d/%d edges received +%.2f confidence bonus",
                validated_count, len(result), xref_bonus,
            )

        return result

    # ------------------------------------------------------------------
    # Data object lifecycle
    # ------------------------------------------------------------------

    def _build_data_objects(
        self, edges: list[DataFlowEdge],
    ) -> dict[str, list[str]]:
        """Her veri nesnesinin gecirdigi fonksiyonlari (lifecycle) cikar.

        data_name -> [source_func1, target_func1, target_func2, ...]
        """
        objects: dict[str, list[str]] = defaultdict(list)

        for e in edges:
            funcs = objects[e.data_name]
            if e.source_func not in funcs:
                funcs.append(e.source_func)
            if e.target_func not in funcs:
                funcs.append(e.target_func)

        return dict(objects)

    # ------------------------------------------------------------------
    # Tekillesttirme
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate_edges(edges: list[DataFlowEdge]) -> list[DataFlowEdge]:
        """Ayni (source, target, flow_type) uclularini birlesttir.  # v1.6.5

        Ayni kenardan birden fazla varsa en yuksek confidence'li olani tut.
        v1.6.5: Batch deduplication with max-confidence selection.
        """
        if not edges:
            return []

        # v1.6.5: Batch dedup
        edge_keys = [
            (e.source_func, e.target_func, e.flow_type, e.data_name)
            for e in edges
        ]
        confidences = [e.confidence for e in edges]
        selected_indices = _batch_dedup_edges(edge_keys, confidences)

        result = [edges[i] for i in selected_indices]
        return sorted(result, key=lambda x: -x.confidence)

    # ------------------------------------------------------------------
    # Yardimcilar: JSON yukleme, dosya toplama, fonksiyon cikarma
    # ------------------------------------------------------------------

    @staticmethod
    def _load_json(
        path: Path | None, errors: list[str],
    ) -> dict[str, Any]:
        """JSON dosyasini yukle; hata olursa bos dict dondur."""
        if path is None or not path.exists():
            return {}
        try:
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
            if isinstance(data, list):
                result: dict[str, Any] = {}
                for item in data:
                    if isinstance(item, dict):
                        name = item.get("name") or item.get("function_name", "")
                        if name:
                            result[name] = item
                return result
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            errors.append(f"Cannot load {path.name}: {exc}")
            return {}

    @staticmethod
    def _collect_c_files(
        directory: Path, errors: list[str],
    ) -> list[Path]:
        """Dizindeki C dosyalarini topla (recursive)."""
        if not directory.exists():
            errors.append(f"Directory does not exist: {directory}")
            return []
        files: list[Path] = []
        seen: set[Path] = set()
        for ext in ("*.c", "*.h", "*.cpp", "*.cc"):
            for f in directory.rglob(ext):
                resolved = f.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    files.append(f)
        return sorted(files)

    def _normalize_call_graph(
        self, raw: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """Call graph JSON'unu func_name -> {callers, callees} dict'ine cevir.

        Desteklenen formatlar:
          1. {"nodes": {"addr": {"name": ..., "callers": [...], "callees": [...]}}}
          2. {"addr": {"name": ..., "callers": [...], "callees": [...]}}
          3. {"func_name": {"callers": [...], "callees": [...]}}
        """
        result: dict[str, dict[str, Any]] = {}

        nodes = raw.get("nodes", raw)
        if not isinstance(nodes, dict):
            return result

        for key, entry in nodes.items():
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", key)
            result[name] = {
                "callers": entry.get("callers", []),
                "callees": entry.get("callees", []),
                "address": entry.get("address", key),
            }

        return result

    def _normalize_functions(
        self, raw: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        """Fonksiyon metadata'sini func_name -> info dict'ine cevir.

        Desteklenen formatlar:
          1. {"total": ..., "functions": [...]}  (Ghidra ciktisi)
          2. {"func_name": {...}}                (zaten normalize)
        """
        result: dict[str, dict[str, Any]] = {}

        # Format 1: functions listesi
        if "functions" in raw and isinstance(raw["functions"], list):
            for func in raw["functions"]:
                if isinstance(func, dict):
                    name = func.get("name", "")
                    if name:
                        result[name] = func
            return result

        # Format 2: zaten dict
        for key, val in raw.items():
            if isinstance(val, dict) and "name" in val:
                result[val["name"]] = val
            elif isinstance(val, dict):
                result[key] = val

        return result

    def _extract_functions(
        self,
        content: str,
        func_info: dict[str, dict[str, Any]],
        file_stem: str,
    ) -> list[tuple[str, str]]:
        """C iceriginden (func_name, func_body) cikar."""
        results: list[tuple[str, str]] = []

        for match in _FUNC_DEF_RE.finditer(content):
            func_name = match.group(1)
            body = _extract_body(content, match.end() - 1)
            results.append((func_name, body))

        # Hic bulunmadiysa -- dosya icerigi tek fonksiyon olarak
        if not results and content.strip():
            # Dosya adindaki ozel karakterleri temizle
            clean_stem = re.sub(r"[^a-zA-Z0-9_]", "_", file_stem)
            results.append((clean_stem, content))

        return results

    def _get_func_params(
        self,
        func_name: str,
        func_code: str,
        func_info: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Fonksiyonun parametre listesini dondur.

        Oncelik:
          1. func_info metadata (Ghidra'dan)
          2. Kod icindeki fonksiyon imzasindan parse
        """
        # Metadata'dan
        info = func_info.get(func_name, {})
        if "parameters" in info and info["parameters"]:
            params = info["parameters"]
            # Normalize: her param'in ordinal ve name alanini garantile
            result: list[dict[str, Any]] = []
            for i, p in enumerate(params):
                if isinstance(p, dict):
                    result.append({
                        "name": p.get("name", f"param_{i + 1}"),
                        "type": p.get("type", ""),
                        "ordinal": p.get("ordinal", i),
                    })
            return result

        # Kod icinden parse et
        if not func_code:
            return []

        m = _FUNC_DEF_RE.search(func_code)
        if not m:
            return []

        params_str = m.group(2)
        if not params_str.strip() or params_str.strip() == "void":
            return []

        parsed_params: list[dict[str, Any]] = []
        for i, param_decl in enumerate(params_str.split(",")):
            param_decl = param_decl.strip()
            if not param_decl:
                continue
            # "typedef ID qword param_1" veya "int param_1" veya "double *K"
            parts = param_decl.rsplit(None, 1)
            if len(parts) >= 2:
                ptype, pname = " ".join(parts[:-1]), parts[-1]
            else:
                ptype, pname = "", parts[0]

            # Pointer yildizi isimde olabilir
            pname = pname.lstrip("*")

            parsed_params.append({
                "name": pname,
                "type": ptype,
                "ordinal": i,
            })

        return parsed_params

    # ------------------------------------------------------------------
    # Cikti yazma
    # ------------------------------------------------------------------

    def _write_output(self, result: DataFlowResult, output_dir: Path) -> None:
        """Sonuclari JSON olarak yaz."""
        output_dir.mkdir(parents=True, exist_ok=True)

        # Ana JSON
        out_path = output_dir / "data_flow.json"
        try:
            with open(out_path, "w") as f:
                json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
            logger.info("Data flow results written to %s", out_path)
        except OSError as exc:
            result.errors.append(f"Cannot write output: {exc}")

        # Pipeline'lari ayri dosyaya
        if result.pipelines:
            pipeline_path = output_dir / "data_flow_pipelines.json"
            try:
                with open(pipeline_path, "w") as f:
                    json.dump(
                        {
                            "total_pipelines": len(result.pipelines),
                            "pipelines": [
                                {
                                    "id": i,
                                    "length": len(p),
                                    "functions": p,
                                }
                                for i, p in enumerate(result.pipelines)
                            ],
                        },
                        f, indent=2,
                    )
            except OSError:
                pass

        # Human-readable ozet
        summary_path = output_dir / "data_flow_summary.txt"
        try:
            with open(summary_path, "w") as f:
                f.write("=" * 72 + "\n")
                f.write("Inter-Procedural Data Flow Summary\n")
                f.write("=" * 72 + "\n\n")
                f.write(f"Total edges:        {result.total_edges}\n")
                f.write(f"Total data objects: {result.total_data_objects}\n")
                f.write(f"Total pipelines:    {len(result.pipelines)}\n")
                f.write(f"Total functions:    {len(result.graph.nodes)}\n\n")

                # Edge type breakdown
                type_counts: dict[str, int] = defaultdict(int)
                for e in result.graph.edges:
                    type_counts[e.flow_type] += 1
                f.write("Edge type breakdown:\n")
                for ft, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                    f.write(f"  {ft:25s} {count:6d}\n")

                # Confidence distribution
                conf_buckets: dict[str, int] = {"high (>=0.8)": 0, "medium (0.6-0.8)": 0, "low (<0.6)": 0}
                for e in result.graph.edges:
                    if e.confidence >= 0.8:
                        conf_buckets["high (>=0.8)"] += 1
                    elif e.confidence >= 0.6:
                        conf_buckets["medium (0.6-0.8)"] += 1
                    else:
                        conf_buckets["low (<0.6)"] += 1
                f.write("\nConfidence distribution:\n")
                for bucket, count in conf_buckets.items():
                    f.write(f"  {bucket:25s} {count:6d}\n")

                # Top pipelines
                if result.pipelines:
                    f.write(f"\nTop {min(10, len(result.pipelines))} pipelines:\n")
                    for i, pipeline in enumerate(result.pipelines[:10]):
                        f.write(f"\n  Pipeline #{i} (length {len(pipeline)}):\n")
                        for j, func in enumerate(pipeline):
                            arrow = "  -> " if j > 0 else "     "
                            f.write(f"    {arrow}{func}\n")

                # Top data objects (by lifecycle length)
                if result.graph.data_objects:
                    sorted_objects = sorted(
                        result.graph.data_objects.items(),
                        key=lambda x: len(x[1]),
                        reverse=True,
                    )
                    f.write(f"\nTop {min(20, len(sorted_objects))} data objects (by lifecycle length):\n")
                    for name, funcs in sorted_objects[:20]:
                        f.write(f"  {name}: {' -> '.join(funcs)}\n")

                if result.errors:
                    f.write(f"\nErrors ({len(result.errors)}):\n")
                    for err in result.errors[:20]:
                        f.write(f"  - {err}\n")

        except OSError:
            pass

        # DOT graph (Graphviz)
        dot_path = output_dir / "data_flow.dot"
        try:
            self._write_dot_graph(result.graph, dot_path)
        except OSError:
            pass

    @staticmethod
    def _write_dot_graph(graph: DataFlowGraph, path: Path) -> None:
        """Graphviz DOT formatinda graph yaz.

        Sonra `dot -Tpng data_flow.dot -o data_flow.png` ile gorsellestirilir.
        """
        # Sadece yuksek guvenli kenarlari goster (yoksa cok karisik olur)
        min_conf = 0.60
        high_edges = [e for e in graph.edges if e.confidence >= min_conf]

        if not high_edges:
            return

        # Unik node'lar
        nodes = set()
        for e in high_edges:
            nodes.add(e.source_func)
            nodes.add(e.target_func)

        # Node isimleri cok uzunsa kirp
        def short_name(n: str) -> str:
            if len(n) > 40:
                return n[:37] + "..."
            return n

        with open(path, "w") as f:
            f.write("digraph DataFlow {\n")
            f.write("  rankdir=LR;\n")
            f.write("  node [shape=box, fontsize=10];\n")
            f.write("  edge [fontsize=8];\n\n")

            # Node tanimlari
            for node in sorted(nodes):
                label = short_name(node).replace('"', '\\"')
                f.write(f'  "{node}" [label="{label}"];\n')

            f.write("\n")

            # Kenarlar
            type_colors = {
                "param_passthrough": "blue",
                "return_to_arg": "darkgreen",
                "struct_field": "red",
                "allocation_chain": "orange",
            }

            for e in high_edges:
                color = type_colors.get(e.flow_type, "black")
                label = short_name(e.data_name).replace('"', '\\"')
                f.write(
                    f'  "{e.source_func}" -> "{e.target_func}" '
                    f'[label="{label}", color="{color}", '
                    f'tooltip="{e.evidence[:80]}"];\n'
                )

            # Legend
            f.write("\n  // Legend\n")
            f.write('  subgraph cluster_legend {\n')
            f.write('    label="Legend";\n')
            f.write('    style=dashed;\n')
            f.write('    fontsize=10;\n')
            for ft, color in type_colors.items():
                safe = ft.replace("_", " ")
                f.write(f'    "legend_{ft}" [label="{safe}", shape=plaintext];\n')
                f.write(f'    "legend_{ft}_end" [label="", shape=point, width=0];\n')
                f.write(f'    "legend_{ft}" -> "legend_{ft}_end" [color="{color}"];\n')
            f.write("  }\n")

            f.write("}\n")
