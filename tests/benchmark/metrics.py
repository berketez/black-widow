"""Accuracy metrics for reverse engineering quality measurement.

Scoring:
- Exact match: 1.0 (original name ile birebir ayni)
- Semantic match: 0.8 (ayni anlama gelen isim, or: send_data vs send_buffer)
- Partial match: 0.5 (class veya method dogru, diger kisim farkli)
- Wrong name: 0.0
- No name (FUN_xxx kaldi): 0.0
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NamingResult:
    """Result of comparing recovered name vs original."""

    original: str
    recovered: str
    score: float  # 0.0 - 1.0
    match_type: str  # "exact", "semantic", "partial", "wrong", "missing"
    # v1.10.0 Batch 5A: Per-source F1 hesaplamasi icin ek alan.
    # Ornek: "sig_db", "c_namer", "ngram", "string_intel", "ensemble".
    # Bos string = genel/bilinmiyor (geriye uyumlu).
    source: str = ""


@dataclass
class BenchmarkMetrics:
    """Aggregate metrics for a benchmark run.

    v1.10.0 Batch 5A eklemeleri:
      - precision, recall, f1: Isim kurtarmanin classification F1 skoru.
      - per_source_*: Kaynak bazli kirilim (NamingResult.source alanindan).
      - confusion_matrix: match_type -> {match_type: count} iki boyutlu tablo.
    """

    total_symbols: int = 0
    exact_matches: int = 0
    semantic_matches: int = 0
    partial_matches: int = 0
    wrong_names: int = 0
    missing_names: int = 0  # FUN_xxx / var_N still present

    # v1.10.0: F1 / precision / recall
    # Tanimlar:
    #   TP = exact + semantic + partial (anlamli, dogru isim)
    #   FP = wrong (isim uretildi ama yanlis)
    #   FN = missing (isim uretilemedi)
    #   TN: anlamli degil bu baglamda (yoktur)
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0

    # v1.10.0: Kaynak bazli kirilim -- source -> metric
    per_source_precision: dict[str, float] = field(default_factory=dict)
    per_source_recall: dict[str, float] = field(default_factory=dict)
    per_source_f1: dict[str, float] = field(default_factory=dict)

    # v1.10.0: Confusion matrix (match_type -> match_type -> count).
    # Normalde "expected" (dogru olan) match_type'dan "actual"'a gecisler
    # hesaplaniyor; ancak burada her NamingResult'in kendi match_type'i
    # hem beklenen hem gerceklesen oldugu icin diagonal matris.
    # Kullanim: match_type dagilimini gormek.
    confusion_matrix: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def accuracy(self) -> float:
        """Weighted accuracy score (0-100%).

        Exact=1.0, Semantic=0.8, Partial=0.5, Wrong/Missing=0.0
        """
        if self.total_symbols == 0:
            return 0.0
        score = (
            self.exact_matches * 1.0
            + self.semantic_matches * 0.8
            + self.partial_matches * 0.5
        )
        return (score / self.total_symbols) * 100

    @property
    def recovery_rate(self) -> float:
        """% of symbols that got any name (not FUN_xxx/sub_xxx etc)."""
        if self.total_symbols == 0:
            return 0.0
        named = self.total_symbols - self.missing_names
        return (named / self.total_symbols) * 100

    def to_dict(self) -> dict:
        return {
            "total_symbols": self.total_symbols,
            "exact_matches": self.exact_matches,
            "semantic_matches": self.semantic_matches,
            "partial_matches": self.partial_matches,
            "wrong_names": self.wrong_names,
            "missing_names": self.missing_names,
            "accuracy": round(self.accuracy, 2),
            "recovery_rate": round(self.recovery_rate, 2),
            # v1.10.0 eklemeleri
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "per_source_precision": {
                k: round(v, 4) for k, v in self.per_source_precision.items()
            },
            "per_source_recall": {
                k: round(v, 4) for k, v in self.per_source_recall.items()
            },
            "per_source_f1": {
                k: round(v, 4) for k, v in self.per_source_f1.items()
            },
            "confusion_matrix": {
                k: dict(v) for k, v in self.confusion_matrix.items()
            },
        }

    def summary(self) -> str:
        """Human-readable single-line summary."""
        return (
            f"accuracy={self.accuracy:.1f}% recovery={self.recovery_rate:.1f}% "
            f"f1={self.f1:.3f} "
            f"(exact={self.exact_matches} semantic={self.semantic_matches} "
            f"partial={self.partial_matches} wrong={self.wrong_names} "
            f"missing={self.missing_names} / total={self.total_symbols})"
        )


class AccuracyCalculator:
    """Calculates naming accuracy by comparing recovered vs original names.

    Uses a multi-tier comparison:
    1. Exact match (normalized) -> 1.0
    2. Semantic equivalence (synonym table) -> 0.8
    3. Partial component overlap (>= 40%) -> 0.5
    4. Otherwise -> 0.0 (wrong or missing)
    """

    # Common semantic equivalences grouped by domain.
    # Each key is a "canonical" word, values are synonyms.
    SEMANTIC_EQUIV: dict[str, set[str]] = {
        # --- I/O & Networking ---
        "send": {"transmit", "write", "emit", "dispatch", "post", "push", "output"},
        "recv": {"receive", "read", "get", "fetch", "input", "pull"},
        "connect": {"attach", "bind", "link", "join", "open"},
        "disconnect": {"detach", "unbind", "unlink", "close", "shutdown"},
        "listen": {"accept", "wait", "serve"},
        # --- Lifecycle ---
        "init": {"initialize", "setup", "create", "construct", "new", "start", "boot"},
        "destroy": {"cleanup", "teardown", "free", "delete", "release", "close", "fini",
                     "deinit", "shutdown", "dispose"},
        "reset": {"clear", "reinit", "restart", "flush"},
        # --- Parsing / Serialization ---
        "parse": {"decode", "deserialize", "read", "extract", "unpack", "unmarshal"},
        "serialize": {"encode", "marshal", "write", "format", "pack", "dump"},
        # --- Event handling ---
        "handle": {"process", "on", "dispatch", "callback", "handler"},
        "notify": {"signal", "emit", "fire", "trigger", "broadcast"},
        # --- Validation ---
        "check": {"validate", "verify", "test", "assert", "is", "ensure", "guard"},
        # --- CRUD ---
        "get": {"fetch", "read", "load", "retrieve", "query", "find", "lookup", "obtain"},
        "set": {"update", "write", "store", "save", "put", "assign", "configure"},
        "add": {"insert", "append", "push", "enqueue", "register"},
        "remove": {"delete", "erase", "pop", "dequeue", "unregister", "drop"},
        # --- Concurrency ---
        "lock": {"acquire", "enter", "begin", "grab", "take"},
        "unlock": {"release", "leave", "end", "drop", "give"},
        # --- Memory ---
        "alloc": {"malloc", "new", "create", "allocate", "calloc", "realloc"},
        "dealloc": {"free", "release", "destroy", "deallocate"},
        # --- Abbreviations / Aliases ---
        "size": {"length", "count", "num", "len", "total", "capacity"},
        "buf": {"buffer", "data", "bytes", "payload", "blob"},
        "msg": {"message", "packet", "frame", "datagram", "pdu"},
        "err": {"error", "fault", "failure", "exception", "status"},
        "ctx": {"context", "state", "env", "environment", "session"},
        "cfg": {"config", "configuration", "settings", "options", "prefs", "preferences"},
        "conn": {"connection", "socket", "link", "session", "channel"},
        "idx": {"index", "pos", "position", "offset", "cursor"},
        "ptr": {"pointer", "ref", "reference", "handle"},
        "str": {"string", "text", "name", "label"},
        "val": {"value", "result", "ret", "output"},
        "src": {"source", "origin", "from", "input"},
        "dst": {"destination", "target", "to", "output", "sink"},
        "cb": {"callback", "handler", "hook", "fn", "func", "function"},
        "tmp": {"temp", "temporary", "scratch"},
        "prev": {"previous", "last", "old", "prior"},
        "next": {"following", "subsequent", "after"},
        "cur": {"current", "active", "present", "now"},
        # --- Security / Crypto ---
        "encrypt": {"encipher", "encode", "seal", "protect", "cipher"},
        "decrypt": {"decipher", "decode", "unseal", "unprotect"},
        "hash": {"digest", "checksum", "fingerprint", "md5", "sha"},
        "sign": {"authenticate", "mac", "hmac", "verify_signature"},
        "key": {"secret", "token", "credential", "passkey"},
        "cert": {"certificate", "x509", "crt", "pem"},
        "auth": {"authenticate", "authorize", "login", "verify", "credentials"},
        "rand": {"random", "nonce", "iv", "salt", "seed", "entropy"},
        "cipher": {"aes", "des", "chacha", "rc4", "blowfish", "algorithm"},
        "tls": {"ssl", "secure", "handshake"},
        "perm": {"permission", "access", "privilege", "acl", "right"},
        # --- Logging / Debug ---
        "log": {"trace", "debug", "print", "dump", "record", "audit"},
        "warn": {"warning", "alert", "caution"},
        # --- Comparison ---
        "cmp": {"compare", "diff", "match", "equal", "eq"},
        "sort": {"order", "arrange", "rank"},
        "search": {"find", "locate", "scan", "grep", "lookup"},
        "copy": {"clone", "dup", "duplicate", "replicate"},
    }

    def __init__(self) -> None:
        # Build reverse lookup: word -> set of all equivalent words.
        # Each SEMANTIC_EQUIV entry defines one equivalence group.
        # A word may appear in multiple groups — we union them but
        # do NOT transitively merge groups (to avoid "encode" linking
        # serialize-group to encrypt-group and cascading everywhere).
        self._equiv_map: dict[str, set[str]] = {}
        for canonical, synonyms in self.SEMANTIC_EQUIV.items():
            group = synonyms | {canonical}
            for word in group:
                if word not in self._equiv_map:
                    self._equiv_map[word] = set(group)
                else:
                    self._equiv_map[word] |= group

    def compare_name(self, original: str, recovered: str) -> NamingResult:
        """Compare a recovered name against the original.

        Args:
            original: The ground truth name (from debug symbols).
            recovered: The name recovered by Karadul.

        Returns:
            NamingResult with score and match type.
        """
        # Missing check — still a Ghidra placeholder
        if self._is_unnamed(recovered):
            return NamingResult(original, recovered, 0.0, "missing")

        # Normalize both
        orig_norm = self._normalize(original)
        recv_norm = self._normalize(recovered)

        # Exact match (after normalization)
        if orig_norm == recv_norm:
            return NamingResult(original, recovered, 1.0, "exact")

        # Semantic match (same meaning, different words)
        if self._is_semantic_match(orig_norm, recv_norm):
            return NamingResult(original, recovered, 0.8, "semantic")

        # Partial match (some name components overlap)
        partial_score = self._partial_match_score(orig_norm, recv_norm)
        if partial_score >= 0.4:
            return NamingResult(original, recovered, 0.5, "partial")

        return NamingResult(original, recovered, 0.0, "wrong")

    def calculate_metrics(self, comparisons: list[NamingResult]) -> BenchmarkMetrics:
        """Calculate aggregate metrics from individual comparisons.

        v1.10.0 Batch 5A: F1 / precision / recall / per-source ve confusion
        matrix da hesaplanir.

        F1 tanimi (multi-class -> binary indirgeme):
            TP = exact + semantic + partial (anlamli dogru isim uretildi)
            FP = wrong (isim uretildi ama yanlis)
            FN = missing (isim uretilemedi, Ghidra placeholder)
            precision = TP / (TP + FP)
            recall    = TP / (TP + FN)
            F1        = 2*P*R / (P+R)
        """
        metrics = BenchmarkMetrics(total_symbols=len(comparisons))
        for c in comparisons:
            if c.match_type == "exact":
                metrics.exact_matches += 1
            elif c.match_type == "semantic":
                metrics.semantic_matches += 1
            elif c.match_type == "partial":
                metrics.partial_matches += 1
            elif c.match_type == "missing":
                metrics.missing_names += 1
            else:
                metrics.wrong_names += 1

        # Global F1 / precision / recall
        metrics.precision, metrics.recall, metrics.f1 = self._compute_prf(
            tp=metrics.exact_matches + metrics.semantic_matches + metrics.partial_matches,
            fp=metrics.wrong_names,
            fn=metrics.missing_names,
        )

        # Per-source kirilim
        per_src = self.compute_per_source(comparisons)
        metrics.per_source_precision = per_src["precision"]
        metrics.per_source_recall = per_src["recall"]
        metrics.per_source_f1 = per_src["f1"]

        # Confusion matrix (diagonal: match_type -> match_type)
        # Her match_type icin sayac, daha karmasik senaryolar icin cerceve.
        cm: dict[str, dict[str, int]] = {}
        for c in comparisons:
            mt = c.match_type or "unknown"
            cm.setdefault(mt, {}).setdefault(mt, 0)
            cm[mt][mt] += 1
        metrics.confusion_matrix = cm

        return metrics

    @staticmethod
    def _compute_prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
        """Precision, Recall, F1 hesapla. Sifir-bolme korumali."""
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        return prec, rec, f1

    def compute_per_source(
        self,
        comparisons: list[NamingResult],
    ) -> dict[str, dict[str, float]]:
        """Kaynak (source) bazli precision/recall/F1 hesapla.

        NamingResult.source alanina gore gruplandirir. Source="" olanlar
        "unknown" kategorisinde toplanir.

        Returns:
            {"precision": {source: val}, "recall": {source: val}, "f1": {source: val}}
        """
        buckets: dict[str, dict[str, int]] = {}
        for c in comparisons:
            src = c.source or "unknown"
            b = buckets.setdefault(src, {"tp": 0, "fp": 0, "fn": 0})
            if c.match_type in ("exact", "semantic", "partial"):
                b["tp"] += 1
            elif c.match_type == "missing":
                b["fn"] += 1
            else:  # wrong
                b["fp"] += 1

        out_p: dict[str, float] = {}
        out_r: dict[str, float] = {}
        out_f: dict[str, float] = {}
        for src, b in buckets.items():
            p, r, f = self._compute_prf(b["tp"], b["fp"], b["fn"])
            out_p[src] = p
            out_r[src] = r
            out_f[src] = f

        return {"precision": out_p, "recall": out_r, "f1": out_f}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    # Patterns matching Ghidra/IDA auto-generated placeholder names.
    # Kept in sync with karadul.reconstruction.c_namer patterns.
    _UNNAMED_PATTERNS = [
        re.compile(r"^FUN_[0-9a-fA-F]+$"),
        re.compile(r"^sub_[0-9a-fA-F]+$"),
        re.compile(r"^var_[0-9a-fA-F]+$"),
        re.compile(r"^local_[0-9a-fA-F]+$"),
        re.compile(r"^param_\d+$"),
        re.compile(r"^DAT_[0-9a-fA-F]+$"),
        re.compile(r"^field_0x[0-9a-fA-F]+$"),
        re.compile(r"^PTR_[0-9a-fA-F]+$"),
        re.compile(r"^[a-z]Var\d+$"),  # uVar1, iVar2 etc.
    ]

    def _is_unnamed(self, name: str) -> bool:
        """Check if name is still a Ghidra/IDA placeholder."""
        if not name:
            return True
        return any(p.match(name) for p in self._UNNAMED_PATTERNS)

    def _normalize(self, name: str) -> str:
        """Normalize a name for comparison.

        - Strip common prefixes (m_, s_, g_, p_, leading _)
        - Convert camelCase -> snake_case
        - Lowercase
        - Strip trailing underscores/digits used for dedup
        """
        # Remove common C/C++ prefixes
        name = re.sub(r"^(m_|s_|g_|p_|k_|_+)", "", name)
        # Convert camelCase to snake_case
        name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
        name = name.lower().strip("_")
        # Remove trailing numeric dedup suffixes (e.g. _2, _03)
        name = re.sub(r"_\d+$", "", name)
        return name

    def _is_semantic_match(self, orig: str, recv: str) -> bool:
        """Check if two normalized names are semantically equivalent.

        Expands each word part using the synonym table, then checks
        Jaccard similarity of expanded sets >= 0.5.
        """
        orig_parts = set(orig.split("_"))
        recv_parts = set(recv.split("_"))

        # Remove empty parts
        orig_parts.discard("")
        recv_parts.discard("")

        if not orig_parts or not recv_parts:
            return False

        # Expand both with equivalences
        orig_expanded = self._expand_parts(orig_parts)
        recv_expanded = self._expand_parts(recv_parts)

        overlap = orig_expanded & recv_expanded
        union = orig_expanded | recv_expanded
        if not union:
            return False
        jaccard = len(overlap) / len(union)
        return jaccard >= 0.5

    def _expand_parts(self, parts: set[str]) -> set[str]:
        """Expand a set of name parts with their semantic equivalences."""
        expanded = set()
        for p in parts:
            expanded.add(p)
            if p in self._equiv_map:
                expanded |= self._equiv_map[p]
        return expanded

    def _partial_match_score(self, orig: str, recv: str) -> float:
        """Calculate partial match score based on common name components.

        Returns the ratio of common parts to the max part count.
        """
        orig_parts = set(orig.split("_"))
        recv_parts = set(recv.split("_"))

        orig_parts.discard("")
        recv_parts.discard("")

        if not orig_parts or not recv_parts:
            return 0.0

        common = orig_parts & recv_parts
        return len(common) / max(len(orig_parts), len(recv_parts))
