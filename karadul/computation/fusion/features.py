"""Signature fusion icin 4 aile feature extractor.

Aileler:
    1. shape     -- byte skoru, CFG hash benzerligi, fonksiyon boyutu, compiler
    2. proto     -- parametre sayisi, return type, calling convention, decompiler conf
    3. context   -- callgraph pozisyonu, caller/callee Jaccard, import bagsami
    4. interaction -- shape x context cross-term (byte+CFG double-counting KARSITI)

Her feature [~ -1, +1] araligi hedefli tasarlanmistir; log-odds ensemble
icin makul buyuklukte. Missing sinyal -> 0 (neutral prior).

KRITIK NOT (codex):
    byte_score ve cfg_hash_similarity yuksek KORELEDIR (ayni compiler +
    ayni kaynak -> benzer byte *ve* benzer CFG). Naive toplamak
    double-counting yapar. Cozum:
      - interaction_features() -> byte x context cross term
      - ensemble agirliklari shape alanina DAHA DUSUK katsayi verir
      - Platt calibration final olasiligi duzeltir
"""

from __future__ import annotations

from typing import Optional

from karadul.computation.fusion.types import SignatureCandidate


# ---------------------------------------------------------------------------
# Yardimcilar
# ---------------------------------------------------------------------------


def _hash_similarity(a: str, b: str) -> float:
    """Iki WL hash (hex string) arasi karakter-bazli benzerlik.

    Tam esit -> 1.0; farkli uzunluk veya hicbir karakter eslesmiyorsa 0.0.
    Hash fonksiyonunun yapisi geregi benzer CFG'ler benzer hash uretmez,
    bu yuzden bu metrik `tam esleme` vs `eslememe` ikilisi gibi davranir
    (soft gradasyon sadece kismi hash eslesmesi icin).
    """
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    # Kismi eslesme: ortak prefix orani (LSH bucket ipucu)
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    common = sum(1 for i in range(n) if a[i] == b[i])
    return common / max(len(a), len(b))


def _jaccard(a: Optional[list[str]], b: Optional[list[str]]) -> float:
    if not a or not b:
        return 0.0
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    if union == 0:
        return 0.0
    return inter / union


def _size_similarity(s1: int, s2: int) -> float:
    """Fonksiyon boyut oranlari -- ne kadar yakinsa o kadar 1.0."""
    if s1 <= 0 or s2 <= 0:
        return 0.0
    ratio = min(s1, s2) / max(s1, s2)
    return ratio  # [0, 1]


# ---------------------------------------------------------------------------
# Shape family
# ---------------------------------------------------------------------------


def shape_features(c: SignatureCandidate) -> dict[str, float]:
    """Byte + CFG + boyut + compiler yapisal sinyalleri.

    Returns:
        dict: {
            "byte_score": [0, 1],
            "cfg_hash_similarity": [0, 1],
            "func_size_normalized": [0, 1] -- log-olcekli fonksiyon boyutu,
            "compiler_match": 0.0 veya 1.0 (unknown ise 0.5).
        }
    """
    out: dict[str, float] = {}
    out["byte_score"] = max(0.0, min(1.0, float(c.byte_score)))

    if c.reference_cfg_hash and c.cfg_hash:
        out["cfg_hash_similarity"] = _hash_similarity(
            c.cfg_hash, c.reference_cfg_hash,
        )
    else:
        # Referans yoksa cfg_hash varlikligini soft sinyal olarak kullan
        out["cfg_hash_similarity"] = 0.0

    # Boyut normalize: log(size+1) / log(10000+1) ~ [0,1].
    # Tipik fonksiyon 50-5000 byte, log-olcek outlier'i dusurur.
    from math import log1p
    if c.func_size > 0:
        out["func_size_normalized"] = min(1.0, log1p(c.func_size) / log1p(10000))
    else:
        out["func_size_normalized"] = 0.0

    cb = (c.compiler_bucket or "unknown").lower()
    if cb == "unknown":
        out["compiler_match"] = 0.5  # Neutral -- bilgimiz yok
    elif cb in {"gcc", "clang", "msvc"}:
        out["compiler_match"] = 1.0
    else:
        out["compiler_match"] = 0.0

    return out


# ---------------------------------------------------------------------------
# Proto family
# ---------------------------------------------------------------------------


def proto_features(c: SignatureCandidate) -> dict[str, float]:
    """Prototype sinyalleri: param count, return type, CC, decompiler conf."""
    out: dict[str, float] = {}

    # param_count_match: aday vs reference
    if c.param_count is not None and c.reference_param_count is not None:
        if c.param_count == c.reference_param_count:
            out["param_count_match"] = 1.0
        else:
            # 1 fark -> 0.5; 2+ fark -> 0.0 (degismemis variadic toleransi)
            delta = abs(c.param_count - c.reference_param_count)
            out["param_count_match"] = max(0.0, 1.0 - 0.5 * delta)
    else:
        out["param_count_match"] = 0.0

    # return_type_match
    if c.return_type is not None and c.reference_return_type is not None:
        out["return_type_match"] = 1.0 if c.return_type == c.reference_return_type else 0.0
    else:
        out["return_type_match"] = 0.0

    # cc_match: bool -> 1/0; None -> 0 (neutral)
    if c.cc_match is True:
        out["cc_match"] = 1.0
    elif c.cc_match is False:
        out["cc_match"] = 0.0
    else:
        out["cc_match"] = 0.0  # unknown ~ neutral penalty (0)

    # decompiler_conf: zaten [0,1]
    if c.decompiler_conf is not None:
        out["decompiler_conf"] = max(0.0, min(1.0, float(c.decompiler_conf)))
    else:
        out["decompiler_conf"] = 0.0

    return out


# ---------------------------------------------------------------------------
# Context family
# ---------------------------------------------------------------------------


def context_features(c: SignatureCandidate) -> dict[str, float]:
    """Callgraph + import context sinyalleri."""
    out: dict[str, float] = {}

    # callgraph_position: caller + callee Jaccard ortalama
    if c.callgraph_pos is not None:
        callers = c.callgraph_pos.get("callers") or []
        callees = c.callgraph_pos.get("callees") or []
        ref_callers = c.reference_callers or []
        ref_callees = c.reference_callees or []
        j_cal = _jaccard(callers, ref_callers)
        j_cee = _jaccard(callees, ref_callees)
        out["callgraph_position"] = (j_cal + j_cee) / 2.0
    else:
        out["callgraph_position"] = 0.0

    # caller_overlap: explicit precomputed Jaccard
    if c.caller_overlap is not None:
        out["caller_callee_overlap"] = max(0.0, min(1.0, float(c.caller_overlap)))
    else:
        # callgraph_pos varsa ondan turetilen Jaccard'i geri kullan
        out["caller_callee_overlap"] = out.get("callgraph_position", 0.0)

    # import_context_similarity: import listesi Jaccard
    if c.import_context and c.reference_imports:
        out["import_context_similarity"] = _jaccard(
            c.import_context, c.reference_imports,
        )
    else:
        out["import_context_similarity"] = 0.0

    return out


# ---------------------------------------------------------------------------
# Interaction (decorrelation) family
# ---------------------------------------------------------------------------


def interaction_features(c: SignatureCandidate) -> dict[str, float]:
    """shape x context cross-term -- byte+CFG double counting karsiti.

    Rationale: shape sinyali guclu AMA context zayifsa, olusi eslesme
    riski var (ayni CFG farkli bir sembole ait olabilir). Context de
    dogrularsa confidence yukselmeli; context zayifsa shape tek basina
    tam guven vermemeli.

    UYARI (M5): ``shape_mean`` ``byte_score``'u iceriyor, yani ``w_shape *
    byte_score`` ile ``w_interaction * shape_x_context`` arasinda
    kismi double-count vardir. Default ``w_interaction=1.4`` EMPIRIK
    validation data uzerinde FIT EDILMEMISTIR; bu katsayi elle secilmis
    bir ilk tahmindir. Production deploy oncesinde gercek (logit, label)
    ciftleri uzerinde ``FusionWeights``'un tumu birlikte fit edilmeli,
    aksi halde shape-heavy adaylar sistematik overconfidence alabilir.

    Returns:
        dict: {
            "shape_x_context": shape_mean * context_mean,
            "proto_x_context": proto_mean * context_mean,
            "shape_weighted_context": shape x callgraph_position,
        }
    """
    shape = shape_features(c)
    proto = proto_features(c)
    ctx = context_features(c)

    shape_mean = sum(shape.values()) / max(1, len(shape))
    proto_mean = sum(proto.values()) / max(1, len(proto))
    ctx_mean = sum(ctx.values()) / max(1, len(ctx))

    return {
        "shape_x_context": shape_mean * ctx_mean,
        "proto_x_context": proto_mean * ctx_mean,
        "shape_weighted_context": shape.get("byte_score", 0.0)
        * ctx.get("callgraph_position", 0.0),
    }


def all_features(c: SignatureCandidate) -> dict[str, float]:
    """4 aileyi tek dict'te birlestir (flat, isim catismasi yok)."""
    out: dict[str, float] = {}
    out.update(shape_features(c))
    out.update(proto_features(c))
    out.update(context_features(c))
    out.update(interaction_features(c))
    return out
