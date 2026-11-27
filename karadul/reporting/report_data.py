"""Rapor verisi katmanı: her rapor bölümü verisini adı belli bir yapıttan alır.

Dört raporlayıcı (JSON, Markdown, HTML, SARIF) ve temiz çıktının HTML üreticisi
(``core/report_generator.py``) bölümlerini buradan okur; böylece aynı koşu için aynı
şeyi söylerler (P07, RAPOR §3 T2).

Her bölüm (``Section``) bir durum taşır. Yapıt yoksa, tarama yapılamadıysa ya da durum
kaydedilmemişse bölüm bunu ve nedenini söyler; 0 ya da boş göstermez.

Durumlar:
  - ``findings``: tarama tamam (ya da kısmi değil), en az bir bulgu.
  - ``clean``: tarama tamamlandı, bulgu yok (P-S1 ``calisti`` + 0).
  - ``partial``: tarama eksik (P-S1 ``kismi``); bulgular gerçek, sayı alt sınır.
  - ``status_unknown``: yapıt var ama taramanın durumu kaydedilmemiş (P-S1 öncesi yapıt);
    0 bulgu "temiz" mi "tarama düştü" mü ayırt edilemez.
  - ``not_scanned``: tarama yapılamadı (hata, araç yok).
  - ``unsupported``: girdi aracın kapsamı dışında.
  - ``disabled``: ayarla kapalı.
  - ``no_data``: yapıt yok ya da gereken alanlar kaydedilmemiş.

Okunan yapıtlar ve alanlar (sözleşme):
  - ``static/anti_debug_findings.json``: ``status``, ``status_reason``, ``file_size``,
    ``scanned_bytes``, ``layers``, ``findings`` (P-S1); P-S1 öncesi yapıtta durum yok, durum
    ``reconstruct.stats.anti_debug_status``'tan (eski sözlük ``ok/disabled/no_binary/
    module_missing/error``).
  - ``static/packer_fingerprints.json``: aynı düzen; ``fingerprints``;
    eski durum ``reconstruct.stats.packer_fingerprint_status``.
  - ``static.stats``: ``yara_status``, ``yara_status_reason``, ``yara_hits`` (P-S1 yapılandırılmış
    kayıt), ``yara_matches``, ``yara_backend``, ``detected_tech`` (eski düz dizgi
    ``"<kural> (<etiket>,...)"``; ``yara_hits`` varsa okunmaz, aynı isabet iki kez sayılmasın).
  - ``static.stats`` ``capa_status`` / ``capa_status_reason`` / ``capa_backend`` /
    ``capa_code_feed`` ve ``static/capa_scan.json`` (P-S1; ``capa_capabilities.json`` yalnız
    koda besleme bayrağı açıkken yazılır). K-1: capa yetenekleri doğrulanmamış adaydır;
    bölüm yalnız durumu ve sayıyı verir, yetenek adlarını iddia gibi göstermez.
  - ``reconstructed/signature_matches.json`` (şema 2: ``family`` / ``tier`` / ``category`` /
    ``libraries``) ve ``reconstruct.stats.sigdb_status`` / ``sigdb_ioc_matches`` (P08).
  - ``reconstructed/algorithms.json`` (``algorithms[]``: ``name``, ``category``,
    ``confidence``, ``function``, ``evidence``).
  - ``reconstructed/algorithm_compositions.json``: ``compositions`` (kapıdan geçmiş) ve
    ``total_pending`` / ``pending_compositions`` (K-1: iddia değil, yalnız sayı gösterilir).
  - ``reconstruct.stats``: ``variables_renamed``, ``naming_by_label`` (ad etiketi dağılımı).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from karadul.analyzers.ustveri.tutarlilik import DAMGA_TUTARSIZ, KARAR_UST_VERI_SUPHELI, KARAR_UYARI
from karadul.core.naming_labels import (
    LABEL_CERTAIN,
    LABEL_METADATA,
    LABEL_UNVERIFIED,
    LABEL_VERIFIED,
    SOURCE_GO_PCLNTAB,
)

logger = logging.getLogger(__name__)

SECTION_FINDINGS = "findings"
SECTION_CLEAN = "clean"
SECTION_PARTIAL = "partial"
SECTION_UNKNOWN = "status_unknown"
SECTION_NOT_SCANNED = "not_scanned"
SECTION_UNSUPPORTED = "unsupported"
SECTION_DISABLED = "disabled"
SECTION_NO_DATA = "no_data"

ALL_SECTION_STATUSES = (
    SECTION_FINDINGS, SECTION_CLEAN, SECTION_PARTIAL, SECTION_UNKNOWN,
    SECTION_NOT_SCANNED, SECTION_UNSUPPORTED, SECTION_DISABLED, SECTION_NO_DATA,
)
# Bulgu listesi gösterilen durumlar (kısmi taramada bulunanlar gerçektir).
SECTION_STATUSES_WITH_ITEMS = (SECTION_FINDINGS, SECTION_PARTIAL, SECTION_UNKNOWN)

# P-S1 / P03 tarama durum sözlüğü -> bölüm durumu (bulgu sayısına göre findings/clean).
_SCAN_STATUS_MAP = {
    "calisti": None,  # bulgu sayısına göre
    "kismi": SECTION_PARTIAL,
    "hata": SECTION_NOT_SCANNED,
    "arac_yok": SECTION_NOT_SCANNED,
    "desteklenmiyor": SECTION_UNSUPPORTED,
    "kapali": SECTION_DISABLED,
}
# P-S1 öncesi adım istatistiği (anti_debug_status / packer_fingerprint_status).
_LEGACY_STEP_STATUS_MAP = {
    "ok": None,  # durum güvenilmez: üç katman düşse de "ok" yazılıyordu (P-S1 kalem 1)
    "disabled": SECTION_DISABLED,
    "no_binary": SECTION_NOT_SCANNED,
    "module_missing": SECTION_NOT_SCANNED,
    "error": SECTION_NOT_SCANNED,
}

# KRDL001 (kriptografik algoritma) sayılan algoritma kategorileri
# (``reconstruction/c_algorithm_id.py`` kategori adları). compression / encoding /
# checksum kripto değildir.
CRYPTO_CATEGORIES = frozenset({
    "symmetric_cipher", "asymmetric", "hash", "mac", "kdf", "key_management",
    "random", "protocol",
})

# Bilinen zararlı yazılım aileleri (``analyzers/sigdb_builtin/malware_tier1.py``).
IOC_FAMILIES = frozenset({"sliver", "cobaltstrike"})

# Eski düz dizgi YARA kaydı: "<kural> (<etiket>,<etiket>)"
_DETECTED_TECH_RE = re.compile(r"^\s*(?P<rule>[^()\s]+)\s*\((?P<tags>[^()]*)\)\s*$")


@dataclass
class Section:
    """Bir rapor bölümünün verisi ve durumu."""

    key: str
    title: str
    status: str
    source: str
    summary: str
    reason: str = ""
    items: list[dict[str, Any]] = field(default_factory=list)
    count: Optional[int] = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def has_items(self) -> bool:
        return self.status in SECTION_STATUSES_WITH_ITEMS and bool(self.items)

    def to_dict(self, include_items: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "status": self.status,
            "source": self.source,
            "summary": self.summary,
            "reason": self.reason or None,
            "count": self.count,
        }
        if self.extra:
            d["extra"] = self.extra
        if include_items:
            d["items"] = self.items
        return d


@dataclass
class ReportData:
    """Bütün bölümler ve sayaçlar (kaynağı olmayan sayaç ``None``)."""

    sections: dict[str, Section]
    counters: dict[str, Any]

    def section(self, key: str) -> Section:
        return self.sections[key]


# Bölüm sırası (bütün üreticilerde aynı).
SECTION_ORDER = ("packer", "anti_debug", "yara", "capa", "ioc", "crypto", "naming", "compositions")


# ---------------------------------------------------------------------------
# yardımcılar
# ---------------------------------------------------------------------------

def _stage_stats(result: Any, name: str) -> Optional[dict[str, Any]]:
    stages = getattr(result, "stages", None) or {}
    sr = stages.get(name)
    if sr is None:
        return None
    stats = getattr(sr, "stats", None)
    return stats if isinstance(stats, dict) else {}


def _stage_state(result: Any, name: str) -> tuple[bool, str]:
    """(aşama çalıştı ve başarısız değil mi, değilse neden)."""
    stages = getattr(result, "stages", None) or {}
    sr = stages.get(name)
    if sr is None:
        return False, f"'{name}' stage did not run"
    if getattr(sr, "skipped", False):
        reason = (getattr(sr, "stats", None) or {}).get("skip_reason")
        return False, f"'{name}' stage skipped" + (f": {' '.join(str(reason).split())}" if reason else "")
    return True, ""


def _load(workspace: Any, stage: str, name: str) -> Optional[dict[str, Any]]:
    try:
        data = workspace.load_json(stage, name)
    except Exception:  # bozuk yapıt raporu düşürmesin
        logger.debug("rapor verisi: %s/%s okunamadi", stage, name, exc_info=True)
        return None
    return data if isinstance(data, dict) else None


def _int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _scan_status(artifact: Optional[dict[str, Any]], legacy_status: Any) -> tuple[Optional[str], str, bool]:
    """(bölüm durumu ya da None = bulguya göre, neden, durum kaydı var mı)."""
    if artifact is not None and isinstance(artifact.get("status"), str):
        st = artifact["status"]
        reason = str(artifact.get("status_reason") or "")
        if st in _SCAN_STATUS_MAP:
            return _SCAN_STATUS_MAP[st], reason, True
        return SECTION_NO_DATA, f"unknown scan status '{st}'", True
    if isinstance(legacy_status, str) and legacy_status in _LEGACY_STEP_STATUS_MAP:
        mapped = _LEGACY_STEP_STATUS_MAP[legacy_status]
        reason = f"step status '{legacy_status}'"
        return mapped, reason, mapped is not None
    return None, "", False


def resolve_score(data: dict[str, Any], items: list[dict[str, Any]], summary_key: str) -> Optional[float]:
    """Önem skoru: üst düzey ``score`` -> ``summary[summary_key]`` -> ``summary.max_confidence``
    -> bulguların en yüksek ``confidence``'ı. Bulgu yoksa ve skor kaydı yoksa ``None``.

    Dedektör yapıtlarında üst düzey ``score`` yoktur (``summary.anti_debug_score`` var);
    eski raporlayıcının öncelik sırası korunur.
    """
    candidates: list[Any] = [data.get("score")]
    summary = data.get("summary")
    if isinstance(summary, dict):
        candidates += [summary.get(summary_key), summary.get("max_confidence")]
    for raw in candidates:
        if raw is None or isinstance(raw, bool):
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    confs: list[float] = []
    for it in items:
        try:
            confs.append(float(it.get("confidence", 0.0)))
        except (TypeError, ValueError):
            pass
    return max(confs) if confs else None


def _byte_note(artifact: Optional[dict[str, Any]]) -> str:
    if not artifact:
        return ""
    size, scanned = artifact.get("file_size"), artifact.get("scanned_bytes")
    if isinstance(size, int) and isinstance(scanned, int):
        return f"scanned {scanned:,} / {size:,} bytes"
    return ""


def _layer_note(artifact: Optional[dict[str, Any]]) -> str:
    layers = (artifact or {}).get("layers")
    if not isinstance(layers, dict):
        return ""
    parts = []
    for name, info in layers.items():
        if isinstance(info, dict) and info.get("status") and info.get("status") != "calisti":
            r = info.get("reason") or ""
            parts.append(f"{name} layer {info['status']}" + (f" ({r})" if r else ""))
    return "; ".join(parts)


def _finish_scan_section(
    key: str, title: str, source: str, items: list[dict[str, Any]],
    mapped: Optional[str], reason: str, recorded: bool, noun: str, clean_text: str,
    extra_note: str = "",
) -> Section:
    n = len(items)
    note = f" ({extra_note})" if extra_note else ""
    if mapped is None and recorded:
        status = SECTION_FINDINGS if n else SECTION_CLEAN
        summary = (f"{n} {noun} found{note}" if n else f"{clean_text}{note}")
        return Section(key, title, status, source, summary, items=items, count=n)
    if mapped is None:  # durum kaydı yok (P-S1 öncesi yapıt)
        summary = (
            f"{n} {noun} found; scan status not recorded (artifact predates scan-status "
            "fields), so a scan failure cannot be ruled out"
            if n else
            f"0 {noun} recorded, but the scan status was not recorded (artifact predates "
            "scan-status fields): 'clean' cannot be distinguished from 'scan failed'"
        )
        return Section(key, title, SECTION_UNKNOWN, source, summary, items=items, count=None)
    if mapped == SECTION_PARTIAL:
        summary = (f"partial scan ({reason or 'reason not recorded'}); {n} {noun} found, "
                   "a lower bound")
        return Section(key, title, mapped, source, summary, reason=reason, items=items, count=None)
    # Durum etiketi (status_label) ayrıca yazılır; özet yalnız nedeni söyler.
    summary = reason or "reason not recorded"
    return Section(key, title, mapped, source, summary, reason=reason, count=None)


def _missing(key: str, title: str, source: str, reason: str) -> Section:
    return Section(key, title, SECTION_NO_DATA, source, reason, reason=reason)


# ---------------------------------------------------------------------------
# bölümler
# ---------------------------------------------------------------------------

def _anti_debug(result: Any, workspace: Any) -> Section:
    key, title, src = "anti_debug", "Anti-Debug Findings", "static/anti_debug_findings.json"
    data = _load(workspace, "static", "anti_debug_findings")
    legacy = (_stage_stats(result, "reconstruct") or {}).get("anti_debug_status")
    if data is None:
        mapped, reason, recorded = _scan_status(None, legacy)
        if recorded and mapped is not None:
            return _finish_scan_section(key, title, src, [], mapped, reason, True, "", "")
        ran, why = _stage_state(result, "reconstruct")
        return _missing(key, title, src, "artifact not written" + (f" ({why})" if not ran else ""))
    items = [f for f in (data.get("findings") or []) if isinstance(f, dict)]
    mapped, reason, recorded = _scan_status(data, legacy)
    note = "; ".join(x for x in (_byte_note(data), _layer_note(data)) if x)
    sec = _finish_scan_section(key, title, src, items, mapped, reason, recorded,
                               "anti-debug technique(s)", "scanned, no anti-debug technique found",
                               note)
    score = resolve_score(data, items, "anti_debug_score")
    if score is not None:
        sec.extra["score"] = score
    return sec


def _packer(result: Any, workspace: Any) -> Section:
    key, title, src = "packer", "Detected Packer", "static/packer_fingerprints.json"
    data = _load(workspace, "static", "packer_fingerprints")
    legacy = (_stage_stats(result, "reconstruct") or {}).get("packer_fingerprint_status")
    if data is None:
        mapped, reason, recorded = _scan_status(None, legacy)
        if recorded and mapped is not None:
            return _finish_scan_section(key, title, src, [], mapped, reason, True, "", "")
        ran, why = _stage_state(result, "reconstruct")
        return _missing(key, title, src, "artifact not written" + (f" ({why})" if not ran else ""))
    raw = data.get("fingerprints")
    if raw is None:  # eski sentetik şema
        raw = data.get("packers") or data.get("findings") or []
    items = [p for p in raw if isinstance(p, dict)]
    mapped, reason, recorded = _scan_status(data, legacy)
    sec = _finish_scan_section(key, title, src, items, mapped, reason, recorded,
                               "packer fingerprint(s)", "scanned, no packer detected",
                               _byte_note(data))
    score = resolve_score(data, items, "score")
    if score is not None:
        sec.extra["score"] = score
    return sec


def yara_hit_from_detected_tech(text: Any) -> dict[str, Any]:
    """Eski düz dizgi kaydını (``"<kural> (<etiket>,...)"``) kural + etikete ayır."""
    if isinstance(text, dict):  # {name, type} biçimi
        tag = str(text.get("type") or "")
        return {"rule": str(text.get("name") or "?"), "tags": [tag] if tag and tag != "unknown" else [],
                "meta": {}, "strings": [], "legacy": True}
    m = _DETECTED_TECH_RE.match(str(text))
    if not m:
        return {"rule": str(text).strip(), "tags": [], "meta": {}, "strings": [], "legacy": True}
    tags = [t.strip() for t in m.group("tags").split(",") if t.strip() and t.strip() != "unknown"]
    return {"rule": m.group("rule"), "tags": tags, "meta": {}, "strings": [], "legacy": True}


def _yara(result: Any, workspace: Any) -> Section:
    key, title, src = "yara", "YARA Matches", "static.stats (yara_status, yara_hits)"
    st = _stage_stats(result, "static")
    if st is None:
        return _missing(key, title, src, "static stage did not run")
    hits_raw = st.get("yara_hits")
    status = st.get("yara_status")
    if isinstance(status, str):
        reason = str(st.get("yara_status_reason") or "")
        mapped = _SCAN_STATUS_MAP.get(status, SECTION_NO_DATA)
        items = [h for h in (hits_raw or []) if isinstance(h, dict)] if isinstance(hits_raw, list) else []
        if mapped is None and not isinstance(hits_raw, list) and st.get("detected_tech"):
            items = [yara_hit_from_detected_tech(t) for t in st.get("detected_tech") or []]
        note = f"backend {st['yara_backend']}" if st.get("yara_backend") else ""
        sec = _finish_scan_section(key, title, src, items, mapped, reason, True,
                                   "YARA rule match(es)", "scanned, no YARA rule matched", note)
    elif st.get("yara_backend") or st.get("yara_matches") or st.get("detected_tech"):
        # P-S1 öncesi: alanlar yalnız eşleşme varken yazılıyordu; isabetler düz dizgi.
        items = [yara_hit_from_detected_tech(t) for t in st.get("detected_tech") or []]
        sec = _finish_scan_section(key, title, src, items, None, "", False,
                                   "YARA rule match(es)", "")
    else:
        sec = _missing(key, title, src,
                       "YARA status not recorded (before scan-status fields, YARA fields were "
                       "written only when a rule matched): 'no match' cannot be distinguished "
                       "from 'not scanned'")
    sec.extra["rules_loaded"] = _int_or_none(st.get("yara_rules_loaded"))
    return sec


def _capa(result: Any, workspace: Any) -> Section:
    key, title, src = "capa", "capa Capabilities", "static.stats (capa_status) + static/capa_scan.json"
    st = _stage_stats(result, "static")
    if st is None:
        return _missing(key, title, src, "static stage did not run")
    status = st.get("capa_status")
    scan = _load(workspace, "static", "capa_scan")
    if not isinstance(status, str):
        if st.get("capa_rules_matched") is not None:
            n = _int_or_none(st.get("capa_rules_matched"))
            return Section(key, title, SECTION_UNKNOWN, "static.stats (capa_rules_matched)",
                           f"{n} capa rule(s) matched; status fields not recorded. Capabilities "
                           "are unverified candidates (decision K-1) and are not listed here",
                           count=None)
        return _missing(key, title, src, "capa status not recorded")
    reason = str(st.get("capa_status_reason") or "")
    mapped = _SCAN_STATUS_MAP.get(status, SECTION_NO_DATA)
    if mapped is not None:
        return _finish_scan_section(key, title, src, [], mapped, reason, True, "", "")
    rules = _int_or_none((scan or {}).get("total_rules_matched"))
    if rules is None:
        rules = _int_or_none(st.get("capa_rules_matched"))
    funcs = _int_or_none((scan or {}).get("total_functions_matched"))
    if funcs is None:
        funcs = _int_or_none(st.get("capa_functions_matched"))
    if rules is None:
        return _missing(key, title, src, "capa ran but its result was not recorded")
    status_out = SECTION_FINDINGS if rules else SECTION_CLEAN
    summary = (
        f"{rules} capa rule(s) matched in {funcs if funcs is not None else 'an unknown number of'} "
        "function(s). Unverified candidates (decision K-1): capa capabilities are not verified "
        "by Karadul and are not listed as findings; raw output in static/capa_scan.json"
        if rules else "scanned, no capa rule matched"
    )
    sec = Section(key, title, status_out, src, summary, count=rules)
    sec.extra["functions_matched"] = funcs
    sec.extra["backend"] = st.get("capa_backend") or (scan or {}).get("backend") or None
    sec.extra["code_feed"] = st.get("capa_code_feed")
    return sec


def _signature_claim(m: dict[str, Any]) -> str:
    """İmza kaydının iddia türü (P15c): kayıtta yazılıysa o, yoksa yöntemden türetilir.

    ``string_ref`` / ``call_pattern`` → ``davranis`` (betimleyici tahmin, kimlik değil);
    öbür yöntemler → ``kimlik``. Kural tek yerde: ``signature_db.claim_for_method``.
    """
    from karadul.analyzers.signature_db import CLAIM_BEHAVIOR, CLAIM_IDENTITY, claim_for_method
    claim = m.get("claim")
    if claim in (CLAIM_IDENTITY, CLAIM_BEHAVIOR):
        return str(claim)
    return claim_for_method(str(m.get("method") or m.get("match_method") or ""))


def _is_ioc(m: dict[str, Any]) -> bool:
    # P15c: davranış tahmini (dizgi / çağrı deseni) bilinen bir zararlı simgenin KİMLİĞİ değildir.
    from karadul.analyzers.signature_db import CLAIM_BEHAVIOR
    if _signature_claim(m) == CLAIM_BEHAVIOR:
        return False
    family = str(m.get("family") or "").lower()
    return (family in IOC_FAMILIES or str(m.get("tier") or "") == "1"
            or str(m.get("category") or "").lower() == "malware")


def _sigdb_note(db: dict[str, Any], st: Optional[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    """İmza veritabanının künyesi (IMZA-11 / P15b): kimlik, şema, uyarı, veri kökü.

    Değer ``signature_matches.json``'daki ``database`` bloğundan, yoksa aşama istatistiğinden;
    ikisinde de yoksa yazılmaz (uydurulmaz).
    """
    def pick(key: str) -> Any:
        value = db.get(key)
        return value if value is not None else (st or {}).get(key)

    info = {k: pick(k) for k in ("sigdb_build_id", "sigdb_schema_version", "sigdb_schema_warning",
                                 "sigdb_path_source", "sigdb_lmdb_symbol_count", "sigdb_data_root",
                                 "sigdb_data_root_source")}
    parts: list[str] = []
    if info["sigdb_build_id"]:
        parts.append(f"signature database {info['sigdb_build_id']}")
    if info["sigdb_schema_version"] is not None:
        parts.append(f"schema {info['sigdb_schema_version']}")
    if info["sigdb_lmdb_symbol_count"] is not None:
        parts.append(f"{info['sigdb_lmdb_symbol_count']} names")
    if info["sigdb_path_source"]:
        parts.append(f"from {info['sigdb_path_source']}")
    if info["sigdb_data_root"]:
        src = f" ({info['sigdb_data_root_source']})" if info["sigdb_data_root_source"] else ""
        parts.append(f"data root {info['sigdb_data_root']}{src}")
    if info["sigdb_schema_warning"]:
        parts.append(f"WARNING: {info['sigdb_schema_warning']}")
    return ", ".join(parts), {k: v for k, v in info.items() if v is not None}


def _ioc(result: Any, workspace: Any) -> Section:
    key, title = "ioc", "Malware IOC"
    src = "reconstructed/signature_matches.json + reconstruct.stats (sigdb_status)"
    st = _stage_stats(result, "reconstruct")
    data = _load(workspace, "reconstructed", "signature_matches")
    legacy_path = False
    if data is None:
        data = _load(workspace, "static", "signature_matches")  # eski yol
        legacy_path = data is not None
    sig_status = (st or {}).get("sigdb_status")
    if data is None and st is None:
        return _missing(key, title, src, "reconstruct stage did not run")
    if sig_status in ("error", "unavailable"):
        why = (st or {}).get("sigdb_lmdb_error") or f"sigdb_status '{sig_status}'"
        return Section(key, title, SECTION_NOT_SCANNED, src,
                       f"signature database {sig_status} ({why})",
                       reason=str(why))
    db = (data or {}).get("database") if isinstance((data or {}).get("database"), dict) else {}
    # P15c kalem 8: künye, şema uyarısı ve veri kökü raporda (eskiden yalnız build_id).
    db_note, db_info = _sigdb_note(db, st)
    if data is None:
        if sig_status == "no_match":
            sec = Section(key, title, SECTION_CLEAN, src,
                          "no signature matched, so no known-malware (Sliver / Cobalt Strike) "
                          "symbol matched" + (f" ({db_note})" if db_note else ""), count=0)
            if db_info:
                sec.extra["database"] = db_info
            return sec
        return _missing(key, title, src, "signature matches not written and signature database "
                        "status not recorded")
    raw = data.get("matches") or data.get("signature_matches") or []
    matches = [m for m in raw if isinstance(m, dict)]
    schema = data.get("schema")
    has_fields = any(("family" in m or "tier" in m or "category" in m) for m in matches)
    if not (isinstance(schema, int) and schema >= 2) and not has_fields:
        return _missing(key, title, src,
                        "signature records carry no family / tier / category fields "
                        f"(schema {schema or 1}{', legacy static/ path' if legacy_path else ''}): "
                        "IOC matches cannot be told apart")
    iocs = [m for m in matches if _is_ioc(m)]
    # P15c (K-2): dizgi / çağrı deseni kayıtları fonksiyonun kimliği değil, davranış tahminidir;
    # sayımda ayrı yazılır ki "N imza eşleşmesi" N kimlik iddiası gibi okunmasın.
    from karadul.analyzers.signature_db import CLAIM_BEHAVIOR, CLAIM_IDENTITY
    claims = {CLAIM_IDENTITY: 0, CLAIM_BEHAVIOR: 0}
    for m in matches:
        claims[_signature_claim(m)] += 1
    claim_txt = (f"{claims[CLAIM_IDENTITY]} identity (symbol / byte pattern), "
                 f"{claims[CLAIM_BEHAVIOR]} behaviour guess(es) (string / call pattern: describes "
                 "what the function does, not which function it is)")
    if iocs:
        fams: dict[str, int] = {}
        for m in iocs:
            f = str(m.get("family") or "?")
            fams[f] = fams.get(f, 0) + 1
        fam_txt = ", ".join(f"{k}: {v}" for k, v in sorted(fams.items()))
        sec = Section(key, title, SECTION_FINDINGS, src,
                      f"{len(iocs)} known-malware symbol match(es) ({fam_txt})"
                      + (f"; {db_note}" if db_note else ""), items=iocs, count=len(iocs))
        sec.extra["families"] = fams
    else:
        sec = Section(key, title, SECTION_CLEAN, src,
                      f"{len(matches)} signature match(es) ({claim_txt}), none from a "
                      "known-malware family (Sliver / Cobalt Strike symbol names)"
                      + (f"; {db_note}" if db_note else ""),
                      count=0)
    sec.extra["claims"] = claims
    if db_info:
        sec.extra["database"] = db_info
    return sec


def _crypto(result: Any, workspace: Any) -> Section:
    key, title, src = "crypto", "Crypto Algorithms", "reconstructed/algorithms.json"
    st = _stage_stats(result, "reconstruct")
    if st is None:
        return _missing(key, title, src, "reconstruct stage did not run")
    data = _load(workspace, "reconstructed", "algorithms")
    if data is None:
        errs = getattr(result.stages.get("reconstruct"), "errors", None) or []
        err = next((e for e in errs if "Algorithm ID" in str(e)), None)
        if err:
            return Section(key, title, SECTION_NOT_SCANNED, src, str(err), reason=str(err))
        return _missing(key, title, src, "algorithm identification wrote no result "
                        "(disabled or did not run)")
    algos = [a for a in (data.get("algorithms") or []) if isinstance(a, dict)]
    crypto = [a for a in algos if a.get("category") in CRYPTO_CATEGORIES]
    other = len(algos) - len(crypto)
    tail = f"; {other} non-crypto algorithm(s) (compression / encoding / checksum) not counted" if other else ""
    if crypto:
        by_ev: dict[str, int] = {}
        for a in crypto:
            k = _evidence_kind(a)
            by_ev[k] = by_ev.get(k, 0) + 1
        ev_txt = ", ".join(f"{v} {k}" for k, v in sorted(by_ev.items()))
        sec = Section(key, title, SECTION_FINDINGS, src,
                      f"{len(crypto)} crypto algorithm detection(s) ({ev_txt}){tail}",
                      items=crypto, count=len(crypto))
        sec.extra["by_evidence"] = by_ev
        return sec
    return Section(key, title, SECTION_CLEAN, src,
                   f"algorithm identification ran, no crypto algorithm identified{tail}", count=0)


def _evidence_kind(a: dict[str, Any]) -> str:
    """Tespitin kanıt türü, ``evidence`` metninden (ürünün yazdığı önekler)."""
    ev = " ".join(str(e) for e in (a.get("evidence") or []))
    if "API call" in ev:
        return "by API call"
    if "constant" in ev.lower() or "S-box" in ev or "table" in ev.lower():
        return "by constants"
    return "by structure / other"


GNULIB_CANDIDATES_SOURCE = "static/gnulib_candidates.json"
# Raporda tek tek listelenen en çok tutulan aday (fazlası sayıyla; tamamı kaynak yapıtta).
GNULIB_CANDIDATES_SHOWN = 20


def gnulib_candidates(workspace: Any) -> Optional[dict[str, Any]]:
    """gnulib ön ad kanalının yazmadığı adaylar (P-S3 / P-S3b, K-2: aday kaybolmaz).

    Kaynak ``static/gnulib_candidates.json`` (``stages._write_gnulib_candidates``). Yapıt
    yoksa ``None`` (kanal koşmadı ya da kaydı yazamadı; 0 aday DEĞİL). Dönen sözlük:
    ``withheld`` (ad yazılmayan aday sayısı), ``by_reason``, ``presence`` (varlık kanıtı satırı),
    ``items`` (anahtar, aday ad, kanal, neden, kanıt satırı; en çok ``GNULIB_CANDIDATES_SHOWN``).
    """
    data = _load(workspace, "static", "gnulib_candidates")
    if data is None:
        return None
    decisions = [d for d in (data.get("decisions") or []) if isinstance(d, dict)]
    withheld = [d for d in decisions if d.get("decision") == "withheld"]
    by_reason: dict[str, int] = {}
    for d in withheld:
        r = str(d.get("reason") or "?")
        by_reason[r] = by_reason.get(r, 0) + 1
    presence = data.get("presence") if isinstance(data.get("presence"), dict) else {}
    items = []
    for d in withheld[:GNULIB_CANDIDATES_SHOWN]:
        evidence = d.get("evidence_presence") or d.get("evidence_layout") or ""
        items.append({"key": d.get("key"), "name": d.get("name"), "channel": d.get("channel"),
                      "reason": d.get("reason"),
                      "evidence": "; ".join(str(x) for x in (d.get("evidence"), evidence) if x)})
    return {"source": GNULIB_CANDIDATES_SOURCE, "withheld": len(withheld),
            "applied": sum(1 for d in decisions if d.get("decision") == "applied"),
            "by_reason": by_reason, "presence": presence.get("evidence"),
            "presence_sufficient": presence.get("sufficient"), "items": items}


def gnulib_candidates_note(gc: Optional[dict[str, Any]]) -> str:
    """Ad güvenilirliği özetine eklenen tek cümle (yapıt yoksa boş: kanal koşmadı)."""
    if not gc:
        return ""
    if not gc["withheld"]:
        return "; gnulib channel: no candidate withheld"
    reasons = ", ".join(f"{r}: {n}" for r, n in sorted(gc["by_reason"].items()))
    return (f"; gnulib channel: {gc['withheld']} candidate name(s) withheld, no name written "
            f"({reasons}; evidence in {gc['source']})")


def _naming(result: Any, workspace: Any) -> Section:
    sec = _naming_labels(result, workspace)
    gc = gnulib_candidates(workspace)
    if gc is not None:
        sec.extra["gnulib_candidates"] = gc
        sec.summary += gnulib_candidates_note(gc)
    warning = go_metadata_warning(_stage_stats(result, "reconstruct"))
    if warning is not None:
        sec.extra["go_metadata_warning"] = warning
        sec.summary += "; WARNING: " + warning["text"]
    return sec


# P-ÜV6c: Go üst verisinin tutarlılık denetimi (``go_metadata_recovery`` →
# ``reconstruct.stats["go_metadata_integrity"]``). Uyarı yalnız ikili kararı ``uyari`` ya da
# ``ust_veri_supheli`` iken; metin gerçek sayıları taşır (puan yok).
GO_INTEGRITY_WARN_VERDICTS = (KARAR_UYARI, KARAR_UST_VERI_SUPHELI)


def go_metadata_warning(st: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Go tutarlılık uyarısı (``extra["go_metadata_warning"]`` + özet satırı); yoksa ``None``."""
    if not isinstance(st, dict):
        return None
    gi = st.get("go_metadata_integrity")
    if not isinstance(gi, dict) or gi.get("karar") not in GO_INTEGRITY_WARN_VERDICTS:
        return None
    verdict = gi["karar"]
    strong = _int_or_none(gi.get("guclu_isaretli_fonksiyon"))
    total = _int_or_none(gi.get("fonksiyon"))
    checks = gi.get("guclu_isaret_dagilimi") if isinstance(gi.get("guclu_isaret_dagilimi"), dict) else {}
    stamps = gi.get("adli_damga") if isinstance(gi.get("adli_damga"), dict) else {}
    inconsistent = _int_or_none(stamps.get(DAMGA_TUTARSIZ))
    ch = ((st.get("naming_channels") or {}).get(SOURCE_GO_PCLNTAB) or {})
    withheld = (_int_or_none(ch.get("ust_veri_supheli_elendi")) if verdict == KARAR_UST_VERI_SUPHELI
                else _int_or_none(ch.get("tutarsiz_elendi")))
    check_txt = ", ".join(f"{k}: {v}" for k, v in sorted(checks.items())) or "none"
    parts = [f"Go metadata integrity check verdict '{verdict}'"]
    if strong is not None and total is not None:
        parts.append(f"{strong} of {total} Go functions carry a strong inconsistency signal "
                     f"[{check_txt}]")
    if gi.get("karar_nedeni"):
        parts.append(f"reason: {gi['karar_nedeni']}")
    if inconsistent is not None:
        parts.append(f"{inconsistent} named function(s) stamped '{DAMGA_TUTARSIZ}'")
    if verdict == KARAR_UST_VERI_SUPHELI:
        parts.append("all Go metadata names withheld as evidence rows"
                     + (f" ({withheld})" if withheld is not None else ""))
    else:
        parts.append(f"names stamped '{DAMGA_TUTARSIZ}' withheld as evidence rows"
                     + (f" ({withheld})" if withheld is not None else "")
                     + f"; the other Go names are written, labelled '{LABEL_METADATA}' "
                     "(consistent forgery is not detectable)")
    return {"verdict": verdict, "strong_signal_functions": strong, "functions": total,
            "strong_checks": dict(checks), "stamped_inconsistent": inconsistent,
            "withheld": withheld, "reason": gi.get("karar_nedeni") or None,
            "text": "; ".join(parts)}


def _naming_labels(result: Any, workspace: Any) -> Section:
    key, title, src = "naming", "Name Reliability", "reconstruct.stats (naming_by_label, variables_renamed)"
    st = _stage_stats(result, "reconstruct")
    if st is None:
        return _missing(key, title, src, "reconstruct stage did not run")
    labels = st.get("naming_by_label")
    renamed = _int_or_none(st.get("variables_renamed"))
    # P-ÜV6a: birleştiricinin yazdığı üst veri adları (``name_merger_by_label``) etiket dağılımına
    # eklenir; ``üst veriden`` ne "doğrulanmadı" ne "kesin" sayılır, ayrı yazılır.
    merger_labels = st.get("name_merger_by_label")
    if isinstance(merger_labels, dict) and merger_labels:
        labels = dict(labels) if isinstance(labels, dict) else {}
        for k, v in merger_labels.items():
            if isinstance(v, int) and not isinstance(v, bool):
                labels[k] = labels.get(k, 0) + v
    if not isinstance(labels, dict):
        if renamed:
            return Section(key, title, SECTION_UNKNOWN, src,
                           f"{renamed} identifiers renamed; name label distribution not "
                           "recorded, so every recovered name is unverified", count=None,
                           extra={"variables_renamed": renamed})
        return _missing(key, title, src, "no name label distribution recorded")
    total = sum(v for v in labels.values() if isinstance(v, int))
    unverified = sum(v for k, v in labels.items() if isinstance(v, int)
                     and k not in (LABEL_CERTAIN, LABEL_VERIFIED, LABEL_METADATA))
    metadata = sum(v for k, v in labels.items() if isinstance(v, int) and k == LABEL_METADATA)
    parts = ", ".join(f"{k}: {v}" for k, v in sorted(labels.items()))
    extra = {"labels": dict(labels), "function_names_total": total,
             "function_names_unverified": unverified, "variables_renamed": renamed}
    if metadata:
        extra["function_names_metadata"] = metadata
    metadata_note = (f"; {metadata} function name(s) read from binary metadata, labelled "
                     f"'{LABEL_METADATA}' (measured channel, name text not verifiable; not "
                     f"'{LABEL_CERTAIN}')" if metadata else "")
    local_note = (f"; {renamed} identifier renames in total (local names carry no "
                  "verification label, so they are unverified)" if renamed else "")
    if total == 0:
        head = "no labelled function name recorded"
    elif unverified:
        head = (f"{unverified} of {total} recovered function names are labelled "
                f"'{LABEL_UNVERIFIED}' (producing channel not measured or below its "
                f"precision target) [{parts}]")
    elif metadata:
        head = (f"all {total} recovered function names are labelled certain/verified/"
                f"'{LABEL_METADATA}' [{parts}]")
    else:
        head = f"all {total} recovered function names are labelled certain/verified [{parts}]"
    if unverified or renamed:
        # Yerel adlar etiket taşımaz: ad değişikliği varsa doğrulanmamış ad vardır.
        return Section(key, title, SECTION_FINDINGS, src, head + metadata_note + local_note,
                       items=[], count=unverified, extra=extra)
    if total == 0:
        return _missing(key, title, src, "no recovered name recorded")
    return Section(key, title, SECTION_CLEAN, src, head + metadata_note, count=0, extra=extra)


def _compositions(result: Any, workspace: Any) -> Section:
    key, title, src = "compositions", "Algorithm Compositions", "reconstructed/algorithm_compositions.json"
    st = _stage_stats(result, "reconstruct")
    if st is None:
        return _missing(key, title, src, "reconstruct stage did not run")
    data = _load(workspace, "reconstructed", "algorithm_compositions")
    if data is None:
        if "compositions" in st:
            return _missing(key, title, src, "composition count recorded but the artifact "
                            "with the compositions is missing")
        return _missing(key, title, src, "composition analysis wrote no result")
    comps = [c for c in (data.get("compositions") or []) if isinstance(c, dict)]
    pending = _int_or_none(data.get("total_pending"))
    if pending is None and isinstance(data.get("pending_compositions"), list):
        pending = len(data["pending_compositions"])
    pend_txt = (f"; {pending} template match(es) held back by the evidence gate (decision K-1: "
                "unverified, not claims, not listed)" if pending else "")
    extra = {"pending": pending}
    if comps:
        return Section(key, title, SECTION_FINDINGS, src,
                       f"{len(comps)} composition(s); the score is uncalibrated{pend_txt}",
                       items=comps, count=len(comps), extra=extra)
    return Section(key, title, SECTION_CLEAN, src, f"no composition reported{pend_txt}",
                   count=0, extra=extra)


_BUILDERS = {
    "packer": _packer,
    "anti_debug": _anti_debug,
    "yara": _yara,
    "capa": _capa,
    "ioc": _ioc,
    "crypto": _crypto,
    "naming": _naming,
    "compositions": _compositions,
}


def _counters(result: Any) -> dict[str, Any]:
    """Sayaçlar: kaynağı olmayan sayaç ``None`` (0 ya da "N/A" değil)."""
    static = _stage_stats(result, "static") or {}
    recon = _stage_stats(result, "reconstruct") or {}
    deob = _stage_stats(result, "deobfuscate") or {}

    def first(stats: dict[str, Any], *keys: str) -> Any:
        for k in keys:
            if k in stats and stats[k] is not None:
                return stats[k]
        return None

    return {
        "functions": first(static, "functions_found", "ghidra_function_count", "functions"),
        "thunks": first(static, "ghidra_thunk_count"),
        "strings": first(static, "strings_found", "ghidra_string_count", "string_count", "strings"),
        "imports": first(static, "imports_found"),
        "deobfuscation_steps": first(deob, "steps_completed"),
        "modules_extracted": first(recon, "modules_extracted"),
        "variables_renamed": first(recon, "variables_renamed"),
        "coverage_percent": first(recon, "coverage_percent"),
    }


def build_report_data(result: Any, workspace: Any) -> ReportData:
    """Bütün bölümleri kur. Bir bölüm kurulurken hata olursa o bölüm ``no_data`` + neden."""
    sections: dict[str, Section] = {}
    for key in SECTION_ORDER:
        try:
            sections[key] = _BUILDERS[key](result, workspace)
        except Exception as exc:  # bir bölüm bütün raporu düşürmesin; neden yazılır
            logger.warning("rapor verisi: %s bolumu kurulamadi: %s", key, exc, exc_info=True)
            sections[key] = _missing(key, key, "?", f"section could not be built: {type(exc).__name__}: {exc}")
    return ReportData(sections=sections, counters=_counters(result))


def status_label(status: str) -> str:
    """Kısa, insan okur durum etiketi (bütün üreticilerde aynı)."""
    return {
        SECTION_FINDINGS: "FINDINGS",
        SECTION_CLEAN: "CLEAN",
        SECTION_PARTIAL: "PARTIAL SCAN",
        SECTION_UNKNOWN: "STATUS NOT RECORDED",
        SECTION_NOT_SCANNED: "NOT SCANNED",
        SECTION_UNSUPPORTED: "NOT SUPPORTED",
        SECTION_DISABLED: "DISABLED",
        SECTION_NO_DATA: "NO DATA",
    }.get(status, status.upper())


def to_json_dict(data: ReportData) -> dict[str, Any]:
    """JSON raporu için bölüm özeti (aynı durum, aynı cümle)."""
    return {key: data.sections[key].to_dict() for key in SECTION_ORDER if key in data.sections}


def dumps_items(items: list[dict[str, Any]]) -> str:
    return json.dumps(items, ensure_ascii=False, default=str)
