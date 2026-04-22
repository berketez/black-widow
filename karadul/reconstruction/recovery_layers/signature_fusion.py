"""Layer 3: Signature Fusion -- Dempster-Shafer evidence theory ile birlestirme.

Constraint Solver (Layer 1), CFG Fingerprinting (Layer 2) ve mevcut
signature/algorithm/engineering eslesmelerini Dempster-Shafer evidence
theory ile birlestirerek her fonksiyon icin tek bir FusedIdentification uretir.

Call graph uzerinde hint propagasyonu yaparak dusuk-guvenli tanımlamalarin
guvenini artirabilir (ornek: callee kesin AES ise, caller muhtemelen
AES wrapper'dir).

Kullanim:
    from karadul.reconstruction.recovery_layers.signature_fusion import SignatureFusion
    fusion = SignatureFusion(config)
    result = fusion.fuse(
        constraint_structs=constraint_results,
        cfg_matches=cfg_matches,
        existing_sig_matches=sig_dict,
        existing_algo_matches=algo_dict,
        existing_eng_matches=eng_dict,
        call_graph_json=call_graph_path,
    )
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sinyal tipleri ve varsayilan agirliklar
# ---------------------------------------------------------------------------

# Her sinyal tipi icin base belief mass (Dempster-Shafer frame'inde).
# Daha yuksek = o kaynaga daha fazla guven.
_DEFAULT_SIGNAL_WEIGHTS: dict[str, float] = {
    "constraint_solver": 0.55,   # Struct layout dogrulama -- oldukca guvenilir
    "cfg_fingerprint": 0.65,     # CFG yapisal eslestirme -- cok guvenilir
    "signature_db": 0.80,        # Mevcut FLIRT/BSim signature -- en guvenilir
    "algorithm_id": 0.60,        # Mevcut regex-based algorithm detection
    "engineering_match": 0.50,   # Engineering pattern eslestirme
}

# Hint propagasyonunda callee -> caller guven transferi
_PROPAGATION_DECAY: float = 0.3


# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class NamingCandidate:
    """Tek bir kaynaktan gelen isim onerisi.

    NameMerger'daki NamingCandidate ile ayni formatta olmali.

    Attributes:
        name: Onerilen isim.
        confidence: Guven skoru [0,1].
        source: Kaynak ("constraint_solver", "cfg_fingerprint", "signature_fusion").
        reason: Aciklama.
    """
    name: str
    confidence: float
    source: str
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "confidence": round(self.confidence, 4),
            "source": self.source,
            "reason": self.reason,
        }


@dataclass
class EvidenceMass:
    """Bir sinyal kaynagindan gelen belief mass.

    Attributes:
        source: Sinyal kaynagi (ornek: "cfg_fingerprint").
        hypothesis: Hipotez (ornek: "quicksort").
        mass: Belief mass [0,1].
        category: Algoritma kategorisi (ornek: "sorting").
        detail: Ek bilgi.
    """
    source: str
    hypothesis: str
    mass: float
    category: str = ""
    detail: str = ""


@dataclass
class FusedIdentification:
    """Birlesik tanimlama -- bir fonksiyon icin tum sinyallerin birlesmesi.

    Attributes:
        function_name: Mevcut fonksiyon adi (FUN_xxx vb.).
        function_address: Fonksiyon giris adresi.
        identified_as: En yuksek guvenli tanimlama (ornek: "quicksort").
        category: Algoritma kategorisi.
        fused_confidence: Dempster-Shafer birlestirmesinden cikan nihai guven.
        evidence_masses: Her kaynaktan gelen evidence listesi.
        naming_candidates: NameMerger'a gonderilecek isim onerileri.
        agreement_count: Ayni sonucu veren bagimsiz kaynak sayisi.
        conflict_level: Kaynaklar arasi celisme duzeyi [0,1].
        propagated_hints: Call graph propagasyonundan gelen ipuclari.
    """
    function_name: str
    function_address: str
    identified_as: str = ""
    category: str = ""
    fused_confidence: float = 0.0
    evidence_masses: list[EvidenceMass] = field(default_factory=list)
    naming_candidates: list[NamingCandidate] = field(default_factory=list)
    agreement_count: int = 0
    conflict_level: float = 0.0
    propagated_hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "function_address": self.function_address,
            "identified_as": self.identified_as,
            "category": self.category,
            "fused_confidence": round(self.fused_confidence, 4),
            "evidence_masses": [
                {
                    "source": em.source,
                    "hypothesis": em.hypothesis,
                    "mass": round(em.mass, 4),
                    "category": em.category,
                }
                for em in self.evidence_masses
            ],
            "naming_candidates": [nc.to_dict() for nc in self.naming_candidates],
            "agreement_count": self.agreement_count,
            "conflict_level": round(self.conflict_level, 4),
            "propagated_hints": self.propagated_hints,
        }


# ---------------------------------------------------------------------------
# SignatureFusion -- ana sinif
# ---------------------------------------------------------------------------

class SignatureFusion:
    """Coklu sinyal kaynaklarini Dempster-Shafer ile birlestiren sinif.

    Args:
        config: Opsiyonel config dict:
            - min_fused_confidence (float): Min birlestirmis guven (varsayilan 0.40).
            - propagation_enabled (bool): Call graph propagasyonu (varsayilan True).
            - propagation_decay (float): Propagasyon guven azalmasi (varsayilan 0.3).
            - signal_weights (dict): Sinyal tipi -> base weight override.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        self._min_confidence: float = config.get("min_fused_confidence", 0.40)
        self._propagation_enabled: bool = config.get("propagation_enabled", True)
        self._propagation_decay: float = config.get(
            "propagation_decay", _PROPAGATION_DECAY,
        )
        # v1.5.9: Multi-hop propagation parametreleri
        self._max_hops: int = config.get("max_hops", 2)
        self._min_hint: float = config.get("min_hint", 0.15)
        self._signal_weights: dict[str, float] = {
            **_DEFAULT_SIGNAL_WEIGHTS,
            **config.get("signal_weights", {}),
        }
        # v1.7: Iterative callee-profile propagation
        self._callee_profile_enabled: bool = config.get(
            "callee_profile_enabled", True,
        )
        self._callee_profile_config: dict[str, Any] = config.get(
            "callee_profile_config", {},
        )
        logger.info(
            "SignatureFusion baslatildi: min_confidence=%.2f, propagation=%s, "
            "max_hops=%d, decay=%.2f, callee_profile=%s",
            self._min_confidence,
            self._propagation_enabled,
            self._max_hops,
            self._propagation_decay,
            self._callee_profile_enabled,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fuse(
        self,
        constraint_structs: dict[str, Any] | None = None,
        cfg_matches: list[Any] | None = None,
        existing_sig_matches: dict[str, Any] | None = None,
        existing_algo_matches: dict[str, Any] | None = None,
        existing_eng_matches: dict[str, Any] | None = None,
        call_graph_json: Path | None = None,
        xrefs_json: Path | None = None,
        strings_json: Path | None = None,
        dynamic_libs_json: Path | None = None,
    ) -> dict[str, FusedIdentification]:
        """Tum sinyalleri birlestirip her fonksiyon icin FusedIdentification uret.

        Args:
            constraint_structs: Layer 1 ciktisi --
                {func_addr: {"struct_candidates": [...], "array_dims": [...]}}
            cfg_matches: Layer 2 ciktisi -- list[CFGMatch] (veya to_dict() listesi).
            existing_sig_matches: Mevcut signature DB eslesmeleri --
                {func_addr: {"name": ..., "confidence": ..., "library": ...}}
            existing_algo_matches: Mevcut algorithm ID eslesmeleri --
                {func_addr: {"algorithms": [{"name": ..., "confidence": ...}]}}
            existing_eng_matches: Mevcut engineering eslesmeleri --
                {func_addr: {"domain": ..., "patterns": [...]}}
            call_graph_json: Call graph JSON dosya yolu (hint propagasyonu icin).
            xrefs_json: Cross-reference JSON dosya yolu (xref-based confidence boost).
            strings_json: Binary string'ler JSON dosya yolu (string evidence dogrulama).
            dynamic_libs_json: Import edilen dynamic library JSON dosya yolu.
                Beklenen format: {"libraries": ["libssl.so", ...]} veya
                {"imports": {func_addr: {"library": "libssl.so", ...}}}.

        Returns:
            dict[str, FusedIdentification]: func_address -> FusedIdentification eslesmesi.
        """
        constraint_structs = constraint_structs or {}
        cfg_matches = cfg_matches or []
        existing_sig_matches = existing_sig_matches or {}
        existing_algo_matches = existing_algo_matches or {}
        existing_eng_matches = existing_eng_matches or {}

        # --- Format normalization ---
        # sig_matches bazen {"matches": [...]} formatinda gelir, name-keyed dict'e cevir
        if "matches" in existing_sig_matches and isinstance(
            existing_sig_matches.get("matches"), list,
        ):
            _normalized_sig: dict[str, Any] = {}
            for m in existing_sig_matches["matches"]:
                name = m.get("original", m.get("name", ""))
                if name:
                    _normalized_sig[name] = m
            existing_sig_matches = _normalized_sig

        # algo_matches bazen {"algorithms": [...]} formatinda gelir
        if "algorithms" in existing_algo_matches and isinstance(
            existing_algo_matches.get("algorithms"), list,
        ):
            _normalized_algo: dict[str, Any] = {}
            for a in existing_algo_matches["algorithms"]:
                fname = a.get("function_name", a.get("name", ""))
                if fname:
                    _normalized_algo[fname] = a
            existing_algo_matches = _normalized_algo

        # eng_matches bazen {"algorithms": [...]} formatinda gelir
        if "algorithms" in existing_eng_matches and isinstance(
            existing_eng_matches.get("algorithms"), list,
        ):
            _normalized_eng: dict[str, Any] = {}
            for e in existing_eng_matches["algorithms"]:
                fname = e.get("function_name", e.get("name", ""))
                if fname:
                    _normalized_eng[fname] = e
            existing_eng_matches = _normalized_eng

        # Tum fonksiyon key'lerini topla (adres veya isim olabilir)
        all_addresses: set[str] = set()
        all_addresses.update(constraint_structs.keys())
        all_addresses.update(existing_sig_matches.keys())
        all_addresses.update(existing_algo_matches.keys())
        all_addresses.update(existing_eng_matches.keys())

        # CFG match'lerden adresleri VE isimleri cek (her ikisini de key olarak kullan)
        cfg_by_key: dict[str, list[dict[str, Any]]] = {}
        for match in cfg_matches:
            if isinstance(match, dict):
                addr = match.get("function_address", "")
                name = match.get("function_name", "")
            else:
                addr = getattr(match, "function_address", "")
                name = getattr(match, "function_name", "")
            match_dict = match if isinstance(match, dict) else _cfg_match_to_dict(match)
            if addr:
                all_addresses.add(addr)
                cfg_by_key.setdefault(addr, []).append(match_dict)
            if name:
                all_addresses.add(name)
                cfg_by_key.setdefault(name, []).append(match_dict)
        # Backward compat alias
        cfg_by_addr = cfg_by_key

        # Her fonksiyon icin evidence topla ve birlestir
        fused_results: dict[str, FusedIdentification] = {}

        # addr → function_name mapping (CFG match'lerden)
        _addr_to_name: dict[str, str] = {}
        for match in cfg_matches:
            if isinstance(match, dict):
                a = match.get("function_address", "")
                n = match.get("function_name", "")
            else:
                a = getattr(match, "function_address", "")
                n = getattr(match, "function_name", "")
            if a and n:
                _addr_to_name[a] = n
                _addr_to_name[n] = n  # isim key'i de isimle esle

        for addr in all_addresses:
            evidence_list = self._collect_evidence(
                addr,
                constraint_structs.get(addr),
                cfg_by_addr.get(addr, []),
                existing_sig_matches.get(addr),
                existing_algo_matches.get(addr),
                existing_eng_matches.get(addr),
            )

            if not evidence_list:
                continue

            fused = self._fuse_evidence(addr, evidence_list)

            # function_name'i doldur (addr isim olabilir veya mapping'den)
            if not fused.function_name:
                fused.function_name = _addr_to_name.get(addr, addr)

            if fused.fused_confidence >= self._min_confidence:
                fused_results[addr] = fused

        # Call graph propagasyonu
        if self._propagation_enabled and call_graph_json is not None:
            call_graph = self._load_call_graph(call_graph_json)
            if call_graph:
                self._propagate_hints(fused_results, call_graph)
                # Callee-based inference (call graph gerekli)
                self._infer_from_callees(fused_results, call_graph)
                # v1.7: Iterative callee-profile propagation
                if self._callee_profile_enabled:
                    # existing_sig_matches'i callee_profile'a list olarak gecir
                    _sig_list_for_cp: list[dict[str, Any]] | None = None
                    if existing_sig_matches:
                        _sig_list_for_cp = [
                            {"original_name": k, **v}
                            for k, v in existing_sig_matches.items()
                            if isinstance(v, dict)
                        ]
                    self._run_callee_profile_propagation(
                        fused_results, call_graph,
                        signature_matches=_sig_list_for_cp,
                    )

        # Xref-based confidence boost
        self._boost_by_xref_count(fused_results, xrefs_json)

        # String evidence ile dogrulama
        self._validate_with_strings(fused_results, strings_json)

        # Import table sinyal kaynagi
        self._add_import_signal(fused_results, dynamic_libs_json)

        # Naming candidate'leri olustur
        self._generate_naming_candidates(fused_results)

        logger.info(
            "Signature fusion tamamlandi: %d fonksiyon islendi, %d tanimlama uretildi",
            len(all_addresses),
            len(fused_results),
        )
        return fused_results

    # ------------------------------------------------------------------
    # Evidence toplama
    # ------------------------------------------------------------------

    def _collect_evidence(
        self,
        func_addr: str,
        constraint_data: dict[str, Any] | None,
        cfg_match_list: list[dict[str, Any]],
        sig_data: dict[str, Any] | None,
        algo_data: dict[str, Any] | None,
        eng_data: dict[str, Any] | None,
    ) -> list[EvidenceMass]:
        """Tek bir fonksiyon icin tum kaynaklardan evidence topla.

        Args:
            func_addr: Fonksiyon adresi.
            constraint_data: Constraint solver ciktisi.
            cfg_match_list: CFG match listesi.
            sig_data: Signature DB eslesmesi.
            algo_data: Algorithm ID eslesmesi.
            eng_data: Engineering eslesmesi.

        Returns:
            list[EvidenceMass]: Toplanan evidence'lar.
        """
        evidence: list[EvidenceMass] = []

        # 1. Constraint solver sinyali
        if constraint_data:
            mass = self._compute_belief_mass("constraint_solver", constraint_data)
            if mass > 0.0:
                hypothesis = constraint_data.get("identified_type", "struct")
                evidence.append(EvidenceMass(
                    source="constraint_solver",
                    hypothesis=hypothesis,
                    mass=mass,
                    category=constraint_data.get("category", ""),
                    detail=constraint_data.get("detail", ""),
                ))

        # 2. CFG fingerprint sinyalleri (birden fazla olabilir)
        for cm in cfg_match_list:
            raw_confidence = cm.get("confidence", 0.0)
            mass = self._compute_belief_mass("cfg_fingerprint", cm)
            if mass > 0.0:
                evidence.append(EvidenceMass(
                    source="cfg_fingerprint",
                    hypothesis=cm.get("matched_algorithm", "unknown"),
                    mass=mass,
                    category=cm.get("matched_category", ""),
                ))

        # 3. Mevcut signature DB
        if sig_data:
            mass = self._compute_belief_mass("signature_db", sig_data)
            if mass > 0.0:
                evidence.append(EvidenceMass(
                    source="signature_db",
                    hypothesis=sig_data.get("name", sig_data.get("matched_name", "")),
                    mass=mass,
                    category=sig_data.get("library", ""),
                ))

        # 4. Mevcut algorithm ID
        if algo_data:
            algorithms = algo_data.get("algorithms", [])
            if isinstance(algorithms, list):
                for algo in algorithms:
                    if isinstance(algo, dict):
                        mass = self._compute_belief_mass("algorithm_id", algo)
                        if mass > 0.0:
                            evidence.append(EvidenceMass(
                                source="algorithm_id",
                                hypothesis=algo.get("name", ""),
                                mass=mass,
                                category=algo.get("category", ""),
                            ))

        # 5. Mevcut engineering eslesmesi
        if eng_data:
            mass = self._compute_belief_mass("engineering_match", eng_data)
            if mass > 0.0:
                patterns = eng_data.get("patterns", [])
                hypothesis = patterns[0] if patterns else eng_data.get("domain", "")
                evidence.append(EvidenceMass(
                    source="engineering_match",
                    hypothesis=hypothesis,
                    mass=mass,
                    category=eng_data.get("domain", ""),
                ))

        return evidence

    # ------------------------------------------------------------------
    # Belief mass hesaplama
    # ------------------------------------------------------------------

    def _compute_belief_mass(
        self,
        signal_type: str,
        match: dict[str, Any],
    ) -> float:
        """Sinyal tipine ve eslestirme kalitesine gore belief mass hesapla.

        Belief mass = base_weight * match_quality

        match_quality, eslestirme kaynagina gore farkli hesaplanir:
        - cfg_fingerprint: similarity * (1 + hash_match * 0.1)
        - signature_db: confidence degeri direkt
        - algorithm_id: confidence degeri
        - constraint_solver: constraint_satisfaction_ratio
        - engineering_match: pattern count bazli

        Args:
            signal_type: Sinyal tipi (ornek: "cfg_fingerprint").
            match: Eslestirme bilgisi dict.

        Returns:
            float: Belief mass [0, 0.95].
        """
        base_weight = self._signal_weights.get(signal_type, 0.5)

        if signal_type == "cfg_fingerprint":
            similarity = match.get("similarity", match.get("confidence", 0.0))
            quality = similarity
        elif signal_type == "signature_db":
            quality = match.get("confidence", match.get("score", 0.5))
        elif signal_type == "algorithm_id":
            quality = match.get("confidence", 0.5)
        elif signal_type == "constraint_solver":
            # Constraint satisfaction ratio veya basit confidence
            quality = match.get("satisfaction_ratio", match.get("confidence", 0.5))
        elif signal_type == "engineering_match":
            patterns = match.get("patterns", [])
            n_patterns = len(patterns) if isinstance(patterns, list) else 1
            quality = min(0.3 + 0.15 * n_patterns, 0.9)
        else:
            quality = match.get("confidence", 0.5)

        mass = base_weight * quality
        return min(mass, 0.95)

    # ------------------------------------------------------------------
    # Dempster-Shafer birlestirme
    # ------------------------------------------------------------------

    def _ds_combine_with_ignorance(self, beliefs: list[float]) -> float:
        """Dempster-Shafer with proper ignorance modeling.

        Her belief m_H olarak gelir. m_Theta (ignorance) = 1 - m_H.
        Disbelief m_NOT_H = 0 (kapali dunya varsayimi yok).

        Eski _dempster_combine YANLISTI: dusuk confidence'i "bu degil"
        (disbelief) olarak yorumluyordu. Dogru model: "bilmiyorum" (ignorance).

        Args:
            beliefs: Belief mass'leri listesi [0,1].

        Returns:
            float: Birlestirmis belief mass [0, 0.98].
        """
        current_h = 0.0
        current_theta = 1.0  # vacuous start (tam belirsizlik)

        for m_h in beliefs:
            m_theta = 1.0 - m_h
            new_h = current_h * m_h + current_h * m_theta + current_theta * m_h
            new_theta = current_theta * m_theta
            total = new_h + new_theta
            if total > 0:
                current_h = new_h / total
                current_theta = new_theta / total
            else:
                current_h = 0.0
                current_theta = 1.0

        return min(current_h, 0.98)

    def _fuse_evidence(
        self,
        func_addr: str,
        evidence_list: list[EvidenceMass],
    ) -> FusedIdentification:
        """Bir fonksiyonun tum evidence'larini birlestir.

        Algoritma:
        1. Evidence'lari hipoteze gore grupla.
        2. Ayni hipotezdeki mass'leri Dempster kuraliyla birlestir.
        3. En yuksek birlestirmis mass'li hipotezi sec.
        4. Agreement ve conflict duzeylerini hesapla.

        Args:
            func_addr: Fonksiyon adresi.
            evidence_list: Tum evidence'lar.

        Returns:
            FusedIdentification: Birlestirmis tanimlama.
        """
        # Fonksiyon adini bul (ilk evidence'dan)
        func_name = ""
        for ev in evidence_list:
            if ev.hypothesis:
                # CFG match'lerde function_name vardir
                break

        # Hipoteze gore grupla
        hypothesis_groups: dict[str, list[EvidenceMass]] = {}
        for ev in evidence_list:
            h = self._normalize_hypothesis(ev.hypothesis)
            if h:
                hypothesis_groups.setdefault(h, []).append(ev)

        if not hypothesis_groups:
            return FusedIdentification(
                function_name=func_name,
                function_address=func_addr,
            )

        # Her hipotez icin mass'leri birlestir
        fused_masses: dict[str, float] = {}
        fused_categories: dict[str, str] = {}

        for hypothesis, evidences in hypothesis_groups.items():
            masses = [ev.mass for ev in evidences]
            combined = self._ds_combine_with_ignorance(masses)
            fused_masses[hypothesis] = combined
            # Kategoriyi en yuksek mass'li evidence'dan al
            fused_categories[hypothesis] = max(
                evidences, key=lambda e: e.mass,
            ).category

        # En iyi hipotezi sec
        best_hypothesis = max(fused_masses, key=lambda h: fused_masses[h])
        best_confidence = fused_masses[best_hypothesis]
        best_category = fused_categories.get(best_hypothesis, "")

        # Agreement: kac FARKLI kaynak ayni hipotezi destekliyor?
        best_evidences = hypothesis_groups.get(best_hypothesis, [])
        unique_sources = {ev.source for ev in best_evidences}
        agreement = len(unique_sources)

        # Conflict: ikinci en iyi / en iyi oran
        # 0 = hic rekabet yok (tek dominant hipotez)
        # 1 = tam esit (belirsiz, yuksek catisma)
        # Eski formul (1 - fark) counterintuitive idi: best=0.90, second=0.80
        # -> conflict=0.90 (cok yuksek). Oran formulu bunu duzeltir.
        sorted_masses = sorted(fused_masses.values(), reverse=True)
        if len(sorted_masses) >= 2 and sorted_masses[0] > 0:
            conflict = sorted_masses[1] / sorted_masses[0]
        else:
            conflict = 0.0

        return FusedIdentification(
            function_name=func_name,
            function_address=func_addr,
            identified_as=best_hypothesis,
            category=best_category,
            fused_confidence=best_confidence,
            evidence_masses=evidence_list,
            agreement_count=agreement,
            conflict_level=conflict,
        )

    # ------------------------------------------------------------------
    # Call graph propagasyonu
    # ------------------------------------------------------------------

    def _propagate_hints(
        self,
        fused: dict[str, FusedIdentification],
        call_graph: dict[str, list[str]],
    ) -> None:
        """Call graph uzerinde tanimlama ipuclarini yay (in-place guncelleme).

        Yuksek-guvenli callee tanimlamalarini caller'lara propagate eder.
        Ornek: AES_encrypt -> caller muhtemelen crypto wrapper.

        Multi-hop BFS propagasyon destegi.

        Args:
            fused: Mevcut birlestirmis tanimlamalar (degistirilir).
            call_graph: {caller_addr: [callee_addr, ...]} eslesmesi.
        """
        # Reverse call graph: callee -> [caller, ...]
        reverse_cg: dict[str, list[str]] = {}
        for caller, callees in call_graph.items():
            for callee in callees:
                reverse_cg.setdefault(callee, []).append(caller)

        # Yuksek guvenli tanimlamalardan baslangic seed'lerini topla
        # (source_addr, identified_as, category, base_confidence)
        initial_seeds: list[tuple[str, str, str, float]] = []
        for addr, fid in fused.items():
            if fid.fused_confidence >= 0.70:
                initial_seeds.append(
                    (addr, fid.identified_as, fid.category, fid.fused_confidence)
                )

        # Multi-hop iteratif propagasyon
        # current_queue: bu hop'ta yayilacak hint'ler
        # Her eleman: (source_addr, identified_as, category, base_confidence)
        current_queue = initial_seeds

        # Visited: (source_addr, target_addr) ciftleri -- ayni hint'i ayni hedefe
        # iki kez yayma (cycle prevention)
        visited: set[tuple[str, str]] = set()

        total_propagated = 0

        for hop in range(self._max_hops):
            decay_factor = self._propagation_decay ** (hop + 1)
            next_queue: list[tuple[str, str, str, float]] = []

            for source_addr, identified, category, base_conf in current_queue:
                callers = reverse_cg.get(source_addr, [])
                for caller_addr in callers:
                    # Cycle check
                    edge_key = (source_addr, caller_addr)
                    if edge_key in visited:
                        continue
                    visited.add(edge_key)

                    hint_confidence = base_conf * decay_factor

                    # Minimum hint threshold
                    if hint_confidence < self._min_hint:
                        continue

                    hint_name = f"{identified}_caller"
                    hop_label = f"hop{hop + 1}" if hop > 0 else ""
                    hint_detail = (
                        f"calls {identified} ({category})"
                        if not hop_label
                        else f"calls {identified} ({category}) [{hop_label}]"
                    )

                    if caller_addr in fused:
                        # Mevcut tanimlama varsa, hint ekle
                        fused[caller_addr].propagated_hints.append(hint_detail)
                        # Eger mevcut tanimlama dusuk guvenli ise boost et
                        if fused[caller_addr].fused_confidence < 0.50:
                            fused[caller_addr].fused_confidence = min(
                                fused[caller_addr].fused_confidence
                                + hint_confidence * 0.5,
                                0.60,
                            )
                    else:
                        # Yeni tanimlama olustur (dusuk guvenli)
                        fused[caller_addr] = FusedIdentification(
                            function_name="",
                            function_address=caller_addr,
                            identified_as=hint_name,
                            category=category,
                            fused_confidence=hint_confidence,
                            propagated_hints=[hint_detail],
                        )

                    total_propagated += 1

                    # Bu caller sonraki hop icin kaynak olabilir
                    next_queue.append(
                        (caller_addr, identified, category, base_conf)
                    )

            current_queue = next_queue
            if not current_queue:
                break  # Yayilacak bir sey kalmadi

        if total_propagated:
            logger.info(
                "Hint propagation: %d hint yayildi (%d hop)",
                total_propagated,
                min(hop + 1, self._max_hops) if initial_seeds else 0,
            )

    # ------------------------------------------------------------------
    # Iterative callee-profile propagation
    # ------------------------------------------------------------------

    def _run_callee_profile_propagation(
        self,
        fused: dict[str, FusedIdentification],
        call_graph: dict[str, list[str]],
        signature_matches: list[Any] | None = None,
    ) -> None:
        """Iteratif callee-profile propagasyonu calistir ve sonuclari fused'a yaz.

        CalleeProfilePropagator'u kullanarak iteratif domain-based fonksiyon
        adlandirmasi yapar. Bulunan yeni isimler fused dict'e FusedIdentification
        olarak eklenir (veya mevcut dusuk-guvenli tanimlamalari gunceller).

        Args:
            fused: Mevcut tanimlamalar (in-place guncellenir).
            call_graph: {caller_addr: [callee_addr, ...]} eslesmesi.
            signature_matches: Opsiyonel signature DB match listesi.
                Confidence >= 0.70 olanlar ek seed olarak eklenir.
        """
        try:
            from karadul.reconstruction.recovery_layers.callee_profile_propagator import (
                CalleeProfilePropagator,
            )
        except ImportError:
            logger.debug("callee_profile_propagator import edilemedi -- atlaniyor")
            return

        propagator = CalleeProfilePropagator(config=self._callee_profile_config)
        result = propagator.propagate(
            fused_results=fused,
            call_graph=call_graph,
            signature_matches=signature_matches,
        )

        if not result.propagated_names:
            return

        applied = 0
        for pn in result.propagated_names:
            addr = pn.function_address
            if addr in fused:
                existing = fused[addr]
                # Sadece dusuk guvenli veya tanimlanmamis olanlari guncelle
                if existing.fused_confidence < 0.50 or not existing.identified_as:
                    existing.identified_as = pn.name
                    existing.category = pn.domain
                    existing.fused_confidence = max(
                        existing.fused_confidence, pn.confidence,
                    )
                    existing.propagated_hints.append(
                        f"callee_profile(r{pn.round_discovered},"
                        f"{pn.direction}): {pn.reason}"
                    )
                    applied += 1
            else:
                # Yeni FusedIdentification olustur
                fused[addr] = FusedIdentification(
                    function_name="",
                    function_address=addr,
                    identified_as=pn.name,
                    category=pn.domain,
                    fused_confidence=pn.confidence,
                    propagated_hints=[
                        f"callee_profile(r{pn.round_discovered},"
                        f"{pn.direction}): {pn.reason}"
                    ],
                )
                applied += 1

        if applied:
            logger.info(
                "Callee-profile propagation: %d yeni tanimlama uygulanmis "
                "(%d rounds, sebep=%s)",
                applied,
                result.total_rounds,
                result.convergence_reason,
            )

    # ------------------------------------------------------------------
    # Naming candidate uretimi
    # ------------------------------------------------------------------

    def _generate_naming_candidates(
        self,
        fused: dict[str, FusedIdentification],
    ) -> None:
        """Her FusedIdentification icin NamingCandidate listesi olustur.

        Isimlendirme stratejisi:
        1. identified_as'i dogrudan isim adayi yap.
        2. category + identified_as birlesik isim.
        3. Propagated hint'lerden turetilmis isimler.

        Args:
            fused: Birlestirmis tanimlamalar (in-place naming_candidates eklenir).
        """
        for addr, fid in fused.items():
            candidates: list[NamingCandidate] = []

            # Callee-profile propagasyonundan gelenleri ayirt et
            _is_callee_profile = any(
                "callee_profile(" in h for h in fid.propagated_hints
            )
            _source = "callee_profile" if _is_callee_profile else "signature_fusion"

            if fid.identified_as:
                # Ana isim adayi
                primary_name = self._to_function_name(fid.identified_as)
                candidates.append(NamingCandidate(
                    name=primary_name,
                    confidence=fid.fused_confidence,
                    source=_source,
                    reason=f"Fused from {fid.agreement_count} source(s), "
                           f"category={fid.category}",
                ))

                # Kategori + isim
                if fid.category and fid.category.lower() != fid.identified_as.lower():
                    cat_name = self._to_function_name(
                        f"{fid.category}_{fid.identified_as}"
                    )
                    candidates.append(NamingCandidate(
                        name=cat_name,
                        confidence=fid.fused_confidence * 0.85,
                        source=_source,
                        reason=f"Category-qualified: {fid.category}",
                    ))

            # Propagated hint'lerden isimler
            for hint in fid.propagated_hints:
                # "calls quicksort (sorting)" -> "quicksort_wrapper"
                parts = hint.replace("calls ", "").split(" (")
                if parts:
                    hint_base = parts[0].strip()
                    hint_name = self._to_function_name(f"{hint_base}_wrapper")
                    candidates.append(NamingCandidate(
                        name=hint_name,
                        confidence=fid.fused_confidence * 0.60,
                        source="signature_fusion",
                        reason=f"Call graph hint: {hint}",
                    ))

            fid.naming_candidates = candidates

    # ------------------------------------------------------------------
    # Xref-based confidence boost
    # ------------------------------------------------------------------

    def _boost_by_xref_count(
        self,
        fused: dict[str, FusedIdentification],
        xrefs_json: Path | None,
    ) -> None:
        """Cok referans edilen fonksiyonlar icin confidence artisi (in-place).

        Mantik: Cok fazla yerden cagrilan fonksiyonlar buyuk olasilikla
        kutuphane fonksiyonlaridir (malloc, printf, memcpy vb.). Bu da
        tespitin guvenilirligini arttirir.

        Boost kurallari:
            xref_count > 20  -> confidence * 1.1
            xref_count > 50  -> confidence * 1.2
            xref_count > 100 -> confidence * 1.3
            Maksimum cap: 0.98

        Args:
            fused: Mevcut birlestirmis tanimlamalar (in-place guncellenir).
            xrefs_json: Cross-reference JSON dosya yolu. Beklenen format:
                {func_addr: {"xref_count": int, ...}} veya
                {func_addr: [list of xref addrs]}.
        """
        if xrefs_json is None or not xrefs_json.exists():
            logger.debug("Xrefs JSON bulunamadi -- xref boost atlaniyor")
            return

        try:
            raw = json.loads(xrefs_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Xrefs JSON okunamiyor: %s -- %s", xrefs_json, exc)
            return

        if not isinstance(raw, dict):
            return

        # Generic isimler icin boost UYGULANMAZ -- bunlar gercek tanimlama degil
        _GENERIC_NAMES = {"wrapper", "caller", "handler", "unknown", "func", "sub"}

        boosted = 0
        for addr, fid in fused.items():
            xref_data = raw.get(addr)
            if xref_data is None:
                continue

            # Generic isimlere boost verme -- yaniltici olur
            if fid.identified_as:
                id_lower = fid.identified_as.lower()
                if id_lower in _GENERIC_NAMES or id_lower.endswith("_caller"):
                    continue

            # xref_count'u cikar
            if isinstance(xref_data, dict):
                xref_count = xref_data.get("xref_count", 0)
                if isinstance(xref_count, list):
                    xref_count = len(xref_count)
            elif isinstance(xref_data, list):
                xref_count = len(xref_data)
            elif isinstance(xref_data, (int, float)):
                xref_count = int(xref_data)
            else:
                continue

            # Boost uygula
            if xref_count > 100:
                multiplier = 1.3
            elif xref_count > 50:
                multiplier = 1.2
            elif xref_count > 20:
                multiplier = 1.1
            else:
                continue

            old_conf = fid.fused_confidence
            fid.fused_confidence = min(old_conf * multiplier, 0.98)
            boosted += 1
            logger.debug(
                "Xref boost: %s xref=%d, %.3f -> %.3f",
                addr, xref_count, old_conf, fid.fused_confidence,
            )

        if boosted:
            logger.info("Xref boost uygulandi: %d fonksiyon", boosted)

    # ------------------------------------------------------------------
    # String evidence dogrulama
    # ------------------------------------------------------------------

    def _validate_with_strings(
        self,
        fused: dict[str, FusedIdentification],
        strings_json: Path | None,
    ) -> None:
        """Binary'deki string'ler ile algoritma tespitini dogrula (in-place).

        Eger tespit edilen algoritma/kutuphane adi binary string'lerde geciyorsa
        bu guclu bir dogrulama sinyalidir ve confidence arttirilir.

        Ornek: CFG "quicksort" dedi, string'lerde "qsort" var -> boost
               CFG "aes_encrypt" dedi, string'lerde "AES" var -> boost

        Args:
            fused: Mevcut birlestirmis tanimlamalar (in-place guncellenir).
            strings_json: Binary string'ler JSON. Beklenen format:
                {"strings": ["str1", "str2", ...]} veya dogrudan ["str1", ...].
        """
        if strings_json is None or not strings_json.exists():
            logger.debug("Strings JSON bulunamadi -- string dogrulama atlaniyor")
            return

        try:
            raw = json.loads(strings_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Strings JSON okunamiyor: %s -- %s", strings_json, exc)
            return

        # String listesini cikar
        if isinstance(raw, dict):
            string_list = raw.get("strings", raw.get("defined_strings", []))
        elif isinstance(raw, list):
            string_list = raw
        else:
            return

        if not string_list:
            return

        # Tum string'leri kucuk harfe cevirip tek set'te topla
        all_strings_lower: set[str] = set()
        for s in string_list:
            if isinstance(s, str):
                all_strings_lower.add(s.lower())
            elif isinstance(s, dict):
                # {"value": "...", "address": "0x..."} formati
                val = s.get("value", s.get("string", ""))
                if val:
                    all_strings_lower.add(val.lower())

        if not all_strings_lower:
            return

        # Her tanimlama icin string match ara
        validated = 0
        for addr, fid in fused.items():
            if not fid.identified_as:
                continue

            # identified_as'i parcalara bol ve kucuk harf yap
            hypothesis_lower = fid.identified_as.lower().replace("_", " ")
            # Ana kelimeyi ve varyasyonlarini olustur
            keywords = {hypothesis_lower, hypothesis_lower.replace(" ", "")}
            # Her kelimeyi ayri da ekle (orn: "quick sort" -> "quick", "sort")
            for word in hypothesis_lower.split():
                if len(word) >= 5:  # 5 karakterden kisa kelimeleri atla (false positive onleme)
                    keywords.add(word)

            # String'lerde eslesen var mi? -- Word boundary match kullan
            # Substring yerine kelimenin basinda/sonunda non-alnum karakter olmali
            found_match = False
            for kw in keywords:
                for s in all_strings_lower:
                    # Word boundary match: kw'nin s icinde gecip gecmedigini kontrol et
                    idx = s.find(kw)
                    if idx == -1:
                        continue
                    # Sol boundary: basinda mi yoksa onceki karakter non-alnum mi?
                    left_ok = (idx == 0) or not s[idx - 1].isalnum()
                    # Sag boundary: sonunda mi yoksa sonraki karakter non-alnum mi?
                    end_idx = idx + len(kw)
                    right_ok = (end_idx >= len(s)) or not s[end_idx].isalnum()
                    if left_ok and right_ok:
                        found_match = True
                        break
                if found_match:
                    break

            if found_match:
                old_conf = fid.fused_confidence
                # Boost: %15 artis, max 0.98
                fid.fused_confidence = min(old_conf * 1.15, 0.98)
                fid.propagated_hints.append(
                    f"string_evidence: '{fid.identified_as}' found in binary strings"
                )
                validated += 1
                logger.debug(
                    "String dogrulama: %s '%s', %.3f -> %.3f",
                    addr, fid.identified_as, old_conf, fid.fused_confidence,
                )

        if validated:
            logger.info("String dogrulama uygulandi: %d fonksiyon", validated)

    # ------------------------------------------------------------------
    # Import table sinyal kaynagi
    # ------------------------------------------------------------------

    # Kutuphane adi -> (iliskili hipotez anahtar kelimeleri, kategori, boost carpani)
    _IMPORT_LIB_MAP: dict[str, tuple[list[str], str, float]] = {
        "libssl": (["ssl", "tls", "openssl", "aes", "sha", "evp", "rsa"], "crypto", 1.12),
        "libcrypto": (["aes", "sha", "md5", "evp", "rsa", "hmac", "crypto"], "crypto", 1.12),
        "libz": (["zlib", "deflate", "inflate", "compress", "gzip"], "compression", 1.10),
        "libsqlite3": (["sqlite", "database", "sql", "query"], "database", 1.10),
        "libpthread": (["thread", "pthread", "mutex", "concurrency"], "concurrency", 1.08),
        "libm": (["sin", "cos", "sqrt", "exp", "log", "math", "pow"], "math", 1.05),
        "libcurl": (["curl", "http", "url", "transfer", "download"], "network", 1.10),
        "libpcap": (["pcap", "packet", "capture", "sniff"], "network", 1.10),
        "libxml2": (["xml", "parse", "xpath", "sax", "dom"], "parsing", 1.10),
        "libjson": (["json", "parse", "serialize"], "parsing", 1.10),
        "libpng": (["png", "image", "pixel"], "image", 1.08),
        "libjpeg": (["jpeg", "jpg", "image", "compress"], "image", 1.08),
        "libgmp": (["bignum", "multiprecision", "gmp", "mpz"], "math", 1.10),
        "libfftw": (["fft", "fourier", "spectral", "fftw"], "math", 1.12),
        "libblas": (["blas", "dgemm", "dgemv", "matrix", "vector"], "linear_algebra", 1.12),
        "liblapack": (["lapack", "dgetrf", "dgetrs", "eigenvalue", "svd"], "linear_algebra", 1.12),
    }

    def _add_import_signal(
        self,
        fused: dict[str, FusedIdentification],
        dynamic_libs_json: Path | None,
    ) -> None:
        """Import tablosundaki kutuphane isimlerinden ek sinyal (in-place).

        Dynamic libraries listesinden (libssl, libz, libsqlite3 vb.) ilgili
        fonksiyonlara confidence boost uygular. Eger bir fonksiyon "aes_encrypt"
        olarak tanimlanmis ve binary libssl import ediyorsa, bu guclu bir
        dogrulama sinyalidir.

        Args:
            fused: Mevcut birlestirmis tanimlamalar (in-place guncellenir).
            dynamic_libs_json: Dynamic library JSON dosya yolu. Beklenen format:
                {"libraries": ["libssl.so.3", ...]} veya
                {"imports": {func_addr: {"library": "libssl", ...}}} veya
                dogrudan ["libssl.so.3", ...].
        """
        if dynamic_libs_json is None or not dynamic_libs_json.exists():
            logger.debug("Dynamic libs JSON bulunamadi -- import sinyal atlaniyor")
            return

        try:
            raw = json.loads(dynamic_libs_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Dynamic libs JSON okunamiyor: %s -- %s", dynamic_libs_json, exc,
            )
            return

        # Kutuphane listesini cikar
        lib_names: list[str] = []
        per_func_libs: dict[str, list[str]] = {}  # func_addr -> [lib, ...]

        if isinstance(raw, dict):
            # Format 1: {"libraries": [...]}
            if "libraries" in raw:
                lib_names = raw["libraries"]
            # Format 2: {"imports": {func_addr: {"library": "..."}}}
            if "imports" in raw and isinstance(raw["imports"], dict):
                for func_addr, imp_data in raw["imports"].items():
                    if isinstance(imp_data, dict):
                        lib = imp_data.get("library", "")
                        if lib:
                            per_func_libs.setdefault(func_addr, []).append(lib)
                    elif isinstance(imp_data, list):
                        for entry in imp_data:
                            lib = entry.get("library", "") if isinstance(entry, dict) else str(entry)
                            if lib:
                                per_func_libs.setdefault(func_addr, []).append(lib)
        elif isinstance(raw, list):
            lib_names = raw

        if not lib_names and not per_func_libs:
            return

        # Kutuphane adlarini normalize et (libssl.so.3 -> libssl)
        def _normalize_lib(name: str) -> str:
            # lib ismi: path'in son parcasi, .so/.dylib/.dll'den once
            base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            for suffix in (".so", ".dylib", ".dll", ".a"):
                idx = base.find(suffix)
                if idx > 0:
                    base = base[:idx]
                    break
            return base.lower()

        normalized_libs: set[str] = set()
        for lib in lib_names:
            if isinstance(lib, str):
                normalized_libs.add(_normalize_lib(lib))

        # Per-func lib'leri de normalize et
        normalized_per_func: dict[str, set[str]] = {}
        for func_addr, libs in per_func_libs.items():
            normalized_per_func[func_addr] = {_normalize_lib(l) for l in libs}

        # Hangi kategorilere boost uygulanacak?
        active_categories: dict[str, float] = {}  # category -> max boost
        for lib_key, (keywords, category, boost) in self._IMPORT_LIB_MAP.items():
            if lib_key in normalized_libs:
                if category not in active_categories or boost > active_categories[category]:
                    active_categories[category] = boost

        if not active_categories and not normalized_per_func:
            return

        boosted = 0
        for addr, fid in fused.items():
            if not fid.identified_as:
                continue

            id_lower = fid.identified_as.lower()
            applied_boost = 1.0

            # Global lib check: kategori eslesmesi
            if fid.category and fid.category.lower() in active_categories:
                applied_boost = max(applied_boost, active_categories[fid.category.lower()])

            # Global lib check: hipotez anahtar kelime eslesmesi
            for lib_key, (keywords, category, boost) in self._IMPORT_LIB_MAP.items():
                if lib_key not in normalized_libs:
                    continue
                for kw in keywords:
                    if kw in id_lower:
                        applied_boost = max(applied_boost, boost)
                        break

            # Per-function lib check
            func_libs = normalized_per_func.get(addr, set())
            for lib_key, (keywords, category, boost) in self._IMPORT_LIB_MAP.items():
                if lib_key in func_libs:
                    for kw in keywords:
                        if kw in id_lower:
                            applied_boost = max(applied_boost, boost)
                            break

            if applied_boost > 1.0:
                old_conf = fid.fused_confidence
                fid.fused_confidence = min(old_conf * applied_boost, 0.98)
                fid.propagated_hints.append(
                    f"import_signal: matched libs={normalized_libs & set(self._IMPORT_LIB_MAP.keys())}"
                )
                boosted += 1
                logger.debug(
                    "Import boost: %s '%s', boost=%.2f, %.3f -> %.3f",
                    addr, fid.identified_as, applied_boost, old_conf, fid.fused_confidence,
                )

        if boosted:
            logger.info("Import signal boost uygulandi: %d fonksiyon", boosted)

    # ------------------------------------------------------------------
    # Callee-based inference
    # ------------------------------------------------------------------

    # Bilinen callee pattern -> muhtemel ust fonksiyon isimleri
    _CALLEE_PATTERNS: list[tuple[set[str], str, str]] = [
        # (callee keywords seti, inferred name, category)
        ({"malloc", "memset", "dgemm", "free"}, "matrix_operation_wrapper", "linear_algebra"),
        ({"malloc", "memset", "free"}, "memory_management_wrapper", "memory"),
        ({"fopen", "fread", "fclose"}, "file_reader", "io"),
        ({"fopen", "fwrite", "fclose"}, "file_writer", "io"),
        ({"fopen", "fprintf", "fclose"}, "file_logger", "io"),
        ({"socket", "connect", "send", "recv"}, "network_client", "network"),
        ({"socket", "bind", "listen", "accept"}, "network_server", "network"),
        ({"pthread_create", "pthread_join"}, "thread_manager", "concurrency"),
        ({"malloc", "realloc", "free"}, "dynamic_array", "data_structure"),
        ({"sin", "cos"}, "trigonometric_computation", "math"),
        ({"sin", "cos", "sqrt"}, "vector_rotation", "math"),
        ({"exp", "log"}, "exponential_computation", "math"),
        ({"pow", "sqrt"}, "power_computation", "math"),
        ({"dgemm", "dgemv"}, "blas_wrapper", "linear_algebra"),
        ({"dgetrf", "dgetrs"}, "lapack_solver", "linear_algebra"),
        ({"AES_encrypt", "AES_decrypt"}, "aes_wrapper", "crypto"),
        ({"SHA256_Init", "SHA256_Update", "SHA256_Final"}, "sha256_wrapper", "crypto"),
        ({"EVP_EncryptInit", "EVP_EncryptUpdate", "EVP_EncryptFinal"}, "openssl_encrypt", "crypto"),
        ({"qsort"}, "sorting_wrapper", "sorting"),
        ({"strcmp", "strncmp", "strlen"}, "string_processor", "string"),
        # --- v1.4.1 eklenen pattern'ler ---
        # Compression
        ({"deflateInit", "deflate", "deflateEnd"}, "zlib_compress_wrapper", "compression"),
        ({"inflateInit", "inflate", "inflateEnd"}, "zlib_decompress_wrapper", "compression"),
        # Database
        ({"sqlite3_open", "sqlite3_exec", "sqlite3_close"}, "sqlite_database_handler", "database"),
        ({"sqlite3_prepare", "sqlite3_step", "sqlite3_finalize"}, "sqlite_query_executor", "database"),
        # Crypto init/update/final
        ({"MD5_Init", "MD5_Update", "MD5_Final"}, "md5_hash_wrapper", "crypto"),
        ({"SHA256_Init", "SHA256_Update", "SHA256_Final"}, "sha256_hash_wrapper", "crypto"),
        ({"EVP_EncryptInit", "EVP_EncryptUpdate", "EVP_EncryptFinal"}, "evp_encrypt_wrapper", "crypto"),
        ({"EVP_DecryptInit", "EVP_DecryptUpdate", "EVP_DecryptFinal"}, "evp_decrypt_wrapper", "crypto"),
        # Process
        ({"fork", "execve", "waitpid"}, "process_spawn_handler", "process"),
        ({"pipe", "dup2", "execve"}, "pipe_exec_handler", "process"),
        # Filesystem
        ({"opendir", "readdir", "closedir"}, "directory_scanner", "filesystem"),
        ({"stat", "chmod", "chown"}, "file_permission_handler", "filesystem"),
        # Network extended
        ({"getaddrinfo", "socket", "connect"}, "dns_connect_handler", "network"),
        ({"SSL_CTX_new", "SSL_new", "SSL_connect"}, "tls_client_handler", "crypto"),
        ({"SSL_CTX_new", "SSL_new", "SSL_accept"}, "tls_server_handler", "crypto"),
        # C++ allocator (mangled names)
        ({"_Znwm", "_ZdlPv"}, "cpp_new_delete_wrapper", "memory"),
        # String extended
        ({"strlen", "strdup", "strcpy"}, "string_copy_handler", "string"),
        ({"regex_compile", "regex_exec", "regex_free"}, "regex_handler", "string"),
        ({"json_parse", "json_get", "json_free"}, "json_handler", "parsing"),
    ]

    def _infer_from_callees(
        self,
        fused: dict[str, FusedIdentification],
        call_graph: dict[str, list[str]],
    ) -> None:
        """Fonksiyonun cagirdigi bilinen fonksiyonlardan ust fonksiyonu cikar (in-place).

        Eger func_A -> {malloc, memset, dgemm, free} cagriyorsa:
        func_A muhtemelen "matrix_operation_wrapper".

        Bu metod sadece henuz tanimlanmamis (identified_as bos) veya
        dusuk guvenli fonksiyonlar icin calisan ek bir inferans katmanidir.

        Args:
            fused: Mevcut tanimlamalar (in-place guncellenir).
            call_graph: {caller_addr: [callee_addr, ...]} eslesmesi.
        """
        # Once callee addr -> bilinen isim eslesmesi olustur
        # Tanimlanmis fonksiyonlardan bilinen isimleri al
        known_names: dict[str, str] = {}  # addr -> identified_as
        for addr, fid in fused.items():
            if fid.identified_as and fid.fused_confidence >= 0.60:
                known_names[addr] = fid.identified_as

        inferred_count = 0
        for caller_addr, callee_addrs in call_graph.items():
            # Caller'in callee'lerinin bilinen isimlerini topla
            callee_names: set[str] = set()
            for callee_addr in callee_addrs:
                name = known_names.get(callee_addr, "")
                if name:
                    # Ismi normalize et (orn: "malloc_wrapper" -> "malloc")
                    base_name = name.lower().replace("_wrapper", "").replace("_caller", "")
                    callee_names.add(base_name)

            if not callee_names:
                continue

            # Callee pattern eslestirmesi
            best_match: tuple[str, str, float] | None = None  # (name, cat, score)
            for required_callees, inferred_name, category in self._CALLEE_PATTERNS:
                # Kac required callee bulunuyor?
                matched = required_callees & callee_names
                if len(matched) >= len(required_callees):
                    # Tam eslesti
                    score = 0.55
                elif len(matched) >= max(1, len(required_callees) - 1):
                    # Neredeyse tam eslesti (1 eksik tolere edilir)
                    score = 0.40
                else:
                    continue

                if best_match is None or score > best_match[2]:
                    best_match = (inferred_name, category, score)

            if best_match is None:
                continue

            inferred_name, category, score = best_match

            # Caller'i guncelle
            if caller_addr in fused:
                fid = fused[caller_addr]
                # Sadece dusuk guvenli veya tanimlanmamis olanlari guncelle
                if fid.fused_confidence < 0.50 or not fid.identified_as:
                    fid.identified_as = inferred_name
                    fid.category = category
                    fid.fused_confidence = max(fid.fused_confidence, score)
                    fid.propagated_hints.append(
                        f"callee_inference: calls {callee_names} -> {inferred_name}"
                    )
                    inferred_count += 1
            else:
                # Yeni tanimlama olustur
                fused[caller_addr] = FusedIdentification(
                    function_name="",
                    function_address=caller_addr,
                    identified_as=inferred_name,
                    category=category,
                    fused_confidence=score,
                    propagated_hints=[
                        f"callee_inference: calls {callee_names} -> {inferred_name}"
                    ],
                )
                inferred_count += 1

        if inferred_count:
            logger.info("Callee-based inference: %d fonksiyon", inferred_count)

    # ------------------------------------------------------------------
    # Yardimci metodlar
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_hypothesis(name: str) -> str:
        """Hipotez adini normalize et.

        quicksort, quick_sort, QuickSort, quick-sort -> quicksort
        Ayni algoritmaya farkli kaynaklardan farkli isimler gelebilir;
        bu metod hepsini ayni anahtara indirger.

        Args:
            name: Ham hipotez adi.

        Returns:
            str: Normalize edilmis hipotez.
        """
        if not name:
            return ""
        return name.strip().lower().replace("-", "_").replace(" ", "_").rstrip("_")

    @staticmethod
    def _to_function_name(raw: str) -> str:
        """Ham ismi C fonksiyon adi formatina cevir.

        Ornek: "Quicksort with Lomuto" -> "quicksort_with_lomuto"
        Ornek: "AES-128 Round" -> "aes_128_round"

        Args:
            raw: Ham isim.

        Returns:
            str: C-uyumlu fonksiyon adi.
        """
        if not raw:
            return ""
        # Kucuk harf, ozel karakterleri kaldir
        result = raw.strip().lower()
        result = result.replace("-", "_").replace(" ", "_").replace(".", "_")
        # Ardisik underscore'lari tek yap
        while "__" in result:
            result = result.replace("__", "_")
        # Bas/son underscore'lari kaldir
        result = result.strip("_")
        return result

    @staticmethod
    def _load_call_graph(call_graph_json: Path) -> dict[str, list[str]]:
        """Call graph JSON'dan caller -> callee eslesmesini yukle.

        Beklenen JSON formati:
        {
            "call_graph": {
                "0x1234": ["0x5678", "0x9abc"],
                ...
            }
        }
        veya dogrudan {caller: [callees]} formati.

        Args:
            call_graph_json: JSON dosya yolu.

        Returns:
            dict: caller_addr -> [callee_addr, ...] eslesmesi.
        """
        call_graph_json = Path(call_graph_json) if not isinstance(call_graph_json, Path) else call_graph_json
        if not call_graph_json.exists():
            logger.warning("Call graph dosyasi bulunamadi: %s", call_graph_json)
            return {}

        try:
            raw = json.loads(call_graph_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Call graph okunamiyor: %s -- %s", call_graph_json, exc)
            return {}

        if isinstance(raw, dict):
            # Ghidra call graph formati: {"edges": [{"from": addr, "to": addr, "from_name": ..., "to_name": ...}]}
            if "edges" in raw and isinstance(raw["edges"], list):
                result: dict[str, list[str]] = {}
                for edge in raw["edges"]:
                    caller = edge.get("from_name", edge.get("from", ""))
                    callee = edge.get("to_name", edge.get("to", ""))
                    if caller and callee:
                        result.setdefault(caller, []).append(callee)
                return result

            # Eski format: {"call_graph": {caller: [callees]}} veya {caller: [callees]}
            if "call_graph" in raw:
                cg = raw["call_graph"]
            elif "calls" in raw:
                cg = raw["calls"]
            else:
                cg = raw

            result2: dict[str, list[str]] = {}
            for caller, callees in cg.items():
                if isinstance(callees, list):
                    result2[caller] = [c if isinstance(c, str) else str(c) for c in callees]
                elif isinstance(callees, str):
                    result2[caller] = [callees]
            return result2

        return {}


# ---------------------------------------------------------------------------
# Yardimci fonksiyonlar (modul duzeyi)
# ---------------------------------------------------------------------------

def _cfg_match_to_dict(match: Any) -> dict[str, Any]:
    """CFGMatch objesini dict'e cevir (to_dict yoksa fallback).

    Args:
        match: CFGMatch veya benzeri obje.

    Returns:
        dict: Eslestirme bilgisi.
    """
    if hasattr(match, "to_dict"):
        return match.to_dict()
    return {
        "function_name": getattr(match, "function_name", ""),
        "function_address": getattr(match, "function_address", ""),
        "matched_algorithm": getattr(match, "matched_algorithm", ""),
        "matched_category": getattr(match, "matched_category", ""),
        "similarity": getattr(match, "similarity", 0.0),
        "confidence": getattr(match, "confidence", 0.0),
    }
