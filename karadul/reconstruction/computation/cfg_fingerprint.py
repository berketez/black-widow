"""Layer 2: CFG Fingerprinting -- bilinen algoritma sablonlariyla eslestirme.

Ghidra CFG JSON ciktisindaki her fonksiyonun CFG'sinden 24-boyutlu bir
feature vector cikarir, Weisfeiler-Lehman benzeri yapi hash'i hesaplar
ve known_algorithms.json sablonlariyla cosine similarity eslestirmesi yapar.

v1.4.1: Feature vector 16-dim -> 24-dim genisletildi.
         Cosine similarity backward-compatible (padding destegi).
v1.5.9: Feature 16 (call_depth) ve 21 (recursive_flag) dolduruldu.

Kullanim:
    from karadul.reconstruction.computation.cfg_fingerprint import CFGFingerprinter
    fp = CFGFingerprinter(config)
    matches = fp.match_all(cfg_json_path)
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Normalization scale sabitleri
# ---------------------------------------------------------------------------
# min(val / scale, 1.0) ile [0,1] araligina normalize edilir.
# Degerler buyuk binary'lerdeki tipik dagilimlardan turetilmistir.

_SCALES = {
    "block_count": 100.0,
    "edge_count": 200.0,
    "loop_count": 10.0,
    "max_loop_depth": 5.0,
    "cyclomatic_complexity": 50.0,
    "dominator_tree_depth": 20.0,
    "avg_block_size": 30.0,
    "max_block_size": 100.0,
}


# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class CFGFingerprint:
    """24-boyutlu feature vector + yapisi hash.

    Attributes:
        function_name: Fonksiyon adi (Ghidra'dan).
        function_address: Fonksiyon giris adresi.
        feature_vector: 24 float'lik normalized feature dizisi.
        structure_hash: Weisfeiler-Lehman benzeri adres-bagimsiz hash.
    """
    function_name: str
    function_address: str
    feature_vector: list[float] = field(default_factory=list)
    structure_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "function_address": self.function_address,
            "feature_vector": self.feature_vector,
            "structure_hash": self.structure_hash,
        }


@dataclass
class CFGTemplate:
    """Bilinen bir algoritmanin CFG sablonu.

    known_algorithms.json'dan yuklenir.

    Attributes:
        name: Algoritma adi (ornek: "quicksort").
        category: Kategori (ornek: "sorting").
        fingerprint: 24-dim referans feature vector (eski 16-dim de desteklenir).
        structure_hash: Beklenen yapi hash'i.
        description: Kisa aciklama.
        expected_params: Beklenen parametre tipleri.
        expected_return: Beklenen donus tipi.
    """
    name: str
    category: str
    fingerprint: list[float] = field(default_factory=list)
    structure_hash: str = ""
    description: str = ""
    expected_params: dict[str, str] = field(default_factory=dict)
    expected_return: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "fingerprint": self.fingerprint,
            "structure_hash": self.structure_hash,
            "description": self.description,
            "expected_params": self.expected_params,
            "expected_return": self.expected_return,
        }


@dataclass
class CFGMatch:
    """Bir fonksiyonun sablon eslestirme sonucu.

    Attributes:
        function_name: Eslestirilen fonksiyonun mevcut adi.
        function_address: Fonksiyon giris adresi.
        matched_algorithm: Eslesen sablonun adi.
        matched_category: Eslesen sablonun kategorisi.
        similarity: Cosine similarity degeri [0,1].
        confidence: Toplam guven skoru [0,1] (similarity + hash bonus).
        fingerprint: Fonksiyonun 24-dim fingerprint'i.
    """
    function_name: str
    function_address: str
    matched_algorithm: str
    matched_category: str
    similarity: float
    confidence: float
    fingerprint: CFGFingerprint | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "function_address": self.function_address,
            "matched_algorithm": self.matched_algorithm,
            "matched_category": self.matched_category,
            "similarity": round(self.similarity, 4),
            "confidence": round(self.confidence, 4),
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
        }


# ---------------------------------------------------------------------------
# CFGFingerprinter -- ana sinif
# ---------------------------------------------------------------------------

class CFGFingerprinter:
    """CFG'lerden fingerprint cikar ve bilinen sablonlarla eslestirir.

    Args:
        config: Opsiyonel config dict -- threshold degerleri icin.
            - similarity_threshold (float): Min cosine similarity (varsayilan 0.85).
            - hash_bonus (float): structure_hash eslesmesinde ek guven (varsayilan 0.15).
            - max_matches_per_function (int): Fonksiyon basina max eslesme (varsayilan 3).
        templates_path: known_algorithms.json yolu.
            None ise varsayilan konum (templates/known_algorithms.json) kullanilir.
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        templates_path: Path | None = None,
    ) -> None:
        config = config or {}
        self._similarity_threshold: float = config.get("similarity_threshold", 0.85)
        self._hash_bonus: float = config.get("hash_bonus", 0.15)
        self._max_matches: int = config.get("max_matches_per_function", 3)

        # Sablonlari yukle
        if templates_path is None:
            templates_path = Path(__file__).parent / "templates" / "known_algorithms.json"
        self._templates: list[CFGTemplate] = self._load_templates(templates_path)
        logger.info(
            "CFGFingerprinter baslatildi: %d sablon yuklendi, threshold=%.2f",
            len(self._templates),
            self._similarity_threshold,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fingerprint_function(self, func_cfg: dict[str, Any]) -> CFGFingerprint:
        """Tek bir fonksiyonun CFG'sinden fingerprint cikar.

        Args:
            func_cfg: Ghidra CFG JSON'daki tek fonksiyon dict'i.
                Beklenen anahtarlar: name, address, blocks, edges,
                cyclomatic_complexity, loop_headers, back_edges.

        Returns:
            CFGFingerprint: 24-dim feature vector ve yapi hash'i.
        """
        name = func_cfg.get("name", "unknown")
        address = func_cfg.get("address", "0x0")

        fv = self._compute_feature_vector(func_cfg)
        sh = self._compute_structure_hash(func_cfg)

        return CFGFingerprint(
            function_name=name,
            function_address=address,
            feature_vector=fv,
            structure_hash=sh,
        )

    def match_all(
        self,
        cfg_json_path: Path | None = None,
        cfg_data: dict[str, Any] | None = None,
        templates: list[CFGTemplate] | None = None,
    ) -> list[CFGMatch]:
        """Tum fonksiyonlari sablonlarla eslestirir.

        cfg_json_path veya cfg_data'dan biri verilmeli.

        Args:
            cfg_json_path: ghidra_cfg.json dosya yolu.
            cfg_data: Onceden parse edilmis CFG dict (functions listesi icermeli).
            templates: Kullanilacak sablonlar. None ise yuklenenleri kullan.

        Returns:
            list[CFGMatch]: Threshold ustu eslesmeler, confidence'a gore sirali.
        """
        if cfg_data is None:
            if cfg_json_path is None:
                logger.error("cfg_json_path veya cfg_data verilmeli")
                return []
            try:
                raw = json.loads(cfg_json_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
                logger.error("CFG JSON okunamiyor: %s -- %s", cfg_json_path, exc)
                return []
            cfg_data = raw

        functions = cfg_data.get("functions", [])
        if not isinstance(functions, list):
            logger.error("CFG JSON 'functions' listesi degil")
            return []

        active_templates = templates if templates is not None else self._templates
        if not active_templates:
            logger.warning("Hic sablon yuklenmemis, eslestirme yapilamaz")
            return []

        # -- Phase 1: Fingerprint extraction (per-function, CPU) --
        fingerprints: list[CFGFingerprint] = []
        fp_indices: list[int] = []  # functions listesindeki indeks (trivial atlaninca gerekli)

        for idx, func_cfg in enumerate(functions):
            try:
                fp = self.fingerprint_function(func_cfg)
            except Exception as exc:
                logger.warning(
                    "Fingerprint cikarilemiyor: %s -- %s",
                    func_cfg.get("name", "?"),
                    exc,
                )
                continue

            # Trivial fonksiyonlari atla (1-2 block)
            block_count = len(func_cfg.get("blocks", []))
            if block_count < 3:
                continue

            fingerprints.append(fp)
            fp_indices.append(idx)

        if not fingerprints:
            logger.info("CFG eslestirme: islenecek non-trivial fonksiyon yok")
            return []

        # -- Phase 2: Similarity hesaplama --
        # Template fingerprint'leri hazirla (bos olanlari filtrele)
        valid_templates: list[CFGTemplate] = [
            t for t in active_templates if t.fingerprint
        ]
        if not valid_templates:
            logger.warning("Gecerli fingerprint'i olan sablon yok")
            return []

        # -- Phase 3: Match assembly --
        # Per-pair cosine similarity + structure hash bonus + margin filtering.
        all_matches: list[CFGMatch] = []

        for fi, fp in enumerate(fingerprints):
            func_matches: list[CFGMatch] = []

            for ti, tmpl in enumerate(valid_templates):
                sim = self._cosine_similarity(fp.feature_vector, tmpl.fingerprint)

                if sim < self._similarity_threshold:
                    continue

                # Domain-specific template'ler icin minimum block_count kontrolu.
                # feature_vector[0] = block_count (normalized log).
                # Kucuk fonksiyonlar domain-specific algoritma olamaz.
                if tmpl.category in ("cfd", "fea", "finance") and fp.feature_vector and fp.feature_vector[0] < 0.5:
                    continue

                # Structure hash bonusu
                confidence = sim
                if fp.structure_hash and tmpl.structure_hash:
                    if fp.structure_hash == tmpl.structure_hash:
                        confidence = min(confidence + self._hash_bonus, 0.99)

                func_matches.append(CFGMatch(
                    function_name=fp.function_name,
                    function_address=fp.function_address,
                    matched_algorithm=tmpl.name,
                    matched_category=tmpl.category,
                    similarity=sim,
                    confidence=confidence,
                    fingerprint=fp,
                ))

            # En iyi N eslesmeyi al — margin-based filtering (v1.5.3, v1.8.0 sikistirildi)
            func_matches.sort(key=lambda m: m.confidence, reverse=True)
            if len(func_matches) >= 2:
                margin = func_matches[0].confidence - func_matches[1].confidence
                if margin < 0.10:
                    # Top-2 arasi fark <%10 → template'lar ayirt edilemiyor, hicbirini alma
                    func_matches = []
            all_matches.extend(func_matches[: self._max_matches])

        # Global siralama
        all_matches.sort(key=lambda m: m.confidence, reverse=True)
        logger.info(
            "CFG eslestirme tamamlandi: %d fonksiyon islendi, %d eslesme bulundu",
            len(functions),
            len(all_matches),
        )
        return all_matches

    # ------------------------------------------------------------------
    # Feature vector hesaplama (24-dim)
    # ------------------------------------------------------------------

    def _compute_feature_vector(self, func_cfg: dict[str, Any]) -> list[float]:
        """24-boyutlu normalized feature vector hesapla.

        Feature sirasi:
            0:  block_count (normalized log)
            1:  edge_count (normalized log)
            2:  loop_count
            3:  max_loop_depth
            4:  cyclomatic_complexity (normalized log)
            5:  diamond_count / block_count
            6:  back_edge_count / edge_count
            7:  dominator_tree_depth (normalized)
            8:  entry_block_out_degree
            9:  exit_block_in_degree
            10: avg_block_size (instruction count, normalized)
            11: max_block_size (normalized)
            12: conditional_edge_ratio
            13: fall_through_edge_ratio
            14: self_loop_count
            15: linear_chain_ratio
            -- v1.4.1 eklenen feature'lar --
            16: call_depth (v1.5.9: CALL/BL/BLR sayisi / 10.0)
            17: arithmetic_intensity
            18: constant_usage_ratio (reserved, 0.0 default)
            19: switch_case_ratio
            20: memory_access_pattern
            21: recursive_flag (v1.5.9: self-call tespit, 0.0 veya 1.0)
            22: simd_indicator (reserved, 0.0 default)
            23: avg_operand_complexity

        Args:
            func_cfg: Ghidra CFG JSON fonksiyon dict'i.

        Returns:
            list[float]: 24 degerlik normalized vector.
        """
        blocks = func_cfg.get("blocks", [])
        edges = func_cfg.get("edges", [])
        loop_headers = func_cfg.get("loop_headers", [])
        back_edges_raw = func_cfg.get("back_edges", [])

        n_blocks = len(blocks)
        n_edges = len(edges)
        n_loops = len(loop_headers)
        n_back_edges = len(back_edges_raw)
        complexity = func_cfg.get("cyclomatic_complexity", 0)

        # -- Adjacency bilgileri --
        # Successor/predecessor sayilari
        out_degree: dict[str, int] = {}
        in_degree: dict[str, int] = {}
        block_addrs: set[str] = set()

        for b in blocks:
            addr = b.get("start_address", "")
            block_addrs.add(addr)
            out_degree[addr] = 0
            in_degree[addr] = 0

        conditional_count = 0
        fall_through_count = 0
        self_loop_count = 0

        for e in edges:
            src = e.get("from_block", "")
            dst = e.get("to_block", "")
            etype = e.get("edge_type", "unknown")

            if src in out_degree:
                out_degree[src] += 1
            if dst in in_degree:
                in_degree[dst] += 1

            if etype == "conditional_jump":
                conditional_count += 1
            elif etype == "fall_through":
                fall_through_count += 1

            if src == dst:
                self_loop_count += 1

        # -- Block boyutlari --
        block_sizes: list[int] = []
        for b in blocks:
            # instruction_count varsa onu kullan, yoksa size/4 ile tahmin et
            ic = b.get("instruction_count", 0)
            if ic <= 0:
                ic = max(b.get("size", 0) // 4, 1)
            block_sizes.append(ic)

        avg_block_size = (sum(block_sizes) / n_blocks) if n_blocks > 0 else 0.0
        max_block_size = max(block_sizes, default=0)

        # -- Diamond count --
        # Diamond = 2+ giris, 1+ cikis (if-then-else join noktasi)
        diamond_count = 0
        for addr in block_addrs:
            if in_degree.get(addr, 0) >= 2 and out_degree.get(addr, 0) >= 1:
                diamond_count += 1

        # -- Max loop depth --
        # Basit heuristik: her loop header icin, kac loop header'in body'sinde
        # oldugunu tahmin et (back_edges uzerinden).
        # Detayli hesap CFGAnalyzer.detect_loops() ile yapilir ama burasi
        # lightweight olmali. Loop sayisi ve back_edge'lerden yaklasik depth.
        max_loop_depth = self._estimate_max_loop_depth(
            loop_headers, back_edges_raw, blocks, edges,
        )

        # -- Dominator tree depth --
        dom_depth = self._estimate_dominator_depth(blocks, edges, back_edges_raw)

        # -- Entry/exit block metrikleri --
        entry_out_degree = 0
        exit_in_degree = 0
        if blocks:
            entry_addr = blocks[0].get("start_address", "")
            entry_out_degree = out_degree.get(entry_addr, 0)

            # Exit block = out_degree 0 olan block(lar)
            exit_blocks = [
                addr for addr in block_addrs
                if out_degree.get(addr, 0) == 0
            ]
            if exit_blocks:
                exit_in_degree = max(in_degree.get(eb, 0) for eb in exit_blocks)
            else:
                # Fallback: en yuksek in_degree'li block
                exit_in_degree = max(in_degree.values(), default=0)

        # -- Linear chain ratio --
        # Linear block = tam olarak 1 giris, 1 cikis
        linear_count = 0
        for addr in block_addrs:
            if in_degree.get(addr, 0) == 1 and out_degree.get(addr, 0) == 1:
                linear_count += 1
        linear_chain_ratio = (linear_count / n_blocks) if n_blocks > 0 else 0.0

        # -- Feature vector olustur (24 boyut) --
        def _norm_log(val: float, scale: float) -> float:
            """Log-normalized [0,1] degeri."""
            if val <= 0:
                return 0.0
            return min(math.log1p(val) / math.log1p(scale), 1.0)

        def _norm(val: float, scale: float) -> float:
            """Linear normalized [0,1] degeri."""
            if val <= 0:
                return 0.0
            return min(val / scale, 1.0)

        def _ratio(num: float, den: float) -> float:
            """Guvenli oran [0,1]."""
            if den <= 0:
                return 0.0
            return min(num / den, 1.0)

        # -- v1.4.1: Ek metrikler (feature 16-23 icin) --
        total_instructions = sum(block_sizes)

        # Feature 17: arithmetic_intensity
        # Block boyutu / edge sayisi orani -- hesaplama yogun fonksiyonlarda yuksek
        arithmetic_intensity = min(
            (total_instructions / max(n_edges, 1)) / 20.0, 1.0
        )

        # Feature 19: switch_case_ratio
        # Conditional edge sayisi / toplam edge -- yuksekse switch/case agirlikli
        switch_ratio = _ratio(conditional_count, n_edges)

        # Feature 20: memory_access_pattern
        # avg_block_size buyuk + cok loop = linear scan; kucuk block + cok loop = random
        mem_pattern = min((avg_block_size * n_loops) / 500.0, 1.0)

        # Feature 23: avg_operand_complexity
        # Instruction / block orani proxy -- complex instructions = yuksek
        avg_operand = min(
            (total_instructions / max(n_blocks, 1)) / 30.0, 1.0
        )

        # -- v1.5.9: Feature 16 -- call_depth --
        # CFG block'larindaki CALL/BL/BLR instruction sayisindan turetilir.
        # Oncelik: block'un has_call veya call_count alanlari; fallback olarak
        # instruction listesinde CALL/BL/BLR aranir.
        call_count = sum(
            1 for b in blocks
            if b.get("has_call") or b.get("call_count", 0) > 0
        )
        if call_count == 0:
            # Fallback: instruction string'lerinde CALL / BL / BLR ara
            call_count = sum(
                1 for b in blocks
                if any(
                    kw in str(b.get("instructions", ""))
                    for kw in ("CALL", "BL", "BLR")
                )
            )
            call_count = min(call_count, n_blocks)  # sanity cap
        call_depth_feature = min(call_count / 10.0, 1.0)

        # -- v1.5.9: Feature 21 -- recursive_flag --
        # Fonksiyonun kendi adresine veya adina geri cagri yapip yapmadigini
        # kontrol eder. Edge target'larinda func address veya name varsa recursive.
        func_addr = func_cfg.get("address", "")
        func_name = func_cfg.get("name", "")
        is_recursive = any(
            (func_addr and e.get("target") == func_addr)
            or (func_addr and e.get("to_block") == func_addr and e.get("edge_type") == "call")
            or (func_name and e.get("target_name") == func_name)
            for e in edges
        )
        recursive_flag = 1.0 if is_recursive else 0.0

        fv = [
            _norm_log(n_blocks, _SCALES["block_count"]),             # 0
            _norm_log(n_edges, _SCALES["edge_count"]),               # 1
            _norm(n_loops, _SCALES["loop_count"]),                   # 2
            _norm(max_loop_depth, _SCALES["max_loop_depth"]),        # 3
            _norm_log(complexity, _SCALES["cyclomatic_complexity"]), # 4
            _ratio(diamond_count, n_blocks),                         # 5
            _ratio(n_back_edges, n_edges),                           # 6
            _norm(dom_depth, _SCALES["dominator_tree_depth"]),       # 7
            _norm(entry_out_degree, 5.0),                            # 8
            _norm(exit_in_degree, 10.0),                             # 9
            _norm(avg_block_size, _SCALES["avg_block_size"]),        # 10
            _norm(max_block_size, _SCALES["max_block_size"]),        # 11
            _ratio(conditional_count, n_edges),                      # 12
            _ratio(fall_through_count, n_edges),                     # 13
            _norm(self_loop_count, 3.0),                             # 14
            linear_chain_ratio,                                      # 15
            # -- v1.4.1 -> v1.5.9: Yeni feature'lar (16-23) --
            call_depth_feature,                                      # 16: call_depth (v1.5.9)
            arithmetic_intensity,                                    # 17: arithmetic_intensity
            0.0,                                                     # 18: constant_usage_ratio (reserved)
            switch_ratio,                                            # 19: switch_case_ratio
            mem_pattern,                                             # 20: memory_access_pattern
            recursive_flag,                                          # 21: recursive_flag (v1.5.9)
            0.0,                                                     # 22: simd_indicator (reserved)
            avg_operand,                                             # 23: avg_operand_complexity
        ]

        return [round(v, 4) for v in fv]

    # ------------------------------------------------------------------
    # Structure hash (Weisfeiler-Lehman benzeri)
    # ------------------------------------------------------------------

    def _compute_structure_hash(self, func_cfg: dict[str, Any]) -> str:
        """Adres-bagimsiz yapisal hash hesapla.

        Weisfeiler-Lehman 1-dim graph hash'in basitlestirilmis versiyonu.
        Block adresleri yerine topolojik pozisyonlari kullanir, boylece
        ayni yapidaki farkli binary'ler ayni hash'i uretir.

        Algoritma:
        1. Block'lari BFS sirasiyla numaralandir (entry=0, successors=1,2,...).
        2. Her node icin (out_degree, in_degree, block_size_quantized) label'i ata.
        3. 2 iterasyon boyunca komsularin label'larini birlestirerek hash'le.
        4. Tum node label'larini sirala ve final hash olustur.

        Args:
            func_cfg: Ghidra CFG JSON fonksiyon dict'i.

        Returns:
            str: "wl_" + hex digest (16 karakter). Bos CFG icin "wl_empty".
        """
        blocks = func_cfg.get("blocks", [])
        edges = func_cfg.get("edges", [])

        if not blocks:
            return "wl_empty"

        # Adres -> BFS index eslesmesi
        addr_to_idx: dict[str, int] = {}
        successors: dict[str, list[str]] = {}

        for b in blocks:
            addr = b.get("start_address", "")
            successors[addr] = []

        for e in edges:
            src = e.get("from_block", "")
            dst = e.get("to_block", "")
            if src in successors:
                successors[src].append(dst)

        # BFS siralama (entry = ilk block)
        entry = blocks[0].get("start_address", "")
        visited: list[str] = []
        queue = [entry]
        seen: set[str] = {entry}

        while queue:
            node = queue.pop(0)
            visited.append(node)
            for succ in sorted(successors.get(node, [])):
                if succ not in seen and succ in successors:
                    seen.add(succ)
                    queue.append(succ)

        # BFS'te ulasilamayan node'lari da ekle
        for b in blocks:
            addr = b.get("start_address", "")
            if addr not in seen:
                visited.append(addr)

        for idx, addr in enumerate(visited):
            addr_to_idx[addr] = idx

        # Block boyutlarini quantize et (cok kucuk farklar hash'i degistirmesin)
        # 4 katmana ayir: tiny(0-3), small(4-10), medium(11-30), large(31+)
        block_size_map: dict[str, int] = {}
        for b in blocks:
            addr = b.get("start_address", "")
            ic = b.get("instruction_count", 0)
            if ic <= 0:
                ic = max(b.get("size", 0) // 4, 1)
            if ic <= 3:
                q = 0
            elif ic <= 10:
                q = 1
            elif ic <= 30:
                q = 2
            else:
                q = 3
            block_size_map[addr] = q

        # In/out degree hesapla
        out_deg: dict[str, int] = {b.get("start_address", ""): 0 for b in blocks}
        in_deg: dict[str, int] = {b.get("start_address", ""): 0 for b in blocks}
        for e in edges:
            src = e.get("from_block", "")
            dst = e.get("to_block", "")
            if src in out_deg:
                out_deg[src] += 1
            if dst in in_deg:
                in_deg[dst] += 1

        # Baslangic label'lari: (out_degree, in_degree, size_quantile)
        labels: dict[str, str] = {}
        for addr in addr_to_idx:
            lbl = f"{out_deg.get(addr, 0)}:{in_deg.get(addr, 0)}:{block_size_map.get(addr, 0)}"
            labels[addr] = lbl

        # WL iterasyonlari (2 tur yeterli -- 16-dim fingerprint ile birlikte
        # kullanilacak, cok hassas ayrim gereksiz)
        for _ in range(2):
            new_labels: dict[str, str] = {}
            for addr in addr_to_idx:
                neighbor_labels = sorted(
                    labels.get(s, "0:0:0")
                    for s in successors.get(addr, [])
                    if s in labels
                )
                combined = labels[addr] + "|" + ",".join(neighbor_labels)
                h = hashlib.md5(combined.encode()).hexdigest()[:8]
                new_labels[addr] = h
            labels = new_labels

        # Final hash: tum label'lari BFS sirasinda birlestir
        ordered_labels = [
            labels.get(addr, "0")
            for addr in visited
            if addr in labels
        ]
        final_str = ";".join(ordered_labels)
        digest = hashlib.sha256(final_str.encode()).hexdigest()[:16]
        return f"wl_{digest}"

    # ------------------------------------------------------------------
    # Cosine similarity
    # ------------------------------------------------------------------

    # Feature 18 (constant_usage_ratio) ve 22 (simd_indicator) daima 0.0 (reserved).
    # Cosine similarity'de gereksiz boyut olarak noise eklerler; hesaplamadan
    # haric tutulur. Vektor indexleri degismez (geriye uyumluluk).
    _ACTIVE_FEATURES = [i for i in range(24) if i not in (18, 22)]

    @staticmethod
    def _cosine_similarity(v1: list[float], v2: list[float]) -> float:
        """Iki vector arasinda cosine similarity hesapla.

        Farkli boyutlu vektorler desteklenir (kisa olan sifirla pad edilir).
        Bu sayede 16-dim eski sablonlar 24-dim yeni fingerprint'lerle
        karsilastirilabilir.

        Feature 18 (constant_usage_ratio) ve 22 (simd_indicator) daima 0.0
        oldugu icin aktif feature listesinden haric tutulur. Bu sayede
        zero-padded reserved feature'lar cosine hesabini etkilemez.

        Args:
            v1: Birinci vector.
            v2: Ikinci vector.

        Returns:
            float: Cosine similarity [0,1]. Sifir vector icin 0.0.
        """
        # Farkli boyutlarda ise kisa olani sifirla padding
        max_len = max(len(v1), len(v2))
        if len(v1) < max_len:
            v1 = v1 + [0.0] * (max_len - len(v1))
        if len(v2) < max_len:
            v2 = v2 + [0.0] * (max_len - len(v2))

        # Sadece aktif feature'lari kullan (reserved 18, 22 haric)
        active = CFGFingerprinter._ACTIVE_FEATURES
        a_active = [v1[i] for i in active if i < len(v1)]
        b_active = [v2[i] for i in active if i < len(v2)]

        dot = sum(a * b for a, b in zip(a_active, b_active))
        mag1 = math.sqrt(sum(a * a for a in a_active))
        mag2 = math.sqrt(sum(b * b for b in b_active))

        if mag1 < 1e-10 or mag2 < 1e-10:
            return 0.0

        return max(0.0, min(dot / (mag1 * mag2), 1.0))

    # ------------------------------------------------------------------
    # Yardimci metodlar
    # ------------------------------------------------------------------

    def _estimate_max_loop_depth(
        self,
        loop_headers: list[str],
        back_edges: list[Any],
        blocks: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> int:
        """Loop derinligini back-edge ve dominator bilgisinden tahmin et.

        Tam dominator-based hesap CFGAnalyzer'da yapilir.
        Burasi lightweight bir tahmin yapar:
        - Back-edge hedeflerinden (loop header'lar) nested olanlari bul.
        - Bir loop header, baska bir loop header'in "icinde" ise
          (aralarinda yol varsa ve back-edge ile kapaniyorsa) depth artar.

        Args:
            loop_headers: Loop header adresleri.
            back_edges: Back-edge (from, to) listesi.
            blocks: Block listesi.
            edges: Edge listesi.

        Returns:
            int: Tahmini max loop derinligi.
        """
        if not loop_headers:
            return 0

        if len(loop_headers) == 1:
            return 1

        # Successor haritasi olustur
        succ_map: dict[str, list[str]] = {}
        block_set: set[str] = set()
        for b in blocks:
            addr = b.get("start_address", "")
            block_set.add(addr)
            succ_map[addr] = []

        for e in edges:
            src = e.get("from_block", "")
            dst = e.get("to_block", "")
            if src in succ_map:
                succ_map[src].append(dst)

        # Her loop header icin, baska loop header'lara ulasabilir mi?
        # (eger A header'indan B header'ina yol varsa, B nested olabilir)
        header_set = set(loop_headers)
        nesting: dict[str, int] = {h: 0 for h in loop_headers}

        for h_outer in loop_headers:
            # BFS: h_outer'dan ulasilabilen header'lari bul
            visited: set[str] = set()
            queue = [h_outer]
            visited.add(h_outer)
            while queue:
                node = queue.pop(0)
                for s in succ_map.get(node, []):
                    if s not in visited and s in block_set:
                        visited.add(s)
                        queue.append(s)

            # h_outer'dan ulasilabilen diger header'lar nested
            for h_inner in loop_headers:
                if h_inner != h_outer and h_inner in visited:
                    # h_inner, h_outer'in icinde olabilir
                    nesting[h_inner] = max(nesting[h_inner], nesting.get(h_outer, 0) + 1)

        return max(nesting.values(), default=0) if nesting else 0

    def _estimate_dominator_depth(
        self,
        blocks: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        back_edges: list[Any] | None = None,
    ) -> int:
        """Dominator tree derinligini tahmin et.

        Tam Cooper-Harvey-Kennedy hesabi yerine lightweight bir BFS-based
        tahmin kullanir: entry'den en uzun path (DAG uzerinde).

        Back-edge'ler filtrelenir ki dongusel yollar sonsuz donguye
        neden olmasin. Filtreleme onceligi:
        1. back_edges parametresindeki (from, to) ciftleri
        2. Edge uzerindeki is_back_edge alani
        3. Hicbiri yoksa: visit limiti ile korunma

        Args:
            blocks: Block listesi.
            edges: Edge listesi.
            back_edges: Back-edge (from, to) listesi (opsiyonel).

        Returns:
            int: Tahmini dominator tree derinligi.
        """
        if not blocks:
            return 0

        # Back-edge ciftlerini set olarak olustur (hizli lookup icin)
        back_edge_set: set[tuple[str, str]] = set()
        if back_edges:
            for be in back_edges:
                if isinstance(be, dict):
                    src = be.get("from", be.get("from_block", ""))
                    dst = be.get("to", be.get("to_block", ""))
                    if src and dst:
                        back_edge_set.add((src, dst))

        # Forward edge'ler uzerinden en uzun yol (BFS + level tracking)
        succ_map: dict[str, list[str]] = {}
        block_set: set[str] = set()

        for b in blocks:
            addr = b.get("start_address", "")
            block_set.add(addr)
            succ_map[addr] = []

        for e in edges:
            src = e.get("from_block", "")
            dst = e.get("to_block", "")
            # Back-edge'leri dahil etme (DAG icin)
            if e.get("is_back_edge", False):
                continue
            if (src, dst) in back_edge_set:
                continue
            if src in succ_map:
                succ_map[src].append(dst)

        entry = blocks[0].get("start_address", "")
        depth: dict[str, int] = {entry: 0}
        queue = [entry]
        max_depth = 0
        n_blocks = len(blocks)

        while queue:
            node = queue.pop(0)
            current_depth = depth[node]
            # Savunma: depth asla block sayisindan buyuk olamaz
            if current_depth >= n_blocks:
                continue
            for s in succ_map.get(node, []):
                if s in block_set:
                    new_depth = current_depth + 1
                    if s not in depth or depth[s] < new_depth:
                        depth[s] = new_depth
                        max_depth = max(max_depth, new_depth)
                        queue.append(s)

        return max_depth

    def _load_templates(self, templates_path: Path) -> list[CFGTemplate]:
        """known_algorithms.json'dan sablonlari yukle.

        Args:
            templates_path: JSON dosya yolu.

        Returns:
            list[CFGTemplate]: Yuklenen sablonlar. Dosya yoksa bos liste.
        """
        if not templates_path.exists():
            logger.warning("Sablon dosyasi bulunamadi: %s", templates_path)
            return []

        try:
            raw = json.loads(templates_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Sablon dosyasi okunamiyor: %s -- %s", templates_path, exc)
            return []

        if not isinstance(raw, list):
            # {"templates": [...]} formati da desteklenir
            if isinstance(raw, dict) and "templates" in raw:
                raw = raw["templates"]
            else:
                logger.error("Sablon dosyasi liste veya {templates: []} formati degil")
                return []

        templates: list[CFGTemplate] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            if not name:
                continue

            templates.append(CFGTemplate(
                name=name,
                category=entry.get("category", "unknown"),
                fingerprint=entry.get("fingerprint", []),
                structure_hash=entry.get("structure_hash", ""),
                description=entry.get("description", ""),
                expected_params=entry.get("expected_params", {}),
                expected_return=entry.get("expected_return", ""),
            ))

        logger.debug("%d sablon yuklendi: %s", len(templates), templates_path)
        return templates

    # ------------------------------------------------------------------
    # Cross-Binary Cache API (v1.8.0)
    # ------------------------------------------------------------------
    # Cache dizini: ~/.cache/karadul/cfg_cache/
    # Her binary icin {sha256_ilk16}.json dosyasi.
    # Sadece isimlendirilmis (non-FUN_xxx) fonksiyonlar cache'lenir.

    _CACHE_DIR = Path.home() / ".cache" / "karadul" / "cfg_cache"
    _MAX_CACHE_BINARIES = 100
    _MAX_CACHE_FILE_MB = 50

    @staticmethod
    def save_to_cache(
        fingerprints: dict[str, "CFGFingerprint"],
        binary_hash: str,
        named_functions: dict[str, str] | None = None,
    ) -> bool:
        """Analiz edilen binary'nin fingerprint'lerini cache'e kaydet.

        Sadece isimlendirilmis fonksiyonlari kaydeder (FUN_xxx, sub_, thunk_ olanlar atlanir).

        Args:
            fingerprints: {func_address: CFGFingerprint} dict'i.
            binary_hash: Binary dosyanin SHA256'sinin ilk 16 karakteri.
            named_functions: {func_address: func_name} eslesmesi.
                None ise fingerprint.function_name'den alinir.

        Returns:
            bool: Basarili ise True.
        """
        try:
            cache_dir = CFGFingerprinter._CACHE_DIR
            cache_dir.mkdir(parents=True, exist_ok=True)

            # Sadece isimlendirilmis fonksiyonlari filtrele
            _unnamed_prefixes = ("FUN_", "sub_", "thunk_", "LAB_", "switchD_")
            cache_data: dict[str, dict] = {}

            for addr, fp in fingerprints.items():
                # Isim kaynagi: named_functions dict veya fingerprint'in kendi adi
                name = (named_functions or {}).get(addr, fp.function_name)
                if not name or any(name.startswith(p) for p in _unnamed_prefixes):
                    continue
                if not fp.feature_vector:
                    continue

                cache_data[addr] = {
                    "name": name,
                    "feature_vector": fp.feature_vector,
                    "structure_hash": fp.structure_hash,
                    "confidence": 1.0,  # kaynak binary'de bilinen isim
                }

            if not cache_data:
                logger.debug("Cache: Kayit edilecek isimlendirilmis fonksiyon yok")
                return True

            cache_file = cache_dir / f"{binary_hash}.json"
            import json as _json
            cache_file.write_text(
                _json.dumps(cache_data, separators=(",", ":")),
                encoding="utf-8",
            )
            logger.info(
                "CFG cache: %d fonksiyon kaydedildi -> %s",
                len(cache_data), cache_file.name,
            )

            # LRU temizligi
            CFGFingerprinter._manage_cache_lru()
            return True

        except Exception as exc:
            logger.warning("CFG cache kayit hatasi (atlaniyor): %s", exc)
            return False

    @staticmethod
    def match_from_cache(
        fingerprints: dict[str, "CFGFingerprint"],
        exclude_binary_hash: str | None = None,
    ) -> list[tuple[str, str, str, float]]:
        """Cache'deki onceki binary'lerden cross-binary eslestirme yap.

        Her unnamed fonksiyon icin cache'deki tum named fonksiyonlarla
        cosine similarity hesaplar.

        Esik kurallari:
        - similarity >= 0.90 VE structure_hash eslesmesi -> confidence 0.85
        - similarity >= 0.95 ama hash farkliysa -> confidence 0.70

        Args:
            fingerprints: {func_address: CFGFingerprint} dict'i (mevcut binary'nin).
            exclude_binary_hash: Kendi binary'sinin hash'i (self-match onleme).

        Returns:
            list[(func_address, matched_name, source_binary, confidence)]
            Bos liste: cache yok veya eslesme yok.
        """
        cache_dir = CFGFingerprinter._CACHE_DIR
        if not cache_dir.exists():
            return []

        import json as _json

        # Cache'deki tum binary fingerprint'lerini yukle
        cached_entries: list[tuple[str, dict]] = []  # (binary_hash, {addr: {...}})
        try:
            for cache_file in sorted(cache_dir.glob("*.json")):
                bh = cache_file.stem
                if bh == exclude_binary_hash:
                    continue
                try:
                    raw = _json.loads(cache_file.read_text(encoding="utf-8"))
                    if isinstance(raw, dict):
                        cached_entries.append((bh, raw))
                except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
                    logger.warning(
                        "CFG cache corrupt dosya atlaniyor: %s -- %s",
                        cache_file.name, exc,
                    )
                    continue
        except OSError as exc:
            logger.warning("CFG cache dizini okunamiyor: %s", exc)
            return []

        if not cached_entries:
            return []

        # Unnamed fonksiyonlari filtrele (sadece bunlari eslestir)
        _unnamed_prefixes = ("FUN_", "sub_", "thunk_")
        unnamed_fps: dict[str, "CFGFingerprint"] = {
            addr: fp for addr, fp in fingerprints.items()
            if fp.function_name and any(
                fp.function_name.startswith(p) for p in _unnamed_prefixes
            )
            and fp.feature_vector
        }

        if not unnamed_fps:
            logger.debug("Cross-binary match: Unnamed fonksiyon yok, atlaniyor")
            return []

        # Pre-filter: structure_hash index olustur (O(n) lookup vs O(n*m) brute-force)
        hash_index: dict[str, list[tuple[str, str, dict]]] = {}  # hash -> [(binary_hash, addr, data)]
        all_cached_count = 0
        for bh, cached_funcs in cached_entries:
            for _caddr, cdata in cached_funcs.items():
                cached_name = cdata.get("name", "")
                cached_fv = cdata.get("feature_vector", [])
                if not cached_fv or not cached_name:
                    continue
                all_cached_count += 1
                cached_sh = cdata.get("structure_hash", "")
                if cached_sh:
                    hash_index.setdefault(cached_sh, []).append((bh, _caddr, cdata))

        results: list[tuple[str, str, str, float]] = []

        for addr, fp in unnamed_fps.items():
            best_match: tuple[str, str, float] | None = None  # (name, binary_hash, confidence)

            # Strateji 1: structure_hash eslesmesi ile hizli arama
            if fp.structure_hash and fp.structure_hash in hash_index:
                for bh, _caddr, cdata in hash_index[fp.structure_hash]:
                    cached_fv = cdata.get("feature_vector", [])
                    sim = CFGFingerprinter._cosine_similarity(
                        fp.feature_vector, cached_fv,
                    )
                    if sim >= 0.90:
                        confidence = 0.85
                        cached_name = cdata["name"]
                        if best_match is None or confidence > best_match[2]:
                            best_match = (cached_name, bh, confidence)

            # Strateji 2: hash eslesmesi yoksa VE cache kucukse brute-force
            # (200K+ fonksiyonda brute-force timeout riski — sadece kucuk cache'lerde)
            if best_match is None and all_cached_count <= 50_000:
                for bh, cached_funcs in cached_entries:
                    for _caddr, cdata in cached_funcs.items():
                        cached_fv = cdata.get("feature_vector", [])
                        cached_name = cdata.get("name", "")
                        if not cached_fv or not cached_name:
                            continue
                        sim = CFGFingerprinter._cosine_similarity(
                            fp.feature_vector, cached_fv,
                        )
                        if sim >= 0.95:
                            confidence = 0.70
                            if best_match is None or confidence > best_match[2]:
                                best_match = (cached_name, bh, confidence)

            if best_match:
                results.append((addr, best_match[0], best_match[1], best_match[2]))

        logger.info(
            "Cross-binary match: %d unnamed fonksiyon tarandi, %d eslesme bulundu",
            len(unnamed_fps), len(results),
        )
        return results

    @staticmethod
    def _manage_cache_lru() -> None:
        """Cache dizininde max binary sayisini asarsa en eski dosyalari sil.

        Ayrica toplam cache boyutu > 50MB ise en eski binary'leri siler.
        """
        cache_dir = CFGFingerprinter._CACHE_DIR
        if not cache_dir.exists():
            return

        try:
            cache_files = sorted(
                cache_dir.glob("*.json"),
                key=lambda f: f.stat().st_mtime,
            )

            # Toplam boyut kontrolu (MB)
            total_size = sum(f.stat().st_size for f in cache_files)
            max_bytes = CFGFingerprinter._MAX_CACHE_FILE_MB * 1024 * 1024

            # LRU: en eski dosyalardan sil
            while (
                len(cache_files) > CFGFingerprinter._MAX_CACHE_BINARIES
                or total_size > max_bytes
            ) and cache_files:
                oldest = cache_files.pop(0)
                fsize = oldest.stat().st_size
                oldest.unlink(missing_ok=True)
                total_size -= fsize
                logger.debug("CFG cache LRU: silindi %s (%.1f KB)", oldest.name, fsize / 1024)

        except OSError as exc:
            logger.warning("CFG cache LRU temizlik hatasi: %s", exc)
