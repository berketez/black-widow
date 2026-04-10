"""Control Flow Graph analiz modulu.

Ghidra'dan cikarilan CFG verilerini analiz ederek
loop detection, cyclomatic complexity ve fonksiyon siniflandirmasi yapar.
Bu bilgiler CompositionAnalyzer'a beslenerek
algoritma pattern tespitini iyilestirir.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Veri yapilari
# ---------------------------------------------------------------------------

@dataclass
class BasicBlock:
    """Tek bir basic block -- kesintisiz instruction dizisi.

    Attributes:
        start_address: Block'un baslangic adresi (hex string).
        end_address: Block'un bitis adresi (hex string).
        size: Block'un byte cinsinden boyutu.
        instruction_count: Block icindeki instruction sayisi.
    """
    start_address: str
    end_address: str
    size: int
    instruction_count: int = 0


@dataclass
class CFGEdge:
    """Iki basic block arasindaki kontrol akis kenari.

    Attributes:
        from_block: Kaynak block'un baslangic adresi.
        to_block: Hedef block'un baslangic adresi.
        edge_type: Kenar tipi -- "fall_through", "conditional_jump",
                   "unconditional_jump", "unknown".
    """
    from_block: str
    to_block: str
    edge_type: str


@dataclass
class LoopInfo:
    """Tespit edilen bir natural loop.

    Attributes:
        header_block: Loop header'inin baslangic adresi.
        back_edge: Loop'u olusturan back-edge (from, to) tuple'i.
        body_blocks: Loop body'sindeki block adresleri kumesi.
        nesting_depth: Ic ice loop derinligi (0 = en dis loop).
    """
    header_block: str
    back_edge: tuple[str, str]
    body_blocks: set[str] = field(default_factory=set)
    nesting_depth: int = 0


@dataclass
class FunctionCFG:
    """Tek bir fonksiyonun CFG temsili.

    Attributes:
        name: Fonksiyon adi.
        address: Fonksiyon giris adresi.
        blocks: Basic block listesi.
        edges: CFG edge listesi.
        cyclomatic_complexity: McCabe cyclomatic complexity.
        loop_headers: Loop header adresleri listesi.
        back_edges: Back-edge (from, to) tuple'lari listesi.
    """
    name: str
    address: str
    blocks: list[BasicBlock] = field(default_factory=list)
    edges: list[CFGEdge] = field(default_factory=list)
    cyclomatic_complexity: int = 0
    loop_headers: list[str] = field(default_factory=list)
    back_edges: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class CFGAnalysisResult:
    """Tum fonksiyonlarin CFG analiz sonucu.

    Attributes:
        total_functions: Toplam analiz edilen fonksiyon sayisi.
        total_blocks: Toplam basic block sayisi.
        total_edges: Toplam edge sayisi.
        functions: Her fonksiyonun FunctionCFG'si.
        stats: Toplu istatistikler (classification dagilimi vb.).
    """
    total_functions: int = 0
    total_blocks: int = 0
    total_edges: int = 0
    functions: list[FunctionCFG] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# CFGAnalyzer -- ana sinif
# ---------------------------------------------------------------------------

class CFGAnalyzer:
    """Ghidra CFG JSON ciktisini analiz eden sinif.

    Ghidra'nin cfg_extraction.py script'inin urettigi
    ghidra_cfg.json dosyasini okur, dominator tree hesaplar,
    natural loop'lari tespit eder ve fonksiyonlari siniflandirir.

    Kullanim:
        analyzer = CFGAnalyzer()
        result = analyzer.analyze(Path("ghidra_cfg.json"))
        summary = analyzer.get_summary(result)
    """

    def analyze(self, cfg_json_path: Path) -> CFGAnalysisResult:
        """JSON dosyasini yukle ve tum fonksiyonlari analiz et.

        Args:
            cfg_json_path: Ghidra'nin urettigi ghidra_cfg.json dosya yolu.

        Returns:
            CFGAnalysisResult: Analiz sonucu. Hata durumunda bos result doner.
        """
        try:
            raw = json.loads(cfg_json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
            logger.error("CFG JSON okunamiyor: %s -- %s", cfg_json_path, exc)
            return CFGAnalysisResult()

        if not isinstance(raw, dict):
            logger.error("CFG JSON root dict degil: %s", type(raw).__name__)
            return CFGAnalysisResult()

        raw_functions = raw.get("functions", [])
        if not isinstance(raw_functions, list):
            logger.error("CFG JSON 'functions' listesi degil")
            return CFGAnalysisResult()

        result = CFGAnalysisResult()
        classification_counts: dict[str, int] = {
            "linear": 0,
            "branching": 0,
            "looping": 0,
            "complex": 0,
        }

        for raw_func in raw_functions:
            try:
                cfg = self._parse_function(raw_func)
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning(
                    "Fonksiyon parse edilemiyor: %s -- %s",
                    raw_func.get("name", "?"),
                    exc,
                )
                continue

            # Cyclomatic complexity'yi yeniden hesapla (dogrulama)
            cfg.cyclomatic_complexity = self.compute_cyclomatic_complexity(cfg)

            # Dominator-based loop detection
            loops = self.detect_loops(cfg)
            cfg.loop_headers = [loop.header_block for loop in loops]
            cfg.back_edges = [loop.back_edge for loop in loops]

            # Siniflandirma
            classification = self.classify_function(cfg)
            classification_counts[classification] += 1

            result.functions.append(cfg)
            result.total_blocks += len(cfg.blocks)
            result.total_edges += len(cfg.edges)

        result.total_functions = len(result.functions)
        result.stats = {
            "classification_distribution": classification_counts,
            "avg_complexity": self._safe_avg(
                [f.cyclomatic_complexity for f in result.functions]
            ),
        }

        logger.info(
            "CFG analizi tamamlandi: %d fonksiyon, %d block, %d edge",
            result.total_functions,
            result.total_blocks,
            result.total_edges,
        )
        return result

    # ------------------------------------------------------------------
    # Dominator hesaplama (Cooper, Harvey, Kennedy algoritmasi)
    # ------------------------------------------------------------------

    def compute_dominators(self, cfg: FunctionCFG) -> dict[str, str | None]:
        """Iteratif dominator hesapla -- Cooper, Harvey, Kennedy algoritmasi.

        Her block icin immediate dominator'u (idom) hesaplar.
        Entry block'un idom'u None'dir.

        Algoritma:
        1. Block'lari reverse postorder'a sir.
        2. Entry'nin idom'u = kendisi.
        3. Diger block'lar icin predecessor'larin idom'larinin
           kesisimini (intersect) bul.
        4. Degisiklik olmayana kadar tekrarla.

        Args:
            cfg: FunctionCFG objesi.

        Returns:
            dict: block_address -> idom_address eslesmesi.
                  Entry block icin None.
        """
        if not cfg.blocks:
            return {}

        # Entry block = ilk block (fonksiyon giris noktasi)
        entry = cfg.blocks[0].start_address

        # Predecessor haritasi olustur
        predecessors: dict[str, list[str]] = {
            b.start_address: [] for b in cfg.blocks
        }
        for edge in cfg.edges:
            if edge.to_block in predecessors:
                predecessors[edge.to_block].append(edge.from_block)

        # Successor haritasi (DFS icin)
        successors: dict[str, list[str]] = {
            b.start_address: [] for b in cfg.blocks
        }
        for edge in cfg.edges:
            if edge.from_block in successors:
                successors[edge.from_block].append(edge.to_block)

        # Reverse postorder hesapla (DFS ile)
        rpo = self._reverse_postorder(entry, successors, set(predecessors.keys()))
        rpo_number: dict[str, int] = {addr: idx for idx, addr in enumerate(rpo)}

        # Ilklendirme
        idom: dict[str, str | None] = {b.start_address: None for b in cfg.blocks}
        idom[entry] = entry  # Entry kendine dominate eder

        changed = True
        while changed:
            changed = False
            for block_addr in rpo:
                if block_addr == entry:
                    continue

                # Processed predecessor'lardan ilkini sec
                preds = [
                    p for p in predecessors.get(block_addr, [])
                    if idom.get(p) is not None
                ]
                if not preds:
                    continue

                new_idom = preds[0]
                for pred in preds[1:]:
                    new_idom = self._intersect(
                        pred, new_idom, idom, rpo_number,
                    )

                if idom[block_addr] != new_idom:
                    idom[block_addr] = new_idom
                    changed = True

        # Entry'nin idom'u None (kendini dominate eder ama bunu None ile gosteriyoruz)
        idom[entry] = None
        return idom

    # ------------------------------------------------------------------
    # Natural loop detection
    # ------------------------------------------------------------------

    def detect_loops(self, cfg: FunctionCFG) -> list[LoopInfo]:
        """Natural loop'lari tespit et.

        Yontem:
        1. Dominator tree'yi hesapla.
        2. Back-edge bul: to_block, from_block'u dominate ediyorsa.
        3. Her back-edge icin loop body'yi bul (BFS/DFS geriye dogru).
        4. Nesting derinligini hesapla.

        Args:
            cfg: FunctionCFG objesi.

        Returns:
            list[LoopInfo]: Tespit edilen natural loop'lar.
        """
        if not cfg.blocks or not cfg.edges:
            return []

        idom = self.compute_dominators(cfg)

        # Domination kontrolu: a, b'yi dominate ediyor mu?
        # (a, b'nin idom zincirinde mi?)
        def dominates(a: str, b: str) -> bool:
            """a block'u b block'unu dominate ediyor mu?"""
            visited: set[str] = set()
            current = b
            while current is not None and current not in visited:
                if current == a:
                    return True
                visited.add(current)
                current = idom.get(current)
            return False

        # Back-edge tespiti: edge(u -> v) where v dominates u
        back_edges: list[tuple[str, str]] = []
        for edge in cfg.edges:
            if dominates(edge.to_block, edge.from_block):
                back_edges.append((edge.from_block, edge.to_block))

        # Her back-edge icin natural loop body bul
        # Predecessor haritasi
        predecessors: dict[str, list[str]] = {
            b.start_address: [] for b in cfg.blocks
        }
        for edge in cfg.edges:
            if edge.to_block in predecessors:
                predecessors[edge.to_block].append(edge.from_block)

        loops: list[LoopInfo] = []
        for tail, header in back_edges:
            # Loop body: header'dan basla, tail'e kadar geriye git
            body: set[str] = {header}
            if tail != header:
                body.add(tail)
                # BFS geriye dogru: tail'den header'a ulasana kadar
                worklist = [tail]
                while worklist:
                    node = worklist.pop()
                    for pred in predecessors.get(node, []):
                        if pred not in body:
                            body.add(pred)
                            worklist.append(pred)

            loops.append(LoopInfo(
                header_block=header,
                back_edge=(tail, header),
                body_blocks=body,
                nesting_depth=0,
            ))

        # --- Fallback: dominator-based 0 loop bulduysa, address-based heuristic ---
        # Gercek binary CFG'lerde edge/block orani ~1.3-1.8 olmali.
        # Eger dominator tree hesabinda sorun varsa (unreachable node'lar,
        # yanlis predecessor zinciri vb.) back-edge tespit edilemeyebilir.
        # Bu durumda adres karsilastirmasi ile back-edge adaylarini buluruz.
        if not loops and cfg.edges:
            logger.debug(
                "Dominator-based loop detection 0 loop buldu, "
                "address-based fallback deneniyor: %s",
                cfg.name,
            )
            fallback_headers_seen: set[str] = set()
            for edge in cfg.edges:
                try:
                    to_int = int(edge.to_block, 16)
                    from_int = int(edge.from_block, 16)
                except (ValueError, TypeError):
                    continue
                # to_addr < from_addr => muhtemelen geriye atlama (back-edge)
                if to_int < from_int:
                    header = edge.to_block
                    if header in fallback_headers_seen:
                        continue
                    fallback_headers_seen.add(header)
                    # Body hesabi: basit BFS geriye (predecessor'lar)
                    body: set[str] = {header}
                    tail = edge.from_block
                    if tail != header:
                        body.add(tail)
                        worklist = [tail]
                        while worklist:
                            node = worklist.pop()
                            for pred in predecessors.get(node, []):
                                if pred not in body:
                                    body.add(pred)
                                    worklist.append(pred)
                    loops.append(LoopInfo(
                        header_block=header,
                        back_edge=(edge.from_block, header),
                        body_blocks=body,
                        nesting_depth=0,
                    ))
            if loops:
                logger.info(
                    "Address-based fallback %d loop buldu: %s",
                    len(loops),
                    cfg.name,
                )

        # Nesting derinligi: bir loop header baska bir loop body'sinde mi?
        for i, loop_a in enumerate(loops):
            depth = 0
            for j, loop_b in enumerate(loops):
                if i == j:
                    continue
                # loop_a'nin header'i loop_b'nin body'sinde ise,
                # loop_a loop_b'nin icinde (nested)
                if loop_a.header_block in loop_b.body_blocks:
                    depth += 1
            loop_a.nesting_depth = depth

        return loops

    # ------------------------------------------------------------------
    # Cyclomatic complexity
    # ------------------------------------------------------------------

    def compute_cyclomatic_complexity(self, cfg: FunctionCFG) -> int:
        """McCabe cyclomatic complexity: V(G) = E - N + 2.

        Args:
            cfg: FunctionCFG objesi.

        Returns:
            int: Cyclomatic complexity degeri. Block yoksa 0.
        """
        n = len(cfg.blocks)
        e = len(cfg.edges)
        if n == 0:
            return 0
        return e - n + 2

    # ------------------------------------------------------------------
    # Fonksiyon siniflandirmasi
    # ------------------------------------------------------------------

    def classify_function(self, cfg: FunctionCFG) -> str:
        """Fonksiyonu CFG ozelliklerine gore siniflandir.

        Siniflar:
            "linear"    : 0 loop, complexity <= 2  (basit fonksiyon)
            "branching" : 0 loop, complexity > 2   (cok dallanma)
            "looping"   : 1+ loop, complexity <= 10 (dongusu var, orta karmasiklik)
            "complex"   : 1+ loop, complexity > 10  (karmasik fonksiyon)

        Args:
            cfg: FunctionCFG objesi.

        Returns:
            str: Sinif etiketi.
        """
        loop_count = len(cfg.loop_headers)
        complexity = cfg.cyclomatic_complexity

        if loop_count == 0:
            if complexity <= 2:
                return "linear"
            return "branching"
        else:
            if complexity <= 10:
                return "looping"
            return "complex"

    # ------------------------------------------------------------------
    # Metrik ve ozet metodlari
    # ------------------------------------------------------------------

    def get_function_metrics(self, cfg: FunctionCFG) -> dict[str, Any]:
        """Tek bir fonksiyon icin ozet metrikleri don.

        Args:
            cfg: FunctionCFG objesi.

        Returns:
            dict: block_count, edge_count, complexity, loop_count,
                  max_loop_depth, classification.
        """
        loops = self.detect_loops(cfg)
        max_depth = max((lp.nesting_depth for lp in loops), default=0)

        return {
            "name": cfg.name,
            "address": cfg.address,
            "block_count": len(cfg.blocks),
            "edge_count": len(cfg.edges),
            "complexity": cfg.cyclomatic_complexity,
            "loop_count": len(loops),
            "max_loop_depth": max_depth,
            "classification": self.classify_function(cfg),
        }

    def get_summary(self, result: CFGAnalysisResult) -> dict[str, Any]:
        """Analiz sonucu uzerinden toplu ozet.

        Args:
            result: CFGAnalysisResult objesi.

        Returns:
            dict: Toplam istatistikler ve classification dagilimi.
        """
        complexities = [f.cyclomatic_complexity for f in result.functions]
        loop_counts = [len(f.loop_headers) for f in result.functions]

        classification_counts: dict[str, int] = {
            "linear": 0,
            "branching": 0,
            "looping": 0,
            "complex": 0,
        }
        for func in result.functions:
            cls = self.classify_function(func)
            classification_counts[cls] += 1

        return {
            "total_functions": result.total_functions,
            "total_blocks": result.total_blocks,
            "total_edges": result.total_edges,
            "avg_complexity": self._safe_avg(complexities),
            "max_complexity": max(complexities, default=0),
            "total_loops": sum(loop_counts),
            "functions_with_loops": sum(1 for lc in loop_counts if lc > 0),
            "classification_distribution": classification_counts,
        }

    # ------------------------------------------------------------------
    # Dahili yardimci metodlar
    # ------------------------------------------------------------------

    def _parse_function(self, raw: dict[str, Any]) -> FunctionCFG:
        """JSON'dan bir FunctionCFG objesi olustur.

        Args:
            raw: Ghidra CFG JSON'daki tek fonksiyon dict'i.

        Returns:
            FunctionCFG: Parse edilmis CFG.

        Raises:
            KeyError: Zorunlu alan eksikse.
        """
        blocks = [
            BasicBlock(
                start_address=b["start_address"],
                end_address=b["end_address"],
                size=b.get("size", 0),
                instruction_count=b.get("instruction_count", 0),
            )
            for b in raw.get("blocks", [])
        ]

        edges = [
            CFGEdge(
                from_block=e["from_block"],
                to_block=e["to_block"],
                edge_type=e.get("edge_type", "unknown"),
            )
            for e in raw.get("edges", [])
        ]

        return FunctionCFG(
            name=raw["name"],
            address=raw["address"],
            blocks=blocks,
            edges=edges,
            cyclomatic_complexity=raw.get("cyclomatic_complexity", 0),
            loop_headers=raw.get("loop_headers", []),
            back_edges=[
                self._parse_back_edge(be) for be in raw.get("back_edges", [])
            ],
        )

    @staticmethod
    def _parse_back_edge(be: Any) -> tuple[str, str]:
        """Back-edge'i hem dict hem list/tuple formatindan parse et.

        Ghidra ciktisinda back_edges iki formatta gelebilir:
          - Eski format (dict): {"from": "00401000", "to": "00400ff0"}
          - Yeni format (list): ["00401000", "00400ff0"]

        Args:
            be: Back-edge verisi (dict, list veya tuple).

        Returns:
            tuple[str, str]: (from_block, to_block) tuple'i.
        """
        if isinstance(be, dict):
            # Dict format: {"from": addr, "to": addr}
            # veya {"from_block": addr, "to_block": addr}
            from_addr = be.get("from") or be.get("from_block", "0")
            to_addr = be.get("to") or be.get("to_block", "0")
            return (str(from_addr), str(to_addr))
        # List/tuple format: [from, to]
        return tuple(be)

    def _reverse_postorder(
        self,
        entry: str,
        successors: dict[str, list[str]],
        all_nodes: set[str],
    ) -> list[str]:
        """DFS ile reverse postorder sirasi hesapla.

        Entry'den ulasilamayan node'lar listeye sona eklenir.

        Args:
            entry: CFG giris block adresi.
            successors: Block -> successor listesi eslesmesi.
            all_nodes: Tum block adresleri kumesi.

        Returns:
            list[str]: Reverse postorder sirasindaki block adresleri.
        """
        visited: set[str] = set()
        postorder: list[str] = []

        # Iteratif DFS (derin CFG'lerde recursion limit asilmasini onler)
        stack: list[tuple[str, bool]] = [(entry, False)]
        while stack:
            node, processed = stack.pop()
            if processed:
                postorder.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            for succ in reversed(successors.get(node, [])):
                if succ not in visited and succ in all_nodes:
                    stack.append((succ, False))

        # Ulasilamayan node'lari da ekle
        for node in all_nodes:
            if node not in visited:
                postorder.append(node)

        postorder.reverse()
        return postorder

    def _intersect(
        self,
        b1: str,
        b2: str,
        idom: dict[str, str | None],
        rpo_number: dict[str, int],
    ) -> str:
        """Iki node'un dominator tree'deki ortak atasini bul.

        Cooper-Harvey-Kennedy intersect fonksiyonu.

        Args:
            b1: Birinci block adresi.
            b2: Ikinci block adresi.
            idom: Immediate dominator eslesmesi.
            rpo_number: Block -> reverse postorder numarasi eslesmesi.

        Returns:
            str: Ortak ata block adresi.
        """
        finger1 = b1
        finger2 = b2

        # Sonsuz donguyu onlemek icin iterasyon limiti
        max_iter = len(rpo_number) + 10
        iterations = 0

        while finger1 != finger2 and iterations < max_iter:
            while (
                rpo_number.get(finger1, 0) > rpo_number.get(finger2, 0)
                and iterations < max_iter
            ):
                parent = idom.get(finger1)
                if parent is None or parent == finger1:
                    return finger2
                finger1 = parent
                iterations += 1
            while (
                rpo_number.get(finger2, 0) > rpo_number.get(finger1, 0)
                and iterations < max_iter
            ):
                parent = idom.get(finger2)
                if parent is None or parent == finger2:
                    return finger1
                finger2 = parent
                iterations += 1
            iterations += 1

        return finger1

    @staticmethod
    def _safe_avg(values: list[int | float]) -> float:
        """Bos liste icin guvenli ortalama.

        Args:
            values: Sayisal deger listesi.

        Returns:
            float: Ortalama veya 0.0 (bos listede).
        """
        if not values:
            return 0.0
        return round(sum(values) / len(values), 2)
