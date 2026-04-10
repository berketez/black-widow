"""Control Flow Flattening (CFF) deflattening modulu.

CFF, obfuscation'in en yaygin tekniklerinden biri. Orijinal
control flow'u bir switch-case dispatcher'a donusturur:

    while(true) {
        switch(state) {
            case 0: ... state = 3; break;
            case 1: ... state = 5; break;
            case 2: ... state = 1; break;
            ...
        }
    }

Bu modul:
1. Switch-case dispatcher pattern'ini tespit eder
2. State transition graph'i cikarir
3. Topological sort ile orijinal control flow'u yeniden olusturur
4. Hem C kodu hem JS kodu uzerinde calisir

JS icin: Mevcut deep_pipeline.py + synchrony zaten bazi CFF'leri cozer.
Bu modul EK olarak daha karmasik CFF'leri hedefler.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CFFBlock:
    """CFF icindeki tek bir state blogu."""
    state_value: int | str  # case degeri
    code: str  # Bu blogun kodu
    next_states: list[int | str] = field(default_factory=list)  # Gecis yaptigi state'ler
    is_entry: bool = False
    is_exit: bool = False


@dataclass
class CFFResult:
    """CFF deflattening sonucu."""
    detected: bool = False
    total_dispatchers: int = 0
    total_blocks: int = 0
    deflattened_code: str = ""
    state_graph: dict = field(default_factory=dict)  # state -> [next_states]
    original_order: list = field(default_factory=list)  # Topological sort sonucu


class CFFDeflattener:
    """Control Flow Flattening deflattening motoru.

    C ve JS kodunda CFF pattern'lerini tespit edip
    orijinal control flow'a geri donusturur.
    """

    # CFF dispatcher pattern: while(1) { switch(state) { ... } }
    _WHILE_SWITCH_C = re.compile(
        r"while\s*\(\s*(?:1|true)\s*\)\s*\{"
        r"\s*switch\s*\(\s*(\w+)\s*\)\s*\{",
        re.IGNORECASE,
    )

    # JS CFF: while(true) { switch(state) { ... } } veya for(;;) { switch... }
    _WHILE_SWITCH_JS = re.compile(
        r"(?:while\s*\(\s*(?:!0|true|1)\s*\)|for\s*\(\s*;;\s*\))\s*\{"
        r"\s*switch\s*\(\s*(\w+)\s*\)\s*\{",
        re.IGNORECASE,
    )

    # case N: ... state = M; break;
    _CASE_BLOCK = re.compile(
        r"case\s+([\d\w]+)\s*:\s*(.*?)(?=case\s+[\d\w]+\s*:|default\s*:|$)",
        re.DOTALL,
    )

    # State assignment: state = N; veya state_var = 0xNN;
    _STATE_ASSIGN = re.compile(
        r"(\w+)\s*=\s*(\d+|0x[0-9a-fA-F]+)\s*;",
    )

    def detect_cff(self, code: str) -> bool:
        """CFF pattern mevcut mu kontrol et."""
        return bool(self._WHILE_SWITCH_C.search(code) or self._WHILE_SWITCH_JS.search(code))

    def analyze_cff(self, code: str) -> CFFResult:
        """CFF yapısını analiz et ve state graph oluştur."""
        result = CFFResult()

        # Dispatcher bul
        dispatchers = list(self._WHILE_SWITCH_C.finditer(code))
        if not dispatchers:
            dispatchers = list(self._WHILE_SWITCH_JS.finditer(code))

        if not dispatchers:
            return result

        result.detected = True
        result.total_dispatchers = len(dispatchers)

        for dispatcher in dispatchers:
            state_var = dispatcher.group(1)
            # Dispatcher'dan sonraki switch body'yi bul
            # Regex match switch'in acilan brace'ini icerir ("{" son karakter).
            # _extract_switch_body "{" pozisyonundan baslamali, end()-1 vererek
            # acilan brace'i gosteriyoruz.
            start = dispatcher.end() - 1
            switch_body = self._extract_switch_body(code, start)

            if not switch_body:
                continue

            # Case bloklarini cikar
            blocks = self._parse_case_blocks(switch_body, state_var)
            result.total_blocks += len(blocks)

            # State transition graph olustur
            graph = {}
            for block in blocks:
                graph[block.state_value] = block.next_states

            result.state_graph = graph

            # Topological sort ile orijinal siralamayi bul
            result.original_order = self._topological_sort(graph, blocks)

            # Deflattened kodu olustur
            result.deflattened_code = self._reconstruct_linear_code(blocks, result.original_order)

        return result

    def deflatten_code(self, code: str) -> tuple[str, CFFResult]:
        """CFF'yi tespit edip kodda degistir.

        Args:
            code: C veya JS kaynak kodu.

        Returns:
            (modified_code, result): CFF kaldirilmis kod ve rapor.
        """
        result = self.analyze_cff(code)

        if not result.detected or not result.deflattened_code:
            return code, result

        # CFF dispatcher'i deflattened kodla degistir
        # Basit yaklasim: tum while-switch blogunu yeni kodla degistir
        for pattern in [self._WHILE_SWITCH_C, self._WHILE_SWITCH_JS]:
            match = pattern.search(code)
            if match:
                start = match.start()
                # Switch body'nin sonunu bul (matching braces)
                end = self._find_matching_brace(code, match.end() - 1)
                if end > 0:
                    # Dis while'in kapanan brace'i
                    end = self._find_matching_brace(code, start + code[start:].index("{"))
                    if end > 0:
                        comment = "/* CFF DEFLATTENED by Karadul v1.0 */\n"
                        code = code[:start] + comment + result.deflattened_code + code[end + 1:]
                        break

        return code, result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_switch_body(self, code: str, start: int) -> str:
        """Switch statement'in body'sini cikar (brace matching)."""
        # Switch'in acilis brace'ini bul
        brace_pos = code.find("{", start)
        if brace_pos < 0:
            return ""

        end = self._find_matching_brace(code, brace_pos)
        if end < 0:
            return ""

        return code[brace_pos + 1:end]

    def _find_matching_brace(self, code: str, open_pos: int) -> int:
        """Acik brace'in eslesik kapama brace'ini bul."""
        if open_pos >= len(code) or code[open_pos] != "{":
            return -1

        depth = 1
        i = open_pos + 1
        in_string = False
        string_char = ""

        while i < len(code) and depth > 0:
            c = code[i]

            # String literal icindeyken brace sayma
            if in_string:
                if c == string_char and code[i - 1] != "\\":
                    in_string = False
            else:
                if c in ('"', "'"):
                    in_string = True
                    string_char = c
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
            i += 1

        return i - 1 if depth == 0 else -1

    def _parse_case_blocks(self, switch_body: str, state_var: str) -> list[CFFBlock]:
        """Switch body'den case bloklarini cikar."""
        blocks = []

        for match in self._CASE_BLOCK.finditer(switch_body):
            state_value = match.group(1)
            try:
                state_value = int(state_value, 16) if state_value.startswith("0x") else int(state_value)
            except ValueError:
                pass  # String state (enum)

            block_code = match.group(2).strip()

            # Bu bloktan gecis yapilan state'leri bul
            next_states = []
            for assign in self._STATE_ASSIGN.finditer(block_code):
                var = assign.group(1)
                val = assign.group(2)
                if var == state_var or var.endswith("state") or var.endswith("State"):
                    try:
                        val = int(val, 16) if val.startswith("0x") else int(val)
                    except ValueError:
                        pass
                    next_states.append(val)

            # break/return kontrolu
            is_exit = "return" in block_code and state_var not in block_code.split("return")[0]

            blocks.append(CFFBlock(
                state_value=state_value,
                code=self._clean_block_code(block_code, state_var),
                next_states=next_states,
                is_exit=is_exit,
            ))

        # Entry point: ilk atanan state veya case 0
        if blocks:
            blocks[0].is_entry = True

        return blocks

    def _clean_block_code(self, code: str, state_var: str) -> str:
        """Block kodundan state assignment ve break'leri cikar.

        Tek satirlik (inline) case bloklarini da destekler:
          init(); state = 2; break;  ->  init();
        """
        # Once statement-bazli temizlik: state assignment ve break ifadelerini sil
        # Bu, tek satirda birden fazla statement varsa da calisir
        escaped = re.escape(state_var)
        # state_var = <deger>; kalibini sil
        code = re.sub(rf"\s*{escaped}\s*=\s*(?:\d+|0x[0-9a-fA-F]+)\s*;", "", code)
        # break; kalibini sil
        code = re.sub(r"\s*break\s*;", "", code)

        # Satir bazli bos satirlari temizle
        lines = []
        for line in code.split("\n"):
            if line.strip():
                lines.append(line)
        return "\n".join(lines)

    def _topological_sort(self, graph: dict, blocks: list[CFFBlock]) -> list:
        """State transition graph'i topological sort ile sirala."""
        # BFS benzeri: entry'den baslayip state gecislerini takip et
        if not blocks:
            return []

        order = []
        visited = set()

        # Entry point
        entry = blocks[0].state_value
        queue = [entry]

        while queue:
            state = queue.pop(0)
            if state in visited:
                continue
            visited.add(state)
            order.append(state)

            # Bu state'in gecis yaptigi state'ler
            next_states = graph.get(state, [])
            for ns in next_states:
                if ns not in visited:
                    queue.append(ns)

        # Ziyaret edilmemis state'leri sona ekle
        for block in blocks:
            if block.state_value not in visited:
                order.append(block.state_value)

        return order

    def _reconstruct_linear_code(self, blocks: list[CFFBlock], order: list) -> str:
        """Topological siralamayla orijinal kodu yeniden olustur."""
        block_map = {b.state_value: b for b in blocks}
        lines = []

        for state in order:
            block = block_map.get(state)
            if block and block.code.strip():
                lines.append(f"/* === Block (was state {state}) === */")
                lines.append(block.code)
                lines.append("")

        return "\n".join(lines)
