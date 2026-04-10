"""Ghidra decompile ciktisindaki goto/label pattern'lerini sadeler.

6 katmanli simplifikasyon:
1. Error cleanup goto inlining (tek hedefli goto + cleanup block)
2. Label anlamlandirma (LAB_ -> error_cleanup/success/retry)
3. Goto zinciri sadelelestirme
4. Early return elimination (goto LAB_end -> return x;)
5. Break/continue recognition + cascading goto collapse
6. If-else restructuring (goto ELSE; ... goto END; ELSE: ... END:)

Guvenlik: Sadece tek-hedefli goto'lar inline edilir (Pass 1).
Pass 4-6 pattern-based donusumler: sadece unambiguous pattern'ler.
Cok hedefli veya karmasik pattern'ler sadece yorum + rename alir.
"""

from __future__ import annotations

import logging
import re


def _replace_whole_word(text: str, old: str, new: str) -> str:
    """str.replace gibi hizli ama sadece tam kelime eslesir (word boundary).

    re.sub(r'\\b...\\b') buyuk dosyalarda catastrophic backtracking yapar.
    Bu fonksiyon O(n) garanti eder.
    """
    old_len = len(old)
    if not old_len:
        return text
    result: list[str] = []
    start = 0
    while True:
        idx = text.find(old, start)
        if idx == -1:
            result.append(text[start:])
            break
        # Sol sinir kontrolu: basinda mi veya onceki karakter identifier degil mi
        if idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
            result.append(text[start : idx + old_len])
            start = idx + old_len
            continue
        # Sag sinir kontrolu
        end = idx + old_len
        if end < len(text) and (text[end].isalnum() or text[end] == "_"):
            result.append(text[start : idx + old_len])
            start = idx + old_len
            continue
        # Tam eslesme — degistir
        result.append(text[start:idx])
        result.append(new)
        start = end
    return "".join(result)
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex pattern'ler
# ---------------------------------------------------------------------------

# goto LAB_xxx;
_GOTO_RE = re.compile(r"\bgoto\s+(LAB_[0-9a-fA-F]+)\s*;")

# LAB_xxx:
_LABEL_RE = re.compile(r"^(\s*)(LAB_[0-9a-fA-F]+)\s*:", re.MULTILINE)

# Cleanup API'leri (error cleanup tespiti icin)
_CLEANUP_APIS = frozenset({
    "free", "close", "fclose", "munmap", "release",
    "destroy", "cleanup", "dispose", "dealloc",
    "SSL_free", "BIO_free", "EVP_CIPHER_CTX_free",
    "EVP_MD_CTX_free", "OPENSSL_free", "sk_pop_free",
})

# Return pattern (cleanup block sonu)
_RETURN_RE = re.compile(r"\breturn\b\s*[^;]*;")


@dataclass
class SimplifyResult:
    """Simplifikasyon sonucu."""
    total_files: int = 0
    gotos_eliminated: int = 0
    labels_renamed: int = 0
    labels_inlined: int = 0
    files_modified: int = 0
    early_returns: int = 0
    breaks_continues: int = 0
    ifelse_restructured: int = 0
    cascading_collapsed: int = 0
    multi_target_inlined: int = 0


class CFlowSimplifier:
    """Ghidra goto/label pattern'lerini sadeler.

    Ghidra decompiler ciktilarinda cok sayida ``goto LAB_xxx`` pattern'i
    bulunur.  Bu sinif:

    * Tek hedefli goto'lari cleanup bloguyla inline eder (guvenli).
    * Kalan label'lari anlamsallik bazli yeniden isimlendirir.
    * Cok hedefli veya karmasik pattern'lere dokunmaz (guvenlik).

    Tum islemler *in-place* veya ayri bir output dizinine yazilabilir.
    """

    def __init__(self, config=None):
        self._max_inline_lines: int = 15
        self._enabled: bool = True
        if config and hasattr(config, "binary_reconstruction"):
            br = config.binary_reconstruction
            self._max_inline_lines = getattr(br, "goto_max_inline_lines", 15)
            self._enabled = getattr(br, "enable_flow_simplification", True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def simplify_directory(
        self,
        input_dir: Path,
        output_dir: Path | None = None,
    ) -> SimplifyResult:
        """Dizindeki tum C dosyalarini sadeler.

        *output_dir* ``None`` ise **input_dir uzerinde in-place** degisiklik
        yapar.  Farkli bir *output_dir* verilirse once dizin kopyalanir.
        """
        result = SimplifyResult()

        if not self._enabled:
            logger.debug("Flow simplification devre disi, atlaniyor")
            return result

        if output_dir and output_dir != input_dir:
            import shutil

            if output_dir.exists():
                shutil.rmtree(output_dir)
            shutil.copytree(input_dir, output_dir)
            target_dir = output_dir
        else:
            target_dir = input_dir

        c_files = sorted(target_dir.glob("*.c"))
        result.total_files = len(c_files)

        for c_file in c_files:
            try:
                content = c_file.read_text(encoding="utf-8", errors="replace")
                new_content, stats = self._simplify_content(content)
                if new_content != content:
                    c_file.write_text(new_content, encoding="utf-8")
                    result.files_modified += 1
                result.gotos_eliminated += stats.get("eliminated", 0)
                result.labels_renamed += stats.get("renamed", 0)
                result.labels_inlined += stats.get("inlined", 0)
                result.early_returns += stats.get("early_returns", 0)
                result.breaks_continues += stats.get("breaks_continues", 0)
                result.ifelse_restructured += stats.get("ifelse_restructured", 0)
                result.cascading_collapsed += stats.get("cascading_collapsed", 0)
                result.multi_target_inlined += stats.get("multi_target_inlined", 0)
            except Exception as exc:
                logger.debug("Flow simplify hatasi %s: %s", c_file.name, exc)

        logger.info(
            "Flow simplify: %d dosya, %d goto eliminated, %d label renamed, "
            "%d inlined, %d early_ret, %d break/cont, %d if-else, %d cascade, %d multi",
            result.total_files,
            result.gotos_eliminated,
            result.labels_renamed,
            result.labels_inlined,
            result.early_returns,
            result.breaks_continues,
            result.ifelse_restructured,
            result.cascading_collapsed,
            result.multi_target_inlined,
        )
        return result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _simplify_content(self, content: str) -> tuple[str, dict]:
        """Tek bir C dosyasinin icerigini sadeler.

        Donus: ``(yeni_icerik, istatistik_dict)``

        v1.6.4 Performans optimizasyonu:
        Eski algoritma her inline icin content'i bastan tariyordu (O(n*k) —
        n=content boyutu, k=inlinable label sayisi). gh binary gibi buyuk
        ciktilarda (12K+ dosya, binlerce label) ~10dk hang yapiyordu.

        Yeni algoritma:
        1. Tek bir taramada tum inlinable adaylari topla (label + goto pozisyonlari)
        2. Adaylari dokuman sonundan basina dogru isle (reverse order) boylece
           string mutation'lari onceki pozisyonlari bozmaz
        3. Dinamik regex derleme yerine string-based arama kullan
        Bu degisiklikle karmasiklik O(n + k*b) olur (b = ortalama block boyutu).
        """
        stats: dict[str, int] = {"eliminated": 0, "renamed": 0, "inlined": 0}

        # 1. Label ve goto envanteri
        gotos = _GOTO_RE.findall(content)
        labels = _LABEL_RE.findall(content)

        if not gotos and not labels:
            return content, stats

        # Goto hedef sayisi: her label'a kac goto var?
        goto_targets = Counter(gotos)

        # v1.6.4: Buyuk icerik korumasi — 500K+ karakter iceriklerde
        # sadece rename yap, inline atla (maliyet/fayda orani dusuk).
        skip_inline = len(content) > 500_000

        # ---------------------------------------------------------------
        # Pre-pass siralama: Tum yeni pass'lar Pass 1'den ONCE calisir.
        # Pass 1 cok agresif (return iceren her blogu inline eder), bu yuzden
        # daha spesifik donusumlerin once calisip pattern'leri claim etmesi lazim.
        #
        # Sira: cascade -> ifelse -> early_return -> break/continue
        # ---------------------------------------------------------------
        _any_prepass_changed = False

        # Pre-pass 1: Cascading goto collapse
        if not skip_inline:
            content, n_cascade = self._pass_cascading_goto(content)
            stats["cascading_collapsed"] = n_cascade
            stats["eliminated"] += n_cascade
            if n_cascade > 0:
                _any_prepass_changed = True

        # Pre-pass 2: If-else restructuring
        if not skip_inline:
            content, n_ifelse = self._pass_ifelse_restructure(content)
            stats["ifelse_restructured"] = n_ifelse
            stats["eliminated"] += n_ifelse * 2
            if n_ifelse > 0:
                _any_prepass_changed = True

        # Pre-pass 3: Early return elimination
        if not skip_inline:
            content, n_early = self._pass_early_return(content)
            stats["early_returns"] = n_early
            stats["eliminated"] += n_early
            if n_early > 0:
                _any_prepass_changed = True

        # Pre-pass 4: Break/continue recognition
        if not skip_inline:
            content, n_brk = self._pass_break_continue(content)
            stats["breaks_continues"] = n_brk
            stats["eliminated"] += n_brk
            if n_brk > 0:
                _any_prepass_changed = True

        # Pre-pass 5: Multi-target cleanup inlining
        # Birden fazla goto ayni cleanup label'a gidiyorsa VE block kucukse
        # hepsini inline et. Pass 1'den once calisir cunku Pass 1 sadece
        # tek-hedefli goto'lari alir.
        if not skip_inline:
            content, n_multi = self._pass_multi_target_cleanup(content)
            stats["multi_target_inlined"] = n_multi
            stats["eliminated"] += n_multi
            if n_multi > 0:
                _any_prepass_changed = True

        # Pre-pass'lar content'i degistirdiyse, envanter guncelle
        if _any_prepass_changed:
            gotos = _GOTO_RE.findall(content)
            labels = _LABEL_RE.findall(content)
            goto_targets = Counter(gotos)

        # 2. Katman 1: Error cleanup inline (tek hedefli)
        # v1.6.4: Tek tarama, ters sirada isleme (reverse-order batch).
        inlined_labels: set[str] = set()

        if not skip_inline:
            # -- Aday toplama (tek tarama) --
            # Her aday: (label_match, block, goto_match) ucluleri
            @dataclass
            class _InlineCandidate:
                label_name: str
                label_start: int      # label match baslangici
                label_end: int        # label match bitisi (block buradan baslar)
                block: str            # label'dan sonraki cleanup block
                block_len: int        # block'un content icindeki karakter uzunlugu
                goto_start: int       # goto statement baslangici
                goto_end: int         # goto statement bitisi
                goto_indent: str      # goto'nun indent'i

            # Goto pozisyonlarini bir kerede topla (label_name -> [(start, end, indent)])
            goto_positions: dict[str, list[tuple[int, int, str]]] = {}
            for gm in re.finditer(r"(\s*)goto\s+(LAB_[0-9a-fA-F]+)\s*;", content):
                lname = gm.group(2)
                if lname not in goto_positions:
                    goto_positions[lname] = []
                goto_positions[lname].append((gm.start(), gm.end(), gm.group(1)))

            candidates: list[_InlineCandidate] = []
            for label_match in _LABEL_RE.finditer(content):
                label_name = label_match.group(2)
                if goto_targets.get(label_name, 0) != 1:
                    continue  # Cok hedefli -> dokunma

                label_end = label_match.end()
                block = self._extract_label_block(content, label_end)
                if not block or block.count("\n") > self._max_inline_lines:
                    continue

                if not self._is_cleanup_block(block):
                    continue

                # Bu label'in goto'sunu bul
                gpos = goto_positions.get(label_name)
                if not gpos:
                    continue
                g_start, g_end, g_indent = gpos[0]  # Tek hedefli, ilk (ve tek) eslesme

                candidates.append(_InlineCandidate(
                    label_name=label_name,
                    label_start=label_match.start(),
                    label_end=label_end,
                    block=block,
                    block_len=len(block),
                    goto_start=g_start,
                    goto_end=g_end,
                    goto_indent=g_indent,
                ))

            # Guvenlik limiti: en fazla 50 inline (eski davranisla uyumlu)
            candidates = candidates[:50]

            # -- Ters sirada isleme --
            # Her adayin 2 mutasyonu var: goto->inline, label+block->sil.
            # Bunlari tek geciste yapmak icin tum mutasyon araliklerini topla,
            # sondan basa dogru uygula.
            # Dikkat: goto ve label birbirinden BAGIMSIZ pozisyonlarda oldugu icin
            # ayni adayin iki mutasyonu arasinda da siralama lazim.

            # (start, end, replacement) uclulerini topla
            mutations: list[tuple[int, int, str]] = []
            for cand in candidates:
                # Mutasyon 1: goto -> inlined block
                inlined_block = self._indent_block(cand.block, cand.goto_indent)
                inlined_comment = (
                    "%s/* error cleanup (inlined from %s) */\n"
                    % (cand.goto_indent, cand.label_name)
                )
                goto_replacement = "\n" + inlined_comment + inlined_block
                mutations.append((cand.goto_start, cand.goto_end, goto_replacement))

                # Mutasyon 2: label + block -> sil
                # Label satirini bul: "\n  LABEL:\n" seklinde
                # Label match'i zaten biliyoruz, ama blogu da kesmemiz lazim.
                # Label baslangicini onceki newline'a geri al.
                lbl_cut_start = content.rfind("\n", 0, cand.label_start)
                if lbl_cut_start == -1:
                    lbl_cut_start = cand.label_start
                # Block'un bitisi: label_end + block_len (+ olasi trailing newline)
                lbl_cut_end = cand.label_end + cand.block_len
                if lbl_cut_end < len(content) and content[lbl_cut_end] == "\n":
                    lbl_cut_end += 1
                mutations.append((lbl_cut_start, lbl_cut_end, "\n"))

                inlined_labels.add(cand.label_name)
                stats["inlined"] += 1
                stats["eliminated"] += 1

            # Mutasyonlari SONDAN BASA sirala ve uygula
            # Cakisan araliklari kontrol et: eger iki mutasyon cakisiyorsa,
            # ikincisini (daha ondeki) atla (guvenlik).
            mutations.sort(key=lambda m: m[0], reverse=True)
            # Cakisma filtresi: her mutasyon sonrasi "korunan sag sinir" takip et
            protected_boundary = len(content)
            for mut_start, mut_end, replacement in mutations:
                if mut_end > protected_boundary:
                    # Bu mutasyon daha sonra uygulanan biriyle cakisiyor, atla
                    continue
                content = content[:mut_start] + replacement + content[mut_end:]
                protected_boundary = mut_start

        # 3. Katman 2: Kalan label'lari anlamlandir
        # Ayni isimden birden fazla varsa cakismayi onle
        renamed: dict[str, str] = {}
        name_counts: Counter[str] = Counter()
        for label_match in _LABEL_RE.finditer(content):
            label_name = label_match.group(2)
            if label_name in renamed or label_name in inlined_labels:
                continue

            label_end = label_match.end()
            block = self._extract_label_block(content, label_end)
            if not block:
                continue

            new_name = self._classify_label(label_name, block)
            if new_name != label_name:
                # Isim cakismasini onle: error_cleanup_2, error_cleanup_3 ...
                name_counts[new_name] += 1
                if name_counts[new_name] > 1:
                    new_name = f"{new_name}_{name_counts[new_name]}"
                renamed[label_name] = new_name

        # Rename'leri uygula (en uzun isimden baslayarak cakisma onle)
        for old_name, new_name in sorted(
            renamed.items(), key=lambda x: len(x[0]), reverse=True
        ):
            content = _replace_whole_word(content, old_name, new_name)
            stats["renamed"] += 1

        # (Tum yeni pass'lar pre-pass olarak yukarida calisti)

        return content, stats

    def _extract_label_block(self, content: str, start_pos: int) -> str:
        """Label'dan sonraki blogu cikar (return/break/goto'ya kadar)."""
        lines = content[start_pos : start_pos + 2000].split("\n")
        block_lines: list[str] = []
        for line in lines[: self._max_inline_lines + 5]:
            stripped = line.strip()
            if not stripped:
                continue
            block_lines.append(line)
            if (
                stripped.startswith("return ")
                or stripped == "return;"
                or stripped.startswith("break;")
                or stripped.startswith("goto ")
            ):
                break
        return "\n".join(block_lines)

    def _is_cleanup_block(self, block: str) -> bool:
        """Block cleanup pattern'i mi? (free/close/return iceriyor mu)"""
        has_cleanup = any(api in block for api in _CLEANUP_APIS)
        has_return = bool(_RETURN_RE.search(block))
        return has_cleanup or has_return

    def _classify_label(self, label_name: str, block: str) -> str:
        """Label'in amacini belirle ve anlamli isim ver."""
        block_lower = block.lower()

        # Cleanup pattern: free/close + return
        if any(api in block for api in _CLEANUP_APIS):
            if re.search(r"\breturn\b", block):
                return "cleanup_and_return"
            return "error_cleanup"

        # Basarili donus: return 0 / return result
        if re.search(
            r"\breturn\s+0\s*;|\breturn\s+result\s*;|\breturn\s+\w+\s*;", block
        ):
            return "exit_function"

        # Hata donusu: return -1 / "error" / "fail"
        if re.search(r"\breturn\s*-", block) or "error" in block_lower or "fail" in block_lower:
            return "error_exit"

        # Siniflandirilamadi -> oldugu gibi birak
        return label_name

    @staticmethod
    def _indent_block(block: str, base_indent: str) -> str:
        """Block'u verilen indent seviyesine getir."""
        lines = block.split("\n")
        return "\n".join(
            base_indent + line.lstrip() for line in lines if line.strip()
        )

    # ==================================================================
    # Pass 4: Early return elimination
    # ==================================================================

    # Pattern: if (cond) goto LAB_xxx;
    #          ...
    #          LAB_xxx:
    #            return VALUE;
    # -> if (cond) return VALUE;
    #    ...
    # (label removed if no other references)
    _EARLY_RET_GOTO_RE = re.compile(
        r"^(\s*)if\s*\(([^)]+)\)\s*goto\s+(LAB_[0-9a-fA-F]+)\s*;",
        re.MULTILINE,
    )

    def _pass_early_return(self, content: str) -> tuple[str, int]:
        """goto LAB_xxx -> return VALUE; pattern'lerini donustur.

        Sadece su durumda donusum yapar:
        - Label'dan sonra SADECE tek bir return statement var (bos satirlar haric)
        - return statement kisa (< 120 karakter)
        """
        count = 0
        # Once hangi label'larin "sadece return" icerdigini bul
        label_returns: dict[str, str] = {}  # label_name -> "return ...;"
        for lm in _LABEL_RE.finditer(content):
            label_name = lm.group(2)
            after = content[lm.end(): lm.end() + 500]
            lines = [l.strip() for l in after.split("\n") if l.strip()]
            if not lines:
                continue
            first_line = lines[0]
            # Sadece return statement mi?
            if first_line.startswith("return ") or first_line == "return;":
                if first_line.endswith(";") and len(first_line) < 120:
                    # Label'dan sonra baska anlamli kod var mi?
                    # Ikinci satirda label veya fonksiyon kapanisi varsa
                    # sadece return block'u
                    is_pure_return = True
                    if len(lines) > 1:
                        second = lines[1]
                        # Ikinci satir baska label, } veya fonksiyon tanimiysa OK
                        if not (second.startswith("LAB_") or second == "}"
                                or second.startswith("//")):
                            is_pure_return = False
                    if is_pure_return:
                        label_returns[label_name] = first_line

        if not label_returns:
            return content, 0

        # Her label icin goto sayisini hesapla
        goto_counts = Counter(_GOTO_RE.findall(content))

        # Tek geciste: if (cond) goto LAB -> if (cond) return VALUE;
        # Sondan basa degistir (pozisyon kaymasi onleme)
        matches = list(self._EARLY_RET_GOTO_RE.finditer(content))
        # Ters sirayla isleyelim
        for m in reversed(matches):
            label_name = m.group(3)
            if label_name not in label_returns:
                continue
            indent = m.group(1)
            cond = m.group(2)
            ret_stmt = label_returns[label_name]
            replacement = f"{indent}if ({cond}) {ret_stmt}"
            content = content[:m.start()] + replacement + content[m.end():]
            count += 1

        # Artik referansi kalmayan label'lari temizle
        if count > 0:
            content = self._remove_orphan_return_labels(content, label_returns)

        return content, count

    def _remove_orphan_return_labels(
        self, content: str, label_returns: dict[str, str]
    ) -> str:
        """Artik hicbir goto tarafindan hedeflenmemis return label'larini sil."""
        # Guncel goto sayilarini hesapla
        goto_counts = Counter(_GOTO_RE.findall(content))

        for label_name, ret_stmt in label_returns.items():
            if goto_counts.get(label_name, 0) > 0:
                continue  # Hala baska goto'lar var, label'i birak

            # Label + return satirlarini sil
            # Pattern: \n  LAB_xxx:\n    return ...;\n
            pattern = re.compile(
                r"\n[ \t]*" + re.escape(label_name) + r"\s*:\s*\n"
                r"[ \t]*" + re.escape(ret_stmt) + r"\s*\n?",
            )
            content = pattern.sub("\n", content, count=1)

        return content

    # ==================================================================
    # Pass 5a: Cascading goto collapse
    # ==================================================================

    def _pass_cascading_goto(self, content: str) -> tuple[str, int]:
        """goto LAB_a; ... LAB_a: goto LAB_b; -> goto LAB_b;

        Zincir: A->B->C varsa A->C'ye kadar collapse eder (max 10 derinlik).
        """
        # Once her label icin "sadece goto iceriyor mu?" map'i olustur
        label_redirects: dict[str, str] = {}  # LAB_a -> LAB_b
        for lm in _LABEL_RE.finditer(content):
            label_name = lm.group(2)
            after = content[lm.end(): lm.end() + 200]
            lines = [l.strip() for l in after.split("\n") if l.strip()]
            if not lines:
                continue
            first_line = lines[0]
            gm = re.match(r"goto\s+(LAB_[0-9a-fA-F]+)\s*;$", first_line)
            if gm:
                target = gm.group(1)
                if target != label_name:  # Self-loop onleme
                    label_redirects[label_name] = target

        if not label_redirects:
            return content, 0

        # Zincirleri coz: LAB_a -> LAB_b -> LAB_c => LAB_a -> LAB_c
        resolved: dict[str, str] = {}
        for label_name in label_redirects:
            target = label_redirects[label_name]
            visited = {label_name}
            depth = 0
            while target in label_redirects and depth < 10:
                if target in visited:
                    break  # Dongu tespit, dur
                visited.add(target)
                target = label_redirects[target]
                depth += 1
            resolved[label_name] = target

        # goto LAB_a; -> goto FINAL_TARGET; (eger farkli ise)
        count = 0

        def _replace_cascading(m: re.Match) -> str:
            nonlocal count
            label = m.group(1)
            if label in resolved and resolved[label] != label:
                count += 1
                return f"goto {resolved[label]};"
            return m.group(0)

        content = _GOTO_RE.sub(_replace_cascading, content)

        # Artik referansi kalmayan ara label'lari temizle
        if count > 0:
            goto_counts = Counter(_GOTO_RE.findall(content))
            for label_name in resolved:
                if goto_counts.get(label_name, 0) > 0:
                    continue
                # Label + goto satirini sil
                target = label_redirects[label_name]
                pattern = re.compile(
                    r"\n[ \t]*" + re.escape(label_name) + r"\s*:\s*\n"
                    r"[ \t]*goto\s+" + re.escape(target) + r"\s*;\s*\n?",
                )
                content = pattern.sub("\n", content, count=1)

        return content, count

    # ==================================================================
    # Pass 5b: Break/continue recognition
    # ==================================================================

    # While/for/do dongu pattern'leri (basit tespiti)
    _LOOP_START_RE = re.compile(
        r"^(\s*)(while|for|do)\s*[\({]", re.MULTILINE
    )

    def _pass_break_continue(self, content: str) -> tuple[str, int]:
        """Loop icindeki goto'lari break/continue ile degistir.

        Basit heuristik:
        - Label, loop'un kapanan }'sinin hemen sonrasindaysa -> break
        - Label, loop baslangicindaysa -> continue
        Sadece kolay tespit edilen durumlar.
        """
        count = 0
        lines = content.split("\n")

        # Goto hedefleri
        goto_counts = Counter(_GOTO_RE.findall(content))

        # Her label'in satir numarasini bul
        label_lines: dict[str, int] = {}
        for i, line in enumerate(lines):
            lm = re.match(r"\s*(LAB_[0-9a-fA-F]+)\s*:", line)
            if lm:
                label_lines[lm.group(1)] = i

        # Loop yapilarini tespit et: (start_line, end_line) araliklari
        # Basit brace-count ile loop body'sini bulalim
        loops: list[tuple[int, int]] = []  # (loop_start, closing_brace_line)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r"(while|for)\s*\(", stripped) or stripped.startswith("do {") or stripped == "do":
                # Loop basladigi satiri bulduk, kapanan }'yi ara
                brace_depth = 0
                found_open = False
                for j in range(i, min(i + 500, len(lines))):
                    for ch in lines[j]:
                        if ch == "{":
                            brace_depth += 1
                            found_open = True
                        elif ch == "}":
                            brace_depth -= 1
                    if found_open and brace_depth <= 0:
                        loops.append((i, j))
                        break

        if not loops or not label_lines:
            return content, 0

        # Her loop icin: label, loop sonu + 1 satirdaysa -> break pattern
        # Sondanbasa degistir
        replacements: list[tuple[int, str, str]] = []  # (line_idx, old, new)

        for loop_start, loop_end in loops:
            for label_name, label_line in label_lines.items():
                # Break pattern: label, loop'un kapanan }'sinin hemen sonrasinda
                # (loop_end satiri } iceriyor, label_line == loop_end + 1
                #  VEYA label_line == loop_end ve label } ile ayni satirda)
                if label_line == loop_end + 1 or label_line == loop_end:
                    # Bu label'a giden goto'lar loop ICINDE mi?
                    for gi in range(loop_start, loop_end + 1):
                        gm = re.search(
                            r"(\s*)goto\s+" + re.escape(label_name) + r"\s*;",
                            lines[gi],
                        )
                        if gm:
                            indent = gm.group(1)
                            old_text = gm.group(0)
                            replacements.append((gi, old_text, f"{indent}break;"))

                # Continue pattern: label, loop basina yakin (loop_start veya loop_start + 1)
                if label_line == loop_start or label_line == loop_start - 1:
                    for gi in range(loop_start, loop_end + 1):
                        gm = re.search(
                            r"(\s*)goto\s+" + re.escape(label_name) + r"\s*;",
                            lines[gi],
                        )
                        if gm:
                            indent = gm.group(1)
                            old_text = gm.group(0)
                            replacements.append((gi, old_text, f"{indent}continue;"))

        # Uygula (satirlari degistir)
        applied_lines: set[int] = set()
        for line_idx, old_text, new_text in replacements:
            if line_idx in applied_lines:
                continue
            lines[line_idx] = lines[line_idx].replace(old_text, new_text, 1)
            applied_lines.add(line_idx)
            count += 1

        if count > 0:
            content = "\n".join(lines)
            # Orphan label temizligi: artik goto hedefi olmayan label'lari sil
            goto_counts_new = Counter(_GOTO_RE.findall(content))
            for label_name in label_lines:
                if goto_counts_new.get(label_name, 0) == 0:
                    # Label satirini sil (ama sadece label'in kendisi, sonraki kod degil)
                    content = re.sub(
                        r"\n[ \t]*" + re.escape(label_name) + r"\s*:\s*(?=\n)",
                        "",
                        content,
                        count=1,
                    )

        return content, count

    # ==================================================================
    # Pass 6: If-else restructuring
    # ==================================================================

    # Pattern:
    #   if (cond) goto ELSE;
    #   ... code_a (then block) ...
    #   goto END;
    #   ELSE:
    #   ... code_b (else block) ...
    #   END:

    _IF_GOTO_RE = re.compile(
        r"^(\s*)if\s*\(([^)]+)\)\s*goto\s+(LAB_[0-9a-fA-F]+)\s*;",
        re.MULTILINE,
    )

    def _pass_ifelse_restructure(self, content: str) -> tuple[str, int]:
        """if(cond) goto ELSE; ... goto END; ELSE: ... END: -> if-else."""
        count = 0
        # Guvenlik: max 30 donusum per file (karmasiklik siniri)
        max_transforms = 30

        # Label pozisyonlarini bul
        label_positions: dict[str, int] = {}
        for lm in _LABEL_RE.finditer(content):
            label_positions[lm.group(2)] = lm.start()

        # If-goto match'lerini topla
        matches = list(self._IF_GOTO_RE.finditer(content))

        # Sondan basa isle
        for m in reversed(matches):
            if count >= max_transforms:
                break

            indent = m.group(1)
            cond = m.group(2)
            else_label = m.group(3)

            # ELSE label pozisyonunu bul
            if else_label not in label_positions:
                continue

            # if goto ile ELSE label arasindaki kodu al (then block)
            if_end = m.end()
            else_label_pos = label_positions[else_label]

            if else_label_pos <= if_end:
                continue  # Label if'ten ONCE, bu pattern degil

            between = content[if_end:else_label_pos]

            # "goto END;" then block'un son non-empty satiri olmali
            between_lines = between.rstrip().split("\n")
            # Son anlamli satiri bul
            last_meaningful = ""
            last_meaningful_idx = -1
            for i in range(len(between_lines) - 1, -1, -1):
                if between_lines[i].strip():
                    last_meaningful = between_lines[i].strip()
                    last_meaningful_idx = i
                    break

            end_goto_match = re.match(
                r"goto\s+(LAB_[0-9a-fA-F]+)\s*;$", last_meaningful
            )
            if not end_goto_match:
                continue

            end_label = end_goto_match.group(1)
            if end_label not in label_positions:
                continue
            if end_label == else_label:
                continue  # Ayni label'a atlama, bu if-else degil

            end_label_pos = label_positions[end_label]

            # END label, ELSE label'dan SONRA olmali
            if end_label_pos <= else_label_pos:
                continue

            # Then block: if ile "goto END;" arasindaki satirlar (goto END haric)
            then_lines = between_lines[:last_meaningful_idx]
            then_block = "\n".join(l for l in then_lines if l.strip())

            # Else block: ELSE label ile END label arasindaki kod
            # ELSE label satirini atla
            else_label_match = re.search(
                re.escape(else_label) + r"\s*:", content[else_label_pos:]
            )
            if not else_label_match:
                continue
            else_block_start = else_label_pos + else_label_match.end()
            else_block_raw = content[else_block_start:end_label_pos]
            else_lines = [l for l in else_block_raw.split("\n") if l.strip()]
            else_block = "\n".join(else_lines)

            # Guvenlik: block'lar cok buyuk olmasin (max 20 satir her biri)
            if len(then_lines) > 20 or len(else_lines) > 20:
                continue

            # Guvenlik: block'lar icinde baska goto olmamali (ic ice yapilar)
            if _GOTO_RE.search(then_block) or _GOTO_RE.search(else_block):
                continue

            # Donusumu yap
            new_code = f"{indent}if (!({cond})) {{\n"
            for line in then_block.split("\n"):
                if line.strip():
                    new_code += f"{indent}    {line.strip()}\n"
            new_code += f"{indent}}} else {{\n"
            for line in else_block.split("\n"):
                if line.strip():
                    new_code += f"{indent}    {line.strip()}\n"
            new_code += f"{indent}}}"

            # END label satirini bul (sadece "END_LABEL:" ise kaldir, degilse birak)
            end_label_line_match = re.search(
                r"\n[ \t]*" + re.escape(end_label) + r"\s*:", content[end_label_pos:]
            )

            # Degistir: if(cond) goto ELSE; ... goto END; ELSE: ... END: -> new_code
            # Kesim: m.start() ile end_label satirinin bitisine kadar
            cut_end = end_label_pos
            if end_label_line_match:
                cut_end = end_label_pos + end_label_line_match.end()

            content = content[:m.start()] + new_code + content[cut_end:]
            count += 1

            # Label pozisyonlarini guncelle (shift)
            shift = len(new_code) - (cut_end - m.start())
            new_positions = {}
            for lbl, pos in label_positions.items():
                if pos > m.start():
                    new_positions[lbl] = pos + shift
                else:
                    new_positions[lbl] = pos
            label_positions = new_positions

        return content, count

    # ==================================================================
    # Pass 7: Multi-target cleanup inlining
    # ==================================================================

    def _pass_multi_target_cleanup(self, content: str) -> tuple[str, int]:
        """Birden fazla goto ayni cleanup label'a gidiyorsa ve block kucukse
        hepsini inline et.

        Pass 1 sadece tek-hedefli goto'lari inline ediyordu. Bu pass
        birden fazla goto'nun ayni kucuk cleanup block'a gittigini tespit eder
        ve her goto'yu block ile degistirir.
        """
        count = 0
        goto_counts = Counter(_GOTO_RE.findall(content))

        # Cok hedefli cleanup label'lari bul (2-10 arasi goto)
        multi_labels: dict[str, str] = {}  # label -> cleanup block
        for lm in _LABEL_RE.finditer(content):
            label_name = lm.group(2)
            ref_count = goto_counts.get(label_name, 0)
            if ref_count < 2 or ref_count > 10:
                continue

            block = self._extract_label_block(content, lm.end())
            if not block:
                continue

            # Block cok kucuk olmali: max 5 satir (multi-inline icin daha siki)
            if block.count("\n") > 5:
                continue

            # Cleanup pattern olmali
            if not self._is_cleanup_block(block):
                continue

            multi_labels[label_name] = block

        if not multi_labels:
            return content, 0

        # Her label icin tum goto'lari inline et
        for label_name, block in multi_labels.items():
            # Tum goto pozisyonlarini bul
            goto_pattern = re.compile(
                r"(\s*)goto\s+" + re.escape(label_name) + r"\s*;"
            )

            def _inline_replace(m: re.Match) -> str:
                nonlocal count
                g_indent = m.group(1)
                inlined = self._indent_block(block, g_indent)
                comment = (
                    "%s/* cleanup (inlined from %s) */\n"
                    % (g_indent, label_name)
                )
                count += 1
                return "\n" + comment + inlined

            content = goto_pattern.sub(_inline_replace, content)

            # Label + block'u sil (artik referansi yok)
            # Label satirini ve devamindaki block'u bul ve sil
            # v1.7.x: Eski regex [\s\S]*? DOTALL ile catastrophic backtracking
            # yapiyordu (500KB+ body'lerde pipeline hang). String-bazli arama
            # ile O(n) garanti.
            _label_marker = label_name + ":"
            _label_pos = content.find(_label_marker)
            if _label_pos >= 0:
                # Label satirinin baslangicina geri git (onceki \n'e)
                _line_start = content.rfind("\n", 0, _label_pos)
                if _line_start == -1:
                    _line_start = 0
                # Block'un son satirini bul
                _last_line = block.strip().split("\n")[-1].strip()
                _end_pos = content.find(_last_line, _label_pos)
                if _end_pos >= 0:
                    _end_pos += len(_last_line)
                    # Sondaki whitespace/newline'i tüket
                    while _end_pos < len(content) and content[_end_pos] in " \t\n":
                        _end_pos += 1
                    content = content[:_line_start] + "\n" + content[_end_pos:]

        return content, count
