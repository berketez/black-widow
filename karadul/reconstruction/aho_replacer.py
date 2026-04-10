"""Aho-Corasick tabanli toplu isim degistirme -- O(N + M) karmasiklik.

Buyuk naming_map'leri (3K-22K+ entry) C koduna uygulamak icin
devasa regex alternation (O(N*M)) yerine Aho-Corasick automaton
(O(N + matches)) kullanir.

Kullanim:
    from karadul.reconstruction.aho_replacer import AhoReplacer

    replacer = AhoReplacer(naming_map)      # {"FUN_001": "init_ssl", ...}
    new_code = replacer.replace(old_code)   # Word-boundary-aware replace

    # Fonksiyon tespiti (function body extraction icin)
    finder = AhoFinder(func_names)          # ["FUN_001", "FUN_002", ...]
    name = finder.find_first_word(line)

Garanti:
    - Word boundary: regex \b ile BIT-EXACT ayni davranis
    - Overlap: En uzun match kazanir (kisa match'ler filtrelenir)
    - Sonuc: Regex alternation ile ayni cikti uretir
"""

from __future__ import annotations

import ahocorasick


# ---------------------------------------------------------------------------
# AhoReplacer -- naming_map uygulamak icin
# ---------------------------------------------------------------------------

class AhoReplacer:
    """Aho-Corasick tabanli word-boundary-aware toplu replace.

    Regex alternation r\"\\b(a|b|c|...N)\\b\" ile ayni sonucu uretir
    ama O(text_len + match_count) karmasiklikla.

    Args:
        naming_map: {eski_isim: yeni_isim} dict'i.  Bos veya 2 karakterden
                    kisa key'ler otomatik filtrelenir.
    """

    __slots__ = ("_automaton", "_empty")

    def __init__(self, naming_map: dict[str, str]) -> None:
        # Bos/kisa key filtresi (regex versiyonuyla ayni davranis)
        cleaned = {k: v for k, v in naming_map.items() if k and len(k) >= 2}
        if not cleaned:
            self._automaton = None
            self._empty = True
            return

        self._empty = False
        A = ahocorasick.Automaton()
        for old_name, new_name in cleaned.items():
            A.add_word(old_name, (old_name, new_name))
        A.make_automaton()
        self._automaton = A

    def replace(self, text: str) -> str:
        """Text icindeki tum eslesen isimleri degistir.

        Word boundary kurali: regex \\b ile AYNI davranis.
        \\b = word char ile non-word char (veya string basi/sonu) arasindaki sinir.

        Onemli: \\b, match'in ilk/son karakterinin tipine bagli:
        - Ilk char word-char ise -> oncesinde non-word (veya bos) olmali
        - Ilk char non-word ise -> oncesinde word-char olmali
        - Son char word-char ise -> sonrasinda non-word (veya bos) olmali
        - Son char non-word ise -> sonrasinda word-char olmali

        Returns:
            Degistirilmis text.
        """
        if self._empty or self._automaton is None:
            return text

        text_len = len(text)

        # Tum match'leri topla: (start, end_exclusive, new_name)
        raw_matches: list[tuple[int, int, str]] = []
        for end_idx, (old, new) in self._automaton.iter(text):
            start_idx = end_idx - len(old) + 1
            end_exclusive = end_idx + 1

            # \b emulasyonu: match sinirlarinda word boundary kontrolu
            if not _check_word_boundary(text, text_len, start_idx, end_exclusive, old):
                continue

            raw_matches.append((start_idx, end_exclusive, new))

        if not raw_matches:
            return text

        # Overlap cozmesi: Ayni pozisyonu kapsayan match'lerden
        # en uzun olani sec (regex alternation davranisi -- longest match first)
        resolved = _resolve_overlaps(raw_matches)

        # Sondan basa replace (index kaymasini onlemek icin)
        result = list(text)
        for start, end, new in reversed(resolved):
            result[start:end] = list(new)

        return "".join(result)


# ---------------------------------------------------------------------------
# AhoFinder -- fonksiyon isimlerini bulmak icin (replace degil, sadece find)
# ---------------------------------------------------------------------------

class AhoFinder:
    """Aho-Corasick ile text icinde isimleri bul (replace yapmaz).

    _extract_function_bodies gibi yerlerde kullanilir: bir satirdaki
    fonksiyon isimlerini bulup pozisyonlarini dondurur.

    Args:
        names: Aranacak isim listesi.
    """

    __slots__ = ("_automaton", "_empty")

    def __init__(self, names: list[str]) -> None:
        if not names:
            self._automaton = None
            self._empty = True
            return

        self._empty = False
        A = ahocorasick.Automaton()
        for name in names:
            A.add_word(name, name)
        A.make_automaton()
        self._automaton = A

    def find_first_word(self, text: str) -> str | None:
        """Text icinde word boundary'ye uyan ilk ismi dondur.

        Returns:
            Bulunan isim veya None.
        """
        if self._empty or self._automaton is None:
            return None

        text_len = len(text)
        best: str | None = None
        best_start = text_len + 1

        for end_idx, name in self._automaton.iter(text):
            start_idx = end_idx - len(name) + 1
            end_exclusive = end_idx + 1

            # Word boundary (regex \b ile ayni)
            if not _check_word_boundary(text, text_len, start_idx, end_exclusive, name):
                continue

            # En erken pozisyondaki match'i sec, esitlikte en uzunu
            if start_idx < best_start or (
                start_idx == best_start
                and best is not None
                and len(name) > len(best)
            ):
                best = name
                best_start = start_idx

        return best

    def find_all_words(self, text: str) -> list[tuple[int, str]]:
        """Text icinde word boundary'ye uyan TUM isimleri dondur.

        Her match icin (start_pozisyon, isim) tuple'i dondurur.
        Overlap'ler cozulmus halde -- ayni pozisyonda en uzun match kalir.

        Returns:
            [(start, name), ...] siralanmis liste.
        """
        if self._empty or self._automaton is None:
            return []

        text_len = len(text)
        raw: list[tuple[int, int, str]] = []

        for end_idx, name in self._automaton.iter(text):
            start_idx = end_idx - len(name) + 1
            end_exclusive = end_idx + 1

            if not _check_word_boundary(text, text_len, start_idx, end_exclusive, name):
                continue

            raw.append((start_idx, end_exclusive, name))

        if not raw:
            return []

        resolved = _resolve_overlaps(raw)
        return [(start, name) for start, _, name in resolved]


# ---------------------------------------------------------------------------
# Yardimci fonksiyonlar
# ---------------------------------------------------------------------------

def _is_word_char(ch: str) -> bool:
    """Karakter \\w grubuna ait mi? (alfanumerik veya _)

    Regex \\b icin word character = [a-zA-Z0-9_]
    """
    return ch.isalnum() or ch == "_"


def _check_word_boundary(
    text: str,
    text_len: int,
    start: int,
    end: int,
    pattern: str,
) -> bool:
    """Regex \\b(pattern)\\b ile ayni word boundary kontrolu.

    \\b kurali:
    - Pattern ilk char WORD ise -> oncesinde NON-WORD (veya string basi) olmali
    - Pattern ilk char NON-WORD ise -> oncesinde WORD olmali
    - Pattern son char WORD ise -> sonrasinda NON-WORD (veya string sonu) olmali
    - Pattern son char NON-WORD ise -> sonrasinda WORD olmali

    Args:
        text: Kaynak metin.
        text_len: len(text) -- tekrar hesaplamamak icin.
        start: Match baslangic indexi (inclusive).
        end: Match bitis indexi (exclusive).
        pattern: Match eden string.

    Returns:
        True eger word boundary kosulilarini sagliyorsa.
    """
    if not pattern:
        return False

    first_char = pattern[0]
    last_char = pattern[-1]

    # Baslangic siniri kontrolu
    first_is_word = _is_word_char(first_char)
    if start > 0:
        prev_is_word = _is_word_char(text[start - 1])
        # \b = farkli tip'te karakterler siniri
        if first_is_word == prev_is_word:
            return False
    else:
        # String basi -- \b sadece word char ile baslarsa gecerli
        # (string basi non-word gibi sayilir)
        if not first_is_word:
            return False

    # Bitis siniri kontrolu
    last_is_word = _is_word_char(last_char)
    if end < text_len:
        next_is_word = _is_word_char(text[end])
        # \b = farkli tip'te karakterler siniri
        if last_is_word == next_is_word:
            return False
    else:
        # String sonu -- \b sadece word char ile biterse gecerli
        if not last_is_word:
            return False

    return True


def _resolve_overlaps(
    matches: list[tuple[int, int, str]],
) -> list[tuple[int, int, str]]:
    """Overlapping match'leri coz: en uzun match kazanir.

    Regex alternation'daki sorted-by-length-desc davranisini simule eder.
    Ayni start pozisyonunda en uzun match secilir.
    Cakisan match'lerden onceki (sol) olan kalir.

    Args:
        matches: [(start, end_exclusive, new_name), ...] -- siralanmamis.

    Returns:
        Cakismayan, siralanmis match listesi.
    """
    if not matches:
        return []

    # Start'a gore sirala, esitlikte uzun match once
    sorted_matches = sorted(matches, key=lambda m: (m[0], -(m[1] - m[0])))

    result: list[tuple[int, int, str]] = []
    last_end = -1

    for start, end, new in sorted_matches:
        if start >= last_end:
            result.append((start, end, new))
            last_end = end
        # else: overlap -- atla (onceki uzun match kazanmis)

    return result
