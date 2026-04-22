"""STRIDE/XTRIDE-inspired N-gram degisken isim tahmini.

Decompiled C kodundan degisken isimlerini n-gram eslesmesiyle tahmin eder.
STRIDE (Green et al., 2024) ve XTRIDE (Seidel et al., 2026) yaklasimlarini
Ghidra ciktisi icin Python'da implement eder.

Calisma prensibi:
    1. Ghidra decompiled C kodunu tokenize et
    2. Token'lari normalize et (adresler, literaller, degisken isimleri)
    3. Her degisken kullanimi icin etraftaki N token'i cikar (n-gram)
    4. N-gram hash'ini veritabaninda ara
    5. En yuksek skorlu isim tahminini dondur

Kullanim:
    from karadul.reconstruction.ngram_namer import NgramNamer

    namer = NgramNamer(db_dir=Path("sigs/ngram_name_db"))
    result = namer.predict(func_code, "my_function")
    # -> {"param_1": NgramPrediction("buffer", 0.82), ...}

Performans hedefi: <1ms / fonksiyon.
"""

from __future__ import annotations

import hashlib
import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sonuc veri yapisi
# ---------------------------------------------------------------------------


@dataclass
class NgramPrediction:
    """Tek bir degisken icin isim tahmini.

    Attributes:
        var_name: Orijinal degisken adi (param_1, local_10, vb.).
        predicted_name: Tahmin edilen anlamli isim (buffer, counter, vb.).
        confidence: Guven skoru [0.0, 1.0].
        ngram_size: Eslesen en buyuk n-gram boyutu.
        evidence: Kanit metni (debug icin).
    """

    var_name: str
    predicted_name: str
    confidence: float
    ngram_size: int = 0
    evidence: str = ""


@dataclass
class NgramNamerResult:
    """Fonksiyon bazli n-gram isim tahmin sonucu."""

    func_name: str
    predictions: dict[str, NgramPrediction] = field(default_factory=dict)

    @property
    def total_predicted(self) -> int:
        return len(self.predictions)


# ---------------------------------------------------------------------------
# Token normalizasyonu
# ---------------------------------------------------------------------------

# Ghidra / IDA compiler-generated prefiksler
_COMPILER_PREFIXES = (
    # Ghidra
    "FUN_", "thunk_FUN_", "LAB_", "DAT_", "_DAT_",
    "switchD_", "switchdataD_", "caseD_",
    "code_r0x", "joined_r0x", "uRam",
    # IDA
    "sub_", "loc_", "unk_", "off_", "asc_", "stru_", "funcs_",
    "byte_", "word_", "dword_", "qword_", "xmmword_", "ymmword_",
    "LABEL_",
)

# Generic degisken isimleri (tahmin edilecek olanlar)
_GENERIC_VAR_RE = re.compile(
    r"^(?:param_\d+|local_[0-9a-f]+|iVar\d+|uVar\d+|lVar\d+|bVar\d+"
    r"|sVar\d+|cVar\d+|fVar\d+|dVar\d+|pVar\d+|ppVar\d+"
    r"|in_\w+|auStack\w+|puVar\d+|pcVar\d+|piVar\d+"
    r"|plVar\d+|pbVar\d+|extraout_\w+|Var\d+)$"
)

# Ghidra stack var pattern
_GHIDRA_STACK_RE = re.compile(r"^[a-z]*Stack_[0-9]+$", re.IGNORECASE)
_GHIDRA_VAR_RE = re.compile(r"^[a-z]*Var[0-9]+$", re.IGNORECASE)

# Hex / decimal sayi pattern
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_DEC_RE = re.compile(r"^[0-9]+$")

# String literal pattern (cift tirnak)
_STRING_RE = re.compile(r'^".*"$')

# C tokenizer
_C_TOKEN_RE = re.compile(r"[a-zA-Z_]\w*|0x[0-9a-fA-F]+|[0-9]+|[^\s]")

# Degisken marker pattern (@@var_N@@ formatinda)
_VAR_MARKER = "@@"

# Flank normalizasyonu icin: @@var_N@@ -> @@var_X@@ (pozisyon-bagimsiz)
# v1.10.0 Batch 6B fix: Flank icindeki @@var_N@@ marker'larinin N'si,
# fonksiyondaki degisken kullanim sirasina bagli degisiyor. Ayni context
# farkli pozisyonlarda farkli hash uretir. Bunu normalize ederek
# "burada bir degisken var" bilgisini korur ama N kimligini siler.
_VAR_N_RE = re.compile(r"^@@var_\d+@@$")
_FLANK_VAR_PLACEHOLDER = "@@var_X@@"


def _mask_flank_vars(span: list[str]) -> list[str]:
    """Bir span icindeki tum @@var_N@@ token'larini @@var_X@@ ile degistir.

    Hem build hem predict tarafinda kullanilir ki hash'ler uyumlu olsun.
    """
    return [
        _FLANK_VAR_PLACEHOLDER if _VAR_N_RE.match(t) else t
        for t in span
    ]

# N-gram boyutlari (XTRIDE config)
NGRAM_SIZES = (48, 12, 8, 4, 2)

# Top-K tahmin sayisi
TOP_K = 5


def tokenize_c(code: str) -> list[str]:
    """Ghidra decompiled C kodunu token listesine donustur."""
    return _C_TOKEN_RE.findall(code)


def normalize_token(token: str) -> str:
    """Tek bir token'i normalize et (STRIDE kurallari)."""
    # Compiler-generated prefiksler
    for pfx in _COMPILER_PREFIXES:
        if token.startswith(pfx) and len(token) > len(pfx):
            return f"{pfx}XXX"

    # String literal
    if _STRING_RE.match(token):
        return "<STRING>"

    # Ghidra stack var
    if _GHIDRA_STACK_RE.match(token):
        return "<ghidra_stack>"

    # Ghidra var
    if _GHIDRA_VAR_RE.match(token):
        return "<ghidra_var>"

    # Hex sayi
    if _HEX_RE.match(token):
        value = int(token, 16)
        if value >= 0x100:
            hex_digits = len(f"{value:x}")
            return f"<NUM_{hex_digits}>"
        return hex(value)

    # Decimal sayi
    if _DEC_RE.match(token):
        value = int(token)
        if value >= 0x100:
            hex_digits = len(f"{value:x}")
            return f"<NUM_{hex_digits}>"
        return hex(value)

    return token


def normalize_tokens(tokens: list[str]) -> list[str]:
    """Token listesini normalize et."""
    return [normalize_token(t) for t in tokens]


def _mark_variables(tokens: list[str]) -> tuple[list[str], dict[int, str]]:
    """Generic degisken isimlerini @@var_N@@ marker'lariyla degistir.

    Returns:
        (marked_tokens, var_positions): marker'li token listesi ve
            {pozisyon: orijinal_degisken_adi} eslesmesi.
    """
    marked = []
    var_positions: dict[int, str] = {}
    var_ids: dict[str, int] = {}  # orijinal_ad -> sira no
    next_id = 0

    for i, tok in enumerate(tokens):
        if _GENERIC_VAR_RE.match(tok):
            var_positions[i] = tok
            if tok not in var_ids:
                var_ids[tok] = next_id
                next_id += 1
            vid = var_ids[tok]
            marked.append(f"{_VAR_MARKER}var_{vid}{_VAR_MARKER}")
        else:
            marked.append(tok)

    return marked, var_positions


# ---------------------------------------------------------------------------
# N-gram hash
# ---------------------------------------------------------------------------


def ngram_hash(tokens: list[str], discriminator: bytes = b"") -> bytes:
    """Token dizisinden 12-byte n-gram hash uret (SHA256[:12]).

    Args:
        tokens: Normalize edilmis token dizisi.
        discriminator: Flanking modu icin b"left" veya b"right".
    """
    raw = b"\xff".join(t.encode("utf-8") for t in tokens) + discriminator
    return hashlib.sha256(raw).digest()[:12]


def _extract_centered_ngrams(
    tokens: list[str],
    var_positions: dict[int, str],
    size: int,
) -> Iterator[tuple[bytes, int, str]]:
    """Centered n-gram'lari cikar.

    v1.10.0 Batch 5A (DB v2 uyumluluk): Center pozisyonunu `@@var_0@@`
    ile normalize eder. DB build zamaninda da ayni normalization
    kullanildigi icin hash'ler kararli match eder. Onceki davranistan
    farki: center'daki `@@var_N@@` (N=0,1,2,...) yerine her durumda
    `@@var_0@@` kullaniliyor. Bu, ayni baglamda farkli pozisyonlardaki
    degiskenlerin ayni n-gram olarak gorulmesini saglar.

    Yields:
        (hash_key, position, original_var_name)
    """
    half = size
    padded = ["??"] * half + tokens + ["??"] * half

    for orig_pos, var_name in var_positions.items():
        pos = orig_pos + half  # padded offset
        span = list(padded[pos - half: pos + half + 1])
        # Center'i sabit marker ile normalize et (DB build ile uyumlu).
        span[half] = "@@var_0@@"
        # v1.10.0 Batch 6B: Flank'lardaki @@var_N@@ marker'lari da
        # pozisyon-bagimsiz @@var_X@@ ile maskle (build ile uyumlu).
        left = _mask_flank_vars(span[:half])
        right = _mask_flank_vars(span[half + 1:])
        normalized = left + [span[half]] + right
        key = ngram_hash(normalized)
        yield key, orig_pos, var_name


def _extract_flanking_ngrams(
    tokens: list[str],
    var_positions: dict[int, str],
    size: int,
) -> Iterator[tuple[bytes, int, str, str]]:
    """Flanking n-gram'lari cikar (sol + sag ayri).

    Yields:
        (hash_key, position, original_var_name, side)
    """
    padded = ["??"] * size + tokens + ["??"] * size

    for orig_pos, var_name in var_positions.items():
        pos = orig_pos + size
        # v1.10.0 Batch 6B: Flank icindeki @@var_N@@ marker'lari pozisyon
        # bagimli N icerir — normalize et (DB build ile uyumlu).
        left = _mask_flank_vars(padded[pos - size: pos])
        right = _mask_flank_vars(padded[pos + 1: pos + 1 + size])

        yield ngram_hash(left, b"left"), orig_pos, var_name, "left"
        yield ngram_hash(right, b"right"), orig_pos, var_name, "right"


# ---------------------------------------------------------------------------
# N-gram Vocabulary
# ---------------------------------------------------------------------------


class NgramVocab:
    """Degisken isim vocabularisi.

    Tab-separated format: name<TAB>count
    """

    def __init__(self) -> None:
        self._name_to_id: dict[str, int] = {}
        self._id_to_name: list[str] = []
        self._id_to_count: list[int] = []

    def __len__(self) -> int:
        return len(self._id_to_name)

    def lookup(self, name: str) -> int:
        """Isim -> ID. Bulunamazsa -1."""
        return self._name_to_id.get(name, -1)

    def reverse(self, vid: int) -> str:
        """ID -> isim."""
        if 0 <= vid < len(self._id_to_name):
            return self._id_to_name[vid]
        return ""

    def count_by_id(self, vid: int) -> int:
        """ID'ye gore frekans."""
        if 0 <= vid < len(self._id_to_count):
            return self._id_to_count[vid]
        return 0

    def add(self, name: str, count: int = 1) -> int:
        """Isim ekle veya sayacini artir. ID dondur."""
        vid = self._name_to_id.get(name, -1)
        if vid >= 0:
            self._id_to_count[vid] += count
            return vid
        vid = len(self._id_to_name)
        self._name_to_id[name] = vid
        self._id_to_name.append(name)
        self._id_to_count.append(count)
        return vid

    def save(self, path: Path) -> None:
        """Tab-separated dosyaya kaydet (frekans sirasina gore)."""
        pairs = sorted(
            zip(self._id_to_name, self._id_to_count),
            key=lambda x: -x[1],
        )
        with open(path, "w", encoding="utf-8") as f:
            for name, count in pairs:
                f.write(f"{name}\t{count}\n")

    @classmethod
    def load(cls, path: Path) -> NgramVocab:
        """Tab-separated dosyadan yukle."""
        vocab = cls()
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                parts = line.split("\t", 1)
                name = parts[0]
                count = int(parts[1]) if len(parts) > 1 else 1
                vocab.add(name, count)
        return vocab


# ---------------------------------------------------------------------------
# N-gram Veritabani
# ---------------------------------------------------------------------------

# DB entry: 12-byte hash + uint32 total + K * (uint32 vocab_id, uint32 count)
_HASH_LEN = 12


class NgramDB:
    """Sorted hash-based n-gram veritabani.

    In-memory binary search ile O(log N) lookup.
    Format: sorted array of (hash[12], total[4], topk * (vid[4], cnt[4]))
    """

    def __init__(self, hashes: list[bytes], totals: list[int],
                 predictions: list[list[tuple[int, int]]], size: int) -> None:
        self._hashes = hashes  # sorted 12-byte keys
        self._totals = totals
        self._predictions = predictions  # [(vocab_id, count), ...]
        self.size = size

    def __len__(self) -> int:
        return len(self._hashes)

    def lookup(self, key: bytes) -> tuple[int, list[tuple[int, int]]] | None:
        """Binary search ile hash ara.

        Returns:
            (total_count, [(vocab_id, count), ...]) veya None.
        """
        hashes = self._hashes
        lo, hi = 0, len(hashes)
        while lo < hi:
            mid = (lo + hi) // 2
            h = hashes[mid]
            if h == key:
                return self._totals[mid], self._predictions[mid]
            elif h < key:
                lo = mid + 1
            else:
                hi = mid
        return None

    def save(self, path: Path) -> None:
        """Binary formatta kaydet.

        v1.10.0 Batch 6B fix: `topk` sabitini TOP_K sabit degerine alir
        (onceden `_predictions[0]`'in uzunluguna gore aliyor — yanlis,
        cunku her entry'nin prediction sayisi farkli olabilir, ama dosya
        formati sabit-boyut). Sonucta load tarafi desenkronize olup dogru
        hash'leri bulamiyordu. Fix: her entry EXACTLY TOP_K predictions
        ile yazilsin (eksikse 0-padding).
        """
        topk = TOP_K
        with open(path, "wb") as f:
            # Header: magic(4) + version(4) + size(4) + count(4) + topk(4)
            f.write(b"NGDB")
            f.write(struct.pack("<IIII", 1, self.size, len(self._hashes), topk))

            for i, h in enumerate(self._hashes):
                f.write(h)  # 12 bytes
                f.write(struct.pack("<I", self._totals[i]))
                # Her zaman TOP_K adet (vid, cnt) pair yaz — eksikse 0 pad.
                preds = self._predictions[i][:topk]
                for vid, cnt in preds:
                    f.write(struct.pack("<II", vid, cnt))
                for _ in range(topk - len(preds)):
                    f.write(struct.pack("<II", 0, 0))

    @classmethod
    def load(cls, path: Path) -> NgramDB:
        """Binary formattan yukle."""
        data = path.read_bytes()
        if data[:4] != b"NGDB":
            raise ValueError(f"Gecersiz DB dosyasi: {path}")

        version, size, count, topk = struct.unpack_from("<IIII", data, 4)
        if version != 1:
            raise ValueError(f"Desteklenmeyen DB versiyon: {version}")

        entry_size = _HASH_LEN + 4 + topk * 8  # hash + total + topk*(vid+cnt)
        offset = 20  # header size

        hashes: list[bytes] = []
        totals: list[int] = []
        predictions: list[list[tuple[int, int]]] = []

        for _ in range(count):
            h = data[offset: offset + _HASH_LEN]
            offset += _HASH_LEN
            total = struct.unpack_from("<I", data, offset)[0]
            offset += 4

            preds = []
            for _ in range(topk):
                vid, cnt = struct.unpack_from("<II", data, offset)
                offset += 8
                if cnt > 0:
                    preds.append((vid, cnt))

            hashes.append(h)
            totals.append(total)
            predictions.append(preds)

        return cls(hashes, totals, predictions, size)

    @classmethod
    def build(cls, entries: dict[bytes, dict[int, int]], size: int,
              topk: int = TOP_K) -> NgramDB:
        """Hash -> {vocab_id: count} dict'inden DB olustur.

        Args:
            entries: {hash_key: {vocab_id: count}} eslesmesi.
            size: N-gram boyutu.
            topk: Her hash icin saklanacak top tahmin sayisi.
        """
        hashes = []
        totals = []
        predictions = []

        for h in sorted(entries.keys()):
            vid_counts = entries[h]
            total = sum(vid_counts.values())
            top = sorted(vid_counts.items(), key=lambda x: -x[1])[:topk]
            hashes.append(h)
            totals.append(total)
            predictions.append(top)

        return cls(hashes, totals, predictions, size)


# ---------------------------------------------------------------------------
# N-gram Namer (ana sinif)
# ---------------------------------------------------------------------------

# Isim filtreleri: tahmin edilen isimler bu pattern'lere uyarsa atla
_SKIP_NAMES = frozenset({
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    "v1", "v2", "v3", "v4", "v5", "a1", "a2", "a3", "a4",
    "arg", "var", "tmp", "ret", "result",
})

# Gecersiz C isimleri
_C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary",
})


class NgramNamer:
    """STRIDE-inspired n-gram isim tahmin motoru.

    Ghidra decompiled C kodundaki generic degisken isimlerini (param_1, local_10)
    anlamli isimlerle degistirmek icin n-gram eslestirme kullanir.
    """

    def __init__(self, db_dir: Path | None = None) -> None:
        """NgramNamer olustur.

        Args:
            db_dir: N-gram DB dizini. None ise tahmin yapilamaz (sadece tokenize).
                    Beklenen dosyalar: vocab.txt, db_2.ngdb, db_4.ngdb, ...
        """
        self._vocab: NgramVocab | None = None
        self._dbs: list[NgramDB] = []
        self._db_dir = db_dir
        self._loaded = False

        self.stats: dict[str, int] = {
            "total_functions": 0,
            "total_predictions": 0,
            "total_variables_seen": 0,
        }

    def _ensure_loaded(self) -> bool:
        """DB'leri lazy-load et. Basarili ise True."""
        if self._loaded:
            return self._vocab is not None

        self._loaded = True
        if self._db_dir is None:
            return False

        vocab_path = self._db_dir / "vocab.txt"
        if not vocab_path.exists():
            logger.debug("N-gram vocab bulunamadi: %s", vocab_path)
            return False

        try:
            self._vocab = NgramVocab.load(vocab_path)
        except Exception as exc:
            logger.warning("N-gram vocab yuklenemedi: %s", exc)
            return False

        # DB dosyalarini boyut sirasina gore yukle (buyukten kucuge)
        for size in NGRAM_SIZES:
            db_path = self._db_dir / f"db_{size}.ngdb"
            if db_path.exists():
                try:
                    db = NgramDB.load(db_path)
                    self._dbs.append(db)
                except Exception as exc:
                    logger.warning("N-gram DB yuklenemedi (%s): %s", db_path.name, exc)

        if not self._dbs:
            logger.debug("Hicbir N-gram DB bulunamadi: %s", self._db_dir)
            return False

        # Buyukten kucuge sirala
        self._dbs.sort(key=lambda d: -d.size)
        logger.info(
            "N-gram namer yuklendi: vocab=%d, dbs=%s",
            len(self._vocab), [d.size for d in self._dbs],
        )
        return True

    def predict(self, func_code: str, func_name: str = "") -> NgramNamerResult:
        """Fonksiyon kodundan degisken isimlerini tahmin et.

        Args:
            func_code: Ghidra decompiled C fonksiyon kodu.
            func_name: Fonksiyon adi (istatistik/log icin).

        Returns:
            NgramNamerResult: {var_name: NgramPrediction} eslesmesi.
        """
        self.stats["total_functions"] += 1
        result = NgramNamerResult(func_name=func_name)

        if not self._ensure_loaded():
            return result

        assert self._vocab is not None

        # 1. Tokenize + normalize
        tokens = tokenize_c(func_code)
        tokens = normalize_tokens(tokens)

        # 2. Degiskenleri marker'la
        marked, var_positions = _mark_variables(tokens)

        if not var_positions:
            return result

        self.stats["total_variables_seen"] += len(set(var_positions.values()))

        # 3. Her degisken kullanimi icin n-gram tahminleri topla
        # candidates[var_name][(predicted_name)] = toplam skor
        candidates: dict[str, dict[str, float]] = {}
        # Hangi pozisyonlarda zaten buyuk n-gram eslesmesi bulundu
        matched_positions: set[int] = set()

        for db in self._dbs:
            # Centered n-gram'lar
            for key, pos, var_name in _extract_centered_ngrams(
                marked, var_positions, db.size
            ):
                if pos in matched_positions:
                    continue
                hit = db.lookup(key)
                if hit is None:
                    continue
                total, preds = hit
                matched_positions.add(pos)

                if var_name not in candidates:
                    candidates[var_name] = {}

                for vid, cnt in preds:
                    name = self._vocab.reverse(vid)
                    if not name or name in _SKIP_NAMES or name in _C_KEYWORDS:
                        continue
                    # STRIDE skor formulu: (count/total) * 0.5 + 0.5
                    score = (cnt / total) * 0.5 + 0.5 if total > 0 else 0.5
                    candidates[var_name][name] = (
                        candidates[var_name].get(name, 0.0) + score
                    )

            # Flanking n-gram'lar
            for key, pos, var_name, _side in _extract_flanking_ngrams(
                marked, var_positions, db.size
            ):
                if pos in matched_positions:
                    continue
                hit = db.lookup(key)
                if hit is None:
                    continue
                total, preds = hit

                if var_name not in candidates:
                    candidates[var_name] = {}

                for vid, cnt in preds:
                    name = self._vocab.reverse(vid)
                    if not name or name in _SKIP_NAMES or name in _C_KEYWORDS:
                        continue
                    score = (cnt / total) * 0.5 + 0.5 if total > 0 else 0.5
                    # Flanking yarisi kadar katkida bulunur
                    candidates[var_name][name] = (
                        candidates[var_name].get(name, 0.0) + score * 0.5
                    )

        # 4. Her degisken icin en iyi tahmini sec
        for var_name, name_scores in candidates.items():
            if not name_scores:
                continue

            # Sirala: skor desc, esitse vocab frekansi desc
            ranked = sorted(
                name_scores.items(),
                key=lambda x: (-x[1], -self._vocab.count_by_id(
                    self._vocab.lookup(x[0])
                )),
            )
            best_name, best_score = ranked[0]

            # Normalize confidence: [0.5, max_possible] -> [0.0, 1.0]
            # Basit yaklasim: var_occurrences * 1.0 = maks skor
            var_count = sum(1 for v in var_positions.values() if v == var_name)
            max_score = var_count * 1.0  # her konum 1.0 puan verebilir
            confidence = min(best_score / max_score, 1.0) if max_score > 0 else 0.0

            # C identifier kontrolu
            if not best_name.isidentifier():
                continue

            result.predictions[var_name] = NgramPrediction(
                var_name=var_name,
                predicted_name=best_name,
                confidence=confidence,
                ngram_size=self._dbs[0].size if self._dbs else 0,
                evidence=f"score={best_score:.2f}, occurrences={var_count}",
            )

        self.stats["total_predictions"] += len(result.predictions)
        return result

    def batch_predict(
        self, functions: dict[str, str],
    ) -> dict[str, NgramNamerResult]:
        """Birden fazla fonksiyon icin batch isim tahmini."""
        results: dict[str, NgramNamerResult] = {}
        for func_name, func_code in functions.items():
            results[func_name] = self.predict(func_code, func_name)
        return results

    @property
    def db_count(self) -> int:
        """Yuklenen DB sayisi."""
        self._ensure_loaded()
        return len(self._dbs)

    @property
    def vocab_size(self) -> int:
        """Vocabulari buyuklugu."""
        self._ensure_loaded()
        return len(self._vocab) if self._vocab else 0
