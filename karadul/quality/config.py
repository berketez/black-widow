"""Readability scorer konfigurasyonu -- agirliklar ve esikler.

Tum magic number'lar burada tanimli. Metric modulleri bu sabitleri
import ederek kullanir; boylece ayni esik farkli dosyalarda
farkli yazilamaz (CLAUDE.md kural 11).
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Boyut agirliklari (toplam = 1.00)
# ---------------------------------------------------------------------------
# Gorev dokumaninda verilen 6 boyutun katkisi. Toplama 1.0 olmali.

WEIGHT_FUNCTION_NAMES: float = 0.25
WEIGHT_PARAM_NAMES: float = 0.15
WEIGHT_LOCAL_VARS: float = 0.15
WEIGHT_TYPE_QUALITY: float = 0.20
WEIGHT_COMMENTS: float = 0.10
WEIGHT_CODE_STRUCTURE: float = 0.15


# ---------------------------------------------------------------------------
# Skor sinirlari
# ---------------------------------------------------------------------------

SCORE_MIN: float = 0.0
SCORE_MAX: float = 100.0
# Debug binary ground truth'un varsayilan skoru (baseline)
GROUND_TRUTH_SCORE: float = 100.0


# ---------------------------------------------------------------------------
# Boyut 1: Fonksiyon isimleri
# ---------------------------------------------------------------------------
# Snake_case / camelCase uyumlulugunu kontrol ederken minimum uzunluk
MIN_FUNC_NAME_LENGTH: int = 3
# Dict similarity: anlamli isimlerin ingilizce kelime benzerligi
# Ornek kelimeler -- ufak internal sozluk. Tum dict yuklenmez, hizli kontrol.
COMMON_ENGLISH_ROOTS: frozenset[str] = frozenset({
    "init", "deinit", "start", "stop", "open", "close", "read", "write",
    "create", "destroy", "alloc", "free", "get", "set", "add", "remove",
    "delete", "insert", "update", "parse", "format", "encode", "decode",
    "encrypt", "decrypt", "hash", "compare", "copy", "move", "clone",
    "load", "save", "send", "recv", "receive", "connect", "disconnect",
    "listen", "accept", "bind", "socket", "file", "buffer", "data",
    "size", "length", "count", "index", "offset", "pointer", "value",
    "string", "number", "list", "array", "table", "map", "queue", "stack",
    "tree", "node", "graph", "user", "name", "path", "key", "lock",
    "mutex", "thread", "process", "signal", "event", "handler", "callback",
    "main", "exit", "error", "warn", "info", "debug", "log", "print",
    "check", "verify", "validate", "match", "search", "find", "sort",
    "filter", "merge", "split", "join", "push", "pop", "peek", "flush",
    "reset", "clear", "clean", "build", "make", "new", "old", "first",
    "last", "next", "prev", "head", "tail", "size", "end", "begin",
    "calc", "calculate", "compute", "process", "handle", "manage",
    "config", "option", "flag", "state", "status", "result", "response",
    "request", "packet", "message", "header", "body", "payload", "field",
})


# ---------------------------------------------------------------------------
# Boyut 3: Lokal degisken
# ---------------------------------------------------------------------------
# Lokal isim icin minimum anlami uzunluk
MIN_LOCAL_NAME_LENGTH: int = 2


# ---------------------------------------------------------------------------
# Boyut 5: Yorum
# ---------------------------------------------------------------------------
# comment_lines / function_count oranini "ideal" sayacagimiz deger.
# Formul: min(100, (ratio / COMMENT_IDEAL_RATIO) * 100)
# 2.0 = fonksiyon basina 2 satir yorum = %100 skor.
COMMENT_IDEAL_RATIO: float = 2.0


# ---------------------------------------------------------------------------
# Boyut 6: Kod yapisi
# ---------------------------------------------------------------------------
# Ortalama nesting derinligi cezasi (derinlik basina puan dusur)
NESTING_PENALTY_PER_LEVEL: float = 5.0
# Her goto icin ceza
GOTO_PENALTY: float = 10.0
# Fonksiyon basina satir sayisi esikleri
FUNC_LEN_SOFT_LIMIT: int = 50      # 50 satira kadar ceza yok
FUNC_LEN_HARD_LIMIT: int = 150     # 150 satir uzerinde tam ceza
FUNC_LEN_MAX_PENALTY: float = 40.0 # Maksimum fonksiyon-uzunluk cezasi


# ---------------------------------------------------------------------------
# Detay raporlama
# ---------------------------------------------------------------------------

@dataclass
class ScorerConfig:
    """Skorlayici konfigurasyon nesnesi.

    Test/kullanici kendi agirliklarini overlay edebilsin diye
    dataclass olarak expose ediyoruz.
    """

    weight_function_names: float = WEIGHT_FUNCTION_NAMES
    weight_param_names: float = WEIGHT_PARAM_NAMES
    weight_local_vars: float = WEIGHT_LOCAL_VARS
    weight_type_quality: float = WEIGHT_TYPE_QUALITY
    weight_comments: float = WEIGHT_COMMENTS
    weight_code_structure: float = WEIGHT_CODE_STRUCTURE

    min_func_name_length: int = MIN_FUNC_NAME_LENGTH
    min_local_name_length: int = MIN_LOCAL_NAME_LENGTH

    comment_ideal_ratio: float = COMMENT_IDEAL_RATIO

    nesting_penalty_per_level: float = NESTING_PENALTY_PER_LEVEL
    goto_penalty: float = GOTO_PENALTY
    func_len_soft_limit: int = FUNC_LEN_SOFT_LIMIT
    func_len_hard_limit: int = FUNC_LEN_HARD_LIMIT
    func_len_max_penalty: float = FUNC_LEN_MAX_PENALTY

    common_english_roots: frozenset[str] = field(
        default_factory=lambda: COMMON_ENGLISH_ROOTS,
    )

    def total_weight(self) -> float:
        """Agirliklarin toplami. 1.0 olmali (dogrulama)."""
        return (
            self.weight_function_names
            + self.weight_param_names
            + self.weight_local_vars
            + self.weight_type_quality
            + self.weight_comments
            + self.weight_code_structure
        )

    def validate(self) -> None:
        """Konfigurasyon tutarli mi? Hata varsa ValueError."""
        total = self.total_weight()
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Agirliklarin toplami 1.0 olmali, alinan: {total:.4f}"
            )
        if self.comment_ideal_ratio <= 0:
            raise ValueError("comment_ideal_ratio pozitif olmali")
        if self.func_len_hard_limit <= self.func_len_soft_limit:
            raise ValueError(
                "func_len_hard_limit > func_len_soft_limit olmali"
            )
