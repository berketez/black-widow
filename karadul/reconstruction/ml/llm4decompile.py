"""LLM4Decompile 6.7B v1.5 -- Binary decompilation iyilestirme modeli.

Ghidra'nin urettigi ham decompile ciktisini alip daha okunabilir,
anlamli C koduna donusturur. Degisken ve fonksiyon isimlerini
kodun baglamina gore iyilestirir.

Model: LLM4Binary/llm4decompile-6.7b-v1.5
Base: deepseek-coder-6.7b (LlamaForCausalLM)
Boyut: ~13GB (bfloat16), 6.7B parametre
Context: 8192 token (rope scaling ile 32K'ya kadar)

Kullanim:
    model = LLM4DecompileModel()
    model.load()
    result = model.refine_decompiled_code(ghidra_output)
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from karadul.reconstruction.ml.model_base import MLNamingModel, NamingPrediction

logger = logging.getLogger(__name__)

# Model default konumu
DEFAULT_MODEL_PATH = Path.home() / ".cache" / "karadul" / "models" / "llm4decompile-6.7b-v1.5"

# Singleton: Model bir kez yuklenir, tum pipeline boyunca bellekte kalir
_SINGLETON_INSTANCE: Optional["LLM4DecompileModel"] = None


def get_model(
    model_path: Optional[Path] = None,
    device: Optional[str] = None,
    **kwargs,
) -> "LLM4DecompileModel":
    """Singleton model instance dondur. Tek yukleme, tum pipeline kullanir."""
    global _SINGLETON_INSTANCE
    if _SINGLETON_INSTANCE is None:
        _SINGLETON_INSTANCE = LLM4DecompileModel(
            model_path=model_path,
            device=device,
            **kwargs,
        )
    if not _SINGLETON_INSTANCE.is_loaded():
        _SINGLETON_INSTANCE.load()
    return _SINGLETON_INSTANCE

# Ghidra otomatik isim pattern'leri
_GHIDRA_AUTO_NAMES = re.compile(
    r"\b(FUN_[0-9a-fA-F]+|param_\d+|local_[0-9a-fA-F]+|"
    r"DAT_[0-9a-fA-F]+|PTR_[0-9a-fA-F]+|[a-z]Var\d+)\b"
)

# C identifier pattern
_C_IDENTIFIER = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b")


@dataclass
class DecompileResult:
    """LLM4Decompile ciktisi."""
    original_code: str
    refined_code: str
    name_mappings: dict[str, str] = field(default_factory=dict)  # old -> new
    confidence: float = 0.0
    generation_time_ms: float = 0.0
    tokens_generated: int = 0


class LLM4DecompileModel(MLNamingModel):
    """LLM4Decompile 6.7B v1.5 model wrapper.

    Ghidra decompile ciktisini alip iyilestirilmis C kodu uretir.
    Uretilen koddaki degisken/fonksiyon isimlerini eslestirerek
    naming pipeline'a entegre olur.
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        device: Optional[str] = None,
        max_new_tokens: int = 512,
        temperature: float = 0.0,
        dtype: str = "auto",
    ):
        super().__init__("llm4decompile-6.7b-v1.5", device)
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.max_new_tokens = max_new_tokens
        self.temperature = temperature
        self.dtype_str = dtype
        # transformers tiplemesi mevcut ortamda eksik olabilir -> Any.
        self._tokenizer: Any = None
        self._model: Any = None

    def load(self) -> None:
        """Model agirliklarini yukle."""
        if self._loaded:
            return

        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"LLM4Decompile model bulunamadi: {self.model_path}\n"
                f"Indirmek icin: huggingface-cli download LLM4Binary/llm4decompile-6.7b-v1.5 "
                f"--local-dir {self.model_path}"
            )

        logger.info("LLM4Decompile 6.7B yukleniyor: %s", self.model_path)
        start = time.time()

        # Tokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(
            str(self.model_path),
            local_files_only=True,
        )

        # Dtype secimi
        if self.dtype_str == "auto":
            # MPS bfloat16 desteklemiyor, float16 kullan
            if self.device.type == "mps":
                dtype = torch.float16
            elif self.device.type == "cuda":
                dtype = torch.bfloat16
            else:
                dtype = torch.float32
        elif self.dtype_str == "float16":
            dtype = torch.float16
        elif self.dtype_str == "bfloat16":
            dtype = torch.bfloat16
        else:
            dtype = torch.float32

        # Model (transformers API dinamik tip -> Any'e sakla).
        _loaded_model: Any = AutoModelForCausalLM.from_pretrained(
            str(self.model_path),
            torch_dtype=dtype,
            local_files_only=True,
            low_cpu_mem_usage=True,
        )
        self._model = _loaded_model

        # Device'a tasi (MPS icin parcali tasima gerekebilir)
        try:
            self._model = self._model.to(self.device)
        except Exception as e:
            logger.warning(
                "Model %s device'a tasinamadi, CPU'da calisacak: %s",
                self.device, e,
            )
            import torch
            self.device = torch.device("cpu")
            self._model = self._model.to(self.device)

        self._model.eval()
        self._loaded = True

        elapsed = time.time() - start
        logger.info(
            "LLM4Decompile yuklendi: device=%s, dtype=%s, sure=%.1fs",
            self.device, dtype, elapsed,
        )

    def refine_decompiled_code(
        self,
        decompiled_code: str,
        optimization_level: str = "O2",
    ) -> DecompileResult:
        """Ghidra decompile ciktisini iyilestir.

        Args:
            decompiled_code: Ghidra'nin urettigi C kodu (tek fonksiyon).
            optimization_level: Derleme optimizasyon seviyesi (O0, O1, O2, O3).

        Returns:
            DecompileResult: Iyilestirilmis kod ve isim eslestirmeleri.
        """
        import torch

        if not self._loaded:
            self.load()

        # Kodu token limitine gore kirp (model 8K context)
        max_input_tokens = 4096  # Yarisi input, yarisi output icin
        truncated = self._truncate_code(decompiled_code, max_input_tokens)

        # LLM4Decompile prompt formati
        prompt = (
            f"# This is the decompiled code with {optimization_level} optimization:\n"
            f"{truncated}\n"
            f"# What is the source code?\n"
        )

        start = time.time()

        inputs = self._tokenizer(prompt, return_tensors="pt").to(self.device)
        input_length = inputs["input_ids"].shape[1]

        with torch.no_grad():
            outputs = self._model.generate(
                **inputs,
                max_new_tokens=self.max_new_tokens,
                do_sample=self.temperature > 0,
                temperature=max(self.temperature, 1e-7),
                pad_token_id=self._tokenizer.eos_token_id,
            )

        # Sadece yeni uretilen token'lari decode et
        generated_ids = outputs[0][input_length:]
        refined_code = self._tokenizer.decode(
            generated_ids,
            skip_special_tokens=True,
            clean_up_tokenization_spaces=True,
        )

        elapsed_ms = (time.time() - start) * 1000
        tokens_generated = len(generated_ids)

        # Orijinal ve iyilestirilmis koddaki isimleri karsilastir
        name_mappings = self._extract_name_mappings(decompiled_code, refined_code)

        # Confidence: uretilen kodun kalitesine gore
        confidence = self._estimate_confidence(
            decompiled_code, refined_code, name_mappings,
        )

        return DecompileResult(
            original_code=decompiled_code,
            refined_code=refined_code,
            name_mappings=name_mappings,
            confidence=confidence,
            generation_time_ms=elapsed_ms,
            tokens_generated=tokens_generated,
        )

    def predict_names(
        self,
        decompiled_code: str,
        function_name: str = "",
    ) -> list[NamingPrediction]:
        """Decompile ciktisindaki degiskenler icin anlamli isim oner.

        c_namer.py entegrasyonu icin kullanilir.
        """
        result = self.refine_decompiled_code(decompiled_code)

        predictions = []
        for old_name, new_name in result.name_mappings.items():
            if old_name == new_name:
                continue
            predictions.append(NamingPrediction(
                name=new_name,
                confidence=result.confidence,
                source="llm4decompile",
                original_name=old_name,
            ))

        return predictions

    def predict_function_name(self, decompiled_code: str) -> NamingPrediction:
        """Fonksiyon ismi tahmini.

        LLM4Decompile fonksiyon ismi yerine tum kodu iyilestirdigi icin,
        uretilen koddaki fonksiyon imzasindan isim cikarir.
        """
        result = self.refine_decompiled_code(decompiled_code)

        # Uretilen kodda fonksiyon tanimini bul
        func_match = re.search(
            r"(?:void|int|char|float|double|long|unsigned|struct\s+\w+|"
            r"[a-zA-Z_]\w*(?:\s*\*)?\s+)"
            r"([a-zA-Z_]\w*)\s*\(",
            result.refined_code,
        )

        if func_match:
            func_name = func_match.group(1)
            # main, entry gibi generic isimler dusuk confidence
            if func_name in ("main", "entry", "start", "func", "function"):
                confidence = 0.3
            else:
                confidence = result.confidence
            return NamingPrediction(
                name=func_name,
                confidence=confidence,
                source="llm4decompile",
            )

        return NamingPrediction(
            name="",
            confidence=0.0,
            source="llm4decompile",
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _truncate_code(self, code: str, max_tokens: int) -> str:
        """Kodu token limitine gore kirp."""
        if self._tokenizer is None:
            # Tokenizer henuz yuklenmediyse karakter bazli kirp
            return code[:max_tokens * 4]  # ~4 char/token ortalama

        tokens = self._tokenizer.encode(code, add_special_tokens=False)
        if len(tokens) <= max_tokens:
            return code
        truncated_tokens = tokens[:max_tokens]
        return self._tokenizer.decode(truncated_tokens, skip_special_tokens=True)

    def _extract_name_mappings(
        self,
        original: str,
        refined: str,
    ) -> dict[str, str]:
        """Orijinal ve iyilestirilmis kod arasindaki isim farkliklarini bul.

        Strateji (set-based diff — satir hizalama KULLANMAZ):
        1. Orijinaldeki tum Ghidra auto isimlerini cikar (FUN_xxx, param_N, local_XX)
        2. Refined koddaki tum identifier'lari cikar
        3. Orijinalde olan ama refined'da olmayan Ghidra isimleri = degistirilmis
        4. Refined'da yeni olan ve Ghidra auto ismi olmayan = yeni isimler
        5. Kaybolma sikligi ile yeni isim sikligi eslestirilir (coktan aza)

        NOT: LLM ciktisi orijinalle ayni satir sayisinda olmaz,
        bu yuzden satir-bazli hizalama guvenilir DEGIL.
        """
        mappings: dict[str, str] = {}

        # Orijinaldeki tum Ghidra otomatik isimleri
        ghidra_names = set(_GHIDRA_AUTO_NAMES.findall(original))
        if not ghidra_names:
            return mappings

        # Refined koddaki tum identifier'lar
        refined_all_idents = set(_C_IDENTIFIER.findall(refined))
        refined_non_keyword = {
            m for m in refined_all_idents
            if not _is_c_keyword(m) and not _GHIDRA_AUTO_NAMES.match(m)
        }

        # Orijinal koddaki tum non-keyword non-ghidra identifier'lar
        original_all_idents = set(_C_IDENTIFIER.findall(original))
        original_non_ghidra = {
            m for m in original_all_idents
            if not _is_c_keyword(m) and not _GHIDRA_AUTO_NAMES.match(m)
        }

        # Kaybolan Ghidra isimleri: orijinalde var, refined'da yok
        disappeared_ghidra = sorted(
            [g for g in ghidra_names if g not in refined_all_idents],
        )

        # Yeni isimler: refined'da var ama orijinalde yoktu (ne keyword ne ghidra)
        new_names = sorted(
            [n for n in refined_non_keyword
             if n not in original_all_idents and len(n) > 1],
        )

        # Frekansi yuksek kaybolan Ghidra isimlerini frekansi yuksek yeni isimlerle esle
        # Ek bilgi: orijinaldeki kullanim sayisi ile refined'daki kullanim sayisi
        from collections import Counter
        orig_ghidra_counts = Counter(_GHIDRA_AUTO_NAMES.findall(original))
        refined_new_counts = Counter(
            m for m in _C_IDENTIFIER.findall(refined)
            if m in set(new_names)
        )

        # En cok kullanilan kaybolan Ghidra isimlerini en cok kullanilan yeni isimlerle esle
        disappeared_sorted = sorted(
            disappeared_ghidra,
            key=lambda g: orig_ghidra_counts.get(g, 0),
            reverse=True,
        )
        new_sorted = sorted(
            new_names,
            key=lambda n: refined_new_counts.get(n, 0),
            reverse=True,
        )

        # 1:1 eslestir (sira bazli — en siktan en aza)
        for ghidra_name, new_name in zip(disappeared_sorted, new_sorted):
            mappings[ghidra_name] = new_name

        return mappings

    def _estimate_confidence(
        self,
        original: str,
        refined: str,
        mappings: dict[str, str],
    ) -> float:
        """Iyilestirme kalitesini tahmin et.

        Yuksek confidence = model anlamli degisiklikler yapmis.
        Dusuk confidence = model fazla degistirmemis veya anlamsiz cikti.
        """
        if not refined or not refined.strip():
            return 0.0

        # 1. Refined kod gecerli C gibi gorunuyor mu?
        has_braces = "{" in refined and "}" in refined
        has_semicolons = ";" in refined
        if not has_braces or not has_semicolons:
            return 0.1

        # 2. Kac Ghidra ismi degistirilmis?
        ghidra_count = len(set(_GHIDRA_AUTO_NAMES.findall(original)))
        if ghidra_count == 0:
            return 0.5  # Zaten temiz kod

        mapping_ratio = len(mappings) / max(ghidra_count, 1)

        # 3. Refined'da kalan Ghidra isimleri
        remaining_ghidra = len(set(_GHIDRA_AUTO_NAMES.findall(refined)))
        remaining_ratio = 1.0 - (remaining_ghidra / max(ghidra_count, 1))

        # 4. Uzunluk orani (cok kisa veya cok uzun = suphe)
        len_ratio = len(refined) / max(len(original), 1)
        length_penalty = 1.0
        if len_ratio < 0.3 or len_ratio > 3.0:
            length_penalty = 0.5

        # Agirlikli skor
        confidence = (
            0.3 * min(mapping_ratio, 1.0) +
            0.4 * remaining_ratio +
            0.3 * length_penalty
        )

        return round(max(0.1, min(0.9, confidence)), 2)

    def batch_refine(
        self,
        functions: list[dict[str, str]],
        optimization_level: str = "O2",
    ) -> list[DecompileResult]:
        """Birden fazla fonksiyonu sirali olarak iyilestir.

        Args:
            functions: [{"name": "FUN_xxx", "code": "..."}]
            optimization_level: Derleme seviyesi.

        Returns:
            Her fonksiyon icin DecompileResult.
        """
        results = []
        total = len(functions)

        for i, func in enumerate(functions):
            try:
                result = self.refine_decompiled_code(
                    func["code"],
                    optimization_level,
                )
                results.append(result)
                if (i + 1) % 10 == 0:
                    logger.info(
                        "LLM4Decompile: %d/%d fonksiyon islendi (%.1f%%)",
                        i + 1, total, (i + 1) / total * 100,
                    )
            except Exception as e:
                logger.warning("LLM4Decompile hata (func %s): %s", func.get("name", "?"), e)
                results.append(DecompileResult(
                    original_code=func["code"],
                    refined_code="",
                    confidence=0.0,
                ))

        return results


# ---------------------------------------------------------------------------
# Yardimci fonksiyonlar
# ---------------------------------------------------------------------------

_C_KEYWORDS = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if",
    "inline", "int", "long", "register", "restrict", "return", "short",
    "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
    "unsigned", "void", "volatile", "while", "_Bool", "_Complex", "_Imaginary",
    "bool", "true", "false", "NULL", "nullptr",
    # Common types
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "size_t", "ssize_t", "ptrdiff_t", "uintptr_t",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",  # Ghidra types
    "byte", "word", "dword", "qword", "longlong",  # Ghidra primitives
})


def _is_c_keyword(name: str) -> bool:
    """C keyword veya yaygın tip mi kontrol et."""
    return name in _C_KEYWORDS
