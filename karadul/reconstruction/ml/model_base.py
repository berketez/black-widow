"""Base class for ML-based naming models."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class NamingPrediction:
    """A predicted name with confidence score."""
    name: str
    confidence: float
    source: str  # e.g., "varbert", "gennm", "symgen"
    original_name: str = ""  # The FUN_xxx or var_N being renamed


class MLNamingModel(ABC):
    """Abstract base class for ML naming models.

    All ML-based naming models (VarBERT, GenNm, SymGen, etc.) inherit
    from this class. It handles device selection (MPS > CUDA > CPU)
    and defines the interface for name prediction.
    """

    def __init__(self, model_name: str, device: Optional[str] = None):
        import torch  # lazy import: torch kurulu degilse proje patlamasin

        self.model_name = model_name
        if device is None:
            if torch.backends.mps.is_available():
                self.device = torch.device("mps")
            elif torch.cuda.is_available():
                self.device = torch.device("cuda")
            else:
                self.device = torch.device("cpu")
        else:
            self.device = torch.device(device)
        self._loaded = False

    @abstractmethod
    def load(self) -> None:
        """Load the model weights."""
        pass

    @abstractmethod
    def predict_names(self, decompiled_code: str, function_name: str = "") -> list[NamingPrediction]:
        """Predict meaningful names for variables/functions in decompiled code.

        Args:
            decompiled_code: Ghidra decompile output or similar
            function_name: Current function name (e.g., FUN_00401000)

        Returns:
            List of NamingPrediction for each identifier
        """
        pass

    @abstractmethod
    def predict_function_name(self, decompiled_code: str) -> NamingPrediction:
        """Predict a meaningful name for the function itself.

        Args:
            decompiled_code: Full decompiled function code

        Returns:
            Single NamingPrediction for the function name
        """
        pass

    def is_loaded(self) -> bool:
        return self._loaded

    def get_device(self) -> str:
        return str(self.device)
