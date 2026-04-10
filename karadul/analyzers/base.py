"""
Analyzer temel sinifi — tum analyzer'larin implement edecegi interface.

Her TargetType icin bir analyzer yazilir ve @register_analyzer ile kaydedilir.
Analyzer, Pipeline stage'leri tarafindan cagirilir.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from karadul.config import Config
from karadul.core.result import StageResult
from karadul.core.target import TargetInfo, TargetType
from karadul.core.workspace import Workspace


class BaseAnalyzer(ABC):
    """Tum analyzer'larin implement edecegi interface.

    Alt siniflar en az ``analyze_static`` ve ``deobfuscate`` metodlarini
    implement etmelidir. ``analyze_dynamic`` ve ``reconstruct`` opsiyoneldir,
    varsayilan olarak None dondurur (stage atlanir).

    Attributes:
        supported_types: Bu analyzer'in destekledigi TargetType listesi.
        config: Merkezi konfigurasyon.
    """

    supported_types: list[TargetType]

    def __init__(self, config: Config) -> None:
        self.config = config

    @abstractmethod
    def analyze_static(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Stage 2: Statik analiz.

        Hedef dosyayi parse eder, fonksiyonlari/stringleri/import'lari cikarir.

        Args:
            target: Hedef bilgileri (path, tip, dil, boyut vb.).
            workspace: Calisma dizini yoneticisi (artifact kaydetme/yukleme).

        Returns:
            StageResult: Statik analiz sonucu (istatistikler, artifact'ler, hatalar).
        """
        ...

    @abstractmethod
    def deobfuscate(self, target: TargetInfo, workspace: Workspace) -> StageResult:
        """Stage 4: Deobfuscation.

        Obfuscated kodu cozumler, beautify eder, modullere ayirir.

        Args:
            target: Hedef bilgileri.
            workspace: Calisma dizini yoneticisi.

        Returns:
            StageResult: Deobfuscation sonucu.
        """
        ...

    def analyze_dynamic(self, target: TargetInfo, workspace: Workspace) -> StageResult | None:
        """Stage 3: Dinamik analiz (opsiyonel).

        Runtime'da hook/trace ile veri toplar. Alt siniflar override edebilir.
        Varsayilan olarak None dondurur (stage atlanir).

        Args:
            target: Hedef bilgileri.
            workspace: Calisma dizini yoneticisi.

        Returns:
            StageResult veya None (implement edilmediyse).
        """
        return None

    def reconstruct(self, target: TargetInfo, workspace: Workspace) -> StageResult | None:
        """Stage 5: Kod rekonstruksiyonu (opsiyonel).

        Deobfuscation sonucu uzerinde yapı yeniden olusturma.
        Alt siniflar override edebilir.

        Args:
            target: Hedef bilgileri.
            workspace: Calisma dizini yoneticisi.

        Returns:
            StageResult veya None (implement edilmediyse).
        """
        return None
