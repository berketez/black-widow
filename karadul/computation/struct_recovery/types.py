"""Struct layout MaxSMT kurtarma — veri tipleri.

Bu modul, Z3-MaxSMT cozucusunun girdi/cikti veri yapilarini tanimlar.
Tum dataclass'lar frozen=False (encoder/solver'in decode asamasinda
alanlari doldurabilmesi icin). Ancak `merge` benzeri saf fonksiyonlar
girdileri mutate ETMEZ — kopya uzerinde calisir.

Ayrinti:
    - ``MemoryAccess``: tek bir bellek erisimi (offset/width/var).
    - ``StructField``: aday struct'in tek bir alani.
    - ``StructCandidate``: synthesizer tarafindan uretilen aday layout.
    - ``AliasClass``: ``same_object`` kumesi + ``same_type`` kimligi.
      KRITIK: same_object (SSA must-alias) ile same_type (struct ailesi)
      iki ayri iliskidir. Tek same() YETMEZ.
    - ``RecoveredStructLayout``: solver sonucu (class -> struct atamasi,
      acilmamis erisimler, guven, solver zamani).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MemoryAccess:
    """Tek bir okuma/yazma erisimi.

    Attributes:
        var_name: Erisimi yapan degiskenin ismi (SSA sonrasi).
        offset: Struct basindan bayt cinsinden ofset.
        width: Erisim genisligi (1/2/4/8 bayt).
        access_type: "read" veya "write".
    """
    var_name: str
    offset: int
    width: int
    access_type: str = "read"

    def __post_init__(self) -> None:
        if self.width not in (1, 2, 4, 8):
            raise ValueError(f"width 1/2/4/8 olmali, {self.width} geldi")
        if self.offset < 0:
            raise ValueError(f"offset negatif olamaz: {self.offset}")
        if self.access_type not in ("read", "write"):
            raise ValueError(f"access_type 'read'|'write' olmali: {self.access_type}")


@dataclass
class StructField:
    """Aday struct icindeki tek bir alan.

    Attributes:
        offset: Struct basindan bayt cinsinden ofset.
        size: Alan boyutu (bayt).
        type_hint: Opsiyonel tip ipucu ("int32", "ptr", "double" vb.).
    """
    offset: int
    size: int
    type_hint: Optional[str] = None

    def __post_init__(self) -> None:
        if self.offset < 0 or self.size <= 0:
            raise ValueError(
                f"gecersiz alan: offset={self.offset}, size={self.size}",
            )

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass
class StructCandidate:
    """Aday struct layout.

    Attributes:
        name: Aday icin okunabilir isim ("cand_0", "STAT_24B" vb.).
        size: Toplam struct boyutu (bayt).
        fields: Offset-sorted alan listesi.
    """
    name: str
    size: int
    fields: list[StructField] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.size <= 0:
            raise ValueError(f"size > 0 olmali: {self.size}")
        # Offset-sorted sakla (solver icin gerekli).
        self.fields = sorted(self.fields, key=lambda f: f.offset)
        # Alanlar struct icinde mi kontrolu.
        for fld in self.fields:
            if fld.end > self.size:
                raise ValueError(
                    f"alan struct disina tasiyor: "
                    f"field@{fld.offset}+{fld.size} > size={self.size}",
                )


@dataclass
class AliasClass:
    """Ayni objeyi isaret eden degiskenler kumesi + tip ailesi kimligi.

    KRITIK ayirim:
        - ``variables``: gerclekten ayni instance (same_object).
          SSA copy/phi/must-alias analizinden gelir.
        - ``type_family``: ayni struct tipi (same_type).
          Cok daha genis — ayni type_family'deki iki class ayni tipte
          olabilir ama farkli instance'lar.

    Solver tek bir aday struct'i type_family'nin TUMU icin secer,
    ama same_object iliskisi class icindeki erisimleri birlestirir.
    """
    variables: list[str]
    type_family: str

    def __post_init__(self) -> None:
        if not self.variables:
            raise ValueError("AliasClass bos olamaz")
        if not self.type_family:
            raise ValueError("type_family bos olamaz")


@dataclass
class RecoveredStructLayout:
    """MaxSMT solver sonucu.

    Attributes:
        classes: Girdi alias-class listesi (degistirilmez, referans).
        assigned_structs: type_family -> secilen StructCandidate haritasi.
        unknown_accesses: Hicbir adayla uyusmayan erisimler.
        confidence: Acilanan erisim orani [0.0, 1.0].
        solver_time_seconds: Z3 cozum suresi (saniye).
    """
    classes: list[AliasClass]
    assigned_structs: dict[str, StructCandidate]
    unknown_accesses: list[MemoryAccess]
    confidence: float
    solver_time_seconds: float

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence [0,1] disinda: {self.confidence}")
        if self.solver_time_seconds < 0:
            raise ValueError(
                f"solver_time_seconds negatif: {self.solver_time_seconds}",
            )
