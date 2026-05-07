"""Demangler registry -- ortak demangler arabirimi ve dispatcher.

Bu modul karadul'daki cesitli dil-spesifik demangler'lari (rust, go, ...)
ortak bir Protocol arkasinda toplar ve gelen sembolu hangi demangler'a
yonlendirecegine ilk eslesen ``detect()`` cevabina gore karar verir.

Tasarim Felsefesi
-----------------

- **LLM yok**: tum demangler'lar deterministik (regex + parser).
- **Tek giris noktasi**: cagiran kod hangi dilden oldugunu bilmez,
  ``DemanglerRegistry.demangle(symbol)`` ile genel API alir.
- **Sira oncelikli**: register sirasina gore kontrol edilir; ilk
  ``detect()`` -> True donen demangler kullanilir.
- **Genisletilebilir**: yeni dil (Swift, C++ Itanium, .NET vb.) eklenmek
  istenirse Protocol'u uygulayan bir adapter yazip ``register()`` etmek
  yeterli.

Kullanim
--------

>>> from karadul.analyzers.demangler_registry import get_default_registry
>>> reg = get_default_registry()
>>> reg.demangle("_ZN4core3fmt5writeE")
'core::fmt::write'
>>> reg.demangle_with_format("_ZN4core3fmt5writeE")
('rust', 'core::fmt::write')
>>> reg.list_formats()
['rust', 'go']

Paralel ajan notu (2026-05-07): pipeline/stages.py ve sigdb yapilari
paralel ajanlar tarafindan editleniyor; bu modul onlardan bagimsizdir.
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from karadul.analyzers import go_demangler, rust_demangler

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Demangler(Protocol):
    """Ortak demangler arabirimi.

    Protocol oldugu icin kalitim olmadan da uyulabilir; ancak
    ``runtime_checkable`` ile ``isinstance(x, Demangler)`` mumkundur.

    Methodlar:

    - ``detect(symbol)``     : Bu demangler sembolu tanir mi?
    - ``demangle(symbol)``   : Demangle edilmis ismi dondur (yoksa None).
    - ``format_name()``      : "rust", "go", "swift" gibi format etiketi.
    """

    def detect(self, symbol: str) -> bool: ...

    def demangle(self, symbol: str) -> str | None: ...

    def format_name(self) -> str: ...


# ---------------------------------------------------------------------------
# Adapter'lar -- mevcut modulleri Protocol'a sar
# ---------------------------------------------------------------------------


class RustDemanglerAdapter:
    """``rust_demangler`` modulunu Protocol arabirimine uyarlar."""

    def detect(self, symbol: str) -> bool:
        if not symbol or not isinstance(symbol, str):
            return False
        return rust_demangler.detect_format(symbol) != "unknown"

    def demangle(self, symbol: str) -> str | None:
        if not symbol or not isinstance(symbol, str):
            return None
        return rust_demangler.demangle(symbol)

    def format_name(self) -> str:
        return "rust"


class GoDemanglerAdapter:
    """``go_demangler`` modulunu Protocol arabirimine uyarlar."""

    def detect(self, symbol: str) -> bool:
        if not symbol or not isinstance(symbol, str):
            return False
        return go_demangler.is_go_symbol(symbol)

    def demangle(self, symbol: str) -> str | None:
        if not symbol or not isinstance(symbol, str):
            return None
        return go_demangler.demangle(symbol)

    def format_name(self) -> str:
        return "go"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class DemanglerRegistry:
    """Demangler dispatcher.

    Kayitli demangler'lar listesini ``detect()`` ile sirayla denersin;
    ilk True donen ``demangle()`` cagrilir.

    Thread-safety: Tek bir registry'i farkli thread'lerden yalniz
    okumak icin kullanmak guvenli (mutate edilmiyorsa). ``register()``
    isleminin atomik olmasi gerekiyorsa cagiran taraf kilit yonetmeli;
    pratikte registry test/baslangic disinda mutate edilmez.
    """

    def __init__(self) -> None:
        self._demanglers: list[Demangler] = []

    def register(self, demangler: Demangler) -> None:
        """Yeni bir demangler kaydet.

        Args:
            demangler: Protocol'u uygulayan herhangi bir nesne.

        Yinelenen ``format_name()`` durumunda yeni gelen ESKISININ
        UZERINE eklenir (sira sonuna), ama eski silinmez. Bu davranis
        bilincli: cagiran taraf ozellestirilmis bir adapter'i ekler ve
        ilk eslesme sirayla onun varyantina dusene kadar denenir.
        """
        if demangler is None:
            raise ValueError("demangler None olamaz")
        # Hafif dogrulama: gerekli metodlar mevcut mu?
        for attr in ("detect", "demangle", "format_name"):
            if not callable(getattr(demangler, attr, None)):
                raise TypeError(
                    f"demangler '{attr}' metodu eksik veya cagirilamaz",
                )
        self._demanglers.append(demangler)
        logger.debug(
            "demangler kaydedildi: format=%s (toplam=%d)",
            demangler.format_name(),
            len(self._demanglers),
        )

    def demangle(self, symbol: str) -> str | None:
        """Sembolu demangle etmeye calis.

        Returns:
            Ilk eslesen demangler'in dondurdugu string. Hicbir
            demangler tanimazsa veya tum eslesenler None donerse
            None doner.
        """
        result = self.demangle_with_format(symbol)
        if result is None:
            return None
        return result[1]

    def demangle_with_format(
        self, symbol: str,
    ) -> tuple[str, str] | None:
        """Sembolu demangle et ve hangi format oldugunu da dondur.

        Returns:
            ``(format_name, demangled)`` tuple'i. Eslesme yoksa None.

        Birden fazla demangler ``detect()`` -> True donerse SADECE ilk
        eslesen denenir. Eger o demangler ``demangle()`` -> None donerse
        SONRAKI demangler denenir (dispatcher fallback davranisi).
        Bu, "Rust mangled gibi gozuken ama Rust olmayan" semboller icin
        gevsek heuristic'lerin diger demangler'lara firsat vermesini
        saglar.
        """
        if not symbol or not isinstance(symbol, str):
            return None

        for dem in self._demanglers:
            try:
                if not dem.detect(symbol):
                    continue
            except Exception as exc:  # noqa: BLE001
                # Detect kullanici-tanimli olabilir; coken bir detect
                # registry'i bozmamali.
                logger.debug(
                    "demangler.detect hatasi (%s): %s",
                    dem.format_name(),
                    exc,
                )
                continue

            try:
                out = dem.demangle(symbol)
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "demangler.demangle hatasi (%s): %s",
                    dem.format_name(),
                    exc,
                )
                continue

            if out is not None:
                # Idempotent durum (out == symbol) da "tanidim" sayilir;
                # Go top-level ``pkg.Func`` gibi semboller demangle sonrasi
                # ayni metni dondurebilir ama bu eslesmedi anlamina gelmez.
                return (dem.format_name(), out)
            # None ise sonraki demangler'a dus (fallback)

        return None

    def list_formats(self) -> list[str]:
        """Kayitli demangler'larin format isimlerini sirayla dondur."""
        return [d.format_name() for d in self._demanglers]

    def __len__(self) -> int:
        return len(self._demanglers)

    def __repr__(self) -> str:
        return f"DemanglerRegistry(formats={self.list_formats()})"


# ---------------------------------------------------------------------------
# Default registry (singleton)
# ---------------------------------------------------------------------------


_DEFAULT_REGISTRY: DemanglerRegistry | None = None


def get_default_registry() -> DemanglerRegistry:
    """Varsayilan registry'i dondur (lazy singleton).

    Ilk cagrida ``RustDemanglerAdapter`` ve ``GoDemanglerAdapter``
    sirayla kayit edilir. Sonraki cagrilarda ayni instance dondurulur.

    Sira: rust ONCE -> go SONRA. Sebep: Rust mangled prefix'leri
    (``_Z`` / ``_R``) kesin sinyaldir; Go heuristic'i daha gevsektir
    ve "_Z" ile baslayan bir sembolu (yanlislikla) Go gibi
    yorumlamamasi icin ``go_demangler.is_go_symbol`` zaten ``_Z``/``_R``
    prefix'lerini Go-disi sayar -- yine de sira ile garantiye alinir.
    """
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        reg = DemanglerRegistry()
        reg.register(RustDemanglerAdapter())
        reg.register(GoDemanglerAdapter())
        _DEFAULT_REGISTRY = reg
    return _DEFAULT_REGISTRY


def _reset_default_registry_for_tests() -> None:
    """Sadece test amacli: default registry'i sifirla.

    Production kodu BU FONKSIYONU CAGIRMASIN. Sadece ``conftest.py`` veya
    test fixture'lari registry state'ini izole etmek icin kullanir.
    """
    global _DEFAULT_REGISTRY
    _DEFAULT_REGISTRY = None


__all__ = [
    "Demangler",
    "DemanglerRegistry",
    "RustDemanglerAdapter",
    "GoDemanglerAdapter",
    "get_default_registry",
]
