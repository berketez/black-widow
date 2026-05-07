"""Rust demangler test suite.

Smoke + edge + negative testler. Gercek Rust binary olmadan calismali --
mock semboller hardcoded olarak gomulu.

Test sembolleri rustc-demangle Rust crate'inin test verilerinden ve
RFC 2603 ornek setinden alinmistir.
"""

from __future__ import annotations

import pytest

from karadul.analyzers.rust_demangler import (
    demangle,
    demangle_batch,
    detect_format,
)


# ---------------------------------------------------------------------------
# Format tespiti (legacy / v0 / unknown)
# ---------------------------------------------------------------------------

class TestDetectFormat:
    """detect_format() bilesik testleri."""

    def test_legacy_basit(self) -> None:
        assert detect_format("_ZN3foo3barE") == "legacy"

    def test_legacy_hash_suffix(self) -> None:
        assert detect_format(
            "_ZN4core3fmt5write17h1234567890abcdefE",
        ) == "legacy"

    def test_legacy_double_underscore_macos(self) -> None:
        # macOS bazen __Z (cift underscore) kullanir
        assert detect_format("__ZN3std3fooE") == "legacy"

    def test_v0_basit(self) -> None:
        assert detect_format("_RNvCs1234_3foo3bar") == "v0"

    def test_v0_double_underscore(self) -> None:
        assert detect_format("__RNvCs1234_3foo3bar") == "v0"

    def test_unknown_normal_c_isim(self) -> None:
        assert detect_format("main") == "unknown"

    def test_unknown_python_dunder(self) -> None:
        assert detect_format("_print_hex") == "unknown"

    def test_unknown_swift(self) -> None:
        # Swift: $s prefix
        assert detect_format("$sSi") == "unknown"

    def test_unknown_bos_string(self) -> None:
        assert detect_format("") == "unknown"

    def test_unknown_none_tip(self) -> None:
        assert detect_format(None) == "unknown"  # type: ignore[arg-type]

    def test_unknown_kismi_z(self) -> None:
        # Sadece "_Z" ama N veya rakam yok -> ne legacy ne v0
        # (Cogu C++ legacy de _Z ile baslar; bu modul rust degil
        # diye reddetmez ama _R icin _R<harf|digit> kalibi gerekli)
        assert detect_format("_R") == "unknown"


# ---------------------------------------------------------------------------
# Legacy demangle smoke
# ---------------------------------------------------------------------------

class TestLegacyDemangle:
    """Legacy mangling demangle testleri."""

    def test_basit_iki_segment(self) -> None:
        # _ZN3foo3barE -> foo::bar
        assert demangle("_ZN3foo3barE") == "foo::bar"

    def test_uc_segment(self) -> None:
        assert demangle("_ZN4core3fmt5writeE") == "core::fmt::write"

    def test_hash_suffix_atlanmali(self) -> None:
        # 17h<hex16> son segment hash'tir, kaldirilmali
        result = demangle("_ZN4core3fmt5write17h1234567890abcdefE")
        assert result == "core::fmt::write"

    def test_hash_suffix_baska_ornek(self) -> None:
        result = demangle(
            "_ZN3std2io5Write9write_all17habcdef1234567890E",
        )
        assert result == "std::io::Write::write_all"

    def test_macos_double_underscore(self) -> None:
        # macOS sembolleri __ZN ile baslayabilir
        result = demangle("__ZN3foo3barE")
        assert result == "foo::bar"

    def test_uzun_crate_isim(self) -> None:
        # 6tokio + 7runtime + 5spawn + hash
        result = demangle(
            "_ZN5tokio7runtime5spawn17h0011223344556677E",
        )
        assert result == "tokio::runtime::spawn"


# ---------------------------------------------------------------------------
# V0 demangle smoke (pragmatic subset)
# ---------------------------------------------------------------------------

class TestV0Demangle:
    """Modern v0 (_R...) demangle testleri.

    Bu testler pragmatic subset'i dogrular -- tam RFC 2603 destegi
    YOK. Sadece:
    - C (crate root)
    - N (nested path)
    - Identifier (length-prefixed, optional disambiguator)
    """

    def test_basit_crate_root(self) -> None:
        # _RC3foo -> foo (crate root sembolu)
        assert demangle("_RC3foo") == "foo"

    def test_nested_iki_seviye(self) -> None:
        # _RNvC3foo3bar -> foo::bar
        # N = nested, v = value namespace, C3foo = crate "foo", 3bar = ident
        assert demangle("_RNvC3foo3bar") == "foo::bar"

    def test_disambiguator_atlanmali(self) -> None:
        # _RNvCs1234_3foo3bar
        # s1234_ disambiguator, sonuc gostermede atlanmali
        result = demangle("_RNvCs1234_3foo3bar")
        assert result == "foo::bar"

    def test_uc_seviye_nested(self) -> None:
        # std::io::write benzeri
        # _RNvNvC3std2io5write
        result = demangle("_RNvNvC3std2io5write")
        # Beklenen: std::io::write
        assert result == "std::io::write"

    def test_v0_heuristic_fallback(self) -> None:
        # Karmasik bir sembol -- parser hatasi versin, heuristic
        # length-prefixed cikarma yapsin. En azindan bir parca gormeliyiz.
        # (Bu sembol pragmatik subset disinda olabilir)
        result = demangle("_RINvNtCs1234_4core3fmt5writeINtNtCs5_4core6option6OptionjEE")
        assert result is not None
        # Heuristic en azindan "core" ve "write" gibi kelimeleri yakalamali
        assert "core" in result or "write" in result


# ---------------------------------------------------------------------------
# Negative -- mangle olmayan sembolleri es gec
# ---------------------------------------------------------------------------

class TestNegativeCases:
    """demangle() mangled olmayan icin None donmeli."""

    def test_python_isim(self) -> None:
        assert demangle("_print_hex") is None

    def test_c_main(self) -> None:
        assert demangle("main") is None

    def test_libc_fonksiyon(self) -> None:
        assert demangle("printf") is None

    def test_swift_sembol(self) -> None:
        # Swift sembolleri rust demangler tarafindan reddedilmeli
        assert demangle("$sSiSayyAA") is None

    def test_bos_string(self) -> None:
        assert demangle("") is None

    def test_none_input(self) -> None:
        assert demangle(None) is None  # type: ignore[arg-type]

    def test_objc_sembol(self) -> None:
        # ObjC: _OBJC_CLASS_$_NSString
        assert demangle("_OBJC_CLASS_$_NSString") is None

    def test_z_ama_legacy_degil(self) -> None:
        # _Z ile baslayan ama mangle formati uymayan -> None
        # (legacy parser N olmadan da deneyebilir; bu durum sinir vakasi)
        # _Zfoo -> N bekliyor, decimal yok -> None donmeli
        result = demangle("_Zfoo")
        # Permissive davranis: None donsun veya bos string donsun
        assert result is None or result == ""


# ---------------------------------------------------------------------------
# Hatali / yanlis-bicimli inputlar
# ---------------------------------------------------------------------------

class TestMalformedInputs:
    """Eksik veya bozuk mangled semboller crash etmemeli."""

    def test_eksik_kapanis_E(self) -> None:
        # _ZN3foo3bar (E yok) -> parser yine de cikarmali
        result = demangle("_ZN3foo3bar")
        assert result == "foo::bar"

    def test_uzunluk_buffer_disinda(self) -> None:
        # _ZN99foo -- 99 karakter ister, sadece 3 var -> None
        result = demangle("_ZN99foo")
        # Parser hata vermek yerine None donmeli
        assert result is None

    def test_negatif_uzunluk_yok(self) -> None:
        # Sayilar pozitif, _ZN0E -> bos parts -> None
        assert demangle("_ZN0E") is None

    def test_v0_parser_crash_etmemeli(self) -> None:
        # Tam bilinmeyen v0 sembol -- en kotu durumda None doner
        result = demangle("_R???INVALID???")
        assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# Batch API
# ---------------------------------------------------------------------------

class TestBatchAPI:
    """demangle_batch() toplu sembol islemi."""

    def test_bos_liste(self) -> None:
        assert demangle_batch([]) == {}

    def test_karisik_liste(self) -> None:
        symbols = [
            "_ZN3foo3barE",                            # legacy
            "_ZN4core3fmt5write17h1234567890abcdefE",  # legacy + hash
            "main",                                    # mangle degil
            "printf",                                  # mangle degil
            "_RNvC3foo3bar",                           # v0
        ]
        result = demangle_batch(symbols)

        # Mangle olanlar dict'te, olmayanlar yok
        assert "_ZN3foo3barE" in result
        assert result["_ZN3foo3barE"] == "foo::bar"

        assert "_ZN4core3fmt5write17h1234567890abcdefE" in result
        assert result[
            "_ZN4core3fmt5write17h1234567890abcdefE"
        ] == "core::fmt::write"

        assert "main" not in result
        assert "printf" not in result

        assert "_RNvC3foo3bar" in result
        assert result["_RNvC3foo3bar"] == "foo::bar"

    def test_buyuk_batch(self) -> None:
        # 100 sembol, hepsi gecerli legacy
        symbols = [f"_ZN3std3fmt{i}fooE" for i in range(10)]
        # (yukaridaki format yanlis, dogrusunu kuralim)
        symbols = []
        for i in range(50):
            ident = f"fn{i:04d}"
            symbols.append(f"_ZN3std3fmt{len(ident)}{ident}E")
        result = demangle_batch(symbols)
        assert len(result) == 50
        for sym in symbols:
            assert sym in result
            assert result[sym].startswith("std::fmt::fn")


# ---------------------------------------------------------------------------
# Idempotence ve property-bazli
# ---------------------------------------------------------------------------

class TestIdempotenceAndProperties:
    """Demangle edilmis bir sembol tekrar demangle edilirse None doner."""

    def test_demangled_tekrar_demangle_none(self) -> None:
        first = demangle("_ZN3foo3barE")
        assert first == "foo::bar"
        # "foo::bar" mangled degildir -> None
        assert demangle(first) is None

    def test_legacy_segment_sayisi_max_dogru(self) -> None:
        # 4 segmentli sembol cift kontrol
        result = demangle("_ZN4tide6router4Node3newE")
        assert result == "tide::router::Node::new"

    @pytest.mark.parametrize(
        "symbol,expected",
        [
            ("_ZN3foo3barE", "foo::bar"),
            ("_ZN3foo3bar3bazE", "foo::bar::baz"),
            ("__ZN3foo3barE", "foo::bar"),
        ],
    )
    def test_parametric_legacy(self, symbol: str, expected: str) -> None:
        assert demangle(symbol) == expected


# ---------------------------------------------------------------------------
# Smoke: gercek-dunya ornek semboller (rustc-demangle test verisinden esin)
# ---------------------------------------------------------------------------

class TestRealWorldSamples:
    """Gercek Rust binary'lerden alinan tipik semboller."""

    def test_panic_handler(self) -> None:
        # core::panicking::panic_fmt benzeri
        result = demangle(
            "_ZN4core9panicking9panic_fmt17h0123456789abcdefE",
        )
        assert result == "core::panicking::panic_fmt"

    def test_alloc_box_new(self) -> None:
        result = demangle(
            "_ZN5alloc5boxed12Box$LT$T$GT$3new17h1111222233334444E",
        )
        # Pragmatic: $LT$ ve $GT$ legacy escape'i (< ve >)
        # Bu modul escape'i decode ETMEZ -- ham metin gosterir.
        assert result is not None
        assert "alloc::boxed" in result

    def test_hash_kaldirma_pozitif(self) -> None:
        # h ile baslayan ama 16 hex karakter olmayan segment -> hash degil
        # _ZN3foo5hello5habcdEf  -> 5habcd: "habcd" 5 karakter, hash degil
        # (segmentler legacy formatinda hep length-prefixed gelir)
        # Burada son segment "habcd" -- 16 hex degil, korunmali
        result = demangle("_ZN3foo5hello5habcdE")
        assert result is not None
        # "habcd" segmenti hash gibi gorunmedigi icin korunur
        assert result == "foo::hello::habcd"

    def test_hash_kaldirma_negatif_kisa_h(self) -> None:
        # 17h<3-hex> -- 17 length 3 hex+h sigmaz, parser bos doner
        # Bu negatif sinir vakasi olarak parser None donmesi normaldir
        result = demangle("_ZN3foo5hello17hABCE")
        # Length 17 ama buffer'da yeterli yer yok -> None
        assert result is None
