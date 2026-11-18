"""P01b kalem 4: ikili istihbarat başarımı — gerekli dizgi ön süzgeci sonucu DEĞİŞTİRMEZ.

P01'den sonra her kural her kanıt öğesinde ayrı ``combined.search`` koşuyordu (bluetoothd:
42 477 öğe × 219 kural, 56 sn). Onarım: her göstergenin her eşleşmesinde küçük harfle bulunması
gereken düz dizgi (``_required_literal``) çıkarılır; birleşik küçük harfli metinde tek C taramasıyla
aday öğeler bulunur (``_ItemIndex``), ``combined`` yalnız adaylarda aranır. Gerekli koşul olduğu
için sonuç bayt bayt aynı olmalı: bu dosya bunu bütün kurallarda, zor girdilerle sınar.
"""

from __future__ import annotations

import pytest

from karadul.analyzers import binary_intelligence as bim
from karadul.analyzers.binary_intelligence import (
    ALGORITHM_PATTERNS,
    PROTOCOL_PATTERNS,
    SECURITY_PATTERNS,
    STRING_PATTERNS,
    BinaryIntelligence,
    _ItemIndex,
    _collect_items,
    _match_rule,
    _required_literal,
    _split_alternatives,
)
from karadul.config import Config

TUM_KURALLAR = (
    [("str", n, r) for n, r in bim._STRING_RULES.items()]
    + [("alg", n, r) for n, r in bim._ALGO_RULES.items()]
    + [("sec", n, r) for n, r in bim._SECURITY_RULES.items()]
    + [("pro", n, r) for n, r in bim._PROTOCOL_RULES.items()]
)


def _tum_alternatifler() -> list[str]:
    out = []
    for src in (ALGORITHM_PATTERNS, SECURITY_PATTERNS, PROTOCOL_PATTERNS):
        for d in src.values():
            out.extend(_split_alternatives(d["pattern"]))
    for d in STRING_PATTERNS.values():
        for p in d["patterns"]:
            out.extend(_split_alternatives(p))
    return out


def _zor_derlem() -> list[str]:
    """Her göstergenin gerekli dizgisini farklı harf ve bağlamlarla içeren + tuzaklı dizgiler."""
    derlem = [
        "aes128-wrap", "AES-256-CBC", "EVP_aes_128_cbc", "aes192", "_glBindTexture", "glFlush",
        "vkCreateInstance", "dgemm_", "sgesv_", "S4R", "B31", "BLEScanner", "CBCentralManager",
        "crypto-miner", "cryptominer", "HTTPS", "https://example.com/x", "QUIC", "quicklist",
        "sha256sum", "SHA256_Init", "sha256", "_ptrace", "debugger detected", "PT_DENY_ATTACH",
        "AmIBeingDebugged", "being debugged", "IsDebuggerPresent", "__stack_chk_fail", "iv", "xz",
        "V8", "s3", "x86_64", "", "a", "_", "git2", "libgit2.so.1", "git_repository_open",
        # ASCII olmayan: Unicode harf katlaması (Kelvin K, uzun s, noktalı İ) ön süzgeci atlar
        "Kerberos", "ſha256", "İpc", "Bluetoothé", "�HTTPS�",
        # öğe içinde satır sonu
        "line1\nopenssl", "SSL_\nCTX",
    ]
    for alt in _tum_alternatifler():
        lit = _required_literal(alt)
        if lit:
            derlem += [lit, lit.upper(), lit.capitalize(), "x" + lit + "y", "_" + lit + "_",
                       lit + "2", "pre " + lit + " post"]
    return derlem


DERLEM = _zor_derlem()


def _sonuc(m) -> list[tuple[str, str, tuple[int, ...]]]:
    return [(it.text, it.kind, tuple(sorted(idx))) for it, idx in m.hits]


class TestGerekliDizgi:
    @pytest.mark.parametrize("alt,beklenen", [
        (r"crypto.?miner", "crypto"),
        (r"[Aa][Ee][Ss]-?(128|192|256)", "aes"),
        (r"\bgl[A-Z]\w+", "gl"),
        (r"https://", "https://"),
        (r"PT_DENY_ATTACH", "pt_deny_attach"),
        (r"(foo)bar", "foobar"),
        (r"a|b", ""),          # üst düzey dal: tek gerekli dizgi yok
        (r"x*", ""),
    ])
    def test_ornekler(self, alt, beklenen) -> None:
        assert _required_literal(alt) == beklenen

    def test_her_gosterge_icin_gerekli(self) -> None:
        # Gerekli dizgi, göstergenin eşleştiği her derlem öğesinde (küçük harfle) bulunur.
        import re as _re
        for alt in _tum_alternatifler():
            lit = _required_literal(alt)
            rx = _re.compile(bim._indicator_source(alt, None))
            for s in DERLEM:
                if s.isascii() and rx.search(s):
                    assert lit in s.lower(), (alt, lit, s)


class TestOnSuzgecAyniSonuc:
    def test_butun_kurallar_derlemde_ayni(self) -> None:
        items = _collect_items(DERLEM, DERLEM[:40], ["/usr/lib/libgit2.dylib"], "x")
        index = _ItemIndex(items)
        farkli = []
        for fam, ad, kural in TUM_KURALLAR:
            if _sonuc(_match_rule(kural, items, index)) != _sonuc(_match_rule(kural, items)):
                farkli.append((fam, ad))
        assert farkli == []

    def test_son_oge_ve_ascii_olmayan(self) -> None:
        kural = bim._PROTOCOL_RULES["HTTPS"]
        items = _collect_items(["abc", "def", "NSURLSession"], [], [], "x")
        assert [it.text for it, _ in _match_rule(kural, items, _ItemIndex(items)).hits] == [
            "NSURLSession"]
        # Kelvin işareti küçük harfe 'k' olur ama ASCII değildir: her zaman aday
        kural = bim._STRING_RULES["encryption"]
        items = _collect_items(["zzzz", "Kerberos ticket"], [], [], "x")
        a = _sonuc(_match_rule(kural, items, _ItemIndex(items)))
        assert a == _sonuc(_match_rule(kural, items))

    def test_analyze_raporu_ayni(self, monkeypatch) -> None:
        bi = BinaryIntelligence(Config())
        hizli = bi.analyze(DERLEM, DERLEM[:60], ["/usr/lib/libgit2.dylib"], "x").to_dict()
        # Ön süzgeç kapalı: her kural her öğede aranır (P01 davranışı)
        monkeypatch.setattr(bim._ItemIndex, "candidates",
                            lambda self, rx: list(range(self.n)))
        yavas = bi.analyze(DERLEM, DERLEM[:60], ["/usr/lib/libgit2.dylib"], "x").to_dict()
        assert hizli == yavas
