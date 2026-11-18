"""binary_intelligence kanıt modeli (2026-11-18 onarımı, IMZA-01).

Girdiler genel taramada gerçek ikililerde görülen dizgi / simgelerdir (Debian coreutils,
redis-tools, macOS vim, masum PE). Her sınıf eski kodda KIRMIZI'dır: eski desenler harf
duyarsız ve sınırsız alt dizgi arıyor, tek kanıtla hüküm veriyordu.
"""

from __future__ import annotations

import pytest

from karadul.analyzers.binary_intelligence import (
    ALGORITHM_PATTERNS,
    BinaryIntelligence,
)
from karadul.config import Config

# Debian coreutils `true` / `[` ikililerinin gerçek dizgi + simge örneği.
COREUTILS_TRUE_STRINGS = [
    "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable", "__gmon_start__",
    "__cxa_finalize", "stderr", "GLIBC_2.17", "GLIBC_2.34", "GLIBC_2.38",
    "bindtextdomain", "textdomain", "sha256sum", "sha384sum", "sha512sum", "sha224sum",
    "License GPLv3+: GNU GPL version 3 or later <%s>.",
    "https://www.gnu.org/software/coreutils/", "https://gnu.org/licenses/gpl.html",
    "Report any translation bugs to <https://translationproject.org/team/>",
    "Follow symbolic links like directories.", "Output pieces of FILE to PREFIXaa, PREFIXab",
    "/lib/ld-linux-aarch64.so.1", "GCC: (Debian 14.2.0-19) 14.2.0", ".gnu.version_r",
]
COREUTILS_TRUE_SYMBOLS = [
    "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable", "__gmon_start__",
    "__cxa_finalize", "stderr", "bindtextdomain", "textdomain", "__stack_chk_fail",
    "__stack_chk_guard",
]


@pytest.fixture
def bi() -> BinaryIntelligence:
    return BinaryIntelligence(Config())


def _names(report, kind: str) -> set[str]:
    return {x.name for x in getattr(report.architecture, kind)}


class TestMasumIkiliSahteIddiaYok:
    def test_coreutils_true(self, bi: BinaryIntelligence) -> None:
        r = bi.analyze(COREUTILS_TRUE_STRINGS, COREUTILS_TRUE_SYMBOLS, [], "true")
        subs, algos = _names(r, "subsystems"), _names(r, "algorithms")
        for yanlis in ("Bluetooth", "Encryption", "Browser Engine", "Licensing",
                       "Cryptographic Hashing", "HTTP Client"):
            assert yanlis not in subs, yanlis
        for yanlis in ("OpenGL", "SHA-256", "SHA-512"):
            assert yanlis not in algos, yanlis
        assert "HTTPS" not in _names(r, "protocols")
        assert "IPsec" not in _names(r, "protocols")
        assert "ASLR" not in _names(r, "security")
        # Doğru iddia kalır: yığın koruyucusu gerçekten açık.
        assert "Stack Protection" in _names(r, "security")

    def test_redis_kisaltma_alt_dizgileri(self, bi: BinaryIntelligence) -> None:
        strings = ["siphash", "siptlw", "verifyGossipSectionNodeIds", "Gossip",
                   "maskModuleConfigFlags", "moduleConfigFlags", "__quicklistCompress",
                   "quicklistCreate", "Output pieces of FILE", "copied verbatim"]
        r = bi.analyze(strings, strings[:3], [], "redis-check-rdb")
        sec = _names(r, "security")
        assert "SIP (System Integrity)" not in sec
        assert "Kernel Extension" not in sec
        assert "ASLR" not in sec
        assert "HTTP/3" not in _names(r, "protocols")

    def test_vim_ve_pe_alt_dizgileri(self, bi: BinaryIntelligence) -> None:
        strings = ["CurrentPC", "GetCurrentProcessId", "GetCurrentThreadId", "strikethrough",
                   'Vi mode (like "vi")', "[Quickfix List]", "# Bar lines, copied verbatim:"]
        r = bi.analyze(strings, [], [], "vim")
        proto = _names(r, "protocols")
        assert {"NTP", "IPsec", "HTTP/3"}.isdisjoint(proto)
        assert "ASLR" not in _names(r, "security")


class TestHarfDuyarliligiIkiYolda:
    def test_case_sensitive_alani_dosya_duzeyinde(self, bi: BinaryIntelligence) -> None:
        # AES / RSA "case_sensitive": True; küçük harfli girdi eşleşmemeli.
        assert ALGORITHM_PATTERNS["AES"]["case_sensitive"] is True
        algos = {a.name for a in bi._detect_algorithms(["aes_key", "aes_iv", "rsa", "the rsa"])}
        assert "AES" not in algos and "RSA" not in algos

    def test_case_sensitive_alani_fonksiyon_basina(self, bi: BinaryIntelligence) -> None:
        found = bi._find_algorithms_in_code("int rsa = 0; char *aes_key = buf; FrontMtx = 1;")
        assert "RSA" not in found
        assert "AES" not in found
        # Büyük harfli doğru biçim aynı yolda bulunur (P01b: fonksiyon başına da iki bağımsız
        # kanıt; tek RSA_sign / tek AES_encrypt çağrısı yetmez — tests/test_p01b_islev.py).
        found = bi._find_algorithms_in_code(
            "RSA_sign(key); RSA_verify(key); AES_set_encrypt_key(k); AES_encrypt(in, out, k);")
        assert "RSA" in found and "AES" in found

    def test_kisaltma_buyuk_harf_ve_sinir(self, bi: BinaryIntelligence) -> None:
        r = bi.analyze(["BLE scan started", "CBCentralManager"], ["_CBPeripheral"], [], "x")
        assert "Bluetooth" in _names(r, "subsystems")
        r = bi.analyze(["able", "table", "TMCloneTable", "BLEED"], [], [], "x")
        assert "Bluetooth" not in _names(r, "subsystems")


class TestIkiBagimsizKanit:
    def test_tek_simge_hukum_vermez(self, bi: BinaryIntelligence) -> None:
        r = bi.analyze([], ["_SHA256_Init"], [], "x")
        assert "SHA-256" not in _names(r, "algorithms")
        r = bi.analyze([], ["_SHA256_Init", "_SHA256_Update"], [], "x")
        assert "SHA-256" in _names(r, "algorithms")

    def test_dizgi_ve_simge_ayni_ad_tek_kanit(self, bi: BinaryIntelligence) -> None:
        # Debian openssl: EVP_aes_256_cbc hem .dynstr dizgisi hem dinamik simge.
        r = bi.analyze(["EVP_aes_256_cbc"], ["EVP_aes_256_cbc"], [], "openssl")
        assert "AES" not in _names(r, "algorithms")
        r = bi.analyze(["EVP_aes_256_cbc", "AES-256-CBC"], ["EVP_aes_256_cbc"], [], "openssl")
        assert "AES" in _names(r, "algorithms")

    def test_ortusen_gosterge_cifti_tek_kanit_turu(self, bi: BinaryIntelligence) -> None:
        # "__swift_1" / "__swift_2" PE bölüm adları: ikisi de aynı iki göstergeyi tutuyor.
        r = bi.analyze(["__swift_1", "__swift_2"], [], [], "t64.exe")
        assert "Swift Runtime" not in _names(r, "subsystems")

    def test_alt_sistem_yalniz_yardim_metniyle_kurulmaz(self, bi: BinaryIntelligence) -> None:
        strings = ["  nocache   Request to drop cache.", "https://www.gnu.org/software/coreutils/",
                   "[trial division] ", "License GPLv3+: GNU GPL version 3 or later <%s>."]
        r = bi.analyze(strings, [], [], "dd")
        subs = _names(r, "subsystems")
        assert "HTTP Client" not in subs and "Licensing" not in subs

    def test_alt_sistemde_ayni_sozcuklu_iki_api_yetmez(self, bi: BinaryIntelligence) -> None:
        syms = ["sd_session_get_remote_user", "sd_session_get_remote_host"]
        r = bi.analyze([], syms, [], "pinky")
        assert "Version Control" not in _names(r, "subsystems")


class TestRiskDuzeyiGucluKanit:
    def test_cekirdek_iddiasi_simge_ister(self, bi: BinaryIntelligence) -> None:
        strings = ["kext loading failed", "kernel extension", "com.example.kext.Driver"]
        r = bi.analyze(strings, [], [], "x")
        assert "Kernel Extension" not in _names(r, "security")
        r = bi.analyze(strings, ["_KextManagerLoadKextWithURL"], [], "kextload")
        ke = next(s for s in r.architecture.security if s.name == "Kernel Extension")
        assert ke.risk_level == "kernel"
        assert "symbol" in ke.evidence_kinds

    def test_sip_api_kaniti(self, bi: BinaryIntelligence) -> None:
        r = bi.analyze(["failed to retrieve system integrity configuration"],
                       ["_csr_get_active_config"], [], "csrutil")
        assert "SIP (System Integrity)" in _names(r, "security")


class TestKanitTasima:
    def test_kanit_turleri_paralel(self, bi: BinaryIntelligence) -> None:
        r = bi.analyze(["Bluetooth power state"], ["_OBJC_CLASS_$_CBCentralManager"],
                       ["/System/Library/Frameworks/CoreBluetooth.framework/CoreBluetooth"],
                       "bluetoothd")
        bt = next(s for s in r.architecture.subsystems if s.name == "Bluetooth")
        assert len(bt.evidence) == len(bt.evidence_kinds)
        assert set(bt.evidence_kinds) == {"symbol", "library", "string"}
        d = r.to_dict()["architecture"]["subsystems"][0]
        assert isinstance(d["evidence"], list) and isinstance(d["confidence"], float)

    def test_ikilinin_kendi_yolu_kitaplik_sayilmaz(self, bi: BinaryIntelligence) -> None:
        # otool -L evrensel ikilide her mimari için ikilinin kendi yolunu da yazar.
        r = bi.analyze(["OpenSSH_9.9"], [], ["/usr/bin/ssh", "/usr/bin/ssh"], "ssh")
        assert "SSH" not in _names(r, "protocols")

    def test_gurultu_kanit_degil(self, bi: BinaryIntelligence) -> None:
        r = bi.analyze(["GLIBC_2.17", "GLIBCXX_3.4.21", "glibc", ".gnu.version_r"],
                       ["__gmon_start__", "_ITM_deregisterTMCloneTable",
                        "_ITM_registerTMCloneTable"], [], "x")
        assert r.raw_cluster_counts == {}

    def test_sip_pozitif_eski_kodda_da_vardi(self, bi: BinaryIntelligence) -> None:
        """Pozitif koruma: SIP API'si ve metni birlikte → iddia (eski ve yeni kodda)."""
        r = bi.analyze(["System Integrity Protection status: enabled."],
                       ["_csr_check"], [], "csrutil")
        assert "SIP (System Integrity)" in _names(r, "security")


class TestGostergeKurali:
    def test_sol_belirtec_siniri(self, bi: BinaryIntelligence) -> None:
        # "actor" ⊂ refactoring, "predict" ⊂ unpredictable, "patch" ⊂ dispatch: sözcük içi.
        clusters = bi._cluster_strings(["refactoring", "unpredictable", "dispatch_once"])
        assert "concurrency" not in clusters
        assert "machine_learning" not in clusters
        assert "update_system" not in clusters

    def test_gurultu_ogeleri_dusurulur(self) -> None:
        from karadul.analyzers.binary_intelligence import _collect_items

        items = _collect_items(
            ["GLIBC_2.17", "GLIBCXX_3.4.21", ".gnu.version_r", "/lib/ld-linux-aarch64.so.1",
             "SHA256_Init"],
            ["__gmon_start__", "_ITM_deregisterTMCloneTable", "__cxa_finalize"], [])
        assert [it.text for it in items] == ["SHA256_Init"]

    def test_api_yolu_iki_api_benzeri_oge_ister(self, bi: BinaryIntelligence) -> None:
        # Tek API adı + aynı göstergeyi taşıyan düzyazı: bağımsız değil.
        algos = {a.name for a in bi._detect_algorithms(["EVP_aes_128_cbc",
                                                        "uses EVP_aes_ functions"])}
        assert "AES" not in algos

    def test_case_sensitive_alani_derlemede_okunur(self) -> None:
        from karadul.analyzers.binary_intelligence import _ALGO_RULES

        # RSA girdisinde küçük harfli alternatifler (rsa_oaep) de harf duyarlı derlenmeli.
        assert all("(?-i:" in rx.pattern for rx in _ALGO_RULES["RSA"].indicators)
        assert any("(?i:" in rx.pattern for rx in _ALGO_RULES["SHA-256"].indicators)

    def test_fonksiyon_basina_paralel_yol(self) -> None:
        from karadul.analyzers.binary_intelligence import _analyze_single_file

        code = ("void f(void) {\n    int rsa = 0;\n    char *aes_key = buf;\n"
                "    use(rsa, aes_key);\n}\n")
        out = _analyze_single_file(("f", code))
        assert out is not None
        assert "RSA" not in out["algorithms"] and "AES" not in out["algorithms"]
