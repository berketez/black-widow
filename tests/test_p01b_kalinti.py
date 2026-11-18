"""P01b kalem 2: yaygın İngilizce sözcüklerden kurulan kalıntı alt sistem iddiaları.

Kanıtlar gerçek ama alt sistem adı yanıltıcıydı: htop / redis / openssl "Version Control"
(``collapseAllBranches``, ``push``, ``fetch``, ``diff``), coreutils ``[`` ve ``stty`` "Testing
Framework" (``__assert_fail`` + "expected"), ``dir`` / ``dircolors`` / ``ls`` "Terminal Emulator"
(TERM veritabanı, "shell"), openssl "Licensing" (CMS ``Receipt``, ``serialNumber``). Onarım: bu dört
grup en az bir AYIRT EDİCİ göstergeyi (``anchors``) API benzeri bir öğede (simge, kitaplık,
tanımlayıcı dizgi) ister: libgit2 API'si, XCTest / unittest, pty ayırma API'si, StoreKit /
uygulama içi satın alma / ürün anahtarı / lisans denetimi. Girdiler masum kapı koşusundaki gerçek
kanıt satırlarıdır (``P01b/masum_k0/masum_kapi.json``).
"""

from __future__ import annotations

import pytest

from karadul.analyzers.binary_intelligence import BinaryIntelligence
from karadul.config import Config


@pytest.fixture
def bi() -> BinaryIntelligence:
    return BinaryIntelligence(Config())


def _alt(bi: BinaryIntelligence, dizgi, simge=(), kitaplik=()) -> dict:
    r = bi.analyze(list(dizgi), list(simge), list(kitaplik), "x")
    return {s.name: s for s in r.architecture.subsystems}


class TestKalintiYanlisYok:
    def test_htop_version_control(self, bi) -> None:
        subs = _alt(bi, ["toggle merged command", "Merge exe, comm and cmdline in Command",
                         "- Try to find comm in cmdline (when Command is merged)",
                         "show_merged_command=%d%c", "xterm", "(no tty) ", "TTY      "],
                    ["Table_collapseAllBranches", "Vector_add"])
        assert "Version Control" not in subs
        assert "Terminal Emulator" not in subs

    def test_redis_cli(self, bi) -> None:
        subs = _alt(bi, ["=== ASSERTION FAILED ===", "*** Assertion failed: Reshard table",
                         "Missing expected hint for input '%s'", "xterm",
                         "parent->type == REDIS_REPLY_PUSH"],
                    ["redisSetPushCallback", "isPubsubPush", "redisAsyncSetPushCallback",
                     "dictFetchValue", "__assert_fail", "_serverAssert", "tcsetattr",
                     "tcgetattr", "cliRestoreTTY", "cliFormatInvalidateTTY"])
        for yanlis in ("Version Control", "Testing Framework", "Terminal Emulator"):
            assert yanlis not in subs, yanlis

    def test_coreutils_test_ve_stty(self, bi) -> None:
        subs = _alt(bi, ["%s: unary operator expected", "%s expected", "%s expected, found %s",
                         "%s: binary operator expected"], ["__assert_fail"])
        assert "Testing Framework" not in subs
        subs = _alt(bi, [" * swtch CHAR    CHAR will switch to a different shell layer",
                         "   [-]hup        send a hangup signal when the last process closes the tty",
                         "   [-]parenb     generate parity bit in output and expect parity bit"],
                    ["tcgetattr", "tcsetattr", "__assert_fail"])
        assert "Terminal Emulator" not in subs
        assert "Testing Framework" not in subs

    def test_ls_dircolors_term(self, bi) -> None:
        subs = _alt(bi, ["TERM ansi", "TERM vt100", "TERM xterm*", "SHELL",
                         "  -b, --sh, --bourne-shell    output Bourne shell code to set LS_COLORS",
                         "shell-escape", "shell-always"], ["tcgetattr", "isatty"])
        assert "Terminal Emulator" not in subs

    def test_openssl(self, bi) -> None:
        subs = _alt(bi, ["%d out of %d certificate requests certified, commit? [y/n]",
                         "certhash merge failed"],
                    ["OSSL_CRMF_CERTID_get0_serialNumber", "CMS_ReceiptRequest_create0_ex",
                     "CMS_sign_receipt", "CMS_verify_receipt", "OSSL_PARAM_BLD_push_BN",
                     "EVP_KDF_fetch", "X509_CRL_diff", "EVP_MAC_fetch", "BIO_push",
                     "OSSL_STORE_expect", "OSSL_CMP_CTX_set1_expected_sender"])
        for yanlis in ("Licensing", "Version Control", "Testing Framework"):
            assert yanlis not in subs, yanlis

    def test_yalniz_dizgide_ayirt_edici_yetmez(self, bi) -> None:
        # ayırt edici gösterge düz metinde (API benzeri değil) yetmez: ssh "pty-req", hata iletisi
        # içinde "openpty" (API çağrısı değil, düzyazı)
        subs = _alt(bi, ["Pseudo-terminal will not be allocated because stdin is not a terminal.",
                         "send pty-req", "PTY allocation request failed", "openpty failed: %s"],
                    ["tcgetattr", "tcsetattr"])
        assert "Terminal Emulator" not in subs


class TestAyirtEdiciVarsaKalir:
    def test_tmux_forkpty(self, bi) -> None:
        subs = _alt(bi, ["tcgetattr failed: %s", "lost tty", "shell %s, command %s"],
                    ["_tcgetattr", "_tcsetattr", "_forkpty"])
        assert "Terminal Emulator" in subs
        assert subs["Terminal Emulator"].evidence[0] == "_forkpty"

    def test_vim_posix_openpt(self, bi) -> None:
        subs = _alt(bi, ["using pty %s on fd %d"], ["_posix_openpt", "_ptsname", "_tcgetattr"])
        assert "Terminal Emulator" in subs

    def test_libgit2(self, bi) -> None:
        subs = _alt(bi, ["commit", "branch"], ["_git_repository_open", "_git_commit_lookup"],
                    ["/opt/homebrew/lib/libgit2.1.7.dylib"])
        assert "Version Control" in subs

    def test_xctest(self, bi) -> None:
        subs = _alt(bi, ["test case"], ["_XCTAssertEqual", "_OBJC_CLASS_$_XCTestCase"])
        assert "Testing Framework" in subs

    def test_storekit(self, bi) -> None:
        subs = _alt(bi, ["license", "trial expired"],
                    ["_OBJC_CLASS_$_SKPaymentQueue"],
                    ["/System/Library/Frameworks/StoreKit.framework/Versions/A/StoreKit"])
        assert "Licensing" in subs
