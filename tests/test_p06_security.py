"""TIP-08: ``@security`` belge etiketinin kanıt kuralları (2026-11-18 onarımı, P06).

Eski kural etiketi fonksiyon adının küçük harfli hâlinde ALT DİZE aramasıyla veriyordu:
"patch" ⊂ "dis**patch**er" → "Code injection/hooking mechanism", "token" ⊂ ifade
çözümleyicisi → "Handles authentication/credentials", "key" ⊂ Redis anahtar adları →
"Handles sensitive key material", "rsa" ⊂ "trave**rsa**l", "sha" ⊂ "**sha**red". Ad Karadul'un
kendi önerisi de olabiliyordu. Ölçüm (119 ikili, yeniden oynatma): 4 327 etiket; kanca 15,
kimlik 70, anahtar 894.

Yeni kural:
- "Handles ..." yalnız çağrı kanıtıyla (gerçek API çağrıda); API adları ``@security_evidence``;
- ad kaynaklı etiket yalnız ad ikilinin kendi simgesiyse ve adın SÖZCÜĞÜ sözlükte tam geçiyorsa,
  "By name only: ... (no call evidence)" niteliğiyle; kanca/enjeksiyon addan verilmez;
- parametre etiketi yalnız Ghidra'nın parametre adlarından.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from karadul.reconstruction.c_comment_generator import (
    CCommentGenerator,
    _name_words,
    _security_call_class,
)

detect = CCommentGenerator._detect_security_relevance


# ---------------------------------------------------------------------------
# Ad kaynaklı etiket: tam sözcük, yalnız ikilinin kendi simgesi
# ---------------------------------------------------------------------------


class TestAdKaynakli:
    @pytest.mark.parametrize("ad", [
        "RedisModuleCommandDispatcher",   # patch ⊂ dispatcher
        "luaLdbLineHook",                 # hook: geri çağırma kancası, kod enjeksiyonu değil
        "notify_insert_one_hook",
        "sqlite3session_patchset",
        "exprNewToken", "exprTokenRelease",  # sözcük çözümleyici belirteci
        "RM_ClusterCanonicalKeyNameInSlot", "decodeTimeoutKey",  # veritabanı anahtarı
        "tree_traversal", "conversation_reset",  # rsa ⊂ traversal / conversation
        "shared_mem_init", "shadow_copy",        # sha ⊂ shared / shadow
        "getlogin", "find_root_node", "hash_table_insert",
    ])
    def test_masum_adlar_etiketsiz(self, ad: str) -> None:
        assert detect(ad, "", (), own_symbol=True) == ("", "")

    def test_gercek_kripto_adi_nitelikli(self) -> None:
        etiket, kanit = detect("SHA256_Update", "", (), own_symbol=True)
        assert etiket == "By name only: cryptographic operations (no call evidence)"
        assert kanit == ""

    def test_gercek_tls_adi_nitelikli(self) -> None:
        etiket, _ = detect("SSL_set_verify", "", (), own_symbol=True)
        assert etiket == "By name only: certificates/TLS (no call evidence)"

    def test_ozel_anahtar_ikilisi(self) -> None:
        etiket, _ = detect("SSL_CTX_use_PrivateKey_file", "", (), own_symbol=True)
        assert etiket == "By name only: sensitive key material (no call evidence)"

    def test_karadul_adi_kanit_degil(self) -> None:
        # Ad Ghidra'nın simgesi değil (Karadul'un önerisi): addan etiket yok
        assert detect("sha256_update", "", (), own_symbol=False) == ("", "")

    def test_fun_adi_etiketsiz(self) -> None:
        assert detect("FUN_00101000", "", (), own_symbol=True) == ("", "")

    def test_kanca_addan_verilmez(self) -> None:
        for ad in ("inject_payload", "install_detour", "MSHookFunction_wrapper"):
            assert detect(ad, "", (), own_symbol=True) == ("", "")

    def test_ad_sozcukleri(self) -> None:
        assert _name_words("RedisModuleCommandDispatcher") == ["redis", "module", "command", "dispatcher"]
        assert _name_words("SHA256_Update") == ["sha256", "update"]
        assert _name_words("EVP_PKEY_get_raw_private_key")[-2:] == ["private", "key"]


# ---------------------------------------------------------------------------
# Çağrı kanıtı
# ---------------------------------------------------------------------------


class TestCagriKaniti:
    def test_kripto_api_cagrisi(self) -> None:
        etiket, kanit = detect("FUN_00101000", "", ["malloc", "EVP_DigestInit_ex", "EVP_DigestUpdate"])
        assert etiket == "Handles cryptographic operations"
        assert kanit == "calls EVP_DigestInit_ex, EVP_DigestUpdate"

    def test_macho_alt_cizgi_ve_surum_eki(self) -> None:
        assert detect("FUN_1", "", ["_CC_SHA256"])[0] == "Handles cryptographic operations"
        assert detect("FUN_1", "", ["setuid@GLIBC_2.17"]) == (
            "Handles privilege/sandbox operations", "calls setuid")

    def test_enjeksiyon_api(self) -> None:
        etiket, kanit = detect("FUN_1", "", ["OpenProcess", "WriteProcessMemory", "CreateRemoteThread"])
        assert etiket == "Code injection/hooking mechanism"
        assert kanit == "calls WriteProcessMemory, CreateRemoteThread"

    def test_ozel_anahtar_api(self) -> None:
        assert detect("FUN_1", "", ["SSL_CTX_use_PrivateKey_file"])[0] == "Handles sensitive key material"

    def test_cagri_addan_once_gelir(self) -> None:
        # Karadul adı da olsa çağrı kanıtı varsa güçlü etiket
        assert detect("dispatch", "", ["SSL_read"], own_symbol=False)[0] == "Handles certificates/TLS"

    @pytest.mark.parametrize("cagri", [
        "dlsym", "mprotect", "ptrace", "task_for_pid", "strtok", "hash_lookup",
        "keyboard_read", "getlogin", "patch_table", "SHAREDmem", "Cryptic_helper_x",
        "CryptStringToBinaryA", "CryptBinaryToStringW", "evp_like_helper", "ssl_buffer",
    ])
    def test_siradan_cagrilar_kanit_degil(self, cagri: str) -> None:
        # önekler büyük/küçük harf duyarlı ve API ailesinin kendisi; CryptStringToBinary
        # base64 kodlamasıdır (kripto değil)
        assert _security_call_class(cagri) == ""

    def test_windows_cryptoapi(self) -> None:
        assert _security_call_class("CryptAcquireContextW") == "crypto"
        assert _security_call_class("CryptProtectData") == "crypto"


# ---------------------------------------------------------------------------
# Parametre kanıtı
# ---------------------------------------------------------------------------


class TestParametre:
    def test_imza_metni_kanit_degil(self) -> None:
        # Karadul'un yeniden adlandırdığı parametre (imza metni) etiket vermez
        assert detect("FUN_1", "char *password, int len", ()) == ("", "")

    def test_ghidra_parametre_adi(self) -> None:
        etiket, _ = detect("do_login", "", (), own_symbol=True, param_names=["user", "password"])
        assert etiket == "By parameter name only: receives sensitive data (no call evidence)"

    def test_belirsiz_parametre_adlari(self) -> None:
        assert detect("f", "", (), own_symbol=True,
                      param_names=["monkey", "keyboard", "key", "token", "keylen"]) == ("", "")


# ---------------------------------------------------------------------------
# Ürün yolu: CCommentGenerator.generate
# ---------------------------------------------------------------------------


def _baslik(ad: str, adres: str) -> str:
    return (f"// Function: {ad}\n// Address:  {adres}\n// Size:     64 bytes\n"
            "// Callers:  0\n// Callees:  0\n// Stack:    frame=0, locals=0, params=0\n\n\n")


def _uret(tmp_path: Path, dosyalar: dict[str, str], fonksiyonlar: list, kenarlar: list) -> dict[str, str]:
    girdi = tmp_path / "girdi"
    girdi.mkdir()
    for ad, metin in dosyalar.items():
        (girdi / ad).write_text(metin, encoding="utf-8")
    fj = tmp_path / "f.json"
    fj.write_text(json.dumps({"functions": fonksiyonlar}), encoding="utf-8")
    cg = tmp_path / "cg.json"
    cg.write_text(json.dumps({"edges": kenarlar}), encoding="utf-8")
    sonuc = CCommentGenerator().generate(
        decompiled_dir=girdi, output_dir=tmp_path / "cikti",
        functions_json=fj, call_graph_json=cg,
    )
    assert sonuc.success, sonuc.errors
    return {ad: (tmp_path / "cikti" / ad).read_text(encoding="utf-8") for ad in dosyalar}


class TestUrunYolu:
    def test_uc_fonksiyon(self, tmp_path: Path) -> None:
        dosyalar = {
            # Karadul'un adlandırdığı (Ghidra: FUN_00101000), kripto çağrısı yok
            "FUN_00101000.c": _baslik("sha256_update", "00101000")
            + "void sha256_update(long param_1)\n\n{\n  FUN_00102000(param_1);\n  return;\n}\n",
            # ikilinin kendi simgesi, ama "patch" yalnız "dispatcher"ın parçası
            "RedisModuleCommandDispatcher.c": _baslik("RedisModuleCommandDispatcher", "00103000")
            + "void RedisModuleCommandDispatcher(long param_1)\n\n{\n  FUN_00102000(param_1);\n  return;\n}\n",
            # gerçek kripto API çağrısı
            "FUN_00104000.c": _baslik("FUN_00104000", "00104000")
            + "void FUN_00104000(long param_1)\n\n{\n  EVP_DigestInit_ex(param_1,0,0);\n  return;\n}\n",
        }
        fonksiyonlar = [
            {"name": "FUN_00101000", "address": "00101000", "parameters": []},
            {"name": "RedisModuleCommandDispatcher", "address": "00103000", "parameters": []},
            {"name": "FUN_00104000", "address": "00104000", "parameters": []},
        ]
        kenarlar = [
            {"from": "00101000", "to": "00102000", "from_name": "FUN_00101000", "to_name": "FUN_00102000"},
            {"from": "00103000", "to": "00102000", "from_name": "RedisModuleCommandDispatcher",
             "to_name": "FUN_00102000"},
            {"from": "00104000", "to": "00109000", "from_name": "FUN_00104000",
             "to_name": "EVP_DigestInit_ex"},
        ]
        cikti = _uret(tmp_path, dosyalar, fonksiyonlar, kenarlar)
        assert "@security" not in cikti["FUN_00101000.c"]
        assert "@security" not in cikti["RedisModuleCommandDispatcher.c"]
        assert " * @security Handles cryptographic operations\n" in cikti["FUN_00104000.c"]
        assert " * @security_evidence calls EVP_DigestInit_ex\n" in cikti["FUN_00104000.c"]

    def test_kendi_simgesi_nitelikli(self, tmp_path: Path) -> None:
        dosyalar = {"SHA256_Update.c": _baslik("SHA256_Update", "00105000")
                    + "void SHA256_Update(long param_1)\n\n{\n  FUN_00102000(param_1);\n  return;\n}\n"}
        fonksiyonlar = [{"name": "SHA256_Update", "address": "00105000",
                         "parameters": [{"name": "c", "type": "SHA256_CTX *", "ordinal": 0}]}]
        kenarlar = [{"from": "00105000", "to": "00102000", "from_name": "SHA256_Update",
                     "to_name": "FUN_00102000"}]
        cikti = _uret(tmp_path, dosyalar, fonksiyonlar, kenarlar)
        assert " * @security By name only: cryptographic operations (no call evidence)\n" in cikti["SHA256_Update.c"]
