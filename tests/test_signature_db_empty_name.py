"""Regression: SignatureDB public add_X API'leri bos input reject etmeli.

v1.10.0 Batch 3D MED fix:
- add_byte_signature: sig.name bos veya byte_pattern bos -> ValueError
- add_string_signature: matched_name bos veya keywords bos -> ValueError
- add_call_pattern: matched_name bos veya callees bos -> ValueError

Programmatic user bug'larini sessizce yutmak yerine erken hata verir.
"""
from __future__ import annotations

import pytest

from karadul.analyzers.signature_db import FunctionSignature, SignatureDB


# ---------------------------------------------------------------------------
# add_byte_signature
# ---------------------------------------------------------------------------

class TestAddByteSignatureValidation:
    def test_empty_name_raises(self) -> None:
        db = SignatureDB()
        sig = FunctionSignature(
            name="", library="test",
            byte_pattern=b"\x90\x90", byte_mask=b"\xff\xff",
        )
        with pytest.raises(ValueError, match="sig.name bos olamaz"):
            db.add_byte_signature(sig)

    def test_whitespace_only_name_raises(self) -> None:
        db = SignatureDB()
        sig = FunctionSignature(
            name="   ", library="test",
            byte_pattern=b"\x90", byte_mask=b"\xff",
        )
        with pytest.raises(ValueError, match="sig.name bos olamaz"):
            db.add_byte_signature(sig)

    def test_empty_byte_pattern_raises(self) -> None:
        db = SignatureDB()
        sig = FunctionSignature(
            name="foo", library="test",
            byte_pattern=b"", byte_mask=b"",
        )
        with pytest.raises(ValueError, match="byte_pattern bos olamaz"):
            db.add_byte_signature(sig)

    def test_valid_signature_accepted(self) -> None:
        db = SignatureDB()
        sig = FunctionSignature(
            name="EVP_EncryptInit_ex", library="openssl",
            byte_pattern=b"\x55\x48\x89\xe5", byte_mask=b"\xff\xff\xff\xff",
        )
        db.add_byte_signature(sig)  # raise etmemeli


# ---------------------------------------------------------------------------
# add_string_signature
# ---------------------------------------------------------------------------

class TestAddStringSignatureValidation:
    def test_empty_matched_name_raises(self) -> None:
        db = SignatureDB()
        with pytest.raises(ValueError, match="matched_name bos olamaz"):
            db.add_string_signature(
                keywords=frozenset({"aes", "encrypt"}),
                matched_name="",
                library="openssl",
            )

    def test_whitespace_only_matched_name_raises(self) -> None:
        db = SignatureDB()
        with pytest.raises(ValueError, match="matched_name bos olamaz"):
            db.add_string_signature(
                keywords=frozenset({"aes"}),
                matched_name="   ",
                library="openssl",
            )

    def test_empty_keywords_raises(self) -> None:
        db = SignatureDB()
        with pytest.raises(ValueError, match="keywords bos olamaz"):
            db.add_string_signature(
                keywords=frozenset(),
                matched_name="some_fn",
                library="openssl",
            )

    def test_valid_signature_accepted(self) -> None:
        db = SignatureDB()
        db.add_string_signature(
            keywords=frozenset({"AES"}),
            matched_name="aes_encrypt",
            library="openssl",
        )


# ---------------------------------------------------------------------------
# add_call_pattern
# ---------------------------------------------------------------------------

class TestAddCallPatternValidation:
    def test_empty_matched_name_raises(self) -> None:
        db = SignatureDB()
        with pytest.raises(ValueError, match="matched_name bos olamaz"):
            db.add_call_pattern(
                callees=frozenset({"malloc", "free"}),
                matched_name="",
                library="libc",
            )

    def test_whitespace_only_matched_name_raises(self) -> None:
        db = SignatureDB()
        with pytest.raises(ValueError, match="matched_name bos olamaz"):
            db.add_call_pattern(
                callees=frozenset({"malloc"}),
                matched_name="   ",
                library="libc",
            )

    def test_empty_callees_raises(self) -> None:
        db = SignatureDB()
        with pytest.raises(ValueError, match="callees bos olamaz"):
            db.add_call_pattern(
                callees=frozenset(),
                matched_name="alloc_wrapper",
                library="libc",
            )

    def test_valid_pattern_accepted(self) -> None:
        db = SignatureDB()
        db.add_call_pattern(
            callees=frozenset({"malloc", "free"}),
            matched_name="alloc_wrapper",
            library="libc",
            confidence=0.85,
        )
