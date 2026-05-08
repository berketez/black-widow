"""sig_db Graphics/media migration testleri (Faz A-DELETE sonrasi).

v1.13 Dalga 2 A-DELETE: legacy ``_*_SIGNATURES`` inline literal bloklari
silindi, signature_db.py artik
``from sigdb_builtin.graphics_media import SIGNATURES`` referansi uzerinden
dogrudan import yapiyor. AST parse parity testleri tautolojik hale geldigi
icin kaldirildi.

Korunan parity katmanlari:
1. Runtime identity (``is`` check)
2. Coverage count
3. Cross-dict overlap kontrolu
4. Bilinen sembol lookup
5. Post-A-DELETE: signature_db.py'da inline literal YOK + dogrudan
   ``_BUILTIN_GRAPHICS_MEDIA_SIGS`` referansi VAR.

Kapsam (8 alt-kategori, 362 imza).
"""
from __future__ import annotations

import pytest


_EXPECTED_KEYS = {
    "opengl_metal_gpu_signatures",
    "coregraphics_signatures",
    "coreimage_coreml_signatures",
    "image_lib_signatures",
    "audio_signatures",
    "ffmpeg_signatures",
    "sdl2_signatures",
    "graphics_ext_signatures",
}

_EXPECTED_COUNTS = {
    "opengl_metal_gpu_signatures": 57,
    "coregraphics_signatures": 34,
    "coreimage_coreml_signatures": 10,
    "image_lib_signatures": 51,
    "audio_signatures": 45,
    "ffmpeg_signatures": 34,
    "sdl2_signatures": 31,
    "graphics_ext_signatures": 100,
}

_TOTAL_EXPECTED = 362

_KEY_TO_ORIG = {
    "opengl_metal_gpu_signatures": "_OPENGL_METAL_GPU_SIGNATURES",
    "coregraphics_signatures": "_COREGRAPHICS_SIGNATURES",
    "coreimage_coreml_signatures": "_COREIMAGE_COREML_SIGNATURES",
    "image_lib_signatures": "_IMAGE_LIB_SIGNATURES",
    "audio_signatures": "_AUDIO_SIGNATURES",
    "ffmpeg_signatures": "_FFMPEG_SIGNATURES",
    "sdl2_signatures": "_SDL2_SIGNATURES",
    "graphics_ext_signatures": "_GRAPHICS_EXT_SIGNATURES",
}


# ---------------------------------------------------------------------------
# 1. Modul yuklenebilir mi?
# ---------------------------------------------------------------------------

def test_sigdb_builtin_graphics_media_importable() -> None:
    """sigdb_builtin.graphics_media import edilebilir ve SIGNATURES dict'i var."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    assert hasattr(graphics_media, "SIGNATURES")
    assert isinstance(graphics_media.SIGNATURES, dict)
    assert len(graphics_media.SIGNATURES) == 8


def test_sigdb_builtin_graphics_media_has_expected_keys() -> None:
    """SIGNATURES 8 top-level anahtar icerir."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    assert set(graphics_media.SIGNATURES.keys()) == _EXPECTED_KEYS


def test_coverage_count() -> None:
    """Her kategori beklenen entry sayisina sahip; toplam = 362."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    for key, expected in _EXPECTED_COUNTS.items():
        actual = len(graphics_media.SIGNATURES[key])
        assert actual == expected, f"{key}: expected {expected}, got {actual}"

    total = sum(len(v) for v in graphics_media.SIGNATURES.values())
    assert total == _TOTAL_EXPECTED, (
        f"Total graphics_media entry count: expected {_TOTAL_EXPECTED}, got {total}"
    )


# ---------------------------------------------------------------------------
# 2. Cross-dict overlap / duplicate kontrolu
# ---------------------------------------------------------------------------

def test_no_duplicate_keys() -> None:
    """Hem her dict icinde tekildirler, hem dict'ler arasi cakisma yoktur."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    for key, dct in graphics_media.SIGNATURES.items():
        assert len(dct) == _EXPECTED_COUNTS[key]

    seen: dict[str, str] = {}
    for cat_key, dct in graphics_media.SIGNATURES.items():
        for sym in dct.keys():
            assert sym not in seen, (
                f"cross-dict duplicate: '{sym}' in '{seen.get(sym)}' ve '{cat_key}'"
            )
            seen[sym] = cat_key


# ---------------------------------------------------------------------------
# 3. Runtime identity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("builtin_key,legacy_name", sorted(_KEY_TO_ORIG.items()))
def test_runtime_identity_each_dict(builtin_key: str, legacy_name: str) -> None:
    """signature_db._<NAME> ile builtin graphics_media[<key>] AYNI obje (`is`)."""
    from karadul.analyzers import signature_db as sdb
    from karadul.analyzers.sigdb_builtin import graphics_media

    legacy = getattr(sdb, legacy_name)
    migrated = graphics_media.SIGNATURES[builtin_key]
    assert legacy is migrated, (
        f"{legacy_name} <-> {builtin_key} runtime identity ihlali"
    )
    assert len(migrated) == _EXPECTED_COUNTS[builtin_key]


# ---------------------------------------------------------------------------
# 4. Bilindik sembol noktasal kontrolleri
# ---------------------------------------------------------------------------

def test_known_opengl_metal_symbols_present() -> None:
    """OpenGL temel API + Metal device factory yerinde."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    gl = graphics_media.SIGNATURES["opengl_metal_gpu_signatures"]
    assert "_glGenBuffers" in gl
    assert gl["_glGenBuffers"]["lib"] == "OpenGL"
    assert gl["_glGenBuffers"]["category"] == "graphics"
    assert "_glDrawArrays" in gl
    assert "_glCreateProgram" in gl
    assert "_MTLCreateSystemDefaultDevice" in gl
    assert gl["_MTLCreateSystemDefaultDevice"]["lib"] == "Metal"
    assert "_CVDisplayLinkStart" in gl


def test_known_coregraphics_symbols_present() -> None:
    """CoreGraphics bitmap/path/CTM API."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    cg = graphics_media.SIGNATURES["coregraphics_signatures"]
    assert "_CGBitmapContextCreate" in cg
    assert "_CGContextDrawImage" in cg
    assert "_CGPathAddEllipseInRect" in cg
    assert cg["_CGPathAddEllipseInRect"]["lib"] == "CoreGraphics"


def test_known_image_lib_symbols_present() -> None:
    """libpng/libjpeg/libwebp/ImageIO."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    img = graphics_media.SIGNATURES["image_lib_signatures"]
    assert "_png_create_read_struct" in img
    assert img["_png_create_read_struct"]["lib"] == "libpng"
    assert "_jpeg_start_compress" in img
    assert img["_jpeg_start_compress"]["lib"] == "libjpeg"
    assert "_WebPDecodeRGBA" in img
    assert "_CGImageSourceCreateWithURL" in img
    assert img["_CGImageSourceCreateWithURL"]["lib"] == "ImageIO"


def test_known_audio_symbols_present() -> None:
    """CoreAudio + AVFoundation + OpenAL."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    au = graphics_media.SIGNATURES["audio_signatures"]
    assert "_AudioComponentInstanceNew" in au
    assert au["_AudioComponentInstanceNew"]["lib"] == "CoreAudio"
    assert "_AVAudioEngine" in au
    assert au["_AVAudioEngine"]["lib"] == "AVFoundation"
    assert "_alGenSources" in au
    assert au["_alGenSources"]["lib"] == "OpenAL"


def test_known_ffmpeg_symbols_present() -> None:
    """FFmpeg send/receive API + sws + swr."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    ff = graphics_media.SIGNATURES["ffmpeg_signatures"]
    assert "_avformat_open_input" in ff
    assert ff["_avformat_open_input"]["lib"] == "libavformat"
    assert "_avcodec_send_packet" in ff
    assert "_avcodec_receive_frame" in ff
    assert "_sws_scale" in ff
    assert ff["_sws_scale"]["lib"] == "libswscale"
    assert "_swr_convert" in ff
    assert ff["_swr_convert"]["lib"] == "libswresample"


def test_known_sdl2_symbols_present() -> None:
    """SDL2 init/window/renderer/audio."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    sd = graphics_media.SIGNATURES["sdl2_signatures"]
    assert "_SDL_Init" in sd
    assert sd["_SDL_Init"]["lib"] == "SDL2"
    assert "_SDL_CreateWindow" in sd
    assert "_SDL_CreateRenderer" in sd
    assert "_SDL_OpenAudio" in sd


def test_known_graphics_ext_symbols_present() -> None:
    """Vulkan/D3D11/D3D12/DXGI/FreeType/HarfBuzz/Cairo."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    gx = graphics_media.SIGNATURES["graphics_ext_signatures"]
    assert "vkCreateInstance" in gx
    assert gx["vkCreateInstance"]["lib"] == "vulkan"
    assert "vkQueueSubmit" in gx
    assert "D3D11CreateDevice" in gx
    assert "D3D12CreateDevice" in gx
    assert "CreateDXGIFactory2" in gx
    assert "FT_Init_FreeType" in gx
    assert gx["FT_Init_FreeType"]["lib"] == "freetype"
    assert "hb_shape" in gx
    assert "cairo_create" in gx
    assert gx["cairo_create"]["category"] == "graphics_2d"


# ---------------------------------------------------------------------------
# 5. Schema tutarliligi
# ---------------------------------------------------------------------------

def test_entry_schema_consistency() -> None:
    """Her entry {lib, purpose, category} string anahtar tasimali."""
    from karadul.analyzers.sigdb_builtin import graphics_media

    required_keys = {"lib", "purpose", "category"}
    for cat_key, dct in graphics_media.SIGNATURES.items():
        for sym, entry in dct.items():
            assert isinstance(entry, dict), f"{cat_key}::{sym} entry dict degil"
            assert required_keys <= set(entry.keys()), (
                f"{cat_key}::{sym} eksik anahtar: {required_keys - set(entry.keys())}"
            )
            for k in required_keys:
                assert isinstance(entry[k], str), f"{cat_key}::{sym}::{k} string degil"


# ---------------------------------------------------------------------------
# 6. Post-A-DELETE: legacy literal silindi, dogrudan referans
# ---------------------------------------------------------------------------

def test_post_a_delete_no_inline_literal() -> None:
    """signature_db.py'da legacy ``_<KAT>_SIGNATURES = {...}`` literal'leri YOK."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert (
        '_OPENGL_METAL_GPU_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_GRAPHICS_MEDIA_SIGS["opengl_metal_gpu_signatures"]'
    ) in text
    assert (
        '_AUDIO_SIGNATURES: dict[str, dict[str, str]] = '
        '_BUILTIN_GRAPHICS_MEDIA_SIGS["audio_signatures"]'
    ) in text
    for legacy in _KEY_TO_ORIG.values():
        assert f'\n{legacy}: dict[str, dict[str, str]] = {{' not in text, (
            f"{legacy} hala inline literal olarak duruyor"
        )


def test_post_a_delete_direct_import() -> None:
    """signature_db.py graphics_media SIGNATURES'i ``sigdb_builtin.graphics_media``'dan dogrudan alir."""
    from pathlib import Path

    text = Path("karadul/analyzers/signature_db.py").read_text(encoding="utf-8")
    assert "_BUILTIN_GRAPHICS_MEDIA_SIGS" in text
    assert "sigdb_builtin" in text and "graphics_media" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
