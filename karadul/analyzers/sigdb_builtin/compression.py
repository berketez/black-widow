"""Compression category signatures — sig_db Faz 3'te tasindi.

Kaynak: karadul/analyzers/signature_db.py
  - _ZLIB_SIGNATURES               ( 58 entry, satir 1279-1338)
  - _BZIP2_SIGNATURES              ( 17 entry, satir 1345-1363)
  - _LZ4_SIGNATURES                ( 25 entry, satir 1370-1396)
  - _ZSTD_SIGNATURES               ( 42 entry, satir 1403-1446)
  - _COMPRESSION_EXT_SIGNATURES    ( 72 entry, satir 6218-6302)

Toplam: 214 signature.

Faz 3'te ikinci taşınan kategoridir (crypto + compression + network dalgasi).
signature_db.py icindeki orijinal dict'ler SILINMEMIS; rollback icin override
yontemi kullanilir. Bkz: signature_db.py icindeki ``_BUILTIN_COMPRESSION`` import bloku.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# zlib (58 entry) — deflate/inflate, gzip, CRC-32, Adler-32, ...
# Kaynak: signature_db.py satir 1279-1338
# ---------------------------------------------------------------------------
_ZLIB_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_deflateInit_": {"lib": "zlib", "purpose": "deflate init (compression)", "category": "compression"},
    "_deflateInit2_": {"lib": "zlib", "purpose": "deflate init with params", "category": "compression"},
    "_deflate": {"lib": "zlib", "purpose": "deflate compress", "category": "compression"},
    "_deflateEnd": {"lib": "zlib", "purpose": "deflate cleanup", "category": "compression"},
    "_deflateReset": {"lib": "zlib", "purpose": "deflate state reset", "category": "compression"},
    "_deflateBound": {"lib": "zlib", "purpose": "deflate output bound", "category": "compression"},
    "_deflateSetDictionary": {"lib": "zlib", "purpose": "deflate set dictionary", "category": "compression"},
    "_inflateInit_": {"lib": "zlib", "purpose": "inflate init (decompression)", "category": "compression"},
    "_inflateInit2_": {"lib": "zlib", "purpose": "inflate init with params", "category": "compression"},
    "_inflate": {"lib": "zlib", "purpose": "inflate decompress", "category": "compression"},
    "_inflateEnd": {"lib": "zlib", "purpose": "inflate cleanup", "category": "compression"},
    "_inflateReset": {"lib": "zlib", "purpose": "inflate state reset", "category": "compression"},
    "_inflateSync": {"lib": "zlib", "purpose": "inflate sync to next block", "category": "compression"},
    "_inflateSetDictionary": {"lib": "zlib", "purpose": "inflate set dictionary", "category": "compression"},
    "_compress": {"lib": "zlib", "purpose": "one-shot compress", "category": "compression"},
    "_compress2": {"lib": "zlib", "purpose": "one-shot compress with level", "category": "compression"},
    "_compressBound": {"lib": "zlib", "purpose": "compress output bound", "category": "compression"},
    "_uncompress": {"lib": "zlib", "purpose": "one-shot decompress", "category": "compression"},
    "_uncompress2": {"lib": "zlib", "purpose": "one-shot decompress (with src len)", "category": "compression"},
    "_crc32": {"lib": "zlib", "purpose": "CRC-32 checksum", "category": "checksum"},
    "_crc32_combine": {"lib": "zlib", "purpose": "CRC-32 combine", "category": "checksum"},
    "_adler32": {"lib": "zlib", "purpose": "Adler-32 checksum", "category": "checksum"},
    "_adler32_combine": {"lib": "zlib", "purpose": "Adler-32 combine", "category": "checksum"},
    "_gzopen": {"lib": "zlib", "purpose": "gzip file open", "category": "compression"},
    "_gzclose": {"lib": "zlib", "purpose": "gzip file close", "category": "compression"},
    "_gzread": {"lib": "zlib", "purpose": "gzip file read", "category": "compression"},
    "_gzwrite": {"lib": "zlib", "purpose": "gzip file write", "category": "compression"},
    "_gzgets": {"lib": "zlib", "purpose": "gzip read line", "category": "compression"},
    "_gzputs": {"lib": "zlib", "purpose": "gzip write string", "category": "compression"},
    "_gzeof": {"lib": "zlib", "purpose": "gzip end-of-file check", "category": "compression"},
    "_zlibVersion": {"lib": "zlib", "purpose": "zlib version string", "category": "info"},
    "_zlibCompileFlags": {"lib": "zlib", "purpose": "zlib compile-time flags", "category": "info"},
    "_gztell": {"lib": "zlib", "purpose": "gzip file position", "category": "compression"},
    "_gzseek": {"lib": "zlib", "purpose": "gzip file seek", "category": "compression"},
    "_gzflush": {"lib": "zlib", "purpose": "gzip flush output", "category": "compression"},
    "_gzprintf": {"lib": "zlib", "purpose": "gzip formatted write", "category": "compression"},
    "_gzdopen": {"lib": "zlib", "purpose": "gzip open from fd", "category": "compression"},
    "_gzbuffer": {"lib": "zlib", "purpose": "gzip set buffer size", "category": "compression"},
    "_gzoffset": {"lib": "zlib", "purpose": "gzip raw file offset", "category": "compression"},
    "_gzdirect": {"lib": "zlib", "purpose": "gzip direct mode check", "category": "compression"},
    "_gzerror": {"lib": "zlib", "purpose": "gzip error string", "category": "compression"},
    "_gzclearerr": {"lib": "zlib", "purpose": "gzip clear error", "category": "compression"},
    "_crc32_z": {"lib": "zlib", "purpose": "CRC-32 checksum (size_t len)", "category": "checksum"},
    "_adler32_z": {"lib": "zlib", "purpose": "Adler-32 checksum (size_t len)", "category": "checksum"},
    "_inflateCopy": {"lib": "zlib", "purpose": "inflate state copy", "category": "compression"},
    "_inflateGetHeader": {"lib": "zlib", "purpose": "inflate get gzip header", "category": "compression"},
    "_deflateCopy": {"lib": "zlib", "purpose": "deflate state copy", "category": "compression"},
    "_deflateSetHeader": {"lib": "zlib", "purpose": "deflate set gzip header", "category": "compression"},
    "_deflateTune": {"lib": "zlib", "purpose": "deflate tuning parameters", "category": "compression"},
    "_deflatePending": {"lib": "zlib", "purpose": "deflate pending output bytes", "category": "compression"},
    "_deflatePrime": {"lib": "zlib", "purpose": "deflate insert bits", "category": "compression"},
    "_inflateBackInit_": {"lib": "zlib", "purpose": "inflate back init (raw)", "category": "compression"},
    "_inflateBack": {"lib": "zlib", "purpose": "inflate back (callback)", "category": "compression"},
    "_inflateBackEnd": {"lib": "zlib", "purpose": "inflate back cleanup", "category": "compression"},
    "_inflatePrime": {"lib": "zlib", "purpose": "inflate insert bits", "category": "compression"},
    "_inflateMark": {"lib": "zlib", "purpose": "inflate mark position", "category": "compression"},
    "_inflateReset2": {"lib": "zlib", "purpose": "inflate reset with window bits", "category": "compression"},
    "_inflateGetDictionary": {"lib": "zlib", "purpose": "inflate get dictionary", "category": "compression"},
}


# ---------------------------------------------------------------------------
# bzip2 (17 entry) — BZ2 block-sort compression
# Kaynak: signature_db.py satir 1345-1363
# ---------------------------------------------------------------------------
_BZIP2_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_BZ2_bzCompressInit": {"lib": "bzip2", "purpose": "bzip2 compressor init", "category": "compression"},
    "_BZ2_bzCompress": {"lib": "bzip2", "purpose": "bzip2 compress step", "category": "compression"},
    "_BZ2_bzCompressEnd": {"lib": "bzip2", "purpose": "bzip2 compressor cleanup", "category": "compression"},
    "_BZ2_bzDecompressInit": {"lib": "bzip2", "purpose": "bzip2 decompressor init", "category": "compression"},
    "_BZ2_bzDecompress": {"lib": "bzip2", "purpose": "bzip2 decompress step", "category": "compression"},
    "_BZ2_bzDecompressEnd": {"lib": "bzip2", "purpose": "bzip2 decompressor cleanup", "category": "compression"},
    "_BZ2_bzReadOpen": {"lib": "bzip2", "purpose": "bzip2 file read open", "category": "compression"},
    "_BZ2_bzRead": {"lib": "bzip2", "purpose": "bzip2 file read", "category": "compression"},
    "_BZ2_bzReadClose": {"lib": "bzip2", "purpose": "bzip2 file read close", "category": "compression"},
    "_BZ2_bzReadGetUnused": {"lib": "bzip2", "purpose": "bzip2 get unused bytes after read", "category": "compression"},
    "_BZ2_bzWriteOpen": {"lib": "bzip2", "purpose": "bzip2 file write open", "category": "compression"},
    "_BZ2_bzWrite": {"lib": "bzip2", "purpose": "bzip2 file write", "category": "compression"},
    "_BZ2_bzWriteClose": {"lib": "bzip2", "purpose": "bzip2 file write close", "category": "compression"},
    "_BZ2_bzWriteClose64": {"lib": "bzip2", "purpose": "bzip2 file write close (64-bit counts)", "category": "compression"},
    "_BZ2_bzBuffToBuffCompress": {"lib": "bzip2", "purpose": "bzip2 one-shot compress", "category": "compression"},
    "_BZ2_bzBuffToBuffDecompress": {"lib": "bzip2", "purpose": "bzip2 one-shot decompress", "category": "compression"},
    "_BZ2_bzlibVersion": {"lib": "bzip2", "purpose": "bzip2 library version", "category": "info"},
}


# ---------------------------------------------------------------------------
# lz4 (25 entry) — LZ4 block + frame compression
# Kaynak: signature_db.py satir 1370-1396
# ---------------------------------------------------------------------------
_LZ4_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_LZ4_compress_default": {"lib": "lz4", "purpose": "LZ4 compress (default)", "category": "compression"},
    "_LZ4_compress_fast": {"lib": "lz4", "purpose": "LZ4 compress (fast)", "category": "compression"},
    "_LZ4_compress_fast_extState": {"lib": "lz4", "purpose": "LZ4 compress fast with external state", "category": "compression"},
    "_LZ4_compress_HC": {"lib": "lz4", "purpose": "LZ4 high-compression compress", "category": "compression"},
    "_LZ4_compress_HC_extStateHC": {"lib": "lz4", "purpose": "LZ4 HC compress with external state", "category": "compression"},
    "_LZ4_compress_destSize": {"lib": "lz4", "purpose": "LZ4 compress to target size", "category": "compression"},
    "_LZ4_decompress_safe": {"lib": "lz4", "purpose": "LZ4 decompress (safe)", "category": "compression"},
    "_LZ4_decompress_fast": {"lib": "lz4", "purpose": "LZ4 decompress (legacy, unsafe)", "category": "compression"},
    "_LZ4_decompress_safe_partial": {"lib": "lz4", "purpose": "LZ4 partial decompress", "category": "compression"},
    "_LZ4_compressBound": {"lib": "lz4", "purpose": "LZ4 max compressed size", "category": "compression"},
    "_LZ4_versionNumber": {"lib": "lz4", "purpose": "LZ4 version number", "category": "info"},
    "_LZ4_versionString": {"lib": "lz4", "purpose": "LZ4 version string", "category": "info"},
    "_LZ4F_createCompressionContext": {"lib": "lz4", "purpose": "LZ4 frame compression context create", "category": "compression"},
    "_LZ4F_compressBegin": {"lib": "lz4", "purpose": "LZ4 frame compress begin", "category": "compression"},
    "_LZ4F_compressUpdate": {"lib": "lz4", "purpose": "LZ4 frame compress update", "category": "compression"},
    "_LZ4F_compressEnd": {"lib": "lz4", "purpose": "LZ4 frame compress end", "category": "compression"},
    "_LZ4F_flush": {"lib": "lz4", "purpose": "LZ4 frame flush", "category": "compression"},
    "_LZ4F_freeCompressionContext": {"lib": "lz4", "purpose": "LZ4 frame compression context free", "category": "compression"},
    "_LZ4F_createDecompressionContext": {"lib": "lz4", "purpose": "LZ4 frame decompression context create", "category": "compression"},
    "_LZ4F_decompress": {"lib": "lz4", "purpose": "LZ4 frame decompress", "category": "compression"},
    "_LZ4F_freeDecompressionContext": {"lib": "lz4", "purpose": "LZ4 frame decompression context free", "category": "compression"},
    "_LZ4F_compressFrameBound": {"lib": "lz4", "purpose": "LZ4 frame max compressed size", "category": "compression"},
    "_LZ4F_isError": {"lib": "lz4", "purpose": "LZ4 frame error check", "category": "info"},
    "_LZ4F_getErrorName": {"lib": "lz4", "purpose": "LZ4 frame error name", "category": "info"},
    "_LZ4F_getVersion": {"lib": "lz4", "purpose": "LZ4 frame API version", "category": "info"},
}


# ---------------------------------------------------------------------------
# zstd (42 entry) — Zstandard compression API
# Kaynak: signature_db.py satir 1403-1446
# ---------------------------------------------------------------------------
_ZSTD_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_ZSTD_compress": {"lib": "zstd", "purpose": "zstd one-shot compress", "category": "compression"},
    "_ZSTD_decompress": {"lib": "zstd", "purpose": "zstd one-shot decompress", "category": "compression"},
    "_ZSTD_compressBound": {"lib": "zstd", "purpose": "zstd max compressed size", "category": "compression"},
    "_ZSTD_getFrameContentSize": {"lib": "zstd", "purpose": "zstd get decompressed size", "category": "compression"},
    "_ZSTD_findFrameCompressedSize": {"lib": "zstd", "purpose": "zstd find compressed frame size", "category": "compression"},
    "_ZSTD_createCCtx": {"lib": "zstd", "purpose": "zstd compression context create", "category": "compression"},
    "_ZSTD_freeCCtx": {"lib": "zstd", "purpose": "zstd compression context free", "category": "compression"},
    "_ZSTD_compressCCtx": {"lib": "zstd", "purpose": "zstd compress with context", "category": "compression"},
    "_ZSTD_compress2": {"lib": "zstd", "purpose": "zstd compress with parameters", "category": "compression"},
    "_ZSTD_CCtx_setParameter": {"lib": "zstd", "purpose": "zstd set compression parameter", "category": "compression"},
    "_ZSTD_CCtx_setPledgedSrcSize": {"lib": "zstd", "purpose": "zstd set pledged source size", "category": "compression"},
    "_ZSTD_createDCtx": {"lib": "zstd", "purpose": "zstd decompression context create", "category": "compression"},
    "_ZSTD_freeDCtx": {"lib": "zstd", "purpose": "zstd decompression context free", "category": "compression"},
    "_ZSTD_decompressDCtx": {"lib": "zstd", "purpose": "zstd decompress with context", "category": "compression"},
    "_ZSTD_DCtx_setParameter": {"lib": "zstd", "purpose": "zstd set decompression parameter", "category": "compression"},
    "_ZSTD_createCStream": {"lib": "zstd", "purpose": "zstd compression stream create", "category": "compression"},
    "_ZSTD_freeCStream": {"lib": "zstd", "purpose": "zstd compression stream free", "category": "compression"},
    "_ZSTD_initCStream": {"lib": "zstd", "purpose": "zstd init compression stream", "category": "compression"},
    "_ZSTD_compressStream": {"lib": "zstd", "purpose": "zstd streaming compress", "category": "compression"},
    "_ZSTD_compressStream2": {"lib": "zstd", "purpose": "zstd streaming compress (v2)", "category": "compression"},
    "_ZSTD_flushStream": {"lib": "zstd", "purpose": "zstd flush compression stream", "category": "compression"},
    "_ZSTD_endStream": {"lib": "zstd", "purpose": "zstd end compression stream", "category": "compression"},
    "_ZSTD_createDStream": {"lib": "zstd", "purpose": "zstd decompression stream create", "category": "compression"},
    "_ZSTD_freeDStream": {"lib": "zstd", "purpose": "zstd decompression stream free", "category": "compression"},
    "_ZSTD_initDStream": {"lib": "zstd", "purpose": "zstd init decompression stream", "category": "compression"},
    "_ZSTD_decompressStream": {"lib": "zstd", "purpose": "zstd streaming decompress", "category": "compression"},
    "_ZSTD_compress_usingDict": {"lib": "zstd", "purpose": "zstd compress with dictionary", "category": "compression"},
    "_ZSTD_decompress_usingDict": {"lib": "zstd", "purpose": "zstd decompress with dictionary", "category": "compression"},
    "_ZSTD_createCDict": {"lib": "zstd", "purpose": "zstd compiled compression dict", "category": "compression"},
    "_ZSTD_freeCDict": {"lib": "zstd", "purpose": "zstd free compression dict", "category": "compression"},
    "_ZSTD_compress_usingCDict": {"lib": "zstd", "purpose": "zstd compress with compiled dict", "category": "compression"},
    "_ZSTD_createDDict": {"lib": "zstd", "purpose": "zstd compiled decompression dict", "category": "compression"},
    "_ZSTD_freeDDict": {"lib": "zstd", "purpose": "zstd free decompression dict", "category": "compression"},
    "_ZSTD_decompress_usingDDict": {"lib": "zstd", "purpose": "zstd decompress with compiled dict", "category": "compression"},
    "_ZSTD_versionNumber": {"lib": "zstd", "purpose": "zstd version number", "category": "info"},
    "_ZSTD_versionString": {"lib": "zstd", "purpose": "zstd version string", "category": "info"},
    "_ZSTD_isError": {"lib": "zstd", "purpose": "zstd error code check", "category": "info"},
    "_ZSTD_getErrorName": {"lib": "zstd", "purpose": "zstd error name string", "category": "info"},
    "_ZSTD_getErrorCode": {"lib": "zstd", "purpose": "zstd error code from result", "category": "info"},
    "_ZSTD_maxCLevel": {"lib": "zstd", "purpose": "zstd max compression level", "category": "info"},
    "_ZSTD_minCLevel": {"lib": "zstd", "purpose": "zstd min compression level", "category": "info"},
    "_ZSTD_defaultCLevel": {"lib": "zstd", "purpose": "zstd default compression level", "category": "info"},
}


# ---------------------------------------------------------------------------
# compression_ext (72 entry) — xz/lzma, Snappy, LZO, Brotli, libarchive, minizip
# Kaynak: signature_db.py satir 6218-6302
# ---------------------------------------------------------------------------
_COMPRESSION_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- XZ / LZMA ---
    "lzma_stream_decoder": {"lib": "liblzma", "purpose": "initialize LZMA stream decoder", "category": "compression"},
    "lzma_stream_encoder": {"lib": "liblzma", "purpose": "initialize LZMA stream encoder", "category": "compression"},
    "lzma_alone_decoder": {"lib": "liblzma", "purpose": "initialize legacy LZMA alone decoder", "category": "compression"},
    "lzma_alone_encoder": {"lib": "liblzma", "purpose": "initialize legacy LZMA alone encoder", "category": "compression"},
    "lzma_code": {"lib": "liblzma", "purpose": "encode/decode data block", "category": "compression"},
    "lzma_end": {"lib": "liblzma", "purpose": "free LZMA stream", "category": "compression"},
    "lzma_easy_encoder": {"lib": "liblzma", "purpose": "initialize easy xz encoder", "category": "compression"},
    "lzma_easy_buffer_encode": {"lib": "liblzma", "purpose": "one-shot xz encode", "category": "compression"},
    "lzma_stream_buffer_decode": {"lib": "liblzma", "purpose": "one-shot xz decode", "category": "compression"},
    "lzma_auto_decoder": {"lib": "liblzma", "purpose": "auto-detect xz/lzma format and decode", "category": "compression"},
    "lzma_crc32": {"lib": "liblzma", "purpose": "LZMA CRC-32 calculation", "category": "compression"},
    "lzma_crc64": {"lib": "liblzma", "purpose": "LZMA CRC-64 calculation", "category": "compression"},

    # --- Snappy ---
    "snappy_compress": {"lib": "snappy", "purpose": "compress data with Snappy", "category": "compression"},
    "snappy_uncompress": {"lib": "snappy", "purpose": "decompress Snappy data", "category": "compression"},
    "snappy_max_compressed_length": {"lib": "snappy", "purpose": "get max compressed size", "category": "compression"},
    "snappy_uncompressed_length": {"lib": "snappy", "purpose": "get uncompressed size from header", "category": "compression"},
    "snappy_validate_compressed_buffer": {"lib": "snappy", "purpose": "validate Snappy compressed data", "category": "compression"},

    # --- LZO ---
    "lzo1x_1_compress": {"lib": "lzo", "purpose": "LZO1X-1 compress (fast)", "category": "compression"},
    "lzo1x_decompress": {"lib": "lzo", "purpose": "LZO1X decompress", "category": "compression"},
    "lzo1x_decompress_safe": {"lib": "lzo", "purpose": "LZO1X safe decompress (bounds check)", "category": "compression"},
    "lzo_init": {"lib": "lzo", "purpose": "initialize LZO library", "category": "compression"},

    # --- Brotli ---
    "BrotliEncoderCompress": {"lib": "brotli", "purpose": "one-shot Brotli compress", "category": "compression"},
    "BrotliDecoderDecompress": {"lib": "brotli", "purpose": "one-shot Brotli decompress", "category": "compression"},
    "BrotliEncoderCreateInstance": {"lib": "brotli", "purpose": "create Brotli encoder", "category": "compression"},
    "BrotliEncoderCompressStream": {"lib": "brotli", "purpose": "streaming Brotli compress", "category": "compression"},
    "BrotliEncoderDestroyInstance": {"lib": "brotli", "purpose": "destroy Brotli encoder", "category": "compression"},
    "BrotliDecoderCreateInstance": {"lib": "brotli", "purpose": "create Brotli decoder", "category": "compression"},
    "BrotliDecoderDecompressStream": {"lib": "brotli", "purpose": "streaming Brotli decompress", "category": "compression"},
    "BrotliDecoderDestroyInstance": {"lib": "brotli", "purpose": "destroy Brotli decoder", "category": "compression"},

    # --- libarchive ---
    "archive_read_new": {"lib": "libarchive", "purpose": "create archive reader", "category": "archive"},
    "archive_read_support_format_all": {"lib": "libarchive", "purpose": "enable all archive formats", "category": "archive"},
    "archive_read_support_filter_all": {"lib": "libarchive", "purpose": "enable all decompression filters", "category": "archive"},
    "archive_read_open_filename": {"lib": "libarchive", "purpose": "open archive file for reading", "category": "archive"},
    "archive_read_next_header": {"lib": "libarchive", "purpose": "read next archive entry header", "category": "archive"},
    "archive_read_data": {"lib": "libarchive", "purpose": "read entry data", "category": "archive"},
    "archive_read_data_block": {"lib": "libarchive", "purpose": "read entry data block", "category": "archive"},
    "archive_read_close": {"lib": "libarchive", "purpose": "close archive reader", "category": "archive"},
    "archive_read_free": {"lib": "libarchive", "purpose": "free archive reader", "category": "archive"},
    "archive_write_new": {"lib": "libarchive", "purpose": "create archive writer", "category": "archive"},
    "archive_write_set_format_zip": {"lib": "libarchive", "purpose": "set ZIP output format", "category": "archive"},
    "archive_write_set_format_pax_restricted": {"lib": "libarchive", "purpose": "set tar (pax restricted) format", "category": "archive"},
    "archive_write_add_filter_gzip": {"lib": "libarchive", "purpose": "add gzip compression filter", "category": "archive"},
    "archive_write_add_filter_xz": {"lib": "libarchive", "purpose": "add xz compression filter", "category": "archive"},
    "archive_write_open_filename": {"lib": "libarchive", "purpose": "open archive file for writing", "category": "archive"},
    "archive_write_header": {"lib": "libarchive", "purpose": "write archive entry header", "category": "archive"},
    "archive_write_data": {"lib": "libarchive", "purpose": "write entry data", "category": "archive"},
    "archive_write_close": {"lib": "libarchive", "purpose": "close archive writer", "category": "archive"},
    "archive_write_free": {"lib": "libarchive", "purpose": "free archive writer", "category": "archive"},
    "archive_entry_new": {"lib": "libarchive", "purpose": "create new archive entry", "category": "archive"},
    "archive_entry_free": {"lib": "libarchive", "purpose": "free archive entry", "category": "archive"},
    "archive_entry_pathname": {"lib": "libarchive", "purpose": "get entry pathname", "category": "archive"},
    "archive_entry_set_pathname": {"lib": "libarchive", "purpose": "set entry pathname", "category": "archive"},
    "archive_entry_size": {"lib": "libarchive", "purpose": "get entry file size", "category": "archive"},
    "archive_entry_set_size": {"lib": "libarchive", "purpose": "set entry file size", "category": "archive"},
    "archive_entry_filetype": {"lib": "libarchive", "purpose": "get entry file type", "category": "archive"},
    "archive_entry_set_filetype": {"lib": "libarchive", "purpose": "set entry file type", "category": "archive"},
    "archive_entry_perm": {"lib": "libarchive", "purpose": "get entry permissions", "category": "archive"},
    "archive_entry_set_perm": {"lib": "libarchive", "purpose": "set entry permissions", "category": "archive"},
    "archive_error_string": {"lib": "libarchive", "purpose": "get error description string", "category": "archive"},

    # --- minizip ---
    "zipOpen": {"lib": "minizip", "purpose": "open ZIP file for writing", "category": "archive"},
    "zipOpenNewFileInZip": {"lib": "minizip", "purpose": "start new file in ZIP", "category": "archive"},
    "zipWriteInFileInZip": {"lib": "minizip", "purpose": "write data to file in ZIP", "category": "archive"},
    "zipCloseFileInZip": {"lib": "minizip", "purpose": "close current file in ZIP", "category": "archive"},
    "zipClose": {"lib": "minizip", "purpose": "close ZIP file", "category": "archive"},
    "unzOpen": {"lib": "minizip", "purpose": "open ZIP file for reading", "category": "archive"},
    "unzGoToFirstFile": {"lib": "minizip", "purpose": "go to first file in ZIP", "category": "archive"},
    "unzGoToNextFile": {"lib": "minizip", "purpose": "go to next file in ZIP", "category": "archive"},
    "unzOpenCurrentFile": {"lib": "minizip", "purpose": "open current file for reading", "category": "archive"},
    "unzReadCurrentFile": {"lib": "minizip", "purpose": "read from current file in ZIP", "category": "archive"},
    "unzCloseCurrentFile": {"lib": "minizip", "purpose": "close current file in ZIP", "category": "archive"},
    "unzClose": {"lib": "minizip", "purpose": "close ZIP reader", "category": "archive"},
    "unzGetCurrentFileInfo": {"lib": "minizip", "purpose": "get info about current file in ZIP", "category": "archive"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — sigdb_builtin.get_category("compression") bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur
# (ornek: "zlib_signatures" <-> _ZLIB_SIGNATURES).
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "zlib_signatures": _ZLIB_SIGNATURES_DATA,
    "bzip2_signatures": _BZIP2_SIGNATURES_DATA,
    "lz4_signatures": _LZ4_SIGNATURES_DATA,
    "zstd_signatures": _ZSTD_SIGNATURES_DATA,
    "compression_ext_signatures": _COMPRESSION_EXT_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
