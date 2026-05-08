"""Graphics & media signatures — sig_db v1.13 Dalga 2 migrasyonu (ADR 0007 A8).

Kaynak: karadul/analyzers/signature_db.py
  - _OPENGL_METAL_GPU_SIGNATURES   -> opengl_metal_gpu_signatures   (57 entry)
  - _COREGRAPHICS_SIGNATURES        -> coregraphics_signatures        (34 entry)
  - _COREIMAGE_COREML_SIGNATURES    -> coreimage_coreml_signatures    (10 entry)
  - _IMAGE_LIB_SIGNATURES           -> image_lib_signatures           (51 entry)
  - _AUDIO_SIGNATURES               -> audio_signatures               (45 entry)
  - _FFMPEG_SIGNATURES              -> ffmpeg_signatures              (34 entry)
  - _SDL2_SIGNATURES                -> sdl2_signatures                (31 entry)
  - _GRAPHICS_EXT_SIGNATURES        -> graphics_ext_signatures        (100 entry)

Toplam: 362 signature (8 dict).

ADR 0007/0008 Tip A yumusak override pattern'i: signature_db.py'de orijinal
dict govdeleri SILINMEDI; runtime'da bu modulden gelen veriyle yeniden
baglanir. Rollback icin override blogu silinince (try/except ImportError)
eski inline veri otomatik geri devreye girer. Birebir parite garanti
(AST literal_eval ile dogrulanir; bkz. tests/test_sigdb_graphics_media_migration.py).

Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur:
  ``opengl_metal_gpu_signatures``    <-> ``_OPENGL_METAL_GPU_SIGNATURES``
  ``coregraphics_signatures``        <-> ``_COREGRAPHICS_SIGNATURES``
  ``coreimage_coreml_signatures``    <-> ``_COREIMAGE_COREML_SIGNATURES``
  ``image_lib_signatures``           <-> ``_IMAGE_LIB_SIGNATURES``
  ``audio_signatures``               <-> ``_AUDIO_SIGNATURES``
  ``ffmpeg_signatures``              <-> ``_FFMPEG_SIGNATURES``
  ``sdl2_signatures``                <-> ``_SDL2_SIGNATURES``
  ``graphics_ext_signatures``        <-> ``_GRAPHICS_EXT_SIGNATURES``
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# OpenGL / Metal / CoreVideo / Apple GPU (57 entry).
# # Kaynak: signature_db.py _OPENGL_METAL_GPU_SIGNATURES.
# ---------------------------------------------------------------------------
_OPENGL_METAL_GPU_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_glGenBuffers": {"lib": "OpenGL", "purpose": "generate buffer object names", "category": "graphics"},
    "_glBindBuffer": {"lib": "OpenGL", "purpose": "bind a named buffer object", "category": "graphics"},
    "_glBufferData": {"lib": "OpenGL", "purpose": "create/initialize buffer data store", "category": "graphics"},
    "_glDeleteBuffers": {"lib": "OpenGL", "purpose": "delete named buffer objects", "category": "graphics"},
    "_glGenTextures": {"lib": "OpenGL", "purpose": "generate texture names", "category": "graphics"},
    "_glBindTexture": {"lib": "OpenGL", "purpose": "bind a named texture", "category": "graphics"},
    "_glTexImage2D": {"lib": "OpenGL", "purpose": "specify 2D texture image", "category": "graphics"},
    "_glTexParameteri": {"lib": "OpenGL", "purpose": "set texture parameter (integer)", "category": "graphics"},
    "_glDeleteTextures": {"lib": "OpenGL", "purpose": "delete named textures", "category": "graphics"},
    "_glCreateShader": {"lib": "OpenGL", "purpose": "create a shader object", "category": "graphics"},
    "_glShaderSource": {"lib": "OpenGL", "purpose": "set shader source code", "category": "graphics"},
    "_glCompileShader": {"lib": "OpenGL", "purpose": "compile a shader object", "category": "graphics"},
    "_glDeleteShader": {"lib": "OpenGL", "purpose": "delete a shader object", "category": "graphics"},
    "_glCreateProgram": {"lib": "OpenGL", "purpose": "create a program object", "category": "graphics"},
    "_glAttachShader": {"lib": "OpenGL", "purpose": "attach shader to program", "category": "graphics"},
    "_glLinkProgram": {"lib": "OpenGL", "purpose": "link a program object", "category": "graphics"},
    "_glUseProgram": {"lib": "OpenGL", "purpose": "install a program object as current", "category": "graphics"},
    "_glDeleteProgram": {"lib": "OpenGL", "purpose": "delete a program object", "category": "graphics"},
    "_glGetUniformLocation": {"lib": "OpenGL", "purpose": "get uniform variable location", "category": "graphics"},
    "_glUniform1f": {"lib": "OpenGL", "purpose": "set float uniform value", "category": "graphics"},
    "_glUniform1i": {"lib": "OpenGL", "purpose": "set integer uniform value", "category": "graphics"},
    "_glUniform2f": {"lib": "OpenGL", "purpose": "set vec2 uniform value", "category": "graphics"},
    "_glUniform3f": {"lib": "OpenGL", "purpose": "set vec3 uniform value", "category": "graphics"},
    "_glUniform4f": {"lib": "OpenGL", "purpose": "set vec4 uniform value", "category": "graphics"},
    "_glUniformMatrix4fv": {"lib": "OpenGL", "purpose": "set 4x4 matrix uniform value", "category": "graphics"},
    "_glVertexAttribPointer": {"lib": "OpenGL", "purpose": "define vertex attribute data layout", "category": "graphics"},
    "_glEnableVertexAttribArray": {"lib": "OpenGL", "purpose": "enable vertex attribute array", "category": "graphics"},
    "_glDisableVertexAttribArray": {"lib": "OpenGL", "purpose": "disable vertex attribute array", "category": "graphics"},
    "_glDrawArrays": {"lib": "OpenGL", "purpose": "render primitives from array data", "category": "graphics"},
    "_glDrawElements": {"lib": "OpenGL", "purpose": "render indexed primitives", "category": "graphics"},
    "_glDrawArraysInstanced": {"lib": "OpenGL", "purpose": "draw multiple instances of primitives", "category": "graphics"},
    "_glEnable": {"lib": "OpenGL", "purpose": "enable server-side GL capability", "category": "graphics"},
    "_glDisable": {"lib": "OpenGL", "purpose": "disable server-side GL capability", "category": "graphics"},
    "_glBlendFunc": {"lib": "OpenGL", "purpose": "specify pixel blending factors", "category": "graphics"},
    "_glDepthFunc": {"lib": "OpenGL", "purpose": "specify depth comparison function", "category": "graphics"},
    "_glCullFace": {"lib": "OpenGL", "purpose": "specify face culling mode", "category": "graphics"},
    "_glViewport": {"lib": "OpenGL", "purpose": "set the viewport", "category": "graphics"},
    "_glClear": {"lib": "OpenGL", "purpose": "clear buffers to preset values", "category": "graphics"},
    "_glClearColor": {"lib": "OpenGL", "purpose": "specify clear values for color buffer", "category": "graphics"},
    "_glFlush": {"lib": "OpenGL", "purpose": "force execution of GL commands", "category": "graphics"},
    "_glFinish": {"lib": "OpenGL", "purpose": "block until all GL execution is complete", "category": "graphics"},
    "_glGenFramebuffers": {"lib": "OpenGL", "purpose": "generate framebuffer object names", "category": "graphics"},
    "_glBindFramebuffer": {"lib": "OpenGL", "purpose": "bind a framebuffer object", "category": "graphics"},
    "_glFramebufferTexture2D": {"lib": "OpenGL", "purpose": "attach texture to framebuffer", "category": "graphics"},
    "_glCheckFramebufferStatus": {"lib": "OpenGL", "purpose": "check framebuffer completeness", "category": "graphics"},
    "_glGetError": {"lib": "OpenGL", "purpose": "return error information", "category": "graphics"},
    "_glGetString": {"lib": "OpenGL", "purpose": "return a string describing GL", "category": "graphics"},
    "_glGetIntegerv": {"lib": "OpenGL", "purpose": "return integer GL parameter value", "category": "graphics"},
    "_MTLCreateSystemDefaultDevice": {"lib": "Metal", "purpose": "create default Metal GPU device", "category": "graphics"},
    "_newCommandQueue": {"lib": "Metal", "purpose": "create Metal command queue", "category": "graphics"},
    "_newRenderPipelineStateWithDescriptor": {"lib": "Metal", "purpose": "create Metal render pipeline state", "category": "graphics"},
    "_newBufferWithBytes": {"lib": "Metal", "purpose": "create Metal buffer with initial data", "category": "graphics"},
    "_newTextureWithDescriptor": {"lib": "Metal", "purpose": "create Metal texture object", "category": "graphics"},
    "_newLibraryWithSource": {"lib": "Metal", "purpose": "create Metal shader library from source", "category": "graphics"},
    "_CVDisplayLinkCreateWithActiveCGDisplays": {"lib": "CoreVideo", "purpose": "create display link for active displays", "category": "graphics"},
    "_CVDisplayLinkStart": {"lib": "CoreVideo", "purpose": "start display link callbacks", "category": "graphics"},
    "_CVDisplayLinkStop": {"lib": "CoreVideo", "purpose": "stop display link callbacks", "category": "graphics"},
}


# ---------------------------------------------------------------------------
# CoreGraphics / Quartz 2D bitmap context, path, color (34 entry).
# # Kaynak: signature_db.py _COREGRAPHICS_SIGNATURES.
# ---------------------------------------------------------------------------
_COREGRAPHICS_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_CGContextRef": {"lib": "CoreGraphics", "purpose": "graphics context reference type", "category": "graphics"},
    "_CGImageRef": {"lib": "CoreGraphics", "purpose": "image reference type", "category": "graphics"},
    "_CGColorSpaceRef": {"lib": "CoreGraphics", "purpose": "color space reference type", "category": "graphics"},
    "_CGBitmapContextCreate": {"lib": "CoreGraphics", "purpose": "create bitmap graphics context", "category": "graphics"},
    "_CGBitmapContextCreateImage": {"lib": "CoreGraphics", "purpose": "create image from bitmap context", "category": "graphics"},
    "_CGContextRelease": {"lib": "CoreGraphics", "purpose": "release graphics context", "category": "graphics"},
    "_CGContextSetFillColorWithColor": {"lib": "CoreGraphics", "purpose": "set fill color", "category": "graphics"},
    "_CGContextFillRect": {"lib": "CoreGraphics", "purpose": "fill a rectangle", "category": "graphics"},
    "_CGContextStrokeRect": {"lib": "CoreGraphics", "purpose": "stroke a rectangle outline", "category": "graphics"},
    "_CGContextDrawImage": {"lib": "CoreGraphics", "purpose": "draw image into context", "category": "graphics"},
    "_CGContextDrawPath": {"lib": "CoreGraphics", "purpose": "draw current path", "category": "graphics"},
    "_CGContextAddPath": {"lib": "CoreGraphics", "purpose": "add path to context", "category": "graphics"},
    "_CGContextMoveToPoint": {"lib": "CoreGraphics", "purpose": "begin new subpath at point", "category": "graphics"},
    "_CGContextAddLineToPoint": {"lib": "CoreGraphics", "purpose": "add line segment to path", "category": "graphics"},
    "_CGContextAddCurveToPoint": {"lib": "CoreGraphics", "purpose": "add cubic Bezier curve to path", "category": "graphics"},
    "_CGContextSaveGState": {"lib": "CoreGraphics", "purpose": "save current graphics state", "category": "graphics"},
    "_CGContextRestoreGState": {"lib": "CoreGraphics", "purpose": "restore saved graphics state", "category": "graphics"},
    "_CGContextTranslateCTM": {"lib": "CoreGraphics", "purpose": "translate current transform matrix", "category": "graphics"},
    "_CGContextScaleCTM": {"lib": "CoreGraphics", "purpose": "scale current transform matrix", "category": "graphics"},
    "_CGContextRotateCTM": {"lib": "CoreGraphics", "purpose": "rotate current transform matrix", "category": "graphics"},
    "_CGPathCreateMutable": {"lib": "CoreGraphics", "purpose": "create mutable graphics path", "category": "graphics"},
    "_CGPathAddRect": {"lib": "CoreGraphics", "purpose": "add rectangle to path", "category": "graphics"},
    "_CGPathAddEllipseInRect": {"lib": "CoreGraphics", "purpose": "add ellipse to path", "category": "graphics"},
    "_CGPathRelease": {"lib": "CoreGraphics", "purpose": "release graphics path", "category": "graphics"},
    "_CGColorSpaceCreateDeviceRGB": {"lib": "CoreGraphics", "purpose": "create device RGB color space", "category": "graphics"},
    "_CGColorSpaceCreateDeviceGray": {"lib": "CoreGraphics", "purpose": "create device gray color space", "category": "graphics"},
    "_CGColorSpaceRelease": {"lib": "CoreGraphics", "purpose": "release color space", "category": "graphics"},
    "_CGImageCreate": {"lib": "CoreGraphics", "purpose": "create image from bitmap data", "category": "graphics"},
    "_CGImageRelease": {"lib": "CoreGraphics", "purpose": "release image", "category": "graphics"},
    "_CGImageGetWidth": {"lib": "CoreGraphics", "purpose": "get image width in pixels", "category": "graphics"},
    "_CGImageGetHeight": {"lib": "CoreGraphics", "purpose": "get image height in pixels", "category": "graphics"},
    "_CGRectMake": {"lib": "CoreGraphics", "purpose": "construct CGRect from components", "category": "graphics"},
    "_CGPointMake": {"lib": "CoreGraphics", "purpose": "construct CGPoint from components", "category": "graphics"},
    "_CGSizeMake": {"lib": "CoreGraphics", "purpose": "construct CGSize from components", "category": "graphics"},
}


# ---------------------------------------------------------------------------
# CoreImage filter + CoreML inference (10 entry).
# # Kaynak: signature_db.py _COREIMAGE_COREML_SIGNATURES.
# ---------------------------------------------------------------------------
_COREIMAGE_COREML_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_CIFilter": {"lib": "CoreImage", "purpose": "image processing filter object", "category": "image_processing"},
    "_CIImage": {"lib": "CoreImage", "purpose": "immutable image representation", "category": "image_processing"},
    "_CIContext": {"lib": "CoreImage", "purpose": "image processing evaluation context", "category": "image_processing"},
    "_CIFilter_filterWithName": {"lib": "CoreImage", "purpose": "create filter by name", "category": "image_processing"},
    "_CIContext_render": {"lib": "CoreImage", "purpose": "render filtered image to output", "category": "image_processing"},
    "_MLModel": {"lib": "CoreML", "purpose": "machine learning model object", "category": "ml"},
    "_MLPrediction": {"lib": "CoreML", "purpose": "ML prediction result", "category": "ml"},
    "_MLFeatureValue": {"lib": "CoreML", "purpose": "ML feature value wrapper", "category": "ml"},
    "_CoreML_loadModel": {"lib": "CoreML", "purpose": "load compiled ML model", "category": "ml"},
    "_CoreML_prediction": {"lib": "CoreML", "purpose": "run ML model prediction", "category": "ml"},
}


# ---------------------------------------------------------------------------
# libpng / libjpeg / libwebp / ImageIO (51 entry).
# # Kaynak: signature_db.py _IMAGE_LIB_SIGNATURES.
# ---------------------------------------------------------------------------
_IMAGE_LIB_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # libpng
    "_png_create_read_struct": {"lib": "libpng", "purpose": "allocate PNG read structure", "category": "image"},
    "_png_create_write_struct": {"lib": "libpng", "purpose": "allocate PNG write structure", "category": "image"},
    "_png_destroy_read_struct": {"lib": "libpng", "purpose": "free PNG read structure", "category": "image"},
    "_png_destroy_write_struct": {"lib": "libpng", "purpose": "free PNG write structure", "category": "image"},
    "_png_init_io": {"lib": "libpng", "purpose": "initialize PNG I/O with FILE pointer", "category": "image"},
    "_png_set_sig_bytes": {"lib": "libpng", "purpose": "set number of signature bytes already read", "category": "image"},
    "_png_read_info": {"lib": "libpng", "purpose": "read PNG file info chunks", "category": "image"},
    "_png_read_image": {"lib": "libpng", "purpose": "read entire PNG image into memory", "category": "image"},
    "_png_read_end": {"lib": "libpng", "purpose": "finish reading PNG file", "category": "image"},
    "_png_write_info": {"lib": "libpng", "purpose": "write PNG info chunks", "category": "image"},
    "_png_write_image": {"lib": "libpng", "purpose": "write entire PNG image", "category": "image"},
    "_png_write_end": {"lib": "libpng", "purpose": "finish writing PNG file", "category": "image"},
    "_png_get_image_width": {"lib": "libpng", "purpose": "get image width from info struct", "category": "image"},
    "_png_get_image_height": {"lib": "libpng", "purpose": "get image height from info struct", "category": "image"},
    "_png_get_bit_depth": {"lib": "libpng", "purpose": "get image bit depth", "category": "image"},
    "_png_get_color_type": {"lib": "libpng", "purpose": "get image color type", "category": "image"},
    "_png_set_IHDR": {"lib": "libpng", "purpose": "set image header parameters", "category": "image"},
    "_png_set_rows": {"lib": "libpng", "purpose": "set row pointers for writing", "category": "image"},
    "_png_malloc": {"lib": "libpng", "purpose": "allocate memory via PNG allocator", "category": "image"},
    "_png_free": {"lib": "libpng", "purpose": "free memory via PNG allocator", "category": "image"},
    # libjpeg
    "_jpeg_create_compress": {"lib": "libjpeg", "purpose": "allocate JPEG compression struct", "category": "image"},
    "_jpeg_create_decompress": {"lib": "libjpeg", "purpose": "allocate JPEG decompression struct", "category": "image"},
    "_jpeg_destroy_compress": {"lib": "libjpeg", "purpose": "free JPEG compression struct", "category": "image"},
    "_jpeg_destroy_decompress": {"lib": "libjpeg", "purpose": "free JPEG decompression struct", "category": "image"},
    "_jpeg_stdio_dest": {"lib": "libjpeg", "purpose": "set FILE as JPEG output destination", "category": "image"},
    "_jpeg_stdio_src": {"lib": "libjpeg", "purpose": "set FILE as JPEG input source", "category": "image"},
    "_jpeg_mem_dest": {"lib": "libjpeg", "purpose": "set memory buffer as JPEG output", "category": "image"},
    "_jpeg_mem_src": {"lib": "libjpeg", "purpose": "set memory buffer as JPEG input", "category": "image"},
    "_jpeg_set_defaults": {"lib": "libjpeg", "purpose": "set default JPEG compression parameters", "category": "image"},
    "_jpeg_set_quality": {"lib": "libjpeg", "purpose": "set JPEG output quality (0-100)", "category": "image"},
    "_jpeg_start_compress": {"lib": "libjpeg", "purpose": "start JPEG compression", "category": "image"},
    "_jpeg_write_scanlines": {"lib": "libjpeg", "purpose": "write scanlines during compression", "category": "image"},
    "_jpeg_finish_compress": {"lib": "libjpeg", "purpose": "finish JPEG compression", "category": "image"},
    "_jpeg_read_header": {"lib": "libjpeg", "purpose": "read JPEG file header", "category": "image"},
    "_jpeg_start_decompress": {"lib": "libjpeg", "purpose": "start JPEG decompression", "category": "image"},
    "_jpeg_read_scanlines": {"lib": "libjpeg", "purpose": "read scanlines during decompression", "category": "image"},
    "_jpeg_finish_decompress": {"lib": "libjpeg", "purpose": "finish JPEG decompression", "category": "image"},
    # libwebp
    "_WebPDecodeRGBA": {"lib": "libwebp", "purpose": "decode WebP image to RGBA", "category": "image"},
    "_WebPDecodeRGB": {"lib": "libwebp", "purpose": "decode WebP image to RGB", "category": "image"},
    "_WebPDecodeBGRA": {"lib": "libwebp", "purpose": "decode WebP image to BGRA", "category": "image"},
    "_WebPEncodeRGBA": {"lib": "libwebp", "purpose": "encode RGBA data as WebP", "category": "image"},
    "_WebPEncodeRGB": {"lib": "libwebp", "purpose": "encode RGB data as WebP", "category": "image"},
    "_WebPEncodeLosslessRGBA": {"lib": "libwebp", "purpose": "encode RGBA as lossless WebP", "category": "image"},
    "_WebPGetInfo": {"lib": "libwebp", "purpose": "get WebP image dimensions without decoding", "category": "image"},
    "_WebPFree": {"lib": "libwebp", "purpose": "free WebP allocated memory", "category": "image"},
    # ImageIO (macOS)
    "_CGImageSourceCreateWithData": {"lib": "ImageIO", "purpose": "create image source from data", "category": "image"},
    "_CGImageSourceCreateWithURL": {"lib": "ImageIO", "purpose": "create image source from URL", "category": "image"},
    "_CGImageSourceCreateImageAtIndex": {"lib": "ImageIO", "purpose": "create image from source at index", "category": "image"},
    "_CGImageDestinationCreateWithURL": {"lib": "ImageIO", "purpose": "create image destination for URL", "category": "image"},
    "_CGImageDestinationAddImage": {"lib": "ImageIO", "purpose": "add image to destination", "category": "image"},
    "_CGImageDestinationFinalize": {"lib": "ImageIO", "purpose": "finalize and write image destination", "category": "image"},
}


# ---------------------------------------------------------------------------
# CoreAudio / AVFoundation / OpenAL audio API (45 entry).
# # Kaynak: signature_db.py _AUDIO_SIGNATURES.
# ---------------------------------------------------------------------------
_AUDIO_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # CoreAudio: Audio Component
    "_AudioComponentFindNext": {"lib": "CoreAudio", "purpose": "find next matching audio component", "category": "audio"},
    "_AudioComponentInstanceNew": {"lib": "CoreAudio", "purpose": "create audio component instance", "category": "audio"},
    "_AudioComponentInstanceDispose": {"lib": "CoreAudio", "purpose": "dispose audio component instance", "category": "audio"},
    # CoreAudio: Audio Unit
    "_AudioUnitInitialize": {"lib": "CoreAudio", "purpose": "initialize audio unit", "category": "audio"},
    "_AudioUnitUninitialize": {"lib": "CoreAudio", "purpose": "uninitialize audio unit", "category": "audio"},
    "_AudioUnitRender": {"lib": "CoreAudio", "purpose": "render audio unit output", "category": "audio"},
    "_AudioOutputUnitStart": {"lib": "CoreAudio", "purpose": "start audio output unit", "category": "audio"},
    "_AudioOutputUnitStop": {"lib": "CoreAudio", "purpose": "stop audio output unit", "category": "audio"},
    # CoreAudio: Audio Queue
    "_AudioQueueNewOutput": {"lib": "CoreAudio", "purpose": "create new output audio queue", "category": "audio"},
    "_AudioQueueNewInput": {"lib": "CoreAudio", "purpose": "create new input audio queue", "category": "audio"},
    "_AudioQueueStart": {"lib": "CoreAudio", "purpose": "start audio queue processing", "category": "audio"},
    "_AudioQueueStop": {"lib": "CoreAudio", "purpose": "stop audio queue processing", "category": "audio"},
    "_AudioQueueDispose": {"lib": "CoreAudio", "purpose": "dispose audio queue", "category": "audio"},
    "_AudioQueueAllocateBuffer": {"lib": "CoreAudio", "purpose": "allocate audio queue buffer", "category": "audio"},
    "_AudioQueueEnqueueBuffer": {"lib": "CoreAudio", "purpose": "enqueue buffer for audio queue", "category": "audio"},
    "_AudioQueueFreeBuffer": {"lib": "CoreAudio", "purpose": "free audio queue buffer", "category": "audio"},
    # CoreAudio: Audio File
    "_AudioFileOpenURL": {"lib": "CoreAudio", "purpose": "open audio file from URL", "category": "audio"},
    "_AudioFileClose": {"lib": "CoreAudio", "purpose": "close audio file", "category": "audio"},
    "_AudioFileReadPacketData": {"lib": "CoreAudio", "purpose": "read packet data from audio file", "category": "audio"},
    # CoreAudio: Extended Audio File
    "_ExtAudioFileOpenURL": {"lib": "CoreAudio", "purpose": "open extended audio file from URL", "category": "audio"},
    "_ExtAudioFileRead": {"lib": "CoreAudio", "purpose": "read from extended audio file", "category": "audio"},
    "_ExtAudioFileWrite": {"lib": "CoreAudio", "purpose": "write to extended audio file", "category": "audio"},
    "_ExtAudioFileDispose": {"lib": "CoreAudio", "purpose": "dispose extended audio file", "category": "audio"},
    # AVFoundation
    "_AVAudioPlayer": {"lib": "AVFoundation", "purpose": "audio player object", "category": "audio"},
    "_AVAudioEngine": {"lib": "AVFoundation", "purpose": "audio processing graph engine", "category": "audio"},
    "_AVAudioSession": {"lib": "AVFoundation", "purpose": "audio session configuration", "category": "audio"},
    "_AVCaptureSession": {"lib": "AVFoundation", "purpose": "media capture session", "category": "media"},
    "_AVCaptureDevice": {"lib": "AVFoundation", "purpose": "capture device (camera/mic)", "category": "media"},
    "_AVCaptureVideoDataOutput": {"lib": "AVFoundation", "purpose": "video frame capture output", "category": "media"},
    # OpenAL: Sources
    "_alGenSources": {"lib": "OpenAL", "purpose": "generate audio source names", "category": "audio"},
    "_alDeleteSources": {"lib": "OpenAL", "purpose": "delete audio sources", "category": "audio"},
    "_alSourcePlay": {"lib": "OpenAL", "purpose": "play audio source", "category": "audio"},
    "_alSourceStop": {"lib": "OpenAL", "purpose": "stop audio source", "category": "audio"},
    "_alSourcePause": {"lib": "OpenAL", "purpose": "pause audio source", "category": "audio"},
    # OpenAL: Buffers
    "_alGenBuffers": {"lib": "OpenAL", "purpose": "generate audio buffer names", "category": "audio"},
    "_alDeleteBuffers": {"lib": "OpenAL", "purpose": "delete audio buffers", "category": "audio"},
    "_alBufferData": {"lib": "OpenAL", "purpose": "fill buffer with audio data", "category": "audio"},
    # OpenAL: Listener & Source Properties
    "_alListenerf": {"lib": "OpenAL", "purpose": "set listener float property", "category": "audio"},
    "_alSourcef": {"lib": "OpenAL", "purpose": "set source float property", "category": "audio"},
    "_alSourcei": {"lib": "OpenAL", "purpose": "set source integer property", "category": "audio"},
    "_alSource3f": {"lib": "OpenAL", "purpose": "set source 3-float property (position/velocity)", "category": "audio"},
    # OpenAL: Device & Context
    "_alcOpenDevice": {"lib": "OpenAL", "purpose": "open audio device", "category": "audio"},
    "_alcCloseDevice": {"lib": "OpenAL", "purpose": "close audio device", "category": "audio"},
    "_alcCreateContext": {"lib": "OpenAL", "purpose": "create audio context", "category": "audio"},
    "_alcDestroyContext": {"lib": "OpenAL", "purpose": "destroy audio context", "category": "audio"},
}


# ---------------------------------------------------------------------------
# FFmpeg libavformat/libavcodec/libavutil/libswscale/libswresample (34 entry).
# # Kaynak: signature_db.py _FFMPEG_SIGNATURES.
# ---------------------------------------------------------------------------
_FFMPEG_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Format I/O
    "_avformat_open_input": {"lib": "libavformat", "purpose": "open input media file/stream", "category": "media"},
    "_avformat_close_input": {"lib": "libavformat", "purpose": "close input media file/stream", "category": "media"},
    "_avformat_find_stream_info": {"lib": "libavformat", "purpose": "read stream info from media", "category": "media"},
    "_avformat_alloc_output_context2": {"lib": "libavformat", "purpose": "allocate output format context", "category": "media"},
    "_av_read_frame": {"lib": "libavformat", "purpose": "read next packet from media", "category": "media"},
    "_av_write_frame": {"lib": "libavformat", "purpose": "write packet to output media", "category": "media"},
    "_av_interleaved_write_frame": {"lib": "libavformat", "purpose": "write interleaved packet to output", "category": "media"},
    # Codec Discovery
    "_avcodec_find_decoder": {"lib": "libavcodec", "purpose": "find registered decoder by ID", "category": "media"},
    "_avcodec_find_encoder": {"lib": "libavcodec", "purpose": "find registered encoder by ID", "category": "media"},
    "_avcodec_open2": {"lib": "libavcodec", "purpose": "open codec for encoding/decoding", "category": "media"},
    "_avcodec_close": {"lib": "libavcodec", "purpose": "close codec", "category": "media"},
    # Codec Send/Receive API
    "_avcodec_send_packet": {"lib": "libavcodec", "purpose": "send packet to decoder", "category": "media"},
    "_avcodec_receive_frame": {"lib": "libavcodec", "purpose": "receive decoded frame from decoder", "category": "media"},
    "_avcodec_send_frame": {"lib": "libavcodec", "purpose": "send frame to encoder", "category": "media"},
    "_avcodec_receive_packet": {"lib": "libavcodec", "purpose": "receive encoded packet from encoder", "category": "media"},
    # Codec Context
    "_avcodec_alloc_context3": {"lib": "libavcodec", "purpose": "allocate codec context", "category": "media"},
    "_avcodec_free_context": {"lib": "libavcodec", "purpose": "free codec context", "category": "media"},
    "_avcodec_parameters_to_context": {"lib": "libavcodec", "purpose": "copy codec parameters to context", "category": "media"},
    # Frame Management
    "_av_frame_alloc": {"lib": "libavutil", "purpose": "allocate AVFrame", "category": "media"},
    "_av_frame_free": {"lib": "libavutil", "purpose": "free AVFrame", "category": "media"},
    "_av_frame_unref": {"lib": "libavutil", "purpose": "unreference frame data", "category": "media"},
    # Packet Management
    "_av_packet_alloc": {"lib": "libavcodec", "purpose": "allocate AVPacket", "category": "media"},
    "_av_packet_free": {"lib": "libavcodec", "purpose": "free AVPacket", "category": "media"},
    "_av_packet_unref": {"lib": "libavcodec", "purpose": "unreference packet data", "category": "media"},
    # Software Scaler
    "_sws_getContext": {"lib": "libswscale", "purpose": "create software scaler context", "category": "media"},
    "_sws_scale": {"lib": "libswscale", "purpose": "scale/convert video frame", "category": "media"},
    "_sws_freeContext": {"lib": "libswscale", "purpose": "free software scaler context", "category": "media"},
    # Software Resampler
    "_swr_alloc": {"lib": "libswresample", "purpose": "allocate audio resampler context", "category": "media"},
    "_swr_init": {"lib": "libswresample", "purpose": "initialize audio resampler", "category": "media"},
    "_swr_convert": {"lib": "libswresample", "purpose": "convert/resample audio samples", "category": "media"},
    "_swr_free": {"lib": "libswresample", "purpose": "free audio resampler context", "category": "media"},
    # Utility
    "_av_malloc": {"lib": "libavutil", "purpose": "allocate memory with alignment", "category": "media"},
    "_av_free": {"lib": "libavutil", "purpose": "free av-allocated memory", "category": "media"},
    "_av_log": {"lib": "libavutil", "purpose": "FFmpeg logging function", "category": "media"},
}


# ---------------------------------------------------------------------------
# SDL2 multimedia (window, renderer, texture, audio, threading) (31 entry).
# # Kaynak: signature_db.py _SDL2_SIGNATURES.
# ---------------------------------------------------------------------------
_SDL2_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Init / Quit
    "_SDL_Init": {"lib": "SDL2", "purpose": "initialize SDL subsystems", "category": "multimedia"},
    "_SDL_Quit": {"lib": "SDL2", "purpose": "shut down all SDL subsystems", "category": "multimedia"},
    # Window
    "_SDL_CreateWindow": {"lib": "SDL2", "purpose": "create a window", "category": "multimedia"},
    "_SDL_DestroyWindow": {"lib": "SDL2", "purpose": "destroy a window", "category": "multimedia"},
    # Renderer
    "_SDL_CreateRenderer": {"lib": "SDL2", "purpose": "create 2D rendering context", "category": "multimedia"},
    "_SDL_DestroyRenderer": {"lib": "SDL2", "purpose": "destroy 2D rendering context", "category": "multimedia"},
    "_SDL_RenderPresent": {"lib": "SDL2", "purpose": "present renderer to screen", "category": "multimedia"},
    "_SDL_RenderClear": {"lib": "SDL2", "purpose": "clear renderer with draw color", "category": "multimedia"},
    # Texture
    "_SDL_CreateTexture": {"lib": "SDL2", "purpose": "create texture for renderer", "category": "multimedia"},
    "_SDL_DestroyTexture": {"lib": "SDL2", "purpose": "destroy texture", "category": "multimedia"},
    "_SDL_UpdateTexture": {"lib": "SDL2", "purpose": "update texture with new pixel data", "category": "multimedia"},
    "_SDL_RenderCopy": {"lib": "SDL2", "purpose": "copy texture to renderer", "category": "multimedia"},
    # Events
    "_SDL_PollEvent": {"lib": "SDL2", "purpose": "poll for pending events", "category": "multimedia"},
    "_SDL_WaitEvent": {"lib": "SDL2", "purpose": "wait for next event", "category": "multimedia"},
    "_SDL_PushEvent": {"lib": "SDL2", "purpose": "push event onto event queue", "category": "multimedia"},
    # Timer
    "_SDL_GetTicks": {"lib": "SDL2", "purpose": "get milliseconds since SDL init", "category": "multimedia"},
    "_SDL_Delay": {"lib": "SDL2", "purpose": "wait specified milliseconds", "category": "multimedia"},
    "_SDL_GetPerformanceCounter": {"lib": "SDL2", "purpose": "get high-resolution counter value", "category": "multimedia"},
    "_SDL_GetPerformanceFrequency": {"lib": "SDL2", "purpose": "get high-resolution counter frequency", "category": "multimedia"},
    # Surface
    "_SDL_LoadBMP": {"lib": "SDL2", "purpose": "load BMP image to surface", "category": "multimedia"},
    "_SDL_FreeSurface": {"lib": "SDL2", "purpose": "free surface memory", "category": "multimedia"},
    "_SDL_ConvertSurface": {"lib": "SDL2", "purpose": "convert surface to different format", "category": "multimedia"},
    # Audio
    "_SDL_OpenAudio": {"lib": "SDL2", "purpose": "open audio device", "category": "multimedia"},
    "_SDL_CloseAudio": {"lib": "SDL2", "purpose": "close audio device", "category": "multimedia"},
    "_SDL_PauseAudio": {"lib": "SDL2", "purpose": "pause/unpause audio playback", "category": "multimedia"},
    "_SDL_MixAudio": {"lib": "SDL2", "purpose": "mix audio data into buffer", "category": "multimedia"},
    # Threading
    "_SDL_CreateThread": {"lib": "SDL2", "purpose": "create a new thread", "category": "multimedia"},
    "_SDL_WaitThread": {"lib": "SDL2", "purpose": "wait for thread to finish", "category": "multimedia"},
    "_SDL_CreateMutex": {"lib": "SDL2", "purpose": "create a mutex", "category": "multimedia"},
    "_SDL_LockMutex": {"lib": "SDL2", "purpose": "lock a mutex", "category": "multimedia"},
    "_SDL_UnlockMutex": {"lib": "SDL2", "purpose": "unlock a mutex", "category": "multimedia"},
}


# ---------------------------------------------------------------------------
# Vulkan / Direct3D 11/12 / DXGI / FreeType / HarfBuzz / Cairo (100 entry).
# # Kaynak: signature_db.py _GRAPHICS_EXT_SIGNATURES.
# ---------------------------------------------------------------------------
_GRAPHICS_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- Vulkan ---
    "vkCreateInstance": {"lib": "vulkan", "purpose": "create Vulkan instance", "category": "graphics"},
    "vkDestroyInstance": {"lib": "vulkan", "purpose": "destroy Vulkan instance", "category": "graphics"},
    "vkEnumeratePhysicalDevices": {"lib": "vulkan", "purpose": "enumerate GPUs", "category": "graphics"},
    "vkCreateDevice": {"lib": "vulkan", "purpose": "create logical device", "category": "graphics"},
    "vkDestroyDevice": {"lib": "vulkan", "purpose": "destroy logical device", "category": "graphics"},
    "vkGetDeviceQueue": {"lib": "vulkan", "purpose": "get device queue handle", "category": "graphics"},
    "vkCreateSwapchainKHR": {"lib": "vulkan", "purpose": "create swap chain", "category": "graphics"},
    "vkDestroySwapchainKHR": {"lib": "vulkan", "purpose": "destroy swap chain", "category": "graphics"},
    "vkAcquireNextImageKHR": {"lib": "vulkan", "purpose": "acquire next swap chain image", "category": "graphics"},
    "vkQueuePresentKHR": {"lib": "vulkan", "purpose": "present rendered image", "category": "graphics"},
    "vkCreateRenderPass": {"lib": "vulkan", "purpose": "create render pass", "category": "graphics"},
    "vkCreateFramebuffer": {"lib": "vulkan", "purpose": "create framebuffer", "category": "graphics"},
    "vkCreateGraphicsPipelines": {"lib": "vulkan", "purpose": "create graphics pipeline", "category": "graphics"},
    "vkCreateComputePipelines": {"lib": "vulkan", "purpose": "create compute pipeline", "category": "graphics"},
    "vkCreatePipelineLayout": {"lib": "vulkan", "purpose": "create pipeline layout", "category": "graphics"},
    "vkCreateShaderModule": {"lib": "vulkan", "purpose": "create shader module from SPIR-V", "category": "graphics"},
    "vkCreateBuffer": {"lib": "vulkan", "purpose": "create buffer object", "category": "graphics"},
    "vkCreateImage": {"lib": "vulkan", "purpose": "create image object", "category": "graphics"},
    "vkAllocateMemory": {"lib": "vulkan", "purpose": "allocate device memory", "category": "graphics"},
    "vkFreeMemory": {"lib": "vulkan", "purpose": "free device memory", "category": "graphics"},
    "vkBindBufferMemory": {"lib": "vulkan", "purpose": "bind memory to buffer", "category": "graphics"},
    "vkBindImageMemory": {"lib": "vulkan", "purpose": "bind memory to image", "category": "graphics"},
    "vkMapMemory": {"lib": "vulkan", "purpose": "map device memory to host", "category": "graphics"},
    "vkUnmapMemory": {"lib": "vulkan", "purpose": "unmap device memory", "category": "graphics"},
    "vkCreateCommandPool": {"lib": "vulkan", "purpose": "create command pool", "category": "graphics"},
    "vkAllocateCommandBuffers": {"lib": "vulkan", "purpose": "allocate command buffers", "category": "graphics"},
    "vkBeginCommandBuffer": {"lib": "vulkan", "purpose": "begin recording command buffer", "category": "graphics"},
    "vkEndCommandBuffer": {"lib": "vulkan", "purpose": "end recording command buffer", "category": "graphics"},
    "vkCmdBeginRenderPass": {"lib": "vulkan", "purpose": "begin render pass in command buffer", "category": "graphics"},
    "vkCmdEndRenderPass": {"lib": "vulkan", "purpose": "end render pass", "category": "graphics"},
    "vkCmdBindPipeline": {"lib": "vulkan", "purpose": "bind pipeline to command buffer", "category": "graphics"},
    "vkCmdDraw": {"lib": "vulkan", "purpose": "record non-indexed draw", "category": "graphics"},
    "vkCmdDrawIndexed": {"lib": "vulkan", "purpose": "record indexed draw", "category": "graphics"},
    "vkCmdDispatch": {"lib": "vulkan", "purpose": "record compute dispatch", "category": "graphics"},
    "vkCmdCopyBuffer": {"lib": "vulkan", "purpose": "record buffer copy", "category": "graphics"},
    "vkCmdCopyImage": {"lib": "vulkan", "purpose": "record image copy", "category": "graphics"},
    "vkCmdCopyBufferToImage": {"lib": "vulkan", "purpose": "record buffer-to-image copy", "category": "graphics"},
    "vkQueueSubmit": {"lib": "vulkan", "purpose": "submit command buffers to queue", "category": "graphics"},
    "vkQueueWaitIdle": {"lib": "vulkan", "purpose": "wait for queue to finish", "category": "graphics"},
    "vkDeviceWaitIdle": {"lib": "vulkan", "purpose": "wait for device to finish all work", "category": "graphics"},
    "vkCreateSemaphore": {"lib": "vulkan", "purpose": "create synchronization semaphore", "category": "graphics"},
    "vkCreateFence": {"lib": "vulkan", "purpose": "create synchronization fence", "category": "graphics"},
    "vkWaitForFences": {"lib": "vulkan", "purpose": "wait for fence to be signaled", "category": "graphics"},
    "vkResetFences": {"lib": "vulkan", "purpose": "reset fence to unsignaled state", "category": "graphics"},
    "vkCreateDescriptorSetLayout": {"lib": "vulkan", "purpose": "create descriptor set layout", "category": "graphics"},
    "vkCreateDescriptorPool": {"lib": "vulkan", "purpose": "create descriptor pool", "category": "graphics"},
    "vkAllocateDescriptorSets": {"lib": "vulkan", "purpose": "allocate descriptor sets", "category": "graphics"},
    "vkUpdateDescriptorSets": {"lib": "vulkan", "purpose": "update descriptor sets", "category": "graphics"},
    "vkCreateSampler": {"lib": "vulkan", "purpose": "create texture sampler", "category": "graphics"},
    "vkCreateImageView": {"lib": "vulkan", "purpose": "create image view", "category": "graphics"},

    # --- Direct3D 11 ---
    "D3D11CreateDevice": {"lib": "d3d11", "purpose": "create Direct3D 11 device", "category": "graphics"},
    "D3D11CreateDeviceAndSwapChain": {"lib": "d3d11", "purpose": "create D3D11 device + swap chain", "category": "graphics"},

    # --- Direct3D 12 ---
    "D3D12CreateDevice": {"lib": "d3d12", "purpose": "create Direct3D 12 device", "category": "graphics"},
    "D3D12GetDebugInterface": {"lib": "d3d12", "purpose": "get D3D12 debug interface", "category": "graphics"},
    "D3D12SerializeRootSignature": {"lib": "d3d12", "purpose": "serialize D3D12 root signature", "category": "graphics"},

    # --- DXGI ---
    "CreateDXGIFactory": {"lib": "dxgi", "purpose": "create DXGI factory", "category": "graphics"},
    "CreateDXGIFactory1": {"lib": "dxgi", "purpose": "create DXGI factory 1.1+", "category": "graphics"},
    "CreateDXGIFactory2": {"lib": "dxgi", "purpose": "create DXGI factory 2 (debug support)", "category": "graphics"},

    # --- FreeType ---
    "FT_Init_FreeType": {"lib": "freetype", "purpose": "initialize FreeType library", "category": "font"},
    "FT_Done_FreeType": {"lib": "freetype", "purpose": "finalize FreeType library", "category": "font"},
    "FT_New_Face": {"lib": "freetype", "purpose": "create face from font file", "category": "font"},
    "FT_Done_Face": {"lib": "freetype", "purpose": "destroy font face", "category": "font"},
    "FT_Set_Pixel_Sizes": {"lib": "freetype", "purpose": "set character pixel size", "category": "font"},
    "FT_Set_Char_Size": {"lib": "freetype", "purpose": "set character point size", "category": "font"},
    "FT_Load_Glyph": {"lib": "freetype", "purpose": "load glyph by index", "category": "font"},
    "FT_Load_Char": {"lib": "freetype", "purpose": "load glyph by character code", "category": "font"},
    "FT_Render_Glyph": {"lib": "freetype", "purpose": "render glyph to bitmap", "category": "font"},
    "FT_Get_Char_Index": {"lib": "freetype", "purpose": "get glyph index for character", "category": "font"},

    # --- HarfBuzz ---
    "hb_buffer_create": {"lib": "harfbuzz", "purpose": "create text shaping buffer", "category": "font"},
    "hb_buffer_destroy": {"lib": "harfbuzz", "purpose": "destroy shaping buffer", "category": "font"},
    "hb_buffer_add_utf8": {"lib": "harfbuzz", "purpose": "add UTF-8 text to buffer", "category": "font"},
    "hb_buffer_set_direction": {"lib": "harfbuzz", "purpose": "set text direction (LTR/RTL)", "category": "font"},
    "hb_buffer_set_script": {"lib": "harfbuzz", "purpose": "set script for shaping", "category": "font"},
    "hb_buffer_set_language": {"lib": "harfbuzz", "purpose": "set language for shaping", "category": "font"},
    "hb_shape": {"lib": "harfbuzz", "purpose": "perform text shaping", "category": "font"},
    "hb_buffer_get_glyph_infos": {"lib": "harfbuzz", "purpose": "get shaped glyph infos", "category": "font"},
    "hb_buffer_get_glyph_positions": {"lib": "harfbuzz", "purpose": "get shaped glyph positions", "category": "font"},
    "hb_font_create": {"lib": "harfbuzz", "purpose": "create font for shaping", "category": "font"},
    "hb_font_destroy": {"lib": "harfbuzz", "purpose": "destroy font object", "category": "font"},
    "hb_ft_font_create": {"lib": "harfbuzz", "purpose": "create HarfBuzz font from FreeType face", "category": "font"},

    # --- Cairo ---
    "cairo_create": {"lib": "cairo", "purpose": "create drawing context", "category": "graphics_2d"},
    "cairo_destroy": {"lib": "cairo", "purpose": "destroy drawing context", "category": "graphics_2d"},
    "cairo_image_surface_create": {"lib": "cairo", "purpose": "create image surface", "category": "graphics_2d"},
    "cairo_surface_destroy": {"lib": "cairo", "purpose": "destroy surface", "category": "graphics_2d"},
    "cairo_set_source_rgb": {"lib": "cairo", "purpose": "set RGB source color", "category": "graphics_2d"},
    "cairo_set_source_rgba": {"lib": "cairo", "purpose": "set RGBA source color", "category": "graphics_2d"},
    "cairo_set_line_width": {"lib": "cairo", "purpose": "set line width", "category": "graphics_2d"},
    "cairo_move_to": {"lib": "cairo", "purpose": "move current point", "category": "graphics_2d"},
    "cairo_line_to": {"lib": "cairo", "purpose": "add line to path", "category": "graphics_2d"},
    "cairo_rectangle": {"lib": "cairo", "purpose": "add rectangle to path", "category": "graphics_2d"},
    "cairo_arc": {"lib": "cairo", "purpose": "add arc to path", "category": "graphics_2d"},
    "cairo_stroke": {"lib": "cairo", "purpose": "stroke current path", "category": "graphics_2d"},
    "cairo_fill": {"lib": "cairo", "purpose": "fill current path", "category": "graphics_2d"},
    "cairo_paint": {"lib": "cairo", "purpose": "paint entire surface", "category": "graphics_2d"},
    "cairo_show_text": {"lib": "cairo", "purpose": "draw text string", "category": "graphics_2d"},
    "cairo_select_font_face": {"lib": "cairo", "purpose": "select font family", "category": "graphics_2d"},
    "cairo_set_font_size": {"lib": "cairo", "purpose": "set font size", "category": "graphics_2d"},
    "cairo_surface_write_to_png": {"lib": "cairo", "purpose": "write surface to PNG file", "category": "graphics_2d"},
    "cairo_pdf_surface_create": {"lib": "cairo", "purpose": "create PDF surface", "category": "graphics_2d"},
    "cairo_svg_surface_create": {"lib": "cairo", "purpose": "create SVG surface", "category": "graphics_2d"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — sigdb_builtin.get_category('graphics_media') bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur.
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "opengl_metal_gpu_signatures": _OPENGL_METAL_GPU_SIGNATURES_DATA,
    "coregraphics_signatures": _COREGRAPHICS_SIGNATURES_DATA,
    "coreimage_coreml_signatures": _COREIMAGE_COREML_SIGNATURES_DATA,
    "image_lib_signatures": _IMAGE_LIB_SIGNATURES_DATA,
    "audio_signatures": _AUDIO_SIGNATURES_DATA,
    "ffmpeg_signatures": _FFMPEG_SIGNATURES_DATA,
    "sdl2_signatures": _SDL2_SIGNATURES_DATA,
    "graphics_ext_signatures": _GRAPHICS_EXT_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
