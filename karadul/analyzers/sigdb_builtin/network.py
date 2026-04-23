"""Network category signatures — sig_db Faz 3'te tasindi.

Kaynak: karadul/analyzers/signature_db.py
  - _LIBCURL_SIGNATURES                  ( 67 entry, satir 1453-1521)
  - _POSIX_NETWORKING_SIGNATURES         ( 43 entry, satir 2458-2502)
  - _NGHTTP2_SIGNATURES                  ( 28 entry, satir 2543-2572)
  - _WEBSOCKET_SIGNATURES                ( 18 entry, satir 2579-2598)
  - _MACOS_NETWORKING_SIGNATURES         ( 50 entry, satir 2652-2703)
  - _APPLE_NETWORK_FRAMEWORK_SIGNATURES  ( 35 entry, satir 3460-3500)
  - _NETWORKING_EXT_SIGNATURES           ( 99 entry, satir 5713-5822)

Toplam: 340 signature.

Faz 3'te ucuncu tasinan kategoridir (crypto + compression + network dalgasi).
signature_db.py icindeki orijinal dict'ler SILINMEMIS; rollback icin override
yontemi kullanilir. Bkz: signature_db.py icindeki ``_BUILTIN_NETWORK`` import bloku.

NOT: SSL/TLS lib'leri (OpenSSL, BoringSSL, mbedTLS) crypto kategorisine
aittir; bu dosya yalnizca network-layer (HTTP, TCP/UDP, WebSocket, DNS, ...)
imzalarini icerir.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# libcurl (67 entry) — curl_easy_*, curl_multi_*, options, info, slist
# Kaynak: signature_db.py satir 1453-1521
# ---------------------------------------------------------------------------
_LIBCURL_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_curl_easy_init": {"lib": "libcurl", "purpose": "easy handle creation", "category": "network"},
    "_curl_easy_cleanup": {"lib": "libcurl", "purpose": "easy handle cleanup", "category": "network"},
    "_curl_easy_setopt": {"lib": "libcurl", "purpose": "easy option set", "category": "network"},
    "_curl_easy_perform": {"lib": "libcurl", "purpose": "execute HTTP request", "category": "network"},
    "_curl_easy_getinfo": {"lib": "libcurl", "purpose": "get transfer info", "category": "network"},
    "_curl_easy_reset": {"lib": "libcurl", "purpose": "easy handle reset", "category": "network"},
    "_curl_easy_duphandle": {"lib": "libcurl", "purpose": "duplicate easy handle", "category": "network"},
    "_curl_easy_strerror": {"lib": "libcurl", "purpose": "error string lookup", "category": "network"},
    "_curl_multi_init": {"lib": "libcurl", "purpose": "multi handle creation", "category": "network"},
    "_curl_multi_cleanup": {"lib": "libcurl", "purpose": "multi handle cleanup", "category": "network"},
    "_curl_multi_add_handle": {"lib": "libcurl", "purpose": "add easy to multi", "category": "network"},
    "_curl_multi_remove_handle": {"lib": "libcurl", "purpose": "remove easy from multi", "category": "network"},
    "_curl_multi_perform": {"lib": "libcurl", "purpose": "multi perform transfers", "category": "network"},
    "_curl_multi_wait": {"lib": "libcurl", "purpose": "multi wait for activity", "category": "network"},
    "_curl_multi_poll": {"lib": "libcurl", "purpose": "multi poll for activity", "category": "network"},
    "_curl_multi_info_read": {"lib": "libcurl", "purpose": "multi read status info", "category": "network"},
    "_curl_multi_setopt": {"lib": "libcurl", "purpose": "multi option set", "category": "network"},
    "_curl_multi_strerror": {"lib": "libcurl", "purpose": "multi error string", "category": "network"},
    "_curl_global_init": {"lib": "libcurl", "purpose": "global init", "category": "network"},
    "_curl_global_cleanup": {"lib": "libcurl", "purpose": "global cleanup", "category": "network"},
    "_curl_slist_append": {"lib": "libcurl", "purpose": "string list append (headers)", "category": "network"},
    "_curl_slist_free_all": {"lib": "libcurl", "purpose": "string list cleanup", "category": "network"},
    "_curl_url": {"lib": "libcurl", "purpose": "URL handle creation", "category": "network"},
    "_curl_url_cleanup": {"lib": "libcurl", "purpose": "URL handle cleanup", "category": "network"},
    "_curl_url_set": {"lib": "libcurl", "purpose": "URL component set", "category": "network"},
    "_curl_url_get": {"lib": "libcurl", "purpose": "URL component get", "category": "network"},
    "_curl_mime_init": {"lib": "libcurl", "purpose": "MIME init (multipart)", "category": "network"},
    "_curl_mime_free": {"lib": "libcurl", "purpose": "MIME cleanup", "category": "network"},
    "_curl_mime_addpart": {"lib": "libcurl", "purpose": "MIME add part", "category": "network"},
    "_curl_mime_data": {"lib": "libcurl", "purpose": "MIME set data", "category": "network"},
    "_curl_mime_name": {"lib": "libcurl", "purpose": "MIME set name", "category": "network"},
    "_curl_mime_filename": {"lib": "libcurl", "purpose": "MIME set filename", "category": "network"},
    "_curl_mime_type": {"lib": "libcurl", "purpose": "MIME set content type", "category": "network"},
    "_curl_mime_filedata": {"lib": "libcurl", "purpose": "MIME set file data", "category": "network"},
    "_curl_share_init": {"lib": "libcurl", "purpose": "share handle creation", "category": "network"},
    "_curl_share_cleanup": {"lib": "libcurl", "purpose": "share handle cleanup", "category": "network"},
    "_curl_share_setopt": {"lib": "libcurl", "purpose": "share option set", "category": "network"},
    "_curl_version": {"lib": "libcurl", "purpose": "version string", "category": "network"},
    "_curl_version_info": {"lib": "libcurl", "purpose": "version info struct", "category": "network"},
    "_curl_free": {"lib": "libcurl", "purpose": "curl memory free", "category": "network"},
    "_curl_escape": {"lib": "libcurl", "purpose": "URL-encode string", "category": "network"},
    "_curl_unescape": {"lib": "libcurl", "purpose": "URL-decode string", "category": "network"},
    "_curl_easy_escape": {"lib": "libcurl", "purpose": "URL-encode string (easy)", "category": "network"},
    "_curl_easy_unescape": {"lib": "libcurl", "purpose": "URL-decode string (easy)", "category": "network"},
    "_curl_ws_recv": {"lib": "libcurl", "purpose": "WebSocket receive", "category": "network"},
    "_curl_ws_send": {"lib": "libcurl", "purpose": "WebSocket send", "category": "network"},
    "_curl_ws_meta": {"lib": "libcurl", "purpose": "WebSocket frame metadata", "category": "network"},
    "_curl_formadd": {"lib": "libcurl", "purpose": "add form section (deprecated)", "category": "network"},
    "_curl_formfree": {"lib": "libcurl", "purpose": "free form data (deprecated)", "category": "network"},
    "_curl_easy_send": {"lib": "libcurl", "purpose": "raw send over easy handle", "category": "network"},
    "_curl_easy_recv": {"lib": "libcurl", "purpose": "raw recv over easy handle", "category": "network"},
    "_curl_easy_pause": {"lib": "libcurl", "purpose": "pause/unpause transfer", "category": "network"},
    "_curl_easy_upkeep": {"lib": "libcurl", "purpose": "connection upkeep", "category": "network"},
    "_curl_multi_socket_action": {"lib": "libcurl", "purpose": "multi socket action", "category": "network"},
    "_curl_multi_assign": {"lib": "libcurl", "purpose": "multi assign socket data", "category": "network"},
    "_curl_multi_timeout": {"lib": "libcurl", "purpose": "multi get timeout value", "category": "network"},
    "_curl_multi_fdset": {"lib": "libcurl", "purpose": "multi extract fd_set", "category": "network"},
    "_curl_mime_subparts": {"lib": "libcurl", "purpose": "MIME set subparts", "category": "network"},
    "_curl_mime_headers": {"lib": "libcurl", "purpose": "MIME set custom headers", "category": "network"},
    "_curl_mime_encoder": {"lib": "libcurl", "purpose": "MIME set transfer encoding", "category": "network"},
    "_curl_getdate": {"lib": "libcurl", "purpose": "parse date string", "category": "network"},
    "_curl_easy_option_by_name": {"lib": "libcurl", "purpose": "lookup option by name", "category": "network"},
    "_curl_easy_option_by_id": {"lib": "libcurl", "purpose": "lookup option by id", "category": "network"},
    "_curl_easy_option_next": {"lib": "libcurl", "purpose": "iterate curl options", "category": "network"},
    "_curl_url_dup": {"lib": "libcurl", "purpose": "duplicate URL handle", "category": "network"},
    "_curl_pushheader_bynum": {"lib": "libcurl", "purpose": "server push header by index", "category": "network"},
    "_curl_pushheader_byname": {"lib": "libcurl", "purpose": "server push header by name", "category": "network"},
}


# ---------------------------------------------------------------------------
# posix_networking (43 entry) — socket(), bind, connect, send/recv, poll/select
# Kaynak: signature_db.py satir 2458-2502
# ---------------------------------------------------------------------------
_POSIX_NETWORKING_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_socket": {"lib": "libc", "purpose": "create socket", "category": "network"},
    "_bind": {"lib": "libc", "purpose": "bind socket to address", "category": "network"},
    "_listen": {"lib": "libc", "purpose": "listen for connections", "category": "network"},
    "_accept": {"lib": "libc", "purpose": "accept incoming connection", "category": "network"},
    "_connect": {"lib": "libc", "purpose": "connect to remote host", "category": "network"},
    "_shutdown": {"lib": "libc", "purpose": "shutdown socket", "category": "network"},
    "_close": {"lib": "libc", "purpose": "close file descriptor", "category": "io"},
    "_send": {"lib": "libc", "purpose": "send data on socket", "category": "network"},
    "_recv": {"lib": "libc", "purpose": "receive data from socket", "category": "network"},
    "_sendto": {"lib": "libc", "purpose": "send datagram to address", "category": "network"},
    "_recvfrom": {"lib": "libc", "purpose": "receive datagram with sender", "category": "network"},
    "_sendmsg": {"lib": "libc", "purpose": "send message with ancillary data", "category": "network"},
    "_recvmsg": {"lib": "libc", "purpose": "receive message with ancillary data", "category": "network"},
    "_setsockopt": {"lib": "libc", "purpose": "set socket option", "category": "network"},
    "_getsockopt": {"lib": "libc", "purpose": "get socket option", "category": "network"},
    "_getsockname": {"lib": "libc", "purpose": "get local socket address", "category": "network"},
    "_getpeername": {"lib": "libc", "purpose": "get remote peer address", "category": "network"},
    "_select": {"lib": "libc", "purpose": "synchronous I/O multiplexing", "category": "network"},
    "_poll": {"lib": "libc", "purpose": "poll file descriptors", "category": "network"},
    "_epoll_create": {"lib": "libc", "purpose": "create epoll instance", "category": "network"},
    "_epoll_create1": {"lib": "libc", "purpose": "create epoll instance (flags)", "category": "network"},
    "_epoll_ctl": {"lib": "libc", "purpose": "control epoll instance", "category": "network"},
    "_epoll_wait": {"lib": "libc", "purpose": "wait for epoll events", "category": "network"},
    "_kqueue": {"lib": "libc", "purpose": "create kqueue instance (BSD)", "category": "network"},
    "_kevent": {"lib": "libc", "purpose": "register/poll kqueue events", "category": "network"},
    "_kevent64": {"lib": "libc", "purpose": "register/poll kqueue events (64-bit)", "category": "network"},
    "_getaddrinfo": {"lib": "libc", "purpose": "DNS name resolution", "category": "network"},
    "_freeaddrinfo": {"lib": "libc", "purpose": "free addrinfo list", "category": "network"},
    "_gai_strerror": {"lib": "libc", "purpose": "getaddrinfo error string", "category": "network"},
    "_getnameinfo": {"lib": "libc", "purpose": "reverse DNS lookup", "category": "network"},
    "_gethostbyname": {"lib": "libc", "purpose": "DNS lookup (deprecated)", "category": "network"},
    "_gethostbyaddr": {"lib": "libc", "purpose": "reverse DNS (deprecated)", "category": "network"},
    "_inet_aton": {"lib": "libc", "purpose": "dotted-decimal to in_addr", "category": "network"},
    "_inet_ntoa": {"lib": "libc", "purpose": "in_addr to dotted-decimal", "category": "network"},
    "_inet_pton": {"lib": "libc", "purpose": "text to binary address", "category": "network"},
    "_inet_ntop": {"lib": "libc", "purpose": "binary address to text", "category": "network"},
    "_htons": {"lib": "libc", "purpose": "host to network short", "category": "network"},
    "_htonl": {"lib": "libc", "purpose": "host to network long", "category": "network"},
    "_ntohs": {"lib": "libc", "purpose": "network to host short", "category": "network"},
    "_ntohl": {"lib": "libc", "purpose": "network to host long", "category": "network"},
    "_socketpair": {"lib": "libc", "purpose": "create connected socket pair", "category": "ipc"},
    "_pipe": {"lib": "libc", "purpose": "create pipe", "category": "ipc"},
    "_pipe2": {"lib": "libc", "purpose": "create pipe (with flags)", "category": "ipc"},
}


# ---------------------------------------------------------------------------
# nghttp2 (28 entry) — HTTP/2 session, stream, settings, headers
# Kaynak: signature_db.py satir 2543-2572
# ---------------------------------------------------------------------------
_NGHTTP2_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_nghttp2_session_client_new": {"lib": "nghttp2", "purpose": "create HTTP/2 client session", "category": "network"},
    "_nghttp2_session_server_new": {"lib": "nghttp2", "purpose": "create HTTP/2 server session", "category": "network"},
    "_nghttp2_session_del": {"lib": "nghttp2", "purpose": "delete HTTP/2 session", "category": "network"},
    "_nghttp2_session_recv": {"lib": "nghttp2", "purpose": "receive HTTP/2 frames", "category": "network"},
    "_nghttp2_session_send": {"lib": "nghttp2", "purpose": "send HTTP/2 frames", "category": "network"},
    "_nghttp2_session_mem_recv": {"lib": "nghttp2", "purpose": "process HTTP/2 data from buffer", "category": "network"},
    "_nghttp2_session_mem_send": {"lib": "nghttp2", "purpose": "serialize HTTP/2 frames to buffer", "category": "network"},
    "_nghttp2_submit_request": {"lib": "nghttp2", "purpose": "submit HTTP/2 request", "category": "network"},
    "_nghttp2_submit_response": {"lib": "nghttp2", "purpose": "submit HTTP/2 response", "category": "network"},
    "_nghttp2_submit_headers": {"lib": "nghttp2", "purpose": "submit HTTP/2 headers", "category": "network"},
    "_nghttp2_submit_data": {"lib": "nghttp2", "purpose": "submit HTTP/2 data frame", "category": "network"},
    "_nghttp2_submit_settings": {"lib": "nghttp2", "purpose": "submit HTTP/2 SETTINGS", "category": "network"},
    "_nghttp2_submit_ping": {"lib": "nghttp2", "purpose": "submit HTTP/2 PING", "category": "network"},
    "_nghttp2_submit_goaway": {"lib": "nghttp2", "purpose": "submit HTTP/2 GOAWAY", "category": "network"},
    "_nghttp2_submit_rst_stream": {"lib": "nghttp2", "purpose": "submit HTTP/2 RST_STREAM", "category": "network"},
    "_nghttp2_submit_priority": {"lib": "nghttp2", "purpose": "submit HTTP/2 PRIORITY", "category": "network"},
    "_nghttp2_submit_window_update": {"lib": "nghttp2", "purpose": "submit HTTP/2 WINDOW_UPDATE", "category": "network"},
    "_nghttp2_session_want_read": {"lib": "nghttp2", "purpose": "check if session wants to read", "category": "network"},
    "_nghttp2_session_want_write": {"lib": "nghttp2", "purpose": "check if session wants to write", "category": "network"},
    "_nghttp2_session_get_stream_user_data": {"lib": "nghttp2", "purpose": "get stream user data", "category": "network"},
    "_nghttp2_hd_inflate_new": {"lib": "nghttp2", "purpose": "HPACK inflater creation", "category": "network"},
    "_nghttp2_hd_inflate_hd": {"lib": "nghttp2", "purpose": "HPACK header decompression", "category": "network"},
    "_nghttp2_hd_inflate_del": {"lib": "nghttp2", "purpose": "HPACK inflater cleanup", "category": "network"},
    "_nghttp2_hd_deflate_new": {"lib": "nghttp2", "purpose": "HPACK deflater creation", "category": "network"},
    "_nghttp2_hd_deflate_hd": {"lib": "nghttp2", "purpose": "HPACK header compression", "category": "network"},
    "_nghttp2_hd_deflate_del": {"lib": "nghttp2", "purpose": "HPACK deflater cleanup", "category": "network"},
    "_nghttp2_strerror": {"lib": "nghttp2", "purpose": "error string lookup", "category": "network"},
    "_nghttp2_version": {"lib": "nghttp2", "purpose": "nghttp2 version info", "category": "network"},
}


# ---------------------------------------------------------------------------
# websocket (18 entry) — lws/websockets client+server API
# Kaynak: signature_db.py satir 2579-2598
# ---------------------------------------------------------------------------
_WEBSOCKET_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_lws_create_context": {"lib": "libwebsockets", "purpose": "create LWS context", "category": "network"},
    "_lws_context_destroy": {"lib": "libwebsockets", "purpose": "destroy LWS context", "category": "network"},
    "_lws_service": {"lib": "libwebsockets", "purpose": "service pending WebSocket events", "category": "network"},
    "_lws_callback_on_writable": {"lib": "libwebsockets", "purpose": "request writable callback", "category": "network"},
    "_lws_write": {"lib": "libwebsockets", "purpose": "write WebSocket frame", "category": "network"},
    "_lws_remaining_packet_payload": {"lib": "libwebsockets", "purpose": "remaining payload bytes", "category": "network"},
    "_lws_client_connect_via_info": {"lib": "libwebsockets", "purpose": "WebSocket client connect", "category": "network"},
    "_lws_cancel_service": {"lib": "libwebsockets", "purpose": "cancel LWS service", "category": "network"},
    "_lws_set_log_level": {"lib": "libwebsockets", "purpose": "set LWS log level", "category": "network"},
    "_lws_get_protocol": {"lib": "libwebsockets", "purpose": "get protocol for connection", "category": "network"},
    "_lws_frame_is_binary": {"lib": "libwebsockets", "purpose": "check if frame is binary", "category": "network"},
    "_lws_is_final_fragment": {"lib": "libwebsockets", "purpose": "check if last fragment", "category": "network"},
    "_lws_ring_create": {"lib": "libwebsockets", "purpose": "create ring buffer", "category": "network"},
    "_lws_ring_destroy": {"lib": "libwebsockets", "purpose": "destroy ring buffer", "category": "network"},
    "_lws_ring_insert": {"lib": "libwebsockets", "purpose": "insert into ring buffer", "category": "network"},
    "_lws_ring_consume": {"lib": "libwebsockets", "purpose": "consume from ring buffer", "category": "network"},
    "_lws_hdr_total_length": {"lib": "libwebsockets", "purpose": "header total length", "category": "network"},
    "_lws_hdr_copy": {"lib": "libwebsockets", "purpose": "copy header value", "category": "network"},
}


# ---------------------------------------------------------------------------
# macos_networking (50 entry) — CFSocket, CFStream, CFNetwork (legacy Darwin)
# Kaynak: signature_db.py satir 2652-2703
# ---------------------------------------------------------------------------
_MACOS_NETWORKING_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "_CFSocketCreate": {"lib": "CFNetwork", "purpose": "create CFSocket", "category": "network"},
    "_CFSocketCreateWithNative": {"lib": "CFNetwork", "purpose": "CFSocket from native fd", "category": "network"},
    "_CFSocketGetNative": {"lib": "CFNetwork", "purpose": "get native fd from CFSocket", "category": "network"},
    "_CFSocketInvalidate": {"lib": "CFNetwork", "purpose": "invalidate CFSocket", "category": "network"},
    "_CFSocketSetAddress": {"lib": "CFNetwork", "purpose": "set CFSocket address", "category": "network"},
    "_CFSocketCopyAddress": {"lib": "CFNetwork", "purpose": "copy CFSocket address", "category": "network"},
    "_CFSocketCreateRunLoopSource": {"lib": "CFNetwork", "purpose": "CFSocket run loop source", "category": "network"},
    "_CFStreamCreatePairWithSocketToHost": {"lib": "CFNetwork", "purpose": "create stream pair to host", "category": "network"},
    "_CFReadStreamOpen": {"lib": "CFNetwork", "purpose": "open CFReadStream", "category": "network"},
    "_CFReadStreamClose": {"lib": "CFNetwork", "purpose": "close CFReadStream", "category": "network"},
    "_CFReadStreamRead": {"lib": "CFNetwork", "purpose": "read from CFReadStream", "category": "network"},
    "_CFReadStreamHasBytesAvailable": {"lib": "CFNetwork", "purpose": "check CFReadStream bytes", "category": "network"},
    "_CFWriteStreamOpen": {"lib": "CFNetwork", "purpose": "open CFWriteStream", "category": "network"},
    "_CFWriteStreamClose": {"lib": "CFNetwork", "purpose": "close CFWriteStream", "category": "network"},
    "_CFWriteStreamWrite": {"lib": "CFNetwork", "purpose": "write to CFWriteStream", "category": "network"},
    "_CFWriteStreamCanAcceptBytes": {"lib": "CFNetwork", "purpose": "check CFWriteStream capacity", "category": "network"},
    "_CFHTTPMessageCreateRequest": {"lib": "CFNetwork", "purpose": "create HTTP request message", "category": "network"},
    "_CFHTTPMessageCreateResponse": {"lib": "CFNetwork", "purpose": "create HTTP response message", "category": "network"},
    "_CFHTTPMessageSetBody": {"lib": "CFNetwork", "purpose": "set HTTP message body", "category": "network"},
    "_CFHTTPMessageSetHeaderFieldValue": {"lib": "CFNetwork", "purpose": "set HTTP header value", "category": "network"},
    "_CFHTTPMessageCopyHeaderFieldValue": {"lib": "CFNetwork", "purpose": "get HTTP header value", "category": "network"},
    "_CFHTTPMessageCopyAllHeaderFields": {"lib": "CFNetwork", "purpose": "get all HTTP headers", "category": "network"},
    "_CFHTTPMessageGetResponseStatusCode": {"lib": "CFNetwork", "purpose": "get HTTP status code", "category": "network"},
    "_CFHTTPMessageCopyBody": {"lib": "CFNetwork", "purpose": "get HTTP message body", "category": "network"},
    "_nw_connection_create": {"lib": "Network", "purpose": "create network connection", "category": "network"},
    "_nw_connection_start": {"lib": "Network", "purpose": "start network connection", "category": "network"},
    "_nw_connection_send": {"lib": "Network", "purpose": "send data on connection", "category": "network"},
    "_nw_connection_receive": {"lib": "Network", "purpose": "receive data from connection", "category": "network"},
    "_nw_connection_receive_message": {"lib": "Network", "purpose": "receive complete message", "category": "network"},
    "_nw_connection_cancel": {"lib": "Network", "purpose": "cancel network connection", "category": "network"},
    "_nw_connection_set_state_changed_handler": {"lib": "Network", "purpose": "connection state handler", "category": "network"},
    "_nw_connection_set_queue": {"lib": "Network", "purpose": "set connection dispatch queue", "category": "network"},
    "_nw_listener_create": {"lib": "Network", "purpose": "create network listener", "category": "network"},
    "_nw_listener_start": {"lib": "Network", "purpose": "start network listener", "category": "network"},
    "_nw_listener_cancel": {"lib": "Network", "purpose": "cancel network listener", "category": "network"},
    "_nw_listener_set_queue": {"lib": "Network", "purpose": "set listener dispatch queue", "category": "network"},
    "_nw_listener_set_new_connection_handler": {"lib": "Network", "purpose": "listener connection handler", "category": "network"},
    "_nw_listener_set_state_changed_handler": {"lib": "Network", "purpose": "listener state handler", "category": "network"},
    "_nw_endpoint_create_host": {"lib": "Network", "purpose": "create host endpoint", "category": "network"},
    "_nw_endpoint_create_url": {"lib": "Network", "purpose": "create URL endpoint", "category": "network"},
    "_nw_endpoint_get_hostname": {"lib": "Network", "purpose": "get endpoint hostname", "category": "network"},
    "_nw_endpoint_get_port": {"lib": "Network", "purpose": "get endpoint port", "category": "network"},
    "_nw_parameters_create_secure_tcp": {"lib": "Network", "purpose": "create secure TCP params", "category": "network"},
    "_nw_parameters_create_secure_udp": {"lib": "Network", "purpose": "create secure UDP params", "category": "network"},
    "_nw_parameters_set_local_endpoint": {"lib": "Network", "purpose": "set local endpoint", "category": "network"},
    "_nw_path_monitor_create": {"lib": "Network", "purpose": "create path monitor", "category": "network"},
    "_nw_path_monitor_start": {"lib": "Network", "purpose": "start path monitor", "category": "network"},
    "_nw_path_monitor_cancel": {"lib": "Network", "purpose": "cancel path monitor", "category": "network"},
    "_nw_path_monitor_set_update_handler": {"lib": "Network", "purpose": "path monitor update handler", "category": "network"},
    "_nw_path_get_status": {"lib": "Network", "purpose": "get network path status", "category": "network"},
}


# ---------------------------------------------------------------------------
# apple_network_framework (35 entry) — Network.framework (nw_*) modern API
# Kaynak: signature_db.py satir 3460-3500
# ---------------------------------------------------------------------------
_APPLE_NETWORK_FRAMEWORK_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # Connection lifecycle
    "_nw_connection_create": {"lib": "Network", "purpose": "create network connection", "category": "network"},
    "_nw_connection_start": {"lib": "Network", "purpose": "start network connection", "category": "network"},
    "_nw_connection_cancel": {"lib": "Network", "purpose": "cancel network connection", "category": "network"},
    "_nw_connection_send": {"lib": "Network", "purpose": "send data on connection", "category": "network"},
    "_nw_connection_receive": {"lib": "Network", "purpose": "receive data on connection", "category": "network"},
    "_nw_connection_receive_message": {"lib": "Network", "purpose": "receive complete message on connection", "category": "network"},
    "_nw_connection_set_queue": {"lib": "Network", "purpose": "set connection dispatch queue", "category": "network"},
    "_nw_connection_set_state_changed_handler": {"lib": "Network", "purpose": "set connection state handler", "category": "network"},
    "_nw_connection_copy_endpoint": {"lib": "Network", "purpose": "copy connection endpoint", "category": "network"},
    "_nw_connection_copy_current_path": {"lib": "Network", "purpose": "copy current network path", "category": "network"},
    "_nw_connection_restart": {"lib": "Network", "purpose": "restart network connection", "category": "network"},
    # Listener
    "_nw_listener_create": {"lib": "Network", "purpose": "create network listener", "category": "network"},
    "_nw_listener_start": {"lib": "Network", "purpose": "start network listener", "category": "network"},
    "_nw_listener_cancel": {"lib": "Network", "purpose": "cancel network listener", "category": "network"},
    "_nw_listener_set_queue": {"lib": "Network", "purpose": "set listener dispatch queue", "category": "network"},
    "_nw_listener_set_new_connection_handler": {"lib": "Network", "purpose": "set listener connection handler", "category": "network"},
    "_nw_listener_set_state_changed_handler": {"lib": "Network", "purpose": "set listener state handler", "category": "network"},
    # Endpoint & parameters
    "_nw_endpoint_create_host": {"lib": "Network", "purpose": "create host endpoint", "category": "network"},
    "_nw_endpoint_create_url": {"lib": "Network", "purpose": "create URL endpoint", "category": "network"},
    "_nw_endpoint_create_bonjour_service": {"lib": "Network", "purpose": "create Bonjour endpoint", "category": "network"},
    "_nw_endpoint_get_hostname": {"lib": "Network", "purpose": "get endpoint hostname", "category": "network"},
    "_nw_endpoint_get_port": {"lib": "Network", "purpose": "get endpoint port", "category": "network"},
    "_nw_parameters_create_secure_tcp": {"lib": "Network", "purpose": "create secure TCP parameters", "category": "network"},
    "_nw_parameters_create_secure_udp": {"lib": "Network", "purpose": "create secure UDP parameters", "category": "network"},
    "_nw_parameters_create": {"lib": "Network", "purpose": "create custom network parameters", "category": "network"},
    "_nw_parameters_set_local_endpoint": {"lib": "Network", "purpose": "set local endpoint on parameters", "category": "network"},
    # Path monitor
    "_nw_path_monitor_create": {"lib": "Network", "purpose": "create network path monitor", "category": "network"},
    "_nw_path_monitor_start": {"lib": "Network", "purpose": "start network path monitor", "category": "network"},
    "_nw_path_monitor_cancel": {"lib": "Network", "purpose": "cancel network path monitor", "category": "network"},
    "_nw_path_monitor_set_queue": {"lib": "Network", "purpose": "set path monitor dispatch queue", "category": "network"},
    "_nw_path_monitor_set_update_handler": {"lib": "Network", "purpose": "set path monitor update handler", "category": "network"},
    "_nw_path_get_status": {"lib": "Network", "purpose": "get network path status", "category": "network"},
    "_nw_path_uses_interface_type": {"lib": "Network", "purpose": "check if path uses interface type", "category": "network"},
    "_nw_path_is_expensive": {"lib": "Network", "purpose": "check if path is expensive (cellular)", "category": "network"},
    "_nw_path_is_constrained": {"lib": "Network", "purpose": "check if path is constrained (low data)", "category": "network"},
}


# ---------------------------------------------------------------------------
# networking_ext (99 entry) — c-ares DNS, libevent, libuv, protobuf, gRPC, ZeroMQ
# Kaynak: signature_db.py satir 5713-5822
# ---------------------------------------------------------------------------
_NETWORKING_EXT_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- OpenSSL / BoringSSL extended ---
    "SSL_new": {"lib": "openssl", "purpose": "create new SSL connection object", "category": "network_tls"},
    "SSL_free": {"lib": "openssl", "purpose": "free SSL connection object", "category": "network_tls"},
    "SSL_connect": {"lib": "openssl", "purpose": "initiate TLS client handshake", "category": "network_tls"},
    "SSL_accept": {"lib": "openssl", "purpose": "accept TLS server handshake", "category": "network_tls"},
    "SSL_read": {"lib": "openssl", "purpose": "read decrypted data from TLS connection", "category": "network_tls"},
    "SSL_write": {"lib": "openssl", "purpose": "write data to TLS connection", "category": "network_tls"},
    "SSL_shutdown": {"lib": "openssl", "purpose": "shut down TLS connection", "category": "network_tls"},
    "SSL_set_fd": {"lib": "openssl", "purpose": "set socket fd for SSL", "category": "network_tls"},
    "SSL_get_error": {"lib": "openssl", "purpose": "get SSL error code", "category": "network_tls"},
    "SSL_get_peer_certificate": {"lib": "openssl", "purpose": "get peer's X509 certificate", "category": "network_tls"},
    "SSL_get_verify_result": {"lib": "openssl", "purpose": "get certificate verification result", "category": "network_tls"},
    "SSL_set_tlsext_host_name": {"lib": "openssl", "purpose": "set SNI hostname for TLS", "category": "network_tls"},
    "SSL_CTX_new": {"lib": "openssl", "purpose": "create new SSL context", "category": "network_tls"},
    "SSL_CTX_free": {"lib": "openssl", "purpose": "free SSL context", "category": "network_tls"},
    "SSL_CTX_set_verify": {"lib": "openssl", "purpose": "set certificate verification mode", "category": "network_tls"},
    "SSL_CTX_use_certificate_file": {"lib": "openssl", "purpose": "load certificate from file", "category": "network_tls"},
    "SSL_CTX_use_PrivateKey_file": {"lib": "openssl", "purpose": "load private key from file", "category": "network_tls"},
    "SSL_CTX_load_verify_locations": {"lib": "openssl", "purpose": "set CA certificate locations", "category": "network_tls"},
    "SSL_CTX_set_cipher_list": {"lib": "openssl", "purpose": "set allowed cipher suites (TLS 1.2)", "category": "network_tls"},
    "SSL_CTX_set_ciphersuites": {"lib": "openssl", "purpose": "set allowed cipher suites (TLS 1.3)", "category": "network_tls"},
    "SSL_CTX_set_min_proto_version": {"lib": "openssl", "purpose": "set minimum TLS protocol version", "category": "network_tls"},
    "SSL_CTX_set_max_proto_version": {"lib": "openssl", "purpose": "set maximum TLS protocol version", "category": "network_tls"},
    "SSL_CTX_set_options": {"lib": "openssl", "purpose": "set SSL context options", "category": "network_tls"},
    "SSL_CTX_set_session_cache_mode": {"lib": "openssl", "purpose": "configure TLS session caching", "category": "network_tls"},
    "SSL_CTX_set_alpn_protos": {"lib": "openssl", "purpose": "set ALPN protocol list", "category": "network_tls"},

    # --- Networking resolution ---
    "getaddrinfo": {"lib": "libc", "purpose": "resolve hostname to socket addresses", "category": "network_dns"},
    "freeaddrinfo": {"lib": "libc", "purpose": "free addrinfo linked list", "category": "network_dns"},
    "getnameinfo": {"lib": "libc", "purpose": "reverse DNS lookup (address to name)", "category": "network_dns"},
    "gethostbyname": {"lib": "libc", "purpose": "resolve hostname (deprecated, use getaddrinfo)", "category": "network_dns"},
    "gethostbyname2": {"lib": "libc", "purpose": "resolve hostname with address family", "category": "network_dns"},
    "gethostbyaddr": {"lib": "libc", "purpose": "reverse DNS lookup (deprecated)", "category": "network_dns"},
    "inet_pton": {"lib": "libc", "purpose": "convert IP address string to binary", "category": "network_dns"},
    "inet_ntop": {"lib": "libc", "purpose": "convert binary IP address to string", "category": "network_dns"},
    "inet_addr": {"lib": "libc", "purpose": "convert IPv4 dotted-decimal to binary (deprecated)", "category": "network_dns"},
    "inet_ntoa": {"lib": "libc", "purpose": "convert binary IPv4 to dotted-decimal (deprecated)", "category": "network_dns"},
    "inet_aton": {"lib": "libc", "purpose": "convert IPv4 string to in_addr", "category": "network_dns"},
    "htons": {"lib": "libc", "purpose": "host to network byte order (16-bit)", "category": "network_util"},
    "ntohs": {"lib": "libc", "purpose": "network to host byte order (16-bit)", "category": "network_util"},
    "htonl": {"lib": "libc", "purpose": "host to network byte order (32-bit)", "category": "network_util"},
    "ntohl": {"lib": "libc", "purpose": "network to host byte order (32-bit)", "category": "network_util"},

    # --- libcurl extended ---
    "curl_easy_init": {"lib": "libcurl", "purpose": "initialize easy curl handle", "category": "network_http"},
    "curl_easy_cleanup": {"lib": "libcurl", "purpose": "cleanup easy curl handle", "category": "network_http"},
    "curl_easy_setopt": {"lib": "libcurl", "purpose": "set curl option", "category": "network_http"},
    "curl_easy_perform": {"lib": "libcurl", "purpose": "perform curl transfer", "category": "network_http"},
    "curl_easy_getinfo": {"lib": "libcurl", "purpose": "get transfer information", "category": "network_http"},
    "curl_easy_reset": {"lib": "libcurl", "purpose": "reset curl handle to defaults", "category": "network_http"},
    "curl_easy_duphandle": {"lib": "libcurl", "purpose": "duplicate curl handle", "category": "network_http"},
    "curl_easy_strerror": {"lib": "libcurl", "purpose": "get curl error string", "category": "network_http"},
    "curl_multi_init": {"lib": "libcurl", "purpose": "initialize multi curl handle", "category": "network_http"},
    "curl_multi_add_handle": {"lib": "libcurl", "purpose": "add easy handle to multi", "category": "network_http"},
    "curl_multi_remove_handle": {"lib": "libcurl", "purpose": "remove easy handle from multi", "category": "network_http"},
    "curl_multi_perform": {"lib": "libcurl", "purpose": "perform multi transfers", "category": "network_http"},
    "curl_multi_wait": {"lib": "libcurl", "purpose": "wait for multi activity", "category": "network_http"},
    "curl_multi_cleanup": {"lib": "libcurl", "purpose": "cleanup multi handle", "category": "network_http"},
    "curl_global_init": {"lib": "libcurl", "purpose": "initialize libcurl globally", "category": "network_http"},
    "curl_global_cleanup": {"lib": "libcurl", "purpose": "cleanup libcurl globally", "category": "network_http"},
    "curl_slist_append": {"lib": "libcurl", "purpose": "append to curl string list (headers)", "category": "network_http"},
    "curl_slist_free_all": {"lib": "libcurl", "purpose": "free curl string list", "category": "network_http"},
    "curl_url": {"lib": "libcurl", "purpose": "create URL object", "category": "network_http"},
    "curl_url_set": {"lib": "libcurl", "purpose": "set URL component", "category": "network_http"},
    "curl_url_get": {"lib": "libcurl", "purpose": "get URL component", "category": "network_http"},
    "curl_ws_recv": {"lib": "libcurl", "purpose": "receive WebSocket frame", "category": "network_ws"},
    "curl_ws_send": {"lib": "libcurl", "purpose": "send WebSocket frame", "category": "network_ws"},

    # --- QUIC / HTTP3 (ngtcp2, nghttp3) ---
    "ngtcp2_conn_client_new": {"lib": "ngtcp2", "purpose": "create QUIC client connection", "category": "network_quic"},
    "ngtcp2_conn_server_new": {"lib": "ngtcp2", "purpose": "create QUIC server connection", "category": "network_quic"},
    "ngtcp2_conn_read_pkt": {"lib": "ngtcp2", "purpose": "process incoming QUIC packet", "category": "network_quic"},
    "ngtcp2_conn_write_pkt": {"lib": "ngtcp2", "purpose": "generate outgoing QUIC packet", "category": "network_quic"},
    "ngtcp2_conn_open_bidi_stream": {"lib": "ngtcp2", "purpose": "open bidirectional QUIC stream", "category": "network_quic"},
    "ngtcp2_conn_open_uni_stream": {"lib": "ngtcp2", "purpose": "open unidirectional QUIC stream", "category": "network_quic"},
    "ngtcp2_conn_writev_stream": {"lib": "ngtcp2", "purpose": "write data to QUIC stream", "category": "network_quic"},
    "ngtcp2_conn_del": {"lib": "ngtcp2", "purpose": "delete QUIC connection", "category": "network_quic"},
    "nghttp3_conn_client_new": {"lib": "nghttp3", "purpose": "create HTTP/3 client connection", "category": "network_h3"},
    "nghttp3_conn_server_new": {"lib": "nghttp3", "purpose": "create HTTP/3 server connection", "category": "network_h3"},
    "nghttp3_conn_submit_request": {"lib": "nghttp3", "purpose": "submit HTTP/3 request", "category": "network_h3"},
    "nghttp3_conn_read_stream": {"lib": "nghttp3", "purpose": "process HTTP/3 stream data", "category": "network_h3"},
    "nghttp3_conn_writev_stream": {"lib": "nghttp3", "purpose": "write HTTP/3 stream data", "category": "network_h3"},
    "nghttp3_conn_del": {"lib": "nghttp3", "purpose": "delete HTTP/3 connection", "category": "network_h3"},

    # --- libssh2 ---
    "libssh2_init": {"lib": "libssh2", "purpose": "initialize libssh2", "category": "network_ssh"},
    "libssh2_exit": {"lib": "libssh2", "purpose": "cleanup libssh2", "category": "network_ssh"},
    "libssh2_session_init": {"lib": "libssh2", "purpose": "create SSH session", "category": "network_ssh"},
    "libssh2_session_handshake": {"lib": "libssh2", "purpose": "perform SSH handshake", "category": "network_ssh"},
    "libssh2_session_disconnect": {"lib": "libssh2", "purpose": "disconnect SSH session", "category": "network_ssh"},
    "libssh2_session_free": {"lib": "libssh2", "purpose": "free SSH session", "category": "network_ssh"},
    "libssh2_userauth_password": {"lib": "libssh2", "purpose": "SSH password authentication", "category": "network_ssh"},
    "libssh2_userauth_publickey_fromfile": {"lib": "libssh2", "purpose": "SSH public key authentication", "category": "network_ssh"},
    "libssh2_channel_open_session": {"lib": "libssh2", "purpose": "open SSH channel", "category": "network_ssh"},
    "libssh2_channel_exec": {"lib": "libssh2", "purpose": "execute command on SSH channel", "category": "network_ssh"},
    "libssh2_channel_read": {"lib": "libssh2", "purpose": "read from SSH channel", "category": "network_ssh"},
    "libssh2_channel_write": {"lib": "libssh2", "purpose": "write to SSH channel", "category": "network_ssh"},
    "libssh2_channel_close": {"lib": "libssh2", "purpose": "close SSH channel", "category": "network_ssh"},
    "libssh2_channel_free": {"lib": "libssh2", "purpose": "free SSH channel", "category": "network_ssh"},
    "libssh2_sftp_init": {"lib": "libssh2", "purpose": "initialize SFTP session", "category": "network_ssh"},
    "libssh2_sftp_open": {"lib": "libssh2", "purpose": "open SFTP file", "category": "network_ssh"},
    "libssh2_sftp_read": {"lib": "libssh2", "purpose": "read SFTP file", "category": "network_ssh"},
    "libssh2_sftp_write": {"lib": "libssh2", "purpose": "write SFTP file", "category": "network_ssh"},
    "libssh2_sftp_close": {"lib": "libssh2", "purpose": "close SFTP file", "category": "network_ssh"},
    "libssh2_sftp_shutdown": {"lib": "libssh2", "purpose": "shutdown SFTP session", "category": "network_ssh"},
    "libssh2_scp_send64": {"lib": "libssh2", "purpose": "start SCP send", "category": "network_ssh"},
    "libssh2_scp_recv2": {"lib": "libssh2", "purpose": "start SCP receive", "category": "network_ssh"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — sigdb_builtin.get_category("network") bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur
# (ornek: "libcurl_signatures" <-> _LIBCURL_SIGNATURES).
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "libcurl_signatures": _LIBCURL_SIGNATURES_DATA,
    "posix_networking_signatures": _POSIX_NETWORKING_SIGNATURES_DATA,
    "nghttp2_signatures": _NGHTTP2_SIGNATURES_DATA,
    "websocket_signatures": _WEBSOCKET_SIGNATURES_DATA,
    "macos_networking_signatures": _MACOS_NETWORKING_SIGNATURES_DATA,
    "apple_network_framework_signatures": _APPLE_NETWORK_FRAMEWORK_SIGNATURES_DATA,
    "networking_ext_signatures": _NETWORKING_EXT_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
