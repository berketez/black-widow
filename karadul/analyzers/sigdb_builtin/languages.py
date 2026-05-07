"""Languages category signatures — sig_db Faz 10 migrasyonu (ADR 0007 A6).

Kaynak: karadul/analyzers/signature_db.py
  - _V8_NODE_SIGNATURES   (73 entry, satir 6794-6871)  -> v8/node N-API
  - _LUA_SIGNATURES       (52 entry, satir 6879-6932)  -> Lua C API embedding
  - _RUBY_SIGNATURES      (30 entry, satir 6939-6970)  -> Ruby C extension API

Toplam: 155 signature.

ADR 0008 / ADR 0007 A6 — Grup "Languages". Tip A yumusak override pattern'i
(crypto/compression/network/vm_runtime/logging ile ozdes): signature_db.py'de
orijinal dict gövdeleri SILINMEDI; runtime'da bu modulden gelen veriyle
yeniden baglanir. Rollback icin override blogu silinince (try/except
ImportError) eski inline veri otomatik geri devreye girer. Faz A-DELETE
v1.13'te legacy dict'leri kaldiracaktir.

Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur:
  ``v8_node``  <-> ``_V8_NODE_SIGNATURES``
  ``lua``      <-> ``_LUA_SIGNATURES``
  ``ruby``     <-> ``_RUBY_SIGNATURES``

Bilgi: ``v8_node`` dict'i hem V8 embedder API (category="v8") hem Node.js
N-API (category="node") entry'lerini ayni sepette tutar — tarihsel olarak
birlikte yer aldiklari icin Faz 10 kapsami sadece tasimadir; alt kategori
ayirimi sonraki rafinaj fazlarinda ele alinabilir.
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# v8_node (73 entry) — V8 embedder API (Isolate/Context/HandleScope/...)
# ve Node.js N-API (napi_*) yerel addon pattern'leri.
# Kaynak: signature_db.py satir 6794-6871.
# ---------------------------------------------------------------------------
_V8_NODE_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    # --- V8 core ---
    "v8::Isolate::New": {"lib": "v8", "purpose": "create new V8 isolate", "category": "v8"},
    "v8::Isolate::Dispose": {"lib": "v8", "purpose": "dispose V8 isolate", "category": "v8"},
    "v8::Isolate::GetCurrent": {"lib": "v8", "purpose": "get current V8 isolate", "category": "v8"},
    "v8::HandleScope::HandleScope": {"lib": "v8", "purpose": "create V8 handle scope", "category": "v8"},
    "v8::Context::New": {"lib": "v8", "purpose": "create new V8 execution context", "category": "v8"},
    "v8::Script::Compile": {"lib": "v8", "purpose": "compile JavaScript source", "category": "v8"},
    "v8::Script::Run": {"lib": "v8", "purpose": "run compiled JavaScript", "category": "v8"},
    "v8::String::NewFromUtf8": {"lib": "v8", "purpose": "create V8 string from UTF-8", "category": "v8"},
    "v8::Number::New": {"lib": "v8", "purpose": "create V8 number", "category": "v8"},
    "v8::Integer::New": {"lib": "v8", "purpose": "create V8 integer", "category": "v8"},
    "v8::Boolean::New": {"lib": "v8", "purpose": "create V8 boolean", "category": "v8"},
    "v8::Object::New": {"lib": "v8", "purpose": "create V8 object", "category": "v8"},
    "v8::Array::New": {"lib": "v8", "purpose": "create V8 array", "category": "v8"},
    "v8::Function::New": {"lib": "v8", "purpose": "create V8 function", "category": "v8"},
    "v8::Function::Call": {"lib": "v8", "purpose": "call V8 function", "category": "v8"},
    "v8::FunctionTemplate::New": {"lib": "v8", "purpose": "create function template", "category": "v8"},
    "v8::ObjectTemplate::New": {"lib": "v8", "purpose": "create object template", "category": "v8"},
    "v8::FunctionTemplate::GetFunction": {"lib": "v8", "purpose": "get function from template", "category": "v8"},
    "v8::TryCatch::TryCatch": {"lib": "v8", "purpose": "create exception handler scope", "category": "v8"},
    "v8::Value::IsObject": {"lib": "v8", "purpose": "check if value is object", "category": "v8"},
    "v8::Value::IsString": {"lib": "v8", "purpose": "check if value is string", "category": "v8"},
    "v8::Value::IsNumber": {"lib": "v8", "purpose": "check if value is number", "category": "v8"},
    "v8::Value::IsArray": {"lib": "v8", "purpose": "check if value is array", "category": "v8"},
    "v8::Value::IsFunction": {"lib": "v8", "purpose": "check if value is function", "category": "v8"},
    "v8::Value::ToObject": {"lib": "v8", "purpose": "convert value to object", "category": "v8"},
    "v8::Value::ToString": {"lib": "v8", "purpose": "convert value to string", "category": "v8"},
    "v8::Object::Get": {"lib": "v8", "purpose": "get object property", "category": "v8"},
    "v8::Object::Set": {"lib": "v8", "purpose": "set object property", "category": "v8"},
    "v8::Persistent::New": {"lib": "v8", "purpose": "create persistent handle", "category": "v8"},
    "v8::Persistent::Reset": {"lib": "v8", "purpose": "reset persistent handle", "category": "v8"},

    # --- Node.js N-API ---
    "napi_create_function": {"lib": "node", "purpose": "create N-API function", "category": "node"},
    "napi_get_cb_info": {"lib": "node", "purpose": "get N-API callback info", "category": "node"},
    "napi_get_value_string_utf8": {"lib": "node", "purpose": "get string from N-API value", "category": "node"},
    "napi_create_string_utf8": {"lib": "node", "purpose": "create N-API string", "category": "node"},
    "napi_get_value_int32": {"lib": "node", "purpose": "get int32 from N-API value", "category": "node"},
    "napi_get_value_double": {"lib": "node", "purpose": "get double from N-API value", "category": "node"},
    "napi_create_int32": {"lib": "node", "purpose": "create N-API int32", "category": "node"},
    "napi_create_double": {"lib": "node", "purpose": "create N-API double", "category": "node"},
    "napi_create_object": {"lib": "node", "purpose": "create N-API object", "category": "node"},
    "napi_create_array": {"lib": "node", "purpose": "create N-API array", "category": "node"},
    "napi_set_named_property": {"lib": "node", "purpose": "set property on N-API object", "category": "node"},
    "napi_get_named_property": {"lib": "node", "purpose": "get property from N-API object", "category": "node"},
    "napi_set_element": {"lib": "node", "purpose": "set array element", "category": "node"},
    "napi_get_element": {"lib": "node", "purpose": "get array element", "category": "node"},
    "napi_typeof": {"lib": "node", "purpose": "get type of N-API value", "category": "node"},
    "napi_throw_error": {"lib": "node", "purpose": "throw JavaScript error", "category": "node"},
    "napi_create_error": {"lib": "node", "purpose": "create JavaScript error", "category": "node"},
    "napi_is_exception_pending": {"lib": "node", "purpose": "check pending exception", "category": "node"},
    "napi_create_promise": {"lib": "node", "purpose": "create JavaScript Promise", "category": "node"},
    "napi_resolve_deferred": {"lib": "node", "purpose": "resolve Promise", "category": "node"},
    "napi_reject_deferred": {"lib": "node", "purpose": "reject Promise", "category": "node"},
    "napi_create_async_work": {"lib": "node", "purpose": "create async work item", "category": "node"},
    "napi_queue_async_work": {"lib": "node", "purpose": "queue async work for execution", "category": "node"},
    "napi_cancel_async_work": {"lib": "node", "purpose": "cancel async work", "category": "node"},
    "napi_create_buffer": {"lib": "node", "purpose": "create Node.js Buffer", "category": "node"},
    "napi_create_buffer_copy": {"lib": "node", "purpose": "create Buffer with data copy", "category": "node"},
    "napi_get_buffer_info": {"lib": "node", "purpose": "get Buffer data and length", "category": "node"},
    "napi_create_external": {"lib": "node", "purpose": "wrap native pointer as JS value", "category": "node"},
    "napi_get_value_external": {"lib": "node", "purpose": "get native pointer from external", "category": "node"},
    "napi_create_reference": {"lib": "node", "purpose": "create reference to prevent GC", "category": "node"},
    "napi_delete_reference": {"lib": "node", "purpose": "delete reference", "category": "node"},
    "napi_get_reference_value": {"lib": "node", "purpose": "get value from reference", "category": "node"},
    "napi_define_class": {"lib": "node", "purpose": "define JavaScript class from N-API", "category": "node"},
    "napi_wrap": {"lib": "node", "purpose": "associate native data with JS object", "category": "node"},
    "napi_unwrap": {"lib": "node", "purpose": "get native data from JS object", "category": "node"},
    "napi_open_handle_scope": {"lib": "node", "purpose": "open N-API handle scope", "category": "node"},
    "napi_close_handle_scope": {"lib": "node", "purpose": "close N-API handle scope", "category": "node"},
    "napi_get_global": {"lib": "node", "purpose": "get JavaScript global object", "category": "node"},
    "napi_call_function": {"lib": "node", "purpose": "call JavaScript function", "category": "node"},
    "napi_new_instance": {"lib": "node", "purpose": "create new JavaScript instance (new)", "category": "node"},
    "napi_create_threadsafe_function": {"lib": "node", "purpose": "create thread-safe JS function callback", "category": "node"},
    "napi_call_threadsafe_function": {"lib": "node", "purpose": "call thread-safe function from any thread", "category": "node"},
    "napi_release_threadsafe_function": {"lib": "node", "purpose": "release thread-safe function", "category": "node"},
}


# ---------------------------------------------------------------------------
# lua (52 entry) — Lua C API: state lifecycle, stack manipulation,
# table/userdata/metatable, error handling, registry references.
# Kaynak: signature_db.py satir 6879-6932.
# ---------------------------------------------------------------------------
_LUA_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "luaL_newstate": {"lib": "lua", "purpose": "create new Lua state", "category": "lua"},
    "lua_close": {"lib": "lua", "purpose": "close Lua state", "category": "lua"},
    "luaL_openlibs": {"lib": "lua", "purpose": "open standard Lua libraries", "category": "lua"},
    "luaL_dofile": {"lib": "lua", "purpose": "load and execute Lua file", "category": "lua"},
    "luaL_dostring": {"lib": "lua", "purpose": "load and execute Lua string", "category": "lua"},
    "luaL_loadfile": {"lib": "lua", "purpose": "load Lua file as chunk", "category": "lua"},
    "luaL_loadstring": {"lib": "lua", "purpose": "load Lua string as chunk", "category": "lua"},
    "luaL_loadbuffer": {"lib": "lua", "purpose": "load Lua buffer as chunk", "category": "lua"},
    "lua_pcall": {"lib": "lua", "purpose": "protected call (with error handler)", "category": "lua"},
    "lua_call": {"lib": "lua", "purpose": "call Lua function", "category": "lua"},
    "lua_getglobal": {"lib": "lua", "purpose": "get global variable value", "category": "lua"},
    "lua_setglobal": {"lib": "lua", "purpose": "set global variable value", "category": "lua"},
    "lua_pushstring": {"lib": "lua", "purpose": "push string onto stack", "category": "lua"},
    "lua_pushnumber": {"lib": "lua", "purpose": "push number onto stack", "category": "lua"},
    "lua_pushinteger": {"lib": "lua", "purpose": "push integer onto stack", "category": "lua"},
    "lua_pushboolean": {"lib": "lua", "purpose": "push boolean onto stack", "category": "lua"},
    "lua_pushnil": {"lib": "lua", "purpose": "push nil onto stack", "category": "lua"},
    "lua_pushcfunction": {"lib": "lua", "purpose": "push C function onto stack", "category": "lua"},
    "lua_pushlightuserdata": {"lib": "lua", "purpose": "push light userdata", "category": "lua"},
    "lua_tostring": {"lib": "lua", "purpose": "convert stack value to string", "category": "lua"},
    "lua_tonumber": {"lib": "lua", "purpose": "convert stack value to number", "category": "lua"},
    "lua_tointeger": {"lib": "lua", "purpose": "convert stack value to integer", "category": "lua"},
    "lua_toboolean": {"lib": "lua", "purpose": "convert stack value to boolean", "category": "lua"},
    "lua_touserdata": {"lib": "lua", "purpose": "get userdata pointer", "category": "lua"},
    "lua_type": {"lib": "lua", "purpose": "get type of stack value", "category": "lua"},
    "lua_isstring": {"lib": "lua", "purpose": "check if stack value is string", "category": "lua"},
    "lua_isnumber": {"lib": "lua", "purpose": "check if stack value is number", "category": "lua"},
    "lua_istable": {"lib": "lua", "purpose": "check if stack value is table", "category": "lua"},
    "lua_isfunction": {"lib": "lua", "purpose": "check if stack value is function", "category": "lua"},
    "lua_createtable": {"lib": "lua", "purpose": "create new table on stack", "category": "lua"},
    "lua_newtable": {"lib": "lua", "purpose": "create new empty table", "category": "lua"},
    "lua_settable": {"lib": "lua", "purpose": "set table field (t[k]=v)", "category": "lua"},
    "lua_gettable": {"lib": "lua", "purpose": "get table field (v=t[k])", "category": "lua"},
    "lua_setfield": {"lib": "lua", "purpose": "set named field in table", "category": "lua"},
    "lua_getfield": {"lib": "lua", "purpose": "get named field from table", "category": "lua"},
    "lua_rawset": {"lib": "lua", "purpose": "raw table set (no metamethods)", "category": "lua"},
    "lua_rawget": {"lib": "lua", "purpose": "raw table get (no metamethods)", "category": "lua"},
    "lua_newuserdata": {"lib": "lua", "purpose": "create full userdata", "category": "lua"},
    "luaL_newmetatable": {"lib": "lua", "purpose": "create new metatable in registry", "category": "lua"},
    "lua_setmetatable": {"lib": "lua", "purpose": "set metatable for value", "category": "lua"},
    "lua_pop": {"lib": "lua", "purpose": "pop values from stack", "category": "lua"},
    "lua_settop": {"lib": "lua", "purpose": "set stack top index", "category": "lua"},
    "lua_gettop": {"lib": "lua", "purpose": "get stack top index", "category": "lua"},
    "lua_error": {"lib": "lua", "purpose": "raise Lua error", "category": "lua"},
    "luaL_error": {"lib": "lua", "purpose": "raise formatted Lua error", "category": "lua"},
    "luaL_checkstring": {"lib": "lua", "purpose": "check and get string argument", "category": "lua"},
    "luaL_checknumber": {"lib": "lua", "purpose": "check and get number argument", "category": "lua"},
    "luaL_checkinteger": {"lib": "lua", "purpose": "check and get integer argument", "category": "lua"},
    "luaL_ref": {"lib": "lua", "purpose": "create reference in registry", "category": "lua"},
    "luaL_unref": {"lib": "lua", "purpose": "release registry reference", "category": "lua"},
    "lua_register": {"lib": "lua", "purpose": "register C function as global", "category": "lua"},
    "luaL_register": {"lib": "lua", "purpose": "register library functions", "category": "lua"},
}


# ---------------------------------------------------------------------------
# ruby (30 entry) — Ruby C extension API: interpreter lifecycle,
# class/module/method definition, value conversion, exception handling, GC.
# Kaynak: signature_db.py satir 6939-6970.
# ---------------------------------------------------------------------------
_RUBY_SIGNATURES_DATA: dict[str, dict[str, str]] = {
    "ruby_init": {"lib": "ruby", "purpose": "initialize Ruby interpreter", "category": "ruby"},
    "ruby_finalize": {"lib": "ruby", "purpose": "finalize Ruby interpreter", "category": "ruby"},
    "rb_eval_string": {"lib": "ruby", "purpose": "evaluate Ruby string", "category": "ruby"},
    "rb_funcall": {"lib": "ruby", "purpose": "call Ruby method", "category": "ruby"},
    "rb_define_class": {"lib": "ruby", "purpose": "define new Ruby class", "category": "ruby"},
    "rb_define_module": {"lib": "ruby", "purpose": "define new Ruby module", "category": "ruby"},
    "rb_define_method": {"lib": "ruby", "purpose": "define Ruby method", "category": "ruby"},
    "rb_define_singleton_method": {"lib": "ruby", "purpose": "define singleton method", "category": "ruby"},
    "rb_str_new": {"lib": "ruby", "purpose": "create Ruby string", "category": "ruby"},
    "rb_str_new_cstr": {"lib": "ruby", "purpose": "create Ruby string from C string", "category": "ruby"},
    "rb_int2inum": {"lib": "ruby", "purpose": "convert C int to Ruby Integer", "category": "ruby"},
    "rb_float_new": {"lib": "ruby", "purpose": "create Ruby Float", "category": "ruby"},
    "rb_ary_new": {"lib": "ruby", "purpose": "create Ruby Array", "category": "ruby"},
    "rb_ary_push": {"lib": "ruby", "purpose": "push to Ruby Array", "category": "ruby"},
    "rb_hash_new": {"lib": "ruby", "purpose": "create Ruby Hash", "category": "ruby"},
    "rb_hash_aset": {"lib": "ruby", "purpose": "set Hash key-value", "category": "ruby"},
    "rb_hash_aref": {"lib": "ruby", "purpose": "get Hash value by key", "category": "ruby"},
    "rb_raise": {"lib": "ruby", "purpose": "raise Ruby exception", "category": "ruby"},
    "rb_protect": {"lib": "ruby", "purpose": "call with exception protection", "category": "ruby"},
    "rb_rescue": {"lib": "ruby", "purpose": "call with rescue handler", "category": "ruby"},
    "rb_ensure": {"lib": "ruby", "purpose": "call with ensure block", "category": "ruby"},
    "rb_gc_register_mark_object": {"lib": "ruby", "purpose": "register object with GC", "category": "ruby"},
    "rb_iv_get": {"lib": "ruby", "purpose": "get instance variable", "category": "ruby"},
    "rb_iv_set": {"lib": "ruby", "purpose": "set instance variable", "category": "ruby"},
    "rb_require": {"lib": "ruby", "purpose": "require Ruby file", "category": "ruby"},
    "rb_yield": {"lib": "ruby", "purpose": "yield to block", "category": "ruby"},
    "rb_block_given_p": {"lib": "ruby", "purpose": "check if block given", "category": "ruby"},
    "rb_thread_create": {"lib": "ruby", "purpose": "create Ruby thread", "category": "ruby"},
    "rb_thread_schedule": {"lib": "ruby", "purpose": "schedule Ruby thread", "category": "ruby"},
    "Data_Wrap_Struct": {"lib": "ruby", "purpose": "wrap C struct as Ruby object", "category": "ruby"},
}


# ---------------------------------------------------------------------------
# Dispatcher hook — sigdb_builtin.get_category("languages") bu dict'i alir.
# Anahtar isimleri signature_db.py'deki orijinal dict adlariyla uyumludur
# (ornek: "v8_node" <-> _V8_NODE_SIGNATURES).
# ---------------------------------------------------------------------------
SIGNATURES: dict[str, Any] = {
    "v8_node": _V8_NODE_SIGNATURES_DATA,
    "lua": _LUA_SIGNATURES_DATA,
    "ruby": _RUBY_SIGNATURES_DATA,
}


__all__ = ["SIGNATURES"]
