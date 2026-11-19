#!/usr/bin/env python3
"""Kalem 6 — bağımsız sınama nüfusu adaylarının paket boyutları (yerel Debian 13 arm64 dizininden).

Hiçbir şey indirilmez. Kaynak: ``~/karadul_olcum/downloads/debian13/indeks/{main,debug}.Packages.xz``
(2026-10-21'de alınmış dizin dosyaları). Kilitli test / doğrulama setlerindeki programlar aday
listesine konmamıştır (adlar ``docs/arge/test_seti_kilidi.md`` ve ``dogrulama_seti_kilidi.md``'den
okunup dışlandı; setlerin içeriğine bakılmadı).

Kullanım: PYTHONDONTWRITEBYTECODE=1 python scripts/arge/ozkod/aday_paket.py
"""
from __future__ import annotations

import lzma
from pathlib import Path

INDEKS = Path.home() / "karadul_olcum" / "downloads" / "debian13" / "indeks"
# (paket, kayıt çifti türü beklentisi)
ADAYLAR = [
    ("bash", "builtin tablosu {ad, işlev, …} (shell_builtins)"),
    ("nginx", "ngx_command_t {ngx_string(ad), …, işleyici}"),
    ("irssi", "çağrı yeri: command_bind(\"ad\", NULL, işlev), signal_add(\"olay\", işlev)"),
    ("hexchat", "komut tablosu {\"AD\", cmd_ad, …} + GTK sinyalleri"),
    ("jq", "function_list {işlev, \"ad\", n}"),
    ("gawk", "tokentab {\"ad\", …, işlev}"),
    ("tcl8.6", "Tcl_CreateObjCommand(interp, \"ad\", işlev) + komut tabloları"),
    ("libtcl8.6", "Tcl komut tabloları (paylaşımlı kitaplık)"),
    ("python3.13-minimal", "PyMethodDef {\"ad\", işlev, bayrak, belge}"),
    ("libpython3.13-stdlib", "PyMethodDef (uzantı modülleri, .so)"),
    ("lua-socket", "luaL_Reg {\"ad\", işlev}"),
    ("lua-cjson", "luaL_Reg {\"ad\", işlev}"),
    ("postgresql-17", "fmgr_builtins {…, \"ad\", işlev}"),
    ("gedit", "GObject: g_signal_connect(o, \"olay\", G_CALLBACK(işlev)), GActionEntry {\"ad\", işlev}"),
    ("evince", "GActionEntry {\"ad\", işlev}, g_signal_connect"),
    ("mousepad", "GActionEntry {\"ad\", işlev}"),
    ("xfce4-terminal", "GtkActionEntry / g_signal_connect"),
    ("geany", "g_signal_connect + tuş bağlama tabloları"),
    ("pidgin", "purple_signal_connect(h, \"olay\", …, PURPLE_CALLBACK(işlev))"),
    ("xterm", "XtActionsRec {\"ad\", işlev}"),
    ("mc", "komut / tuş tabloları (GLib)"),
    ("busybox", "applet adları ve applet_main[] koşut diziler (kayıt değil, dizin eşlemesi)"),
    ("lighttpd", "config_plugin_values_t {CONST_STR_LEN(ad), …} + eklenti işleyicileri"),
    ("neomutt", "komut tablosu {\"ad\", işlev, veri}"),
]


def paketler(yol: Path) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    with lzma.open(yol, "rt", encoding="utf-8", errors="replace") as f:
        kayit: dict[str, str] = {}
        for satir in f:
            if satir == "\n":
                if "Package" in kayit:
                    out.setdefault(kayit["Package"], kayit)
                kayit = {}
            elif satir[0] not in " \t" and ":" in satir:
                k, v = satir.split(":", 1)
                if k in ("Package", "Version", "Size", "Installed-Size", "Source"):
                    kayit[k] = v.strip()
        if "Package" in kayit:
            out.setdefault(kayit["Package"], kayit)
    return out


def mib(bayt: str | None) -> str:
    return f"{int(bayt) / 1048576:.1f}" if bayt else "—"


def main() -> int:
    ana = paketler(INDEKS / "main.Packages.xz")
    hata = paketler(INDEKS / "debug.Packages.xz")
    print("| paket | sürüm | .deb (MiB) | kurulu (MiB) | -dbgsym .deb (MiB) | beklenen kayıt çifti |")
    print("|---|---|---:|---:|---:|---|")
    toplam = 0
    for ad, tur in ADAYLAR:
        p = ana.get(ad)
        d = hata.get(f"{ad}-dbgsym")
        if p is None:
            print(f"| {ad} | dizinde yok | — | — | — | {tur} |")
            continue
        kurulu = f"{int(p.get('Installed-Size', '0')) / 1024:.1f}"
        toplam += int(p["Size"]) + (int(d["Size"]) if d else 0)
        print(f"| {ad} | {p['Version']} | {mib(p['Size'])} | {kurulu} | {mib(d['Size']) if d else 'dizinde yok'} | {tur} |")
    print(f"\nToplam indirme (.deb + bulunan -dbgsym): {toplam / 1048576:.1f} MiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
