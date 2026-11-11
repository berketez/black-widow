"""GGUF model dosyasının anahtar-değer başlığından mimari alanlarını yazar (tensörler okunmaz).

Kullanım: python3 -I gguf_basligi.py ~/.lmstudio/models/lmstudio-community/Qwen3.8-27B-GGUF/Qwen3.8-27B-Q4_K_M.gguf
"""
import struct
import sys

ALANLAR = ("arch", "block_count", "context_length", "ssm", "interval", "head_count", "embedding_length",
           "attention.key_length", "general.name", "nextn")
TIP = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}

f = open(sys.argv[1], "rb")
assert f.read(4) == b"GGUF"
struct.unpack("<I", f.read(4))
_, n_kv = struct.unpack("<QQ", f.read(16))


def dizgi():
    n, = struct.unpack("<Q", f.read(8))
    return f.read(n).decode("utf-8", "replace")


def deger(t):
    if t in TIP:
        return struct.unpack("<" + TIP[t], f.read(struct.calcsize(TIP[t])))[0]
    if t == 8:
        return dizgi()
    if t == 9:
        at, = struct.unpack("<I", f.read(4))
        n, = struct.unpack("<Q", f.read(8))
        v = [deger(at) for _ in range(n)]
        return v if n <= 70 else f"<dizi, {n} öğe>"
    raise ValueError(t)


for _ in range(n_kv):
    k = dizgi()
    t, = struct.unpack("<I", f.read(4))
    v = deger(t)
    if not k.startswith("tokenizer") and any(a in k for a in ALANLAR):
        print(k, "=", v)
