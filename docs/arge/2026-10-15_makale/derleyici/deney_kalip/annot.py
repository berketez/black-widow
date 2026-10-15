"""objdump çıktısındaki stub adreslerini içe aktarılan sembol adlarıyla değiştirir.
Kullanım: python3 annot.py <binary> <asm dosyası> <çıktı>"""
import re, subprocess, sys
b, asm, out = sys.argv[1:4]
txt = subprocess.run(["objdump", "--macho", "--indirect-symbols", b], capture_output=True, text=True).stdout
stubs = {}
sec = None
for line in txt.splitlines():
    if line.startswith("Indirect symbols for"):
        sec = "stubs" if "__stubs" in line else None
        continue
    m = re.match(r"0x([0-9a-f]+)\s+\d+\s+(\S+)", line)
    if m and sec == "stubs":
        stubs[int(m.group(1), 16)] = m.group(2)
def rep(m):
    a = int(m.group(1), 16)
    return f"{m.group(0).split(' <')[0]} <{stubs[a]}@stub>" if a in stubs else m.group(0)
s = open(asm).read()
s = re.sub(r"0x([0-9a-f]+) <_strncmp\+0x[0-9a-f]+>", rep, s)
open(out, "w").write(s)
print(len(stubs), "stub")
