"""P02 gerçek pozitif örneği (Windows PE): ithal tablolu, gerçek x86 / x86-64 kodlu küçük PE.

Bu makinede PE bağlayıcısı (lld-link, MinGW) yok; PE elle kurulur. Kod gerçek makine
kodudur (aşağıda her komutun karşılığı yazılı) ve ``--denetle`` ile capstone'la geri
çözülüp yazdırılır. Bölümler:

  .text  (IMAGE_SCN_MEM_EXECUTE) — anti-debug kodu:
         IsDebuggerPresent çağrısı → sonuç sıfır değilse ExitProcess'e dallan;
         CheckRemoteDebuggerPresent(GetCurrentProcess(), &bayrak) → bayrak varsa çık;
         PEB.BeingDebugged (x86-64: mov rax, gs:[60h]; x86: mov eax, fs:[30h]) → çık;
         rdtsc … rdtsc farkı eşiği aşarsa çık;
         x86-64'te ayrıca NtQueryInformationProcess(ProcessDebugPort) → port varsa çık.
         İşlevler arası 0xCC hizalama dolgusu (sonraki işlev 16 bayta hizalı başlar).
  .rdata (yürütülemez) — ithal tablosu + TUZAK: PEB deseni, 7 adet "0F 31", 16 adet 0xCC.
         Bunlar kod olmadığı için SAYILMAMALI (IMZA-02 / IMZA-03).

Kullanım:
    python scripts/measurement/p02_pozitif/pe_sentetik.py --mimari x86_64 --cikti ad_pe_x64.exe
    python scripts/measurement/p02_pozitif/pe_sentetik.py --mimari x86 --cikti ad_pe_x86.exe --denetle
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

DOSYA_HIZA = 0x200
BOLUM_HIZA = 0x1000
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000


class Kod:
    """Etiket + düzeltmeli küçük bayt derleyicisi (yalnız bu örneğin komutları)."""

    def __init__(self) -> None:
        self.b = bytearray()
        self.etiket: dict[str, int] = {}
        self.duzelt: list[tuple[int, str, str]] = []  # (konum, tür, hedef)

    def ekle(self, veri: bytes) -> None:
        self.b += veri

    def ad(self, etiket: str) -> None:
        self.etiket[etiket] = len(self.b)

    def jcc(self, opkod2: bytes, etiket: str) -> None:
        self.b += opkod2 + b"\0\0\0\0"
        self.duzelt.append((len(self.b) - 4, "rel32", etiket))

    def cagir_iat(self, ithal: str, x64: bool) -> None:
        self.b += b"\xff\x15" + b"\0\0\0\0"
        self.duzelt.append((len(self.b) - 4, "riprel" if x64 else "abs32", ithal))

    def hizala(self, n: int, dolgu: bytes = b"\xcc") -> None:
        while len(self.b) % n:
            self.b += dolgu


def _kod_x64(k: Kod) -> None:
    k.ad("main")
    k.ekle(b"\x48\x83\xec\x48")                      # sub rsp, 0x48
    k.cagir_iat("IsDebuggerPresent", True)           # call [IsDebuggerPresent]
    k.ekle(b"\x85\xc0")                              # test eax, eax
    k.jcc(b"\x0f\x85", "cik")                        # jnz cik
    k.cagir_iat("GetCurrentProcess", True)           # call [GetCurrentProcess]
    k.ekle(b"\x48\x89\xc1")                          # mov rcx, rax
    k.ekle(b"\x48\x8d\x54\x24\x30")                  # lea rdx, [rsp+0x30]
    k.cagir_iat("CheckRemoteDebuggerPresent", True)  # call [CheckRemoteDebuggerPresent]
    k.ekle(b"\x83\x7c\x24\x30\x00")                  # cmp dword [rsp+0x30], 0
    k.jcc(b"\x0f\x85", "cik")                        # jne cik
    k.ekle(b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00")  # mov rax, gs:[0x60]  (PEB)
    k.ekle(b"\x0f\xb6\x40\x02")                      # movzx eax, byte [rax+2] (BeingDebugged)
    k.ekle(b"\x85\xc0")                              # test eax, eax
    k.jcc(b"\x0f\x85", "cik")                        # jnz cik
    k.ekle(b"\x0f\x31")                              # rdtsc
    k.ekle(b"\x41\x89\xc0")                          # mov r8d, eax
    k.ekle(b"\x0f\x31")                              # rdtsc
    k.ekle(b"\x44\x29\xc0")                          # sub eax, r8d
    k.ekle(b"\x3d\x00\x00\x10\x00")                  # cmp eax, 0x100000
    k.jcc(b"\x0f\x87", "cik")                        # ja cik
    k.ekle(b"\x48\xc7\xc1\xff\xff\xff\xff")          # mov rcx, -1 (GetCurrentProcess())
    k.ekle(b"\xba\x07\x00\x00\x00")                  # mov edx, 7 (ProcessDebugPort)
    k.ekle(b"\x4c\x8d\x44\x24\x38")                  # lea r8, [rsp+0x38]
    k.ekle(b"\x41\xb9\x08\x00\x00\x00")              # mov r9d, 8
    k.ekle(b"\x48\xc7\x44\x24\x20\x00\x00\x00\x00")  # mov qword [rsp+0x20], 0
    k.cagir_iat("NtQueryInformationProcess", True)   # call [NtQueryInformationProcess]
    k.ekle(b"\x48\x83\x7c\x24\x38\x00")              # cmp qword [rsp+0x38], 0
    k.jcc(b"\x0f\x85", "cik")                        # jne cik
    k.ekle(b"\x31\xc0")                              # xor eax, eax
    k.ekle(b"\x48\x83\xc4\x48")                      # add rsp, 0x48
    k.ekle(b"\xc3")                                  # ret
    k.hizala(16)                                     # int3 hizalama dolgusu
    k.ad("cik")
    k.ekle(b"\x48\x83\xec\x28")                      # sub rsp, 0x28
    k.ekle(b"\x31\xc9")                              # xor ecx, ecx
    k.cagir_iat("ExitProcess", True)                 # call [ExitProcess]
    k.ekle(b"\xcc")                                  # int3
    k.hizala(16)


def _kod_x86(k: Kod) -> None:
    k.ad("main")
    k.cagir_iat("IsDebuggerPresent", False)          # call [IsDebuggerPresent]
    k.ekle(b"\x85\xc0")                              # test eax, eax
    k.jcc(b"\x0f\x85", "cik")                        # jnz cik
    k.ekle(b"\x83\xec\x04")                          # sub esp, 4  (bayrak)
    k.cagir_iat("GetCurrentProcess", False)          # call [GetCurrentProcess]
    k.ekle(b"\x54")                                  # push esp  (&bayrak)
    k.ekle(b"\x50")                                  # push eax  (süreç)
    k.cagir_iat("CheckRemoteDebuggerPresent", False)  # call [CheckRemoteDebuggerPresent]
    k.ekle(b"\x58")                                  # pop eax  (bayrak)
    k.ekle(b"\x85\xc0")                              # test eax, eax
    k.jcc(b"\x0f\x85", "cik")                        # jnz cik
    k.ekle(b"\x64\xa1\x30\x00\x00\x00")              # mov eax, fs:[0x30]  (PEB)
    k.ekle(b"\x0f\xb6\x40\x02")                      # movzx eax, byte [eax+2] (BeingDebugged)
    k.ekle(b"\x85\xc0")                              # test eax, eax
    k.jcc(b"\x0f\x85", "cik")                        # jnz cik
    k.ekle(b"\x0f\x31")                              # rdtsc
    k.ekle(b"\x89\xc1")                              # mov ecx, eax
    k.ekle(b"\x0f\x31")                              # rdtsc
    k.ekle(b"\x29\xc8")                              # sub eax, ecx
    k.ekle(b"\x3d\x00\x00\x10\x00")                  # cmp eax, 0x100000
    k.jcc(b"\x0f\x87", "cik")                        # ja cik
    k.ekle(b"\x31\xc0")                              # xor eax, eax
    k.ekle(b"\xc3")                                  # ret
    k.hizala(16)                                     # int3 hizalama dolgusu
    k.ad("cik")
    k.ekle(b"\x6a\x00")                              # push 0
    k.cagir_iat("ExitProcess", False)                # call [ExitProcess]
    k.ekle(b"\xcc")                                  # int3
    k.hizala(16)


def _hiza(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def pe_kur(mimari: str) -> bytes:
    """Bu örneğin PE'si: anti-debug kodu + ithaller + .rdata tuzağı."""
    x64 = mimari == "x86_64"
    ithaller = {
        "KERNEL32.dll": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                         "GetCurrentProcess", "ExitProcess"],
    }
    if x64:
        ithaller["ntdll.dll"] = ["NtQueryInformationProcess"]
    # Tuzak (yürütülemez bölümde; sayılmamalı)
    tuzak = (b"\0" * 16
             + (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00" if x64 else b"\x64\xa1\x30\x00\x00\x00")
             + b"\x0f\x31" * 7 + b"\xcc" * 16 + b"\0" * 7)
    return pe_olustur(mimari, _kod_x64 if x64 else _kod_x86, ithaller, tuzak)


def pe_olustur(mimari: str, kod_yaz, ithaller: dict[str, list[str]], tuzak: bytes = b"",
               text_nitelik: int = 0x60000020) -> bytes:
    """Genel PE kurucu: .text (``kod_yaz(Kod)`` ya da ham bayt) + .rdata (ithal tablosu + ``tuzak``).

    ``mimari``: "x86_64" (PE32+, AMD64), "x86" (PE32, I386) ya da "arm64" (PE32+, ARM64;
    kod ham bayt olmalı). ``text_nitelik``: .text bölümünün Characteristics alanı.
    """
    x64 = mimari in ("x86_64", "arm64")
    thunk = 8 if x64 else 4
    image_base = 0x140000000 if x64 else 0x400000

    # --- .rdata yerleşimi: IAT | tanımlayıcılar | ILT | ad/ipucu | DLL adları | tuzak ---
    rd = bytearray()
    iat_rva: dict[str, int] = {}
    iat_bas = {}
    for dll, adlar in ithaller.items():
        iat_bas[dll] = RDATA_RVA + len(rd)
        for a in adlar:
            iat_rva[a] = RDATA_RVA + len(rd)
            rd += b"\0" * thunk
        rd += b"\0" * thunk
    iat_boyut = len(rd)
    tanim_rva = RDATA_RVA + len(rd)
    rd += b"\0" * (20 * (len(ithaller) + 1))
    ilt_bas = {}
    for dll, adlar in ithaller.items():
        ilt_bas[dll] = RDATA_RVA + len(rd)
        rd += b"\0" * (thunk * (len(adlar) + 1))
    ad_rva: dict[str, int] = {}
    for adlar in ithaller.values():
        for a in adlar:
            if len(rd) % 2:
                rd += b"\0"
            ad_rva[a] = RDATA_RVA + len(rd)
            rd += struct.pack("<H", 0) + a.encode() + b"\0"
    dll_rva = {}
    for dll in ithaller:
        dll_rva[dll] = RDATA_RVA + len(rd)
        rd += dll.encode() + b"\0"
    rd += tuzak

    def yaz(rva: int, veri: bytes) -> None:
        o = rva - RDATA_RVA
        rd[o:o + len(veri)] = veri

    fmt = "<Q" if x64 else "<I"
    for i, (dll, adlar) in enumerate(ithaller.items()):
        for j, a in enumerate(adlar):
            yaz(iat_bas[dll] + j * thunk, struct.pack(fmt, ad_rva[a]))
            yaz(ilt_bas[dll] + j * thunk, struct.pack(fmt, ad_rva[a]))
        yaz(tanim_rva + 20 * i, struct.pack("<IIIII", ilt_bas[dll], 0, 0, dll_rva[dll], iat_bas[dll]))

    # --- .text ---
    k = Kod()
    if isinstance(kod_yaz, (bytes, bytearray)):
        k.ekle(bytes(kod_yaz))
    else:
        kod_yaz(k)
    for konum, tur, hedef in k.duzelt:
        if tur == "rel32":
            deger = k.etiket[hedef] - (konum + 4)
            k.b[konum:konum + 4] = struct.pack("<i", deger)
        elif tur == "riprel":
            deger = iat_rva[hedef] - (TEXT_RVA + konum + 4)
            k.b[konum:konum + 4] = struct.pack("<i", deger)
        else:  # abs32
            k.b[konum:konum + 4] = struct.pack("<I", image_base + iat_rva[hedef])
    text = bytes(k.b)
    assert len(text) <= RDATA_RVA - TEXT_RVA, "kod .text bölümüne sığmıyor"

    text_ham = _hiza(len(text), DOSYA_HIZA)
    rd_ham = _hiza(len(rd), DOSYA_HIZA)
    text_dosya = DOSYA_HIZA
    rd_dosya = text_dosya + text_ham
    boyut_imaj = RDATA_RVA + _hiza(len(rd), BOLUM_HIZA)

    # --- başlıklar ---
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_boyut = 0xF0 if x64 else 0xE0
    makine = {"x86_64": 0x8664, "x86": 0x14C, "arm64": 0xAA64}[mimari]
    coff = struct.pack("<HHIIIHH", makine, 2, 0, 0, 0, opt_boyut, 0x22 if x64 else 0x102)
    dizinler = [(0, 0)] * 16
    dizinler[1] = (tanim_rva, 20 * (len(ithaller) + 1))
    dizinler[12] = (RDATA_RVA, iat_boyut)
    dizin_b = b"".join(struct.pack("<II", r, s) for r, s in dizinler)
    if x64:
        opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, text_ham, rd_ham, 0, TEXT_RVA, TEXT_RVA)
        opt += struct.pack("<QIIHHHHHHIIIIHHQQQQII", image_base, BOLUM_HIZA, DOSYA_HIZA,
                           6, 0, 0, 0, 6, 0, 0, boyut_imaj, DOSYA_HIZA, 0, 3, 0x8100,
                           0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        opt = struct.pack("<HBBIIIIII", 0x10B, 14, 0, text_ham, rd_ham, 0, TEXT_RVA, TEXT_RVA,
                          RDATA_RVA)
        opt += struct.pack("<IIIHHHHHHIIIIHHIIIIII", image_base, BOLUM_HIZA, DOSYA_HIZA,
                           6, 0, 0, 0, 6, 0, 0, boyut_imaj, DOSYA_HIZA, 0, 3, 0x8100,
                           0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += dizin_b
    assert len(opt) == opt_boyut, (len(opt), opt_boyut)

    def bolum(ad: bytes, vboy: int, rva: int, hboy: int, hptr: int, nit: int) -> bytes:
        return struct.pack("<8sIIIIIIHHI", ad, vboy, rva, hboy, hptr, 0, 0, 0, 0, nit)

    bolumler = (bolum(b".text", len(text), TEXT_RVA, text_ham, text_dosya, text_nitelik)
                + bolum(b".rdata", len(rd), RDATA_RVA, rd_ham, rd_dosya, 0x40000040))
    baslik = bytes(dos) + b"PE\0\0" + coff + opt + bolumler
    assert len(baslik) <= DOSYA_HIZA
    return (baslik.ljust(DOSYA_HIZA, b"\0") + text.ljust(text_ham, b"\0")
            + bytes(rd).ljust(rd_ham, b"\0"))


def denetle(veri: bytes, mimari: str) -> None:
    import capstone
    kip = capstone.CS_MODE_64 if mimari == "x86_64" else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, kip)
    text = veri[DOSYA_HIZA:2 * DOSYA_HIZA]
    for ins in md.disasm(text.rstrip(b"\0"), TEXT_RVA):
        print(f"{ins.address:#06x}  {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mimari", choices=("x86_64", "x86"), required=True)
    ap.add_argument("--cikti", type=Path, required=True)
    ap.add_argument("--denetle", action="store_true", help="kodu capstone ile geri çöz, yazdır")
    a = ap.parse_args()
    veri = pe_kur(a.mimari)
    a.cikti.write_bytes(veri)
    if a.denetle:
        denetle(veri, a.mimari)


if __name__ == "__main__":
    main()
