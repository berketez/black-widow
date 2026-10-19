"""Ghidra 12.1.2 CParser'ın __attribute__((packed)) davranışı (gözlem sınaması).

Aynı alanlarla üç yapı ayrıştırılır: tmux'taki iki __packed__ yapı ve #pragma pack(1)
ile sarılmış bir eşi. Ölçülen (2026-10-19): grid_extd_entry 24 (doğrusu 23),
grid_cell_entry 8 (doğrusu 5), pragma_paketli 23. Yani öznitelik okunup atılıyor,
yalnız #pragma pack uygulanıyor.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ortak, tipler  # noqa: E402

KAYNAK = """
typedef unsigned int u_int; typedef unsigned short u_short; typedef unsigned char u_char;
struct grid_extd_entry { u_int data; u_short attr; u_char flags; int fg; int bg; int us; u_int link; } __attribute__ ((__packed__));
struct grid_cell_entry { union { u_int offset; struct { u_char attr; u_char fg; u_char bg; u_char data; } data; }; u_char flags; } __attribute__ ((__packed__));
#pragma pack(push, 1)
struct pragma_paketli { u_int data; u_short attr; u_char flags; int fg; int bg; int us; u_int link; };
#pragma pack(pop)
"""


def main():
    ortak.jvm_baslat()
    from ghidra.program.model.data import StandAloneDataTypeManager  # type: ignore
    from ghidra.app.util.cparser.C import CParser  # type: ignore
    from java.io import ByteArrayInputStream  # type: ignore
    dtm = StandAloneDataTypeManager("sinama", tipler.veri_duzeni())
    tx = dtm.startTransaction("p")
    CParser(dtm, True, None).parse(ByteArrayInputStream(KAYNAK.encode()))
    for ad, dogru in (("grid_extd_entry", 23), ("grid_cell_entry", 5), ("pragma_paketli", 23)):
        s = tipler.yapilar(dtm, ad)[0]
        print(f"{ad}: Ghidra {s.getLength()} bayt, doğrusu {dogru}, paketleme {s.getPackingType()}")
    dtm.endTransaction(tx, True)


if __name__ == "__main__":
    main()
