"""T0b bağımsız örneklem denetimi: ajanın ayrıştırıcıları yerine ham Ghidra JSON'u ve Apple dwarfdump.

Her örnekte üç şey denetlenir:
1. DIE'nin adı kayıttaki adla aynı, üst subprogram'ın low_pc + 0x100000 Ghidra girişine eşit.
2. DIE'nin DW_AT_location'ındaki yazmaç (ya da konum listesinin ilk girdisi) Ghidra'da eşlenen
   parametrenin depolamasıyla aynı yazmaç.
"""
import glob
import json
import os
import random
import re
import subprocess
import sys

H = os.path.expanduser('~/karadul_olcum/runs/t0b-1acba60/hizalama')
G = os.path.expanduser('~/karadul_olcum/runs/t0b-1acba60/ghidra_2')
D = os.path.expanduser('~/karadul_olcum/downloads/debian13')
TOHUM, N = int(sys.argv[1]), int(sys.argv[2])

havuz = []
for p in sorted(glob.glob(H + '/*.json')):
    d = json.load(open(p))
    if 'fonksiyonlar' not in d:
        continue
    for fn in d['fonksiyonlar']:
        for pr in fn.get('parametreler', []):
            if pr.get('depolama_kaynagi') == 'dwarf' and pr.get('eslesme') == 'tam':
                havuz.append((d['girdi'], fn, pr))
print('havuz', len(havuz))
ornek = random.Random(TOHUM).sample(havuz, N)


def debug_dosyasi(build_id):
    yol = glob.glob(f'{D}/x_*-dbgsym_*/usr/lib/debug/.build-id/{build_id[:2]}/{build_id[2:]}.debug')
    return yol[0] if yol else None


def yazmac_dwarf(n):
    n = int(n)
    if 0 <= n <= 30:
        return f'x{n}'
    if 64 <= n <= 95:
        return f'v{n - 64}'
    return f'dwarf{n}'


def yazmac_ghidra(ad):
    ad = ad.lower()
    m = re.fullmatch(r'[xw](\d+)', ad)
    if m:
        return f'x{m.group(1)}'
    m = re.fullmatch(r'[qdsbhv](\d+)', ad)
    if m:
        return f'v{m.group(1)}'
    return ad


ghidra_onbellek = {}
tamam = 0
for girdi, fn, pr in ornek:
    ikili = girdi['ikili']
    dbg = debug_dosyasi(girdi['build_id'])
    konum = pr['dwarf']['konum']
    if not konum.startswith('ana:'):
        print('ATLA (ek dosyada):', ikili, konum)
        continue
    off = konum.split(':')[1]
    cikti = subprocess.run(['/usr/bin/dwarfdump', f'--debug-info={off}', '-p', dbg],
                           capture_output=True, text=True).stdout
    # Ad ve konum (DIE'nin kendi satırları: son DW_TAG_formal_parameter bloğu)
    blok = cikti[cikti.rfind('DW_TAG_formal_parameter'):]
    ad_m = (re.search(r'DW_AT_name\s+\("([^"]+)"\)', blok)
            or re.search(r'DW_AT_abstract_origin\s+\(0x[0-9a-f]+ "([^"]+)"\)', blok))
    loc_m = re.search(r'DW_AT_location\s+\((.*?)\)\n\s*(?:DW_AT|$)', blok, re.S)
    lowpc = re.findall(r'DW_TAG_subprogram.*?DW_AT_low_pc\s+\((0x[0-9a-f]+)\)', cikti, re.S)
    regs = re.findall(r'DW_OP_reg(\d+)', loc_m.group(1)) if loc_m else []
    dwarf_reg = yazmac_dwarf(regs[0]) if regs else None
    # Ghidra ham çıktısı
    if ikili not in ghidra_onbellek:
        ghidra_onbellek[ikili] = {f['giris']: f for f in json.load(open(f'{G}/{ikili}.json'))['fonksiyonlar']}
    gf = ghidra_onbellek[ikili].get(fn['ghidra']['giris'])
    gp = gf['decompile']['parametreler'][pr['depolama_ortagi'] - 1]
    g_metin = json.dumps(gp.get('depolama') or gp, ensure_ascii=False)
    g_regs = [yazmac_ghidra(x) for x in re.findall(r'\b([xwqdsbhv]\d{1,2})\b', g_metin)]
    giris_ok = bool(lowpc) and int(lowpc[-1], 16) + 0x100000 == int(fn['ghidra']['giris'], 16)
    ad_ok = bool(ad_m) and ad_m.group(1) == pr['dwarf']['ad']
    reg_ok = dwarf_reg is not None and dwarf_reg in g_regs
    sonuc = 'DOGRU' if (giris_ok and ad_ok and reg_ok) else 'BAK'
    tamam += sonuc == 'DOGRU'
    print(f"{sonuc} {ikili} {fn['dwarf']['ad']}#{pr['dwarf']['sira']} {pr['dwarf']['ad']}: "
          f"dwarf={dwarf_reg} ghidra={g_regs[:3]} giris={giris_ok} ad={ad_ok}"
          + ('' if regs else f" | konum: {(loc_m.group(1)[:90] if loc_m else 'yok')!r}"))
print(f'{tamam}/{len(ornek)}')
