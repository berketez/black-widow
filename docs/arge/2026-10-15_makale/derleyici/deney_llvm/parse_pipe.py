import re, sys
def flat(s):
    # parametreleri <...> sil (iç içe olabilir)
    out=[]; depth=0
    for ch in s:
        if ch=='<': depth+=1; continue
        if ch=='>': depth-=1; continue
        if depth==0: out.append(ch)
    s=''.join(out)
    toks=re.split(r'[(),]', s)
    return [t.strip() for t in toks if t.strip()]
levels=['0','1','2','3','s','z']
seqs={L:flat(open(f'pipe_O{L}.txt').read().strip()) for L in levels}
wrappers={'function','cgscc','loop','loop-mssa','devirt','require','invalidate','coro-cond','repeat'}
for L in levels:
    names=[t for t in seqs[L] if t not in wrappers]
    print(f'O{L}: toplam {len(names)} geçiş örneği, {len(set(names))} farklı')
key=['always-inline','inline','sroa','mem2reg','gvn','newgvn','licm','loop-unroll','loop-unroll-full','loop-vectorize','slp-vectorizer','tailcallelim','ipsccp','deadargelim','argpromotion','globalopt','globaldce','mergefunc','function-specialization','called-value-propagation','jump-threading','instcombine','simplifycfg','early-cse','loop-rotate','indvars','loop-idiom','loop-deletion','memcpyopt','dse','adce','bdce','sccp','correlated-propagation','constraint-elimination','elim-avail-extern','hotcoldsplit','partial-inliner','function-attrs','rpo-function-attrs','openmp-opt','speculative-execution','aggressive-instcombine','loop-distribute','loop-load-elim','vector-combine','div-rem-pairs','loop-sink','instsimplify','constmerge','rel-lookup-table-converter','cg-profile','annotation-remarks','globaldce','mldst-motion','gvn-hoist','lower-constant-intrinsics','chr','loop-unroll-and-jam','loop-interchange','loop-fusion','infer-alignment','alignment-from-assumptions','float2int','lower-expect','loop-instsimplify','loop-simplifycfg','simple-loop-unswitch','move-auto-init','coro-split','inject-tli-mappings','alloc-token','drop-unnecessary-assumes']
print('\n| geçiş | O0 | O1 | O2 | O3 | Os | Oz |')
print('|---|---|---|---|---|---|---|')
for k in key:
    row=[str(seqs[L].count(k)) if k in seqs[L] else '–' for L in levels]
    if any(r!='–' for r in row):
        print(f'| `{k}` | '+' | '.join(row)+' |')
print('\nSadece bazı seviyelerde olanlar:')
allp=set().union(*[set(seqs[L]) for L in levels])-wrappers
for p in sorted(allp):
    pres=[L for L in levels if p in seqs[L]]
    if 1<len(pres)<6 or (len(pres)==1):
        print(p, '->', ','.join('O'+x for x in pres))
