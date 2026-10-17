
IPA constant propagation start:
Determining dynamic type for call: _5 = alan_oku (p_18(D), 0);
  Starting walk at: _5 = alan_oku (p_18(D), 0);
  instance pointer: p_18(D)  Outer instance pointer: p_18(D) offset: 0 (bits) vtbl reference: 
Determining dynamic type for call: _7 = bol (s_19(D));
  Starting walk at: _7 = bol (s_19(D));
  instance pointer: s_19(D)  Outer instance pointer: s_19(D) offset: 0 (bits) vtbl reference: 
Determining dynamic type for call: _10 = bol (_9);
  Starting walk at: _10 = bol (_9);
  instance pointer: _9  Outer instance pointer: _9 offset: 0 (bits) vtbl reference: 
  Function call may change dynamic type:_7 = bol (s_19(D));
Determining dynamic type for call: bol.part.0 (s_14(D));
  Starting walk at: bol.part.0 (s_14(D));
  instance pointer: s_14(D)  Outer instance pointer: s_14(D) offset: 0 (bits) vtbl reference: 
  Function call may change dynamic type:dis_cagri (_7);

IPA structures before propagation:

Jump functions:
  Jump functions of caller  bol.part.0/19:
    callsite  bol.part.0/19 -> fprintf/17 : 
       no arg info
    callsite  bol.part.0/19 -> abort/18 : 
       no arg info
  Jump functions of caller  abort/18:
  Jump functions of caller  fprintf/17:
  Jump functions of caller  dis_cagri/15:
  Jump functions of caller  kullan/14:
    callsite  kullan/14 -> ikiz_c/10 : 
       param 0: PASS THROUGH: 0, op plus_expr 2 (in type long int)
         [irange] long int [-9223372036854775806, +INF]
    callsite  kullan/14 -> ikiz_c/10 : 
       param 0: PASS THROUGH: 0, op nop_expr
         Unknown VR
    callsite  kullan/14 -> bol/7 : 
       param 0: PASS THROUGH: 1, op pointer_plus_expr 1 (in type const char *)
         [prange] const char * [1, +INF]
    callsite  kullan/14 -> bol/7 : 
       param 0: PASS THROUGH: 1, op nop_expr, agg_preserved
         Unknown VR
    callsite  kullan/14 -> alan_oku/6 : 
       param 0: PASS THROUGH: 2, op nop_expr, agg_preserved
         Unknown VR
       param 1: CONST: 0
         [irange] int [0, 0]
    callsite  kullan/14 -> olcekle/5 : 
       param 0: PASS THROUGH: 0, op plus_expr 1 (in type long int)
         [irange] long int [-9223372036854775807, +INF]
       param 1: CONST: 3
         [irange] int [3, 3]
    callsite  kullan/14 -> olcekle/5 : 
       param 0: PASS THROUGH: 0, op nop_expr
         Unknown VR
       param 1: CONST: 3
         [irange] int [3, 3]
  Jump functions of caller  ikiz_c/10:
  Jump functions of caller  ikiz_b/9:
  Jump functions of caller  ikiz_a/8:
  Jump functions of caller  bol/7:
    callsite  bol/7 -> bol.part.0/19 : 
       param 0: PASS THROUGH: 0, op nop_expr
         [prange] const char * [1, +INF]
    callsite  bol/7 -> dis_cagri/15 : 
       no arg info
  Jump functions of caller  alan_oku/6:
  Jump functions of caller  olcekle/5:

 Propagating constants:

Not considering kullan/14 for cloning; -fipa-cp-clone disabled.
Not considering ikiz_b/9 for cloning; -fipa-cp-clone disabled.
Not considering ikiz_a/8 for cloning; -fipa-cp-clone disabled.

overall_size: 97

IPA lattices after all propagation:

Lattices:
  Node: bol.part.0/19:
    param [0]: VARIABLE
         ctxs: VARIABLE
         Bits unusable (BOTTOM)
         [unsupported_range] VARYING
        AGGS VARIABLE
  Node: kullan/14:
    param [0]: BOTTOM
         ctxs: BOTTOM
         Bits unusable (BOTTOM)
         [unsupported_range] VARYING
        AGGS BOTTOM
    param [1]: BOTTOM
         ctxs: BOTTOM
         Bits unusable (BOTTOM)
         [unsupported_range] VARYING
        AGGS BOTTOM
    param [2]: BOTTOM
         ctxs: BOTTOM
         Bits unusable (BOTTOM)
         [unsupported_range] VARYING
        AGGS BOTTOM
  Node: ikiz_c/10:
    param [0]: VARIABLE
         ctxs: VARIABLE
         Bits unusable (BOTTOM)
         [unsupported_range] VARYING
        AGGS VARIABLE
  Node: ikiz_b/9:
    param [0]: BOTTOM
         ctxs: BOTTOM
         Bits unusable (BOTTOM)
         [unsupported_range] VARYING
        AGGS BOTTOM
  Node: ikiz_a/8:
    param [0]: BOTTOM
         ctxs: BOTTOM
         Bits unusable (BOTTOM)
         [unsupported_range] VARYING
        AGGS BOTTOM
  Node: bol/7:
    param [0]: VARIABLE
         ctxs: VARIABLE
         Bits unusable (BOTTOM)
         [unsupported_range] VARYING
        AGGS VARIABLE
  Node: alan_oku/6:
    param [0]: VARIABLE
         ctxs: VARIABLE
         Bits unusable (BOTTOM)
         [unsupported_range] VARYING
        AGGS VARIABLE
    param [1]: 0 [loc_time: 0, loc_size: 0, prop_time: 0, prop_size: 0]
         ctxs: VARIABLE
         Bits: value = 0x0, mask = 0x0
         [irange] int [0, 0]
        AGGS VARIABLE
  Node: olcekle/5:
    param [0]: VARIABLE
         ctxs: VARIABLE
         Bits unusable (BOTTOM)
         [unsupported_range] VARYING
        AGGS VARIABLE
    param [1]: 3 [loc_time: 0, loc_size: 0, prop_time: 0, prop_size: 0]
         ctxs: VARIABLE
         Bits: value = 0x3, mask = 0xf..f00000000
         [irange] int [3, 3]
        AGGS VARIABLE

IPA decision stage (3 sweeps):
   Creating a specialized node of alan_oku/6 for all known contexts.
    replacing param #1 kullanilmayan with const 0
   Creating a specialized node of olcekle/5 for all known contexts.
    replacing param #1 mode with const 3

Purging useless callback edges:

Propagated bits info for function olcekle.constprop/21:
 param 1: value = 0x3, mask = 0xf..f00000000
Propagated bits info for function alan_oku.constprop/20:
 param 1: value = 0x0, mask = 0x0
Propagated bits info for function alan_oku/6:
 param 1: value = 0x0, mask = 0x0
Propagated bits info for function olcekle/5:
 param 1: value = 0x3, mask = 0xf..f00000000

IPA constant propagation end

Reclaiming functions: alan_oku/6 olcekle/5
Reclaiming variables:
Clearing address taken flags:
Symbol table:

olcekle.constprop.0/21 (olcekle.constprop)
  Type: function definition analyzed
  Visibility:
  References: 
  Referring: 
  Clone of olcekle/5
  Availability: local
  Function flags: count:118111600 (estimated locally) local
  Called by: kullan/14 (1073741824 (estimated locally),1.00 per call) kullan/14 (1073741824 (estimated locally),1.00 per call) 
  Calls: 
alan_oku.constprop.0/20 (alan_oku.constprop)
  Type: function definition analyzed
  Visibility:
  References: 
  Referring: 
  Clone of alan_oku/6
  Availability: local
  Function flags: count:1073741824 (estimated locally) local
  Called by: kullan/14 (1073741824 (estimated locally),1.00 per call) 
  Calls: 
bol.part.0/19 (bol.part.0)
  Type: function definition analyzed
  Visibility: semantic_interposition prevailing_def_ironly artificial
  References: __stderrp/16 (read) 
  Referring: 
  Availability: local
  Function flags: count:1073741824 (estimated locally) body local split_part
  Called by: bol/7 (47245 (estimated locally),0.00 per call) 
  Calls: fprintf/17 (1073741824 (estimated locally),1.00 per call) abort/18 (1073741824 (estimated locally),1.00 per call) 
abort/18 (abort)
  Type: function
  Visibility: semantic_interposition external public
  References: 
  Referring: 
  Availability: not_available
  Function flags:
  Called by: bol.part.0/19 (1073741824 (estimated locally),1.00 per call) 
  Calls: 
fprintf/17 (fprintf)
  Type: function
  Visibility: semantic_interposition external public
  References: 
  Referring: 
  Availability: not_available
  Function flags:
  Called by: bol.part.0/19 (1073741824 (estimated locally),1.00 per call) 
  Calls: 
__stderrp/16 (__stderrp)
  Type: variable
  Body removed by symtab_remove_unreachable_nodes
  Visibility: semantic_interposition external public
  References: 
  Referring: bol.part.0/19 (read) 
  Availability: not_available
  Varpool flags:
dis_cagri/15 (dis_cagri)
  Type: function
  Visibility: semantic_interposition external public
  References: 
  Referring: 
  Availability: not_available
  Function flags:
  Called by: bol/7 (193419556 (estimated locally),1.34 per call) 
  Calls: 
kullan/14 (kullan)
  Type: function definition analyzed
  Visibility: externally_visible semantic_interposition public
  References: 
  Referring: 
  Availability: available
  Function flags: count:1073741824 (estimated locally) body
  Called by: 
  Calls: ikiz_c/10 (1073741824 (estimated locally),1.00 per call) ikiz_c/10 (1073741824 (estimated locally),1.00 per call) bol/7 (1073741824 (estimated locally),1.00 per call) bol/7 (1073741824 (estimated locally),1.00 per call) alan_oku.constprop.0/20 (1073741824 (estimated locally),1.00 per call) olcekle.constprop.0/21 (1073741824 (estimated locally),1.00 per call) olcekle.constprop.0/21 (1073741824 (estimated locally),1.00 per call) 
adres_al2/13 (adres_al2)
  Type: variable definition analyzed
  Visibility: externally_visible semantic_interposition public
  References: ikiz_b/9 (addr) 
  Referring: 
  Availability: available
  Varpool flags: initialized
adres_al/12 (adres_al)
  Type: variable definition analyzed
  Visibility: externally_visible semantic_interposition public
  References: ikiz_a/8 (addr) 
  Referring: 
  Availability: available
  Varpool flags: initialized
ikiz_c/10 (ikiz_c)
  Type: function definition analyzed
  Visibility: semantic_interposition prevailing_def_ironly
  References: 
  Referring: 
  Availability: local
  Function flags: count:1073741824 (estimated locally) body local icf_merged
  Called by: kullan/14 (1073741824 (estimated locally),1.00 per call) kullan/14 (1073741824 (estimated locally),1.00 per call) 
  Calls: 
ikiz_b/9 (ikiz_b)
  Type: function definition analyzed
  Visibility: externally_visible semantic_interposition public
  Address is taken.
  References: 
  Referring: adres_al2/13 (addr) 
  Availability: available
  Function flags: count:1073741824 (estimated locally) body
  Called by: 
  Calls: 
ikiz_a/8 (ikiz_a)
  Type: function definition analyzed
  Visibility: externally_visible semantic_interposition public
  Address is taken.
  References: 
  Referring: adres_al/12 (addr) 
  Availability: available
  Function flags: count:1073741824 (estimated locally) body
  Called by: 
  Calls: 
bol/7 (bol)
  Type: function definition analyzed
  Visibility: semantic_interposition prevailing_def_ironly
  References: 
  Referring: 
  Availability: local
  Function flags: count:144196801 (estimated locally) body local
  Called by: kullan/14 (1073741824 (estimated locally),1.00 per call) kullan/14 (1073741824 (estimated locally),1.00 per call) 
  Calls: bol.part.0/19 (47245 (estimated locally),0.00 per call) dis_cagri/15 (193419556 (estimated locally),1.34 per call) 
alan_oku/6 (alan_oku)
  Type: function
  Body removed by symtab_remove_unreachable_nodes
  Visibility: semantic_interposition prevailing_def_ironly
  References: 
  Referring: 
  Availability: not_available
  Function flags: count:1073741824 (estimated locally) body
  Called by: 
  Calls: 
olcekle/5 (olcekle)
  Type: function
  Body removed by symtab_remove_unreachable_nodes
  Visibility: semantic_interposition prevailing_def_ironly
  References: 
  Referring: 
  Availability: not_available
  Function flags: count:118111600 (estimated locally) body
  Called by: 
  Calls: 

;; Function ikiz_a (ikiz_a, funcdef_no=7, decl_uid=6209, cgraph_uid=8, symbol_order=7)

Modification phase of node ikiz_a/8
__attribute__((noinline))
long int ikiz_a (long int x)
{
  long int _1;
  long int _3;

  <bb 2> [local count: 1073741824]:
  _1 = x_2(D) * 7;
  _3 = _1 + 13;
  return _3;

}



;; Function ikiz_b (ikiz_b, funcdef_no=8, decl_uid=6212, cgraph_uid=9, symbol_order=8)

Modification phase of node ikiz_b/9
__attribute__((noinline))
long int ikiz_b (long int x)
{
  long int _1;
  long int _3;

  <bb 2> [local count: 1073741824]:
  _1 = x_2(D) * 7;
  _3 = _1 + 13;
  return _3;

}



;; Function ikiz_c (ikiz_c, funcdef_no=9, decl_uid=6215, cgraph_uid=10, symbol_order=9)

Modification phase of node ikiz_c/10
__attribute__((noinline))
long int ikiz_c (long int x)
{
  long int _1;
  long int _3;

  <bb 2> [local count: 1073741824]:
  _1 = x_2(D) * 5;
  _3 = _1 + 11;
  return _3;

}



;; Function bol (bol, funcdef_no=6, decl_uid=6200, cgraph_uid=7, symbol_order=6)

Modification phase of node bol/7
long int bol (const char * s)
{
  int i;
  long int t;
  long int _1;
  long int _4;
  long int _5;
  sizetype _6;
  const char * _7;
  char _8;
  long int _11;

  <bb 2> [local count: 144196801]:
  if (s_14(D) == 0B)
    goto <bb 9>; [18.09%]
  else
    goto <bb 10>; [81.91%]

  <bb 10> [local count: 118111600]:
  goto <bb 6>; [100.00%]

  <bb 3> [local count: 955630224]:
  _1 = t_9 * 31;
  _4 = (long int) _8;
  t_16 = _1 + _4;
  _5 = t_16 % 97;
  if (_5 == 3)
    goto <bb 4>; [20.24%]
  else
    goto <bb 5>; [79.76%]

  <bb 4> [local count: 193419556]:
  dis_cagri (_7);

  <bb 5> [local count: 955630224]:
  i_18 = i_10 + 1;

  <bb 6> [local count: 1073741824]:
  # t_9 = PHI <0(10), t_16(5)>
  # i_10 = PHI <0(10), i_18(5)>
  _6 = (sizetype) i_10;
  _7 = s_14(D) + _6;
  _8 = *_7;
  if (_8 != 0)
    goto <bb 3>; [89.00%]
  else
    goto <bb 7>; [11.00%]

  <bb 7> [local count: 118111600]:
  if (t_9 == 42)
    goto <bb 8>; [0.04%]
  else
    goto <bb 9>; [99.96%]

  <bb 8> [local count: 47245]:
  bol.part.0 (s_14(D));

  <bb 9> [local count: 144149557]:
  # _11 = PHI <0(2), t_9(7)>
  return _11;

}



;; Function olcekle.constprop (olcekle.constprop.0, funcdef_no=13, decl_uid=6276, cgraph_uid=21, symbol_order=4)

Modification phase of node olcekle.constprop/21
__attribute__((noinline))
long int olcekle.constprop (long int x)
{
  long int r;
  int i;
  int mode;
  long int _2;
  long int _4;
  long int _5;
  long int _6;

  <bb 6> [local count: 118111600]:

  <bb 2> [local count: 118111600]:
  goto <bb 4>; [100.00%]

  <bb 3> [local count: 955630224]:
  _2 = (long int) i_1;
  _4 = _2 * x_3(D);
  _5 = x_3(D) >> i_1;
  _6 = _4 + _5;
  r_8 = _6 + r_7;
  i_9 = i_1 + 1;

  <bb 4> [local count: 1073741824]:
  # r_7 = PHI <0(2), r_8(3)>
  # i_1 = PHI <0(2), i_9(3)>
  if (i_1 <= 2)
    goto <bb 3>; [89.00%]
  else
    goto <bb 5>; [11.00%]

  <bb 5> [local count: 118111600]:
  return r_7;

}



;; Function alan_oku.constprop.isra (alan_oku.constprop.0.isra.0, funcdef_no=15, decl_uid=6277, cgraph_uid=22, symbol_order=5)

Modification phase of node alan_oku.constprop.isra/22
__attribute__((noinline))
long int alan_oku.constprop.isra (long int ISRA.33)
{
  int kullanilmayan;
  struct cift * p;
  long int _1;
  long int _2;
  long int _3;
  long int _4;

  <bb 4> [local count: 1073741824]:

  <bb 2> [local count: 1073741824]:

  <bb 3> [local count: 1073741824]:
  _1 = ISRA.33_5(D);
  _2 = _1 * 3;
  _3 = _1 / 7;
  _4 = _2 + _3;
  return _4;

}



;; Function kullan (kullan, funcdef_no=11, decl_uid=6227, cgraph_uid=14, symbol_order=13)

Modification phase of node kullan/14
long int kullan (long int v, const char * s, struct cift * p)
{
  long int _1;
  long int _2;
  long int _3;
  long int _4;
  long int _5;
  long int _6;
  long int _7;
  long int _8;
  const char * _9;
  long int _10;
  long int _11;
  long int _12;
  long int _13;
  long int _14;
  long int _15;
  long int _22;

  <bb 2> [local count: 1073741824]:
  _1 = olcekle (v_17(D), 3);
  _2 = v_17(D) + 1;
  _3 = olcekle (_2, 3);
  _4 = _1 + _3;
  _5 = alan_oku (p_18(D), 0);
  _6 = _4 + _5;
  _7 = bol (s_19(D));
  _8 = _6 + _7;
  _9 = s_19(D) + 1;
  _10 = bol (_9);
  _11 = _8 + _10;
  _12 = ikiz_c (v_17(D));
  _13 = _11 + _12;
  _14 = v_17(D) + 2;
  _15 = ikiz_d (_14);
  _22 = _13 + _15;
  return _22;

}


