Creating summary for bol.part.0/19:
  Descriptor for parameter 0 sD.6269
    unused with 1 call_uses
    unsafe by_ref with 1 pass throughs
----------------------------------------
Always executed bbbs : 2, 3
  Descriptor for parameter 0 sD.6269
    (locally) unused
    param_size_limit: 16, size_reached: 0, by_ref


Creating summary for kullan/14:
  Descriptor for parameter 0 vD.6224
    unused with 4 call_uses
    not a candidate
  Descriptor for parameter 1 sD.6225
    unused with 2 call_uses
    not a candidate
  Descriptor for parameter 2 pD.6226
    unused with 1 call_uses
    unsafe by_ref with 1 pass throughs
----------------------------------------
Always executed bbbs : 2
  Descriptor for parameter 0 vD.6224
    (locally) unused
    not a candidate for splitting
  Descriptor for parameter 1 sD.6225
    (locally) unused
    not a candidate for splitting
  Descriptor for parameter 2 pD.6226
    (locally) unused
    param_size_limit: 16, size_reached: 0, by_ref


Creating summary for ikiz_d/11:
  Descriptor for parameter 0 xD.6217
    unused with 0 call_uses remove_only_when_retval_removed
    not a candidate
----------------------------------------
  Descriptor for parameter 0 xD.6217
    (locally) unused
    not a candidate for splitting


Creating summary for ikiz_c/10:
  Descriptor for parameter 0 xD.6214
    unused with 0 call_uses remove_only_when_retval_removed
    not a candidate
----------------------------------------
  Descriptor for parameter 0 xD.6214
    (locally) unused
    not a candidate for splitting


Creating summary for ikiz_b/9:
  Descriptor for parameter 0 xD.6211
    unused with 0 call_uses remove_only_when_retval_removed
    not a candidate
----------------------------------------
  Descriptor for parameter 0 xD.6211
    (locally) unused
    not a candidate for splitting


Creating summary for ikiz_a/8:
  Descriptor for parameter 0 xD.6208
    unused with 0 call_uses remove_only_when_retval_removed
    not a candidate
----------------------------------------
  Descriptor for parameter 0 xD.6208
    (locally) unused
    not a candidate for splitting


Creating summary for bol/7:
  Descriptor for parameter 0 sD.6199
    not a candidate
----------------------------------------
  Descriptor for parameter 0 sD.6199
    not a candidate for splitting


Creating summary for alan_oku/6:
  Descriptor for parameter 0 pD.6195
    unused with 0 call_uses remove_only_when_retval_removed
    unsafe by_ref with 0 pass throughs
        * Access to offset: 64, size: 64, type: long int, alias_ptr_type: long int *, load_count: 1073741824 (estimated locally), nonarg: 1, reverse: 0
  Descriptor for parameter 1 kullanilmayanD.6196
    unused with 0 call_uses
    not a candidate
----------------------------------------
  Descriptor for parameter 0 pD.6195
    (locally) unused
    param_size_limit: 16, size_reached: 8, by_ref, remove_only_when_retval_removed
    * Access to unit offset: 8, unit size: 8, type: long int, alias_ptr_type: long int *, certain
  Descriptor for parameter 1 kullanilmayanD.6196
    (locally) unused
    not a candidate for splitting


Creating summary for olcekle/5:
  Descriptor for parameter 0 xD.6185
    unused with 0 call_uses remove_only_when_retval_removed
    not a candidate
  Descriptor for parameter 1 modeD.6186
    not a candidate
----------------------------------------
  Descriptor for parameter 0 xD.6185
    (locally) unused
    not a candidate for splitting
  Descriptor for parameter 1 modeD.6186
    not a candidate for splitting



========== IPA-SRA IPA stage ==========

Summary for node olcekle.constprop/21:
  Returns value
  Descriptor for parameter 0:
    (locally) unused
    not a candidate for splitting
  Descriptor for parameter 1:
    not a candidate for splitting


Summary for node alan_oku.constprop/20:
  Returns value
  Descriptor for parameter 0:
    (locally) unused
    param_size_limit: 16, size_reached: 8, by_ref, remove_only_when_retval_removed
    * Access to unit offset: 8, unit size: 8, type: long int, alias_ptr_type: long int *, certain
  Descriptor for parameter 1:
    (locally) unused
    not a candidate for splitting


Summary for node bol.part.0/19:
  Descriptor for parameter 0:
    (locally) unused
    param_size_limit: 16, size_reached: 0, by_ref

  Summary for edge bol.part.0/19->fprintf/17:
    return value ignored
    happens before any store to memory
    Parameter 0:
    Parameter 1:
    Parameter 2:
      Scalar param sources: 0
      Pointer pass through from the param given above, safe_to_import_accesses: 1
  Summary for edge bol.part.0/19->abort/18:
    return value ignored

Summary for node kullan/14:
  Returns value
  Descriptor for parameter 0:
    (locally) unused
    not a candidate for splitting
  Descriptor for parameter 1:
    (locally) unused
    not a candidate for splitting
  Descriptor for parameter 2:
    (locally) unused
    param_size_limit: 16, size_reached: 0, by_ref

  Summary for edge kullan/14->ikiz_c/10:
    return value used only to compute caller return value
    Parameter 0:
      Scalar param sources: 0
  Summary for edge kullan/14->ikiz_c/10:
    return value used only to compute caller return value
    Parameter 0:
      Scalar param sources: 0
  Summary for edge kullan/14->bol/7:
    return value used only to compute caller return value
    Parameter 0:
      Scalar param sources: 1
  Summary for edge kullan/14->bol/7:
    return value used only to compute caller return value
    happens before any store to memory
    Parameter 0:
      Scalar param sources: 1
  Summary for edge kullan/14->alan_oku.constprop/20:
    return value used only to compute caller return value
    happens before any store to memory
    Parameter 0:
      Scalar param sources: 2
      Pointer pass through from the param given above, safe_to_import_accesses: 1
    Parameter 1:
  Summary for edge kullan/14->olcekle.constprop/21:
    return value used only to compute caller return value
    Parameter 0:
      Scalar param sources: 0
    Parameter 1:
  Summary for edge kullan/14->olcekle.constprop/21:
    return value used only to compute caller return value
    Parameter 0:
      Scalar param sources: 0
    Parameter 1:

Summary for node ikiz_c/10:
  Returns value
  Descriptor for parameter 0:
    (locally) unused
    not a candidate for splitting


Summary for node ikiz_b/9:
  Returns value
  Descriptor for parameter 0:
    (locally) unused
    not a candidate for splitting


Summary for node ikiz_a/8:
  Returns value
  Descriptor for parameter 0:
    (locally) unused
    not a candidate for splitting


Summary for node bol/7:
  Returns value
  Descriptor for parameter 0:
    not a candidate for splitting

  Summary for edge bol/7->bol.part.0/19:
    return value ignored
    Parameter 0:
      Scalar param sources: 0
      Pointer pass through from the param given above, safe_to_import_accesses: 0
  Summary for edge bol/7->dis_cagri/15:
    return value ignored
    Parameter 0:
      Scalar param sources: 0


Function kullan/14 disqualified because it cannot be made local.
Function ikiz_b/9 disqualified because it cannot be made local.
Function ikiz_a/8 disqualified because it cannot be made local.

========== IPA-SRA decisions ==========

Evaluating analysis results for alan_oku.constprop/20
  Will split parameter 0
    - component at byte offset 8, size 8
  Created new node alan_oku.constprop.isra/22

========== IPA SRA IPA analysis done ==========


Reclaiming functions: alan_oku.constprop/20
Reclaiming variables:
Clearing address taken flags:
Symbol table:

alan_oku.constprop.0.isra.0/22 (alan_oku.constprop.isra)
  Type: function definition analyzed
  Visibility:
  References: 
  Referring: 
  Clone of alan_oku.constprop.0/20
  Availability: local
  Function flags: count:1073741824 (estimated locally) local
  Called by: kullan/14 (1073741824 (estimated locally),1.00 per call) 
  Calls: 
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
  Type: function
  Body removed by symtab_remove_unreachable_nodes
  Visibility:
  References: 
  Referring: 
  Clone of alan_oku/6
  Availability: not_available
  Function flags: count:1073741824 (estimated locally)
  Called by: 
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
  Calls: ikiz_c/10 (1073741824 (estimated locally),1.00 per call) ikiz_c/10 (1073741824 (estimated locally),1.00 per call) bol/7 (1073741824 (estimated locally),1.00 per call) bol/7 (1073741824 (estimated locally),1.00 per call) alan_oku.constprop.0.isra.0/22 (1073741824 (estimated locally),1.00 per call) olcekle.constprop.0/21 (1073741824 (estimated locally),1.00 per call) olcekle.constprop.0/21 (1073741824 (estimated locally),1.00 per call) 
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
void bol.part.0 (const char * s)
{
  long int D.6272;
  long int t;
  int i;
  struct FILE * __stderrp.0_1;

  <bb 3> [local count: 1073741824]:

  <bb 2> [local count: 1073741824]:
  __stderrp.0_1 = __stderrp;
  fprintf (__stderrp.0_1, "hata %s\n", s_2(D));
  abort ();

}


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


