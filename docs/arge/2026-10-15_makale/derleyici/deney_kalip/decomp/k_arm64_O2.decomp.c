// ==== _sw_dense @ 100000548

undefined4 _sw_dense(uint param_1)

{
  if (param_1 < 8) {
    return *(undefined4 *)(&DAT_1000018c8 + (ulong)param_1 * 4);
  }
  return 0xffffffff;
}


// ==== _sw_sparse @ 100000568

undefined8 _sw_sparse(int param_1)

{
  if (param_1 < 5000) {
    if (param_1 == 3) {
      return 1;
    }
    if (param_1 == 100) {
      return 2;
    }
    if (param_1 == 1000) {
      return 3;
    }
  }
  else if (param_1 < 0x12fd1) {
    if (param_1 == 5000) {
      return 4;
    }
    if (param_1 == 20000) {
      return 5;
    }
  }
  else {
    if (param_1 == 0x12fd1) {
      return 6;
    }
    if (param_1 == 0x1e240) {
      return 7;
    }
  }
  return 0;
}


// ==== _sw_bittest @ 100000614

undefined8 _sw_bittest(uint param_1)

{
  if ((param_1 < 0x3c) && ((1L << ((ulong)param_1 & 0x3f) & 0x800100100003e00U) != 0)) {
    return 1;
  }
  return 0;
}


// ==== _udiv7 @ 10000064c

ulong _udiv7(uint param_1)

{
  return (ulong)param_1 / 7;
}


// ==== _sdiv7 @ 10000066c

int _sdiv7(int param_1)

{
  return param_1 / 7;
}


// ==== _umod10 @ 10000068c

uint _umod10(uint param_1)

{
  return param_1 % 10;
}


// ==== _sdiv16 @ 1000006a8

int _sdiv16(int param_1)

{
  int iVar1;
  
  iVar1 = param_1 + 0xf;
  if (-1 < param_1) {
    iVar1 = param_1;
  }
  return iVar1 >> 4;
}


// ==== _udiv1000_64 @ 1000006bc

ulong _udiv1000_64(ulong param_1)

{
  return param_1 / 1000;
}


// ==== _sel_max @ 1000006dc

int _sel_max(int param_1,int param_2)

{
  if (param_1 <= param_2) {
    param_1 = param_2;
  }
  return param_1;
}


// ==== _sel_abs @ 1000006e8

int _sel_abs(int param_1)

{
  int iVar1;
  
  iVar1 = -param_1;
  if (-1 < param_1) {
    iVar1 = param_1;
  }
  return iVar1;
}


// ==== _sel_clamp @ 1000006f4

int _sel_clamp(int param_1,int param_2,int param_3)

{
  int iVar1;
  
  iVar1 = param_1;
  if (param_3 <= param_1) {
    iVar1 = param_3;
  }
  if (param_2 <= param_1) {
    param_2 = iVar1;
  }
  return param_2;
}


// ==== _popcount_loop @ 100000708

undefined4 _popcount_loop(undefined4 param_1)

{
  char cVar1;
  char cVar2;
  char cVar3;
  
  cVar1 = POPCOUNT((char)((uint)param_1 >> 8));
  cVar2 = POPCOUNT((char)((uint)param_1 >> 0x10));
  cVar3 = POPCOUNT((char)((uint)param_1 >> 0x18));
  return CONCAT31((int3)(CONCAT13(cVar3,CONCAT12(cVar2,CONCAT11(cVar1,POPCOUNT((char)param_1)))) >>
                        8),POPCOUNT((char)param_1) + cVar1 + cVar2 + cVar3);
}


// ==== _bswap32_manual @ 10000071c

uint _bswap32_manual(uint param_1)

{
  uint uVar1;
  
  uVar1 = (param_1 & 0xff00ff00) >> 8 | (param_1 & 0xff00ff) << 8;
  return uVar1 >> 0x10 | uVar1 << 0x10;
}


// ==== _rotl32 @ 100000724

uint _rotl32(uint param_1,int param_2)

{
  return param_1 >> (-param_2 & 0x1fU) | param_1 << 0x20 - (-param_2 & 0x1fU);
}


// ==== _is_pow2 @ 100000730

bool _is_pow2(uint param_1)

{
  return param_1 != 0 && (param_1 & param_1 - 1) == 0;
}


// ==== _copy16 @ 100000748

void _copy16(undefined8 *param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  
  uVar1 = *param_2;
  param_1[1] = param_2[1];
  *param_1 = uVar1;
  return;
}


// ==== _zero64 @ 100000754

void _zero64(undefined8 *param_1)

{
  param_1[5] = 0;
  param_1[4] = 0;
  param_1[7] = 0;
  param_1[6] = 0;
  param_1[1] = 0;
  *param_1 = 0;
  param_1[3] = 0;
  param_1[2] = 0;
  return;
}


// ==== _strlen_const @ 100000768

undefined8 _strlen_const(void)

{
  return 7;
}


// ==== _strcmp_const @ 100000770

bool _strcmp_const(char *param_1)

{
  int iVar1;
  
  iVar1 = _strcmp(param_1,"GET");
  return iVar1 == 0;
}


// ==== _strncmp_const @ 100000794

bool _strncmp_const(char *param_1)

{
  int iVar1;
  
  iVar1 = _strncmp(param_1,"HTTP/1.",7);
  return iVar1 == 0;
}


// ==== _loop_zero @ 1000007bc

void _loop_zero(void *param_1,uint param_2)

{
  if (0 < (int)param_2) {
    _bzero(param_1,(ulong)param_2 << 2);
    return;
  }
  return;
}


// ==== _loop_copy @ 1000007d0

void _loop_copy(void *param_1,void *param_2,uint param_3)

{
  if (0 < (int)param_3) {
    _memcpy(param_1,param_2,(ulong)param_3);
    return;
  }
  return;
}


// ==== _make_big @ 1000007e8

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void _make_big(long *param_1,long param_2)

{
  long lVar1;
  
  *param_1 = param_2;
  lVar1 = param_2 + _DAT_100001670;
  param_1[2] = param_2 + _UNK_100001678;
  param_1[1] = lVar1;
  lVar1 = param_2 + _DAT_100001680;
  param_1[4] = param_2 + _UNK_100001688;
  param_1[3] = lVar1;
  lVar1 = param_2 + _DAT_100001690;
  param_1[6] = param_2 + _UNK_100001698;
  param_1[5] = lVar1;
  param_1[7] = param_2 + 7;
  return;
}


// ==== _use_big @ 10000082c

long _use_big(void)

{
  undefined1 auStack_50 [24];
  long local_38;
  long local_18;
  
  _make_big(auStack_50);
  return local_18 + local_38;
}


// ==== _make_small @ 100000858

undefined8 _make_small(int param_1)

{
  return CONCAT44(param_1 * 3,param_1);
}


// ==== _sum_va @ 100000868

int _sum_va(int param_1)

{
  int iVar1;
  int *piVar2;
  
  if (param_1 < 1) {
    iVar1 = 0;
  }
  else {
    iVar1 = 0;
    piVar2 = (int *)register0x00000008;
    do {
      iVar1 = *piVar2 + iVar1;
      param_1 = param_1 + -1;
      piVar2 = piVar2 + 2;
    } while (param_1 != 0);
  }
  return iVar1;
}


// ==== _ssp_copy @ 1000008b0

int _ssp_copy(undefined8 param_1)

{
  size_t sVar1;
  char acStack_58 [3];
  char local_55;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004018;
  ___strcpy_chk(acStack_58,param_1,0x40);
  sVar1 = _strlen(acStack_58);
  if (*(long *)PTR____stack_chk_guard_100004018 == local_18) {
    return (int)local_55 + (int)sVar1;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}


// ==== _fortify_memcpy @ 100000914

void _fortify_memcpy(undefined8 *param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 local_48;
  undefined8 uStack_40;
  undefined8 local_38;
  undefined8 uStack_30;
  long local_28;
  
  local_28 = *(long *)PTR____stack_chk_guard_100004018;
  ___memcpy_chk(&local_48,param_2,param_3,0x20);
  param_1[1] = uStack_40;
  *param_1 = local_48;
  param_1[3] = uStack_30;
  param_1[2] = local_38;
  if (*(long *)PTR____stack_chk_guard_100004018 == local_28) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}


// ==== _fortify_snprintf @ 10000097c

int _fortify_snprintf(char *param_1,size_t param_2)

{
  int iVar1;
  
  iVar1 = _snprintf(param_1,param_2,"deger=%d");
  return iVar1;
}


// ==== _read_file_head @ 1000009a4

size_t _read_file_head(char *param_1,void *param_2,size_t param_3)

{
  int iVar1;
  void *pvVar2;
  size_t sVar3;
  int *piVar4;
  FILE *pFVar5;
  
  iVar1 = _open(param_1,0x1000000);
  if (iVar1 < 0) {
    pFVar5 = *(FILE **)PTR____stderrp_100004020;
    piVar4 = ___error();
    _strerror(*piVar4);
    _fprintf(pFVar5,"open %s: %s\n");
    sVar3 = 0xffffffff;
  }
  else {
    pvVar2 = _malloc(param_3);
    if (pvVar2 == (void *)0x0) {
      sVar3 = 0xffffffff;
    }
    else {
      sVar3 = _read(iVar1,pvVar2,param_3);
      if ((long)sVar3 < 0) {
        piVar4 = ___error();
        *piVar4 = 5;
        sVar3 = 0xffffffff;
      }
      else {
        _memcpy(param_2,pvVar2,sVar3);
      }
      _free(pvVar2);
    }
    _close(iVar1);
  }
  return sVar3;
}


// ==== _tail_target @ 100000a8c

int _tail_target(int param_1)

{
  return param_1 * 3 + 1;
}


// ==== _tail_caller @ 100000a98

void _tail_caller(int param_1)

{
  _tail_target(param_1 + 1);
  return;
}


// ==== _tail_ext @ 100000aa0

int _tail_ext(long param_1)

{
  int iVar1;
  
  iVar1 = _atoi((char *)(param_1 + 1));
  return iVar1;
}


// ==== _vadd @ 100000aa8

void _vadd(long param_1,long param_2,long param_3,uint param_4)

{
  ulong uVar1;
  long lVar2;
  ulong uVar3;
  ulong uVar4;
  undefined8 *puVar5;
  int *piVar6;
  undefined8 *puVar7;
  int *piVar8;
  undefined8 *puVar9;
  long lVar10;
  int *piVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  undefined8 uVar14;
  undefined8 uVar15;
  undefined8 uVar16;
  undefined8 uVar17;
  undefined8 uVar18;
  undefined8 uVar19;
  undefined8 uVar20;
  undefined8 uVar21;
  undefined8 uVar22;
  undefined8 uVar23;
  undefined8 uVar24;
  undefined8 uVar25;
  
  if ((int)param_4 < 1) {
    return;
  }
  uVar1 = (ulong)param_4;
  if (param_4 < 4) {
    uVar3 = 0;
  }
  else {
    if (param_4 < 0x10) {
      uVar4 = 0;
    }
    else {
      uVar3 = uVar1 & 0x7ffffff0;
      puVar5 = (undefined8 *)(param_2 + 0x20);
      puVar7 = (undefined8 *)(param_3 + 0x20);
      puVar9 = (undefined8 *)(param_1 + 0x20);
      uVar4 = uVar3;
      do {
        uVar12 = puVar5[-4];
        uVar14 = puVar5[-1];
        uVar13 = puVar5[-2];
        uVar16 = puVar5[1];
        uVar15 = *puVar5;
        uVar18 = puVar5[3];
        uVar17 = puVar5[2];
        uVar19 = puVar7[-4];
        uVar21 = puVar7[-1];
        uVar20 = puVar7[-2];
        uVar23 = puVar7[1];
        uVar22 = *puVar7;
        uVar25 = puVar7[3];
        uVar24 = puVar7[2];
        puVar9[-3] = CONCAT44((int)((ulong)puVar7[-3] >> 0x20) + (int)((ulong)puVar5[-3] >> 0x20),
                              (int)puVar7[-3] + (int)puVar5[-3]);
        puVar9[-4] = CONCAT44((int)((ulong)uVar19 >> 0x20) + (int)((ulong)uVar12 >> 0x20),
                              (int)uVar19 + (int)uVar12);
        puVar9[-1] = CONCAT44((int)((ulong)uVar21 >> 0x20) + (int)((ulong)uVar14 >> 0x20),
                              (int)uVar21 + (int)uVar14);
        puVar9[-2] = CONCAT44((int)((ulong)uVar20 >> 0x20) + (int)((ulong)uVar13 >> 0x20),
                              (int)uVar20 + (int)uVar13);
        puVar9[1] = CONCAT44((int)((ulong)uVar23 >> 0x20) + (int)((ulong)uVar16 >> 0x20),
                             (int)uVar23 + (int)uVar16);
        *puVar9 = CONCAT44((int)((ulong)uVar22 >> 0x20) + (int)((ulong)uVar15 >> 0x20),
                           (int)uVar22 + (int)uVar15);
        puVar9[3] = CONCAT44((int)((ulong)uVar25 >> 0x20) + (int)((ulong)uVar18 >> 0x20),
                             (int)uVar25 + (int)uVar18);
        puVar9[2] = CONCAT44((int)((ulong)uVar24 >> 0x20) + (int)((ulong)uVar17 >> 0x20),
                             (int)uVar24 + (int)uVar17);
        uVar4 = uVar4 - 0x10;
        puVar5 = puVar5 + 8;
        puVar7 = puVar7 + 8;
        puVar9 = puVar9 + 8;
      } while (uVar4 != 0);
      if (uVar3 == uVar1) {
        return;
      }
      uVar4 = uVar3;
      if ((param_4 & 0xc) == 0) goto LAB_100000b64;
    }
    uVar3 = uVar1 & 0x7ffffffc;
    lVar2 = uVar4 - uVar3;
    lVar10 = uVar4 * 4;
    puVar5 = (undefined8 *)(param_1 + lVar10);
    puVar7 = (undefined8 *)(param_3 + lVar10);
    puVar9 = (undefined8 *)(param_2 + lVar10);
    do {
      uVar12 = *puVar9;
      uVar13 = *puVar7;
      puVar5[1] = CONCAT44((int)((ulong)puVar7[1] >> 0x20) + (int)((ulong)puVar9[1] >> 0x20),
                           (int)puVar7[1] + (int)puVar9[1]);
      *puVar5 = CONCAT44((int)((ulong)uVar13 >> 0x20) + (int)((ulong)uVar12 >> 0x20),
                         (int)uVar13 + (int)uVar12);
      lVar2 = lVar2 + 4;
      puVar5 = puVar5 + 2;
      puVar7 = puVar7 + 2;
      puVar9 = puVar9 + 2;
    } while (lVar2 != 0);
    if (uVar3 == uVar1) {
      return;
    }
  }
LAB_100000b64:
  lVar10 = uVar3 * 4;
  lVar2 = uVar1 - uVar3;
  piVar6 = (int *)(param_1 + lVar10);
  piVar8 = (int *)(param_3 + lVar10);
  piVar11 = (int *)(param_2 + lVar10);
  do {
    *piVar6 = *piVar8 + *piVar11;
    lVar2 = lVar2 + -1;
    piVar6 = piVar6 + 1;
    piVar8 = piVar8 + 1;
    piVar11 = piVar11 + 1;
  } while (lVar2 != 0);
  return;
}


// ==== _vsum @ 100000b94

int _vsum(long param_1,uint param_2)

{
  undefined8 *puVar1;
  ulong uVar2;
  long lVar3;
  ulong uVar4;
  ulong uVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  int iVar20;
  int iVar21;
  int iVar22;
  
  if ((int)param_2 < 1) {
    return 0;
  }
  uVar2 = (ulong)param_2;
  if (param_2 < 4) {
    uVar4 = 0;
    iVar7 = 0;
  }
  else {
    if (param_2 < 0x10) {
      iVar7 = 0;
      uVar5 = 0;
    }
    else {
      uVar4 = uVar2 & 0x7ffffff0;
      iVar7 = 0;
      iVar8 = 0;
      iVar9 = 0;
      iVar10 = 0;
      iVar11 = 0;
      iVar12 = 0;
      iVar13 = 0;
      iVar14 = 0;
      iVar15 = 0;
      iVar16 = 0;
      iVar17 = 0;
      iVar18 = 0;
      iVar19 = 0;
      iVar20 = 0;
      iVar21 = 0;
      iVar22 = 0;
      puVar1 = (undefined8 *)(param_1 + 0x20);
      uVar5 = uVar4;
      do {
        iVar7 = (int)puVar1[-4] + iVar7;
        iVar8 = (int)((ulong)puVar1[-4] >> 0x20) + iVar8;
        iVar9 = (int)puVar1[-3] + iVar9;
        iVar10 = (int)((ulong)puVar1[-3] >> 0x20) + iVar10;
        iVar11 = (int)puVar1[-2] + iVar11;
        iVar12 = (int)((ulong)puVar1[-2] >> 0x20) + iVar12;
        iVar13 = (int)puVar1[-1] + iVar13;
        iVar14 = (int)((ulong)puVar1[-1] >> 0x20) + iVar14;
        iVar15 = (int)*puVar1 + iVar15;
        iVar16 = (int)((ulong)*puVar1 >> 0x20) + iVar16;
        iVar17 = (int)puVar1[1] + iVar17;
        iVar18 = (int)((ulong)puVar1[1] >> 0x20) + iVar18;
        iVar19 = (int)puVar1[2] + iVar19;
        iVar20 = (int)((ulong)puVar1[2] >> 0x20) + iVar20;
        iVar21 = (int)puVar1[3] + iVar21;
        iVar22 = (int)((ulong)puVar1[3] >> 0x20) + iVar22;
        uVar5 = uVar5 - 0x10;
        puVar1 = puVar1 + 8;
      } while (uVar5 != 0);
      iVar7 = iVar19 + iVar15 + iVar11 + iVar7 + iVar20 + iVar16 + iVar12 + iVar8 +
              iVar21 + iVar17 + iVar13 + iVar9 + iVar22 + iVar18 + iVar14 + iVar10;
      if (uVar4 == uVar2) {
        return iVar7;
      }
      uVar5 = uVar4;
      if ((param_2 & 0xc) == 0) goto LAB_100000c6c;
    }
    uVar4 = uVar2 & 0x7ffffffc;
    iVar9 = 0;
    iVar10 = 0;
    iVar8 = 0;
    lVar3 = uVar5 - uVar4;
    puVar1 = (undefined8 *)(param_1 + uVar5 * 4);
    do {
      iVar7 = (int)*puVar1 + iVar7;
      iVar8 = (int)((ulong)*puVar1 >> 0x20) + iVar8;
      iVar9 = (int)puVar1[1] + iVar9;
      iVar10 = (int)((ulong)puVar1[1] >> 0x20) + iVar10;
      lVar3 = lVar3 + 4;
      puVar1 = puVar1 + 2;
    } while (lVar3 != 0);
    iVar7 = iVar7 + iVar8 + iVar9 + iVar10;
    if (uVar4 == uVar2) {
      return iVar7;
    }
  }
LAB_100000c6c:
  lVar3 = uVar2 - uVar4;
  piVar6 = (int *)(param_1 + uVar4 * 4);
  do {
    iVar7 = *piVar6 + iVar7;
    lVar3 = lVar3 + -1;
    piVar6 = piVar6 + 1;
  } while (lVar3 != 0);
  return iVar7;
}


// ==== _vdot @ 100000c8c

float _vdot(long param_1,long param_2,uint param_3)

{
  ulong uVar1;
  long lVar2;
  ulong uVar3;
  ulong uVar4;
  undefined8 *puVar5;
  float *pfVar6;
  undefined8 *puVar7;
  float *pfVar8;
  float fVar9;
  
  if ((int)param_3 < 1) {
    return 0.0;
  }
  uVar1 = (ulong)param_3;
  if (param_3 < 4) {
    uVar3 = 0;
    fVar9 = 0.0;
  }
  else {
    if (param_3 < 0x10) {
      fVar9 = 0.0;
      uVar4 = 0;
    }
    else {
      uVar3 = uVar1 & 0x7ffffff0;
      fVar9 = 0.0;
      puVar5 = (undefined8 *)(param_1 + 0x20);
      puVar7 = (undefined8 *)(param_2 + 0x20);
      uVar4 = uVar3;
      do {
        fVar9 = fVar9 + (float)puVar5[-4] * (float)puVar7[-4] +
                (float)((ulong)puVar5[-4] >> 0x20) * (float)((ulong)puVar7[-4] >> 0x20) +
                (float)puVar5[-3] * (float)puVar7[-3] +
                (float)((ulong)puVar5[-3] >> 0x20) * (float)((ulong)puVar7[-3] >> 0x20) +
                (float)puVar5[-2] * (float)puVar7[-2] +
                (float)((ulong)puVar5[-2] >> 0x20) * (float)((ulong)puVar7[-2] >> 0x20) +
                (float)puVar5[-1] * (float)puVar7[-1] +
                (float)((ulong)puVar5[-1] >> 0x20) * (float)((ulong)puVar7[-1] >> 0x20) +
                (float)*puVar5 * (float)*puVar7 +
                (float)((ulong)*puVar5 >> 0x20) * (float)((ulong)*puVar7 >> 0x20) +
                (float)puVar5[1] * (float)puVar7[1] +
                (float)((ulong)puVar5[1] >> 0x20) * (float)((ulong)puVar7[1] >> 0x20) +
                (float)puVar5[2] * (float)puVar7[2] +
                (float)((ulong)puVar5[2] >> 0x20) * (float)((ulong)puVar7[2] >> 0x20) +
                (float)puVar5[3] * (float)puVar7[3] +
                (float)((ulong)puVar5[3] >> 0x20) * (float)((ulong)puVar7[3] >> 0x20);
        uVar4 = uVar4 - 0x10;
        puVar5 = puVar5 + 8;
        puVar7 = puVar7 + 8;
      } while (uVar4 != 0);
      if (uVar3 == uVar1) {
        return fVar9;
      }
      uVar4 = uVar3;
      if ((param_3 & 0xc) == 0) goto LAB_100000dd4;
    }
    uVar3 = uVar1 & 0x7ffffffc;
    lVar2 = uVar4 - uVar3;
    puVar5 = (undefined8 *)(param_2 + uVar4 * 4);
    puVar7 = (undefined8 *)(param_1 + uVar4 * 4);
    do {
      fVar9 = fVar9 + (float)*puVar7 * (float)*puVar5 +
              (float)((ulong)*puVar7 >> 0x20) * (float)((ulong)*puVar5 >> 0x20) +
              (float)puVar7[1] * (float)puVar5[1] +
              (float)((ulong)puVar7[1] >> 0x20) * (float)((ulong)puVar5[1] >> 0x20);
      lVar2 = lVar2 + 4;
      puVar5 = puVar5 + 2;
      puVar7 = puVar7 + 2;
    } while (lVar2 != 0);
    if (uVar3 == uVar1) {
      return fVar9;
    }
  }
LAB_100000dd4:
  lVar2 = uVar1 - uVar3;
  pfVar6 = (float *)(param_2 + uVar3 * 4);
  pfVar8 = (float *)(param_1 + uVar3 * 4);
  do {
    fVar9 = fVar9 + *pfVar6 * *pfVar8;
    lVar2 = lVar2 + -1;
    pfVar6 = pfVar6 + 1;
    pfVar8 = pfVar8 + 1;
  } while (lVar2 != 0);
  return fVar9;
}


// ==== _md5_init @ 100000dfc

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void _md5_init(undefined8 *param_1)

{
  undefined8 uVar1;
  
  uVar1 = _DAT_1000016a0;
  param_1[1] = _UNK_1000016a8;
  *param_1 = uVar1;
  return;
}


// ==== _crc32_make_table @ 100000e0c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void _crc32_make_table(void)

{
  undefined1 auVar1 [16];
  undefined3 uVar2;
  undefined1 auVar3 [16];
  undefined1 auVar4 [16];
  undefined1 auVar5 [16];
  undefined1 auVar6 [16];
  undefined1 auVar7 [16];
  undefined1 auVar8 [16];
  undefined1 auVar9 [16];
  uint uVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  undefined1 auVar15 [16];
  undefined1 auVar16 [16];
  undefined1 auVar17 [16];
  undefined1 auVar18 [16];
  undefined1 auVar19 [16];
  undefined1 auVar20 [16];
  undefined1 auVar21 [16];
  undefined1 auVar22 [16];
  long lVar23;
  uint uVar25;
  undefined *puVar24;
  uint uVar27;
  ulong uVar26;
  uint5 uVar28;
  undefined1 auVar29 [16];
  undefined1 auVar30 [16];
  undefined1 auVar31 [16];
  undefined1 auVar32 [16];
  undefined1 auVar33 [16];
  undefined1 auVar34 [16];
  undefined1 auVar35 [16];
  undefined1 auVar36 [16];
  undefined1 auVar37 [16];
  byte bVar38;
  undefined1 uVar39;
  undefined1 uVar40;
  undefined1 uVar41;
  byte bVar42;
  byte bVar43;
  byte bVar44;
  byte bVar45;
  byte bVar46;
  byte bVar47;
  byte bVar48;
  byte bVar49;
  byte bVar50;
  byte bVar51;
  byte bVar52;
  byte bVar53;
  byte bVar54;
  byte bVar55;
  byte bVar56;
  
  lVar23 = 0;
  puVar24 = PTR___mh_execute_header_1000016b0;
  uVar26 = _UNK_1000016b8;
  do {
    uVar28 = CONCAT14((char)((ulong)puVar24 >> 0x20),(uint)((byte)puVar24 & 1)) & 0x1ffffffff;
    bVar38 = (byte)((ulong)puVar24 >> 0x18) >> 1;
    uVar25 = (uint)((ulong)puVar24 >> 0x20);
    uVar10 = uVar25 >> 1;
    uVar39 = (undefined1)uVar10;
    uVar40 = (undefined1)(uVar10 >> 8);
    uVar41 = (undefined1)(uVar10 >> 0x10);
    bVar42 = (byte)((ulong)puVar24 >> 0x39);
    uVar10 = (uint)uVar26 >> 1;
    bVar43 = (byte)(uVar10 >> 8);
    bVar44 = (byte)(uVar10 >> 0x10);
    bVar45 = (byte)(uVar26 >> 0x18) >> 1;
    uVar27 = (uint)(uVar26 >> 0x20);
    uVar13 = uVar27 >> 1;
    bVar46 = (byte)(uVar13 >> 8);
    bVar47 = (byte)(uVar13 >> 0x10);
    bVar48 = (byte)(uVar26 >> 0x39);
    auVar29._0_4_ = -(uint)((int)uVar28 == 0);
    auVar29._4_4_ = -(uint)((char)(uVar28 >> 0x20) == '\0');
    auVar29._8_4_ = -(uint)((uVar26 & 1) == 0);
    auVar29._12_4_ = -(uint)((uVar26 & 0x100000000) == 0);
    bVar49 = (byte)uVar10 ^ 0x20;
    bVar50 = bVar43 ^ 0x83;
    bVar51 = bVar44 ^ 0xb8;
    bVar52 = bVar45 ^ 0xed;
    bVar53 = (byte)uVar13 ^ 0x20;
    bVar54 = bVar46 ^ 0x83;
    bVar55 = bVar47 ^ 0xb8;
    bVar56 = bVar48 ^ 0xed;
    uVar2 = (undefined3)((uint)puVar24 >> 1);
    auVar1[3] = bVar38;
    auVar1._0_3_ = uVar2;
    auVar1[4] = uVar39;
    auVar1[5] = uVar40;
    auVar1[6] = uVar41;
    auVar1[7] = bVar42;
    auVar1[8] = (byte)uVar10;
    auVar1[9] = bVar43;
    auVar1[10] = bVar44;
    auVar1[0xb] = bVar45;
    auVar1[0xc] = (byte)uVar13;
    auVar1[0xd] = bVar46;
    auVar1[0xe] = bVar47;
    auVar1[0xf] = bVar48;
    auVar15[8] = bVar49;
    auVar15._0_8_ =
         CONCAT17(bVar42,CONCAT16(uVar41,CONCAT15(uVar40,CONCAT14(uVar39,CONCAT13(bVar38,uVar2)))))
         ^ 0xedb88320edb88320;
    auVar15[9] = bVar50;
    auVar15[10] = bVar51;
    auVar15[0xb] = bVar52;
    auVar15[0xc] = bVar53;
    auVar15[0xd] = bVar54;
    auVar15[0xe] = bVar55;
    auVar15[0xf] = bVar56;
    auVar30[8] = bVar49;
    auVar30._0_8_ =
         CONCAT17(bVar42,CONCAT16(uVar41,CONCAT15(uVar40,CONCAT14(uVar39,CONCAT13(bVar38,uVar2)))))
         ^ 0xedb88320edb88320;
    auVar30[9] = bVar50;
    auVar30[10] = bVar51;
    auVar30[0xb] = bVar52;
    auVar30[0xc] = bVar53;
    auVar30[0xd] = bVar54;
    auVar30[0xe] = bVar55;
    auVar30[0xf] = bVar56;
    auVar30 = auVar30 ^ (auVar15 ^ auVar1) & auVar29;
    iVar11 = -(uint)((auVar30[4] & 1) == 0);
    iVar12 = -(uint)((auVar30[8] & 1) == 0);
    iVar14 = -(uint)((auVar30[0xc] & 1) == 0);
    auVar31._0_4_ = auVar30._0_4_ >> 1;
    auVar31._4_4_ = auVar30._4_4_ >> 1;
    auVar31._8_4_ = auVar30._8_4_ >> 1;
    auVar31._12_4_ = auVar30._12_4_ >> 1;
    auVar16[8] = (byte)auVar31._8_4_ ^ 0x20;
    auVar16._0_8_ =
         CONCAT17(auVar30[7] >> 1,
                  CONCAT16((char)(auVar31._4_4_ >> 0x10),
                           CONCAT15((char)(auVar31._4_4_ >> 8),
                                    CONCAT14((char)auVar31._4_4_,
                                             CONCAT13(auVar30[3] >> 1,(int3)auVar31._0_4_))))) ^
         0xedb88320edb88320;
    auVar16[9] = (byte)(auVar31._8_4_ >> 8) ^ 0x83;
    auVar16[10] = (byte)(auVar31._8_4_ >> 0x10) ^ 0xb8;
    auVar16[0xb] = auVar30[0xb] >> 1 ^ 0xed;
    auVar16[0xc] = (byte)auVar31._12_4_ ^ 0x20;
    auVar16[0xd] = (byte)(auVar31._12_4_ >> 8) ^ 0x83;
    auVar16[0xe] = (byte)(auVar31._12_4_ >> 0x10) ^ 0xb8;
    auVar16[0xf] = auVar30[0xf] >> 1 ^ 0xed;
    auVar3[4] = (char)iVar11;
    auVar3._0_4_ = -(uint)((auVar30[0] & 1) == 0);
    auVar3[5] = (char)((uint)iVar11 >> 8);
    auVar3[6] = (char)((uint)iVar11 >> 0x10);
    auVar3[7] = (char)((uint)iVar11 >> 0x18);
    auVar3[8] = (char)iVar12;
    auVar3[9] = (char)((uint)iVar12 >> 8);
    auVar3[10] = (char)((uint)iVar12 >> 0x10);
    auVar3[0xb] = (char)((uint)iVar12 >> 0x18);
    auVar3[0xc] = (char)iVar14;
    auVar3[0xd] = (char)((uint)iVar14 >> 8);
    auVar3[0xe] = (char)((uint)iVar14 >> 0x10);
    auVar3[0xf] = (char)((uint)iVar14 >> 0x18);
    auVar31 = auVar31 ^ (auVar31 ^ auVar16) & ~auVar3;
    iVar11 = -(uint)((auVar31[4] & 1) == 0);
    iVar12 = -(uint)((auVar31[8] & 1) == 0);
    iVar14 = -(uint)((auVar31[0xc] & 1) == 0);
    auVar32._0_4_ = auVar31._0_4_ >> 1;
    auVar32._4_4_ = auVar31._4_4_ >> 1;
    auVar32._8_4_ = auVar31._8_4_ >> 1;
    auVar32._12_4_ = auVar31._12_4_ >> 1;
    auVar17[8] = (byte)auVar32._8_4_ ^ 0x20;
    auVar17._0_8_ =
         CONCAT17(auVar31[7] >> 1,
                  CONCAT16((char)(auVar32._4_4_ >> 0x10),
                           CONCAT15((char)(auVar32._4_4_ >> 8),
                                    CONCAT14((char)auVar32._4_4_,
                                             CONCAT13(auVar31[3] >> 1,(int3)auVar32._0_4_))))) ^
         0xedb88320edb88320;
    auVar17[9] = (byte)(auVar32._8_4_ >> 8) ^ 0x83;
    auVar17[10] = (byte)(auVar32._8_4_ >> 0x10) ^ 0xb8;
    auVar17[0xb] = auVar31[0xb] >> 1 ^ 0xed;
    auVar17[0xc] = (byte)auVar32._12_4_ ^ 0x20;
    auVar17[0xd] = (byte)(auVar32._12_4_ >> 8) ^ 0x83;
    auVar17[0xe] = (byte)(auVar32._12_4_ >> 0x10) ^ 0xb8;
    auVar17[0xf] = auVar31[0xf] >> 1 ^ 0xed;
    auVar4[4] = (char)iVar11;
    auVar4._0_4_ = -(uint)((auVar31[0] & 1) == 0);
    auVar4[5] = (char)((uint)iVar11 >> 8);
    auVar4[6] = (char)((uint)iVar11 >> 0x10);
    auVar4[7] = (char)((uint)iVar11 >> 0x18);
    auVar4[8] = (char)iVar12;
    auVar4[9] = (char)((uint)iVar12 >> 8);
    auVar4[10] = (char)((uint)iVar12 >> 0x10);
    auVar4[0xb] = (char)((uint)iVar12 >> 0x18);
    auVar4[0xc] = (char)iVar14;
    auVar4[0xd] = (char)((uint)iVar14 >> 8);
    auVar4[0xe] = (char)((uint)iVar14 >> 0x10);
    auVar4[0xf] = (char)((uint)iVar14 >> 0x18);
    auVar32 = auVar32 ^ (auVar32 ^ auVar17) & ~auVar4;
    iVar11 = -(uint)((auVar32[4] & 1) == 0);
    iVar12 = -(uint)((auVar32[8] & 1) == 0);
    iVar14 = -(uint)((auVar32[0xc] & 1) == 0);
    auVar33._0_4_ = auVar32._0_4_ >> 1;
    auVar33._4_4_ = auVar32._4_4_ >> 1;
    auVar33._8_4_ = auVar32._8_4_ >> 1;
    auVar33._12_4_ = auVar32._12_4_ >> 1;
    auVar18[8] = (byte)auVar33._8_4_ ^ 0x20;
    auVar18._0_8_ =
         CONCAT17(auVar32[7] >> 1,
                  CONCAT16((char)(auVar33._4_4_ >> 0x10),
                           CONCAT15((char)(auVar33._4_4_ >> 8),
                                    CONCAT14((char)auVar33._4_4_,
                                             CONCAT13(auVar32[3] >> 1,(int3)auVar33._0_4_))))) ^
         0xedb88320edb88320;
    auVar18[9] = (byte)(auVar33._8_4_ >> 8) ^ 0x83;
    auVar18[10] = (byte)(auVar33._8_4_ >> 0x10) ^ 0xb8;
    auVar18[0xb] = auVar32[0xb] >> 1 ^ 0xed;
    auVar18[0xc] = (byte)auVar33._12_4_ ^ 0x20;
    auVar18[0xd] = (byte)(auVar33._12_4_ >> 8) ^ 0x83;
    auVar18[0xe] = (byte)(auVar33._12_4_ >> 0x10) ^ 0xb8;
    auVar18[0xf] = auVar32[0xf] >> 1 ^ 0xed;
    auVar5[4] = (char)iVar11;
    auVar5._0_4_ = -(uint)((auVar32[0] & 1) == 0);
    auVar5[5] = (char)((uint)iVar11 >> 8);
    auVar5[6] = (char)((uint)iVar11 >> 0x10);
    auVar5[7] = (char)((uint)iVar11 >> 0x18);
    auVar5[8] = (char)iVar12;
    auVar5[9] = (char)((uint)iVar12 >> 8);
    auVar5[10] = (char)((uint)iVar12 >> 0x10);
    auVar5[0xb] = (char)((uint)iVar12 >> 0x18);
    auVar5[0xc] = (char)iVar14;
    auVar5[0xd] = (char)((uint)iVar14 >> 8);
    auVar5[0xe] = (char)((uint)iVar14 >> 0x10);
    auVar5[0xf] = (char)((uint)iVar14 >> 0x18);
    auVar33 = auVar33 ^ (auVar33 ^ auVar18) & ~auVar5;
    iVar11 = -(uint)((auVar33[4] & 1) == 0);
    iVar12 = -(uint)((auVar33[8] & 1) == 0);
    iVar14 = -(uint)((auVar33[0xc] & 1) == 0);
    auVar34._0_4_ = auVar33._0_4_ >> 1;
    auVar34._4_4_ = auVar33._4_4_ >> 1;
    auVar34._8_4_ = auVar33._8_4_ >> 1;
    auVar34._12_4_ = auVar33._12_4_ >> 1;
    auVar19[8] = (byte)auVar34._8_4_ ^ 0x20;
    auVar19._0_8_ =
         CONCAT17(auVar33[7] >> 1,
                  CONCAT16((char)(auVar34._4_4_ >> 0x10),
                           CONCAT15((char)(auVar34._4_4_ >> 8),
                                    CONCAT14((char)auVar34._4_4_,
                                             CONCAT13(auVar33[3] >> 1,(int3)auVar34._0_4_))))) ^
         0xedb88320edb88320;
    auVar19[9] = (byte)(auVar34._8_4_ >> 8) ^ 0x83;
    auVar19[10] = (byte)(auVar34._8_4_ >> 0x10) ^ 0xb8;
    auVar19[0xb] = auVar33[0xb] >> 1 ^ 0xed;
    auVar19[0xc] = (byte)auVar34._12_4_ ^ 0x20;
    auVar19[0xd] = (byte)(auVar34._12_4_ >> 8) ^ 0x83;
    auVar19[0xe] = (byte)(auVar34._12_4_ >> 0x10) ^ 0xb8;
    auVar19[0xf] = auVar33[0xf] >> 1 ^ 0xed;
    auVar6[4] = (char)iVar11;
    auVar6._0_4_ = -(uint)((auVar33[0] & 1) == 0);
    auVar6[5] = (char)((uint)iVar11 >> 8);
    auVar6[6] = (char)((uint)iVar11 >> 0x10);
    auVar6[7] = (char)((uint)iVar11 >> 0x18);
    auVar6[8] = (char)iVar12;
    auVar6[9] = (char)((uint)iVar12 >> 8);
    auVar6[10] = (char)((uint)iVar12 >> 0x10);
    auVar6[0xb] = (char)((uint)iVar12 >> 0x18);
    auVar6[0xc] = (char)iVar14;
    auVar6[0xd] = (char)((uint)iVar14 >> 8);
    auVar6[0xe] = (char)((uint)iVar14 >> 0x10);
    auVar6[0xf] = (char)((uint)iVar14 >> 0x18);
    auVar34 = auVar34 ^ (auVar34 ^ auVar19) & ~auVar6;
    iVar11 = -(uint)((auVar34[4] & 1) == 0);
    iVar12 = -(uint)((auVar34[8] & 1) == 0);
    iVar14 = -(uint)((auVar34[0xc] & 1) == 0);
    auVar35._0_4_ = auVar34._0_4_ >> 1;
    auVar35._4_4_ = auVar34._4_4_ >> 1;
    auVar35._8_4_ = auVar34._8_4_ >> 1;
    auVar35._12_4_ = auVar34._12_4_ >> 1;
    auVar20[8] = (byte)auVar35._8_4_ ^ 0x20;
    auVar20._0_8_ =
         CONCAT17(auVar34[7] >> 1,
                  CONCAT16((char)(auVar35._4_4_ >> 0x10),
                           CONCAT15((char)(auVar35._4_4_ >> 8),
                                    CONCAT14((char)auVar35._4_4_,
                                             CONCAT13(auVar34[3] >> 1,(int3)auVar35._0_4_))))) ^
         0xedb88320edb88320;
    auVar20[9] = (byte)(auVar35._8_4_ >> 8) ^ 0x83;
    auVar20[10] = (byte)(auVar35._8_4_ >> 0x10) ^ 0xb8;
    auVar20[0xb] = auVar34[0xb] >> 1 ^ 0xed;
    auVar20[0xc] = (byte)auVar35._12_4_ ^ 0x20;
    auVar20[0xd] = (byte)(auVar35._12_4_ >> 8) ^ 0x83;
    auVar20[0xe] = (byte)(auVar35._12_4_ >> 0x10) ^ 0xb8;
    auVar20[0xf] = auVar34[0xf] >> 1 ^ 0xed;
    auVar7[4] = (char)iVar11;
    auVar7._0_4_ = -(uint)((auVar34[0] & 1) == 0);
    auVar7[5] = (char)((uint)iVar11 >> 8);
    auVar7[6] = (char)((uint)iVar11 >> 0x10);
    auVar7[7] = (char)((uint)iVar11 >> 0x18);
    auVar7[8] = (char)iVar12;
    auVar7[9] = (char)((uint)iVar12 >> 8);
    auVar7[10] = (char)((uint)iVar12 >> 0x10);
    auVar7[0xb] = (char)((uint)iVar12 >> 0x18);
    auVar7[0xc] = (char)iVar14;
    auVar7[0xd] = (char)((uint)iVar14 >> 8);
    auVar7[0xe] = (char)((uint)iVar14 >> 0x10);
    auVar7[0xf] = (char)((uint)iVar14 >> 0x18);
    auVar35 = auVar35 ^ (auVar35 ^ auVar20) & ~auVar7;
    auVar36._0_4_ = auVar35._0_4_ >> 1;
    auVar36._4_4_ = auVar35._4_4_ >> 1;
    auVar36._8_4_ = auVar35._8_4_ >> 1;
    auVar36._12_4_ = auVar35._12_4_ >> 1;
    iVar11 = -(uint)((auVar35[4] & 1) == 0);
    iVar12 = -(uint)((auVar35[8] & 1) == 0);
    iVar14 = -(uint)((auVar35[0xc] & 1) == 0);
    auVar21[8] = (byte)auVar36._8_4_ ^ 0x20;
    auVar21._0_8_ =
         CONCAT17(auVar35[7] >> 1,
                  CONCAT16((char)(auVar36._4_4_ >> 0x10),
                           CONCAT15((char)(auVar36._4_4_ >> 8),
                                    CONCAT14((char)auVar36._4_4_,
                                             CONCAT13(auVar35[3] >> 1,(int3)auVar36._0_4_))))) ^
         0xedb88320edb88320;
    auVar21[9] = (byte)(auVar36._8_4_ >> 8) ^ 0x83;
    auVar21[10] = (byte)(auVar36._8_4_ >> 0x10) ^ 0xb8;
    auVar21[0xb] = auVar35[0xb] >> 1 ^ 0xed;
    auVar21[0xc] = (byte)auVar36._12_4_ ^ 0x20;
    auVar21[0xd] = (byte)(auVar36._12_4_ >> 8) ^ 0x83;
    auVar21[0xe] = (byte)(auVar36._12_4_ >> 0x10) ^ 0xb8;
    auVar21[0xf] = auVar35[0xf] >> 1 ^ 0xed;
    auVar8[4] = (char)iVar11;
    auVar8._0_4_ = -(uint)((auVar35[0] & 1) == 0);
    auVar8[5] = (char)((uint)iVar11 >> 8);
    auVar8[6] = (char)((uint)iVar11 >> 0x10);
    auVar8[7] = (char)((uint)iVar11 >> 0x18);
    auVar8[8] = (char)iVar12;
    auVar8[9] = (char)((uint)iVar12 >> 8);
    auVar8[10] = (char)((uint)iVar12 >> 0x10);
    auVar8[0xb] = (char)((uint)iVar12 >> 0x18);
    auVar8[0xc] = (char)iVar14;
    auVar8[0xd] = (char)((uint)iVar14 >> 8);
    auVar8[0xe] = (char)((uint)iVar14 >> 0x10);
    auVar8[0xf] = (char)((uint)iVar14 >> 0x18);
    auVar36 = auVar36 ^ (auVar36 ^ auVar21) & ~auVar8;
    iVar11 = -(uint)((auVar36[4] & 1) == 0);
    iVar12 = -(uint)((auVar36[8] & 1) == 0);
    iVar14 = -(uint)((auVar36[0xc] & 1) == 0);
    auVar37._0_4_ = auVar36._0_4_ >> 1;
    auVar37._4_4_ = auVar36._4_4_ >> 1;
    auVar37._8_4_ = auVar36._8_4_ >> 1;
    auVar37._12_4_ = auVar36._12_4_ >> 1;
    auVar22[8] = (byte)auVar37._8_4_ ^ 0x20;
    auVar22._0_8_ =
         CONCAT17(auVar36[7] >> 1,
                  CONCAT16((char)(auVar37._4_4_ >> 0x10),
                           CONCAT15((char)(auVar37._4_4_ >> 8),
                                    CONCAT14((char)auVar37._4_4_,
                                             CONCAT13(auVar36[3] >> 1,(int3)auVar37._0_4_))))) ^
         0xedb88320edb88320;
    auVar22[9] = (byte)(auVar37._8_4_ >> 8) ^ 0x83;
    auVar22[10] = (byte)(auVar37._8_4_ >> 0x10) ^ 0xb8;
    auVar22[0xb] = auVar36[0xb] >> 1 ^ 0xed;
    auVar22[0xc] = (byte)auVar37._12_4_ ^ 0x20;
    auVar22[0xd] = (byte)(auVar37._12_4_ >> 8) ^ 0x83;
    auVar22[0xe] = (byte)(auVar37._12_4_ >> 0x10) ^ 0xb8;
    auVar22[0xf] = auVar36[0xf] >> 1 ^ 0xed;
    auVar9[4] = (char)iVar11;
    auVar9._0_4_ = -(uint)((auVar36[0] & 1) == 0);
    auVar9[5] = (char)((uint)iVar11 >> 8);
    auVar9[6] = (char)((uint)iVar11 >> 0x10);
    auVar9[7] = (char)((uint)iVar11 >> 0x18);
    auVar9[8] = (char)iVar12;
    auVar9[9] = (char)((uint)iVar12 >> 8);
    auVar9[10] = (char)((uint)iVar12 >> 0x10);
    auVar9[0xb] = (char)((uint)iVar12 >> 0x18);
    auVar9[0xc] = (char)iVar14;
    auVar9[0xd] = (char)((uint)iVar14 >> 8);
    auVar9[0xe] = (char)((uint)iVar14 >> 0x10);
    auVar9[0xf] = (char)((uint)iVar14 >> 0x18);
    auVar37 = auVar37 ^ (auVar37 ^ auVar22) & ~auVar9;
    *(long *)(lVar23 + 0x100008008) = auVar37._8_8_;
    *(long *)(&_crc_table + lVar23) = auVar37._0_8_;
    puVar24 = (undefined *)CONCAT44(uVar25 + 4,(uint)puVar24 + 4);
    uVar26 = CONCAT44(uVar27 + 4,(uint)uVar26 + 4);
    lVar23 = lVar23 + 0x10;
  } while (lVar23 != 0x400);
  return;
}


// ==== _crc32_buf @ 100000eec

uint _crc32_buf(byte *param_1,long param_2)

{
  uint uVar1;
  
  if (param_2 != 0) {
    uVar1 = 0xffffffff;
    do {
      uVar1 = *(uint *)(&_crc_table + ((ulong)(*param_1 ^ uVar1) & 0xff) * 4) ^ uVar1 >> 8;
      param_2 = param_2 + -1;
      param_1 = param_1 + 1;
    } while (param_2 != 0);
    return ~uVar1;
  }
  return 0;
}


// ==== _tea_encrypt @ 100000f28

void _tea_encrypt(uint *param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  uVar1 = *param_1;
  uVar2 = param_1[1];
  iVar3 = 0x20;
  iVar4 = -0x61c88647;
  do {
    uVar1 = (*param_2 + uVar2 * 0x10 ^ uVar2 + iVar4 ^ param_2[1] + (uVar2 >> 5)) + uVar1;
    uVar2 = (param_2[2] + uVar1 * 0x10 ^ iVar4 + uVar1 ^ param_2[3] + (uVar1 >> 5)) + uVar2;
    iVar4 = iVar4 + -0x61c88647;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  *param_1 = uVar1;
  param_1[1] = uVar2;
  return;
}


// ==== entry @ 100000f8c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 entry(int param_1,long param_2)

{
  uint uVar1;
  int iVar2;
  size_t sVar3;
  char *pcVar4;
  ulong uVar5;
  ulong uVar6;
  char *pcVar7;
  float fVar8;
  byte bVar9;
  byte bVar10;
  byte bVar11;
  byte bVar12;
  undefined1 auStack_638 [16];
  uint local_628;
  undefined8 local_624;
  undefined4 local_61c;
  undefined8 local_618;
  undefined8 local_610 [2];
  undefined8 local_600;
  undefined8 uStack_5f8;
  undefined8 uStack_5f0;
  undefined8 uStack_5e8;
  undefined8 local_5e0;
  undefined8 uStack_5d8;
  undefined8 uStack_5d0;
  undefined8 uStack_5c8;
  undefined8 local_5c0;
  undefined8 uStack_5b8;
  undefined8 local_5b0;
  undefined8 uStack_5a8;
  undefined8 uStack_5a0;
  undefined8 uStack_598;
  undefined8 local_590;
  undefined8 uStack_588;
  undefined8 uStack_580;
  undefined8 uStack_578;
  undefined8 local_570;
  undefined8 uStack_568;
  undefined8 uStack_560;
  undefined8 uStack_558;
  undefined8 local_550;
  undefined8 uStack_548;
  undefined8 uStack_540;
  undefined8 uStack_538;
  undefined8 local_530;
  undefined8 uStack_528;
  undefined8 uStack_520;
  undefined8 uStack_518;
  undefined8 local_510;
  undefined8 uStack_508;
  undefined8 uStack_500;
  undefined8 uStack_4f8;
  undefined8 local_4f0;
  undefined8 uStack_4e8;
  undefined8 uStack_4e0;
  undefined8 uStack_4d8;
  undefined8 local_4d0;
  undefined8 uStack_4c8;
  undefined8 uStack_4c0;
  undefined8 uStack_4b8;
  undefined8 local_4b0;
  undefined8 uStack_4a8;
  undefined8 uStack_4a0;
  undefined8 uStack_498;
  undefined8 local_490;
  undefined8 uStack_488;
  undefined8 uStack_480;
  undefined8 uStack_478;
  undefined8 local_470;
  undefined8 uStack_468;
  undefined8 uStack_460;
  undefined8 uStack_458;
  undefined8 local_450;
  undefined8 uStack_448;
  undefined8 uStack_440;
  undefined8 uStack_438;
  undefined8 local_430;
  undefined8 uStack_428;
  undefined8 uStack_420;
  undefined8 uStack_418;
  undefined8 local_410;
  undefined8 uStack_408;
  undefined8 uStack_400;
  undefined8 uStack_3f8;
  undefined8 local_3f0;
  undefined8 uStack_3e8;
  undefined8 uStack_3e0;
  undefined8 uStack_3d8;
  undefined8 local_3d0;
  undefined8 uStack_3c8;
  undefined8 uStack_3c0;
  undefined8 uStack_3b8;
  undefined8 local_3b0;
  undefined8 uStack_3a8;
  undefined8 uStack_3a0;
  undefined8 uStack_398;
  undefined8 local_390;
  undefined8 uStack_388;
  undefined8 uStack_380;
  undefined8 uStack_378;
  undefined8 local_370;
  undefined8 uStack_368;
  undefined8 uStack_360;
  undefined8 uStack_358;
  undefined8 local_350;
  undefined8 uStack_348;
  undefined8 uStack_340;
  undefined8 uStack_338;
  undefined8 local_330;
  undefined8 uStack_328;
  undefined8 uStack_320;
  undefined8 uStack_318;
  undefined8 local_310;
  undefined8 uStack_308;
  undefined8 uStack_300;
  undefined8 uStack_2f8;
  undefined8 local_2f0;
  undefined8 uStack_2e8;
  undefined8 uStack_2e0;
  undefined8 uStack_2d8;
  undefined8 local_2d0;
  undefined8 uStack_2c8;
  undefined8 uStack_2c0;
  undefined8 uStack_2b8;
  undefined8 local_2b0;
  undefined8 uStack_2a8;
  undefined8 uStack_2a0;
  undefined8 uStack_298;
  undefined8 local_290;
  undefined8 uStack_288;
  undefined8 uStack_280;
  undefined8 uStack_278;
  undefined8 local_270;
  undefined8 uStack_268;
  undefined8 uStack_260;
  undefined8 uStack_258;
  undefined8 local_250;
  undefined8 uStack_248;
  undefined8 uStack_240;
  undefined8 uStack_238;
  undefined8 local_230;
  undefined8 uStack_228;
  undefined8 uStack_220;
  undefined8 uStack_218;
  undefined8 local_210;
  undefined8 uStack_208;
  undefined1 auStack_1f8 [256];
  undefined1 auStack_f8 [128];
  long local_78;
  
  local_78 = *(long *)PTR____stack_chk_guard_100004018;
  if (param_1 < 2) {
    pcVar7 = "GET";
    uVar6 = 3;
  }
  else {
    uVar1 = _atoi(*(char **)(param_2 + 8));
    uVar6 = (ulong)uVar1;
    if (param_1 == 2) {
      pcVar7 = "GET";
    }
    else {
      pcVar7 = *(char **)(param_2 + 0x10);
    }
  }
  uVar1 = (uint)uVar6;
  fVar8 = (float)(int)uVar1;
  local_600 = CONCAT44(fVar8,fVar8);
  uStack_5f8 = CONCAT44(fVar8,fVar8);
  uVar5 = (ulong)(int)uVar1;
  bVar9 = (byte)uVar6;
  bVar10 = (byte)(uVar6 >> 8);
  bVar11 = (byte)(uVar6 >> 0x10);
  bVar12 = (byte)(uVar6 >> 0x18);
  uStack_300 = CONCAT17(bVar12 ^ (byte)((ulong)PTR___mh_execute_header_1000016b0 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)PTR___mh_execute_header_1000016b0 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)PTR___mh_execute_header_1000016b0
                                                         >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)
                                                  PTR___mh_execute_header_1000016b0 >> 0x20),
                                                  CONCAT13(bVar12 ^ (byte)((ulong)
                                                  PTR___mh_execute_header_1000016b0 >> 0x18),
                                                  CONCAT12(bVar11 ^ (byte)((ulong)
                                                  PTR___mh_execute_header_1000016b0 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)
                                                  PTR___mh_execute_header_1000016b0 >> 8),
                                                  bVar9 ^ (byte)PTR___mh_execute_header_1000016b0)))
                                                  ))));
  uStack_2f8 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_1000016b8 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_1000016b8 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_1000016b8 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_1000016b8 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_1000016b8 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_1000016b8 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_1000016b8 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_1000016b8)))))));
  local_2f0 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_1000016c0 >> 0x38),
                       CONCAT16(bVar11 ^ (byte)((ulong)_DAT_1000016c0 >> 0x30),
                                CONCAT15(bVar10 ^ (byte)((ulong)_DAT_1000016c0 >> 0x28),
                                         CONCAT14(bVar9 ^ (byte)((ulong)_DAT_1000016c0 >> 0x20),
                                                  CONCAT13(bVar12 ^ (byte)((ulong)_DAT_1000016c0 >>
                                                                          0x18),
                                                           CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_1000016c0 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_1000016c0 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_1000016c0)))))));
  uStack_2e8 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_1000016c8 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_1000016c8 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_1000016c8 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_1000016c8 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_1000016c8 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_1000016c8 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_1000016c8 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_1000016c8)))))));
  uStack_2e0 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_1000016d0 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_DAT_1000016d0 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_DAT_1000016d0 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_DAT_1000016d0 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_DAT_1000016d0 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_1000016d0 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_1000016d0 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_1000016d0)))))));
  uStack_2d8 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_1000016d8 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_1000016d8 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_1000016d8 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_1000016d8 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_1000016d8 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_1000016d8 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_1000016d8 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_1000016d8)))))));
  local_2d0 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_1000016e0 >> 0x38),
                       CONCAT16(bVar11 ^ (byte)((ulong)_DAT_1000016e0 >> 0x30),
                                CONCAT15(bVar10 ^ (byte)((ulong)_DAT_1000016e0 >> 0x28),
                                         CONCAT14(bVar9 ^ (byte)((ulong)_DAT_1000016e0 >> 0x20),
                                                  CONCAT13(bVar12 ^ (byte)((ulong)_DAT_1000016e0 >>
                                                                          0x18),
                                                           CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_1000016e0 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_1000016e0 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_1000016e0)))))));
  uStack_2c8 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_1000016e8 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_1000016e8 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_1000016e8 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_1000016e8 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_1000016e8 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_1000016e8 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_1000016e8 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_1000016e8)))))));
  uStack_400 = CONCAT44(uVar1 + (int)((ulong)PTR___mh_execute_header_1000016b0 >> 0x20),
                        uVar1 + (int)PTR___mh_execute_header_1000016b0);
  uStack_3f8 = CONCAT44(uVar1 + (int)((ulong)_UNK_1000016b8 >> 0x20),uVar1 + (int)_UNK_1000016b8);
  local_3f0 = CONCAT44(uVar1 + (int)((ulong)_DAT_1000016c0 >> 0x20),uVar1 + (int)_DAT_1000016c0);
  uStack_3e8 = CONCAT44(uVar1 + (int)((ulong)_UNK_1000016c8 >> 0x20),uVar1 + (int)_UNK_1000016c8);
  uStack_3e0 = CONCAT44(uVar1 + (int)((ulong)_DAT_1000016d0 >> 0x20),uVar1 + (int)_DAT_1000016d0);
  uStack_3d8 = CONCAT44(uVar1 + (int)((ulong)_UNK_1000016d8 >> 0x20),uVar1 + (int)_UNK_1000016d8);
  local_3d0 = CONCAT44(uVar1 + (int)((ulong)_DAT_1000016e0 >> 0x20),uVar1 + (int)_DAT_1000016e0);
  uStack_3c8 = CONCAT44(uVar1 + (int)((ulong)_UNK_1000016e8 >> 0x20),uVar1 + (int)_UNK_1000016e8);
  uStack_4e8 = _UNK_100001708;
  local_4f0 = _DAT_100001700;
  uStack_4d8 = _UNK_100001718;
  uStack_4e0 = _DAT_100001710;
  uStack_2c0 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_100001730 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_DAT_100001730 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_DAT_100001730 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_DAT_100001730 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_DAT_100001730 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_100001730 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_100001730 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_100001730)))))));
  uStack_2b8 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_100001738 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_100001738 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_100001738 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_100001738 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_100001738 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_100001738 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_100001738 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_100001738)))))));
  local_2b0 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_100001740 >> 0x38),
                       CONCAT16(bVar11 ^ (byte)((ulong)_DAT_100001740 >> 0x30),
                                CONCAT15(bVar10 ^ (byte)((ulong)_DAT_100001740 >> 0x28),
                                         CONCAT14(bVar9 ^ (byte)((ulong)_DAT_100001740 >> 0x20),
                                                  CONCAT13(bVar12 ^ (byte)((ulong)_DAT_100001740 >>
                                                                          0x18),
                                                           CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_100001740 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_100001740 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_100001740)))))));
  uStack_2a8 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_100001748 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_100001748 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_100001748 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_100001748 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_100001748 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_100001748 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_100001748 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_100001748)))))));
  uStack_2a0 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_100001750 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_DAT_100001750 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_DAT_100001750 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_DAT_100001750 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_DAT_100001750 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_100001750 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_100001750 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_100001750)))))));
  uStack_298 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_100001758 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_100001758 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_100001758 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_100001758 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_100001758 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_100001758 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_100001758 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_100001758)))))));
  uStack_3c0 = CONCAT44(uVar1 + (int)((ulong)_DAT_100001730 >> 0x20),uVar1 + (int)_DAT_100001730);
  uStack_3b8 = CONCAT44(uVar1 + (int)((ulong)_UNK_100001738 >> 0x20),uVar1 + (int)_UNK_100001738);
  local_3b0 = CONCAT44(uVar1 + (int)((ulong)_DAT_100001740 >> 0x20),uVar1 + (int)_DAT_100001740);
  uStack_3a8 = CONCAT44(uVar1 + (int)((ulong)_UNK_100001748 >> 0x20),uVar1 + (int)_UNK_100001748);
  uStack_3a0 = CONCAT44(uVar1 + (int)((ulong)_DAT_100001750 >> 0x20),uVar1 + (int)_DAT_100001750);
  uStack_398 = CONCAT44(uVar1 + (int)((ulong)_UNK_100001758 >> 0x20),uVar1 + (int)_UNK_100001758);
  local_390 = CONCAT44(uVar1 + (int)((ulong)_DAT_100001760 >> 0x20),uVar1 + (int)_DAT_100001760);
  uStack_388 = CONCAT44(uVar1 + (int)((ulong)_UNK_100001768 >> 0x20),uVar1 + (int)_UNK_100001768);
  uStack_4c8 = _UNK_100001728;
  local_4d0 = _DAT_100001720;
  uStack_4b8 = _UNK_100001778;
  uStack_4c0 = _DAT_100001770;
  uStack_4a8 = _UNK_100001788;
  local_4b0 = _DAT_100001780;
  uStack_498 = _UNK_100001798;
  uStack_4a0 = _DAT_100001790;
  uStack_280 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_1000017b0 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_DAT_1000017b0 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_DAT_1000017b0 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_DAT_1000017b0 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_DAT_1000017b0 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_1000017b0 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_1000017b0 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_1000017b0)))))));
  uStack_278 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_1000017b8 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_1000017b8 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_1000017b8 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_1000017b8 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_1000017b8 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_1000017b8 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_1000017b8 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_1000017b8)))))));
  local_270 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_1000017c0 >> 0x38),
                       CONCAT16(bVar11 ^ (byte)((ulong)_DAT_1000017c0 >> 0x30),
                                CONCAT15(bVar10 ^ (byte)((ulong)_DAT_1000017c0 >> 0x28),
                                         CONCAT14(bVar9 ^ (byte)((ulong)_DAT_1000017c0 >> 0x20),
                                                  CONCAT13(bVar12 ^ (byte)((ulong)_DAT_1000017c0 >>
                                                                          0x18),
                                                           CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_1000017c0 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_1000017c0 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_1000017c0)))))));
  uStack_268 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_1000017c8 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_1000017c8 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_1000017c8 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_1000017c8 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_1000017c8 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_1000017c8 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_1000017c8 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_1000017c8)))))));
  uStack_260 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_1000017d0 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_DAT_1000017d0 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_DAT_1000017d0 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_DAT_1000017d0 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_DAT_1000017d0 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_1000017d0 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_1000017d0 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_1000017d0)))))));
  uStack_258 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_1000017d8 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_1000017d8 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_1000017d8 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_1000017d8 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_1000017d8 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_1000017d8 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_1000017d8 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_1000017d8)))))));
  uStack_288 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_100001768 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_100001768 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_100001768 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_100001768 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_100001768 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_100001768 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_100001768 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_100001768)))))));
  local_290 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_100001760 >> 0x38),
                       CONCAT16(bVar11 ^ (byte)((ulong)_DAT_100001760 >> 0x30),
                                CONCAT15(bVar10 ^ (byte)((ulong)_DAT_100001760 >> 0x28),
                                         CONCAT14(bVar9 ^ (byte)((ulong)_DAT_100001760 >> 0x20),
                                                  CONCAT13(bVar12 ^ (byte)((ulong)_DAT_100001760 >>
                                                                          0x18),
                                                           CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_100001760 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_100001760 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_100001760)))))));
  local_250 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_1000017e0 >> 0x38),
                       CONCAT16(bVar11 ^ (byte)((ulong)_DAT_1000017e0 >> 0x30),
                                CONCAT15(bVar10 ^ (byte)((ulong)_DAT_1000017e0 >> 0x28),
                                         CONCAT14(bVar9 ^ (byte)((ulong)_DAT_1000017e0 >> 0x20),
                                                  CONCAT13(bVar12 ^ (byte)((ulong)_DAT_1000017e0 >>
                                                                          0x18),
                                                           CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_1000017e0 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_1000017e0 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_1000017e0)))))));
  uStack_248 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_1000017e8 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_1000017e8 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_1000017e8 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_1000017e8 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_1000017e8 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_1000017e8 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_1000017e8 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_1000017e8)))))));
  uStack_380 = CONCAT44(uVar1 + (int)((ulong)_DAT_1000017b0 >> 0x20),uVar1 + (int)_DAT_1000017b0);
  uStack_378 = CONCAT44(uVar1 + (int)((ulong)_UNK_1000017b8 >> 0x20),uVar1 + (int)_UNK_1000017b8);
  local_370 = CONCAT44(uVar1 + (int)((ulong)_DAT_1000017c0 >> 0x20),uVar1 + (int)_DAT_1000017c0);
  uStack_368 = CONCAT44(uVar1 + (int)((ulong)_UNK_1000017c8 >> 0x20),uVar1 + (int)_UNK_1000017c8);
  uStack_360 = CONCAT44(uVar1 + (int)((ulong)_DAT_1000017d0 >> 0x20),uVar1 + (int)_DAT_1000017d0);
  uStack_358 = CONCAT44(uVar1 + (int)((ulong)_UNK_1000017d8 >> 0x20),uVar1 + (int)_UNK_1000017d8);
  uStack_488 = _UNK_1000017a8;
  local_490 = _DAT_1000017a0;
  uStack_478 = _UNK_1000017f8;
  uStack_480 = _DAT_1000017f0;
  uStack_468 = _UNK_100001808;
  local_470 = _DAT_100001800;
  uStack_458 = _UNK_100001818;
  uStack_460 = _DAT_100001810;
  uStack_240 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_100001830 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_DAT_100001830 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_DAT_100001830 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_DAT_100001830 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_DAT_100001830 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_100001830 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_100001830 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_100001830)))))));
  uStack_238 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_100001838 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_100001838 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_100001838 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_100001838 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_100001838 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_100001838 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_100001838 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_100001838)))))));
  local_230 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_100001840 >> 0x38),
                       CONCAT16(bVar11 ^ (byte)((ulong)_DAT_100001840 >> 0x30),
                                CONCAT15(bVar10 ^ (byte)((ulong)_DAT_100001840 >> 0x28),
                                         CONCAT14(bVar9 ^ (byte)((ulong)_DAT_100001840 >> 0x20),
                                                  CONCAT13(bVar12 ^ (byte)((ulong)_DAT_100001840 >>
                                                                          0x18),
                                                           CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_100001840 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_100001840 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_100001840)))))));
  uStack_228 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_100001848 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_100001848 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_100001848 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_100001848 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_100001848 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_100001848 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_100001848 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_100001848)))))));
  uStack_220 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_100001850 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_DAT_100001850 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_DAT_100001850 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_DAT_100001850 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_DAT_100001850 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_100001850 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_100001850 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_100001850)))))));
  uStack_218 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_100001858 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_100001858 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_100001858 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_100001858 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_100001858 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_100001858 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_100001858 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_100001858)))))));
  local_210 = CONCAT17(bVar12 ^ (byte)((ulong)_DAT_100001860 >> 0x38),
                       CONCAT16(bVar11 ^ (byte)((ulong)_DAT_100001860 >> 0x30),
                                CONCAT15(bVar10 ^ (byte)((ulong)_DAT_100001860 >> 0x28),
                                         CONCAT14(bVar9 ^ (byte)((ulong)_DAT_100001860 >> 0x20),
                                                  CONCAT13(bVar12 ^ (byte)((ulong)_DAT_100001860 >>
                                                                          0x18),
                                                           CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _DAT_100001860 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_DAT_100001860 >>
                                                                          8),
                                                           bVar9 ^ (byte)_DAT_100001860)))))));
  uStack_208 = CONCAT17(bVar12 ^ (byte)((ulong)_UNK_100001868 >> 0x38),
                        CONCAT16(bVar11 ^ (byte)((ulong)_UNK_100001868 >> 0x30),
                                 CONCAT15(bVar10 ^ (byte)((ulong)_UNK_100001868 >> 0x28),
                                          CONCAT14(bVar9 ^ (byte)((ulong)_UNK_100001868 >> 0x20),
                                                   CONCAT13(bVar12 ^ (byte)((ulong)_UNK_100001868 >>
                                                                           0x18),
                                                            CONCAT12(bVar11 ^ (byte)((ulong)
                                                  _UNK_100001868 >> 0x10),
                                                  CONCAT11(bVar10 ^ (byte)((ulong)_UNK_100001868 >>
                                                                          8),
                                                           bVar9 ^ (byte)_UNK_100001868)))))));
  local_350 = CONCAT44(uVar1 + (int)((ulong)_DAT_1000017e0 >> 0x20),uVar1 + (int)_DAT_1000017e0);
  uStack_348 = CONCAT44(uVar1 + (int)((ulong)_UNK_1000017e8 >> 0x20),uVar1 + (int)_UNK_1000017e8);
  uStack_340 = CONCAT44(uVar1 + (int)((ulong)_DAT_100001830 >> 0x20),uVar1 + (int)_DAT_100001830);
  uStack_338 = CONCAT44(uVar1 + (int)((ulong)_UNK_100001838 >> 0x20),uVar1 + (int)_UNK_100001838);
  local_330 = CONCAT44(uVar1 + (int)((ulong)_DAT_100001840 >> 0x20),uVar1 + (int)_DAT_100001840);
  uStack_328 = CONCAT44(uVar1 + (int)((ulong)_UNK_100001848 >> 0x20),uVar1 + (int)_UNK_100001848);
  uStack_320 = CONCAT44(uVar1 + (int)((ulong)_DAT_100001850 >> 0x20),uVar1 + (int)_DAT_100001850);
  uStack_318 = CONCAT44(uVar1 + (int)((ulong)_UNK_100001858 >> 0x20),uVar1 + (int)_UNK_100001858);
  local_310 = CONCAT44(uVar1 + (int)((ulong)_DAT_100001860 >> 0x20),uVar1 + (int)_DAT_100001860);
  uStack_308 = CONCAT44(uVar1 + (int)((ulong)_UNK_100001868 >> 0x20),uVar1 + (int)_UNK_100001868);
  uStack_448 = _UNK_100001828;
  local_450 = _DAT_100001820;
  uStack_438 = _UNK_100001878;
  uStack_440 = _DAT_100001870;
  uStack_428 = _UNK_100001888;
  local_430 = _DAT_100001880;
  uStack_418 = _UNK_100001898;
  uStack_420 = _DAT_100001890;
  uStack_408 = _UNK_1000018a8;
  local_410 = _DAT_1000018a0;
  uStack_4f8 = _UNK_1000016f8;
  uStack_500 = _DAT_1000016f0;
  local_624 = DAT_1000018c0;
  local_61c = 3;
  local_628 = uVar1;
  uStack_5f0 = local_600;
  uStack_5e8 = uStack_5f8;
  local_5e0 = local_600;
  uStack_5d8 = uStack_5f8;
  uStack_5d0 = local_600;
  uStack_5c8 = uStack_5f8;
  local_5c0 = local_600;
  uStack_5b8 = uStack_5f8;
  local_5b0 = local_600;
  uStack_5a8 = uStack_5f8;
  uStack_5a0 = local_600;
  uStack_598 = uStack_5f8;
  local_590 = local_600;
  uStack_588 = uStack_5f8;
  uStack_580 = local_600;
  uStack_578 = uStack_5f8;
  local_570 = local_600;
  uStack_568 = uStack_5f8;
  uStack_560 = local_600;
  uStack_558 = uStack_5f8;
  local_550 = local_600;
  uStack_548 = uStack_5f8;
  uStack_540 = local_600;
  uStack_538 = uStack_5f8;
  local_530 = local_600;
  uStack_528 = uStack_5f8;
  uStack_520 = local_600;
  uStack_518 = uStack_5f8;
  local_510 = local_600;
  uStack_508 = uStack_5f8;
  _copy16(auStack_638,&local_628);
  _zero64(auStack_f8);
  _zero_n(auStack_f8,uVar5 & 0x3f);
  _strcmp_const(pcVar7);
  _strncmp_const(pcVar7);
  _loop_zero(auStack_1f8,uVar1 & 0x3f);
  sVar3 = _strlen(pcVar7);
  _loop_copy(auStack_f8,pcVar7,sVar3);
  _loop_strlen(pcVar7);
  _sum_va(3);
  _ssp_copy(pcVar7);
  sVar3 = _strlen(pcVar7);
  _fortify_memcpy(auStack_f8,pcVar7,sVar3 & 0x1f);
  _fortify_snprintf(auStack_f8,0x80,uVar6);
  if (param_1 < 4) {
    pcVar4 = "/etc/hosts";
  }
  else {
    pcVar4 = *(char **)(param_2 + 0x18);
  }
  _make_small(uVar5);
  _use_big(uVar5);
  _is_pow2(uVar5);
  _rotl32(uVar5,uVar5);
  _bswap32_manual(uVar5);
  _popcount_loop(uVar5);
  _sel_clamp(uVar5,0,9);
  _sel_abs(uVar5);
  _sel_max(uVar5,5);
  _udiv1000_64(uVar5);
  _sdiv16(uVar5);
  _umod10(uVar5);
  _sdiv7(uVar5);
  _udiv7(uVar5);
  _sw_bittest(uVar5);
  _sw_sparse(uVar5);
  _sw_dense(uVar5);
  _read_file_head(pcVar4,auStack_f8,0x80);
  _tail_caller(uVar5);
  _tail_ext(pcVar7);
  _vadd(auStack_1f8,&uStack_300,&uStack_400,0x40);
  _vsum(auStack_1f8,0x40);
  _vdot(&uStack_500,&local_600,0x40);
  _md5_init(local_610);
  _crc32_make_table();
  sVar3 = _strlen(pcVar7);
  _crc32_buf(pcVar7,sVar3);
  local_618 = local_610[0];
  _tea_encrypt(&local_618,&DAT_1000018b0);
  iVar2 = _printf("%ld\n");
  if (*(long *)PTR____stack_chk_guard_100004018 == local_78) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail(iVar2);
}


