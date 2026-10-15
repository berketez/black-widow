// ==== _sw_dense @ 100000560

undefined4 _sw_dense(uint param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0xffffffff;
  if (param_1 < 8) {
    uVar1 = *(undefined4 *)(&DAT_100001b60 + (ulong)param_1 * 4);
  }
  return uVar1;
}


// ==== _sw_sparse @ 100000580

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


// ==== _sw_bittest @ 100000600

undefined8 _sw_bittest(uint param_1)

{
  if ((param_1 < 0x3c) && ((0x800100100003e00U >> ((ulong)param_1 & 0x3f) & 1) != 0)) {
    return 1;
  }
  return 0;
}


// ==== _udiv7 @ 100000630

uint _udiv7(uint param_1)

{
  return param_1 / 7;
}


// ==== _sdiv7 @ 100000650

int _sdiv7(int param_1)

{
  return param_1 / 7;
}


// ==== _umod10 @ 100000670

uint _umod10(uint param_1)

{
  return param_1 % 10;
}


// ==== _sdiv16 @ 100000690

int _sdiv16(int param_1)

{
  int iVar1;
  
  iVar1 = param_1 + 0xf;
  if (-1 < param_1) {
    iVar1 = param_1;
  }
  return iVar1 >> 4;
}


// ==== _udiv1000_64 @ 1000006b0

ulong _udiv1000_64(ulong param_1)

{
  return param_1 / 1000;
}


// ==== _sel_max @ 1000006e0

int _sel_max(int param_1,int param_2)

{
  if (param_2 < param_1) {
    param_2 = param_1;
  }
  return param_2;
}


// ==== _sel_abs @ 1000006f0

int _sel_abs(int param_1)

{
  int iVar1;
  
  iVar1 = -param_1;
  if (-param_1 < 0) {
    iVar1 = param_1;
  }
  return iVar1;
}


// ==== _sel_clamp @ 100000700

int _sel_clamp(int param_1,int param_2,int param_3)

{
  if (param_1 < param_3) {
    param_3 = param_1;
  }
  if (param_1 < param_2) {
    param_3 = param_2;
  }
  return param_3;
}


// ==== _popcount_loop @ 100000720

int _popcount_loop(uint param_1)

{
  int iVar1;
  
  iVar1 = 0;
  for (; param_1 != 0; param_1 = param_1 - 1 & param_1) {
    iVar1 = iVar1 + 1;
  }
  return iVar1;
}


// ==== _bswap32_manual @ 100000740

uint _bswap32_manual(uint param_1)

{
  return param_1 >> 0x18 | (param_1 & 0xff0000) >> 8 | (param_1 & 0xff00) << 8 | param_1 << 0x18;
}


// ==== _rotl32 @ 100000750

uint _rotl32(uint param_1,byte param_2)

{
  return param_1 << (param_2 & 0x1f) | param_1 >> 0x20 - (param_2 & 0x1f);
}


// ==== _is_pow2 @ 100000760

bool _is_pow2(uint param_1)

{
  if (param_1 != 0) {
    return (param_1 & param_1 - 1) == 0;
  }
  return false;
}


// ==== _copy16 @ 100000780

void _copy16(undefined8 *param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  
  uVar1 = param_2[1];
  *param_1 = *param_2;
  param_1[1] = uVar1;
  return;
}


// ==== _zero64 @ 100000790

void _zero64(undefined8 *param_1)

{
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  *param_1 = 0;
  param_1[1] = 0;
  return;
}


// ==== _zero_n @ 1000007b0

void _zero_n(void)

{
  ___bzero();
  return;
}


// ==== _strlen_const @ 1000007c0

undefined8 _strlen_const(void)

{
  return 7;
}


// ==== _strcmp_const @ 1000007d0

bool _strcmp_const(char *param_1)

{
  int iVar1;
  
  iVar1 = _strcmp(param_1,"GET");
  return iVar1 == 0;
}


// ==== _strncmp_const @ 1000007f0

bool _strncmp_const(char *param_1)

{
  int iVar1;
  
  iVar1 = _strncmp(param_1,"HTTP/1.",7);
  return iVar1 == 0;
}


// ==== _loop_zero @ 100000810

void _loop_zero(undefined8 param_1,uint param_2)

{
  if (0 < (int)param_2) {
    ___bzero(param_1,(ulong)param_2 << 2);
    return;
  }
  return;
}


// ==== _loop_copy @ 100000830

void _loop_copy(void *param_1,void *param_2,uint param_3)

{
  if (0 < (int)param_3) {
    _memcpy(param_1,param_2,(ulong)param_3);
    return;
  }
  return;
}


// ==== _loop_strlen @ 100000850

void _loop_strlen(char *param_1)

{
  _strlen(param_1);
  return;
}


// ==== _make_big @ 100000860

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

long * _make_big(long *param_1,long param_2)

{
  undefined1 auVar1 [16];
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  
  *param_1 = param_2;
  auVar1._8_4_ = (int)param_2;
  auVar1._0_8_ = param_2;
  auVar1._12_4_ = (int)((ulong)param_2 >> 0x20);
  lVar3 = _DAT_1000018f0 + param_2;
  lVar2 = auVar1._8_8_;
  lVar4 = _UNK_1000018f8 + lVar2;
  lVar5 = _DAT_100001900 + param_2;
  lVar6 = _UNK_100001908 + lVar2;
  lVar2 = lVar2 + _UNK_100001918;
  param_1[5] = param_2 + _DAT_100001910;
  param_1[6] = lVar2;
  param_1[3] = lVar5;
  param_1[4] = lVar6;
  param_1[1] = lVar3;
  param_1[2] = lVar4;
  param_1[7] = param_2 + 7;
  return param_1;
}


// ==== _use_big @ 1000008b0

long _use_big(undefined8 param_1)

{
  undefined1 local_48 [24];
  long local_30;
  long local_10;
  
  _make_big(local_48,param_1);
  return local_10 + local_30;
}


// ==== _make_small @ 1000008e0

undefined8 _make_small(int param_1)

{
  return CONCAT44(param_1 * 3,param_1);
}


// ==== _sum_va @ 100000900

int _sum_va(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
           undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,
           undefined8 param_10,undefined8 param_11,undefined8 param_12,undefined8 param_13,
           undefined8 param_14)

{
  char in_AL;
  int iVar1;
  int *piVar2;
  ulong uVar3;
  int *piVar4;
  uint uVar5;
  int *piVar6;
  int *piVar7;
  int local_d8 [2];
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_98;
  undefined8 local_88;
  undefined8 local_78;
  undefined8 local_68;
  undefined8 local_58;
  undefined8 local_48;
  undefined8 local_38;
  uint local_28;
  undefined4 uStack_24;
  int *local_20;
  int *local_18;
  long local_10;
  
  if (in_AL != '\0') {
    local_a8 = param_1;
    local_98 = param_2;
    local_88 = param_3;
    local_78 = param_4;
    local_68 = param_5;
    local_58 = param_6;
    local_48 = param_7;
    local_38 = param_8;
  }
  local_10 = *(long *)PTR____stack_chk_guard_100002020;
  local_18 = local_d8;
  piVar2 = (int *)&stack0x00000008;
  local_28 = 8;
  local_20 = piVar2;
  if ((int)param_9 < 1) {
    iVar1 = 0;
  }
  else {
    uVar3 = 8;
    if (param_9 == 1) {
      iVar1 = 0;
    }
    else {
      uVar5 = param_9 & 0x7ffffffe;
      iVar1 = 0;
      do {
        if ((uint)uVar3 < 0x29) {
          piVar4 = (int *)((long)local_18 + uVar3);
          local_28 = (uint)uVar3 + 8;
          uVar3 = (ulong)local_28;
          piVar7 = piVar2;
        }
        else {
          piVar7 = piVar2 + 2;
          piVar4 = piVar2;
          local_20 = piVar7;
        }
        if ((uint)uVar3 < 0x29) {
          piVar6 = (int *)((long)local_18 + uVar3);
          local_28 = (uint)uVar3 + 8;
          uVar3 = (ulong)local_28;
          piVar2 = piVar7;
        }
        else {
          local_20 = piVar7 + 2;
          piVar2 = local_20;
          piVar6 = piVar7;
        }
        iVar1 = iVar1 + *piVar4 + *piVar6;
        uVar5 = uVar5 - 2;
      } while (uVar5 != 0);
    }
    if ((param_9 & 1) != 0) {
      if ((uint)uVar3 < 0x29) {
        piVar2 = (int *)((long)local_18 + uVar3);
        local_28 = (uint)uVar3 + 8;
      }
      else {
        local_20 = piVar2 + 2;
      }
      iVar1 = iVar1 + *piVar2;
    }
  }
  uStack_24 = 0x30;
  if (*(long *)PTR____stack_chk_guard_100002020 == local_10) {
    return iVar1;
  }
  local_d0 = param_10;
  local_c8 = param_11;
  local_c0 = param_12;
  local_b8 = param_13;
  local_b0 = param_14;
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}


// ==== _ssp_copy @ 100000a50

int _ssp_copy(undefined8 param_1)

{
  size_t sVar1;
  char local_58 [3];
  char local_55;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100002020;
  ___strcpy_chk(local_58,param_1,0x40);
  sVar1 = _strlen(local_58);
  if (*(long *)PTR____stack_chk_guard_100002020 == local_18) {
    return (int)local_55 + (int)sVar1;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}


// ==== _fortify_memcpy @ 100000ab0

void _fortify_memcpy(undefined4 *param_1,undefined8 param_2,undefined8 param_3)

{
  undefined4 local_38;
  undefined4 uStack_34;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  undefined4 local_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100002020;
  ___memcpy_chk(&local_38,param_2,param_3,0x20);
  *param_1 = local_38;
  param_1[1] = uStack_34;
  param_1[2] = uStack_30;
  param_1[3] = uStack_2c;
  param_1[4] = local_28;
  param_1[5] = uStack_24;
  param_1[6] = uStack_20;
  param_1[7] = uStack_1c;
  if (*(long *)PTR____stack_chk_guard_100002020 == local_18) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}


// ==== _fortify_snprintf @ 100000b10

void _fortify_snprintf(char *param_1,size_t param_2,ulong param_3)

{
  _snprintf(param_1,param_2,"deger=%d",param_3 & 0xffffffff);
  return;
}


// ==== _read_file_head @ 100000b30

ulong _read_file_head(char *param_1,void *param_2,size_t param_3)

{
  FILE *pFVar1;
  int iVar2;
  void *pvVar3;
  size_t sVar4;
  char *pcVar5;
  int *piVar6;
  
  iVar2 = _open(param_1,0x1000000);
  if (iVar2 < 0) {
    pFVar1 = *(FILE **)PTR____stderrp_100002028;
    piVar6 = ___error();
    pcVar5 = _strerror(*piVar6);
    _fprintf(pFVar1,"open %s: %s\n",param_1,pcVar5);
    sVar4 = 0xffffffff;
  }
  else {
    pvVar3 = _malloc(param_3);
    if (pvVar3 == (void *)0x0) {
      sVar4 = 0xffffffff;
    }
    else {
      sVar4 = _read(iVar2,pvVar3,param_3);
      if ((long)sVar4 < 0) {
        piVar6 = ___error();
        *piVar6 = 5;
        sVar4 = 0xffffffff;
      }
      else {
        _memcpy(param_2,pvVar3,sVar4);
      }
      _free(pvVar3);
    }
    _close(iVar2);
  }
  return sVar4 & 0xffffffff;
}


// ==== _tail_target @ 100000c00

int _tail_target(int param_1)

{
  return param_1 * 3 + 1;
}


// ==== _tail_caller @ 100000c10

void _tail_caller(int param_1)

{
  _tail_target(param_1 + 1);
  return;
}


// ==== _tail_ext @ 100000c20

void _tail_ext(long param_1)

{
  _atoi((char *)(param_1 + 1));
  return;
}


// ==== _vadd @ 100000c30

void _vadd(long param_1,long param_2,long param_3,uint param_4)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
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
  ulong uVar18;
  long lVar19;
  
  if (0 < (int)param_4) {
    if (param_4 < 8) {
      uVar18 = 0;
    }
    else {
      uVar18 = (ulong)(param_4 & 0x7ffffff8);
      lVar19 = 0;
      do {
        piVar1 = (int *)(param_2 + lVar19);
        iVar4 = piVar1[1];
        iVar5 = piVar1[2];
        iVar6 = piVar1[3];
        piVar2 = (int *)(param_2 + 0x10 + lVar19);
        iVar7 = *piVar2;
        iVar8 = piVar2[1];
        iVar9 = piVar2[2];
        iVar10 = piVar2[3];
        piVar2 = (int *)(param_3 + lVar19);
        iVar11 = piVar2[1];
        iVar12 = piVar2[2];
        iVar13 = piVar2[3];
        piVar3 = (int *)(param_3 + 0x10 + lVar19);
        iVar14 = *piVar3;
        iVar15 = piVar3[1];
        iVar16 = piVar3[2];
        iVar17 = piVar3[3];
        piVar3 = (int *)(param_1 + lVar19);
        *piVar3 = *piVar2 + *piVar1;
        piVar3[1] = iVar11 + iVar4;
        piVar3[2] = iVar12 + iVar5;
        piVar3[3] = iVar13 + iVar6;
        piVar1 = (int *)(param_1 + 0x10 + lVar19);
        *piVar1 = iVar14 + iVar7;
        piVar1[1] = iVar15 + iVar8;
        piVar1[2] = iVar16 + iVar9;
        piVar1[3] = iVar17 + iVar10;
        lVar19 = lVar19 + 0x20;
      } while ((ulong)(param_4 >> 3 & 0xfffffff) << 5 != lVar19);
      if ((param_4 & 0x7ffffff8) == param_4) {
        return;
      }
    }
    do {
      *(int *)(param_1 + uVar18 * 4) =
           *(int *)(param_3 + uVar18 * 4) + *(int *)(param_2 + uVar18 * 4);
      uVar18 = uVar18 + 1;
    } while (param_4 != uVar18);
  }
  return;
}


// ==== _vsum @ 100000cc0

int _vsum(long param_1,uint param_2)

{
  int *piVar1;
  int iVar2;
  ulong uVar3;
  long lVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  
  if ((int)param_2 < 1) {
    return 0;
  }
  if (param_2 < 8) {
    uVar3 = 0;
    iVar2 = 0;
  }
  else {
    uVar3 = (ulong)(param_2 & 0x7ffffff8);
    iVar2 = 0;
    iVar5 = 0;
    iVar6 = 0;
    iVar7 = 0;
    lVar4 = 0;
    iVar8 = 0;
    iVar9 = 0;
    iVar10 = 0;
    iVar11 = 0;
    do {
      piVar1 = (int *)(param_1 + lVar4);
      iVar2 = iVar2 + *piVar1;
      iVar5 = iVar5 + piVar1[1];
      iVar6 = iVar6 + piVar1[2];
      iVar7 = iVar7 + piVar1[3];
      piVar1 = (int *)(param_1 + 0x10 + lVar4);
      iVar8 = iVar8 + *piVar1;
      iVar9 = iVar9 + piVar1[1];
      iVar10 = iVar10 + piVar1[2];
      iVar11 = iVar11 + piVar1[3];
      lVar4 = lVar4 + 0x20;
    } while ((ulong)(param_2 >> 3 & 0xfffffff) << 5 != lVar4);
    iVar2 = iVar11 + iVar7 + iVar9 + iVar5 + iVar10 + iVar6 + iVar8 + iVar2;
    if ((param_2 & 0x7ffffff8) == param_2) {
      return iVar2;
    }
  }
  do {
    iVar2 = iVar2 + *(int *)(param_1 + uVar3 * 4);
    uVar3 = uVar3 + 1;
  } while (param_2 != uVar3);
  return iVar2;
}


// ==== _vdot @ 100000d50

float _vdot(long param_1,long param_2,uint param_3)

{
  ulong uVar1;
  ulong uVar2;
  float fVar3;
  
  if (0 < (int)param_3) {
    if (param_3 < 4) {
      fVar3 = 0.0;
      uVar1 = 0;
    }
    else {
      fVar3 = 0.0;
      uVar1 = 0;
      do {
        fVar3 = *(float *)(param_1 + 0xc + uVar1 * 4) * *(float *)(param_2 + 0xc + uVar1 * 4) +
                *(float *)(param_1 + 8 + uVar1 * 4) * *(float *)(param_2 + 8 + uVar1 * 4) +
                *(float *)(param_1 + 4 + uVar1 * 4) * *(float *)(param_2 + 4 + uVar1 * 4) +
                *(float *)(param_1 + uVar1 * 4) * *(float *)(param_2 + uVar1 * 4) + fVar3;
        uVar1 = uVar1 + 4;
      } while ((param_3 & 0x7ffffffc) != uVar1);
    }
    if ((ulong)(param_3 & 3) != 0) {
      uVar2 = 0;
      do {
        fVar3 = fVar3 + *(float *)(param_1 + uVar1 * 4 + uVar2 * 4) *
                        *(float *)(param_2 + uVar1 * 4 + uVar2 * 4);
        uVar2 = uVar2 + 1;
      } while ((param_3 & 3) != uVar2);
    }
    return fVar3;
  }
  return 0.0;
}


// ==== _md5_init @ 100000e00

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void _md5_init(undefined8 *param_1)

{
  undefined8 uVar1;
  
  uVar1 = _UNK_100001928;
  *param_1 = _DAT_100001920;
  param_1[1] = uVar1;
  return;
}


// ==== _crc32_make_table @ 100000e10

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void _crc32_make_table(void)

{
  undefined1 auVar1 [16];
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  long lVar6;
  undefined1 auVar7 [16];
  undefined1 auVar8 [16];
  undefined1 auVar9 [16];
  undefined1 auVar10 [16];
  undefined1 auVar11 [16];
  undefined1 auVar12 [16];
  undefined1 auVar13 [16];
  undefined1 auVar14 [16];
  undefined1 auVar15 [16];
  undefined1 auVar16 [16];
  undefined1 auVar17 [16];
  undefined1 auVar18 [16];
  undefined1 auVar19 [16];
  undefined1 auVar20 [16];
  undefined1 auVar21 [16];
  undefined1 auVar22 [16];
  uint uVar23;
  uint uVar24;
  uint uVar25;
  uint uVar26;
  
  iVar5 = _UNK_10000195c;
  iVar4 = _UNK_100001958;
  iVar3 = _UNK_100001954;
  iVar2 = _DAT_100001950;
  auVar1 = _DAT_100001940;
  lVar6 = 0;
  uVar23 = (uint)PTR___mh_execute_header_100001930;
  uVar24 = PTR___mh_execute_header_100001930._4_4_;
  uVar25 = _UNK_100001938;
  uVar26 = _UNK_10000193c;
  do {
    auVar7._0_4_ = uVar23 >> 1;
    auVar7._4_4_ = uVar24 >> 1;
    auVar7._8_4_ = uVar25 >> 1;
    auVar7._12_4_ = uVar26 >> 1;
    auVar8._0_4_ = uVar23 << 0x1f;
    auVar8._4_4_ = uVar24 << 0x1f;
    auVar8._8_4_ = uVar25 << 0x1f;
    auVar8._12_4_ = uVar26 << 0x1f;
    auVar8 = blendvps(auVar7,auVar7 ^ auVar1,auVar8);
    auVar16._0_4_ = auVar8._0_4_ >> 1;
    auVar16._4_4_ = auVar8._4_4_ >> 1;
    auVar16._8_4_ = auVar8._8_4_ >> 1;
    auVar16._12_4_ = auVar8._12_4_ >> 1;
    auVar9._0_4_ = auVar8._0_4_ << 0x1f;
    auVar9._4_4_ = auVar8._4_4_ << 0x1f;
    auVar9._8_4_ = auVar8._8_4_ << 0x1f;
    auVar9._12_4_ = auVar8._12_4_ << 0x1f;
    auVar8 = blendvps(auVar16,auVar16 ^ auVar1,auVar9);
    auVar10._0_4_ = auVar8._0_4_ >> 1;
    auVar10._4_4_ = auVar8._4_4_ >> 1;
    auVar10._8_4_ = auVar8._8_4_ >> 1;
    auVar10._12_4_ = auVar8._12_4_ >> 1;
    auVar17._0_4_ = auVar8._0_4_ << 0x1f;
    auVar17._4_4_ = auVar8._4_4_ << 0x1f;
    auVar17._8_4_ = auVar8._8_4_ << 0x1f;
    auVar17._12_4_ = auVar8._12_4_ << 0x1f;
    auVar8 = blendvps(auVar10,auVar10 ^ auVar1,auVar17);
    auVar18._0_4_ = auVar8._0_4_ >> 1;
    auVar18._4_4_ = auVar8._4_4_ >> 1;
    auVar18._8_4_ = auVar8._8_4_ >> 1;
    auVar18._12_4_ = auVar8._12_4_ >> 1;
    auVar11._0_4_ = auVar8._0_4_ << 0x1f;
    auVar11._4_4_ = auVar8._4_4_ << 0x1f;
    auVar11._8_4_ = auVar8._8_4_ << 0x1f;
    auVar11._12_4_ = auVar8._12_4_ << 0x1f;
    auVar8 = blendvps(auVar18,auVar18 ^ auVar1,auVar11);
    auVar12._0_4_ = auVar8._0_4_ >> 1;
    auVar12._4_4_ = auVar8._4_4_ >> 1;
    auVar12._8_4_ = auVar8._8_4_ >> 1;
    auVar12._12_4_ = auVar8._12_4_ >> 1;
    auVar19._0_4_ = auVar8._0_4_ << 0x1f;
    auVar19._4_4_ = auVar8._4_4_ << 0x1f;
    auVar19._8_4_ = auVar8._8_4_ << 0x1f;
    auVar19._12_4_ = auVar8._12_4_ << 0x1f;
    auVar8 = blendvps(auVar12,auVar12 ^ auVar1,auVar19);
    auVar20._0_4_ = auVar8._0_4_ >> 1;
    auVar20._4_4_ = auVar8._4_4_ >> 1;
    auVar20._8_4_ = auVar8._8_4_ >> 1;
    auVar20._12_4_ = auVar8._12_4_ >> 1;
    auVar13._0_4_ = auVar8._0_4_ << 0x1f;
    auVar13._4_4_ = auVar8._4_4_ << 0x1f;
    auVar13._8_4_ = auVar8._8_4_ << 0x1f;
    auVar13._12_4_ = auVar8._12_4_ << 0x1f;
    auVar8 = blendvps(auVar20,auVar20 ^ auVar1,auVar13);
    auVar14._0_4_ = auVar8._0_4_ >> 1;
    auVar14._4_4_ = auVar8._4_4_ >> 1;
    auVar14._8_4_ = auVar8._8_4_ >> 1;
    auVar14._12_4_ = auVar8._12_4_ >> 1;
    auVar21._0_4_ = auVar8._0_4_ << 0x1f;
    auVar21._4_4_ = auVar8._4_4_ << 0x1f;
    auVar21._8_4_ = auVar8._8_4_ << 0x1f;
    auVar21._12_4_ = auVar8._12_4_ << 0x1f;
    auVar8 = blendvps(auVar14,auVar14 ^ auVar1,auVar21);
    auVar22._0_4_ = auVar8._0_4_ >> 1;
    auVar22._4_4_ = auVar8._4_4_ >> 1;
    auVar22._8_4_ = auVar8._8_4_ >> 1;
    auVar22._12_4_ = auVar8._12_4_ >> 1;
    auVar15._0_4_ = auVar8._0_4_ << 0x1f;
    auVar15._4_4_ = auVar8._4_4_ << 0x1f;
    auVar15._8_4_ = auVar8._8_4_ << 0x1f;
    auVar15._12_4_ = auVar8._12_4_ << 0x1f;
    auVar8 = blendvps(auVar22,auVar22 ^ auVar1,auVar15);
    *(undefined1 (*) [16])(&_crc_table + lVar6) = auVar8;
    uVar23 = uVar23 + iVar2;
    uVar24 = uVar24 + iVar3;
    uVar25 = uVar25 + iVar4;
    uVar26 = uVar26 + iVar5;
    lVar6 = lVar6 + 0x10;
  } while (lVar6 != 0x400);
  return;
}


// ==== _crc32_buf @ 100000f50

uint _crc32_buf(byte *param_1,ulong param_2)

{
  byte *pbVar1;
  uint uVar2;
  ulong uVar3;
  
  if (param_2 != 0) {
    if (param_2 == 1) {
      uVar2 = 0xffffffff;
    }
    else {
      uVar3 = param_2 & 0xfffffffffffffffe;
      uVar2 = 0xffffffff;
      do {
        uVar2 = uVar2 >> 8 ^ *(uint *)(&_crc_table + (ulong)(byte)(*param_1 ^ (byte)uVar2) * 4);
        pbVar1 = param_1 + 1;
        param_1 = param_1 + 2;
        uVar2 = uVar2 >> 8 ^ *(uint *)(&_crc_table + (ulong)(byte)(*pbVar1 ^ (byte)uVar2) * 4);
        uVar3 = uVar3 - 2;
      } while (uVar3 != 0);
    }
    if ((param_2 & 1) != 0) {
      uVar2 = uVar2 >> 8 ^ *(uint *)(&_crc_table + (ulong)(byte)(*param_1 ^ (byte)uVar2) * 4);
    }
    return ~uVar2;
  }
  return 0;
}


// ==== _tea_encrypt @ 100000fd0

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
    uVar1 = uVar1 + ((uVar2 >> 5) + param_2[1] ^ uVar2 + iVar4 ^ uVar2 * 0x10 + *param_2);
    uVar2 = ((uVar1 >> 5) + param_2[3] ^ iVar4 + uVar1 ^ uVar1 * 0x10 + param_2[2]) + uVar2;
    iVar4 = iVar4 + -0x61c88647;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  *param_1 = uVar1;
  param_1[1] = uVar2;
  return;
}


// ==== entry @ 100001050

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 entry(int param_1,long param_2)

{
  char *pcVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  size_t sVar9;
  long lVar10;
  long lVar11;
  uint uVar12;
  long lVar13;
  long lVar14;
  long lVar15;
  uint uVar16;
  float fVar17;
  undefined1 local_678 [12];
  int local_66c;
  ulong local_668;
  undefined8 uStack_660;
  long local_650;
  long local_648;
  long local_640;
  long local_638;
  char *local_630;
  int local_628;
  int local_624;
  int local_620;
  int local_61c;
  int local_618;
  int local_614;
  int local_610;
  int local_60c;
  int local_608;
  int local_604;
  long local_600;
  long local_5f8;
  long local_5f0;
  ulong local_5e8;
  char *local_5e0;
  long local_5d8;
  ulong local_5d0;
  ulong local_5c8 [2];
  float local_5b8;
  float fStack_5b4;
  float fStack_5b0;
  float fStack_5ac;
  float local_5a8;
  float fStack_5a4;
  float fStack_5a0;
  float fStack_59c;
  float local_598;
  float fStack_594;
  float fStack_590;
  float fStack_58c;
  float local_588;
  float fStack_584;
  float fStack_580;
  float fStack_57c;
  float local_578;
  float fStack_574;
  float fStack_570;
  float fStack_56c;
  float local_568;
  float fStack_564;
  float fStack_560;
  float fStack_55c;
  float local_558;
  float fStack_554;
  float fStack_550;
  float fStack_54c;
  float local_548;
  float fStack_544;
  float fStack_540;
  float fStack_53c;
  float local_538;
  float fStack_534;
  float fStack_530;
  float fStack_52c;
  float local_528;
  float fStack_524;
  float fStack_520;
  float fStack_51c;
  float local_518;
  float fStack_514;
  float fStack_510;
  float fStack_50c;
  float local_508;
  float fStack_504;
  float fStack_500;
  float fStack_4fc;
  float local_4f8;
  float fStack_4f4;
  float fStack_4f0;
  float fStack_4ec;
  float local_4e8;
  float fStack_4e4;
  float fStack_4e0;
  float fStack_4dc;
  float local_4d8;
  float fStack_4d4;
  float fStack_4d0;
  float fStack_4cc;
  float local_4c8;
  float fStack_4c4;
  float fStack_4c0;
  float fStack_4bc;
  undefined8 local_4b8;
  undefined8 uStack_4b0;
  undefined8 local_4a8;
  undefined8 uStack_4a0;
  undefined8 local_498;
  undefined8 uStack_490;
  undefined8 local_488;
  undefined8 uStack_480;
  undefined8 local_478;
  undefined8 uStack_470;
  undefined8 local_468;
  undefined8 uStack_460;
  undefined8 local_458;
  undefined8 uStack_450;
  undefined8 local_448;
  undefined8 uStack_440;
  undefined8 local_438;
  undefined8 uStack_430;
  undefined8 local_428;
  undefined8 uStack_420;
  undefined8 local_418;
  undefined8 uStack_410;
  undefined8 local_408;
  undefined8 uStack_400;
  undefined8 local_3f8;
  undefined8 uStack_3f0;
  undefined8 local_3e8;
  undefined8 uStack_3e0;
  undefined8 local_3d8;
  undefined8 uStack_3d0;
  undefined8 local_3c8;
  undefined8 uStack_3c0;
  int local_3b8;
  int iStack_3b4;
  int iStack_3b0;
  int iStack_3ac;
  int local_3a8;
  int iStack_3a4;
  int iStack_3a0;
  int iStack_39c;
  int local_398;
  int iStack_394;
  int iStack_390;
  int iStack_38c;
  int local_388;
  int iStack_384;
  int iStack_380;
  int iStack_37c;
  int local_378;
  int iStack_374;
  int iStack_370;
  int iStack_36c;
  int local_368;
  int iStack_364;
  int iStack_360;
  int iStack_35c;
  int local_358;
  int iStack_354;
  int iStack_350;
  int iStack_34c;
  int local_348;
  int iStack_344;
  int iStack_340;
  int iStack_33c;
  int local_338;
  int iStack_334;
  int iStack_330;
  int iStack_32c;
  int local_328;
  int iStack_324;
  int iStack_320;
  int iStack_31c;
  int local_318;
  int iStack_314;
  int iStack_310;
  int iStack_30c;
  int local_308;
  int iStack_304;
  int iStack_300;
  int iStack_2fc;
  int local_2f8;
  int iStack_2f4;
  int iStack_2f0;
  int iStack_2ec;
  int local_2e8;
  int iStack_2e4;
  int iStack_2e0;
  int iStack_2dc;
  int local_2d8;
  int iStack_2d4;
  int iStack_2d0;
  int iStack_2cc;
  int local_2c8;
  int iStack_2c4;
  int iStack_2c0;
  int iStack_2bc;
  undefined1 local_2b8 [16];
  undefined1 local_2a8 [16];
  undefined1 local_298 [16];
  undefined1 local_288 [16];
  undefined1 local_278 [16];
  undefined1 local_268 [16];
  undefined1 local_258 [16];
  undefined1 local_248 [16];
  undefined1 local_238 [16];
  undefined1 local_228 [16];
  undefined1 local_218 [16];
  undefined1 local_208 [16];
  undefined1 local_1f8 [16];
  undefined1 local_1e8 [16];
  undefined1 local_1d8 [16];
  undefined1 local_1c8 [16];
  undefined1 local_1b8 [256];
  undefined1 local_b8 [128];
  long local_38;
  
  local_38 = *(long *)PTR____stack_chk_guard_100002020;
  local_5e0 = "GET";
  uVar2 = 3;
  local_5f8 = param_2;
  if (1 < param_1) {
    uVar2 = _atoi(*(char **)(param_2 + 8));
    if (param_1 != 2) {
      local_5e0 = *(char **)(param_2 + 0x10);
    }
  }
  local_5b8 = (float)(int)uVar2;
  local_1c8._4_4_ = uVar2;
  local_1c8._0_4_ = uVar2;
  local_1c8._8_4_ = uVar2;
  local_1c8._12_4_ = uVar2;
  local_2b8._8_8_ = _UNK_100001938;
  local_2b8._0_8_ = PTR___mh_execute_header_100001930;
  local_2b8 = local_1c8 ^ local_2b8;
  local_2a8 = local_1c8 ^ _DAT_100001960;
  local_3b8 = (int)PTR___mh_execute_header_100001930 + uVar2;
  iStack_3b4 = (int)((ulong)PTR___mh_execute_header_100001930 >> 0x20) + uVar2;
  iStack_3b0 = (int)_UNK_100001938 + uVar2;
  iStack_3ac = (int)((ulong)_UNK_100001938 >> 0x20) + uVar2;
  local_3a8 = (int)DAT_100001960 + uVar2;
  iStack_3a4 = DAT_100001960._4_4_ + uVar2;
  iStack_3a0 = DAT_100001960._8_4_ + uVar2;
  iStack_39c = DAT_100001960._12_4_ + uVar2;
  local_4b8 = _DAT_100001970;
  uStack_4b0 = _UNK_100001978;
  local_4a8 = _DAT_100001980;
  uStack_4a0 = _UNK_100001988;
  local_298 = local_1c8 ^ _DAT_100001990;
  local_288 = local_1c8 ^ _DAT_1000019a0;
  local_398 = (int)DAT_100001990 + uVar2;
  iStack_394 = DAT_100001990._4_4_ + uVar2;
  iStack_390 = DAT_100001990._8_4_ + uVar2;
  iStack_38c = DAT_100001990._12_4_ + uVar2;
  local_388 = (int)DAT_1000019a0 + uVar2;
  iStack_384 = DAT_1000019a0._4_4_ + uVar2;
  iStack_380 = DAT_1000019a0._8_4_ + uVar2;
  iStack_37c = DAT_1000019a0._12_4_ + uVar2;
  local_498 = _DAT_1000019b0;
  uStack_490 = _UNK_1000019b8;
  local_488 = _DAT_1000019c0;
  uStack_480 = _UNK_1000019c8;
  local_278 = local_1c8 ^ _DAT_1000019d0;
  local_268 = local_1c8 ^ _DAT_1000019e0;
  local_378 = (int)DAT_1000019d0 + uVar2;
  iStack_374 = DAT_1000019d0._4_4_ + uVar2;
  iStack_370 = DAT_1000019d0._8_4_ + uVar2;
  iStack_36c = DAT_1000019d0._12_4_ + uVar2;
  local_368 = (int)DAT_1000019e0 + uVar2;
  iStack_364 = DAT_1000019e0._4_4_ + uVar2;
  iStack_360 = DAT_1000019e0._8_4_ + uVar2;
  iStack_35c = DAT_1000019e0._12_4_ + uVar2;
  local_478 = _DAT_1000019f0;
  uStack_470 = _UNK_1000019f8;
  local_468 = _DAT_100001a00;
  uStack_460 = _UNK_100001a08;
  local_258 = local_1c8 ^ _DAT_100001a10;
  local_248 = local_1c8 ^ _DAT_100001a20;
  local_358 = (int)DAT_100001a10 + uVar2;
  iStack_354 = DAT_100001a10._4_4_ + uVar2;
  iStack_350 = DAT_100001a10._8_4_ + uVar2;
  iStack_34c = DAT_100001a10._12_4_ + uVar2;
  local_348 = (int)DAT_100001a20 + uVar2;
  iStack_344 = DAT_100001a20._4_4_ + uVar2;
  iStack_340 = DAT_100001a20._8_4_ + uVar2;
  iStack_33c = DAT_100001a20._12_4_ + uVar2;
  local_458 = _DAT_100001a30;
  uStack_450 = _UNK_100001a38;
  local_448 = _DAT_100001a40;
  uStack_440 = _UNK_100001a48;
  local_238 = local_1c8 ^ _DAT_100001a50;
  local_228 = local_1c8 ^ _DAT_100001a60;
  local_338 = (int)DAT_100001a50 + uVar2;
  iStack_334 = DAT_100001a50._4_4_ + uVar2;
  iStack_330 = DAT_100001a50._8_4_ + uVar2;
  iStack_32c = DAT_100001a50._12_4_ + uVar2;
  local_328 = (int)DAT_100001a60 + uVar2;
  iStack_324 = DAT_100001a60._4_4_ + uVar2;
  iStack_320 = DAT_100001a60._8_4_ + uVar2;
  iStack_31c = DAT_100001a60._12_4_ + uVar2;
  local_438 = _DAT_100001a70;
  uStack_430 = _UNK_100001a78;
  local_428 = _DAT_100001a80;
  uStack_420 = _UNK_100001a88;
  local_218 = local_1c8 ^ _DAT_100001a90;
  local_208 = local_1c8 ^ _DAT_100001aa0;
  local_318 = (int)DAT_100001a90 + uVar2;
  iStack_314 = DAT_100001a90._4_4_ + uVar2;
  iStack_310 = DAT_100001a90._8_4_ + uVar2;
  iStack_30c = DAT_100001a90._12_4_ + uVar2;
  local_308 = (int)DAT_100001aa0 + uVar2;
  iStack_304 = DAT_100001aa0._4_4_ + uVar2;
  iStack_300 = DAT_100001aa0._8_4_ + uVar2;
  iStack_2fc = DAT_100001aa0._12_4_ + uVar2;
  local_418 = _DAT_100001ab0;
  uStack_410 = _UNK_100001ab8;
  local_408 = _DAT_100001ac0;
  uStack_400 = _UNK_100001ac8;
  local_1f8 = local_1c8 ^ _DAT_100001ad0;
  local_1e8 = local_1c8 ^ _DAT_100001ae0;
  local_2f8 = (int)DAT_100001ad0 + uVar2;
  iStack_2f4 = DAT_100001ad0._4_4_ + uVar2;
  iStack_2f0 = DAT_100001ad0._8_4_ + uVar2;
  iStack_2ec = DAT_100001ad0._12_4_ + uVar2;
  local_2e8 = (int)DAT_100001ae0 + uVar2;
  iStack_2e4 = DAT_100001ae0._4_4_ + uVar2;
  iStack_2e0 = DAT_100001ae0._8_4_ + uVar2;
  iStack_2dc = DAT_100001ae0._12_4_ + uVar2;
  local_3f8 = _DAT_100001af0;
  uStack_3f0 = _UNK_100001af8;
  local_3e8 = _DAT_100001b00;
  uStack_3e0 = _UNK_100001b08;
  local_1d8 = local_1c8 ^ _DAT_100001b10;
  local_1c8 = local_1c8 ^ _DAT_100001b20;
  local_2d8 = (int)DAT_100001b10 + uVar2;
  iStack_2d4 = DAT_100001b10._4_4_ + uVar2;
  iStack_2d0 = DAT_100001b10._8_4_ + uVar2;
  iStack_2cc = DAT_100001b10._12_4_ + uVar2;
  local_2c8 = uVar2 + (int)DAT_100001b20;
  iStack_2c4 = uVar2 + DAT_100001b20._4_4_;
  iStack_2c0 = uVar2 + DAT_100001b20._8_4_;
  iStack_2bc = uVar2 + DAT_100001b20._12_4_;
  local_3d8 = _DAT_100001b30;
  uStack_3d0 = _UNK_100001b38;
  local_3c8 = _DAT_100001b40;
  uStack_3c0 = _UNK_100001b48;
  fStack_5b4 = local_5b8;
  fStack_5b0 = local_5b8;
  fStack_5ac = local_5b8;
  local_5a8 = local_5b8;
  fStack_5a4 = local_5b8;
  fStack_5a0 = local_5b8;
  fStack_59c = local_5b8;
  local_598 = local_5b8;
  fStack_594 = local_5b8;
  fStack_590 = local_5b8;
  fStack_58c = local_5b8;
  local_588 = local_5b8;
  fStack_584 = local_5b8;
  fStack_580 = local_5b8;
  fStack_57c = local_5b8;
  local_578 = local_5b8;
  fStack_574 = local_5b8;
  fStack_570 = local_5b8;
  fStack_56c = local_5b8;
  local_568 = local_5b8;
  fStack_564 = local_5b8;
  fStack_560 = local_5b8;
  fStack_55c = local_5b8;
  local_558 = local_5b8;
  fStack_554 = local_5b8;
  fStack_550 = local_5b8;
  fStack_54c = local_5b8;
  local_548 = local_5b8;
  fStack_544 = local_5b8;
  fStack_540 = local_5b8;
  fStack_53c = local_5b8;
  local_538 = local_5b8;
  fStack_534 = local_5b8;
  fStack_530 = local_5b8;
  fStack_52c = local_5b8;
  local_528 = local_5b8;
  fStack_524 = local_5b8;
  fStack_520 = local_5b8;
  fStack_51c = local_5b8;
  local_518 = local_5b8;
  fStack_514 = local_5b8;
  fStack_510 = local_5b8;
  fStack_50c = local_5b8;
  local_508 = local_5b8;
  fStack_504 = local_5b8;
  fStack_500 = local_5b8;
  fStack_4fc = local_5b8;
  local_4f8 = local_5b8;
  fStack_4f4 = local_5b8;
  fStack_4f0 = local_5b8;
  fStack_4ec = local_5b8;
  local_4e8 = local_5b8;
  fStack_4e4 = local_5b8;
  fStack_4e0 = local_5b8;
  fStack_4dc = local_5b8;
  local_4d8 = local_5b8;
  fStack_4d4 = local_5b8;
  fStack_4d0 = local_5b8;
  fStack_4cc = local_5b8;
  local_4c8 = local_5b8;
  fStack_4c4 = local_5b8;
  fStack_4c0 = local_5b8;
  fStack_4bc = local_5b8;
  uVar3 = _popcount_loop(uVar2);
  local_5f0 = CONCAT44(local_5f0._4_4_,uVar3);
  local_668 = (ulong)PTR___mh_execute_header_100001930 & 0xffffffff00000000 | (ulong)uVar2;
  uStack_660 = _UNK_100001938;
  _copy16(local_678,&local_668);
  local_650 = (long)local_66c;
  _zero64(local_b8);
  _zero_n(local_b8,uVar2 & 0x3f);
  pcVar1 = local_5e0;
  local_600 = _strcmp_const(local_5e0);
  uVar3 = _strncmp_const(pcVar1);
  local_5d8 = CONCAT44(local_5d8._4_4_,uVar3);
  _loop_zero(local_1b8,uVar2 & 0x3f);
  sVar9 = _strlen(pcVar1);
  _loop_copy(local_b8,pcVar1,sVar9 & 0xffffffff);
  local_648 = _loop_strlen(pcVar1);
  local_628 = _sum_va(3,uVar2,uVar2 + 1,uVar2 + 2);
  local_624 = _ssp_copy(pcVar1);
  sVar9 = _strlen(pcVar1);
  _fortify_memcpy(local_b8,pcVar1,(uint)sVar9 & 0x1f);
  local_620 = _fortify_snprintf(local_b8,0x80,uVar2);
  if (param_1 < 4) {
    local_630 = "/etc/hosts";
  }
  else {
    local_630 = *(char **)(local_5f8 + 0x18);
  }
  local_638 = _make_small(uVar2);
  local_5f8 = _use_big((long)(int)uVar2);
  local_61c = _is_pow2(uVar2);
  iVar4 = _rotl32(uVar2,uVar2);
  local_618 = _bswap32_manual(uVar2);
  local_614 = _sel_clamp(uVar2,0,9);
  local_610 = _sel_abs(uVar2);
  local_60c = _sel_max(uVar2,5);
  local_640 = _udiv1000_64((long)(int)uVar2);
  uVar3 = _sdiv16(uVar2);
  local_5e8 = CONCAT44(local_5e8._4_4_,uVar3);
  iVar5 = _umod10(uVar2);
  local_608 = _sdiv7(uVar2);
  iVar6 = _udiv7(uVar2);
  local_604 = _sw_bittest(uVar2);
  iVar7 = _sw_sparse(uVar2);
  iVar8 = _sw_dense(uVar2);
  local_5e8 = (ulong)(uint)(iVar6 + local_608 + iVar5 + (int)local_5e8);
  uVar16 = iVar4 + local_61c + local_618;
  uVar12 = (int)local_600 + (int)local_5d8;
  lVar10 = (long)local_624;
  lVar13 = (long)local_620;
  lVar11 = local_638 >> 0x20;
  local_5d8 = (long)(iVar7 + local_604 + iVar8);
  local_600 = (long)(local_60c + local_610 + local_614 + (int)local_5f0);
  local_5f0 = (long)local_628;
  iVar4 = _read_file_head(local_630,local_b8,0x80);
  lVar14 = iVar4 + local_5d8;
  iVar4 = _tail_caller(uVar2);
  iVar5 = _tail_ext(local_5e0);
  _vadd(local_1b8,local_2b8,&local_3b8,0x40);
  iVar6 = _vsum(local_1b8,0x40);
  fVar17 = (float)_vdot(&local_4b8,&local_5b8,0x40);
  local_5d8 = (long)fVar17;
  _md5_init(local_5c8);
  _crc32_make_table();
  pcVar1 = local_5e0;
  sVar9 = _strlen(local_5e0);
  uVar2 = _crc32_buf(pcVar1,sVar9);
  lVar15 = (ulong)uVar2 + local_5d8;
  local_5d0 = local_5c8[0];
  _tea_encrypt(&local_5d0,&DAT_100001b50);
  _printf("%ld\n",(local_5d0 & 0xffffffff) +
                  (ulong)uVar16 + local_640 + local_600 + local_5e8 +
                  lVar13 + lVar10 + lVar11 + local_5f8 +
                  (ulong)uVar12 + local_648 + local_5f0 + local_650 +
                  (long)iVar6 + (iVar5 + iVar4) + lVar14 + lVar15 + 7);
  if (*(long *)PTR____stack_chk_guard_100002020 == local_38) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  ___stack_chk_fail();
}


