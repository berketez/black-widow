
bin/k3_x86_64-linux-gnu.o:	file format elf64-x86-64

Disassembly of section .text:

0000000000000000 <dispatch8>:
       0:      	cmpl	$0x7, %edi
       3:      	ja	0x4f <dispatch8+0x4f>
       5:      	movl	%edi, %eax
       7:      	leaq	(%rip), %rcx            # 0xe <dispatch8+0xe>
		000000000000000a:  R_X86_64_PC32	.rodata-0x4
       e:      	movslq	(%rcx,%rax,4), %rax
      12:      	addq	%rcx, %rax
      15:      	jmpq	*%rax
      17:      	movl	%esi, %edi
      19:      	jmp	0x1e <dispatch8+0x1e>
		000000000000001a:  R_X86_64_PLT32	g8_0-0x4
      1e:      	movl	%esi, %edi
      20:      	jmp	0x25 <dispatch8+0x25>
		0000000000000021:  R_X86_64_PLT32	g8_4-0x4
      25:      	movl	%esi, %edi
      27:      	jmp	0x2c <dispatch8+0x2c>
		0000000000000028:  R_X86_64_PLT32	g8_2-0x4
      2c:      	movl	%esi, %edi
      2e:      	jmp	0x33 <dispatch8+0x33>
		000000000000002f:  R_X86_64_PLT32	g8_3-0x4
      33:      	movl	%esi, %edi
      35:      	jmp	0x3a <dispatch8+0x3a>
		0000000000000036:  R_X86_64_PLT32	g8_7-0x4
      3a:      	movl	%esi, %edi
      3c:      	jmp	0x41 <dispatch8+0x41>
		000000000000003d:  R_X86_64_PLT32	g8_1-0x4
      41:      	movl	%esi, %edi
      43:      	jmp	0x48 <dispatch8+0x48>
		0000000000000044:  R_X86_64_PLT32	g8_5-0x4
      48:      	movl	%esi, %edi
      4a:      	jmp	0x4f <dispatch8+0x4f>
		000000000000004b:  R_X86_64_PLT32	g8_6-0x4
      4f:      	movl	$0xffffffff, %eax       # imm = 0xFFFFFFFF
      54:      	retq
      55:      	nopw	%cs:(%rax,%rax)

0000000000000060 <dispatch12>:
      60:      	cmpl	$0xb, %edi
      63:      	ja	0xcb <dispatch12+0x6b>
      65:      	movl	%edi, %eax
      67:      	leaq	(%rip), %rcx            # 0x6e <dispatch12+0xe>
		000000000000006a:  R_X86_64_PC32	.rodata+0x1c
      6e:      	movslq	(%rcx,%rax,4), %rax
      72:      	addq	%rcx, %rax
      75:      	jmpq	*%rax
      77:      	movl	%esi, %edi
      79:      	jmp	0x7e <dispatch12+0x1e>
		000000000000007a:  R_X86_64_PLT32	g12_0-0x4
      7e:      	movl	%esi, %edi
      80:      	jmp	0x85 <dispatch12+0x25>
		0000000000000081:  R_X86_64_PLT32	g12_11-0x4
      85:      	movl	%esi, %edi
      87:      	jmp	0x8c <dispatch12+0x2c>
		0000000000000088:  R_X86_64_PLT32	g12_4-0x4
      8c:      	movl	%esi, %edi
      8e:      	jmp	0x93 <dispatch12+0x33>
		000000000000008f:  R_X86_64_PLT32	g12_9-0x4
      93:      	movl	%esi, %edi
      95:      	jmp	0x9a <dispatch12+0x3a>
		0000000000000096:  R_X86_64_PLT32	g12_2-0x4
      9a:      	movl	%esi, %edi
      9c:      	jmp	0xa1 <dispatch12+0x41>
		000000000000009d:  R_X86_64_PLT32	g12_3-0x4
      a1:      	movl	%esi, %edi
      a3:      	jmp	0xa8 <dispatch12+0x48>
		00000000000000a4:  R_X86_64_PLT32	g12_7-0x4
      a8:      	movl	%esi, %edi
      aa:      	jmp	0xaf <dispatch12+0x4f>
		00000000000000ab:  R_X86_64_PLT32	g12_1-0x4
      af:      	movl	%esi, %edi
      b1:      	jmp	0xb6 <dispatch12+0x56>
		00000000000000b2:  R_X86_64_PLT32	g12_5-0x4
      b6:      	movl	%esi, %edi
      b8:      	jmp	0xbd <dispatch12+0x5d>
		00000000000000b9:  R_X86_64_PLT32	g12_6-0x4
      bd:      	movl	%esi, %edi
      bf:      	jmp	0xc4 <dispatch12+0x64>
		00000000000000c0:  R_X86_64_PLT32	g12_10-0x4
      c4:      	movl	%esi, %edi
      c6:      	jmp	0xcb <dispatch12+0x6b>
		00000000000000c7:  R_X86_64_PLT32	g12_8-0x4
      cb:      	movl	$0xffffffff, %eax       # imm = 0xFFFFFFFF
      d0:      	retq
      d1:      	nopw	%cs:(%rax,%rax)

00000000000000e0 <dispatch16>:
      e0:      	cmpl	$0xf, %edi
      e3:      	ja	0x16b <dispatch16+0x8b>
      e9:      	movl	%edi, %eax
      eb:      	leaq	(%rip), %rcx            # 0xf2 <dispatch16+0x12>
		00000000000000ee:  R_X86_64_PC32	.rodata+0x4c
      f2:      	movslq	(%rcx,%rax,4), %rax
      f6:      	addq	%rcx, %rax
      f9:      	jmpq	*%rax
      fb:      	movl	%esi, %edi
      fd:      	jmp	0x102 <dispatch16+0x22>
		00000000000000fe:  R_X86_64_PLT32	g16_0-0x4
     102:      	movl	%esi, %edi
     104:      	jmp	0x109 <dispatch16+0x29>
		0000000000000105:  R_X86_64_PLT32	g16_14-0x4
     109:      	movl	%esi, %edi
     10b:      	jmp	0x110 <dispatch16+0x30>
		000000000000010c:  R_X86_64_PLT32	g16_11-0x4
     110:      	movl	%esi, %edi
     112:      	jmp	0x117 <dispatch16+0x37>
		0000000000000113:  R_X86_64_PLT32	g16_4-0x4
     117:      	movl	%esi, %edi
     119:      	jmp	0x11e <dispatch16+0x3e>
		000000000000011a:  R_X86_64_PLT32	g16_12-0x4
     11e:      	movl	%esi, %edi
     120:      	jmp	0x125 <dispatch16+0x45>
		0000000000000121:  R_X86_64_PLT32	g16_9-0x4
     125:      	movl	%esi, %edi
     127:      	jmp	0x12c <dispatch16+0x4c>
		0000000000000128:  R_X86_64_PLT32	g16_2-0x4
     12c:      	movl	%esi, %edi
     12e:      	jmp	0x133 <dispatch16+0x53>
		000000000000012f:  R_X86_64_PLT32	g16_15-0x4
     133:      	movl	%esi, %edi
     135:      	jmp	0x13a <dispatch16+0x5a>
		0000000000000136:  R_X86_64_PLT32	g16_3-0x4
     13a:      	movl	%esi, %edi
     13c:      	jmp	0x141 <dispatch16+0x61>
		000000000000013d:  R_X86_64_PLT32	g16_7-0x4
     141:      	movl	%esi, %edi
     143:      	jmp	0x148 <dispatch16+0x68>
		0000000000000144:  R_X86_64_PLT32	g16_1-0x4
     148:      	movl	%esi, %edi
     14a:      	jmp	0x14f <dispatch16+0x6f>
		000000000000014b:  R_X86_64_PLT32	g16_5-0x4
     14f:      	movl	%esi, %edi
     151:      	jmp	0x156 <dispatch16+0x76>
		0000000000000152:  R_X86_64_PLT32	g16_13-0x4
     156:      	movl	%esi, %edi
     158:      	jmp	0x15d <dispatch16+0x7d>
		0000000000000159:  R_X86_64_PLT32	g16_6-0x4
     15d:      	movl	%esi, %edi
     15f:      	jmp	0x164 <dispatch16+0x84>
		0000000000000160:  R_X86_64_PLT32	g16_10-0x4
     164:      	movl	%esi, %edi
     166:      	jmp	0x16b <dispatch16+0x8b>
		0000000000000167:  R_X86_64_PLT32	g16_8-0x4
     16b:      	movl	$0xffffffff, %eax       # imm = 0xFFFFFFFF
     170:      	retq
