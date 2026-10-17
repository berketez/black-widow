
bin/k2_aarch64-linux-gnu.o:	file format elf64-littleaarch64

Disassembly of section .text:

0000000000000000 <dispatch>:
       0:      	cmp	w0, #0x2
       4:      	b.le	0x28 <dispatch+0x28>
       8:      	cmp	w0, #0x4
       c:      	b.gt	0x44 <dispatch+0x44>
      10:      	cmp	w0, #0x3
      14:      	b.eq	0x6c <dispatch+0x6c>
      18:      	cmp	w0, #0x4
      1c:      	b.ne	0x64 <dispatch+0x64>
      20:      	eor	w0, w1, #0x3
      24:      	b	0x24 <dispatch+0x24>
		0000000000000024:  R_AARCH64_JUMP26	f4
      28:      	cbz	w0, 0x5c <dispatch+0x5c>
      2c:      	cmp	w0, #0x1
      30:      	b.eq	0x7c <dispatch+0x7c>
      34:      	cmp	w0, #0x2
      38:      	b.ne	0x64 <dispatch+0x64>
      3c:      	lsl	w0, w1, #1
      40:      	b	0x40 <dispatch+0x40>
		0000000000000040:  R_AARCH64_JUMP26	f2
      44:      	cmp	w0, #0x5
      48:      	b.eq	0x74 <dispatch+0x74>
      4c:      	cmp	w0, #0x6
      50:      	b.ne	0x64 <dispatch+0x64>
      54:      	asr	w0, w1, #1
      58:      	b	0x58 <dispatch+0x58>
		0000000000000058:  R_AARCH64_JUMP26	f6
      5c:      	mov	w0, w1
      60:      	b	0x60 <dispatch+0x60>
		0000000000000060:  R_AARCH64_JUMP26	f0
      64:      	mov	w0, #-0x1               // =-1
      68:      	ret
      6c:      	sub	w0, w1, #0x7
      70:      	b	0x70 <dispatch+0x70>
		0000000000000070:  R_AARCH64_JUMP26	f3
      74:      	mov	w0, w1
      78:      	b	0x78 <dispatch+0x78>
		0000000000000078:  R_AARCH64_JUMP26	f5
      7c:      	add	w0, w1, #0x1
      80:      	b	0x80 <dispatch+0x80>
		0000000000000080:  R_AARCH64_JUMP26	f1

0000000000000084 <canary>:
      84:      	sub	sp, sp, #0x60
      88:      	stp	x29, x30, [sp, #0x50]
      8c:      	add	x29, sp, #0x50
      90:      	adrp	x8, 0x0 <dispatch>
		0000000000000090:  R_AARCH64_ADR_GOT_PAGE	__stack_chk_guard
      94:      	mov	x1, x0
      98:      	add	x0, sp, #0x8
      9c:      	ldr	x8, [x8]
		000000000000009c:  R_AARCH64_LD64_GOT_LO12_NC	__stack_chk_guard
      a0:      	ldr	x8, [x8]
      a4:      	stur	x8, [x29, #-0x8]
      a8:      	bl	0xa8 <canary+0x24>
		00000000000000a8:  R_AARCH64_CALL26	strcpy
      ac:      	add	x0, sp, #0x8
      b0:      	bl	0xb0 <canary+0x2c>
		00000000000000b0:  R_AARCH64_CALL26	strlen
      b4:      	adrp	x8, 0x0 <dispatch>
		00000000000000b4:  R_AARCH64_ADR_GOT_PAGE	__stack_chk_guard
      b8:      	ldr	x8, [x8]
		00000000000000b8:  R_AARCH64_LD64_GOT_LO12_NC	__stack_chk_guard
      bc:      	ldur	x9, [x29, #-0x8]
      c0:      	ldr	x8, [x8]
      c4:      	cmp	x8, x9
      c8:      	b.ne	0xd8 <canary+0x54>
      cc:      	ldp	x29, x30, [sp, #0x50]
      d0:      	add	sp, sp, #0x60
      d4:      	ret
      d8:      	bl	0xd8 <canary+0x54>
		00000000000000d8:  R_AARCH64_CALL26	__stack_chk_fail

00000000000000dc <seterr>:
      dc:      	stp	x29, x30, [sp, #-0x20]!
      e0:      	str	x19, [sp, #0x10]
      e4:      	mov	x29, sp
      e8:      	mov	w19, w0
      ec:      	bl	0xec <seterr+0x10>
		00000000000000ec:  R_AARCH64_CALL26	__errno_location
      f0:      	mov	x8, x0
      f4:      	mov	w0, #-0x1               // =-1
      f8:      	str	w19, [x8]
      fc:      	ldr	x19, [sp, #0x10]
     100:      	ldp	x29, x30, [sp], #0x20
     104:      	ret
