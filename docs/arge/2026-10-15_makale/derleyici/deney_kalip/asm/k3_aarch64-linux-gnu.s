
bin/k3_aarch64-linux-gnu.o:	file format elf64-littleaarch64

Disassembly of section .text:

0000000000000000 <dispatch8>:
       0:      	cmp	w0, #0x3
       4:      	b.gt	0x24 <dispatch8+0x24>
       8:      	cmp	w0, #0x1
       c:      	b.gt	0x44 <dispatch8+0x44>
      10:      	cbz	w0, 0x74 <dispatch8+0x74>
      14:      	cmp	w0, #0x1
      18:      	b.ne	0x94 <dispatch8+0x94>
      1c:      	mov	w0, w1
      20:      	b	0x20 <dispatch8+0x20>
		0000000000000020:  R_AARCH64_JUMP26	g8_1
      24:      	cmp	w0, #0x5
      28:      	b.gt	0x5c <dispatch8+0x5c>
      2c:      	cmp	w0, #0x4
      30:      	b.eq	0x7c <dispatch8+0x7c>
      34:      	cmp	w0, #0x5
      38:      	b.ne	0x94 <dispatch8+0x94>
      3c:      	mov	w0, w1
      40:      	b	0x40 <dispatch8+0x40>
		0000000000000040:  R_AARCH64_JUMP26	g8_5
      44:      	cmp	w0, #0x2
      48:      	b.eq	0x84 <dispatch8+0x84>
      4c:      	cmp	w0, #0x3
      50:      	b.ne	0x94 <dispatch8+0x94>
      54:      	mov	w0, w1
      58:      	b	0x58 <dispatch8+0x58>
		0000000000000058:  R_AARCH64_JUMP26	g8_3
      5c:      	cmp	w0, #0x6
      60:      	b.eq	0x8c <dispatch8+0x8c>
      64:      	cmp	w0, #0x7
      68:      	b.ne	0x94 <dispatch8+0x94>
      6c:      	mov	w0, w1
      70:      	b	0x70 <dispatch8+0x70>
		0000000000000070:  R_AARCH64_JUMP26	g8_7
      74:      	mov	w0, w1
      78:      	b	0x78 <dispatch8+0x78>
		0000000000000078:  R_AARCH64_JUMP26	g8_0
      7c:      	mov	w0, w1
      80:      	b	0x80 <dispatch8+0x80>
		0000000000000080:  R_AARCH64_JUMP26	g8_4
      84:      	mov	w0, w1
      88:      	b	0x88 <dispatch8+0x88>
		0000000000000088:  R_AARCH64_JUMP26	g8_2
      8c:      	mov	w0, w1
      90:      	b	0x90 <dispatch8+0x90>
		0000000000000090:  R_AARCH64_JUMP26	g8_6
      94:      	mov	w0, #-0x1               // =-1
      98:      	ret

000000000000009c <dispatch12>:
      9c:      	cmp	w0, #0xb
      a0:      	b.hi	0x120 <dispatch12+0x84>
      a4:      	mov	w8, w0
      a8:      	adrp	x9, 0x0 <dispatch8>
		00000000000000a8:  R_AARCH64_ADR_PREL_PG_HI21	.rodata
      ac:      	add	x9, x9, #0x0
		00000000000000ac:  R_AARCH64_ADD_ABS_LO12_NC	.rodata
      b0:      	adr	x10, 0xc0 <dispatch12+0x24>
      b4:      	ldrb	w11, [x9, x8]
      b8:      	add	x10, x10, x11, lsl #2
      bc:      	br	x10
      c0:      	mov	w0, w1
      c4:      	b	0xc4 <dispatch12+0x28>
		00000000000000c4:  R_AARCH64_JUMP26	g12_0
      c8:      	mov	w0, w1
      cc:      	b	0xcc <dispatch12+0x30>
		00000000000000cc:  R_AARCH64_JUMP26	g12_11
      d0:      	mov	w0, w1
      d4:      	b	0xd4 <dispatch12+0x38>
		00000000000000d4:  R_AARCH64_JUMP26	g12_4
      d8:      	mov	w0, w1
      dc:      	b	0xdc <dispatch12+0x40>
		00000000000000dc:  R_AARCH64_JUMP26	g12_9
      e0:      	mov	w0, w1
      e4:      	b	0xe4 <dispatch12+0x48>
		00000000000000e4:  R_AARCH64_JUMP26	g12_2
      e8:      	mov	w0, w1
      ec:      	b	0xec <dispatch12+0x50>
		00000000000000ec:  R_AARCH64_JUMP26	g12_3
      f0:      	mov	w0, w1
      f4:      	b	0xf4 <dispatch12+0x58>
		00000000000000f4:  R_AARCH64_JUMP26	g12_7
      f8:      	mov	w0, w1
      fc:      	b	0xfc <dispatch12+0x60>
		00000000000000fc:  R_AARCH64_JUMP26	g12_1
     100:      	mov	w0, w1
     104:      	b	0x104 <dispatch12+0x68>
		0000000000000104:  R_AARCH64_JUMP26	g12_5
     108:      	mov	w0, w1
     10c:      	b	0x10c <dispatch12+0x70>
		000000000000010c:  R_AARCH64_JUMP26	g12_6
     110:      	mov	w0, w1
     114:      	b	0x114 <dispatch12+0x78>
		0000000000000114:  R_AARCH64_JUMP26	g12_10
     118:      	mov	w0, w1
     11c:      	b	0x11c <dispatch12+0x80>
		000000000000011c:  R_AARCH64_JUMP26	g12_8
     120:      	mov	w0, #-0x1               // =-1
     124:      	ret

0000000000000128 <dispatch16>:
     128:      	cmp	w0, #0xf
     12c:      	b.hi	0x1cc <dispatch16+0xa4>
     130:      	mov	w8, w0
     134:      	adrp	x9, 0x0 <dispatch8>
		0000000000000134:  R_AARCH64_ADR_PREL_PG_HI21	.rodata+0xc
     138:      	add	x9, x9, #0x0
		0000000000000138:  R_AARCH64_ADD_ABS_LO12_NC	.rodata+0xc
     13c:      	adr	x10, 0x14c <dispatch16+0x24>
     140:      	ldrb	w11, [x9, x8]
     144:      	add	x10, x10, x11, lsl #2
     148:      	br	x10
     14c:      	mov	w0, w1
     150:      	b	0x150 <dispatch16+0x28>
		0000000000000150:  R_AARCH64_JUMP26	g16_0
     154:      	mov	w0, w1
     158:      	b	0x158 <dispatch16+0x30>
		0000000000000158:  R_AARCH64_JUMP26	g16_14
     15c:      	mov	w0, w1
     160:      	b	0x160 <dispatch16+0x38>
		0000000000000160:  R_AARCH64_JUMP26	g16_11
     164:      	mov	w0, w1
     168:      	b	0x168 <dispatch16+0x40>
		0000000000000168:  R_AARCH64_JUMP26	g16_4
     16c:      	mov	w0, w1
     170:      	b	0x170 <dispatch16+0x48>
		0000000000000170:  R_AARCH64_JUMP26	g16_12
     174:      	mov	w0, w1
     178:      	b	0x178 <dispatch16+0x50>
		0000000000000178:  R_AARCH64_JUMP26	g16_9
     17c:      	mov	w0, w1
     180:      	b	0x180 <dispatch16+0x58>
		0000000000000180:  R_AARCH64_JUMP26	g16_2
     184:      	mov	w0, w1
     188:      	b	0x188 <dispatch16+0x60>
		0000000000000188:  R_AARCH64_JUMP26	g16_15
     18c:      	mov	w0, w1
     190:      	b	0x190 <dispatch16+0x68>
		0000000000000190:  R_AARCH64_JUMP26	g16_3
     194:      	mov	w0, w1
     198:      	b	0x198 <dispatch16+0x70>
		0000000000000198:  R_AARCH64_JUMP26	g16_7
     19c:      	mov	w0, w1
     1a0:      	b	0x1a0 <dispatch16+0x78>
		00000000000001a0:  R_AARCH64_JUMP26	g16_1
     1a4:      	mov	w0, w1
     1a8:      	b	0x1a8 <dispatch16+0x80>
		00000000000001a8:  R_AARCH64_JUMP26	g16_5
     1ac:      	mov	w0, w1
     1b0:      	b	0x1b0 <dispatch16+0x88>
		00000000000001b0:  R_AARCH64_JUMP26	g16_13
     1b4:      	mov	w0, w1
     1b8:      	b	0x1b8 <dispatch16+0x90>
		00000000000001b8:  R_AARCH64_JUMP26	g16_6
     1bc:      	mov	w0, w1
     1c0:      	b	0x1c0 <dispatch16+0x98>
		00000000000001c0:  R_AARCH64_JUMP26	g16_10
     1c4:      	mov	w0, w1
     1c8:      	b	0x1c8 <dispatch16+0xa0>
		00000000000001c8:  R_AARCH64_JUMP26	g16_8
     1cc:      	mov	w0, #-0x1               // =-1
     1d0:      	ret
