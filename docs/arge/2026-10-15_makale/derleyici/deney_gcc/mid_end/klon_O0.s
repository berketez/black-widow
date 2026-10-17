	.arch armv8.5-a
	.build_version macos,  26, 0
	.text
	.align	2
_olcekle:
LFB4:
	sub	sp, sp, #32
LCFI0:
	str	x0, [sp, 8]
	str	w1, [sp, 4]
	str	xzr, [sp, 24]
	str	wzr, [sp, 20]
	b	L2
L3:
	ldrsw	x1, [sp, 20]
	ldr	x0, [sp, 8]
	mul	x1, x1, x0
	ldr	w0, [sp, 20]
	ldr	x2, [sp, 8]
	asr	x0, x2, x0
	add	x0, x1, x0
	ldr	x1, [sp, 24]
	add	x0, x1, x0
	str	x0, [sp, 24]
	ldr	w0, [sp, 20]
	add	w0, w0, 1
	str	w0, [sp, 20]
L2:
	ldr	w1, [sp, 20]
	ldr	w0, [sp, 4]
	cmp	w1, w0
	blt	L3
	ldr	x0, [sp, 24]
	add	sp, sp, 32
LCFI1:
	ret
LFE4:
	.align	2
_alan_oku:
LFB5:
	sub	sp, sp, #16
LCFI2:
	str	x0, [sp, 8]
	str	w1, [sp, 4]
	ldr	x0, [sp, 8]
	ldr	x1, [x0, 8]
	mov	x0, x1
	lsl	x0, x0, 1
	add	x1, x0, x1
	ldr	x0, [sp, 8]
	ldr	x0, [x0, 8]
	mov	x2, 18725
	movk	x2, 0x2492, lsl 16
	movk	x2, 0x9249, lsl 32
	movk	x2, 0x4924, lsl 48
	smulh	x2, x0, x2
	asr	x2, x2, 1
	asr	x0, x0, 63
	sub	x0, x2, x0
	add	x0, x1, x0
	add	sp, sp, 16
LCFI3:
	ret
LFE5:
	.cstring
	.align	3
l.str.0:
	.ascii "hata %s\12\0"
	.text
	.align	2
_bol:
LFB6:
	sub	sp, sp, #80
LCFI4:
	stp	x29, x30, [sp, 16]
LCFI5:
	add	x29, sp, 16
LCFI6:
	stp	x20, x21, [sp, 32]
LCFI7:
	str	x0, [x29, 40]
	ldr	x0, [x29, 40]
	cmp	x0, 0
	bne	L8
	mov	x0, 0
	b	L9
L8:
	str	xzr, [x29, 56]
	str	wzr, [x29, 52]
	b	L10
L12:
	ldr	x1, [x29, 56]
	mov	x0, x1
	lsl	x0, x0, 5
	sub	x1, x0, x1
	ldrsw	x0, [x29, 52]
	ldr	x2, [x29, 40]
	add	x0, x2, x0
	ldrsb	w0, [x0]
	sxtb	x0, w0
	add	x0, x1, x0
	str	x0, [x29, 56]
	ldr	x1, [x29, 56]
	mov	x0, 43241
	movk	x0, 0x17c0, lsl 16
	movk	x0, 0x3f57, lsl 32
	movk	x0, 0xa8e8, lsl 48
	mul	x2, x1, x0
	smulh	x0, x1, x0
	mov	x20, x2
	mov	x21, x0
	mov	x0, x21
	add	x0, x1, x0
	asr	x2, x0, 6
	asr	x0, x1, 63
	sub	x2, x2, x0
	mov	x0, x2
	lsl	x0, x0, 1
	add	x0, x0, x2
	lsl	x0, x0, 5
	add	x0, x0, x2
	sub	x2, x1, x0
	cmp	x2, 3
	bne	L11
	ldrsw	x0, [x29, 52]
	ldr	x1, [x29, 40]
	add	x0, x1, x0
	bl	_dis_cagri
L11:
	ldr	w0, [x29, 52]
	add	w0, w0, 1
	str	w0, [x29, 52]
L10:
	ldrsw	x0, [x29, 52]
	ldr	x1, [x29, 40]
	add	x0, x1, x0
	ldrsb	w0, [x0]
	cmp	w0, 0
	bne	L12
	ldr	x0, [x29, 56]
	cmp	x0, 42
	bne	L13
	adrp	x0, ___stderrp@GOTPAGE
	ldr	x0, [x0, ___stderrp@GOTPAGEOFF]
	ldr	x2, [x0]
	ldr	x0, [x29, 40]
	str	x0, [sp]
	adrp	x0, l.str.0@PAGE
	add	x1, x0, l.str.0@PAGEOFF;
	mov	x0, x2
	bl	_fprintf
	bl	_abort
L13:
	ldr	x0, [x29, 56]
L9:
	ldp	x29, x30, [sp, 16]
	ldp	x20, x21, [sp, 32]
	add	sp, sp, 80
LCFI8:
	ret
LFE6:
	.align	2
	.globl _ikiz_a
_ikiz_a:
LFB7:
	sub	sp, sp, #16
LCFI9:
	str	x0, [sp, 8]
	ldr	x1, [sp, 8]
	mov	x0, x1
	lsl	x0, x0, 3
	sub	x0, x0, x1
	add	x0, x0, 13
	add	sp, sp, 16
LCFI10:
	ret
LFE7:
	.align	2
	.globl _ikiz_b
_ikiz_b:
LFB8:
	sub	sp, sp, #16
LCFI11:
	str	x0, [sp, 8]
	ldr	x1, [sp, 8]
	mov	x0, x1
	lsl	x0, x0, 3
	sub	x0, x0, x1
	add	x0, x0, 13
	add	sp, sp, 16
LCFI12:
	ret
LFE8:
	.align	2
_ikiz_c:
LFB9:
	sub	sp, sp, #16
LCFI13:
	str	x0, [sp, 8]
	ldr	x1, [sp, 8]
	mov	x0, x1
	lsl	x0, x0, 2
	add	x0, x0, x1
	add	x0, x0, 11
	add	sp, sp, 16
LCFI14:
	ret
LFE9:
	.align	2
_ikiz_d:
LFB10:
	sub	sp, sp, #16
LCFI15:
	str	x0, [sp, 8]
	ldr	x1, [sp, 8]
	mov	x0, x1
	lsl	x0, x0, 2
	add	x0, x0, x1
	add	x0, x0, 11
	add	sp, sp, 16
LCFI16:
	ret
LFE10:
	.globl _adres_al
	.data
	.align	3
_adres_al:
	.quad	_ikiz_a
	.globl _adres_al2
	.align	3
_adres_al2:
	.quad	_ikiz_b
	.text
	.align	2
	.globl _kullan
_kullan:
LFB11:
	stp	x29, x30, [sp, -64]!
LCFI17:
	mov	x29, sp
LCFI18:
	str	x19, [sp, 16]
LCFI19:
	str	x0, [x29, 56]
	str	x1, [x29, 48]
	str	x2, [x29, 40]
	mov	w1, 3
	ldr	x0, [x29, 56]
	bl	_olcekle
	mov	x19, x0
	ldr	x0, [x29, 56]
	add	x0, x0, 1
	mov	w1, 3
	bl	_olcekle
	add	x19, x19, x0
	mov	w1, 0
	ldr	x0, [x29, 40]
	bl	_alan_oku
	add	x19, x19, x0
	ldr	x0, [x29, 48]
	bl	_bol
	add	x19, x19, x0
	ldr	x0, [x29, 48]
	add	x0, x0, 1
	bl	_bol
	add	x19, x19, x0
	ldr	x0, [x29, 56]
	bl	_ikiz_c
	add	x19, x19, x0
	ldr	x0, [x29, 56]
	add	x0, x0, 2
	bl	_ikiz_d
	add	x0, x19, x0
	ldr	x19, [sp, 16]
	ldp	x29, x30, [sp], 64
LCFI20:
	ret
LFE11:
	.section __TEXT,__eh_frame,coalesced,no_toc+strip_static_syms+live_support
EH_frame1:
	.set L$set$0,LECIE1-LSCIE1
	.long L$set$0
LSCIE1:
	.long	0
	.byte	0x3
	.ascii "zR\0"
	.uleb128 0x1
	.sleb128 -8
	.uleb128 0x1e
	.uleb128 0x1
	.byte	0x10
	.byte	0xc
	.uleb128 0x1f
	.uleb128 0
	.align	3
LECIE1:
LSFDE1:
	.set L$set$1,LEFDE1-LASFDE1
	.long L$set$1
LASFDE1:
	.long	LASFDE1-EH_frame1
	.quad	LFB4-.
	.set L$set$2,LFE4-LFB4
	.quad L$set$2
	.uleb128 0
	.byte	0x4
	.set L$set$3,LCFI0-LFB4
	.long L$set$3
	.byte	0xe
	.uleb128 0x20
	.byte	0x4
	.set L$set$4,LCFI1-LCFI0
	.long L$set$4
	.byte	0xe
	.uleb128 0
	.align	3
LEFDE1:
LSFDE3:
	.set L$set$5,LEFDE3-LASFDE3
	.long L$set$5
LASFDE3:
	.long	LASFDE3-EH_frame1
	.quad	LFB5-.
	.set L$set$6,LFE5-LFB5
	.quad L$set$6
	.uleb128 0
	.byte	0x4
	.set L$set$7,LCFI2-LFB5
	.long L$set$7
	.byte	0xe
	.uleb128 0x10
	.byte	0x4
	.set L$set$8,LCFI3-LCFI2
	.long L$set$8
	.byte	0xe
	.uleb128 0
	.align	3
LEFDE3:
LSFDE5:
	.set L$set$9,LEFDE5-LASFDE5
	.long L$set$9
LASFDE5:
	.long	LASFDE5-EH_frame1
	.quad	LFB6-.
	.set L$set$10,LFE6-LFB6
	.quad L$set$10
	.uleb128 0
	.byte	0x4
	.set L$set$11,LCFI4-LFB6
	.long L$set$11
	.byte	0xe
	.uleb128 0x50
	.byte	0x4
	.set L$set$12,LCFI5-LCFI4
	.long L$set$12
	.byte	0x9d
	.uleb128 0x8
	.byte	0x9e
	.uleb128 0x7
	.byte	0x4
	.set L$set$13,LCFI6-LCFI5
	.long L$set$13
	.byte	0xc
	.uleb128 0x1d
	.uleb128 0x40
	.byte	0x4
	.set L$set$14,LCFI7-LCFI6
	.long L$set$14
	.byte	0x94
	.uleb128 0x6
	.byte	0x95
	.uleb128 0x5
	.byte	0x4
	.set L$set$15,LCFI8-LCFI7
	.long L$set$15
	.byte	0xd4
	.byte	0xd5
	.byte	0xdd
	.byte	0xde
	.byte	0xc
	.uleb128 0x1f
	.uleb128 0
	.align	3
LEFDE5:
LSFDE7:
	.set L$set$16,LEFDE7-LASFDE7
	.long L$set$16
LASFDE7:
	.long	LASFDE7-EH_frame1
	.quad	LFB7-.
	.set L$set$17,LFE7-LFB7
	.quad L$set$17
	.uleb128 0
	.byte	0x4
	.set L$set$18,LCFI9-LFB7
	.long L$set$18
	.byte	0xe
	.uleb128 0x10
	.byte	0x4
	.set L$set$19,LCFI10-LCFI9
	.long L$set$19
	.byte	0xe
	.uleb128 0
	.align	3
LEFDE7:
LSFDE9:
	.set L$set$20,LEFDE9-LASFDE9
	.long L$set$20
LASFDE9:
	.long	LASFDE9-EH_frame1
	.quad	LFB8-.
	.set L$set$21,LFE8-LFB8
	.quad L$set$21
	.uleb128 0
	.byte	0x4
	.set L$set$22,LCFI11-LFB8
	.long L$set$22
	.byte	0xe
	.uleb128 0x10
	.byte	0x4
	.set L$set$23,LCFI12-LCFI11
	.long L$set$23
	.byte	0xe
	.uleb128 0
	.align	3
LEFDE9:
LSFDE11:
	.set L$set$24,LEFDE11-LASFDE11
	.long L$set$24
LASFDE11:
	.long	LASFDE11-EH_frame1
	.quad	LFB9-.
	.set L$set$25,LFE9-LFB9
	.quad L$set$25
	.uleb128 0
	.byte	0x4
	.set L$set$26,LCFI13-LFB9
	.long L$set$26
	.byte	0xe
	.uleb128 0x10
	.byte	0x4
	.set L$set$27,LCFI14-LCFI13
	.long L$set$27
	.byte	0xe
	.uleb128 0
	.align	3
LEFDE11:
LSFDE13:
	.set L$set$28,LEFDE13-LASFDE13
	.long L$set$28
LASFDE13:
	.long	LASFDE13-EH_frame1
	.quad	LFB10-.
	.set L$set$29,LFE10-LFB10
	.quad L$set$29
	.uleb128 0
	.byte	0x4
	.set L$set$30,LCFI15-LFB10
	.long L$set$30
	.byte	0xe
	.uleb128 0x10
	.byte	0x4
	.set L$set$31,LCFI16-LCFI15
	.long L$set$31
	.byte	0xe
	.uleb128 0
	.align	3
LEFDE13:
LSFDE15:
	.set L$set$32,LEFDE15-LASFDE15
	.long L$set$32
LASFDE15:
	.long	LASFDE15-EH_frame1
	.quad	LFB11-.
	.set L$set$33,LFE11-LFB11
	.quad L$set$33
	.uleb128 0
	.byte	0x4
	.set L$set$34,LCFI17-LFB11
	.long L$set$34
	.byte	0xe
	.uleb128 0x40
	.byte	0x9d
	.uleb128 0x8
	.byte	0x9e
	.uleb128 0x7
	.byte	0x4
	.set L$set$35,LCFI18-LCFI17
	.long L$set$35
	.byte	0xd
	.uleb128 0x1d
	.byte	0x4
	.set L$set$36,LCFI19-LCFI18
	.long L$set$36
	.byte	0x93
	.uleb128 0x6
	.byte	0x4
	.set L$set$37,LCFI20-LCFI19
	.long L$set$37
	.byte	0xde
	.byte	0xdd
	.byte	0xd3
	.byte	0xc
	.uleb128 0x1f
	.uleb128 0
	.align	3
LEFDE15:
	.ident	"GCC: (Homebrew GCC 16.2.0) 16.2.0"
	.subsections_via_symbols
