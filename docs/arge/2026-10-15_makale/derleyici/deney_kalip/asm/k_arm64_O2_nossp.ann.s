
bin/k_arm64_O2_nossp:	file format mach-o arm64

Disassembly of section __TEXT,__text:

0000000100000548 <_sw_dense>:
100000548:     	cmp	w0, #0x7
10000054c:     	b.hi	0x100000560 <_sw_dense+0x18>
100000550:     	adrp	x8, 0x100001000 <_main+0xd0>
100000554:     	add	x8, x8, #0x838
100000558:     	ldr	w0, [x8, w0, uxtw #2]
10000055c:     	ret
100000560:     	mov	w0, #-0x1               ; =-1
100000564:     	ret

0000000100000568 <_sw_sparse>:
100000568:     	mov	w8, #0x1387             ; =4999
10000056c:     	cmp	w0, w8
100000570:     	b.le	0x1000005a4 <_sw_sparse+0x3c>
100000574:     	mov	w8, #0x2fd0             ; =12240
100000578:     	movk	w8, #0x1, lsl #16
10000057c:     	cmp	w0, w8
100000580:     	b.gt	0x1000005c4 <_sw_sparse+0x5c>
100000584:     	mov	w8, #0x1388             ; =5000
100000588:     	cmp	w0, w8
10000058c:     	b.eq	0x1000005fc <_sw_sparse+0x94>
100000590:     	mov	w8, #0x4e20             ; =20000
100000594:     	cmp	w0, w8
100000598:     	b.ne	0x1000005f4 <_sw_sparse+0x8c>
10000059c:     	mov	w0, #0x5                ; =5
1000005a0:     	ret
1000005a4:     	cmp	w0, #0x3
1000005a8:     	b.eq	0x1000005ec <_sw_sparse+0x84>
1000005ac:     	cmp	w0, #0x64
1000005b0:     	b.eq	0x10000060c <_sw_sparse+0xa4>
1000005b4:     	cmp	w0, #0x3e8
1000005b8:     	b.ne	0x1000005f4 <_sw_sparse+0x8c>
1000005bc:     	mov	w0, #0x3                ; =3
1000005c0:     	ret
1000005c4:     	mov	w8, #0x2fd1             ; =12241
1000005c8:     	movk	w8, #0x1, lsl #16
1000005cc:     	cmp	w0, w8
1000005d0:     	b.eq	0x100000604 <_sw_sparse+0x9c>
1000005d4:     	mov	w8, #0xe240             ; =57920
1000005d8:     	movk	w8, #0x1, lsl #16
1000005dc:     	cmp	w0, w8
1000005e0:     	b.ne	0x1000005f4 <_sw_sparse+0x8c>
1000005e4:     	mov	w0, #0x7                ; =7
1000005e8:     	ret
1000005ec:     	mov	w0, #0x1                ; =1
1000005f0:     	ret
1000005f4:     	mov	w0, #0x0                ; =0
1000005f8:     	ret
1000005fc:     	mov	w0, #0x4                ; =4
100000600:     	ret
100000604:     	mov	w0, #0x6                ; =6
100000608:     	ret
10000060c:     	mov	w0, #0x2                ; =2
100000610:     	ret

0000000100000614 <_sw_bittest>:
100000614:     	cmp	w0, #0x3b
100000618:     	b.hi	0x100000644 <_sw_bittest+0x30>
10000061c:     	mov	w8, w0
100000620:     	mov	w9, #0x1                ; =1
100000624:     	lsl	x8, x9, x8
100000628:     	mov	x9, #0x3e00             ; =15872
10000062c:     	movk	x9, #0x1001, lsl #32
100000630:     	movk	x9, #0x800, lsl #48
100000634:     	tst	x8, x9
100000638:     	b.eq	0x100000644 <_sw_bittest+0x30>
10000063c:     	mov	w0, #0x1                ; =1
100000640:     	ret
100000644:     	mov	w0, #0x0                ; =0
100000648:     	ret

000000010000064c <_udiv7>:
10000064c:     	mov	w8, #0x4925             ; =18725
100000650:     	movk	w8, #0x2492, lsl #16
100000654:     	umull	x8, w0, w8
100000658:     	lsr	x8, x8, #32
10000065c:     	sub	w9, w0, w8
100000660:     	add	w8, w8, w9, lsr #1
100000664:     	lsr	w0, w8, #2
100000668:     	ret

000000010000066c <_sdiv7>:
10000066c:     	mov	w8, #0x2493             ; =9363
100000670:     	movk	w8, #0x9249, lsl #16
100000674:     	smull	x8, w0, w8
100000678:     	lsr	x8, x8, #32
10000067c:     	add	w8, w8, w0
100000680:     	asr	w9, w8, #2
100000684:     	add	w0, w9, w8, lsr #31
100000688:     	ret

000000010000068c <_umod10>:
10000068c:     	mov	w8, #0xcccd             ; =52429
100000690:     	movk	w8, #0xcccc, lsl #16
100000694:     	umull	x8, w0, w8
100000698:     	lsr	x8, x8, #35
10000069c:     	mov	w9, #0xa                ; =10
1000006a0:     	msub	w0, w8, w9, w0
1000006a4:     	ret

00000001000006a8 <_sdiv16>:
1000006a8:     	add	w8, w0, #0xf
1000006ac:     	cmp	w0, #0x0
1000006b0:     	csel	w8, w8, w0, lt
1000006b4:     	asr	w0, w8, #4
1000006b8:     	ret

00000001000006bc <_udiv1000_64>:
1000006bc:     	lsr	x8, x0, #3
1000006c0:     	mov	x9, #0xf7cf             ; =63439
1000006c4:     	movk	x9, #0xe353, lsl #16
1000006c8:     	movk	x9, #0x9ba5, lsl #32
1000006cc:     	movk	x9, #0x20c4, lsl #48
1000006d0:     	umulh	x8, x8, x9
1000006d4:     	lsr	x0, x8, #4
1000006d8:     	ret

00000001000006dc <_sel_max>:
1000006dc:     	cmp	w0, w1
1000006e0:     	csel	w0, w0, w1, gt
1000006e4:     	ret

00000001000006e8 <_sel_abs>:
1000006e8:     	cmp	w0, #0x0
1000006ec:     	cneg	w0, w0, mi
1000006f0:     	ret

00000001000006f4 <_sel_clamp>:
1000006f4:     	cmp	w0, w2
1000006f8:     	csel	w8, w0, w2, lt
1000006fc:     	cmp	w0, w1
100000700:     	csel	w0, w1, w8, lt
100000704:     	ret

0000000100000708 <_popcount_loop>:
100000708:     	fmov	s0, w0
10000070c:     	cnt.8b	v0, v0
100000710:     	addv.8b	b0, v0
100000714:     	fmov	w0, s0
100000718:     	ret

000000010000071c <_bswap32_manual>:
10000071c:     	rev	w0, w0
100000720:     	ret

0000000100000724 <_rotl32>:
100000724:     	neg	w8, w1
100000728:     	ror	w0, w0, w8
10000072c:     	ret

0000000100000730 <_is_pow2>:
100000730:     	sub	w8, w0, #0x1
100000734:     	tst	w0, w8
100000738:     	cset	w8, eq
10000073c:     	cmp	w0, #0x0
100000740:     	csel	w0, wzr, w8, eq
100000744:     	ret

0000000100000748 <_copy16>:
100000748:     	ldr	q0, [x1]
10000074c:     	str	q0, [x0]
100000750:     	ret

0000000100000754 <_zero64>:
100000754:     	movi.2d	v0, #0000000000000000
100000758:     	stp	q0, q0, [x0, #0x20]
10000075c:     	stp	q0, q0, [x0]
100000760:     	ret

0000000100000764 <_zero_n>:
100000764:     	b	0x100001530 <_bzero@stub>

0000000100000768 <_strlen_const>:
100000768:     	mov	w0, #0x7                ; =7
10000076c:     	ret

0000000100000770 <_strcmp_const>:
100000770:     	stp	x29, x30, [sp, #-0x10]!
100000774:     	mov	x29, sp
100000778:     	adrp	x1, 0x100001000 <_main+0xd0>
10000077c:     	add	x1, x1, #0x858
100000780:     	bl	0x1000015a8 <_strcmp@stub>
100000784:     	cmp	w0, #0x0
100000788:     	cset	w0, eq
10000078c:     	ldp	x29, x30, [sp], #0x10
100000790:     	ret

0000000100000794 <_strncmp_const>:
100000794:     	stp	x29, x30, [sp, #-0x10]!
100000798:     	mov	x29, sp
10000079c:     	adrp	x1, 0x100001000 <_main+0xd0>
1000007a0:     	add	x1, x1, #0x85c
1000007a4:     	mov	w2, #0x7                ; =7
1000007a8:     	bl	0x1000015cc <_strncmp@stub>
1000007ac:     	cmp	w0, #0x0
1000007b0:     	cset	w0, eq
1000007b4:     	ldp	x29, x30, [sp], #0x10
1000007b8:     	ret

00000001000007bc <_loop_zero>:
1000007bc:     	cmp	w1, #0x1
1000007c0:     	b.lt	0x1000007cc <_loop_zero+0x10>
1000007c4:     	ubfiz	x1, x1, #2, #32
1000007c8:     	b	0x100001530 <_bzero@stub>
1000007cc:     	ret

00000001000007d0 <_loop_copy>:
1000007d0:     	cmp	w2, #0x1
1000007d4:     	b.lt	0x1000007e0 <_loop_copy+0x10>
1000007d8:     	mov	w2, w2
1000007dc:     	b	0x10000156c <_memcpy@stub>
1000007e0:     	ret

00000001000007e4 <_loop_strlen>:
1000007e4:     	b	0x1000015c0 <_strlen@stub>

00000001000007e8 <_make_big>:
1000007e8:     	str	x0, [x8]
1000007ec:     	dup.2d	v0, x0
1000007f0:     	adrp	x9, 0x100001000 <_main+0xd0>
1000007f4:     	ldr	q1, [x9, #0x5e0]
1000007f8:     	add.2d	v1, v0, v1
1000007fc:     	stur	q1, [x8, #0x8]
100000800:     	adrp	x9, 0x100001000 <_main+0xd0>
100000804:     	ldr	q1, [x9, #0x5f0]
100000808:     	add.2d	v1, v0, v1
10000080c:     	stur	q1, [x8, #0x18]
100000810:     	adrp	x9, 0x100001000 <_main+0xd0>
100000814:     	ldr	q1, [x9, #0x600]
100000818:     	add.2d	v0, v0, v1
10000081c:     	stur	q0, [x8, #0x28]
100000820:     	add	x9, x0, #0x7
100000824:     	str	x9, [x8, #0x38]
100000828:     	ret

000000010000082c <_use_big>:
10000082c:     	sub	sp, sp, #0x50
100000830:     	stp	x29, x30, [sp, #0x40]
100000834:     	add	x29, sp, #0x40
100000838:     	mov	x8, sp
10000083c:     	bl	0x1000007e8 <_make_big>
100000840:     	ldr	x8, [sp, #0x18]
100000844:     	ldr	x9, [sp, #0x38]
100000848:     	add	x0, x9, x8
10000084c:     	ldp	x29, x30, [sp, #0x40]
100000850:     	add	sp, sp, #0x50
100000854:     	ret

0000000100000858 <_make_small>:
100000858:     	add	w8, w0, w0, lsl #1
10000085c:     	mov	w9, w0
100000860:     	orr	x0, x9, x8, lsl #32
100000864:     	ret

0000000100000868 <_sum_va>:
100000868:     	sub	sp, sp, #0x10
10000086c:     	add	x8, sp, #0x10
100000870:     	str	x8, [sp, #0x8]
100000874:     	cmp	w0, #0x1
100000878:     	b.lt	0x1000008a0 <_sum_va+0x38>
10000087c:     	mov	w8, #0x0                ; =0
100000880:     	ldr	x9, [sp, #0x8]
100000884:     	add	x10, x9, #0x8
100000888:     	str	x10, [sp, #0x8]
10000088c:     	ldr	w9, [x9]
100000890:     	add	w8, w9, w8
100000894:     	subs	w0, w0, #0x1
100000898:     	b.ne	0x100000880 <_sum_va+0x18>
10000089c:     	b	0x1000008a4 <_sum_va+0x3c>
1000008a0:     	mov	w8, #0x0                ; =0
1000008a4:     	mov	x0, x8
1000008a8:     	add	sp, sp, #0x10
1000008ac:     	ret

00000001000008b0 <_ssp_copy>:
1000008b0:     	sub	sp, sp, #0x50
1000008b4:     	stp	x29, x30, [sp, #0x40]
1000008b8:     	add	x29, sp, #0x40
1000008bc:     	mov	x1, x0
1000008c0:     	mov	x0, sp
1000008c4:     	mov	w2, #0x40               ; =64
1000008c8:     	bl	0x100001518 <___strcpy_chk@stub>
1000008cc:     	mov	x0, sp
1000008d0:     	bl	0x1000015c0 <_strlen@stub>
1000008d4:     	ldrsb	w8, [sp, #0x3]
1000008d8:     	add	w0, w8, w0
1000008dc:     	ldp	x29, x30, [sp, #0x40]
1000008e0:     	add	sp, sp, #0x50
1000008e4:     	ret

00000001000008e8 <_fortify_memcpy>:
1000008e8:     	sub	sp, sp, #0x40
1000008ec:     	stp	x20, x19, [sp, #0x20]
1000008f0:     	stp	x29, x30, [sp, #0x30]
1000008f4:     	add	x29, sp, #0x30
1000008f8:     	mov	x19, x0
1000008fc:     	mov	x0, sp
100000900:     	mov	w3, #0x20               ; =32
100000904:     	bl	0x10000150c <___memcpy_chk@stub>
100000908:     	ldp	q0, q1, [sp]
10000090c:     	stp	q0, q1, [x19]
100000910:     	ldp	x29, x30, [sp, #0x30]
100000914:     	ldp	x20, x19, [sp, #0x20]
100000918:     	add	sp, sp, #0x40
10000091c:     	ret

0000000100000920 <_fortify_snprintf>:
100000920:     	sub	sp, sp, #0x20
100000924:     	stp	x29, x30, [sp, #0x10]
100000928:     	add	x29, sp, #0x10
10000092c:     	str	x2, [sp]
100000930:     	adrp	x2, 0x100001000 <_main+0xd0>
100000934:     	add	x2, x2, #0x864
100000938:     	bl	0x10000159c <_snprintf@stub>
10000093c:     	ldp	x29, x30, [sp, #0x10]
100000940:     	add	sp, sp, #0x20
100000944:     	ret

0000000100000948 <_read_file_head>:
100000948:     	sub	sp, sp, #0x50
10000094c:     	stp	x24, x23, [sp, #0x10]
100000950:     	stp	x22, x21, [sp, #0x20]
100000954:     	stp	x20, x19, [sp, #0x30]
100000958:     	stp	x29, x30, [sp, #0x40]
10000095c:     	add	x29, sp, #0x40
100000960:     	mov	x23, x2
100000964:     	mov	x22, x1
100000968:     	mov	x20, x0
10000096c:     	mov	w1, #0x1000000          ; =16777216
100000970:     	bl	0x100001578 <_open@stub>
100000974:     	tbnz	w0, #0x1f, 0x1000009b8 <_read_file_head+0x70>
100000978:     	mov	x19, x0
10000097c:     	mov	x0, x23
100000980:     	bl	0x100001560 <_malloc@stub>
100000984:     	cbz	x0, 0x1000009ec <_read_file_head+0xa4>
100000988:     	mov	x21, x0
10000098c:     	mov	x0, x19
100000990:     	mov	x1, x21
100000994:     	mov	x2, x23
100000998:     	bl	0x100001590 <_read@stub>
10000099c:     	tbnz	x0, #0x3f, 0x1000009f4 <_read_file_head+0xac>
1000009a0:     	mov	x20, x0
1000009a4:     	mov	x0, x22
1000009a8:     	mov	x1, x21
1000009ac:     	mov	x2, x20
1000009b0:     	bl	0x10000156c <_memcpy@stub>
1000009b4:     	b	0x100000a04 <_read_file_head+0xbc>
1000009b8:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
1000009bc:     	ldr	x8, [x8, #0x10]
1000009c0:     	ldr	x19, [x8]
1000009c4:     	bl	0x100001500 <___error@stub>
1000009c8:     	ldr	w0, [x0]
1000009cc:     	bl	0x1000015b4 <_strerror@stub>
1000009d0:     	stp	x20, x0, [sp]
1000009d4:     	adrp	x1, 0x100001000 <_main+0xd0>
1000009d8:     	add	x1, x1, #0x86d
1000009dc:     	mov	x0, x19
1000009e0:     	bl	0x100001548 <_fprintf@stub>
1000009e4:     	mov	w20, #-0x1              ; =-1
1000009e8:     	b	0x100000a14 <_read_file_head+0xcc>
1000009ec:     	mov	w20, #-0x1              ; =-1
1000009f0:     	b	0x100000a0c <_read_file_head+0xc4>
1000009f4:     	bl	0x100001500 <___error@stub>
1000009f8:     	mov	w8, #0x5                ; =5
1000009fc:     	str	w8, [x0]
100000a00:     	mov	w20, #-0x1              ; =-1
100000a04:     	mov	x0, x21
100000a08:     	bl	0x100001554 <_free@stub>
100000a0c:     	mov	x0, x19
100000a10:     	bl	0x10000153c <_close@stub>
100000a14:     	mov	x0, x20
100000a18:     	ldp	x29, x30, [sp, #0x40]
100000a1c:     	ldp	x20, x19, [sp, #0x30]
100000a20:     	ldp	x22, x21, [sp, #0x20]
100000a24:     	ldp	x24, x23, [sp, #0x10]
100000a28:     	add	sp, sp, #0x50
100000a2c:     	ret

0000000100000a30 <_tail_target>:
100000a30:     	add	w8, w0, w0, lsl #1
100000a34:     	add	w0, w8, #0x1
100000a38:     	ret

0000000100000a3c <_tail_caller>:
100000a3c:     	add	w0, w0, #0x1
100000a40:     	b	0x100000a30 <_tail_target>

0000000100000a44 <_tail_ext>:
100000a44:     	add	x0, x0, #0x1
100000a48:     	b	0x100001524 <_atoi@stub>

0000000100000a4c <_vadd>:
100000a4c:     	cmp	w3, #0x1
100000a50:     	b.lt	0x100000b34 <_vadd+0xe8>
100000a54:     	mov	w8, w3
100000a58:     	cmp	w3, #0x3
100000a5c:     	b.hi	0x100000a68 <_vadd+0x1c>
100000a60:     	mov	x9, #0x0                ; =0
100000a64:     	b	0x100000b08 <_vadd+0xbc>
100000a68:     	cmp	w3, #0x10
100000a6c:     	b.hs	0x100000a78 <_vadd+0x2c>
100000a70:     	mov	x9, #0x0                ; =0
100000a74:     	b	0x100000acc <_vadd+0x80>
100000a78:     	and	x9, x8, #0x7ffffff0
100000a7c:     	add	x10, x1, #0x20
100000a80:     	add	x11, x2, #0x20
100000a84:     	add	x12, x0, #0x20
100000a88:     	mov	x13, x9
100000a8c:     	ldp	q0, q1, [x10, #-0x20]
100000a90:     	ldp	q2, q3, [x10], #0x40
100000a94:     	ldp	q4, q5, [x11, #-0x20]
100000a98:     	ldp	q6, q7, [x11], #0x40
100000a9c:     	add.4s	v0, v4, v0
100000aa0:     	add.4s	v1, v5, v1
100000aa4:     	add.4s	v2, v6, v2
100000aa8:     	add.4s	v3, v7, v3
100000aac:     	stp	q0, q1, [x12, #-0x20]
100000ab0:     	stp	q2, q3, [x12], #0x40
100000ab4:     	subs	x13, x13, #0x10
100000ab8:     	b.ne	0x100000a8c <_vadd+0x40>
100000abc:     	cmp	x9, x8
100000ac0:     	b.eq	0x100000b34 <_vadd+0xe8>
100000ac4:     	tst	x8, #0xc
100000ac8:     	b.eq	0x100000b08 <_vadd+0xbc>
100000acc:     	mov	x11, x9
100000ad0:     	and	x9, x8, #0x7ffffffc
100000ad4:     	sub	x10, x11, x9
100000ad8:     	lsl	x13, x11, #2
100000adc:     	add	x11, x0, x13
100000ae0:     	add	x12, x2, x13
100000ae4:     	add	x13, x1, x13
100000ae8:     	ldr	q0, [x13], #0x10
100000aec:     	ldr	q1, [x12], #0x10
100000af0:     	add.4s	v0, v1, v0
100000af4:     	str	q0, [x11], #0x10
100000af8:     	adds	x10, x10, #0x4
100000afc:     	b.ne	0x100000ae8 <_vadd+0x9c>
100000b00:     	cmp	x9, x8
100000b04:     	b.eq	0x100000b34 <_vadd+0xe8>
100000b08:     	lsl	x12, x9, #2
100000b0c:     	add	x10, x0, x12
100000b10:     	add	x11, x2, x12
100000b14:     	add	x12, x1, x12
100000b18:     	sub	x8, x8, x9
100000b1c:     	ldr	w9, [x12], #0x4
100000b20:     	ldr	w13, [x11], #0x4
100000b24:     	add	w9, w13, w9
100000b28:     	str	w9, [x10], #0x4
100000b2c:     	subs	x8, x8, #0x1
100000b30:     	b.ne	0x100000b1c <_vadd+0xd0>
100000b34:     	ret

0000000100000b38 <_vsum>:
100000b38:     	cmp	w1, #0x1
100000b3c:     	b.lt	0x100000b58 <_vsum+0x20>
100000b40:     	mov	w9, w1
100000b44:     	cmp	w1, #0x3
100000b48:     	b.hi	0x100000b64 <_vsum+0x2c>
100000b4c:     	mov	x10, #0x0               ; =0
100000b50:     	mov	w8, #0x0                ; =0
100000b54:     	b	0x100000c10 <_vsum+0xd8>
100000b58:     	mov	w8, #0x0                ; =0
100000b5c:     	mov	x0, x8
100000b60:     	ret
100000b64:     	cmp	w1, #0x10
100000b68:     	b.hs	0x100000b78 <_vsum+0x40>
100000b6c:     	mov	x10, #0x0               ; =0
100000b70:     	mov	w8, #0x0                ; =0
100000b74:     	b	0x100000bd8 <_vsum+0xa0>
100000b78:     	and	x10, x9, #0x7ffffff0
100000b7c:     	add	x8, x0, #0x20
100000b80:     	movi.2d	v0, #0000000000000000
100000b84:     	mov	x11, x10
100000b88:     	movi.2d	v1, #0000000000000000
100000b8c:     	movi.2d	v2, #0000000000000000
100000b90:     	movi.2d	v3, #0000000000000000
100000b94:     	ldp	q4, q5, [x8, #-0x20]
100000b98:     	ldp	q6, q7, [x8], #0x40
100000b9c:     	add.4s	v0, v4, v0
100000ba0:     	add.4s	v1, v5, v1
100000ba4:     	add.4s	v2, v6, v2
100000ba8:     	add.4s	v3, v7, v3
100000bac:     	subs	x11, x11, #0x10
100000bb0:     	b.ne	0x100000b94 <_vsum+0x5c>
100000bb4:     	add.4s	v0, v1, v0
100000bb8:     	add.4s	v0, v2, v0
100000bbc:     	add.4s	v0, v3, v0
100000bc0:     	addv.4s	s0, v0
100000bc4:     	fmov	w8, s0
100000bc8:     	cmp	x10, x9
100000bcc:     	b.eq	0x100000c28 <_vsum+0xf0>
100000bd0:     	tst	x9, #0xc
100000bd4:     	b.eq	0x100000c10 <_vsum+0xd8>
100000bd8:     	mov	x11, x10
100000bdc:     	and	x10, x9, #0x7ffffffc
100000be0:     	movi.2d	v0, #0000000000000000
100000be4:     	mov.s	v0[0], w8
100000be8:     	sub	x8, x11, x10
100000bec:     	add	x11, x0, x11, lsl #2
100000bf0:     	ldr	q1, [x11], #0x10
100000bf4:     	add.4s	v0, v1, v0
100000bf8:     	adds	x8, x8, #0x4
100000bfc:     	b.ne	0x100000bf0 <_vsum+0xb8>
100000c00:     	addv.4s	s0, v0
100000c04:     	fmov	w8, s0
100000c08:     	cmp	x10, x9
100000c0c:     	b.eq	0x100000c28 <_vsum+0xf0>
100000c10:     	add	x11, x0, x10, lsl #2
100000c14:     	sub	x9, x9, x10
100000c18:     	ldr	w10, [x11], #0x4
100000c1c:     	add	w8, w10, w8
100000c20:     	subs	x9, x9, #0x1
100000c24:     	b.ne	0x100000c18 <_vsum+0xe0>
100000c28:     	mov	x0, x8
100000c2c:     	ret

0000000100000c30 <_vdot>:
100000c30:     	cmp	w2, #0x1
100000c34:     	b.lt	0x100000c50 <_vdot+0x20>
100000c38:     	mov	w8, w2
100000c3c:     	cmp	w2, #0x3
100000c40:     	b.hi	0x100000c58 <_vdot+0x28>
100000c44:     	mov	x9, #0x0                ; =0
100000c48:     	movi.2d	v0, #0000000000000000
100000c4c:     	b	0x100000d78 <_vdot+0x148>
100000c50:     	movi.2d	v0, #0000000000000000
100000c54:     	ret
100000c58:     	cmp	w2, #0x10
100000c5c:     	b.hs	0x100000c6c <_vdot+0x3c>
100000c60:     	mov	x9, #0x0                ; =0
100000c64:     	movi.2d	v0, #0000000000000000
100000c68:     	b	0x100000d28 <_vdot+0xf8>
100000c6c:     	and	x9, x8, #0x7ffffff0
100000c70:     	add	x10, x0, #0x20
100000c74:     	add	x11, x1, #0x20
100000c78:     	movi.2d	v0, #0000000000000000
100000c7c:     	mov	x12, x9
100000c80:     	ldp	q1, q2, [x10, #-0x20]
100000c84:     	ldp	q3, q4, [x10], #0x40
100000c88:     	ldp	q5, q6, [x11, #-0x20]
100000c8c:     	ldp	q7, q16, [x11], #0x40
100000c90:     	fmul.4s	v1, v1, v5
100000c94:     	mov	s5, v1[3]
100000c98:     	mov	s17, v1[2]
100000c9c:     	mov	s18, v1[1]
100000ca0:     	fmul.4s	v2, v2, v6
100000ca4:     	mov	s6, v2[3]
100000ca8:     	mov	s19, v2[2]
100000cac:     	mov	s20, v2[1]
100000cb0:     	fmul.4s	v3, v3, v7
100000cb4:     	mov	s7, v3[3]
100000cb8:     	mov	s21, v3[2]
100000cbc:     	mov	s22, v3[1]
100000cc0:     	fmul.4s	v4, v4, v16
100000cc4:     	mov	s16, v4[3]
100000cc8:     	mov	s23, v4[2]
100000ccc:     	mov	s24, v4[1]
100000cd0:     	fadd	s0, s0, s1
100000cd4:     	fadd	s0, s0, s18
100000cd8:     	fadd	s0, s0, s17
100000cdc:     	fadd	s0, s0, s5
100000ce0:     	fadd	s0, s0, s2
100000ce4:     	fadd	s0, s0, s20
100000ce8:     	fadd	s0, s0, s19
100000cec:     	fadd	s0, s0, s6
100000cf0:     	fadd	s0, s0, s3
100000cf4:     	fadd	s0, s0, s22
100000cf8:     	fadd	s0, s0, s21
100000cfc:     	fadd	s0, s0, s7
100000d00:     	fadd	s0, s0, s4
100000d04:     	fadd	s0, s0, s24
100000d08:     	fadd	s0, s0, s23
100000d0c:     	fadd	s0, s0, s16
100000d10:     	subs	x12, x12, #0x10
100000d14:     	b.ne	0x100000c80 <_vdot+0x50>
100000d18:     	cmp	x9, x8
100000d1c:     	b.eq	0x100000d9c <_vdot+0x16c>
100000d20:     	tst	x8, #0xc
100000d24:     	b.eq	0x100000d78 <_vdot+0x148>
100000d28:     	mov	x11, x9
100000d2c:     	and	x9, x8, #0x7ffffffc
100000d30:     	sub	x10, x11, x9
100000d34:     	lsl	x12, x11, #2
100000d38:     	add	x11, x1, x12
100000d3c:     	add	x12, x0, x12
100000d40:     	ldr	q1, [x12], #0x10
100000d44:     	ldr	q2, [x11], #0x10
100000d48:     	fmul.4s	v1, v1, v2
100000d4c:     	mov	s2, v1[3]
100000d50:     	mov	s3, v1[2]
100000d54:     	mov	s4, v1[1]
100000d58:     	fadd	s0, s0, s1
100000d5c:     	fadd	s0, s0, s4
100000d60:     	fadd	s0, s0, s3
100000d64:     	fadd	s0, s0, s2
100000d68:     	adds	x10, x10, #0x4
100000d6c:     	b.ne	0x100000d40 <_vdot+0x110>
100000d70:     	cmp	x9, x8
100000d74:     	b.eq	0x100000d9c <_vdot+0x16c>
100000d78:     	lsl	x11, x9, #2
100000d7c:     	add	x10, x1, x11
100000d80:     	add	x11, x0, x11
100000d84:     	sub	x8, x8, x9
100000d88:     	ldr	s1, [x11], #0x4
100000d8c:     	ldr	s2, [x10], #0x4
100000d90:     	fmadd	s0, s1, s2, s0
100000d94:     	subs	x8, x8, #0x1
100000d98:     	b.ne	0x100000d88 <_vdot+0x158>
100000d9c:     	ret

0000000100000da0 <_md5_init>:
100000da0:     	adrp	x8, 0x100001000 <_main+0xd0>
100000da4:     	ldr	q0, [x8, #0x610]
100000da8:     	str	q0, [x0]
100000dac:     	ret

0000000100000db0 <_crc32_make_table>:
100000db0:     	mov	x8, #0x0                ; =0
100000db4:     	adrp	x9, 0x100001000 <_main+0xd0>
100000db8:     	ldr	q0, [x9, #0x620]
100000dbc:     	movi.4s	v1, #0x1
100000dc0:     	mov	w9, #0x8320             ; =33568
100000dc4:     	movk	w9, #0xedb8, lsl #16
100000dc8:     	dup.4s	v2, w9
100000dcc:     	adrp	x9, 0x100008000 <_crc_table>
100000dd0:     	add	x9, x9, #0x0
100000dd4:     	movi.4s	v3, #0x4
100000dd8:     	and.16b	v4, v0, v1
100000ddc:     	ushr.4s	v5, v0, #0x1
100000de0:     	cmeq.4s	v4, v4, #0
100000de4:     	eor.16b	v6, v5, v2
100000de8:     	bsl.16b	v4, v5, v6
100000dec:     	and.16b	v5, v4, v1
100000df0:     	cmeq.4s	v5, v5, #0
100000df4:     	ushr.4s	v4, v4, #0x1
100000df8:     	eor.16b	v6, v4, v2
100000dfc:     	bif.16b	v4, v6, v5
100000e00:     	and.16b	v5, v4, v1
100000e04:     	cmeq.4s	v5, v5, #0
100000e08:     	ushr.4s	v4, v4, #0x1
100000e0c:     	eor.16b	v6, v4, v2
100000e10:     	bif.16b	v4, v6, v5
100000e14:     	and.16b	v5, v4, v1
100000e18:     	cmeq.4s	v5, v5, #0
100000e1c:     	ushr.4s	v4, v4, #0x1
100000e20:     	eor.16b	v6, v4, v2
100000e24:     	bif.16b	v4, v6, v5
100000e28:     	and.16b	v5, v4, v1
100000e2c:     	cmeq.4s	v5, v5, #0
100000e30:     	ushr.4s	v4, v4, #0x1
100000e34:     	eor.16b	v6, v4, v2
100000e38:     	bif.16b	v4, v6, v5
100000e3c:     	and.16b	v5, v4, v1
100000e40:     	cmeq.4s	v5, v5, #0
100000e44:     	ushr.4s	v4, v4, #0x1
100000e48:     	eor.16b	v6, v4, v2
100000e4c:     	bif.16b	v4, v6, v5
100000e50:     	and.16b	v5, v4, v1
100000e54:     	ushr.4s	v4, v4, #0x1
100000e58:     	cmeq.4s	v5, v5, #0
100000e5c:     	eor.16b	v6, v4, v2
100000e60:     	bif.16b	v4, v6, v5
100000e64:     	and.16b	v5, v4, v1
100000e68:     	cmeq.4s	v5, v5, #0
100000e6c:     	ushr.4s	v4, v4, #0x1
100000e70:     	eor.16b	v6, v4, v2
100000e74:     	bif.16b	v4, v6, v5
100000e78:     	str	q4, [x9, x8]
100000e7c:     	add.4s	v0, v0, v3
100000e80:     	add	x8, x8, #0x10
100000e84:     	cmp	x8, #0x400
100000e88:     	b.ne	0x100000dd8 <_crc32_make_table+0x28>
100000e8c:     	ret

0000000100000e90 <_crc32_buf>:
100000e90:     	cbz	x1, 0x100000ec4 <_crc32_buf+0x34>
100000e94:     	mov	w8, #-0x1               ; =-1
100000e98:     	adrp	x9, 0x100008000 <_crc_table>
100000e9c:     	add	x9, x9, #0x0
100000ea0:     	ldrb	w10, [x0], #0x1
100000ea4:     	eor	w10, w10, w8
100000ea8:     	and	x10, x10, #0xff
100000eac:     	ldr	w10, [x9, x10, lsl #2]
100000eb0:     	eor	w8, w10, w8, lsr #8
100000eb4:     	subs	x1, x1, #0x1
100000eb8:     	b.ne	0x100000ea0 <_crc32_buf+0x10>
100000ebc:     	mvn	w0, w8
100000ec0:     	ret
100000ec4:     	mov	w0, #0x0                ; =0
100000ec8:     	ret

0000000100000ecc <_tea_encrypt>:
100000ecc:     	mov	w8, #0x79b9             ; =31161
100000ed0:     	movk	w8, #0x9e37, lsl #16
100000ed4:     	ldp	w9, w10, [x0]
100000ed8:     	ldp	w11, w12, [x1]
100000edc:     	mov	w13, #0x20              ; =32
100000ee0:     	mov	w14, #0x79b9            ; =31161
100000ee4:     	movk	w14, #0x9e37, lsl #16
100000ee8:     	ldp	w15, w16, [x1, #0x8]
100000eec:     	add	w17, w11, w10, lsl #4
100000ef0:     	add	w1, w10, w14
100000ef4:     	eor	w17, w17, w1
100000ef8:     	add	w1, w12, w10, lsr #5
100000efc:     	eor	w17, w17, w1
100000f00:     	add	w9, w17, w9
100000f04:     	add	w17, w14, w9
100000f08:     	add	w1, w15, w9, lsl #4
100000f0c:     	eor	w17, w1, w17
100000f10:     	add	w1, w16, w9, lsr #5
100000f14:     	eor	w17, w17, w1
100000f18:     	add	w10, w17, w10
100000f1c:     	add	w14, w14, w8
100000f20:     	subs	w13, w13, #0x1
100000f24:     	b.ne	0x100000eec <_tea_encrypt+0x20>
100000f28:     	stp	w9, w10, [x0]
100000f2c:     	ret

0000000100000f30 <_main>:
100000f30:     	stp	x28, x27, [sp, #-0x60]!
100000f34:     	stp	x26, x25, [sp, #0x10]
100000f38:     	stp	x24, x23, [sp, #0x20]
100000f3c:     	stp	x22, x21, [sp, #0x30]
100000f40:     	stp	x20, x19, [sp, #0x40]
100000f44:     	stp	x29, x30, [sp, #0x50]
100000f48:     	add	x29, sp, #0x50
100000f4c:     	sub	sp, sp, #0x640
100000f50:     	mov	x21, x1
100000f54:     	mov	x22, x0
100000f58:     	add	x24, sp, #0xb0
100000f5c:     	mov	w19, #0x3               ; =3
100000f60:     	cmp	w0, #0x2
100000f64:     	b.lt	0x100000f88 <_main+0x58>
100000f68:     	ldr	x0, [x21, #0x8]
100000f6c:     	bl	0x100001524 <_atoi@stub>
100000f70:     	mov	x23, x0
100000f74:     	cmp	w22, #0x2
100000f78:     	b.ne	0x100000f98 <_main+0x68>
100000f7c:     	adrp	x25, 0x100001000 <_main+0xd0>
100000f80:     	add	x25, x25, #0x858
100000f84:     	b	0x100000f9c <_main+0x6c>
100000f88:     	adrp	x25, 0x100001000 <_main+0xd0>
100000f8c:     	add	x25, x25, #0x858
100000f90:     	mov	w23, #0x3               ; =3
100000f94:     	b	0x100000f9c <_main+0x6c>
100000f98:     	ldr	x25, [x21, #0x10]
100000f9c:     	scvtf	s0, w23
100000fa0:     	dup.4s	v0, v0[0]
100000fa4:     	sxtw	x20, w23
100000fa8:     	dup.4s	v3, w23
100000fac:     	adrp	x8, 0x100001000 <_main+0xd0>
100000fb0:     	ldr	q1, [x8, #0x620]
100000fb4:     	eor.16b	v2, v3, v1
100000fb8:     	adrp	x8, 0x100001000 <_main+0xd0>
100000fbc:     	ldr	q4, [x8, #0x630]
100000fc0:     	eor.16b	v5, v3, v4
100000fc4:     	adrp	x8, 0x100001000 <_main+0xd0>
100000fc8:     	ldr	q6, [x8, #0x640]
100000fcc:     	eor.16b	v7, v3, v6
100000fd0:     	adrp	x8, 0x100001000 <_main+0xd0>
100000fd4:     	ldr	q16, [x8, #0x650]
100000fd8:     	eor.16b	v17, v3, v16
100000fdc:     	stp	q5, q7, [x24, #0x310]
100000fe0:     	add.4s	v1, v3, v1
100000fe4:     	add.4s	v4, v3, v4
100000fe8:     	add.4s	v5, v3, v6
100000fec:     	add.4s	v6, v3, v16
100000ff0:     	stp	q4, q5, [x24, #0x210]
100000ff4:     	adrp	x8, 0x100001000 <_main+0xd0>
100000ff8:     	ldr	q4, [x8, #0x670]
100000ffc:     	adrp	x8, 0x100001000 <_main+0xd0>
100001000:     	ldr	q5, [x8, #0x680]
100001004:     	stp	q4, q5, [x24, #0x110]
100001008:     	adrp	x8, 0x100001000 <_main+0xd0>
10000100c:     	ldr	q4, [x8, #0x690]
100001010:     	adrp	x8, 0x100001000 <_main+0xd0>
100001014:     	ldr	q5, [x8, #0x6a0]
100001018:     	eor.16b	v7, v3, v5
10000101c:     	adrp	x8, 0x100001000 <_main+0xd0>
100001020:     	ldr	q16, [x8, #0x6b0]
100001024:     	eor.16b	v18, v3, v16
100001028:     	adrp	x8, 0x100001000 <_main+0xd0>
10000102c:     	ldr	q19, [x8, #0x6c0]
100001030:     	eor.16b	v20, v3, v19
100001034:     	adrp	x8, 0x100001000 <_main+0xd0>
100001038:     	ldr	q21, [x8, #0x6d0]
10000103c:     	eor.16b	v22, v3, v21
100001040:     	stp	q17, q7, [x24, #0x330]
100001044:     	stp	q18, q20, [x24, #0x350]
100001048:     	add.4s	v5, v3, v5
10000104c:     	add.4s	v7, v3, v16
100001050:     	add.4s	v16, v3, v19
100001054:     	add.4s	v17, v3, v21
100001058:     	stp	q6, q5, [x24, #0x230]
10000105c:     	stp	q7, q16, [x24, #0x250]
100001060:     	adrp	x8, 0x100001000 <_main+0xd0>
100001064:     	ldr	q5, [x8, #0x6e0]
100001068:     	stp	q4, q5, [x24, #0x130]
10000106c:     	adrp	x8, 0x100001000 <_main+0xd0>
100001070:     	ldr	q4, [x8, #0x6f0]
100001074:     	adrp	x8, 0x100001000 <_main+0xd0>
100001078:     	ldr	q5, [x8, #0x700]
10000107c:     	stp	q4, q5, [x24, #0x150]
100001080:     	adrp	x8, 0x100001000 <_main+0xd0>
100001084:     	ldr	q4, [x8, #0x710]
100001088:     	adrp	x8, 0x100001000 <_main+0xd0>
10000108c:     	ldr	q5, [x8, #0x720]
100001090:     	eor.16b	v6, v3, v5
100001094:     	adrp	x8, 0x100001000 <_main+0xd0>
100001098:     	ldr	q7, [x8, #0x730]
10000109c:     	eor.16b	v16, v3, v7
1000010a0:     	adrp	x8, 0x100001000 <_main+0xd0>
1000010a4:     	ldr	q18, [x8, #0x740]
1000010a8:     	eor.16b	v19, v3, v18
1000010ac:     	adrp	x8, 0x100001000 <_main+0xd0>
1000010b0:     	ldr	q20, [x8, #0x750]
1000010b4:     	stp	q22, q6, [x24, #0x370]
1000010b8:     	eor.16b	v6, v3, v20
1000010bc:     	stp	q16, q19, [x24, #0x390]
1000010c0:     	add.4s	v5, v3, v5
1000010c4:     	add.4s	v7, v3, v7
1000010c8:     	add.4s	v16, v3, v18
1000010cc:     	stp	q17, q5, [x24, #0x270]
1000010d0:     	stp	q7, q16, [x24, #0x290]
1000010d4:     	adrp	x8, 0x100001000 <_main+0xd0>
1000010d8:     	ldr	q5, [x8, #0x760]
1000010dc:     	stp	q4, q5, [x24, #0x170]
1000010e0:     	adrp	x8, 0x100001000 <_main+0xd0>
1000010e4:     	ldr	q4, [x8, #0x770]
1000010e8:     	adrp	x8, 0x100001000 <_main+0xd0>
1000010ec:     	ldr	q5, [x8, #0x780]
1000010f0:     	stp	q4, q5, [x24, #0x190]
1000010f4:     	adrp	x8, 0x100001000 <_main+0xd0>
1000010f8:     	ldr	q4, [x8, #0x7a0]
1000010fc:     	eor.16b	v5, v3, v4
100001100:     	adrp	x8, 0x100001000 <_main+0xd0>
100001104:     	ldr	q7, [x8, #0x7b0]
100001108:     	eor.16b	v16, v3, v7
10000110c:     	adrp	x8, 0x100001000 <_main+0xd0>
100001110:     	ldr	q17, [x8, #0x7c0]
100001114:     	eor.16b	v18, v3, v17
100001118:     	stp	q6, q5, [x24, #0x3b0]
10000111c:     	adrp	x8, 0x100001000 <_main+0xd0>
100001120:     	ldr	q5, [x8, #0x7d0]
100001124:     	stp	q16, q18, [x24, #0x3d0]
100001128:     	eor.16b	v6, v3, v5
10000112c:     	str	q6, [x24, #0x3f0]
100001130:     	adrp	x8, 0x100001000 <_main+0xd0>
100001134:     	ldr	q6, [x8, #0x660]
100001138:     	stp	q0, q0, [sp, #0xb0]
10000113c:     	stp	q0, q0, [sp, #0xd0]
100001140:     	str	q0, [sp, #0xf0]
100001144:     	stp	q0, q0, [x24, #0x50]
100001148:     	add.4s	v16, v3, v20
10000114c:     	add.4s	v4, v3, v4
100001150:     	add.4s	v7, v3, v7
100001154:     	add.4s	v17, v3, v17
100001158:     	add.4s	v3, v3, v5
10000115c:     	adrp	x8, 0x100001000 <_main+0xd0>
100001160:     	ldr	q5, [x8, #0x790]
100001164:     	stp	q0, q0, [x24, #0x70]
100001168:     	stp	q0, q0, [x24, #0x90]
10000116c:     	stp	q16, q4, [x24, #0x2b0]
100001170:     	stp	q7, q17, [x24, #0x2d0]
100001174:     	stp	q3, q2, [x24, #0x2f0]
100001178:     	adrp	x8, 0x100001000 <_main+0xd0>
10000117c:     	ldr	q2, [x8, #0x7e0]
100001180:     	stp	q5, q2, [x24, #0x1b0]
100001184:     	adrp	x8, 0x100001000 <_main+0xd0>
100001188:     	ldr	q2, [x8, #0x7f0]
10000118c:     	adrp	x8, 0x100001000 <_main+0xd0>
100001190:     	ldr	q3, [x8, #0x800]
100001194:     	stp	q2, q3, [x24, #0x1d0]
100001198:     	adrp	x8, 0x100001000 <_main+0xd0>
10000119c:     	ldr	q2, [x8, #0x810]
1000011a0:     	stp	q2, q1, [x24, #0x1f0]
1000011a4:     	stp	q0, q0, [x24, #0xb0]
1000011a8:     	stp	q0, q0, [x24, #0xd0]
1000011ac:     	stp	q0, q6, [x24, #0xf0]
1000011b0:     	str	w23, [sp, #0xa0]
1000011b4:     	adrp	x8, 0x100001000 <_main+0xd0>
1000011b8:     	ldr	d0, [x8, #0x830]
1000011bc:     	stur	d0, [sp, #0xa4]
1000011c0:     	str	w19, [sp, #0xac]
1000011c4:     	add	x0, sp, #0x90
1000011c8:     	add	x1, sp, #0xa0
1000011cc:     	bl	0x100000748 <_copy16>
1000011d0:     	ldrsw	x8, [sp, #0x9c]
1000011d4:     	str	x8, [sp, #0x68]
1000011d8:     	sub	x0, x29, #0xe0
1000011dc:     	bl	0x100000754 <_zero64>
1000011e0:     	sub	x0, x29, #0xe0
1000011e4:     	and	x1, x20, #0x3f
1000011e8:     	bl	0x100000764 <_zero_n>
1000011ec:     	mov	x0, x25
1000011f0:     	bl	0x100000770 <_strcmp_const>
1000011f4:     	str	w0, [sp, #0x50]
1000011f8:     	mov	x0, x25
1000011fc:     	bl	0x100000794 <_strncmp_const>
100001200:     	str	w0, [sp, #0x3c]
100001204:     	add	x0, sp, #0x4b0
100001208:     	and	w1, w23, #0x3f
10000120c:     	bl	0x1000007bc <_loop_zero>
100001210:     	mov	x0, x25
100001214:     	bl	0x1000015c0 <_strlen@stub>
100001218:     	mov	x2, x0
10000121c:     	sub	x0, x29, #0xe0
100001220:     	mov	x1, x25
100001224:     	bl	0x1000007d0 <_loop_copy>
100001228:     	mov	x0, x25
10000122c:     	bl	0x1000007e4 <_loop_strlen>
100001230:     	str	x0, [sp, #0x60]
100001234:     	add	w8, w23, #0x1
100001238:     	add	w9, w23, #0x2
10000123c:     	stp	x8, x9, [sp, #0x8]
100001240:     	str	x23, [sp]
100001244:     	mov	w0, #0x3                ; =3
100001248:     	bl	0x100000868 <_sum_va>
10000124c:     	str	w0, [sp, #0x5c]
100001250:     	mov	x0, x25
100001254:     	bl	0x1000008b0 <_ssp_copy>
100001258:     	str	w0, [sp, #0x58]
10000125c:     	mov	x0, x25
100001260:     	bl	0x1000015c0 <_strlen@stub>
100001264:     	mov	x8, x0
100001268:     	sub	x0, x29, #0xe0
10000126c:     	and	x2, x8, #0x1f
100001270:     	mov	x1, x25
100001274:     	bl	0x1000008e8 <_fortify_memcpy>
100001278:     	sub	x0, x29, #0xe0
10000127c:     	mov	w1, #0x80               ; =128
100001280:     	mov	x2, x23
100001284:     	bl	0x100000920 <_fortify_snprintf>
100001288:     	str	w0, [sp, #0x54]
10000128c:     	cmp	w22, #0x4
100001290:     	str	x25, [sp, #0x70]
100001294:     	b.lt	0x1000012a0 <_main+0x370>
100001298:     	ldr	x8, [x21, #0x18]
10000129c:     	b	0x1000012a8 <_main+0x378>
1000012a0:     	adrp	x8, 0x100001000 <_main+0xd0>
1000012a4:     	add	x8, x8, #0x87a
1000012a8:     	str	x8, [sp, #0x28]
1000012ac:     	mov	x0, x20
1000012b0:     	bl	0x100000858 <_make_small>
1000012b4:     	str	x0, [sp, #0x48]
1000012b8:     	mov	x0, x20
1000012bc:     	bl	0x10000082c <_use_big>
1000012c0:     	str	x0, [sp, #0x40]
1000012c4:     	mov	x0, x20
1000012c8:     	bl	0x100000730 <_is_pow2>
1000012cc:     	str	w0, [sp, #0x24]
1000012d0:     	mov	x0, x20
1000012d4:     	mov	x1, x20
1000012d8:     	bl	0x100000724 <_rotl32>
1000012dc:     	str	w0, [sp, #0x20]
1000012e0:     	mov	x0, x20
1000012e4:     	bl	0x10000071c <_bswap32_manual>
1000012e8:     	str	w0, [sp, #0x1c]
1000012ec:     	mov	x0, x20
1000012f0:     	bl	0x100000708 <_popcount_loop>
1000012f4:     	str	w0, [sp, #0x18]
1000012f8:     	mov	x0, x20
1000012fc:     	mov	w1, #0x0                ; =0
100001300:     	mov	w2, #0x9                ; =9
100001304:     	bl	0x1000006f4 <_sel_clamp>
100001308:     	mov	x22, x0
10000130c:     	mov	x0, x20
100001310:     	bl	0x1000006e8 <_sel_abs>
100001314:     	mov	x28, x0
100001318:     	mov	x0, x20
10000131c:     	mov	w1, #0x5                ; =5
100001320:     	bl	0x1000006dc <_sel_max>
100001324:     	mov	x24, x0
100001328:     	mov	x0, x20
10000132c:     	bl	0x1000006bc <_udiv1000_64>
100001330:     	str	x0, [sp, #0x30]
100001334:     	mov	x0, x20
100001338:     	bl	0x1000006a8 <_sdiv16>
10000133c:     	mov	x25, x0
100001340:     	mov	x0, x20
100001344:     	bl	0x10000068c <_umod10>
100001348:     	mov	x26, x0
10000134c:     	mov	x0, x20
100001350:     	bl	0x10000066c <_sdiv7>
100001354:     	mov	x23, x0
100001358:     	mov	x0, x20
10000135c:     	bl	0x10000064c <_udiv7>
100001360:     	mov	x21, x0
100001364:     	mov	x0, x20
100001368:     	bl	0x100000614 <_sw_bittest>
10000136c:     	mov	x27, x0
100001370:     	mov	x0, x20
100001374:     	bl	0x100000568 <_sw_sparse>
100001378:     	mov	x19, x0
10000137c:     	mov	x0, x20
100001380:     	bl	0x100000548 <_sw_dense>
100001384:     	add	w8, w26, w25
100001388:     	add	w9, w23, w21
10000138c:     	add	w21, w8, w9
100001390:     	add	w8, w19, w27
100001394:     	add	w25, w8, w0
100001398:     	ldr	w8, [sp, #0x18]
10000139c:     	add	w8, w22, w8
1000013a0:     	add	w9, w28, w24
1000013a4:     	add	w22, w8, w9
1000013a8:     	ldp	w9, w8, [sp, #0x20]
1000013ac:     	add	w8, w9, w8
1000013b0:     	ldr	w9, [sp, #0x1c]
1000013b4:     	add	w24, w8, w9
1000013b8:     	ldr	w8, [sp, #0x50]
1000013bc:     	ldr	w9, [sp, #0x3c]
1000013c0:     	add	w8, w8, w9
1000013c4:     	add	w26, w8, #0x7
1000013c8:     	sub	x1, x29, #0xe0
1000013cc:     	ldr	x0, [sp, #0x28]
1000013d0:     	mov	w2, #0x80               ; =128
1000013d4:     	bl	0x100000948 <_read_file_head>
1000013d8:     	mov	x23, x0
1000013dc:     	mov	x0, x20
1000013e0:     	bl	0x100000a3c <_tail_caller>
1000013e4:     	mov	x19, x0
1000013e8:     	ldr	x20, [sp, #0x70]
1000013ec:     	mov	x0, x20
1000013f0:     	bl	0x100000a44 <_tail_ext>
1000013f4:     	add	w27, w0, w19
1000013f8:     	add	x0, sp, #0x4b0
1000013fc:     	add	x1, sp, #0x3b0
100001400:     	add	x2, sp, #0x2b0
100001404:     	mov	w3, #0x40               ; =64
100001408:     	bl	0x100000a4c <_vadd>
10000140c:     	add	x0, sp, #0x4b0
100001410:     	mov	w1, #0x40               ; =64
100001414:     	bl	0x100000b38 <_vsum>
100001418:     	mov	x19, x0
10000141c:     	add	x0, sp, #0x1b0
100001420:     	add	x1, sp, #0xb0
100001424:     	mov	w2, #0x40               ; =64
100001428:     	bl	0x100000c30 <_vdot>
10000142c:     	fcvtzs	x28, s0
100001430:     	add	x0, sp, #0x80
100001434:     	bl	0x100000da0 <_md5_init>
100001438:     	bl	0x100000db0 <_crc32_make_table>
10000143c:     	mov	x0, x20
100001440:     	bl	0x1000015c0 <_strlen@stub>
100001444:     	mov	x1, x0
100001448:     	mov	x0, x20
10000144c:     	bl	0x100000e90 <_crc32_buf>
100001450:     	mov	x20, x0
100001454:     	ldr	d0, [sp, #0x80]
100001458:     	str	d0, [sp, #0x78]
10000145c:     	adrp	x1, 0x100001000 <_main+0xd0>
100001460:     	add	x1, x1, #0x820
100001464:     	add	x0, sp, #0x78
100001468:     	bl	0x100000ecc <_tea_encrypt>
10000146c:     	ldr	w8, [sp, #0x78]
100001470:     	ldp	x10, x9, [sp, #0x60]
100001474:     	add	x9, x9, x10
100001478:     	add	x9, x26, x9
10000147c:     	ldp	w10, w11, [sp, #0x58]
100001480:     	add	x9, x9, w11, sxtw
100001484:     	add	x9, x9, w10, sxtw
100001488:     	ldr	w10, [sp, #0x54]
10000148c:     	add	x9, x9, w10, sxtw
100001490:     	ldp	x10, x11, [sp, #0x40]
100001494:     	add	x9, x9, x11, asr #32
100001498:     	add	x10, x10, x24
10000149c:     	ldr	x11, [sp, #0x30]
1000014a0:     	add	x10, x10, x11
1000014a4:     	add	x9, x9, x10
1000014a8:     	add	x9, x9, w22, sxtw
1000014ac:     	add	x9, x9, x21
1000014b0:     	add	x9, x9, w23, sxtw
1000014b4:     	add	x9, x9, w25, sxtw
1000014b8:     	add	x9, x9, w27, sxtw
1000014bc:     	add	x9, x9, w19, sxtw
1000014c0:     	add	x9, x9, x28
1000014c4:     	add	x9, x9, w20, uxtw
1000014c8:     	add	x8, x9, x8
1000014cc:     	str	x8, [sp]
1000014d0:     	adrp	x0, 0x100001000 <_main+0xd0>
1000014d4:     	add	x0, x0, #0x885
1000014d8:     	bl	0x100001584 <_printf@stub>
1000014dc:     	mov	w0, #0x0                ; =0
1000014e0:     	add	sp, sp, #0x640
1000014e4:     	ldp	x29, x30, [sp, #0x50]
1000014e8:     	ldp	x20, x19, [sp, #0x40]
1000014ec:     	ldp	x22, x21, [sp, #0x30]
1000014f0:     	ldp	x24, x23, [sp, #0x20]
1000014f4:     	ldp	x26, x25, [sp, #0x10]
1000014f8:     	ldp	x28, x27, [sp], #0x60
1000014fc:     	ret

Disassembly of section __TEXT,__stubs:

0000000100001500 <__stubs>:
100001500:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001504:     	ldr	x16, [x16]
100001508:     	br	x16
10000150c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001510:     	ldr	x16, [x16, #0x8]
100001514:     	br	x16
100001518:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
10000151c:     	ldr	x16, [x16, #0x18]
100001520:     	br	x16
100001524:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001528:     	ldr	x16, [x16, #0x20]
10000152c:     	br	x16
100001530:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001534:     	ldr	x16, [x16, #0x28]
100001538:     	br	x16
10000153c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001540:     	ldr	x16, [x16, #0x30]
100001544:     	br	x16
100001548:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
10000154c:     	ldr	x16, [x16, #0x38]
100001550:     	br	x16
100001554:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001558:     	ldr	x16, [x16, #0x40]
10000155c:     	br	x16
100001560:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001564:     	ldr	x16, [x16, #0x48]
100001568:     	br	x16
10000156c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001570:     	ldr	x16, [x16, #0x50]
100001574:     	br	x16
100001578:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
10000157c:     	ldr	x16, [x16, #0x58]
100001580:     	br	x16
100001584:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001588:     	ldr	x16, [x16, #0x60]
10000158c:     	br	x16
100001590:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001594:     	ldr	x16, [x16, #0x68]
100001598:     	br	x16
10000159c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015a0:     	ldr	x16, [x16, #0x70]
1000015a4:     	br	x16
1000015a8:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015ac:     	ldr	x16, [x16, #0x78]
1000015b0:     	br	x16
1000015b4:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015b8:     	ldr	x16, [x16, #0x80]
1000015bc:     	br	x16
1000015c0:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015c4:     	ldr	x16, [x16, #0x88]
1000015c8:     	br	x16
1000015cc:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
1000015d0:     	ldr	x16, [x16, #0x90]
1000015d4:     	br	x16
