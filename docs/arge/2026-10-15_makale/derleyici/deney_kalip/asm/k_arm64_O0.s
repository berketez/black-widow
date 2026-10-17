
bin/k_arm64_O0:	file format mach-o arm64

Disassembly of section __TEXT,__text:

0000000100000548 <_sw_dense>:
100000548:     	sub	sp, sp, #0x10
10000054c:     	str	w0, [sp, #0x8]
100000550:     	ldr	w8, [sp, #0x8]
100000554:     	str	w8, [sp, #0x4]
100000558:     	cbz	w8, 0x1000005d0 <_sw_dense+0x88>
10000055c:     	b	0x100000560 <_sw_dense+0x18>
100000560:     	ldr	w8, [sp, #0x4]
100000564:     	subs	w8, w8, #0x1
100000568:     	b.eq	0x1000005dc <_sw_dense+0x94>
10000056c:     	b	0x100000570 <_sw_dense+0x28>
100000570:     	ldr	w8, [sp, #0x4]
100000574:     	subs	w8, w8, #0x2
100000578:     	b.eq	0x1000005e8 <_sw_dense+0xa0>
10000057c:     	b	0x100000580 <_sw_dense+0x38>
100000580:     	ldr	w8, [sp, #0x4]
100000584:     	subs	w8, w8, #0x3
100000588:     	b.eq	0x1000005f4 <_sw_dense+0xac>
10000058c:     	b	0x100000590 <_sw_dense+0x48>
100000590:     	ldr	w8, [sp, #0x4]
100000594:     	subs	w8, w8, #0x4
100000598:     	b.eq	0x100000600 <_sw_dense+0xb8>
10000059c:     	b	0x1000005a0 <_sw_dense+0x58>
1000005a0:     	ldr	w8, [sp, #0x4]
1000005a4:     	subs	w8, w8, #0x5
1000005a8:     	b.eq	0x10000060c <_sw_dense+0xc4>
1000005ac:     	b	0x1000005b0 <_sw_dense+0x68>
1000005b0:     	ldr	w8, [sp, #0x4]
1000005b4:     	subs	w8, w8, #0x6
1000005b8:     	b.eq	0x100000618 <_sw_dense+0xd0>
1000005bc:     	b	0x1000005c0 <_sw_dense+0x78>
1000005c0:     	ldr	w8, [sp, #0x4]
1000005c4:     	subs	w8, w8, #0x7
1000005c8:     	b.eq	0x100000624 <_sw_dense+0xdc>
1000005cc:     	b	0x100000630 <_sw_dense+0xe8>
1000005d0:     	mov	w8, #0xb                ; =11
1000005d4:     	str	w8, [sp, #0xc]
1000005d8:     	b	0x10000063c <_sw_dense+0xf4>
1000005dc:     	mov	w8, #0x1b               ; =27
1000005e0:     	str	w8, [sp, #0xc]
1000005e4:     	b	0x10000063c <_sw_dense+0xf4>
1000005e8:     	mov	w8, #0x23               ; =35
1000005ec:     	str	w8, [sp, #0xc]
1000005f0:     	b	0x10000063c <_sw_dense+0xf4>
1000005f4:     	mov	w8, #0x31               ; =49
1000005f8:     	str	w8, [sp, #0xc]
1000005fc:     	b	0x10000063c <_sw_dense+0xf4>
100000600:     	mov	w8, #0x34               ; =52
100000604:     	str	w8, [sp, #0xc]
100000608:     	b	0x10000063c <_sw_dense+0xf4>
10000060c:     	mov	w8, #0x44               ; =68
100000610:     	str	w8, [sp, #0xc]
100000614:     	b	0x10000063c <_sw_dense+0xf4>
100000618:     	mov	w8, #0x47               ; =71
10000061c:     	str	w8, [sp, #0xc]
100000620:     	b	0x10000063c <_sw_dense+0xf4>
100000624:     	mov	w8, #0x59               ; =89
100000628:     	str	w8, [sp, #0xc]
10000062c:     	b	0x10000063c <_sw_dense+0xf4>
100000630:     	mov	w8, #-0x1               ; =-1
100000634:     	str	w8, [sp, #0xc]
100000638:     	b	0x10000063c <_sw_dense+0xf4>
10000063c:     	ldr	w0, [sp, #0xc]
100000640:     	add	sp, sp, #0x10
100000644:     	ret

0000000100000648 <_sw_sparse>:
100000648:     	sub	sp, sp, #0x10
10000064c:     	str	w0, [sp, #0x8]
100000650:     	ldr	w8, [sp, #0x8]
100000654:     	str	w8, [sp, #0x4]
100000658:     	subs	w8, w8, #0x3
10000065c:     	b.eq	0x1000006dc <_sw_sparse+0x94>
100000660:     	b	0x100000664 <_sw_sparse+0x1c>
100000664:     	ldr	w8, [sp, #0x4]
100000668:     	subs	w8, w8, #0x64
10000066c:     	b.eq	0x1000006e8 <_sw_sparse+0xa0>
100000670:     	b	0x100000674 <_sw_sparse+0x2c>
100000674:     	ldr	w8, [sp, #0x4]
100000678:     	subs	w8, w8, #0x3e8
10000067c:     	b.eq	0x1000006f4 <_sw_sparse+0xac>
100000680:     	b	0x100000684 <_sw_sparse+0x3c>
100000684:     	ldr	w8, [sp, #0x4]
100000688:     	mov	w9, #0x1388             ; =5000
10000068c:     	subs	w8, w8, w9
100000690:     	b.eq	0x100000700 <_sw_sparse+0xb8>
100000694:     	b	0x100000698 <_sw_sparse+0x50>
100000698:     	ldr	w8, [sp, #0x4]
10000069c:     	mov	w9, #0x4e20             ; =20000
1000006a0:     	subs	w8, w8, w9
1000006a4:     	b.eq	0x10000070c <_sw_sparse+0xc4>
1000006a8:     	b	0x1000006ac <_sw_sparse+0x64>
1000006ac:     	ldr	w8, [sp, #0x4]
1000006b0:     	mov	w9, #0x2fd1             ; =12241
1000006b4:     	movk	w9, #0x1, lsl #16
1000006b8:     	subs	w8, w8, w9
1000006bc:     	b.eq	0x100000718 <_sw_sparse+0xd0>
1000006c0:     	b	0x1000006c4 <_sw_sparse+0x7c>
1000006c4:     	ldr	w8, [sp, #0x4]
1000006c8:     	mov	w9, #0xe240             ; =57920
1000006cc:     	movk	w9, #0x1, lsl #16
1000006d0:     	subs	w8, w8, w9
1000006d4:     	b.eq	0x100000724 <_sw_sparse+0xdc>
1000006d8:     	b	0x100000730 <_sw_sparse+0xe8>
1000006dc:     	mov	w8, #0x1                ; =1
1000006e0:     	str	w8, [sp, #0xc]
1000006e4:     	b	0x100000738 <_sw_sparse+0xf0>
1000006e8:     	mov	w8, #0x2                ; =2
1000006ec:     	str	w8, [sp, #0xc]
1000006f0:     	b	0x100000738 <_sw_sparse+0xf0>
1000006f4:     	mov	w8, #0x3                ; =3
1000006f8:     	str	w8, [sp, #0xc]
1000006fc:     	b	0x100000738 <_sw_sparse+0xf0>
100000700:     	mov	w8, #0x4                ; =4
100000704:     	str	w8, [sp, #0xc]
100000708:     	b	0x100000738 <_sw_sparse+0xf0>
10000070c:     	mov	w8, #0x5                ; =5
100000710:     	str	w8, [sp, #0xc]
100000714:     	b	0x100000738 <_sw_sparse+0xf0>
100000718:     	mov	w8, #0x6                ; =6
10000071c:     	str	w8, [sp, #0xc]
100000720:     	b	0x100000738 <_sw_sparse+0xf0>
100000724:     	mov	w8, #0x7                ; =7
100000728:     	str	w8, [sp, #0xc]
10000072c:     	b	0x100000738 <_sw_sparse+0xf0>
100000730:     	str	wzr, [sp, #0xc]
100000734:     	b	0x100000738 <_sw_sparse+0xf0>
100000738:     	ldr	w0, [sp, #0xc]
10000073c:     	add	sp, sp, #0x10
100000740:     	ret

0000000100000744 <_sw_bittest>:
100000744:     	sub	sp, sp, #0x10
100000748:     	str	w0, [sp, #0x8]
10000074c:     	ldr	w8, [sp, #0x8]
100000750:     	str	w8, [sp, #0x4]
100000754:     	subs	w8, w8, #0x9
100000758:     	subs	w8, w8, #0x4
10000075c:     	b.ls	0x100000794 <_sw_bittest+0x50>
100000760:     	b	0x100000764 <_sw_bittest+0x20>
100000764:     	ldr	w8, [sp, #0x4]
100000768:     	subs	w8, w8, #0x20
10000076c:     	b.eq	0x100000794 <_sw_bittest+0x50>
100000770:     	b	0x100000774 <_sw_bittest+0x30>
100000774:     	ldr	w8, [sp, #0x4]
100000778:     	subs	w8, w8, #0x2c
10000077c:     	b.eq	0x100000794 <_sw_bittest+0x50>
100000780:     	b	0x100000784 <_sw_bittest+0x40>
100000784:     	ldr	w8, [sp, #0x4]
100000788:     	subs	w8, w8, #0x3b
10000078c:     	b.ne	0x1000007a0 <_sw_bittest+0x5c>
100000790:     	b	0x100000794 <_sw_bittest+0x50>
100000794:     	mov	w8, #0x1                ; =1
100000798:     	str	w8, [sp, #0xc]
10000079c:     	b	0x1000007a8 <_sw_bittest+0x64>
1000007a0:     	str	wzr, [sp, #0xc]
1000007a4:     	b	0x1000007a8 <_sw_bittest+0x64>
1000007a8:     	ldr	w0, [sp, #0xc]
1000007ac:     	add	sp, sp, #0x10
1000007b0:     	ret

00000001000007b4 <_udiv7>:
1000007b4:     	sub	sp, sp, #0x10
1000007b8:     	str	w0, [sp, #0xc]
1000007bc:     	ldr	w8, [sp, #0xc]
1000007c0:     	mov	w9, #0x7                ; =7
1000007c4:     	udiv	w0, w8, w9
1000007c8:     	add	sp, sp, #0x10
1000007cc:     	ret

00000001000007d0 <_sdiv7>:
1000007d0:     	sub	sp, sp, #0x10
1000007d4:     	str	w0, [sp, #0xc]
1000007d8:     	ldr	w8, [sp, #0xc]
1000007dc:     	mov	w9, #0x7                ; =7
1000007e0:     	sdiv	w0, w8, w9
1000007e4:     	add	sp, sp, #0x10
1000007e8:     	ret

00000001000007ec <_umod10>:
1000007ec:     	sub	sp, sp, #0x10
1000007f0:     	str	w0, [sp, #0xc]
1000007f4:     	ldr	w8, [sp, #0xc]
1000007f8:     	mov	w10, #0xa               ; =10
1000007fc:     	udiv	w9, w8, w10
100000800:     	mul	w9, w9, w10
100000804:     	subs	w0, w8, w9
100000808:     	add	sp, sp, #0x10
10000080c:     	ret

0000000100000810 <_sdiv16>:
100000810:     	sub	sp, sp, #0x10
100000814:     	str	w0, [sp, #0xc]
100000818:     	ldr	w8, [sp, #0xc]
10000081c:     	mov	w9, #0x10               ; =16
100000820:     	sdiv	w0, w8, w9
100000824:     	add	sp, sp, #0x10
100000828:     	ret

000000010000082c <_udiv1000_64>:
10000082c:     	sub	sp, sp, #0x10
100000830:     	str	x0, [sp, #0x8]
100000834:     	ldr	x8, [sp, #0x8]
100000838:     	mov	x9, #0x3e8              ; =1000
10000083c:     	udiv	x0, x8, x9
100000840:     	add	sp, sp, #0x10
100000844:     	ret

0000000100000848 <_sel_max>:
100000848:     	sub	sp, sp, #0x10
10000084c:     	str	w0, [sp, #0xc]
100000850:     	str	w1, [sp, #0x8]
100000854:     	ldr	w8, [sp, #0xc]
100000858:     	ldr	w9, [sp, #0x8]
10000085c:     	subs	w8, w8, w9
100000860:     	b.le	0x100000874 <_sel_max+0x2c>
100000864:     	b	0x100000868 <_sel_max+0x20>
100000868:     	ldr	w8, [sp, #0xc]
10000086c:     	str	w8, [sp, #0x4]
100000870:     	b	0x100000880 <_sel_max+0x38>
100000874:     	ldr	w8, [sp, #0x8]
100000878:     	str	w8, [sp, #0x4]
10000087c:     	b	0x100000880 <_sel_max+0x38>
100000880:     	ldr	w0, [sp, #0x4]
100000884:     	add	sp, sp, #0x10
100000888:     	ret

000000010000088c <_sel_abs>:
10000088c:     	sub	sp, sp, #0x10
100000890:     	str	w0, [sp, #0xc]
100000894:     	ldr	w8, [sp, #0xc]
100000898:     	tbz	w8, #0x1f, 0x1000008b4 <_sel_abs+0x28>
10000089c:     	b	0x1000008a0 <_sel_abs+0x14>
1000008a0:     	ldr	w9, [sp, #0xc]
1000008a4:     	mov	w8, #0x0                ; =0
1000008a8:     	subs	w8, w8, w9
1000008ac:     	str	w8, [sp, #0x8]
1000008b0:     	b	0x1000008c0 <_sel_abs+0x34>
1000008b4:     	ldr	w8, [sp, #0xc]
1000008b8:     	str	w8, [sp, #0x8]
1000008bc:     	b	0x1000008c0 <_sel_abs+0x34>
1000008c0:     	ldr	w0, [sp, #0x8]
1000008c4:     	add	sp, sp, #0x10
1000008c8:     	ret

00000001000008cc <_sel_clamp>:
1000008cc:     	sub	sp, sp, #0x20
1000008d0:     	str	w0, [sp, #0x1c]
1000008d4:     	str	w1, [sp, #0x18]
1000008d8:     	str	w2, [sp, #0x14]
1000008dc:     	ldr	w8, [sp, #0x1c]
1000008e0:     	ldr	w9, [sp, #0x18]
1000008e4:     	subs	w8, w8, w9
1000008e8:     	b.ge	0x1000008fc <_sel_clamp+0x30>
1000008ec:     	b	0x1000008f0 <_sel_clamp+0x24>
1000008f0:     	ldr	w8, [sp, #0x18]
1000008f4:     	str	w8, [sp, #0x10]
1000008f8:     	b	0x100000934 <_sel_clamp+0x68>
1000008fc:     	ldr	w8, [sp, #0x1c]
100000900:     	ldr	w9, [sp, #0x14]
100000904:     	subs	w8, w8, w9
100000908:     	b.le	0x10000091c <_sel_clamp+0x50>
10000090c:     	b	0x100000910 <_sel_clamp+0x44>
100000910:     	ldr	w8, [sp, #0x14]
100000914:     	str	w8, [sp, #0xc]
100000918:     	b	0x100000928 <_sel_clamp+0x5c>
10000091c:     	ldr	w8, [sp, #0x1c]
100000920:     	str	w8, [sp, #0xc]
100000924:     	b	0x100000928 <_sel_clamp+0x5c>
100000928:     	ldr	w8, [sp, #0xc]
10000092c:     	str	w8, [sp, #0x10]
100000930:     	b	0x100000934 <_sel_clamp+0x68>
100000934:     	ldr	w0, [sp, #0x10]
100000938:     	add	sp, sp, #0x20
10000093c:     	ret

0000000100000940 <_popcount_loop>:
100000940:     	sub	sp, sp, #0x10
100000944:     	str	w0, [sp, #0xc]
100000948:     	str	wzr, [sp, #0x8]
10000094c:     	b	0x100000950 <_popcount_loop+0x10>
100000950:     	ldr	w8, [sp, #0xc]
100000954:     	cbz	w8, 0x100000980 <_popcount_loop+0x40>
100000958:     	b	0x10000095c <_popcount_loop+0x1c>
10000095c:     	ldr	w8, [sp, #0xc]
100000960:     	subs	w9, w8, #0x1
100000964:     	ldr	w8, [sp, #0xc]
100000968:     	and	w8, w8, w9
10000096c:     	str	w8, [sp, #0xc]
100000970:     	ldr	w8, [sp, #0x8]
100000974:     	add	w8, w8, #0x1
100000978:     	str	w8, [sp, #0x8]
10000097c:     	b	0x100000950 <_popcount_loop+0x10>
100000980:     	ldr	w0, [sp, #0x8]
100000984:     	add	sp, sp, #0x10
100000988:     	ret

000000010000098c <_bswap32_manual>:
10000098c:     	sub	sp, sp, #0x10
100000990:     	str	w0, [sp, #0xc]
100000994:     	ldr	w9, [sp, #0xc]
100000998:     	ldr	w8, [sp, #0xc]
10000099c:     	lsr	w8, w8, #8
1000009a0:     	and	w8, w8, #0xff00
1000009a4:     	orr	w8, w8, w9, lsr #24
1000009a8:     	ldr	w9, [sp, #0xc]
1000009ac:     	lsl	w9, w9, #8
1000009b0:     	and	w9, w9, #0xff0000
1000009b4:     	orr	w8, w8, w9
1000009b8:     	ldr	w9, [sp, #0xc]
1000009bc:     	orr	w0, w8, w9, lsl #24
1000009c0:     	add	sp, sp, #0x10
1000009c4:     	ret

00000001000009c8 <_rotl32>:
1000009c8:     	sub	sp, sp, #0x10
1000009cc:     	str	w0, [sp, #0xc]
1000009d0:     	str	w1, [sp, #0x8]
1000009d4:     	ldr	w8, [sp, #0xc]
1000009d8:     	ldr	w9, [sp, #0x8]
1000009dc:     	and	w9, w9, #0x1f
1000009e0:     	lsl	w8, w8, w9
1000009e4:     	ldr	w9, [sp, #0xc]
1000009e8:     	ldr	w11, [sp, #0x8]
1000009ec:     	mov	w10, #0x20              ; =32
1000009f0:     	subs	w10, w10, w11
1000009f4:     	and	w10, w10, #0x1f
1000009f8:     	lsr	w9, w9, w10
1000009fc:     	orr	w0, w8, w9
100000a00:     	add	sp, sp, #0x10
100000a04:     	ret

0000000100000a08 <_is_pow2>:
100000a08:     	sub	sp, sp, #0x10
100000a0c:     	str	w0, [sp, #0xc]
100000a10:     	ldr	w8, [sp, #0xc]
100000a14:     	mov	w9, #0x0                ; =0
100000a18:     	str	w9, [sp, #0x8]
100000a1c:     	cbz	w8, 0x100000a40 <_is_pow2+0x38>
100000a20:     	b	0x100000a24 <_is_pow2+0x1c>
100000a24:     	ldr	w8, [sp, #0xc]
100000a28:     	ldr	w9, [sp, #0xc]
100000a2c:     	subs	w9, w9, #0x1
100000a30:     	ands	w8, w8, w9
100000a34:     	cset	w8, eq
100000a38:     	str	w8, [sp, #0x8]
100000a3c:     	b	0x100000a40 <_is_pow2+0x38>
100000a40:     	ldr	w8, [sp, #0x8]
100000a44:     	and	w0, w8, #0x1
100000a48:     	add	sp, sp, #0x10
100000a4c:     	ret

0000000100000a50 <_copy16>:
100000a50:     	sub	sp, sp, #0x20
100000a54:     	stp	x29, x30, [sp, #0x10]
100000a58:     	add	x29, sp, #0x10
100000a5c:     	str	x0, [sp, #0x8]
100000a60:     	str	x1, [sp]
100000a64:     	ldr	x0, [sp, #0x8]
100000a68:     	ldr	x1, [sp]
100000a6c:     	mov	x2, #0x10               ; =16
100000a70:     	mov	x3, #-0x1               ; =-1
100000a74:     	bl	0x100001a0c <_strncmp+0x100001a0c>
100000a78:     	ldp	x29, x30, [sp, #0x10]
100000a7c:     	add	sp, sp, #0x20
100000a80:     	ret

0000000100000a84 <_zero64>:
100000a84:     	sub	sp, sp, #0x20
100000a88:     	stp	x29, x30, [sp, #0x10]
100000a8c:     	add	x29, sp, #0x10
100000a90:     	str	x0, [sp, #0x8]
100000a94:     	ldr	x0, [sp, #0x8]
100000a98:     	mov	w1, #0x0                ; =0
100000a9c:     	mov	x2, #0x40               ; =64
100000aa0:     	mov	x3, #-0x1               ; =-1
100000aa4:     	bl	0x100001a18 <_strncmp+0x100001a18>
100000aa8:     	ldp	x29, x30, [sp, #0x10]
100000aac:     	add	sp, sp, #0x20
100000ab0:     	ret

0000000100000ab4 <_zero_n>:
100000ab4:     	sub	sp, sp, #0x20
100000ab8:     	stp	x29, x30, [sp, #0x10]
100000abc:     	add	x29, sp, #0x10
100000ac0:     	str	x0, [sp, #0x8]
100000ac4:     	str	x1, [sp]
100000ac8:     	ldr	x0, [sp, #0x8]
100000acc:     	ldr	x2, [sp]
100000ad0:     	mov	w1, #0x0                ; =0
100000ad4:     	mov	x3, #-0x1               ; =-1
100000ad8:     	bl	0x100001a18 <_strncmp+0x100001a18>
100000adc:     	ldp	x29, x30, [sp, #0x10]
100000ae0:     	add	sp, sp, #0x20
100000ae4:     	ret

0000000100000ae8 <_strlen_const>:
100000ae8:     	mov	x0, #0x7                ; =7
100000aec:     	ret

0000000100000af0 <_strcmp_const>:
100000af0:     	sub	sp, sp, #0x20
100000af4:     	stp	x29, x30, [sp, #0x10]
100000af8:     	add	x29, sp, #0x10
100000afc:     	str	x0, [sp, #0x8]
100000b00:     	ldr	x0, [sp, #0x8]
100000b04:     	adrp	x1, 0x100001000 <_read_file_head+0x124>
100000b08:     	add	x1, x1, #0xae4
100000b0c:     	bl	0x100001a24 <_strncmp+0x100001a24>
100000b10:     	subs	w8, w0, #0x0
100000b14:     	cset	w0, eq
100000b18:     	ldp	x29, x30, [sp, #0x10]
100000b1c:     	add	sp, sp, #0x20
100000b20:     	ret

0000000100000b24 <_strncmp_const>:
100000b24:     	sub	sp, sp, #0x20
100000b28:     	stp	x29, x30, [sp, #0x10]
100000b2c:     	add	x29, sp, #0x10
100000b30:     	str	x0, [sp, #0x8]
100000b34:     	ldr	x0, [sp, #0x8]
100000b38:     	adrp	x1, 0x100001000 <_read_file_head+0x124>
100000b3c:     	add	x1, x1, #0xae8
100000b40:     	mov	x2, #0x7                ; =7
100000b44:     	bl	0x100001a30 <_strncmp+0x100001a30>
100000b48:     	subs	w8, w0, #0x0
100000b4c:     	cset	w0, eq
100000b50:     	ldp	x29, x30, [sp, #0x10]
100000b54:     	add	sp, sp, #0x20
100000b58:     	ret

0000000100000b5c <_loop_zero>:
100000b5c:     	sub	sp, sp, #0x10
100000b60:     	str	x0, [sp, #0x8]
100000b64:     	str	w1, [sp, #0x4]
100000b68:     	str	wzr, [sp]
100000b6c:     	b	0x100000b70 <_loop_zero+0x14>
100000b70:     	ldr	w8, [sp]
100000b74:     	ldr	w9, [sp, #0x4]
100000b78:     	subs	w8, w8, w9
100000b7c:     	b.ge	0x100000ba8 <_loop_zero+0x4c>
100000b80:     	b	0x100000b84 <_loop_zero+0x28>
100000b84:     	ldr	x9, [sp, #0x8]
100000b88:     	ldrsw	x10, [sp]
100000b8c:     	mov	w8, #0x0                ; =0
100000b90:     	str	w8, [x9, x10, lsl #2]
100000b94:     	b	0x100000b98 <_loop_zero+0x3c>
100000b98:     	ldr	w8, [sp]
100000b9c:     	add	w8, w8, #0x1
100000ba0:     	str	w8, [sp]
100000ba4:     	b	0x100000b70 <_loop_zero+0x14>
100000ba8:     	add	sp, sp, #0x10
100000bac:     	ret

0000000100000bb0 <_loop_copy>:
100000bb0:     	sub	sp, sp, #0x20
100000bb4:     	str	x0, [sp, #0x18]
100000bb8:     	str	x1, [sp, #0x10]
100000bbc:     	str	w2, [sp, #0xc]
100000bc0:     	str	wzr, [sp, #0x8]
100000bc4:     	b	0x100000bc8 <_loop_copy+0x18>
100000bc8:     	ldr	w8, [sp, #0x8]
100000bcc:     	ldr	w9, [sp, #0xc]
100000bd0:     	subs	w8, w8, w9
100000bd4:     	b.ge	0x100000c10 <_loop_copy+0x60>
100000bd8:     	b	0x100000bdc <_loop_copy+0x2c>
100000bdc:     	ldr	x8, [sp, #0x10]
100000be0:     	ldrsw	x9, [sp, #0x8]
100000be4:     	add	x8, x8, x9
100000be8:     	ldrb	w8, [x8]
100000bec:     	ldr	x9, [sp, #0x18]
100000bf0:     	ldrsw	x10, [sp, #0x8]
100000bf4:     	add	x9, x9, x10
100000bf8:     	strb	w8, [x9]
100000bfc:     	b	0x100000c00 <_loop_copy+0x50>
100000c00:     	ldr	w8, [sp, #0x8]
100000c04:     	add	w8, w8, #0x1
100000c08:     	str	w8, [sp, #0x8]
100000c0c:     	b	0x100000bc8 <_loop_copy+0x18>
100000c10:     	add	sp, sp, #0x20
100000c14:     	ret

0000000100000c18 <_loop_strlen>:
100000c18:     	sub	sp, sp, #0x10
100000c1c:     	str	x0, [sp, #0x8]
100000c20:     	ldr	x8, [sp, #0x8]
100000c24:     	str	x8, [sp]
100000c28:     	b	0x100000c2c <_loop_strlen+0x14>
100000c2c:     	ldr	x8, [sp]
100000c30:     	ldrb	w8, [x8]
100000c34:     	cbz	w8, 0x100000c4c <_loop_strlen+0x34>
100000c38:     	b	0x100000c3c <_loop_strlen+0x24>
100000c3c:     	ldr	x8, [sp]
100000c40:     	add	x8, x8, #0x1
100000c44:     	str	x8, [sp]
100000c48:     	b	0x100000c2c <_loop_strlen+0x14>
100000c4c:     	ldr	x8, [sp]
100000c50:     	ldr	x9, [sp, #0x8]
100000c54:     	subs	x0, x8, x9
100000c58:     	add	sp, sp, #0x10
100000c5c:     	ret

0000000100000c60 <_make_big>:
100000c60:     	sub	sp, sp, #0x20
100000c64:     	str	x8, [sp, #0x8]
100000c68:     	str	x0, [sp, #0x18]
100000c6c:     	str	wzr, [sp, #0x14]
100000c70:     	b	0x100000c74 <_make_big+0x14>
100000c74:     	ldr	w8, [sp, #0x14]
100000c78:     	subs	w8, w8, #0x8
100000c7c:     	b.ge	0x100000cb0 <_make_big+0x50>
100000c80:     	b	0x100000c84 <_make_big+0x24>
100000c84:     	ldr	x9, [sp, #0x8]
100000c88:     	ldr	x8, [sp, #0x18]
100000c8c:     	ldrsw	x10, [sp, #0x14]
100000c90:     	add	x8, x8, x10
100000c94:     	ldrsw	x10, [sp, #0x14]
100000c98:     	str	x8, [x9, x10, lsl #3]
100000c9c:     	b	0x100000ca0 <_make_big+0x40>
100000ca0:     	ldr	w8, [sp, #0x14]
100000ca4:     	add	w8, w8, #0x1
100000ca8:     	str	w8, [sp, #0x14]
100000cac:     	b	0x100000c74 <_make_big+0x14>
100000cb0:     	add	sp, sp, #0x20
100000cb4:     	ret

0000000100000cb8 <_use_big>:
100000cb8:     	sub	sp, sp, #0x60
100000cbc:     	stp	x29, x30, [sp, #0x50]
100000cc0:     	add	x29, sp, #0x50
100000cc4:     	stur	x0, [x29, #-0x8]
100000cc8:     	ldur	x0, [x29, #-0x8]
100000ccc:     	add	x8, sp, #0x8
100000cd0:     	bl	0x100000c60 <_make_big>
100000cd4:     	ldr	x8, [sp, #0x20]
100000cd8:     	ldr	x9, [sp, #0x40]
100000cdc:     	add	x0, x8, x9
100000ce0:     	ldp	x29, x30, [sp, #0x50]
100000ce4:     	add	sp, sp, #0x60
100000ce8:     	ret

0000000100000cec <_make_small>:
100000cec:     	sub	sp, sp, #0x10
100000cf0:     	str	w0, [sp, #0x4]
100000cf4:     	ldr	w8, [sp, #0x4]
100000cf8:     	str	w8, [sp, #0x8]
100000cfc:     	ldr	w8, [sp, #0x4]
100000d00:     	mov	w9, #0x3                ; =3
100000d04:     	mul	w8, w8, w9
100000d08:     	str	w8, [sp, #0xc]
100000d0c:     	ldr	x0, [sp, #0x8]
100000d10:     	add	sp, sp, #0x10
100000d14:     	ret

0000000100000d18 <_sum_va>:
100000d18:     	sub	sp, sp, #0x20
100000d1c:     	str	w0, [sp, #0x1c]
100000d20:     	add	x9, sp, #0x10
100000d24:     	add	x8, sp, #0x20
100000d28:     	str	x8, [x9]
100000d2c:     	str	wzr, [sp, #0xc]
100000d30:     	str	wzr, [sp, #0x8]
100000d34:     	b	0x100000d38 <_sum_va+0x20>
100000d38:     	ldr	w8, [sp, #0x8]
100000d3c:     	ldr	w9, [sp, #0x1c]
100000d40:     	subs	w8, w8, w9
100000d44:     	b.ge	0x100000d84 <_sum_va+0x6c>
100000d48:     	b	0x100000d4c <_sum_va+0x34>
100000d4c:     	ldr	x9, [sp, #0x10]
100000d50:     	ldr	w8, [x9]
100000d54:     	add	x9, x9, #0x8
100000d58:     	str	x9, [sp, #0x10]
100000d5c:     	str	w8, [sp, #0x4]
100000d60:     	ldr	w9, [sp, #0x4]
100000d64:     	ldr	w8, [sp, #0xc]
100000d68:     	add	w8, w8, w9
100000d6c:     	str	w8, [sp, #0xc]
100000d70:     	b	0x100000d74 <_sum_va+0x5c>
100000d74:     	ldr	w8, [sp, #0x8]
100000d78:     	add	w8, w8, #0x1
100000d7c:     	str	w8, [sp, #0x8]
100000d80:     	b	0x100000d38 <_sum_va+0x20>
100000d84:     	ldr	w0, [sp, #0xc]
100000d88:     	add	sp, sp, #0x20
100000d8c:     	ret

0000000100000d90 <_ssp_copy>:
100000d90:     	sub	sp, sp, #0x70
100000d94:     	stp	x29, x30, [sp, #0x60]
100000d98:     	add	x29, sp, #0x60
100000d9c:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100000da0:     	ldr	x8, [x8, #0x20]
100000da4:     	ldr	x8, [x8]
100000da8:     	stur	x8, [x29, #-0x8]
100000dac:     	str	x0, [sp, #0x10]
100000db0:     	ldr	x1, [sp, #0x10]
100000db4:     	add	x0, sp, #0x18
100000db8:     	str	x0, [sp]
100000dbc:     	mov	x2, #0x40               ; =64
100000dc0:     	bl	0x100001a3c <_strncmp+0x100001a3c>
100000dc4:     	ldr	x0, [sp]
100000dc8:     	bl	0x100001a48 <_strncmp+0x100001a48>
100000dcc:     	mov	x8, x0
100000dd0:     	ldrsb	w9, [sp, #0x1b]
100000dd4:     	add	w8, w8, w9
100000dd8:     	str	w8, [sp, #0xc]
100000ddc:     	ldur	x9, [x29, #-0x8]
100000de0:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100000de4:     	ldr	x8, [x8, #0x20]
100000de8:     	ldr	x8, [x8]
100000dec:     	subs	x8, x8, x9
100000df0:     	b.eq	0x100000dfc <_ssp_copy+0x6c>
100000df4:     	b	0x100000df8 <_ssp_copy+0x68>
100000df8:     	bl	0x100001a54 <_strncmp+0x100001a54>
100000dfc:     	ldr	w0, [sp, #0xc]
100000e00:     	ldp	x29, x30, [sp, #0x60]
100000e04:     	add	sp, sp, #0x70
100000e08:     	ret

0000000100000e0c <_fortify_memcpy>:
100000e0c:     	sub	sp, sp, #0x60
100000e10:     	stp	x29, x30, [sp, #0x50]
100000e14:     	add	x29, sp, #0x50
100000e18:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100000e1c:     	ldr	x8, [x8, #0x20]
100000e20:     	ldr	x8, [x8]
100000e24:     	stur	x8, [x29, #-0x8]
100000e28:     	str	x0, [sp, #0x20]
100000e2c:     	str	x1, [sp, #0x18]
100000e30:     	str	x2, [sp, #0x10]
100000e34:     	ldr	x1, [sp, #0x18]
100000e38:     	ldr	x2, [sp, #0x10]
100000e3c:     	add	x0, sp, #0x28
100000e40:     	str	x0, [sp]
100000e44:     	mov	x3, #0x20               ; =32
100000e48:     	str	x3, [sp, #0x8]
100000e4c:     	bl	0x100001a0c <_strncmp+0x100001a0c>
100000e50:     	ldr	x1, [sp]
100000e54:     	ldr	x2, [sp, #0x8]
100000e58:     	ldr	x0, [sp, #0x20]
100000e5c:     	mov	x3, #-0x1               ; =-1
100000e60:     	bl	0x100001a0c <_strncmp+0x100001a0c>
100000e64:     	ldur	x9, [x29, #-0x8]
100000e68:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100000e6c:     	ldr	x8, [x8, #0x20]
100000e70:     	ldr	x8, [x8]
100000e74:     	subs	x8, x8, x9
100000e78:     	b.eq	0x100000e84 <_fortify_memcpy+0x78>
100000e7c:     	b	0x100000e80 <_fortify_memcpy+0x74>
100000e80:     	bl	0x100001a54 <_strncmp+0x100001a54>
100000e84:     	ldp	x29, x30, [sp, #0x50]
100000e88:     	add	sp, sp, #0x60
100000e8c:     	ret

0000000100000e90 <_fortify_snprintf>:
100000e90:     	sub	sp, sp, #0x30
100000e94:     	stp	x29, x30, [sp, #0x20]
100000e98:     	add	x29, sp, #0x20
100000e9c:     	stur	x0, [x29, #-0x8]
100000ea0:     	str	x1, [sp, #0x10]
100000ea4:     	str	w2, [sp, #0xc]
100000ea8:     	ldur	x0, [x29, #-0x8]
100000eac:     	ldr	x1, [sp, #0x10]
100000eb0:     	ldr	w8, [sp, #0xc]
100000eb4:     	mov	x9, sp
100000eb8:     	str	x8, [x9]
100000ebc:     	mov	w2, #0x0                ; =0
100000ec0:     	mov	x3, #-0x1               ; =-1
100000ec4:     	adrp	x4, 0x100001000 <_read_file_head+0x124>
100000ec8:     	add	x4, x4, #0xaf0
100000ecc:     	bl	0x100001a60 <_strncmp+0x100001a60>
100000ed0:     	ldp	x29, x30, [sp, #0x20]
100000ed4:     	add	sp, sp, #0x30
100000ed8:     	ret

0000000100000edc <_read_file_head>:
100000edc:     	sub	sp, sp, #0x70
100000ee0:     	stp	x29, x30, [sp, #0x60]
100000ee4:     	add	x29, sp, #0x60
100000ee8:     	stur	x0, [x29, #-0x10]
100000eec:     	stur	x1, [x29, #-0x18]
100000ef0:     	stur	x2, [x29, #-0x20]
100000ef4:     	mov	w8, #-0x1               ; =-1
100000ef8:     	stur	w8, [x29, #-0x24]
100000efc:     	ldur	x0, [x29, #-0x10]
100000f00:     	mov	w1, #0x1000000          ; =16777216
100000f04:     	bl	0x100001a6c <_strncmp+0x100001a6c>
100000f08:     	stur	w0, [x29, #-0x28]
100000f0c:     	ldur	w8, [x29, #-0x28]
100000f10:     	tbz	w8, #0x1f, 0x100000f6c <_read_file_head+0x90>
100000f14:     	b	0x100000f18 <_read_file_head+0x3c>
100000f18:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100000f1c:     	ldr	x8, [x8, #0x50]
100000f20:     	ldr	x8, [x8]
100000f24:     	str	x8, [sp, #0x20]
100000f28:     	ldur	x8, [x29, #-0x10]
100000f2c:     	str	x8, [sp, #0x18]
100000f30:     	bl	0x100001a78 <_strncmp+0x100001a78>
100000f34:     	ldr	w0, [x0]
100000f38:     	bl	0x100001a84 <_strncmp+0x100001a84>
100000f3c:     	ldr	x10, [sp, #0x18]
100000f40:     	mov	x8, x0
100000f44:     	ldr	x0, [sp, #0x20]
100000f48:     	mov	x9, sp
100000f4c:     	str	x10, [x9]
100000f50:     	str	x8, [x9, #0x8]
100000f54:     	adrp	x1, 0x100001000 <_read_file_head+0x124>
100000f58:     	add	x1, x1, #0xaf9
100000f5c:     	bl	0x100001a90 <_strncmp+0x100001a90>
100000f60:     	mov	w8, #-0x1               ; =-1
100000f64:     	stur	w8, [x29, #-0x4]
100000f68:     	b	0x100000ff8 <_read_file_head+0x11c>
100000f6c:     	ldur	x0, [x29, #-0x20]
100000f70:     	bl	0x100001a9c <_strncmp+0x100001a9c>
100000f74:     	str	x0, [sp, #0x30]
100000f78:     	ldr	x8, [sp, #0x30]
100000f7c:     	cbnz	x8, 0x100000f88 <_read_file_head+0xac>
100000f80:     	b	0x100000f84 <_read_file_head+0xa8>
100000f84:     	b	0x100000fe4 <_read_file_head+0x108>
100000f88:     	ldur	w0, [x29, #-0x28]
100000f8c:     	ldr	x1, [sp, #0x30]
100000f90:     	ldur	x2, [x29, #-0x20]
100000f94:     	bl	0x100001aa8 <_strncmp+0x100001aa8>
100000f98:     	str	x0, [sp, #0x28]
100000f9c:     	ldr	x8, [sp, #0x28]
100000fa0:     	tbz	x8, #0x3f, 0x100000fb8 <_read_file_head+0xdc>
100000fa4:     	b	0x100000fa8 <_read_file_head+0xcc>
100000fa8:     	bl	0x100001a78 <_strncmp+0x100001a78>
100000fac:     	mov	w8, #0x5                ; =5
100000fb0:     	str	w8, [x0]
100000fb4:     	b	0x100000fd8 <_read_file_head+0xfc>
100000fb8:     	ldur	x0, [x29, #-0x18]
100000fbc:     	ldr	x1, [sp, #0x30]
100000fc0:     	ldr	x2, [sp, #0x28]
100000fc4:     	mov	x3, #-0x1               ; =-1
100000fc8:     	bl	0x100001a0c <_strncmp+0x100001a0c>
100000fcc:     	ldr	x8, [sp, #0x28]
100000fd0:     	stur	w8, [x29, #-0x24]
100000fd4:     	b	0x100000fd8 <_read_file_head+0xfc>
100000fd8:     	ldr	x0, [sp, #0x30]
100000fdc:     	bl	0x100001ab4 <_strncmp+0x100001ab4>
100000fe0:     	b	0x100000fe4 <_read_file_head+0x108>
100000fe4:     	ldur	w0, [x29, #-0x28]
100000fe8:     	bl	0x100001ac0 <_strncmp+0x100001ac0>
100000fec:     	ldur	w8, [x29, #-0x24]
100000ff0:     	stur	w8, [x29, #-0x4]
100000ff4:     	b	0x100000ff8 <_read_file_head+0x11c>
100000ff8:     	ldur	w0, [x29, #-0x4]
100000ffc:     	ldp	x29, x30, [sp, #0x60]
100001000:     	add	sp, sp, #0x70
100001004:     	ret

0000000100001008 <_tail_target>:
100001008:     	sub	sp, sp, #0x10
10000100c:     	str	w0, [sp, #0xc]
100001010:     	ldr	w8, [sp, #0xc]
100001014:     	mov	w9, #0x3                ; =3
100001018:     	mul	w8, w8, w9
10000101c:     	add	w0, w8, #0x1
100001020:     	add	sp, sp, #0x10
100001024:     	ret

0000000100001028 <_tail_caller>:
100001028:     	sub	sp, sp, #0x20
10000102c:     	stp	x29, x30, [sp, #0x10]
100001030:     	add	x29, sp, #0x10
100001034:     	stur	w0, [x29, #-0x4]
100001038:     	ldur	w8, [x29, #-0x4]
10000103c:     	add	w0, w8, #0x1
100001040:     	bl	0x100001008 <_tail_target>
100001044:     	ldp	x29, x30, [sp, #0x10]
100001048:     	add	sp, sp, #0x20
10000104c:     	ret

0000000100001050 <_tail_ext>:
100001050:     	sub	sp, sp, #0x20
100001054:     	stp	x29, x30, [sp, #0x10]
100001058:     	add	x29, sp, #0x10
10000105c:     	str	x0, [sp, #0x8]
100001060:     	ldr	x8, [sp, #0x8]
100001064:     	add	x0, x8, #0x1
100001068:     	bl	0x100001acc <_strncmp+0x100001acc>
10000106c:     	ldp	x29, x30, [sp, #0x10]
100001070:     	add	sp, sp, #0x20
100001074:     	ret

0000000100001078 <_vadd>:
100001078:     	sub	sp, sp, #0x20
10000107c:     	str	x0, [sp, #0x18]
100001080:     	str	x1, [sp, #0x10]
100001084:     	str	x2, [sp, #0x8]
100001088:     	str	w3, [sp, #0x4]
10000108c:     	str	wzr, [sp]
100001090:     	b	0x100001094 <_vadd+0x1c>
100001094:     	ldr	w8, [sp]
100001098:     	ldr	w9, [sp, #0x4]
10000109c:     	subs	w8, w8, w9
1000010a0:     	b.ge	0x1000010e4 <_vadd+0x6c>
1000010a4:     	b	0x1000010a8 <_vadd+0x30>
1000010a8:     	ldr	x8, [sp, #0x10]
1000010ac:     	ldrsw	x9, [sp]
1000010b0:     	ldr	w8, [x8, x9, lsl #2]
1000010b4:     	ldr	x9, [sp, #0x8]
1000010b8:     	ldrsw	x10, [sp]
1000010bc:     	ldr	w9, [x9, x10, lsl #2]
1000010c0:     	add	w8, w8, w9
1000010c4:     	ldr	x9, [sp, #0x18]
1000010c8:     	ldrsw	x10, [sp]
1000010cc:     	str	w8, [x9, x10, lsl #2]
1000010d0:     	b	0x1000010d4 <_vadd+0x5c>
1000010d4:     	ldr	w8, [sp]
1000010d8:     	add	w8, w8, #0x1
1000010dc:     	str	w8, [sp]
1000010e0:     	b	0x100001094 <_vadd+0x1c>
1000010e4:     	add	sp, sp, #0x20
1000010e8:     	ret

00000001000010ec <_vsum>:
1000010ec:     	sub	sp, sp, #0x20
1000010f0:     	str	x0, [sp, #0x18]
1000010f4:     	str	w1, [sp, #0x14]
1000010f8:     	str	wzr, [sp, #0x10]
1000010fc:     	str	wzr, [sp, #0xc]
100001100:     	b	0x100001104 <_vsum+0x18>
100001104:     	ldr	w8, [sp, #0xc]
100001108:     	ldr	w9, [sp, #0x14]
10000110c:     	subs	w8, w8, w9
100001110:     	b.ge	0x100001144 <_vsum+0x58>
100001114:     	b	0x100001118 <_vsum+0x2c>
100001118:     	ldr	x8, [sp, #0x18]
10000111c:     	ldrsw	x9, [sp, #0xc]
100001120:     	ldr	w9, [x8, x9, lsl #2]
100001124:     	ldr	w8, [sp, #0x10]
100001128:     	add	w8, w8, w9
10000112c:     	str	w8, [sp, #0x10]
100001130:     	b	0x100001134 <_vsum+0x48>
100001134:     	ldr	w8, [sp, #0xc]
100001138:     	add	w8, w8, #0x1
10000113c:     	str	w8, [sp, #0xc]
100001140:     	b	0x100001104 <_vsum+0x18>
100001144:     	ldr	w0, [sp, #0x10]
100001148:     	add	sp, sp, #0x20
10000114c:     	ret

0000000100001150 <_vdot>:
100001150:     	sub	sp, sp, #0x20
100001154:     	str	x0, [sp, #0x18]
100001158:     	str	x1, [sp, #0x10]
10000115c:     	str	w2, [sp, #0xc]
100001160:     	movi.2d	v0, #0000000000000000
100001164:     	str	s0, [sp, #0x8]
100001168:     	str	wzr, [sp, #0x4]
10000116c:     	b	0x100001170 <_vdot+0x20>
100001170:     	ldr	w8, [sp, #0x4]
100001174:     	ldr	w9, [sp, #0xc]
100001178:     	subs	w8, w8, w9
10000117c:     	b.ge	0x1000011bc <_vdot+0x6c>
100001180:     	b	0x100001184 <_vdot+0x34>
100001184:     	ldr	x8, [sp, #0x18]
100001188:     	ldrsw	x9, [sp, #0x4]
10000118c:     	ldr	s0, [x8, x9, lsl #2]
100001190:     	ldr	x8, [sp, #0x10]
100001194:     	ldrsw	x9, [sp, #0x4]
100001198:     	ldr	s1, [x8, x9, lsl #2]
10000119c:     	ldr	s2, [sp, #0x8]
1000011a0:     	fmadd	s0, s0, s1, s2
1000011a4:     	str	s0, [sp, #0x8]
1000011a8:     	b	0x1000011ac <_vdot+0x5c>
1000011ac:     	ldr	w8, [sp, #0x4]
1000011b0:     	add	w8, w8, #0x1
1000011b4:     	str	w8, [sp, #0x4]
1000011b8:     	b	0x100001170 <_vdot+0x20>
1000011bc:     	ldr	s0, [sp, #0x8]
1000011c0:     	add	sp, sp, #0x20
1000011c4:     	ret

00000001000011c8 <_md5_init>:
1000011c8:     	sub	sp, sp, #0x10
1000011cc:     	str	x0, [sp, #0x8]
1000011d0:     	ldr	x9, [sp, #0x8]
1000011d4:     	mov	w8, #0x2301             ; =8961
1000011d8:     	movk	w8, #0x6745, lsl #16
1000011dc:     	str	w8, [x9]
1000011e0:     	ldr	x9, [sp, #0x8]
1000011e4:     	mov	w8, #0xab89             ; =43913
1000011e8:     	movk	w8, #0xefcd, lsl #16
1000011ec:     	str	w8, [x9, #0x4]
1000011f0:     	ldr	x9, [sp, #0x8]
1000011f4:     	mov	w8, #0xdcfe             ; =56574
1000011f8:     	movk	w8, #0x98ba, lsl #16
1000011fc:     	str	w8, [x9, #0x8]
100001200:     	ldr	x9, [sp, #0x8]
100001204:     	mov	w8, #0x5476             ; =21622
100001208:     	movk	w8, #0x1032, lsl #16
10000120c:     	str	w8, [x9, #0xc]
100001210:     	add	sp, sp, #0x10
100001214:     	ret

0000000100001218 <_crc32_make_table>:
100001218:     	sub	sp, sp, #0x10
10000121c:     	str	wzr, [sp, #0xc]
100001220:     	b	0x100001224 <_crc32_make_table+0xc>
100001224:     	ldr	w8, [sp, #0xc]
100001228:     	subs	w8, w8, #0x100
10000122c:     	b.hs	0x1000012d0 <_crc32_make_table+0xb8>
100001230:     	b	0x100001234 <_crc32_make_table+0x1c>
100001234:     	ldr	w8, [sp, #0xc]
100001238:     	str	w8, [sp, #0x8]
10000123c:     	str	wzr, [sp, #0x4]
100001240:     	b	0x100001244 <_crc32_make_table+0x2c>
100001244:     	ldr	w8, [sp, #0x4]
100001248:     	subs	w8, w8, #0x8
10000124c:     	b.ge	0x1000012a4 <_crc32_make_table+0x8c>
100001250:     	b	0x100001254 <_crc32_make_table+0x3c>
100001254:     	ldr	w8, [sp, #0x8]
100001258:     	tbz	w8, #0x0, 0x100001278 <_crc32_make_table+0x60>
10000125c:     	b	0x100001260 <_crc32_make_table+0x48>
100001260:     	ldr	w9, [sp, #0x8]
100001264:     	mov	w8, #0x8320             ; =33568
100001268:     	movk	w8, #0xedb8, lsl #16
10000126c:     	eor	w8, w8, w9, lsr #1
100001270:     	str	w8, [sp]
100001274:     	b	0x100001288 <_crc32_make_table+0x70>
100001278:     	ldr	w8, [sp, #0x8]
10000127c:     	lsr	w8, w8, #1
100001280:     	str	w8, [sp]
100001284:     	b	0x100001288 <_crc32_make_table+0x70>
100001288:     	ldr	w8, [sp]
10000128c:     	str	w8, [sp, #0x8]
100001290:     	b	0x100001294 <_crc32_make_table+0x7c>
100001294:     	ldr	w8, [sp, #0x4]
100001298:     	add	w8, w8, #0x1
10000129c:     	str	w8, [sp, #0x4]
1000012a0:     	b	0x100001244 <_crc32_make_table+0x2c>
1000012a4:     	ldr	w8, [sp, #0x8]
1000012a8:     	ldr	w9, [sp, #0xc]
1000012ac:     	mov	x10, x9
1000012b0:     	adrp	x9, 0x100008000 <_crc_table>
1000012b4:     	add	x9, x9, #0x0
1000012b8:     	str	w8, [x9, x10, lsl #2]
1000012bc:     	b	0x1000012c0 <_crc32_make_table+0xa8>
1000012c0:     	ldr	w8, [sp, #0xc]
1000012c4:     	add	w8, w8, #0x1
1000012c8:     	str	w8, [sp, #0xc]
1000012cc:     	b	0x100001224 <_crc32_make_table+0xc>
1000012d0:     	add	sp, sp, #0x10
1000012d4:     	ret

00000001000012d8 <_crc32_buf>:
1000012d8:     	sub	sp, sp, #0x20
1000012dc:     	str	x0, [sp, #0x18]
1000012e0:     	str	x1, [sp, #0x10]
1000012e4:     	mov	w8, #-0x1               ; =-1
1000012e8:     	str	w8, [sp, #0xc]
1000012ec:     	b	0x1000012f0 <_crc32_buf+0x18>
1000012f0:     	ldr	x8, [sp, #0x10]
1000012f4:     	subs	x9, x8, #0x1
1000012f8:     	str	x9, [sp, #0x10]
1000012fc:     	cbz	x8, 0x10000133c <_crc32_buf+0x64>
100001300:     	b	0x100001304 <_crc32_buf+0x2c>
100001304:     	ldr	w8, [sp, #0xc]
100001308:     	ldr	x9, [sp, #0x18]
10000130c:     	add	x10, x9, #0x1
100001310:     	str	x10, [sp, #0x18]
100001314:     	ldrb	w9, [x9]
100001318:     	eor	w8, w8, w9
10000131c:     	and	w9, w8, #0xff
100001320:     	adrp	x8, 0x100008000 <_crc_table>
100001324:     	add	x8, x8, #0x0
100001328:     	ldr	w8, [x8, w9, uxtw #2]
10000132c:     	ldr	w9, [sp, #0xc]
100001330:     	eor	w8, w8, w9, lsr #8
100001334:     	str	w8, [sp, #0xc]
100001338:     	b	0x1000012f0 <_crc32_buf+0x18>
10000133c:     	ldr	w8, [sp, #0xc]
100001340:     	mvn	w0, w8
100001344:     	add	sp, sp, #0x20
100001348:     	ret

000000010000134c <_tea_encrypt>:
10000134c:     	sub	sp, sp, #0x30
100001350:     	str	x0, [sp, #0x28]
100001354:     	str	x1, [sp, #0x20]
100001358:     	ldr	x8, [sp, #0x28]
10000135c:     	ldr	w8, [x8]
100001360:     	str	w8, [sp, #0x1c]
100001364:     	ldr	x8, [sp, #0x28]
100001368:     	ldr	w8, [x8, #0x4]
10000136c:     	str	w8, [sp, #0x18]
100001370:     	str	wzr, [sp, #0x14]
100001374:     	mov	w8, #0x79b9             ; =31161
100001378:     	movk	w8, #0x9e37, lsl #16
10000137c:     	str	w8, [sp, #0x10]
100001380:     	str	wzr, [sp, #0xc]
100001384:     	b	0x100001388 <_tea_encrypt+0x3c>
100001388:     	ldr	w8, [sp, #0xc]
10000138c:     	subs	w8, w8, #0x20
100001390:     	b.ge	0x10000143c <_tea_encrypt+0xf0>
100001394:     	b	0x100001398 <_tea_encrypt+0x4c>
100001398:     	ldr	w9, [sp, #0x10]
10000139c:     	ldr	w8, [sp, #0x14]
1000013a0:     	add	w8, w8, w9
1000013a4:     	str	w8, [sp, #0x14]
1000013a8:     	ldr	w9, [sp, #0x18]
1000013ac:     	ldr	x8, [sp, #0x20]
1000013b0:     	ldr	w8, [x8]
1000013b4:     	add	w8, w8, w9, lsl #4
1000013b8:     	ldr	w9, [sp, #0x18]
1000013bc:     	ldr	w10, [sp, #0x14]
1000013c0:     	add	w9, w9, w10
1000013c4:     	eor	w8, w8, w9
1000013c8:     	ldr	w10, [sp, #0x18]
1000013cc:     	ldr	x9, [sp, #0x20]
1000013d0:     	ldr	w9, [x9, #0x4]
1000013d4:     	add	w9, w9, w10, lsr #5
1000013d8:     	eor	w9, w8, w9
1000013dc:     	ldr	w8, [sp, #0x1c]
1000013e0:     	add	w8, w8, w9
1000013e4:     	str	w8, [sp, #0x1c]
1000013e8:     	ldr	w9, [sp, #0x1c]
1000013ec:     	ldr	x8, [sp, #0x20]
1000013f0:     	ldr	w8, [x8, #0x8]
1000013f4:     	add	w8, w8, w9, lsl #4
1000013f8:     	ldr	w9, [sp, #0x1c]
1000013fc:     	ldr	w10, [sp, #0x14]
100001400:     	add	w9, w9, w10
100001404:     	eor	w8, w8, w9
100001408:     	ldr	w10, [sp, #0x1c]
10000140c:     	ldr	x9, [sp, #0x20]
100001410:     	ldr	w9, [x9, #0xc]
100001414:     	add	w9, w9, w10, lsr #5
100001418:     	eor	w9, w8, w9
10000141c:     	ldr	w8, [sp, #0x18]
100001420:     	add	w8, w8, w9
100001424:     	str	w8, [sp, #0x18]
100001428:     	b	0x10000142c <_tea_encrypt+0xe0>
10000142c:     	ldr	w8, [sp, #0xc]
100001430:     	add	w8, w8, #0x1
100001434:     	str	w8, [sp, #0xc]
100001438:     	b	0x100001388 <_tea_encrypt+0x3c>
10000143c:     	ldr	w8, [sp, #0x1c]
100001440:     	ldr	x9, [sp, #0x28]
100001444:     	str	w8, [x9]
100001448:     	ldr	w8, [sp, #0x18]
10000144c:     	ldr	x9, [sp, #0x28]
100001450:     	str	w8, [x9, #0x4]
100001454:     	add	sp, sp, #0x30
100001458:     	ret

000000010000145c <_main>:
10000145c:     	stp	x28, x27, [sp, #-0x20]!
100001460:     	stp	x29, x30, [sp, #0x10]
100001464:     	add	x29, sp, #0x10
100001468:     	sub	sp, sp, #0x6d0
10000146c:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
100001470:     	ldr	x8, [x8, #0x20]
100001474:     	ldr	x8, [x8]
100001478:     	stur	x8, [x29, #-0x18]
10000147c:     	str	wzr, [sp, #0x11c]
100001480:     	str	w0, [sp, #0x118]
100001484:     	str	x1, [sp, #0x110]
100001488:     	ldr	w8, [sp, #0x118]
10000148c:     	subs	w8, w8, #0x1
100001490:     	b.le	0x1000014ac <_main+0x50>
100001494:     	b	0x100001498 <_main+0x3c>
100001498:     	ldr	x8, [sp, #0x110]
10000149c:     	ldr	x0, [x8, #0x8]
1000014a0:     	bl	0x100001acc <_strncmp+0x100001acc>
1000014a4:     	str	w0, [sp, #0xc4]
1000014a8:     	b	0x1000014b8 <_main+0x5c>
1000014ac:     	mov	w8, #0x3                ; =3
1000014b0:     	str	w8, [sp, #0xc4]
1000014b4:     	b	0x1000014b8 <_main+0x5c>
1000014b8:     	ldr	w8, [sp, #0xc4]
1000014bc:     	str	w8, [sp, #0x10c]
1000014c0:     	ldr	w8, [sp, #0x118]
1000014c4:     	subs	w8, w8, #0x2
1000014c8:     	b.le	0x1000014e0 <_main+0x84>
1000014cc:     	b	0x1000014d0 <_main+0x74>
1000014d0:     	ldr	x8, [sp, #0x110]
1000014d4:     	ldr	x8, [x8, #0x10]
1000014d8:     	str	x8, [sp, #0xb8]
1000014dc:     	b	0x1000014f0 <_main+0x94>
1000014e0:     	adrp	x8, 0x100001000 <_read_file_head+0x124>
1000014e4:     	add	x8, x8, #0xae4
1000014e8:     	str	x8, [sp, #0xb8]
1000014ec:     	b	0x1000014f0 <_main+0x94>
1000014f0:     	ldr	x8, [sp, #0xb8]
1000014f4:     	str	x8, [sp, #0x100]
1000014f8:     	str	wzr, [sp, #0xfc]
1000014fc:     	b	0x100001500 <_main+0xa4>
100001500:     	ldr	w8, [sp, #0xfc]
100001504:     	subs	w8, w8, #0x40
100001508:     	b.ge	0x10000157c <_main+0x120>
10000150c:     	b	0x100001510 <_main+0xb4>
100001510:     	ldr	w8, [sp, #0xfc]
100001514:     	ldr	w9, [sp, #0x10c]
100001518:     	eor	w8, w8, w9
10000151c:     	ldrsw	x10, [sp, #0xfc]
100001520:     	add	x9, sp, #0x448
100001524:     	str	w8, [x9, x10, lsl #2]
100001528:     	ldr	w8, [sp, #0xfc]
10000152c:     	ldr	w9, [sp, #0x10c]
100001530:     	add	w8, w8, w9
100001534:     	ldrsw	x10, [sp, #0xfc]
100001538:     	add	x9, sp, #0x348
10000153c:     	str	w8, [x9, x10, lsl #2]
100001540:     	ldr	s0, [sp, #0xfc]
100001544:     	scvtf	s0, s0
100001548:     	ldrsw	x9, [sp, #0xfc]
10000154c:     	add	x8, sp, #0x248
100001550:     	str	s0, [x8, x9, lsl #2]
100001554:     	ldr	s0, [sp, #0x10c]
100001558:     	scvtf	s0, s0
10000155c:     	ldrsw	x9, [sp, #0xfc]
100001560:     	add	x8, sp, #0x148
100001564:     	str	s0, [x8, x9, lsl #2]
100001568:     	b	0x10000156c <_main+0x110>
10000156c:     	ldr	w8, [sp, #0xfc]
100001570:     	add	w8, w8, #0x1
100001574:     	str	w8, [sp, #0xfc]
100001578:     	b	0x100001500 <_main+0xa4>
10000157c:     	str	xzr, [sp, #0xf0]
100001580:     	ldr	w0, [sp, #0x10c]
100001584:     	bl	0x100000548 <_sw_dense>
100001588:     	str	w0, [sp, #0x44]
10000158c:     	ldr	w0, [sp, #0x10c]
100001590:     	bl	0x100000648 <_sw_sparse>
100001594:     	mov	x8, x0
100001598:     	ldr	w0, [sp, #0x44]
10000159c:     	add	w8, w0, w8
1000015a0:     	str	w8, [sp, #0x48]
1000015a4:     	ldr	w0, [sp, #0x10c]
1000015a8:     	bl	0x100000744 <_sw_bittest>
1000015ac:     	ldr	w8, [sp, #0x48]
1000015b0:     	add	w9, w8, w0
1000015b4:     	ldr	x8, [sp, #0xf0]
1000015b8:     	add	x8, x8, w9, sxtw
1000015bc:     	str	x8, [sp, #0xf0]
1000015c0:     	ldr	w0, [sp, #0x10c]
1000015c4:     	bl	0x1000007b4 <_udiv7>
1000015c8:     	str	w0, [sp, #0x4c]
1000015cc:     	ldr	w0, [sp, #0x10c]
1000015d0:     	bl	0x1000007d0 <_sdiv7>
1000015d4:     	mov	x8, x0
1000015d8:     	ldr	w0, [sp, #0x4c]
1000015dc:     	add	w8, w0, w8
1000015e0:     	str	w8, [sp, #0x50]
1000015e4:     	ldr	w0, [sp, #0x10c]
1000015e8:     	bl	0x1000007ec <_umod10>
1000015ec:     	ldr	w8, [sp, #0x50]
1000015f0:     	add	w8, w8, w0
1000015f4:     	str	w8, [sp, #0x54]
1000015f8:     	ldr	w0, [sp, #0x10c]
1000015fc:     	bl	0x100000810 <_sdiv16>
100001600:     	ldr	w8, [sp, #0x54]
100001604:     	add	w8, w8, w0
100001608:     	mov	w8, w8
10000160c:     	str	x8, [sp, #0x58]
100001610:     	ldrsw	x0, [sp, #0x10c]
100001614:     	bl	0x10000082c <_udiv1000_64>
100001618:     	ldr	x8, [sp, #0x58]
10000161c:     	add	x9, x8, x0
100001620:     	ldr	x8, [sp, #0xf0]
100001624:     	add	x8, x8, x9
100001628:     	str	x8, [sp, #0xf0]
10000162c:     	ldr	w0, [sp, #0x10c]
100001630:     	mov	w1, #0x5                ; =5
100001634:     	bl	0x100000848 <_sel_max>
100001638:     	str	w0, [sp, #0x64]
10000163c:     	ldr	w0, [sp, #0x10c]
100001640:     	bl	0x10000088c <_sel_abs>
100001644:     	mov	x8, x0
100001648:     	ldr	w0, [sp, #0x64]
10000164c:     	add	w8, w0, w8
100001650:     	str	w8, [sp, #0x68]
100001654:     	ldr	w0, [sp, #0x10c]
100001658:     	mov	w1, #0x0                ; =0
10000165c:     	mov	w2, #0x9                ; =9
100001660:     	bl	0x1000008cc <_sel_clamp>
100001664:     	ldr	w8, [sp, #0x68]
100001668:     	add	w8, w8, w0
10000166c:     	str	w8, [sp, #0x6c]
100001670:     	ldr	w0, [sp, #0x10c]
100001674:     	bl	0x100000940 <_popcount_loop>
100001678:     	ldr	w8, [sp, #0x6c]
10000167c:     	add	w9, w8, w0
100001680:     	ldr	x8, [sp, #0xf0]
100001684:     	add	x8, x8, w9, sxtw
100001688:     	str	x8, [sp, #0xf0]
10000168c:     	ldr	w0, [sp, #0x10c]
100001690:     	bl	0x10000098c <_bswap32_manual>
100001694:     	str	w0, [sp, #0x70]
100001698:     	ldr	w0, [sp, #0x10c]
10000169c:     	ldr	w1, [sp, #0x10c]
1000016a0:     	bl	0x1000009c8 <_rotl32>
1000016a4:     	mov	x8, x0
1000016a8:     	ldr	w0, [sp, #0x70]
1000016ac:     	add	w8, w0, w8
1000016b0:     	str	w8, [sp, #0x74]
1000016b4:     	ldr	w0, [sp, #0x10c]
1000016b8:     	bl	0x100000a08 <_is_pow2>
1000016bc:     	ldr	w8, [sp, #0x74]
1000016c0:     	add	w8, w8, w0
1000016c4:     	mov	w8, w8
1000016c8:     	mov	x9, x8
1000016cc:     	ldr	x8, [sp, #0xf0]
1000016d0:     	add	x8, x8, x9
1000016d4:     	str	x8, [sp, #0xf0]
1000016d8:     	ldr	w8, [sp, #0x10c]
1000016dc:     	add	x1, sp, #0xe0
1000016e0:     	str	w8, [sp, #0xe0]
1000016e4:     	mov	w8, #0x1                ; =1
1000016e8:     	str	w8, [sp, #0xe4]
1000016ec:     	mov	w8, #0x2                ; =2
1000016f0:     	str	w8, [sp, #0xe8]
1000016f4:     	mov	w8, #0x3                ; =3
1000016f8:     	str	w8, [sp, #0x9c]
1000016fc:     	str	w8, [sp, #0xec]
100001700:     	add	x0, sp, #0xd0
100001704:     	bl	0x100000a50 <_copy16>
100001708:     	ldrsw	x9, [sp, #0xdc]
10000170c:     	ldr	x8, [sp, #0xf0]
100001710:     	add	x8, x8, x9
100001714:     	str	x8, [sp, #0xf0]
100001718:     	sub	x0, x29, #0x98
10000171c:     	str	x0, [sp, #0xb0]
100001720:     	bl	0x100000a84 <_zero64>
100001724:     	ldr	x0, [sp, #0xb0]
100001728:     	ldrsw	x8, [sp, #0x10c]
10000172c:     	and	x1, x8, #0x3f
100001730:     	bl	0x100000ab4 <_zero_n>
100001734:     	bl	0x100000ae8 <_strlen_const>
100001738:     	str	x0, [sp, #0x78]
10000173c:     	ldr	x0, [sp, #0x100]
100001740:     	bl	0x100000af0 <_strcmp_const>
100001744:     	mov	x8, x0
100001748:     	ldr	x0, [sp, #0x78]
10000174c:     	add	x8, x0, w8, sxtw
100001750:     	str	x8, [sp, #0x80]
100001754:     	ldr	x0, [sp, #0x100]
100001758:     	bl	0x100000b24 <_strncmp_const>
10000175c:     	ldr	x8, [sp, #0x80]
100001760:     	add	x9, x8, w0, sxtw
100001764:     	ldr	x8, [sp, #0xf0]
100001768:     	add	x8, x8, x9
10000176c:     	str	x8, [sp, #0xf0]
100001770:     	ldr	w8, [sp, #0x10c]
100001774:     	and	w1, w8, #0x3f
100001778:     	add	x0, sp, #0x548
10000177c:     	bl	0x100000b5c <_loop_zero>
100001780:     	ldr	x8, [sp, #0x100]
100001784:     	str	x8, [sp, #0x88]
100001788:     	ldr	x0, [sp, #0x100]
10000178c:     	bl	0x100001a48 <_strncmp+0x100001a48>
100001790:     	ldr	x1, [sp, #0x88]
100001794:     	mov	x8, x0
100001798:     	ldr	x0, [sp, #0xb0]
10000179c:     	mov	x2, x8
1000017a0:     	bl	0x100000bb0 <_loop_copy>
1000017a4:     	ldr	x0, [sp, #0x100]
1000017a8:     	bl	0x100000c18 <_loop_strlen>
1000017ac:     	ldr	x8, [sp, #0xf0]
1000017b0:     	add	x8, x8, x0
1000017b4:     	str	x8, [sp, #0xf0]
1000017b8:     	ldrsw	x0, [sp, #0x10c]
1000017bc:     	bl	0x100000cb8 <_use_big>
1000017c0:     	str	x0, [sp, #0x90]
1000017c4:     	ldr	w0, [sp, #0x10c]
1000017c8:     	bl	0x100000cec <_make_small>
1000017cc:     	ldr	x8, [sp, #0x90]
1000017d0:     	mov	x9, x0
1000017d4:     	ldr	w0, [sp, #0x9c]
1000017d8:     	str	x9, [sp, #0xc8]
1000017dc:     	ldrsw	x9, [sp, #0xcc]
1000017e0:     	add	x8, x8, x9
1000017e4:     	str	x8, [sp, #0xa0]
1000017e8:     	ldr	w8, [sp, #0x10c]
1000017ec:     	ldr	w9, [sp, #0x10c]
1000017f0:     	add	w11, w9, #0x1
1000017f4:     	ldr	w9, [sp, #0x10c]
1000017f8:     	add	w10, w9, #0x2
1000017fc:     	mov	x9, sp
100001800:     	str	x8, [x9]
100001804:     	mov	x8, x11
100001808:     	str	x8, [x9, #0x8]
10000180c:     	mov	x8, x10
100001810:     	str	x8, [x9, #0x10]
100001814:     	bl	0x100000d18 <_sum_va>
100001818:     	ldr	x8, [sp, #0xa0]
10000181c:     	add	x9, x8, w0, sxtw
100001820:     	ldr	x8, [sp, #0xf0]
100001824:     	add	x8, x8, x9
100001828:     	str	x8, [sp, #0xf0]
10000182c:     	ldr	x0, [sp, #0x100]
100001830:     	bl	0x100000d90 <_ssp_copy>
100001834:     	ldr	x8, [sp, #0xf0]
100001838:     	add	x8, x8, w0, sxtw
10000183c:     	str	x8, [sp, #0xf0]
100001840:     	ldr	x8, [sp, #0x100]
100001844:     	str	x8, [sp, #0xa8]
100001848:     	ldr	x0, [sp, #0x100]
10000184c:     	bl	0x100001a48 <_strncmp+0x100001a48>
100001850:     	ldr	x1, [sp, #0xa8]
100001854:     	mov	x8, x0
100001858:     	ldr	x0, [sp, #0xb0]
10000185c:     	and	x2, x8, #0x1f
100001860:     	bl	0x100000e0c <_fortify_memcpy>
100001864:     	ldr	x0, [sp, #0xb0]
100001868:     	ldr	w2, [sp, #0x10c]
10000186c:     	mov	x1, #0x80               ; =128
100001870:     	bl	0x100000e90 <_fortify_snprintf>
100001874:     	ldr	x8, [sp, #0xf0]
100001878:     	add	x8, x8, w0, sxtw
10000187c:     	str	x8, [sp, #0xf0]
100001880:     	ldr	w8, [sp, #0x118]
100001884:     	subs	w8, w8, #0x3
100001888:     	b.le	0x1000018a0 <_main+0x444>
10000188c:     	b	0x100001890 <_main+0x434>
100001890:     	ldr	x8, [sp, #0x110]
100001894:     	ldr	x8, [x8, #0x18]
100001898:     	str	x8, [sp, #0x38]
10000189c:     	b	0x1000018b0 <_main+0x454>
1000018a0:     	adrp	x8, 0x100001000 <_read_file_head+0x124>
1000018a4:     	add	x8, x8, #0xb06
1000018a8:     	str	x8, [sp, #0x38]
1000018ac:     	b	0x1000018b0 <_main+0x454>
1000018b0:     	ldr	x0, [sp, #0x38]
1000018b4:     	sub	x1, x29, #0x98
1000018b8:     	mov	x2, #0x80               ; =128
1000018bc:     	bl	0x100000edc <_read_file_head>
1000018c0:     	ldr	x8, [sp, #0xf0]
1000018c4:     	add	x8, x8, w0, sxtw
1000018c8:     	str	x8, [sp, #0xf0]
1000018cc:     	ldr	w0, [sp, #0x10c]
1000018d0:     	bl	0x100001028 <_tail_caller>
1000018d4:     	str	w0, [sp, #0x1c]
1000018d8:     	ldr	x0, [sp, #0x100]
1000018dc:     	bl	0x100001050 <_tail_ext>
1000018e0:     	mov	x8, x0
1000018e4:     	ldr	w0, [sp, #0x1c]
1000018e8:     	add	w9, w0, w8
1000018ec:     	ldr	x8, [sp, #0xf0]
1000018f0:     	add	x8, x8, w9, sxtw
1000018f4:     	str	x8, [sp, #0xf0]
1000018f8:     	add	x0, sp, #0x548
1000018fc:     	str	x0, [sp, #0x20]
100001900:     	add	x1, sp, #0x448
100001904:     	add	x2, sp, #0x348
100001908:     	mov	w3, #0x40               ; =64
10000190c:     	str	w3, [sp, #0x28]
100001910:     	bl	0x100001078 <_vadd>
100001914:     	ldr	x0, [sp, #0x20]
100001918:     	ldr	w1, [sp, #0x28]
10000191c:     	bl	0x1000010ec <_vsum>
100001920:     	ldr	w2, [sp, #0x28]
100001924:     	str	w0, [sp, #0x2c]
100001928:     	add	x0, sp, #0x248
10000192c:     	add	x1, sp, #0x148
100001930:     	bl	0x100001150 <_vdot>
100001934:     	ldr	w0, [sp, #0x2c]
100001938:     	fcvtzs	x8, s0
10000193c:     	add	x9, x8, w0, sxtw
100001940:     	ldr	x8, [sp, #0xf0]
100001944:     	add	x8, x8, x9
100001948:     	str	x8, [sp, #0xf0]
10000194c:     	add	x0, sp, #0x138
100001950:     	bl	0x1000011c8 <_md5_init>
100001954:     	bl	0x100001218 <_crc32_make_table>
100001958:     	ldr	x8, [sp, #0x100]
10000195c:     	str	x8, [sp, #0x30]
100001960:     	ldr	x0, [sp, #0x100]
100001964:     	bl	0x100001a48 <_strncmp+0x100001a48>
100001968:     	mov	x1, x0
10000196c:     	ldr	x0, [sp, #0x30]
100001970:     	bl	0x1000012d8 <_crc32_buf>
100001974:     	ldr	x8, [sp, #0xf0]
100001978:     	add	x8, x8, w0, uxtw
10000197c:     	str	x8, [sp, #0xf0]
100001980:     	ldr	w8, [sp, #0x138]
100001984:     	add	x0, sp, #0x130
100001988:     	str	w8, [sp, #0x130]
10000198c:     	ldr	w8, [sp, #0x13c]
100001990:     	str	w8, [sp, #0x134]
100001994:     	adrp	x8, 0x100001000 <_read_file_head+0x124>
100001998:     	add	x8, x8, #0xb20
10000199c:     	ldr	q0, [x8]
1000019a0:     	add	x1, sp, #0x120
1000019a4:     	str	q0, [sp, #0x120]
1000019a8:     	bl	0x10000134c <_tea_encrypt>
1000019ac:     	ldr	w8, [sp, #0x130]
1000019b0:     	mov	x9, x8
1000019b4:     	ldr	x8, [sp, #0xf0]
1000019b8:     	add	x8, x8, x9
1000019bc:     	str	x8, [sp, #0xf0]
1000019c0:     	ldr	x8, [sp, #0xf0]
1000019c4:     	mov	x9, sp
1000019c8:     	str	x8, [x9]
1000019cc:     	adrp	x0, 0x100001000 <_read_file_head+0x124>
1000019d0:     	add	x0, x0, #0xb11
1000019d4:     	bl	0x100001ad8 <_strncmp+0x100001ad8>
1000019d8:     	ldur	x9, [x29, #-0x18]
1000019dc:     	adrp	x8, 0x100004000 <_strncmp+0x100004000>
1000019e0:     	ldr	x8, [x8, #0x20]
1000019e4:     	ldr	x8, [x8]
1000019e8:     	subs	x8, x8, x9
1000019ec:     	b.eq	0x1000019f8 <_main+0x59c>
1000019f0:     	b	0x1000019f4 <_main+0x598>
1000019f4:     	bl	0x100001a54 <_strncmp+0x100001a54>
1000019f8:     	mov	w0, #0x0                ; =0
1000019fc:     	add	sp, sp, #0x6d0
100001a00:     	ldp	x29, x30, [sp, #0x10]
100001a04:     	ldp	x28, x27, [sp], #0x20
100001a08:     	ret

Disassembly of section __TEXT,__stubs:

0000000100001a0c <__stubs>:
100001a0c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a10:     	ldr	x16, [x16]
100001a14:     	br	x16
100001a18:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a1c:     	ldr	x16, [x16, #0x8]
100001a20:     	br	x16
100001a24:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a28:     	ldr	x16, [x16, #0x10]
100001a2c:     	br	x16
100001a30:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a34:     	ldr	x16, [x16, #0x18]
100001a38:     	br	x16
100001a3c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a40:     	ldr	x16, [x16, #0x28]
100001a44:     	br	x16
100001a48:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a4c:     	ldr	x16, [x16, #0x30]
100001a50:     	br	x16
100001a54:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a58:     	ldr	x16, [x16, #0x38]
100001a5c:     	br	x16
100001a60:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a64:     	ldr	x16, [x16, #0x40]
100001a68:     	br	x16
100001a6c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a70:     	ldr	x16, [x16, #0x48]
100001a74:     	br	x16
100001a78:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a7c:     	ldr	x16, [x16, #0x58]
100001a80:     	br	x16
100001a84:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a88:     	ldr	x16, [x16, #0x60]
100001a8c:     	br	x16
100001a90:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001a94:     	ldr	x16, [x16, #0x68]
100001a98:     	br	x16
100001a9c:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001aa0:     	ldr	x16, [x16, #0x70]
100001aa4:     	br	x16
100001aa8:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001aac:     	ldr	x16, [x16, #0x78]
100001ab0:     	br	x16
100001ab4:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001ab8:     	ldr	x16, [x16, #0x80]
100001abc:     	br	x16
100001ac0:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001ac4:     	ldr	x16, [x16, #0x88]
100001ac8:     	br	x16
100001acc:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001ad0:     	ldr	x16, [x16, #0x90]
100001ad4:     	br	x16
100001ad8:     	adrp	x16, 0x100004000 <_strncmp+0x100004000>
100001adc:     	ldr	x16, [x16, #0x98]
100001ae0:     	br	x16
