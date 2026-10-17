
bin/k_x86_64_O0:	file format mach-o 64-bit x86-64

Disassembly of section __TEXT,__text:

0000000100000560 <_sw_dense>:
100000560:     	pushq	%rbp
100000561:     	movq	%rsp, %rbp
100000564:     	movl	%edi, -0x8(%rbp)
100000567:     	movl	-0x8(%rbp), %eax
10000056a:     	movq	%rax, -0x10(%rbp)
10000056e:     	subq	$0x7, %rax
100000572:     	ja	0x1000005d0 <_sw_dense+0x70>
100000574:     	movq	-0x10(%rbp), %rcx
100000578:     	leaq	0x5d(%rip), %rax        ## 0x1000005dc <_sw_dense+0x7c>
10000057f:     	movslq	(%rax,%rcx,4), %rcx
100000583:     	addq	%rcx, %rax
100000586:     	jmpq	*%rax
100000588:     	movl	$0xb, -0x4(%rbp)
10000058f:     	jmp	0x1000005d7 <_sw_dense+0x77>
100000591:     	movl	$0x1b, -0x4(%rbp)
100000598:     	jmp	0x1000005d7 <_sw_dense+0x77>
10000059a:     	movl	$0x23, -0x4(%rbp)
1000005a1:     	jmp	0x1000005d7 <_sw_dense+0x77>
1000005a3:     	movl	$0x31, -0x4(%rbp)
1000005aa:     	jmp	0x1000005d7 <_sw_dense+0x77>
1000005ac:     	movl	$0x34, -0x4(%rbp)
1000005b3:     	jmp	0x1000005d7 <_sw_dense+0x77>
1000005b5:     	movl	$0x44, -0x4(%rbp)
1000005bc:     	jmp	0x1000005d7 <_sw_dense+0x77>
1000005be:     	movl	$0x47, -0x4(%rbp)
1000005c5:     	jmp	0x1000005d7 <_sw_dense+0x77>
1000005c7:     	movl	$0x59, -0x4(%rbp)
1000005ce:     	jmp	0x1000005d7 <_sw_dense+0x77>
1000005d0:     	movl	$0xffffffff, -0x4(%rbp) ## imm = 0xFFFFFFFF
1000005d7:     	movl	-0x4(%rbp), %eax
1000005da:     	popq	%rbp
1000005db:     	retq
1000005dc:     	lodsb	(%rsi), %al
1000005dd:     	<unknown>
1000005df:     	pushq	-0x41000001(%rbp)
1000005e5:     	<unknown>
1000005e7:     	incl	%edi
1000005e9:     	<unknown>
1000005eb:     	callq	*%rax
1000005ed:     	<unknown>
1000005ef:     	<unknown>
1000005f1:     	<unknown>
1000005f3:     	jmpq	*%rdx
1000005f5:     	<unknown>
1000005f7:     	<unknown>
1000005f9:     	<unknown>
1000005fb:     	decl	(%rdi)
1000005fd:     	<unknown>
1000005fe:     	addb	%dl, 0x48(%rbp)

0000000100000600 <_sw_sparse>:
100000600:     	pushq	%rbp
100000601:     	movq	%rsp, %rbp
100000604:     	movl	%edi, -0x8(%rbp)
100000607:     	movl	-0x8(%rbp), %eax
10000060a:     	movl	%eax, -0xc(%rbp)
10000060d:     	subl	$0x3, %eax
100000610:     	je	0x10000065a <_sw_sparse+0x5a>
100000612:     	jmp	0x100000614 <_sw_sparse+0x14>
100000614:     	movl	-0xc(%rbp), %eax
100000617:     	subl	$0x64, %eax
10000061a:     	je	0x100000663 <_sw_sparse+0x63>
10000061c:     	jmp	0x10000061e <_sw_sparse+0x1e>
10000061e:     	movl	-0xc(%rbp), %eax
100000621:     	subl	$0x3e8, %eax            ## imm = 0x3E8
100000626:     	je	0x10000066c <_sw_sparse+0x6c>
100000628:     	jmp	0x10000062a <_sw_sparse+0x2a>
10000062a:     	movl	-0xc(%rbp), %eax
10000062d:     	subl	$0x1388, %eax           ## imm = 0x1388
100000632:     	je	0x100000675 <_sw_sparse+0x75>
100000634:     	jmp	0x100000636 <_sw_sparse+0x36>
100000636:     	movl	-0xc(%rbp), %eax
100000639:     	subl	$0x4e20, %eax           ## imm = 0x4E20
10000063e:     	je	0x10000067e <_sw_sparse+0x7e>
100000640:     	jmp	0x100000642 <_sw_sparse+0x42>
100000642:     	movl	-0xc(%rbp), %eax
100000645:     	subl	$0x12fd1, %eax          ## imm = 0x12FD1
10000064a:     	je	0x100000687 <_sw_sparse+0x87>
10000064c:     	jmp	0x10000064e <_sw_sparse+0x4e>
10000064e:     	movl	-0xc(%rbp), %eax
100000651:     	subl	$0x1e240, %eax          ## imm = 0x1E240
100000656:     	je	0x100000690 <_sw_sparse+0x90>
100000658:     	jmp	0x100000699 <_sw_sparse+0x99>
10000065a:     	movl	$0x1, -0x4(%rbp)
100000661:     	jmp	0x1000006a0 <_sw_sparse+0xa0>
100000663:     	movl	$0x2, -0x4(%rbp)
10000066a:     	jmp	0x1000006a0 <_sw_sparse+0xa0>
10000066c:     	movl	$0x3, -0x4(%rbp)
100000673:     	jmp	0x1000006a0 <_sw_sparse+0xa0>
100000675:     	movl	$0x4, -0x4(%rbp)
10000067c:     	jmp	0x1000006a0 <_sw_sparse+0xa0>
10000067e:     	movl	$0x5, -0x4(%rbp)
100000685:     	jmp	0x1000006a0 <_sw_sparse+0xa0>
100000687:     	movl	$0x6, -0x4(%rbp)
10000068e:     	jmp	0x1000006a0 <_sw_sparse+0xa0>
100000690:     	movl	$0x7, -0x4(%rbp)
100000697:     	jmp	0x1000006a0 <_sw_sparse+0xa0>
100000699:     	movl	$0x0, -0x4(%rbp)
1000006a0:     	movl	-0x4(%rbp), %eax
1000006a3:     	popq	%rbp
1000006a4:     	retq
1000006a5:     	nopw	%cs:(%rax,%rax)

00000001000006b0 <_sw_bittest>:
1000006b0:     	pushq	%rbp
1000006b1:     	movq	%rsp, %rbp
1000006b4:     	movl	%edi, -0x8(%rbp)
1000006b7:     	movl	-0x8(%rbp), %eax
1000006ba:     	movl	%eax, -0xc(%rbp)
1000006bd:     	addl	$-0x9, %eax
1000006c0:     	subl	$0x5, %eax
1000006c3:     	jb	0x1000006e5 <_sw_bittest+0x35>
1000006c5:     	jmp	0x1000006c7 <_sw_bittest+0x17>
1000006c7:     	movl	-0xc(%rbp), %eax
1000006ca:     	subl	$0x20, %eax
1000006cd:     	je	0x1000006e5 <_sw_bittest+0x35>
1000006cf:     	jmp	0x1000006d1 <_sw_bittest+0x21>
1000006d1:     	movl	-0xc(%rbp), %eax
1000006d4:     	subl	$0x2c, %eax
1000006d7:     	je	0x1000006e5 <_sw_bittest+0x35>
1000006d9:     	jmp	0x1000006db <_sw_bittest+0x2b>
1000006db:     	movl	-0xc(%rbp), %eax
1000006de:     	subl	$0x3b, %eax
1000006e1:     	jne	0x1000006ee <_sw_bittest+0x3e>
1000006e3:     	jmp	0x1000006e5 <_sw_bittest+0x35>
1000006e5:     	movl	$0x1, -0x4(%rbp)
1000006ec:     	jmp	0x1000006f5 <_sw_bittest+0x45>
1000006ee:     	movl	$0x0, -0x4(%rbp)
1000006f5:     	movl	-0x4(%rbp), %eax
1000006f8:     	popq	%rbp
1000006f9:     	retq
1000006fa:     	nopw	(%rax,%rax)

0000000100000700 <_udiv7>:
100000700:     	pushq	%rbp
100000701:     	movq	%rsp, %rbp
100000704:     	movl	%edi, -0x4(%rbp)
100000707:     	movl	-0x4(%rbp), %eax
10000070a:     	movl	$0x7, %ecx
10000070f:     	xorl	%edx, %edx
100000711:     	divl	%ecx
100000713:     	popq	%rbp
100000714:     	retq
100000715:     	nopw	%cs:(%rax,%rax)

0000000100000720 <_sdiv7>:
100000720:     	pushq	%rbp
100000721:     	movq	%rsp, %rbp
100000724:     	movl	%edi, -0x4(%rbp)
100000727:     	movl	-0x4(%rbp), %eax
10000072a:     	movl	$0x7, %ecx
10000072f:     	cltd
100000730:     	idivl	%ecx
100000732:     	popq	%rbp
100000733:     	retq
100000734:     	nopw	%cs:(%rax,%rax)

0000000100000740 <_umod10>:
100000740:     	pushq	%rbp
100000741:     	movq	%rsp, %rbp
100000744:     	movl	%edi, -0x4(%rbp)
100000747:     	movl	-0x4(%rbp), %eax
10000074a:     	movl	$0xa, %ecx
10000074f:     	xorl	%edx, %edx
100000751:     	divl	%ecx
100000753:     	movl	%edx, %eax
100000755:     	popq	%rbp
100000756:     	retq
100000757:     	nopw	(%rax,%rax)

0000000100000760 <_sdiv16>:
100000760:     	pushq	%rbp
100000761:     	movq	%rsp, %rbp
100000764:     	movl	%edi, -0x4(%rbp)
100000767:     	movl	-0x4(%rbp), %eax
10000076a:     	movl	$0x10, %ecx
10000076f:     	cltd
100000770:     	idivl	%ecx
100000772:     	popq	%rbp
100000773:     	retq
100000774:     	nopw	%cs:(%rax,%rax)

0000000100000780 <_udiv1000_64>:
100000780:     	pushq	%rbp
100000781:     	movq	%rsp, %rbp
100000784:     	movq	%rdi, -0x8(%rbp)
100000788:     	movq	-0x8(%rbp), %rax
10000078c:     	movl	$0x3e8, %ecx            ## imm = 0x3E8
100000791:     	xorl	%edx, %edx
100000793:     	divq	%rcx
100000796:     	popq	%rbp
100000797:     	retq
100000798:     	nopl	(%rax,%rax)

00000001000007a0 <_sel_max>:
1000007a0:     	pushq	%rbp
1000007a1:     	movq	%rsp, %rbp
1000007a4:     	movl	%edi, -0x4(%rbp)
1000007a7:     	movl	%esi, -0x8(%rbp)
1000007aa:     	movl	-0x4(%rbp), %eax
1000007ad:     	cmpl	-0x8(%rbp), %eax
1000007b0:     	jle	0x1000007ba <_sel_max+0x1a>
1000007b2:     	movl	-0x4(%rbp), %eax
1000007b5:     	movl	%eax, -0xc(%rbp)
1000007b8:     	jmp	0x1000007c0 <_sel_max+0x20>
1000007ba:     	movl	-0x8(%rbp), %eax
1000007bd:     	movl	%eax, -0xc(%rbp)
1000007c0:     	movl	-0xc(%rbp), %eax
1000007c3:     	popq	%rbp
1000007c4:     	retq
1000007c5:     	nopw	%cs:(%rax,%rax)

00000001000007d0 <_sel_abs>:
1000007d0:     	pushq	%rbp
1000007d1:     	movq	%rsp, %rbp
1000007d4:     	movl	%edi, -0x4(%rbp)
1000007d7:     	cmpl	$0x0, -0x4(%rbp)
1000007db:     	jge	0x1000007e7 <_sel_abs+0x17>
1000007dd:     	xorl	%eax, %eax
1000007df:     	subl	-0x4(%rbp), %eax
1000007e2:     	movl	%eax, -0x8(%rbp)
1000007e5:     	jmp	0x1000007ed <_sel_abs+0x1d>
1000007e7:     	movl	-0x4(%rbp), %eax
1000007ea:     	movl	%eax, -0x8(%rbp)
1000007ed:     	movl	-0x8(%rbp), %eax
1000007f0:     	popq	%rbp
1000007f1:     	retq
1000007f2:     	nopw	%cs:(%rax,%rax)

0000000100000800 <_sel_clamp>:
100000800:     	pushq	%rbp
100000801:     	movq	%rsp, %rbp
100000804:     	movl	%edi, -0x4(%rbp)
100000807:     	movl	%esi, -0x8(%rbp)
10000080a:     	movl	%edx, -0xc(%rbp)
10000080d:     	movl	-0x4(%rbp), %eax
100000810:     	cmpl	-0x8(%rbp), %eax
100000813:     	jge	0x10000081d <_sel_clamp+0x1d>
100000815:     	movl	-0x8(%rbp), %eax
100000818:     	movl	%eax, -0x10(%rbp)
10000081b:     	jmp	0x100000839 <_sel_clamp+0x39>
10000081d:     	movl	-0x4(%rbp), %eax
100000820:     	cmpl	-0xc(%rbp), %eax
100000823:     	jle	0x10000082d <_sel_clamp+0x2d>
100000825:     	movl	-0xc(%rbp), %eax
100000828:     	movl	%eax, -0x14(%rbp)
10000082b:     	jmp	0x100000833 <_sel_clamp+0x33>
10000082d:     	movl	-0x4(%rbp), %eax
100000830:     	movl	%eax, -0x14(%rbp)
100000833:     	movl	-0x14(%rbp), %eax
100000836:     	movl	%eax, -0x10(%rbp)
100000839:     	movl	-0x10(%rbp), %eax
10000083c:     	popq	%rbp
10000083d:     	retq
10000083e:     	nop

0000000100000840 <_popcount_loop>:
100000840:     	pushq	%rbp
100000841:     	movq	%rsp, %rbp
100000844:     	movl	%edi, -0x4(%rbp)
100000847:     	movl	$0x0, -0x8(%rbp)
10000084e:     	cmpl	$0x0, -0x4(%rbp)
100000852:     	je	0x10000086b <_popcount_loop+0x2b>
100000854:     	movl	-0x4(%rbp), %eax
100000857:     	subl	$0x1, %eax
10000085a:     	andl	-0x4(%rbp), %eax
10000085d:     	movl	%eax, -0x4(%rbp)
100000860:     	movl	-0x8(%rbp), %eax
100000863:     	addl	$0x1, %eax
100000866:     	movl	%eax, -0x8(%rbp)
100000869:     	jmp	0x10000084e <_popcount_loop+0xe>
10000086b:     	movl	-0x8(%rbp), %eax
10000086e:     	popq	%rbp
10000086f:     	retq

0000000100000870 <_bswap32_manual>:
100000870:     	pushq	%rbp
100000871:     	movq	%rsp, %rbp
100000874:     	movl	%edi, -0x4(%rbp)
100000877:     	movl	-0x4(%rbp), %eax
10000087a:     	shrl	$0x18, %eax
10000087d:     	movl	-0x4(%rbp), %ecx
100000880:     	shrl	$0x8, %ecx
100000883:     	andl	$0xff00, %ecx           ## imm = 0xFF00
100000889:     	orl	%ecx, %eax
10000088b:     	movl	-0x4(%rbp), %ecx
10000088e:     	shll	$0x8, %ecx
100000891:     	andl	$0xff0000, %ecx         ## imm = 0xFF0000
100000897:     	orl	%ecx, %eax
100000899:     	movl	-0x4(%rbp), %ecx
10000089c:     	shll	$0x18, %ecx
10000089f:     	orl	%ecx, %eax
1000008a1:     	popq	%rbp
1000008a2:     	retq
1000008a3:     	nopw	%cs:(%rax,%rax)

00000001000008b0 <_rotl32>:
1000008b0:     	pushq	%rbp
1000008b1:     	movq	%rsp, %rbp
1000008b4:     	movl	%edi, -0x4(%rbp)
1000008b7:     	movl	%esi, -0x8(%rbp)
1000008ba:     	movl	-0x4(%rbp), %eax
1000008bd:     	movl	-0x8(%rbp), %ecx
1000008c0:     	andl	$0x1f, %ecx
1000008c3:     	shll	%cl, %eax
1000008c5:     	movl	-0x4(%rbp), %edx
1000008c8:     	movl	$0x20, %ecx
1000008cd:     	subl	-0x8(%rbp), %ecx
1000008d0:     	andl	$0x1f, %ecx
1000008d3:     	shrl	%cl, %edx
1000008d5:     	movl	%edx, %ecx
1000008d7:     	orl	%ecx, %eax
1000008d9:     	popq	%rbp
1000008da:     	retq
1000008db:     	nopl	(%rax,%rax)

00000001000008e0 <_is_pow2>:
1000008e0:     	pushq	%rbp
1000008e1:     	movq	%rsp, %rbp
1000008e4:     	movl	%edi, -0x4(%rbp)
1000008e7:     	xorl	%eax, %eax
1000008e9:     	cmpl	$0x0, -0x4(%rbp)
1000008ed:     	movb	%al, -0x5(%rbp)
1000008f0:     	je	0x100000908 <_is_pow2+0x28>
1000008f2:     	movl	-0x4(%rbp), %eax
1000008f5:     	movl	-0x4(%rbp), %ecx
1000008f8:     	subl	$0x1, %ecx
1000008fb:     	andl	%ecx, %eax
1000008fd:     	cmpl	$0x0, %eax
100000900:     	setne	%al
100000903:     	xorb	$-0x1, %al
100000905:     	movb	%al, -0x5(%rbp)
100000908:     	movb	-0x5(%rbp), %al
10000090b:     	andb	$0x1, %al
10000090d:     	movzbl	%al, %eax
100000910:     	popq	%rbp
100000911:     	retq
100000912:     	nopw	%cs:(%rax,%rax)

0000000100000920 <_copy16>:
100000920:     	pushq	%rbp
100000921:     	movq	%rsp, %rbp
100000924:     	subq	$0x10, %rsp
100000928:     	movq	%rdi, -0x8(%rbp)
10000092c:     	movq	%rsi, -0x10(%rbp)
100000930:     	movq	-0x8(%rbp), %rdi
100000934:     	movq	-0x10(%rbp), %rsi
100000938:     	movl	$0x10, %edx
10000093d:     	movq	$-0x1, %rcx
100000944:     	callq	0x10000194a <_strncmp+0x10000194a>
100000949:     	addq	$0x10, %rsp
10000094d:     	popq	%rbp
10000094e:     	retq
10000094f:     	nop

0000000100000950 <_zero64>:
100000950:     	pushq	%rbp
100000951:     	movq	%rsp, %rbp
100000954:     	subq	$0x10, %rsp
100000958:     	movq	%rdi, -0x8(%rbp)
10000095c:     	movq	-0x8(%rbp), %rdi
100000960:     	xorl	%esi, %esi
100000962:     	movl	$0x40, %edx
100000967:     	movq	$-0x1, %rcx
10000096e:     	callq	0x100001950 <_strncmp+0x100001950>
100000973:     	addq	$0x10, %rsp
100000977:     	popq	%rbp
100000978:     	retq
100000979:     	nopl	(%rax)

0000000100000980 <_zero_n>:
100000980:     	pushq	%rbp
100000981:     	movq	%rsp, %rbp
100000984:     	subq	$0x10, %rsp
100000988:     	movq	%rdi, -0x8(%rbp)
10000098c:     	movq	%rsi, -0x10(%rbp)
100000990:     	movq	-0x8(%rbp), %rdi
100000994:     	movq	-0x10(%rbp), %rdx
100000998:     	xorl	%esi, %esi
10000099a:     	movq	$-0x1, %rcx
1000009a1:     	callq	0x100001950 <_strncmp+0x100001950>
1000009a6:     	addq	$0x10, %rsp
1000009aa:     	popq	%rbp
1000009ab:     	retq
1000009ac:     	nopl	(%rax)

00000001000009b0 <_strlen_const>:
1000009b0:     	pushq	%rbp
1000009b1:     	movq	%rsp, %rbp
1000009b4:     	movl	$0x7, %eax
1000009b9:     	popq	%rbp
1000009ba:     	retq
1000009bb:     	nopl	(%rax,%rax)

00000001000009c0 <_strcmp_const>:
1000009c0:     	pushq	%rbp
1000009c1:     	movq	%rsp, %rbp
1000009c4:     	subq	$0x10, %rsp
1000009c8:     	movq	%rdi, -0x8(%rbp)
1000009cc:     	movq	-0x8(%rbp), %rdi
1000009d0:     	leaq	0xfdf(%rip), %rsi       ## 0x1000019b6 <_strncmp+0x1000019b6>
1000009d7:     	callq	0x100001956 <_strncmp+0x100001956>
1000009dc:     	cmpl	$0x0, %eax
1000009df:     	sete	%al
1000009e2:     	andb	$0x1, %al
1000009e4:     	movzbl	%al, %eax
1000009e7:     	addq	$0x10, %rsp
1000009eb:     	popq	%rbp
1000009ec:     	retq
1000009ed:     	nopl	(%rax)

00000001000009f0 <_strncmp_const>:
1000009f0:     	pushq	%rbp
1000009f1:     	movq	%rsp, %rbp
1000009f4:     	subq	$0x10, %rsp
1000009f8:     	movq	%rdi, -0x8(%rbp)
1000009fc:     	movq	-0x8(%rbp), %rdi
100000a00:     	leaq	0xfb3(%rip), %rsi       ## 0x1000019ba <_strncmp+0x1000019ba>
100000a07:     	movl	$0x7, %edx
100000a0c:     	callq	0x10000195c <_strncmp+0x10000195c>
100000a11:     	cmpl	$0x0, %eax
100000a14:     	sete	%al
100000a17:     	andb	$0x1, %al
100000a19:     	movzbl	%al, %eax
100000a1c:     	addq	$0x10, %rsp
100000a20:     	popq	%rbp
100000a21:     	retq
100000a22:     	nopw	%cs:(%rax,%rax)

0000000100000a30 <_loop_zero>:
100000a30:     	pushq	%rbp
100000a31:     	movq	%rsp, %rbp
100000a34:     	movq	%rdi, -0x8(%rbp)
100000a38:     	movl	%esi, -0xc(%rbp)
100000a3b:     	movl	$0x0, -0x10(%rbp)
100000a42:     	movl	-0x10(%rbp), %eax
100000a45:     	cmpl	-0xc(%rbp), %eax
100000a48:     	jge	0x100000a64 <_loop_zero+0x34>
100000a4a:     	movq	-0x8(%rbp), %rax
100000a4e:     	movslq	-0x10(%rbp), %rcx
100000a52:     	movl	$0x0, (%rax,%rcx,4)
100000a59:     	movl	-0x10(%rbp), %eax
100000a5c:     	addl	$0x1, %eax
100000a5f:     	movl	%eax, -0x10(%rbp)
100000a62:     	jmp	0x100000a42 <_loop_zero+0x12>
100000a64:     	popq	%rbp
100000a65:     	retq
100000a66:     	nopw	%cs:(%rax,%rax)

0000000100000a70 <_loop_copy>:
100000a70:     	pushq	%rbp
100000a71:     	movq	%rsp, %rbp
100000a74:     	movq	%rdi, -0x8(%rbp)
100000a78:     	movq	%rsi, -0x10(%rbp)
100000a7c:     	movl	%edx, -0x14(%rbp)
100000a7f:     	movl	$0x0, -0x18(%rbp)
100000a86:     	movl	-0x18(%rbp), %eax
100000a89:     	cmpl	-0x14(%rbp), %eax
100000a8c:     	jge	0x100000aaf <_loop_copy+0x3f>
100000a8e:     	movq	-0x10(%rbp), %rax
100000a92:     	movslq	-0x18(%rbp), %rcx
100000a96:     	movb	(%rax,%rcx), %dl
100000a99:     	movq	-0x8(%rbp), %rax
100000a9d:     	movslq	-0x18(%rbp), %rcx
100000aa1:     	movb	%dl, (%rax,%rcx)
100000aa4:     	movl	-0x18(%rbp), %eax
100000aa7:     	addl	$0x1, %eax
100000aaa:     	movl	%eax, -0x18(%rbp)
100000aad:     	jmp	0x100000a86 <_loop_copy+0x16>
100000aaf:     	popq	%rbp
100000ab0:     	retq
100000ab1:     	nopw	%cs:(%rax,%rax)

0000000100000ac0 <_loop_strlen>:
100000ac0:     	pushq	%rbp
100000ac1:     	movq	%rsp, %rbp
100000ac4:     	movq	%rdi, -0x8(%rbp)
100000ac8:     	movq	-0x8(%rbp), %rax
100000acc:     	movq	%rax, -0x10(%rbp)
100000ad0:     	movq	-0x10(%rbp), %rax
100000ad4:     	cmpb	$0x0, (%rax)
100000ad7:     	je	0x100000ae7 <_loop_strlen+0x27>
100000ad9:     	movq	-0x10(%rbp), %rax
100000add:     	addq	$0x1, %rax
100000ae1:     	movq	%rax, -0x10(%rbp)
100000ae5:     	jmp	0x100000ad0 <_loop_strlen+0x10>
100000ae7:     	movq	-0x10(%rbp), %rax
100000aeb:     	movq	-0x8(%rbp), %rcx
100000aef:     	subq	%rcx, %rax
100000af2:     	popq	%rbp
100000af3:     	retq
100000af4:     	nopw	%cs:(%rax,%rax)

0000000100000b00 <_make_big>:
100000b00:     	pushq	%rbp
100000b01:     	movq	%rsp, %rbp
100000b04:     	movq	%rdi, -0x20(%rbp)
100000b08:     	movq	%rdi, -0x18(%rbp)
100000b0c:     	movq	%rsi, -0x8(%rbp)
100000b10:     	movl	$0x0, -0xc(%rbp)
100000b17:     	cmpl	$0x8, -0xc(%rbp)
100000b1b:     	jge	0x100000b3f <_make_big+0x3f>
100000b1d:     	movq	-0x20(%rbp), %rax
100000b21:     	movq	-0x8(%rbp), %rdx
100000b25:     	movslq	-0xc(%rbp), %rcx
100000b29:     	addq	%rcx, %rdx
100000b2c:     	movslq	-0xc(%rbp), %rcx
100000b30:     	movq	%rdx, (%rax,%rcx,8)
100000b34:     	movl	-0xc(%rbp), %eax
100000b37:     	addl	$0x1, %eax
100000b3a:     	movl	%eax, -0xc(%rbp)
100000b3d:     	jmp	0x100000b17 <_make_big+0x17>
100000b3f:     	movq	-0x18(%rbp), %rax
100000b43:     	popq	%rbp
100000b44:     	retq
100000b45:     	nopw	%cs:(%rax,%rax)

0000000100000b50 <_use_big>:
100000b50:     	pushq	%rbp
100000b51:     	movq	%rsp, %rbp
100000b54:     	subq	$0x50, %rsp
100000b58:     	movq	%rdi, -0x8(%rbp)
100000b5c:     	movq	-0x8(%rbp), %rsi
100000b60:     	leaq	-0x48(%rbp), %rdi
100000b64:     	callq	0x100000b00 <_make_big>
100000b69:     	movq	-0x30(%rbp), %rax
100000b6d:     	addq	-0x10(%rbp), %rax
100000b71:     	addq	$0x50, %rsp
100000b75:     	popq	%rbp
100000b76:     	retq
100000b77:     	nopw	(%rax,%rax)

0000000100000b80 <_make_small>:
100000b80:     	pushq	%rbp
100000b81:     	movq	%rsp, %rbp
100000b84:     	movl	%edi, -0xc(%rbp)
100000b87:     	movl	-0xc(%rbp), %eax
100000b8a:     	movl	%eax, -0x8(%rbp)
100000b8d:     	imull	$0x3, -0xc(%rbp), %eax
100000b91:     	movl	%eax, -0x4(%rbp)
100000b94:     	movq	-0x8(%rbp), %rax
100000b98:     	popq	%rbp
100000b99:     	retq
100000b9a:     	nopw	(%rax,%rax)

0000000100000ba0 <_sum_va>:
100000ba0:     	pushq	%rbp
100000ba1:     	movq	%rsp, %rbp
100000ba4:     	subq	$0x100, %rsp            ## imm = 0x100
100000bab:     	testb	%al, %al
100000bad:     	je	0x100000bd8 <_sum_va+0x38>
100000baf:     	movaps	%xmm0, -0xb0(%rbp)
100000bb6:     	movaps	%xmm1, -0xa0(%rbp)
100000bbd:     	movaps	%xmm2, -0x90(%rbp)
100000bc4:     	movaps	%xmm3, -0x80(%rbp)
100000bc8:     	movaps	%xmm4, -0x70(%rbp)
100000bcc:     	movaps	%xmm5, -0x60(%rbp)
100000bd0:     	movaps	%xmm6, -0x50(%rbp)
100000bd4:     	movaps	%xmm7, -0x40(%rbp)
100000bd8:     	movq	%r9, -0xb8(%rbp)
100000bdf:     	movq	%r8, -0xc0(%rbp)
100000be6:     	movq	%rcx, -0xc8(%rbp)
100000bed:     	movq	%rdx, -0xd0(%rbp)
100000bf4:     	movq	%rsi, -0xd8(%rbp)
100000bfb:     	movq	0x141e(%rip), %rax      ## 0x100002020 <_strncmp+0x100002020>
100000c02:     	movq	(%rax), %rax
100000c05:     	movq	%rax, -0x8(%rbp)
100000c09:     	movl	%edi, -0x24(%rbp)
100000c0c:     	leaq	-0x20(%rbp), %rax
100000c10:     	leaq	-0xe0(%rbp), %rcx
100000c17:     	movq	%rcx, 0x10(%rax)
100000c1b:     	leaq	0x10(%rbp), %rcx
100000c1f:     	movq	%rcx, 0x8(%rax)
100000c23:     	movl	$0x30, 0x4(%rax)
100000c2a:     	movl	$0x8, (%rax)
100000c30:     	movl	$0x0, -0x28(%rbp)
100000c37:     	movl	$0x0, -0x2c(%rbp)
100000c3e:     	movl	-0x2c(%rbp), %eax
100000c41:     	cmpl	-0x24(%rbp), %eax
100000c44:     	jge	0x100000cb8 <_sum_va+0x118>
100000c46:     	leaq	-0x20(%rbp), %rax
100000c4a:     	movq	%rax, -0xf0(%rbp)
100000c51:     	movl	-0x20(%rbp), %eax
100000c54:     	movl	%eax, -0xe4(%rbp)
100000c5a:     	cmpl	$0x28, %eax
100000c5d:     	ja	0x100000c81 <_sum_va+0xe1>
100000c5f:     	movq	-0xf0(%rbp), %rcx
100000c66:     	movl	-0xe4(%rbp), %edx
100000c6c:     	movslq	%edx, %rax
100000c6f:     	addq	0x10(%rcx), %rax
100000c73:     	addl	$0x8, %edx
100000c76:     	movl	%edx, (%rcx)
100000c78:     	movq	%rax, -0xf8(%rbp)
100000c7f:     	jmp	0x100000c9e <_sum_va+0xfe>
100000c81:     	movq	-0xf0(%rbp), %rcx
100000c88:     	movq	0x8(%rcx), %rax
100000c8c:     	movq	%rax, %rdx
100000c8f:     	addq	$0x8, %rdx
100000c93:     	movq	%rdx, 0x8(%rcx)
100000c97:     	movq	%rax, -0xf8(%rbp)
100000c9e:     	movq	-0xf8(%rbp), %rax
100000ca5:     	movl	(%rax), %eax
100000ca7:     	addl	-0x28(%rbp), %eax
100000caa:     	movl	%eax, -0x28(%rbp)
100000cad:     	movl	-0x2c(%rbp), %eax
100000cb0:     	addl	$0x1, %eax
100000cb3:     	movl	%eax, -0x2c(%rbp)
100000cb6:     	jmp	0x100000c3e <_sum_va+0x9e>
100000cb8:     	leaq	-0x20(%rbp), %rax
100000cbc:     	movl	-0x28(%rbp), %eax
100000cbf:     	movl	%eax, -0xfc(%rbp)
100000cc5:     	movq	0x1354(%rip), %rax      ## 0x100002020 <_strncmp+0x100002020>
100000ccc:     	movq	(%rax), %rax
100000ccf:     	movq	-0x8(%rbp), %rcx
100000cd3:     	cmpq	%rcx, %rax
100000cd6:     	jne	0x100000ce7 <_sum_va+0x147>
100000cd8:     	movl	-0xfc(%rbp), %eax
100000cde:     	addq	$0x100, %rsp            ## imm = 0x100
100000ce5:     	popq	%rbp
100000ce6:     	retq
100000ce7:     	callq	0x100001962 <_strncmp+0x100001962>
100000cec:     	nopl	(%rax)

0000000100000cf0 <_ssp_copy>:
100000cf0:     	pushq	%rbp
100000cf1:     	movq	%rsp, %rbp
100000cf4:     	subq	$0x60, %rsp
100000cf8:     	movq	0x1321(%rip), %rax      ## 0x100002020 <_strncmp+0x100002020>
100000cff:     	movq	(%rax), %rax
100000d02:     	movq	%rax, -0x8(%rbp)
100000d06:     	movq	%rdi, -0x58(%rbp)
100000d0a:     	leaq	-0x50(%rbp), %rdi
100000d0e:     	movq	-0x58(%rbp), %rsi
100000d12:     	movl	$0x40, %edx
100000d17:     	callq	0x100001968 <_strncmp+0x100001968>
100000d1c:     	leaq	-0x50(%rbp), %rdi
100000d20:     	callq	0x10000196e <_strncmp+0x10000196e>
100000d25:     	movsbl	-0x4d(%rbp), %ecx
100000d29:     	addl	%ecx, %eax
100000d2b:     	movl	%eax, -0x5c(%rbp)
100000d2e:     	movq	0x12eb(%rip), %rax      ## 0x100002020 <_strncmp+0x100002020>
100000d35:     	movq	(%rax), %rax
100000d38:     	movq	-0x8(%rbp), %rcx
100000d3c:     	cmpq	%rcx, %rax
100000d3f:     	jne	0x100000d4a <_ssp_copy+0x5a>
100000d41:     	movl	-0x5c(%rbp), %eax
100000d44:     	addq	$0x60, %rsp
100000d48:     	popq	%rbp
100000d49:     	retq
100000d4a:     	callq	0x100001962 <_strncmp+0x100001962>
100000d4f:     	nop

0000000100000d50 <_fortify_memcpy>:
100000d50:     	pushq	%rbp
100000d51:     	movq	%rsp, %rbp
100000d54:     	subq	$0x50, %rsp
100000d58:     	movq	0x12c1(%rip), %rax      ## 0x100002020 <_strncmp+0x100002020>
100000d5f:     	movq	(%rax), %rax
100000d62:     	movq	%rax, -0x8(%rbp)
100000d66:     	movq	%rdi, -0x38(%rbp)
100000d6a:     	movq	%rsi, -0x40(%rbp)
100000d6e:     	movq	%rdx, -0x48(%rbp)
100000d72:     	leaq	-0x30(%rbp), %rdi
100000d76:     	movq	-0x40(%rbp), %rsi
100000d7a:     	movq	-0x48(%rbp), %rdx
100000d7e:     	movl	$0x20, %ecx
100000d83:     	callq	0x10000194a <_strncmp+0x10000194a>
100000d88:     	movq	-0x38(%rbp), %rdi
100000d8c:     	leaq	-0x30(%rbp), %rsi
100000d90:     	movl	$0x20, %edx
100000d95:     	movq	$-0x1, %rcx
100000d9c:     	callq	0x10000194a <_strncmp+0x10000194a>
100000da1:     	movq	0x1278(%rip), %rax      ## 0x100002020 <_strncmp+0x100002020>
100000da8:     	movq	(%rax), %rax
100000dab:     	movq	-0x8(%rbp), %rcx
100000daf:     	cmpq	%rcx, %rax
100000db2:     	jne	0x100000dba <_fortify_memcpy+0x6a>
100000db4:     	addq	$0x50, %rsp
100000db8:     	popq	%rbp
100000db9:     	retq
100000dba:     	callq	0x100001962 <_strncmp+0x100001962>
100000dbf:     	nop

0000000100000dc0 <_fortify_snprintf>:
100000dc0:     	pushq	%rbp
100000dc1:     	movq	%rsp, %rbp
100000dc4:     	subq	$0x20, %rsp
100000dc8:     	movq	%rdi, -0x8(%rbp)
100000dcc:     	movq	%rsi, -0x10(%rbp)
100000dd0:     	movl	%edx, -0x14(%rbp)
100000dd3:     	movq	-0x8(%rbp), %rdi
100000dd7:     	movq	-0x10(%rbp), %rsi
100000ddb:     	movl	-0x14(%rbp), %r9d
100000ddf:     	xorl	%edx, %edx
100000de1:     	movq	$-0x1, %rcx
100000de8:     	leaq	0xbd3(%rip), %r8        ## 0x1000019c2 <_strncmp+0x1000019c2>
100000def:     	movb	$0x0, %al
100000df1:     	callq	0x100001974 <_strncmp+0x100001974>
100000df6:     	addq	$0x20, %rsp
100000dfa:     	popq	%rbp
100000dfb:     	retq
100000dfc:     	nopl	(%rax)

0000000100000e00 <_read_file_head>:
100000e00:     	pushq	%rbp
100000e01:     	movq	%rsp, %rbp
100000e04:     	subq	$0x50, %rsp
100000e08:     	movq	%rdi, -0x10(%rbp)
100000e0c:     	movq	%rsi, -0x18(%rbp)
100000e10:     	movq	%rdx, -0x20(%rbp)
100000e14:     	movl	$0xffffffff, -0x24(%rbp) ## imm = 0xFFFFFFFF
100000e1b:     	movq	-0x10(%rbp), %rdi
100000e1f:     	movl	$0x1000000, %esi        ## imm = 0x1000000
100000e24:     	movb	$0x0, %al
100000e26:     	callq	0x10000197a <_strncmp+0x10000197a>
100000e2b:     	movl	%eax, -0x28(%rbp)
100000e2e:     	cmpl	$0x0, -0x28(%rbp)
100000e32:     	jge	0x100000e78 <_read_file_head+0x78>
100000e34:     	movq	0x1215(%rip), %rax      ## 0x100002050 <_strncmp+0x100002050>
100000e3b:     	movq	(%rax), %rax
100000e3e:     	movq	%rax, -0x48(%rbp)
100000e42:     	movq	-0x10(%rbp), %rax
100000e46:     	movq	%rax, -0x40(%rbp)
100000e4a:     	callq	0x100001980 <_strncmp+0x100001980>
100000e4f:     	movl	(%rax), %edi
100000e51:     	callq	0x100001986 <_strncmp+0x100001986>
100000e56:     	movq	-0x48(%rbp), %rdi
100000e5a:     	movq	-0x40(%rbp), %rdx
100000e5e:     	movq	%rax, %rcx
100000e61:     	leaq	0xb63(%rip), %rsi       ## 0x1000019cb <_strncmp+0x1000019cb>
100000e68:     	movb	$0x0, %al
100000e6a:     	callq	0x10000198c <_strncmp+0x10000198c>
100000e6f:     	movl	$0xffffffff, -0x4(%rbp) ## imm = 0xFFFFFFFF
100000e76:     	jmp	0x100000eec <_read_file_head+0xec>
100000e78:     	movq	-0x20(%rbp), %rdi
100000e7c:     	callq	0x100001992 <_strncmp+0x100001992>
100000e81:     	movq	%rax, -0x30(%rbp)
100000e85:     	cmpq	$0x0, -0x30(%rbp)
100000e8a:     	jne	0x100000e8e <_read_file_head+0x8e>
100000e8c:     	jmp	0x100000ede <_read_file_head+0xde>
100000e8e:     	movl	-0x28(%rbp), %edi
100000e91:     	movq	-0x30(%rbp), %rsi
100000e95:     	movq	-0x20(%rbp), %rdx
100000e99:     	callq	0x100001998 <_strncmp+0x100001998>
100000e9e:     	movq	%rax, -0x38(%rbp)
100000ea2:     	cmpq	$0x0, -0x38(%rbp)
100000ea7:     	jge	0x100000eb6 <_read_file_head+0xb6>
100000ea9:     	callq	0x100001980 <_strncmp+0x100001980>
100000eae:     	movl	$0x5, (%rax)
100000eb4:     	jmp	0x100000ed5 <_read_file_head+0xd5>
100000eb6:     	movq	-0x18(%rbp), %rdi
100000eba:     	movq	-0x30(%rbp), %rsi
100000ebe:     	movq	-0x38(%rbp), %rdx
100000ec2:     	movq	$-0x1, %rcx
100000ec9:     	callq	0x10000194a <_strncmp+0x10000194a>
100000ece:     	movq	-0x38(%rbp), %rax
100000ed2:     	movl	%eax, -0x24(%rbp)
100000ed5:     	movq	-0x30(%rbp), %rdi
100000ed9:     	callq	0x10000199e <_strncmp+0x10000199e>
100000ede:     	movl	-0x28(%rbp), %edi
100000ee1:     	callq	0x1000019a4 <_strncmp+0x1000019a4>
100000ee6:     	movl	-0x24(%rbp), %eax
100000ee9:     	movl	%eax, -0x4(%rbp)
100000eec:     	movl	-0x4(%rbp), %eax
100000eef:     	addq	$0x50, %rsp
100000ef3:     	popq	%rbp
100000ef4:     	retq
100000ef5:     	nopw	%cs:(%rax,%rax)

0000000100000f00 <_tail_target>:
100000f00:     	pushq	%rbp
100000f01:     	movq	%rsp, %rbp
100000f04:     	movl	%edi, -0x4(%rbp)
100000f07:     	imull	$0x3, -0x4(%rbp), %eax
100000f0b:     	addl	$0x1, %eax
100000f0e:     	popq	%rbp
100000f0f:     	retq

0000000100000f10 <_tail_caller>:
100000f10:     	pushq	%rbp
100000f11:     	movq	%rsp, %rbp
100000f14:     	subq	$0x10, %rsp
100000f18:     	movl	%edi, -0x4(%rbp)
100000f1b:     	movl	-0x4(%rbp), %edi
100000f1e:     	addl	$0x1, %edi
100000f21:     	callq	0x100000f00 <_tail_target>
100000f26:     	addq	$0x10, %rsp
100000f2a:     	popq	%rbp
100000f2b:     	retq
100000f2c:     	nopl	(%rax)

0000000100000f30 <_tail_ext>:
100000f30:     	pushq	%rbp
100000f31:     	movq	%rsp, %rbp
100000f34:     	subq	$0x10, %rsp
100000f38:     	movq	%rdi, -0x8(%rbp)
100000f3c:     	movq	-0x8(%rbp), %rdi
100000f40:     	addq	$0x1, %rdi
100000f44:     	callq	0x1000019aa <_strncmp+0x1000019aa>
100000f49:     	addq	$0x10, %rsp
100000f4d:     	popq	%rbp
100000f4e:     	retq
100000f4f:     	nop

0000000100000f50 <_vadd>:
100000f50:     	pushq	%rbp
100000f51:     	movq	%rsp, %rbp
100000f54:     	movq	%rdi, -0x8(%rbp)
100000f58:     	movq	%rsi, -0x10(%rbp)
100000f5c:     	movq	%rdx, -0x18(%rbp)
100000f60:     	movl	%ecx, -0x1c(%rbp)
100000f63:     	movl	$0x0, -0x20(%rbp)
100000f6a:     	movl	-0x20(%rbp), %eax
100000f6d:     	cmpl	-0x1c(%rbp), %eax
100000f70:     	jge	0x100000f9e <_vadd+0x4e>
100000f72:     	movq	-0x10(%rbp), %rax
100000f76:     	movslq	-0x20(%rbp), %rcx
100000f7a:     	movl	(%rax,%rcx,4), %edx
100000f7d:     	movq	-0x18(%rbp), %rax
100000f81:     	movslq	-0x20(%rbp), %rcx
100000f85:     	addl	(%rax,%rcx,4), %edx
100000f88:     	movq	-0x8(%rbp), %rax
100000f8c:     	movslq	-0x20(%rbp), %rcx
100000f90:     	movl	%edx, (%rax,%rcx,4)
100000f93:     	movl	-0x20(%rbp), %eax
100000f96:     	addl	$0x1, %eax
100000f99:     	movl	%eax, -0x20(%rbp)
100000f9c:     	jmp	0x100000f6a <_vadd+0x1a>
100000f9e:     	popq	%rbp
100000f9f:     	retq

0000000100000fa0 <_vsum>:
100000fa0:     	pushq	%rbp
100000fa1:     	movq	%rsp, %rbp
100000fa4:     	movq	%rdi, -0x8(%rbp)
100000fa8:     	movl	%esi, -0xc(%rbp)
100000fab:     	movl	$0x0, -0x10(%rbp)
100000fb2:     	movl	$0x0, -0x14(%rbp)
100000fb9:     	movl	-0x14(%rbp), %eax
100000fbc:     	cmpl	-0xc(%rbp), %eax
100000fbf:     	jge	0x100000fdd <_vsum+0x3d>
100000fc1:     	movq	-0x8(%rbp), %rax
100000fc5:     	movslq	-0x14(%rbp), %rcx
100000fc9:     	movl	(%rax,%rcx,4), %eax
100000fcc:     	addl	-0x10(%rbp), %eax
100000fcf:     	movl	%eax, -0x10(%rbp)
100000fd2:     	movl	-0x14(%rbp), %eax
100000fd5:     	addl	$0x1, %eax
100000fd8:     	movl	%eax, -0x14(%rbp)
100000fdb:     	jmp	0x100000fb9 <_vsum+0x19>
100000fdd:     	movl	-0x10(%rbp), %eax
100000fe0:     	popq	%rbp
100000fe1:     	retq
100000fe2:     	nopw	%cs:(%rax,%rax)

0000000100000ff0 <_vdot>:
100000ff0:     	pushq	%rbp
100000ff1:     	movq	%rsp, %rbp
100000ff4:     	movq	%rdi, -0x8(%rbp)
100000ff8:     	movq	%rsi, -0x10(%rbp)
100000ffc:     	movl	%edx, -0x14(%rbp)
100000fff:     	xorps	%xmm0, %xmm0
100001002:     	movss	%xmm0, -0x18(%rbp)
100001007:     	movl	$0x0, -0x1c(%rbp)
10000100e:     	movl	-0x1c(%rbp), %eax
100001011:     	cmpl	-0x14(%rbp), %eax
100001014:     	jge	0x10000104d <_vdot+0x5d>
100001016:     	movq	-0x8(%rbp), %rax
10000101a:     	movslq	-0x1c(%rbp), %rcx
10000101e:     	movss	(%rax,%rcx,4), %xmm0
100001023:     	movq	-0x10(%rbp), %rax
100001027:     	movslq	-0x1c(%rbp), %rcx
10000102b:     	movss	(%rax,%rcx,4), %xmm2
100001030:     	movss	-0x18(%rbp), %xmm1
100001035:     	mulss	%xmm2, %xmm0
100001039:     	addss	%xmm1, %xmm0
10000103d:     	movss	%xmm0, -0x18(%rbp)
100001042:     	movl	-0x1c(%rbp), %eax
100001045:     	addl	$0x1, %eax
100001048:     	movl	%eax, -0x1c(%rbp)
10000104b:     	jmp	0x10000100e <_vdot+0x1e>
10000104d:     	movss	-0x18(%rbp), %xmm0
100001052:     	popq	%rbp
100001053:     	retq
100001054:     	nopw	%cs:(%rax,%rax)

0000000100001060 <_md5_init>:
100001060:     	pushq	%rbp
100001061:     	movq	%rsp, %rbp
100001064:     	movq	%rdi, -0x8(%rbp)
100001068:     	movq	-0x8(%rbp), %rax
10000106c:     	movl	$0x67452301, (%rax)     ## imm = 0x67452301
100001072:     	movq	-0x8(%rbp), %rax
100001076:     	movl	$0xefcdab89, 0x4(%rax)  ## imm = 0xEFCDAB89
10000107d:     	movq	-0x8(%rbp), %rax
100001081:     	movl	$0x98badcfe, 0x8(%rax)  ## imm = 0x98BADCFE
100001088:     	movq	-0x8(%rbp), %rax
10000108c:     	movl	$0x10325476, 0xc(%rax)  ## imm = 0x10325476
100001093:     	popq	%rbp
100001094:     	retq
100001095:     	nopw	%cs:(%rax,%rax)

00000001000010a0 <_crc32_make_table>:
1000010a0:     	pushq	%rbp
1000010a1:     	movq	%rsp, %rbp
1000010a4:     	movl	$0x0, -0x4(%rbp)
1000010ab:     	cmpl	$0x100, -0x4(%rbp)      ## imm = 0x100
1000010b2:     	jae	0x100001117 <_crc32_make_table+0x77>
1000010b4:     	movl	-0x4(%rbp), %eax
1000010b7:     	movl	%eax, -0x8(%rbp)
1000010ba:     	movl	$0x0, -0xc(%rbp)
1000010c1:     	cmpl	$0x8, -0xc(%rbp)
1000010c5:     	jge	0x1000010fa <_crc32_make_table+0x5a>
1000010c7:     	movl	-0x8(%rbp), %eax
1000010ca:     	andl	$0x1, %eax
1000010cd:     	cmpl	$0x0, %eax
1000010d0:     	je	0x1000010e1 <_crc32_make_table+0x41>
1000010d2:     	movl	-0x8(%rbp), %eax
1000010d5:     	shrl	%eax
1000010d7:     	xorl	$0xedb88320, %eax       ## imm = 0xEDB88320
1000010dc:     	movl	%eax, -0x10(%rbp)
1000010df:     	jmp	0x1000010e9 <_crc32_make_table+0x49>
1000010e1:     	movl	-0x8(%rbp), %eax
1000010e4:     	shrl	%eax
1000010e6:     	movl	%eax, -0x10(%rbp)
1000010e9:     	movl	-0x10(%rbp), %eax
1000010ec:     	movl	%eax, -0x8(%rbp)
1000010ef:     	movl	-0xc(%rbp), %eax
1000010f2:     	addl	$0x1, %eax
1000010f5:     	movl	%eax, -0xc(%rbp)
1000010f8:     	jmp	0x1000010c1 <_crc32_make_table+0x21>
1000010fa:     	movl	-0x8(%rbp), %edx
1000010fd:     	movl	-0x4(%rbp), %eax
100001100:     	movl	%eax, %ecx
100001102:     	leaq	0x1ef7(%rip), %rax      ## 0x100003000 <_crc_table>
100001109:     	movl	%edx, (%rax,%rcx,4)
10000110c:     	movl	-0x4(%rbp), %eax
10000110f:     	addl	$0x1, %eax
100001112:     	movl	%eax, -0x4(%rbp)
100001115:     	jmp	0x1000010ab <_crc32_make_table+0xb>
100001117:     	popq	%rbp
100001118:     	retq
100001119:     	nopl	(%rax)

0000000100001120 <_crc32_buf>:
100001120:     	pushq	%rbp
100001121:     	movq	%rsp, %rbp
100001124:     	movq	%rdi, -0x8(%rbp)
100001128:     	movq	%rsi, -0x10(%rbp)
10000112c:     	movl	$0xffffffff, -0x14(%rbp) ## imm = 0xFFFFFFFF
100001133:     	movq	-0x10(%rbp), %rax
100001137:     	movq	%rax, %rcx
10000113a:     	addq	$-0x1, %rcx
10000113e:     	movq	%rcx, -0x10(%rbp)
100001142:     	cmpq	$0x0, %rax
100001146:     	je	0x10000117f <_crc32_buf+0x5f>
100001148:     	movl	-0x14(%rbp), %eax
10000114b:     	movq	-0x8(%rbp), %rcx
10000114f:     	movq	%rcx, %rdx
100001152:     	addq	$0x1, %rdx
100001156:     	movq	%rdx, -0x8(%rbp)
10000115a:     	movzbl	(%rcx), %ecx
10000115d:     	xorl	%ecx, %eax
10000115f:     	andl	$0xff, %eax
100001164:     	movl	%eax, %eax
100001166:     	movl	%eax, %ecx
100001168:     	leaq	0x1e91(%rip), %rax      ## 0x100003000 <_crc_table>
10000116f:     	movl	(%rax,%rcx,4), %eax
100001172:     	movl	-0x14(%rbp), %ecx
100001175:     	shrl	$0x8, %ecx
100001178:     	xorl	%ecx, %eax
10000117a:     	movl	%eax, -0x14(%rbp)
10000117d:     	jmp	0x100001133 <_crc32_buf+0x13>
10000117f:     	movl	-0x14(%rbp), %eax
100001182:     	xorl	$-0x1, %eax
100001185:     	popq	%rbp
100001186:     	retq
100001187:     	nopw	(%rax,%rax)

0000000100001190 <_tea_encrypt>:
100001190:     	pushq	%rbp
100001191:     	movq	%rsp, %rbp
100001194:     	movq	%rdi, -0x8(%rbp)
100001198:     	movq	%rsi, -0x10(%rbp)
10000119c:     	movq	-0x8(%rbp), %rax
1000011a0:     	movl	(%rax), %eax
1000011a2:     	movl	%eax, -0x14(%rbp)
1000011a5:     	movq	-0x8(%rbp), %rax
1000011a9:     	movl	0x4(%rax), %eax
1000011ac:     	movl	%eax, -0x18(%rbp)
1000011af:     	movl	$0x0, -0x1c(%rbp)
1000011b6:     	movl	$0x9e3779b9, -0x20(%rbp) ## imm = 0x9E3779B9
1000011bd:     	movl	$0x0, -0x24(%rbp)
1000011c4:     	cmpl	$0x20, -0x24(%rbp)
1000011c8:     	jge	0x100001231 <_tea_encrypt+0xa1>
1000011ca:     	movl	-0x20(%rbp), %eax
1000011cd:     	addl	-0x1c(%rbp), %eax
1000011d0:     	movl	%eax, -0x1c(%rbp)
1000011d3:     	movl	-0x18(%rbp), %eax
1000011d6:     	shll	$0x4, %eax
1000011d9:     	movq	-0x10(%rbp), %rcx
1000011dd:     	addl	(%rcx), %eax
1000011df:     	movl	-0x18(%rbp), %ecx
1000011e2:     	addl	-0x1c(%rbp), %ecx
1000011e5:     	xorl	%ecx, %eax
1000011e7:     	movl	-0x18(%rbp), %ecx
1000011ea:     	shrl	$0x5, %ecx
1000011ed:     	movq	-0x10(%rbp), %rdx
1000011f1:     	addl	0x4(%rdx), %ecx
1000011f4:     	xorl	%ecx, %eax
1000011f6:     	addl	-0x14(%rbp), %eax
1000011f9:     	movl	%eax, -0x14(%rbp)
1000011fc:     	movl	-0x14(%rbp), %eax
1000011ff:     	shll	$0x4, %eax
100001202:     	movq	-0x10(%rbp), %rcx
100001206:     	addl	0x8(%rcx), %eax
100001209:     	movl	-0x14(%rbp), %ecx
10000120c:     	addl	-0x1c(%rbp), %ecx
10000120f:     	xorl	%ecx, %eax
100001211:     	movl	-0x14(%rbp), %ecx
100001214:     	shrl	$0x5, %ecx
100001217:     	movq	-0x10(%rbp), %rdx
10000121b:     	addl	0xc(%rdx), %ecx
10000121e:     	xorl	%ecx, %eax
100001220:     	addl	-0x18(%rbp), %eax
100001223:     	movl	%eax, -0x18(%rbp)
100001226:     	movl	-0x24(%rbp), %eax
100001229:     	addl	$0x1, %eax
10000122c:     	movl	%eax, -0x24(%rbp)
10000122f:     	jmp	0x1000011c4 <_tea_encrypt+0x34>
100001231:     	movl	-0x14(%rbp), %ecx
100001234:     	movq	-0x8(%rbp), %rax
100001238:     	movl	%ecx, (%rax)
10000123a:     	movl	-0x18(%rbp), %ecx
10000123d:     	movq	-0x8(%rbp), %rax
100001241:     	movl	%ecx, 0x4(%rax)
100001244:     	popq	%rbp
100001245:     	retq
100001246:     	nopw	%cs:(%rax,%rax)

0000000100001250 <_main>:
100001250:     	pushq	%rbp
100001251:     	movq	%rsp, %rbp
100001254:     	subq	$0x6c0, %rsp            ## imm = 0x6C0
10000125b:     	movq	0xdbe(%rip), %rax       ## 0x100002020 <_strncmp+0x100002020>
100001262:     	movq	(%rax), %rax
100001265:     	movq	%rax, -0x8(%rbp)
100001269:     	movl	$0x0, -0x5c4(%rbp)
100001273:     	movl	%edi, -0x5c8(%rbp)
100001279:     	movq	%rsi, -0x5d0(%rbp)
100001280:     	cmpl	$0x1, -0x5c8(%rbp)
100001287:     	jle	0x1000012a1 <_main+0x51>
100001289:     	movq	-0x5d0(%rbp), %rax
100001290:     	movq	0x8(%rax), %rdi
100001294:     	callq	0x1000019aa <_strncmp+0x1000019aa>
100001299:     	movl	%eax, -0x61c(%rbp)
10000129f:     	jmp	0x1000012ae <_main+0x5e>
1000012a1:     	movl	$0x3, %eax
1000012a6:     	movl	%eax, -0x61c(%rbp)
1000012ac:     	jmp	0x1000012ae <_main+0x5e>
1000012ae:     	movl	-0x61c(%rbp), %eax
1000012b4:     	movl	%eax, -0x5d4(%rbp)
1000012ba:     	cmpl	$0x2, -0x5c8(%rbp)
1000012c1:     	jle	0x1000012d7 <_main+0x87>
1000012c3:     	movq	-0x5d0(%rbp), %rax
1000012ca:     	movq	0x10(%rax), %rax
1000012ce:     	movq	%rax, -0x628(%rbp)
1000012d5:     	jmp	0x1000012e7 <_main+0x97>
1000012d7:     	leaq	0x6d8(%rip), %rax       ## 0x1000019b6 <_strncmp+0x1000019b6>
1000012de:     	movq	%rax, -0x628(%rbp)
1000012e5:     	jmp	0x1000012e7 <_main+0x97>
1000012e7:     	movq	-0x628(%rbp), %rax
1000012ee:     	movq	%rax, -0x5e0(%rbp)
1000012f5:     	movl	$0x0, -0x5e4(%rbp)
1000012ff:     	cmpl	$0x40, -0x5e4(%rbp)
100001306:     	jge	0x10000137d <_main+0x12d>
100001308:     	movl	-0x5e4(%rbp), %ecx
10000130e:     	xorl	-0x5d4(%rbp), %ecx
100001314:     	movslq	-0x5e4(%rbp), %rax
10000131b:     	movl	%ecx, -0x290(%rbp,%rax,4)
100001322:     	movl	-0x5e4(%rbp), %ecx
100001328:     	addl	-0x5d4(%rbp), %ecx
10000132e:     	movslq	-0x5e4(%rbp), %rax
100001335:     	movl	%ecx, -0x390(%rbp,%rax,4)
10000133c:     	cvtsi2ssl	-0x5e4(%rbp), %xmm0
100001344:     	movslq	-0x5e4(%rbp), %rax
10000134b:     	movss	%xmm0, -0x490(%rbp,%rax,4)
100001354:     	cvtsi2ssl	-0x5d4(%rbp), %xmm0
10000135c:     	movslq	-0x5e4(%rbp), %rax
100001363:     	movss	%xmm0, -0x590(%rbp,%rax,4)
10000136c:     	movl	-0x5e4(%rbp), %eax
100001372:     	addl	$0x1, %eax
100001375:     	movl	%eax, -0x5e4(%rbp)
10000137b:     	jmp	0x1000012ff <_main+0xaf>
10000137d:     	movq	$0x0, -0x5f0(%rbp)
100001388:     	movl	-0x5d4(%rbp), %edi
10000138e:     	callq	0x100000560 <_sw_dense>
100001393:     	movl	%eax, -0x69c(%rbp)
100001399:     	movl	-0x5d4(%rbp), %edi
10000139f:     	callq	0x100000600 <_sw_sparse>
1000013a4:     	movl	%eax, %ecx
1000013a6:     	movl	-0x69c(%rbp), %eax
1000013ac:     	addl	%ecx, %eax
1000013ae:     	movl	%eax, -0x698(%rbp)
1000013b4:     	movl	-0x5d4(%rbp), %edi
1000013ba:     	callq	0x1000006b0 <_sw_bittest>
1000013bf:     	movl	%eax, %ecx
1000013c1:     	movl	-0x698(%rbp), %eax
1000013c7:     	addl	%ecx, %eax
1000013c9:     	cltq
1000013cb:     	addq	-0x5f0(%rbp), %rax
1000013d2:     	movq	%rax, -0x5f0(%rbp)
1000013d9:     	movl	-0x5d4(%rbp), %edi
1000013df:     	callq	0x100000700 <_udiv7>
1000013e4:     	movl	%eax, -0x694(%rbp)
1000013ea:     	movl	-0x5d4(%rbp), %edi
1000013f0:     	callq	0x100000720 <_sdiv7>
1000013f5:     	movl	%eax, %ecx
1000013f7:     	movl	-0x694(%rbp), %eax
1000013fd:     	addl	%ecx, %eax
1000013ff:     	movl	%eax, -0x690(%rbp)
100001405:     	movl	-0x5d4(%rbp), %edi
10000140b:     	callq	0x100000740 <_umod10>
100001410:     	movl	%eax, %ecx
100001412:     	movl	-0x690(%rbp), %eax
100001418:     	addl	%ecx, %eax
10000141a:     	movl	%eax, -0x68c(%rbp)
100001420:     	movl	-0x5d4(%rbp), %edi
100001426:     	callq	0x100000760 <_sdiv16>
10000142b:     	movl	%eax, %ecx
10000142d:     	movl	-0x68c(%rbp), %eax
100001433:     	addl	%ecx, %eax
100001435:     	movl	%eax, %eax
100001437:     	movq	%rax, -0x688(%rbp)
10000143e:     	movslq	-0x5d4(%rbp), %rdi
100001445:     	callq	0x100000780 <_udiv1000_64>
10000144a:     	movq	%rax, %rcx
10000144d:     	movq	-0x688(%rbp), %rax
100001454:     	addq	%rcx, %rax
100001457:     	addq	-0x5f0(%rbp), %rax
10000145e:     	movq	%rax, -0x5f0(%rbp)
100001465:     	movl	-0x5d4(%rbp), %edi
10000146b:     	movl	$0x5, %esi
100001470:     	callq	0x1000007a0 <_sel_max>
100001475:     	movl	%eax, -0x67c(%rbp)
10000147b:     	movl	-0x5d4(%rbp), %edi
100001481:     	callq	0x1000007d0 <_sel_abs>
100001486:     	movl	%eax, %ecx
100001488:     	movl	-0x67c(%rbp), %eax
10000148e:     	addl	%ecx, %eax
100001490:     	movl	%eax, -0x678(%rbp)
100001496:     	movl	-0x5d4(%rbp), %edi
10000149c:     	xorl	%esi, %esi
10000149e:     	movl	$0x9, %edx
1000014a3:     	callq	0x100000800 <_sel_clamp>
1000014a8:     	movl	%eax, %ecx
1000014aa:     	movl	-0x678(%rbp), %eax
1000014b0:     	addl	%ecx, %eax
1000014b2:     	movl	%eax, -0x674(%rbp)
1000014b8:     	movl	-0x5d4(%rbp), %edi
1000014be:     	callq	0x100000840 <_popcount_loop>
1000014c3:     	movl	%eax, %ecx
1000014c5:     	movl	-0x674(%rbp), %eax
1000014cb:     	addl	%ecx, %eax
1000014cd:     	cltq
1000014cf:     	addq	-0x5f0(%rbp), %rax
1000014d6:     	movq	%rax, -0x5f0(%rbp)
1000014dd:     	movl	-0x5d4(%rbp), %edi
1000014e3:     	callq	0x100000870 <_bswap32_manual>
1000014e8:     	movl	%eax, -0x670(%rbp)
1000014ee:     	movl	-0x5d4(%rbp), %edi
1000014f4:     	movl	-0x5d4(%rbp), %esi
1000014fa:     	callq	0x1000008b0 <_rotl32>
1000014ff:     	movl	%eax, %ecx
100001501:     	movl	-0x670(%rbp), %eax
100001507:     	addl	%ecx, %eax
100001509:     	movl	%eax, -0x66c(%rbp)
10000150f:     	movl	-0x5d4(%rbp), %edi
100001515:     	callq	0x1000008e0 <_is_pow2>
10000151a:     	movl	%eax, %ecx
10000151c:     	movl	-0x66c(%rbp), %eax
100001522:     	addl	%ecx, %eax
100001524:     	movl	%eax, %eax
100001526:     	addq	-0x5f0(%rbp), %rax
10000152d:     	movq	%rax, -0x5f0(%rbp)
100001534:     	movl	-0x5d4(%rbp), %eax
10000153a:     	movl	%eax, -0x600(%rbp)
100001540:     	movl	$0x1, -0x5fc(%rbp)
10000154a:     	movl	$0x2, -0x5f8(%rbp)
100001554:     	movl	$0x3, -0x5f4(%rbp)
10000155e:     	leaq	-0x610(%rbp), %rdi
100001565:     	leaq	-0x600(%rbp), %rsi
10000156c:     	callq	0x100000920 <_copy16>
100001571:     	movslq	-0x604(%rbp), %rax
100001578:     	addq	-0x5f0(%rbp), %rax
10000157f:     	movq	%rax, -0x5f0(%rbp)
100001586:     	leaq	-0x90(%rbp), %rdi
10000158d:     	callq	0x100000950 <_zero64>
100001592:     	leaq	-0x90(%rbp), %rdi
100001599:     	movslq	-0x5d4(%rbp), %rsi
1000015a0:     	andq	$0x3f, %rsi
1000015a4:     	callq	0x100000980 <_zero_n>
1000015a9:     	callq	0x1000009b0 <_strlen_const>
1000015ae:     	movq	%rax, -0x668(%rbp)
1000015b5:     	movq	-0x5e0(%rbp), %rdi
1000015bc:     	callq	0x1000009c0 <_strcmp_const>
1000015c1:     	movl	%eax, %ecx
1000015c3:     	movq	-0x668(%rbp), %rax
1000015ca:     	movslq	%ecx, %rcx
1000015cd:     	addq	%rcx, %rax
1000015d0:     	movq	%rax, -0x660(%rbp)
1000015d7:     	movq	-0x5e0(%rbp), %rdi
1000015de:     	callq	0x1000009f0 <_strncmp_const>
1000015e3:     	movl	%eax, %ecx
1000015e5:     	movq	-0x660(%rbp), %rax
1000015ec:     	movslq	%ecx, %rcx
1000015ef:     	addq	%rcx, %rax
1000015f2:     	addq	-0x5f0(%rbp), %rax
1000015f9:     	movq	%rax, -0x5f0(%rbp)
100001600:     	leaq	-0x190(%rbp), %rdi
100001607:     	movl	-0x5d4(%rbp), %esi
10000160d:     	andl	$0x3f, %esi
100001610:     	callq	0x100000a30 <_loop_zero>
100001615:     	leaq	-0x90(%rbp), %rax
10000161c:     	movq	%rax, -0x658(%rbp)
100001623:     	movq	-0x5e0(%rbp), %rax
10000162a:     	movq	%rax, -0x650(%rbp)
100001631:     	movq	-0x5e0(%rbp), %rdi
100001638:     	callq	0x10000196e <_strncmp+0x10000196e>
10000163d:     	movq	-0x658(%rbp), %rdi
100001644:     	movq	-0x650(%rbp), %rsi
10000164b:     	movl	%eax, %edx
10000164d:     	callq	0x100000a70 <_loop_copy>
100001652:     	movq	-0x5e0(%rbp), %rdi
100001659:     	callq	0x100000ac0 <_loop_strlen>
10000165e:     	addq	-0x5f0(%rbp), %rax
100001665:     	movq	%rax, -0x5f0(%rbp)
10000166c:     	movslq	-0x5d4(%rbp), %rdi
100001673:     	callq	0x100000b50 <_use_big>
100001678:     	movq	%rax, -0x648(%rbp)
10000167f:     	movl	-0x5d4(%rbp), %edi
100001685:     	callq	0x100000b80 <_make_small>
10000168a:     	movq	%rax, %rcx
10000168d:     	movq	-0x648(%rbp), %rax
100001694:     	movq	%rcx, -0x618(%rbp)
10000169b:     	movslq	-0x614(%rbp), %rcx
1000016a2:     	addq	%rcx, %rax
1000016a5:     	movq	%rax, -0x640(%rbp)
1000016ac:     	movl	-0x5d4(%rbp), %esi
1000016b2:     	movl	-0x5d4(%rbp), %edx
1000016b8:     	addl	$0x1, %edx
1000016bb:     	movl	-0x5d4(%rbp), %ecx
1000016c1:     	addl	$0x2, %ecx
1000016c4:     	movl	$0x3, %edi
1000016c9:     	movb	$0x0, %al
1000016cb:     	callq	0x100000ba0 <_sum_va>
1000016d0:     	movl	%eax, %ecx
1000016d2:     	movq	-0x640(%rbp), %rax
1000016d9:     	movslq	%ecx, %rcx
1000016dc:     	addq	%rcx, %rax
1000016df:     	addq	-0x5f0(%rbp), %rax
1000016e6:     	movq	%rax, -0x5f0(%rbp)
1000016ed:     	movq	-0x5e0(%rbp), %rdi
1000016f4:     	callq	0x100000cf0 <_ssp_copy>
1000016f9:     	cltq
1000016fb:     	addq	-0x5f0(%rbp), %rax
100001702:     	movq	%rax, -0x5f0(%rbp)
100001709:     	leaq	-0x90(%rbp), %rax
100001710:     	movq	%rax, -0x638(%rbp)
100001717:     	movq	-0x5e0(%rbp), %rax
10000171e:     	movq	%rax, -0x630(%rbp)
100001725:     	movq	-0x5e0(%rbp), %rdi
10000172c:     	callq	0x10000196e <_strncmp+0x10000196e>
100001731:     	movq	-0x638(%rbp), %rdi
100001738:     	movq	-0x630(%rbp), %rsi
10000173f:     	movq	%rax, %rdx
100001742:     	andq	$0x1f, %rdx
100001746:     	callq	0x100000d50 <_fortify_memcpy>
10000174b:     	leaq	-0x90(%rbp), %rdi
100001752:     	movl	-0x5d4(%rbp), %edx
100001758:     	movl	$0x80, %esi
10000175d:     	callq	0x100000dc0 <_fortify_snprintf>
100001762:     	cltq
100001764:     	addq	-0x5f0(%rbp), %rax
10000176b:     	movq	%rax, -0x5f0(%rbp)
100001772:     	cmpl	$0x3, -0x5c8(%rbp)
100001779:     	jle	0x10000178f <_main+0x53f>
10000177b:     	movq	-0x5d0(%rbp), %rax
100001782:     	movq	0x18(%rax), %rax
100001786:     	movq	%rax, -0x6a8(%rbp)
10000178d:     	jmp	0x10000179f <_main+0x54f>
10000178f:     	leaq	0x242(%rip), %rax       ## 0x1000019d8 <_strncmp+0x1000019d8>
100001796:     	movq	%rax, -0x6a8(%rbp)
10000179d:     	jmp	0x10000179f <_main+0x54f>
10000179f:     	movq	-0x6a8(%rbp), %rdi
1000017a6:     	leaq	-0x90(%rbp), %rsi
1000017ad:     	movl	$0x80, %edx
1000017b2:     	callq	0x100000e00 <_read_file_head>
1000017b7:     	cltq
1000017b9:     	addq	-0x5f0(%rbp), %rax
1000017c0:     	movq	%rax, -0x5f0(%rbp)
1000017c7:     	movl	-0x5d4(%rbp), %edi
1000017cd:     	callq	0x100000f10 <_tail_caller>
1000017d2:     	movl	%eax, -0x6bc(%rbp)
1000017d8:     	movq	-0x5e0(%rbp), %rdi
1000017df:     	callq	0x100000f30 <_tail_ext>
1000017e4:     	movl	%eax, %ecx
1000017e6:     	movl	-0x6bc(%rbp), %eax
1000017ec:     	addl	%ecx, %eax
1000017ee:     	cltq
1000017f0:     	addq	-0x5f0(%rbp), %rax
1000017f7:     	movq	%rax, -0x5f0(%rbp)
1000017fe:     	leaq	-0x190(%rbp), %rdi
100001805:     	leaq	-0x290(%rbp), %rsi
10000180c:     	leaq	-0x390(%rbp), %rdx
100001813:     	movl	$0x40, %ecx
100001818:     	callq	0x100000f50 <_vadd>
10000181d:     	leaq	-0x190(%rbp), %rdi
100001824:     	movl	$0x40, %esi
100001829:     	callq	0x100000fa0 <_vsum>
10000182e:     	cltq
100001830:     	movq	%rax, -0x6b8(%rbp)
100001837:     	leaq	-0x490(%rbp), %rdi
10000183e:     	leaq	-0x590(%rbp), %rsi
100001845:     	movl	$0x40, %edx
10000184a:     	callq	0x100000ff0 <_vdot>
10000184f:     	movq	-0x6b8(%rbp), %rax
100001856:     	cvttss2si	%xmm0, %rcx
10000185b:     	addq	%rcx, %rax
10000185e:     	addq	-0x5f0(%rbp), %rax
100001865:     	movq	%rax, -0x5f0(%rbp)
10000186c:     	leaq	-0x5a0(%rbp), %rdi
100001873:     	callq	0x100001060 <_md5_init>
100001878:     	callq	0x1000010a0 <_crc32_make_table>
10000187d:     	movq	-0x5e0(%rbp), %rax
100001884:     	movq	%rax, -0x6b0(%rbp)
10000188b:     	movq	-0x5e0(%rbp), %rdi
100001892:     	callq	0x10000196e <_strncmp+0x10000196e>
100001897:     	movq	-0x6b0(%rbp), %rdi
10000189e:     	movq	%rax, %rsi
1000018a1:     	callq	0x100001120 <_crc32_buf>
1000018a6:     	movl	%eax, %eax
1000018a8:     	addq	-0x5f0(%rbp), %rax
1000018af:     	movq	%rax, -0x5f0(%rbp)
1000018b6:     	movl	-0x5a0(%rbp), %eax
1000018bc:     	movl	%eax, -0x5a8(%rbp)
1000018c2:     	movl	-0x59c(%rbp), %eax
1000018c8:     	movl	%eax, -0x5a4(%rbp)
1000018ce:     	movq	0x11b(%rip), %rax       ## 0x1000019f0 <_strncmp+0x1000019f0>
1000018d5:     	movq	%rax, -0x5c0(%rbp)
1000018dc:     	movq	0x115(%rip), %rax       ## 0x1000019f8 <_strncmp+0x1000019f8>
1000018e3:     	movq	%rax, -0x5b8(%rbp)
1000018ea:     	leaq	-0x5a8(%rbp), %rdi
1000018f1:     	leaq	-0x5c0(%rbp), %rsi
1000018f8:     	callq	0x100001190 <_tea_encrypt>
1000018fd:     	movl	-0x5a8(%rbp), %eax
100001903:     	addq	-0x5f0(%rbp), %rax
10000190a:     	movq	%rax, -0x5f0(%rbp)
100001911:     	movq	-0x5f0(%rbp), %rsi
100001918:     	leaq	0xc4(%rip), %rdi        ## 0x1000019e3 <_strncmp+0x1000019e3>
10000191f:     	movb	$0x0, %al
100001921:     	callq	0x1000019b0 <_strncmp+0x1000019b0>
100001926:     	movq	0x6f3(%rip), %rax       ## 0x100002020 <_strncmp+0x100002020>
10000192d:     	movq	(%rax), %rax
100001930:     	movq	-0x8(%rbp), %rcx
100001934:     	cmpq	%rcx, %rax
100001937:     	jne	0x100001944 <_main+0x6f4>
100001939:     	xorl	%eax, %eax
10000193b:     	addq	$0x6c0, %rsp            ## imm = 0x6C0
100001942:     	popq	%rbp
100001943:     	retq
100001944:     	callq	0x100001962 <_strncmp+0x100001962>

Disassembly of section __TEXT,__stubs:

000000010000194a <__stubs>:
10000194a:     	jmpq	*0x6b0(%rip)            ## 0x100002000 <_strncmp+0x100002000>
100001950:     	jmpq	*0x6b2(%rip)            ## 0x100002008 <_strncmp+0x100002008>
100001956:     	jmpq	*0x6b4(%rip)            ## 0x100002010 <_strncmp+0x100002010>
10000195c:     	jmpq	*0x6b6(%rip)            ## 0x100002018 <_strncmp+0x100002018>
100001962:     	jmpq	*0x6c0(%rip)            ## 0x100002028 <_strncmp+0x100002028>
100001968:     	jmpq	*0x6c2(%rip)            ## 0x100002030 <_strncmp+0x100002030>
10000196e:     	jmpq	*0x6c4(%rip)            ## 0x100002038 <_strncmp+0x100002038>
100001974:     	jmpq	*0x6c6(%rip)            ## 0x100002040 <_strncmp+0x100002040>
10000197a:     	jmpq	*0x6c8(%rip)            ## 0x100002048 <_strncmp+0x100002048>
100001980:     	jmpq	*0x6d2(%rip)            ## 0x100002058 <_strncmp+0x100002058>
100001986:     	jmpq	*0x6d4(%rip)            ## 0x100002060 <_strncmp+0x100002060>
10000198c:     	jmpq	*0x6d6(%rip)            ## 0x100002068 <_strncmp+0x100002068>
100001992:     	jmpq	*0x6d8(%rip)            ## 0x100002070 <_strncmp+0x100002070>
100001998:     	jmpq	*0x6da(%rip)            ## 0x100002078 <_strncmp+0x100002078>
10000199e:     	jmpq	*0x6dc(%rip)            ## 0x100002080 <_strncmp+0x100002080>
1000019a4:     	jmpq	*0x6de(%rip)            ## 0x100002088 <_strncmp+0x100002088>
1000019aa:     	jmpq	*0x6e0(%rip)            ## 0x100002090 <_strncmp+0x100002090>
1000019b0:     	jmpq	*0x6e2(%rip)            ## 0x100002098 <_strncmp+0x100002098>
