
bin/k2_x86_64-linux-gnu.o:	file format elf64-x86-64

Disassembly of section .text:

0000000000000000 <dispatch>:
       0:      	cmpl	$0x6, %edi
       3:      	ja	0x3b <dispatch+0x3b>
       5:      	movl	%edi, %eax
       7:      	leaq	(%rip), %rcx            # 0xe <dispatch+0xe>
		000000000000000a:  R_X86_64_PC32	.rodata-0x4
       e:      	movslq	(%rcx,%rax,4), %rax
      12:      	addq	%rcx, %rax
      15:      	jmpq	*%rax
      17:      	movl	%esi, %edi
      19:      	jmp	0x1e <dispatch+0x1e>
		000000000000001a:  R_X86_64_PLT32	f0-0x4
      1e:      	xorl	$0x3, %esi
      21:      	movl	%esi, %edi
      23:      	jmp	0x28 <dispatch+0x28>
		0000000000000024:  R_X86_64_PLT32	f4-0x4
      28:      	addl	%esi, %esi
      2a:      	movl	%esi, %edi
      2c:      	jmp	0x31 <dispatch+0x31>
		000000000000002d:  R_X86_64_PLT32	f2-0x4
      31:      	addl	$-0x7, %esi
      34:      	movl	%esi, %edi
      36:      	jmp	0x3b <dispatch+0x3b>
		0000000000000037:  R_X86_64_PLT32	f3-0x4
      3b:      	movl	$0xffffffff, %eax       # imm = 0xFFFFFFFF
      40:      	retq
      41:      	incl	%esi
      43:      	movl	%esi, %edi
      45:      	jmp	0x4a <dispatch+0x4a>
		0000000000000046:  R_X86_64_PLT32	f1-0x4
      4a:      	movl	%esi, %edi
      4c:      	jmp	0x51 <dispatch+0x51>
		000000000000004d:  R_X86_64_PLT32	f5-0x4
      51:      	sarl	%esi
      53:      	movl	%esi, %edi
      55:      	jmp	0x5a <dispatch+0x5a>
		0000000000000056:  R_X86_64_PLT32	f6-0x4
      5a:      	nopw	(%rax,%rax)

0000000000000060 <canary>:
      60:      	pushq	%rbx
      61:      	subq	$0x50, %rsp
      65:      	movq	%rdi, %rsi
      68:      	movq	%fs:0x28, %rax
      71:      	movq	%rax, 0x48(%rsp)
      76:      	movq	%rsp, %rbx
      79:      	movq	%rbx, %rdi
      7c:      	callq	0x81 <canary+0x21>
		000000000000007d:  R_X86_64_PLT32	strcpy-0x4
      81:      	movq	%rbx, %rdi
      84:      	callq	0x89 <canary+0x29>
		0000000000000085:  R_X86_64_PLT32	strlen-0x4
      89:      	movq	%fs:0x28, %rcx
      92:      	cmpq	0x48(%rsp), %rcx
      97:      	jne	0x9f <canary+0x3f>
      99:      	addq	$0x50, %rsp
      9d:      	popq	%rbx
      9e:      	retq
      9f:      	callq	0xa4 <canary+0x44>
		00000000000000a0:  R_X86_64_PLT32	__stack_chk_fail-0x4
      a4:      	nopw	%cs:(%rax,%rax)

00000000000000b0 <seterr>:
      b0:      	pushq	%rbx
      b1:      	movl	%edi, %ebx
      b3:      	callq	0xb8 <seterr+0x8>
		00000000000000b4:  R_X86_64_PLT32	__errno_location-0x4
      b8:      	movl	%ebx, (%rax)
      ba:      	movl	$0xffffffff, %eax       # imm = 0xFFFFFFFF
      bf:      	popq	%rbx
      c0:      	retq
