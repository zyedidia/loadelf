.text
.align 4
.globl trampoline
.type trampoline,@function
trampoline:
	mov %rsi, %rsp
	jmp *%rdi
	hlt
