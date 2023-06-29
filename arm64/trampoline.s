.text
.align 4
.globl trampoline
.type trampoline,@function
trampoline:
	mov sp, x1
	mov x1, x0
	mov x0, x2
	br  x1
