.text
.align 4
.globl trampoline
.type trampoline,@function
trampoline:
	mov sp, x1
	br x0
	brk 0
