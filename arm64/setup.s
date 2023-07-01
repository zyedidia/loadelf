// void setup(uint64_t segment_id, void* syscall_entry)
.text
.align 4
.globl setup
.type setup,@function
setup:
	mov x20, #0
	mov x21, x0
	mov x22, x1
	ret
