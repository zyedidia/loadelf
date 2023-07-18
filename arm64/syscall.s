.macro PROLOGUE
stp x0, x1,   [sp, #0+16*0]
stp x2, x3,   [sp, #0+16*1]
stp x4, x5,   [sp, #0+16*2]
stp x6, x7,   [sp, #0+16*3]
stp x8, x9,   [sp, #0+16*4]
stp x10, x11, [sp, #0+16*5]
stp x12, x13, [sp, #0+16*6]
stp x16, x17, [sp, #0+16*8]
stp x18, x29, [sp, #0+16*9]
str x30,      [sp, #0+16*10]
.endm

.macro EPILOGUE
ldp x0, x1,   [sp, #0+16*0]
ldp x2, x3,   [sp, #0+16*1]
ldp x4, x5,   [sp, #0+16*2]
ldp x6, x7,   [sp, #0+16*3]
ldp x8, x9,   [sp, #0+16*4]
ldp x10, x11, [sp, #0+16*5]
ldp x12, x13, [sp, #0+16*6]
ldp x16, x17, [sp, #0+16*8]
ldp x18, x29, [sp, #0+16*9]
ldr x30,      [sp, #0+16*10]
.endm

.text
.align 4
.globl syscall_entry
.type syscall_entry,@function
syscall_entry:
	// TODO: optimize by only saving/restoring for hooked syscalls (mmap, brk)
	sub sp, sp, #176
	PROLOGUE
    mov x0, sp
	bl syscall_handler
    cbnz x0, handled
	EPILOGUE
	add sp, sp, #176
    svc #0
    ret
handled:
    EPILOGUE
    add sp, sp, #176
    ret
