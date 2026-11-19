    .intel_syntax noprefix
    .section .text.head, "ax"
    .globl blob_start
blob_start:
    .ascii "SSE42EMU"
    .long 1
    .long emu_entry - blob_start
    .long k55 - blob_start
    .long k33 - blob_start
    .long k0f - blob_start
    .long k01 - blob_start

    .balign 16
k55: .quad 0x5555555555555555
k33: .quad 0x3333333333333333
k0f: .quad 0x0f0f0f0f0f0f0f0f
k01: .quad 0x0101010101010101

    .balign 16
    .globl emu_entry
emu_entry:
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    lea rsp, [rsp - 256]
    movdqu [rsp + 0x00], xmm0
    movdqu [rsp + 0x10], xmm1
    movdqu [rsp + 0x20], xmm2
    movdqu [rsp + 0x30], xmm3
    movdqu [rsp + 0x40], xmm4
    movdqu [rsp + 0x50], xmm5
    movdqu [rsp + 0x60], xmm6
    movdqu [rsp + 0x70], xmm7
    movdqu [rsp + 0x80], xmm8
    movdqu [rsp + 0x90], xmm9
    movdqu [rsp + 0xa0], xmm10
    movdqu [rsp + 0xb0], xmm11
    movdqu [rsp + 0xc0], xmm12
    movdqu [rsp + 0xd0], xmm13
    movdqu [rsp + 0xe0], xmm14
    movdqu [rsp + 0xf0], xmm15
    mov rdi, rsp
    mov rbx, rsp
    and rsp, -16
    cld
    call emu_dispatch
    mov rsp, rbx
    movdqu xmm0,  [rsp + 0x00]
    movdqu xmm1,  [rsp + 0x10]
    movdqu xmm2,  [rsp + 0x20]
    movdqu xmm3,  [rsp + 0x30]
    movdqu xmm4,  [rsp + 0x40]
    movdqu xmm5,  [rsp + 0x50]
    movdqu xmm6,  [rsp + 0x60]
    movdqu xmm7,  [rsp + 0x70]
    movdqu xmm8,  [rsp + 0x80]
    movdqu xmm9,  [rsp + 0x90]
    movdqu xmm10, [rsp + 0xa0]
    movdqu xmm11, [rsp + 0xb0]
    movdqu xmm12, [rsp + 0xc0]
    movdqu xmm13, [rsp + 0xd0]
    movdqu xmm14, [rsp + 0xe0]
    movdqu xmm15, [rsp + 0xf0]
    lea rsp, [rsp + 256]
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
    ret
