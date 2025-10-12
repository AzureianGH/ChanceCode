# ChanceCode GNU assembler x86-64 backend (.intel_syntax) output

.intel_syntax noprefix

.extern printf

.text

.globl main
main:
    push rbp
    mov rbp, rsp
    lea rax, [rip + main____str0]
    push rax
    sub rsp, 32
    mov rax, qword ptr [rsp + 32]
    mov rcx, rax
    call printf
    add rsp, 32
    add rsp, 8
    movsxd rax, eax
    push rax
    add rsp, 8
    mov rax, 0
    push rax
    pop rax
    leave
    ret

.section .rodata
.balign 1
main____str0:
    .byte 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a, 0


.att_syntax prefix
