# ChanceCode GNU assembler x86-64 backend (.intel_syntax) output

.intel_syntax noprefix

.text

.globl main
main:
    push rbp
    mov rbp, rsp
    mov rax, 123
    push rax
    pop rax
    leave
    ret


.att_syntax prefix
