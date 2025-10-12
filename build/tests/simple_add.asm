; ChanceCode x86 backend output
section .text

global main
main:
    push rbp
    mov rbp, rsp
    mov rax, 40
    push rax
    mov rax, 2
    push rax
    pop rbx
    pop rax
    add rax, rbx
    push rax
    pop rax
    leave
    ret

