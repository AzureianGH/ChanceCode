; ChanceCode x86 backend output

extern mix_external

section .data
align 1
g8:
    resb 1

section .data
align 8
gptr:
    resb 8

section .text

global const_binop
const_binop:
    push rbp
    mov rbp, rsp
    mov rax, 40
    push rax
    mov rax, 2
    push rax
    pop rbx
    pop rax
    add rax, rbx
    movsxd rax, eax
    push rax
    pop rax
    leave
    ret

global local_i16
local_i16:
    push rbp
    mov rbp, rsp
    sub rsp, 16
    mov word [rbp-8], cx
    movsx eax, word [rbp-8]
    push rax
    pop rax
    mov word [rbp-10], ax
    movsx eax, word [rbp-10]
    push rax
    mov rax, 3
    push rax
    pop rbx
    pop rax
    add rax, rbx
    movsx eax, ax
    push rax
    pop rax
    movsx eax, ax
    movsxd rax, eax
    push rax
    pop rax
    leave
    ret

global local_ptr
local_ptr:
    push rbp
    mov rbp, rsp
    sub rsp, 16
    mov qword [rbp-8], rcx
    mov rax, qword [rbp-8]
    push rax
    pop rax
    mov qword [rbp-16], rax
    lea rax, [rbp-8]
    push rax
    pop rax
    leave
    ret

global global_ops
global_ops:
    push rbp
    mov rbp, rsp
    movzx eax, byte [rel g8]
    movsx eax, al
    push rax
    mov rax, 1
    push rax
    pop rbx
    pop rax
    add rax, rbx
    movsx eax, al
    push rax
    pop rax
    mov byte [rel g8], al
    movzx eax, byte [rel g8]
    movsx eax, al
    push rax
    pop rax
    movzx eax, al
    mov eax, eax
    push rax
    pop rax
    leave
    ret

global indirect
indirect:
    push rbp
    mov rbp, rsp
    sub rsp, 16
    sub rsp, 8
    mov rax, rsp
    push rax
    pop rax
    mov qword [rbp-8], rax
    mov rax, qword [rbp-8]
    push rax
    mov rax, 99
    push rax
    pop rbx
    pop rcx
    mov dword [rcx], ebx
    mov rax, qword [rbp-8]
    push rax
    pop rcx
    movsxd rax, dword [rcx]
    push rax
    pop rax
    leave
    ret

global branch_test
branch_test:
    push rbp
    mov rbp, rsp
    sub rsp, 16
    mov dword [rbp-8], ecx
    movsxd rax, dword [rbp-8]
    push rax
    mov rax, 0
    push rax
    pop rbx
    pop rax
    cmp rax, rbx
    setg al
    movzx eax, al
    push rax
    pop rax
    leave
    ret

global call_test
call_test:
    push rbp
    mov rbp, rsp
    mov rax, 1
    push rax
    mov rax, 2
    push rax
    sub rsp, 32
    movsxd rax, dword [rsp + 40]
    mov rcx, rax
    movsxd rax, dword [rsp + 32]
    mov rdx, rax
    call mix_external
    add rsp, 32
    add rsp, 16
    movsxd rax, eax
    push rax
    pop rax
    leave
    ret

global drop_test
drop_test:
    push rbp
    mov rbp, rsp
    mov rax, 42
    push rax
    add rsp, 8
    mov rax, 7
    push rax
    pop rax
    leave
    ret

