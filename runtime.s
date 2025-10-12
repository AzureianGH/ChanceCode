# ChanceCode GNU assembler x86-64 backend (.intel_syntax) output

.intel_syntax noprefix

.extern malloc
.extern calloc
.extern memcpy
.extern strlen
.extern puts
.extern exit

.text

.globl report_out_of_memory
report_out_of_memory:
    push rbp
    mov rbp, rsp
    lea rax, [rip + report_out_of_memory____str0]
    push rax
    sub rsp, 32
    mov rax, qword ptr [rsp + 32]
    mov rcx, rax
    call puts
    add rsp, 32
    add rsp, 8
    movsxd rax, eax
    push rax
    add rsp, 8
    mov rax, 1
    push rax
    sub rsp, 32
    movsxd rax, dword ptr [rsp + 32]
    mov rcx, rax
    call exit
    add rsp, 32
    add rsp, 8
    xor eax, eax
    leave
    ret

.globl xmalloc
xmalloc:
    push rbp
    mov rbp, rsp
    sub rsp, 16
    mov qword ptr [rbp-8], rcx
    mov rax, qword ptr [rbp-8]
    push rax
    sub rsp, 32
    mov rax, qword ptr [rsp + 32]
    mov rcx, rax
    call malloc
    add rsp, 32
    add rsp, 8
    push rax
    pop rax
    mov qword ptr [rbp-16], rax
    mov rax, qword ptr [rbp-16]
    push rax
    xor rax, rax
    push rax
    pop rbx
    pop rax
    cmp rax, rbx
    sete al
    movzx eax, al
    push rax
    pop rax
    cmp rax, 0
    jne xmalloc__xmalloc_fail
    jmp xmalloc__xmalloc_ok
xmalloc__xmalloc_ok:
    mov rax, qword ptr [rbp-16]
    push rax
    pop rax
    leave
    ret
xmalloc__xmalloc_fail:
    sub rsp, 32
    call report_out_of_memory
    add rsp, 32
    xor rax, rax
    push rax
    pop rax
    leave
    ret

.globl xcalloc
xcalloc:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    mov qword ptr [rbp-8], rcx
    mov qword ptr [rbp-16], rdx
    mov rax, qword ptr [rbp-8]
    push rax
    mov rax, qword ptr [rbp-16]
    push rax
    sub rsp, 32
    mov rax, qword ptr [rsp + 40]
    mov rcx, rax
    mov rax, qword ptr [rsp + 32]
    mov rdx, rax
    call calloc
    add rsp, 32
    add rsp, 16
    push rax
    pop rax
    mov qword ptr [rbp-24], rax
    mov rax, qword ptr [rbp-24]
    push rax
    xor rax, rax
    push rax
    pop rbx
    pop rax
    cmp rax, rbx
    sete al
    movzx eax, al
    push rax
    pop rax
    cmp rax, 0
    jne xcalloc__xcalloc_fail
    jmp xcalloc__xcalloc_ok
xcalloc__xcalloc_ok:
    mov rax, qword ptr [rbp-24]
    push rax
    pop rax
    leave
    ret
xcalloc__xcalloc_fail:
    sub rsp, 32
    call report_out_of_memory
    add rsp, 32
    xor rax, rax
    push rax
    pop rax
    leave
    ret

.globl xstrdup
xstrdup:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    mov qword ptr [rbp-8], rcx
    mov rax, qword ptr [rbp-8]
    push rax
    sub rsp, 32
    mov rax, qword ptr [rsp + 32]
    mov rcx, rax
    call strlen
    add rsp, 32
    add rsp, 8
    push rax
    mov rax, 0x1
    push rax
    pop rbx
    pop rax
    add rax, rbx
    push rax
    pop rax
    mov qword ptr [rbp-16], rax
    mov rax, qword ptr [rbp-16]
    push rax
    sub rsp, 32
    mov rax, qword ptr [rsp + 32]
    mov rcx, rax
    call xmalloc
    add rsp, 32
    add rsp, 8
    push rax
    pop rax
    mov qword ptr [rbp-24], rax
    mov rax, qword ptr [rbp-24]
    push rax
    mov rax, qword ptr [rbp-8]
    push rax
    mov rax, qword ptr [rbp-16]
    push rax
    sub rsp, 32
    mov rax, qword ptr [rsp + 48]
    mov rcx, rax
    mov rax, qword ptr [rsp + 40]
    mov rdx, rax
    mov rax, qword ptr [rsp + 32]
    mov r8, rax
    call memcpy
    add rsp, 32
    add rsp, 24
    push rax
    add rsp, 8
    mov rax, qword ptr [rbp-24]
    push rax
    pop rax
    leave
    ret

.section .rodata
.balign 1
report_out_of_memory____str0:
    .byte 0x4f, 0x75, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x0a, 0


.att_syntax prefix
