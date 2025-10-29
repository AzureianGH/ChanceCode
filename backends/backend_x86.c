#include "cc/backend.h"
#include "cc/bytecode.h"
#include "cc/diagnostics.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define X86_STACK_ALIGNMENT 16

typedef enum {
    X86_ASM_NASM = 0,
    X86_ASM_GAS
} X86AsmFlavor;

typedef struct {
    X86AsmFlavor flavor;
    const char *backend_name;
    const char *backend_description;
    const char *comment_prefix;
    const char *text_section;
    const char *data_section;
    const char *rodata_section;
    const char *bss_section;
    const char *global_directive;
    const char *extern_directive;
    const char *align_directive;
    const char *byte_directive;
    const char *word_directive;
    const char *dword_directive;
    const char *qword_directive;
    const char *space_directive;
    const char *byte_mem_keyword;
    const char *word_mem_keyword;
    const char *dword_mem_keyword;
    const char *qword_mem_keyword;
    const char *rip_relative_operand_fmt;
    bool needs_intel_syntax;
} X86Syntax;

typedef struct
{
    const char *name;
    size_t int_register_count;
    size_t shadow_space_bytes;
    const char *reg8[6];
    const char *reg16[6];
    const char *reg32[6];
    const char *reg64[6];
    size_t float_register_count;
    const char *xmm[8];
} X86ABIInfo;

static const X86Syntax kNasmSyntax = {
    .flavor = X86_ASM_NASM,
    .backend_name = "x86",
    .backend_description = "NASM-style x86-64 backend",
    .comment_prefix = ";",
    .text_section = "section .text",
    .data_section = "section .data",
    .rodata_section = "section .rodata",
    .bss_section = "section .bss",
    .global_directive = "global",
    .extern_directive = "extern",
    .align_directive = "align",
    .byte_directive = "db",
    .word_directive = "dw",
    .dword_directive = "dd",
    .qword_directive = "dq",
    .space_directive = "resb",
    .byte_mem_keyword = "byte",
    .word_mem_keyword = "word",
    .dword_mem_keyword = "dword",
    .qword_mem_keyword = "qword",
    .rip_relative_operand_fmt = "[rel %s]",
    .needs_intel_syntax = false,
};

static const X86Syntax kGasSyntax = {
    .flavor = X86_ASM_GAS,
    .backend_name = "x86-gas",
    .backend_description = "GNU assembler x86-64 backend (.intel_syntax)",
    .comment_prefix = "#",
    .text_section = ".text",
    .data_section = ".data",
    .rodata_section = ".section .rodata",
    .bss_section = ".bss",
    .global_directive = ".globl",
    .extern_directive = ".extern",
    .align_directive = ".balign",
    .byte_directive = ".byte",
    .word_directive = ".word",
    .dword_directive = ".long",
    .qword_directive = ".quad",
    .space_directive = ".space",
    .byte_mem_keyword = "byte ptr",
    .word_mem_keyword = "word ptr",
    .dword_mem_keyword = "dword ptr",
    .qword_mem_keyword = "qword ptr",
    .rip_relative_operand_fmt = "[rip + %s]",
    .needs_intel_syntax = true,
};

static const X86ABIInfo kX86AbiWin64 = {
    .name = "windows",
    .int_register_count = 4,
    .shadow_space_bytes = 32,
    .reg8 = {"cl", "dl", "r8b", "r9b", NULL, NULL},
    .reg16 = {"cx", "dx", "r8w", "r9w", NULL, NULL},
    .reg32 = {"ecx", "edx", "r8d", "r9d", NULL, NULL},
    .reg64 = {"rcx", "rdx", "r8", "r9", NULL, NULL},
    .float_register_count = 4,
    .xmm = {"xmm0", "xmm1", "xmm2", "xmm3", NULL, NULL, NULL, NULL},
};

static const X86ABIInfo kX86AbiSystemV = {
    .name = "linux",
    .int_register_count = 6,
    .shadow_space_bytes = 0,
    .reg8 = {"dil", "sil", "dl", "cl", "r8b", "r9b"},
    .reg16 = {"di", "si", "dx", "cx", "r8w", "r9w"},
    .reg32 = {"edi", "esi", "edx", "ecx", "r8d", "r9d"},
    .reg64 = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"},
    .float_register_count = 8,
    .xmm = {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"},
};

typedef enum
{
    STACK_LOC_NONE = 0,
    STACK_LOC_RAX,
    STACK_LOC_R10,
    STACK_LOC_R11,
    STACK_LOC_STACK,
} StackLocation;

typedef struct
{
    CCValueType type;
    bool is_unsigned;
    StackLocation location;
} StackValue;

typedef struct {
    char *label;
    const char *data;
    size_t length;
} X86StringLiteral;

typedef struct {
    X86StringLiteral *items;
    size_t count;
    size_t capacity;
} X86StringTable;

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} X86StringSet;

typedef struct {
    FILE *out;
    const CCModule *module;
    CCDiagnosticSink *sink;
    X86StringTable strings;
    X86StringSet externs;
    size_t string_counter;
    const X86Syntax *syntax;
    const X86ABIInfo *abi;
} X86ModuleContext;

typedef struct {
    X86ModuleContext *module;
    const CCFunction *fn;
    FILE *out;
    CCDiagnosticSink *sink;
    const X86Syntax *syntax;
    const X86ABIInfo *abi;
    StackValue *stack;
    size_t stack_size;
    size_t stack_capacity;
    int stack_depth;
    int32_t *param_offsets;
    int32_t *local_offsets;
    size_t param_count;
    size_t local_count;
    size_t frame_size;
    bool saw_return;
    bool reg_r10_in_use;
    bool reg_r11_in_use;
    bool use_frame;
    bool terminated;
} X86FunctionContext;

static size_t align_to(size_t value, size_t alignment)
{
    if (alignment == 0)
        return value;
    size_t mask = alignment - 1;
    return (value + mask) & ~mask;
}

static const char *backend_option_get(const CCBackendOptions *options, const char *key)
{
    if (!options || !key)
        return NULL;
    for (size_t i = 0; i < options->option_count; ++i)
    {
        if (strcmp(options->options[i].key, key) == 0)
            return options->options[i].value;
    }
    return NULL;
}

static void string_table_destroy(X86StringTable *table)
{
    if (!table)
        return;
    for (size_t i = 0; i < table->count; ++i)
        free(table->items[i].label);
    free(table->items);
    table->items = NULL;
    table->count = 0;
    table->capacity = 0;
}

static bool string_table_reserve(X86StringTable *table, size_t desired)
{
    if (table->capacity >= desired)
        return true;
    size_t new_capacity = table->capacity ? table->capacity * 2 : 8;
    while (new_capacity < desired)
        new_capacity *= 2;
    X86StringLiteral *new_items = (X86StringLiteral *)realloc(table->items, new_capacity * sizeof(X86StringLiteral));
    if (!new_items)
        return false;
    table->items = new_items;
    table->capacity = new_capacity;
    return true;
}

static bool string_table_add(X86StringTable *table, const char *label, const char *data, size_t length)
{
    if (!string_table_reserve(table, table->count + 1))
        return false;
    char *label_copy = NULL;
    if (label)
    {
        size_t len = strlen(label);
        label_copy = (char *)malloc(len + 1);
        if (!label_copy)
            return false;
        memcpy(label_copy, label, len + 1);
    }
    table->items[table->count].label = label_copy;
    table->items[table->count].data = data;
    table->items[table->count].length = length;
    ++table->count;
    return true;
}

static void string_set_destroy(X86StringSet *set)
{
    if (!set)
        return;
    for (size_t i = 0; i < set->count; ++i)
        free(set->items[i]);
    free(set->items);
    set->items = NULL;
    set->count = 0;
    set->capacity = 0;
}

static bool string_set_reserve(X86StringSet *set, size_t desired)
{
    if (set->capacity >= desired)
        return true;
    size_t new_capacity = set->capacity ? set->capacity * 2 : 8;
    while (new_capacity < desired)
        new_capacity *= 2;
    char **new_items = (char **)realloc(set->items, new_capacity * sizeof(char *));
    if (!new_items)
        return false;
    set->items = new_items;
    set->capacity = new_capacity;
    return true;
}

static bool string_set_contains(const X86StringSet *set, const char *value)
{
    if (!set || !value)
        return false;
    for (size_t i = 0; i < set->count; ++i)
    {
        if (strcmp(set->items[i], value) == 0)
            return true;
    }
    return false;
}

static bool string_set_add(X86StringSet *set, const char *value)
{
    if (!value)
        return true;
    if (string_set_contains(set, value))
        return true;
    if (!string_set_reserve(set, set->count + 1))
        return false;
    size_t len = strlen(value);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
        return false;
    memcpy(copy, value, len + 1);
    set->items[set->count++] = copy;
    return true;
}

static bool equals_ignore_case(const char *a, const char *b)
{
    if (!a || !b)
        return false;
    while (*a && *b)
    {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        ca = (unsigned char)tolower(ca);
        cb = (unsigned char)tolower(cb);
        if (ca != cb)
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

static bool module_has_function(const CCModule *module, const char *name)
{
    if (!module || !name)
        return false;
    for (size_t i = 0; i < module->function_count; ++i)
    {
        if (module->functions[i].name && strcmp(module->functions[i].name, name) == 0)
            return true;
    }
    return false;
}

static bool module_symbol_is_noreturn(const CCModule *module, const char *name)
{
    if (!module || !name)
        return false;
    const CCExtern *ext = cc_module_find_extern_const(module, name);
    if (ext && ext->is_noreturn)
        return true;
    for (size_t i = 0; i < module->function_count; ++i)
    {
        const CCFunction *fn = &module->functions[i];
        if (fn->name && strcmp(fn->name, name) == 0)
            return fn->is_noreturn;
    }
    return false;
}

static bool module_symbol_is_varargs(const CCModule *module, const char *name)
{
    if (!module || !name)
        return false;

    const CCExtern *ext = cc_module_find_extern_const(module, name);
    if (ext && ext->is_varargs)
        return true;

    for (size_t i = 0; i < module->function_count; ++i)
    {
        const CCFunction *fn = &module->functions[i];
        if (fn->name && strcmp(fn->name, name) == 0)
            return fn->is_varargs;
    }

    return false;
}

static const CCGlobal *module_find_global(const CCModule *module, const char *name)
{
    if (!module || !name)
        return NULL;
    for (size_t i = 0; i < module->global_count; ++i)
    {
        if (module->globals[i].name && strcmp(module->globals[i].name, name) == 0)
            return &module->globals[i];
    }
    return NULL;
}

static void emit_diag(CCDiagnosticSink *sink, CCDiagnosticSeverity severity, size_t line, const char *fmt, ...)
{
    if (!sink || !sink->callback)
        return;
    va_list args;
    va_start(args, fmt);
    char buffer[512];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    CCDiagnostic diag;
    diag.severity = severity;
    diag.line = line;
    diag.column = 0;
    diag.message = buffer;
    sink->callback(&diag, sink->userdata);
}

static bool module_add_string_literal(X86ModuleContext *ctx, const char *label, const char *data, size_t length)
{
    return string_table_add(&ctx->strings, label, data, length);
}

static const char *module_intern_string_literal(X86ModuleContext *ctx, const CCFunction *fn, const CCInstruction *ins)
{
    if (!ctx || !fn || !ins)
        return NULL;
    char label[256];
    if (ins->data.const_string.label_hint && ins->data.const_string.label_hint[0] != '\0')
        snprintf(label, sizeof(label), "%s__%s", fn->name, ins->data.const_string.label_hint);
    else
        snprintf(label, sizeof(label), "%s__str%zu", fn->name, ctx->string_counter++);
    if (!module_add_string_literal(ctx, label, ins->data.const_string.bytes, ins->data.const_string.length))
        return NULL;
    return ctx->strings.items[ctx->strings.count - 1].label;
}

static void format_rip_relative_operand(const X86Syntax *syntax, char *buffer, size_t buffer_size, const char *symbol)
{
    if (!syntax || !buffer || buffer_size == 0)
        return;
    if (!symbol)
        symbol = "";
    snprintf(buffer, buffer_size, syntax->rip_relative_operand_fmt, symbol);
}

static bool function_stack_reserve(X86FunctionContext *ctx, size_t desired)
{
    if (ctx->stack_capacity >= desired)
        return true;
    size_t new_capacity = ctx->stack_capacity ? ctx->stack_capacity * 2 : 16;
    while (new_capacity < desired)
        new_capacity *= 2;
    StackValue *new_items = (StackValue *)realloc(ctx->stack, new_capacity * sizeof(StackValue));
    if (!new_items)
        return false;
    ctx->stack = new_items;
    ctx->stack_capacity = new_capacity;
    return true;
}

static bool function_stack_push(X86FunctionContext *ctx, CCValueType type, bool is_unsigned)
{
    if (!function_stack_reserve(ctx, ctx->stack_size + 1))
        return false;
    ctx->stack[ctx->stack_size].type = type;
    ctx->stack[ctx->stack_size].is_unsigned = is_unsigned;
    ctx->stack[ctx->stack_size].location = STACK_LOC_NONE;
    ++ctx->stack_size;
    ++ctx->stack_depth;
    return true;
}

static bool function_stack_pop(X86FunctionContext *ctx, StackValue *out)
{
    if (ctx->stack_size == 0)
        return false;
    --ctx->stack_size;
    --ctx->stack_depth;
    if (out)
        *out = ctx->stack[ctx->stack_size];
    return true;
}

static StackValue *function_stack_peek(X86FunctionContext *ctx, size_t index_from_top)
{
    if (!ctx || index_from_top >= ctx->stack_size)
        return NULL;
    return &ctx->stack[ctx->stack_size - 1 - index_from_top];
}

static void x86_release_location(X86FunctionContext *ctx, StackLocation loc)
{
    if (!ctx)
        return;
    if (loc == STACK_LOC_R10)
        ctx->reg_r10_in_use = false;
    else if (loc == STACK_LOC_R11)
        ctx->reg_r11_in_use = false;
}

static void x86_move_top_from_rax(X86FunctionContext *ctx)
{
    if (!ctx)
        return;
    StackValue *top = function_stack_peek(ctx, 0);
    if (!top || top->location != STACK_LOC_RAX)
        return;

    if (!ctx->reg_r10_in_use)
    {
        fprintf(ctx->out, "    mov r10, rax\n");
        top->location = STACK_LOC_R10;
        ctx->reg_r10_in_use = true;
    }
    else if (!ctx->reg_r11_in_use)
    {
        fprintf(ctx->out, "    mov r11, rax\n");
        top->location = STACK_LOC_R11;
        ctx->reg_r11_in_use = true;
    }
    else
    {
        /* Spill the oldest register-backed value so argument order is preserved. */
        size_t spill_index = SIZE_MAX;
        StackLocation spill_loc = STACK_LOC_NONE;

        for (size_t i = 0; i < ctx->stack_size; ++i)
        {
            StackLocation loc = ctx->stack[i].location;
            if (loc == STACK_LOC_R10 || loc == STACK_LOC_R11)
            {
                spill_index = i;
                spill_loc = loc;
                break;
            }
        }

        if (spill_loc == STACK_LOC_R10)
        {
            fprintf(ctx->out, "    push r10\n");
            ctx->reg_r10_in_use = false;
            ctx->stack[spill_index].location = STACK_LOC_STACK;
            fprintf(ctx->out, "    mov r10, rax\n");
            top->location = STACK_LOC_R10;
            ctx->reg_r10_in_use = true;
        }
        else if (spill_loc == STACK_LOC_R11)
        {
            fprintf(ctx->out, "    push r11\n");
            ctx->reg_r11_in_use = false;
            ctx->stack[spill_index].location = STACK_LOC_STACK;
            fprintf(ctx->out, "    mov r11, rax\n");
            top->location = STACK_LOC_R11;
            ctx->reg_r11_in_use = true;
        }
        else
        {
            fprintf(ctx->out, "    push rax\n");
            top->location = STACK_LOC_STACK;
        }
    }
}

static void x86_ensure_rax_available(X86FunctionContext *ctx)
{
    if (!ctx)
        return;
    x86_move_top_from_rax(ctx);
}

static void x86_flush_virtual_stack(X86FunctionContext *ctx)
{
    if (!ctx)
        return;
    for (size_t i = 0; i < ctx->stack_size; ++i)
    {
        StackValue *value = &ctx->stack[i];
        switch (value->location)
        {
        case STACK_LOC_RAX:
            fprintf(ctx->out, "    push rax\n");
            value->location = STACK_LOC_STACK;
            break;
        case STACK_LOC_R10:
            fprintf(ctx->out, "    push r10\n");
            value->location = STACK_LOC_STACK;
            ctx->reg_r10_in_use = false;
            break;
        case STACK_LOC_R11:
            fprintf(ctx->out, "    push r11\n");
            value->location = STACK_LOC_STACK;
            ctx->reg_r11_in_use = false;
            break;
        default:
            break;
        }
    }
}

static bool ensure_param_offsets(X86FunctionContext *ctx)
{
    size_t param_count = ctx->fn->param_count;
    if (param_count == 0)
    {
        ctx->param_offsets = NULL;
        ctx->param_count = 0;
        return true;
    }
    ctx->param_offsets = (int32_t *)malloc(sizeof(int32_t) * param_count);
    if (!ctx->param_offsets)
        return false;
    size_t offset = 0;
    for (size_t i = 0; i < param_count; ++i)
    {
        offset += 8;
        ctx->param_offsets[i] = -(int32_t)offset;
    }
    ctx->param_count = param_count;
    return true;
}

static bool ensure_local_offsets(X86FunctionContext *ctx)
{
    size_t local_count = ctx->fn->local_count;
    if (local_count == 0)
    {
        ctx->local_offsets = NULL;
        ctx->local_count = 0;
        ctx->frame_size = align_to(ctx->param_count * 8, X86_STACK_ALIGNMENT);
        return true;
    }
    ctx->local_offsets = (int32_t *)malloc(sizeof(int32_t) * local_count);
    if (!ctx->local_offsets)
        return false;
    size_t offset = ctx->param_count * 8;
    for (size_t i = 0; i < local_count; ++i)
    {
        size_t slot_size = cc_value_type_size(ctx->fn->local_types ? ctx->fn->local_types[i] : CC_TYPE_I64);
        if (slot_size == 0 || slot_size > 8)
            slot_size = 8;
        offset = align_to(offset, slot_size < 8 ? slot_size : 8);
        offset += slot_size;
        ctx->local_offsets[i] = -(int32_t)offset;
    }
    ctx->local_count = local_count;
    ctx->frame_size = align_to(offset, X86_STACK_ALIGNMENT);
    return true;
}

static void function_context_free(X86FunctionContext *ctx)
{
    if (!ctx)
        return;
    free(ctx->stack);
    free(ctx->param_offsets);
    free(ctx->local_offsets);
    ctx->stack = NULL;
    ctx->param_offsets = NULL;
    ctx->local_offsets = NULL;
    ctx->stack_capacity = 0;
    ctx->stack_size = 0;
}

static void emit_zero_extend(FILE *out, CCValueType type)
{
    switch (type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_U8:
    case CC_TYPE_I8:
        fprintf(out, "    movzx eax, al\n");
        break;
    case CC_TYPE_U16:
    case CC_TYPE_I16:
        fprintf(out, "    movzx eax, ax\n");
        break;
    case CC_TYPE_U32:
    case CC_TYPE_I32:
    case CC_TYPE_F32:
        fprintf(out, "    mov eax, eax\n");
        break;
    default:
        break;
    }
}

static void emit_sign_extend(FILE *out, CCValueType type)
{
    switch (type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_I8:
        fprintf(out, "    movsx eax, al\n");
        break;
    case CC_TYPE_I16:
        fprintf(out, "    movsx eax, ax\n");
        break;
    case CC_TYPE_I32:
        fprintf(out, "    movsxd rax, eax\n");
        break;
    default:
        break;
    }
}

static bool emit_load_into_rax_from_rbp(X86FunctionContext *ctx, size_t line, int32_t offset, CCValueType type, bool is_unsigned)
{
    (void)line;
    FILE *out = ctx->out;
    switch (type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_U8:
    case CC_TYPE_I8:
        fprintf(out, "    movzx eax, %s [rbp%+d]\n", ctx->syntax->byte_mem_keyword, offset);
        if (!is_unsigned && type != CC_TYPE_U8)
            fprintf(out, "    movsx eax, al\n");
        break;
    case CC_TYPE_I16:
    case CC_TYPE_U16:
        if (is_unsigned)
            fprintf(out, "    movzx eax, %s [rbp%+d]\n", ctx->syntax->word_mem_keyword, offset);
        else
            fprintf(out, "    movsx eax, %s [rbp%+d]\n", ctx->syntax->word_mem_keyword, offset);
        break;
    case CC_TYPE_I32:
    case CC_TYPE_U32:
    case CC_TYPE_F32:
        if (is_unsigned)
            fprintf(out, "    mov eax, %s [rbp%+d]\n", ctx->syntax->dword_mem_keyword, offset);
        else
            fprintf(out, "    movsxd rax, %s [rbp%+d]\n", ctx->syntax->dword_mem_keyword, offset);
        break;
    default:
        fprintf(out, "    mov rax, %s [rbp%+d]\n", ctx->syntax->qword_mem_keyword, offset);
        break;
    }
    return true;
}

static bool emit_store_from_rax_to_rbp(X86FunctionContext *ctx, size_t line, int32_t offset, CCValueType type)
{
    (void)line;
    FILE *out = ctx->out;
    switch (type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_U8:
    case CC_TYPE_I8:
        fprintf(out, "    mov %s [rbp%+d], al\n", ctx->syntax->byte_mem_keyword, offset);
        break;
    case CC_TYPE_I16:
    case CC_TYPE_U16:
        fprintf(out, "    mov %s [rbp%+d], ax\n", ctx->syntax->word_mem_keyword, offset);
        break;
    case CC_TYPE_I32:
    case CC_TYPE_U32:
    case CC_TYPE_F32:
        fprintf(out, "    mov %s [rbp%+d], eax\n", ctx->syntax->dword_mem_keyword, offset);
        break;
    default:
        fprintf(out, "    mov %s [rbp%+d], rax\n", ctx->syntax->qword_mem_keyword, offset);
        break;
    }
    return true;
}

static void emit_truncate_rax(FILE *out, CCValueType type, bool is_unsigned)
{
    if (is_unsigned)
        emit_zero_extend(out, type);
    else
        emit_sign_extend(out, type);
}

static bool emit_pop_to(FILE *out, X86FunctionContext *ctx, const char *reg, StackValue *value)
{
    if (!function_stack_pop(ctx, value))
        return false;

    StackLocation loc = value->location;
    switch (loc)
    {
    case STACK_LOC_STACK:
        fprintf(out, "    pop %s\n", reg);
        break;
    case STACK_LOC_RAX:
        if (strcmp(reg, "rax") != 0)
            fprintf(out, "    mov %s, rax\n", reg);
        break;
    case STACK_LOC_R10:
        if (strcmp(reg, "r10") != 0)
            fprintf(out, "    mov %s, r10\n", reg);
        ctx->reg_r10_in_use = false;
        break;
    case STACK_LOC_R11:
        if (strcmp(reg, "r11") != 0)
            fprintf(out, "    mov %s, r11\n", reg);
        ctx->reg_r11_in_use = false;
        break;
    default:
        break;
    }
    return true;
}

static bool emit_pop_to_rax(FILE *out, X86FunctionContext *ctx, StackValue *value)
{
    if (!function_stack_pop(ctx, value))
        return false;

    switch (value->location)
    {
    case STACK_LOC_STACK:
        fprintf(out, "    pop rax\n");
        break;
    case STACK_LOC_R10:
        fprintf(out, "    mov rax, r10\n");
        ctx->reg_r10_in_use = false;
        break;
    case STACK_LOC_R11:
        fprintf(out, "    mov rax, r11\n");
        ctx->reg_r11_in_use = false;
        break;
    case STACK_LOC_RAX:
    case STACK_LOC_NONE:
        break;
    }
    value->location = STACK_LOC_RAX;
    return true;
}

static bool emit_push_rax(FILE *out, X86FunctionContext *ctx, CCValueType type, bool is_unsigned)
{
    (void)out;
    if (!function_stack_push(ctx, type, is_unsigned))
        return false;
    StackValue *slot = function_stack_peek(ctx, 0);
    if (!slot)
        return false;
    slot->type = type;
    slot->is_unsigned = is_unsigned;
    slot->location = STACK_LOC_RAX;
    return true;
}

static bool emit_pop_float_operand(X86FunctionContext *ctx, const char *xmm_reg, CCValueType type, size_t line)
{
    if (!ctx || !xmm_reg)
        return false;

    StackValue value;
    if (!function_stack_pop(ctx, &value))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, line, "floating-point operand missing");
        return false;
    }

    switch (value.location)
    {
    case STACK_LOC_STACK:
        fprintf(ctx->out, "    pop rax\n");
        break;
    case STACK_LOC_RAX:
        break;
    case STACK_LOC_R10:
        fprintf(ctx->out, "    mov rax, r10\n");
        ctx->reg_r10_in_use = false;
        break;
    case STACK_LOC_R11:
        fprintf(ctx->out, "    mov rax, r11\n");
        ctx->reg_r11_in_use = false;
        break;
    case STACK_LOC_NONE:
    default:
        emit_diag(ctx->sink, CC_DIAG_ERROR, line, "floating-point operand unavailable");
        return false;
    }

    if (type == CC_TYPE_F32)
        fprintf(ctx->out, "    movd %s, eax\n", xmm_reg);
    else if (type == CC_TYPE_F64)
        fprintf(ctx->out, "    movq %s, rax\n", xmm_reg);
    else
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, line, "unexpected non-float type in floating-point operand");
        return false;
    }

    return true;
}

static bool emit_push_float_from_xmm(X86FunctionContext *ctx, const char *xmm_reg, CCValueType type)
{
    if (!ctx || !xmm_reg)
        return false;

    if (type == CC_TYPE_F32)
        fprintf(ctx->out, "    movd eax, %s\n", xmm_reg);
    else if (type == CC_TYPE_F64)
        fprintf(ctx->out, "    movq rax, %s\n", xmm_reg);
    else
        return false;

    return emit_push_rax(ctx->out, ctx, type, false);
}

static bool emit_load_const(X86FunctionContext *ctx, const CCInstruction *ins)
{
    const CCValueType type = ins->data.constant.type;
    bool is_unsigned = ins->data.constant.is_unsigned;
    x86_ensure_rax_available(ctx);

    if (type == CC_TYPE_F32)
    {
        union
        {
            float f;
            uint32_t u;
        } bits;
        bits.f = ins->data.constant.value.f32;
        fprintf(ctx->out, "    mov eax, 0x%08x\n", bits.u);
        return emit_push_rax(ctx->out, ctx, type, false);
    }
    if (type == CC_TYPE_F64)
    {
        union
        {
            double d;
            uint64_t u;
        } bits;
        bits.d = ins->data.constant.value.f64;
        fprintf(ctx->out, "    mov rax, 0x%016llx\n", (unsigned long long)bits.u);
        return emit_push_rax(ctx->out, ctx, type, false);
    }

    if (type == CC_TYPE_PTR && ins->data.constant.is_null)
    {
        fprintf(ctx->out, "    xor rax, rax\n");
    }
    else if (is_unsigned)
    {
        fprintf(ctx->out, "    mov rax, 0x%llx\n", (unsigned long long)ins->data.constant.value.u64);
    }
    else
    {
        fprintf(ctx->out, "    mov rax, %lld\n", (long long)ins->data.constant.value.i64);
    }
    return emit_push_rax(ctx->out, ctx, type, is_unsigned);
}

static bool emit_load_local(X86FunctionContext *ctx, const CCInstruction *ins)
{
    uint32_t index = ins->data.local.index;
    if (index >= ctx->local_count)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "load_local index %u out of range", index);
        return false;
    }
    int32_t offset = ctx->local_offsets[index];
    bool is_unsigned = !cc_value_type_is_signed(ins->data.local.type);
    x86_ensure_rax_available(ctx);
    if (!emit_load_into_rax_from_rbp(ctx, ins->line, offset, ins->data.local.type, is_unsigned))
        return false;
    return emit_push_rax(ctx->out, ctx, ins->data.local.type, is_unsigned);
}

static bool emit_store_local(X86FunctionContext *ctx, const CCInstruction *ins)
{
    uint32_t index = ins->data.local.index;
    if (index >= ctx->local_count)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "store_local index %u out of range", index);
        return false;
    }
    StackValue value;
    if (!emit_pop_to_rax(ctx->out, ctx, &value))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "store_local missing value on stack");
        return false;
    }
    (void)value;
    return emit_store_from_rax_to_rbp(ctx, ins->line, ctx->local_offsets[index], ins->data.local.type);
}

static bool emit_drop(X86FunctionContext *ctx, const CCInstruction *ins)
{
    StackValue value;
    if (!function_stack_pop(ctx, &value))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "drop requires value on stack");
        return false;
    }
    if (value.type != ins->data.drop.type)
    {
        const char *expected = cc_value_type_name(ins->data.drop.type);
        const char *actual = cc_value_type_name(value.type);
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "drop expected %s but found %s",
                  expected ? expected : "<unknown>", actual ? actual : "<unknown>");
        return false;
    }
    switch (value.location)
    {
    case STACK_LOC_STACK:
        fprintf(ctx->out, "    add rsp, 8\n");
        break;
    case STACK_LOC_R10:
        ctx->reg_r10_in_use = false;
        break;
    case STACK_LOC_R11:
        ctx->reg_r11_in_use = false;
        break;
    case STACK_LOC_RAX:
    case STACK_LOC_NONE:
        break;
    }
    return true;
}

static bool emit_addr_local(X86FunctionContext *ctx, const CCInstruction *ins)
{
    uint32_t index = ins->data.local.index;
    if (index >= ctx->local_count)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "addr_local index %u out of range", index);
        return false;
    }
    x86_ensure_rax_available(ctx);
    fprintf(ctx->out, "    lea rax, [rbp%+d]\n", ctx->local_offsets[index]);
    return emit_push_rax(ctx->out, ctx, CC_TYPE_PTR, true);
}

static bool emit_load_param(X86FunctionContext *ctx, const CCInstruction *ins)
{
    uint32_t index = ins->data.param.index;
    if (index >= ctx->param_count)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "load_param index %u out of range", index);
        return false;
    }
    bool is_unsigned = !cc_value_type_is_signed(ins->data.param.type);
    x86_ensure_rax_available(ctx);
    if (!emit_load_into_rax_from_rbp(ctx, ins->line, ctx->param_offsets[index], ins->data.param.type, is_unsigned))
        return false;
    return emit_push_rax(ctx->out, ctx, ins->data.param.type, is_unsigned);
}

static bool emit_addr_param(X86FunctionContext *ctx, const CCInstruction *ins)
{
    uint32_t index = ins->data.param.index;
    if (index >= ctx->param_count)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "addr_param index %u out of range", index);
        return false;
    }
    x86_ensure_rax_available(ctx);
    fprintf(ctx->out, "    lea rax, [rbp%+d]\n", ctx->param_offsets[index]);
    return emit_push_rax(ctx->out, ctx, CC_TYPE_PTR, true);
}

static bool emit_load_global(X86FunctionContext *ctx, const CCInstruction *ins)
{
    const char *symbol = ins->data.global.symbol;
    (void)module_find_global(ctx->module->module, symbol);
    bool is_unsigned = !cc_value_type_is_signed(ins->data.global.type);
    char addr[128];
    format_rip_relative_operand(ctx->syntax, addr, sizeof(addr), symbol);
    x86_ensure_rax_available(ctx);
    switch (ins->data.global.type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_I8:
    case CC_TYPE_U8:
        fprintf(ctx->out, "    movzx eax, %s %s\n", ctx->syntax->byte_mem_keyword, addr);
        if (!is_unsigned && ins->data.global.type != CC_TYPE_U8)
            fprintf(ctx->out, "    movsx eax, al\n");
        break;
    case CC_TYPE_I16:
    case CC_TYPE_U16:
        if (is_unsigned)
            fprintf(ctx->out, "    movzx eax, %s %s\n", ctx->syntax->word_mem_keyword, addr);
        else
            fprintf(ctx->out, "    movsx eax, %s %s\n", ctx->syntax->word_mem_keyword, addr);
        break;
    case CC_TYPE_I32:
    case CC_TYPE_U32:
    case CC_TYPE_F32:
        if (is_unsigned)
            fprintf(ctx->out, "    mov eax, %s %s\n", ctx->syntax->dword_mem_keyword, addr);
        else
            fprintf(ctx->out, "    movsxd rax, %s %s\n", ctx->syntax->dword_mem_keyword, addr);
        break;
    default:
        fprintf(ctx->out, "    mov rax, %s %s\n", ctx->syntax->qword_mem_keyword, addr);
        break;
    }
    return emit_push_rax(ctx->out, ctx, ins->data.global.type, is_unsigned);
}

static bool emit_store_global(X86FunctionContext *ctx, const CCInstruction *ins)
{
    const char *symbol = ins->data.global.symbol;
    char addr[128];
    format_rip_relative_operand(ctx->syntax, addr, sizeof(addr), symbol);
    StackValue value;
    if (!emit_pop_to_rax(ctx->out, ctx, &value))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "store_global missing value on stack");
        return false;
    }
    (void)value;
    switch (ins->data.global.type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_U8:
    case CC_TYPE_I8:
        fprintf(ctx->out, "    mov %s %s, al\n", ctx->syntax->byte_mem_keyword, addr);
        break;
    case CC_TYPE_I16:
    case CC_TYPE_U16:
        fprintf(ctx->out, "    mov %s %s, ax\n", ctx->syntax->word_mem_keyword, addr);
        break;
    case CC_TYPE_I32:
    case CC_TYPE_U32:
    case CC_TYPE_F32:
        fprintf(ctx->out, "    mov %s %s, eax\n", ctx->syntax->dword_mem_keyword, addr);
        break;
    default:
        fprintf(ctx->out, "    mov %s %s, rax\n", ctx->syntax->qword_mem_keyword, addr);
        break;
    }
    return true;
}

static bool emit_addr_global(X86FunctionContext *ctx, const CCInstruction *ins)
{
    char addr[128];
    format_rip_relative_operand(ctx->syntax, addr, sizeof(addr), ins->data.global.symbol);
    x86_ensure_rax_available(ctx);
    fprintf(ctx->out, "    lea rax, %s\n", addr);
    return emit_push_rax(ctx->out, ctx, CC_TYPE_PTR, true);
}

static bool emit_load_indirect(X86FunctionContext *ctx, const CCInstruction *ins)
{
    StackValue pointer;
    if (!emit_pop_to(ctx->out, ctx, "rcx", &pointer))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "load_indirect requires pointer");
        return false;
    }
    (void)pointer;
    bool is_unsigned = ins->data.memory.is_unsigned;
    x86_ensure_rax_available(ctx);
    switch (ins->data.memory.type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_U8:
    case CC_TYPE_I8:
        fprintf(ctx->out, "    movzx eax, %s [rcx]\n", ctx->syntax->byte_mem_keyword);
        if (!is_unsigned && ins->data.memory.type != CC_TYPE_U8)
            fprintf(ctx->out, "    movsx eax, al\n");
        break;
    case CC_TYPE_I16:
    case CC_TYPE_U16:
        if (is_unsigned)
            fprintf(ctx->out, "    movzx eax, %s [rcx]\n", ctx->syntax->word_mem_keyword);
        else
            fprintf(ctx->out, "    movsx eax, %s [rcx]\n", ctx->syntax->word_mem_keyword);
        break;
    case CC_TYPE_I32:
    case CC_TYPE_U32:
    case CC_TYPE_F32:
        if (is_unsigned)
            fprintf(ctx->out, "    mov eax, %s [rcx]\n", ctx->syntax->dword_mem_keyword);
        else
            fprintf(ctx->out, "    movsxd rax, %s [rcx]\n", ctx->syntax->dword_mem_keyword);
        break;
    default:
        fprintf(ctx->out, "    mov rax, %s [rcx]\n", ctx->syntax->qword_mem_keyword);
        break;
    }
    return emit_push_rax(ctx->out, ctx, ins->data.memory.type, !cc_value_type_is_signed(ins->data.memory.type) && is_unsigned);
}

static bool emit_store_indirect(X86FunctionContext *ctx, const CCInstruction *ins)
{
    StackValue value;
    if (!emit_pop_to(ctx->out, ctx, "rbx", &value))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "store_indirect missing value");
        return false;
    }
    StackValue pointer;
    if (!emit_pop_to(ctx->out, ctx, "rcx", &pointer))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "store_indirect missing pointer");
        return false;
    }
    (void)value;
    (void)pointer;
    switch (ins->data.memory.type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_U8:
    case CC_TYPE_I8:
        fprintf(ctx->out, "    mov %s [rcx], bl\n", ctx->syntax->byte_mem_keyword);
        break;
    case CC_TYPE_I16:
    case CC_TYPE_U16:
        fprintf(ctx->out, "    mov %s [rcx], bx\n", ctx->syntax->word_mem_keyword);
        break;
    case CC_TYPE_I32:
    case CC_TYPE_U32:
    case CC_TYPE_F32:
        fprintf(ctx->out, "    mov %s [rcx], ebx\n", ctx->syntax->dword_mem_keyword);
        break;
    default:
        fprintf(ctx->out, "    mov %s [rcx], rbx\n", ctx->syntax->qword_mem_keyword);
        break;
    }
    return true;
}

static bool emit_binary_op(X86FunctionContext *ctx, const CCInstruction *ins)
{
    if (cc_value_type_is_float(ins->data.binop.type))
    {
        CCValueType type = ins->data.binop.type;
        if (!emit_pop_float_operand(ctx, "xmm1", type, ins->line))
            return false;
        if (!emit_pop_float_operand(ctx, "xmm0", type, ins->line))
            return false;

        switch (ins->data.binop.op)
        {
        case CC_BINOP_ADD:
            fprintf(ctx->out, type == CC_TYPE_F32 ? "    addss xmm0, xmm1\n" : "    addsd xmm0, xmm1\n");
            break;
        case CC_BINOP_SUB:
            fprintf(ctx->out, type == CC_TYPE_F32 ? "    subss xmm0, xmm1\n" : "    subsd xmm0, xmm1\n");
            break;
        case CC_BINOP_MUL:
            fprintf(ctx->out, type == CC_TYPE_F32 ? "    mulss xmm0, xmm1\n" : "    mulsd xmm0, xmm1\n");
            break;
        case CC_BINOP_DIV:
            fprintf(ctx->out, type == CC_TYPE_F32 ? "    divss xmm0, xmm1\n" : "    divsd xmm0, xmm1\n");
            break;
        default:
            emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported floating-point binop %d", ins->data.binop.op);
            return false;
        }

        return emit_push_float_from_xmm(ctx, "xmm0", type);
    }

    StackValue rhs;
    StackValue lhs;
    if (!emit_pop_to(ctx->out, ctx, "rbx", &rhs) || !emit_pop_to_rax(ctx->out, ctx, &lhs))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "binop requires two operands");
        return false;
    }
    (void)rhs;
    (void)lhs;
    bool is_unsigned = ins->data.binop.is_unsigned || !cc_value_type_is_signed(ins->data.binop.type);
    size_t type_size = cc_value_type_size(ins->data.binop.type);

    switch (ins->data.binop.op)
    {
    case CC_BINOP_ADD:
        fprintf(ctx->out, "    add rax, rbx\n");
        break;
    case CC_BINOP_SUB:
        fprintf(ctx->out, "    sub rax, rbx\n");
        break;
    case CC_BINOP_MUL:
        fprintf(ctx->out, "    imul rax, rbx\n");
        break;
    case CC_BINOP_DIV:
    case CC_BINOP_MOD:
        if (is_unsigned)
        {
            fprintf(ctx->out, "    xor rdx, rdx\n");
            fprintf(ctx->out, "    div rbx\n");
        }
        else
        {
            fprintf(ctx->out, "    cqo\n");
            fprintf(ctx->out, "    idiv rbx\n");
        }
        if (ins->data.binop.op == CC_BINOP_MOD)
            fprintf(ctx->out, "    mov rax, rdx\n");
        break;
    case CC_BINOP_AND:
        fprintf(ctx->out, "    and rax, rbx\n");
        break;
    case CC_BINOP_OR:
        fprintf(ctx->out, "    or rax, rbx\n");
        break;
    case CC_BINOP_XOR:
        fprintf(ctx->out, "    xor rax, rbx\n");
        break;
    case CC_BINOP_SHL:
        fprintf(ctx->out, "    mov rcx, rbx\n");
        fprintf(ctx->out, "    shl rax, cl\n");
        break;
    case CC_BINOP_SHR:
        fprintf(ctx->out, "    mov rcx, rbx\n");
        if (is_unsigned)
            fprintf(ctx->out, "    shr rax, cl\n");
        else
            fprintf(ctx->out, "    sar rax, cl\n");
        break;
    default:
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported binop %d", ins->data.binop.op);
        return false;
    }

    if (type_size < 8)
        emit_truncate_rax(ctx->out, ins->data.binop.type, is_unsigned);
    return emit_push_rax(ctx->out, ctx, ins->data.binop.type, is_unsigned);
}

static bool emit_unary_op(X86FunctionContext *ctx, const CCInstruction *ins)
{
    StackValue value;
    if (!emit_pop_to_rax(ctx->out, ctx, &value))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unop operand missing");
        return false;
    }
    switch (ins->data.unop.op)
    {
    case CC_UNOP_NEG:
        fprintf(ctx->out, "    neg rax\n");
        break;
    case CC_UNOP_NOT:
        fprintf(ctx->out, "    cmp rax, 0\n");
        fprintf(ctx->out, "    sete al\n");
        fprintf(ctx->out, "    movzx eax, al\n");
        break;
    case CC_UNOP_BITNOT:
        fprintf(ctx->out, "    not rax\n");
        break;
    default:
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported unary op %d", ins->data.unop.op);
        return false;
    }
    emit_truncate_rax(ctx->out, ins->data.unop.type, !cc_value_type_is_signed(ins->data.unop.type));
    return emit_push_rax(ctx->out, ctx, ins->data.unop.type, !cc_value_type_is_signed(ins->data.unop.type));
}

static bool emit_compare(X86FunctionContext *ctx, const CCInstruction *ins)
{
    if (cc_value_type_is_float(ins->data.compare.type))
    {
        CCValueType type = ins->data.compare.type;
        if (!emit_pop_float_operand(ctx, "xmm1", type, ins->line))
            return false;
        if (!emit_pop_float_operand(ctx, "xmm0", type, ins->line))
            return false;

        uint8_t predicate = 0xFF;
        switch (ins->data.compare.op)
        {
        case CC_COMPARE_EQ:
            predicate = 0;
            break;
        case CC_COMPARE_NE:
            predicate = 4;
            break;
        case CC_COMPARE_LT:
            predicate = 1;
            break;
        case CC_COMPARE_LE:
            predicate = 2;
            break;
        case CC_COMPARE_GT:
            predicate = 6;
            break;
        case CC_COMPARE_GE:
            predicate = 5;
            break;
        default:
            emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported floating-point compare op %d", ins->data.compare.op);
            return false;
        }

        if (predicate == 0xFF)
            return false;

        if (type == CC_TYPE_F32)
            fprintf(ctx->out, "    cmpss xmm0, xmm1, %u\n", predicate);
        else
            fprintf(ctx->out, "    cmpsd xmm0, xmm1, %u\n", predicate);

        if (type == CC_TYPE_F32)
            fprintf(ctx->out, "    movd eax, xmm0\n");
        else
            fprintf(ctx->out, "    movq rax, xmm0\n");

        fprintf(ctx->out, "    and eax, 1\n");
        return emit_push_rax(ctx->out, ctx, CC_TYPE_I1, true);
    }

    StackValue rhs;
    StackValue lhs;
    if (!emit_pop_to(ctx->out, ctx, "rbx", &rhs) || !emit_pop_to_rax(ctx->out, ctx, &lhs))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "compare requires two operands");
        return false;
    }
    fprintf(ctx->out, "    cmp rax, rbx\n");
    bool is_unsigned = ins->data.compare.is_unsigned || !cc_value_type_is_signed(ins->data.compare.type);
    const char *set_instr = NULL;
    switch (ins->data.compare.op)
    {
    case CC_COMPARE_EQ: set_instr = "sete"; break;
    case CC_COMPARE_NE: set_instr = "setne"; break;
    case CC_COMPARE_LT: set_instr = is_unsigned ? "setb" : "setl"; break;
    case CC_COMPARE_LE: set_instr = is_unsigned ? "setbe" : "setle"; break;
    case CC_COMPARE_GT: set_instr = is_unsigned ? "seta" : "setg"; break;
    case CC_COMPARE_GE: set_instr = is_unsigned ? "setae" : "setge"; break;
    default:
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported compare op %d", ins->data.compare.op);
        return false;
    }
    fprintf(ctx->out, "    %s al\n", set_instr);
    fprintf(ctx->out, "    movzx eax, al\n");
    return emit_push_rax(ctx->out, ctx, CC_TYPE_I1, true);
}

static bool emit_convert(X86FunctionContext *ctx, const CCInstruction *ins)
{
    StackValue value;
    if (!emit_pop_to_rax(ctx->out, ctx, &value))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "convert operand missing");
        return false;
    }

    CCValueType from = ins->data.convert.from_type;
    CCValueType to = ins->data.convert.to_type;
    bool from_is_float = cc_value_type_is_float(from);
    bool to_is_float = cc_value_type_is_float(to);
    bool from_is_int = cc_value_type_is_integer(from) || from == CC_TYPE_PTR;
    bool to_is_int = cc_value_type_is_integer(to) || to == CC_TYPE_PTR;

    switch (ins->data.convert.kind)
    {
    case CC_CONVERT_TRUNC:
        if (!from_is_int || !to_is_int)
        {
            emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "truncate conversion requires integer types");
            return false;
        }
        emit_truncate_rax(ctx->out, to, !cc_value_type_is_signed(to));
        break;
    case CC_CONVERT_SEXT:
        if (!from_is_int || !to_is_int)
        {
            emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "sign-extend conversion requires integer types");
            return false;
        }
        emit_sign_extend(ctx->out, from);
        emit_sign_extend(ctx->out, to);
        break;
    case CC_CONVERT_ZEXT:
        if (!from_is_int || !to_is_int)
        {
            emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "zero-extend conversion requires integer types");
            return false;
        }
        emit_zero_extend(ctx->out, from);
        emit_zero_extend(ctx->out, to);
        break;
    case CC_CONVERT_F2I:
        if (!from_is_float || !to_is_int)
        {
            emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported f2i conversion");
            return false;
        }
        if (from == CC_TYPE_F32)
            fprintf(ctx->out, "    movd xmm0, eax\n");
        else
            fprintf(ctx->out, "    movq xmm0, rax\n");

        size_t to_size = cc_value_type_size(to);
        if (from == CC_TYPE_F32)
        {
            if (to_size > 4)
                fprintf(ctx->out, "    cvttss2si rax, xmm0\n");
            else
                fprintf(ctx->out, "    cvttss2si eax, xmm0\n");
        }
        else
        {
            if (to_size > 4)
                fprintf(ctx->out, "    cvttsd2si rax, xmm0\n");
            else
                fprintf(ctx->out, "    cvttsd2si eax, xmm0\n");
        }

        if (to_size < 8)
            emit_truncate_rax(ctx->out, to, !cc_value_type_is_signed(to));
        return emit_push_rax(ctx->out, ctx, to, !cc_value_type_is_signed(to));
    case CC_CONVERT_I2F:
        if (!from_is_int || !to_is_float)
        {
            emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported i2f conversion");
            return false;
        }
        if (cc_value_type_is_signed(from))
            emit_sign_extend(ctx->out, from);
        else
            emit_zero_extend(ctx->out, from);

        if (to == CC_TYPE_F32)
            fprintf(ctx->out, "    cvtsi2ss xmm0, rax\n");
        else
            fprintf(ctx->out, "    cvtsi2sd xmm0, rax\n");

        return emit_push_float_from_xmm(ctx, "xmm0", to);
    case CC_CONVERT_BITCAST:
        if (from_is_float && to_is_float && from != to)
        {
            if (from == CC_TYPE_F32)
                fprintf(ctx->out, "    movd xmm0, eax\n");
            else
                fprintf(ctx->out, "    movq xmm0, rax\n");

            if (from == CC_TYPE_F32 && to == CC_TYPE_F64)
                fprintf(ctx->out, "    cvtss2sd xmm0, xmm0\n");
            else if (from == CC_TYPE_F64 && to == CC_TYPE_F32)
                fprintf(ctx->out, "    cvtsd2ss xmm0, xmm0\n");
            else
            {
                emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported floating bitcast conversion");
                return false;
            }

            return emit_push_float_from_xmm(ctx, "xmm0", to);
        }
        /* fall through: other bitcasts are no-ops */
        break;
    default:
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported convert kind %d", ins->data.convert.kind);
        return false;
    }

    return emit_push_rax(ctx->out, ctx, to, !cc_value_type_is_signed(to));
}

static bool emit_stack_alloc(X86FunctionContext *ctx, const CCInstruction *ins)
{
    uint32_t size = ins->data.stack_alloc.size_bytes;
    uint32_t alignment = ins->data.stack_alloc.alignment;
    if (alignment == 0)
        alignment = 16;
    uint32_t aligned = (uint32_t)align_to(size, alignment);
    if (aligned > 0)
        fprintf(ctx->out, "    sub rsp, %u\n", aligned);
    x86_ensure_rax_available(ctx);
    fprintf(ctx->out, "    mov rax, rsp\n");
    return emit_push_rax(ctx->out, ctx, CC_TYPE_PTR, true);
}

static bool emit_branch(X86FunctionContext *ctx, const CCInstruction *ins)
{
    StackValue cond;
    if (!emit_pop_to_rax(ctx->out, ctx, &cond))
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "branch requires condition");
        return false;
    }
    fprintf(ctx->out, "    cmp rax, 0\n");
    fprintf(ctx->out, "    jne %s__%s\n", ctx->fn->name, ins->data.branch.true_target);
    fprintf(ctx->out, "    jmp %s__%s\n", ctx->fn->name, ins->data.branch.false_target);
    return true;
}

static bool emit_call(X86FunctionContext *ctx, const CCInstruction *ins)
{
    x86_flush_virtual_stack(ctx);
    size_t arg_count = ins->data.call.arg_count;
    if (ctx->stack_size < arg_count)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "call '%s' missing %zu arguments", ins->data.call.symbol, arg_count);
        return false;
    }

    const StackValue *args = ctx->stack + (ctx->stack_size - arg_count);
    const X86ABIInfo *abi = ctx->abi ? ctx->abi : &kX86AbiWin64;
    size_t reg_count = abi->int_register_count;
    size_t stack_args = arg_count > reg_count ? arg_count - reg_count : 0;
    size_t base_call_area = abi->shadow_space_bytes + stack_args * 8;
    size_t spill_bytes = ctx->stack_size * 8;
    size_t prologue_bytes = ctx->use_frame ? ctx->frame_size + 8 : 0;
    size_t entry_bias = 8; // return address pushed by caller
    size_t current_offset = entry_bias + prologue_bytes + spill_bytes;
    size_t total_for_alignment = current_offset + base_call_area;
    size_t remainder = total_for_alignment % X86_STACK_ALIGNMENT;
    size_t align_padding = remainder ? (X86_STACK_ALIGNMENT - remainder) : 0;
    size_t call_frame_size = base_call_area + align_padding;
    bool is_noreturn = module_symbol_is_noreturn(ctx->module->module, ins->data.call.symbol);
    bool is_varargs = module_symbol_is_varargs(ctx->module->module, ins->data.call.symbol);
    if (call_frame_size > 0)
        fprintf(ctx->out, "    sub rsp, %zu\n", call_frame_size);

    for (size_t i = 0; i < arg_count; ++i)
    {
        size_t offset = call_frame_size + (arg_count - 1 - i) * 8;
        CCValueType arg_type = ins->data.call.arg_types ? ins->data.call.arg_types[i] : CC_TYPE_I64;
        bool promote_f32 = is_varargs && arg_type == CC_TYPE_F32;
        CCValueType pass_type = promote_f32 ? CC_TYPE_F64 : arg_type;
        bool is_unsigned = !cc_value_type_is_signed(pass_type) && args[i].is_unsigned;

        if (promote_f32)
        {
            fprintf(ctx->out, "    movss xmm7, %s [rsp + %zu]\n", ctx->syntax->dword_mem_keyword, offset);
            fprintf(ctx->out, "    cvtss2sd xmm7, xmm7\n");
            fprintf(ctx->out, "    movsd %s [rsp + %zu], xmm7\n", ctx->syntax->qword_mem_keyword, offset);
        }

        switch (pass_type)
        {
        case CC_TYPE_I1:
        case CC_TYPE_U8:
        case CC_TYPE_I8:
            fprintf(ctx->out, "    movzx eax, %s [rsp + %zu]\n", ctx->syntax->byte_mem_keyword, offset);
            if (!is_unsigned && arg_type != CC_TYPE_U8)
                fprintf(ctx->out, "    movsx eax, al\n");
            break;
        case CC_TYPE_I16:
        case CC_TYPE_U16:
            if (is_unsigned)
                fprintf(ctx->out, "    movzx eax, %s [rsp + %zu]\n", ctx->syntax->word_mem_keyword, offset);
            else
                fprintf(ctx->out, "    movsx eax, %s [rsp + %zu]\n", ctx->syntax->word_mem_keyword, offset);
            break;
        case CC_TYPE_I32:
        case CC_TYPE_U32:
        case CC_TYPE_F32:
            if (is_unsigned)
                fprintf(ctx->out, "    mov eax, %s [rsp + %zu]\n", ctx->syntax->dword_mem_keyword, offset);
            else
                fprintf(ctx->out, "    movsxd rax, %s [rsp + %zu]\n", ctx->syntax->dword_mem_keyword, offset);
            break;
        default:
            fprintf(ctx->out, "    mov rax, %s [rsp + %zu]\n", ctx->syntax->qword_mem_keyword, offset);
            break;
        }

        if (i < reg_count)
        {
            fprintf(ctx->out, "    mov %s, rax\n", abi->reg64[i]);
        }
        else
        {
            size_t slot = align_padding + abi->shadow_space_bytes + (i - reg_count) * 8;
            fprintf(ctx->out, "    mov %s [rsp + %zu], rax\n", ctx->syntax->qword_mem_keyword, slot);
        }
    }

    if (is_varargs && ctx->abi == &kX86AbiSystemV)
        fprintf(ctx->out, "    xor eax, eax\n");

    fprintf(ctx->out, "    call %s\n", ins->data.call.symbol);

    if (ctx->stack_size >= arg_count)
        ctx->stack_size -= arg_count;
    else
        ctx->stack_size = 0;
    ctx->stack_depth -= (int)arg_count;
    if (ctx->stack_depth < 0)
        ctx->stack_depth = 0;
    if (is_noreturn)
    {
        ctx->stack_size = 0;
        ctx->stack_depth = 0;
        ctx->terminated = true;
        ctx->saw_return = true;
        return true;
    }

    if (call_frame_size > 0)
        fprintf(ctx->out, "    add rsp, %zu\n", call_frame_size);
    if (arg_count > 0)
    {
        fprintf(ctx->out, "    add rsp, %zu\n", arg_count * 8);
    }

    if (ins->data.call.return_type != CC_TYPE_VOID)
    {
        emit_truncate_rax(ctx->out, ins->data.call.return_type, !cc_value_type_is_signed(ins->data.call.return_type));
        if (!emit_push_rax(ctx->out, ctx, ins->data.call.return_type, !cc_value_type_is_signed(ins->data.call.return_type)))
            return false;
    }

    return true;
}

static bool emit_ret(X86FunctionContext *ctx, const CCInstruction *ins)
{
    if (ins->data.ret.has_value)
    {
        StackValue value;
        if (!emit_pop_to_rax(ctx->out, ctx, &value))
        {
            emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "ret requires value on stack");
            return false;
        }
    }
    else
    {
        fprintf(ctx->out, "    xor eax, eax\n");
    }
    if (ctx->use_frame)
        fprintf(ctx->out, "    leave\n");
    fprintf(ctx->out, "    ret\n");
    ctx->stack_depth = 0;
    ctx->saw_return = true;
    return true;
}

static bool emit_instruction(X86FunctionContext *ctx, const CCInstruction *ins)
{
    if (ctx->terminated)
    {
        return true;
    }
    switch (ins->kind)
    {
    case CC_INSTR_CONST:
        return emit_load_const(ctx, ins);
    case CC_INSTR_CONST_STRING:
    {
        const char *label = module_intern_string_literal(ctx->module, ctx->fn, ins);
        if (!label)
            return false;
        char addr[128];
        format_rip_relative_operand(ctx->syntax, addr, sizeof(addr), label);
        x86_ensure_rax_available(ctx);
        fprintf(ctx->out, "    lea rax, %s\n", addr);
        return emit_push_rax(ctx->out, ctx, CC_TYPE_PTR, true);
    }
    case CC_INSTR_LOAD_LOCAL:
        return emit_load_local(ctx, ins);
    case CC_INSTR_STORE_LOCAL:
        return emit_store_local(ctx, ins);
    case CC_INSTR_ADDR_LOCAL:
        return emit_addr_local(ctx, ins);
    case CC_INSTR_LOAD_PARAM:
        return emit_load_param(ctx, ins);
    case CC_INSTR_ADDR_PARAM:
        return emit_addr_param(ctx, ins);
    case CC_INSTR_LOAD_GLOBAL:
        return emit_load_global(ctx, ins);
    case CC_INSTR_STORE_GLOBAL:
        return emit_store_global(ctx, ins);
    case CC_INSTR_ADDR_GLOBAL:
        return emit_addr_global(ctx, ins);
    case CC_INSTR_LOAD_INDIRECT:
        return emit_load_indirect(ctx, ins);
    case CC_INSTR_STORE_INDIRECT:
        return emit_store_indirect(ctx, ins);
    case CC_INSTR_BINOP:
        return emit_binary_op(ctx, ins);
    case CC_INSTR_UNOP:
        return emit_unary_op(ctx, ins);
    case CC_INSTR_COMPARE:
        return emit_compare(ctx, ins);
    case CC_INSTR_CONVERT:
        return emit_convert(ctx, ins);
    case CC_INSTR_STACK_ALLOC:
        return emit_stack_alloc(ctx, ins);
    case CC_INSTR_DROP:
        return emit_drop(ctx, ins);
    case CC_INSTR_LABEL:
        fprintf(ctx->out, "%s__%s:\n", ctx->fn->name, ins->data.label.name);
        return true;
    case CC_INSTR_JUMP:
        fprintf(ctx->out, "    jmp %s__%s\n", ctx->fn->name, ins->data.jump.target);
        return true;
    case CC_INSTR_BRANCH:
        return emit_branch(ctx, ins);
    case CC_INSTR_CALL:
        return emit_call(ctx, ins);
    case CC_INSTR_RET:
        return emit_ret(ctx, ins);
    case CC_INSTR_COMMENT:
        fprintf(ctx->out, "    %s %s\n", ctx->syntax->comment_prefix, ins->data.comment.text ? ins->data.comment.text : "");
        return true;
    default:
        emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported instruction kind %d", ins->kind);
        return false;
    }
}

static void emit_function_prologue(X86FunctionContext *ctx)
{
    fprintf(ctx->out, "%s %s\n", ctx->syntax->global_directive, ctx->fn->name);
    fprintf(ctx->out, "%s:\n", ctx->fn->name);
    if (!ctx->use_frame)
        return;
    fprintf(ctx->out, "    push rbp\n");
    fprintf(ctx->out, "    mov rbp, rsp\n");
    if (ctx->frame_size > 0)
        fprintf(ctx->out, "    sub rsp, %zu\n", ctx->frame_size);

    const X86ABIInfo *abi = ctx->abi ? ctx->abi : &kX86AbiWin64;
    size_t reg_count = abi->int_register_count;

    for (size_t i = 0; i < ctx->param_count; ++i)
    {
        CCValueType type = ctx->fn->param_types ? ctx->fn->param_types[i] : CC_TYPE_I64;
        int32_t offset = ctx->param_offsets[i];
        if (i < reg_count)
        {
            switch (type)
            {
            case CC_TYPE_I1:
            case CC_TYPE_U8:
            case CC_TYPE_I8:
                fprintf(ctx->out, "    mov %s [rbp%+d], %s\n", ctx->syntax->byte_mem_keyword, offset, abi->reg8[i]);
                break;
            case CC_TYPE_I16:
            case CC_TYPE_U16:
                fprintf(ctx->out, "    mov %s [rbp%+d], %s\n", ctx->syntax->word_mem_keyword, offset, abi->reg16[i]);
                break;
            case CC_TYPE_I32:
            case CC_TYPE_U32:
            case CC_TYPE_F32:
                fprintf(ctx->out, "    mov %s [rbp%+d], %s\n", ctx->syntax->dword_mem_keyword, offset, abi->reg32[i]);
                break;
            default:
                fprintf(ctx->out, "    mov %s [rbp%+d], %s\n", ctx->syntax->qword_mem_keyword, offset, abi->reg64[i]);
                break;
            }
        }
        else
        {
            size_t stack_offset = 16 + abi->shadow_space_bytes + (i - reg_count) * 8;
            fprintf(ctx->out, "    mov rax, %s [rbp + %zu]\n", ctx->syntax->qword_mem_keyword, stack_offset);
            emit_store_from_rax_to_rbp(ctx, 0, offset, type);
        }
    }
}

static bool emit_function(X86ModuleContext *module_ctx, const CCFunction *fn)
{
    X86FunctionContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.module = module_ctx;
    ctx.fn = fn;
    ctx.out = module_ctx->out;
    ctx.sink = module_ctx->sink;
    ctx.syntax = module_ctx->syntax;
    ctx.abi = module_ctx->abi;

    if (!ensure_param_offsets(&ctx))
    {
        function_context_free(&ctx);
        return false;
    }
    if (!ensure_local_offsets(&ctx))
    {
        function_context_free(&ctx);
        return false;
    }

    ctx.use_frame = (ctx.frame_size > 0) || (ctx.param_count > 0);
    if (!ctx.use_frame)
    {
        for (size_t i = 0; i < fn->instruction_count; ++i)
        {
            CCInstrKind kind = fn->instructions[i].kind;
            if (kind == CC_INSTR_STACK_ALLOC ||
                kind == CC_INSTR_LOAD_PARAM ||
                kind == CC_INSTR_ADDR_PARAM ||
                kind == CC_INSTR_LOAD_LOCAL ||
                kind == CC_INSTR_STORE_LOCAL ||
                kind == CC_INSTR_ADDR_LOCAL)
            {
                ctx.use_frame = true;
                break;
            }
        }
    }

    emit_function_prologue(&ctx);

    for (size_t i = 0; i < fn->instruction_count; ++i)
    {
        if (!emit_instruction(&ctx, &fn->instructions[i]))
        {
            function_context_free(&ctx);
            return false;
        }
    }

    if (!ctx.saw_return)
    {
        fprintf(ctx.out, "    xor eax, eax\n");
        if (ctx.use_frame)
            fprintf(ctx.out, "    leave\n");
        fprintf(ctx.out, "    ret\n");
    }

    if (ctx.stack_depth != 0)
        emit_diag(ctx.sink, CC_DIAG_WARNING, 0, "function '%s' leaves %d values on the evaluation stack", fn->name, ctx.stack_depth);

    fprintf(ctx.out, "\n");
    function_context_free(&ctx);
    return true;
}

static void emit_global_data(const X86ModuleContext *ctx, const CCGlobal *global)
{
    FILE *out = ctx->out;
    const char *section = global->is_const ? ctx->syntax->rodata_section : ctx->syntax->data_section;
    fprintf(out, "%s\n", section);
    fprintf(out, "%s %zu\n", ctx->syntax->align_directive, global->alignment ? global->alignment : cc_value_type_size(global->type));
    fprintf(out, "%s:\n", global->name);
    size_t size = cc_value_type_size(global->type);
    if (size == 0)
        size = 8;

    switch (global->init.kind)
    {
    case CC_GLOBAL_INIT_INT:
        if (size <= 1)
            fprintf(out, "    %s 0x%02llx\n", ctx->syntax->byte_directive, (unsigned long long)global->init.payload.u64 & 0xFFULL);
        else if (size <= 2)
            fprintf(out, "    %s 0x%04llx\n", ctx->syntax->word_directive, (unsigned long long)global->init.payload.u64 & 0xFFFFULL);
        else if (size <= 4)
            fprintf(out, "    %s 0x%08llx\n", ctx->syntax->dword_directive, (unsigned long long)global->init.payload.u64 & 0xFFFFFFFFULL);
        else
            fprintf(out, "    %s 0x%016llx\n", ctx->syntax->qword_directive, (unsigned long long)global->init.payload.u64);
        break;
    case CC_GLOBAL_INIT_STRING:
        fprintf(out, "    %s ", ctx->syntax->byte_directive);
        for (size_t i = 0; i < global->init.payload.string.length; ++i)
            fprintf(out, "%s0x%02x", (i == 0 ? "" : ", "), (unsigned char)global->init.payload.string.data[i]);
        fprintf(out, ", 0\n");
        break;
    case CC_GLOBAL_INIT_BYTES:
        fprintf(out, "    %s ", ctx->syntax->byte_directive);
        for (size_t i = 0; i < global->init.payload.bytes.size; ++i)
            fprintf(out, "%s0x%02x", (i == 0 ? "" : ", "), global->init.payload.bytes.data[i]);
        fprintf(out, "\n");
        break;
    default:
        fprintf(out, "    %s %zu\n", ctx->syntax->space_directive, size);
        break;
    }
    fprintf(out, "\n");
}

static void emit_string_literals(const X86ModuleContext *ctx)
{
    if (ctx->strings.count == 0)
        return;
    FILE *out = ctx->out;
    fprintf(out, "%s\n", ctx->syntax->rodata_section);
    for (size_t i = 0; i < ctx->strings.count; ++i)
    {
        const X86StringLiteral *lit = &ctx->strings.items[i];
        fprintf(out, "%s 1\n", ctx->syntax->align_directive);
        fprintf(out, "%s:\n", lit->label);
        fprintf(out, "    %s ", ctx->syntax->byte_directive);
        for (size_t j = 0; j < lit->length; ++j)
            fprintf(out, "%s0x%02x", (j == 0 ? "" : ", "), (unsigned char)lit->data[j]);
        fprintf(out, ", 0\n\n");
    }
}

static bool collect_externs(X86ModuleContext *ctx)
{
    if (!ctx || !ctx->module)
        return false;
    const CCModule *module = ctx->module;

    for (size_t i = 0; i < module->extern_count; ++i)
    {
        const CCExtern *ext = &module->externs[i];
        if (ext->name && !string_set_add(&ctx->externs, ext->name))
            return false;
    }

    for (size_t i = 0; i < module->function_count; ++i)
    {
        const CCFunction *fn = &module->functions[i];
        for (size_t j = 0; j < fn->instruction_count; ++j)
        {
            const CCInstruction *ins = &fn->instructions[j];
            if (ins->kind == CC_INSTR_CALL)
            {
                const char *symbol = ins->data.call.symbol;
                if (symbol && !module_has_function(module, symbol))
                {
                    if (!string_set_add(&ctx->externs, symbol))
                        return false;
                }
            }
        }
    }
    return true;
}

static void emit_externs(const X86ModuleContext *ctx)
{
    for (size_t i = 0; i < ctx->externs.count; ++i)
        fprintf(ctx->out, "%s %s\n", ctx->syntax->extern_directive, ctx->externs.items[i]);
    if (ctx->externs.count > 0)
        fprintf(ctx->out, "\n");
}

static bool emit_module(const CCBackend *backend,
                        const CCModule *module,
                        const CCBackendOptions *options,
                        CCDiagnosticSink *sink,
                        void *userdata)
{
    (void)userdata;
    if (!module)
        return false;

    const char *output_path = backend_option_get(options, "output");
    FILE *out = stdout;
    if (output_path)
    {
        out = fopen(output_path, "w");
        if (!out)
        {
            emit_diag(sink, CC_DIAG_ERROR, 0, "failed to open output '%s'", output_path);
            return false;
        }
    }

    X86ModuleContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.out = out;
    ctx.module = module;
    ctx.sink = sink;
    ctx.syntax = backend && backend->userdata ? (const X86Syntax *)backend->userdata : &kNasmSyntax;
    const char *target_os_opt = backend_option_get(options, "target-os");
    if (target_os_opt)
    {
        if (equals_ignore_case(target_os_opt, "windows"))
            ctx.abi = &kX86AbiWin64;
        else if (equals_ignore_case(target_os_opt, "linux"))
            ctx.abi = &kX86AbiSystemV;
        else
        {
            emit_diag(sink, CC_DIAG_ERROR, 0, "unknown target-os '%s' (expected windows or linux)", target_os_opt);
            if (out != stdout)
                fclose(out);
            return false;
        }
    }
    else
    {
#ifdef _WIN32
        ctx.abi = &kX86AbiWin64;
#else
        ctx.abi = &kX86AbiSystemV;
#endif
    }

    if (!collect_externs(&ctx))
    {
        if (out != stdout)
            fclose(out);
        string_table_destroy(&ctx.strings);
        string_set_destroy(&ctx.externs);
        return false;
    }

    fprintf(out, "%s ChanceCode %s output\n\n", ctx.syntax->comment_prefix, ctx.syntax->backend_description);

    if (ctx.syntax->needs_intel_syntax)
        fprintf(out, ".intel_syntax noprefix\n\n");

    emit_externs(&ctx);

    for (size_t i = 0; i < module->global_count; ++i)
        emit_global_data(&ctx, &module->globals[i]);

    fprintf(out, "%s\n\n", ctx.syntax->text_section);

    for (size_t i = 0; i < module->function_count; ++i)
    {
        if (!emit_function(&ctx, &module->functions[i]))
        {
            if (out != stdout)
                fclose(out);
            string_table_destroy(&ctx.strings);
            string_set_destroy(&ctx.externs);
            return false;
        }
    }

    emit_string_literals(&ctx);

    if (ctx.syntax->needs_intel_syntax)
        fprintf(out, "\n.att_syntax prefix\n");

    if (out != stdout)
        fclose(out);
    string_table_destroy(&ctx.strings);
    string_set_destroy(&ctx.externs);
    return true;
}

static const CCBackend kX86BackendNasm = {
    .name = "x86",
    .description = "NASM-style x86-64 backend with integer and pointer support",
    .emit = emit_module,
    .userdata = (void *)&kNasmSyntax,
};

static const CCBackend kX86BackendGas = {
    .name = "x86-gas",
    .description = "GNU assembler x86-64 backend with integer and pointer support",
    .emit = emit_module,
    .userdata = (void *)&kGasSyntax,
};

bool cc_register_backend_x86(void)
{
    bool ok = true;
    ok = ok && cc_backend_register(&kX86BackendNasm);
    ok = ok && cc_backend_register(&kX86BackendGas);
    return ok;
}
