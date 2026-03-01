#include "cc/backend.h"
#include "cc/bytecode.h"
#include "cc/diagnostics.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>

typedef struct
{
    char *label;
    const char *bytes;
    size_t length;
    bool needed;
} BSlashStringLiteral;

typedef struct
{
    BSlashStringLiteral *items;
    size_t count;
    size_t capacity;
} BSlashStringTable;

typedef struct
{
    char *label;
    size_t size_bytes;
} BSlashDataSlot;

typedef struct
{
    BSlashDataSlot *items;
    size_t count;
    size_t capacity;
} BSlashDataTable;

typedef struct
{
    char *buffer;
    size_t size;
    bool needed;
    bool force_emit;
    const CCFunction *fn;
} BSlashFunctionOutput;

#define BSLASH_VALUE_STACK_CAPACITY 8
#define BSLASH_PARAM_REG_COUNT 8

static const char *const kValueStackOrder[BSLASH_VALUE_STACK_CAPACITY] = {"B8", "B9", "B10", "B11", "B12", "B13", "B14", "B15"};
static const char *const kParamRegs[BSLASH_PARAM_REG_COUNT] = {"B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7"};

typedef struct
{
    bool is_const;
    uint32_t const_value;
    bool materialized;
    const char *label;
} BSlashRegisterInfo;

typedef struct
{
    FILE *out;
    CCDiagnosticSink *sink;
    const CCFunction *fn;
    const CCModule *module;
    BSlashStringTable *strings;
    BSlashFunctionOutput *module_outputs;
    size_t module_output_count;
    size_t stack_depth;
    const char *stack_regs[BSLASH_VALUE_STACK_CAPACITY];
    size_t stack_indices[BSLASH_VALUE_STACK_CAPACITY];
    size_t scratch_depth;
    size_t scratch_indices[BSLASH_VALUE_STACK_CAPACITY];
    bool reg_in_use[BSLASH_VALUE_STACK_CAPACITY];
    bool reg_reserved[BSLASH_VALUE_STACK_CAPACITY];
    BSlashRegisterInfo reg_info[BSLASH_VALUE_STACK_CAPACITY];
    BSlashDataTable *locals_table;
    char **local_labels;
    bool *local_needs_memory;
    const char **local_registers;
    int *local_register_indices;
    size_t local_count;
    bool *local_known_values;
    uint32_t *local_known_u32;
    bool *local_known_ptr;
    const char **local_known_labels;
    bool *local_materialized;
    bool *local_storage_registered;
    int opt_level;
    size_t temp_label_counter;
} BSlashFunctionContext;

static const char *bslash_require_local_storage(BSlashFunctionContext *ctx, size_t index);
static int bslash_local_index_from_label(BSlashFunctionContext *ctx, const char *label);
static bool bslash_stack_push_new(BSlashFunctionContext *ctx, size_t line, const char **out_reg);

static bool bslash_emit_simple_param_add(FILE *out, const CCFunction *fn)
{
    if (!out || !fn || !fn->instructions)
        return false;
    if (fn->instruction_count != 4)
        return false;
    const CCInstruction *load_a = &fn->instructions[0];
    const CCInstruction *load_b = &fn->instructions[1];
    const CCInstruction *binop = &fn->instructions[2];
    const CCInstruction *ret = &fn->instructions[3];
    if (load_a->kind != CC_INSTR_LOAD_PARAM || load_a->data.param.index != 0)
        return false;
    if (load_b->kind != CC_INSTR_LOAD_PARAM || load_b->data.param.index != 1)
        return false;
    if (binop->kind != CC_INSTR_BINOP || binop->data.binop.op != CC_BINOP_ADD)
        return false;
    if (ret->kind != CC_INSTR_RET || !ret->data.ret.has_value)
        return false;
    fprintf(out, "    ADD B0, B1\n");
    fprintf(out, "    RET\n\n");
    return true;
}

static char *bslash_strdup(const char *src)
{
    if (!src)
        return NULL;
    size_t len = strlen(src);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
        return NULL;
    memcpy(copy, src, len + 1);
    return copy;
}

static void bslash_string_table_destroy(BSlashStringTable *table)
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

static void bslash_mark_string_needed(BSlashStringTable *table, const char *label)
{
    if (!table || !label)
        return;
    for (size_t i = 0; i < table->count; ++i)
    {
        if (strcmp(table->items[i].label, label) == 0)
        {
            table->items[i].needed = true;
            return;
        }
    }
}

static bool bslash_string_table_reserve(BSlashStringTable *table, size_t desired)
{
    if (table->capacity >= desired)
        return true;
    size_t new_capacity = table->capacity ? table->capacity * 2 : 8;
    while (new_capacity < desired)
        new_capacity *= 2;
    BSlashStringLiteral *items = (BSlashStringLiteral *)realloc(table->items, new_capacity * sizeof(BSlashStringLiteral));
    if (!items)
        return false;
    table->items = items;
    table->capacity = new_capacity;
    return true;
}

static void bslash_data_table_destroy(BSlashDataTable *table)
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

static bool bslash_data_table_reserve(BSlashDataTable *table, size_t desired)
{
    if (table->capacity >= desired)
        return true;
    size_t new_capacity = table->capacity ? table->capacity * 2 : 8;
    while (new_capacity < desired)
        new_capacity *= 2;
    BSlashDataSlot *items = (BSlashDataSlot *)realloc(table->items, new_capacity * sizeof(BSlashDataSlot));
    if (!items)
        return false;
    table->items = items;
    table->capacity = new_capacity;
    return true;
}

static const char *bslash_data_table_add(BSlashDataTable *table, const char *label, size_t size_bytes)
{
    if (!table || !label)
        return NULL;
    for (size_t i = 0; i < table->count; ++i)
    {
        if (strcmp(table->items[i].label, label) == 0)
            return table->items[i].label;
    }
    if (!bslash_data_table_reserve(table, table->count + 1))
        return NULL;
    char *label_copy = bslash_strdup(label);
    if (!label_copy)
        return NULL;
    BSlashDataSlot *slot = &table->items[table->count++];
    slot->label = label_copy;
    slot->size_bytes = size_bytes;
    return slot->label;
}

static const char *bslash_register_string_literal(BSlashStringTable *table, const CCFunction *fn, const CCInstruction *ins, size_t *counter)
{
    if (!table || !ins || !counter)
        return NULL;
    if (!bslash_string_table_reserve(table, table->count + 1))
        return NULL;

    size_t id = (*counter)++;
    char label[128];
    if (ins->data.const_string.label_hint && ins->data.const_string.label_hint[0])
    {
        const char *fn_name = (fn && fn->name) ? fn->name : "fn";
        snprintf(label, sizeof(label), "%s__%s_%zu", fn_name, ins->data.const_string.label_hint, id);
    }
    else if (fn && fn->name)
    {
        snprintf(label, sizeof(label), "%s__const_str_%zu", fn->name, id);
    }
    else
    {
        snprintf(label, sizeof(label), "const_str_%zu", id);
    }

    char *label_copy = bslash_strdup(label);
    if (!label_copy)
        return NULL;

    BSlashStringLiteral *lit = &table->items[table->count++];
    lit->label = label_copy;
    lit->bytes = ins->data.const_string.bytes;
    lit->length = ins->data.const_string.length;
    lit->needed = false;
    return label_copy;
}

static const BSlashStringLiteral *bslash_find_string_literal(const BSlashStringTable *table, const char *label)
{
    if (!table || !label)
        return NULL;
    for (size_t i = 0; i < table->count; ++i)
    {
        if (strcmp(table->items[i].label, label) == 0)
            return &table->items[i];
    }
    return NULL;
}

static void bslash_emit_string_literal(FILE *out, const BSlashStringLiteral *lit)
{
    if (!out || !lit || !lit->label || !lit->needed)
        return;
    fprintf(out, "%%align 4\n%s:\n    .stringz \"", lit->label);
    for (size_t i = 0; i < lit->length; ++i)
    {
        unsigned char c = (unsigned char)lit->bytes[i];
        switch (c)
        {
        case '\\':
            fputs("\\\\", out);
            break;
        case '\"':
            fputs("\\\"", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        case '\b':
            fputs("\\b", out);
            break;
        default:
            if (c < 0x20 || c >= 0x7f)
            {
                fprintf(out, "\\x%02X", c);
            }
            else
            {
                fputc((int)c, out);
            }
            break;
        }
    }
    fprintf(out, "\"\n\n");
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

static int bslash_register_index(const char *reg)
{
    if (!reg)
        return -1;
    for (size_t i = 0; i < BSLASH_VALUE_STACK_CAPACITY; ++i)
    {
        if (strcmp(reg, kValueStackOrder[i]) == 0)
            return (int)i;
    }
    return -1;
}

static int bslash_find_free_register(BSlashFunctionContext *ctx, bool prefer_high)
{
    if (!ctx)
        return -1;
    if (prefer_high)
    {
        for (int i = (int)BSLASH_VALUE_STACK_CAPACITY - 1; i >= 0; --i)
        {
            if (!ctx->reg_in_use[i] && !ctx->reg_reserved[i])
                return i;
        }
    }
    else
    {
        for (int i = 0; i < (int)BSLASH_VALUE_STACK_CAPACITY; ++i)
        {
            if (!ctx->reg_in_use[i] && !ctx->reg_reserved[i])
                return i;
        }
    }
    return -1;
}

static void bslash_clear_register_info(BSlashFunctionContext *ctx, const char *reg)
{
    if (!ctx)
        return;
    int idx = bslash_register_index(reg);
    if (idx < 0)
        return;
    ctx->reg_info[idx].is_const = false;
    ctx->reg_info[idx].const_value = 0;
    ctx->reg_info[idx].materialized = false;
    ctx->reg_info[idx].label = NULL;
}

static void bslash_set_register_const(BSlashFunctionContext *ctx, const char *reg, uint32_t value, bool materialized)
{
    if (!ctx)
        return;
    int idx = bslash_register_index(reg);
    if (idx < 0)
        return;
    ctx->reg_info[idx].is_const = true;
    ctx->reg_info[idx].const_value = value;
    ctx->reg_info[idx].materialized = materialized;
    ctx->reg_info[idx].label = NULL;
}

static bool bslash_get_register_const(BSlashFunctionContext *ctx, const char *reg, uint32_t *out_value)
{
    if (!ctx)
        return false;
    int idx = bslash_register_index(reg);
    if (idx < 0)
        return false;
    if (!ctx->reg_info[idx].is_const)
        return false;
    if (out_value)
        *out_value = ctx->reg_info[idx].const_value;
    return true;
}

static void bslash_copy_register_info(BSlashFunctionContext *ctx, const char *dst, const char *src)
{
    if (!ctx)
        return;
    int dst_idx = bslash_register_index(dst);
    if (dst_idx < 0)
        return;
    int src_idx = bslash_register_index(src);
    if (src_idx >= 0)
    {
        ctx->reg_info[dst_idx] = ctx->reg_info[src_idx];
    }
    else
    {
        ctx->reg_info[dst_idx].is_const = false;
        ctx->reg_info[dst_idx].const_value = 0;
        ctx->reg_info[dst_idx].materialized = false;
        ctx->reg_info[dst_idx].label = NULL;
    }
}

static void bslash_emit_movi32_u32(BSlashFunctionContext *ctx, const char *dst, uint32_t value)
{
    if (!ctx || !dst)
        return;
    fprintf(ctx->out, "    MOVI32 %s, #0x%08" PRIx32 "\n", dst, value);
    bslash_set_register_const(ctx, dst, value, true);
}

static void bslash_mark_function_needed(BSlashFunctionContext *ctx, const char *symbol)
{
    if (!ctx || !symbol || !ctx->module_outputs)
        return;
    for (size_t i = 0; i < ctx->module_output_count; ++i)
    {
        const CCFunction *fn = ctx->module_outputs[i].fn;
        if (fn && fn->name && strcmp(fn->name, symbol) == 0)
        {
            ctx->module_outputs[i].needed = true;
            return;
        }
    }
}

static void bslash_set_register_label(BSlashFunctionContext *ctx, const char *reg, const char *label, bool materialized)
{
    if (!ctx || !reg)
        return;
    int idx = bslash_register_index(reg);
    if (idx < 0)
        return;
    ctx->reg_info[idx].is_const = false;
    ctx->reg_info[idx].const_value = 0;
    ctx->reg_info[idx].materialized = materialized;
    ctx->reg_info[idx].label = label;
}

static void bslash_emit_movi32_label(BSlashFunctionContext *ctx, const char *dst, const char *label)
{
    if (!ctx || !dst || !label)
        return;
    fprintf(ctx->out, "    MOVI32 %s, #%s\n", dst, label);
    bslash_mark_string_needed(ctx->strings, label);
    bslash_set_register_label(ctx, dst, label, true);
}

static const char *bslash_get_register_label(const BSlashFunctionContext *ctx, const char *reg)
{
    if (!ctx || !reg)
        return NULL;
    int idx = bslash_register_index(reg);
    if (idx < 0)
        return NULL;
    return ctx->reg_info[idx].label;
}

static void bslash_ensure_register_materialized(BSlashFunctionContext *ctx, const char *reg)
{
    if (!ctx || !reg)
        return;
    int idx = bslash_register_index(reg);
    if (idx < 0)
        return;
    if (ctx->reg_info[idx].is_const && !ctx->reg_info[idx].materialized)
        bslash_emit_movi32_u32(ctx, reg, ctx->reg_info[idx].const_value);
    else if (ctx->reg_info[idx].label && !ctx->reg_info[idx].materialized)
    {
        const char *label = ctx->reg_info[idx].label;
        int local_idx = bslash_local_index_from_label(ctx, label);
        if (local_idx >= 0)
        {
            const char *stored = bslash_require_local_storage(ctx, (size_t)local_idx);
            if (!stored)
                return;
            label = stored;
            ctx->reg_info[idx].label = stored;
        }
        bslash_emit_movi32_label(ctx, reg, label);
    }
}

static void bslash_emit_mov(BSlashFunctionContext *ctx, const char *dst, const char *src)
{
    if (!ctx || !dst || !src)
        return;
    if (strcmp(dst, src) == 0)
        return;
    bslash_ensure_register_materialized(ctx, src);
    fprintf(ctx->out, "    MOV %s, %s\n", dst, src);
    bslash_copy_register_info(ctx, dst, src);
}

static void bslash_emit_addi(BSlashFunctionContext *ctx, const char *dst, int32_t value)
{
    if (!ctx || !dst)
        return;
    uint32_t previous = 0;
    bool had_const = bslash_get_register_const(ctx, dst, &previous);
    if (value >= -128 && value <= 127)
    {
        uint32_t encoded = (uint32_t)(value & 0xFF);
        fprintf(ctx->out, "    ADDI8 %s, #0x%02" PRIx32 "\n", dst, encoded);
    }
    else if (value >= -32768 && value <= 32767)
    {
        uint32_t encoded = (uint32_t)(value & 0xFFFF);
        fprintf(ctx->out, "    ADDI16 %s, #0x%04" PRIx32 "\n", dst, encoded);
    }
    else
    {
        uint32_t encoded = (uint32_t)value;
        fprintf(ctx->out, "    ADDI32 %s, #0x%08" PRIx32 "\n", dst, encoded);
    }
    if (had_const)
    {
        uint32_t result = previous + (uint32_t)value;
        bslash_set_register_const(ctx, dst, result, true);
    }
    else
    {
        bslash_clear_register_info(ctx, dst);
    }
}

static const char *bslash_function_name(const BSlashFunctionContext *ctx)
{
    return (ctx && ctx->fn && ctx->fn->name) ? ctx->fn->name : "fn";
}

static void bslash_make_temp_label(BSlashFunctionContext *ctx, char *buffer, size_t buffer_size, const char *kind)
{
    if (!ctx || !buffer || buffer_size == 0)
        return;
    snprintf(buffer, buffer_size, "%s__%s_%zu", bslash_function_name(ctx), kind ? kind : "tmp", ctx->temp_label_counter++);
}

static const char *bslash_compare_branch_opcode(CCCompareOp op, bool is_unsigned)
{
    switch (op)
    {
    case CC_COMPARE_EQ:
        return "BZ";
    case CC_COMPARE_NE:
        return "BNZ";
    case CC_COMPARE_LT:
        return is_unsigned ? "BLTU" : "BLT";
    case CC_COMPARE_LE:
        return is_unsigned ? "BLEU" : "BLE";
    case CC_COMPARE_GT:
        return is_unsigned ? "BGTU" : "BGT";
    case CC_COMPARE_GE:
        return is_unsigned ? "BGEU" : "BGE";
    default:
        return NULL;
    }
}

static const char *bslash_load_mnemonic(CCValueType type, bool is_unsigned)
{
    switch (type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_I8:
    case CC_TYPE_U8:
        return is_unsigned ? "LDBU" : "LDBS";
    case CC_TYPE_I16:
    case CC_TYPE_U16:
        return is_unsigned ? "LDHU" : "LDHS";
    default:
        return "LD";
    }
}

static const char *bslash_store_mnemonic(CCValueType type)
{
    switch (type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_I8:
    case CC_TYPE_U8:
        return "STB";
    case CC_TYPE_I16:
    case CC_TYPE_U16:
        return "STH";
    default:
        return "ST";
    }
}

static bool bslash_prepare_locals(BSlashFunctionContext *ctx, const CCFunction *fn)
{
    if (!ctx || ctx->local_count == 0)
        return true;

    ctx->local_needs_memory = (bool *)calloc(ctx->local_count, sizeof(bool));
    ctx->local_registers = (const char **)calloc(ctx->local_count, sizeof(const char *));
    ctx->local_register_indices = (int *)calloc(ctx->local_count, sizeof(int));
    if (!ctx->local_needs_memory || !ctx->local_registers || !ctx->local_register_indices)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "out of memory allocating local metadata");
        free(ctx->local_needs_memory);
        free(ctx->local_registers);
        free(ctx->local_register_indices);
        ctx->local_needs_memory = NULL;
        ctx->local_registers = NULL;
        ctx->local_register_indices = NULL;
        return false;
    }
    for (size_t i = 0; i < ctx->local_count; ++i)
    {
        ctx->local_register_indices[i] = -1;
        if (ctx->local_materialized)
            ctx->local_materialized[i] = true;
    }

    if (ctx->opt_level < 3)
    {
        for (size_t i = 0; i < ctx->local_count; ++i)
            ctx->local_needs_memory[i] = true;
        return true;
    }

    for (size_t i = 0; i < ctx->local_count; ++i)
    {
        ctx->local_needs_memory[i] = false;
        ctx->local_registers[i] = NULL;
        ctx->local_register_indices[i] = -1;
    }

    for (size_t ii = 0; ii < fn->instruction_count; ++ii)
    {
        const CCInstruction *ins = &fn->instructions[ii];
        if (!ins)
            continue;
        if (ins->kind == CC_INSTR_ADDR_LOCAL)
        {
            size_t idx = ins->data.local.index;
            if (idx < ctx->local_count)
                ctx->local_needs_memory[idx] = true;
        }
    }

    return true;
}

static const CCFunction *bslash_find_function(const CCModule *module, const char *name)
{
    if (!module || !name)
        return NULL;
    for (size_t i = 0; i < module->function_count; ++i)
    {
        const CCFunction *fn = &module->functions[i];
        if (fn->name && strcmp(fn->name, name) == 0)
            return fn;
    }
    return NULL;
}

static bool bslash_try_emit_o3_string_inline(BSlashFunctionContext *ctx, const CCInstruction *call_ins, const char *const *args, size_t arg_count)
{
    if (!ctx || !call_ins || ctx->opt_level < 3 || !args || arg_count == 0)
        return false;
    if (!ctx->module || !ctx->strings)
        return false;
    if (call_ins->data.call.return_type != CC_TYPE_VOID)
        return false;
    if (!call_ins->data.call.symbol)
        return false;
    if (arg_count != call_ins->data.call.arg_count || arg_count != 1)
        return false;

    const char *ptr_reg = args[0];
    if (!ptr_reg)
        return false;
    const char *label = bslash_get_register_label(ctx, ptr_reg);
    if (!label)
        return false;
    const BSlashStringLiteral *literal = bslash_find_string_literal(ctx->strings, label);
    if (!literal || !literal->bytes)
        return false;

    const CCFunction *callee = bslash_find_function(ctx->module, call_ins->data.call.symbol);
    if (!callee)
        return false;
    if (callee->return_type != CC_TYPE_VOID)
        return false;
    if (callee->param_count != 1 || !callee->param_types)
        return false;
    if (callee->param_types[0] != CC_TYPE_PTR)
        return false;

    const char *printer_symbol = NULL;
    for (size_t ci = 0; ci < callee->instruction_count; ++ci)
    {
        const CCInstruction *callee_ins = &callee->instructions[ci];
        if (!callee_ins)
            continue;
        if (callee_ins->kind == CC_INSTR_CALL)
        {
            if (!callee_ins->data.call.symbol)
                return false;
            if (!printer_symbol)
                printer_symbol = callee_ins->data.call.symbol;
            else if (strcmp(printer_symbol, callee_ins->data.call.symbol) != 0)
                return false;
        }
        else if (callee_ins->kind == CC_INSTR_RET && callee_ins->data.ret.has_value)
        {
            return false;
        }
    }

    if (!printer_symbol)
        return false;

    const CCFunction *printer_fn = bslash_find_function(ctx->module, printer_symbol);
    bool printer_force_inline = printer_fn && printer_fn->force_inline_literal &&
                                printer_fn->literal_count > 0 && printer_fn->literal_lines;

    for (size_t i = 0; i < literal->length; ++i)
    {
        unsigned char ch = (unsigned char)literal->bytes[i];
        if (ch == '\0')
            break;
        bslash_emit_movi32_u32(ctx, "B0", (uint32_t)ch);
        if (printer_force_inline)
        {
            for (size_t li = 0; li < printer_fn->literal_count; ++li)
            {
                const char *line = printer_fn->literal_lines[li] ? printer_fn->literal_lines[li] : "";
                fprintf(ctx->out, "    %s\n", line);
            }
        }
        else
        {
            fprintf(ctx->out, "    CALL %s\n", printer_symbol);
            bslash_mark_function_needed(ctx, printer_symbol);
        }
    }
    return true;
}

static bool bslash_emit_force_inline_literal_call(BSlashFunctionContext *ctx, const CCInstruction *call_ins, const CCFunction *callee, const char *const *args, size_t arg_count)
{
    if (!ctx || !call_ins || !callee || !callee->is_literal || !callee->force_inline_literal)
        return false;
    if (!callee->literal_lines || callee->literal_count == 0)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, call_ins->line,
                  "force-inline literal '%s' has no body", callee->name ? callee->name : "<anon>");
        return false;
    }
    for (size_t ai = 0; ai < arg_count; ++ai)
    {
        if (args[ai])
            bslash_emit_mov(ctx, kParamRegs[ai], args[ai]);
    }
    for (size_t li = 0; li < callee->literal_count; ++li)
    {
        const char *line = callee->literal_lines[li] ? callee->literal_lines[li] : "";
        fprintf(ctx->out, "    %s\n", line);
    }
    if (call_ins->data.call.return_type != CC_TYPE_VOID)
    {
        const char *dst = NULL;
        if (!bslash_stack_push_new(ctx, call_ins->line, &dst))
            return false;
        if (strcmp(dst, "B0") != 0)
            bslash_emit_mov(ctx, dst, "B0");
    }
    return true;
}

static bool bslash_try_parse_int(const char *text, int *out_value)
{
    if (!text || !*text || !out_value)
        return false;
    int sign = 1;
    if (*text == '-')
    {
        sign = -1;
        ++text;
    }
    if (!*text)
        return false;
    int value = 0;
    for (const char *p = text; *p; ++p)
    {
        if (!isdigit((unsigned char)*p))
            return false;
        value = value * 10 + (*p - '0');
    }
    *out_value = sign * value;
    return true;
}

static bool bslash_get_opt_level(const CCBackendOptions *options, CCDiagnosticSink *sink, int *out_opt_level)
{
    if (!out_opt_level)
        return false;
    *out_opt_level = 0;
    if (!options || !options->options)
        return true;
    for (size_t i = 0; i < options->option_count; ++i)
    {
        const CCBackendOption *opt = &options->options[i];
        if (!opt->key || strcmp(opt->key, "opt-level") != 0)
            continue;
        int parsed = 0;
        if (!opt->value || !bslash_try_parse_int(opt->value, &parsed) || parsed < 0)
        {
            emit_diag(sink, CC_DIAG_ERROR, 0, "invalid opt-level '%s'", opt->value ? opt->value : "");
            return false;
        }
        if (parsed > 3)
            parsed = 3;
        *out_opt_level = parsed;
        break;
    }
    return true;
}

static bool bslash_stack_push_new(BSlashFunctionContext *ctx, size_t line, const char **out_reg)
{
    if (!ctx)
        return false;
    if (ctx->stack_depth >= BSLASH_VALUE_STACK_CAPACITY)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, line, "value stack overflow");
        return false;
    }
    int reg_idx = bslash_find_free_register(ctx, false);
    if (reg_idx < 0)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, line, "no registers available for value stack");
        return false;
    }
    ctx->reg_in_use[reg_idx] = true;
    const char *reg = kValueStackOrder[reg_idx];
    ctx->stack_indices[ctx->stack_depth] = (size_t)reg_idx;
    ctx->stack_regs[ctx->stack_depth++] = reg;
    bslash_clear_register_info(ctx, reg);
    if (out_reg)
        *out_reg = reg;
    return true;
}

static bool bslash_stack_push_existing(BSlashFunctionContext *ctx, size_t line, const char *reg)
{
    if (!ctx || !reg)
        return false;
    if (ctx->stack_depth >= BSLASH_VALUE_STACK_CAPACITY)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, line, "value stack overflow");
        return false;
    }
    int reg_idx = bslash_register_index(reg);
    if (reg_idx < 0)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, line, "unknown register '%s'", reg);
        return false;
    }
    ctx->reg_in_use[reg_idx] = true;
    ctx->stack_indices[ctx->stack_depth] = (size_t)reg_idx;
    ctx->stack_regs[ctx->stack_depth++] = reg;
    return true;
}

static const char *bslash_stack_pop(BSlashFunctionContext *ctx, size_t line)
{
    if (!ctx)
        return NULL;
    if (ctx->stack_depth == 0)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, line, "value stack underflow");
        return NULL;
    }
    size_t slot = --ctx->stack_depth;
    return ctx->stack_regs[slot];
}

static void bslash_stack_reset(BSlashFunctionContext *ctx)
{
    if (!ctx)
        return;
    ctx->stack_depth = 0;
    ctx->scratch_depth = 0;
    for (size_t i = 0; i < BSLASH_VALUE_STACK_CAPACITY; ++i)
    {
        ctx->reg_in_use[i] = false;
        ctx->reg_info[i].is_const = false;
        ctx->reg_info[i].const_value = 0;
        ctx->reg_info[i].materialized = false;
        ctx->reg_info[i].label = NULL;
    }
}

static void bslash_release_register(BSlashFunctionContext *ctx, const char *reg)
{
    if (!ctx || !reg)
        return;
    int idx = bslash_register_index(reg);
    if (idx >= 0 && idx < (int)BSLASH_VALUE_STACK_CAPACITY)
    {
        ctx->reg_in_use[idx] = false;
        if (!ctx->reg_reserved[idx])
        {
            ctx->reg_info[idx].is_const = false;
            ctx->reg_info[idx].const_value = 0;
            ctx->reg_info[idx].materialized = false;
            ctx->reg_info[idx].label = NULL;
        }
    }
}

static bool bslash_try_emit_add_const(BSlashFunctionContext *ctx, const char *lhs, const char *rhs)
{
    if (!ctx || ctx->opt_level == 0)
        return false;
    if (lhs && rhs && strcmp(lhs, rhs) == 0)
        return false;
    uint32_t rhs_value = 0;
    if (!bslash_get_register_const(ctx, rhs, &rhs_value))
        return false;
    uint32_t lhs_value = 0;
    if (bslash_get_register_const(ctx, lhs, &lhs_value))
    {
        uint32_t result = lhs_value + rhs_value;
        bslash_set_register_const(ctx, lhs, result, false);
    }
    else
    {
        bslash_emit_addi(ctx, lhs, (int32_t)rhs_value);
    }
    bslash_release_register(ctx, rhs);
    return true;
}

static void bslash_local_release_register(BSlashFunctionContext *ctx, size_t local_index)
{
    if (!ctx || !ctx->local_register_indices || local_index >= ctx->local_count)
        return;
    int prev = ctx->local_register_indices[local_index];
    if (prev >= 0 && prev < (int)BSLASH_VALUE_STACK_CAPACITY)
        ctx->reg_reserved[prev] = false;
    ctx->local_register_indices[local_index] = -1;
    if (ctx->local_registers)
        ctx->local_registers[local_index] = NULL;
}

static bool bslash_local_bind_register(BSlashFunctionContext *ctx, size_t local_index, const char *reg)
{
    if (!ctx || !reg || !ctx->local_register_indices || local_index >= ctx->local_count)
        return false;
    int idx = bslash_register_index(reg);
    if (idx < 0)
        return false;
    bslash_local_release_register(ctx, local_index);
    ctx->local_register_indices[local_index] = idx;
    if (ctx->local_registers)
        ctx->local_registers[local_index] = kValueStackOrder[idx];
    ctx->reg_reserved[idx] = true;
    return true;
}

static const char *bslash_scratch_acquire(BSlashFunctionContext *ctx, size_t line)
{
    if (!ctx)
        return NULL;
    if (ctx->scratch_depth >= BSLASH_VALUE_STACK_CAPACITY)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, line, "scratch stack overflow");
        return NULL;
    }
    int reg_idx = bslash_find_free_register(ctx, false);
    if (reg_idx < 0)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, line, "no registers available for scratch use");
        return NULL;
    }
    ctx->reg_in_use[reg_idx] = true;
    ctx->scratch_indices[ctx->scratch_depth] = (size_t)reg_idx;
    ctx->scratch_depth++;
    bslash_clear_register_info(ctx, kValueStackOrder[reg_idx]);
    return kValueStackOrder[reg_idx];
}

static void bslash_scratch_release(BSlashFunctionContext *ctx)
{
    if (!ctx || ctx->scratch_depth == 0)
        return;
    size_t idx = ctx->scratch_indices[--ctx->scratch_depth];
    if (idx < BSLASH_VALUE_STACK_CAPACITY)
    {
        ctx->reg_in_use[idx] = false;
        ctx->reg_info[idx].is_const = false;
        ctx->reg_info[idx].const_value = 0;
        ctx->reg_info[idx].materialized = false;
    }
}

static void bslash_function_cleanup(BSlashFunctionContext *ctx)
{
    if (!ctx)
        return;
    if (ctx->local_labels)
    {
        if (ctx->local_storage_registered)
        {
            for (size_t i = 0; i < ctx->local_count; ++i)
            {
                if (!ctx->local_storage_registered[i] && ctx->local_labels[i])
                    free(ctx->local_labels[i]);
            }
        }
        else
        {
            for (size_t i = 0; i < ctx->local_count; ++i)
            {
                if (ctx->local_labels[i])
                    free(ctx->local_labels[i]);
            }
        }
        free(ctx->local_labels);
        ctx->local_labels = NULL;
    }
    free(ctx->local_needs_memory);
    ctx->local_needs_memory = NULL;
    free(ctx->local_registers);
    ctx->local_registers = NULL;
    free(ctx->local_register_indices);
    ctx->local_register_indices = NULL;
    free(ctx->local_known_values);
    ctx->local_known_values = NULL;
    free(ctx->local_known_u32);
    ctx->local_known_u32 = NULL;
    free(ctx->local_known_ptr);
    ctx->local_known_ptr = NULL;
    free(ctx->local_known_labels);
    ctx->local_known_labels = NULL;
    free(ctx->local_materialized);
    ctx->local_materialized = NULL;
    free(ctx->local_storage_registered);
    ctx->local_storage_registered = NULL;
}

static const char *bslash_get_local_label_name(BSlashFunctionContext *ctx, size_t index)
{
    if (!ctx)
        return NULL;
    if (index >= ctx->local_count)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "local index %zu out of range", index);
        return NULL;
    }
    if (ctx->local_needs_memory && index < ctx->local_count && !ctx->local_needs_memory[index])
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "internal error: label requested for register-only local %zu", index);
        return NULL;
    }
    if (ctx->local_labels && ctx->local_labels[index])
        return ctx->local_labels[index];

    const char *fn_name = (ctx->fn && ctx->fn->name) ? ctx->fn->name : "fn";
    char label[128];
    snprintf(label, sizeof(label), "%s__local_%zu", fn_name, index);
    char *copy = bslash_strdup(label);
    if (!copy)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "failed to allocate name for local %zu", index);
        return NULL;
    }
    ctx->local_labels[index] = copy;
    return ctx->local_labels[index];
}

static const char *bslash_require_local_storage(BSlashFunctionContext *ctx, size_t index)
{
    if (!ctx)
        return NULL;
    if (!ctx->local_needs_memory || index >= ctx->local_count)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "storage requested for invalid local %zu", index);
        return NULL;
    }
    if (!ctx->local_needs_memory[index])
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "storage requested for register-only local %zu", index);
        return NULL;
    }
    const char *label = bslash_get_local_label_name(ctx, index);
    if (!label)
        return NULL;
    if (ctx->local_storage_registered && ctx->local_storage_registered[index])
        return ctx->local_labels[index];
    const char *registered = bslash_data_table_add(ctx->locals_table, label, 4);
    if (!registered)
    {
        emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "failed to allocate storage for local %zu", index);
        return NULL;
    }
    if (ctx->local_storage_registered)
        ctx->local_storage_registered[index] = true;
    ctx->local_labels[index] = (char *)registered;
    return ctx->local_labels[index];
}

static int bslash_local_index_from_label(BSlashFunctionContext *ctx, const char *label)
{
    if (!ctx || !label || !ctx->local_labels)
        return -1;
    for (size_t i = 0; i < ctx->local_count; ++i)
    {
        if (ctx->local_labels[i] && strcmp(ctx->local_labels[i], label) == 0)
            return (int)i;
    }
    return -1;
}

static void bslash_local_forget(BSlashFunctionContext *ctx, size_t index)
{
    if (!ctx || index >= ctx->local_count)
        return;
    if (ctx->local_known_values)
        ctx->local_known_values[index] = false;
    if (ctx->local_known_ptr)
        ctx->local_known_ptr[index] = false;
    if (ctx->local_known_labels)
        ctx->local_known_labels[index] = NULL;
    if (ctx->local_materialized)
        ctx->local_materialized[index] = true;
}

static void bslash_local_invalidate(BSlashFunctionContext *ctx, size_t index)
{
    bslash_local_forget(ctx, index);
}

static void bslash_local_invalidate_all(BSlashFunctionContext *ctx)
{
    if (!ctx)
        return;
    for (size_t i = 0; i < ctx->local_count; ++i)
        bslash_local_forget(ctx, i);
}

static void bslash_local_note_store(BSlashFunctionContext *ctx, size_t index, const char *value_reg)
{
    if (!ctx || index >= ctx->local_count)
        return;
    uint32_t value = 0;
    if (ctx->local_known_values && bslash_get_register_const(ctx, value_reg, &value))
    {
        ctx->local_known_values[index] = true;
        ctx->local_known_u32[index] = value;
        if (ctx->local_known_ptr)
            ctx->local_known_ptr[index] = false;
        if (ctx->local_known_labels)
            ctx->local_known_labels[index] = NULL;
        return;
    }
    const char *label = bslash_get_register_label(ctx, value_reg);
    if (ctx->local_known_ptr && ctx->local_known_labels && label)
    {
        ctx->local_known_ptr[index] = true;
        ctx->local_known_labels[index] = label;
        if (ctx->local_known_values)
            ctx->local_known_values[index] = false;
        return;
    }
    bslash_local_forget(ctx, index);
}

static void bslash_local_note_pointer_store(BSlashFunctionContext *ctx, const char *ptr_reg, const char *value_reg)
{
    if (!ctx || !ptr_reg)
        return;
    const char *label = bslash_get_register_label(ctx, ptr_reg);
    if (!label)
    {
        bslash_local_invalidate_all(ctx);
        return;
    }
    int idx = bslash_local_index_from_label(ctx, label);
    if (idx < 0)
        return;
    bslash_local_note_store(ctx, (size_t)idx, value_reg);
}

static bool bslash_try_fold_local_load(BSlashFunctionContext *ctx, size_t index, const char *dst)
{
    if (!ctx || !dst || index >= ctx->local_count)
        return false;
    if (ctx->local_known_values && ctx->local_known_values[index])
    {
        if (ctx->opt_level >= 3)
            bslash_set_register_const(ctx, dst, ctx->local_known_u32[index], false);
        else
            bslash_emit_movi32_u32(ctx, dst, ctx->local_known_u32[index]);
        return true;
    }
    if (ctx->local_known_ptr && ctx->local_known_ptr[index] && ctx->local_known_labels && ctx->local_known_labels[index])
    {
        if (ctx->opt_level >= 3)
        {
            bslash_set_register_label(ctx, dst, ctx->local_known_labels[index], false);
        }
        else
        {
            bslash_emit_movi32_label(ctx, dst, ctx->local_known_labels[index]);
        }
        return true;
    }
    return false;
}

static bool bslash_try_fold_pointer_load(BSlashFunctionContext *ctx, const char *ptr_reg, const char *dst, CCValueType type)
{
    if (!ctx || !ptr_reg || !dst || !ctx->local_known_values)
        return false;
    if (!(type == CC_TYPE_I32 || type == CC_TYPE_U32 || type == CC_TYPE_PTR))
        return false;
    const char *label = bslash_get_register_label(ctx, ptr_reg);
    if (!label)
        return false;
    int idx = bslash_local_index_from_label(ctx, label);
    if (idx < 0)
        return false;
    if (!ctx->local_known_values[idx])
        return false;
    if (ctx->opt_level >= 3)
        bslash_set_register_const(ctx, dst, ctx->local_known_u32[idx], false);
    else
        bslash_emit_movi32_u32(ctx, dst, ctx->local_known_u32[idx]);
    return true;
}

static void bslash_local_mark_dirty(BSlashFunctionContext *ctx, size_t index)
{
    if (!ctx || !ctx->local_materialized || index >= ctx->local_count)
        return;
    ctx->local_materialized[index] = false;
}

static void bslash_local_mark_clean(BSlashFunctionContext *ctx, size_t index)
{
    if (!ctx || !ctx->local_materialized || index >= ctx->local_count)
        return;
    ctx->local_materialized[index] = true;
}

static bool bslash_local_materialize(BSlashFunctionContext *ctx, size_t index, size_t line)
{
    if (!ctx || index >= ctx->local_count)
        return false;
    if (!ctx->local_needs_memory || !ctx->local_needs_memory[index])
        return true;
    if (!ctx->local_materialized || ctx->local_materialized[index])
        return true;
    const char *label = bslash_require_local_storage(ctx, index);
    if (!label)
        return false;
    const char *addr_reg = bslash_scratch_acquire(ctx, line);
    if (!addr_reg)
        return false;
    bslash_emit_movi32_label(ctx, addr_reg, label);
    bslash_ensure_register_materialized(ctx, addr_reg);
    const char *value_reg = bslash_scratch_acquire(ctx, line);
    if (!value_reg)
    {
        bslash_scratch_release(ctx);
        return false;
    }
    if (ctx->local_known_values && ctx->local_known_values[index])
    {
        bslash_emit_movi32_u32(ctx, value_reg, ctx->local_known_u32[index]);
    }
    else if (ctx->local_known_ptr && ctx->local_known_ptr[index] && ctx->local_known_labels && ctx->local_known_labels[index])
    {
        bslash_emit_movi32_label(ctx, value_reg, ctx->local_known_labels[index]);
    }
    else
    {
        bslash_scratch_release(ctx);
        bslash_scratch_release(ctx);
        return false;
    }
    fprintf(ctx->out, "    ST [%s], %s\n", addr_reg, value_reg);
    bslash_scratch_release(ctx);
    bslash_scratch_release(ctx);
    bslash_local_mark_clean(ctx, index);
    return true;
}

static void bslash_local_handle_call_alias(BSlashFunctionContext *ctx, const char *const *args, size_t arg_count, size_t line)
{
    if (!ctx || !args || !ctx->local_known_values)
        return;
    for (size_t i = 0; i < arg_count; ++i)
    {
        const char *reg = args[i];
        if (!reg)
            continue;
        const char *label = bslash_get_register_label(ctx, reg);
        if (!label)
            continue;
        int idx = bslash_local_index_from_label(ctx, label);
        if (idx >= 0)
        {
            bslash_local_materialize(ctx, (size_t)idx, line);
            bslash_local_invalidate(ctx, (size_t)idx);
        }
    }
}

static bool bslash_emit_function(BSlashFunctionContext *ctx, const CCFunction *fn, BSlashStringTable *strings, size_t *string_counter)
{
    ctx->fn = fn;
    ctx->strings = strings;
    ctx->stack_depth = 0;
    ctx->scratch_depth = 0;
    memset(ctx->reg_in_use, 0, sizeof(ctx->reg_in_use));
    memset(ctx->reg_reserved, 0, sizeof(ctx->reg_reserved));
    memset(ctx->reg_info, 0, sizeof(ctx->reg_info));
    ctx->temp_label_counter = 0;
    ctx->local_count = fn->local_count;
    ctx->local_labels = NULL;
    ctx->local_needs_memory = NULL;
    ctx->local_registers = NULL;
    ctx->local_register_indices = NULL;
    ctx->local_known_values = NULL;
    ctx->local_known_u32 = NULL;
    ctx->local_known_ptr = NULL;
    ctx->local_known_labels = NULL;
    ctx->local_materialized = NULL;
    ctx->local_storage_registered = NULL;
    bool success = true;
    if (ctx->local_count > 0)
    {
        ctx->local_labels = (char **)calloc(ctx->local_count, sizeof(char *));
        if (!ctx->local_labels)
        {
            emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "out of memory allocating local map");
            return false;
        }
        ctx->local_known_values = (bool *)calloc(ctx->local_count, sizeof(bool));
        ctx->local_known_u32 = (uint32_t *)calloc(ctx->local_count, sizeof(uint32_t));
        ctx->local_known_ptr = (bool *)calloc(ctx->local_count, sizeof(bool));
        ctx->local_known_labels = (const char **)calloc(ctx->local_count, sizeof(const char *));
        ctx->local_materialized = (bool *)calloc(ctx->local_count, sizeof(bool));
        ctx->local_storage_registered = (bool *)calloc(ctx->local_count, sizeof(bool));
        if (!ctx->local_known_values || !ctx->local_known_u32 || !ctx->local_known_ptr || !ctx->local_known_labels ||
            !ctx->local_materialized || !ctx->local_storage_registered)
        {
            emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "out of memory tracking local constants");
            success = false;
            goto cleanup;
        }
        if (!bslash_prepare_locals(ctx, fn))
        {
            success = false;
            goto cleanup;
        }
    }
    else
    {
        ctx->local_labels = NULL;
        ctx->local_known_values = NULL;
        ctx->local_known_u32 = NULL;
        ctx->local_known_ptr = NULL;
        ctx->local_known_labels = NULL;
        ctx->local_materialized = NULL;
        ctx->local_storage_registered = NULL;
    }

    fprintf(ctx->out, "%s:\n", fn->name);

    if (fn->is_literal)
    {
        for (size_t li = 0; li < fn->literal_count; ++li)
            fprintf(ctx->out, "    %s\n", fn->literal_lines[li]);
        fprintf(ctx->out, "\n");
        fprintf(ctx->out, "\n");
        goto cleanup;
    }

    if (ctx->opt_level > 0 && bslash_emit_simple_param_add(ctx->out, fn))
        goto cleanup;

    bool emitted_return = false;

    for (size_t ii = 0; ii < fn->instruction_count; ++ii)
    {
        const CCInstruction *ins = &fn->instructions[ii];
        if (!ins)
            continue;

        switch (ins->kind)
        {
        case CC_INSTR_CONST:
        {
            const char *reg = NULL;
            if (!bslash_stack_push_new(ctx, ins->line, &reg))
            {
                success = false;
                goto cleanup;
            }
            uint64_t value = (uint64_t)ins->data.constant.value.i64;
            if (ins->data.constant.is_null)
                value = 0;
            bslash_set_register_const(ctx, reg, (uint32_t)(value & 0xffffffffULL), false);
            break;
        }
        case CC_INSTR_CONST_STRING:
        {
            const char *label = bslash_register_string_literal(strings, fn, ins, string_counter);
            if (!label)
            {
                emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "failed to allocate string literal");
                return false;
            }
            const char *reg = NULL;
            if (!bslash_stack_push_new(ctx, ins->line, &reg))
            {
                success = false;
                goto cleanup;
            }
            bslash_set_register_label(ctx, reg, label, false);
            break;
        }
        case CC_INSTR_LOAD_PARAM:
        {
            uint32_t index = ins->data.param.index;
            if (index >= BSLASH_PARAM_REG_COUNT)
            {
                emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "param %u exceeds supported register count", index);
                success = false;
                goto cleanup;
            }
            const char *dst = NULL;
            if (!bslash_stack_push_new(ctx, ins->line, &dst))
            {
                success = false;
                goto cleanup;
            }
            bslash_emit_mov(ctx, dst, kParamRegs[index]);
            break;
        }
        case CC_INSTR_STORE_LOCAL:
        {
            size_t local_index = ins->data.local.index;
            const char *scratch = NULL;
            const char *value = bslash_stack_pop(ctx, ins->line);
            if (!value)
            {
                success = false;
                goto cleanup;
            }
            bool reg_candidate = ctx->local_needs_memory && local_index < ctx->local_count && !ctx->local_needs_memory[local_index];
            if (reg_candidate)
            {
                int value_idx = bslash_register_index(value);
                if (value_idx >= 0 && value_idx < (int)BSLASH_VALUE_STACK_CAPACITY)
                    ctx->reg_in_use[value_idx] = false;
                if (!bslash_local_bind_register(ctx, local_index, value))
                {
                    emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "failed to bind register local %zu", local_index);
                    success = false;
                    goto cleanup;
                }
                if (ctx->opt_level >= 3)
                    bslash_local_note_store(ctx, local_index, value);
                break;
            }
            bool recorded_store = false;
            bool skip_store = false;
            if (ctx->opt_level >= 3)
            {
                bslash_local_note_store(ctx, local_index, value);
                recorded_store = true;
                if (ctx->local_needs_memory && ctx->local_needs_memory[local_index])
                {
                    bool has_known_value = (ctx->local_known_values && ctx->local_known_values[local_index]) ||
                                           (ctx->local_known_ptr && ctx->local_known_ptr[local_index]);
                    if (has_known_value)
                        skip_store = true;
                }
            }
            if (skip_store)
            {
                bslash_local_mark_dirty(ctx, local_index);
                bslash_release_register(ctx, value);
                break;
            }
            const char *label = bslash_require_local_storage(ctx, ins->data.local.index);
            if (!label)
            {
                bslash_release_register(ctx, value);
                success = false;
                goto cleanup;
            }
            if (ctx->opt_level > 0)
            {
                scratch = bslash_scratch_acquire(ctx, ins->line);
                if (!scratch)
                {
                    bslash_release_register(ctx, value);
                    success = false;
                    goto cleanup;
                }
            }
            if (ctx->opt_level > 0)
            {
                bslash_emit_movi32_label(ctx, scratch, label);
                bslash_ensure_register_materialized(ctx, scratch);
                bslash_ensure_register_materialized(ctx, value);
                fprintf(ctx->out, "    ST [%s], %s\n", scratch, value);
                bslash_scratch_release(ctx);
            }
            else
            {
                fprintf(ctx->out, "    PUSHR B1\n");
                bslash_emit_movi32_label(ctx, "B1", label);
                bslash_ensure_register_materialized(ctx, value);
                fprintf(ctx->out, "    ST [B1], %s\n", value);
                fprintf(ctx->out, "    POPR B1\n");
            }
            if (recorded_store)
                bslash_local_mark_clean(ctx, local_index);
            bslash_release_register(ctx, value);
            break;
        }
        case CC_INSTR_LOAD_LOCAL:
        {
            size_t local_index = ins->data.local.index;
            bool reg_candidate = ctx->local_needs_memory && local_index < ctx->local_count && !ctx->local_needs_memory[local_index];
            if (reg_candidate)
            {
                const char *src_reg = ctx->local_registers[local_index];
                if (!src_reg)
                {
                    emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "register local %zu used before initialization", local_index);
                    success = false;
                    goto cleanup;
                }
                if (!bslash_stack_push_existing(ctx, ins->line, src_reg))
                {
                    success = false;
                    goto cleanup;
                }
                break;
            }
            const char *dst = NULL;
            if (!bslash_stack_push_new(ctx, ins->line, &dst))
            {
                success = false;
                goto cleanup;
            }
            if (ctx->opt_level >= 3 && bslash_try_fold_local_load(ctx, local_index, dst))
                break;
            if (ctx->opt_level >= 3)
            {
                if (!bslash_local_materialize(ctx, local_index, ins->line))
                {
                    success = false;
                    goto cleanup;
                }
            }
            const char *label = bslash_require_local_storage(ctx, ins->data.local.index);
            if (!label)
            {
                success = false;
                goto cleanup;
            }
            if (ctx->opt_level > 0)
            {
                const char *scratch = bslash_scratch_acquire(ctx, ins->line);
                if (!scratch)
                {
                    success = false;
                    goto cleanup;
                }
                bslash_emit_movi32_label(ctx, scratch, label);
                bslash_ensure_register_materialized(ctx, scratch);
                fprintf(ctx->out, "    LD %s, [%s]\n", dst, scratch);
                bslash_scratch_release(ctx);
            }
            else
            {
                fprintf(ctx->out, "    PUSHR B1\n");
                bslash_emit_movi32_label(ctx, "B1", label);
                fprintf(ctx->out, "    LD %s, [B1]\n", dst);
                fprintf(ctx->out, "    POPR B1\n");
            }
            bslash_clear_register_info(ctx, dst);
            break;
        }
        case CC_INSTR_ADDR_LOCAL:
        {
            const char *dst = NULL;
            if (!bslash_stack_push_new(ctx, ins->line, &dst))
            {
                success = false;
                goto cleanup;
            }
            size_t local_index = ins->data.local.index;
            bool reg_candidate = ctx->local_needs_memory && local_index < ctx->local_count && !ctx->local_needs_memory[local_index];
            if (reg_candidate)
            {
                emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "cannot take address of register-allocated local %zu", local_index);
                success = false;
                goto cleanup;
            }
            const char *label = (ctx->opt_level >= 3)
                                    ? bslash_get_local_label_name(ctx, ins->data.local.index)
                                    : bslash_require_local_storage(ctx, ins->data.local.index);
            if (!label)
            {
                success = false;
                goto cleanup;
            }
            if (ctx->opt_level >= 3)
            {
                bslash_set_register_label(ctx, dst, label, false);
            }
            else
            {
                bslash_emit_movi32_label(ctx, dst, label);
            }
            break;
        }
        case CC_INSTR_LABEL:
        {
            if (ins->data.label.name && ins->data.label.name[0])
            {
                fprintf(ctx->out, "%s:\n", ins->data.label.name);
                bslash_stack_reset(ctx);
                if (ctx->opt_level >= 3)
                    bslash_local_invalidate_all(ctx);
            }
            break;
        }
        case CC_INSTR_JUMP:
        {
            if (!ins->data.jump.target)
            {
                emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "jump missing target");
                success = false;
                goto cleanup;
            }
            fprintf(ctx->out, "    J32 %s\n", ins->data.jump.target);
            bslash_stack_reset(ctx);
            if (ctx->opt_level >= 3)
                bslash_local_invalidate_all(ctx);
            break;
        }
        case CC_INSTR_BRANCH:
        {
            if (!ins->data.branch.true_target || !ins->data.branch.false_target)
            {
                emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "branch missing target");
                success = false;
                goto cleanup;
            }
            const char *cond = bslash_stack_pop(ctx, ins->line);
            if (!cond)
            {
                success = false;
                goto cleanup;
            }
            bslash_ensure_register_materialized(ctx, cond);
            fprintf(ctx->out, "    CMPI32 %s, #0x00000000\n", cond);
            fprintf(ctx->out, "    BNZ %s\n", ins->data.branch.true_target);
            fprintf(ctx->out, "    J32 %s\n", ins->data.branch.false_target);
            bslash_release_register(ctx, cond);
            bslash_stack_reset(ctx);
            if (ctx->opt_level >= 3)
                bslash_local_invalidate_all(ctx);
            break;
        }
        case CC_INSTR_BINOP:
        {
            const char *rhs = bslash_stack_pop(ctx, ins->line);
            const char *lhs = bslash_stack_pop(ctx, ins->line);
            if (!rhs || !lhs)
            {
                if (rhs)
                    bslash_release_register(ctx, rhs);
                if (lhs)
                    bslash_release_register(ctx, lhs);
                success = false;
                goto cleanup;
            }
            bool pushed = false;
            bool rhs_released = false;
            switch (ins->data.binop.op)
            {
            case CC_BINOP_ADD:
                if (!bslash_try_emit_add_const(ctx, lhs, rhs))
                {
                    bslash_ensure_register_materialized(ctx, lhs);
                    bslash_ensure_register_materialized(ctx, rhs);
                    fprintf(ctx->out, "    ADD %s, %s\n", lhs, rhs);
                    bslash_clear_register_info(ctx, lhs);
                }
                else
                {
                    rhs_released = true;
                }
                break;
            default:
                fprintf(ctx->out, "    // unhandled binop %d\n", (int)ins->data.binop.op);
                if (!bslash_stack_push_existing(ctx, ins->line, lhs))
                {
                    bslash_release_register(ctx, rhs);
                    bslash_release_register(ctx, lhs);
                    success = false;
                    goto cleanup;
                }
                pushed = true;
                break;
            }
            if (!rhs_released)
                bslash_release_register(ctx, rhs);
            if (!pushed)
            {
                if (!bslash_stack_push_existing(ctx, ins->line, lhs))
                {
                    success = false;
                    goto cleanup;
                }
            }
            break;
        }
        case CC_INSTR_COMPARE:
        {
            const char *rhs = bslash_stack_pop(ctx, ins->line);
            const char *lhs = bslash_stack_pop(ctx, ins->line);
            if (!rhs || !lhs)
            {
                if (rhs)
                    bslash_release_register(ctx, rhs);
                if (lhs)
                    bslash_release_register(ctx, lhs);
                success = false;
                goto cleanup;
            }
            const char *branch_op = bslash_compare_branch_opcode(ins->data.compare.op, ins->data.compare.is_unsigned);
            if (!branch_op)
            {
                emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "compare op %d unsupported", (int)ins->data.compare.op);
                bslash_release_register(ctx, rhs);
                bslash_release_register(ctx, lhs);
                success = false;
                goto cleanup;
            }
            bslash_ensure_register_materialized(ctx, lhs);
            bslash_ensure_register_materialized(ctx, rhs);
            fprintf(ctx->out, "    CMP %s, %s\n", lhs, rhs);
            bslash_release_register(ctx, rhs);
            char true_label[128];
            char end_label[128];
            bslash_make_temp_label(ctx, true_label, sizeof(true_label), "cmp_true");
            bslash_make_temp_label(ctx, end_label, sizeof(end_label), "cmp_end");
            bslash_emit_movi32_u32(ctx, lhs, 0);
            fprintf(ctx->out, "    %s %s\n", branch_op, true_label);
            fprintf(ctx->out, "    J32 %s\n", end_label);
            fprintf(ctx->out, "%s:\n", true_label);
            bslash_emit_movi32_u32(ctx, lhs, 1);
            fprintf(ctx->out, "%s:\n", end_label);
            bslash_clear_register_info(ctx, lhs);
            if (!bslash_stack_push_existing(ctx, ins->line, lhs))
            {
                success = false;
                goto cleanup;
            }
            break;
        }
        case CC_INSTR_TEST_NULL:
        {
            const char *value = bslash_stack_pop(ctx, ins->line);
            if (!value)
            {
                success = false;
                goto cleanup;
            }

            bslash_ensure_register_materialized(ctx, value);
            fprintf(ctx->out, "    CMPI32 %s, #0x00000000\n", value);

            char true_label[128];
            char end_label[128];
            bslash_make_temp_label(ctx, true_label, sizeof(true_label), "tnull_true");
            bslash_make_temp_label(ctx, end_label, sizeof(end_label), "tnull_end");

            bslash_emit_movi32_u32(ctx, value, 0);
            fprintf(ctx->out, "    BZ %s\n", true_label);
            fprintf(ctx->out, "    J32 %s\n", end_label);
            fprintf(ctx->out, "%s:\n", true_label);
            bslash_emit_movi32_u32(ctx, value, 1);
            fprintf(ctx->out, "%s:\n", end_label);

            bslash_clear_register_info(ctx, value);
            if (!bslash_stack_push_existing(ctx, ins->line, value))
            {
                success = false;
                goto cleanup;
            }
            break;
        }
        case CC_INSTR_DUP:
        {
            const char *value = bslash_stack_pop(ctx, ins->line);
            if (!value)
            {
                success = false;
                goto cleanup;
            }

            if (!bslash_stack_push_existing(ctx, ins->line, value))
            {
                success = false;
                goto cleanup;
            }

            const char *copy = NULL;
            if (!bslash_stack_push_new(ctx, ins->line, &copy))
            {
                success = false;
                goto cleanup;
            }

            bslash_ensure_register_materialized(ctx, value);
            bslash_emit_mov(ctx, copy, value);
            bslash_clear_register_info(ctx, copy);
            break;
        }
        case CC_INSTR_CONVERT:
        {
            const char *value = bslash_stack_pop(ctx, ins->line);
            if (!value)
            {
                success = false;
                goto cleanup;
            }
            size_t from_bits = cc_value_type_size(ins->data.convert.from_type) * 8;
            size_t to_bits = cc_value_type_size(ins->data.convert.to_type) * 8;
            bool handled = true;
            switch (ins->data.convert.kind)
            {
            case CC_CONVERT_TRUNC:
            case CC_CONVERT_ZEXT:
            {
                if (to_bits < 32 && to_bits > 0)
                {
                    uint32_t mask = to_bits >= 32 ? 0xffffffffu : ((1u << to_bits) - 1u);
                    bslash_ensure_register_materialized(ctx, value);
                    fprintf(ctx->out, "    ANDI32 %s, #0x%08" PRIX32 "\n", value, mask);
                    bslash_clear_register_info(ctx, value);
                }
                break;
            }
            case CC_CONVERT_SEXT:
            {
                if (from_bits > 0 && from_bits < 32)
                {
                    uint32_t shift = 32u - (uint32_t)from_bits;
                    bslash_ensure_register_materialized(ctx, value);
                    fprintf(ctx->out, "    SHLI8 %s, #0x%02" PRIX32 "\n", value, shift);
                    fprintf(ctx->out, "    ASRI8 %s, #0x%02" PRIX32 "\n", value, shift);
                    bslash_clear_register_info(ctx, value);
                }
                break;
            }
            case CC_CONVERT_BITCAST:
                break;
            default:
                handled = false;
                break;
            }
            if (!handled)
            {
                emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "convert kind %d unsupported", (int)ins->data.convert.kind);
                bslash_release_register(ctx, value);
                success = false;
                goto cleanup;
            }
            if (!bslash_stack_push_existing(ctx, ins->line, value))
            {
                bslash_release_register(ctx, value);
                success = false;
                goto cleanup;
            }
            break;
        }
        case CC_INSTR_CALL:
        {
            if (!ins->data.call.symbol)
            {
                emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "call with no symbol not supported");
                success = false;
                goto cleanup;
            }
            size_t arg_count = ins->data.call.arg_count;
            if (arg_count > BSLASH_PARAM_REG_COUNT)
            {
                emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "call with %zu args exceeds register support", arg_count);
                success = false;
                goto cleanup;
            }
            const char *args[BSLASH_PARAM_REG_COUNT] = {0};
            for (size_t ai = 0; ai < arg_count; ++ai)
            {
                const char *reg = bslash_stack_pop(ctx, ins->line);
                if (!reg)
                {
                    success = false;
                    goto cleanup;
                }
                args[arg_count - 1 - ai] = reg;
            }
            if (ctx->opt_level >= 3)
                bslash_local_handle_call_alias(ctx, args, arg_count, ins->line);
            bool handled = false;
            if (ctx->opt_level >= 3)
                handled = bslash_try_emit_o3_string_inline(ctx, ins, args, arg_count);

            if (!handled)
            {
                const CCFunction *callee = bslash_find_function(ctx->module, ins->data.call.symbol);
                if (callee && callee->force_inline_literal)
                {
                    if (!bslash_emit_force_inline_literal_call(ctx, ins, callee, args, arg_count))
                    {
                        success = false;
                        goto cleanup;
                    }
                    handled = true;
                }
            }

            if (!handled)
            {
                for (size_t ai = 0; ai < arg_count; ++ai)
                {
                    if (args[ai])
                        bslash_emit_mov(ctx, kParamRegs[ai], args[ai]);
                }
                fprintf(ctx->out, "    CALL %s\n", ins->data.call.symbol);
                bslash_mark_function_needed(ctx, ins->data.call.symbol);
                if (ins->data.call.return_type != CC_TYPE_VOID)
                {
                    const char *dst = NULL;
                    if (!bslash_stack_push_new(ctx, ins->line, &dst))
                    {
                        success = false;
                        goto cleanup;
                    }
                    if (strcmp(dst, "B0") != 0)
                        bslash_emit_mov(ctx, dst, "B0");
                }
            }
            for (size_t ai = 0; ai < arg_count; ++ai)
            {
                if (args[ai])
                    bslash_release_register(ctx, args[ai]);
            }
            break;
        }
        case CC_INSTR_RET:
        {
            if (ins->data.ret.has_value)
            {
                const char *value = bslash_stack_pop(ctx, ins->line);
                if (!value)
                {
                    success = false;
                    goto cleanup;
                }
                bool optimized_return = false;
                if (ctx->opt_level >= 3)
                {
                    uint32_t const_value = 0;
                    if (bslash_get_register_const(ctx, value, &const_value))
                    {
                        bslash_emit_movi32_u32(ctx, "B0", const_value);
                        optimized_return = true;
                    }
                    else
                    {
                        const char *label = bslash_get_register_label(ctx, value);
                        if (label)
                        {
                            bslash_emit_movi32_label(ctx, "B0", label);
                            optimized_return = true;
                        }
                    }
                }
                if (!optimized_return && strcmp(value, "B0") != 0)
                    bslash_emit_mov(ctx, "B0", value);
                bslash_release_register(ctx, value);
            }
            fprintf(ctx->out, "    RET\n");
            bslash_stack_reset(ctx);
            if (ctx->opt_level >= 3)
                bslash_local_invalidate_all(ctx);
            emitted_return = true;
            break;
        }
        case CC_INSTR_DROP:
        {
            const char *dropped = bslash_stack_pop(ctx, ins->line);
            if (!dropped)
            {
                success = false;
                goto cleanup;
            }
            bslash_release_register(ctx, dropped);
            break;
        }
        case CC_INSTR_LOAD_INDIRECT:
        {
            const char *ptr = bslash_stack_pop(ctx, ins->line);
            if (!ptr)
            {
                success = false;
                goto cleanup;
            }
            const char *dst = NULL;
            if (!bslash_stack_push_new(ctx, ins->line, &dst))
            {
                bslash_release_register(ctx, ptr);
                success = false;
                goto cleanup;
            }
            bool folded = false;
            if (ctx->opt_level >= 3)
                folded = bslash_try_fold_pointer_load(ctx, ptr, dst, ins->data.memory.type);
            if (!folded)
            {
                const char *ptr_label = bslash_get_register_label(ctx, ptr);
                if (ptr_label)
                {
                    int local_idx = bslash_local_index_from_label(ctx, ptr_label);
                    if (local_idx >= 0 && ctx->opt_level >= 3)
                    {
                        if (!bslash_local_materialize(ctx, (size_t)local_idx, ins->line))
                        {
                            bslash_release_register(ctx, ptr);
                            success = false;
                            goto cleanup;
                        }
                    }
                }
                const char *load_op = bslash_load_mnemonic(ins->data.memory.type, ins->data.memory.is_unsigned);
                bslash_ensure_register_materialized(ctx, ptr);
                fprintf(ctx->out, "    %s %s, [%s]\n", load_op, dst, ptr);
                bslash_clear_register_info(ctx, dst);
            }
            bslash_release_register(ctx, ptr);
            break;
        }
        case CC_INSTR_STORE_INDIRECT:
        {
            const char *value = bslash_stack_pop(ctx, ins->line);
            const char *ptr = bslash_stack_pop(ctx, ins->line);
            if (!value || !ptr)
            {
                if (value)
                    bslash_release_register(ctx, value);
                if (ptr)
                    bslash_release_register(ctx, ptr);
                success = false;
                goto cleanup;
            }
            const char *store_op = bslash_store_mnemonic(ins->data.memory.type);
            int local_idx = -1;
            const char *ptr_label = bslash_get_register_label(ctx, ptr);
            if (ptr_label)
                local_idx = bslash_local_index_from_label(ctx, ptr_label);
            bool recorded_pointer_store = false;
            bool skip_pointer_store = false;
            if (ctx->opt_level >= 3)
            {
                bslash_local_note_pointer_store(ctx, ptr, value);
                recorded_pointer_store = true;
                if (local_idx >= 0)
                {
                    bool has_known = (ctx->local_known_values && ctx->local_known_values[local_idx]) ||
                                     (ctx->local_known_ptr && ctx->local_known_ptr[local_idx]);
                    if (has_known)
                        skip_pointer_store = true;
                }
            }
            if (skip_pointer_store)
            {
                bslash_local_mark_dirty(ctx, (size_t)local_idx);
                bslash_release_register(ctx, value);
                bslash_release_register(ctx, ptr);
                break;
            }
            if (recorded_pointer_store && local_idx >= 0)
            {
                if (!bslash_require_local_storage(ctx, (size_t)local_idx))
                {
                    bslash_release_register(ctx, value);
                    bslash_release_register(ctx, ptr);
                    success = false;
                    goto cleanup;
                }
            }
            bslash_ensure_register_materialized(ctx, ptr);
            bslash_ensure_register_materialized(ctx, value);
            fprintf(ctx->out, "    %s [%s], %s\n", store_op, ptr, value);
            if (recorded_pointer_store && local_idx >= 0)
                bslash_local_mark_clean(ctx, (size_t)local_idx);
            bslash_release_register(ctx, value);
            bslash_release_register(ctx, ptr);
            break;
        }
        case CC_INSTR_COMMENT:
        {
            if (ins->data.comment.text)
                fprintf(ctx->out, "    // %s\n", ins->data.comment.text);
            break;
        }
        default:
        {
            fprintf(ctx->out, "    // unhandled instr kind %d\n", (int)ins->kind);
            break;
        }
        }
    }

    if (!emitted_return)
    {
        fprintf(ctx->out, "    RET\n");
        bslash_stack_reset(ctx);
    }

    fprintf(ctx->out, "\n");
    goto cleanup;

cleanup:
    bslash_function_cleanup(ctx);
    return success;
}

static bool bslash_emit_module(const CCBackend *backend, const CCModule *module, const CCBackendOptions *options, CCDiagnosticSink *sink, void *userdata)
{
    (void)backend;
    (void)userdata;
    if (!module)
        return false;

    int opt_level = 0;
    if (!bslash_get_opt_level(options, sink, &opt_level))
        return false;

    const char *output_path = NULL;
    if (options && options->options)
    {
        for (size_t i = 0; i < options->option_count; ++i)
        {
            const CCBackendOption *opt = &options->options[i];
            if (strcmp(opt->key, "output") == 0)
                output_path = opt->value;
        }
    }

    BSlashStringTable strings = {0};
    BSlashDataTable locals = {0};
    size_t string_counter = 0;
    bool success = true;

    FILE *out = stdout;
    bool opened_file = false;
    if (output_path)
    {
        out = fopen(output_path, "w");
        if (!out)
        {
            emit_diag(sink, CC_DIAG_ERROR, 0, "failed to open '%s'", output_path);
            bslash_string_table_destroy(&strings);
            return false;
        }
        opened_file = true;
    }

    fprintf(out, "// ChanceCode BSlash backend output\n\n");

    BSlashFunctionOutput *fn_outputs = NULL;
    if (module->function_count > 0)
    {
        fn_outputs = (BSlashFunctionOutput *)calloc(module->function_count, sizeof(BSlashFunctionOutput));
        if (!fn_outputs)
        {
            emit_diag(sink, CC_DIAG_ERROR, 0, "out of memory allocating function buffers");
            success = false;
            goto cleanup;
        }
    }

    for (size_t fi = 0; fi < module->function_count; ++fi)
    {
        const CCFunction *fn = &module->functions[fi];
        BSlashFunctionOutput *out_entry = &fn_outputs[fi];
        out_entry->fn = fn;
        bool literal_needs_emit = fn && fn->is_literal && !fn->force_inline_literal;
        out_entry->force_emit = fn && (fn->is_preserve || literal_needs_emit);
        if (!fn || !fn->name)
            continue;

        FILE *fn_file = tmpfile();
        if (!fn_file)
        {
            emit_diag(sink, CC_DIAG_ERROR, 0, "failed to allocate temporary function buffer");
            success = false;
            goto cleanup;
        }

        BSlashFunctionContext fn_ctx = {
            .out = fn_file,
            .sink = sink,
            .fn = fn,
            .module = module,
            .strings = &strings,
            .module_outputs = fn_outputs,
            .module_output_count = module->function_count,
            .stack_depth = 0,
            .scratch_depth = 0,
            .locals_table = &locals,
            .local_labels = NULL,
            .local_count = 0,
            .opt_level = opt_level,
        };

        if (!bslash_emit_function(&fn_ctx, fn, &strings, &string_counter))
        {
            fclose(fn_file);
            success = false;
            goto cleanup;
        }

        fflush(fn_file);
        long size = ftell(fn_file);
        if (size < 0)
        {
            fclose(fn_file);
            emit_diag(sink, CC_DIAG_ERROR, 0, "failed to measure function buffer");
            success = false;
            goto cleanup;
        }
        rewind(fn_file);
        if (size > 0)
        {
            char *buffer = (char *)malloc((size_t)size + 1);
            if (!buffer)
            {
                fclose(fn_file);
                emit_diag(sink, CC_DIAG_ERROR, 0, "out of memory duplicating function text");
                success = false;
                goto cleanup;
            }
            size_t read = fread(buffer, 1, (size_t)size, fn_file);
            if (read != (size_t)size)
            {
                free(buffer);
                fclose(fn_file);
                emit_diag(sink, CC_DIAG_ERROR, 0, "failed to read function buffer");
                success = false;
                goto cleanup;
            }
            buffer[size] = '\0';
            out_entry->buffer = buffer;
            out_entry->size = (size_t)size;
        }
        fclose(fn_file);
    }

    for (size_t fi = 0; fi < module->function_count; ++fi)
    {
        BSlashFunctionOutput *entry = &fn_outputs[fi];
        if (!entry->buffer || entry->size == 0)
            continue;
        if (!entry->force_emit && !entry->needed)
            continue;
        fwrite(entry->buffer, 1, entry->size, out);
    }

    if (locals.count > 0)
    {
        fprintf(out, "// local storage\n\n");
        for (size_t li = 0; li < locals.count; ++li)
        {
            fprintf(out, "%%align 4\n%s:\n", locals.items[li].label);
            fprintf(out, "    .dword 0\n\n");
        }
    }

    if (strings.count > 0)
    {
        bool emitted_strings = false;
        for (size_t si = 0; si < strings.count; ++si)
        {
            if (!strings.items[si].needed)
                continue;
            if (!emitted_strings)
            {
                fprintf(out, "// string literals\n\n");
                emitted_strings = true;
            }
            bslash_emit_string_literal(out, &strings.items[si]);
        }
    }

cleanup:
    if (fn_outputs)
    {
        for (size_t fi = 0; fi < module->function_count; ++fi)
        {
            free(fn_outputs[fi].buffer);
        }
        free(fn_outputs);
    }
    if (opened_file && out)
        fclose(out);
    bslash_string_table_destroy(&strings);
    bslash_data_table_destroy(&locals);
    return success;
}

static const CCBackend kBslashBackend = {
    .name = "bslash",
    .description = "BSlash 32-bit backend",
    .emit = bslash_emit_module,
    .userdata = NULL};

bool cc_register_backend_bslash(void)
{
    return cc_backend_register(&kBslashBackend);
}
