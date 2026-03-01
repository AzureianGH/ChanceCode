#include "cc/loader.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct PendingAddrGlobal
{
    char *name;
    size_t line;
} PendingAddrGlobal;

typedef struct LoaderState
{
    const char *path;
    CCModule *module;
    CCDiagnosticSink *sink;
    size_t line;
    size_t string_counter;
    char **pending_noreturn;
    size_t pending_noreturn_count;
    size_t pending_noreturn_capacity;
    PendingAddrGlobal *pending_addr_globals;
    size_t pending_addr_global_count;
    size_t pending_addr_global_capacity;
    int reading_literal;
    CCFunction *literal_fn;
    uint32_t current_debug_file;
    uint32_t current_debug_line;
    uint32_t current_debug_column;
} LoaderState;

static CCGlobal *find_global(CCModule *module, const char *name);
static CCFunction *find_function(CCModule *module, const char *name);
static char *duplicate_token(const char *token);
static void strip_trailing_newline(char *line);
static bool cc_function_literal_append(CCFunction *fn, const char *text);
static bool mark_function_preserve(LoaderState *st, const char *name);
static bool mark_function_force_inline_literal(LoaderState *st, const char *name);
static CCInstruction *append_instruction(LoaderState *st, CCFunction *fn, CCInstrKind kind);
static bool parse_file_directive(LoaderState *st, char *line);
static bool parse_loc_directive(LoaderState *st, char *line);

static void loader_diag(LoaderState *st, CCDiagnosticSeverity severity, size_t line, const char *fmt, ...)
{
    if (!st || !st->sink || !st->sink->callback)
        return;

    va_list args;
    va_start(args, fmt);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    CCDiagnostic diag;
    diag.severity = severity;
    diag.line = line;
    diag.column = 0;
    diag.message = buffer;
    st->sink->callback(&diag, st->sink->userdata);
}

static void pending_noreturn_destroy(LoaderState *st)
{
    if (!st || !st->pending_noreturn)
        return;
    for (size_t i = 0; i < st->pending_noreturn_count; ++i)
        free(st->pending_noreturn[i]);
    free(st->pending_noreturn);
    st->pending_noreturn = NULL;
    st->pending_noreturn_count = 0;
    st->pending_noreturn_capacity = 0;
}

static void pending_addr_globals_destroy(LoaderState *st)
{
    if (!st || !st->pending_addr_globals)
        return;
    for (size_t i = 0; i < st->pending_addr_global_count; ++i)
        free(st->pending_addr_globals[i].name);
    free(st->pending_addr_globals);
    st->pending_addr_globals = NULL;
    st->pending_addr_global_count = 0;
    st->pending_addr_global_capacity = 0;
}

static bool mark_symbol_noreturn(LoaderState *st, const char *name)
{
    if (!st || !name)
        return false;
    CCExtern *ext = cc_module_find_extern(st->module, name);
    if (ext)
    {
        ext->is_noreturn = true;
        return true;
    }
    CCFunction *fn = find_function(st->module, name);
    if (fn)
    {
        fn->is_noreturn = true;
        return true;
    }
    return false;
}

static bool mark_function_preserve(LoaderState *st, const char *name)
{
    if (!st || !name)
        return false;
    CCFunction *fn = find_function(st->module, name);
    if (!fn)
        return false;
    fn->is_preserve = true;
    return true;
}

static bool mark_function_force_inline_literal(LoaderState *st, const char *name)
{
    if (!st || !name)
        return false;
    CCFunction *fn = find_function(st->module, name);
    if (!fn)
        return false;
    fn->force_inline_literal = true;
    return true;
}

static CCInstruction *append_instruction(LoaderState *st, CCFunction *fn, CCInstrKind kind)
{
    if (!st || !fn)
        return NULL;
    CCInstruction *ins = cc_function_append_instruction(fn, kind, st->line);
    if (!ins)
        return NULL;
    ins->debug_file = st->current_debug_file;
    ins->debug_line = st->current_debug_line;
    ins->debug_column = st->current_debug_column;
    return ins;
}

static bool pending_noreturn_add(LoaderState *st, const char *name)
{
    if (!st || !name || *name == '\0')
        return false;
    if (st->pending_noreturn_count == st->pending_noreturn_capacity)
    {
        size_t new_cap = st->pending_noreturn_capacity ? st->pending_noreturn_capacity * 2 : 4;
        char **new_list = (char **)realloc(st->pending_noreturn, new_cap * sizeof(char *));
        if (!new_list)
            return false;
        st->pending_noreturn = new_list;
        st->pending_noreturn_capacity = new_cap;
    }
    char *copy = duplicate_token(name);
    if (!copy)
        return false;
    st->pending_noreturn[st->pending_noreturn_count++] = copy;
    return true;
}

static bool pending_addr_globals_add(LoaderState *st, const char *name, size_t line)
{
    if (!st || !name || *name == '\0')
        return false;
    if (st->pending_addr_global_count == st->pending_addr_global_capacity)
    {
        size_t new_cap = st->pending_addr_global_capacity ? st->pending_addr_global_capacity * 2 : 4;
        PendingAddrGlobal *new_list = (PendingAddrGlobal *)realloc(st->pending_addr_globals, new_cap * sizeof(PendingAddrGlobal));
        if (!new_list)
            return false;
        st->pending_addr_globals = new_list;
        st->pending_addr_global_capacity = new_cap;
    }
    char *copy = duplicate_token(name);
    if (!copy)
        return false;
    st->pending_addr_globals[st->pending_addr_global_count].name = copy;
    st->pending_addr_globals[st->pending_addr_global_count].line = line;
    st->pending_addr_global_count++;
    return true;
}

static void resolve_pending_noreturn(LoaderState *st, const char *name)
{
    if (!st || !name)
        return;
    if (!st->pending_noreturn || st->pending_noreturn_count == 0)
        return;
    for (size_t i = 0; i < st->pending_noreturn_count; ++i)
    {
        if (st->pending_noreturn[i] && strcmp(st->pending_noreturn[i], name) == 0)
        {
            mark_symbol_noreturn(st, name);
            free(st->pending_noreturn[i]);
            st->pending_noreturn_count--;
            memmove(&st->pending_noreturn[i], &st->pending_noreturn[i + 1],
                    (st->pending_noreturn_count - i) * sizeof(char *));
            break;
        }
    }
}

static bool resolve_pending_addr_globals(LoaderState *st)
{
    if (!st || st->pending_addr_global_count == 0)
        return true;

    bool ok = true;
    for (size_t i = 0; i < st->pending_addr_global_count; ++i)
    {
        const PendingAddrGlobal *entry = &st->pending_addr_globals[i];
        if (!entry->name)
            continue;
        if (find_global(st->module, entry->name))
            continue;
        if (find_function(st->module, entry->name))
            continue;
        if (cc_module_find_extern(st->module, entry->name))
            continue;
        loader_diag(st, CC_DIAG_ERROR, entry->line, "unknown symbol '%s' referenced by addr_global", entry->name);
        ok = false;
    }
    return ok;
}

static void reset_global_init(CCGlobalInit *init)
{
    if (!init)
        return;

    if (init->kind == CC_GLOBAL_INIT_STRING)
    {
        free(init->payload.string.data);
        init->payload.string.data = NULL;
        init->payload.string.length = 0;
    }
    else if (init->kind == CC_GLOBAL_INIT_BYTES)
    {
        free(init->payload.bytes.data);
        init->payload.bytes.data = NULL;
        init->payload.bytes.size = 0;
    }
    else if (init->kind == CC_GLOBAL_INIT_PTRS)
    {
        if (init->payload.ptrs.symbols)
        {
            for (size_t i = 0; i < init->payload.ptrs.count; ++i)
                free(init->payload.ptrs.symbols[i]);
            free(init->payload.ptrs.symbols);
        }
        init->payload.ptrs.symbols = NULL;
        init->payload.ptrs.count = 0;
    }
    init->kind = CC_GLOBAL_INIT_NONE;
    memset(&init->payload, 0, sizeof(init->payload));
}

static char *trim(char *line)
{
    char *start = line;
    while (*start && isspace((unsigned char)*start))
        ++start;

    if (*start == '\0')
        return start;

    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end))
    {
        *end = '\0';
        --end;
    }
    return start;
}

static bool parse_uint32_token(const char *token, uint32_t *out)
{
    if (!token || !out)
        return false;

    char *endptr = NULL;
    unsigned long value = strtoul(token, &endptr, 0);
    if (token[0] == '\0' || *endptr != '\0' || value > UINT32_MAX)
        return false;

    *out = (uint32_t)value;
    return true;
}

static bool parse_uint64_token(const char *token, uint64_t *out)
{
    if (!token || !out)
        return false;

    char *endptr = NULL;
    unsigned long long value = strtoull(token, &endptr, 0);
    if (token[0] == '\0' || *endptr != '\0')
        return false;

    *out = (uint64_t)value;
    return true;
}

static bool parse_int64_token(const char *token, int64_t *out)
{
    if (!token || !out)
        return false;

    char *endptr = NULL;
    long long value = strtoll(token, &endptr, 0);
    if (token[0] == '\0' || *endptr != '\0')
        return false;

    *out = (int64_t)value;
    return true;
}

static bool parse_double_token(const char *token, double *out)
{
    if (!token || !out)
        return false;

    char *endptr = NULL;
    double value = strtod(token, &endptr);
    if (token[0] == '\0' || *endptr != '\0')
        return false;

    *out = value;
    return true;
}

static CCValueType parse_type_token(const char *token)
{
    if (!token)
        return CC_TYPE_INVALID;

    if (strcmp(token, "i1") == 0)
        return CC_TYPE_I1;
    if (strcmp(token, "i8") == 0)
        return CC_TYPE_I8;
    if (strcmp(token, "u8") == 0)
        return CC_TYPE_U8;
    if (strcmp(token, "i16") == 0)
        return CC_TYPE_I16;
    if (strcmp(token, "u16") == 0)
        return CC_TYPE_U16;
    if (strcmp(token, "i32") == 0)
        return CC_TYPE_I32;
    if (strcmp(token, "u32") == 0)
        return CC_TYPE_U32;
    if (strcmp(token, "i64") == 0)
        return CC_TYPE_I64;
    if (strcmp(token, "u64") == 0)
        return CC_TYPE_U64;
    if (strcmp(token, "f32") == 0)
        return CC_TYPE_F32;
    if (strcmp(token, "f64") == 0)
        return CC_TYPE_F64;
    if (strcmp(token, "ptr") == 0)
        return CC_TYPE_PTR;
    if (strcmp(token, "void") == 0)
        return CC_TYPE_VOID;

    return CC_TYPE_INVALID;
}

static CCBinaryOp parse_binop_token(const char *token)
{
    if (strcmp(token, "add") == 0)
        return CC_BINOP_ADD;
    if (strcmp(token, "sub") == 0)
        return CC_BINOP_SUB;
    if (strcmp(token, "mul") == 0)
        return CC_BINOP_MUL;
    if (strcmp(token, "div") == 0)
        return CC_BINOP_DIV;
    if (strcmp(token, "mod") == 0)
        return CC_BINOP_MOD;
    if (strcmp(token, "and") == 0)
        return CC_BINOP_AND;
    if (strcmp(token, "or") == 0)
        return CC_BINOP_OR;
    if (strcmp(token, "xor") == 0)
        return CC_BINOP_XOR;
    if (strcmp(token, "shl") == 0)
        return CC_BINOP_SHL;
    if (strcmp(token, "shr") == 0)
        return CC_BINOP_SHR;

    return (CCBinaryOp)-1;
}

static CCUnaryOp parse_unop_token(const char *token)
{
    if (strcmp(token, "neg") == 0)
        return CC_UNOP_NEG;
    if (strcmp(token, "not") == 0)
        return CC_UNOP_NOT;
    if (strcmp(token, "bitnot") == 0)
        return CC_UNOP_BITNOT;
    return (CCUnaryOp)-1;
}

static CCCompareOp parse_compare_token(const char *token)
{
    if (strcmp(token, "eq") == 0)
        return CC_COMPARE_EQ;
    if (strcmp(token, "ne") == 0)
        return CC_COMPARE_NE;
    if (strcmp(token, "lt") == 0)
        return CC_COMPARE_LT;
    if (strcmp(token, "le") == 0)
        return CC_COMPARE_LE;
    if (strcmp(token, "gt") == 0)
        return CC_COMPARE_GT;
    if (strcmp(token, "ge") == 0)
        return CC_COMPARE_GE;
    return (CCCompareOp)-1;
}

static CCConvertKind parse_convert_token(const char *token)
{
    if (strcmp(token, "trunc") == 0)
        return CC_CONVERT_TRUNC;
    if (strcmp(token, "sext") == 0)
        return CC_CONVERT_SEXT;
    if (strcmp(token, "zext") == 0)
        return CC_CONVERT_ZEXT;
    if (strcmp(token, "f2i") == 0)
        return CC_CONVERT_F2I;
    if (strcmp(token, "i2f") == 0)
        return CC_CONVERT_I2F;
    if (strcmp(token, "bitcast") == 0)
        return CC_CONVERT_BITCAST;
    return (CCConvertKind)-1;
}

static char *duplicate_token(const char *token)
{
    if (!token)
        return NULL;
    size_t len = strlen(token);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
        return NULL;
    memcpy(copy, token, len + 1);
    return copy;
}

static void strip_trailing_newline(char *line)
{
    if (!line)
        return;
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
    {
        line[len - 1] = '\0';
        --len;
    }
}

static bool cc_function_literal_append(CCFunction *fn, const char *text)
{
    if (!fn || !text)
        return false;
    char *copy = duplicate_token(text);
    if (!copy)
        return false;
    char **new_lines = (char **)realloc(fn->literal_lines, (fn->literal_count + 1) * sizeof(char *));
    if (!new_lines)
    {
        free(copy);
        return false;
    }
    fn->literal_lines = new_lines;
    fn->literal_lines[fn->literal_count++] = copy;
    return true;
}

static bool ccbin_read_exact(FILE *file, void *buffer, size_t size)
{
    if (size == 0)
        return true;
    return fread(buffer, 1, size, file) == size;
}

static bool ccbin_read_u8(FILE *file, uint8_t *value)
{
    unsigned char byte = 0;
    if (!ccbin_read_exact(file, &byte, 1))
        return false;
    *value = (uint8_t)byte;
    return true;
}

static bool ccbin_read_u16(FILE *file, uint16_t *value)
{
    unsigned char buf[2];
    if (!ccbin_read_exact(file, buf, sizeof(buf)))
        return false;
    *value = (uint16_t)(buf[0] | ((uint16_t)buf[1] << 8));
    return true;
}

static bool ccbin_read_u32(FILE *file, uint32_t *value)
{
    unsigned char buf[4];
    if (!ccbin_read_exact(file, buf, sizeof(buf)))
        return false;
    *value = ((uint32_t)buf[0]) |
             ((uint32_t)buf[1] << 8) |
             ((uint32_t)buf[2] << 16) |
             ((uint32_t)buf[3] << 24);
    return true;
}

static bool ccbin_read_u64(FILE *file, uint64_t *value)
{
    unsigned char buf[8];
    if (!ccbin_read_exact(file, buf, sizeof(buf)))
        return false;
    uint64_t result = 0;
    for (int i = 0; i < 8; ++i)
        result |= ((uint64_t)buf[i]) << (8 * i);
    *value = result;
    return true;
}

static bool ccbin_read_s32(FILE *file, int32_t *value)
{
    uint32_t tmp = 0;
    if (!ccbin_read_u32(file, &tmp))
        return false;
    *value = (int32_t)tmp;
    return true;
}

static bool ccbin_read_bool(FILE *file, bool *value)
{
    uint8_t byte = 0;
    if (!ccbin_read_u8(file, &byte))
        return false;
    *value = (byte != 0);
    return true;
}

static bool ccbin_read_size32(FILE *file, size_t *value)
{
    uint32_t tmp = 0;
    if (!ccbin_read_u32(file, &tmp))
        return false;
    if (tmp > (uint32_t)SIZE_MAX)
        return false;
    *value = (size_t)tmp;
    return true;
}

static bool ccbin_read_value_type(FILE *file, CCValueType *type)
{
    int32_t tmp = 0;
    if (!ccbin_read_s32(file, &tmp))
        return false;
    if (tmp < CC_TYPE_INVALID || tmp > CC_TYPE_VOID)
        return false;
    *type = (CCValueType)tmp;
    return true;
}

static bool ccbin_read_value_type_array(FILE *file, size_t count, CCValueType **out_types)
{
    if (count == 0)
    {
        *out_types = NULL;
        return true;
    }

    CCValueType *types = (CCValueType *)malloc(sizeof(CCValueType) * count);
    if (!types)
        return false;

    for (size_t i = 0; i < count; ++i)
    {
        if (!ccbin_read_value_type(file, &types[i]))
        {
            free(types);
            return false;
        }
    }

    *out_types = types;
    return true;
}

static bool ccbin_read_cstring(FILE *file, char **out, bool allow_empty)
{
    size_t len = 0;
    if (!ccbin_read_size32(file, &len))
        return false;

    if (len == 0)
    {
        if (!allow_empty)
            return false;
        *out = NULL;
        return true;
    }

    char *buf = (char *)malloc(len + 1);
    if (!buf)
        return false;
    if (!ccbin_read_exact(file, buf, len))
    {
        free(buf);
        return false;
    }
    buf[len] = '\0';
    *out = buf;
    return true;
}

static bool ccbin_read_bytes(FILE *file, size_t *length, uint8_t **data)
{
    if (!length || !data)
        return false;
    size_t len = 0;
    if (!ccbin_read_size32(file, &len))
        return false;
    if (len == 0)
    {
        *length = 0;
        *data = NULL;
        return true;
    }
    uint8_t *buffer = (uint8_t *)malloc(len);
    if (!buffer)
        return false;
    if (!ccbin_read_exact(file, buffer, len))
    {
        free(buffer);
        return false;
    }
    *length = len;
    *data = buffer;
    return true;
}

static bool cc_load_binary(FILE *file, const char *path, CCModule *module, CCDiagnosticSink *sink)
{
    const char *display_path = path ? path : "<input>";

    char magic[5] = {0};
    if (!ccbin_read_exact(file, magic, sizeof(magic)))
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated header in %s", display_path);
        return false;
    }
    if (memcmp(magic, "CCBIN", sizeof(magic)) != 0)
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid magic in %s", display_path);
        return false;
    }

    uint16_t format_version = 0;
    if (!ccbin_read_u16(file, &format_version))
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated header in %s", display_path);
        return false;
    }
    if (format_version < 1u || format_version > 4u)
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: unsupported format version %u", (unsigned)format_version);
        return false;
    }
    bool has_extern_globals = (format_version >= 2u);
    bool has_global_visibility = (format_version >= 3u);

    uint32_t module_version = 0;
    if (!ccbin_read_u32(file, &module_version))
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: missing module version in %s", display_path);
        return false;
    }

    cc_module_init(module, module_version);

    size_t global_count = 0;
    if (!ccbin_read_size32(file, &global_count))
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to read global count from %s", display_path);
        goto fail;
    }

    for (size_t i = 0; i < global_count; ++i)
    {
        char *name = NULL;
        if (!ccbin_read_cstring(file, &name, false))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid global name at index %zu in %s", i, display_path);
            goto fail;
        }

        CCGlobal *global = cc_module_add_global(module, name);
        if (!global)
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to allocate global '%s'", name ? name : "<null>");
            free(name);
            goto fail;
        }
        free(name);

        CCValueType type = CC_TYPE_INVALID;
        if (!ccbin_read_value_type(file, &type))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid global type at index %zu", i);
            goto fail;
        }
        global->type = type;

        bool is_const = false;
        if (!ccbin_read_bool(file, &is_const))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated global const flag at index %zu", i);
            goto fail;
        }
        global->is_const = is_const;

        bool is_extern = false;
        if (has_extern_globals)
        {
            if (!ccbin_read_bool(file, &is_extern))
            {
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated global extern flag at index %zu", i);
                goto fail;
            }
        }
        global->is_extern = is_extern;

        bool is_hidden = false;
        if (has_global_visibility)
        {
            if (!ccbin_read_bool(file, &is_hidden))
            {
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated global visibility flag at index %zu", i);
                goto fail;
            }
        }
        global->is_hidden = is_hidden;

        size_t alignment = 0;
        if (!ccbin_read_size32(file, &alignment))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated global alignment at index %zu", i);
            goto fail;
        }
        global->alignment = alignment;

        char *section_name = NULL;
        if (!ccbin_read_cstring(file, &section_name, true))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid global section at index %zu", i);
            goto fail;
        }
        free(global->section);
        global->section = section_name;

        uint8_t kind_u8 = 0;
        if (!ccbin_read_u8(file, &kind_u8) || kind_u8 > (uint8_t)CC_GLOBAL_INIT_PTRS)
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid global initializer kind at index %zu", i);
            goto fail;
        }
        global->init.kind = (CCGlobalInitKind)kind_u8;

        switch (global->init.kind)
        {
        case CC_GLOBAL_INIT_NONE:
            break;
        case CC_GLOBAL_INIT_INT:
        {
            uint64_t value = 0;
            if (!ccbin_read_u64(file, &value))
            {
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated integer initializer for global index %zu", i);
                goto fail;
            }
            global->init.payload.u64 = value;
            break;
        }
        case CC_GLOBAL_INIT_FLOAT:
        {
            uint64_t bits = 0;
            if (!ccbin_read_u64(file, &bits))
            {
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated float initializer for global index %zu", i);
                goto fail;
            }
            double value = 0.0;
            memcpy(&value, &bits, sizeof(value));
            global->init.payload.f64 = value;
            break;
        }
        case CC_GLOBAL_INIT_PTRS:
        {
            size_t count = 0;
            if (!ccbin_read_size32(file, &count))
            {
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated ptrs initializer for global index %zu", i);
                goto fail;
            }
            char **symbols = NULL;
            if (count > 0)
            {
                symbols = (char **)calloc(count, sizeof(char *));
                if (!symbols)
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: out of memory reading ptrs initializer");
                    goto fail;
                }
                for (size_t si = 0; si < count; ++si)
                {
                    char *sym = NULL;
                    if (!ccbin_read_cstring(file, &sym, true))
                    {
                        if (sink)
                            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid ptrs symbol at global index %zu", i);
                        for (size_t sj = 0; sj < si; ++sj)
                            free(symbols[sj]);
                        free(symbols);
                        goto fail;
                    }
                    symbols[si] = sym;
                }
            }
            global->init.payload.ptrs.symbols = symbols;
            global->init.payload.ptrs.count = count;
            break;
        }
        case CC_GLOBAL_INIT_STRING:
        {
            size_t len = 0;
            uint8_t *raw = NULL;
            if (!ccbin_read_bytes(file, &len, &raw))
            {
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated string initializer for global index %zu", i);
                goto fail;
            }
            global->init.payload.string.length = len;
            global->init.payload.string.data = (char *)raw;
            break;
        }
        case CC_GLOBAL_INIT_BYTES:
        {
            size_t len = 0;
            uint8_t *raw = NULL;
            if (!ccbin_read_bytes(file, &len, &raw))
            {
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated bytes initializer for global index %zu", i);
                goto fail;
            }
            global->init.payload.bytes.size = len;
            global->init.payload.bytes.data = raw;
            break;
        }
        default:
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: unknown global initializer kind at index %zu", i);
            goto fail;
        }

        if (global->alignment == 0)
            global->alignment = cc_value_type_size(global->type);
    }

    size_t extern_count = 0;
    if (!ccbin_read_size32(file, &extern_count))
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to read extern count from %s", display_path);
        goto fail;
    }

    for (size_t i = 0; i < extern_count; ++i)
    {
        char *name = NULL;
        if (!ccbin_read_cstring(file, &name, false))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid extern name at index %zu", i);
            goto fail;
        }

        CCExtern *ext = cc_module_add_extern(module, name);
        if (!ext)
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to allocate extern '%s'", name ? name : "<null>");
            free(name);
            goto fail;
        }
        free(name);

        CCValueType ret_type = CC_TYPE_VOID;
        if (!ccbin_read_value_type(file, &ret_type))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid return type for extern index %zu", i);
            goto fail;
        }
        ext->return_type = ret_type;

        bool flag = false;
        if (!ccbin_read_bool(file, &flag))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated varargs flag for extern index %zu", i);
            goto fail;
        }
        ext->is_varargs = flag;

        if (!ccbin_read_bool(file, &flag))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated noreturn flag for extern index %zu", i);
            goto fail;
        }
        ext->is_noreturn = flag;

        size_t param_count = 0;
        if (!ccbin_read_size32(file, &param_count))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated param count for extern index %zu", i);
            goto fail;
        }

        CCValueType *param_types = NULL;
        if (!ccbin_read_value_type_array(file, param_count, &param_types))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid parameter types for extern index %zu", i);
            goto fail;
        }

        free(ext->param_types);
        ext->param_types = param_types;
        ext->param_count = param_count;
    }

    size_t function_count = 0;
    if (!ccbin_read_size32(file, &function_count))
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to read function count from %s", display_path);
        goto fail;
    }

    for (size_t i = 0; i < function_count; ++i)
    {
        char *name = NULL;
        if (!ccbin_read_cstring(file, &name, false))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid function name at index %zu", i);
            goto fail;
        }

        CCFunction *fn = cc_module_add_function(module, name);
        if (!fn)
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to allocate function '%s'", name ? name : "<null>");
            free(name);
            goto fail;
        }
        free(name);

        CCValueType ret_type = CC_TYPE_VOID;
        if (!ccbin_read_value_type(file, &ret_type))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid return type for function index %zu", i);
            goto fail;
        }
        fn->return_type = ret_type;

        bool flag = false;
        if (!ccbin_read_bool(file, &flag))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated varargs flag for function index %zu", i);
            goto fail;
        }
        fn->is_varargs = flag;

        if (!ccbin_read_bool(file, &flag))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated noreturn flag for function index %zu", i);
            goto fail;
        }
        fn->is_noreturn = flag;

        char *section_name = NULL;
        if (!ccbin_read_cstring(file, &section_name, true))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid function section at index %zu", i);
            goto fail;
        }
        free(fn->section);
        fn->section = section_name;

        size_t param_count = 0;
        if (!ccbin_read_size32(file, &param_count))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated parameter count for function index %zu", i);
            goto fail;
        }

        CCValueType *param_types = NULL;
        if (!ccbin_read_value_type_array(file, param_count, &param_types))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid parameter types for function index %zu", i);
            goto fail;
        }
        if (!cc_function_set_param_types(fn, param_types, param_count))
        {
            free(param_types);
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to assign parameter types for function index %zu", i);
            goto fail;
        }
        free(param_types);

        size_t local_count = 0;
        if (!ccbin_read_size32(file, &local_count))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated locals count for function index %zu", i);
            goto fail;
        }

        CCValueType *local_types = NULL;
        if (!ccbin_read_value_type_array(file, local_count, &local_types))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid local types for function index %zu", i);
            goto fail;
        }
        if (!cc_function_set_local_types(fn, local_types, local_count))
        {
            free(local_types);
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to assign local types for function index %zu", i);
            goto fail;
        }
        free(local_types);

        size_t instr_count = 0;
        if (!ccbin_read_size32(file, &instr_count))
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated instruction count for function index %zu", i);
            goto fail;
        }

        for (size_t ins_index = 0; ins_index < instr_count; ++ins_index)
        {
            uint8_t kind_byte = 0;
            if (!ccbin_read_u8(file, &kind_byte) || kind_byte > (uint8_t)CC_INSTR_DUP)
            {
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid instruction kind in function index %zu", i);
                goto fail;
            }
            CCInstrKind kind = (CCInstrKind)kind_byte;

            uint32_t line = 0;
            if (!ccbin_read_u32(file, &line))
            {
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated instruction line in function index %zu", i);
                goto fail;
            }

            CCInstruction *ins = cc_function_append_instruction(fn, kind, (size_t)line);
            if (!ins)
            {
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to append instruction %zu in function index %zu", ins_index, i);
                goto fail;
            }

            switch (kind)
            {
            case CC_INSTR_CONST:
            {
                CCValueType type = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &type))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid const type in function index %zu", i);
                    goto fail;
                }
                ins->data.constant.type = type;

                bool is_unsigned = false;
                if (!ccbin_read_bool(file, &is_unsigned))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated const unsigned flag in function index %zu", i);
                    goto fail;
                }
                ins->data.constant.is_unsigned = is_unsigned;

                bool is_null = false;
                if (!ccbin_read_bool(file, &is_null))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated const null flag in function index %zu", i);
                    goto fail;
                }
                ins->data.constant.is_null = is_null;

                if (type == CC_TYPE_F32)
                {
                    uint32_t bits = 0;
                    if (!ccbin_read_u32(file, &bits))
                    {
                        if (sink)
                            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated f32 const in function index %zu", i);
                        goto fail;
                    }
                    float value = 0.0f;
                    memcpy(&value, &bits, sizeof(value));
                    ins->data.constant.value.f32 = value;
                }
                else if (type == CC_TYPE_F64)
                {
                    uint64_t bits = 0;
                    if (!ccbin_read_u64(file, &bits))
                    {
                        if (sink)
                            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated f64 const in function index %zu", i);
                        goto fail;
                    }
                    double value = 0.0;
                    memcpy(&value, &bits, sizeof(value));
                    ins->data.constant.value.f64 = value;
                }
                else
                {
                    uint64_t raw = 0;
                    if (!ccbin_read_u64(file, &raw))
                    {
                        if (sink)
                            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated integer const in function index %zu", i);
                        goto fail;
                    }
                    if (type == CC_TYPE_PTR || is_unsigned)
                        ins->data.constant.value.u64 = raw;
                    else
                        ins->data.constant.value.i64 = (int64_t)raw;
                }
                break;
            }
            case CC_INSTR_CONST_STRING:
            {
                size_t len = 0;
                uint8_t *raw = NULL;
                if (!ccbin_read_bytes(file, &len, &raw))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated const_string payload in function index %zu", i);
                    goto fail;
                }
                ins->data.const_string.length = len;
                ins->data.const_string.bytes = (char *)raw;

                char *hint = NULL;
                if (!ccbin_read_cstring(file, &hint, true))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid const_string hint in function index %zu", i);
                    goto fail;
                }
                ins->data.const_string.label_hint = hint;
                break;
            }
            case CC_INSTR_LOAD_PARAM:
            case CC_INSTR_ADDR_PARAM:
            {
                CCValueType ty = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &ty))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid load_param type in function index %zu", i);
                    goto fail;
                }
                uint32_t index = 0;
                if (!ccbin_read_u32(file, &index))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated load_param index in function index %zu", i);
                    goto fail;
                }
                ins->data.param.type = ty;
                ins->data.param.index = index;
                break;
            }
            case CC_INSTR_LOAD_LOCAL:
            case CC_INSTR_STORE_LOCAL:
            case CC_INSTR_ADDR_LOCAL:
            {
                CCValueType ty = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &ty))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid local type in function index %zu", i);
                    goto fail;
                }
                uint32_t index = 0;
                if (!ccbin_read_u32(file, &index))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated local index in function index %zu", i);
                    goto fail;
                }
                ins->data.local.type = ty;
                ins->data.local.index = index;
                break;
            }
            case CC_INSTR_LOAD_GLOBAL:
            case CC_INSTR_STORE_GLOBAL:
            case CC_INSTR_ADDR_GLOBAL:
            {
                CCValueType ty = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &ty))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid global instruction type in function index %zu", i);
                    goto fail;
                }
                char *symbol = NULL;
                if (!ccbin_read_cstring(file, &symbol, false))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid global symbol in function index %zu", i);
                    goto fail;
                }
                ins->data.global.type = ty;
                ins->data.global.symbol = symbol;
                break;
            }
            case CC_INSTR_LOAD_INDIRECT:
            case CC_INSTR_STORE_INDIRECT:
            {
                CCValueType ty = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &ty))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid indirect type in function index %zu", i);
                    goto fail;
                }
                bool is_unsigned = false;
                if (!ccbin_read_bool(file, &is_unsigned))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated indirect flag in function index %zu", i);
                    goto fail;
                }
                ins->data.memory.type = ty;
                ins->data.memory.is_unsigned = is_unsigned;
                break;
            }
            case CC_INSTR_BINOP:
            {
                uint8_t op = 0;
                if (!ccbin_read_u8(file, &op) || op > (uint8_t)CC_BINOP_SHR)
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid binop opcode in function index %zu", i);
                    goto fail;
                }
                CCValueType ty = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &ty))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid binop type in function index %zu", i);
                    goto fail;
                }
                bool is_unsigned = false;
                if (!ccbin_read_bool(file, &is_unsigned))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated binop flag in function index %zu", i);
                    goto fail;
                }
                ins->data.binop.op = (CCBinaryOp)op;
                ins->data.binop.type = ty;
                ins->data.binop.is_unsigned = is_unsigned;
                break;
            }
            case CC_INSTR_UNOP:
            {
                uint8_t op = 0;
                if (!ccbin_read_u8(file, &op) || op > (uint8_t)CC_UNOP_BITNOT)
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid unop opcode in function index %zu", i);
                    goto fail;
                }
                CCValueType ty = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &ty))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid unop type in function index %zu", i);
                    goto fail;
                }
                ins->data.unop.op = (CCUnaryOp)op;
                ins->data.unop.type = ty;
                break;
            }
            case CC_INSTR_COMPARE:
            {
                uint8_t op = 0;
                if (!ccbin_read_u8(file, &op) || op > (uint8_t)CC_COMPARE_GE)
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid compare opcode in function index %zu", i);
                    goto fail;
                }
                CCValueType ty = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &ty))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid compare type in function index %zu", i);
                    goto fail;
                }
                bool is_unsigned = false;
                if (!ccbin_read_bool(file, &is_unsigned))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated compare flag in function index %zu", i);
                    goto fail;
                }
                ins->data.compare.op = (CCCompareOp)op;
                ins->data.compare.type = ty;
                ins->data.compare.is_unsigned = is_unsigned;
                break;
            }
            case CC_INSTR_TEST_NULL:
                break;
            case CC_INSTR_DUP:
            {
                CCValueType ty = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &ty))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid dup type in function index %zu", i);
                    goto fail;
                }
                ins->data.dup.type = ty;
                break;
            }
            case CC_INSTR_CONVERT:
            {
                uint8_t op = 0;
                if (!ccbin_read_u8(file, &op) || op > (uint8_t)CC_CONVERT_BITCAST)
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid convert opcode in function index %zu", i);
                    goto fail;
                }
                CCValueType from = CC_TYPE_INVALID;
                CCValueType to = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &from) || !ccbin_read_value_type(file, &to))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid convert types in function index %zu", i);
                    goto fail;
                }
                ins->data.convert.kind = (CCConvertKind)op;
                ins->data.convert.from_type = from;
                ins->data.convert.to_type = to;
                break;
            }
            case CC_INSTR_STACK_ALLOC:
            {
                uint32_t size_bytes = 0;
                uint32_t alignment = 0;
                if (!ccbin_read_u32(file, &size_bytes) || !ccbin_read_u32(file, &alignment))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated stack_alloc operands in function index %zu", i);
                    goto fail;
                }
                ins->data.stack_alloc.size_bytes = size_bytes;
                ins->data.stack_alloc.alignment = alignment;
                break;
            }
            case CC_INSTR_DROP:
            {
                CCValueType ty = CC_TYPE_INVALID;
                if (!ccbin_read_value_type(file, &ty))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid drop type in function index %zu", i);
                    goto fail;
                }
                ins->data.drop.type = ty;
                break;
            }
            case CC_INSTR_LABEL:
            {
                char *name_tok = NULL;
                if (!ccbin_read_cstring(file, &name_tok, false))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid label name in function index %zu", i);
                    goto fail;
                }
                ins->data.label.name = name_tok;
                break;
            }
            case CC_INSTR_JUMP:
            {
                char *target = NULL;
                if (!ccbin_read_cstring(file, &target, false))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid jump target in function index %zu", i);
                    goto fail;
                }
                ins->data.jump.target = target;
                break;
            }
            case CC_INSTR_BRANCH:
            {
                char *true_target = NULL;
                char *false_target = NULL;
                if (!ccbin_read_cstring(file, &true_target, false) || !ccbin_read_cstring(file, &false_target, false))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid branch targets in function index %zu", i);
                    goto fail;
                }
                ins->data.branch.true_target = true_target;
                ins->data.branch.false_target = false_target;
                break;
            }
            case CC_INSTR_CALL:
            case CC_INSTR_CALL_INDIRECT:
            {
                char *symbol = NULL;
                bool allow_empty_symbol = (ins->kind == CC_INSTR_CALL_INDIRECT);
                if (!ccbin_read_cstring(file, &symbol, allow_empty_symbol))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid call symbol in function index %zu", i);
                    goto fail;
                }
                if (allow_empty_symbol && symbol && symbol[0] == '\0')
                {
                    free(symbol);
                    symbol = NULL;
                }
                CCValueType ret_ty = CC_TYPE_VOID;
                if (!ccbin_read_value_type(file, &ret_ty))
                {
                    free(symbol);
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid call return type in function index %zu", i);
                    goto fail;
                }
                size_t arg_count = 0;
                if (!ccbin_read_size32(file, &arg_count))
                {
                    free(symbol);
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated call arg count in function index %zu", i);
                    goto fail;
                }
                CCValueType *arg_types = NULL;
                if (!ccbin_read_value_type_array(file, arg_count, &arg_types))
                {
                    free(symbol);
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid call arg types in function index %zu", i);
                    goto fail;
                }
                bool is_varargs = false;
                if (!ccbin_read_bool(file, &is_varargs))
                {
                    free(symbol);
                    free(arg_types);
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated call tail flag in function index %zu", i);
                    goto fail;
                }
                ins->data.call.symbol = symbol;
                ins->data.call.return_type = ret_ty;
                ins->data.call.arg_types = arg_types;
                ins->data.call.arg_count = arg_count;
                ins->data.call.is_varargs = is_varargs;
                break;
            }
            case CC_INSTR_RET:
            {
                bool has_value = false;
                if (!ccbin_read_bool(file, &has_value))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: truncated ret flag in function index %zu", i);
                    goto fail;
                }
                ins->data.ret.has_value = has_value;
                break;
            }
            case CC_INSTR_COMMENT:
            {
                char *text = NULL;
                if (!ccbin_read_cstring(file, &text, true))
                {
                    if (sink)
                        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid comment text in function index %zu", i);
                    goto fail;
                }
                ins->data.comment.text = text;
                break;
            }
            default:
                if (sink)
                    cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: unsupported instruction kind %u", (unsigned)kind);
                goto fail;
            }
        }
    }

    return true;

fail:
    cc_module_free(module);
    return false;
}

static bool parse_string_literal(const char *input, char **out_data, size_t *out_len, const char **out_end)
{
    if (!input || !out_data || !out_len || input[0] != '"') {
        fprintf(stderr, "parse_string_literal: input does not start with quote or is null. First bytes: '%.16s'\n", input ? input : "<null>");
        return false;
    }

    const char *src = input + 1;
    size_t col = 1;
    size_t capacity = 16;
    size_t length = 0;
    char *buffer = (char *)malloc(capacity);
    if (!buffer)
        return false;

    while (*src && *src != '"')
    {
        char ch = *src++;
        ++col;
        if (ch == '\\')
        {
            char esc = *src++;
            ++col;
            if (!esc)
            {
                fprintf(stderr, "parse_string_literal: incomplete escape at column %zu: '%.16s'\n", col, src);
                free(buffer);
                return false;
            }
            switch (esc)
            {
            case 'n':
                ch = '\n';
                break;
            case 'r':
                ch = '\r';
                break;
            case 't':
                ch = '\t';
                break;
            case '\\':
                ch = '\\';
                break;
            case '"':
                ch = '"';
                break;
            case '0':
                ch = '\0';
                break;
            case 'x':
            {
                if (!isxdigit((unsigned char)src[0]) || !isxdigit((unsigned char)src[1]))
                {
                    fprintf(stderr, "parse_string_literal: invalid hex escape at column %zu: '%.16s'\n", col, src);
                    free(buffer);
                    return false;
                }
                col += 2;
                char hex[3] = {src[0], src[1], '\0'};
                ch = (char)strtol(hex, NULL, 16);
                src += 2;
                break;
            }
            default:
                free(buffer);
                return false;
            }
        }

        if (length + 1 >= capacity)
        {
            capacity *= 2;
            char *new_buf = (char *)realloc(buffer, capacity);
            if (!new_buf)
            {
                free(buffer);
                return false;
            }
            buffer = new_buf;
        }
        buffer[length++] = ch;
    }

    if (*src != '"')
    {
        fprintf(stderr, "parse_string_literal: missing closing quote at column %zu. Remainder: '%.16s'\n", col, src);
        free(buffer);
        return false;
    }

    if (out_end)
        *out_end = src + 1;

    *out_data = buffer;
    *out_len = length;
    return true;
}

static bool parse_string_literal_to_cstring(LoaderState *st, const char *input, char **out_text, const char **out_end, const char *context)
{
    if (!out_text)
        return false;
    if (!input || input[0] != '"')
    {
        if (st && context)
            loader_diag(st, CC_DIAG_ERROR, st->line, "%s requires a quoted string literal", context);
        return false;
    }

    char *raw = NULL;
    size_t raw_len = 0;
    const char *tmp_end = NULL;
    const char **end_ptr = out_end ? out_end : &tmp_end;
    if (!parse_string_literal(input, &raw, &raw_len, end_ptr))
    {
        if (st && context)
            loader_diag(st, CC_DIAG_ERROR, st->line, "malformed %s string literal", context);
        free(raw);
        return false;
    }

    char *copy = (char *)malloc(raw_len + 1);
    if (!copy)
    {
        free(raw);
        if (st)
            loader_diag(st, CC_DIAG_ERROR, st->line, "out of memory while parsing %s", context ? context : "string literal");
        return false;
    }
    if (raw_len > 0)
        memcpy(copy, raw, raw_len);
    copy[raw_len] = '\0';
    free(raw);

    *out_text = copy;
    return true;
}

static CCGlobal *find_global(CCModule *module, const char *name)
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

static CCFunction *find_function(CCModule *module, const char *name)
{
    if (!module || !name)
        return NULL;

    for (size_t i = 0; i < module->function_count; ++i)
    {
        if (module->functions[i].name && strcmp(module->functions[i].name, name) == 0)
            return &module->functions[i];
    }
    return NULL;
}

static bool ensure_function_metadata(LoaderState *st, const CCFunction *fn, bool params_set, bool locals_set)
{
    if (!fn)
        return false;

    if (fn->param_count > 0 && !params_set)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "missing .params definition for function '%s'", fn->name);
        return false;
    }
    if (fn->local_count > 0 && !locals_set)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "missing .locals definition for function '%s'", fn->name);
        return false;
    }
    return true;
}

static bool parse_type_list(LoaderState *st, const char *list, CCValueType **out_types, size_t *out_count)
{
    if (!list || !out_types || !out_count)
        return false;

    size_t len = strlen(list);
    if (len < 2 || list[0] != '(' || list[len - 1] != ')')
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "expected type list in parentheses");
        return false;
    }

    char *copy = (char *)malloc(len - 1);
    if (!copy)
        return false;
    memcpy(copy, list + 1, len - 2);
    copy[len - 2] = '\0';

    size_t capacity = 4;
    size_t count = 0;
    CCValueType *types = NULL;
    if (capacity > 0)
    {
        types = (CCValueType *)malloc(sizeof(CCValueType) * capacity);
        if (!types)
        {
            free(copy);
            return false;
        }
    }

    char *token = copy;
    while (token)
    {
        while (*token && isspace((unsigned char)*token))
            ++token;
        if (*token == '\0')
            break;

        char *end = token;
        while (*end && *end != ',')
            ++end;
        if (*end == ',')
            *end++ = '\0';

        CCValueType ty = parse_type_token(token);
        if (ty == CC_TYPE_INVALID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "unknown type '%s' in argument list", token);
            free(types);
            free(copy);
            return false;
        }

        if (count == capacity)
        {
            capacity = capacity ? capacity * 2 : 4;
            CCValueType *new_types = (CCValueType *)realloc(types, sizeof(CCValueType) * capacity);
            if (!new_types)
            {
                free(types);
                free(copy);
                return false;
            }
            types = new_types;
        }
        types[count++] = ty;
        token = end;
    }

    free(copy);
    *out_types = types;
    *out_count = count;
    if (count == 0 && types)
    {
        free(types);
        *out_types = NULL;
    }
    return true;
}

static bool parse_file_directive(LoaderState *st, char *line)
{
    if (!st || !line)
        return false;

    char *cursor = line;
    while (*cursor && isspace((unsigned char)*cursor))
        ++cursor;

    char *id_tok = cursor;
    while (*cursor && !isspace((unsigned char)*cursor))
        ++cursor;
    if (*cursor)
        *cursor++ = '\0';

    if (*id_tok == '\0')
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, ".file requires an id");
        return false;
    }

    uint32_t id = 0;
    if (!parse_uint32_token(id_tok, &id) || id == 0)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "invalid .file id '%s'", id_tok);
        return false;
    }

    while (*cursor && isspace((unsigned char)*cursor))
        ++cursor;
    if (*cursor != '"')
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, ".file requires a quoted path");
        return false;
    }

    char *raw = NULL;
    size_t raw_len = 0;
    if (!parse_string_literal(cursor, &raw, &raw_len, NULL))
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "malformed .file path literal");
        return false;
    }

    char *path = (char *)malloc(raw_len + 1);
    if (!path)
    {
        free(raw);
        return false;
    }
    memcpy(path, raw, raw_len);
    path[raw_len] = '\0';
    free(raw);

    bool ok = cc_module_set_debug_file(st->module, id, path);
    free(path);
    if (!ok)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "failed to record .file entry %u", id);
        return false;
    }

    return true;
}

static bool parse_loc_directive(LoaderState *st, char *line)
{
    if (!st || !line)
        return false;

    char *file_tok = strtok(line, " \t");
    char *line_tok = strtok(NULL, " \t");
    char *col_tok = strtok(NULL, " \t");

    if (!file_tok || !line_tok || !col_tok)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, ".loc requires <file-id> <line> <column>");
        return false;
    }

    uint32_t file_id = 0;
    uint32_t line_no = 0;
    uint32_t col_no = 0;
    if (!parse_uint32_token(file_tok, &file_id))
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "invalid .loc file id '%s'", file_tok);
        return false;
    }
    if (!parse_uint32_token(line_tok, &line_no))
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "invalid .loc line '%s'", line_tok);
        return false;
    }
    if (!parse_uint32_token(col_tok, &col_no))
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "invalid .loc column '%s'", col_tok);
        return false;
    }

    if (file_id != 0 && !cc_module_get_debug_file(st->module, file_id))
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, ".loc references unknown .file id %u", file_id);
        return false;
    }

    st->current_debug_file = file_id;
    st->current_debug_line = line_no;
    st->current_debug_column = col_no;
    return true;
}

static bool parse_global(LoaderState *st, char *line)
{
    char *cursor = line + 7; /* skip ".global" */
    while (*cursor && isspace((unsigned char)*cursor))
        ++cursor;

    char *name = cursor;
    while (*cursor && !isspace((unsigned char)*cursor))
        ++cursor;
    if (*cursor)
        *cursor++ = '\0';

    if (!*name)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "expected global name");
        return false;
    }

    CCGlobal *global = cc_module_add_global(st->module, name);
    if (!global)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "failed to allocate global '%s'", name);
        return false;
    }

    global->alignment = 0;
    global->type = CC_TYPE_INVALID;
    global->is_const = false;
    global->is_extern = false;
    global->is_hidden = false;
    reset_global_init(&global->init);
    int saw_initializer = 0;

    while (*cursor)
    {
        while (*cursor && isspace((unsigned char)*cursor))
            ++cursor;
        if (*cursor == '\0')
            break;

        if (strncmp(cursor, "init=", 5) == 0)
        {
            cursor += 5;
            const char *value = cursor;
            if (*value == '"')
            {
                char *data = NULL;
                size_t len = 0;
                const char *end = NULL;
                if (!parse_string_literal(value, &data, &len, &end))
                {
                    loader_diag(st, CC_DIAG_ERROR, st->line, "malformed string initializer");
                    return false;
                }
                reset_global_init(&global->init);
                global->init.kind = CC_GLOBAL_INIT_STRING;
                global->init.payload.string.data = data;
                global->init.payload.string.length = len;
                cursor = (char *)end;
                saw_initializer = 1;
                continue;
            }
            else
            {
                const char *end = value;
                while (*end && !isspace((unsigned char)*end))
                    ++end;
                char saved = *end;
                *((char *)end) = '\0';

                if (strcmp(value, "null") == 0)
                {
                    reset_global_init(&global->init);
                    global->init.kind = CC_GLOBAL_INIT_INT;
                    global->init.payload.u64 = 0;
                }
                else
                {
                    bool parsed_int = false;
                    uint64_t int_value = 0;
                    if (parse_uint64_token(value, &int_value))
                    {
                        parsed_int = true;
                    }
                    else
                    {
                        int64_t signed_value = 0;
                        if (parse_int64_token(value, &signed_value))
                        {
                            parsed_int = true;
                            int_value = (uint64_t)signed_value;
                        }
                    }

                    if (parsed_int)
                    {
                        reset_global_init(&global->init);
                        global->init.kind = CC_GLOBAL_INIT_INT;
                        global->init.payload.u64 = int_value;
                    }
                    else
                    {
                        double float_value = 0.0;
                        if (!parse_double_token(value, &float_value))
                        {
                            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid initializer '%s'", value);
                            *((char *)end) = saved;
                            return false;
                        }
                        reset_global_init(&global->init);
                        global->init.kind = CC_GLOBAL_INIT_FLOAT;
                        global->init.payload.f64 = float_value;
                    }
                }

                *((char *)end) = saved;
                cursor = (char *)end;
                saw_initializer = 1;
                continue;
            }
        }

        if (strncmp(cursor, "data=", 5) == 0)
        {
            cursor += 5;
            const char *value = cursor;
            if (*value != '"')
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "data= attribute requires a string literal");
                return false;
            }
            char *data = NULL;
            size_t len = 0;
            const char *end = NULL;
            if (!parse_string_literal(value, &data, &len, &end))
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "malformed data initializer");
                free(data);
                return false;
            }
            if (global->size != 0 && global->size != len)
            {
                loader_diag(st, CC_DIAG_ERROR, st->line,
                            "data initializer length (%zu) does not match declared size (%zu)",
                            len, (size_t)global->size);
                free(data);
                return false;
            }
            reset_global_init(&global->init);
            global->init.kind = CC_GLOBAL_INIT_BYTES;
            global->init.payload.bytes.data = (uint8_t *)data;
            global->init.payload.bytes.size = len;
            if (global->size == 0)
                global->size = len;
            cursor = (char *)end;
            saw_initializer = 1;
            continue;
        }

        if (strncmp(cursor, "ptrs=", 5) == 0)
        {
            cursor += 5;
            char *value = cursor;
            while (*cursor && !isspace((unsigned char)*cursor))
                ++cursor;
            char saved = *cursor;
            *cursor = '\0';

            char *list = value;
            if (*list == '[')
            {
                ++list;
                size_t len = strlen(list);
                if (len > 0 && list[len - 1] == ']')
                    list[len - 1] = '\0';
            }

            size_t count = 0;
            char **symbols = NULL;
            bool ok = true;
            char *token = list;
            while (ok)
            {
                char *comma = strchr(token, ',');
                if (comma)
                    *comma = '\0';
                if (*token == '\0' || strcmp(token, "null") == 0)
                {
                    char **grown = (char **)realloc(symbols, (count + 1) * sizeof(char *));
                    if (!grown)
                    {
                        ok = false;
                        break;
                    }
                    symbols = grown;
                    symbols[count++] = NULL;
                }
                else
                {
                    char *copy = duplicate_token(token);
                    if (!copy)
                    {
                        ok = false;
                        break;
                    }
                    char **grown = (char **)realloc(symbols, (count + 1) * sizeof(char *));
                    if (!grown)
                    {
                        free(copy);
                        ok = false;
                        break;
                    }
                    symbols = grown;
                    symbols[count++] = copy;
                }

                if (!comma)
                    break;
                token = comma + 1;
            }

            if (!ok)
            {
                if (symbols)
                {
                    for (size_t i = 0; i < count; ++i)
                        free(symbols[i]);
                    free(symbols);
                }
                loader_diag(st, CC_DIAG_ERROR, st->line, "failed to parse ptrs= initializer");
                *cursor = saved;
                return false;
            }

            if (global->size != 0 && global->size != count * 8)
            {
                for (size_t i = 0; i < count; ++i)
                    free(symbols[i]);
                free(symbols);
                loader_diag(st, CC_DIAG_ERROR, st->line,
                            "ptrs initializer length (%zu pointers) does not match declared size (%zu)",
                            count, (size_t)global->size);
                *cursor = saved;
                return false;
            }

            reset_global_init(&global->init);
            global->init.kind = CC_GLOBAL_INIT_PTRS;
            global->init.payload.ptrs.symbols = symbols;
            global->init.payload.ptrs.count = count;
            if (global->size == 0)
                global->size = count * 8;
            if (global->alignment == 0)
                global->alignment = 8;

            *cursor = saved;
            saw_initializer = 1;
            continue;
        }

        const char *end = cursor;
        while (*end && !isspace((unsigned char)*end))
            ++end;
        char saved = *end;
        *((char *)end) = '\0';

        if (strncmp(cursor, "type=", 5) == 0)
        {
            CCValueType ty = parse_type_token(cursor + 5);
            if (ty == CC_TYPE_INVALID)
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "invalid global type '%s'", cursor + 5);
                *((char *)end) = saved;
                return false;
            }
            global->type = ty;
        }
        else if (strncmp(cursor, "size=", 5) == 0)
        {
            uint64_t value = 0;
            if (!parse_uint64_token(cursor + 5, &value))
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "invalid size '%s'", cursor + 5);
                *((char *)end) = saved;
                return false;
            }
            global->size = (size_t)value;
        }
        else if (strncmp(cursor, "align=", 6) == 0)
        {
            uint32_t align = 0;
            if (!parse_uint32_token(cursor + 6, &align))
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "invalid alignment '%s'", cursor + 6);
                *((char *)end) = saved;
                return false;
            }
            global->alignment = align;
        }
        else if (strncmp(cursor, "section=", 8) == 0)
        {
            char *section_name = NULL;
            if (!parse_string_literal_to_cstring(st, cursor + 8, &section_name, NULL, "section attribute"))
            {
                *((char *)end) = saved;
                return false;
            }
            free(global->section);
            global->section = section_name;
        }
        else if (strcmp(cursor, "const") == 0)
        {
            global->is_const = true;
        }
        else if (strcmp(cursor, "extern") == 0)
        {
            global->is_extern = true;
        }
        else if (strcmp(cursor, "hidden") == 0)
        {
            global->is_hidden = true;
        }
        else
        {
            loader_diag(st, CC_DIAG_WARNING, st->line, "unknown global attribute '%s'", cursor);
        }

        *((char *)end) = saved;
        cursor = (char *)end;
    }

    if (global->is_extern && saw_initializer)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "extern global '%s' cannot have an initializer", global->name);
        return false;
    }

    if (global->type == CC_TYPE_INVALID)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "global '%s' missing type= attribute", global->name);
        return false;
    }

    if (global->size == 0)
        global->size = cc_value_type_size(global->type);

    if (global->alignment == 0)
        global->alignment = cc_value_type_size(global->type);

    return true;
}

static bool parse_extern(LoaderState *st, char *line)
{
    char *cursor = line + 7; /* skip ".extern" */
    while (*cursor && isspace((unsigned char)*cursor))
        ++cursor;

    char *name = cursor;
    while (*cursor && !isspace((unsigned char)*cursor))
        ++cursor;
    if (*cursor)
        *cursor++ = '\0';

    if (!*name)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "expected extern name");
        return false;
    }

    if (find_function(st->module, name))
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "extern '%s' conflicts with function", name);
        return false;
    }

    CCExtern *existing = cc_module_find_extern(st->module, name);
    if (existing)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "duplicate extern '%s'", name);
        return false;
    }

    CCExtern *ext = cc_module_add_extern(st->module, name);
    if (!ext)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "failed to allocate extern '%s'", name);
        return false;
    }

    ext->return_type = CC_TYPE_VOID;
    ext->is_varargs = false;
    ext->param_count = 0;
    free(ext->param_types);
    ext->param_types = NULL;

    while (*cursor)
    {
        while (*cursor && isspace((unsigned char)*cursor))
            ++cursor;
        if (*cursor == '\0')
            break;

        char *token = cursor;
        while (*cursor && !isspace((unsigned char)*cursor))
            ++cursor;
        if (*cursor)
            *cursor++ = '\0';

        if (strncmp(token, "params=", 7) == 0)
        {
            const char *value = token + 7;
            size_t count = 0;
            CCValueType *types = NULL;
            if (*value == '(')
            {
                if (!parse_type_list(st, value, &types, &count))
                {
                    free(types);
                    return false;
                }
                free(ext->param_types);
                ext->param_types = types;
                ext->param_count = count;
            }
            else
            {
                uint32_t num = 0;
                if (!parse_uint32_token(value, &num))
                {
                    loader_diag(st, CC_DIAG_ERROR, st->line, "invalid params attribute '%s'", value);
                    return false;
                }
                free(ext->param_types);
                ext->param_types = NULL;
                ext->param_count = num;
            }
        }
        else if (strncmp(token, "returns=", 8) == 0)
        {
            CCValueType ty = parse_type_token(token + 8);
            if (ty == CC_TYPE_INVALID)
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "invalid return type '%s'", token + 8);
                return false;
            }
            ext->return_type = ty;
        }
        else if (strcmp(token, "varargs") == 0)
        {
            ext->is_varargs = true;
        }
        else if (strcmp(token, "no-return") == 0 || strcmp(token, "noreturn") == 0)
        {
            ext->is_noreturn = true;
        }
        else
        {
            loader_diag(st, CC_DIAG_WARNING, st->line, "unknown extern attribute '%s'", token);
        }
    }

    resolve_pending_noreturn(st, name);

    return true;
}

static bool parse_params_or_locals(LoaderState *st, CCFunction *fn, char *line, bool is_params)
{
    size_t expected = is_params ? fn->param_count : fn->local_count;
    char *cursor = line;
    while (*cursor && isspace((unsigned char)*cursor))
        ++cursor;

    if (expected == 0)
    {
        if (*cursor != '\0')
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "%s should be empty", is_params ? ".params" : ".locals");
            return false;
        }
        return true;
    }

    CCValueType *types = (CCValueType *)malloc(sizeof(CCValueType) * expected);
    if (!types)
        return false;

    size_t count = 0;
    while (*cursor)
    {
        while (*cursor && isspace((unsigned char)*cursor))
            ++cursor;
        if (*cursor == '\0')
            break;

        char *end = cursor;
        while (*end && !isspace((unsigned char)*end))
            ++end;
        char saved = *end;
        if (*end)
            *end = '\0';

        if (count >= expected)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "too many types in %s", is_params ? ".params" : ".locals");
            if (*end)
                *end = saved;
            free(types);
            return false;
        }

        CCValueType ty = parse_type_token(cursor);
        if (ty == CC_TYPE_INVALID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "unknown type '%s'", cursor);
            if (*end)
                *end = saved;
            free(types);
            return false;
        }
        types[count++] = ty;

        *end = saved;
        cursor = end;
    }

    if (count != expected)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "expected %zu types in %s, got %zu", expected,
                    is_params ? ".params" : ".locals", count);
        free(types);
        return false;
    }

    bool ok = is_params ? cc_function_set_param_types(fn, types, count)
                        : cc_function_set_local_types(fn, types, count);
    free(types);
    return ok;
}

static bool parse_instruction(LoaderState *st, CCFunction *fn, char *line)
{
    char *mnemonic = strtok(line, " \t");
    if (!mnemonic)
        return true;

    CCInstruction *ins = NULL;

    if (strcmp(mnemonic, "const") == 0)
    {
        const char *type_tok = strtok(NULL, " \t");
        const char *value_tok = strtok(NULL, " \t");
        if (!type_tok || !value_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "const requires <type> <literal>");
            return false;
        }
        CCValueType ty = parse_type_token(type_tok);
        if (ty == CC_TYPE_INVALID || ty == CC_TYPE_VOID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid const type '%s'", type_tok);
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_CONST);
        if (!ins)
            return false;
        ins->data.constant.type = ty;
        ins->data.constant.is_unsigned = !cc_value_type_is_signed(ty) && ty != CC_TYPE_PTR;
        if (ty == CC_TYPE_F32)
        {
            double tmp = 0.0;
            if (!parse_double_token(value_tok, &tmp))
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "invalid f32 literal '%s'", value_tok);
                return false;
            }
            ins->data.constant.value.f32 = (float)tmp;
        }
        else if (ty == CC_TYPE_F64)
        {
            double tmp = 0.0;
            if (!parse_double_token(value_tok, &tmp))
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "invalid f64 literal '%s'", value_tok);
                return false;
            }
            ins->data.constant.value.f64 = tmp;
        }
        else if (ty == CC_TYPE_PTR)
        {
            if (strcmp(value_tok, "null") == 0)
            {
                ins->data.constant.is_null = true;
                ins->data.constant.value.u64 = 0;
            }
            else
            {
                uint64_t ptr_val = 0;
                if (!parse_uint64_token(value_tok, &ptr_val))
                {
                    loader_diag(st, CC_DIAG_ERROR, st->line, "invalid pointer literal '%s'", value_tok);
                    return false;
                }
                ins->data.constant.value.u64 = ptr_val;
            }
        }
        else if (cc_value_type_is_integer(ty))
        {
            if (cc_value_type_is_signed(ty))
            {
                int64_t val = 0;
                if (!parse_int64_token(value_tok, &val))
                {
                    loader_diag(st, CC_DIAG_ERROR, st->line, "invalid integer literal '%s'", value_tok);
                    return false;
                }
                ins->data.constant.value.i64 = val;
            }
            else
            {
                uint64_t val = 0;
                if (!parse_uint64_token(value_tok, &val))
                {
                    loader_diag(st, CC_DIAG_ERROR, st->line, "invalid unsigned literal '%s'", value_tok);
                    return false;
                }
                ins->data.constant.value.u64 = val;
            }
        }
        else
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "unsupported const type");
            return false;
        }
        return true;
    }

    if (strcmp(mnemonic, "const_str") == 0)
    {
        const char *rest = strtok(NULL, "");
        if (!rest)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "const_str expects a quoted literal");
            return false;
        }
        while (*rest && isspace((unsigned char)*rest))
            ++rest;
        char *data = NULL;
        size_t len = 0;
        if (!parse_string_literal(rest, &data, &len, NULL))
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "malformed string literal");
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_CONST_STRING);
        if (!ins)
        {
            free(data);
            return false;
        }
        ins->data.const_string.bytes = data;
        ins->data.const_string.length = len;
        char hint[32];
        snprintf(hint, sizeof(hint), "__str%zu", st->string_counter++);
        ins->data.const_string.label_hint = duplicate_token(hint);
        return true;
    }

    if (strcmp(mnemonic, "load_param") == 0 || strcmp(mnemonic, "addr_param") == 0)
    {
        const char *index_tok = strtok(NULL, " \t");
        if (!index_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "missing parameter index");
            return false;
        }
        uint32_t index = 0;
        if (!parse_uint32_token(index_tok, &index))
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid parameter index '%s'", index_tok);
            return false;
        }
        bool is_addr = strcmp(mnemonic, "addr_param") == 0;
        bool is_vararg_base = is_addr && fn->is_varargs && index == fn->param_count;
        if (index >= fn->param_count && !is_vararg_base)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "parameter index %u out of range", index);
            return false;
        }
        ins = append_instruction(st, fn, strcmp(mnemonic, "load_param") == 0 ? CC_INSTR_LOAD_PARAM : CC_INSTR_ADDR_PARAM);
        if (!ins)
            return false;
        ins->data.param.index = index;
        ins->data.param.type = strcmp(mnemonic, "load_param") == 0 ? fn->param_types[index] : CC_TYPE_PTR;
        return true;
    }

    if (strcmp(mnemonic, "load_local") == 0 || strcmp(mnemonic, "store_local") == 0 || strcmp(mnemonic, "addr_local") == 0)
    {
        const char *index_tok = strtok(NULL, " \t");
        if (!index_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "missing local index");
            return false;
        }
        uint32_t index = 0;
        if (!parse_uint32_token(index_tok, &index))
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid local index '%s'", index_tok);
            return false;
        }
        if (index >= fn->local_count)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "local index %u out of range", index);
            return false;
        }
        CCInstrKind kind = CC_INSTR_LOAD_LOCAL;
        if (strcmp(mnemonic, "store_local") == 0)
            kind = CC_INSTR_STORE_LOCAL;
        else if (strcmp(mnemonic, "addr_local") == 0)
            kind = CC_INSTR_ADDR_LOCAL;
        ins = append_instruction(st, fn, kind);
        if (!ins)
            return false;
        ins->data.local.index = index;
        ins->data.local.type = (kind == CC_INSTR_ADDR_LOCAL) ? CC_TYPE_PTR : fn->local_types[index];
        return true;
    }

    if (strcmp(mnemonic, "load_global") == 0 || strcmp(mnemonic, "store_global") == 0 || strcmp(mnemonic, "addr_global") == 0)
    {
        const char *symbol = strtok(NULL, " \t");
        if (!symbol)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "expected global symbol name");
            return false;
        }

        bool is_addr = strcmp(mnemonic, "addr_global") == 0;
        CCGlobal *global = find_global(st->module, symbol);
        if (!global)
        {
            if (!is_addr)
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "unknown global '%s'", symbol);
                return false;
            }

            if (!find_function(st->module, symbol) && !cc_module_find_extern(st->module, symbol))
            {
                if (!pending_addr_globals_add(st, symbol, st->line))
                {
                    loader_diag(st, CC_DIAG_ERROR, st->line, "failed to record addr_global reference to '%s'", symbol);
                    return false;
                }
            }
        }

        CCInstrKind kind = CC_INSTR_LOAD_GLOBAL;
        if (strcmp(mnemonic, "store_global") == 0)
            kind = CC_INSTR_STORE_GLOBAL;
        else if (is_addr)
            kind = CC_INSTR_ADDR_GLOBAL;

        if ((kind == CC_INSTR_LOAD_GLOBAL || kind == CC_INSTR_STORE_GLOBAL) && !global)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "instruction '%s' requires declared global '%s'", mnemonic, symbol);
            return false;
        }

        ins = append_instruction(st, fn, kind);
        if (!ins)
            return false;
        ins->data.global.symbol = duplicate_token(symbol);
        ins->data.global.type = (kind == CC_INSTR_ADDR_GLOBAL || !global) ? CC_TYPE_PTR : global->type;
        return true;
    }

    if (strcmp(mnemonic, "load_indirect") == 0 || strcmp(mnemonic, "store_indirect") == 0)
    {
        const char *type_tok = strtok(NULL, " \t");
        if (!type_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "missing type for %s", mnemonic);
            return false;
        }
        CCValueType ty = parse_type_token(type_tok);
        if (ty == CC_TYPE_INVALID || ty == CC_TYPE_VOID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid type '%s'", type_tok);
            return false;
        }
        CCInstrKind kind = strcmp(mnemonic, "load_indirect") == 0 ? CC_INSTR_LOAD_INDIRECT : CC_INSTR_STORE_INDIRECT;
        ins = append_instruction(st, fn, kind);
        if (!ins)
            return false;
        ins->data.memory.type = ty;
        ins->data.memory.is_unsigned = !cc_value_type_is_signed(ty);
        return true;
    }

    if (strcmp(mnemonic, "binop") == 0)
    {
        const char *op_tok = strtok(NULL, " \t");
        const char *type_tok = strtok(NULL, " \t");
        const char *flag_tok = strtok(NULL, " \t");
        if (!op_tok || !type_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "binop requires <op> <type>");
            return false;
        }
        CCBinaryOp op = parse_binop_token(op_tok);
        if ((int)op < 0)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "unknown binop '%s'", op_tok);
            return false;
        }
        CCValueType ty = parse_type_token(type_tok);
        if (ty == CC_TYPE_INVALID || ty == CC_TYPE_VOID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid type '%s'", type_tok);
            return false;
        }
        bool is_unsigned = false;
        if (flag_tok)
        {
            if (strcmp(flag_tok, "unsigned") == 0)
                is_unsigned = true;
            else
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "unexpected flag '%s'", flag_tok);
                return false;
            }
        }
        ins = append_instruction(st, fn, CC_INSTR_BINOP);
        if (!ins)
            return false;
        ins->data.binop.op = op;
        ins->data.binop.type = ty;
        ins->data.binop.is_unsigned = is_unsigned;
        return true;
    }

    if (strcmp(mnemonic, "unop") == 0)
    {
        const char *op_tok = strtok(NULL, " \t");
        const char *type_tok = strtok(NULL, " \t");
        if (!op_tok || !type_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "unop requires <op> <type>");
            return false;
        }
        CCUnaryOp op = parse_unop_token(op_tok);
        if ((int)op < 0)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "unknown unary op '%s'", op_tok);
            return false;
        }
        CCValueType ty = parse_type_token(type_tok);
        if (ty == CC_TYPE_INVALID || ty == CC_TYPE_VOID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid type '%s'", type_tok);
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_UNOP);
        if (!ins)
            return false;
        ins->data.unop.op = op;
        ins->data.unop.type = ty;
        return true;
    }

    if (strcmp(mnemonic, "compare") == 0)
    {
        const char *cond_tok = strtok(NULL, " \t");
        const char *type_tok = strtok(NULL, " \t");
        const char *flag_tok = strtok(NULL, " \t");
        if (!cond_tok || !type_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "compare requires <cond> <type>");
            return false;
        }
        CCCompareOp cond = parse_compare_token(cond_tok);
        if ((int)cond < 0)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "unknown compare condition '%s'", cond_tok);
            return false;
        }
        CCValueType ty = parse_type_token(type_tok);
        if (ty == CC_TYPE_INVALID || ty == CC_TYPE_VOID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid type '%s'", type_tok);
            return false;
        }
        bool is_unsigned = false;
        if (flag_tok)
        {
            if (strcmp(flag_tok, "unsigned") == 0)
                is_unsigned = true;
            else
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "unexpected flag '%s'", flag_tok);
                return false;
            }
        }
        ins = append_instruction(st, fn, CC_INSTR_COMPARE);
        if (!ins)
            return false;
        ins->data.compare.op = cond;
        ins->data.compare.type = ty;
        ins->data.compare.is_unsigned = is_unsigned;
        return true;
    }

    if (strcmp(mnemonic, "test_null") == 0)
    {
        const char *extra = strtok(NULL, " \t");
        if (extra)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "test_null does not take operands");
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_TEST_NULL);
        if (!ins)
            return false;
        return true;
    }

    if (strcmp(mnemonic, "dup") == 0)
    {
        const char *type_tok = strtok(NULL, " \t");
        const char *extra = strtok(NULL, " \t");
        if (!type_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "dup requires <type>");
            return false;
        }
        if (extra)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "dup takes only one operand");
            return false;
        }
        CCValueType ty = parse_type_token(type_tok);
        if (ty == CC_TYPE_INVALID || ty == CC_TYPE_VOID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid dup type '%s'", type_tok);
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_DUP);
        if (!ins)
            return false;
        ins->data.dup.type = ty;
        return true;
    }

    if (strcmp(mnemonic, "convert") == 0)
    {
        const char *kind_tok = strtok(NULL, " \t");
        const char *from_tok = strtok(NULL, " \t");
        const char *to_tok = strtok(NULL, " \t");
        if (!kind_tok || !from_tok || !to_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "convert requires <kind> <from> <to>");
            return false;
        }
        CCConvertKind kind = parse_convert_token(kind_tok);
        if ((int)kind < 0)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "unknown convert kind '%s'", kind_tok);
            return false;
        }
        CCValueType from_ty = parse_type_token(from_tok);
        CCValueType to_ty = parse_type_token(to_tok);
        if (from_ty == CC_TYPE_INVALID || to_ty == CC_TYPE_INVALID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid convert types");
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_CONVERT);
        if (!ins)
            return false;
        ins->data.convert.kind = kind;
        ins->data.convert.from_type = from_ty;
        ins->data.convert.to_type = to_ty;
        return true;
    }

    if (strcmp(mnemonic, "stack_alloc") == 0)
    {
        const char *size_tok = strtok(NULL, " \t");
        const char *align_tok = strtok(NULL, " \t");
        if (!size_tok || !align_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "stack_alloc requires <bytes> <align>");
            return false;
        }
        uint32_t size = 0;
        uint32_t align = 0;
        if (!parse_uint32_token(size_tok, &size) || !parse_uint32_token(align_tok, &align))
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid stack_alloc operands");
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_STACK_ALLOC);
        if (!ins)
            return false;
        ins->data.stack_alloc.size_bytes = size;
        ins->data.stack_alloc.alignment = align;
        return true;
    }

    if (strcmp(mnemonic, "label") == 0)
    {
        const char *name_tok = strtok(NULL, " \t");
        if (!name_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "label requires a name");
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_LABEL);
        if (!ins)
            return false;
        ins->data.label.name = duplicate_token(name_tok);
        return true;
    }

    if (strcmp(mnemonic, "jump") == 0)
    {
        const char *target = strtok(NULL, " \t");
        if (!target)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "jump requires a label");
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_JUMP);
        if (!ins)
            return false;
        ins->data.jump.target = duplicate_token(target);
        return true;
    }

    if (strcmp(mnemonic, "branch") == 0)
    {
        const char *true_tok = strtok(NULL, " \t");
        const char *false_tok = strtok(NULL, " \t");
        if (!true_tok || !false_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "branch requires <true> <false> labels");
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_BRANCH);
        if (!ins)
            return false;
        ins->data.branch.true_target = duplicate_token(true_tok);
        ins->data.branch.false_target = duplicate_token(false_tok);
        return true;
    }

    if (strcmp(mnemonic, "call_indirect") == 0)
    {
        const char *ret_type = strtok(NULL, " \t");
        const char *args_tok = strtok(NULL, " \t");
        const char *flag_tok = strtok(NULL, " \t");
        if (!ret_type || !args_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "call_indirect requires <ret> (<args>)");
            return false;
        }
        bool is_varargs = false;
        if (flag_tok)
        {
            if (strcmp(flag_tok, "varargs") == 0)
            {
                is_varargs = true;
                if (strtok(NULL, " \t"))
                {
                    loader_diag(st, CC_DIAG_ERROR, st->line, "unexpected tokens after call_indirect varargs flag");
                    return false;
                }
            }
            else
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "unexpected token '%s' for call_indirect", flag_tok);
                return false;
            }
        }
        CCValueType ret_ty = parse_type_token(ret_type);
        if (ret_ty == CC_TYPE_INVALID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid return type '%s'", ret_type);
            return false;
        }
        CCValueType *arg_types = NULL;
        size_t arg_count = 0;
        if (!parse_type_list(st, args_tok, &arg_types, &arg_count))
            return false;
        ins = append_instruction(st, fn, CC_INSTR_CALL_INDIRECT);
        if (!ins)
        {
            free(arg_types);
            return false;
        }
        ins->data.call.symbol = NULL;
        ins->data.call.return_type = ret_ty;
        ins->data.call.arg_types = arg_types;
        ins->data.call.arg_count = arg_count;
        ins->data.call.is_varargs = is_varargs;
        return true;
    }

    if (strcmp(mnemonic, "call") == 0)
    {
        const char *symbol = strtok(NULL, " \t");
        const char *ret_type = strtok(NULL, " \t");
        const char *args_list = strtok(NULL, "");
        if (!symbol || !ret_type || !args_list)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "call requires <symbol> <ret> (<args>)");
            return false;
        }
        while (*args_list && isspace((unsigned char)*args_list))
            ++args_list;
        bool is_varargs = false;
        size_t args_len = strlen(args_list);
        char *args_copy = (char *)malloc(args_len + 1);
        if (!args_copy)
            return false;
        memcpy(args_copy, args_list, args_len + 1);
        char *end = args_copy + args_len;
        while (end > args_copy && isspace((unsigned char)end[-1]))
            --end;
        *end = '\0';
        const char *varargs_kw = "varargs";
        size_t varargs_len = strlen(varargs_kw);
        if ((size_t)(end - args_copy) >= varargs_len)
        {
            char *tail = end - varargs_len;
            if (strcmp(tail, varargs_kw) == 0)
            {
                char *scan = tail;
                while (scan > args_copy && isspace((unsigned char)scan[-1]))
                    --scan;
                *scan = '\0';
                is_varargs = true;
            }
        }
        CCValueType ret_ty = parse_type_token(ret_type);
        if (ret_ty == CC_TYPE_INVALID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid return type '%s'", ret_type);
            free(args_copy);
            return false;
        }
        CCValueType *arg_types = NULL;
        size_t arg_count = 0;
        if (!parse_type_list(st, args_copy, &arg_types, &arg_count))
        {
            free(args_copy);
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_CALL);
        if (!ins)
        {
            free(arg_types);
            free(args_copy);
            return false;
        }
        ins->data.call.symbol = duplicate_token(symbol);
        ins->data.call.return_type = ret_ty;
        ins->data.call.arg_types = arg_types;
        ins->data.call.arg_count = arg_count;
        ins->data.call.is_varargs = is_varargs;
        free(args_copy);
        return true;
    }

    if (strcmp(mnemonic, "drop") == 0)
    {
        const char *type_tok = strtok(NULL, " \t");
        if (!type_tok)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "drop requires <type>");
            return false;
        }
        CCValueType ty = parse_type_token(type_tok);
        if (ty == CC_TYPE_INVALID || ty == CC_TYPE_VOID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid drop type '%s'", type_tok);
            return false;
        }
        ins = append_instruction(st, fn, CC_INSTR_DROP);
        if (!ins)
            return false;
        ins->data.drop.type = ty;
        return true;
    }

    if (strcmp(mnemonic, "ret") == 0)
    {
        const char *mode = strtok(NULL, " \t");
        ins = append_instruction(st, fn, CC_INSTR_RET);
        if (!ins)
            return false;
        bool has_value = fn->return_type != CC_TYPE_VOID;
        if (mode)
        {
            if (strcmp(mode, "void") == 0)
            {
                if (fn->return_type != CC_TYPE_VOID)
                {
                    loader_diag(st, CC_DIAG_ERROR, st->line, "ret void used in non-void function");
                    return false;
                }
                has_value = false;
            }
            else
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "unexpected operand '%s' for ret", mode);
                return false;
            }
        }
        ins->data.ret.has_value = has_value;
        return true;
    }

    if (strcmp(mnemonic, "comment") == 0)
    {
        const char *text = strtok(NULL, "");
        if (!text)
            text = "";
        ins = append_instruction(st, fn, CC_INSTR_COMMENT);
        if (!ins)
            return false;
        ins->data.comment.text = duplicate_token(text);
        return true;
    }

    loader_diag(st, CC_DIAG_ERROR, st->line, "unknown instruction '%s'", mnemonic);
    return false;
}

bool cc_load_file(const char *path, CCModule *module, CCDiagnosticSink *sink)
{
    if (!path || !module)
        return false;

    FILE *file = fopen(path, "rb");
    if (!file)
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "failed to open %s", path);
        return false;
    }

    // Read the entire file into memory
    if (fseek(file, 0, SEEK_END) != 0)
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "failed to seek %s", path);
        fclose(file);
        return false;
    }
    long file_size = ftell(file);
    if (file_size < 0)
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "failed to ftell %s", path);
        fclose(file);
        return false;
    }
    rewind(file);
    char *file_buf = (char *)malloc((size_t)file_size + 1);
    if (!file_buf)
    {
        if (sink)
            cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "out of memory reading %s", path);
        fclose(file);
        return false;
    }
    size_t read_bytes = fread(file_buf, 1, (size_t)file_size, file);
    file_buf[read_bytes] = '\0';
    fclose(file);

    // Check for CCBIN magic
    if (read_bytes >= 5 && memcmp(file_buf, "CCBIN", 5) == 0)
    {
        // Reopen as binary for cc_load_binary
        FILE *binfile = fopen(path, "rb");
        if (!binfile)
        {
            if (sink)
                cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "failed to reopen %s for binary load", path);
            free(file_buf);
            return false;
        }
        bool ok = cc_load_binary(binfile, path, module, sink);
        fclose(binfile);
        free(file_buf);
        return ok;
    }

    // Parse as text from buffer
    bool success = true;
    LoaderState st = {0};
    st.path = path;
    st.module = module;
    st.sink = sink;
    st.line = 0;
    st.string_counter = 0;

    cc_module_init(module, 0);

    // Split file_buf into lines (handle arbitrarily long lines)
    char *buf_ptr = file_buf;
    bool header_read = false;
    CCFunction *current_fn = NULL;
    bool params_set = false;
    bool locals_set = false;
    while (*buf_ptr)
    {
        char *line_start = buf_ptr;
        char *line_end = strchr(buf_ptr, '\n');
        if (line_end)
        {
            *line_end = '\0';
            buf_ptr = line_end + 1;
        }
        else
        {
            buf_ptr += strlen(buf_ptr);
        }
        ++st.line;
        // Remove trailing carriage return if present
        size_t linelen = strlen(line_start);
        if (linelen > 0 && line_start[linelen - 1] == '\r')
            line_start[linelen - 1] = '\0';
        char *raw_line = NULL;
        char *line = trim(line_start);

        if (st.reading_literal)
        {
            raw_line = strdup(line_start);
            if (!raw_line)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "out of memory reading literal");
                success = false;
                break;
            }
            if (strncmp(line, ".endliteral", 11) == 0 && line[11] == '\0')
            {
                if (!st.literal_fn || st.literal_fn->literal_count == 0)
                {
                    loader_diag(&st, CC_DIAG_ERROR, st.line, "empty literal block");
                    success = false;
                    free(raw_line);
                    break;
                }
                st.literal_fn->is_literal = true;
                st.literal_fn = NULL;
                st.reading_literal = 0;
                free(raw_line);
                continue;
            }
            if (strncmp(line, ".endfunc", 8) == 0 && line[8] == '\0')
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "missing .endliteral before .endfunc");
                success = false;
                free(raw_line);
                break;
            }
            if (!st.literal_fn)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, ".literal block without target function");
                success = false;
                free(raw_line);
                break;
            }
            if (!cc_function_literal_append(st.literal_fn, raw_line))
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "failed to record literal line");
                success = false;
                free(raw_line);
                break;
            }
            free(raw_line);
            continue;
        }

        if (*line == '\0' || *line == '#')
        {
            free(raw_line);
            continue;
        }

        if (!header_read)
        {
            if (strncmp(line, "ccbytecode", 10) != 0)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "missing ccbytecode header");
                success = false;
                free(raw_line);
                break;
            }
            char *version_str = line + 10;
            while (*version_str && isspace((unsigned char)*version_str))
                ++version_str;
            uint32_t version = 0;
            if (!parse_uint32_token(version_str, &version))
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "invalid ccbytecode version");
                success = false;
                break;
            }
            if (version < 2 || version > 3)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "unsupported ccbytecode version %u", version);
                success = false;
                break;
            }
            cc_module_init(module, version);
            header_read = true;
            continue;
        }

        if (strncmp(line, ".global", 7) == 0)
        {
            if (!parse_global(&st, line))
            {
                success = false;
                break;
            }
            continue;
        }

        if (strncmp(line, ".file", 5) == 0)
        {
            if (!parse_file_directive(&st, line + 5))
            {
                success = false;
                break;
            }
            continue;
        }

        if (strncmp(line, ".extern", 7) == 0)
        {
            if (!parse_extern(&st, line))
            {
                success = false;
                break;
            }
            continue;
        }

        if (strncmp(line, ".no-return", 10) == 0)
        {
            char *cursor = line + 10;
            while (*cursor && isspace((unsigned char)*cursor))
                ++cursor;
            if (*cursor == '\0')
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, ".no-return requires a symbol name");
                success = false;
                break;
            }
            char *name = cursor;
            while (*cursor && !isspace((unsigned char)*cursor))
                ++cursor;
            if (*cursor)
            {
                *cursor++ = '\0';
                while (*cursor && isspace((unsigned char)*cursor))
                    ++cursor;
                if (*cursor != '\0')
                {
                    loader_diag(&st, CC_DIAG_ERROR, st.line, "unexpected tokens after .no-return symbol");
                    success = false;
                    break;
                }
            }
            if (!mark_symbol_noreturn(&st, name))
            {
                if (!pending_noreturn_add(&st, name))
                {
                    loader_diag(&st, CC_DIAG_ERROR, st.line, "failed to record .no-return for '%s'", name);
                    success = false;
                    break;
                }
            }
            continue;
        }

        if (strncmp(line, ".preserve", 9) == 0)
        {
            char *cursor = line + 9;
            while (*cursor && isspace((unsigned char)*cursor))
                ++cursor;
            if (*cursor == '\0')
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, ".preserve requires a function name");
                success = false;
                break;
            }
            char *name = cursor;
            while (*cursor && !isspace((unsigned char)*cursor))
                ++cursor;
            if (*cursor)
            {
                *cursor++ = '\0';
                while (*cursor && isspace((unsigned char)*cursor))
                    ++cursor;
                if (*cursor != '\0')
                {
                    loader_diag(&st, CC_DIAG_ERROR, st.line, "unexpected tokens after .preserve symbol");
                    success = false;
                    break;
                }
            }
            if (!mark_function_preserve(&st, name))
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "unknown function '%s' in .preserve", name);
                success = false;
                break;
            }
            continue;
        }

        if (strncmp(line, ".force-inline-literal", 21) == 0)
        {
            char *cursor = line + 21;
            while (*cursor && isspace((unsigned char)*cursor))
                ++cursor;
            if (*cursor == '\0')
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, ".force-inline-literal requires a function name");
                success = false;
                break;
            }
            char *name = cursor;
            while (*cursor && !isspace((unsigned char)*cursor))
                ++cursor;
            if (*cursor)
            {
                *cursor++ = '\0';
                while (*cursor && isspace((unsigned char)*cursor))
                    ++cursor;
                if (*cursor != '\0')
                {
                    loader_diag(&st, CC_DIAG_ERROR, st.line, "unexpected tokens after .force-inline-literal symbol");
                    success = false;
                    break;
                }
            }
            if (!mark_function_force_inline_literal(&st, name))
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "unknown function '%s' in .force-inline-literal", name);
                success = false;
                break;
            }
            continue;
        }

        if (strncmp(line, ".func", 5) == 0)
        {
            if (current_fn)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "nested .func not allowed");
                success = false;
                break;
            }

            char *cursor = line + 5;
            while (*cursor && isspace((unsigned char)*cursor))
                ++cursor;

            char *name = cursor;
            while (*cursor && !isspace((unsigned char)*cursor))
                ++cursor;
            if (*cursor)
                *cursor++ = '\0';

            if (!*name)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "missing function name");
                success = false;
                break;
            }

            if (cc_module_find_extern(st.module, name))
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "function '%s' conflicts with extern", name);
                success = false;
                break;
            }

            current_fn = cc_module_add_function(module, name);
            if (!current_fn)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "failed to create function '%s'", name);
                success = false;
                break;
            }

            st.current_debug_file = 0;
            st.current_debug_line = 0;
            st.current_debug_column = 0;

            current_fn->return_type = CC_TYPE_VOID;
            current_fn->param_count = 0;
            current_fn->local_count = 0;
            params_set = false;
            locals_set = false;

            while (*cursor)
            {
                while (*cursor && isspace((unsigned char)*cursor))
                    ++cursor;
                if (*cursor == '\0')
                    break;

                char *token = cursor;
                while (*cursor && !isspace((unsigned char)*cursor))
                    ++cursor;
                if (*cursor)
                    *cursor++ = '\0';

                if (strncmp(token, "ret=", 4) == 0)
                {
                    CCValueType ret_ty = parse_type_token(token + 4);
                    if (ret_ty == CC_TYPE_INVALID)
                    {
                        loader_diag(&st, CC_DIAG_ERROR, st.line, "invalid return type '%s'", token + 4);
                        success = false;
                        break;
                    }
                    current_fn->return_type = ret_ty;
                }
                else if (strncmp(token, "params=", 7) == 0)
                {
                    uint32_t count = 0;
                    if (!parse_uint32_token(token + 7, &count))
                    {
                        loader_diag(&st, CC_DIAG_ERROR, st.line, "invalid params count '%s'", token + 7);
                        success = false;
                        break;
                    }
                    current_fn->param_count = count;
                }
                else if (strncmp(token, "locals=", 7) == 0)
                {
                    uint32_t count = 0;
                    if (!parse_uint32_token(token + 7, &count))
                    {
                        loader_diag(&st, CC_DIAG_ERROR, st.line, "invalid locals count '%s'", token + 7);
                        success = false;
                        break;
                    }
                    current_fn->local_count = count;
                }
                else if (strcmp(token, "varargs") == 0)
                {
                    current_fn->is_varargs = true;
                }
                else if (strcmp(token, "no-return") == 0 || strcmp(token, "noreturn") == 0)
                {
                    current_fn->is_noreturn = true;
                }
                else if (strcmp(token, "preserve") == 0)
                {
                    current_fn->is_preserve = true;
                }
                else if (strcmp(token, "hidden") == 0)
                {
                    current_fn->is_hidden = true;
                }
                else if (strcmp(token, "force-inline-literal") == 0)
                {
                    current_fn->force_inline_literal = true;
                }
                else if (strncmp(token, "section=", 8) == 0)
                {
                    char *section_name = NULL;
                    if (!parse_string_literal_to_cstring(&st, token + 8, &section_name, NULL, "section attribute"))
                    {
                        success = false;
                        break;
                    }
                    free(current_fn->section);
                    current_fn->section = section_name;
                }
                else
                {
                    loader_diag(&st, CC_DIAG_WARNING, st.line, "unknown function attribute '%s'", token);
                }
            }

            if (!success)
                break;

            // Validate that varargs functions have at least one explicit parameter
            if (current_fn->is_varargs && current_fn->param_count == 0)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line,
                            "variadic function '%s' must have at least one explicit parameter before '...'",
                            current_fn->name);
                success = false;
                break;
            }

            resolve_pending_noreturn(&st, name);

            continue;
        }

        if (strncmp(line, ".endfunc", 8) == 0)
        {
            if (!current_fn)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, ".endfunc without .func");
                success = false;
                break;
            }

            if (!ensure_function_metadata(&st, current_fn, params_set || current_fn->param_count == 0,
                                          locals_set || current_fn->local_count == 0))
            {
                success = false;
                break;
            }

            current_fn = NULL;
            st.current_debug_file = 0;
            st.current_debug_line = 0;
            st.current_debug_column = 0;
            continue;
        }

        if (!current_fn)
        {
            loader_diag(&st, CC_DIAG_ERROR, st.line, "statement outside of function");
            success = false;
            break;
        }

        if (strncmp(line, ".loc", 4) == 0 && (line[4] == ' ' || line[4] == '\t'))
        {
            if (!parse_loc_directive(&st, line + 4))
            {
                success = false;
                break;
            }
            continue;
        }

        if (strncmp(line, ".params", 7) == 0)
        {
            if (!parse_params_or_locals(&st, current_fn, line + 7, true))
            {
                success = false;
                break;
            }
            params_set = true;
            continue;
        }

        if (strncmp(line, ".locals", 7) == 0)
        {
            if (!parse_params_or_locals(&st, current_fn, line + 7, false))
            {
                success = false;
                break;
            }
            locals_set = true;
            continue;
        }

        if (strncmp(line, ".literal", 8) == 0 && line[8] == '\0')
        {
            if (current_fn->is_literal || current_fn->literal_count > 0 || st.reading_literal)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "duplicate .literal block");
                success = false;
                break;
            }
            st.reading_literal = 1;
            st.literal_fn = current_fn;
            continue;
        }

        if (!params_set && current_fn->param_count > 0)
        {
            loader_diag(&st, CC_DIAG_ERROR, st.line, "encountered instruction before .params");
            success = false;
            break;
        }
        if (!locals_set && current_fn->local_count > 0)
        {
            loader_diag(&st, CC_DIAG_ERROR, st.line, "encountered instruction before .locals");
            success = false;
            break;
        }

        if (current_fn->is_literal)
        {
            loader_diag(&st, CC_DIAG_ERROR, st.line, "literal functions cannot contain bytecode instructions");
            success = false;
            break;
        }

        if (!parse_instruction(&st, current_fn, line))
        {
            success = false;
            break;
        }
    }

    if (success)
    {
        if (!header_read)
        {
            loader_diag(&st, CC_DIAG_ERROR, 0, "missing ccbytecode header");
            success = false;
        }
        else if (current_fn)
        {
            loader_diag(&st, CC_DIAG_ERROR, st.line, "unterminated function '%s'", current_fn->name);
            success = false;
        }
        else if (st.reading_literal)
        {
            loader_diag(&st, CC_DIAG_ERROR, st.line, "unterminated .literal block");
            success = false;
        }
    }

    if (success && !resolve_pending_addr_globals(&st))
        success = false;

    free(file_buf);

    pending_noreturn_destroy(&st);
    pending_addr_globals_destroy(&st);

    if (!success)
        cc_module_free(module);

    return success;
}
