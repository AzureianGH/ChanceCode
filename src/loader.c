#include "cc/loader.h"

#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct LoaderState {
    const char *path;
    CCModule *module;
    CCDiagnosticSink *sink;
    size_t line;
    size_t string_counter;
    char **pending_noreturn;
    size_t pending_noreturn_count;
    size_t pending_noreturn_capacity;
} LoaderState;

static CCFunction *find_function(CCModule *module, const char *name);
static char *duplicate_token(const char *token);

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

static void resolve_pending_noreturn(LoaderState *st, const char *name)
{
    if (!st || !name)
        return;
    if (!st->pending_noreturn || st->pending_noreturn_count == 0)
        return;
    for (size_t i = 0; i < st->pending_noreturn_count; ++i)
    {
        if (strcmp(st->pending_noreturn[i], name) == 0)
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

static bool parse_string_literal(const char *input, char **out_data, size_t *out_len, const char **out_end)
{
    if (!input || !out_data || !out_len || input[0] != '"')
        return false;

    const char *src = input + 1;
    size_t capacity = 16;
    size_t length = 0;
    char *buffer = (char *)malloc(capacity);
    if (!buffer)
        return false;

    while (*src && *src != '"')
    {
        char ch = *src++;
        if (ch == '\\')
        {
            char esc = *src++;
            if (!esc)
            {
                free(buffer);
                return false;
            }
            switch (esc)
            {
            case 'n': ch = '\n'; break;
            case 'r': ch = '\r'; break;
            case 't': ch = '\t'; break;
            case '\\': ch = '\\'; break;
            case '"': ch = '"'; break;
            case '0': ch = '\0'; break;
            case 'x':
            {
                if (!isxdigit((unsigned char)src[0]) || !isxdigit((unsigned char)src[1]))
                {
                    free(buffer);
                    return false;
                }
                char hex[3] = { src[0], src[1], '\0' };
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
        free(buffer);
        return false;
    }

    if (out_end)
        *out_end = src + 1;

    *out_data = buffer;
    *out_len = length;
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
    reset_global_init(&global->init);

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
                continue;
            }
            else
            {
                const char *end = value;
                while (*end && !isspace((unsigned char)*end))
                    ++end;
                char saved = *end;
                if (*end)
                    *((char *)end) = '\0';

                if (strcmp(value, "null") == 0)
                {
                    reset_global_init(&global->init);
                    global->init.kind = CC_GLOBAL_INIT_INT;
                    global->init.payload.i64 = 0;
                }
                else
                {
                    uint64_t num = 0;
                    if (!parse_uint64_token(value, &num))
                    {
                        loader_diag(st, CC_DIAG_ERROR, st->line, "invalid initializer '%s'", value);
                        if (*end)
                            *((char *)end) = saved;
                        return false;
                    }
                    reset_global_init(&global->init);
                    global->init.kind = CC_GLOBAL_INIT_INT;
                    global->init.payload.u64 = num;
                }

                if (*end)
                    *((char *)end) = saved;
                cursor = (char *)end;
                continue;
            }
        }

        const char *end = cursor;
        while (*end && !isspace((unsigned char)*end))
            ++end;
        char saved = *end;
        if (*end)
            *((char *)end) = '\0';

        if (strncmp(cursor, "type=", 5) == 0)
        {
            CCValueType ty = parse_type_token(cursor + 5);
            if (ty == CC_TYPE_INVALID)
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "invalid global type '%s'", cursor + 5);
                if (*end)
                    *((char *)end) = saved;
                return false;
            }
            global->type = ty;
        }
        else if (strncmp(cursor, "align=", 6) == 0)
        {
            uint32_t align = 0;
            if (!parse_uint32_token(cursor + 6, &align))
            {
                loader_diag(st, CC_DIAG_ERROR, st->line, "invalid alignment '%s'", cursor + 6);
                if (*end)
                    *((char *)end) = saved;
                return false;
            }
            global->alignment = align;
        }
        else if (strcmp(cursor, "const") == 0)
        {
            global->is_const = true;
        }
        else
        {
            loader_diag(st, CC_DIAG_WARNING, st->line, "unknown global attribute '%s'", cursor);
        }

        if (*end)
            *((char *)end) = saved;
        cursor = (char *)end;
    }

    if (global->type == CC_TYPE_INVALID)
    {
        loader_diag(st, CC_DIAG_ERROR, st->line, "global '%s' missing type= attribute", global->name);
        return false;
    }

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
        ins = cc_function_append_instruction(fn, CC_INSTR_CONST, st->line);
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
        ins = cc_function_append_instruction(fn, CC_INSTR_CONST_STRING, st->line);
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
        if (index >= fn->param_count)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "parameter index %u out of range", index);
            return false;
        }
        ins = cc_function_append_instruction(fn, strcmp(mnemonic, "load_param") == 0 ? CC_INSTR_LOAD_PARAM : CC_INSTR_ADDR_PARAM, st->line);
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
        ins = cc_function_append_instruction(fn, kind, st->line);
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
        CCGlobal *global = find_global(st->module, symbol);
        if (!global)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "unknown global '%s'", symbol);
            return false;
        }
        CCInstrKind kind = CC_INSTR_LOAD_GLOBAL;
        if (strcmp(mnemonic, "store_global") == 0)
            kind = CC_INSTR_STORE_GLOBAL;
        else if (strcmp(mnemonic, "addr_global") == 0)
            kind = CC_INSTR_ADDR_GLOBAL;
        ins = cc_function_append_instruction(fn, kind, st->line);
        if (!ins)
            return false;
        ins->data.global.symbol = duplicate_token(symbol);
        ins->data.global.type = (kind == CC_INSTR_ADDR_GLOBAL) ? CC_TYPE_PTR : global->type;
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
        ins = cc_function_append_instruction(fn, kind, st->line);
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
        ins = cc_function_append_instruction(fn, CC_INSTR_BINOP, st->line);
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
        ins = cc_function_append_instruction(fn, CC_INSTR_UNOP, st->line);
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
        ins = cc_function_append_instruction(fn, CC_INSTR_COMPARE, st->line);
        if (!ins)
            return false;
        ins->data.compare.op = cond;
        ins->data.compare.type = ty;
        ins->data.compare.is_unsigned = is_unsigned;
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
        ins = cc_function_append_instruction(fn, CC_INSTR_CONVERT, st->line);
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
        ins = cc_function_append_instruction(fn, CC_INSTR_STACK_ALLOC, st->line);
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
        ins = cc_function_append_instruction(fn, CC_INSTR_LABEL, st->line);
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
        ins = cc_function_append_instruction(fn, CC_INSTR_JUMP, st->line);
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
        ins = cc_function_append_instruction(fn, CC_INSTR_BRANCH, st->line);
        if (!ins)
            return false;
        ins->data.branch.true_target = duplicate_token(true_tok);
        ins->data.branch.false_target = duplicate_token(false_tok);
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
        CCValueType ret_ty = parse_type_token(ret_type);
        if (ret_ty == CC_TYPE_INVALID)
        {
            loader_diag(st, CC_DIAG_ERROR, st->line, "invalid return type '%s'", ret_type);
            return false;
        }
        CCValueType *arg_types = NULL;
        size_t arg_count = 0;
        if (!parse_type_list(st, args_list, &arg_types, &arg_count))
            return false;
        ins = cc_function_append_instruction(fn, CC_INSTR_CALL, st->line);
        if (!ins)
        {
            free(arg_types);
            return false;
        }
        ins->data.call.symbol = duplicate_token(symbol);
        ins->data.call.return_type = ret_ty;
        ins->data.call.arg_types = arg_types;
        ins->data.call.arg_count = arg_count;
        ins->data.call.is_tail_call = false;
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
        ins = cc_function_append_instruction(fn, CC_INSTR_DROP, st->line);
        if (!ins)
            return false;
        ins->data.drop.type = ty;
        return true;
    }

    if (strcmp(mnemonic, "ret") == 0)
    {
        const char *mode = strtok(NULL, " \t");
        ins = cc_function_append_instruction(fn, CC_INSTR_RET, st->line);
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
        ins = cc_function_append_instruction(fn, CC_INSTR_COMMENT, st->line);
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

    bool success = true;
    LoaderState st;
    st.path = path;
    st.module = module;
    st.sink = sink;
    st.line = 0;
    st.string_counter = 0;

    cc_module_init(module, 0);

    char linebuf[2048];
    bool header_read = false;
    CCFunction *current_fn = NULL;
    bool params_set = false;
    bool locals_set = false;

    while (fgets(linebuf, sizeof(linebuf), file))
    {
        ++st.line;
        char *line = trim(linebuf);
        if (*line == '\0' || *line == '#')
            continue;

        if (!header_read)
        {
            if (strncmp(line, "ccbytecode", 10) != 0)
            {
                loader_diag(&st, CC_DIAG_ERROR, st.line, "missing ccbytecode header");
                success = false;
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
            if (version != 2)
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
                else
                {
                    loader_diag(&st, CC_DIAG_WARNING, st.line, "unknown function attribute '%s'", token);
                }
            }

            if (!success)
                break;

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
            continue;
        }

        if (!current_fn)
        {
            loader_diag(&st, CC_DIAG_ERROR, st.line, "statement outside of function");
            success = false;
            break;
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
    }

    fclose(file);

    if (!success)
        cc_module_free(module);

    return success;
}
