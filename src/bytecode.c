#include "cc/bytecode.h"
#include "cc/diagnostics.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *cc_strdup(const char *src)
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

static void cc_global_init_reset(CCGlobalInit *init)
{
    if (!init)
        return;
    switch (init->kind)
    {
    case CC_GLOBAL_INIT_STRING:
        free(init->payload.string.data);
        init->payload.string.data = NULL;
        init->payload.string.length = 0;
        break;
    case CC_GLOBAL_INIT_BYTES:
        free(init->payload.bytes.data);
        init->payload.bytes.data = NULL;
        init->payload.bytes.size = 0;
        break;
    case CC_GLOBAL_INIT_PTRS:
        if (init->payload.ptrs.symbols)
        {
            for (size_t i = 0; i < init->payload.ptrs.count; ++i)
                free(init->payload.ptrs.symbols[i]);
            free(init->payload.ptrs.symbols);
        }
        init->payload.ptrs.symbols = NULL;
        init->payload.ptrs.count = 0;
        break;
    default:
        break;
    }
    init->kind = CC_GLOBAL_INIT_NONE;
}

static void cc_instruction_free(CCInstruction *ins)
{
    if (!ins)
        return;

    switch (ins->kind)
    {
    case CC_INSTR_CONST_STRING:
        free(ins->data.const_string.bytes);
        ins->data.const_string.bytes = NULL;
        free(ins->data.const_string.label_hint);
        ins->data.const_string.label_hint = NULL;
        break;
    case CC_INSTR_LOAD_GLOBAL:
    case CC_INSTR_STORE_GLOBAL:
    case CC_INSTR_ADDR_GLOBAL:
        free(ins->data.global.symbol);
        ins->data.global.symbol = NULL;
        break;
    case CC_INSTR_LABEL:
        free(ins->data.label.name);
        ins->data.label.name = NULL;
        break;
    case CC_INSTR_JUMP:
        free(ins->data.jump.target);
        ins->data.jump.target = NULL;
        break;
    case CC_INSTR_BRANCH:
        free(ins->data.branch.true_target);
        free(ins->data.branch.false_target);
        ins->data.branch.true_target = NULL;
        ins->data.branch.false_target = NULL;
        break;
    case CC_INSTR_CALL:
        free(ins->data.call.symbol);
        ins->data.call.symbol = NULL;
        free(ins->data.call.arg_types);
        ins->data.call.arg_types = NULL;
        ins->data.call.arg_count = 0;
        break;
    case CC_INSTR_COMMENT:
        free(ins->data.comment.text);
        ins->data.comment.text = NULL;
        break;
    default:
        break;
    }
    memset(&ins->data, 0, sizeof(ins->data));
}

static void cc_function_free(CCFunction *fn)
{
    if (!fn)
        return;

    free(fn->name);
    fn->name = NULL;

    free(fn->section);
    fn->section = NULL;

    free(fn->param_types);
    fn->param_types = NULL;
    fn->param_count = 0;

    free(fn->local_types);
    fn->local_types = NULL;
    fn->local_count = 0;

    if (fn->instructions)
    {
        for (size_t i = 0; i < fn->instruction_count; ++i)
            cc_instruction_free(&fn->instructions[i]);
        free(fn->instructions);
        fn->instructions = NULL;
    }
    fn->instruction_count = 0;
    fn->instruction_capacity = 0;
    fn->return_type = CC_TYPE_VOID;
    fn->is_varargs = false;
    fn->is_noreturn = false;
    fn->is_literal = false;
    fn->force_inline_literal = false;
    if (fn->literal_lines)
    {
        for (size_t i = 0; i < fn->literal_count; ++i)
            free(fn->literal_lines[i]);
        free(fn->literal_lines);
    }
    fn->literal_lines = NULL;
    fn->literal_count = 0;
}

static void cc_global_free(CCGlobal *global)
{
    if (!global)
        return;
    free(global->name);
    global->name = NULL;
    free(global->section);
    global->section = NULL;
    cc_global_init_reset(&global->init);
    global->type = CC_TYPE_INVALID;
    global->is_const = false;
    global->is_extern = false;
    global->is_hidden = false;
    global->alignment = 0;
}

void cc_module_init(CCModule *module, uint32_t version)
{
    if (!module)
        return;

    module->version = version;
    module->globals = NULL;
    module->global_count = 0;
    module->global_capacity = 0;
    module->externs = NULL;
    module->extern_count = 0;
    module->extern_capacity = 0;
    module->functions = NULL;
    module->function_count = 0;
    module->function_capacity = 0;
    module->debug_files = NULL;
    module->debug_file_count = 0;
    module->debug_file_capacity = 0;
}

void cc_module_free(CCModule *module)
{
    if (!module)
        return;

    if (module->globals)
    {
        for (size_t i = 0; i < module->global_count; ++i)
            cc_global_free(&module->globals[i]);
        free(module->globals);
    }

    if (module->externs)
    {
        for (size_t i = 0; i < module->extern_count; ++i)
        {
            free(module->externs[i].name);
            module->externs[i].name = NULL;
            free(module->externs[i].param_types);
            module->externs[i].param_types = NULL;
            module->externs[i].param_count = 0;
        }
        free(module->externs);
    }

    if (module->functions)
    {
        for (size_t i = 0; i < module->function_count; ++i)
            cc_function_free(&module->functions[i]);
        free(module->functions);
    }

    if (module->debug_files)
    {
        for (size_t i = 0; i < module->debug_file_count; ++i)
            free(module->debug_files[i]);
        free(module->debug_files);
    }

    memset(module, 0, sizeof(*module));
}

static bool cc_module_reserve_globals(CCModule *module, size_t desired)
{
    if (module->global_capacity >= desired)
        return true;

    size_t new_capacity = module->global_capacity ? module->global_capacity * 2 : 4;
    while (new_capacity < desired)
        new_capacity *= 2;

    CCGlobal *new_data = (CCGlobal *)realloc(module->globals, new_capacity * sizeof(CCGlobal));
    if (!new_data)
        return false;

    for (size_t i = module->global_capacity; i < new_capacity; ++i)
        memset(&new_data[i], 0, sizeof(CCGlobal));

    module->globals = new_data;
    module->global_capacity = new_capacity;
    return true;
}

static bool cc_module_reserve_externs(CCModule *module, size_t desired)
{
    if (module->extern_capacity >= desired)
        return true;

    size_t new_capacity = module->extern_capacity ? module->extern_capacity * 2 : 4;
    while (new_capacity < desired)
        new_capacity *= 2;

    CCExtern *new_data = (CCExtern *)realloc(module->externs, new_capacity * sizeof(CCExtern));
    if (!new_data)
        return false;

    for (size_t i = module->extern_capacity; i < new_capacity; ++i)
        memset(&new_data[i], 0, sizeof(CCExtern));

    module->externs = new_data;
    module->extern_capacity = new_capacity;
    return true;
}

static bool cc_module_reserve_functions(CCModule *module, size_t desired)
{
    if (module->function_capacity >= desired)
        return true;

    size_t new_capacity = module->function_capacity ? module->function_capacity * 2 : 4;
    while (new_capacity < desired)
        new_capacity *= 2;

    CCFunction *new_data = (CCFunction *)realloc(module->functions, new_capacity * sizeof(CCFunction));
    if (!new_data)
        return false;

    for (size_t i = module->function_capacity; i < new_capacity; ++i)
        memset(&new_data[i], 0, sizeof(CCFunction));

    module->functions = new_data;
    module->function_capacity = new_capacity;
    return true;
}

static bool cc_module_reserve_debug_files(CCModule *module, size_t desired)
{
    if (module->debug_file_capacity >= desired)
        return true;

    size_t new_capacity = module->debug_file_capacity ? module->debug_file_capacity * 2 : 4;
    while (new_capacity < desired)
        new_capacity *= 2;

    char **new_files = (char **)realloc(module->debug_files, new_capacity * sizeof(char *));
    if (!new_files)
        return false;

    for (size_t i = module->debug_file_capacity; i < new_capacity; ++i)
        new_files[i] = NULL;

    module->debug_files = new_files;
    module->debug_file_capacity = new_capacity;
    return true;
}

static bool cc_function_reserve_instructions(CCFunction *function, size_t desired)
{
    if (function->instruction_capacity >= desired)
        return true;

    size_t new_capacity = function->instruction_capacity ? function->instruction_capacity * 2 : 16;
    while (new_capacity < desired)
        new_capacity *= 2;

    CCInstruction *new_data = (CCInstruction *)realloc(function->instructions, new_capacity * sizeof(CCInstruction));
    if (!new_data)
        return false;

    for (size_t i = function->instruction_capacity; i < new_capacity; ++i)
        memset(&new_data[i], 0, sizeof(CCInstruction));

    function->instructions = new_data;
    function->instruction_capacity = new_capacity;
    return true;
}

CCGlobal *cc_module_add_global(CCModule *module, const char *name)
{
    if (!module)
        return NULL;
    if (!cc_module_reserve_globals(module, module->global_count + 1))
        return NULL;

    CCGlobal *global = &module->globals[module->global_count++];
    memset(global, 0, sizeof(*global));
    global->name = cc_strdup(name);
    global->type = CC_TYPE_INVALID;
    global->size = 0;
    global->alignment = 0;
    global->is_const = false;
    global->is_extern = false;
    global->is_hidden = false;
    global->init.kind = CC_GLOBAL_INIT_NONE;
    global->section = NULL;
    return global;
}

CCExtern *cc_module_add_extern(CCModule *module, const char *name)
{
    if (!module)
        return NULL;
    if (!cc_module_reserve_externs(module, module->extern_count + 1))
        return NULL;

    CCExtern *ext = &module->externs[module->extern_count++];
    memset(ext, 0, sizeof(*ext));
    ext->name = cc_strdup(name);
    ext->return_type = CC_TYPE_VOID;
    ext->is_varargs = false;
    ext->is_noreturn = false;
    return ext;
}

CCExtern *cc_module_find_extern(CCModule *module, const char *name)
{
    if (!module || !name)
        return NULL;
    for (size_t i = 0; i < module->extern_count; ++i)
    {
        if (module->externs[i].name && strcmp(module->externs[i].name, name) == 0)
            return &module->externs[i];
    }
    return NULL;
}

const CCExtern *cc_module_find_extern_const(const CCModule *module, const char *name)
{
    if (!module || !name)
        return NULL;
    for (size_t i = 0; i < module->extern_count; ++i)
    {
        if (module->externs[i].name && strcmp(module->externs[i].name, name) == 0)
            return &module->externs[i];
    }
    return NULL;
}

CCFunction *cc_module_add_function(CCModule *module, const char *name)
{
    if (!module)
        return NULL;
    if (!cc_module_reserve_functions(module, module->function_count + 1))
        return NULL;

    CCFunction *fn = &module->functions[module->function_count++];
    memset(fn, 0, sizeof(*fn));
    fn->name = cc_strdup(name);
    fn->return_type = CC_TYPE_VOID;
    fn->is_varargs = false;
    fn->is_noreturn = false;
    fn->is_literal = false;
    fn->literal_lines = NULL;
    fn->literal_count = 0;
    fn->section = NULL;
    return fn;
}

bool cc_module_set_debug_file(CCModule *module, uint32_t id, const char *path)
{
    if (!module || id == 0 || !path || path[0] == '\0')
        return false;

    size_t index = (size_t)id - 1;
    if (!cc_module_reserve_debug_files(module, index + 1))
        return false;

    char *copy = cc_strdup(path);
    if (!copy)
        return false;

    if (module->debug_files[index])
        free(module->debug_files[index]);
    module->debug_files[index] = copy;
    if (module->debug_file_count <= index)
        module->debug_file_count = index + 1;
    return true;
}

const char *cc_module_get_debug_file(const CCModule *module, uint32_t id)
{
    if (!module || id == 0)
        return NULL;
    size_t index = (size_t)id - 1;
    if (index >= module->debug_file_count)
        return NULL;
    return module->debug_files ? module->debug_files[index] : NULL;
}

static void cc_instruction_strip_metadata(CCInstruction *ins)
{
    if (!ins)
        return;
    ins->line = 0;
    ins->debug_file = 0;
    ins->debug_line = 0;
    ins->debug_column = 0;
    if (ins->kind == CC_INSTR_CONST_STRING && ins->data.const_string.label_hint)
    {
        free(ins->data.const_string.label_hint);
        ins->data.const_string.label_hint = NULL;
    }
}

void cc_module_strip_metadata(CCModule *module)
{
    if (!module)
        return;

    if (module->debug_files)
    {
        for (size_t i = 0; i < module->debug_file_count; ++i)
        {
            free(module->debug_files[i]);
            module->debug_files[i] = NULL;
        }
        free(module->debug_files);
    }
    module->debug_files = NULL;
    module->debug_file_count = 0;
    module->debug_file_capacity = 0;

    for (size_t fi = 0; fi < module->function_count; ++fi)
    {
        CCFunction *fn = &module->functions[fi];
        if (!fn || !fn->instructions)
            continue;
        size_t write_index = 0;
        for (size_t ii = 0; ii < fn->instruction_count; ++ii)
        {
            CCInstruction *ins = &fn->instructions[ii];
            cc_instruction_strip_metadata(ins);
            if (ins->kind == CC_INSTR_COMMENT)
            {
                cc_instruction_free(ins);
                continue;
            }
            if (write_index != ii)
                memcpy(&fn->instructions[write_index], ins, sizeof(CCInstruction));
            write_index++;
        }
        fn->instruction_count = write_index;
    }
}

bool cc_function_set_param_types(CCFunction *function, const CCValueType *types, size_t count)
{
    if (!function)
        return false;

    CCValueType *copy = NULL;
    if (count > 0)
    {
        copy = (CCValueType *)malloc(sizeof(CCValueType) * count);
        if (!copy)
            return false;
        memcpy(copy, types, sizeof(CCValueType) * count);
    }

    free(function->param_types);
    function->param_types = copy;
    function->param_count = count;
    return true;
}

bool cc_function_set_local_types(CCFunction *function, const CCValueType *types, size_t count)
{
    if (!function)
        return false;

    CCValueType *copy = NULL;
    if (count > 0)
    {
        copy = (CCValueType *)malloc(sizeof(CCValueType) * count);
        if (!copy)
            return false;
        memcpy(copy, types, sizeof(CCValueType) * count);
    }

    free(function->local_types);
    function->local_types = copy;
    function->local_count = count;
    return true;
}

CCInstruction *cc_function_append_instruction(CCFunction *function, CCInstrKind kind, size_t line)
{
    if (!function)
        return NULL;
    if (!cc_function_reserve_instructions(function, function->instruction_count + 1))
        return NULL;

    CCInstruction *ins = &function->instructions[function->instruction_count++];
    memset(ins, 0, sizeof(*ins));
    ins->kind = kind;
    ins->line = line;
    return ins;
}

static size_t cc_integer_type_size(CCValueType type)
{
    switch (type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_I8:
    case CC_TYPE_U8:
        return 1;
    case CC_TYPE_I16:
    case CC_TYPE_U16:
        return 2;
    case CC_TYPE_I32:
    case CC_TYPE_U32:
        return 4;
    case CC_TYPE_I64:
    case CC_TYPE_U64:
    case CC_TYPE_PTR:
        return 8;
    default:
        return 0;
    }
}

size_t cc_value_type_size(CCValueType type)
{
    switch (type)
    {
    case CC_TYPE_F32:
        return 4;
    case CC_TYPE_F64:
        return 8;
    case CC_TYPE_VOID:
        return 0;
    default:
        return cc_integer_type_size(type);
    }
}

bool cc_value_type_is_float(CCValueType type)
{
    return type == CC_TYPE_F32 || type == CC_TYPE_F64;
}

bool cc_value_type_is_integer(CCValueType type)
{
    switch (type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_I8:
    case CC_TYPE_U8:
    case CC_TYPE_I16:
    case CC_TYPE_U16:
    case CC_TYPE_I32:
    case CC_TYPE_U32:
    case CC_TYPE_I64:
    case CC_TYPE_U64:
        return true;
    default:
        return false;
    }
}

bool cc_value_type_is_signed(CCValueType type)
{
    switch (type)
    {
    case CC_TYPE_I1:
    case CC_TYPE_I8:
    case CC_TYPE_I16:
    case CC_TYPE_I32:
    case CC_TYPE_I64:
        return true;
    default:
        return false;
    }
}

const char *cc_value_type_name(CCValueType type)
{
    switch (type)
    {
    case CC_TYPE_I1:
        return "i1";
    case CC_TYPE_I8:
        return "i8";
    case CC_TYPE_U8:
        return "u8";
    case CC_TYPE_I16:
        return "i16";
    case CC_TYPE_U16:
        return "u16";
    case CC_TYPE_I32:
        return "i32";
    case CC_TYPE_U32:
        return "u32";
    case CC_TYPE_I64:
        return "i64";
    case CC_TYPE_U64:
        return "u64";
    case CC_TYPE_F32:
        return "f32";
    case CC_TYPE_F64:
        return "f64";
    case CC_TYPE_PTR:
        return "ptr";
    case CC_TYPE_VOID:
        return "void";
    default:
        return "invalid";
    }
}

static unsigned long long cc_mask_for_bits(unsigned bits)
{
    if (bits == 0)
        return 0;
    if (bits >= 64)
        return ~0ULL;
    return (1ULL << bits) - 1ULL;
}

static long long cc_sign_extend_bits(unsigned long long value, unsigned bits)
{
    if (bits == 0 || bits >= 64)
        return (long long)value;
    unsigned long long mask = cc_mask_for_bits(bits);
    unsigned long long sign_bit = 1ULL << (bits - 1);
    value &= mask;
    if (value & sign_bit)
        return (long long)(value | (~mask));
    return (long long)value;
}

static unsigned cc_value_type_bit_width(CCValueType type)
{
    size_t bytes = cc_value_type_size(type);
    if (bytes == 0)
        return 0;
    return (unsigned)(bytes * 8);
}

static bool cc_constant_truthy(const CCInstruction *ins)
{
    if (!ins || ins->kind != CC_INSTR_CONST)
        return false;

    CCValueType type = ins->data.constant.type;
    if (cc_value_type_is_float(type))
    {
        double value = (type == CC_TYPE_F32) ? (double)ins->data.constant.value.f32 : ins->data.constant.value.f64;
        return value != 0.0;
    }

    if (type == CC_TYPE_PTR)
        return !ins->data.constant.is_null && ins->data.constant.value.u64 != 0ULL;

    unsigned bits = cc_value_type_bit_width(type);
    if (bits == 0)
        return ins->data.constant.value.u64 != 0ULL;

    unsigned long long mask = cc_mask_for_bits(bits);
    return (ins->data.constant.value.u64 & mask) != 0ULL;
}

static bool cc_instruction_is_pure(const CCInstruction *ins)
{
    if (!ins)
        return false;
    switch (ins->kind)
    {
    case CC_INSTR_CONST:
    case CC_INSTR_CONST_STRING:
    case CC_INSTR_LOAD_PARAM:
    case CC_INSTR_ADDR_PARAM:
    case CC_INSTR_LOAD_LOCAL:
    case CC_INSTR_ADDR_LOCAL:
    case CC_INSTR_LOAD_GLOBAL:
    case CC_INSTR_ADDR_GLOBAL:
    case CC_INSTR_LOAD_INDIRECT:
    case CC_INSTR_BINOP:
    case CC_INSTR_UNOP:
    case CC_INSTR_COMPARE:
    case CC_INSTR_TEST_NULL:
    case CC_INSTR_DUP:
    case CC_INSTR_CONVERT:
        return true;
    default:
        return false;
    }
}

static void cc_function_remove_instructions(CCFunction *fn, size_t index, size_t count)
{
    if (!fn || count == 0 || index >= fn->instruction_count)
        return;
    if (index + count > fn->instruction_count)
        count = fn->instruction_count - index;

    for (size_t i = 0; i < count; ++i)
        cc_instruction_free(&fn->instructions[index + i]);

    size_t tail = fn->instruction_count - (index + count);
    if (tail > 0)
        memmove(&fn->instructions[index], &fn->instructions[index + count], tail * sizeof(CCInstruction));

    size_t old_count = fn->instruction_count;
    fn->instruction_count -= count;
    for (size_t i = fn->instruction_count; i < old_count; ++i)
        memset(&fn->instructions[i], 0, sizeof(CCInstruction));
}

static bool cc_function_prune_dropped_values(CCFunction *fn)
{
    if (!fn)
        return false;

    bool changed = false;
    size_t i = 0;
    while (i < fn->instruction_count)
    {
        if (fn->instructions[i].kind != CC_INSTR_DROP)
        {
            ++i;
            continue;
        }

        size_t remove_start = i;
        bool removed_any = false;
        while (remove_start > 0)
        {
            const CCInstruction *prev = &fn->instructions[remove_start - 1];
            if (!cc_instruction_is_pure(prev))
                break;
            --remove_start;
            removed_any = true;
        }

        if (removed_any)
        {
            size_t remove_count = i - remove_start + 1;
            cc_function_remove_instructions(fn, remove_start, remove_count);
            changed = true;
            if (remove_start > 0)
                i = remove_start - 1;
            else
                i = 0;
        }
        else
        {
            ++i;
        }
    }
    return changed;
}

static bool cc_function_fold_const_binops(CCFunction *fn)
{
    if (!fn)
        return false;

    bool changed = false;
    size_t i = 0;
    while (i + 2 < fn->instruction_count)
    {
        CCInstruction *lhs = &fn->instructions[i];
        CCInstruction *rhs = &fn->instructions[i + 1];
        CCInstruction *bin = &fn->instructions[i + 2];

        if (lhs->kind != CC_INSTR_CONST || rhs->kind != CC_INSTR_CONST || bin->kind != CC_INSTR_BINOP)
        {
            ++i;
            continue;
        }

        CCValueType type = bin->data.binop.type;
        if (lhs->data.constant.type != type || rhs->data.constant.type != type)
        {
            ++i;
            continue;
        }

        if (cc_value_type_is_float(type))
        {
            double lhs_val = (type == CC_TYPE_F32) ? (double)lhs->data.constant.value.f32 : lhs->data.constant.value.f64;
            double rhs_val = (type == CC_TYPE_F32) ? (double)rhs->data.constant.value.f32 : rhs->data.constant.value.f64;
            double result = 0.0;
            bool handled_float = true;

            switch (bin->data.binop.op)
            {
            case CC_BINOP_ADD:
                result = lhs_val + rhs_val;
                break;
            case CC_BINOP_SUB:
                result = lhs_val - rhs_val;
                break;
            case CC_BINOP_MUL:
                result = lhs_val * rhs_val;
                break;
            case CC_BINOP_DIV:
                if (rhs_val == 0.0)
                    handled_float = false;
                else
                    result = lhs_val / rhs_val;
                break;
            default:
                handled_float = false;
                break;
            }

            if (!handled_float)
            {
                ++i;
                continue;
            }

            if (type == CC_TYPE_F32)
            {
                float reduced = (float)result;
                lhs->data.constant.value.f32 = reduced;
                lhs->data.constant.is_null = (reduced == 0.0f);
            }
            else
            {
                lhs->data.constant.value.f64 = result;
                lhs->data.constant.is_null = (result == 0.0);
            }
            lhs->data.constant.type = type;
            lhs->data.constant.is_unsigned = false;

            cc_function_remove_instructions(fn, i + 1, 2);
            changed = true;
            continue;
        }

        if (!cc_value_type_is_integer(type))
        {
            ++i;
            continue;
        }

        unsigned bits = cc_value_type_bit_width(type);
        if (bits == 0)
        {
            ++i;
            continue;
        }

        unsigned long long mask = cc_mask_for_bits(bits);
        unsigned long long lhs_u = lhs->data.constant.value.u64 & mask;
        unsigned long long rhs_u = rhs->data.constant.value.u64 & mask;
        long long lhs_s = cc_sign_extend_bits(lhs_u, bits);
        long long rhs_s = cc_sign_extend_bits(rhs_u, bits);

        bool use_unsigned = bin->data.binop.is_unsigned || !cc_value_type_is_signed(type);
        unsigned long long result_u = 0;
        bool handled = true;

        switch (bin->data.binop.op)
        {
        case CC_BINOP_ADD:
            result_u = use_unsigned ? (lhs_u + rhs_u) : (unsigned long long)(lhs_s + rhs_s);
            break;
        case CC_BINOP_SUB:
            result_u = use_unsigned ? (lhs_u - rhs_u) : (unsigned long long)(lhs_s - rhs_s);
            break;
        case CC_BINOP_MUL:
            result_u = use_unsigned ? (lhs_u * rhs_u) : (unsigned long long)(lhs_s * rhs_s);
            break;
        case CC_BINOP_DIV:
            if (rhs_u == 0)
                handled = false;
            else if (use_unsigned)
                result_u = lhs_u / rhs_u;
            else if (rhs_s != 0)
                result_u = (unsigned long long)(lhs_s / rhs_s);
            else
                handled = false;
            break;
        case CC_BINOP_MOD:
            if (rhs_u == 0)
                handled = false;
            else if (use_unsigned)
                result_u = lhs_u % rhs_u;
            else if (rhs_s != 0)
                result_u = (unsigned long long)(lhs_s % rhs_s);
            else
                handled = false;
            break;
        case CC_BINOP_AND:
            result_u = lhs_u & rhs_u;
            break;
        case CC_BINOP_OR:
            result_u = lhs_u | rhs_u;
            break;
        case CC_BINOP_XOR:
            result_u = lhs_u ^ rhs_u;
            break;
        case CC_BINOP_SHL:
        {
            unsigned shift = (unsigned)(rhs_u & 63U);
            if (bits < 64)
                shift %= bits;
            result_u = lhs_u << shift;
            break;
        }
        case CC_BINOP_SHR:
        {
            unsigned shift = (unsigned)(rhs_u & 63U);
            if (bits < 64)
                shift %= bits;
            if (use_unsigned)
                result_u = lhs_u >> shift;
            else
                result_u = (unsigned long long)(cc_sign_extend_bits(lhs_u, bits) >> shift);
            break;
        }
        default:
            handled = false;
            break;
        }

        if (!handled)
        {
            ++i;
            continue;
        }

        result_u &= mask;
        long long result_s = cc_sign_extend_bits(result_u, bits);

        lhs->data.constant.value.u64 = result_u;
        lhs->data.constant.value.i64 = result_s;
        lhs->data.constant.type = type;
        lhs->data.constant.is_unsigned = use_unsigned;
        lhs->data.constant.is_null = (result_u == 0ULL);

        cc_function_remove_instructions(fn, i + 1, 2);
        changed = true;
    }

    return changed;
}

static bool cc_function_fold_const_unops(CCFunction *fn)
{
    if (!fn)
        return false;

    bool changed = false;
    size_t i = 0;
    while (i + 1 < fn->instruction_count)
    {
        CCInstruction *operand = &fn->instructions[i];
        CCInstruction *unop = &fn->instructions[i + 1];

        if (operand->kind != CC_INSTR_CONST || unop->kind != CC_INSTR_UNOP)
        {
            ++i;
            continue;
        }

        CCValueType type = unop->data.unop.type;
        if (operand->data.constant.type != type)
        {
            ++i;
            continue;
        }

        bool handled = true;
        switch (unop->data.unop.op)
        {
        case CC_UNOP_NEG:
            if (!cc_value_type_is_integer(type))
            {
                handled = false;
                break;
            }
            else
            {
                unsigned bits = cc_value_type_bit_width(type);
                if (bits == 0)
                {
                    handled = false;
                    break;
                }
                unsigned long long mask = cc_mask_for_bits(bits);
                unsigned long long value_u = operand->data.constant.value.u64 & mask;
                long long value_s = cc_sign_extend_bits(value_u, bits);
                long long negated = -value_s;
                unsigned long long neg_u = (unsigned long long)negated;
                if (bits < 64)
                    neg_u &= mask;
                operand->data.constant.value.u64 = neg_u;
                operand->data.constant.value.i64 = cc_sign_extend_bits(neg_u, bits);
                operand->data.constant.is_unsigned = !cc_value_type_is_signed(type);
                operand->data.constant.is_null = (neg_u == 0ULL);
            }
            break;
        case CC_UNOP_NOT:
        {
            bool truthy = cc_constant_truthy(operand);
            operand->data.constant.type = CC_TYPE_I1;
            operand->data.constant.value.u64 = truthy ? 0ULL : 1ULL;
            operand->data.constant.value.i64 = truthy ? 0LL : 1LL;
            operand->data.constant.is_unsigned = true;
            operand->data.constant.is_null = truthy;
            break;
        }
        case CC_UNOP_BITNOT:
            if (!cc_value_type_is_integer(type))
            {
                handled = false;
                break;
            }
            else
            {
                unsigned bits = cc_value_type_bit_width(type);
                if (bits == 0)
                {
                    handled = false;
                    break;
                }
                unsigned long long mask = cc_mask_for_bits(bits);
                unsigned long long value_u = operand->data.constant.value.u64 & mask;
                unsigned long long inverted = (~value_u) & mask;
                operand->data.constant.value.u64 = inverted;
                operand->data.constant.value.i64 = cc_sign_extend_bits(inverted, bits);
                operand->data.constant.is_unsigned = !cc_value_type_is_signed(type);
                operand->data.constant.is_null = (inverted == 0ULL);
            }
            break;
        default:
            handled = false;
            break;
        }

        if (!handled)
        {
            ++i;
            continue;
        }

        if (unop->data.unop.op != CC_UNOP_NOT)
            operand->data.constant.type = type;

        cc_function_remove_instructions(fn, i + 1, 1);
        changed = true;
    }

    return changed;
}

static bool cc_function_fold_const_compares(CCFunction *fn)
{
    if (!fn)
        return false;

    bool changed = false;
    size_t i = 0;
    while (i + 2 < fn->instruction_count)
    {
        CCInstruction *lhs = &fn->instructions[i];
        CCInstruction *rhs = &fn->instructions[i + 1];
        CCInstruction *cmp = &fn->instructions[i + 2];

        if (lhs->kind != CC_INSTR_CONST || rhs->kind != CC_INSTR_CONST || cmp->kind != CC_INSTR_COMPARE)
        {
            ++i;
            continue;
        }

        CCValueType operand_type = cmp->data.compare.type;
        if (lhs->data.constant.type != operand_type || rhs->data.constant.type != operand_type)
        {
            ++i;
            continue;
        }

        bool result = false;
        bool handled = true;

        if (cc_value_type_is_float(operand_type))
        {
            double lhs_val = (operand_type == CC_TYPE_F32) ? (double)lhs->data.constant.value.f32 : lhs->data.constant.value.f64;
            double rhs_val = (operand_type == CC_TYPE_F32) ? (double)rhs->data.constant.value.f32 : rhs->data.constant.value.f64;

            switch (cmp->data.compare.op)
            {
            case CC_COMPARE_EQ:
                result = (lhs_val == rhs_val);
                break;
            case CC_COMPARE_NE:
                result = (lhs_val != rhs_val);
                break;
            case CC_COMPARE_LT:
                result = (lhs_val < rhs_val);
                break;
            case CC_COMPARE_LE:
                result = (lhs_val <= rhs_val);
                break;
            case CC_COMPARE_GT:
                result = (lhs_val > rhs_val);
                break;
            case CC_COMPARE_GE:
                result = (lhs_val >= rhs_val);
                break;
            default:
                handled = false;
                break;
            }
        }
        else if (cc_value_type_is_integer(operand_type) || operand_type == CC_TYPE_PTR)
        {
            unsigned bits = cc_value_type_bit_width(operand_type);
            if (bits == 0)
            {
                ++i;
                continue;
            }

            unsigned long long mask = cc_mask_for_bits(bits);
            unsigned long long lhs_u = lhs->data.constant.value.u64 & mask;
            unsigned long long rhs_u = rhs->data.constant.value.u64 & mask;
            long long lhs_s = cc_sign_extend_bits(lhs_u, bits);
            long long rhs_s = cc_sign_extend_bits(rhs_u, bits);
            bool use_unsigned = cmp->data.compare.is_unsigned || operand_type == CC_TYPE_PTR || !cc_value_type_is_signed(operand_type);

            switch (cmp->data.compare.op)
            {
            case CC_COMPARE_EQ:
                result = use_unsigned ? (lhs_u == rhs_u) : (lhs_s == rhs_s);
                break;
            case CC_COMPARE_NE:
                result = use_unsigned ? (lhs_u != rhs_u) : (lhs_s != rhs_s);
                break;
            case CC_COMPARE_LT:
                result = use_unsigned ? (lhs_u < rhs_u) : (lhs_s < rhs_s);
                break;
            case CC_COMPARE_LE:
                result = use_unsigned ? (lhs_u <= rhs_u) : (lhs_s <= rhs_s);
                break;
            case CC_COMPARE_GT:
                result = use_unsigned ? (lhs_u > rhs_u) : (lhs_s > rhs_s);
                break;
            case CC_COMPARE_GE:
                result = use_unsigned ? (lhs_u >= rhs_u) : (lhs_s >= rhs_s);
                break;
            default:
                handled = false;
                break;
            }
        }
        else
        {
            handled = false;
        }

        if (!handled)
        {
            ++i;
            continue;
        }

        lhs->data.constant.type = CC_TYPE_I1;
        lhs->data.constant.value.u64 = result ? 1ULL : 0ULL;
        lhs->data.constant.value.i64 = result ? 1LL : 0LL;
        lhs->data.constant.is_unsigned = true;
        lhs->data.constant.is_null = !result;

        cc_function_remove_instructions(fn, i + 1, 2);
        changed = true;
    }

    return changed;
}

static bool cc_function_fold_const_test_null(CCFunction *fn)
{
    if (!fn)
        return false;

    bool changed = false;
    size_t i = 0;
    while (i + 1 < fn->instruction_count)
    {
        CCInstruction *value = &fn->instructions[i];
        CCInstruction *test = &fn->instructions[i + 1];

        if (value->kind != CC_INSTR_CONST || test->kind != CC_INSTR_TEST_NULL)
        {
            ++i;
            continue;
        }

        bool is_null = false;
        if (value->data.constant.type == CC_TYPE_PTR)
        {
            is_null = value->data.constant.is_null || value->data.constant.value.u64 == 0ULL;
        }
        else if (cc_value_type_is_integer(value->data.constant.type))
        {
            unsigned bits = cc_value_type_bit_width(value->data.constant.type);
            unsigned long long mask = cc_mask_for_bits(bits);
            is_null = (value->data.constant.value.u64 & mask) == 0ULL;
        }
        else
        {
            ++i;
            continue;
        }

        value->data.constant.type = CC_TYPE_I1;
        value->data.constant.value.u64 = is_null ? 1ULL : 0ULL;
        value->data.constant.value.i64 = is_null ? 1LL : 0LL;
        value->data.constant.is_unsigned = true;
        value->data.constant.is_null = !is_null;

        cc_function_remove_instructions(fn, i + 1, 1);
        changed = true;
    }

    return changed;
}

static bool cc_function_fold_const_converts(CCFunction *fn)
{
    if (!fn)
        return false;

    bool changed = false;
    size_t i = 0;
    while (i + 1 < fn->instruction_count)
    {
        CCInstruction *source = &fn->instructions[i];
        CCInstruction *conv = &fn->instructions[i + 1];

        if (source->kind != CC_INSTR_CONST || conv->kind != CC_INSTR_CONVERT)
        {
            ++i;
            continue;
        }

        CCValueType from = conv->data.convert.from_type;
        CCValueType to = conv->data.convert.to_type;
        if (source->data.constant.type != from)
        {
            ++i;
            continue;
        }

        bool handled = false;
        switch (conv->data.convert.kind)
        {
        case CC_CONVERT_TRUNC:
            if (cc_value_type_is_integer(from) && cc_value_type_is_integer(to))
            {
                unsigned to_bits = cc_value_type_bit_width(to);
                if (to_bits > 0)
                {
                    unsigned from_bits = cc_value_type_bit_width(from);
                    unsigned long long value_u = source->data.constant.value.u64;
                    if (from_bits > 0 && from_bits < 64)
                        value_u &= cc_mask_for_bits(from_bits);
                    unsigned long long mask = cc_mask_for_bits(to_bits);
                    value_u &= mask;
                    source->data.constant.value.u64 = value_u;
                    source->data.constant.value.i64 = cc_sign_extend_bits(value_u, to_bits);
                    source->data.constant.type = to;
                    source->data.constant.is_unsigned = (to == CC_TYPE_PTR) || !cc_value_type_is_signed(to);
                    source->data.constant.is_null = (value_u == 0ULL);
                    handled = true;
                }
            }
            break;
        case CC_CONVERT_SEXT:
            if (cc_value_type_is_integer(from) && cc_value_type_is_integer(to))
            {
                unsigned from_bits = cc_value_type_bit_width(from);
                unsigned to_bits = cc_value_type_bit_width(to);
                if (from_bits > 0 && to_bits >= from_bits)
                {
                    unsigned long long raw = source->data.constant.value.u64 & cc_mask_for_bits(from_bits);
                    long long extended = cc_sign_extend_bits(raw, from_bits);
                    unsigned long long result_u = (unsigned long long)extended;
                    if (to_bits < 64)
                        result_u &= cc_mask_for_bits(to_bits);
                    source->data.constant.value.u64 = result_u;
                    source->data.constant.value.i64 = cc_sign_extend_bits(result_u, to_bits);
                    source->data.constant.type = to;
                    source->data.constant.is_unsigned = false;
                    source->data.constant.is_null = (result_u == 0ULL);
                    handled = true;
                }
            }
            break;
        case CC_CONVERT_ZEXT:
            if (cc_value_type_is_integer(from) && cc_value_type_is_integer(to))
            {
                unsigned from_bits = cc_value_type_bit_width(from);
                unsigned to_bits = cc_value_type_bit_width(to);
                if (from_bits > 0 && to_bits >= from_bits)
                {
                    unsigned long long raw = source->data.constant.value.u64 & cc_mask_for_bits(from_bits);
                    if (to_bits < 64)
                        raw &= cc_mask_for_bits(to_bits);
                    source->data.constant.value.u64 = raw;
                    source->data.constant.value.i64 = (long long)raw;
                    source->data.constant.type = to;
                    source->data.constant.is_unsigned = true;
                    source->data.constant.is_null = (raw == 0ULL);
                    handled = true;
                }
            }
            break;
        case CC_CONVERT_F2I:
            if (cc_value_type_is_float(from) && cc_value_type_is_integer(to) && cc_value_type_is_signed(to))
            {
                double value = (from == CC_TYPE_F32) ? (double)source->data.constant.value.f32 : source->data.constant.value.f64;
                long long truncated = (long long)value;
                unsigned long long result_u = (unsigned long long)truncated;
                unsigned bits = cc_value_type_bit_width(to);
                if (bits > 0 && bits < 64)
                {
                    unsigned long long mask = cc_mask_for_bits(bits);
                    result_u &= mask;
                    truncated = cc_sign_extend_bits(result_u, bits);
                }
                source->data.constant.value.u64 = result_u;
                source->data.constant.value.i64 = truncated;
                source->data.constant.type = to;
                source->data.constant.is_unsigned = false;
                source->data.constant.is_null = (result_u == 0ULL);
                handled = true;
            }
            break;
        case CC_CONVERT_I2F:
            if (cc_value_type_is_integer(from) && cc_value_type_is_float(to))
            {
                unsigned bits = cc_value_type_bit_width(from);
                unsigned long long mask = (bits > 0 && bits < 64) ? cc_mask_for_bits(bits) : ~0ULL;
                unsigned long long raw = source->data.constant.value.u64 & mask;
                long long signed_val = cc_sign_extend_bits(raw, bits);
                double value = cc_value_type_is_signed(from) ? (double)signed_val : (double)raw;
                if (to == CC_TYPE_F32)
                {
                    float fval = (float)value;
                    source->data.constant.value.f32 = fval;
                    source->data.constant.is_null = (fval == 0.0f);
                }
                else
                {
                    double dval = value;
                    source->data.constant.value.f64 = dval;
                    source->data.constant.is_null = (dval == 0.0);
                }
                source->data.constant.type = to;
                source->data.constant.is_unsigned = false;
                handled = true;
            }
            break;
        case CC_CONVERT_BITCAST:
            if (from == to)
                handled = true;
            break;
        default:
            break;
        }

        if (!handled)
        {
            ++i;
            continue;
        }

        cc_function_remove_instructions(fn, i + 1, 1);
        changed = true;
    }

    return changed;
}

static bool cc_instruction_is_optimizer_barrier(const CCInstruction *ins)
{
    if (!ins)
        return true;
    switch (ins->kind)
    {
    case CC_INSTR_LABEL:
    case CC_INSTR_JUMP:
    case CC_INSTR_BRANCH:
    case CC_INSTR_RET:
    case CC_INSTR_CALL:
    case CC_INSTR_CALL_INDIRECT:
    case CC_INSTR_STORE_INDIRECT:
        return true;
    default:
        return false;
    }
}

static bool cc_function_propagate_local_values(CCFunction *fn)
{
    if (!fn || fn->instruction_count < 2)
        return false;

    bool changed = false;
    for (size_t i = 0; i + 1 < fn->instruction_count; ++i)
    {
        CCInstruction *first = &fn->instructions[i];
        CCInstruction *second = &fn->instructions[i + 1];

        if (first->kind == CC_INSTR_CONST && second->kind == CC_INSTR_STORE_LOCAL)
        {
            const uint32_t tracked_local = second->data.local.index;
            const CCValueType tracked_type = second->data.local.type;
            const CCInstruction constant = *first;

            for (size_t j = i + 2; j < fn->instruction_count; ++j)
            {
                CCInstruction *candidate = &fn->instructions[j];
                if (cc_instruction_is_optimizer_barrier(candidate))
                    break;

                if ((candidate->kind == CC_INSTR_STORE_LOCAL || candidate->kind == CC_INSTR_ADDR_LOCAL) &&
                    candidate->data.local.index == tracked_local)
                    break;

                if (candidate->kind == CC_INSTR_LOAD_LOCAL &&
                    candidate->data.local.index == tracked_local &&
                    candidate->data.local.type == tracked_type)
                {
                    candidate->kind = CC_INSTR_CONST;
                    candidate->data.constant = constant.data.constant;
                    changed = true;
                }
            }
        }

        if (first->kind != CC_INSTR_LOAD_LOCAL || second->kind != CC_INSTR_STORE_LOCAL)
            continue;

        const uint32_t src_local = first->data.local.index;
        const uint32_t dst_local = second->data.local.index;
        const CCValueType src_type = first->data.local.type;
        const CCValueType dst_type = second->data.local.type;
        if (src_local == dst_local || src_type != dst_type)
            continue;

        for (size_t j = i + 2; j < fn->instruction_count; ++j)
        {
            CCInstruction *candidate = &fn->instructions[j];
            if (cc_instruction_is_optimizer_barrier(candidate))
                break;

            if ((candidate->kind == CC_INSTR_STORE_LOCAL || candidate->kind == CC_INSTR_ADDR_LOCAL) &&
                (candidate->data.local.index == src_local || candidate->data.local.index == dst_local))
                break;

            if (candidate->kind == CC_INSTR_LOAD_LOCAL &&
                candidate->data.local.index == dst_local &&
                candidate->data.local.type == dst_type)
            {
                candidate->data.local.index = src_local;
                candidate->data.local.type = src_type;
                changed = true;
            }
        }
    }

    return changed;
}

static bool cc_function_remove_dead_local_stores(CCFunction *fn)
{
    if (!fn)
        return false;

    bool changed = false;
    size_t i = 0;
    while (i < fn->instruction_count)
    {
        CCInstruction *store = &fn->instructions[i];
        if (store->kind != CC_INSTR_STORE_LOCAL)
        {
            ++i;
            continue;
        }

        uint32_t local_idx = store->data.local.index;
        bool used = false;
        bool overwritten = false;

        for (size_t j = i + 1; j < fn->instruction_count; ++j)
        {
            const CCInstruction *candidate = &fn->instructions[j];
            if (!candidate)
                break;

            if (candidate->kind == CC_INSTR_LABEL ||
                candidate->kind == CC_INSTR_JUMP ||
                candidate->kind == CC_INSTR_BRANCH ||
                candidate->kind == CC_INSTR_RET)
            {
                break;
            }

            if ((candidate->kind == CC_INSTR_LOAD_LOCAL || candidate->kind == CC_INSTR_ADDR_LOCAL) &&
                candidate->data.local.index == local_idx)
            {
                used = true;
                break;
            }

            if (candidate->kind == CC_INSTR_STORE_LOCAL &&
                candidate->data.local.index == local_idx)
            {
                overwritten = true;
                break;
            }
        }

        if (used)
        {
            ++i;
            continue;
        }

        (void)overwritten;
        size_t remove_index = i;
        size_t remove_count = 1;
        if (i > 0)
        {
            const CCInstruction *prev = &fn->instructions[i - 1];
            if (cc_instruction_is_pure(prev))
            {
                remove_index = i - 1;
                remove_count = 2;
            }
        }
        cc_function_remove_instructions(fn, remove_index, remove_count);
        changed = true;
        if (remove_index > 0)
            --i;
    }

    return changed;
}

static bool cc_function_local_used_after(const CCFunction *fn, size_t start_index, uint32_t local_index)
{
    if (!fn)
        return false;
    for (size_t j = start_index; j < fn->instruction_count; ++j)
    {
        const CCInstruction *ins = &fn->instructions[j];
        switch (ins->kind)
        {
        case CC_INSTR_LOAD_LOCAL:
        case CC_INSTR_STORE_LOCAL:
        case CC_INSTR_ADDR_LOCAL:
            if (ins->data.local.index == local_index)
                return true;
            break;
        default:
            break;
        }
    }
    return false;
}

static bool cc_function_elide_store_load_pairs(CCFunction *fn)
{
    if (!fn)
        return false;

    bool changed = false;
    size_t i = 0;
    while (i + 1 < fn->instruction_count)
    {
        CCInstruction *store = &fn->instructions[i];
        CCInstruction *load = &fn->instructions[i + 1];

        if (store->kind == CC_INSTR_STORE_LOCAL &&
            load->kind == CC_INSTR_LOAD_LOCAL &&
            store->data.local.index == load->data.local.index &&
            store->data.local.type == load->data.local.type)
        {
            uint32_t idx = store->data.local.index;
            if (!cc_function_local_used_after(fn, i + 2, idx))
            {
                cc_function_remove_instructions(fn, i, 2);
                changed = true;
                if (i > 0)
                    --i;
                continue;
            }
        }

        ++i;
    }

    return changed;
}

static bool cc_function_remove_unused_locals(CCFunction *fn)
{
    if (!fn || fn->local_count == 0)
        return false;

    size_t local_count = fn->local_count;
    bool *used = (bool *)calloc(local_count, sizeof(bool));
    if (!used)
        return false;

    for (size_t i = 0; i < fn->instruction_count; ++i)
    {
        const CCInstruction *ins = &fn->instructions[i];
        switch (ins->kind)
        {
        case CC_INSTR_LOAD_LOCAL:
        case CC_INSTR_STORE_LOCAL:
        case CC_INSTR_ADDR_LOCAL:
            if (ins->data.local.index < local_count)
                used[ins->data.local.index] = true;
            break;
        default:
            break;
        }
    }

    size_t new_count = 0;
    for (size_t i = 0; i < local_count; ++i)
    {
        if (used[i])
            ++new_count;
    }

    if (new_count == local_count)
    {
        free(used);
        return false;
    }

    size_t *map = (size_t *)malloc(local_count * sizeof(size_t));
    if (!map)
    {
        free(used);
        return false;
    }

    size_t next = 0;
    for (size_t i = 0; i < local_count; ++i)
    {
        if (used[i])
            map[i] = next++;
        else
            map[i] = SIZE_MAX;
    }

    for (size_t i = 0; i < fn->instruction_count; ++i)
    {
        CCInstruction *ins = &fn->instructions[i];
        switch (ins->kind)
        {
        case CC_INSTR_LOAD_LOCAL:
        case CC_INSTR_STORE_LOCAL:
        case CC_INSTR_ADDR_LOCAL:
        {
            uint32_t idx = ins->data.local.index;
            if (idx < local_count && map[idx] != SIZE_MAX)
                ins->data.local.index = (uint32_t)map[idx];
            break;
        }
        default:
            break;
        }
    }

    CCValueType *new_types = NULL;
    if (new_count > 0)
    {
        new_types = (CCValueType *)malloc(new_count * sizeof(CCValueType));
        if (!new_types)
        {
            free(map);
            free(used);
            return false;
        }

        for (size_t i = 0; i < local_count; ++i)
        {
            if (used[i])
            {
                size_t new_index = map[i];
                new_types[new_index] = fn->local_types ? fn->local_types[i] : CC_TYPE_I64;
            }
        }
    }

    free(fn->local_types);
    fn->local_types = new_types;
    fn->local_count = new_count;

    free(map);
    free(used);
    return true;
}

static bool cc_function_simplify_const_branches(CCFunction *fn)
{
    if (!fn)
        return false;

    bool changed = false;
    size_t i = 0;
    while (i + 1 < fn->instruction_count)
    {
        CCInstruction *cond = &fn->instructions[i];
        CCInstruction *branch = &fn->instructions[i + 1];

        if (cond->kind != CC_INSTR_CONST || branch->kind != CC_INSTR_BRANCH)
        {
            ++i;
            continue;
        }

        if (cc_value_type_is_float(cond->data.constant.type))
        {
            ++i;
            continue;
        }

        bool truthy = cc_constant_truthy(cond);
        char *true_target = branch->data.branch.true_target;
        char *false_target = branch->data.branch.false_target;
        char *dest = truthy ? true_target : false_target;
        char *discard = truthy ? false_target : true_target;

        if (!dest)
        {
            ++i;
            continue;
        }

        if (discard && discard != dest)
            free(discard);

        branch->kind = CC_INSTR_JUMP;
        branch->data.jump.target = dest;

        cc_function_remove_instructions(fn, i, 1);
        changed = true;
    }

    return changed;
}

void cc_module_optimize(CCModule *module, int opt_level)
{
    if (!module || opt_level <= 0)
        return;

    for (size_t i = 0; i < module->function_count; ++i)
    {
        CCFunction *fn = &module->functions[i];
        if (!fn || fn->instruction_count == 0)
            continue;

        bool progress = true;
        while (progress)
        {
            progress = false;
            if (cc_function_prune_dropped_values(fn))
                progress = true;
            if (opt_level >= 2)
            {
                if (cc_function_fold_const_binops(fn))
                    progress = true;
                if (cc_function_fold_const_unops(fn))
                    progress = true;
                if (cc_function_fold_const_converts(fn))
                    progress = true;
                if (cc_function_fold_const_compares(fn))
                    progress = true;
                if (cc_function_fold_const_test_null(fn))
                    progress = true;
                if (cc_function_simplify_const_branches(fn))
                    progress = true;
                if (cc_function_prune_dropped_values(fn))
                    progress = true;
            }
            if (opt_level >= 3)
            {
                if (cc_function_propagate_local_values(fn))
                    progress = true;
                if (cc_function_elide_store_load_pairs(fn))
                    progress = true;
                if (cc_function_remove_unused_locals(fn))
                    progress = true;
            }
        }
    }
}

static bool cc_write_u8(FILE *out, uint8_t value)
{
    return fwrite(&value, 1, 1, out) == 1;
}

static bool cc_write_u16(FILE *out, uint16_t value)
{
    unsigned char buf[2];
    buf[0] = (unsigned char)(value & 0xFFu);
    buf[1] = (unsigned char)((value >> 8) & 0xFFu);
    return fwrite(buf, 1, 2, out) == 2;
}

static bool cc_write_u32(FILE *out, uint32_t value)
{
    unsigned char buf[4];
    buf[0] = (unsigned char)(value & 0xFFu);
    buf[1] = (unsigned char)((value >> 8) & 0xFFu);
    buf[2] = (unsigned char)((value >> 16) & 0xFFu);
    buf[3] = (unsigned char)((value >> 24) & 0xFFu);
    return fwrite(buf, 1, 4, out) == 4;
}

static bool cc_write_u64(FILE *out, uint64_t value)
{
    unsigned char buf[8];
    for (int i = 0; i < 8; ++i)
        buf[i] = (unsigned char)((value >> (8 * i)) & 0xFFu);
    return fwrite(buf, 1, 8, out) == 8;
}

static bool cc_write_s32(FILE *out, int32_t value)
{
    return cc_write_u32(out, (uint32_t)value);
}

static bool cc_write_bool(FILE *out, bool value)
{
    return cc_write_u8(out, value ? 1u : 0u);
}

static bool cc_write_bytes(FILE *out, const void *data, size_t length)
{
    if (length == 0)
        return true;
    if (!data)
        return false;
    return fwrite(data, 1, length, out) == length;
}

static bool cc_write_size32(FILE *out, size_t value)
{
    if (value > UINT32_MAX)
        return false;
    return cc_write_u32(out, (uint32_t)value);
}

static bool cc_write_string(FILE *out, const char *text)
{
    size_t len = text ? strlen(text) : 0;
    if (!cc_write_size32(out, len))
        return false;
    return cc_write_bytes(out, text, len);
}

static bool cc_write_value_type(FILE *out, CCValueType type)
{
    return cc_write_s32(out, (int32_t)type);
}

static bool cc_write_value_type_array(FILE *out, const CCValueType *types, size_t count)
{
    for (size_t i = 0; i < count; ++i)
    {
        if (!cc_write_value_type(out, types ? types[i] : CC_TYPE_INVALID))
            return false;
    }
    return true;
}

static bool cc_write_global(FILE *out, const CCGlobal *global)
{
    if (!cc_write_string(out, global ? global->name : NULL))
        return false;
    if (!cc_write_value_type(out, global ? global->type : CC_TYPE_INVALID))
        return false;
    if (!cc_write_bool(out, global && global->is_const))
        return false;
    if (!cc_write_bool(out, global && global->is_extern))
        return false;
    if (!cc_write_bool(out, global && global->is_hidden))
        return false;
    size_t alignment = global ? global->alignment : 0;
    if (!cc_write_size32(out, alignment))
        return false;
    if (!cc_write_string(out, global ? global->section : NULL))
        return false;

    CCGlobalInitKind kind = global ? global->init.kind : CC_GLOBAL_INIT_NONE;
    if (!cc_write_u8(out, (uint8_t)kind))
        return false;

    if (!global)
        return true;

    switch (kind)
    {
    case CC_GLOBAL_INIT_NONE:
        return true;
    case CC_GLOBAL_INIT_INT:
        return cc_write_u64(out, (uint64_t)global->init.payload.u64);
    case CC_GLOBAL_INIT_FLOAT:
    {
        uint64_t bits = 0;
        memcpy(&bits, &global->init.payload.f64, sizeof(bits));
        return cc_write_u64(out, bits);
    }
    case CC_GLOBAL_INIT_STRING:
    {
        size_t len = global->init.payload.string.length;
        if (!cc_write_size32(out, len))
            return false;
        return cc_write_bytes(out, global->init.payload.string.data, len);
    }
    case CC_GLOBAL_INIT_BYTES:
    {
        size_t len = global->init.payload.bytes.size;
        if (!cc_write_size32(out, len))
            return false;
        return cc_write_bytes(out, global->init.payload.bytes.data, len);
    }
    case CC_GLOBAL_INIT_PTRS:
    {
        size_t count = global->init.payload.ptrs.count;
        if (!cc_write_size32(out, count))
            return false;
        for (size_t i = 0; i < count; ++i)
        {
            if (!cc_write_string(out, global->init.payload.ptrs.symbols[i]))
                return false;
        }
        return true;
    }
    default:
        return false;
    }
}

static bool cc_write_extern(FILE *out, const CCExtern *ext)
{
    if (!cc_write_string(out, ext ? ext->name : NULL))
        return false;
    if (!cc_write_value_type(out, ext ? ext->return_type : CC_TYPE_VOID))
        return false;
    if (!cc_write_bool(out, ext && ext->is_varargs))
        return false;
    if (!cc_write_bool(out, ext && ext->is_noreturn))
        return false;
    size_t param_count = ext ? ext->param_count : 0;
    if (!cc_write_size32(out, param_count))
        return false;
    if (param_count > 0 && !cc_write_value_type_array(out, ext->param_types, param_count))
        return false;
    return true;
}

static bool cc_write_instruction(FILE *out, const CCInstruction *ins)
{
    if (!cc_write_u8(out, (uint8_t)(ins ? ins->kind : 0)))
        return false;
    if (!cc_write_u32(out, ins ? (uint32_t)ins->line : 0))
        return false;

    if (!ins)
        return true;

    switch (ins->kind)
    {
    case CC_INSTR_CONST:
    {
        const CCValueType type = ins->data.constant.type;
        if (!cc_write_value_type(out, type))
            return false;
        if (!cc_write_bool(out, ins->data.constant.is_unsigned))
            return false;
        if (!cc_write_bool(out, ins->data.constant.is_null))
            return false;
        if (type == CC_TYPE_F32)
        {
            uint32_t bits = 0;
            memcpy(&bits, &ins->data.constant.value.f32, sizeof(bits));
            if (!cc_write_u32(out, bits))
                return false;
        }
        else if (type == CC_TYPE_F64)
        {
            uint64_t bits = 0;
            memcpy(&bits, &ins->data.constant.value.f64, sizeof(bits));
            if (!cc_write_u64(out, bits))
                return false;
        }
        else
        {
            if (!cc_write_u64(out, ins->data.constant.value.u64))
                return false;
        }
        return true;
    }
    case CC_INSTR_CONST_STRING:
    {
        size_t len = ins->data.const_string.length;
        if (!cc_write_size32(out, len))
            return false;
        if (!cc_write_bytes(out, ins->data.const_string.bytes, len))
            return false;
        if (!cc_write_string(out, ins->data.const_string.label_hint))
            return false;
        return true;
    }
    case CC_INSTR_LOAD_PARAM:
    case CC_INSTR_ADDR_PARAM:
    {
        if (!cc_write_value_type(out, ins->data.param.type))
            return false;
        if (!cc_write_u32(out, ins->data.param.index))
            return false;
        return true;
    }
    case CC_INSTR_LOAD_LOCAL:
    case CC_INSTR_STORE_LOCAL:
    case CC_INSTR_ADDR_LOCAL:
    {
        if (!cc_write_value_type(out, ins->data.local.type))
            return false;
        if (!cc_write_u32(out, ins->data.local.index))
            return false;
        return true;
    }
    case CC_INSTR_LOAD_GLOBAL:
    case CC_INSTR_STORE_GLOBAL:
    case CC_INSTR_ADDR_GLOBAL:
    {
        if (!cc_write_value_type(out, ins->data.global.type))
            return false;
        if (!cc_write_string(out, ins->data.global.symbol))
            return false;
        return true;
    }
    case CC_INSTR_LOAD_INDIRECT:
    case CC_INSTR_STORE_INDIRECT:
    {
        if (!cc_write_value_type(out, ins->data.memory.type))
            return false;
        if (!cc_write_bool(out, ins->data.memory.is_unsigned))
            return false;
        return true;
    }
    case CC_INSTR_BINOP:
    {
        if (!cc_write_u8(out, (uint8_t)ins->data.binop.op))
            return false;
        if (!cc_write_value_type(out, ins->data.binop.type))
            return false;
        if (!cc_write_bool(out, ins->data.binop.is_unsigned))
            return false;
        return true;
    }
    case CC_INSTR_UNOP:
    {
        if (!cc_write_u8(out, (uint8_t)ins->data.unop.op))
            return false;
        if (!cc_write_value_type(out, ins->data.unop.type))
            return false;
        return true;
    }
    case CC_INSTR_COMPARE:
    {
        if (!cc_write_u8(out, (uint8_t)ins->data.compare.op))
            return false;
        if (!cc_write_value_type(out, ins->data.compare.type))
            return false;
        if (!cc_write_bool(out, ins->data.compare.is_unsigned))
            return false;
        return true;
    }
    case CC_INSTR_TEST_NULL:
        return true;
    case CC_INSTR_DUP:
    {
        if (!cc_write_value_type(out, ins->data.dup.type))
            return false;
        return true;
    }
    case CC_INSTR_CONVERT:
    {
        if (!cc_write_u8(out, (uint8_t)ins->data.convert.kind))
            return false;
        if (!cc_write_value_type(out, ins->data.convert.from_type))
            return false;
        if (!cc_write_value_type(out, ins->data.convert.to_type))
            return false;
        return true;
    }
    case CC_INSTR_STACK_ALLOC:
    {
        if (!cc_write_u32(out, ins->data.stack_alloc.size_bytes))
            return false;
        if (!cc_write_u32(out, ins->data.stack_alloc.alignment))
            return false;
        return true;
    }
    case CC_INSTR_DROP:
    {
        if (!cc_write_value_type(out, ins->data.drop.type))
            return false;
        return true;
    }
    case CC_INSTR_LABEL:
        return cc_write_string(out, ins->data.label.name);
    case CC_INSTR_JUMP:
        return cc_write_string(out, ins->data.jump.target);
    case CC_INSTR_BRANCH:
        if (!cc_write_string(out, ins->data.branch.true_target))
            return false;
        if (!cc_write_string(out, ins->data.branch.false_target))
            return false;
        return true;
    case CC_INSTR_CALL:
    case CC_INSTR_CALL_INDIRECT:
    {
        if (!cc_write_string(out, ins->data.call.symbol))
            return false;
        if (!cc_write_value_type(out, ins->data.call.return_type))
            return false;
        size_t arg_count = ins->data.call.arg_count;
        if (!cc_write_size32(out, arg_count))
            return false;
        if (arg_count > 0 && !cc_write_value_type_array(out, ins->data.call.arg_types, arg_count))
            return false;
        if (!cc_write_bool(out, ins->data.call.is_varargs))
            return false;
        return true;
    }
    case CC_INSTR_RET:
        return cc_write_bool(out, ins->data.ret.has_value);
    case CC_INSTR_COMMENT:
        return cc_write_string(out, ins->data.comment.text);
    default:
        return false;
    }
}

static bool cc_write_function(FILE *out, const CCFunction *fn)
{
    if (!cc_write_string(out, fn ? fn->name : NULL))
        return false;
    if (!cc_write_value_type(out, fn ? fn->return_type : CC_TYPE_VOID))
        return false;
    if (!cc_write_bool(out, fn && fn->is_varargs))
        return false;
    if (!cc_write_bool(out, fn && fn->is_noreturn))
        return false;
    if (!cc_write_string(out, fn ? fn->section : NULL))
        return false;

    size_t param_count = fn ? fn->param_count : 0;
    if (!cc_write_size32(out, param_count))
        return false;
    if (param_count > 0 && !cc_write_value_type_array(out, fn->param_types, param_count))
        return false;

    size_t local_count = fn ? fn->local_count : 0;
    if (!cc_write_size32(out, local_count))
        return false;
    if (local_count > 0 && !cc_write_value_type_array(out, fn->local_types, local_count))
        return false;

    size_t instr_count = fn ? fn->instruction_count : 0;
    if (!cc_write_size32(out, instr_count))
        return false;
    for (size_t i = 0; i < instr_count; ++i)
    {
        if (!cc_write_instruction(out, &fn->instructions[i]))
            return false;
    }
    return true;
}

bool cc_module_write_binary(const CCModule *module, const char *path, CCDiagnosticSink *sink)
{
    if (!module || !path)
    {
        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: invalid arguments");
        return false;
    }

    FILE *out = fopen(path, "wb");
    if (!out)
    {
        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to open '%s': %s", path, strerror(errno));
        return false;
    }

    bool ok = true;

    static const char magic[] = {'C', 'C', 'B', 'I', 'N'};
    if (fwrite(magic, 1, sizeof(magic), out) != sizeof(magic))
        ok = false;
    if (ok && !cc_write_u16(out, 4u))
        ok = false;
    if (ok && !cc_write_u32(out, module->version))
        ok = false;

    if (ok && !cc_write_size32(out, module->global_count))
        ok = false;
    for (size_t i = 0; ok && i < module->global_count; ++i)
    {
        if (!cc_write_global(out, &module->globals[i]))
            ok = false;
    }

    if (ok && !cc_write_size32(out, module->extern_count))
        ok = false;
    for (size_t i = 0; ok && i < module->extern_count; ++i)
    {
        if (!cc_write_extern(out, &module->externs[i]))
            ok = false;
    }

    if (ok && !cc_write_size32(out, module->function_count))
        ok = false;
    for (size_t i = 0; ok && i < module->function_count; ++i)
    {
        if (!cc_write_function(out, &module->functions[i]))
            ok = false;
    }

    if (!ok)
    {
        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed while writing '%s'", path);
        fclose(out);
        remove(path);
        return false;
    }

    if (fclose(out) != 0)
    {
        cc_diag_emit(sink, CC_DIAG_ERROR, 0, 0, "ccbin: failed to close '%s': %s", path, strerror(errno));
        remove(path);
        return false;
    }

    return true;
}
