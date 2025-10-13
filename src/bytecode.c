#include "cc/bytecode.h"

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
}

static void cc_global_free(CCGlobal *global)
{
    if (!global)
        return;
    free(global->name);
    global->name = NULL;
    cc_global_init_reset(&global->init);
    global->type = CC_TYPE_INVALID;
    global->is_const = false;
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
    global->alignment = 0;
    global->is_const = false;
    global->init.kind = CC_GLOBAL_INIT_NONE;
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
    return fn;
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

static void cc_function_prune_dropped_values(CCFunction *fn)
{
    if (!fn)
        return;

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
}

static void cc_function_fold_const_binops(CCFunction *fn)
{
    if (!fn)
        return;

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
        if (!cc_value_type_is_integer(type))
        {
            ++i;
            continue;
        }

        if (lhs->data.constant.type != type || rhs->data.constant.type != type)
        {
            ++i;
            continue;
        }

        size_t type_bytes = cc_value_type_size(type);
        if (type_bytes == 0)
        {
            ++i;
            continue;
        }

        unsigned bits = (unsigned)(type_bytes * 8);
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
            if (use_unsigned)
                result_u = lhs_u + rhs_u;
            else
                result_u = (unsigned long long)(lhs_s + rhs_s);
            break;
        case CC_BINOP_SUB:
            if (use_unsigned)
                result_u = lhs_u - rhs_u;
            else
                result_u = (unsigned long long)(lhs_s - rhs_s);
            break;
        case CC_BINOP_MUL:
            if (use_unsigned)
                result_u = lhs_u * rhs_u;
            else
                result_u = (unsigned long long)(lhs_s * rhs_s);
            break;
        case CC_BINOP_DIV:
            if (rhs_u == 0)
            {
                handled = false;
            }
            else if (use_unsigned)
            {
                result_u = lhs_u / rhs_u;
            }
            else
            {
                if (rhs_s == 0)
                    handled = false;
                else
                    result_u = (unsigned long long)(lhs_s / rhs_s);
            }
            break;
        case CC_BINOP_MOD:
            if (rhs_u == 0)
            {
                handled = false;
            }
            else if (use_unsigned)
            {
                result_u = lhs_u % rhs_u;
            }
            else
            {
                if (rhs_s == 0)
                    handled = false;
                else
                    result_u = (unsigned long long)(lhs_s % rhs_s);
            }
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
            result_u = (lhs_u << shift);
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
        lhs->data.constant.is_null = (result_u == 0);

        cc_function_remove_instructions(fn, i + 1, 2);
    }
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

        cc_function_prune_dropped_values(fn);
        if (opt_level >= 2)
        {
            cc_function_fold_const_binops(fn);
            cc_function_prune_dropped_values(fn);
        }
    }
}
