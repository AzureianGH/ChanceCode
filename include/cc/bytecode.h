#ifndef CC_BYTECODE_H
#define CC_BYTECODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "diagnostics.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        CC_TYPE_INVALID = -1,
        CC_TYPE_I1 = 0,
        CC_TYPE_I8,
        CC_TYPE_U8,
        CC_TYPE_I16,
        CC_TYPE_U16,
        CC_TYPE_I32,
        CC_TYPE_U32,
        CC_TYPE_I64,
        CC_TYPE_U64,
        CC_TYPE_F32,
        CC_TYPE_F64,
        CC_TYPE_PTR,
        CC_TYPE_VOID
    } CCValueType;

    typedef enum
    {
        CC_BINOP_ADD = 0,
        CC_BINOP_SUB,
        CC_BINOP_MUL,
        CC_BINOP_DIV,
        CC_BINOP_MOD,
        CC_BINOP_AND,
        CC_BINOP_OR,
        CC_BINOP_XOR,
        CC_BINOP_SHL,
        CC_BINOP_SHR
    } CCBinaryOp;

    typedef enum
    {
        CC_UNOP_NEG = 0,
        CC_UNOP_NOT,
        CC_UNOP_BITNOT
    } CCUnaryOp;

    typedef enum
    {
        CC_COMPARE_EQ = 0,
        CC_COMPARE_NE,
        CC_COMPARE_LT,
        CC_COMPARE_LE,
        CC_COMPARE_GT,
        CC_COMPARE_GE
    } CCCompareOp;

    typedef enum
    {
        CC_CONVERT_TRUNC = 0,
        CC_CONVERT_SEXT,
        CC_CONVERT_ZEXT,
        CC_CONVERT_F2I,
        CC_CONVERT_I2F,
        CC_CONVERT_BITCAST
    } CCConvertKind;

    typedef enum
    {
        CC_INSTR_CONST = 0,
        CC_INSTR_CONST_STRING,
        CC_INSTR_LOAD_PARAM,
        CC_INSTR_ADDR_PARAM,
        CC_INSTR_LOAD_LOCAL,
        CC_INSTR_STORE_LOCAL,
        CC_INSTR_ADDR_LOCAL,
        CC_INSTR_LOAD_GLOBAL,
        CC_INSTR_STORE_GLOBAL,
        CC_INSTR_ADDR_GLOBAL,
        CC_INSTR_LOAD_INDIRECT,
        CC_INSTR_STORE_INDIRECT,
        CC_INSTR_BINOP,
        CC_INSTR_UNOP,
        CC_INSTR_COMPARE,
        CC_INSTR_CONVERT,
        CC_INSTR_STACK_ALLOC,
        CC_INSTR_DROP,
        CC_INSTR_LABEL,
        CC_INSTR_JUMP,
        CC_INSTR_BRANCH,
        CC_INSTR_CALL,
        CC_INSTR_RET,
        CC_INSTR_COMMENT,
        CC_INSTR_CALL_INDIRECT
    } CCInstrKind;

    typedef enum
    {
        CC_GLOBAL_INIT_NONE = 0,
        CC_GLOBAL_INIT_INT,
        CC_GLOBAL_INIT_FLOAT,
        CC_GLOBAL_INIT_STRING,
        CC_GLOBAL_INIT_BYTES
    } CCGlobalInitKind;

    typedef struct
    {
        CCGlobalInitKind kind;
        union
        {
            int64_t i64;
            uint64_t u64;
            double f64;
            struct
            {
                char *data;
                size_t length;
            } string;
            struct
            {
                uint8_t *data;
                size_t size;
            } bytes;
        } payload;
    } CCGlobalInit;

    typedef struct
    {
        char *name;
        CCValueType type;
        size_t size;
        bool is_const;
        size_t alignment;
        CCGlobalInit init;
    } CCGlobal;

    typedef struct CCInstruction CCInstruction;

    typedef struct
    {
        char *name;
        CCValueType return_type;
        CCValueType *param_types;
        size_t param_count;
        bool is_varargs;
        bool is_noreturn;
    } CCExtern;

    struct CCInstruction
    {
        CCInstrKind kind;
        size_t line;
        union
        {
            struct
            {
                CCValueType type;
                union
                {
                    int64_t i64;
                    uint64_t u64;
                    double f64;
                    float f32;
                } value;
                bool is_unsigned;
                bool is_null;
            } constant;
            struct
            {
                char *bytes;
                size_t length;
                char *label_hint;
            } const_string;
            struct
            {
                CCValueType type;
                uint32_t index;
            } param;
            struct
            {
                CCValueType type;
                uint32_t index;
            } local;
            struct
            {
                CCValueType type;
                char *symbol;
            } global;
            struct
            {
                CCValueType type;
                bool is_unsigned;
            } memory;
            struct
            {
                CCBinaryOp op;
                CCValueType type;
                bool is_unsigned;
            } binop;
            struct
            {
                CCUnaryOp op;
                CCValueType type;
            } unop;
            struct
            {
                CCCompareOp op;
                CCValueType type;
                bool is_unsigned;
            } compare;
            struct
            {
                CCConvertKind kind;
                CCValueType from_type;
                CCValueType to_type;
            } convert;
            struct
            {
                uint32_t size_bytes;
                uint32_t alignment;
            } stack_alloc;
            struct
            {
                char *name;
            } label;
            struct
            {
                char *target;
            } jump;
            struct
            {
                char *true_target;
                char *false_target;
            } branch;
            struct
            {
                char *symbol;
                CCValueType return_type;
                CCValueType *arg_types;
                size_t arg_count;
                bool is_varargs;
            } call;
            struct
            {
                CCValueType type;
            } drop;
            struct
            {
                bool has_value;
            } ret;
            struct
            {
                char *text;
            } comment;
        } data;
    };

    typedef struct
    {
        char *name;
        CCValueType return_type;
        bool is_varargs;
        bool is_noreturn;
        CCValueType *param_types;
        size_t param_count;
        CCValueType *local_types;
        size_t local_count;
        CCInstruction *instructions;
        size_t instruction_count;
        size_t instruction_capacity;
        bool is_literal;
        bool force_inline_literal;
        bool is_preserve;
        char **literal_lines;
        size_t literal_count;
    } CCFunction;

    typedef struct
    {
        uint32_t version;
        CCGlobal *globals;
        size_t global_count;
        size_t global_capacity;
        CCExtern *externs;
        size_t extern_count;
        size_t extern_capacity;
        CCFunction *functions;
        size_t function_count;
        size_t function_capacity;
    } CCModule;

    void cc_module_init(CCModule *module, uint32_t version);
    void cc_module_free(CCModule *module);

    CCGlobal *cc_module_add_global(CCModule *module, const char *name);
    CCExtern *cc_module_add_extern(CCModule *module, const char *name);
    CCExtern *cc_module_find_extern(CCModule *module, const char *name);
    const CCExtern *cc_module_find_extern_const(const CCModule *module, const char *name);
    CCFunction *cc_module_add_function(CCModule *module, const char *name);

    bool cc_function_set_param_types(CCFunction *function, const CCValueType *types, size_t count);
    bool cc_function_set_local_types(CCFunction *function, const CCValueType *types, size_t count);

    CCInstruction *cc_function_append_instruction(CCFunction *function, CCInstrKind kind, size_t line);

    size_t cc_value_type_size(CCValueType type);
    bool cc_value_type_is_float(CCValueType type);
    bool cc_value_type_is_integer(CCValueType type);
    bool cc_value_type_is_signed(CCValueType type);
    const char *cc_value_type_name(CCValueType type);

    void cc_module_optimize(CCModule *module, int opt_level);

    bool cc_module_write_binary(const CCModule *module, const char *path, CCDiagnosticSink *sink);

#ifdef __cplusplus
}
#endif

#endif /* CC_BYTECODE_H */
