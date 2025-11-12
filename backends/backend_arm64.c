#include "cc/backend.h"
#include "cc/bytecode.h"
#include "cc/diagnostics.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#define ARM64_STACK_ALIGNMENT 16

static const char *const ARM64_GP_REGS64[] = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
static const char *const ARM64_GP_REGS32[] = {"w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7"};
static const char *const ARM64_FP_REGS[] = {"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"};
static const char *const ARM64_SCRATCH_GP_REGS64[] = {"x9", "x10", "x11", "x12"};
static const char *const ARM64_SCRATCH_GP_REGS32[] = {"w9", "w10", "w11", "w12"};

typedef struct
{
	char *label;
	const char *bytes;
	size_t length;
} Arm64StringLiteral;

typedef struct
{
	Arm64StringLiteral *items;
	size_t count;
	size_t capacity;
} Arm64StringTable;

typedef struct
{
	char **items;
	size_t count;
	size_t capacity;
} Arm64SymbolSet;

typedef enum
{
	ARM64_VALUE_IMM = 0,
	ARM64_VALUE_LABEL,
	ARM64_VALUE_REGISTER,
	ARM64_VALUE_STACK_SLOT,
} Arm64ValueKind;

typedef struct
{
	Arm64ValueKind kind;
	CCValueType type;
	bool is_unsigned;
	union
	{
		uint64_t imm;
		const char *label;
		struct
		{
			const char *name;
			bool is_w;
		} reg;
		struct
		{
			size_t offset;
			size_t size_bytes;
			bool is_signed;
		} stack;
	} data;
} Arm64Value;

typedef struct
{
	FILE *out;
	const CCModule *module;
	CCDiagnosticSink *sink;
	Arm64StringTable strings;
	Arm64SymbolSet externs;
	size_t string_counter;
} Arm64ModuleContext;

typedef struct
{
	Arm64ModuleContext *module;
	const CCFunction *fn;
	FILE *out;
	CCDiagnosticSink *sink;
	Arm64Value *stack;
	size_t stack_size;
	size_t stack_capacity;
	bool saw_return;
	size_t *param_offsets;
	CCValueType *param_types;
	size_t *local_offsets;
	CCValueType *local_types;
	size_t frame_size;
	size_t max_stack_depth;
	size_t temp_base_offset;
	size_t temp_area_size;
	size_t temp_slot_stride;
} Arm64FunctionContext;

typedef struct
{
	bool uses_gp_reg;
	bool uses_fp_reg;
	bool gp_is_w;
	size_t gp_reg_index;
	CCValueType type;
	bool type_is_signed;
	size_t spill_offset;
	size_t spill_size;
} Arm64ArgLocation;

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

static bool module_has_function(const CCModule *module, const char *name)
{
	if (!module || !name)
		return false;
	for (size_t i = 0; i < module->function_count; ++i)
	{
		const CCFunction *fn = &module->functions[i];
		if (fn->name && strcmp(fn->name, name) == 0)
			return true;
	}
	return false;
}

static size_t align_up_size(size_t value, size_t alignment)
{
	if (alignment == 0)
		return value;
	size_t remainder = value % alignment;
	if (remainder == 0)
		return value;
	return value + (alignment - remainder);
}

static size_t arm64_compute_max_stack_depth(const CCFunction *fn)
{
	if (!fn)
		return 0;
	size_t depth = 0;
	size_t max_depth = 0;
	for (size_t i = 0; i < fn->instruction_count; ++i)
	{
		const CCInstruction *ins = &fn->instructions[i];
		switch (ins->kind)
		{
		case CC_INSTR_CONST:
		case CC_INSTR_CONST_STRING:
		case CC_INSTR_LOAD_PARAM:
		case CC_INSTR_LOAD_LOCAL:
		case CC_INSTR_ADDR_PARAM:
		case CC_INSTR_ADDR_LOCAL:
		case CC_INSTR_ADDR_GLOBAL:
		case CC_INSTR_LOAD_GLOBAL:
		case CC_INSTR_LOAD_INDIRECT:
			depth++;
			break;
		case CC_INSTR_STORE_LOCAL:
		case CC_INSTR_DROP:
			if (depth > 0)
				depth--;
			break;
		case CC_INSTR_STORE_GLOBAL:
			if (depth > 0)
				depth--;
			break;
		case CC_INSTR_STORE_INDIRECT:
			if (depth >= 2)
				depth -= 2;
			else
				depth = 0;
			break;
		case CC_INSTR_BINOP:
			if (depth >= 2)
				depth -= 1; /* pop two, push one */
			else
				depth = 0;
			break;
		case CC_INSTR_CONVERT:
			/* pop then push */
			if (depth == 0)
				depth = 1;
			break;
		case CC_INSTR_CALL:
		{
			size_t args = ins->data.call.arg_count;
			if (depth >= args)
				depth -= args;
			else
				depth = 0;
			if (ins->data.call.return_type != CC_TYPE_VOID)
				depth++;
			break;
		}
		case CC_INSTR_RET:
			if (ins->data.ret.has_value && depth > 0)
				depth--;
			break;
		default:
			break;
		}
		if (depth > max_depth)
			max_depth = depth;
	}
	return max_depth;
}

static bool arm64_lookup_signature(const Arm64ModuleContext *ctx, const char *symbol, size_t *out_param_count, bool *out_is_varargs)
{
	if (!ctx || !ctx->module || !symbol)
		return false;
	const CCModule *module = ctx->module;
	const CCExtern *ext = cc_module_find_extern_const(module, symbol);
	if (ext)
	{
		if (out_param_count)
			*out_param_count = ext->param_count;
		if (out_is_varargs)
			*out_is_varargs = ext->is_varargs;
		return true;
	}
	for (size_t i = 0; i < module->function_count; ++i)
	{
		const CCFunction *fn = &module->functions[i];
		if (fn->name && strcmp(fn->name, symbol) == 0)
		{
			if (out_param_count)
				*out_param_count = fn->param_count;
			if (out_is_varargs)
				*out_is_varargs = fn->is_varargs;
			return true;
		}
	}
	return false;
}

static size_t arm64_type_size(CCValueType type)
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
	case CC_TYPE_F32:
		return 4;
	case CC_TYPE_I64:
	case CC_TYPE_U64:
	case CC_TYPE_F64:
	case CC_TYPE_PTR:
		return 8;
	default:
		return 8;
	}
}

static char *arm64_strdup(const char *src)
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

static bool equals_ignore_case(const char *a, const char *b)
{
	if (!a || !b)
		return false;
	while (*a && *b)
	{
		unsigned char ca = (unsigned char)*a++;
		unsigned char cb = (unsigned char)*b++;
		if (tolower(ca) != tolower(cb))
			return false;
	}
	return *a == '\0' && *b == '\0';
}

static bool string_table_reserve(Arm64StringTable *table, size_t desired)
{
	if (table->capacity >= desired)
		return true;
	size_t new_capacity = table->capacity ? table->capacity * 2 : 8;
	while (new_capacity < desired)
		new_capacity *= 2;
	Arm64StringLiteral *items = (Arm64StringLiteral *)realloc(table->items, new_capacity * sizeof(Arm64StringLiteral));
	if (!items)
		return false;
	table->items = items;
	table->capacity = new_capacity;
	return true;
}

static bool string_table_add(Arm64StringTable *table, const char *label, const char *bytes, size_t length)
{
	if (!string_table_reserve(table, table->count + 1))
		return false;
	Arm64StringLiteral *lit = &table->items[table->count++];
	lit->label = label ? arm64_strdup(label) : NULL;
	lit->bytes = bytes;
	lit->length = length;
	return true;
}

static void string_table_destroy(Arm64StringTable *table)
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

static bool symbol_set_reserve(Arm64SymbolSet *set, size_t desired)
{
	if (set->capacity >= desired)
		return true;
	size_t new_capacity = set->capacity ? set->capacity * 2 : 8;
	while (new_capacity < desired)
		new_capacity *= 2;
	char **items = (char **)realloc(set->items, new_capacity * sizeof(char *));
	if (!items)
		return false;
	set->items = items;
	set->capacity = new_capacity;
	return true;
}

static bool symbol_set_contains(const Arm64SymbolSet *set, const char *symbol)
{
	if (!set || !symbol)
		return false;
	for (size_t i = 0; i < set->count; ++i)
	{
		if (strcmp(set->items[i], symbol) == 0)
			return true;
	}
	return false;
}

static bool symbol_set_add(Arm64SymbolSet *set, const char *symbol)
{
	if (!symbol)
		return true;
	if (symbol_set_contains(set, symbol))
		return true;
	if (!symbol_set_reserve(set, set->count + 1))
		return false;
	char *copy = arm64_strdup(symbol);
	if (!copy)
		return false;
	set->items[set->count++] = copy;
	return true;
}

static void symbol_set_destroy(Arm64SymbolSet *set)
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

static bool function_stack_reserve(Arm64FunctionContext *ctx, size_t desired)
{
	if (ctx->stack_capacity >= desired)
		return true;
	size_t new_capacity = ctx->stack_capacity ? ctx->stack_capacity * 2 : 8;
	while (new_capacity < desired)
		new_capacity *= 2;
	Arm64Value *values = (Arm64Value *)realloc(ctx->stack, new_capacity * sizeof(Arm64Value));
	if (!values)
		return false;
	ctx->stack = values;
	ctx->stack_capacity = new_capacity;
	return true;
}

static bool function_stack_push(Arm64FunctionContext *ctx, Arm64Value value)
{
	if (!function_stack_reserve(ctx, ctx->stack_size + 1))
		return false;
	ctx->stack[ctx->stack_size++] = value;
	return true;
}

static bool function_stack_pop(Arm64FunctionContext *ctx, Arm64Value *value)
{
	if (ctx->stack_size == 0)
		return false;
	ctx->stack_size--;
	if (value)
		*value = ctx->stack[ctx->stack_size];
	return true;
}

static const char *symbol_with_underscore(const char *name, char *buffer, size_t buffer_size)
{
	if (!name || buffer_size < 2)
		return NULL;
	snprintf(buffer, buffer_size, "_%s", name);
	return buffer;
}

static bool arm64_emit_stack_address(FILE *out, CCDiagnosticSink *sink, size_t line, const char *dst_reg, size_t offset)
{
	if (!out || !dst_reg)
		return false;
	if (offset > 4095)
	{
		emit_diag(sink, CC_DIAG_ERROR, line, "arm64 backend does not yet support stack offsets larger than 4095 bytes (got %zu)", offset);
		return false;
	}
	fprintf(out, "    add %s, sp, #%zu\n", dst_reg, offset);
	return true;
}

static void arm64_mov_imm(FILE *out, const char *reg, bool use_w, uint64_t value)
{
	if (value == 0)
	{
		fprintf(out, "    mov %s, %s\n", reg, use_w ? "wzr" : "xzr");
		return;
	}
	unsigned shifts[] = {0, 16, 32, 48};
	bool emitted = false;
	for (size_t i = 0; i < 4; ++i)
	{
		uint64_t chunk = (value >> shifts[i]) & 0xFFFFu;
		if (!chunk && !emitted)
			continue;
		if (!emitted)
		{
			fprintf(out, "    movz %s, #0x%llx%s\n", reg, (unsigned long long)chunk, use_w ? "" : ", lsl #0");
			emitted = true;
		}
		else if (chunk)
		{
			fprintf(out, "    movk %s, #0x%llx, lsl #%u\n", reg, (unsigned long long)chunk, (unsigned)(shifts[i]));
		}
	}
	if (!emitted)
		fprintf(out, "    movz %s, #0\n", reg);
}

static bool arm64_materialize_gp(Arm64FunctionContext *ctx, Arm64Value *value, const char *reg, bool use_w)
{
	FILE *out = ctx->out;
	switch (value->kind)
	{
	case ARM64_VALUE_IMM:
		arm64_mov_imm(out, reg, use_w, value->data.imm);
		return true;
	case ARM64_VALUE_LABEL:
		if (use_w)
		{
			fprintf(out, "    adrp x9, %s@PAGE\n", value->data.label);
			fprintf(out, "    add x9, x9, %s@PAGEOFF\n", value->data.label);
			fprintf(out, "    mov %s, w9\n", reg);
		}
		else
		{
			fprintf(out, "    adrp %s, %s@PAGE\n", reg, value->data.label);
			fprintf(out, "    add %s, %s, %s@PAGEOFF\n", reg, reg, value->data.label);
		}
		return true;
	case ARM64_VALUE_REGISTER:
		if (strcmp(value->data.reg.name, reg) == 0)
			return true;
		fprintf(out, "    mov %s, %s\n", reg, value->data.reg.name);
		return true;
	case ARM64_VALUE_STACK_SLOT:
	{
		size_t offset = value->data.stack.offset;
		size_t size_bytes = value->data.stack.size_bytes;
		bool is_signed = value->data.stack.is_signed && !value->is_unsigned;
		char w_name_buf[8] = {0};
		char x_name_buf[8] = {0};
		const char *w_name = reg;
		const char *x_name = reg;
		if (reg[0] == 'x')
		{
			snprintf(w_name_buf, sizeof(w_name_buf), "w%s", reg + 1);
			w_name = w_name_buf;
		}
		else if (reg[0] == 'w')
		{
			snprintf(x_name_buf, sizeof(x_name_buf), "x%s", reg + 1);
			x_name = x_name_buf;
		}
		if (size_bytes >= 8)
		{
			fprintf(out, "    ldr %s, [sp, #%zu]\n", x_name, offset);
		}
		else if (size_bytes == 4)
		{
			if (!use_w && is_signed)
				fprintf(out, "    ldrsw %s, [sp, #%zu]\n", x_name, offset);
			else
				fprintf(out, "    ldr %s, [sp, #%zu]\n", w_name, offset);
		}
		else if (size_bytes == 2)
		{
			if (is_signed)
			{
				if (use_w)
					fprintf(out, "    ldrsh %s, [sp, #%zu]\n", w_name, offset);
				else
					fprintf(out, "    ldrsh %s, [sp, #%zu]\n", x_name, offset);
			}
			else
				fprintf(out, "    ldrh %s, [sp, #%zu]\n", w_name, offset);
		}
		else
		{
			if (is_signed)
			{
				if (use_w)
					fprintf(out, "    ldrsb %s, [sp, #%zu]\n", w_name, offset);
				else
					fprintf(out, "    ldrsb %s, [sp, #%zu]\n", x_name, offset);
			}
			else
				fprintf(out, "    ldrb %s, [sp, #%zu]\n", w_name, offset);
		}
		return true;
	}
	default:
		emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "unsupported value materialization");
		return false;
	}
}

static bool arm64_spill_register_value(Arm64FunctionContext *ctx, Arm64Value *value, size_t stack_index)
{
	if (!ctx || !value)
		return false;
	if (value->kind != ARM64_VALUE_REGISTER)
		return true;
	if (ctx->temp_slot_stride == 0)
		ctx->temp_slot_stride = 8;
	if (ctx->temp_area_size == 0)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend missing temporary spill area for expression stack");
		return false;
	}
	size_t offset = ctx->temp_base_offset + stack_index * ctx->temp_slot_stride;
	if (offset + ctx->temp_slot_stride > ctx->frame_size)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend temporary spill exceeds frame size");
		return false;
	}
	const char *reg_name = value->data.reg.name;
	if (!reg_name)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend encountered register value without name");
		return false;
	}
	bool is_w = value->data.reg.is_w;
	char w_name[8] = {0};
	char x_name[8] = {0};
	const char *w_reg = NULL;
	const char *x_reg = NULL;
	if (is_w)
	{
		w_reg = reg_name;
		snprintf(x_name, sizeof(x_name), "x%s", reg_name + 1);
		x_reg = x_name;
	}
	else
	{
		x_reg = reg_name;
		snprintf(w_name, sizeof(w_name), "w%s", reg_name + 1);
		w_reg = w_name;
	}
	size_t size_bytes = arm64_type_size(value->type);
	FILE *out = ctx->out;
	if (size_bytes >= 8)
	{
		if (!x_reg)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 spill requires 64-bit register");
			return false;
		}
		fprintf(out, "    str %s, [sp, #%zu]\n", x_reg, offset);
	}
	else if (size_bytes == 4)
	{
		fprintf(out, "    str %s, [sp, #%zu]\n", w_reg, offset);
	}
	else if (size_bytes == 2)
	{
		fprintf(out, "    strh %s, [sp, #%zu]\n", w_reg, offset);
	}
	else
	{
		fprintf(out, "    strb %s, [sp, #%zu]\n", w_reg, offset);
	}
	value->kind = ARM64_VALUE_STACK_SLOT;
	value->data.stack.offset = offset;
	value->data.stack.size_bytes = size_bytes;
	value->data.stack.is_signed = cc_value_type_is_signed(value->type) && !value->is_unsigned;
	return true;
}

static bool arm64_push_const(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	Arm64Value value;
	memset(&value, 0, sizeof(value));
	value.kind = ARM64_VALUE_IMM;
	value.type = ins->data.constant.type;
	value.is_unsigned = ins->data.constant.is_unsigned;
	if (value.type == CC_TYPE_I32 || value.type == CC_TYPE_U32)
		value.data.imm = ins->data.constant.is_unsigned ? ins->data.constant.value.u64 : (uint32_t)ins->data.constant.value.i64;
	else
		value.data.imm = ins->data.constant.value.u64;
	return function_stack_push(ctx, value);
}

static const char *arm64_intern_string(Arm64ModuleContext *module, const CCFunction *fn, const CCInstruction *ins)
{
	char label[256];
	if (ins->data.const_string.label_hint && ins->data.const_string.label_hint[0])
		snprintf(label, sizeof(label), "_%s__%s", fn->name, ins->data.const_string.label_hint);
	else
		snprintf(label, sizeof(label), "L_str%zu", module->string_counter++);
	if (!string_table_add(&module->strings, label, ins->data.const_string.bytes, ins->data.const_string.length))
		return NULL;
	return module->strings.items[module->strings.count - 1].label;
}

static bool arm64_push_const_string(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	const char *label = arm64_intern_string(ctx->module, ctx->fn, ins);
	if (!label)
		return false;
	Arm64Value value;
	memset(&value, 0, sizeof(value));
	value.kind = ARM64_VALUE_LABEL;
	value.type = CC_TYPE_PTR;
	value.is_unsigned = true;
	value.data.label = label;
	return function_stack_push(ctx, value);
}

static bool arm64_emit_load_param(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (!ctx || !ctx->fn)
		return false;
	uint32_t index = ins->data.param.index;
	if (index >= ctx->fn->param_count)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "load_param index %u out of range", index);
		return false;
	}
	Arm64Value value;
	memset(&value, 0, sizeof(value));
	value.kind = ARM64_VALUE_STACK_SLOT;
	value.type = ins->data.param.type;
	value.is_unsigned = !cc_value_type_is_signed(value.type);
	value.data.stack.offset = ctx->param_offsets ? ctx->param_offsets[index] : 0;
	value.data.stack.size_bytes = arm64_type_size(value.type);
	value.data.stack.is_signed = cc_value_type_is_signed(value.type);
	return function_stack_push(ctx, value);
}

static bool arm64_emit_load_local(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	uint32_t index = ins->data.local.index;
	if (index >= ctx->fn->local_count)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "load_local index %u out of range", index);
		return false;
	}
	Arm64Value value;
	memset(&value, 0, sizeof(value));
	value.kind = ARM64_VALUE_STACK_SLOT;
	value.type = ins->data.local.type;
	value.is_unsigned = !cc_value_type_is_signed(value.type);
	value.data.stack.offset = ctx->local_offsets ? ctx->local_offsets[index] : 0;
	value.data.stack.size_bytes = arm64_type_size(value.type);
	value.data.stack.is_signed = cc_value_type_is_signed(value.type);
	return function_stack_push(ctx, value);
}

static bool arm64_emit_store_local(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	uint32_t index = ins->data.local.index;
	if (index >= ctx->fn->local_count)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "store_local index %u out of range", index);
		return false;
	}
	Arm64Value value;
	if (!function_stack_pop(ctx, &value))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "store_local requires value on stack");
		return false;
	}
	size_t offset = ctx->local_offsets ? ctx->local_offsets[index] : 0;
	size_t size_bytes = arm64_type_size(ins->data.local.type);
	bool use_w = (size_bytes <= 4);
	const char *reg = use_w ? ARM64_SCRATCH_GP_REGS32[0] : ARM64_SCRATCH_GP_REGS64[0];
	if (!arm64_materialize_gp(ctx, &value, reg, use_w))
		return false;
	FILE *out = ctx->out;
	if (size_bytes >= 8)
		fprintf(out, "    str %s, [sp, #%zu]\n", reg, offset);
	else if (size_bytes == 4)
		fprintf(out, "    str %s, [sp, #%zu]\n", reg, offset);
	else if (size_bytes == 2)
		fprintf(out, "    strh %s, [sp, #%zu]\n", ARM64_SCRATCH_GP_REGS32[0], offset);
	else
		fprintf(out, "    strb %s, [sp, #%zu]\n", ARM64_SCRATCH_GP_REGS32[0], offset);
	return true;
}

static bool arm64_emit_addr_param(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	uint32_t index = ins->data.param.index;
	if (index >= ctx->fn->param_count)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "addr_param index %u out of range", index);
		return false;
	}
	for (size_t i = 0; i < ctx->stack_size; ++i)
	{
		if (!arm64_spill_register_value(ctx, &ctx->stack[i], i))
			return false;
	}
	const char *dst_reg = ARM64_SCRATCH_GP_REGS64[0];
	size_t offset = ctx->param_offsets ? ctx->param_offsets[index] : 0;
	if (!arm64_emit_stack_address(ctx->out, ctx->sink, ins->line, dst_reg, offset))
		return false;
	Arm64Value value;
	memset(&value, 0, sizeof(value));
	value.kind = ARM64_VALUE_REGISTER;
	value.type = CC_TYPE_PTR;
	value.is_unsigned = true;
	value.data.reg.name = dst_reg;
	value.data.reg.is_w = false;
	return function_stack_push(ctx, value);
}

static bool arm64_emit_addr_local(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	uint32_t index = ins->data.local.index;
	if (index >= ctx->fn->local_count)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "addr_local index %u out of range", index);
		return false;
	}
	for (size_t i = 0; i < ctx->stack_size; ++i)
	{
		if (!arm64_spill_register_value(ctx, &ctx->stack[i], i))
			return false;
	}
	const char *dst_reg = ARM64_SCRATCH_GP_REGS64[0];
	size_t offset = ctx->local_offsets ? ctx->local_offsets[index] : 0;
	if (!arm64_emit_stack_address(ctx->out, ctx->sink, ins->line, dst_reg, offset))
		return false;
	Arm64Value value;
	memset(&value, 0, sizeof(value));
	value.kind = ARM64_VALUE_REGISTER;
	value.type = CC_TYPE_PTR;
	value.is_unsigned = true;
	value.data.reg.name = dst_reg;
	value.data.reg.is_w = false;
	return function_stack_push(ctx, value);
}

static bool arm64_emit_load_indirect(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	Arm64Value pointer_value;
	if (!function_stack_pop(ctx, &pointer_value))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "load_indirect requires pointer");
		return false;
	}
	for (size_t i = 0; i < ctx->stack_size; ++i)
	{
		if (!arm64_spill_register_value(ctx, &ctx->stack[i], i))
			return false;
	}
	const char *ptr_reg = ARM64_SCRATCH_GP_REGS64[0];
	if (!arm64_materialize_gp(ctx, &pointer_value, ptr_reg, false))
		return false;
	size_t size_bytes = arm64_type_size(ins->data.memory.type);
	bool is_unsigned = ins->data.memory.is_unsigned;
	FILE *out = ctx->out;
	const char *dst64 = ARM64_SCRATCH_GP_REGS64[1];
	const char *dst32 = ARM64_SCRATCH_GP_REGS32[1];
	const char *result_reg = dst64;
	bool use_w = false;
	if (size_bytes >= 8)
	{
		fprintf(out, "    ldr %s, [%s]\n", dst64, ptr_reg);
		result_reg = dst64;
		use_w = false;
	}
	else if (size_bytes == 4)
	{
		fprintf(out, "    ldr %s, [%s]\n", dst32, ptr_reg);
		result_reg = dst32;
		use_w = true;
	}
	else if (size_bytes == 2)
	{
		if (is_unsigned)
			fprintf(out, "    ldrh %s, [%s]\n", dst32, ptr_reg);
		else
			fprintf(out, "    ldrsh %s, [%s]\n", dst32, ptr_reg);
		result_reg = dst32;
		use_w = true;
	}
	else
	{
		if (is_unsigned)
			fprintf(out, "    ldrb %s, [%s]\n", dst32, ptr_reg);
		else
			fprintf(out, "    ldrsb %s, [%s]\n", dst32, ptr_reg);
		result_reg = dst32;
		use_w = true;
	}
	Arm64Value result;
	memset(&result, 0, sizeof(result));
	result.kind = ARM64_VALUE_REGISTER;
	result.type = ins->data.memory.type;
	result.is_unsigned = is_unsigned;
	result.data.reg.name = result_reg;
	result.data.reg.is_w = use_w;
	return function_stack_push(ctx, result);
}

static bool arm64_emit_store_indirect(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	Arm64Value value;
	Arm64Value pointer_value;
	if (!function_stack_pop(ctx, &value))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "store_indirect requires value");
		return false;
	}
	if (!function_stack_pop(ctx, &pointer_value))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "store_indirect requires pointer");
		return false;
	}
	for (size_t i = 0; i < ctx->stack_size; ++i)
	{
		if (!arm64_spill_register_value(ctx, &ctx->stack[i], i))
			return false;
	}
	const char *ptr_reg = ARM64_SCRATCH_GP_REGS64[0];
	if (!arm64_materialize_gp(ctx, &pointer_value, ptr_reg, false))
		return false;
	size_t size_bytes = arm64_type_size(ins->data.memory.type);
	bool use_w = (size_bytes <= 4);
	const char *value_reg = use_w ? ARM64_SCRATCH_GP_REGS32[1] : ARM64_SCRATCH_GP_REGS64[1];
	if (!arm64_materialize_gp(ctx, &value, value_reg, use_w))
		return false;
	FILE *out = ctx->out;
	if (size_bytes >= 8)
		fprintf(out, "    str %s, [%s]\n", value_reg, ptr_reg);
	else if (size_bytes == 4)
		fprintf(out, "    str %s, [%s]\n", value_reg, ptr_reg);
	else if (size_bytes == 2)
		fprintf(out, "    strh %s, [%s]\n", value_reg, ptr_reg);
	else
		fprintf(out, "    strb %s, [%s]\n", value_reg, ptr_reg);
	return true;
}

static bool arm64_emit_binop(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (ins->data.binop.op != CC_BINOP_ADD)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend only supports add binop currently");
		return false;
	}
	Arm64Value rhs;
	Arm64Value lhs;
	if (!function_stack_pop(ctx, &rhs) || !function_stack_pop(ctx, &lhs))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "binop requires two operands");
		return false;
	}
	size_t result_size = arm64_type_size(ins->data.binop.type);
	bool use_w = (result_size <= 4);
	const char *dst_reg = use_w ? ARM64_SCRATCH_GP_REGS32[0] : ARM64_SCRATCH_GP_REGS64[0];
	const char *rhs_reg = use_w ? ARM64_SCRATCH_GP_REGS32[1] : ARM64_SCRATCH_GP_REGS64[1];
	if (!arm64_materialize_gp(ctx, &lhs, dst_reg, use_w))
		return false;
	if (!arm64_materialize_gp(ctx, &rhs, rhs_reg, use_w))
		return false;
	FILE *out = ctx->out;
	fprintf(out, "    add %s, %s, %s\n", dst_reg, dst_reg, rhs_reg);
	bool is_signed = cc_value_type_is_signed(ins->data.binop.type) && !ins->data.binop.is_unsigned;
	const char *w_result = ARM64_SCRATCH_GP_REGS32[0];
	if (result_size == 1)
	{
		const char *mnemonic = is_signed ? "sxtb" : "uxtb";
		if (use_w)
			fprintf(out, "    %s %s, %s\n", mnemonic, dst_reg, dst_reg);
		else
		{
			fprintf(out, "    %s %s, %s\n", mnemonic, w_result, w_result);
			fprintf(out, "    %s %s, %s\n", mnemonic, dst_reg, w_result);
		}
	}
	else if (result_size == 2)
	{
		const char *mnemonic = is_signed ? "sxth" : "uxth";
		if (use_w)
			fprintf(out, "    %s %s, %s\n", mnemonic, dst_reg, dst_reg);
		else
		{
			fprintf(out, "    %s %s, %s\n", mnemonic, w_result, w_result);
			fprintf(out, "    %s %s, %s\n", mnemonic, dst_reg, w_result);
		}
	}
	Arm64Value result;
	memset(&result, 0, sizeof(result));
	result.kind = ARM64_VALUE_REGISTER;
	result.type = ins->data.binop.type;
	result.is_unsigned = ins->data.binop.is_unsigned;
	result.data.reg.name = use_w ? ARM64_SCRATCH_GP_REGS32[0] : ARM64_SCRATCH_GP_REGS64[0];
	result.data.reg.is_w = use_w;
	return function_stack_push(ctx, result);
}

static bool arm64_emit_convert(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	Arm64Value value;
	if (!function_stack_pop(ctx, &value))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "convert requires value on stack");
		return false;
	}
	CCConvertKind kind = ins->data.convert.kind;
	CCValueType from_type = ins->data.convert.from_type;
	CCValueType to_type = ins->data.convert.to_type;
	size_t from_size = arm64_type_size(from_type);
	size_t to_size = arm64_type_size(to_type);
	const char *xreg = ARM64_SCRATCH_GP_REGS64[0];
	const char *wreg = ARM64_SCRATCH_GP_REGS32[0];
	bool load_with_w = (from_size <= 4);
	const char *materialize_reg = load_with_w ? wreg : xreg;
	if (!arm64_materialize_gp(ctx, &value, materialize_reg, load_with_w))
		return false;
	FILE *out = ctx->out;
	switch (kind)
	{
	case CC_CONVERT_SEXT:
	{
		if (!cc_value_type_is_integer(from_type) || !cc_value_type_is_integer(to_type))
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "sext conversion requires integer types");
			return false;
		}
		if (to_size < from_size)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "sext destination must be at least source width");
			return false;
		}
		if (!cc_value_type_is_signed(from_type))
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "sext conversion requires signed source type");
			return false;
		}
		if (from_size == 1)
		{
			if (to_size > 4)
				fprintf(out, "    sxtb %s, %s\n", xreg, wreg);
			else
				fprintf(out, "    sxtb %s, %s\n", wreg, wreg);
		}
		else if (from_size == 2)
		{
			if (to_size > 4)
				fprintf(out, "    sxth %s, %s\n", xreg, wreg);
			else
				fprintf(out, "    sxth %s, %s\n", wreg, wreg);
		}
		else if (from_size == 4)
		{
			if (to_size > 4)
				fprintf(out, "    sxtw %s, %s\n", xreg, wreg);
		}
		else if (from_size != to_size)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "sext from %zu bytes unsupported", from_size);
			return false;
		}
		break;
	}
	case CC_CONVERT_ZEXT:
	{
		if (!cc_value_type_is_integer(from_type) || !cc_value_type_is_integer(to_type))
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "zext conversion requires integer types");
			return false;
		}
		if (to_size < from_size)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "zext destination must be at least source width");
			return false;
		}
		if (from_size == 1)
			fprintf(out, "    uxtb %s, %s\n", wreg, wreg);
		else if (from_size == 2)
			fprintf(out, "    uxth %s, %s\n", wreg, wreg);
		else if (from_size == 4 && to_size > 4)
			fprintf(out, "    uxtw %s, %s\n", xreg, wreg);
		else if (from_size != 4 && from_size != 8 && from_size != to_size)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "zext from %zu bytes unsupported", from_size);
			return false;
		}
		break;
	}
	case CC_CONVERT_TRUNC:
	{
		if (!cc_value_type_is_integer(from_type) || !cc_value_type_is_integer(to_type))
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "trunc conversion requires integer types");
			return false;
		}
		if (to_size >= from_size)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "trunc destination must be narrower than source");
			return false;
		}
		if (to_size == 1)
			fprintf(out, "    uxtb %s, %s\n", wreg, wreg);
		else if (to_size == 2)
			fprintf(out, "    uxth %s, %s\n", wreg, wreg);
		else if (to_size == 4)
		{
			/* writing to the 32-bit view already truncates */
		}
		else
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "trunc to %zu bytes unsupported", to_size);
			return false;
		}
		break;
	}
	case CC_CONVERT_BITCAST:
	{
		if (from_size != to_size)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "bitcast requires equal source and destination sizes");
			return false;
		}
		break;
	}
	default:
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "convert kind %d not supported yet on arm64 backend", (int)kind);
		return false;
	}
	Arm64Value result;
	memset(&result, 0, sizeof(result));
	result.kind = ARM64_VALUE_REGISTER;
	result.type = to_type;
	result.is_unsigned = (to_type == CC_TYPE_PTR) || !cc_value_type_is_signed(to_type);
	result.data.reg.name = (to_size <= 4) ? wreg : xreg;
	result.data.reg.is_w = (to_size <= 4);
	return function_stack_push(ctx, result);
}

static bool arm64_emit_call(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	size_t arg_count = ins->data.call.arg_count;
	if (ctx->stack_size < arg_count)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "call '%s' missing arguments", ins->data.call.symbol ? ins->data.call.symbol : "<indirect>");
		return false;
	}
	size_t gp_used = 0;
	size_t fp_used = 0;
	Arm64ArgLocation *locations = NULL;
	bool success = false;
	size_t stack_spill_total = 0;
	size_t arg_base = ctx->stack_size - arg_count;
	for (size_t i = 0; i < arg_base; ++i)
	{
		if (!arm64_spill_register_value(ctx, &ctx->stack[i], i))
			goto cleanup;
	}

	size_t fixed_params = 0;
	bool callee_is_varargs = false;
	bool have_prototype = false;

	if (ins->data.call.symbol)
		have_prototype = arm64_lookup_signature(ctx->module, ins->data.call.symbol, &fixed_params, &callee_is_varargs);

	bool call_declares_varargs = ins->data.call.is_varargs;
	if (!call_declares_varargs && have_prototype && callee_is_varargs && arg_count > fixed_params)
		call_declares_varargs = true;

	if (have_prototype && !callee_is_varargs && arg_count > fixed_params)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "call to '%s' passes %zu args but prototype only lists %zu", ins->data.call.symbol, arg_count, fixed_params);
		goto cleanup;
	}

	if (!have_prototype)
		fixed_params = arg_count;

	if (arg_count > 0)
	{
		locations = (Arm64ArgLocation *)calloc(arg_count, sizeof(Arm64ArgLocation));
		if (!locations)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "out of memory preparing call '%s'", ins->data.call.symbol ? ins->data.call.symbol : "<indirect>");
			goto cleanup;
		}
	}

	for (size_t i = 0; i < arg_count; ++i)
	{
		Arm64Value *value = &ctx->stack[ctx->stack_size - arg_count + i];
		CCValueType arg_type = ins->data.call.arg_types ? ins->data.call.arg_types[i] : CC_TYPE_I64;
		bool is_float = (arg_type == CC_TYPE_F32) || (arg_type == CC_TYPE_F64);
		Arm64ArgLocation *loc = locations ? &locations[i] : NULL;

		if (is_float)
		{
			if (fp_used >= sizeof(ARM64_FP_REGS) / sizeof(ARM64_FP_REGS[0]))
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "floating argument spill not supported on arm64 backend");
				goto cleanup;
			}
			const char *reg = ARM64_FP_REGS[fp_used++];
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "floating arguments not yet supported on arm64 backend");
			(void)reg;
			goto cleanup;
		}
		else
		{
			if (gp_used >= sizeof(ARM64_GP_REGS64) / sizeof(ARM64_GP_REGS64[0]))
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "more than 8 integer arguments not supported yet");
				goto cleanup;
			}
			bool use_w = (arg_type == CC_TYPE_I32 || arg_type == CC_TYPE_U32 || arg_type == CC_TYPE_I16 || arg_type == CC_TYPE_U16 || arg_type == CC_TYPE_I8 || arg_type == CC_TYPE_U8 || arg_type == CC_TYPE_I1);
			const char *reg = use_w ? ARM64_GP_REGS32[gp_used] : ARM64_GP_REGS64[gp_used];
			if (!arm64_materialize_gp(ctx, value, reg, use_w))
				goto cleanup;
			if (loc)
			{
				loc->uses_gp_reg = true;
				loc->gp_is_w = use_w;
				loc->gp_reg_index = gp_used;
				loc->type = arg_type;
				loc->type_is_signed = cc_value_type_is_signed(arg_type);
			}
			gp_used++;
		}
	}

	if (call_declares_varargs)
	{
		if (!ins->data.call.symbol && !ins->data.call.is_varargs)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend requires direct symbol metadata for varargs call");
			goto cleanup;
		}

		if (!have_prototype)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unknown prototype for varargs call '%s'", ins->data.call.symbol ? ins->data.call.symbol : "<unknown>");
			goto cleanup;
		}

		if (fixed_params > arg_count)
			fixed_params = arg_count;

		size_t spill_cursor = 0;
		for (size_t i = fixed_params; i < arg_count; ++i)
		{
			Arm64ArgLocation *loc = &locations[i];
			if (!loc || !loc->uses_gp_reg)
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend does not yet support non-integer varargs");
				goto cleanup;
			}

			CCValueType arg_type = ins->data.call.arg_types ? ins->data.call.arg_types[i] : CC_TYPE_I64;
			size_t value_size = cc_value_type_size(arg_type);
			if (value_size == 0)
				value_size = 8;
			if (value_size > 8)
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend does not yet support vararg aggregates larger than 8 bytes");
				goto cleanup;
			}

			loc->spill_offset = align_up_size(spill_cursor, 8);
			loc->spill_size = 8;
			spill_cursor = loc->spill_offset + loc->spill_size;
		}

		stack_spill_total = align_up_size(spill_cursor, ARM64_STACK_ALIGNMENT);
		if (stack_spill_total > 0)
		{
			fprintf(ctx->out, "    sub sp, sp, #%zu\n", stack_spill_total);
			for (size_t i = fixed_params; i < arg_count; ++i)
			{
				Arm64ArgLocation *loc = &locations[i];
				if (!loc || !loc->uses_gp_reg)
					continue;

				const char *xreg = ARM64_GP_REGS64[loc->gp_reg_index];
				const char *wreg = ARM64_GP_REGS32[loc->gp_reg_index];
				if (loc->gp_is_w && loc->type_is_signed)
					fprintf(ctx->out, "    sxtw %s, %s\n", xreg, wreg);

				if (loc->spill_offset == 0)
					fprintf(ctx->out, "    str %s, [sp]\n", xreg);
				else
					fprintf(ctx->out, "    str %s, [sp, #%zu]\n", xreg, loc->spill_offset);
			}
		}
	}

	if (ins->data.call.symbol)
	{
		char symbol_buf[256];
		const char *sym = symbol_with_underscore(ins->data.call.symbol, symbol_buf, sizeof(symbol_buf));
		fprintf(ctx->out, "    bl %s\n", sym ? sym : ins->data.call.symbol);
		symbol_set_add(&ctx->module->externs, sym ? sym : ins->data.call.symbol);
	}
	else
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "indirect calls not supported yet for arm64 backend");
		goto cleanup;
	}

	if (stack_spill_total > 0)
		fprintf(ctx->out, "    add sp, sp, #%zu\n", stack_spill_total);

	ctx->stack_size -= arg_count;

	if (ins->data.call.return_type != CC_TYPE_VOID)
	{
		bool use_w = (ins->data.call.return_type == CC_TYPE_I32 || ins->data.call.return_type == CC_TYPE_U32 || ins->data.call.return_type == CC_TYPE_I16 || ins->data.call.return_type == CC_TYPE_U16 || ins->data.call.return_type == CC_TYPE_I8 || ins->data.call.return_type == CC_TYPE_U8 || ins->data.call.return_type == CC_TYPE_I1);
		Arm64Value ret_value;
		memset(&ret_value, 0, sizeof(ret_value));
		ret_value.kind = ARM64_VALUE_REGISTER;
		ret_value.type = ins->data.call.return_type;
		ret_value.is_unsigned = !cc_value_type_is_signed(ret_value.type);
		ret_value.data.reg.name = use_w ? "w0" : "x0";
		ret_value.data.reg.is_w = use_w;
		if (!function_stack_push(ctx, ret_value))
			goto cleanup;
	}

	success = true;

cleanup:
	free(locations);
	return success;
}

static bool arm64_emit_drop(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	(void)ins;
	Arm64Value value;
	if (!function_stack_pop(ctx, &value))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "drop requires value on stack");
		return false;
	}
	return true;
}

static bool arm64_emit_ret(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (ins->data.ret.has_value)
	{
		Arm64Value value;
		if (!function_stack_pop(ctx, &value))
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "ret requires value on stack");
			return false;
		}
		CCValueType ret_type = ctx->fn ? ctx->fn->return_type : CC_TYPE_I64;
		bool use_w = (ret_type == CC_TYPE_I32 || ret_type == CC_TYPE_U32 || ret_type == CC_TYPE_I16 || ret_type == CC_TYPE_U16 || ret_type == CC_TYPE_I8 || ret_type == CC_TYPE_U8 || ret_type == CC_TYPE_I1);
		const char *reg = use_w ? "w0" : "x0";
		if (!arm64_materialize_gp(ctx, &value, reg, use_w))
			return false;
	}
	else
	{
		fprintf(ctx->out, "    mov w0, wzr\n");
	}
	if (ctx->frame_size > 0)
		fprintf(ctx->out, "    add sp, sp, #%zu\n", ctx->frame_size);
	fprintf(ctx->out, "    ldp x29, x30, [sp], #16\n");
	fprintf(ctx->out, "    ret\n");
	ctx->saw_return = true;
	return true;
}

static bool arm64_emit_instruction(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	switch (ins->kind)
	{
	case CC_INSTR_CONST:
		return arm64_push_const(ctx, ins);
	case CC_INSTR_CONST_STRING:
		return arm64_push_const_string(ctx, ins);
	case CC_INSTR_LOAD_PARAM:
		return arm64_emit_load_param(ctx, ins);
	case CC_INSTR_LOAD_LOCAL:
		return arm64_emit_load_local(ctx, ins);
	case CC_INSTR_STORE_LOCAL:
		return arm64_emit_store_local(ctx, ins);
	case CC_INSTR_ADDR_PARAM:
		return arm64_emit_addr_param(ctx, ins);
	case CC_INSTR_ADDR_LOCAL:
		return arm64_emit_addr_local(ctx, ins);
	case CC_INSTR_LOAD_INDIRECT:
		return arm64_emit_load_indirect(ctx, ins);
	case CC_INSTR_STORE_INDIRECT:
		return arm64_emit_store_indirect(ctx, ins);
	case CC_INSTR_CALL:
		return arm64_emit_call(ctx, ins);
	case CC_INSTR_BINOP:
		return arm64_emit_binop(ctx, ins);
	case CC_INSTR_CONVERT:
		return arm64_emit_convert(ctx, ins);
	case CC_INSTR_DROP:
		return arm64_emit_drop(ctx, ins);
	case CC_INSTR_RET:
		return arm64_emit_ret(ctx, ins);
	default:
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "instruction kind %d not supported by arm64 backend yet", (int)ins->kind);
		return false;
	}
}

static bool arm64_emit_function(Arm64FunctionContext *ctx)
{
	if (!ctx || !ctx->fn)
		return false;

	ctx->param_offsets = NULL;
	ctx->param_types = NULL;
	ctx->local_offsets = NULL;
	ctx->local_types = NULL;
	ctx->frame_size = 0;
	ctx->saw_return = false;

	size_t param_count = ctx->fn->param_count;
	size_t local_count = ctx->fn->local_count;
	size_t slot_index = 0;
	size_t param_local_bytes = 0;

	if (param_count > 0)
	{
		ctx->param_offsets = (size_t *)calloc(param_count, sizeof(size_t));
		ctx->param_types = (CCValueType *)calloc(param_count, sizeof(CCValueType));
		if (!ctx->param_offsets || !ctx->param_types)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend out of memory allocating parameter metadata");
			goto fail;
		}
		for (size_t i = 0; i < param_count; ++i)
		{
			ctx->param_offsets[i] = slot_index * 8;
			ctx->param_types[i] = ctx->fn->param_types ? ctx->fn->param_types[i] : CC_TYPE_I64;
			slot_index++;
		}
	}

	if (local_count > 0)
	{
		if (!ctx->fn->local_types)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend missing local type metadata");
			goto fail;
		}
		ctx->local_offsets = (size_t *)calloc(local_count, sizeof(size_t));
		ctx->local_types = (CCValueType *)calloc(local_count, sizeof(CCValueType));
		if (!ctx->local_offsets || !ctx->local_types)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend out of memory allocating local metadata");
			goto fail;
		}
		for (size_t i = 0; i < local_count; ++i)
		{
			ctx->local_offsets[i] = slot_index * 8;
			ctx->local_types[i] = ctx->fn->local_types[i];
			slot_index++;
		}
	}

	param_local_bytes = slot_index * 8;
	ctx->max_stack_depth = arm64_compute_max_stack_depth(ctx->fn);
	ctx->temp_slot_stride = 8;
	ctx->temp_base_offset = param_local_bytes;
	if (ctx->max_stack_depth > 0)
		ctx->temp_area_size = align_up_size(ctx->max_stack_depth * ctx->temp_slot_stride, ARM64_STACK_ALIGNMENT);
	else
		ctx->temp_area_size = 0;
	ctx->frame_size = align_up_size(param_local_bytes + ctx->temp_area_size, ARM64_STACK_ALIGNMENT);

	char symbol_buf[256];
	const char *fn_symbol = symbol_with_underscore(ctx->fn->name, symbol_buf, sizeof(symbol_buf));
	fprintf(ctx->out, ".globl %s\n", fn_symbol ? fn_symbol : ctx->fn->name);
	fprintf(ctx->out, ".p2align 2\n");
	fprintf(ctx->out, "%s:\n", fn_symbol ? fn_symbol : ctx->fn->name);
	fprintf(ctx->out, "    stp x29, x30, [sp, #-16]!\n");
	fprintf(ctx->out, "    mov x29, sp\n");
	if (ctx->frame_size > 0)
		fprintf(ctx->out, "    sub sp, sp, #%zu\n", ctx->frame_size);

	for (size_t i = 0; i < param_count; ++i)
	{
		if (i >= sizeof(ARM64_GP_REGS64) / sizeof(ARM64_GP_REGS64[0]))
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend only supports up to 8 register parameters presently");
			goto fail;
		}
		size_t offset = ctx->param_offsets[i];
		size_t size_bytes = arm64_type_size(ctx->param_types[i]);
		if (size_bytes == 1)
			fprintf(ctx->out, "    strb %s, [sp, #%zu]\n", ARM64_GP_REGS32[i], offset);
		else if (size_bytes == 2)
			fprintf(ctx->out, "    strh %s, [sp, #%zu]\n", ARM64_GP_REGS32[i], offset);
		else if (size_bytes == 4)
			fprintf(ctx->out, "    str %s, [sp, #%zu]\n", ARM64_GP_REGS32[i], offset);
		else
			fprintf(ctx->out, "    str %s, [sp, #%zu]\n", ARM64_GP_REGS64[i], offset);
	}

	for (size_t i = 0; i < ctx->fn->instruction_count; ++i)
	{
		if (!arm64_emit_instruction(ctx, &ctx->fn->instructions[i]))
			goto fail;
		if (ctx->saw_return)
			break;
	}

	if (!ctx->saw_return)
	{
		if (ctx->fn->return_type != CC_TYPE_VOID)
		{
			bool use_w = (ctx->fn->return_type == CC_TYPE_I32 || ctx->fn->return_type == CC_TYPE_U32 || ctx->fn->return_type == CC_TYPE_I16 || ctx->fn->return_type == CC_TYPE_U16 || ctx->fn->return_type == CC_TYPE_I8 || ctx->fn->return_type == CC_TYPE_U8 || ctx->fn->return_type == CC_TYPE_I1);
			fprintf(ctx->out, "    mov %s, %s\n", use_w ? "w0" : "x0", use_w ? "wzr" : "xzr");
		}
		if (ctx->frame_size > 0)
			fprintf(ctx->out, "    add sp, sp, #%zu\n", ctx->frame_size);
		fprintf(ctx->out, "    ldp x29, x30, [sp], #16\n");
		fprintf(ctx->out, "    ret\n");
	}

	free(ctx->param_offsets);
	free(ctx->param_types);
	free(ctx->local_offsets);
	free(ctx->local_types);
	ctx->param_offsets = NULL;
	ctx->param_types = NULL;
	ctx->local_offsets = NULL;
	ctx->local_types = NULL;
	ctx->frame_size = 0;
	ctx->max_stack_depth = 0;
	ctx->temp_base_offset = 0;
	ctx->temp_area_size = 0;
	ctx->temp_slot_stride = 0;

	return true;

fail:
	free(ctx->param_offsets);
	free(ctx->param_types);
	free(ctx->local_offsets);
	free(ctx->local_types);
	ctx->param_offsets = NULL;
	ctx->param_types = NULL;
	ctx->local_offsets = NULL;
	ctx->local_types = NULL;
	ctx->frame_size = 0;
	ctx->max_stack_depth = 0;
	ctx->temp_base_offset = 0;
	ctx->temp_area_size = 0;
	ctx->temp_slot_stride = 0;
	return false;
}

static void arm64_emit_string_literals(const Arm64ModuleContext *ctx)
{
	if (!ctx || ctx->strings.count == 0)
		return;
	fprintf(ctx->out, "\n.section __TEXT,__cstring\n");
	for (size_t i = 0; i < ctx->strings.count; ++i)
	{
		const Arm64StringLiteral *lit = &ctx->strings.items[i];
		fprintf(ctx->out, "%s:\n", lit->label ? lit->label : "L_str");
		fprintf(ctx->out, "    .byte ");
		for (size_t j = 0; j < lit->length; ++j)
		{
			unsigned char byte = (unsigned char)lit->bytes[j];
			fprintf(ctx->out, "0x%02x, ", byte);
		}
		fprintf(ctx->out, "0x00\n");
	}
}

static bool arm64_collect_externs(Arm64ModuleContext *ctx)
{
	if (!ctx || !ctx->module)
		return false;
	for (size_t fi = 0; fi < ctx->module->function_count; ++fi)
	{
		const CCFunction *fn = &ctx->module->functions[fi];
		for (size_t ii = 0; ii < fn->instruction_count; ++ii)
		{
			const CCInstruction *ins = &fn->instructions[ii];
			if (ins->kind == CC_INSTR_CALL && ins->data.call.symbol)
			{
				char symbol_buf[256];
				const char *sym = symbol_with_underscore(ins->data.call.symbol, symbol_buf, sizeof(symbol_buf));
				if (!symbol_set_add(&ctx->externs, sym ? sym : ins->data.call.symbol))
					return false;
			}
		}
	}
	return true;
}

static void arm64_emit_externs(const Arm64ModuleContext *ctx)
{
	if (!ctx || ctx->externs.count == 0)
		return;
	for (size_t i = 0; i < ctx->externs.count; ++i)
		fprintf(ctx->out, ".extern %s\n", ctx->externs.items[i]);
	fprintf(ctx->out, "\n");
}

static bool arm64_emit_module(const CCBackend *backend, const CCModule *module, const CCBackendOptions *options, CCDiagnosticSink *sink, void *userdata)
{
	(void)backend;
	(void)options;
	(void)userdata;
	if (!module)
		return false;

	const char *output_path = NULL;
	const char *target_os = NULL;
	if (options && options->options)
	{
		for (size_t i = 0; i < options->option_count; ++i)
		{
			const CCBackendOption *opt = &options->options[i];
			if (strcmp(opt->key, "output") == 0)
				output_path = opt->value;
			else if (strcmp(opt->key, "target-os") == 0)
				target_os = opt->value;
		}
	}

	if (target_os && target_os[0] && !equals_ignore_case(target_os, "macos"))
	{
		emit_diag(sink, CC_DIAG_ERROR, 0, "arm64 backend only supports target-os=macos (got '%s')", target_os);
		return false;
	}

	FILE *out = stdout;
	if (output_path)
	{
		out = fopen(output_path, "w");
		if (!out)
		{
			emit_diag(sink, CC_DIAG_ERROR, 0, "failed to open '%s'", output_path);
			return false;
		}
	}

	Arm64ModuleContext ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.out = out;
	ctx.module = module;
	ctx.sink = sink;

	fprintf(out, "// ChanceCode macOS ARM64 backend output\n");
	fprintf(out, ".build_version macos, 15, 0\n");
	fprintf(out, ".section __TEXT,__text,regular,pure_instructions\n\n");

	if (!arm64_collect_externs(&ctx))
	{
		emit_diag(sink, CC_DIAG_ERROR, 0, "failed to collect extern symbols");
		if (out != stdout)
			fclose(out);
		string_table_destroy(&ctx.strings);
		symbol_set_destroy(&ctx.externs);
		return false;
	}

	arm64_emit_externs(&ctx);

	for (size_t i = 0; i < module->function_count; ++i)
	{
		Arm64FunctionContext fn_ctx;
		memset(&fn_ctx, 0, sizeof(fn_ctx));
		fn_ctx.module = &ctx;
		fn_ctx.fn = &module->functions[i];
		fn_ctx.out = out;
		fn_ctx.sink = sink;
		if (!arm64_emit_function(&fn_ctx))
		{
			free(fn_ctx.stack);
			if (out != stdout)
				fclose(out);
			string_table_destroy(&ctx.strings);
			symbol_set_destroy(&ctx.externs);
			return false;
		}
		free(fn_ctx.stack);
		fprintf(out, "\n");
	}

	arm64_emit_string_literals(&ctx);

	if (out != stdout)
		fclose(out);

	string_table_destroy(&ctx.strings);
	symbol_set_destroy(&ctx.externs);
	return true;
}

static const CCBackend kArm64Backend = {
	.name = "arm64-macos",
	.description = "Experimental macOS ARM64 backend",
	.emit = arm64_emit_module,
	.userdata = NULL,
};

bool cc_register_backend_arm64(void)
{
	return cc_backend_register(&kArm64Backend);
}
