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
static const char *const ARM64_FP_REGS32[] = {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"};
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

typedef struct
{
	char *symbol;
	size_t fixed_param_count;
} Arm64VarargEntry;

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
	Arm64VarargEntry *vararg_cache;
	size_t vararg_count;
	size_t vararg_capacity;
	bool vararg_cache_loaded;
	size_t string_counter;
} Arm64ModuleContext;

typedef struct
{
	char *label;
	Arm64Value *values;
	size_t value_count;
} Arm64StackSnapshot;

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
	size_t dynamic_sp_offset;
	bool has_vararg_area;
	size_t vararg_area_offset;
	size_t vararg_gp_start;
	Arm64StackSnapshot *stack_snapshots;
	size_t stack_snapshot_count;
	size_t stack_snapshot_capacity;
} Arm64FunctionContext;

static void arm64_vararg_cache_load(Arm64ModuleContext *ctx);
static void arm64_vararg_cache_destroy(Arm64ModuleContext *ctx);
static const Arm64VarargEntry *arm64_vararg_cache_lookup(const Arm64ModuleContext *ctx, const char *symbol);

typedef struct
{
	bool uses_gp_reg;
	bool uses_fp_reg;
	bool gp_is_w;
	size_t gp_reg_index;
	size_t fp_reg_index;
	bool fp_is_s;
	CCValueType type;
	bool type_is_signed;
	size_t spill_offset;
	size_t spill_size;
} Arm64ArgLocation;

static bool arm64_spill_register_value(Arm64FunctionContext *ctx, Arm64Value *value, size_t stack_index);
static bool arm64_force_stack_slot(Arm64FunctionContext *ctx, Arm64Value *value, size_t stack_index);

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
	const Arm64VarargEntry *entry = arm64_vararg_cache_lookup(ctx, symbol);
	if (entry)
	{
		if (out_param_count)
			*out_param_count = entry->fixed_param_count;
		if (out_is_varargs)
			*out_is_varargs = true;
		return true;
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

static bool arm64_vararg_cache_reserve(Arm64ModuleContext *ctx, size_t desired)
{
	if (!ctx)
		return false;
	if (ctx->vararg_capacity >= desired)
		return true;
	size_t new_capacity = ctx->vararg_capacity ? ctx->vararg_capacity * 2 : 8;
	while (new_capacity < desired)
		new_capacity *= 2;
	Arm64VarargEntry *entries = (Arm64VarargEntry *)realloc(ctx->vararg_cache, new_capacity * sizeof(Arm64VarargEntry));
	if (!entries)
		return false;
	ctx->vararg_cache = entries;
	ctx->vararg_capacity = new_capacity;
	return true;
}

static void arm64_vararg_cache_destroy(Arm64ModuleContext *ctx)
{
	if (!ctx)
		return;
	for (size_t i = 0; i < ctx->vararg_count; ++i)
		free(ctx->vararg_cache[i].symbol);
	free(ctx->vararg_cache);
	ctx->vararg_cache = NULL;
	ctx->vararg_count = 0;
	ctx->vararg_capacity = 0;
	ctx->vararg_cache_loaded = false;
}

static void arm64_vararg_cache_load(Arm64ModuleContext *ctx)
{
	if (!ctx || ctx->vararg_cache_loaded)
		return;
	ctx->vararg_cache_loaded = true;
	FILE *fp = fopen(".chancecode_vararg_cache", "r");
	if (!fp)
		return;
	char line[512];
	while (fgets(line, sizeof(line), fp))
	{
		char *cursor = line;
		while (*cursor && isspace((unsigned char)*cursor))
			++cursor;
		if (*cursor == '\0' || *cursor == '#')
			continue;
		char symbol[256];
		unsigned long fixed = 0;
		if (sscanf(cursor, "%255s %lu", symbol, &fixed) != 2)
			continue;
		if (!arm64_vararg_cache_reserve(ctx, ctx->vararg_count + 1))
			break;
		Arm64VarargEntry *entry = &ctx->vararg_cache[ctx->vararg_count];
		entry->symbol = arm64_strdup(symbol);
		if (!entry->symbol)
			break;
		entry->fixed_param_count = (size_t)fixed;
		ctx->vararg_count++;
	}
	fclose(fp);
}

static const Arm64VarargEntry *arm64_vararg_cache_lookup(const Arm64ModuleContext *ctx, const char *symbol)
{
	if (!ctx || !symbol || ctx->vararg_count == 0)
		return NULL;
	for (size_t i = 0; i < ctx->vararg_count; ++i)
	{
		const Arm64VarargEntry *entry = &ctx->vararg_cache[i];
		if (entry->symbol && strcmp(entry->symbol, symbol) == 0)
			return entry;
	}
	return NULL;
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
	size_t slot = ctx->stack_size;
	ctx->stack[slot] = value;
	if (value.kind == ARM64_VALUE_REGISTER)
	{
		if (!arm64_spill_register_value(ctx, &ctx->stack[slot], slot))
			return false;
	}
	ctx->stack_size++;
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

static void arm64_emit_symbol_address(FILE *out, const char *symbol, const char *dst_reg)
{
	if (!out || !symbol || !dst_reg)
		return;
	char symbol_buf[256];
	const char *sym = symbol_with_underscore(symbol, symbol_buf, sizeof(symbol_buf));
	const char *label = sym ? sym : symbol;
	fprintf(out, "    adrp %s, %s@PAGE\n", dst_reg, label);
	fprintf(out, "    add %s, %s, %s@PAGEOFF\n", dst_reg, dst_reg, label);
}

static const char *arm64_local_label_name(const CCFunction *fn, const char *suffix, char *buffer, size_t buffer_size)
{
	if (!fn || !fn->name || !suffix || !buffer || buffer_size == 0)
		return NULL;
	snprintf(buffer, buffer_size, "%s__%s", fn->name, suffix);
	return buffer;
}

static void arm64_narrow_integer_result(FILE *out, const char *dst_reg, size_t size_bytes, bool sign_extend)
{
	if (!out || !dst_reg)
		return;
	if (size_bytes >= 4)
		return;
	const char *mnemonic = NULL;
	if (size_bytes == 1)
		mnemonic = sign_extend ? "sxtb" : "uxtb";
	else if (size_bytes == 2)
		mnemonic = sign_extend ? "sxth" : "uxth";
	else
		return;
	bool is_x = (dst_reg[0] == 'x');
	bool is_w = (dst_reg[0] == 'w');
	if (is_x)
	{
		char w_name[8];
		snprintf(w_name, sizeof(w_name), "w%s", dst_reg + 1);
		fprintf(out, "    %s %s, %s\n", mnemonic, w_name, w_name);
		fprintf(out, "    %s %s, %s\n", mnemonic, dst_reg, w_name);
	}
	else if (is_w)
	{
		fprintf(out, "    %s %s, %s\n", mnemonic, dst_reg, dst_reg);
	}
	else
	{
		fprintf(out, "    %s %s, %s\n", mnemonic, dst_reg, dst_reg);
	}
}

static size_t arm64_frame_offset(const Arm64FunctionContext *ctx, size_t offset)
{
	if (!ctx)
		return offset;
	return ctx->dynamic_sp_offset + offset;
}

static bool arm64_emit_stack_address(Arm64FunctionContext *ctx, size_t line, const char *dst_reg, size_t offset)
{
	if (!ctx || !ctx->out || !dst_reg)
		return false;
	size_t absolute = arm64_frame_offset(ctx, offset);
	if (absolute > 4095)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, line, "arm64 backend does not yet support stack offsets larger than 4095 bytes (got %zu)", absolute);
		return false;
	}
	fprintf(ctx->out, "    add %s, sp, #%zu\n", dst_reg, absolute);
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

static bool arm64_adjust_sp(Arm64FunctionContext *ctx, size_t amount)
{
	if (!ctx || amount == 0)
		return true;
	FILE *out = ctx->out;
	if (amount <= 4095)
	{
		fprintf(out, "    sub sp, sp, #%zu\n", amount);
		ctx->dynamic_sp_offset += amount;
		return true;
	}
	const char *tmp_reg = ARM64_SCRATCH_GP_REGS64[0];
	arm64_mov_imm(out, tmp_reg, false, amount);
	fprintf(out, "    sub sp, sp, %s\n", tmp_reg);
	ctx->dynamic_sp_offset += amount;
	return true;
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
		size_t addr = arm64_frame_offset(ctx, offset);
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
			fprintf(out, "    ldr %s, [sp, #%zu]\n", x_name, addr);
		}
		else if (size_bytes == 4)
		{
			if (!use_w && is_signed)
				fprintf(out, "    ldrsw %s, [sp, #%zu]\n", x_name, addr);
			else
				fprintf(out, "    ldr %s, [sp, #%zu]\n", w_name, addr);
		}
		else if (size_bytes == 2)
		{
			if (is_signed)
			{
				if (use_w)
					fprintf(out, "    ldrsh %s, [sp, #%zu]\n", w_name, addr);
				else
					fprintf(out, "    ldrsh %s, [sp, #%zu]\n", x_name, addr);
			}
			else
				fprintf(out, "    ldrh %s, [sp, #%zu]\n", w_name, addr);
		}
		else
		{
			if (is_signed)
			{
				if (use_w)
					fprintf(out, "    ldrsb %s, [sp, #%zu]\n", w_name, addr);
				else
					fprintf(out, "    ldrsb %s, [sp, #%zu]\n", x_name, addr);
			}
			else
				fprintf(out, "    ldrb %s, [sp, #%zu]\n", w_name, addr);
		}
		return true;
	}
	default:
		emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "unsupported value materialization");
		return false;
	}
}

static bool arm64_materialize_fp(Arm64FunctionContext *ctx, Arm64Value *value, const char *fp_reg, CCValueType type)
{
	if (!ctx || !value || !fp_reg)
		return false;
	FILE *out = ctx->out;
	bool is_f32 = (type == CC_TYPE_F32);
	bool is_f64 = (type == CC_TYPE_F64);
	if (!is_f32 && !is_f64)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend expected f32/f64 for floating materialization");
		return false;
	}
	switch (value->kind)
	{
	case ARM64_VALUE_IMM:
	{
		uint64_t bits = value->data.imm;
		const char *tmp_gp = is_f32 ? ARM64_SCRATCH_GP_REGS32[3] : ARM64_SCRATCH_GP_REGS64[3];
		arm64_mov_imm(out, tmp_gp, is_f32, is_f32 ? (uint32_t)bits : bits);
		fprintf(out, "    fmov %s, %s\n", fp_reg, tmp_gp);
		return true;
	}
	case ARM64_VALUE_STACK_SLOT:
	{
		size_t offset = value->data.stack.offset;
		size_t addr = arm64_frame_offset(ctx, offset);
		fprintf(out, "    ldr %s, [sp, #%zu]\n", fp_reg, addr);
		return true;
	}
	case ARM64_VALUE_REGISTER:
	{
		const char *src = value->data.reg.name;
		if (!src)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend missing register name for floating materialization");
			return false;
		}
		if (src[0] == 's' || src[0] == 'd')
		{
			if (strcmp(src, fp_reg) != 0)
				fprintf(out, "    fmov %s, %s\n", fp_reg, src);
			return true;
		}
		char converted[8];
		const char *gp_src = src;
		if (is_f32)
		{
			if (src[0] == 'x')
			{
				snprintf(converted, sizeof(converted), "w%s", src + 1);
				gp_src = converted;
			}
			else if (src[0] != 'w')
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend cannot move value into s-register from '%s'", src);
				return false;
			}
		}
		else
		{
			if (src[0] == 'w')
			{
				snprintf(converted, sizeof(converted), "x%s", src + 1);
				gp_src = converted;
			}
			else if (src[0] != 'x')
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend cannot move value into d-register from '%s'", src);
				return false;
			}
		}
		fprintf(out, "    fmov %s, %s\n", fp_reg, gp_src);
		return true;
	}
	case ARM64_VALUE_LABEL:
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend does not yet support floating labels");
		return false;
	}
	default:
		emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend cannot materialize floating-point value kind %d", (int)value->kind);
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
	size_t addr = arm64_frame_offset(ctx, offset);
	const char *reg_name = value->data.reg.name;
	if (!reg_name)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend encountered register value without name");
		return false;
	}
	bool is_fp_reg = reg_name[0] == 's' || reg_name[0] == 'd';
	size_t size_bytes = arm64_type_size(value->type);
	FILE *out = ctx->out;
	if (is_fp_reg)
	{
		const char *store_reg = reg_name;
		char alt_name[8] = {0};
		if (size_bytes == 4 && reg_name[0] == 'd')
		{
			snprintf(alt_name, sizeof(alt_name), "s%s", reg_name + 1);
			store_reg = alt_name;
		}
		else if (size_bytes == 8 && reg_name[0] == 's')
		{
			snprintf(alt_name, sizeof(alt_name), "d%s", reg_name + 1);
			store_reg = alt_name;
		}
		if (size_bytes != 4 && size_bytes != 8)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 spill does not support %zu-byte floating value", size_bytes);
			return false;
		}
		fprintf(out, "    str %s, [sp, #%zu]\n", store_reg, addr);
	}
	else
	{
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
		if (size_bytes >= 8)
		{
			if (!x_reg)
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 spill requires 64-bit register");
				return false;
			}
			fprintf(out, "    str %s, [sp, #%zu]\n", x_reg, addr);
		}
		else if (size_bytes == 4)
		{
			fprintf(out, "    str %s, [sp, #%zu]\n", w_reg, addr);
		}
		else if (size_bytes == 2)
		{
			fprintf(out, "    strh %s, [sp, #%zu]\n", w_reg, addr);
		}
		else
		{
			fprintf(out, "    strb %s, [sp, #%zu]\n", w_reg, addr);
		}
	}
	value->kind = ARM64_VALUE_STACK_SLOT;
	value->data.stack.offset = offset;
	value->data.stack.size_bytes = size_bytes;
	value->data.stack.is_signed = cc_value_type_is_signed(value->type) && !value->is_unsigned;
	return true;
}

static bool arm64_force_stack_slot(Arm64FunctionContext *ctx, Arm64Value *value, size_t stack_index)
{
	if (!ctx || !value)
		return false;
	if (value->kind == ARM64_VALUE_STACK_SLOT)
		return true;
	if (value->kind == ARM64_VALUE_REGISTER)
		return arm64_spill_register_value(ctx, value, stack_index);
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
	size_t addr = arm64_frame_offset(ctx, offset);
	size_t size_bytes = arm64_type_size(value->type);
	FILE *out = ctx->out;
	if (cc_value_type_is_float(value->type))
	{
		const char *fp_reg = (size_bytes == 4) ? "s15" : "d15";
		if (!arm64_materialize_fp(ctx, value, fp_reg, value->type))
			return false;
		fprintf(out, "    str %s, [sp, #%zu]\n", fp_reg, addr);
	}
	else
	{
		const size_t scratch_index = 2;
		const char *x_reg = ARM64_SCRATCH_GP_REGS64[scratch_index];
		const char *w_reg = ARM64_SCRATCH_GP_REGS32[scratch_index];
		bool use_w = (size_bytes <= 4);
		const char *reg = use_w ? w_reg : x_reg;
		if (!arm64_materialize_gp(ctx, value, reg, use_w))
			return false;
		if (size_bytes >= 8)
			fprintf(out, "    str %s, [sp, #%zu]\n", x_reg, addr);
		else if (size_bytes == 4)
			fprintf(out, "    str %s, [sp, #%zu]\n", w_reg, addr);
		else if (size_bytes == 2)
			fprintf(out, "    strh %s, [sp, #%zu]\n", w_reg, addr);
		else
			fprintf(out, "    strb %s, [sp, #%zu]\n", w_reg, addr);
	}
	value->kind = ARM64_VALUE_STACK_SLOT;
	value->data.stack.offset = offset;
	value->data.stack.size_bytes = size_bytes;
	value->data.stack.is_signed = cc_value_type_is_signed(value->type) && !value->is_unsigned;
	return true;
}

static bool arm64_spill_value_stack(Arm64FunctionContext *ctx)
{
	if (!ctx)
		return false;
	for (size_t i = 0; i < ctx->stack_size; ++i)
	{
		if (!arm64_force_stack_slot(ctx, &ctx->stack[i], i))
			return false;
	}
	return true;
}

static bool arm64_stack_snapshot_reserve(Arm64FunctionContext *ctx, size_t desired)
{
	if (ctx->stack_snapshot_capacity >= desired)
		return true;
	size_t new_capacity = ctx->stack_snapshot_capacity ? ctx->stack_snapshot_capacity * 2 : 4;
	while (new_capacity < desired)
		new_capacity *= 2;
	Arm64StackSnapshot *items = (Arm64StackSnapshot *)realloc(ctx->stack_snapshots, new_capacity * sizeof(Arm64StackSnapshot));
	if (!items)
		return false;
	ctx->stack_snapshots = items;
	ctx->stack_snapshot_capacity = new_capacity;
	return true;
}

static Arm64StackSnapshot *arm64_find_stack_snapshot(const Arm64FunctionContext *ctx, const char *label)
{
	if (!ctx || !label)
		return NULL;
	for (size_t i = 0; i < ctx->stack_snapshot_count; ++i)
	{
		Arm64StackSnapshot *snapshot = &ctx->stack_snapshots[i];
		if (snapshot->label && strcmp(snapshot->label, label) == 0)
			return snapshot;
	}
	return NULL;
}

static bool arm64_copy_stack_to_snapshot(Arm64FunctionContext *ctx, Arm64StackSnapshot *snapshot)
{
	snapshot->value_count = ctx->stack_size;
	if (ctx->stack_size == 0)
	{
		snapshot->values = NULL;
		return true;
	}
	snapshot->values = (Arm64Value *)malloc(ctx->stack_size * sizeof(Arm64Value));
	if (!snapshot->values)
		return false;
	memcpy(snapshot->values, ctx->stack, ctx->stack_size * sizeof(Arm64Value));
	return true;
}

static bool arm64_record_stack_snapshot(Arm64FunctionContext *ctx, size_t line, const char *label)
{
	if (!ctx || !label)
		return false;
	Arm64StackSnapshot *existing = arm64_find_stack_snapshot(ctx, label);
	if (existing)
	{
		if (existing->value_count != ctx->stack_size)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, line, "inconsistent stack depth for label '%s' (expected %zu, saw %zu)", label, existing->value_count, ctx->stack_size);
			return false;
		}
		return true;
	}
	if (!arm64_stack_snapshot_reserve(ctx, ctx->stack_snapshot_count + 1))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, line, "arm64 backend out of memory while tracking label '%s'", label);
		return false;
	}
	Arm64StackSnapshot *snapshot = &ctx->stack_snapshots[ctx->stack_snapshot_count++];
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->label = arm64_strdup(label);
	if (!snapshot->label)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, line, "arm64 backend out of memory while tracking label '%s'", label);
		ctx->stack_snapshot_count--;
		return false;
	}
	if (!arm64_copy_stack_to_snapshot(ctx, snapshot))
	{
		free(snapshot->label);
		snapshot->label = NULL;
		emit_diag(ctx->sink, CC_DIAG_ERROR, line, "arm64 backend out of memory while tracking label '%s'", label);
		ctx->stack_snapshot_count--;
		return false;
	}
	return true;
}

static bool arm64_apply_stack_snapshot(Arm64FunctionContext *ctx, const Arm64StackSnapshot *snapshot)
{
	if (!ctx || !snapshot)
		return false;
	if (!function_stack_reserve(ctx, snapshot->value_count))
		return false;
	if (snapshot->value_count > 0 && snapshot->values)
		memcpy(ctx->stack, snapshot->values, snapshot->value_count * sizeof(Arm64Value));
	ctx->stack_size = snapshot->value_count;
	return true;
}

static bool arm64_handle_label_entry(Arm64FunctionContext *ctx, size_t line, const char *label)
{
	Arm64StackSnapshot *snapshot = arm64_find_stack_snapshot(ctx, label);
	if (snapshot)
		return arm64_apply_stack_snapshot(ctx, snapshot);
	if (!arm64_spill_value_stack(ctx))
		return false;
	return arm64_record_stack_snapshot(ctx, line, label);
}

static void arm64_clear_stack_snapshots(Arm64FunctionContext *ctx)
{
	if (!ctx)
		return;
	for (size_t i = 0; i < ctx->stack_snapshot_count; ++i)
	{
		free(ctx->stack_snapshots[i].label);
		free(ctx->stack_snapshots[i].values);
	}
	free(ctx->stack_snapshots);
	ctx->stack_snapshots = NULL;
	ctx->stack_snapshot_capacity = 0;
	ctx->stack_snapshot_count = 0;
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

static bool arm64_emit_load_global(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (!ctx || !ins || !ins->data.global.symbol)
		return false;
	if (!arm64_spill_value_stack(ctx))
		return false;
	FILE *out = ctx->out;
	const char *addr_reg = ARM64_SCRATCH_GP_REGS64[0];
	arm64_emit_symbol_address(out, ins->data.global.symbol, addr_reg);
	CCValueType type = ins->data.global.type;
	Arm64Value result;
	memset(&result, 0, sizeof(result));
	result.kind = ARM64_VALUE_REGISTER;
	result.type = type;
	result.is_unsigned = !cc_value_type_is_signed(type);
	if (cc_value_type_is_float(type))
	{
		const char *dst_reg = (type == CC_TYPE_F32) ? "s0" : "d0";
		fprintf(out, "    ldr %s, [%s]\n", dst_reg, addr_reg);
		result.data.reg.name = dst_reg;
		result.data.reg.is_w = (type == CC_TYPE_F32);
	}
	else
	{
		size_t size_bytes = arm64_type_size(type);
		bool use_w = (size_bytes <= 4);
		const char *dst_reg = use_w ? ARM64_SCRATCH_GP_REGS32[1] : ARM64_SCRATCH_GP_REGS64[1];
		if (size_bytes >= 8)
			fprintf(out, "    ldr %s, [%s]\n", dst_reg, addr_reg);
		else if (size_bytes == 4)
			fprintf(out, "    ldr %s, [%s]\n", dst_reg, addr_reg);
		else if (size_bytes == 2)
			fprintf(out, "    ldrh %s, [%s]\n", ARM64_SCRATCH_GP_REGS32[1], addr_reg);
		else
			fprintf(out, "    ldrb %s, [%s]\n", ARM64_SCRATCH_GP_REGS32[1], addr_reg);
		result.data.reg.name = dst_reg;
		result.data.reg.is_w = use_w;
	}
	return function_stack_push(ctx, result);
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
	size_t addr = arm64_frame_offset(ctx, offset);
	size_t size_bytes = arm64_type_size(ins->data.local.type);
	bool use_w = (size_bytes <= 4);
	const char *reg = use_w ? ARM64_SCRATCH_GP_REGS32[0] : ARM64_SCRATCH_GP_REGS64[0];
	if (!arm64_materialize_gp(ctx, &value, reg, use_w))
		return false;
	FILE *out = ctx->out;
	if (size_bytes >= 8)
		fprintf(out, "    str %s, [sp, #%zu]\n", reg, addr);
	else if (size_bytes == 4)
		fprintf(out, "    str %s, [sp, #%zu]\n", reg, addr);
	else if (size_bytes == 2)
		fprintf(out, "    strh %s, [sp, #%zu]\n", ARM64_SCRATCH_GP_REGS32[0], addr);
	else
		fprintf(out, "    strb %s, [sp, #%zu]\n", ARM64_SCRATCH_GP_REGS32[0], addr);
	return true;
}

static bool arm64_emit_store_global(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (!ctx || !ins || !ins->data.global.symbol)
		return false;
	Arm64Value value;
	if (!function_stack_pop(ctx, &value))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "store_global requires value on stack");
		return false;
	}
	if (!arm64_spill_value_stack(ctx))
		return false;
	FILE *out = ctx->out;
	const char *addr_reg = ARM64_SCRATCH_GP_REGS64[0];
	arm64_emit_symbol_address(out, ins->data.global.symbol, addr_reg);
	CCValueType type = ins->data.global.type;
	if (cc_value_type_is_float(type))
	{
		const char *src_reg = (type == CC_TYPE_F32) ? "s0" : "d0";
		if (!arm64_materialize_fp(ctx, &value, src_reg, type))
			return false;
		fprintf(out, "    str %s, [%s]\n", src_reg, addr_reg);
		return true;
	}
	size_t size_bytes = arm64_type_size(type);
	bool use_w = (size_bytes <= 4);
	const char *src_reg = use_w ? ARM64_SCRATCH_GP_REGS32[1] : ARM64_SCRATCH_GP_REGS64[1];
	if (!arm64_materialize_gp(ctx, &value, src_reg, use_w))
		return false;
	if (size_bytes >= 8)
		fprintf(out, "    str %s, [%s]\n", src_reg, addr_reg);
	else if (size_bytes == 4)
		fprintf(out, "    str %s, [%s]\n", src_reg, addr_reg);
	else if (size_bytes == 2)
		fprintf(out, "    strh %s, [%s]\n", src_reg, addr_reg);
	else
		fprintf(out, "    strb %s, [%s]\n", src_reg, addr_reg);
	return true;
}

static bool arm64_emit_addr_global(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (!ctx || !ins || !ins->data.global.symbol)
		return false;
	if (!arm64_spill_value_stack(ctx))
		return false;
	FILE *out = ctx->out;
	const char *dst_reg = ARM64_SCRATCH_GP_REGS64[0];
	arm64_emit_symbol_address(out, ins->data.global.symbol, dst_reg);
	Arm64Value value;
	memset(&value, 0, sizeof(value));
	value.kind = ARM64_VALUE_REGISTER;
	value.type = CC_TYPE_PTR;
	value.is_unsigned = true;
	value.data.reg.name = dst_reg;
	value.data.reg.is_w = false;
	return function_stack_push(ctx, value);
}

static bool arm64_emit_label(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (!ctx || !ctx->fn || !ins || !ins->data.label.name)
		return false;
	if (!arm64_handle_label_entry(ctx, ins->line, ins->data.label.name))
		return false;
	char label[512];
	const char *full = arm64_local_label_name(ctx->fn, ins->data.label.name, label, sizeof(label));
	if (!full)
		return false;
	fprintf(ctx->out, "%s:\n", full);
	return true;
}

static bool arm64_emit_jump(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (!ctx || !ctx->fn || !ins || !ins->data.jump.target)
		return false;
	if (!arm64_spill_value_stack(ctx))
		return false;
	if (!arm64_record_stack_snapshot(ctx, ins->line, ins->data.jump.target))
		return false;
	char label[512];
	const char *full = arm64_local_label_name(ctx->fn, ins->data.jump.target, label, sizeof(label));
	if (!full)
		return false;
	fprintf(ctx->out, "    b %s\n", full);
	return true;
}

static bool arm64_emit_addr_param(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	uint32_t index = ins->data.param.index;
	bool wants_vararg_base = ctx->fn->is_varargs && index == ctx->fn->param_count;
	if (!wants_vararg_base && index >= ctx->fn->param_count)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "addr_param index %u out of range", index);
		return false;
	}
	for (size_t i = 0; i < ctx->stack_size; ++i)
	{
		if (!arm64_force_stack_slot(ctx, &ctx->stack[i], i))
			return false;
	}
	const char *dst_reg = ARM64_SCRATCH_GP_REGS64[0];
	if (wants_vararg_base)
	{
		if (!ctx->has_vararg_area)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "vararg base requested in non-varargs function");
			return false;
		}
		size_t offset = ctx->vararg_area_offset + ctx->vararg_gp_start * 8;
		if (!arm64_emit_stack_address(ctx, ins->line, dst_reg, offset))
			return false;
	}
	else
	{
		size_t offset = ctx->param_offsets ? ctx->param_offsets[index] : 0;
		if (!arm64_emit_stack_address(ctx, ins->line, dst_reg, offset))
			return false;
	}
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
		if (!arm64_force_stack_slot(ctx, &ctx->stack[i], i))
			return false;
	}
	const char *dst_reg = ARM64_SCRATCH_GP_REGS64[0];
	size_t offset = ctx->local_offsets ? ctx->local_offsets[index] : 0;
	if (!arm64_emit_stack_address(ctx, ins->line, dst_reg, offset))
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

static bool arm64_emit_stack_alloc(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (!ctx || !ins)
		return false;
	if (!arm64_spill_value_stack(ctx))
		return false;
	size_t size_bytes = ins->data.stack_alloc.size_bytes;
	size_t alignment = ins->data.stack_alloc.alignment;
	if (alignment == 0)
		alignment = ARM64_STACK_ALIGNMENT;
	if (alignment < ARM64_STACK_ALIGNMENT)
		alignment = ARM64_STACK_ALIGNMENT;
	size_t aligned_size = align_up_size(size_bytes, alignment);
	if (!arm64_adjust_sp(ctx, aligned_size))
		return false;
	const char *dst_reg = ARM64_SCRATCH_GP_REGS64[1];
	fprintf(ctx->out, "    mov %s, sp\n", dst_reg);
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
		if (!arm64_force_stack_slot(ctx, &ctx->stack[i], i))
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
		if (!arm64_force_stack_slot(ctx, &ctx->stack[i], i))
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

static bool arm64_emit_float_binop(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	Arm64Value rhs;
	Arm64Value lhs;
	if (!function_stack_pop(ctx, &rhs) || !function_stack_pop(ctx, &lhs))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "binop requires two operands");
		return false;
	}
	if (!arm64_spill_value_stack(ctx))
		return false;
	CCValueType type = ins->data.binop.type;
	bool is_f32 = (type == CC_TYPE_F32);
	const char *lhs_reg = is_f32 ? "s0" : "d0";
	const char *rhs_reg = is_f32 ? "s1" : "d1";
	if (!arm64_materialize_fp(ctx, &lhs, lhs_reg, type))
		return false;
	if (!arm64_materialize_fp(ctx, &rhs, rhs_reg, type))
		return false;
	FILE *out = ctx->out;
	switch (ins->data.binop.op)
	{
	case CC_BINOP_ADD:
		fprintf(out, "    fadd %s, %s, %s\n", lhs_reg, lhs_reg, rhs_reg);
		break;
	case CC_BINOP_SUB:
		fprintf(out, "    fsub %s, %s, %s\n", lhs_reg, lhs_reg, rhs_reg);
		break;
	case CC_BINOP_MUL:
		fprintf(out, "    fmul %s, %s, %s\n", lhs_reg, lhs_reg, rhs_reg);
		break;
	case CC_BINOP_DIV:
		fprintf(out, "    fdiv %s, %s, %s\n", lhs_reg, lhs_reg, rhs_reg);
		break;
	default:
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend does not support floating-point binop %d", ins->data.binop.op);
		return false;
	}
	Arm64Value result;
	memset(&result, 0, sizeof(result));
	result.kind = ARM64_VALUE_REGISTER;
	result.type = type;
	result.is_unsigned = true;
	result.data.reg.name = lhs_reg;
	result.data.reg.is_w = is_f32;
	return function_stack_push(ctx, result);
}

static bool arm64_emit_binop(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (cc_value_type_is_float(ins->data.binop.type))
		return arm64_emit_float_binop(ctx, ins);
	Arm64Value rhs;
	Arm64Value lhs;
	if (!function_stack_pop(ctx, &rhs) || !function_stack_pop(ctx, &lhs))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "binop requires two operands");
		return false;
	}
	if (!arm64_spill_value_stack(ctx))
		return false;
	size_t result_size = arm64_type_size(ins->data.binop.type);
	if (result_size == 0)
		result_size = 8;
	bool use_w = (result_size <= 4);
	const char *dst_reg = use_w ? ARM64_SCRATCH_GP_REGS32[0] : ARM64_SCRATCH_GP_REGS64[0];
	const char *rhs_reg = use_w ? ARM64_SCRATCH_GP_REGS32[1] : ARM64_SCRATCH_GP_REGS64[1];
	const char *tmp_reg = use_w ? ARM64_SCRATCH_GP_REGS32[2] : ARM64_SCRATCH_GP_REGS64[2];
	if (!arm64_materialize_gp(ctx, &lhs, dst_reg, use_w))
		return false;
	if (!arm64_materialize_gp(ctx, &rhs, rhs_reg, use_w))
		return false;
	bool is_unsigned = ins->data.binop.is_unsigned || !cc_value_type_is_signed(ins->data.binop.type);
	FILE *out = ctx->out;
	switch (ins->data.binop.op)
	{
	case CC_BINOP_ADD:
		fprintf(out, "    add %s, %s, %s\n", dst_reg, dst_reg, rhs_reg);
		break;
	case CC_BINOP_SUB:
		fprintf(out, "    sub %s, %s, %s\n", dst_reg, dst_reg, rhs_reg);
		break;
	case CC_BINOP_MUL:
		fprintf(out, "    mul %s, %s, %s\n", dst_reg, dst_reg, rhs_reg);
		break;
	case CC_BINOP_DIV:
	{
		const char *instr = is_unsigned ? "udiv" : "sdiv";
		fprintf(out, "    %s %s, %s, %s\n", instr, dst_reg, dst_reg, rhs_reg);
		break;
	}
	case CC_BINOP_MOD:
	{
		const char *instr = is_unsigned ? "udiv" : "sdiv";
		fprintf(out, "    mov %s, %s\n", tmp_reg, dst_reg);
		fprintf(out, "    %s %s, %s, %s\n", instr, dst_reg, dst_reg, rhs_reg);
		fprintf(out, "    msub %s, %s, %s, %s\n", dst_reg, rhs_reg, dst_reg, tmp_reg);
		break;
	}
	case CC_BINOP_AND:
		fprintf(out, "    and %s, %s, %s\n", dst_reg, dst_reg, rhs_reg);
		break;
	case CC_BINOP_OR:
		fprintf(out, "    orr %s, %s, %s\n", dst_reg, dst_reg, rhs_reg);
		break;
	case CC_BINOP_XOR:
		fprintf(out, "    eor %s, %s, %s\n", dst_reg, dst_reg, rhs_reg);
		break;
	case CC_BINOP_SHL:
		fprintf(out, "    lsl %s, %s, %s\n", dst_reg, dst_reg, rhs_reg);
		break;
	case CC_BINOP_SHR:
		if (is_unsigned)
			fprintf(out, "    lsr %s, %s, %s\n", dst_reg, dst_reg, rhs_reg);
		else
			fprintf(out, "    asr %s, %s, %s\n", dst_reg, dst_reg, rhs_reg);
		break;
	default:
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend does not support binop %d", ins->data.binop.op);
		return false;
	}
	bool sign_extend = cc_value_type_is_signed(ins->data.binop.type) && !is_unsigned;
	arm64_narrow_integer_result(out, dst_reg, result_size, sign_extend);
	Arm64Value result;
	memset(&result, 0, sizeof(result));
	result.kind = ARM64_VALUE_REGISTER;
	result.type = ins->data.binop.type;
	result.is_unsigned = is_unsigned;
	result.data.reg.name = dst_reg;
	result.data.reg.is_w = use_w;
	return function_stack_push(ctx, result);
}

static bool arm64_emit_unop(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	Arm64Value operand;
	if (!function_stack_pop(ctx, &operand))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unary op requires operand on stack");
		return false;
	}

	if (!arm64_spill_value_stack(ctx))
		return false;

	if (cc_value_type_is_float(ins->data.unop.type))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend does not yet support floating-point unary ops");
		return false;
	}

	size_t result_size = arm64_type_size(ins->data.unop.type);
	bool use_w = (result_size <= 4);
	const char *dst_reg = use_w ? ARM64_SCRATCH_GP_REGS32[0] : ARM64_SCRATCH_GP_REGS64[0];
	if (!arm64_materialize_gp(ctx, &operand, dst_reg, use_w))
		return false;

	FILE *out = ctx->out;
	const char *final_reg = dst_reg;
	bool final_is_w = use_w;
	switch (ins->data.unop.op)
	{
	case CC_UNOP_NEG:
		fprintf(out, "    neg %s, %s\n", dst_reg, dst_reg);
		break;
	case CC_UNOP_BITNOT:
		fprintf(out, "    mvn %s, %s\n", dst_reg, dst_reg);
		break;
	case CC_UNOP_NOT:
	{
		const char *cmp_zero = use_w ? "wzr" : "xzr";
		const char *cmp_reg = dst_reg;
		const char *bool_reg = ARM64_SCRATCH_GP_REGS32[1];
		fprintf(out, "    cmp %s, %s\n", cmp_reg, cmp_zero);
		fprintf(out, "    cset %s, eq\n", bool_reg);
		final_reg = bool_reg;
		final_is_w = true;
		break;
	}
	default:
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend does not support unary op %d", ins->data.unop.op);
		return false;
	}

	arm64_narrow_integer_result(out, final_reg, result_size, cc_value_type_is_signed(ins->data.unop.type));

	Arm64Value result;
	memset(&result, 0, sizeof(result));
	result.kind = ARM64_VALUE_REGISTER;
	result.type = ins->data.unop.type;
	result.is_unsigned = !cc_value_type_is_signed(result.type);
	result.data.reg.name = final_reg;
	result.data.reg.is_w = final_is_w;
	return function_stack_push(ctx, result);
}

static const char *arm64_compare_condition(CCCompareOp op, bool is_unsigned)
{
	switch (op)
	{
	case CC_COMPARE_EQ:
		return "eq";
	case CC_COMPARE_NE:
		return "ne";
	case CC_COMPARE_LT:
		return is_unsigned ? "lo" : "lt";
	case CC_COMPARE_LE:
		return is_unsigned ? "ls" : "le";
	case CC_COMPARE_GT:
		return is_unsigned ? "hi" : "gt";
	case CC_COMPARE_GE:
		return is_unsigned ? "hs" : "ge";
	default:
		return NULL;
	}
}

static bool arm64_emit_compare(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	Arm64Value rhs;
	Arm64Value lhs;
	if (!function_stack_pop(ctx, &rhs) || !function_stack_pop(ctx, &lhs))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "compare requires two operands");
		return false;
	}

	if (!arm64_spill_value_stack(ctx))
		return false;

	if (cc_value_type_is_float(ins->data.compare.type))
	{
		bool is_f32 = (ins->data.compare.type == CC_TYPE_F32);
		const char *lhs_fp = is_f32 ? "s0" : "d0";
		const char *rhs_fp = is_f32 ? "s1" : "d1";
		if (!arm64_materialize_fp(ctx, &lhs, lhs_fp, ins->data.compare.type))
			return false;
		if (!arm64_materialize_fp(ctx, &rhs, rhs_fp, ins->data.compare.type))
			return false;
		FILE *out = ctx->out;
		fprintf(out, "    fcmp %s, %s\n", lhs_fp, rhs_fp);
		const char *result_reg = ARM64_SCRATCH_GP_REGS32[0];
		const char *tmp_reg = ARM64_SCRATCH_GP_REGS32[1];
		switch (ins->data.compare.op)
		{
		case CC_COMPARE_EQ:
			fprintf(out, "    cset %s, eq\n", result_reg);
			break;
		case CC_COMPARE_NE:
			fprintf(out, "    cset %s, ne\n", result_reg);
			break;
		case CC_COMPARE_LT:
			fprintf(out, "    cset %s, lt\n", result_reg);
			break;
		case CC_COMPARE_LE:
			fprintf(out, "    cset %s, le\n", result_reg);
			break;
		case CC_COMPARE_GT:
			fprintf(out, "    cset %s, gt\n", result_reg);
			fprintf(out, "    cset %s, vs\n", tmp_reg);
			fprintf(out, "    orr %s, %s, %s\n", result_reg, result_reg, tmp_reg);
			break;
		case CC_COMPARE_GE:
			fprintf(out, "    cset %s, ge\n", result_reg);
			fprintf(out, "    cset %s, vs\n", tmp_reg);
			fprintf(out, "    orr %s, %s, %s\n", result_reg, result_reg, tmp_reg);
			break;
		default:
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported floating-point compare op %d", (int)ins->data.compare.op);
			return false;
		}

		Arm64Value result;
		memset(&result, 0, sizeof(result));
		result.kind = ARM64_VALUE_REGISTER;
		result.type = CC_TYPE_I1;
		result.is_unsigned = true;
		result.data.reg.name = result_reg;
		result.data.reg.is_w = true;
		return function_stack_push(ctx, result);
	}

	size_t operand_size = arm64_type_size(ins->data.compare.type);
	bool use_w = (operand_size <= 4);
	const char *lhs_reg = use_w ? ARM64_SCRATCH_GP_REGS32[0] : ARM64_SCRATCH_GP_REGS64[0];
	const char *rhs_reg = use_w ? ARM64_SCRATCH_GP_REGS32[1] : ARM64_SCRATCH_GP_REGS64[1];
	if (!arm64_materialize_gp(ctx, &lhs, lhs_reg, use_w))
		return false;
	if (!arm64_materialize_gp(ctx, &rhs, rhs_reg, use_w))
		return false;

	bool is_unsigned = ins->data.compare.is_unsigned || !cc_value_type_is_signed(ins->data.compare.type);
	const char *cond = arm64_compare_condition(ins->data.compare.op, is_unsigned);
	if (!cond)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "unsupported compare op %d", (int)ins->data.compare.op);
		return false;
	}

	FILE *out = ctx->out;
	fprintf(out, "    cmp %s, %s\n", lhs_reg, rhs_reg);
	const char *result_reg = ARM64_SCRATCH_GP_REGS32[2];
	fprintf(out, "    cset %s, %s\n", result_reg, cond);

	Arm64Value result;
	memset(&result, 0, sizeof(result));
	result.kind = ARM64_VALUE_REGISTER;
	result.type = CC_TYPE_I1;
	result.is_unsigned = true;
	result.data.reg.name = result_reg;
	result.data.reg.is_w = true;
	return function_stack_push(ctx, result);
}

static bool arm64_emit_branch(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (!ctx || !ctx->fn || !ins || !ins->data.branch.true_target || !ins->data.branch.false_target)
		return false;
	Arm64Value cond;
	if (!function_stack_pop(ctx, &cond))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "branch requires condition");
		return false;
	}
	if (!arm64_spill_value_stack(ctx))
		return false;
	if (!arm64_record_stack_snapshot(ctx, ins->line, ins->data.branch.true_target))
		return false;
	if (!arm64_record_stack_snapshot(ctx, ins->line, ins->data.branch.false_target))
		return false;
	size_t cond_size = arm64_type_size(cond.type);
	bool use_w = (cond_size <= 4);
	const char *cond_reg = use_w ? ARM64_SCRATCH_GP_REGS32[0] : ARM64_SCRATCH_GP_REGS64[0];
	if (!arm64_materialize_gp(ctx, &cond, cond_reg, use_w))
		return false;
	char true_label[512];
	char false_label[512];
	const char *true_full = arm64_local_label_name(ctx->fn, ins->data.branch.true_target, true_label, sizeof(true_label));
	const char *false_full = arm64_local_label_name(ctx->fn, ins->data.branch.false_target, false_label, sizeof(false_label));
	if (!true_full || !false_full)
		return false;
	FILE *out = ctx->out;
	fprintf(out, "    cmp %s, %s\n", cond_reg, use_w ? "wzr" : "xzr");
	fprintf(out, "    b.ne %s\n", true_full);
	fprintf(out, "    b %s\n", false_full);
	return true;
}

static bool arm64_emit_convert(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	Arm64Value value;
	if (!function_stack_pop(ctx, &value))
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "convert requires value on stack");
		return false;
	}
	if (!arm64_spill_value_stack(ctx))
		return false;
	CCConvertKind kind = ins->data.convert.kind;
	CCValueType from_type = ins->data.convert.from_type;
	CCValueType to_type = ins->data.convert.to_type;
	size_t from_size = arm64_type_size(from_type);
	size_t to_size = arm64_type_size(to_type);
	bool from_is_float = cc_value_type_is_float(from_type);
	bool to_is_float = cc_value_type_is_float(to_type);
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
		if (from_is_float && to_is_float && from_type != to_type)
		{
			const char *src_fp = (from_type == CC_TYPE_F32) ? "s0" : "d0";
			const char *dst_fp = (to_type == CC_TYPE_F32) ? "s0" : "d0";
			if (from_type == CC_TYPE_F32)
				fprintf(out, "    fmov %s, %s\n", src_fp, wreg);
			else
				fprintf(out, "    fmov %s, %s\n", src_fp, xreg);
			fprintf(out, "    fcvt %s, %s\n", dst_fp, src_fp);
			if (to_type == CC_TYPE_F32)
				fprintf(out, "    fmov %s, %s\n", wreg, dst_fp);
			else
				fprintf(out, "    fmov %s, %s\n", xreg, dst_fp);
			break;
		}
		if (from_size != to_size)
		{
			if (from_is_float || to_is_float)
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "bitcast between floating and differently-sized types unsupported");
				return false;
			}
			if (from_size < to_size)
			{
				if (from_size == 1)
					fprintf(out, "    uxtb %s, %s\n", wreg, wreg);
				else if (from_size == 2)
					fprintf(out, "    uxth %s, %s\n", wreg, wreg);
				if (to_size > 4)
					fprintf(out, "    uxtw %s, %s\n", xreg, wreg);
			}
			else
			{
				if (to_size == 4)
				{
					/* writing to w-register truncates automatically */
				}
				else if (to_size == 2)
					fprintf(out, "    uxth %s, %s\n", wreg, wreg);
				else if (to_size == 1)
					fprintf(out, "    uxtb %s, %s\n", wreg, wreg);
				else
				{
					emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "bitcast truncation to %zu bytes unsupported", to_size);
					return false;
				}
			}
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
	const bool is_indirect = (ins->kind == CC_INSTR_CALL_INDIRECT) || (ins->data.call.symbol == NULL);
	size_t arg_count = ins->data.call.arg_count;
	size_t required_values = arg_count + (is_indirect ? 1 : 0);
	if (ctx->stack_size < required_values)
	{
		emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "call '%s' missing arguments", ins->data.call.symbol ? ins->data.call.symbol : "<indirect>");
		return false;
	}
	Arm64Value target_value;
	bool have_target_value = false;
	if (is_indirect)
	{
		if (!function_stack_pop(ctx, &target_value))
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "call '<indirect>' missing function pointer");
			return false;
		}
		have_target_value = true;
	}
	size_t gp_used = 0;
	size_t fp_used = 0;
	Arm64ArgLocation *locations = NULL;
	bool success = false;
	size_t stack_spill_total = 0;
	size_t arg_base = ctx->stack_size - arg_count;
	for (size_t i = 0; i < arg_base; ++i)
	{
		if (!arm64_force_stack_slot(ctx, &ctx->stack[i], i))
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
		bool is_vararg_arg = call_declares_varargs && (i >= fixed_params);
		Arm64ArgLocation *loc = locations ? &locations[i] : NULL;

		if (is_float)
		{
			if (fp_used >= sizeof(ARM64_FP_REGS) / sizeof(ARM64_FP_REGS[0]))
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "floating argument spill not supported on arm64 backend");
				goto cleanup;
			}
			const bool use_s = (arg_type == CC_TYPE_F32);
			const char *reg64 = ARM64_FP_REGS[fp_used];
			char reg32_buf[8];
			const char *target_reg = reg64;
			if (use_s)
			{
				snprintf(reg32_buf, sizeof(reg32_buf), "s%s", reg64 + 1);
				target_reg = reg32_buf;
			}
			if (!arm64_materialize_fp(ctx, value, target_reg, arg_type))
				goto cleanup;
			if (loc)
			{
				loc->uses_fp_reg = true;
				loc->fp_reg_index = fp_used;
				loc->fp_is_s = use_s;
				loc->type = arg_type;
				loc->type_is_signed = false;
			}
			if (is_vararg_arg)
			{
				if (gp_used >= sizeof(ARM64_GP_REGS64) / sizeof(ARM64_GP_REGS64[0]))
				{
					emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend cannot mirror vararg float into GP register (ran out of x regs)");
					goto cleanup;
				}
				const size_t gp_index = gp_used++;
				const char *gp_reg64 = ARM64_GP_REGS64[gp_index];
				const char *gp_reg32 = ARM64_GP_REGS32[gp_index];
				if (use_s)
					fprintf(ctx->out, "    fmov %s, %s\n", gp_reg32, target_reg);
				else
					fprintf(ctx->out, "    fmov %s, %s\n", gp_reg64, target_reg);
				if (loc)
				{
					loc->uses_gp_reg = true;
					loc->gp_is_w = false;
					loc->gp_reg_index = gp_index;
					loc->type = arg_type;
					loc->type_is_signed = false;
				}
			}
			fp_used++;
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
			if (!loc || (!loc->uses_gp_reg && !loc->uses_fp_reg))
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend does not yet support spilling stack-only varargs");
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
			if (value_size < 8)
				value_size = 8;

			loc->spill_offset = align_up_size(spill_cursor, 8);
			loc->spill_size = value_size;
			spill_cursor = loc->spill_offset + loc->spill_size;
		}

		stack_spill_total = align_up_size(spill_cursor, ARM64_STACK_ALIGNMENT);
		if (stack_spill_total > 0)
		{
			fprintf(ctx->out, "    sub sp, sp, #%zu\n", stack_spill_total);
			for (size_t i = fixed_params; i < arg_count; ++i)
			{
				Arm64ArgLocation *loc = &locations[i];
				if (!loc)
					continue;

				if (loc->uses_gp_reg)
				{
					const char *xreg = ARM64_GP_REGS64[loc->gp_reg_index];
					const char *wreg = ARM64_GP_REGS32[loc->gp_reg_index];
					if (loc->gp_is_w && loc->type_is_signed)
						fprintf(ctx->out, "    sxtw %s, %s\n", xreg, wreg);

					if (loc->spill_offset == 0)
						fprintf(ctx->out, "    str %s, [sp]\n", xreg);
					else
						fprintf(ctx->out, "    str %s, [sp, #%zu]\n", xreg, loc->spill_offset);
				}
				else if (loc->uses_fp_reg)
				{
					const char *dreg = ARM64_FP_REGS[loc->fp_reg_index];
					if (loc->spill_offset == 0)
						fprintf(ctx->out, "    str %s, [sp]\n", dreg);
					else
						fprintf(ctx->out, "    str %s, [sp, #%zu]\n", dreg, loc->spill_offset);
				}
			}
		}
	}

	if (ins->data.call.symbol && !is_indirect)
	{
		char symbol_buf[256];
		const char *sym = symbol_with_underscore(ins->data.call.symbol, symbol_buf, sizeof(symbol_buf));
		fprintf(ctx->out, "    bl %s\n", sym ? sym : ins->data.call.symbol);
		symbol_set_add(&ctx->module->externs, sym ? sym : ins->data.call.symbol);
	}
	else
	{
		const char *target_reg = "x16";
		if (!have_target_value)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "internal error: missing indirect target");
			goto cleanup;
		}
		if (!arm64_materialize_gp(ctx, &target_value, target_reg, false))
			goto cleanup;
		fprintf(ctx->out, "    blr %s\n", target_reg);
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
	if (ctx->dynamic_sp_offset > 0)
	{
		fprintf(ctx->out, "    add sp, sp, #%zu\n", ctx->dynamic_sp_offset);
		ctx->dynamic_sp_offset = 0;
	}
	fprintf(ctx->out, "    mov sp, x29\n");
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
	case CC_INSTR_LOAD_GLOBAL:
		return arm64_emit_load_global(ctx, ins);
	case CC_INSTR_STORE_GLOBAL:
		return arm64_emit_store_global(ctx, ins);
	case CC_INSTR_ADDR_GLOBAL:
		return arm64_emit_addr_global(ctx, ins);
	case CC_INSTR_ADDR_PARAM:
		return arm64_emit_addr_param(ctx, ins);
	case CC_INSTR_ADDR_LOCAL:
		return arm64_emit_addr_local(ctx, ins);
	case CC_INSTR_LOAD_INDIRECT:
		return arm64_emit_load_indirect(ctx, ins);
	case CC_INSTR_STORE_INDIRECT:
		return arm64_emit_store_indirect(ctx, ins);
	case CC_INSTR_STACK_ALLOC:
		return arm64_emit_stack_alloc(ctx, ins);
	case CC_INSTR_LABEL:
		return arm64_emit_label(ctx, ins);
	case CC_INSTR_JUMP:
		return arm64_emit_jump(ctx, ins);
	case CC_INSTR_BRANCH:
		return arm64_emit_branch(ctx, ins);
	case CC_INSTR_CALL:
		return arm64_emit_call(ctx, ins);
	case CC_INSTR_CALL_INDIRECT:
		return arm64_emit_call(ctx, ins);
	case CC_INSTR_BINOP:
		return arm64_emit_binop(ctx, ins);
	case CC_INSTR_UNOP:
		return arm64_emit_unop(ctx, ins);
	case CC_INSTR_COMPARE:
		return arm64_emit_compare(ctx, ins);
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

static bool arm64_emit_literal_function(Arm64FunctionContext *ctx)
{
	if (!ctx || !ctx->fn)
		return false;
	if (!ctx->fn->literal_lines || ctx->fn->literal_count == 0)
	{
		const char *name = (ctx->fn && ctx->fn->name) ? ctx->fn->name : "<literal>";
		emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "literal function '%s' has no body", name);
		return false;
	}
	char symbol_buf[256];
	const char *fn_symbol = symbol_with_underscore(ctx->fn->name, symbol_buf, sizeof(symbol_buf));
	fprintf(ctx->out, ".globl %s\n", fn_symbol ? fn_symbol : ctx->fn->name);
	fprintf(ctx->out, ".p2align 2\n");
	fprintf(ctx->out, "%s:\n", fn_symbol ? fn_symbol : ctx->fn->name);
	for (size_t i = 0; i < ctx->fn->literal_count; ++i)
	{
		const char *line = ctx->fn->literal_lines[i] ? ctx->fn->literal_lines[i] : "";
		fprintf(ctx->out, "%s\n", line);
	}
	return true;
}

static bool arm64_emit_function(Arm64FunctionContext *ctx)
{
	if (!ctx || !ctx->fn)
		return false;

	if (ctx->fn->is_literal)
		return arm64_emit_literal_function(ctx);

	ctx->param_offsets = NULL;
	ctx->param_types = NULL;
	ctx->local_offsets = NULL;
	ctx->local_types = NULL;
	ctx->frame_size = 0;
	ctx->saw_return = false;
	ctx->dynamic_sp_offset = 0;
	ctx->stack_snapshots = NULL;
	ctx->stack_snapshot_count = 0;
	ctx->stack_snapshot_capacity = 0;
	ctx->has_vararg_area = false;
	ctx->vararg_area_offset = 0;
	ctx->vararg_gp_start = 0;

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

	if (ctx->fn->is_varargs)
	{
		ctx->has_vararg_area = true;
		ctx->vararg_area_offset = slot_index * 8;
		// Reserve space for 8 GPRs (x0-x7) AND 8 FPRs (d0-d7)
		slot_index += 8; // x0-x7
		slot_index += 8; // d0-d7
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

	size_t gp_param_index = 0;
	size_t fp_param_index = 0;
	for (size_t i = 0; i < param_count; ++i)
	{
		CCValueType param_type = ctx->param_types[i];
		bool is_float = cc_value_type_is_float(param_type);
		size_t offset = ctx->param_offsets[i];
		size_t addr = arm64_frame_offset(ctx, offset);
		size_t size_bytes = arm64_type_size(param_type);
		if (is_float)
		{
			if (fp_param_index >= sizeof(ARM64_FP_REGS) / sizeof(ARM64_FP_REGS[0]))
			{

				emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend only supports up to 8 floating parameters presently");
				goto fail;
			}
			if (size_bytes == 4)
				fprintf(ctx->out, "    str %s, [sp, #%zu]\n", ARM64_FP_REGS32[fp_param_index], addr);
			else
				fprintf(ctx->out, "    str %s, [sp, #%zu]\n", ARM64_FP_REGS[fp_param_index], addr);
			fp_param_index++;
			continue;
		}

		if (gp_param_index >= sizeof(ARM64_GP_REGS64) / sizeof(ARM64_GP_REGS64[0]))
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend only supports up to 8 integer parameters presently");
			goto fail;
		}
		if (size_bytes == 1)
			fprintf(ctx->out, "    strb %s, [sp, #%zu]\n", ARM64_GP_REGS32[gp_param_index], addr);
		else if (size_bytes == 2)
			fprintf(ctx->out, "    strh %s, [sp, #%zu]\n", ARM64_GP_REGS32[gp_param_index], addr);
		else if (size_bytes == 4)
			fprintf(ctx->out, "    str %s, [sp, #%zu]\n", ARM64_GP_REGS32[gp_param_index], addr);
		else
			fprintf(ctx->out, "    str %s, [sp, #%zu]\n", ARM64_GP_REGS64[gp_param_index], addr);
		gp_param_index++;
	}

		if (ctx->has_vararg_area)
		{
			ctx->vararg_gp_start = gp_param_index;
			size_t base_offset = ctx->vararg_area_offset;
			size_t gp_reg_count = sizeof(ARM64_GP_REGS64) / sizeof(ARM64_GP_REGS64[0]);
			
			// Spill General Purpose Registers (x0-x7)
			for (size_t reg = 0; reg < gp_reg_count; ++reg)
			{
				size_t addr = arm64_frame_offset(ctx, base_offset + reg * 8);
				fprintf(ctx->out, "    str %s, [sp, #%zu]\n", ARM64_GP_REGS64[reg], addr);
			}
			
			// Spill Floating Point Registers (d0-d7)
			// These follow immediately after the 8 GPRs (8 * 8 = 64 bytes offset)
			size_t fp_base_offset = base_offset + (gp_reg_count * 8);
			size_t fp_reg_count = sizeof(ARM64_FP_REGS) / sizeof(ARM64_FP_REGS[0]);
			for (size_t reg = 0; reg < fp_reg_count; ++reg)
			{
				size_t addr = arm64_frame_offset(ctx, fp_base_offset + reg * 8);
				fprintf(ctx->out, "    str %s, [sp, #%zu]\n", ARM64_FP_REGS[reg], addr);
			}
		}

	for (size_t i = 0; i < ctx->fn->instruction_count; ++i)
	{
		if (!arm64_emit_instruction(ctx, &ctx->fn->instructions[i]))
			goto fail;
	}

	if (!ctx->saw_return)
	{
		if (ctx->fn->return_type != CC_TYPE_VOID)
		{
			bool use_w = (ctx->fn->return_type == CC_TYPE_I32 || ctx->fn->return_type == CC_TYPE_U32 || ctx->fn->return_type == CC_TYPE_I16 || ctx->fn->return_type == CC_TYPE_U16 || ctx->fn->return_type == CC_TYPE_I8 || ctx->fn->return_type == CC_TYPE_U8 || ctx->fn->return_type == CC_TYPE_I1);
			fprintf(ctx->out, "    mov %s, %s\n", use_w ? "w0" : "x0", use_w ? "wzr" : "xzr");
		}
		if (ctx->dynamic_sp_offset > 0)
		{
			fprintf(ctx->out, "    add sp, sp, #%zu\n", ctx->dynamic_sp_offset);
			ctx->dynamic_sp_offset = 0;
		}
		fprintf(ctx->out, "    mov sp, x29\n");
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
	ctx->dynamic_sp_offset = 0;
	arm64_clear_stack_snapshots(ctx);

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
	ctx->dynamic_sp_offset = 0;
	arm64_clear_stack_snapshots(ctx);
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
	arm64_vararg_cache_load(&ctx);

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
		arm64_vararg_cache_destroy(&ctx);
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
			arm64_vararg_cache_destroy(&ctx);
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
	arm64_vararg_cache_destroy(&ctx);
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
