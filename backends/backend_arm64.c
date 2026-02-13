#include "cc/backend.h"
#include "cc/bytecode.h"
#include "cc/diagnostics.h"

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ARM64_STACK_ALIGNMENT 16

static const char *const ARM64_GP_REGS64[] = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
static const char *const ARM64_GP_REGS32[] = {"w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7"};
static const char *const ARM64_FP_REGS[] = {"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"};
static const char *const ARM64_FP_REGS32[] = {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"};
static const char *const ARM64_SCRATCH_GP_REGS64[] = {"x9", "x10", "x11", "x12"};
static const char *const ARM64_SCRATCH_GP_REGS32[] = {"w9", "w10", "w11", "w12"};

#define ARM64_VARARG_PTR_REG "x15"

#define ARM64_FRAME_REG "x27"
#define ARM64_FRAME_REG32 "w27"

typedef enum
{
	ARM64_OBJECT_MACHO = 0,
	ARM64_OBJECT_ELF = 1,
	ARM64_OBJECT_COFF = 2
} Arm64ObjectFormat;

typedef struct
{
	Arm64ObjectFormat format;
	const char *banner;
	const char *text_section;
	const char *data_section;
	const char *const_section;
	const char *cstring_section;
	const char *string_label_hint_format;
	const char *string_label_auto_format;
	const char *target_os_option;
	bool prefix_symbols_with_underscore;
	const char *local_label_prefix;
	bool emit_build_version;
	const char *build_version_directive;
} Arm64BackendConfig;

static const Arm64BackendConfig kArm64ConfigMachO = {
	.format = ARM64_OBJECT_MACHO,
	.banner = "macOS",
	.text_section = ".section __TEXT,__text,regular,pure_instructions",
	.data_section = ".section __DATA,__data",
	.const_section = ".section __DATA,__const",
	.cstring_section = ".section __TEXT,__cstring",
	.string_label_hint_format = "_%s__%s",
	.string_label_auto_format = "L_str%zu",
	.target_os_option = "macos",
	.prefix_symbols_with_underscore = true,
	.local_label_prefix = "L",
	.emit_build_version = true,
	.build_version_directive = ".build_version macos, 15, 0",
};

static const Arm64BackendConfig kArm64ConfigElf = {
	.format = ARM64_OBJECT_ELF,
	.banner = "Linux/ELF",
	.text_section = ".text",
	.data_section = ".data",
	.const_section = ".section .rodata",
	.cstring_section = ".section .rodata.str1.1,\"aMS\",@progbits,1",
	.string_label_hint_format = ".L%s__%s",
	.string_label_auto_format = ".Lstr%zu",
	.target_os_option = "linux",
	.prefix_symbols_with_underscore = false,
	.local_label_prefix = ".L",
	.emit_build_version = false,
	.build_version_directive = NULL,
};

static const Arm64BackendConfig kArm64ConfigCoff = {
	.format = ARM64_OBJECT_COFF,
	.banner = "Windows/COFF",
	.text_section = ".text",
	.data_section = ".data",
	.const_section = ".section .rdata,\"dr\"",
	.cstring_section = ".section .rdata,\"dr\"",
	.string_label_hint_format = ".L%s__%s",
	.string_label_auto_format = ".Lstr%zu",
	.target_os_option = "windows",
	.prefix_symbols_with_underscore = false,
	.local_label_prefix = ".L",
	.emit_build_version = false,
	.build_version_directive = NULL,
};

typedef struct
{
	char *label;
	char *lookup_name;
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
	const CCFunction *fn;
	char *alias;
} Arm64FunctionAlias;

typedef struct
{
	char *original;
	char *alias;
} Arm64LabelAlias;

typedef struct
{
	char *symbol;
	size_t fixed_param_count;
} Arm64VarargEntry;

typedef struct
{
	char *symbol;
	char *lookup_name;
	uint8_t *encoded_bytes;
	size_t length;
	uint32_t key;
	char desc_label[32];
	char str_label[32];
	char stub_label[32];
} Arm64ObfEntry;

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
	const Arm64BackendConfig *config;
	CCDiagnosticSink *sink;
	Arm64StringTable strings;
	Arm64SymbolSet externs;
	Arm64VarargEntry *vararg_cache;
	size_t vararg_count;
	size_t vararg_capacity;
	bool vararg_cache_loaded;
	size_t string_counter;
	bool keep_debug_names;
	bool prefer_local_hidden_symbols;
	bool obfuscate_calls;
	uint32_t obfuscate_seed;
	size_t next_function_id;
	size_t hidden_symbol_counter;
	Arm64FunctionAlias *hidden_fn_aliases;
	size_t hidden_fn_alias_count;
	size_t hidden_fn_alias_capacity;
	Arm64ObfEntry *obf_entries;
	size_t obf_entry_count;
	size_t obf_entry_capacity;
	size_t obf_entry_id_counter;
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
	bool has_vararg_area;
	size_t vararg_area_offset;
	size_t vararg_gp_start;
	Arm64StackSnapshot *stack_snapshots;
	size_t stack_snapshot_count;
	size_t stack_snapshot_capacity;
	uint32_t current_loc_file;
	uint32_t current_loc_line;
	uint32_t current_loc_column;
	size_t function_id;
	const char *symbol_name;
	bool obfuscate_labels;
	bool prefix_labels;
	Arm64LabelAlias *label_aliases;
	size_t label_alias_count;
	size_t label_alias_capacity;
	size_t next_label_id;
	size_t obfuscate_call_counter;
} Arm64FunctionContext;

static void arm64_vararg_cache_load(Arm64ModuleContext *ctx);
static void arm64_vararg_cache_destroy(Arm64ModuleContext *ctx);
static const Arm64VarargEntry *arm64_vararg_cache_lookup(const Arm64ModuleContext *ctx, const char *symbol);
static bool symbol_set_add(Arm64SymbolSet *set, const char *symbol);
static Arm64ObfEntry *arm64_obf_get_entry(Arm64ModuleContext *ctx, const char *symbol);
static bool arm64_emit_obf_support(Arm64ModuleContext *ctx);
static void arm64_obf_entries_destroy(Arm64ModuleContext *ctx);
static uint32_t arm64_obfuscate_mix(uint32_t v);
static uint32_t arm64_obfuscate_next(Arm64FunctionContext *ctx);
static const char *arm64_obfuscate_select_register(Arm64FunctionContext *ctx);
static const char *arm64_format_symbol(const Arm64ModuleContext *ctx, const char *name,
									   char *buffer, size_t buffer_size);
static void arm64_emit_symbol_address(const Arm64ModuleContext *ctx, FILE *out,
									  const char *symbol, const char *dst_reg);

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
	bool uses_stack;
	size_t stack_offset;
	size_t stack_size;
} Arm64ArgLocation;

static bool arm64_spill_register_value(Arm64FunctionContext *ctx, Arm64Value *value, size_t stack_index);
static bool arm64_force_stack_slot(Arm64FunctionContext *ctx, Arm64Value *value, size_t stack_index);

static void arm64_write_quoted(FILE *out, const char *text)
{
	if (!out)
		return;
	fputc('"', out);
	if (text)
	{
		for (const char *p = text; *p; ++p)
		{
			if (*p == '"' || *p == '\\')
				fputc('\\', out);
			fputc(*p, out);
		}
	}
	fputc('"', out);
}

static void arm64_split_path(const char *path, char *dir, size_t dirsz,
							 char *file, size_t filesz)
{
	if (dir && dirsz)
		dir[0] = '\0';
	if (file && filesz)
		file[0] = '\0';
	if (!path || !*path)
		return;
	const char *last_sep = NULL;
	for (const char *p = path; *p; ++p)
	{
		if (*p == '/' || *p == '\\')
			last_sep = p;
	}
	if (!last_sep)
	{
		if (file && filesz)
			snprintf(file, filesz, "%s", path);
		return;
	}
	if (dir && dirsz)
	{
		size_t len = (size_t)(last_sep - path);
		if (len >= dirsz)
			len = dirsz - 1;
		memcpy(dir, path, len);
		dir[len] = '\0';
	}
	if (file && filesz)
		snprintf(file, filesz, "%s", last_sep + 1);
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

static const CCFunction *module_find_function(const CCModule *module, const char *name)
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

static size_t align_up_size(size_t value, size_t alignment)
{
	if (alignment == 0)
		return value;
	size_t remainder = value % alignment;
	if (remainder == 0)
		return value;
	return value + (alignment - remainder);
}

static size_t arm64_assign_stack_slot(size_t *cursor, size_t size_bytes)
{
	if (!cursor)
		return 0;
	size_t slot_size = size_bytes ? size_bytes : 8;
	if (slot_size <= 8)
		slot_size = 8;
	else
		slot_size = align_up_size(slot_size, 8);
	size_t offset = align_up_size(*cursor, 8);
	*cursor = offset + slot_size;
	return offset;
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

static void hidden_function_aliases_destroy(Arm64ModuleContext *ctx)
{
	if (!ctx || !ctx->hidden_fn_aliases)
		return;
	for (size_t i = 0; i < ctx->hidden_fn_alias_count; ++i)
	{
		free(ctx->hidden_fn_aliases[i].alias);
		ctx->hidden_fn_aliases[i].alias = NULL;
		ctx->hidden_fn_aliases[i].fn = NULL;
	}
	free(ctx->hidden_fn_aliases);
	ctx->hidden_fn_aliases = NULL;
	ctx->hidden_fn_alias_count = 0;
	ctx->hidden_fn_alias_capacity = 0;
}

static bool arm64_ensure_hidden_alias_capacity(Arm64ModuleContext *ctx, size_t desired)
{
	if (!ctx)
		return false;
	if (ctx->hidden_fn_alias_capacity >= desired)
		return true;
	size_t new_capacity = ctx->hidden_fn_alias_capacity ? ctx->hidden_fn_alias_capacity * 2 : 4;
	while (new_capacity < desired)
		new_capacity *= 2;
	Arm64FunctionAlias *grown = (Arm64FunctionAlias *)realloc(ctx->hidden_fn_aliases, new_capacity * sizeof(Arm64FunctionAlias));
	if (!grown)
		return false;
	for (size_t i = ctx->hidden_fn_alias_capacity; i < new_capacity; ++i)
	{
		grown[i].fn = NULL;
		grown[i].alias = NULL;
	}
	ctx->hidden_fn_aliases = grown;
	ctx->hidden_fn_alias_capacity = new_capacity;
	return true;
}

static const char *arm64_module_function_symbol(Arm64ModuleContext *ctx, const CCFunction *fn)
{
	if (!ctx || !fn)
		return fn ? fn->name : NULL;
	if (ctx->keep_debug_names || !fn->is_hidden)
		return fn->name;
	for (size_t i = 0; i < ctx->hidden_fn_alias_count; ++i)
	{
		if (ctx->hidden_fn_aliases[i].fn == fn)
			return ctx->hidden_fn_aliases[i].alias;
	}
	if (!arm64_ensure_hidden_alias_capacity(ctx, ctx->hidden_fn_alias_count + 1))
		return fn->name;
	size_t id = ++ctx->hidden_symbol_counter;
	char buffer[64];
	const char *prefix = ctx->prefer_local_hidden_symbols ? "Lcc_hidden_fn" : "__cc_hidden_fn";
	snprintf(buffer, sizeof(buffer), "%s%zu", prefix, id);
	char *alias = arm64_strdup(buffer);
	if (!alias)
		return fn->name;
	ctx->hidden_fn_aliases[ctx->hidden_fn_alias_count].fn = fn;
	ctx->hidden_fn_aliases[ctx->hidden_fn_alias_count].alias = alias;
	ctx->hidden_fn_alias_count++;
	return alias;
}

static const char *arm64_module_symbol_alias(Arm64ModuleContext *ctx, const char *symbol)
{
	if (!ctx || !symbol)
		return symbol;
	const CCFunction *fn = module_find_function(ctx->module, symbol);
	if (!fn)
		return symbol;
	const char *mapped = arm64_module_function_symbol(ctx, fn);
	return mapped ? mapped : symbol;
}

static void arm64_label_aliases_destroy(Arm64FunctionContext *ctx)
{
	if (!ctx || !ctx->label_aliases)
		return;
	for (size_t i = 0; i < ctx->label_alias_count; ++i)
	{
		free(ctx->label_aliases[i].original);
		free(ctx->label_aliases[i].alias);
		ctx->label_aliases[i].original = NULL;
		ctx->label_aliases[i].alias = NULL;
	}
	free(ctx->label_aliases);
	ctx->label_aliases = NULL;
	ctx->label_alias_count = 0;
	ctx->label_alias_capacity = 0;
}

static bool arm64_ensure_label_alias_capacity(Arm64FunctionContext *ctx, size_t desired)
{
	if (!ctx)
		return false;
	if (ctx->label_alias_capacity >= desired)
		return true;
	size_t new_capacity = ctx->label_alias_capacity ? ctx->label_alias_capacity * 2 : 8;
	while (new_capacity < desired)
		new_capacity *= 2;
	Arm64LabelAlias *grown = (Arm64LabelAlias *)realloc(ctx->label_aliases, new_capacity * sizeof(Arm64LabelAlias));
	if (!grown)
		return false;
	for (size_t i = ctx->label_alias_capacity; i < new_capacity; ++i)
	{
		grown[i].original = NULL;
		grown[i].alias = NULL;
	}
	ctx->label_aliases = grown;
	ctx->label_alias_capacity = new_capacity;
	return true;
}

static const char *arm64_alias_label(Arm64FunctionContext *ctx, const char *original)
{
	if (!ctx || !original)
		return original;
	if (!ctx->obfuscate_labels)
		return original;
	for (size_t i = 0; i < ctx->label_alias_count; ++i)
	{
		if (ctx->label_aliases[i].original && strcmp(ctx->label_aliases[i].original, original) == 0)
			return ctx->label_aliases[i].alias;
	}
	if (!arm64_ensure_label_alias_capacity(ctx, ctx->label_alias_count + 1))
		return original;
	char buffer[64];
	snprintf(buffer, sizeof(buffer), "Lcc_label_f%zu_%zu", ctx->function_id, ctx->next_label_id++);
	char *alias = arm64_strdup(buffer);
	char *original_copy = arm64_strdup(original);
	if (!alias || !original_copy)
	{
		free(alias);
		free(original_copy);
		return original;
	}
	ctx->label_aliases[ctx->label_alias_count].original = original_copy;
	ctx->label_aliases[ctx->label_alias_count].alias = alias;
	ctx->label_alias_count++;
	return alias;
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

static bool option_is_enabled(const char *value)
{
	if (!value || *value == '\0')
		return false;
	if (strcmp(value, "0") == 0)
		return false;
	if (equals_ignore_case(value, "false") || equals_ignore_case(value, "off"))
		return false;
	return true;
}

static bool arm64_obf_ensure_capacity(Arm64ModuleContext *ctx, size_t desired)
{
	if (!ctx)
		return false;
	if (ctx->obf_entry_capacity >= desired)
		return true;
	size_t new_capacity = ctx->obf_entry_capacity ? ctx->obf_entry_capacity * 2 : 4;
	while (new_capacity < desired)
		new_capacity *= 2;
	Arm64ObfEntry *grown = (Arm64ObfEntry *)realloc(ctx->obf_entries, new_capacity * sizeof(Arm64ObfEntry));
	if (!grown)
		return false;
	ctx->obf_entries = grown;
	ctx->obf_entry_capacity = new_capacity;
	return true;
}

static void arm64_obf_entry_destroy(Arm64ObfEntry *entry)
{
	if (!entry)
		return;
	free(entry->symbol);
	free(entry->lookup_name);
	free(entry->encoded_bytes);
	entry->symbol = NULL;
	entry->lookup_name = NULL;
	entry->encoded_bytes = NULL;
}

static void arm64_obf_entries_destroy(Arm64ModuleContext *ctx)
{
	if (!ctx || !ctx->obf_entries)
		return;
	for (size_t i = 0; i < ctx->obf_entry_count; ++i)
		arm64_obf_entry_destroy(&ctx->obf_entries[i]);
	free(ctx->obf_entries);
	ctx->obf_entries = NULL;
	ctx->obf_entry_count = 0;
	ctx->obf_entry_capacity = 0;
	ctx->obf_entry_id_counter = 0;
}

static Arm64ObfEntry *arm64_obf_get_entry(Arm64ModuleContext *ctx, const char *symbol)
{
	if (!ctx || !symbol)
		return NULL;
	for (size_t i = 0; i < ctx->obf_entry_count; ++i)
	{
		if (ctx->obf_entries[i].symbol && strcmp(ctx->obf_entries[i].symbol, symbol) == 0)
			return &ctx->obf_entries[i];
	}
	if (!arm64_obf_ensure_capacity(ctx, ctx->obf_entry_count + 1))
		return NULL;
	Arm64ObfEntry *entry = &ctx->obf_entries[ctx->obf_entry_count++];
	memset(entry, 0, sizeof(*entry));
	const char *lookup = (symbol[0] == '_') ? symbol + 1 : symbol;
	entry->symbol = arm64_strdup(symbol);
	entry->lookup_name = arm64_strdup(lookup);
	if (!entry->symbol || !entry->lookup_name)
	{
		arm64_obf_entry_destroy(entry);
		ctx->obf_entry_count--;
		return NULL;
	}
	entry->length = strlen(entry->lookup_name);
	entry->encoded_bytes = (uint8_t *)malloc(entry->length ? entry->length : 1);
	if (!entry->encoded_bytes)
	{
		arm64_obf_entry_destroy(entry);
		ctx->obf_entry_count--;
		return NULL;
	}
	uint32_t raw = arm64_obfuscate_mix((uint32_t)ctx->obf_entry_id_counter * 0x9e3779b1u ^ ctx->obfuscate_seed);
	uint32_t key = raw & 0xFFu;
	if (key == 0)
		key = 0x5Au;
	entry->key = key;
	for (size_t i = 0; i < entry->length; ++i)
		entry->encoded_bytes[i] = ((uint8_t)entry->lookup_name[i]) ^ (uint8_t)key;
	size_t id = ctx->obf_entry_id_counter++;
	snprintf(entry->desc_label, sizeof(entry->desc_label), "Lcc_obf_desc%zu", id);
	snprintf(entry->str_label, sizeof(entry->str_label), "Lcc_obf_str%zu", id);
	snprintf(entry->stub_label, sizeof(entry->stub_label), "Lcc_obf_stub%zu", id);
	return entry;
}

static uint32_t arm64_obfuscate_mix(uint32_t v)
{
	v ^= v >> 17;
	v *= 0xed5ad4bbu;
	v ^= v >> 11;
	v *= 0xac4c1b51u;
	v ^= v >> 15;
	v *= 0x31848babu;
	v ^= v >> 14;
	return v ? v : 0x7f4a7c15u;
}

static uint32_t arm64_obfuscate_next(Arm64FunctionContext *ctx)
{
	uint32_t base = ctx->module->obfuscate_seed;
	base ^= (uint32_t)(ctx->function_id * 0x9e3779b1u);
	base ^= (uint32_t)(ctx->obfuscate_call_counter++ * 0x85ebca6bu);
	return arm64_obfuscate_mix(base);
}

static const char *arm64_obfuscate_select_register(Arm64FunctionContext *ctx)
{
	static const char *const regs[] = {"x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17"};
	uint32_t rnd = arm64_obfuscate_next(ctx);
	return regs[rnd % (sizeof(regs) / sizeof(regs[0]))];
}

static bool arm64_emit_obf_support(Arm64ModuleContext *ctx)
{
	if (!ctx || ctx->obf_entry_count == 0)
		return true;
	FILE *out = ctx->out;
	if (!out)
		return false;
	const char *data_section = (ctx->config && ctx->config->data_section) ? ctx->config->data_section : ".data";
	fprintf(out, "%s\n", data_section);
	fprintf(out, ".p2align 3\n");
	for (size_t i = 0; i < ctx->obf_entry_count; ++i)
	{
		Arm64ObfEntry *entry = &ctx->obf_entries[i];
		fprintf(out, "%s:\n", entry->desc_label);
		fprintf(out, "    .quad 0\n");
		fprintf(out, "    .long 0x%08x\n", entry->key);
		fprintf(out, "    .long %zu\n", entry->length);
		fprintf(out, "    .quad %s\n", entry->str_label);
	}
	const char *const_section = (ctx->config && ctx->config->const_section) ? ctx->config->const_section : ".section __TEXT,__const";
	fprintf(out, "%s\n", const_section);
	for (size_t i = 0; i < ctx->obf_entry_count; ++i)
	{
		Arm64ObfEntry *entry = &ctx->obf_entries[i];
		fprintf(out, "%s:\n", entry->str_label);
		for (size_t b = 0; b < entry->length; ++b)
		{
			fprintf(out, "    .byte 0x%02x\n", entry->encoded_bytes[b]);
		}
	}
	const char *text_section = (ctx->config && ctx->config->text_section) ? ctx->config->text_section : ".section __TEXT,__text,regular,pure_instructions";
	fprintf(out, "%s\n", text_section);
	for (size_t i = 0; i < ctx->obf_entry_count; ++i)
	{
		Arm64ObfEntry *entry = &ctx->obf_entries[i];
		fprintf(out, ".p2align 2\n");
		fprintf(out, "%s:\n", entry->stub_label);
		arm64_emit_symbol_address(ctx, out, entry->desc_label, "x16");
		fprintf(out, "    b __cc_obf_call_gate\n\n");
	}
	fprintf(out, ".p2align 2\n");
	fprintf(out, "__cc_obf_call_gate:\n");
	fprintf(out, "    stp x29, x30, [sp, #-16]!\n");
	fprintf(out, "    mov x29, sp\n");
	fprintf(out, "    stp x19, x20, [sp, #-16]!\n");
	fprintf(out, "    sub sp, sp, #64\n");
	fprintf(out, "    stp x0, x1, [sp, #0]\n");
	fprintf(out, "    stp x2, x3, [sp, #16]\n");
	fprintf(out, "    stp x4, x5, [sp, #32]\n");
	fprintf(out, "    stp x6, x7, [sp, #48]\n");
	fprintf(out, "    mov x19, x16\n");
	fprintf(out, "    ldr x9, [x19]\n");
	fprintf(out, "    cbnz x9, Lcc_obf_gate_done\n");
	fprintf(out, "    ldr w10, [x19, #8]\n\n");
	fprintf(out, "    ldr w11, [x19, #12]\n");
	fprintf(out, "    ldr x12, [x19, #16]\n");
	fprintf(out, "    uxtw x13, w11\n");
	fprintf(out, "    add x13, x13, #1\n");
	fprintf(out, "    add x13, x13, #15\n");
	fprintf(out, "    bic x13, x13, #15\n");
	fprintf(out, "    mov x20, x13\n");
	fprintf(out, "    sub sp, sp, x20\n");
	fprintf(out, "    mov x14, sp\n");
	fprintf(out, "    mov x15, x14\n");
	fprintf(out, "Lcc_obf_gate_decode:\n");
	fprintf(out, "    cbz w11, Lcc_obf_gate_decoded\n");
	fprintf(out, "    ldrb w17, [x12], #1\n");
	fprintf(out, "    eor w17, w17, w10\n");
	fprintf(out, "    strb w17, [x15], #1\n");
	fprintf(out, "    subs w11, w11, #1\n");
	fprintf(out, "    b.ne Lcc_obf_gate_decode\n");
	fprintf(out, "Lcc_obf_gate_decoded:\n");
	fprintf(out, "    mov w17, wzr\n");
	fprintf(out, "    strb w17, [x15]\n");
	char dlsym_buf[32];
	const char *dlsym_sym = arm64_format_symbol(ctx, "dlsym", dlsym_buf, sizeof(dlsym_buf));
	fprintf(out, "    mov x0, #-2\n");
	fprintf(out, "    mov x1, x14\n");
	fprintf(out, "    bl %s\n", dlsym_sym ? dlsym_sym : "dlsym");
	fprintf(out, "    mov x9, x0\n");
	fprintf(out, "    add sp, sp, x20\n");
	fprintf(out, "    cbnz x9, Lcc_obf_gate_cache\n");
	char abort_buf[32];
	const char *abort_sym = arm64_format_symbol(ctx, "abort", abort_buf, sizeof(abort_buf));
	fprintf(out, "    bl %s\n", abort_sym ? abort_sym : "abort");
	fprintf(out, "Lcc_obf_gate_cache:\n");
	fprintf(out, "    str x9, [x19]\n");
	fprintf(out, "Lcc_obf_gate_done:\n");
	fprintf(out, "    ldr x9, [x19]\n");
	fprintf(out, "    ldp x0, x1, [sp, #0]\n");
	fprintf(out, "    ldp x2, x3, [sp, #16]\n");
	fprintf(out, "    ldp x4, x5, [sp, #32]\n");
	fprintf(out, "    ldp x6, x7, [sp, #48]\n");
	fprintf(out, "    add sp, sp, #64\n");
	fprintf(out, "    ldp x19, x20, [sp], #16\n");
	fprintf(out, "    ldp x29, x30, [sp], #16\n");
	fprintf(out, "    br x9\n\n");
	return true;
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

static bool arm64_is_local_symbol(const Arm64ModuleContext *ctx, const char *name)
{
	if (!ctx || !ctx->config || !name)
		return false;
	if (ctx->config->format == ARM64_OBJECT_MACHO)
	{
		if (name[0] != 'L')
			return false;
		if (name[1] == '_')
			return true;
		if (name[1] == 'c' && name[2] == 'c' && name[3] == '_')
			return true;
		const char *double_underscore = strstr(name, "__");
		return double_underscore != NULL;
	}
	return (name[0] == '.' && name[1] == 'L');
}

static const char *arm64_format_symbol(const Arm64ModuleContext *ctx, const char *name, char *buffer, size_t buffer_size)
{
	if (!buffer || buffer_size == 0)
		return NULL;
	if (!name)
	{
		buffer[0] = '\0';
		return buffer;
	}
	if (ctx && ctx->config && ctx->config->prefix_symbols_with_underscore && name[0] != '_' && !arm64_is_local_symbol(ctx, name))
		snprintf(buffer, buffer_size, "_%s", name);
	else
		snprintf(buffer, buffer_size, "%s", name);
	return buffer;
}

static void arm64_emit_symbol_address(const Arm64ModuleContext *ctx, FILE *out, const char *symbol, const char *dst_reg)
{
	if (!ctx || !out || !symbol || !dst_reg)
		return;
	char symbol_buf[256];
	const char *label = arm64_format_symbol(ctx, symbol, symbol_buf, sizeof(symbol_buf));
	if (ctx->config && ctx->config->format == ARM64_OBJECT_MACHO)
	{
		fprintf(out, "    adrp %s, %s@PAGE\n", dst_reg, label);
		fprintf(out, "    add %s, %s, %s@PAGEOFF\n", dst_reg, dst_reg, label);
	}
	else
	{
		fprintf(out, "    adrp %s, %s\n", dst_reg, label);
		fprintf(out, "    add %s, %s, :lo12:%s\n", dst_reg, dst_reg, label);
	}
}

static const char *arm64_local_label_name(Arm64FunctionContext *ctx, const char *suffix, char *buffer, size_t buffer_size)
{
	if (!ctx || !ctx->fn || !suffix)
		return NULL;
	if (ctx->obfuscate_labels)
		return arm64_alias_label(ctx, suffix);
	const char *symbol = ctx->symbol_name ? ctx->symbol_name : ctx->fn->name;
	if (!symbol || !buffer || buffer_size == 0)
		return NULL;
	Arm64ModuleContext *module = ctx->module;
	const Arm64BackendConfig *cfg = module ? module->config : NULL;
	const char *local_prefix = (cfg && cfg->local_label_prefix) ? cfg->local_label_prefix : "L";
	bool needs_prefix = ctx->prefix_labels && (!module || !arm64_is_local_symbol(module, symbol));
	if (needs_prefix)
		snprintf(buffer, buffer_size, "%s%s__%s", local_prefix, symbol, suffix);
	else
		snprintf(buffer, buffer_size, "%s__%s", symbol, suffix);
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
	(void)ctx;
	return offset;
}

// Forward decl for immediate materialization helper used below.
static void arm64_mov_imm(FILE *out, const char *reg, bool use_w, uint64_t value);

static bool arm64_emit_stack_address(Arm64FunctionContext *ctx, size_t line, const char *dst_reg, size_t offset)
{
	if (!ctx || !ctx->out || !dst_reg)
		return false;
	size_t absolute = arm64_frame_offset(ctx, offset);
	if (absolute <= 4095)
	{
		fprintf(ctx->out, "    add %s, %s, #%zu\n", dst_reg, ARM64_FRAME_REG, absolute);
		return true;
	}
	const char *tmp = ARM64_SCRATCH_GP_REGS64[0];
	arm64_mov_imm(ctx->out, tmp, false, absolute);
	fprintf(ctx->out, "    add %s, %s, %s\n", dst_reg, ARM64_FRAME_REG, tmp);
	return true;
}

static void arm64_mov_imm(FILE *out, const char *reg, bool use_w, uint64_t value)
{
	uint64_t masked_value = use_w ? (value & 0xFFFFFFFFull) : value;
	if (masked_value == 0)
	{
		fprintf(out, "    mov %s, %s\n", reg, use_w ? "wzr" : "xzr");
		return;
	}
	unsigned max_bits = use_w ? 32u : 64u;
	bool emitted = false;
	for (unsigned shift = 0; shift < max_bits; shift += 16)
	{
		uint64_t chunk = (masked_value >> shift) & 0xFFFFu;
		if (!chunk && !emitted)
			continue;
		if (!emitted)
		{
			if (shift == 0)
				fprintf(out, "    movz %s, #0x%llx\n", reg, (unsigned long long)chunk);
			else
				fprintf(out, "    movz %s, #0x%llx, lsl #%u\n", reg, (unsigned long long)chunk, shift);
			emitted = true;
		}
		else if (chunk)
		{
			fprintf(out, "    movk %s, #0x%llx, lsl #%u\n", reg, (unsigned long long)chunk, shift);
		}
	}
}

static bool arm64_adjust_sp(Arm64FunctionContext *ctx, size_t amount, bool subtract)
{
	if (!ctx || amount == 0)
		return true;
	FILE *out = ctx->out;
	if (amount <= 4095)
	{
		fprintf(out, "    %s sp, sp, #%zu\n", subtract ? "sub" : "add", amount);
		return true;
	}
	const char *tmp_reg = ARM64_SCRATCH_GP_REGS64[0];
	arm64_mov_imm(out, tmp_reg, false, amount);
	fprintf(out, "    %s sp, sp, %s\n", subtract ? "sub" : "add", tmp_reg);
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
			arm64_emit_symbol_address(ctx->module, out, value->data.label, "x9");
			fprintf(out, "    mov %s, w9\n", reg);
		}
		else
		{
			arm64_emit_symbol_address(ctx->module, out, value->data.label, reg);
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
			fprintf(out, "    ldr %s, [%s, #%zu]\n", x_name, ARM64_FRAME_REG, addr);
		}
		else if (size_bytes == 4)
		{
			if (!use_w && is_signed)
				fprintf(out, "    ldrsw %s, [%s, #%zu]\n", x_name, ARM64_FRAME_REG, addr);
			else
				fprintf(out, "    ldr %s, [%s, #%zu]\n", w_name, ARM64_FRAME_REG, addr);
		}
		else if (size_bytes == 2)
		{
			if (is_signed)
			{
				if (use_w)
					fprintf(out, "    ldrsh %s, [%s, #%zu]\n", w_name, ARM64_FRAME_REG, addr);
				else
					fprintf(out, "    ldrsh %s, [%s, #%zu]\n", x_name, ARM64_FRAME_REG, addr);
			}
			else
				fprintf(out, "    ldrh %s, [%s, #%zu]\n", w_name, ARM64_FRAME_REG, addr);
		}
		else
		{
			if (is_signed)
			{
				if (use_w)
					fprintf(out, "    ldrsb %s, [%s, #%zu]\n", w_name, ARM64_FRAME_REG, addr);
				else
					fprintf(out, "    ldrsb %s, [%s, #%zu]\n", x_name, ARM64_FRAME_REG, addr);
			}
			else
				fprintf(out, "    ldrb %s, [%s, #%zu]\n", w_name, ARM64_FRAME_REG, addr);
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
		fprintf(out, "    ldr %s, [%s, #%zu]\n", fp_reg, ARM64_FRAME_REG, addr);
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
		fprintf(out, "    str %s, [%s, #%zu]\n", store_reg, ARM64_FRAME_REG, addr);
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
			fprintf(out, "    str %s, [%s, #%zu]\n", x_reg, ARM64_FRAME_REG, addr);
		}
		else if (size_bytes == 4)
		{
			fprintf(out, "    str %s, [%s, #%zu]\n", w_reg, ARM64_FRAME_REG, addr);
		}
		else if (size_bytes == 2)
		{
			fprintf(out, "    strh %s, [%s, #%zu]\n", w_reg, ARM64_FRAME_REG, addr);
		}
		else
		{
			fprintf(out, "    strb %s, [%s, #%zu]\n", w_reg, ARM64_FRAME_REG, addr);
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
		fprintf(out, "    str %s, [%s, #%zu]\n", fp_reg, ARM64_FRAME_REG, addr);
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
			fprintf(out, "    str %s, [%s, #%zu]\n", x_reg, ARM64_FRAME_REG, addr);
		else if (size_bytes == 4)
			fprintf(out, "    str %s, [%s, #%zu]\n", w_reg, ARM64_FRAME_REG, addr);
		else if (size_bytes == 2)
			fprintf(out, "    strh %s, [%s, #%zu]\n", w_reg, ARM64_FRAME_REG, addr);
		else
			fprintf(out, "    strb %s, [%s, #%zu]\n", w_reg, ARM64_FRAME_REG, addr);
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

static const char *arm64_intern_string(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (!ctx || !ctx->module)
		return NULL;
	char label[256];
	Arm64ModuleContext *module = ctx->module;
	const Arm64BackendConfig *cfg = module ? module->config : NULL;
	const char *hint_fmt = (cfg && cfg->string_label_hint_format) ? cfg->string_label_hint_format : "%s__%s";
	const char *auto_fmt = (cfg && cfg->string_label_auto_format) ? cfg->string_label_auto_format : "L_str%zu";
	const char *fn_symbol = ctx->symbol_name ? ctx->symbol_name : (ctx->fn ? ctx->fn->name : NULL);
	char fn_buf[256];
	const char *formatted = NULL;
	if (fn_symbol && module)
		formatted = arm64_format_symbol(module, fn_symbol, fn_buf, sizeof(fn_buf));
	if (ins->data.const_string.label_hint && ins->data.const_string.label_hint[0] && formatted && *formatted)
		snprintf(label, sizeof(label), hint_fmt, formatted, ins->data.const_string.label_hint);
	else
	{
		size_t ordinal = module ? module->string_counter++ : 0;
		snprintf(label, sizeof(label), auto_fmt, ordinal);
	}
	if (!string_table_add(&ctx->module->strings, label, ins->data.const_string.bytes, ins->data.const_string.length))
		return NULL;
	return ctx->module->strings.items[ctx->module->strings.count - 1].label;
}

static bool arm64_push_const_string(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	const char *label = arm64_intern_string(ctx, ins);
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
	const char *symbol = ins->data.global.symbol;
	if (ctx->module && module_has_function(ctx->module->module, symbol))
		symbol = arm64_module_symbol_alias(ctx->module, symbol);
	arm64_emit_symbol_address(ctx->module, out, symbol, addr_reg);
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
	FILE *out = ctx->out;
	if (cc_value_type_is_float(ins->data.local.type))
	{
		const bool is_f32 = (ins->data.local.type == CC_TYPE_F32);
		const char *fp_reg = is_f32 ? "s0" : "d0";
		if (!arm64_materialize_fp(ctx, &value, fp_reg, ins->data.local.type))
			return false;
		fprintf(out, "    str %s, [%s, #%zu]\n", fp_reg, ARM64_FRAME_REG, addr);
		return true;
	}
	bool use_w = (size_bytes <= 4);
	const char *reg = use_w ? ARM64_SCRATCH_GP_REGS32[0] : ARM64_SCRATCH_GP_REGS64[0];
	if (!arm64_materialize_gp(ctx, &value, reg, use_w))
		return false;
	if (size_bytes >= 8)
		fprintf(out, "    str %s, [%s, #%zu]\n", reg, ARM64_FRAME_REG, addr);
	else if (size_bytes == 4)
		fprintf(out, "    str %s, [%s, #%zu]\n", reg, ARM64_FRAME_REG, addr);
	else if (size_bytes == 2)
		fprintf(out, "    strh %s, [%s, #%zu]\n", ARM64_SCRATCH_GP_REGS32[0], ARM64_FRAME_REG, addr);
	else
		fprintf(out, "    strb %s, [%s, #%zu]\n", ARM64_SCRATCH_GP_REGS32[0], ARM64_FRAME_REG, addr);
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
	const char *symbol = ins->data.global.symbol;
	if (ctx->module && module_has_function(ctx->module->module, symbol))
		symbol = arm64_module_symbol_alias(ctx->module, symbol);
	arm64_emit_symbol_address(ctx->module, out, symbol, addr_reg);
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
	const char *symbol = ins->data.global.symbol;
	if (ctx->module && module_has_function(ctx->module->module, symbol))
		symbol = arm64_module_symbol_alias(ctx->module, symbol);
	arm64_emit_symbol_address(ctx->module, out, symbol, dst_reg);
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
	const char *full = arm64_local_label_name(ctx, ins->data.label.name, label, sizeof(label));
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
	const char *full = arm64_local_label_name(ctx, ins->data.jump.target, label, sizeof(label));
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
		const char *addr_reg = ARM64_SCRATCH_GP_REGS64[1];
		if (!arm64_emit_stack_address(ctx, ins->line, addr_reg, ctx->vararg_area_offset))
			return false;
		fprintf(ctx->out, "    ldr %s, [%s]\n", dst_reg, addr_reg);
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
	if (!arm64_adjust_sp(ctx, aligned_size, true))
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

static void arm64_emit_debug_location(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	if (!ctx || !ins || !ctx->out)
		return;
	if (ins->debug_file == 0 || ins->debug_line == 0)
		return;
	uint32_t column = ins->debug_column ? ins->debug_column : 1;
	if (ctx->current_loc_file == ins->debug_file && ctx->current_loc_line == ins->debug_line && ctx->current_loc_column == column)
		return;
	ctx->current_loc_file = ins->debug_file;
	ctx->current_loc_line = ins->debug_line;
	ctx->current_loc_column = column;
	fprintf(ctx->out, "    .loc %u %u %u\n", ctx->current_loc_file, ctx->current_loc_line, ctx->current_loc_column);
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
	bool is_float = cc_value_type_is_float(ins->data.memory.type);
	bool use_w = (size_bytes <= 4);
	const char *value_reg = use_w ? ARM64_SCRATCH_GP_REGS32[1] : ARM64_SCRATCH_GP_REGS64[1];
	if (is_float)
	{
		const char *fp_reg = (ins->data.memory.type == CC_TYPE_F32) ? "s0" : "d0";
		if (!arm64_materialize_fp(ctx, &value, fp_reg, ins->data.memory.type))
			return false;
		value_reg = fp_reg;
		use_w = (ins->data.memory.type == CC_TYPE_F32);
	}
	else if (!arm64_materialize_gp(ctx, &value, value_reg, use_w))
	{
		return false;
	}
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
	const char *true_full = arm64_local_label_name(ctx, ins->data.branch.true_target, true_label, sizeof(true_label));
	const char *false_full = arm64_local_label_name(ctx, ins->data.branch.false_target, false_label, sizeof(false_label));
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
	case CC_CONVERT_F2I:
	{
		if (!from_is_float || !cc_value_type_is_integer(to_type))
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "f2i conversion expects floating source and integer destination");
			return false;
		}
		const char *fp_src = (from_type == CC_TYPE_F32) ? "s0" : "d0";
		if (from_type == CC_TYPE_F32)
			fprintf(out, "    fmov %s, %s\n", fp_src, wreg);
		else
			fprintf(out, "    fmov %s, %s\n", fp_src, xreg);
		const char *dest_reg = (to_size <= 4) ? wreg : xreg;
		const char *instr = cc_value_type_is_signed(to_type) ? "fcvtzs" : "fcvtzu";
		fprintf(out, "    %s %s, %s\n", instr, dest_reg, fp_src);
		arm64_narrow_integer_result(out, dest_reg, to_size, cc_value_type_is_signed(to_type));
		break;
	}
	case CC_CONVERT_I2F:
	{
		if (!cc_value_type_is_integer(from_type) && from_type != CC_TYPE_PTR)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "i2f conversion expects integer or pointer source type");
			return false;
		}
		if (!to_is_float)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "i2f conversion expects floating destination type");
			return false;
		}
		const char *src_reg = (from_size <= 4) ? wreg : xreg;
		const char *fp_dst = (to_type == CC_TYPE_F32) ? "s0" : "d0";
		const char *instr = (from_type != CC_TYPE_PTR && cc_value_type_is_signed(from_type)) ? "scvtf" : "ucvtf";
		fprintf(out, "    %s %s, %s\n", instr, fp_dst, src_reg);
		if (to_type == CC_TYPE_F32)
			fprintf(out, "    fmov %s, %s\n", wreg, fp_dst);
		else
			fprintf(out, "    fmov %s, %s\n", xreg, fp_dst);
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
	size_t stack_arg_cursor = 0;
	size_t stack_arg_total = 0;
	Arm64ArgLocation *locations = NULL;
	bool success = false;
	size_t vararg_pack_size = 0;
	size_t vararg_pack_base = 0;
	size_t vararg_count = 0;
	size_t total_stack_adjust = 0;
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
			const size_t fp_reg_limit = sizeof(ARM64_FP_REGS) / sizeof(ARM64_FP_REGS[0]);
			const bool use_s = (arg_type == CC_TYPE_F32);
			if (fp_used < fp_reg_limit)
			{
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
				fp_used++;
			}
			else
			{
				size_t value_size = arm64_type_size(arg_type);
				if (value_size == 0)
					value_size = use_s ? 4 : 8;
				if (value_size > 8)
				{
					emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend does not yet support stack-passed floating arguments larger than 8 bytes");
					goto cleanup;
				}
				if (loc)
				{
					loc->uses_stack = true;
					loc->type = arg_type;
					loc->type_is_signed = false;
					loc->stack_size = value_size;
					loc->stack_offset = arm64_assign_stack_slot(&stack_arg_cursor, value_size);
				}
				continue;
			}
		}
		else
		{
			const size_t gp_reg_limit = sizeof(ARM64_GP_REGS64) / sizeof(ARM64_GP_REGS64[0]);
			bool use_w = (arg_type == CC_TYPE_I32 || arg_type == CC_TYPE_U32 || arg_type == CC_TYPE_I16 || arg_type == CC_TYPE_U16 || arg_type == CC_TYPE_I8 || arg_type == CC_TYPE_U8 || arg_type == CC_TYPE_I1);
			if (gp_used < gp_reg_limit)
			{
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
			else
			{
				size_t value_size = arm64_type_size(arg_type);
				if (value_size == 0)
					value_size = 8;
				if (value_size > 8)
				{
					emit_diag(ctx->sink, CC_DIAG_ERROR, ins->line, "arm64 backend does not yet support stack-passed integer arguments larger than 8 bytes");
					goto cleanup;
				}
				if (loc)
				{
					loc->uses_stack = true;
					loc->type = arg_type;
					loc->type_is_signed = cc_value_type_is_signed(arg_type);
					loc->stack_size = value_size;
					loc->stack_offset = arm64_assign_stack_slot(&stack_arg_cursor, value_size);
				}
			}
		}
	}

	stack_arg_total = align_up_size(stack_arg_cursor, ARM64_STACK_ALIGNMENT);

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

		vararg_count = (arg_count > fixed_params) ? (arg_count - fixed_params) : 0;
		if (vararg_count > 0)
			vararg_pack_size = align_up_size(vararg_count * 8, ARM64_STACK_ALIGNMENT);
		vararg_pack_base = stack_arg_total;
	}

	total_stack_adjust = stack_arg_total + vararg_pack_size;
	if (total_stack_adjust > 0)
		arm64_adjust_sp(ctx, total_stack_adjust, true);

	if (stack_arg_total > 0)
	{
		for (size_t i = 0; i < arg_count; ++i)
		{
			Arm64ArgLocation *loc = &locations[i];
			if (!loc || !loc->uses_stack)
				continue;
			Arm64Value *value = &ctx->stack[arg_base + i];
			size_t addr = loc->stack_offset;
			if (cc_value_type_is_float(loc->type))
			{
				const char *fp_reg = (loc->type == CC_TYPE_F32) ? "s15" : "d15";
				if (!arm64_materialize_fp(ctx, value, fp_reg, loc->type))
					goto cleanup;
				fprintf(ctx->out, "    str %s, [sp, #%zu]\n", fp_reg, addr);
			}
			else
			{
				size_t size_bytes = arm64_type_size(loc->type);
				if (size_bytes == 0)
					size_bytes = 8;
				const char *xreg = ARM64_SCRATCH_GP_REGS64[0];
				const char *wreg = ARM64_SCRATCH_GP_REGS32[0];
				bool use_w = (size_bytes <= 4);
				if (!arm64_materialize_gp(ctx, value, use_w ? wreg : xreg, use_w))
					goto cleanup;
				if (size_bytes >= 8)
					fprintf(ctx->out, "    str %s, [sp, #%zu]\n", xreg, addr);
				else if (size_bytes == 4)
					fprintf(ctx->out, "    str %s, [sp, #%zu]\n", wreg, addr);
				else if (size_bytes == 2)
					fprintf(ctx->out, "    strh %s, [sp, #%zu]\n", wreg, addr);
				else
					fprintf(ctx->out, "    strb %s, [sp, #%zu]\n", wreg, addr);
			}
		}
	}

	if (call_declares_varargs)
	{
		for (size_t i = fixed_params; i < arg_count; ++i)
		{
			Arm64Value *value = &ctx->stack[arg_base + i];
			CCValueType arg_type = ins->data.call.arg_types ? ins->data.call.arg_types[i] : CC_TYPE_I64;
			size_t addr = vararg_pack_base + (i - fixed_params) * 8;
			if (cc_value_type_is_float(arg_type))
			{
				const char *fp_reg = (arg_type == CC_TYPE_F32) ? "s15" : "d15";
				if (!arm64_materialize_fp(ctx, value, fp_reg, arg_type))
					goto cleanup;
				fprintf(ctx->out, "    str %s, [sp, #%zu]\n", fp_reg, addr);
			}
			else
			{
				size_t size_bytes = arm64_type_size(arg_type);
				if (size_bytes == 0)
					size_bytes = 8;
				const char *xreg = ARM64_SCRATCH_GP_REGS64[0];
				const char *wreg = ARM64_SCRATCH_GP_REGS32[0];
				bool use_w = (size_bytes <= 4);
				if (!arm64_materialize_gp(ctx, value, use_w ? wreg : xreg, use_w))
					goto cleanup;
				if (size_bytes < 8)
				{
					bool sign_extend = cc_value_type_is_signed(arg_type);
					if (size_bytes == 1)
						fprintf(ctx->out, "    %s %s, %s\n", sign_extend ? "sxtb" : "uxtb", xreg, wreg);
					else if (size_bytes == 2)
						fprintf(ctx->out, "    %s %s, %s\n", sign_extend ? "sxth" : "uxth", xreg, wreg);
					else
						fprintf(ctx->out, "    %s %s, %s\n", sign_extend ? "sxtw" : "uxtw", xreg, wreg);
				}
				fprintf(ctx->out, "    str %s, [sp, #%zu]\n", xreg, addr);
			}
		}

		if (vararg_pack_base == 0)
		{
			fprintf(ctx->out, "    mov %s, sp\n", ARM64_VARARG_PTR_REG);
		}
		else if (vararg_pack_base <= 4095)
		{
			fprintf(ctx->out, "    add %s, sp, #%zu\n", ARM64_VARARG_PTR_REG, vararg_pack_base);
		}
		else
		{
			const char *tmp = ARM64_SCRATCH_GP_REGS64[0];
			arm64_mov_imm(ctx->out, tmp, false, vararg_pack_base);
			fprintf(ctx->out, "    add %s, sp, %s\n", ARM64_VARARG_PTR_REG, tmp);
		}
	}

	if (ins->data.call.symbol && !is_indirect)
	{
		const bool target_is_internal = module_has_function(ctx->module->module, ins->data.call.symbol);
		const char *mapped = arm64_module_symbol_alias(ctx->module, ins->data.call.symbol);
		const char *symbol_name = mapped ? mapped : ins->data.call.symbol;
		char symbol_buf[256];
		const char *sym = (ctx->module && symbol_name)
							  ? arm64_format_symbol(ctx->module, symbol_name, symbol_buf, sizeof(symbol_buf))
							  : symbol_name;
		const char *visible = sym ? sym : symbol_name;
		if (ctx->module->obfuscate_calls && !target_is_internal)
		{
			Arm64ObfEntry *entry = arm64_obf_get_entry(ctx->module, visible);
			if (!entry)
				goto cleanup;
			fprintf(ctx->out, "    bl %s\n", entry->stub_label);
		}
		else if (ctx->module->obfuscate_calls && target_is_internal)
		{
			const char *target_reg = arm64_obfuscate_select_register(ctx);
			arm64_emit_symbol_address(ctx->module, ctx->out, visible, target_reg);
			fprintf(ctx->out, "    blr %s\n", target_reg);
		}
		else
		{
			fprintf(ctx->out, "    bl %s\n", visible);
		}
		if (!target_is_internal && !ctx->module->obfuscate_calls)
			symbol_set_add(&ctx->module->externs, visible);
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

	if (total_stack_adjust > 0)
		arm64_adjust_sp(ctx, total_stack_adjust, false);

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
	fprintf(ctx->out, "    mov sp, %s\n", ARM64_FRAME_REG);
	if (ctx->frame_size > 0)
		arm64_adjust_sp(ctx, ctx->frame_size, false);
	fprintf(ctx->out, "    ldp %s, x28, [sp], #16\n", ARM64_FRAME_REG);
	fprintf(ctx->out, "    ldp x29, x30, [sp], #16\n");
	fprintf(ctx->out, "    ret\n");
	ctx->saw_return = true;
	return true;
}

static bool arm64_emit_instruction(Arm64FunctionContext *ctx, const CCInstruction *ins)
{
	arm64_emit_debug_location(ctx, ins);
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
	const char *export_name = ctx->symbol_name ? ctx->symbol_name : ctx->fn->name;
	char symbol_buf[256];
	const char *fn_symbol = (export_name && ctx->module) ? arm64_format_symbol(ctx->module, export_name, symbol_buf, sizeof(symbol_buf)) : NULL;
	const char *visible = fn_symbol ? fn_symbol : (export_name ? export_name : "__cc_literal");
	if (!ctx->fn->is_hidden)
		fprintf(ctx->out, ".globl %s\n", visible);
	fprintf(ctx->out, ".p2align 2\n");
	fprintf(ctx->out, "%s:\n", visible);
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
	{
		bool ok = arm64_emit_literal_function(ctx);
		arm64_label_aliases_destroy(ctx);
		return ok;
	}

	ctx->param_offsets = NULL;
	ctx->param_types = NULL;
	ctx->local_offsets = NULL;
	ctx->local_types = NULL;
	ctx->frame_size = 0;
	ctx->saw_return = false;
	ctx->stack_snapshots = NULL;
	ctx->stack_snapshot_count = 0;
	ctx->stack_snapshot_capacity = 0;
	ctx->has_vararg_area = false;
	ctx->vararg_area_offset = 0;
	ctx->vararg_gp_start = 0;
	ctx->current_loc_file = 0;
	ctx->current_loc_line = 0;
	ctx->current_loc_column = 0;

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
		slot_index += 1;
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

	const char *export_name = ctx->symbol_name ? ctx->symbol_name : ctx->fn->name;
	char symbol_buf[256];
	const char *fn_symbol = (export_name && ctx->module) ? arm64_format_symbol(ctx->module, export_name, symbol_buf, sizeof(symbol_buf)) : NULL;
	const char *visible = fn_symbol ? fn_symbol : (export_name ? export_name : "__cc_fn");
	if (!ctx->fn->is_hidden)
		fprintf(ctx->out, ".globl %s\n", visible);
	fprintf(ctx->out, ".p2align 2\n");
	fprintf(ctx->out, "%s:\n", visible);
	fprintf(ctx->out, "    stp x29, x30, [sp, #-16]!\n");
	fprintf(ctx->out, "    mov x29, sp\n");
	fprintf(ctx->out, "    stp %s, x28, [sp, #-16]!\n", ARM64_FRAME_REG);
	if (ctx->frame_size > 0)
		arm64_adjust_sp(ctx, ctx->frame_size, true);
	fprintf(ctx->out, "    mov %s, sp\n", ARM64_FRAME_REG);

	size_t gp_param_index = 0;
	size_t fp_param_index = 0;
	size_t incoming_stack_cursor = 0;
	for (size_t i = 0; i < param_count; ++i)
	{
		CCValueType param_type = ctx->param_types[i];
		bool is_float = cc_value_type_is_float(param_type);
		size_t offset = ctx->param_offsets[i];
		size_t addr = arm64_frame_offset(ctx, offset);
		size_t size_bytes = arm64_type_size(param_type);
		if (is_float)
		{
			const size_t fp_limit = sizeof(ARM64_FP_REGS) / sizeof(ARM64_FP_REGS[0]);
			if (fp_param_index < fp_limit)
			{
				if (size_bytes == 4)
					fprintf(ctx->out, "    str %s, [%s, #%zu]\n", ARM64_FP_REGS32[fp_param_index], ARM64_FRAME_REG, addr);
				else
					fprintf(ctx->out, "    str %s, [%s, #%zu]\n", ARM64_FP_REGS[fp_param_index], ARM64_FRAME_REG, addr);
				fp_param_index++;
				continue;
			}
			if (size_bytes > 8)
			{
				emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend does not yet support stack-passed floating parameters larger than 8 bytes");
				goto fail;
			}
			const size_t stack_offset = arm64_assign_stack_slot(&incoming_stack_cursor, size_bytes);
			const size_t load_addr = 16 + stack_offset;
			const char *tmp_fp = (size_bytes == 4) ? "s15" : "d15";
			fprintf(ctx->out, "    ldr %s, [x29, #%zu]\n", tmp_fp, load_addr);
			fprintf(ctx->out, "    str %s, [%s, #%zu]\n", tmp_fp, ARM64_FRAME_REG, addr);
			continue;
		}

		const size_t gp_limit = sizeof(ARM64_GP_REGS64) / sizeof(ARM64_GP_REGS64[0]);
		if (gp_param_index < gp_limit)
		{
			if (size_bytes == 1)
				fprintf(ctx->out, "    strb %s, [%s, #%zu]\n", ARM64_GP_REGS32[gp_param_index], ARM64_FRAME_REG, addr);
			else if (size_bytes == 2)
				fprintf(ctx->out, "    strh %s, [%s, #%zu]\n", ARM64_GP_REGS32[gp_param_index], ARM64_FRAME_REG, addr);
			else if (size_bytes == 4)
				fprintf(ctx->out, "    str %s, [%s, #%zu]\n", ARM64_GP_REGS32[gp_param_index], ARM64_FRAME_REG, addr);
			else
				fprintf(ctx->out, "    str %s, [%s, #%zu]\n", ARM64_GP_REGS64[gp_param_index], ARM64_FRAME_REG, addr);
			gp_param_index++;
			continue;
		}
		if (size_bytes > 8)
		{
			emit_diag(ctx->sink, CC_DIAG_ERROR, 0, "arm64 backend does not yet support stack-passed integer parameters larger than 8 bytes");
			goto fail;
		}
		const size_t stack_offset = arm64_assign_stack_slot(&incoming_stack_cursor, size_bytes);
		const size_t load_addr = 16 + stack_offset;
		const char *xreg = ARM64_SCRATCH_GP_REGS64[0];
		const char *wreg = ARM64_SCRATCH_GP_REGS32[0];
		if (size_bytes >= 8)
		{
			fprintf(ctx->out, "    ldr %s, [x29, #%zu]\n", xreg, load_addr);
			fprintf(ctx->out, "    str %s, [%s, #%zu]\n", xreg, ARM64_FRAME_REG, addr);
		}
		else if (size_bytes == 4)
		{
			fprintf(ctx->out, "    ldr %s, [x29, #%zu]\n", wreg, load_addr);
			fprintf(ctx->out, "    str %s, [%s, #%zu]\n", wreg, ARM64_FRAME_REG, addr);
		}
		else if (size_bytes == 2)
		{
			fprintf(ctx->out, "    ldrh %s, [x29, #%zu]\n", wreg, load_addr);
			fprintf(ctx->out, "    strh %s, [%s, #%zu]\n", wreg, ARM64_FRAME_REG, addr);
		}
		else
		{
			fprintf(ctx->out, "    ldrb %s, [x29, #%zu]\n", wreg, load_addr);
			fprintf(ctx->out, "    strb %s, [%s, #%zu]\n", wreg, ARM64_FRAME_REG, addr);
		}
	}

	if (ctx->has_vararg_area)
	{
		const char *addr_reg = ARM64_SCRATCH_GP_REGS64[0];
		if (!arm64_emit_stack_address(ctx, 0, addr_reg, ctx->vararg_area_offset))
			goto fail;
		fprintf(ctx->out, "    str %s, [%s]\n", ARM64_VARARG_PTR_REG, addr_reg);
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
		fprintf(ctx->out, "    mov sp, %s\n", ARM64_FRAME_REG);
		if (ctx->frame_size > 0)
			arm64_adjust_sp(ctx, ctx->frame_size, false);
		fprintf(ctx->out, "    ldp %s, x28, [sp], #16\n", ARM64_FRAME_REG);
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
	arm64_clear_stack_snapshots(ctx);
	arm64_label_aliases_destroy(ctx);

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
	arm64_clear_stack_snapshots(ctx);
	arm64_label_aliases_destroy(ctx);
	return false;
}

static void arm64_emit_string_literals(const Arm64ModuleContext *ctx)
{
	if (!ctx || ctx->strings.count == 0)
		return;
	const char *section = (ctx->config && ctx->config->cstring_section) ? ctx->config->cstring_section : ".section __TEXT,__cstring";
	fprintf(ctx->out, "\n%s\n", section);
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
				if (ctx->obfuscate_calls)
					continue;
				if (module_has_function(ctx->module, ins->data.call.symbol))
					continue;
				char symbol_buf[256];
				const char *sym = ctx->module ? arm64_format_symbol(ctx, ins->data.call.symbol, symbol_buf, sizeof(symbol_buf)) : ins->data.call.symbol;
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

static unsigned arm64_p2align_shift(size_t alignment)
{
	if (alignment == 0)
		alignment = 1;
	unsigned shift = 0;
	size_t value = 1;
	while (value < alignment)
	{
		value <<= 1;
		shift++;
	}
	return shift;
}

static size_t arm64_global_storage_size(const CCGlobal *global)
{
	if (!global)
		return 0;
	if (global->size > 0)
		return global->size;
	size_t type_size = arm64_type_size(global->type);
	if (type_size == 0)
		type_size = 8;
	return type_size;
}

static void arm64_emit_global_definition(const Arm64ModuleContext *ctx, const CCGlobal *global)
{
	if (!ctx || !ctx->out || !global || !global->name || global->is_extern)
		return;
	FILE *out = ctx->out;
	char symbol_buf[256];
	const char *symbol = arm64_format_symbol(ctx, global->name, symbol_buf, sizeof(symbol_buf));
	size_t align_bytes = global->alignment ? global->alignment : arm64_type_size(global->type);
	if (align_bytes == 0)
		align_bytes = 8;
	unsigned align_shift = arm64_p2align_shift(align_bytes);
	size_t storage_size = arm64_global_storage_size(global);
	if (storage_size == 0)
		storage_size = 8;

	if (!global->is_hidden)
		fprintf(out, ".globl %s\n", symbol ? symbol : global->name);
	fprintf(out, ".p2align %u\n", align_shift);
	fprintf(out, "%s:\n", symbol ? symbol : global->name);

	size_t initialized_bytes = 0;
	switch (global->init.kind)
	{
	case CC_GLOBAL_INIT_INT:
	{
		size_t elem_size = arm64_type_size(global->type);
		if (elem_size == 0 || elem_size > storage_size)
			elem_size = storage_size < 8 ? storage_size : 8;
		uint64_t value = global->init.payload.u64;
		if (elem_size >= 8)
		{
			fprintf(out, "    .quad 0x%016llx\n", (unsigned long long)value);
			initialized_bytes = 8;
		}
		else if (elem_size == 4)
		{
			fprintf(out, "    .long 0x%08llx\n", (unsigned long long)(value & 0xFFFFFFFFULL));
			initialized_bytes = 4;
		}
		else if (elem_size == 2)
		{
			fprintf(out, "    .short 0x%04llx\n", (unsigned long long)(value & 0xFFFFULL));
			initialized_bytes = 2;
		}
		else
		{
			fprintf(out, "    .byte 0x%02llx\n", (unsigned long long)(value & 0xFFULL));
			initialized_bytes = 1;
		}
		break;
	}
	case CC_GLOBAL_INIT_FLOAT:
	{
		if (global->type == CC_TYPE_F32)
		{
			union
			{
				float f;
				uint32_t bits;
			} conv;
			conv.f = (float)global->init.payload.f64;
			fprintf(out, "    .long 0x%08x\n", conv.bits);
			initialized_bytes = 4;
		}
		else
		{
			union
			{
				double f;
				uint64_t bits;
			} conv;
			conv.f = global->init.payload.f64;
			fprintf(out, "    .quad 0x%016llx\n", (unsigned long long)conv.bits);
			initialized_bytes = 8;
		}
		break;
	}
	case CC_GLOBAL_INIT_STRING:
	{
		size_t len = global->init.payload.string.length;
		if (len > 0)
		{
			fprintf(out, "    .byte ");
			for (size_t i = 0; i < len; ++i)
			{
				unsigned char byte = (unsigned char)global->init.payload.string.data[i];
				fprintf(out, "%s0x%02x", (i == 0 ? "" : ", "), byte);
			}
			fprintf(out, ", 0\n");
		}
		else
		{
			fprintf(out, "    .byte 0\n");
		}
		initialized_bytes = len + 1;
		break;
	}
	case CC_GLOBAL_INIT_BYTES:
	{
		size_t len = global->init.payload.bytes.size;
		if (len > 0)
		{
			fprintf(out, "    .byte ");
			for (size_t i = 0; i < len; ++i)
			{
				unsigned char byte = global->init.payload.bytes.data[i];
				fprintf(out, "%s0x%02x", (i == 0 ? "" : ", "), byte);
			}
			fprintf(out, "\n");
		}
		initialized_bytes = len;
		break;
	}
	case CC_GLOBAL_INIT_PTRS:
	{
		size_t count = global->init.payload.ptrs.count;
		for (size_t i = 0; i < count; ++i)
		{
			const char *entry = global->init.payload.ptrs.symbols[i];
			if (!entry || entry[0] == '\0' || strcmp(entry, "null") == 0)
			{
				fprintf(out, "    .quad 0\n");
			}
			else
			{
				char entry_buf[256];
				const char *entry_sym = arm64_format_symbol(ctx, entry, entry_buf, sizeof(entry_buf));
				fprintf(out, "    .quad %s\n", entry_sym ? entry_sym : entry);
			}
		}
		initialized_bytes = count * 8;
		break;
	}
	case CC_GLOBAL_INIT_NONE:
	default:
		initialized_bytes = 0;
		break;
	}

	if (initialized_bytes < storage_size)
		fprintf(out, "    .zero %zu\n", storage_size - initialized_bytes);
}

static void arm64_emit_globals(const Arm64ModuleContext *ctx)
{
	if (!ctx || !ctx->module || ctx->module->global_count == 0)
		return;
	int current_section = -1;
	for (size_t i = 0; i < ctx->module->global_count; ++i)
	{
		const CCGlobal *global = &ctx->module->globals[i];
		int desired_section = global->is_const ? 1 : 0;
		if (desired_section != current_section)
		{
			const char *section = NULL;
			if (ctx->config)
				section = desired_section ? ctx->config->const_section : ctx->config->data_section;
			if (!section)
				section = desired_section ? ".section .rodata" : ".data";
			fprintf(ctx->out, "\n%s\n", section);
			current_section = desired_section;
		}
		arm64_emit_global_definition(ctx, global);
		fprintf(ctx->out, "\n");
	}
}

static void arm64_emit_debug_files(const Arm64ModuleContext *ctx)
{
	if (!ctx || !ctx->module || ctx->module->debug_file_count == 0)
		return;

	const char *primary = (ctx->module->debug_files && ctx->module->debug_files[0]) ? ctx->module->debug_files[0] : NULL;
	if (primary && *primary)
	{
		char dirbuf[PATH_MAX];
		char filebuf[PATH_MAX];
		arm64_split_path(primary, dirbuf, sizeof(dirbuf), filebuf, sizeof(filebuf));
		const char *dir_part = (dirbuf[0] != '\0') ? dirbuf : ".";
		const char *file_part = (filebuf[0] != '\0') ? filebuf : primary;
		fputs(".file 0 ", ctx->out);
		arm64_write_quoted(ctx->out, dir_part);
		fputc(' ', ctx->out);
		arm64_write_quoted(ctx->out, file_part);
		fputc('\n', ctx->out);
	}

	for (size_t i = 0; i < ctx->module->debug_file_count; ++i)
	{
		const char *path = (ctx->module->debug_files && ctx->module->debug_files[i]) ? ctx->module->debug_files[i] : NULL;
		if (!path || path[0] == '\0')
			continue;
		fprintf(ctx->out, ".file %zu ", i + 1);
		arm64_write_quoted(ctx->out, path);
		fputc('\n', ctx->out);
	}
	fprintf(ctx->out, "\n");
}

static bool arm64_emit_module(const CCBackend *backend, const CCModule *module, const CCBackendOptions *options, CCDiagnosticSink *sink, void *userdata)
{
	(void)userdata;
	if (!module)
		return false;

	const Arm64BackendConfig *config = backend && backend->userdata ? (const Arm64BackendConfig *)backend->userdata : &kArm64ConfigMachO;
	const char *output_path = backend_option_get(options, "output");
	const char *target_os = backend_option_get(options, "target-os");
	const char *debug_opt = backend_option_get(options, "debug");
	const char *strip_opt = backend_option_get(options, "strip");
	const char *obfuscate_opt = backend_option_get(options, "obfuscate");

	if (config && config->target_os_option)
	{
		if (target_os && *target_os)
		{
			if (!equals_ignore_case(target_os, config->target_os_option))
			{
				emit_diag(sink, CC_DIAG_ERROR, 0,
						  "arm64 backend requires target-os=%s (got '%s')",
						  config->target_os_option, target_os);
				return false;
			}
		}
		else
		{
			target_os = config->target_os_option;
		}
	}

	if (config && config->format == ARM64_OBJECT_COFF && option_is_enabled(obfuscate_opt))
	{
		emit_diag(sink, CC_DIAG_ERROR, 0, "arm64 Windows backend does not yet support obfuscation");
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
	ctx.config = config;
	ctx.sink = sink;
	ctx.keep_debug_names = option_is_enabled(debug_opt);
	ctx.prefer_local_hidden_symbols = option_is_enabled(strip_opt);
	ctx.obfuscate_calls = option_is_enabled(obfuscate_opt);
	ctx.obfuscate_seed = 0x6b27c9d5u;
	ctx.obfuscate_seed ^= (uint32_t)(module ? module->function_count : 0) * 0x45d9f3bdu;
	ctx.obfuscate_seed ^= (uint32_t)(module ? module->global_count : 0) * 0x94d049bbu;
	ctx.obfuscate_seed ^= (uint32_t)(module ? module->extern_count : 0) * 0x632be59bu;
	if (!ctx.obfuscate_calls)
		ctx.obfuscate_seed ^= 0xa0761d65u;
	else
	{
		const char *runtime_syms[] = {"dlsym", "abort"};
		for (size_t i = 0; i < sizeof(runtime_syms) / sizeof(runtime_syms[0]); ++i)
		{
			char runtime_buf[64];
			const char *rt = arm64_format_symbol(&ctx, runtime_syms[i], runtime_buf, sizeof(runtime_buf));
			symbol_set_add(&ctx.externs, rt ? rt : runtime_syms[i]);
		}
	}
	arm64_vararg_cache_load(&ctx);

	const char *banner = (config && config->banner) ? config->banner : "ARM64";
	fprintf(out, "// ChanceCode %s ARM64 backend output\n", banner);
	if (config && config->emit_build_version && config->build_version_directive && *config->build_version_directive)
		fprintf(out, "%s\n\n", config->build_version_directive);
	else
		fputc('\n', out);

	if (!arm64_collect_externs(&ctx))
	{
		emit_diag(sink, CC_DIAG_ERROR, 0, "failed to collect extern symbols");
		if (out != stdout)
			fclose(out);
		string_table_destroy(&ctx.strings);
		symbol_set_destroy(&ctx.externs);
		arm64_vararg_cache_destroy(&ctx);
		hidden_function_aliases_destroy(&ctx);
		arm64_obf_entries_destroy(&ctx);
		return false;
	}

	arm64_emit_externs(&ctx);
	arm64_emit_globals(&ctx);
	arm64_emit_debug_files(&ctx);
	const char *text_section = (ctx.config && ctx.config->text_section) ? ctx.config->text_section : ".section __TEXT,__text,regular,pure_instructions";
	fprintf(out, "%s\n\n", text_section);

	for (size_t i = 0; i < module->function_count; ++i)
	{
		Arm64FunctionContext fn_ctx;
		memset(&fn_ctx, 0, sizeof(fn_ctx));
		fn_ctx.module = &ctx;
		fn_ctx.fn = &module->functions[i];
		fn_ctx.out = out;
		fn_ctx.sink = sink;
		fn_ctx.function_id = ctx.next_function_id++;
		fn_ctx.symbol_name = arm64_module_function_symbol(&ctx, fn_ctx.fn);
		if (!fn_ctx.symbol_name)
			fn_ctx.symbol_name = fn_ctx.fn ? fn_ctx.fn->name : NULL;
		fn_ctx.obfuscate_labels = !ctx.keep_debug_names;
		fn_ctx.prefix_labels = ctx.keep_debug_names;
		if (!arm64_emit_function(&fn_ctx))
		{
			free(fn_ctx.stack);
			if (out != stdout)
				fclose(out);
			string_table_destroy(&ctx.strings);
			symbol_set_destroy(&ctx.externs);
			arm64_vararg_cache_destroy(&ctx);
			hidden_function_aliases_destroy(&ctx);
			arm64_obf_entries_destroy(&ctx);
			return false;
		}
		free(fn_ctx.stack);
		fprintf(out, "\n");
	}

	arm64_emit_string_literals(&ctx);
	if (!arm64_emit_obf_support(&ctx))
	{
		emit_diag(sink, CC_DIAG_ERROR, 0, "failed to emit obfuscation support");
		if (out != stdout)
			fclose(out);
		string_table_destroy(&ctx.strings);
		symbol_set_destroy(&ctx.externs);
		arm64_vararg_cache_destroy(&ctx);
		hidden_function_aliases_destroy(&ctx);
		arm64_obf_entries_destroy(&ctx);
		return false;
	}

	if (out != stdout)
		fclose(out);

	string_table_destroy(&ctx.strings);
	symbol_set_destroy(&ctx.externs);
	arm64_vararg_cache_destroy(&ctx);
	hidden_function_aliases_destroy(&ctx);
	arm64_obf_entries_destroy(&ctx);
	return true;
}

static const CCBackend kArm64BackendMac = {
	.name = "arm64-macos",
	.description = "Experimental macOS ARM64 backend",
	.emit = arm64_emit_module,
	.userdata = (void *)&kArm64ConfigMachO,
};

static const CCBackend kArm64BackendElf = {
	.name = "arm64-elf",
	.description = "Experimental Linux ELF ARM64 backend",
	.emit = arm64_emit_module,
	.userdata = (void *)&kArm64ConfigElf,
};

static const CCBackend kArm64BackendCoff = {
	.name = "arm64-windows",
	.description = "Experimental Windows ARM64 backend",
	.emit = arm64_emit_module,
	.userdata = (void *)&kArm64ConfigCoff,
};

bool cc_register_backend_arm64(void)
{
	bool ok = true;
	ok = ok && cc_backend_register(&kArm64BackendMac);
	ok = ok && cc_backend_register(&kArm64BackendElf);
	ok = ok && cc_backend_register(&kArm64BackendCoff);
	return ok;
}
