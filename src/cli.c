#include "cc/backend.h"
#include "cc/diagnostics.h"
#include "cc/loader.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cc_register_builtin_backends(void);

static void print_usage(void)
{
    fprintf(stderr, "Usage: ccb <input.ccb> [-O0|-O1|-O2|-O3] [--backend NAME] [--output PATH] [--option key=value] [--list-backends] [--emit-ccbin PATH] [--strip] [--strip-hard] [--obfuscate]\n");
}

static bool parse_option_assignment(const char *arg, CCBackendOption *out_option)
{
    const char *eq = strchr(arg, '=');
    if (!eq || eq == arg || *(eq + 1) == '\0')
    {
        return false;
    }
    size_t key_len = (size_t)(eq - arg);
    char *key = (char *)malloc(key_len + 1);
    if (!key)
    {
        return false;
    }
    memcpy(key, arg, key_len);
    key[key_len] = '\0';
    out_option->key = key;
    size_t value_len = strlen(eq + 1);
    char *value = (char *)malloc(value_len + 1);
    if (!value)
    {
        free(key);
        return false;
    }
    memcpy(value, eq + 1, value_len + 1);
    out_option->value = value;
    return true;
}

static void free_options(CCBackendOption *options, size_t count)
{
    for (size_t i = 0; i < count; ++i)
    {
        free((void *)options[i].key);
        free((void *)options[i].value);
    }
}

typedef struct
{
    char *from;
    char *to;
} StripMapEntry;

typedef struct
{
    StripMapEntry *entries;
    size_t count;
    size_t capacity;
} StripMap;

static char *cli_strdup(const char *src)
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

static void strip_map_free(StripMap *map)
{
    if (!map)
        return;
    if (map->entries)
    {
        for (size_t i = 0; i < map->count; ++i)
        {
            free(map->entries[i].from);
            free(map->entries[i].to);
        }
        free(map->entries);
    }
    map->entries = NULL;
    map->count = 0;
    map->capacity = 0;
}

static bool strip_map_add_entry(StripMap *map, const char *from, const char *to)
{
    if (!map || !from || !*from || !to || !*to)
        return true;
    if (map->count == map->capacity)
    {
        size_t new_capacity = map->capacity ? map->capacity * 2 : 32;
        StripMapEntry *grown =
            (StripMapEntry *)realloc(map->entries, new_capacity * sizeof(StripMapEntry));
        if (!grown)
            return false;
        map->entries = grown;
        map->capacity = new_capacity;
    }
    StripMapEntry entry;
    entry.from = cli_strdup(from);
    entry.to = cli_strdup(to);
    if (!entry.from || !entry.to)
    {
        free(entry.from);
        free(entry.to);
        return false;
    }
    map->entries[map->count++] = entry;
    return true;
}

static int strip_map_entry_cmp(const void *a, const void *b)
{
    const StripMapEntry *ea = (const StripMapEntry *)a;
    const StripMapEntry *eb = (const StripMapEntry *)b;
    if (!ea || !eb || !ea->from || !eb->from)
        return 0;
    return strcmp(ea->from, eb->from);
}

static void strip_map_sort(StripMap *map)
{
    if (!map || map->count <= 1 || !map->entries)
        return;
    qsort(map->entries, map->count, sizeof(StripMapEntry), strip_map_entry_cmp);
}

static const char *strip_map_lookup(const StripMap *map, const char *name)
{
    if (!map || !map->entries || map->count == 0 || !name || !*name)
        return NULL;
    size_t lo = 0;
    size_t hi = map->count;
    while (lo < hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = strcmp(name, map->entries[mid].from);
        if (cmp == 0)
            return map->entries[mid].to;
        if (cmp < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return NULL;
}

static bool strip_map_load(const char *path, StripMap *map)
{
    if (!path || !map)
        return false;
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        fprintf(stderr, "error: failed to open strip map '%s' (%s)\n", path,
                strerror(errno));
        return false;
    }
    char line[2048];
    while (fgets(line, sizeof(line), fp))
    {
        char *cursor = line;
        while (*cursor && isspace((unsigned char)*cursor))
            ++cursor;
        if (*cursor == '\0' || *cursor == '#' || *cursor == ';')
            continue;
        char *from = cursor;
        while (*cursor && !isspace((unsigned char)*cursor))
            ++cursor;
        if (*cursor)
            *cursor++ = '\0';
        while (*cursor && isspace((unsigned char)*cursor))
            ++cursor;
        if (*cursor == '\0')
            continue;
        char *to = cursor;
        while (*cursor && !isspace((unsigned char)*cursor))
            ++cursor;
        *cursor = '\0';
        if (!strip_map_add_entry(map, from, to))
        {
            fprintf(stderr, "error: out of memory while reading strip map '%s'\n",
                    path);
            fclose(fp);
            return false;
        }
    }
    fclose(fp);
    strip_map_sort(map);
    return true;
}

static bool rename_symbol_if_needed(char **slot, const StripMap *map)
{
    if (!slot || !*slot)
        return true;
    const char *replacement = strip_map_lookup(map, *slot);
    if (!replacement)
        return true;
    char *copy = cli_strdup(replacement);
    if (!copy)
        return false;
    free(*slot);
    *slot = copy;
    return true;
}

static bool patch_instruction_symbols(CCInstruction *ins, const StripMap *map)
{
    if (!ins)
        return true;
    switch (ins->kind)
    {
    case CC_INSTR_CALL:
        return rename_symbol_if_needed(&ins->data.call.symbol, map);
    case CC_INSTR_LOAD_GLOBAL:
    case CC_INSTR_STORE_GLOBAL:
    case CC_INSTR_ADDR_GLOBAL:
        return rename_symbol_if_needed(&ins->data.global.symbol, map);
    default:
        return true;
    }
}

static bool apply_strip_map(CCModule *module, const StripMap *map)
{
    if (!module || !map || map->count == 0)
        return true;
    for (size_t i = 0; i < module->global_count; ++i)
    {
        if (!rename_symbol_if_needed(&module->globals[i].name, map))
            return false;
    }
    for (size_t i = 0; i < module->extern_count; ++i)
    {
        if (!rename_symbol_if_needed(&module->externs[i].name, map))
            return false;
    }
    for (size_t i = 0; i < module->function_count; ++i)
    {
        CCFunction *fn = &module->functions[i];
        if (!rename_symbol_if_needed(&fn->name, map))
            return false;
        for (size_t j = 0; j < fn->instruction_count; ++j)
        {
            if (!patch_instruction_symbols(&fn->instructions[j], map))
                return false;
        }
    }
    return true;
}

int main(int argc, char **argv)
{
    const char *input_path = NULL;
    const char *backend_name = NULL;
    const char *output_path = NULL;
    const char *ccbin_path = NULL;
    const char *strip_map_path = NULL;
    bool list_backends = false;
    bool strip_metadata = false;
    bool strip_hard = false;
    bool obfuscate = false;
    int opt_level = 0;

    CCBackendOption option_storage[16];
    size_t option_count = 0;

    for (int i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        if (strcmp(arg, "--backend") == 0)
        {
            if (i + 1 >= argc)
            {
                print_usage();
                return 1;
            }
            backend_name = argv[++i];
        }
        else if (strcmp(arg, "--output") == 0)
        {
            if (i + 1 >= argc)
            {
                print_usage();
                return 1;
            }
            output_path = argv[++i];
        }
        else if (strcmp(arg, "--list-backends") == 0)
        {
            list_backends = true;
        }
        else if (strcmp(arg, "--emit-ccbin") == 0)
        {
            if (i + 1 >= argc)
            {
                print_usage();
                return 1;
            }
            ccbin_path = argv[++i];
        }
        else if (strcmp(arg, "--strip") == 0)
        {
            strip_metadata = true;
        }
        else if (strcmp(arg, "--strip-hard") == 0)
        {
            strip_metadata = true;
            strip_hard = true;
        }
        else if (strcmp(arg, "--obfuscate") == 0)
        {
            strip_metadata = true;
            strip_hard = true;
            obfuscate = true;
        }
        else if (strcmp(arg, "--option") == 0)
        {
            if (i + 1 >= argc || option_count >= sizeof(option_storage) / sizeof(option_storage[0]))
            {
                fprintf(stderr, "error: --option expects key=value and there is limited capacity\n");
                return 1;
            }
            if (!parse_option_assignment(argv[++i], &option_storage[option_count]))
            {
                fprintf(stderr, "error: invalid option assignment '%s'\n", argv[i]);
                return 1;
            }
            ++option_count;
        }
        else if (strncmp(arg, "-O", 2) == 0)
        {
            const char *level_str = arg + 2;
            if (*level_str == '\0')
            {
                if (i + 1 >= argc)
                {
                    fprintf(stderr, "error: -O expects a level (0,1,2,3)\n");
                    return 1;
                }
                level_str = argv[++i];
            }
            bool valid_digits = (*level_str != '\0');
            for (const char *p = level_str; valid_digits && *p; ++p)
            {
                if (*p < '0' || *p > '9')
                    valid_digits = false;
            }
            if (!valid_digits)
            {
                fprintf(stderr, "error: invalid optimization level '%s' (use -O0|-O1|-O2|-O3)\n", level_str);
                return 1;
            }
            int level = atoi(level_str);
            if (level < 0 || level > 3)
            {
                fprintf(stderr, "error: invalid optimization level '%s' (use -O0|-O1|-O2|-O3)\n", level_str);
                return 1;
            }
            opt_level = level;
        }
        else if (arg[0] == '-')
        {
            print_usage();
            return 1;
        }
        else if (!input_path)
        {
            input_path = arg;
        }
        else
        {
            print_usage();
            return 1;
        }
    }

    for (size_t i = 0; i < option_count; ++i)
    {
        if (option_storage[i].key && strcmp(option_storage[i].key, "strip-map") == 0)
        {
            strip_map_path = option_storage[i].value;
            break;
        }
    }

    cc_register_builtin_backends();

    if (list_backends)
    {
        size_t count = cc_backend_count();
        for (size_t i = 0; i < count; ++i)
        {
            const CCBackend *backend = cc_backend_at(i);
            fprintf(stdout, "%s\t%s\n", backend->name, backend->description ? backend->description : "");
        }
        free_options(option_storage, option_count);
        return 0;
    }

    if (!input_path)
    {
        print_usage();
        free_options(option_storage, option_count);
        return 1;
    }

    CCDiagnosticSink sink;
    cc_diag_init_default(&sink);

    CCModule module;
    if (!cc_load_file(input_path, &module, &sink))
    {
        free_options(option_storage, option_count);
        return 1;
    }

    bool only_ccbin = (ccbin_path != NULL) && (backend_name == NULL) && (output_path == NULL);

    const CCBackend *backend = NULL;
    if (backend_name)
    {
        backend = cc_backend_find(backend_name);
        if (!backend)
        {
            fprintf(stderr, "error: unknown backend '%s'\n", backend_name);
            cc_module_free(&module);
            free_options(option_storage, option_count);
            return 1;
        }
    }
    else if (!only_ccbin)
    {
        backend = cc_backend_at(0);
        if (!backend)
        {
            fprintf(stderr, "error: no backends registered\n");
            cc_module_free(&module);
            free_options(option_storage, option_count);
            return 1;
        }
    }

    cc_module_optimize(&module, opt_level);

    if (strip_metadata)
        cc_module_strip_metadata(&module);

    if (strip_hard)
    {
        if (!strip_map_path || *strip_map_path == '\0')
        {
            fprintf(stderr,
                    "error: --strip-hard requires --option strip-map=<path>\n");
            cc_module_free(&module);
            free_options(option_storage, option_count);
            return 1;
        }
        StripMap map = {0};
        if (!strip_map_load(strip_map_path, &map))
        {
            cc_module_free(&module);
            free_options(option_storage, option_count);
            return 1;
        }
        bool map_ok = apply_strip_map(&module, &map);
        strip_map_free(&map);
        if (!map_ok)
        {
            fprintf(stderr,
                    "error: failed to apply strip map '%s' to module symbols\n",
                    strip_map_path);
            cc_module_free(&module);
            free_options(option_storage, option_count);
            return 1;
        }
    }

    if (ccbin_path)
    {
        if (!cc_module_write_binary(&module, ccbin_path, &sink))
        {
            cc_module_free(&module);
            free_options(option_storage, option_count);
            return 1;
        }
    }

    bool emit_ok = true;
    if (backend)
    {
        CCBackendOption stack_options[20];
        size_t stack_option_count = option_count;
        if (option_count > 0)
        {
            memcpy(stack_options, option_storage, option_count * sizeof(CCBackendOption));
        }
        if (output_path && stack_option_count < sizeof(stack_options) / sizeof(stack_options[0]))
        {
            CCBackendOption output_option;
            output_option.key = "output";
            output_option.value = output_path;
            stack_options[stack_option_count++] = output_option;
        }
        char opt_level_buf[4];
        if (opt_level > 0 && stack_option_count < sizeof(stack_options) / sizeof(stack_options[0]))
        {
            CCBackendOption opt_option;
            snprintf(opt_level_buf, sizeof(opt_level_buf), "%d", opt_level);
            opt_option.key = "opt-level";
            opt_option.value = opt_level_buf;
            stack_options[stack_option_count++] = opt_option;
        }
            if (strip_metadata && stack_option_count < sizeof(stack_options) / sizeof(stack_options[0]))
            {
                CCBackendOption strip_option;
                strip_option.key = "strip";
                strip_option.value = "1";
                stack_options[stack_option_count++] = strip_option;
            }
            if (strip_hard && stack_option_count < sizeof(stack_options) / sizeof(stack_options[0]))
            {
                CCBackendOption strip_hard_option;
                strip_hard_option.key = "strip-hard";
                strip_hard_option.value = "1";
                stack_options[stack_option_count++] = strip_hard_option;
            }
            if (obfuscate && stack_option_count < sizeof(stack_options) / sizeof(stack_options[0]))
            {
                CCBackendOption obfuscate_option;
                obfuscate_option.key = "obfuscate";
                obfuscate_option.value = "1";
                stack_options[stack_option_count++] = obfuscate_option;
            }

        CCBackendOptions options;
        options.options = stack_options;
        options.option_count = stack_option_count;

        emit_ok = backend->emit(backend, &module, &options, &sink, backend->userdata);
    }

    cc_module_free(&module);
    free_options(option_storage, option_count);

    return emit_ok ? 0 : 1;
}
