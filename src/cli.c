#include "cc/backend.h"
#include "cc/diagnostics.h"
#include "cc/loader.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cc_register_builtin_backends(void);

static void print_usage(void)
{
    fprintf(stderr, "Usage: ccb <input.ccb> [-O0|-O1|-O2] [--backend NAME] [--output PATH] [--option key=value] [--list-backends] [--emit-ccbin PATH]\n");
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

int main(int argc, char **argv)
{
    const char *input_path = NULL;
    const char *backend_name = NULL;
    const char *output_path = NULL;
    const char *ccbin_path = NULL;
    bool list_backends = false;
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
                    fprintf(stderr, "error: -O expects a level (0,1,2)\n");
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
                fprintf(stderr, "error: invalid optimization level '%s' (use -O0|-O1|-O2)\n", level_str);
                return 1;
            }
            int level = atoi(level_str);
            if (level < 0 || level > 2)
            {
                fprintf(stderr, "error: invalid optimization level '%s' (use -O0|-O1|-O2)\n", level_str);
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

    bool only_ccbin = (ccbin_path != NULL) && (backend_name == NULL) && (output_path == NULL) && (option_count == 0);

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
        CCBackendOption stack_options[18];
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

        CCBackendOptions options;
        options.options = stack_options;
        options.option_count = stack_option_count;

        emit_ok = backend->emit(backend, &module, &options, &sink, backend->userdata);
    }

    cc_module_free(&module);
    free_options(option_storage, option_count);

    return emit_ok ? 0 : 1;
}
