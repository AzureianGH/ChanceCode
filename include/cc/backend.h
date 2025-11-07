#ifndef CC_BACKEND_H
#define CC_BACKEND_H

#include <stdbool.h>
#include <stddef.h>

#include "bytecode.h"
#include "diagnostics.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        const char *key;
        const char *value;
    } CCBackendOption;

    typedef struct
    {
        const CCBackendOption *options;
        size_t option_count;
    } CCBackendOptions;

    typedef struct CCBackend CCBackend;

    typedef bool (*CCBackendEmitFn)(const CCBackend *backend,
                                    const CCModule *module,
                                    const CCBackendOptions *options,
                                    CCDiagnosticSink *sink,
                                    void *userdata);

    struct CCBackend
    {
        const char *name;
        const char *description;
        CCBackendEmitFn emit;
        void *userdata;
    };

    bool cc_backend_register(const CCBackend *backend);
    size_t cc_backend_count(void);
    const CCBackend *cc_backend_at(size_t index);
    const CCBackend *cc_backend_find(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* CC_BACKEND_H */
