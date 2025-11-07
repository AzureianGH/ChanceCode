#ifndef CC_DIAGNOSTICS_H
#define CC_DIAGNOSTICS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        CC_DIAG_INFO = 0,
        CC_DIAG_WARNING,
        CC_DIAG_ERROR
    } CCDiagnosticSeverity;

    typedef struct
    {
        CCDiagnosticSeverity severity;
        size_t line;
        size_t column;
        const char *message;
    } CCDiagnostic;

    typedef void (*CCDiagnosticCallback)(const CCDiagnostic *diagnostic, void *userdata);

    typedef struct
    {
        CCDiagnosticCallback callback;
        void *userdata;
    } CCDiagnosticSink;

    void cc_diag_init_default(CCDiagnosticSink *sink);
    void cc_diag_emit(CCDiagnosticSink *sink, CCDiagnosticSeverity severity, size_t line, size_t column, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* CC_DIAGNOSTICS_H */
