#include "cc/diagnostics.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void cc_default_diag_callback(const CCDiagnostic *diagnostic, void *userdata) {
    (void)userdata;
    if (!diagnostic || !diagnostic->message) {
        return;
    }
    const char *severity = "info";
    switch (diagnostic->severity) {
        case CC_DIAG_WARNING:
            severity = "warning";
            break;
        case CC_DIAG_ERROR:
            severity = "error";
            break;
        case CC_DIAG_INFO:
        default:
            severity = "info";
            break;
    }
    if (diagnostic->line > 0) {
        fprintf(stderr, "%s:%zu:%zu: %s\n", severity, diagnostic->line, diagnostic->column, diagnostic->message);
    } else {
        fprintf(stderr, "%s: %s\n", severity, diagnostic->message);
    }
}

void cc_diag_init_default(CCDiagnosticSink *sink) {
    if (!sink) {
        return;
    }
    sink->callback = cc_default_diag_callback;
    sink->userdata = NULL;
}

void cc_diag_emit(CCDiagnosticSink *sink, CCDiagnosticSeverity severity, size_t line, size_t column, const char *fmt, ...) {
    if (!sink || !sink->callback || !fmt) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    CCDiagnostic diag;
    diag.severity = severity;
    diag.line = line;
    diag.column = column;
    diag.message = buffer;

    sink->callback(&diag, sink->userdata);
}
