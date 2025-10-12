#ifndef CC_LOADER_H
#define CC_LOADER_H

#include <stdbool.h>

#include "bytecode.h"
#include "diagnostics.h"

#ifdef __cplusplus
extern "C" {
#endif

bool cc_load_file(const char *path, CCModule *module, CCDiagnosticSink *sink);

#ifdef __cplusplus
}
#endif

#endif /* CC_LOADER_H */
