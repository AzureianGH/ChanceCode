#include "cc/backend.h"

bool cc_register_backend_x86(void);
bool cc_register_backend_arm64(void);

void cc_register_builtin_backends(void)
{
    cc_register_backend_x86();
    cc_register_backend_arm64();
}
