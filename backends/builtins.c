#include "cc/backend.h"

bool cc_register_backend_x86(void);

void cc_register_builtin_backends(void)
{
    cc_register_backend_x86();
}
