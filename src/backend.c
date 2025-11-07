#include "cc/backend.h"

#include <stdlib.h>
#include <string.h>

static const CCBackend **g_backends = NULL;
static size_t g_backend_count = 0;
static size_t g_backend_capacity = 0;

static int cc_backend_name_compare(const char *a, const char *b)
{
    if (!a && !b)
    {
        return 0;
    }
    if (!a)
    {
        return -1;
    }
    if (!b)
    {
        return 1;
    }
    return strcmp(a, b);
}

bool cc_backend_register(const CCBackend *backend)
{
    if (!backend || !backend->name || !backend->emit)
    {
        return false;
    }
    if (cc_backend_find(backend->name))
    {
        return false;
    }
    if (g_backend_capacity == g_backend_count)
    {
        size_t new_capacity = g_backend_capacity ? g_backend_capacity * 2 : 4;
        const CCBackend **new_data = (const CCBackend **)realloc(g_backends, new_capacity * sizeof(const CCBackend *));
        if (!new_data)
        {
            return false;
        }
        g_backends = new_data;
        g_backend_capacity = new_capacity;
    }
    g_backends[g_backend_count++] = backend;
    return true;
}

size_t cc_backend_count(void)
{
    return g_backend_count;
}

const CCBackend *cc_backend_at(size_t index)
{
    if (index >= g_backend_count)
    {
        return NULL;
    }
    return g_backends[index];
}

const CCBackend *cc_backend_find(const char *name)
{
    if (!name)
    {
        return NULL;
    }
    for (size_t i = 0; i < g_backend_count; ++i)
    {
        if (cc_backend_name_compare(g_backends[i]->name, name) == 0)
        {
            return g_backends[i];
        }
    }
    return NULL;
}
