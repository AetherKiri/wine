/*
 * Madeira-SE CPU-provider Unix bridge.
 *
 * Copyright (C) 2026 The Madeira contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "unixlib.h"

typedef int32_t (*host_dispatch_fn)(uint32_t operation, void *message,
                                    uint32_t message_size);
typedef int32_t (*runtime_start_fn)(const char *qemu_library_path);

static pthread_once_t resolve_once = PTHREAD_ONCE_INIT;
static host_dispatch_fn host_dispatch;
static void *runtime_library;

static void resolve_host_dispatch(void)
{
    const char *runtime_path;
    const char *qemu_path;
    runtime_start_fn runtime_start = NULL;
    void *symbol;

    symbol = dlsym(RTLD_DEFAULT, "madeira_se_wine_cpu_dispatch_message");
    memcpy(&host_dispatch, &symbol, sizeof(host_dispatch));
    if (host_dispatch) return;

    runtime_path = getenv("MADEIRA_SE_RUNTIME_LIBRARY");
    qemu_path = getenv("MADEIRA_SE_QEMU_LIBRARY");
    if (!runtime_path || !runtime_path[0] || !qemu_path || !qemu_path[0])
        return;

    runtime_library = dlopen(runtime_path, RTLD_NOW | RTLD_GLOBAL);
    if (!runtime_library) return;
    symbol = dlsym(runtime_library, "madeira_se_wine_qemu_runtime_start");
    memcpy(&runtime_start, &symbol, sizeof(runtime_start));
    if (!runtime_start || runtime_start(qemu_path) != MADEIRA_SE_OK)
        return;
    symbol = dlsym(runtime_library,
                   "madeira_se_wine_cpu_dispatch_message");
    memcpy(&host_dispatch, &symbol, sizeof(host_dispatch));
}

static size_t message_size_for_operation(uint32_t operation)
{
    switch (operation)
    {
    case MADEIRA_SE_WINE_CPU_QUERY:
        return sizeof(madeira_se_wine_cpu_query_message_t);
    case MADEIRA_SE_WINE_CPU_PROCESS_INIT:
        return sizeof(madeira_se_wine_cpu_process_init_message_t);
    case MADEIRA_SE_WINE_CPU_PROCESS_TERM:
        return sizeof(madeira_se_wine_cpu_process_term_message_t);
    case MADEIRA_SE_WINE_CPU_THREAD_INIT:
        return sizeof(madeira_se_wine_cpu_thread_init_message_t);
    case MADEIRA_SE_WINE_CPU_THREAD_TERM:
        return sizeof(madeira_se_wine_cpu_thread_term_message_t);
    case MADEIRA_SE_WINE_CPU_RUN:
        return sizeof(madeira_se_wine_cpu_run_message_t);
    case MADEIRA_SE_WINE_CPU_MEMORY_EVENT:
        return sizeof(madeira_se_wine_cpu_memory_message_t);
    case MADEIRA_SE_WINE_CPU_INVALIDATE:
        return sizeof(madeira_se_wine_cpu_invalidate_message_t);
    case MADEIRA_SE_WINE_CPU_INTERRUPT:
        return sizeof(madeira_se_wine_cpu_interrupt_message_t);
    default:
        return 0;
    }
}

static NTSTATUS madeiracpu_dispatch(void *args)
{
    struct madeiracpu_dispatch_params *params = args;
    madeira_se_wine_cpu_message_header_t *header;
    size_t expected_size;

    if (!params || !params->message) return STATUS_INVALID_PARAMETER;
    expected_size = message_size_for_operation(params->operation);
    if (!expected_size || expected_size != params->message_size)
        return STATUS_INVALID_PARAMETER;
    header = params->message;
    if (header->version != MADEIRA_SE_WINE_CPU_ABI_VERSION
        || header->size != params->message_size)
        return STATUS_REVISION_MISMATCH;

    pthread_once(&resolve_once, resolve_host_dispatch);
    if (!host_dispatch) return STATUS_DLL_NOT_FOUND;
    params->madeira_status = host_dispatch(params->operation, params->message,
                                           params->message_size);
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    madeiracpu_dispatch,
};

C_ASSERT(ARRAY_SIZE(__wine_unix_call_funcs) == unix_madeiracpu_funcs_count);
