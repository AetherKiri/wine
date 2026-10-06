/*
 * Madeira-SE CPU-provider PE/Unix boundary.
 *
 * Copyright (C) 2026 The Madeira contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __WINE_MADEIRACPU_UNIXLIB_H
#define __WINE_MADEIRACPU_UNIXLIB_H

#include <stdarg.h>

#include "windef.h"
#include "winternl.h"
#include "wine/unixlib.h"

#include "../../../madeira-se/include/madeira_se_wine_cpu.h"

/* This envelope is native ARM64 on both sides of WINE_UNIX_CALL. */
struct madeiracpu_dispatch_params
{
    uint32_t operation;
    uint32_t message_size;
    void *message;
    int32_t madeira_status;
    uint32_t reserved;
};

enum madeiracpu_unix_funcs
{
    unix_madeiracpu_dispatch,
    unix_madeiracpu_funcs_count
};

#endif /* __WINE_MADEIRACPU_UNIXLIB_H */
