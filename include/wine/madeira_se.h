/*
 * Madeira-SE host address layout.
 *
 * Copyright (C) 2026 The Madeira contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __WINE_MADEIRA_SE_H
#define __WINE_MADEIRA_SE_H

#include <stdint.h>

/*
 * XNU gives native arm64 processes a permanent 4 GiB hard page-zero. Keep a
 * complete PE32 address space in a 4 GiB-aligned host arena so truncating a
 * host address still produces the corresponding x86 guest address.
 */
#if defined(__aarch64__) && (defined(__APPLE__) || defined(MADEIRA_SE_DARWIN_ARM64))
# define MADEIRA_SE_WOW64_BIASED_ADDRESS_SPACE 1
# define MADEIRA_SE_WOW64_GUEST_BIAS 0x0000007000000000ULL
# define MADEIRA_SE_WOW64_GUEST_SIZE 0x0000000100000000ULL
# define MADEIRA_SE_USER_SHARED_DATA_ADDRESS \
    (MADEIRA_SE_WOW64_GUEST_BIAS + 0x7ffe0000ULL)
#else
# define MADEIRA_SE_WOW64_GUEST_BIAS 0ULL
# define MADEIRA_SE_WOW64_GUEST_SIZE 0x0000000100000000ULL
# define MADEIRA_SE_USER_SHARED_DATA_ADDRESS 0x7ffe0000ULL
#endif

#define MADEIRA_SE_WOW64_LOWEST_USER_ADDRESS 0x00010000u

static inline void *madeira_se_wow64_guest_to_host( uint32_t address )
{
    /*
     * WoW64 APIs sometimes carry small integer sentinels in pointer slots
     * (NtContinue's legacy alertable argument is 0 or 1).  Windows cannot map
     * user memory below 64 KiB, so these values must not acquire the Madeira
     * guest arena bias.
     */
    if (address < MADEIRA_SE_WOW64_LOWEST_USER_ADDRESS)
        return (void *)(uintptr_t)address;
    return (void *)(uintptr_t)(MADEIRA_SE_WOW64_GUEST_BIAS + address);
}

static inline uint32_t madeira_se_wow64_host_to_guest( const void *address )
{
    uintptr_t value = (uintptr_t)address;
    uintptr_t base = (uintptr_t)MADEIRA_SE_WOW64_GUEST_BIAS;
    uintptr_t end = base + (uintptr_t)MADEIRA_SE_WOW64_GUEST_SIZE;

    if (!value) return 0;
    if (value >= base && value < end) value -= base;
    return (uint32_t)value;
}

/*
 * Pointer-sized integer arguments in a PE32 Unix thunk are carried in an
 * unsigned 32-bit protocol slot.  They are values rather than guest
 * addresses, so applying the Madeira address bias would corrupt them.  Cast
 * through int32_t to preserve the Win32 sign extension when widening them to
 * the native host width.
 */
static inline intptr_t madeira_se_wow64_widen_integer( uint32_t value )
{
    return (intptr_t)(int32_t)value;
}

#endif /* __WINE_MADEIRA_SE_H */
