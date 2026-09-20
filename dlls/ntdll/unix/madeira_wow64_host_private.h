/*
 * Madeira-SE Mach-O WoW64 host build glue.
 *
 * Copyright (C) 2026 The Madeira contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __WINE_MADEIRA_WOW64_HOST_PRIVATE_H
#define __WINE_MADEIRA_WOW64_HOST_PRIVATE_H

#define MADEIRA_SE_WOW64_HOST 1

/* Keep the host conversion state separate from ntdll.so loader globals. */
#define native_machine madeira_wow64_native_machine
#define current_machine madeira_wow64_current_machine
#define pLdrSystemDllInitBlock madeira_wow64_init_block

#ifndef SetLastError
#define SetLastError(error) (NtCurrentTeb()->LastErrorValue = (error))
#endif
#ifndef GetLastError
#define GetLastError() (NtCurrentTeb()->LastErrorValue)
#endif

#endif /* __WINE_MADEIRA_WOW64_HOST_PRIVATE_H */
