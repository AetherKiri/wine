/*
 * Madeira-SE native helpers used by Wine's WoW64 conversion layer.
 *
 * Copyright (C) 2026 The Madeira contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"

#if defined(__APPLE__) && defined(__aarch64__)

BOOLEAN WINAPI RtlIsCurrentProcess( HANDLE handle )
{
    return handle == NtCurrentProcess() || !NtCompareObjects( handle, NtCurrentProcess() );
}

static NTSTATUS get_shared_info_process( HANDLE process, BOOLEAN *is_wow64, WOW64INFO *info )
{
    PEB32 *peb32;
    NTSTATUS status = NtQueryInformationProcess( process, ProcessWow64Information,
                                                 &peb32, sizeof(peb32), NULL );

    if (status) return status;
    if (peb32) status = NtReadVirtualMemory( process, peb32 + 1, info, sizeof(*info), NULL );
    *is_wow64 = !!peb32;
    return status;
}

void WINAPI RtlOpenCrossProcessEmulatorWorkConnection( HANDLE process, HANDLE *section, void **address )
{
    WOW64INFO info;
    BOOLEAN is_wow64;
    HANDLE remote_section = 0;
    SIZE_T size = 0;

    *address = NULL;
    *section = 0;
    if (RtlIsCurrentProcess( process )) return;
    if (get_shared_info_process( process, &is_wow64, &info ) || !is_wow64) return;
    remote_section = (HANDLE)(ULONG_PTR)info.SectionHandle;
    if (!remote_section) return;
    if (NtDuplicateObject( process, remote_section, GetCurrentProcess(), section,
                           0, 0, DUPLICATE_SAME_ACCESS ))
        return;
    if (!NtMapViewOfSection( *section, GetCurrentProcess(), address, 0, 0, NULL,
                             &size, ViewShare, 0, PAGE_READWRITE ))
        return;
    NtClose( *section );
    *section = 0;
}

CROSS_PROCESS_WORK_ENTRY * WINAPI RtlWow64PopAllCrossProcessWorkFromWorkList(
    CROSS_PROCESS_WORK_HDR *list, BOOLEAN *flush )
{
    CROSS_PROCESS_WORK_HDR previous, next;
    UINT position, previous_position = 0;

    do
    {
        previous.hdr = list->hdr;
        if (!previous.first) break;
        next.first = 0;
        next.counter = previous.counter + 1;
    } while (InterlockedCompareExchange64( &list->hdr, next.hdr, previous.hdr ) != previous.hdr);

    *flush = !!(previous.first & CROSS_PROCESS_LIST_FLUSH);
    if (!(position = previous.first & ~CROSS_PROCESS_LIST_FLUSH)) return NULL;
    for (;;)
    {
        CROSS_PROCESS_WORK_ENTRY *entry = CROSS_PROCESS_LIST_ENTRY( list, position );
        UINT entry_next = entry->next;

        entry->next = previous_position;
        if (!entry_next) return entry;
        previous_position = position;
        position = entry_next;
    }
}

CROSS_PROCESS_WORK_ENTRY * WINAPI RtlWow64PopCrossProcessWorkFromFreeList(
    CROSS_PROCESS_WORK_HDR *list )
{
    CROSS_PROCESS_WORK_ENTRY *result;
    CROSS_PROCESS_WORK_HDR previous, next;

    do
    {
        previous.hdr = list->hdr;
        if (!previous.first) return NULL;
        result = CROSS_PROCESS_LIST_ENTRY( list, previous.first );
        next.first = result->next;
        next.counter = previous.counter + 1;
    } while (InterlockedCompareExchange64( &list->hdr, next.hdr, previous.hdr ) != previous.hdr);

    result->next = 0;
    return result;
}

BOOLEAN WINAPI RtlWow64PushCrossProcessWorkOntoFreeList( CROSS_PROCESS_WORK_HDR *list,
                                                         CROSS_PROCESS_WORK_ENTRY *entry )
{
    CROSS_PROCESS_WORK_HDR previous, next;

    do
    {
        previous.hdr = list->hdr;
        entry->next = previous.first;
        next.first = (char *)entry - (char *)list;
        next.counter = previous.counter + 1;
    } while (InterlockedCompareExchange64( &list->hdr, next.hdr, previous.hdr ) != previous.hdr);
    return TRUE;
}

BOOLEAN WINAPI RtlWow64PushCrossProcessWorkOntoWorkList( CROSS_PROCESS_WORK_HDR *list,
                                                         CROSS_PROCESS_WORK_ENTRY *entry,
                                                         void **unknown )
{
    CROSS_PROCESS_WORK_HDR previous, next;

    *unknown = NULL;
    do
    {
        previous.hdr = list->hdr;
        entry->next = previous.first;
        next.first = ((char *)entry - (char *)list) | (previous.first & CROSS_PROCESS_LIST_FLUSH);
        next.counter = previous.counter + 1;
    } while (InterlockedCompareExchange64( &list->hdr, next.hdr, previous.hdr ) != previous.hdr);
    return TRUE;
}

#endif /* __APPLE__ && __aarch64__ */
