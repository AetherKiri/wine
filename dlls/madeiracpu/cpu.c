/*
 * i386 emulation on ARM64 through Madeira-SE's QEMU TCTI provider.
 *
 * Copyright (C) 2026 The Madeira contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/debug.h"

#include "unixlib.h"

WINE_DEFAULT_DEBUG_CHANNEL(madeiracpu);

#define MADEIRACPU_RUN_BUDGET 50000u

struct thread_entry
{
    ULONG_PTR id;
    uint64_t host_handle;
    struct thread_entry *next;
};

struct guest_unix_call
{
    unixlib_handle_t handle;
    uint32_t id;
    uint32_t args;
};

typedef NTSTATUS (WINAPI *wine_unix_dispatch_fn)(unixlib_handle_t handle,
                                                 unsigned int code,
                                                 void *args);

static RTL_CRITICAL_SECTION thread_lock;
static struct thread_entry *thread_entries;
static uint64_t process_handle;
static void *syscall_dispatcher;
static void *unix_call_dispatcher;
static wine_unix_dispatch_fn wine_unix_dispatch;
static NTSTATUS init_status = STATUS_NOT_SUPPORTED;
static BOOL lock_initialized;

static TEB32 *current_teb32(void)
{
    return (TEB32 *)((char *)NtCurrentTeb() + NtCurrentTeb()->WowTebOffset);
}

static void init_message(void *message, size_t size)
{
    madeira_se_wine_cpu_message_header_t *header = message;

    memset(message, 0, size);
    header->version = MADEIRA_SE_WINE_CPU_ABI_VERSION;
    header->size = (uint32_t)size;
}

static NTSTATUS status_from_madeira(int32_t status)
{
    switch (status)
    {
    case MADEIRA_SE_OK:
        return STATUS_SUCCESS;
    case MADEIRA_SE_E_INVALID_ARGUMENT:
        return STATUS_INVALID_PARAMETER;
    case MADEIRA_SE_E_UNSUPPORTED:
    case MADEIRA_SE_E_UNSUPPORTED_ARCHITECTURE:
        return STATUS_NOT_SUPPORTED;
    case MADEIRA_SE_E_OUT_OF_MEMORY:
        return STATUS_NO_MEMORY;
    case MADEIRA_SE_E_NOT_FOUND:
        return STATUS_DLL_NOT_FOUND;
    case MADEIRA_SE_E_NOT_READY:
        return STATUS_DEVICE_NOT_READY;
    default:
        return STATUS_UNSUCCESSFUL;
    }
}

static NTSTATUS bridge_call(uint32_t operation, void *message, size_t size)
{
    struct madeiracpu_dispatch_params params;
    NTSTATUS status;

    if (size > UINT32_MAX) return STATUS_INVALID_PARAMETER;
    params.operation = operation;
    params.message_size = (uint32_t)size;
    params.message = message;
    params.madeira_status = MADEIRA_SE_E_NOT_READY;
    params.reserved = 0;
    status = WINE_UNIX_CALL(unix_madeiracpu_dispatch, &params);
    if (status) return status;
    return status_from_madeira(params.madeira_status);
}

static uint32_t memory_protection(ULONG protect)
{
    uint32_t result = 0;

    if (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
                   | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE
                   | PAGE_EXECUTE_WRITECOPY))
        result |= MADEIRA_SE_MEMORY_READ;
    if (protect & (PAGE_READWRITE | PAGE_WRITECOPY
                   | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        result |= MADEIRA_SE_MEMORY_WRITE;
    if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ
                   | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        result |= MADEIRA_SE_MEMORY_EXECUTE;
    return result;
}

static NTSTATUS notify_memory(uint32_t event, const void *address,
                              SIZE_T size, ULONG protect)
{
    madeira_se_wine_cpu_memory_message_t params;

    if (!process_handle) return init_status;
    init_message(&params, sizeof(params));
    params.process_handle = process_handle;
    params.event = event;
    params.protection = memory_protection(protect);
    params.guest_address = (uint64_t)(ULONG_PTR)address;
    params.size = (uint64_t)size;
    return bridge_call(MADEIRA_SE_WINE_CPU_MEMORY_EVENT, &params,
                       sizeof(params));
}

static NTSTATUS invalidate_memory(const void *address, SIZE_T size)
{
    madeira_se_wine_cpu_invalidate_message_t params;

    if (!process_handle || !size) return init_status;
    init_message(&params, sizeof(params));
    params.process_handle = process_handle;
    params.guest_address = (uint64_t)(ULONG_PTR)address;
    params.size = (uint64_t)size;
    return bridge_call(MADEIRA_SE_WINE_CPU_INVALIDATE, &params,
                       sizeof(params));
}

static NTSTATUS map_existing_address_space(void)
{
    const uint64_t address_limit = 1ull << 32;
    uint64_t cursor = 0;

    while (cursor < address_limit)
    {
        MEMORY_BASIC_INFORMATION info;
        SIZE_T returned_size;
        uint64_t base;
        uint64_t region_size;
        uint64_t next;
        NTSTATUS status;

        status = NtQueryVirtualMemory(GetCurrentProcess(),
                                      (void *)(ULONG_PTR)cursor,
                                      MemoryBasicInformation, &info,
                                      sizeof(info), &returned_size);
        if (status) return status;
        base = (uint64_t)(ULONG_PTR)info.BaseAddress;
        region_size = (uint64_t)info.RegionSize;
        if (!region_size || base >= address_limit)
            break;
        next = region_size > address_limit - base
             ? address_limit : base + region_size;
        if (next <= cursor) return STATUS_INVALID_ADDRESS;
        if (info.State == MEM_COMMIT && base < address_limit)
        {
            status = notify_memory(MADEIRA_SE_CPU_MEMORY_MAP,
                                   (void *)(ULONG_PTR)base,
                                   (SIZE_T)(next - base), info.Protect);
            if (status) return status;
        }
        cursor = next;
    }
    return STATUS_SUCCESS;
}

static uint64_t find_thread_handle(ULONG_PTR id)
{
    struct thread_entry *entry;
    uint64_t handle = 0;

    RtlEnterCriticalSection(&thread_lock);
    for (entry = thread_entries; entry; entry = entry->next)
        if (entry->id == id)
        {
            handle = entry->host_handle;
            break;
        }
    RtlLeaveCriticalSection(&thread_lock);
    return handle;
}

static uint64_t remove_thread_handle(ULONG_PTR id)
{
    struct thread_entry **link;
    struct thread_entry *entry;
    uint64_t handle = 0;

    RtlEnterCriticalSection(&thread_lock);
    for (link = &thread_entries; *link; link = &(*link)->next)
        if ((*link)->id == id) break;
    entry = *link;
    if (entry)
    {
        *link = entry->next;
        handle = entry->host_handle;
    }
    RtlLeaveCriticalSection(&thread_lock);
    if (entry) RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, entry);
    return handle;
}

static void context_to_canonical(const I386_CONTEXT *source,
                                 madeira_se_x86_context_t *target)
{
    memset(target, 0, sizeof(*target));
    target->version = MADEIRA_SE_CPU_ABI_VERSION;
    target->architecture = MADEIRA_SE_ARCH_X86_32;
    target->gpr[MADEIRA_SE_X86_RAX] = source->Eax;
    target->gpr[MADEIRA_SE_X86_RCX] = source->Ecx;
    target->gpr[MADEIRA_SE_X86_RDX] = source->Edx;
    target->gpr[MADEIRA_SE_X86_RBX] = source->Ebx;
    target->gpr[MADEIRA_SE_X86_RSP] = source->Esp;
    target->gpr[MADEIRA_SE_X86_RBP] = source->Ebp;
    target->gpr[MADEIRA_SE_X86_RSI] = source->Esi;
    target->gpr[MADEIRA_SE_X86_RDI] = source->Edi;
    target->rip = source->Eip;
    target->rflags = source->EFlags;
    target->segment[MADEIRA_SE_X86_SEGMENT_CS] = (uint16_t)source->SegCs;
    target->segment[MADEIRA_SE_X86_SEGMENT_SS] = (uint16_t)source->SegSs;
    target->segment[MADEIRA_SE_X86_SEGMENT_DS] = (uint16_t)source->SegDs;
    target->segment[MADEIRA_SE_X86_SEGMENT_ES] = (uint16_t)source->SegEs;
    target->segment[MADEIRA_SE_X86_SEGMENT_FS] = (uint16_t)source->SegFs;
    target->segment[MADEIRA_SE_X86_SEGMENT_GS] = (uint16_t)source->SegGs;
    target->segment_base[MADEIRA_SE_X86_SEGMENT_FS] =
        (uint64_t)(ULONG_PTR)current_teb32();
    target->debug_register[0] = source->Dr0;
    target->debug_register[1] = source->Dr1;
    target->debug_register[2] = source->Dr2;
    target->debug_register[3] = source->Dr3;
    target->debug_register[6] = source->Dr6;
    target->debug_register[7] = source->Dr7;
    memcpy(target->fxsave, source->ExtendedRegisters,
           sizeof(source->ExtendedRegisters));
}

static void canonical_to_context(const madeira_se_x86_context_t *source,
                                 I386_CONTEXT *target)
{
    target->ContextFlags = CONTEXT_I386_ALL;
    target->Eax = (DWORD)source->gpr[MADEIRA_SE_X86_RAX];
    target->Ecx = (DWORD)source->gpr[MADEIRA_SE_X86_RCX];
    target->Edx = (DWORD)source->gpr[MADEIRA_SE_X86_RDX];
    target->Ebx = (DWORD)source->gpr[MADEIRA_SE_X86_RBX];
    target->Esp = (DWORD)source->gpr[MADEIRA_SE_X86_RSP];
    target->Ebp = (DWORD)source->gpr[MADEIRA_SE_X86_RBP];
    target->Esi = (DWORD)source->gpr[MADEIRA_SE_X86_RSI];
    target->Edi = (DWORD)source->gpr[MADEIRA_SE_X86_RDI];
    target->Eip = (DWORD)source->rip;
    target->EFlags = (DWORD)source->rflags;
    target->SegCs = source->segment[MADEIRA_SE_X86_SEGMENT_CS];
    target->SegSs = source->segment[MADEIRA_SE_X86_SEGMENT_SS];
    target->SegDs = source->segment[MADEIRA_SE_X86_SEGMENT_DS];
    target->SegEs = source->segment[MADEIRA_SE_X86_SEGMENT_ES];
    target->SegFs = source->segment[MADEIRA_SE_X86_SEGMENT_FS];
    target->SegGs = source->segment[MADEIRA_SE_X86_SEGMENT_GS];
    target->Dr0 = (DWORD)source->debug_register[0];
    target->Dr1 = (DWORD)source->debug_register[1];
    target->Dr2 = (DWORD)source->debug_register[2];
    target->Dr3 = (DWORD)source->debug_register[3];
    target->Dr6 = (DWORD)source->debug_register[6];
    target->Dr7 = (DWORD)source->debug_register[7];
    memcpy(target->ExtendedRegisters, source->fxsave,
           sizeof(target->ExtendedRegisters));
}

static void service_dispatcher(I386_CONTEXT *context, BOOL unix_call)
{
    DWORD *stack = ULongToPtr(context->Esp);
    DWORD return_eip = stack[0];
    DWORD return_esp = context->Esp + sizeof(DWORD);
    NTSTATUS status;

    if (unix_call)
    {
        const struct guest_unix_call *call = ULongToPtr(return_esp);

        if (wine_unix_dispatch)
            status = wine_unix_dispatch(call->handle, call->id,
                                        ULongToPtr(call->args));
        else
            status = STATUS_NOT_SUPPORTED;
        return_esp += sizeof(*call);
    }
    else
    {
        Wow64ProcessPendingCrossProcessItems();
        status = Wow64SystemServiceEx(context->Eax,
                                      ULongToPtr(return_esp + sizeof(DWORD)));
    }

    /* A syscall may install a new context. Do not overwrite it in that case. */
    if (context->Eip == PtrToUlong(unix_call ? unix_call_dispatcher
                                             : syscall_dispatcher))
    {
        context->Eax = status;
        context->Esp = return_esp;
        context->Eip = return_eip;
    }
}

static NTSTATUS status_from_exception(uint32_t vector)
{
    switch (vector)
    {
    case 0: return STATUS_INTEGER_DIVIDE_BY_ZERO;
    case 1: return STATUS_SINGLE_STEP;
    case 3: return STATUS_BREAKPOINT;
    case 6: return STATUS_ILLEGAL_INSTRUCTION;
    case 14: return STATUS_ACCESS_VIOLATION;
    default: return STATUS_ILLEGAL_INSTRUCTION;
    }
}

/***********************************************************************
 *           BTCpuProcessInit  (madeiracpu.@)
 */
void WINAPI BTCpuProcessInit(void)
{
    madeira_se_wine_cpu_query_message_t query;
    madeira_se_wine_cpu_process_init_message_t process;
    WOW64INFO *wow64info = NtCurrentTeb()->TlsSlots[WOW64_TLS_WOW64INFO];
    UNICODE_STRING ntdll_name = RTL_CONSTANT_STRING(L"ntdll.dll");
    wine_unix_dispatch_fn *dispatcher_ptr;
    HMODULE ntdll;
    void *bridge_page = NULL;
    void *protect_page;
    SIZE_T size = 0x1000;
    SIZE_T protect_size;
    ULONG old_protection;
    NTSTATUS status;

    if (process_handle) return;

    init_message(&query, sizeof(query));
    status = bridge_call(MADEIRA_SE_WINE_CPU_QUERY, &query, sizeof(query));
    if (status) goto failed;
    if (!(query.capabilities & MADEIRA_SE_CPU_CAP_NO_RUNTIME_CODEGEN)
        || !(query.capabilities & MADEIRA_SE_CPU_CAP_X86_32))
    {
        status = STATUS_NOT_SUPPORTED;
        goto failed;
    }

    status = NtAllocateVirtualMemory(GetCurrentProcess(), &bridge_page,
                                     ((ULONG_PTR)1 << 31) - 1, &size,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (status) goto failed;
    *(DWORD *)bridge_page = 0x2ecd2ecd;
    syscall_dispatcher = bridge_page;
    unix_call_dispatcher = (char *)bridge_page + 2;

    protect_page = bridge_page;
    protect_size = size;
    status = NtProtectVirtualMemory(GetCurrentProcess(), &protect_page,
                                    &protect_size, PAGE_READONLY,
                                    &old_protection);
    if (status) goto failed;

    status = LdrGetDllHandle(NULL, 0, &ntdll_name, &ntdll);
    if (status) goto failed;
    dispatcher_ptr = RtlFindExportedRoutineByName(
        ntdll, "__wine_unix_call_dispatcher");
    if (!dispatcher_ptr)
    {
        status = STATUS_PROCEDURE_NOT_FOUND;
        goto failed;
    }
    wine_unix_dispatch = *dispatcher_ptr;

    init_message(&process, sizeof(process));
    process.architecture = MADEIRA_SE_ARCH_X86_32;
    process.flags = MADEIRA_SE_WINE_CPU_PROCESS_DIRECT_ADDRESS_SPACE;
    status = bridge_call(MADEIRA_SE_WINE_CPU_PROCESS_INIT, &process,
                         sizeof(process));
    if (status) goto failed;
    process_handle = process.process_handle;
    status = map_existing_address_space();
    if (status) goto failed;

    wow64info->CpuFlags |= WOW64_CPUFLAGS_SOFTWARE;
    init_status = STATUS_SUCCESS;
    TRACE("Madeira-SE i386 TCTI provider initialized\n");
    return;

failed:
    if (process_handle)
    {
        madeira_se_wine_cpu_process_term_message_t terminate;

        init_message(&terminate, sizeof(terminate));
        terminate.process_handle = process_handle;
        bridge_call(MADEIRA_SE_WINE_CPU_PROCESS_TERM, &terminate,
                    sizeof(terminate));
        process_handle = 0;
    }
    init_status = status;
    ERR("failed to initialize Madeira-SE i386 provider, status %#lx\n",
        status);
}

/***********************************************************************
 *           BTCpuThreadInit  (madeiracpu.@)
 */
void WINAPI BTCpuThreadInit(void)
{
    madeira_se_wine_cpu_thread_init_message_t params;
    struct thread_entry *entry;
    ULONG_PTR id = (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;
    NTSTATUS status;

    if (init_status || find_thread_handle(id)) return;
    entry = RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap,
                            HEAP_ZERO_MEMORY, sizeof(*entry));
    if (!entry)
    {
        init_status = STATUS_NO_MEMORY;
        return;
    }
    init_message(&params, sizeof(params));
    params.process_handle = process_handle;
    params.thread_id = id;
    status = bridge_call(MADEIRA_SE_WINE_CPU_THREAD_INIT, &params,
                         sizeof(params));
    if (status)
    {
        RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, entry);
        ERR("failed to initialize TCTI thread, status %#lx\n", status);
        return;
    }
    entry->id = id;
    entry->host_handle = params.thread_handle;
    RtlEnterCriticalSection(&thread_lock);
    entry->next = thread_entries;
    thread_entries = entry;
    RtlLeaveCriticalSection(&thread_lock);
}

/***********************************************************************
 *           BTCpuSimulate  (madeiracpu.@)
 */
void WINAPI BTCpuSimulate(void)
{
    madeira_se_wine_cpu_run_message_t params;
    I386_CONTEXT *context;
    uint64_t thread_handle;
    USHORT machine;
    NTSTATUS status;

    if (init_status) RtlRaiseStatus(init_status);
    thread_handle = find_thread_handle(
        (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread);
    if (!thread_handle)
    {
        BTCpuThreadInit();
        thread_handle = find_thread_handle(
            (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread);
        if (!thread_handle) RtlRaiseStatus(STATUS_DEVICE_NOT_READY);
    }
    status = RtlWow64GetCurrentCpuArea(&machine, (void **)&context, NULL);
    if (status) RtlRaiseStatus(status);
    if (machine != IMAGE_FILE_MACHINE_I386)
        RtlRaiseStatus(STATUS_NOT_SUPPORTED);

    if (context->Eip == PtrToUlong(syscall_dispatcher))
    {
        service_dispatcher(context, FALSE);
        return;
    }
    if (context->Eip == PtrToUlong(unix_call_dispatcher))
    {
        service_dispatcher(context, TRUE);
        return;
    }

    init_message(&params, sizeof(params));
    params.thread_handle = thread_handle;
    params.request.version = MADEIRA_SE_CPU_ABI_VERSION;
    params.request.max_instructions = MADEIRACPU_RUN_BUDGET;
    params.request.syscall_dispatcher = (uint64_t)(ULONG_PTR)syscall_dispatcher;
    params.request.unix_call_dispatcher = (uint64_t)(ULONG_PTR)unix_call_dispatcher;
    context_to_canonical(context, &params.context);
    params.result.version = MADEIRA_SE_CPU_ABI_VERSION;
    status = bridge_call(MADEIRA_SE_WINE_CPU_RUN, &params, sizeof(params));
    if (status) RtlRaiseStatus(status);
    canonical_to_context(&params.context, context);

    if (params.result.reason == MADEIRA_SE_CPU_EXIT_SYSCALL
        || context->Eip == PtrToUlong(syscall_dispatcher))
        service_dispatcher(context, FALSE);
    else if (params.result.reason == MADEIRA_SE_CPU_EXIT_UNIX_CALL
             || context->Eip == PtrToUlong(unix_call_dispatcher))
        service_dispatcher(context, TRUE);
    else if (params.result.reason == MADEIRA_SE_CPU_EXIT_EXCEPTION)
        RtlRaiseStatus(status_from_exception(params.result.exception_vector));
    else if (params.result.reason == MADEIRA_SE_CPU_EXIT_HALT)
        RtlRaiseStatus(STATUS_ILLEGAL_INSTRUCTION);
}

void * WINAPI BTCpuGetBopCode(void)
{
    return syscall_dispatcher;
}

void * WINAPI __wine_get_unix_opcode(void)
{
    return unix_call_dispatcher;
}

NTSTATUS WINAPI BTCpuGetContext(HANDLE thread, HANDLE process, void *unknown,
                                I386_CONTEXT *context)
{
    (void)process;
    (void)unknown;
    return RtlWow64GetThreadContext(thread, context);
}

NTSTATUS WINAPI BTCpuSetContext(HANDLE thread, HANDLE process, void *unknown,
                                I386_CONTEXT *context)
{
    (void)process;
    (void)unknown;
    return RtlWow64SetThreadContext(thread, context);
}

NTSTATUS WINAPI BTCpuResetToConsistentState(EXCEPTION_POINTERS *pointers)
{
    (void)pointers;
    return STATUS_SUCCESS;
}

BOOLEAN WINAPI BTCpuIsProcessorFeaturePresent(UINT feature)
{
    static const ULONGLONG features =
        (1ull << PF_COMPARE_EXCHANGE_DOUBLE) |
        (1ull << PF_MMX_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_XMMI_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_RDTSC_INSTRUCTION_AVAILABLE) |
        (1ull << PF_XMMI64_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_NX_ENABLED) |
        (1ull << PF_SSE3_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_COMPARE_EXCHANGE128) |
        (1ull << PF_FASTFAIL_AVAILABLE) |
        (1ull << PF_RDTSCP_INSTRUCTION_AVAILABLE) |
        (1ull << PF_SSSE3_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SSE4_1_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SSE4_2_INSTRUCTIONS_AVAILABLE);

    return feature < 64 && (features & (1ull << feature));
}

NTSTATUS WINAPI BTCpuTurboThunkControl(ULONG enable)
{
    return enable ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

void WINAPI BTCpuUpdateProcessorInformation(SYSTEM_CPU_INFORMATION *info)
{
    info->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
    info->ProcessorLevel = 6;
    info->ProcessorRevision = 0x3a09;
}

void WINAPI BTCpuFlushInstructionCache2(const void *address, SIZE_T size)
{
    NTSTATUS status = invalidate_memory(address, size);
    if (status) WARN("instruction-cache invalidation failed, status %#lx\n",
                     status);
}

void WINAPI BTCpuFlushInstructionCacheHeavy(const void *address, SIZE_T size)
{
    BTCpuFlushInstructionCache2(address, size);
}

void WINAPI BTCpuNotifyMemoryDirty(void *address, SIZE_T size)
{
    NTSTATUS status = notify_memory(MADEIRA_SE_CPU_MEMORY_DIRTY, address,
                                    size, PAGE_READWRITE);
    if (status) WARN("memory-dirty notification failed, status %#lx\n", status);
}

void WINAPI BTCpuNotifyMemoryAlloc(void *address, SIZE_T size, ULONG type,
                                   ULONG protect, BOOL is_post,
                                   NTSTATUS status)
{
    (void)type;
    if (is_post && !status)
        status = notify_memory(MADEIRA_SE_CPU_MEMORY_MAP, address, size, protect);
    if (status) WARN("memory-allocation notification failed, status %#lx\n",
                     status);
}

void WINAPI BTCpuNotifyMemoryProtect(void *address, SIZE_T size, ULONG protect,
                                     BOOL is_post, NTSTATUS status)
{
    if (is_post && !status)
        status = notify_memory(MADEIRA_SE_CPU_MEMORY_PROTECT, address, size,
                               protect);
    if (status) WARN("memory-protection notification failed, status %#lx\n",
                     status);
}

void WINAPI BTCpuNotifyMemoryFree(void *address, SIZE_T size, ULONG type,
                                  BOOL is_post, NTSTATUS status)
{
    (void)type;
    if (is_post && !status)
        status = notify_memory(MADEIRA_SE_CPU_MEMORY_UNMAP, address, size, 0);
    if (status) WARN("memory-free notification failed, status %#lx\n", status);
}

NTSTATUS WINAPI BTCpuNotifyMapViewOfSection(void *unknown1, void *address,
                                             void *unknown2, SIZE_T size,
                                             ULONG allocation_type,
                                             ULONG protect)
{
    (void)unknown1;
    (void)unknown2;
    (void)allocation_type;
    return notify_memory(MADEIRA_SE_CPU_MEMORY_MAP, address, size, protect);
}

void WINAPI BTCpuNotifyUnmapViewOfSection(void *address, BOOL is_post,
                                           NTSTATUS status)
{
    if (is_post && !status)
        status = notify_memory(MADEIRA_SE_CPU_MEMORY_UNMAP, address, 0, 0);
    if (status) WARN("section-unmap notification failed, status %#lx\n", status);
}

void WINAPI BTCpuNotifyReadFile(HANDLE handle, void *address, SIZE_T size,
                                BOOL is_post, NTSTATUS status)
{
    (void)handle;
    if (is_post && !status)
        status = notify_memory(MADEIRA_SE_CPU_MEMORY_DIRTY, address, size,
                               PAGE_READWRITE);
    if (status) WARN("read notification failed, status %#lx\n", status);
}

void WINAPI BTCpuThreadTerm(HANDLE thread, LONG exit_code)
{
    madeira_se_wine_cpu_thread_term_message_t params;
    THREAD_BASIC_INFORMATION info;
    ULONG_PTR id;
    uint64_t handle;
    NTSTATUS status;

    (void)exit_code;
    if (!thread || thread == NtCurrentThread())
        id = (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;
    else
    {
        status = NtQueryInformationThread(thread, ThreadBasicInformation,
                                          &info, sizeof(info), NULL);
        if (status) return;
        id = (ULONG_PTR)info.ClientId.UniqueThread;
    }
    handle = remove_thread_handle(id);
    if (!handle) return;
    init_message(&params, sizeof(params));
    params.thread_handle = handle;
    params.exit_code = exit_code;
    status = bridge_call(MADEIRA_SE_WINE_CPU_THREAD_TERM, &params,
                         sizeof(params));
    if (status) WARN("thread termination failed, status %#lx\n", status);
}

void WINAPI BTCpuProcessTerm(HANDLE process, BOOL is_post, NTSTATUS status)
{
    madeira_se_wine_cpu_process_term_message_t params;
    struct thread_entry *entry;

    (void)process;
    if (is_post || !process_handle) return;
    init_message(&params, sizeof(params));
    params.process_handle = process_handle;
    params.exit_code = status;
    status = bridge_call(MADEIRA_SE_WINE_CPU_PROCESS_TERM, &params,
                         sizeof(params));
    if (status) WARN("process termination failed, status %#lx\n", status);
    process_handle = 0;
    init_status = STATUS_DEVICE_NOT_READY;

    RtlEnterCriticalSection(&thread_lock);
    entry = thread_entries;
    thread_entries = NULL;
    RtlLeaveCriticalSection(&thread_lock);
    while (entry)
    {
        struct thread_entry *next = entry->next;
        RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, entry);
        entry = next;
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    NTSTATUS status;

    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
    {
        status = __wine_init_unix_call();
        if (status) return FALSE;
        status = RtlInitializeCriticalSection(&thread_lock);
        if (status) return FALSE;
        lock_initialized = TRUE;
        LdrDisableThreadCalloutsForDll(instance);
    }
    else if (reason == DLL_PROCESS_DETACH && lock_initialized)
    {
        RtlDeleteCriticalSection(&thread_lock);
        lock_initialized = FALSE;
    }
    return TRUE;
}
