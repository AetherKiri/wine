/*
 * Madeira-SE no-JIT x86 CPU provider hosted directly in Mach-O ntdll.so.
 *
 * Copyright (C) 2026 The Madeira contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winnt.h"
#include "winternl.h"
#include "unix_private.h"
#include "wine/debug.h"
#include "wine/madeira_se.h"
#include "madeira_wow64.h"
#include "../../../../madeira-se/include/madeira_se_wine_cpu.h"

WINE_DEFAULT_DEBUG_CHANNEL(madeiracpu);

#define MADEIRA_CPU_RUN_BUDGET_DEFAULT 8000000u
#define MADEIRA_CPU_RUN_BUDGET_MIN 1000u
#define MADEIRA_CPU_RUN_BUDGET_MAX 100000000u
#define MADEIRA_SE_X64_BRIDGE_HINT ((void *)(uintptr_t)0x6ffe00000000ULL)
#define MADEIRA_SE_X64_CALLBACK_MAX_DATA (16u * 1024u * 1024u)
#define MADEIRA_SE_X64_CALLBACK_RESULT_RESERVE (64u * 1024u)
#define MADEIRA_SE_X64_CALLBACK_STACK_RESERVE (1024u * 1024u)

/* CPU-heavy guest code such as image decoders suffers badly when every
 * 50k-instruction slice has to cross the Wine/QEMU boundary.  Keep the
 * default large enough for useful throughput, while retaining an escape
 * hatch for interactive/debug runs. */
static uint64_t madeira_cpu_run_budget(void)
{
    static uint64_t budget;
    const char *value;
    char *end;
    unsigned long long parsed;

    if (budget) return budget;
    budget = MADEIRA_CPU_RUN_BUDGET_DEFAULT;
    value = getenv( "MADEIRA_SE_CPU_RUN_BUDGET" );
    if (!value || !*value) return budget;

    errno = 0;
    parsed = strtoull( value, &end, 10 );
    if (!errno && end != value && !*end && parsed >= MADEIRA_CPU_RUN_BUDGET_MIN &&
        parsed <= MADEIRA_CPU_RUN_BUDGET_MAX)
        budget = parsed;
    return budget;
}

/* A resident QEMU CPU context is an optimization only when Wine can prove
 * that nothing touched the saved guest context between slices.  That proof
 * is not available on the WoW64 callback path, so keep reuse disabled by
 * default.  A bounded opt-in is useful for profiling and can be enabled once
 * a title has passed the long-running correctness test. */
static unsigned int madeira_cpu_reuse_slices(void)
{
    static int initialized;
    static unsigned int slices;
    const char *value;
    char *end;
    unsigned long parsed;

    if (initialized) return slices;
    initialized = 1;
    if (getenv( "MADEIRA_DISABLE_CPU_REUSE" )) return 0;
    value = getenv( "MADEIRA_SE_CPU_REUSE_SLICES" );
    if (!value || !*value) return 0;
    errno = 0;
    parsed = strtoul( value, &end, 10 );
    if (!errno && end != value && !*end && parsed <= 64) slices = (unsigned int)parsed;
    return slices;
}

typedef int32_t (*host_dispatch_fn)(uint32_t, void *, uint32_t);
typedef int32_t (*runtime_start_fn)(const char *);

/* This is the PE x86-64 ntdll callback frame.  The ARM64 host cannot branch
 * to the guest dispatcher directly, so Madeira-SE constructs the same frame
 * in host memory and runs the guest dispatcher through TCTI. */
struct madeira_x64_machine_frame
{
    ULONG64 rip;
    ULONG64 cs;
    ULONG64 eflags;
    ULONG64 rsp;
    ULONG64 ss;
};

struct madeira_x64_callback_frame
{
    ULONG64 padding[4];
    void *args;
    ULONG len;
    ULONG id;
    struct madeira_x64_machine_frame machine_frame;
    BYTE args_data[1];
};

C_ASSERT( offsetof( struct madeira_x64_callback_frame, machine_frame ) == 0x30 );
C_ASSERT( offsetof( struct madeira_x64_callback_frame, args_data ) == 0x58 );

struct madeira_x64_callback_state
{
    struct madeira_x64_callback_state *previous;
    AMD64_CONTEXT saved_context;
    struct madeira_x64_callback_frame *frame;
    SIZE_T frame_size;
    void *allocation_base;
    SIZE_T allocation_size;
    SIZE_T result_offset;
    SIZE_T result_capacity;
    void *result;
    ULONG result_len;
    NTSTATUS status;
    BOOL returned;
};

struct madeira_thread
{
    ULONG_PTR id;
    uint64_t handle;
    AMD64_CONTEXT amd64_context;
    INITIAL_TEB amd64_stack;
    INITIAL_TEB native_stack;
    BOOL amd64_context_valid;
    BOOL amd64_stack_active;
    BOOL cpu_context_reusable;
    unsigned int cpu_context_reuse_remaining;
    struct madeira_x64_callback_state *callback;
    struct madeira_x64_callback_state *retained_callback;
    struct madeira_thread *next;
};

static void madeira_cpu_disable_context_reuse( struct madeira_thread *thread )
{
    if (!thread) return;
    thread->cpu_context_reusable = FALSE;
    thread->cpu_context_reuse_remaining = 0;
}

static void madeira_cpu_record_budget( struct madeira_thread *thread, BOOL reused )
{
    unsigned int slices = madeira_cpu_reuse_slices();

    if (!thread || !slices)
    {
        madeira_cpu_disable_context_reuse( thread );
        return;
    }
    if (reused && thread->cpu_context_reuse_remaining)
        thread->cpu_context_reuse_remaining--;
    else
        thread->cpu_context_reuse_remaining = slices;
    thread->cpu_context_reusable = thread->cpu_context_reuse_remaining != 0;
}

struct guest_unix_call
{
    unixlib_handle_t handle;
    uint32_t id;
    uint32_t args;
};

static pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct madeira_thread *threads;
static host_dispatch_fn host_dispatch;
static void *runtime_library;
static void *win32u_library;
static uint64_t process_handle;
static void *syscall_dispatcher;
static void *unix_call_dispatcher;
static SYSTEM_DLL_INIT_BLOCK *x64_init_block;
static madeira_se_architecture_t guest_architecture = MADEIRA_SE_ARCH_X86_32;
static NTSTATUS init_status = STATUS_DEVICE_NOT_READY;

typedef void (*wow64win_register_fn)(void);
typedef NTSTATUS (*wow64win_callback_fn)(ULONG, const void *, ULONG, void **, ULONG *);

static NTSTATUS madeira_cpu_initialize(void);
static void terminate_on_error( NTSTATUS status );
static void WINAPI madeira_cpu_simulate(void);
static void madeira_cpu_simulate_amd64( struct madeira_thread *thread );
static wow64win_callback_fn wow64win_callback;

/* Implemented by the native WoW64 syscall bridge.  A host-side Mach
 * exception arrives with an ARM64 CONTEXT, while the guest exception path
 * needs to rebuild the x86 dispatcher frame from the interpreter context. */
extern void WINAPI Wow64PassExceptionToGuest( EXCEPTION_POINTERS *ptrs );

DECLSPEC_EXPORT BOOL madeira_se_wow64_runtime_active(void)
{
    return guest_architecture == MADEIRA_SE_ARCH_X86_32 && !init_status;
}

/* The private futex-table query used by the original Madeira port returns a
 * pointer to native ntdll data.  That pointer is directly addressable when
 * Wine runs native code, but it is outside the address space exported to the
 * TCTI CPU.  Let the system-information bridge identify the interpreted
 * runtime so PE ntdll can keep its queue table in guest-mapped memory. */
BOOL madeira_se_cpu_runtime_active(void)
{
    return process_handle != 0 && !init_status;
}

BOOL madeira_se_wow64_callback_ready(void)
{
    return wow64win_callback != NULL;
}

NTSTATUS madeira_se_wow64_user_callback( ULONG id, const void *args, ULONG len,
                                         void **ret_ptr, ULONG *ret_len )
{
    if (!wow64win_callback) return STATUS_NOT_SUPPORTED;
    return wow64win_callback( id, args, len, ret_ptr, ret_len );
}

static NTSTATUS register_win32_syscalls(void)
{
    const char *override = getenv( "MADEIRA_SE_WIN32U_LIBRARY" );
    char path[PATH_MAX];
    wow64win_register_fn register_func = NULL;
    Dl_info info;
    void *symbol;

    if (win32u_library) return STATUS_SUCCESS;
    if (override && override[0]) win32u_library = dlopen( override, RTLD_NOW | RTLD_LOCAL );
    else if (dladdr( madeira_cpu_initialize, &info ) && info.dli_fname)
    {
        const char *slash = strrchr( info.dli_fname, '/' );
        size_t dir_len = slash ? (size_t)(slash - info.dli_fname) : 0;

        if (dir_len && dir_len + sizeof("/../win32u/win32u.so") <= sizeof(path))
        {
            memcpy( path, info.dli_fname, dir_len );
            strcpy( path + dir_len, "/../win32u/win32u.so" );
            win32u_library = dlopen( path, RTLD_NOW | RTLD_LOCAL );
        }
        if (!win32u_library && dir_len && dir_len + sizeof("/win32u.so") <= sizeof(path))
        {
            memcpy( path, info.dli_fname, dir_len );
            strcpy( path + dir_len, "/win32u.so" );
            win32u_library = dlopen( path, RTLD_NOW | RTLD_LOCAL );
        }
    }
    if (!win32u_library)
    {
        ERR( "failed to preload Madeira-SE win32u host bridge: %s\n", dlerror() );
        return STATUS_DLL_NOT_FOUND;
    }
    if (guest_architecture == MADEIRA_SE_ARCH_X86_64) return STATUS_SUCCESS;

    symbol = dlsym( win32u_library, "madeira_se_wow64win_register" );
    memcpy( &register_func, &symbol, sizeof(register_func) );
    if (!register_func)
    {
        ERR( "Madeira-SE win32u host bridge has no registration entry point\n" );
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    symbol = dlsym( win32u_library, "madeira_se_wow64win_dispatch_callback" );
    memcpy( &wow64win_callback, &symbol, sizeof(wow64win_callback) );
    if (!wow64win_callback)
    {
        ERR( "Madeira-SE win32u host bridge has no callback entry point\n" );
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    register_func();
    TRACE( "registered native WoW64 win32u syscall thunks\n" );
    return STATUS_SUCCESS;
}

static void init_message( void *message, size_t size )
{
    madeira_se_wine_cpu_message_header_t *header = message;

    memset( message, 0, size );
    header->version = MADEIRA_SE_WINE_CPU_ABI_VERSION;
    header->size = size;
}

static NTSTATUS status_from_madeira( int32_t status )
{
    switch (status)
    {
    case MADEIRA_SE_OK: return STATUS_SUCCESS;
    case MADEIRA_SE_E_INVALID_ARGUMENT: return STATUS_INVALID_PARAMETER;
    case MADEIRA_SE_E_UNSUPPORTED:
    case MADEIRA_SE_E_UNSUPPORTED_ARCHITECTURE: return STATUS_NOT_SUPPORTED;
    case MADEIRA_SE_E_OUT_OF_MEMORY: return STATUS_NO_MEMORY;
    case MADEIRA_SE_E_NOT_FOUND: return STATUS_DLL_NOT_FOUND;
    case MADEIRA_SE_E_NOT_READY: return STATUS_DEVICE_NOT_READY;
    default: return STATUS_UNSUCCESSFUL;
    }
}

static NTSTATUS dispatch( uint32_t operation, void *message, size_t size )
{
    int32_t result;

    if (!host_dispatch || size > UINT32_MAX) return STATUS_DEVICE_NOT_READY;
    result = host_dispatch( operation, message, size );
    if (result != MADEIRA_SE_OK)
        ERR( "runtime operation %u failed with Madeira status %d\n", operation, result );
    return status_from_madeira( result );
}

static NTSTATUS resolve_runtime(void)
{
    const char *runtime_path;
    const char *qemu_path;
    runtime_start_fn start = NULL;
    void *symbol;
    int32_t status;

    symbol = dlsym( RTLD_DEFAULT, "madeira_se_wine_cpu_dispatch_message" );
    memcpy( &host_dispatch, &symbol, sizeof(host_dispatch) );
    if (host_dispatch) return STATUS_SUCCESS;

    runtime_path = getenv( "MADEIRA_SE_RUNTIME_LIBRARY" );
    qemu_path = getenv( "MADEIRA_SE_QEMU_LIBRARY" );
    if (!runtime_path || !runtime_path[0] || !qemu_path || !qemu_path[0])
        return STATUS_DLL_NOT_FOUND;
    if (!(runtime_library = dlopen( runtime_path, RTLD_NOW | RTLD_GLOBAL )))
    {
        ERR( "failed to load Madeira-SE runtime %s: %s\n", runtime_path, dlerror() );
        return STATUS_DLL_NOT_FOUND;
    }
    symbol = dlsym( runtime_library, "madeira_se_wine_qemu_runtime_start" );
    memcpy( &start, &symbol, sizeof(start) );
    if (!start) return STATUS_PROCEDURE_NOT_FOUND;
    if ((status = start( qemu_path )) != MADEIRA_SE_OK)
        return status_from_madeira( status );
    symbol = dlsym( runtime_library, "madeira_se_wine_cpu_dispatch_message" );
    memcpy( &host_dispatch, &symbol, sizeof(host_dispatch) );
    return host_dispatch ? STATUS_SUCCESS : STATUS_PROCEDURE_NOT_FOUND;
}

static uint32_t memory_protection( ULONG protect )
{
    uint32_t result = 0;

    if (protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                   PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        result |= MADEIRA_SE_MEMORY_READ;
    if (protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                   PAGE_EXECUTE_WRITECOPY))
        result |= MADEIRA_SE_MEMORY_WRITE;
    if (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                   PAGE_EXECUTE_WRITECOPY))
        result |= MADEIRA_SE_MEMORY_EXECUTE;
    return result;
}

static uint64_t guest_address( const void *address )
{
    uintptr_t value = (uintptr_t)address;

    if (guest_architecture == MADEIRA_SE_ARCH_X86_64)
    {
        uintptr_t shared = (uintptr_t)user_shared_data;

        if (value >= shared && value - shared < 2 * page_size)
            return 0x7ffe0000u + value - shared;
        return value;
    }
    return madeira_se_wow64_host_to_guest( address );
}

static void *guest_pointer( uint64_t address )
{
    if (guest_architecture == MADEIRA_SE_ARCH_X86_64)
    {
        if (address >= MADEIRA_SE_WOW64_LOWEST_USER_ADDRESS && address < (1ULL << 32))
            return (void *)(uintptr_t)(MADEIRA_SE_WOW64_GUEST_BIAS + address);
        return (void *)(uintptr_t)address;
    }
    return madeira_se_wow64_guest_to_host( address );
}

/* Export the address bridge for Unix-side builtin libraries.  A WoW64 Unix
 * call converts its outer argument block before entering the handler, but
 * structures such as DXMT's WMTMemoryPointer still contain guest addresses
 * in nested fields.  Keeping this conversion in ntdll gives those libraries
 * the same guest/host view without coupling them to the CPU implementation. */
DECLSPEC_EXPORT void *madeira_se_guest_pointer( uint64_t address )
{
    return guest_pointer( address );
}

DECLSPEC_EXPORT uint64_t madeira_se_host_pointer( const void *address )
{
    return guest_address( address );
}

static NTSTATUS strip_x64_image_execute( const MEMORY_BASIC_INFORMATION *info,
                                         uintptr_t start, uintptr_t end )
{
    long native_page_size;
    uintptr_t protect_start, protect_end;
    int protection = 0;

    if (guest_architecture != MADEIRA_SE_ARCH_X86_64 || info->Type != MEM_IMAGE ||
        !(info->Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                           PAGE_EXECUTE_WRITECOPY)))
        return STATUS_SUCCESS;
    if (info->Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        protection |= PROT_READ;
    if (info->Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                         PAGE_EXECUTE_WRITECOPY))
        protection |= PROT_WRITE;
    native_page_size = sysconf( _SC_PAGESIZE );
    if (native_page_size <= 0) return STATUS_UNSUCCESSFUL;
    protect_start = start & ~((uintptr_t)native_page_size - 1);
    protect_end = (end + native_page_size - 1) & ~((uintptr_t)native_page_size - 1);
    if (protect_end < end || mprotect( (void *)protect_start, protect_end - protect_start,
                                      protection ) == -1)
    {
        WARN( "failed to remove host execute permission from x86-64 image %p-%p: %s\n",
              (void *)start, (void *)end, strerror( errno ));
        return STATUS_ACCESS_DENIED;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS notify_memory( uint32_t event, const void *address, SIZE_T size, ULONG protect )
{
    madeira_se_wine_cpu_memory_message_t message;

    if (!process_handle) return init_status;
    init_message( &message, sizeof(message) );
    message.process_handle = process_handle;
    message.event = event;
    message.protection = memory_protection( protect );
    message.guest_address = guest_address( address );
    message.size = size;
    return dispatch( MADEIRA_SE_WINE_CPU_MEMORY_EVENT, &message, sizeof(message) );
}

static NTSTATUS map_address_range( const void *address, SIZE_T size )
{
    uintptr_t cursor = (uintptr_t)address;
    uintptr_t end;

    if (!size) return STATUS_SUCCESS;
    if (size > UINTPTR_MAX - cursor) return STATUS_INVALID_PARAMETER;
    end = cursor + size;

    while (cursor < end)
    {
        MEMORY_BASIC_INFORMATION info;
        SIZE_T returned;
        uintptr_t base, next, map_start, map_end;
        NTSTATUS status = NtQueryVirtualMemory( NtCurrentProcess(), (void *)cursor,
                                                MemoryBasicInformation, &info,
                                                sizeof(info), &returned );

        if (status) return status;
        base = (uintptr_t)info.BaseAddress;
        if (!info.RegionSize || info.RegionSize > UINTPTR_MAX - base)
            return STATUS_INVALID_ADDRESS;
        next = base + info.RegionSize;
        if (next <= cursor) return STATUS_INVALID_ADDRESS;

        map_start = cursor > base ? cursor : base;
        map_end = end < next ? end : next;
        if (info.State == MEM_COMMIT && map_start < map_end)
        {
            TRACE( "register memory host %p guest %#llx size %#llx protection %#lx\n",
                   (void *)map_start,
                   (unsigned long long)guest_address( (void *)map_start ),
                   (unsigned long long)(map_end - map_start),
                   (unsigned long)info.Protect );
            status = strip_x64_image_execute( &info, map_start, map_end );
            if (status) return status;
            status = notify_memory( MADEIRA_SE_CPU_MEMORY_MAP, (void *)map_start,
                                    map_end - map_start, info.Protect );
            if (status) return status;
        }
        cursor = next;
    }
    return STATUS_SUCCESS;
}

/* Native Wine components can create process mappings without going through the
 * guest Nt* virtual-memory entry points.  USER and GDI shared tables are a
 * common example.  When TCTI reports a non-present page, check whether Wine
 * already has a committed mapping for the corresponding host address and, if
 * so, publish that mapping to every interpreter thread before retrying the
 * faulting instruction. */
static BOOL sync_fault_mapping( uint64_t fault_address, uint32_t error_code )
{
    EXCEPTION_RECORD record = { 0 };
    MEMORY_BASIC_INFORMATION info;
    SIZE_T returned;
    void *address;
    long native_page_size;
    uint32_t protection;
    NTSTATUS status;

    if (fault_address < MADEIRA_SE_WOW64_LOWEST_USER_ADDRESS) return FALSE;
    if (!(address = guest_pointer( fault_address ))) return FALSE;
    status = NtQueryVirtualMemory( NtCurrentProcess(), address,
                                   MemoryBasicInformation, &info,
                                   sizeof(info), &returned );
    if (status || info.State != MEM_COMMIT || !info.BaseAddress || !info.RegionSize)
        return FALSE;

    /* QEMU reports a guest stack guard access as an x86 page fault.  Native
     * Wine normally grows the stack from its SIGSEGV handler before returning
     * to the faulting instruction.  TCTI returns the fault to this provider
     * instead, so perform the same guard-page handling here.  Raising an
     * application access violation would require writing its exception frame
     * onto the same guard page and can otherwise spin forever. */
    if (info.Protect & PAGE_GUARD)
    {
        record.NumberParameters = 2;
        record.ExceptionInformation[0] = (error_code & 0x10) ? EXCEPTION_EXECUTE_FAULT :
                                         (error_code & 0x02) ? EXCEPTION_WRITE_FAULT :
                                                               EXCEPTION_READ_FAULT;
        record.ExceptionInformation[1] = (ULONG_PTR)address;
        if (virtual_handle_fault( &record, address )) return FALSE;
        native_page_size = sysconf( _SC_PAGESIZE );
        if (native_page_size <= 0 || (native_page_size & (native_page_size - 1))) return FALSE;
        status = map_address_range( (void *)((uintptr_t)address & ~((uintptr_t)native_page_size - 1)),
                                    native_page_size );
        if (status)
        {
            WARN( "failed to synchronize grown guest stack page %#llx, status %#x\n",
                  (unsigned long long)fault_address, (unsigned int)status );
            return FALSE;
        }
        TRACE( "grew guest stack for fault %#llx at host %p\n",
               (unsigned long long)fault_address, address );
        return TRUE;
    }

    if (error_code & 1) return FALSE;  /* protection violation, not a missing map */
    if (info.Protect & PAGE_NOACCESS) return FALSE;

    protection = memory_protection( info.Protect );
    if ((error_code & 0x10) ? !(protection & MADEIRA_SE_MEMORY_EXECUTE) :
        (error_code & 0x02) ? !(protection & MADEIRA_SE_MEMORY_WRITE) :
                              !(protection & MADEIRA_SE_MEMORY_READ))
        return FALSE;
    if (guest_address( info.BaseAddress ) > fault_address ||
        fault_address - guest_address( info.BaseAddress ) >= info.RegionSize)
        return FALSE;
    if ((status = map_address_range( info.BaseAddress, info.RegionSize )))
    {
        WARN( "failed to synchronize fault mapping for guest %#llx, status %#x\n",
              (unsigned long long)fault_address, (unsigned int)status );
        return FALSE;
    }
    TRACE( "synchronized missing guest mapping %#llx from host region %p-%p\n",
           (unsigned long long)fault_address, info.BaseAddress,
           (char *)info.BaseAddress + info.RegionSize );
    return TRUE;
}

static NTSTATUS invalidate_memory( const void *address, SIZE_T size )
{
    madeira_se_wine_cpu_invalidate_message_t message;

    if (!process_handle || !size) return init_status;
    init_message( &message, sizeof(message) );
    message.process_handle = process_handle;
    message.guest_address = guest_address( address );
    message.size = size;
    return dispatch( MADEIRA_SE_WINE_CPU_INVALIDATE, &message, sizeof(message) );
}

static NTSTATUS map_existing_address_space(void)
{
    SYSTEM_BASIC_INFORMATION info;
    const uintptr_t arena_start = MADEIRA_SE_WOW64_GUEST_BIAS;
    const uintptr_t arena_end = arena_start + MADEIRA_SE_WOW64_GUEST_SIZE;
    NTSTATUS status;

    if (guest_architecture == MADEIRA_SE_ARCH_X86_64)
    {
        uintptr_t start = 1ULL << 32;
        uintptr_t end;

        if ((status = NtQuerySystemInformation( SystemBasicInformation, &info,
                                                sizeof(info), NULL )))
            return status;
        end = (uintptr_t)info.HighestUserAddress + 1;
        if (end <= start) return STATUS_INVALID_ADDRESS;
        return map_address_range( (void *)start, end - start );
    }

    /* Keep the architectural null page unavailable to x86 code even when
     * Wine has native bookkeeping allocations at the bottom of the arena. */
    return map_address_range( (void *)(arena_start + 0x10000),
                              arena_end - arena_start - 0x10000 );
}

static struct madeira_thread *find_thread_entry( ULONG_PTR id )
{
    struct madeira_thread *entry;
    struct madeira_thread *result = NULL;

    pthread_mutex_lock( &thread_mutex );
    for (entry = threads; entry; entry = entry->next)
        if (entry->id == id)
        {
            result = entry;
            break;
        }
    pthread_mutex_unlock( &thread_mutex );
    return result;
}

static uint64_t find_thread( ULONG_PTR id )
{
    struct madeira_thread *entry = find_thread_entry( id );
    return entry ? entry->handle : 0;
}

static void free_x64_callback_state( struct madeira_x64_callback_state *callback )
{
    if (!callback) return;
    if (callback->allocation_base)
    {
        void *base = callback->allocation_base;
        SIZE_T size = 0;

        notify_memory( MADEIRA_SE_CPU_MEMORY_UNMAP, base,
                       callback->allocation_size, 0 );
        NtFreeVirtualMemory( NtCurrentProcess(), &base, &size, MEM_RELEASE );
    }
    else free( callback->frame );
    free( callback );
}

static uint64_t remove_thread( ULONG_PTR id )
{
    struct madeira_thread **link, *entry;
    struct madeira_x64_callback_state *callback, *previous;
    uint64_t result = 0;

    pthread_mutex_lock( &thread_mutex );
    for (link = &threads; *link; link = &(*link)->next)
        if ((*link)->id == id) break;
    if ((entry = *link))
    {
        *link = entry->next;
        result = entry->handle;
    }
    pthread_mutex_unlock( &thread_mutex );
    if (entry)
    {
        for (callback = entry->callback; callback; callback = previous)
        {
            previous = callback->previous;
            free_x64_callback_state( callback );
        }
        free_x64_callback_state( entry->retained_callback );
    }
    free( entry );
    return result;
}

static void context_to_canonical( const I386_CONTEXT *source, madeira_se_x86_context_t *target )
{
    memset( target, 0, sizeof(*target) );
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
    target->segment[MADEIRA_SE_X86_SEGMENT_CS] = source->SegCs;
    target->segment[MADEIRA_SE_X86_SEGMENT_SS] = source->SegSs;
    target->segment[MADEIRA_SE_X86_SEGMENT_DS] = source->SegDs;
    target->segment[MADEIRA_SE_X86_SEGMENT_ES] = source->SegEs;
    target->segment[MADEIRA_SE_X86_SEGMENT_FS] = source->SegFs;
    target->segment[MADEIRA_SE_X86_SEGMENT_GS] = source->SegGs;
    target->segment_base[MADEIRA_SE_X86_SEGMENT_FS] =
        guest_address( get_wow_teb( NtCurrentTeb() ));
    target->debug_register[0] = source->Dr0;
    target->debug_register[1] = source->Dr1;
    target->debug_register[2] = source->Dr2;
    target->debug_register[3] = source->Dr3;
    target->debug_register[6] = source->Dr6;
    target->debug_register[7] = source->Dr7;
    memcpy( target->fxsave, source->ExtendedRegisters, sizeof(source->ExtendedRegisters) );
}

static void canonical_to_context( const madeira_se_x86_context_t *source, I386_CONTEXT *target )
{
    target->ContextFlags = CONTEXT_I386_ALL;
    target->Eax = source->gpr[MADEIRA_SE_X86_RAX];
    target->Ecx = source->gpr[MADEIRA_SE_X86_RCX];
    target->Edx = source->gpr[MADEIRA_SE_X86_RDX];
    target->Ebx = source->gpr[MADEIRA_SE_X86_RBX];
    target->Esp = source->gpr[MADEIRA_SE_X86_RSP];
    target->Ebp = source->gpr[MADEIRA_SE_X86_RBP];
    target->Esi = source->gpr[MADEIRA_SE_X86_RSI];
    target->Edi = source->gpr[MADEIRA_SE_X86_RDI];
    target->Eip = source->rip;
    target->EFlags = source->rflags;
    target->SegCs = source->segment[MADEIRA_SE_X86_SEGMENT_CS];
    target->SegSs = source->segment[MADEIRA_SE_X86_SEGMENT_SS];
    target->SegDs = source->segment[MADEIRA_SE_X86_SEGMENT_DS];
    target->SegEs = source->segment[MADEIRA_SE_X86_SEGMENT_ES];
    target->SegFs = source->segment[MADEIRA_SE_X86_SEGMENT_FS];
    target->SegGs = source->segment[MADEIRA_SE_X86_SEGMENT_GS];
    target->Dr0 = source->debug_register[0];
    target->Dr1 = source->debug_register[1];
    target->Dr2 = source->debug_register[2];
    target->Dr3 = source->debug_register[3];
    target->Dr6 = source->debug_register[6];
    target->Dr7 = source->debug_register[7];
    memcpy( target->ExtendedRegisters, source->fxsave, sizeof(target->ExtendedRegisters) );
}

static void amd64_context_to_canonical( const AMD64_CONTEXT *source,
                                        madeira_se_x86_context_t *target )
{
    memset( target, 0, sizeof(*target) );
    target->version = MADEIRA_SE_CPU_ABI_VERSION;
    target->architecture = MADEIRA_SE_ARCH_X86_64;
    target->gpr[MADEIRA_SE_X86_RAX] = source->Rax;
    target->gpr[MADEIRA_SE_X86_RCX] = source->Rcx;
    target->gpr[MADEIRA_SE_X86_RDX] = source->Rdx;
    target->gpr[MADEIRA_SE_X86_RBX] = source->Rbx;
    target->gpr[MADEIRA_SE_X86_RSP] = source->Rsp;
    target->gpr[MADEIRA_SE_X86_RBP] = source->Rbp;
    target->gpr[MADEIRA_SE_X86_RSI] = source->Rsi;
    target->gpr[MADEIRA_SE_X86_RDI] = source->Rdi;
    target->gpr[MADEIRA_SE_X86_R8] = source->R8;
    target->gpr[MADEIRA_SE_X86_R9] = source->R9;
    target->gpr[MADEIRA_SE_X86_R10] = source->R10;
    target->gpr[MADEIRA_SE_X86_R11] = source->R11;
    target->gpr[MADEIRA_SE_X86_R12] = source->R12;
    target->gpr[MADEIRA_SE_X86_R13] = source->R13;
    target->gpr[MADEIRA_SE_X86_R14] = source->R14;
    target->gpr[MADEIRA_SE_X86_R15] = source->R15;
    target->rip = source->Rip;
    target->rflags = source->EFlags;
    target->segment[MADEIRA_SE_X86_SEGMENT_CS] = source->SegCs;
    target->segment[MADEIRA_SE_X86_SEGMENT_SS] = source->SegSs;
    target->segment[MADEIRA_SE_X86_SEGMENT_DS] = source->SegDs;
    target->segment[MADEIRA_SE_X86_SEGMENT_ES] = source->SegEs;
    target->segment[MADEIRA_SE_X86_SEGMENT_FS] = source->SegFs;
    target->segment[MADEIRA_SE_X86_SEGMENT_GS] = source->SegGs;
    target->segment_base[MADEIRA_SE_X86_SEGMENT_GS] = (ULONG_PTR)NtCurrentTeb();
    target->debug_register[0] = source->Dr0;
    target->debug_register[1] = source->Dr1;
    target->debug_register[2] = source->Dr2;
    target->debug_register[3] = source->Dr3;
    target->debug_register[6] = source->Dr6;
    target->debug_register[7] = source->Dr7;
    memcpy( target->fxsave, &source->FltSave, sizeof(source->FltSave) );
}

static void canonical_to_amd64_context( const madeira_se_x86_context_t *source,
                                        AMD64_CONTEXT *target )
{
    target->ContextFlags = CONTEXT_AMD64_ALL;
    target->Rax = source->gpr[MADEIRA_SE_X86_RAX];
    target->Rcx = source->gpr[MADEIRA_SE_X86_RCX];
    target->Rdx = source->gpr[MADEIRA_SE_X86_RDX];
    target->Rbx = source->gpr[MADEIRA_SE_X86_RBX];
    target->Rsp = source->gpr[MADEIRA_SE_X86_RSP];
    target->Rbp = source->gpr[MADEIRA_SE_X86_RBP];
    target->Rsi = source->gpr[MADEIRA_SE_X86_RSI];
    target->Rdi = source->gpr[MADEIRA_SE_X86_RDI];
    target->R8 = source->gpr[MADEIRA_SE_X86_R8];
    target->R9 = source->gpr[MADEIRA_SE_X86_R9];
    target->R10 = source->gpr[MADEIRA_SE_X86_R10];
    target->R11 = source->gpr[MADEIRA_SE_X86_R11];
    target->R12 = source->gpr[MADEIRA_SE_X86_R12];
    target->R13 = source->gpr[MADEIRA_SE_X86_R13];
    target->R14 = source->gpr[MADEIRA_SE_X86_R14];
    target->R15 = source->gpr[MADEIRA_SE_X86_R15];
    target->Rip = source->rip;
    target->EFlags = source->rflags;
    target->SegCs = source->segment[MADEIRA_SE_X86_SEGMENT_CS];
    target->SegSs = source->segment[MADEIRA_SE_X86_SEGMENT_SS];
    target->SegDs = source->segment[MADEIRA_SE_X86_SEGMENT_DS];
    target->SegEs = source->segment[MADEIRA_SE_X86_SEGMENT_ES];
    target->SegFs = source->segment[MADEIRA_SE_X86_SEGMENT_FS];
    target->SegGs = source->segment[MADEIRA_SE_X86_SEGMENT_GS];
    target->Dr0 = source->debug_register[0];
    target->Dr1 = source->debug_register[1];
    target->Dr2 = source->debug_register[2];
    target->Dr3 = source->debug_register[3];
    target->Dr6 = source->debug_register[6];
    target->Dr7 = source->debug_register[7];
    memcpy( &target->FltSave, source->fxsave, sizeof(target->FltSave) );
    target->MxCsr = target->FltSave.MxCsr;
}

static NTSTATUS initialize_amd64_stack( struct madeira_thread *thread )
{
    SIZE_T size;
    NTSTATUS status;

    if (thread->amd64_stack.StackBase) return STATUS_SUCCESS;
    if ((status = virtual_alloc_thread_stack( &thread->amd64_stack, limit_4g, 0,
                                              0, 0, TRUE )))
        return status;
    size = (char *)thread->amd64_stack.StackBase -
           (char *)thread->amd64_stack.DeallocationStack;
    if ((status = map_address_range( thread->amd64_stack.DeallocationStack, size )))
    {
        void *base = thread->amd64_stack.DeallocationStack;
        SIZE_T release_size = 0;

        NtFreeVirtualMemory( NtCurrentProcess(), &base, &release_size, MEM_RELEASE );
        memset( &thread->amd64_stack, 0, sizeof(thread->amd64_stack) );
        return status;
    }
    TRACE( "allocated independent x86-64 guest stack %p-%p\n",
           thread->amd64_stack.DeallocationStack, thread->amd64_stack.StackBase );
    return STATUS_SUCCESS;
}

static void activate_amd64_stack( struct madeira_thread *thread )
{
    TEB *teb = NtCurrentTeb();

    if (thread->amd64_stack_active) return;
    thread->native_stack.StackBase = teb->Tib.StackBase;
    thread->native_stack.StackLimit = teb->Tib.StackLimit;
    thread->native_stack.DeallocationStack = teb->DeallocationStack;
    teb->Tib.StackBase = thread->amd64_stack.StackBase;
    teb->Tib.StackLimit = thread->amd64_stack.StackLimit;
    teb->DeallocationStack = thread->amd64_stack.DeallocationStack;
    thread->amd64_stack_active = TRUE;
}

static void deactivate_amd64_stack( struct madeira_thread *thread )
{
    TEB *teb = NtCurrentTeb();

    if (!thread->amd64_stack_active) return;
    thread->amd64_stack.StackBase = teb->Tib.StackBase;
    thread->amd64_stack.StackLimit = teb->Tib.StackLimit;
    thread->amd64_stack.DeallocationStack = teb->DeallocationStack;
    teb->Tib.StackBase = thread->native_stack.StackBase;
    teb->Tib.StackLimit = thread->native_stack.StackLimit;
    teb->DeallocationStack = thread->native_stack.DeallocationStack;
    thread->amd64_stack_active = FALSE;
}

BOOL madeira_se_x64_callback_ready(void)
{
    return guest_architecture == MADEIRA_SE_ARCH_X86_64 && !init_status &&
           x64_init_block && x64_init_block->pKiUserCallbackDispatcher;
}

/* Capture the guest NtCallbackReturn without trying to execute the ARM64
 * callback-return trampoline.  The result buffer lives in the callback frame;
 * callers consume it synchronously, just as they do for Wine's native
 * callback implementation. */
static BOOL madeira_se_x64_callback_return( AMD64_CONTEXT *context,
                                            const ULONG_PTR *args,
                                            ULONG64 return_rip, ULONG64 return_rsp )
{
    struct madeira_thread *thread;
    struct madeira_x64_callback_state *state;
    void *source = NULL;
    ULONG requested, copied = 0;

    thread = find_thread_entry( (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
    if (!thread || !(state = thread->callback)) return FALSE;

    requested = (ULONG)args[1];
    if (requested && args[0]) source = guest_pointer( args[0] );
    if (source && requested && requested <= state->result_capacity &&
        virtual_check_buffer_for_read( source, requested ))
    {
        memcpy( (char *)state->frame + state->result_offset, source, requested );
        copied = requested;
    }
    else if (requested > state->result_capacity)
        copied = (ULONG)state->result_capacity;

    state->result = (char *)state->frame + state->result_offset;
    state->result_len = copied;
    state->status = (NTSTATUS)args[2];
    state->returned = TRUE;
    TRACE( "x86-64 callback return status %#x length %lu source %p\n",
           (unsigned int)state->status, (unsigned long)copied, source );

    /* Stop the nested interpreter at the callback syscall.  The outer
     * dispatcher restores its saved context after this helper returns. */
    context->Rax = STATUS_SUCCESS;
    context->Rsp = return_rsp;
    context->Rip = return_rip;
    return TRUE;
}

NTSTATUS madeira_se_x64_user_callback( ULONG id, const void *args, ULONG len,
                                       void **ret_ptr, ULONG *ret_len )
{
    struct madeira_thread *thread;
    struct madeira_x64_callback_state *state;
    struct madeira_x64_callback_frame *frame;
    SIZE_T result_capacity, data_offset, frame_size;
    ULONG64 callback_rip;
    NTSTATUS status;

    if (!madeira_se_x64_callback_ready()) return STATUS_NOT_SUPPORTED;
    if (len && !args) return STATUS_INVALID_PARAMETER;
    if (len > MADEIRA_SE_X64_CALLBACK_MAX_DATA) return STATUS_INVALID_PARAMETER;

    thread = find_thread_entry( (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
    if (!thread) return STATUS_DEVICE_NOT_READY;
    if ((status = initialize_amd64_stack( thread ))) return status;
    if (thread->retained_callback)
    {
        free_x64_callback_state( thread->retained_callback );
        thread->retained_callback = NULL;
    }

    data_offset = offsetof( struct madeira_x64_callback_frame, args_data );
    result_capacity = max( (SIZE_T)MADEIRA_SE_X64_CALLBACK_RESULT_RESERVE,
                           (SIZE_T)len );
    if (data_offset > SIZE_MAX - (SIZE_T)len ||
        data_offset + (SIZE_T)len > SIZE_MAX - result_capacity)
        return STATUS_NO_MEMORY;
    frame_size = data_offset + (SIZE_T)len + result_capacity;
    frame_size = (frame_size + 15) & ~(SIZE_T)15;

    if (!(state = calloc( 1, sizeof(*state) ))) return STATUS_NO_MEMORY;
    {
        void *base = NULL;
        SIZE_T allocation_size;

        if (frame_size > SIZE_MAX - MADEIRA_SE_X64_CALLBACK_STACK_RESERVE)
        {
            free( state );
            return STATUS_NO_MEMORY;
        }
        allocation_size = frame_size + MADEIRA_SE_X64_CALLBACK_STACK_RESERVE;

        status = NtAllocateVirtualMemory( NtCurrentProcess(), &base, 0,
                                          &allocation_size,
                                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
        if (status)
        {
            free( state );
            return status;
        }
        frame = (struct madeira_x64_callback_frame *)((char *)base +
                                                       MADEIRA_SE_X64_CALLBACK_STACK_RESERVE);
        memset( base, 0, allocation_size );
        if ((status = map_address_range( base, allocation_size )))
        {
            SIZE_T release_size = 0;
            NtFreeVirtualMemory( NtCurrentProcess(), &base, &release_size, MEM_RELEASE );
            free( state );
            return status;
        }
        state->allocation_base = base;
        state->allocation_size = allocation_size;
    }

    state->previous = thread->callback;
    state->saved_context = thread->amd64_context;
    state->frame = frame;
    state->frame_size = frame_size;
    state->result_offset = data_offset + (SIZE_T)len;
    state->result_capacity = result_capacity;
    state->status = STATUS_UNSUCCESSFUL;
    thread->callback = state;

    frame->args = frame->args_data;
    frame->len = len;
    frame->id = id;
    frame->machine_frame.rip = state->saved_context.Rip;
    frame->machine_frame.cs = state->saved_context.SegCs ? state->saved_context.SegCs : 0x33;
    frame->machine_frame.eflags = state->saved_context.EFlags;
    frame->machine_frame.rsp = state->saved_context.Rsp;
    frame->machine_frame.ss = state->saved_context.SegSs ? state->saved_context.SegSs : 0x2b;
    if (len) memcpy( frame->args_data, args, len );

    callback_rip = x64_init_block->pKiUserCallbackDispatcher;
    thread->amd64_context.Rsp = (ULONG_PTR)(uintptr_t)frame;
    thread->amd64_context.Rip = callback_rip;
    thread->amd64_context.Rcx = 0;
    thread->amd64_context.Rdx = 0;
    thread->amd64_context.R8 = 0;
    thread->amd64_context.R9 = 0;
    thread->amd64_context.Rax = 0;
    thread->amd64_context.ContextFlags = CONTEXT_AMD64_ALL;
    TRACE( "enter x86-64 callback id %lu len %lu rip %#llx frame %p saved rip %#llx rsp %#llx\n",
           (unsigned long)id, (unsigned long)len, (unsigned long long)callback_rip,
           frame, (unsigned long long)state->saved_context.Rip,
           (unsigned long long)state->saved_context.Rsp );

    while (!state->returned) madeira_cpu_simulate_amd64( thread );

    thread->amd64_context = state->saved_context;
    thread->callback = state->previous;
    if (ret_ptr) *ret_ptr = state->result_len ? state->result : NULL;
    if (ret_len) *ret_len = state->result_len;
    status = state->status;
    free_x64_callback_state( thread->retained_callback );
    thread->retained_callback = state;
    TRACE( "leave x86-64 callback id %lu status %#x length %lu\n",
           (unsigned long)id, (unsigned int)status, (unsigned long)state->result_len );
    return status;
}

static NTSTATUS dispatch_unix_call( const struct guest_unix_call *call )
{
    const unixlib_entry_t *functions = (const unixlib_entry_t *)(uintptr_t)call->handle;
    const void *function;
    Dl_info info;
    void *args = madeira_se_wow64_guest_to_host( call->args );

    if (!functions) return STATUS_INVALID_PARAMETER;
    /* A Unix-call handle points at the table exported by the loaded Unix
     * library.  DXMT's winemetal table currently has 127 entries, but Wine's
     * generated libraries are not limited to that size (opengl32 alone has
     * several thousand entries).  The guest dispatcher has already supplied
     * the library-specific call id, so do not apply a DXMT-specific bound to
     * every library. */
    function = functions[call->id];
    if (!function)
    {
        ERR( "Madeira Unix call id %u resolved to NULL (handle %#llx args %#x)\n",
             call->id, (unsigned long long)call->handle, call->args );
        return STATUS_ENTRYPOINT_NOT_FOUND;
    }
    if (dladdr( function, &info ))
        TRACE( "dispatch unix call handle %#llx id %u args %p function %p (%s:%s+%#lx)\n",
               (unsigned long long)call->handle, call->id, args, function,
               info.dli_fname ? info.dli_fname : "?", info.dli_sname ? info.dli_sname : "?",
               info.dli_saddr ? (unsigned long)((uintptr_t)function - (uintptr_t)info.dli_saddr) : 0 );
    else
        TRACE( "dispatch unix call handle %#llx id %u args %p function %p\n",
               (unsigned long long)call->handle, call->id, args, function );
    return ((unixlib_entry_t)function)( args );
}

static void service_dispatcher( I386_CONTEXT *context, BOOL unix_call )
{
    DWORD *stack = madeira_se_wow64_guest_to_host( context->Esp );
    DWORD return_eip = stack[0];
    DWORD return_esp = context->Esp + sizeof(DWORD);
    NTSTATUS status;

    if (unix_call)
    {
        const struct guest_unix_call *call = madeira_se_wow64_guest_to_host( return_esp );

        TRACE( "unix call frame eip %#lx esp %#lx return %#lx\n",
               (unsigned long)context->Eip, (unsigned long)context->Esp,
               (unsigned long)return_eip );
        status = dispatch_unix_call( call );
        return_esp += sizeof(*call);
    }
    else
    {
        Wow64ProcessPendingCrossProcessItems();
        TRACE( "dispatch syscall %#lx from eip %#lx esp %#lx\n",
               (unsigned long)context->Eax, (unsigned long)context->Eip,
               (unsigned long)context->Esp );
        status = Wow64SystemServiceEx( context->Eax,
                                      madeira_se_wow64_guest_to_host( return_esp + sizeof(DWORD) ));
        TRACE( "syscall returned status %#x with eip %#lx esp %#lx\n",
               (unsigned int)status, (unsigned long)context->Eip,
               (unsigned long)context->Esp );
    }
    if (context->Eip == madeira_se_wow64_host_to_guest( unix_call ? unix_call_dispatcher
                                                                  : syscall_dispatcher ))
    {
        context->Eax = status;
        context->Esp = return_esp;
        context->Eip = return_eip;
    }
}

static ULONG_PTR call_native_service( ULONG_PTR function, const ULONG_PTR *args,
                                      unsigned int count )
{
    switch (count)
    {
    case 0: return ((ULONG_PTR (*)(void))function)();
    case 1: return ((ULONG_PTR (*)(ULONG_PTR))function)( args[0] );
    case 2: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR))function)( args[0], args[1] );
    case 3: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2] );
    case 4: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3] );
    case 5: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4] );
    case 6: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5] );
    case 7: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6] );
    case 8: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7] );
    case 9: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8] );
    case 10: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9] );
    case 11: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10] );
    case 12: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11] );
    case 13: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12] );
    case 14: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13] );
    case 15: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14] );
    case 16: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15] );
    case 17: return ((ULONG_PTR (*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))function)( args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15], args[16] );
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}

static NTSTATUS map_x64_region_containing( const void *address )
{
    MEMORY_BASIC_INFORMATION info;
    SIZE_T returned;
    NTSTATUS status;

    if (!address) return STATUS_INVALID_PARAMETER;
    if ((status = NtQueryVirtualMemory( NtCurrentProcess(), address,
                                        MemoryBasicInformation, &info,
                                        sizeof(info), &returned )))
        return status;
    if (info.State == MEM_COMMIT && info.BaseAddress && info.RegionSize)
        return map_address_range( info.BaseAddress, info.RegionSize );
    return STATUS_INVALID_ADDRESS;
}

static void notify_x64_memory_syscall( ULONG number, const ULONG_PTR *args, NTSTATUS status )
{
    void **base_ptr;
    SIZE_T *size_ptr;

    if (status) return;
    switch (number)
    {
    case 0x0018: /* NtAllocateVirtualMemory */
        base_ptr = guest_pointer( args[1] );
        size_ptr = guest_pointer( args[3] );
        if (base_ptr && size_ptr && *base_ptr && *size_ptr) map_address_range( *base_ptr, *size_ptr );
        break;
    case 0x006b: /* NtAllocateVirtualMemoryEx */
        base_ptr = guest_pointer( args[1] );
        size_ptr = guest_pointer( args[2] );
        if (base_ptr && size_ptr && *base_ptr && *size_ptr) map_address_range( *base_ptr, *size_ptr );
        break;
    case 0x0028: /* NtMapViewOfSection */
        base_ptr = guest_pointer( args[2] );
        size_ptr = guest_pointer( args[6] );
        if (base_ptr && size_ptr && *base_ptr && *size_ptr) map_address_range( *base_ptr, *size_ptr );
        break;
    case 0x00aa: /* NtMapViewOfSectionEx */
        base_ptr = guest_pointer( args[2] );
        size_ptr = guest_pointer( args[4] );
        if (base_ptr && size_ptr && *base_ptr && *size_ptr) map_address_range( *base_ptr, *size_ptr );
        break;
    case 0x0050: /* NtProtectVirtualMemory */
        base_ptr = guest_pointer( args[1] );
        size_ptr = guest_pointer( args[2] );
        if (base_ptr && size_ptr && *base_ptr && *size_ptr) map_address_range( *base_ptr, *size_ptr );
        break;
    case 0x009e: /* NtInitializeNlsFiles */
        base_ptr = guest_pointer( args[0] );
        if (base_ptr && *base_ptr) map_x64_region_containing( *base_ptr );
        break;
    case 0x009b: /* NtGetNlsSectionPtr */
        base_ptr = guest_pointer( args[3] );
        size_ptr = guest_pointer( args[4] );
        if (base_ptr && *base_ptr)
        {
            if (size_ptr && *size_ptr) map_address_range( *base_ptr, *size_ptr );
            else map_x64_region_containing( *base_ptr );
        }
        break;
    case 0x001e: /* NtFreeVirtualMemory */
        base_ptr = guest_pointer( args[1] );
        size_ptr = guest_pointer( args[2] );
        if (base_ptr && *base_ptr)
            notify_memory( MADEIRA_SE_CPU_MEMORY_UNMAP, *base_ptr,
                           size_ptr ? *size_ptr : 0, 0 );
        break;
    case 0x002a: /* NtUnmapViewOfSection */
    case 0x00fe: /* NtUnmapViewOfSectionEx */
        if (args[1]) notify_memory( MADEIRA_SE_CPU_MEMORY_UNMAP,
                                    guest_pointer( args[1] ), 0, 0 );
        break;
    }
}

static BOOL x64_apply_continue( AMD64_CONTEXT *context, ULONG_PTR address )
{
    const AMD64_CONTEXT *source = guest_pointer( address );

    if (!source || !virtual_check_buffer_for_read( source, sizeof(*source) )) return FALSE;
    *context = *source;
    return TRUE;
}

static void service_dispatcher_amd64( AMD64_CONTEXT *context, BOOL unix_call )
{
    ULONG_PTR args[17] = { 0 };
    ULONG64 *stack = guest_pointer( context->Rsp );
    ULONG64 return_rip, return_rsp;
    ULONG_PTR result;
    unsigned int table_index, number, count, i;
    const SYSTEM_SERVICE_TABLE *table;

    if (!stack) terminate_on_error( STATUS_ACCESS_VIOLATION );
    return_rip = stack[0];
    return_rsp = context->Rsp + sizeof(ULONG64);
    if (unix_call)
    {
        const unixlib_entry_t *functions = (const unixlib_entry_t *)(uintptr_t)context->Rcx;

        if (!functions) result = STATUS_INVALID_PARAMETER;
        else result = functions[(unsigned int)context->Rdx]( guest_pointer( context->R8 ) );
    }
    else
    {
        table_index = (context->Rax >> 12) & 3;
        number = context->Rax & 0xfff;
        table = &KeServiceDescriptorTable[table_index];
        if (!table->ServiceTable || !table->ArgumentTable || number >= table->ServiceLimit)
            result = STATUS_INVALID_SYSTEM_SERVICE;
        else
        {
            count = table->ArgumentTable[number] / sizeof(ULONG64);
            if (count > ARRAY_SIZE(args)) result = STATUS_INVALID_SYSTEM_SERVICE;
            else
            {
                if (count > 0) args[0] = context->R10;
                if (count > 1) args[1] = context->Rdx;
                if (count > 2) args[2] = context->R8;
                if (count > 3) args[3] = context->R9;
                /* The dispatcher is entered through an indirect call in the
                 * x86-64 syscall stub.  stack[0] returns to that stub and
                 * stack[1] returns to its caller; the caller's four shadow
                 * slots follow, so argument five starts at stack[6]. */
                for (i = 4; i < count; ++i) args[i] = stack[i + 2];

                /* x86-64 KiUserCallbackDispatcher completes through
                 * NtCallbackReturn (syscall 0x0005).  On ARM64 there is no
                 * native x86 return trampoline, so terminate the nested TCTI
                 * callback here and hand the payload back to KeUserModeCallback. */
                if (!table_index && number == 0x0005 &&
                    madeira_se_x64_callback_return( context, args, return_rip, return_rsp ))
                    return;

                if (!table_index && (number == 0x0043 || number == 0x0075))
                {
                    if (!x64_apply_continue( context, args[0] ))
                    {
                        context->Rax = STATUS_ACCESS_VIOLATION;
                        context->Rsp = return_rsp;
                        context->Rip = return_rip;
                    }
                    return;
                }
                TRACE( "dispatch x86-64 syscall %#x table %u count %u "
                       "return %#llx caller %#llx args %#lx %#lx %#lx %#lx %#lx %#lx\n",
                       number, table_index, count,
                       (unsigned long long)stack[0], (unsigned long long)stack[1],
                       (unsigned long)args[0], (unsigned long)args[1],
                       (unsigned long)args[2], (unsigned long)args[3],
                       (unsigned long)args[4], (unsigned long)args[5] );
                if (!table_index && number == 0x00ff)
                {
                    const LARGE_INTEGER *timeout = guest_pointer( args[1] );

                    TRACE( "x86-64 alert wait caller %#llx parent %#llx owner %#llx "
                           "critical-section %#llx teb %#llx timeout %s\n",
                           (unsigned long long)stack[25],
                           (unsigned long long)stack[83],
                           (unsigned long long)stack[89],
                           (unsigned long long)stack[20],
                           (unsigned long long)context->R12,
                           timeout ? wine_dbgstr_longlong( timeout->QuadPart ) : "infinite" );
                }
                result = call_native_service( table->ServiceTable[number], args, count );
                TRACE( "x86-64 syscall %#x returned %#lx\n", number,
                       (unsigned long)result );
                if (!table_index) notify_x64_memory_syscall( number, args, (NTSTATUS)result );
            }
        }
    }
    if (context->Rip == guest_address( unix_call ? unix_call_dispatcher : syscall_dispatcher ))
    {
        context->Rax = result;
        context->Rsp = return_rsp;
        context->Rip = return_rip;
    }
}

static NTSTATUS exception_status( uint32_t vector )
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

static void terminate_on_error( NTSTATUS status )
{
    ERR( "Madeira-SE CPU provider stopped with status %#x\n", (unsigned int)status );
    NtTerminateProcess( NtCurrentProcess(), status );
    _exit( 1 );
}

/* Entry point used by the Darwin signal trampoline when the native host
 * ntdll has no PE KiUserExceptionDispatcher export.  The signal handler has
 * already copied the EXCEPTION_RECORD and ARM64 CONTEXT into a safe frame and
 * installed those pointers in x0/x1.  Convert the fault to the guest ABI and
 * keep running the interpreter; the guest dispatcher decides whether an SEH
 * handler can continue execution or the pseudo-process must terminate. */
DECLSPEC_NORETURN void WINAPI madeira_se_native_exception_dispatcher( EXCEPTION_RECORD *rec,
                                                                        CONTEXT *context )
{
    EXCEPTION_POINTERS ptrs = { rec, context };

    if (guest_architecture == MADEIRA_SE_ARCH_X86_32 && !init_status)
    {
        Wow64PassExceptionToGuest( &ptrs );
        for (;;) madeira_cpu_simulate();
    }

    terminate_on_error( rec ? rec->ExceptionCode : STATUS_ACCESS_VIOLATION );
}

static NTSTATUS madeira_cpu_initialize(void)
{
    madeira_se_wine_cpu_query_message_t query;
    madeira_se_wine_cpu_process_init_message_t process;
    void *bridge = NULL, *protect;
    SIZE_T size = 0x1000, protect_size;
    ULONG old_protection;
    NTSTATUS status;

    if (!init_status) return STATUS_SUCCESS;
    if ((status = register_win32_syscalls())) return init_status = status;
    if ((status = resolve_runtime())) return init_status = status;
    init_message( &query, sizeof(query) );
    if ((status = dispatch( MADEIRA_SE_WINE_CPU_QUERY, &query, sizeof(query) )))
        return init_status = status;
    if (!(query.capabilities & MADEIRA_SE_CPU_CAP_NO_RUNTIME_CODEGEN) ||
        (guest_architecture == MADEIRA_SE_ARCH_X86_32 &&
         !(query.capabilities & MADEIRA_SE_CPU_CAP_X86_32)) ||
        (guest_architecture == MADEIRA_SE_ARCH_X86_64 &&
         !(query.capabilities & MADEIRA_SE_CPU_CAP_X86_64)))
        return init_status = STATUS_NOT_SUPPORTED;

    if (guest_architecture == MADEIRA_SE_ARCH_X86_64)
        bridge = MADEIRA_SE_X64_BRIDGE_HINT;
    if ((status = NtAllocateVirtualMemory( NtCurrentProcess(), &bridge, 0, &size,
                                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE )))
        return init_status = status;
    *(DWORD *)bridge = 0x2ecd2ecd;
    syscall_dispatcher = bridge;
    unix_call_dispatcher = (char *)bridge + 2;
    protect = bridge;
    protect_size = size;
    if ((status = NtProtectVirtualMemory( NtCurrentProcess(), &protect, &protect_size,
                                          PAGE_READONLY, &old_protection )))
        return init_status = status;

    init_message( &process, sizeof(process) );
    process.architecture = guest_architecture;
    if (guest_architecture == MADEIRA_SE_ARCH_X86_64)
    {
        process.flags = MADEIRA_SE_WINE_CPU_PROCESS_SPLIT_LOW_4G_ADDRESS_SPACE;
        process.guest_address_bias = MADEIRA_SE_WOW64_GUEST_BIAS;
    }
    else
    {
        process.flags = MADEIRA_SE_WINE_CPU_PROCESS_BIASED_ADDRESS_SPACE;
        process.guest_address_bias = MADEIRA_SE_WOW64_GUEST_BIAS;
    }
    if ((status = dispatch( MADEIRA_SE_WINE_CPU_PROCESS_INIT, &process, sizeof(process) )))
        return init_status = status;
    process_handle = process.process_handle;
    if ((status = map_existing_address_space())) return init_status = status;
    init_status = STATUS_SUCCESS;
    TRACE( "native %s TCTI provider initialized without executable guest pages\n",
           guest_architecture == MADEIRA_SE_ARCH_X86_64 ? "x86-64" : "i386" );
    return STATUS_SUCCESS;
}

NTSTATUS madeira_se_x64_host_init( SYSTEM_DLL_INIT_BLOCK *init_block, HMODULE module )
{
    extern void *madeira_se_find_guest_export( HMODULE module, const char *name );
    void **syscall_ptr, **unix_call_ptr;
    void *slot = (char *)user_shared_data + page_size;
    uintptr_t page;
    long native_page_size;
    NTSTATUS status;

    guest_architecture = MADEIRA_SE_ARCH_X86_64;
    x64_init_block = init_block;
    /* load_wow64_ntdll() fills the guest init block instead of the native
     * ARM64 callback globals.  Keep the global coherent for diagnostics and
     * for any Wine path that queries it directly. */
    if (init_block->pKiUserCallbackDispatcher)
        pKiUserCallbackDispatcher = (void *)(uintptr_t)init_block->pKiUserCallbackDispatcher;
    if ((status = madeira_cpu_initialize())) return status;

    syscall_ptr = madeira_se_find_guest_export( module, "__wine_syscall_dispatcher" );
    unix_call_ptr = madeira_se_find_guest_export( module, "__wine_unix_call_dispatcher" );
    if (!syscall_ptr || !unix_call_ptr) return STATUS_PROCEDURE_NOT_FOUND;
    *syscall_ptr = (void *)(uintptr_t)guest_address( syscall_dispatcher );
    *unix_call_ptr = (void *)(uintptr_t)guest_address( unix_call_dispatcher );

    native_page_size = sysconf( _SC_PAGESIZE );
    if (native_page_size <= 0) return STATUS_UNSUCCESSFUL;
    page = (uintptr_t)slot & ~((uintptr_t)native_page_size - 1);
    if (mprotect( (void *)page, native_page_size, PROT_READ | PROT_WRITE ) == -1)
        return STATUS_ACCESS_DENIED;
    *(void **)slot = (void *)(uintptr_t)guest_address( syscall_dispatcher );
    if (mprotect( (void *)page, native_page_size, PROT_READ ) == -1)
        return STATUS_ACCESS_DENIED;
    if ((status = notify_memory( MADEIRA_SE_CPU_MEMORY_MAP, slot,
                                 page_size, PAGE_READONLY )))
        return status;
    TRACE( "installed x86-64 syscall bridge %#llx and Unix bridge %#llx\n",
           (unsigned long long)guest_address( syscall_dispatcher ),
           (unsigned long long)guest_address( unix_call_dispatcher ) );
    return STATUS_SUCCESS;
}

static void WINAPI madeira_cpu_process_init(void)
{
    NTSTATUS status = madeira_cpu_initialize();
    if (status) terminate_on_error( status );
}

static void WINAPI madeira_cpu_thread_init(void)
{
    madeira_se_wine_cpu_thread_init_message_t message;
    struct madeira_thread *entry;
    void *cpu_reserved;
    ULONG_PTR id = (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;
    NTSTATUS status;

    if (init_status || find_thread( id )) return;
    if (!(entry = calloc( 1, sizeof(*entry) ))) terminate_on_error( STATUS_NO_MEMORY );
    init_message( &message, sizeof(message) );
    message.process_handle = process_handle;
    message.thread_id = id;
    if ((status = dispatch( MADEIRA_SE_WINE_CPU_THREAD_INIT, &message, sizeof(message) )))
    {
        free( entry );
        terminate_on_error( status );
    }
    entry->id = id;
    entry->handle = message.thread_handle;
    cpu_reserved = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED];
    TRACE( "x86-64 thread memory teb %p peb %p cpu-reserved %p native-stack %p-%p\n",
           NtCurrentTeb(), NtCurrentTeb()->Peb, cpu_reserved,
           NtCurrentTeb()->DeallocationStack, NtCurrentTeb()->Tib.StackBase );
    if (guest_architecture == MADEIRA_SE_ARCH_X86_64 &&
        ((status = map_x64_region_containing( NtCurrentTeb() )) ||
         (cpu_reserved && (status = map_x64_region_containing( cpu_reserved )))))
    {
        madeira_se_wine_cpu_thread_term_message_t destroy;

        init_message( &destroy, sizeof(destroy) );
        destroy.thread_handle = entry->handle;
        dispatch( MADEIRA_SE_WINE_CPU_THREAD_TERM, &destroy, sizeof(destroy) );
        free( entry );
        terminate_on_error( status );
    }
    TRACE( "created TCTI thread %llu for Wine thread %lu\n",
           (unsigned long long)entry->handle, (unsigned long)id );
    pthread_mutex_lock( &thread_mutex );
    entry->next = threads;
    threads = entry;
    pthread_mutex_unlock( &thread_mutex );
}

static void WINAPI madeira_cpu_simulate(void)
{
    madeira_se_wine_cpu_run_message_t message;
    I386_CONTEXT *context = get_cpu_area( IMAGE_FILE_MACHINE_I386 );
    struct madeira_thread *thread = find_thread_entry( (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
    uint64_t thread_handle = thread ? thread->handle : 0;
    NTSTATUS status;

    if (init_status) terminate_on_error( init_status );
    if (!thread_handle)
    {
        madeira_cpu_thread_init();
        thread = find_thread_entry( (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
        thread_handle = thread ? thread->handle : 0;
    }
    if (!thread_handle || !context) terminate_on_error( STATUS_DEVICE_NOT_READY );
    if (context->Eip == guest_address( syscall_dispatcher ))
    {
        madeira_cpu_disable_context_reuse( thread );
        service_dispatcher( context, FALSE );
        return;
    }
    if (context->Eip == guest_address( unix_call_dispatcher ))
    {
        madeira_cpu_disable_context_reuse( thread );
        service_dispatcher( context, TRUE );
        return;
    }
    init_message( &message, sizeof(message) );
    message.thread_handle = thread_handle;
    message.request.version = MADEIRA_SE_CPU_ABI_VERSION;
    message.request.max_instructions = madeira_cpu_run_budget();
    message.request.syscall_dispatcher = guest_address( syscall_dispatcher );
    message.request.unix_call_dispatcher = guest_address( unix_call_dispatcher );
    if (thread && thread->cpu_context_reusable &&
        thread->cpu_context_reuse_remaining && madeira_cpu_reuse_slices())
        message.request.flags |= MADEIRA_SE_CPU_RUN_REUSE_CONTEXT;
    context_to_canonical( context, &message.context );
    TRACE( "run thread %llu eip %#lx esp %#lx eax %#lx ebx %#lx ecx %#lx edx %#lx "
           "esi %#lx edi %#lx ebp %#lx eflags %#lx\n",
           (unsigned long long)thread_handle, (unsigned long)context->Eip,
           (unsigned long)context->Esp, (unsigned long)context->Eax,
           (unsigned long)context->Ebx, (unsigned long)context->Ecx,
           (unsigned long)context->Edx, (unsigned long)context->Esi,
           (unsigned long)context->Edi, (unsigned long)context->Ebp,
           (unsigned long)context->EFlags );
    message.result.version = MADEIRA_SE_CPU_ABI_VERSION;
    if ((status = dispatch( MADEIRA_SE_WINE_CPU_RUN, &message, sizeof(message) )))
        terminate_on_error( status );
    if (!(message.result.reserved[0] & MADEIRA_SE_CPU_RESULT_CONTEXT_UNCHANGED))
        canonical_to_context( &message.context, context );
    TRACE( "run exit reason %u vector %u instructions %llu eip %#lx esp %#lx eax %#lx "
           "ebx %#lx ecx %#lx edx %#lx esi %#lx edi %#lx ebp %#lx eflags %#lx "
           "error %#x fault %#llx\n",
           message.result.reason, message.result.exception_vector,
           (unsigned long long)message.result.instructions_executed,
           (unsigned long)context->Eip, (unsigned long)context->Esp,
           (unsigned long)context->Eax, (unsigned long)context->Ebx,
           (unsigned long)context->Ecx, (unsigned long)context->Edx,
           (unsigned long)context->Esi, (unsigned long)context->Edi,
           (unsigned long)context->Ebp, (unsigned long)context->EFlags,
           message.result.exception_error_code,
           (unsigned long long)message.result.fault_address );

    if (message.result.reason == MADEIRA_SE_CPU_EXIT_SYSCALL ||
        context->Eip == guest_address( syscall_dispatcher ))
    {
        madeira_cpu_disable_context_reuse( thread );
        service_dispatcher( context, FALSE );
    }
    else if (message.result.reason == MADEIRA_SE_CPU_EXIT_UNIX_CALL ||
             context->Eip == guest_address( unix_call_dispatcher ))
    {
        madeira_cpu_disable_context_reuse( thread );
        service_dispatcher( context, TRUE );
    }
    else if (message.result.reason == MADEIRA_SE_CPU_EXIT_EXCEPTION)
    {
        madeira_cpu_disable_context_reuse( thread );
        EXCEPTION_RECORD record = { 0 };

        if (message.result.exception_vector == 14 &&
            sync_fault_mapping( message.result.fault_address,
                                message.result.exception_error_code ))
            return;
        if (message.result.exception_vector == 14)
        {
            record.ExceptionCode = STATUS_ACCESS_VIOLATION;
            record.ExceptionAddress = (void *)(ULONG_PTR)context->Eip;
            record.NumberParameters = 2;
            record.ExceptionInformation[0] = (message.result.exception_error_code & 0x10) ? 8 :
                                             (message.result.exception_error_code & 0x02) ? 1 : 0;
            record.ExceptionInformation[1] = message.result.fault_address;
            if (Wow64RaiseException( -1, &record )) terminate_on_error( record.ExceptionCode );
        }
        else if (Wow64RaiseException( message.result.exception_vector, &record ))
            terminate_on_error( exception_status( message.result.exception_vector ) );
    }
    else if (message.result.reason == MADEIRA_SE_CPU_EXIT_HALT)
    {
        madeira_cpu_disable_context_reuse( thread );
        terminate_on_error( STATUS_ILLEGAL_INSTRUCTION );
    }
    else if (thread)
    {
        if (message.result.reason == MADEIRA_SE_CPU_EXIT_BUDGET)
            madeira_cpu_record_budget( thread,
                                       (message.request.flags & MADEIRA_SE_CPU_RUN_REUSE_CONTEXT) != 0 );
        else
            madeira_cpu_disable_context_reuse( thread );
    }
}

static void madeira_cpu_simulate_amd64( struct madeira_thread *thread )
{
    madeira_se_wine_cpu_run_message_t message;
    AMD64_CONTEXT *context = &thread->amd64_context;
    NTSTATUS status;

    if (context->Rip == guest_address( syscall_dispatcher ))
    {
        madeira_cpu_disable_context_reuse( thread );
        service_dispatcher_amd64( context, FALSE );
        return;
    }
    if (context->Rip == guest_address( unix_call_dispatcher ))
    {
        madeira_cpu_disable_context_reuse( thread );
        service_dispatcher_amd64( context, TRUE );
        return;
    }
    init_message( &message, sizeof(message) );
    message.thread_handle = thread->handle;
    message.request.version = MADEIRA_SE_CPU_ABI_VERSION;
    message.request.max_instructions = madeira_cpu_run_budget();
    message.request.syscall_dispatcher = guest_address( syscall_dispatcher );
    message.request.unix_call_dispatcher = guest_address( unix_call_dispatcher );
    if (thread->cpu_context_reusable && thread->cpu_context_reuse_remaining &&
        madeira_cpu_reuse_slices())
        message.request.flags |= MADEIRA_SE_CPU_RUN_REUSE_CONTEXT;
    amd64_context_to_canonical( context, &message.context );
    message.result.version = MADEIRA_SE_CPU_ABI_VERSION;
    activate_amd64_stack( thread );
    status = dispatch( MADEIRA_SE_WINE_CPU_RUN, &message, sizeof(message) );
    deactivate_amd64_stack( thread );
    if (status)
        terminate_on_error( status );
    if (!(message.result.reserved[0] & MADEIRA_SE_CPU_RESULT_CONTEXT_UNCHANGED))
        canonical_to_amd64_context( &message.context, context );

    if (message.result.reason == MADEIRA_SE_CPU_EXIT_SYSCALL ||
        context->Rip == guest_address( syscall_dispatcher ))
    {
        madeira_cpu_disable_context_reuse( thread );
        service_dispatcher_amd64( context, FALSE );
    }
    else if (message.result.reason == MADEIRA_SE_CPU_EXIT_UNIX_CALL ||
             context->Rip == guest_address( unix_call_dispatcher ))
    {
        madeira_cpu_disable_context_reuse( thread );
        service_dispatcher_amd64( context, TRUE );
    }
    else if (message.result.reason == MADEIRA_SE_CPU_EXIT_EXCEPTION)
    {
        madeira_cpu_disable_context_reuse( thread );
        const unsigned char *code = guest_pointer( context->Rip );
        const ULONG64 *stack = guest_pointer( context->Rsp );

        if (message.result.exception_vector == 14 &&
            sync_fault_mapping( message.result.fault_address,
                                message.result.exception_error_code ))
            return;
        ERR( "x86-64 guest exception vector %u error %#x at rip %#llx fault %#llx "
             "rsp %#llx rax %#llx rcx %#llx rdx %#llx\n",
             message.result.exception_vector, message.result.exception_error_code,
             (unsigned long long)context->Rip,
             (unsigned long long)message.result.fault_address,
             (unsigned long long)context->Rsp, (unsigned long long)context->Rax,
             (unsigned long long)context->Rcx, (unsigned long long)context->Rdx );
        if (code && virtual_check_buffer_for_read( code, 16 ))
            ERR( "x86-64 exception code %02x %02x %02x %02x %02x %02x %02x %02x "
                 "%02x %02x %02x %02x %02x %02x %02x %02x\n",
                 code[0], code[1], code[2], code[3], code[4], code[5], code[6], code[7],
                 code[8], code[9], code[10], code[11], code[12], code[13], code[14], code[15] );
        if (stack && virtual_check_buffer_for_read( stack, 16 * sizeof(*stack) ))
            ERR( "x86-64 exception stack %#llx %#llx %#llx %#llx %#llx %#llx %#llx %#llx "
                 "%#llx %#llx %#llx %#llx %#llx %#llx %#llx %#llx\n",
                 (unsigned long long)stack[0], (unsigned long long)stack[1],
                 (unsigned long long)stack[2], (unsigned long long)stack[3],
                 (unsigned long long)stack[4], (unsigned long long)stack[5],
                 (unsigned long long)stack[6], (unsigned long long)stack[7],
                 (unsigned long long)stack[8], (unsigned long long)stack[9],
                 (unsigned long long)stack[10], (unsigned long long)stack[11],
                 (unsigned long long)stack[12], (unsigned long long)stack[13],
                 (unsigned long long)stack[14], (unsigned long long)stack[15] );
        terminate_on_error( exception_status( message.result.exception_vector ) );
    }
    else if (message.result.reason == MADEIRA_SE_CPU_EXIT_HALT)
    {
        madeira_cpu_disable_context_reuse( thread );
        terminate_on_error( STATUS_ILLEGAL_INSTRUCTION );
    }
    else if (message.result.reason == MADEIRA_SE_CPU_EXIT_BUDGET)
        madeira_cpu_record_budget( thread,
                                   (message.request.flags & MADEIRA_SE_CPU_RUN_REUSE_CONTEXT) != 0 );
    else
        madeira_cpu_disable_context_reuse( thread );
}

void WINAPI madeira_se_x64_ldr_initialize( CONTEXT *native_context )
{
    struct madeira_thread *thread;
    AMD64_CONTEXT initial, *loader_context;
    ULONG_PTR id = (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;

    if (guest_architecture != MADEIRA_SE_ARCH_X86_64 || !x64_init_block)
        terminate_on_error( STATUS_DEVICE_NOT_READY );
    if (init_status) terminate_on_error( init_status );
    madeira_cpu_thread_init();
    if (!(thread = find_thread_entry( id ))) terminate_on_error( STATUS_DEVICE_NOT_READY );
    if (initialize_amd64_stack( thread )) terminate_on_error( STATUS_NO_MEMORY );

    memset( &initial, 0, sizeof(initial) );
    initial.ContextFlags = CONTEXT_AMD64_ALL | CONTEXT_EXCEPTION_REPORTING |
                           CONTEXT_EXCEPTION_ACTIVE;
    initial.Rcx = native_context->X0;
    initial.Rdx = native_context->X1;
    initial.Rsp = (ULONG_PTR)thread->amd64_stack.StackBase - 0x28;
    initial.Rip = x64_init_block->pRtlUserThreadStart;
    initial.SegCs = 0x33;
    initial.SegDs = 0x2b;
    initial.SegEs = 0x2b;
    initial.SegFs = 0x53;
    initial.SegGs = 0x2b;
    initial.SegSs = 0x2b;
    initial.EFlags = 0x202;
    initial.FltSave.ControlWord = 0x27f;
    initial.FltSave.MxCsr = initial.MxCsr = 0x1f80;

    loader_context = (AMD64_CONTEXT *)(initial.Rsp & ~(ULONG_PTR)15) - 1;
    *loader_context = initial;
    thread->amd64_context = initial;
    thread->amd64_context.ContextFlags = CONTEXT_AMD64_ALL;
    thread->amd64_context.Rcx = (ULONG_PTR)loader_context;
    thread->amd64_context.Rsp = (ULONG_PTR)loader_context - sizeof(ULONG64);
    thread->amd64_context.Rip = x64_init_block->pLdrInitializeThunk;
    thread->amd64_context_valid = TRUE;
    TRACE( "entering x86-64 guest loader rip %#llx rsp %#llx context %p\n",
           (unsigned long long)thread->amd64_context.Rip,
           (unsigned long long)thread->amd64_context.Rsp, loader_context );
    TRACE( "native loader context %p x0 %#llx x1 %#llx sp %#llx pc %#llx\n",
           native_context, (unsigned long long)native_context->X0,
           (unsigned long long)native_context->X1,
           (unsigned long long)native_context->Sp,
           (unsigned long long)native_context->Pc );
    for (;;) madeira_cpu_simulate_amd64( thread );
}

static void * WINAPI madeira_cpu_get_bop_code(void) { return syscall_dispatcher; }
static void * WINAPI madeira_cpu_get_unix_opcode(void) { return unix_call_dispatcher; }

static NTSTATUS WINAPI madeira_cpu_get_context( HANDLE thread, HANDLE process, void *unknown, void *context )
{
    (void)process;
    (void)unknown;
    return get_thread_wow64_context( thread, context, sizeof(I386_CONTEXT) );
}

static NTSTATUS WINAPI madeira_cpu_set_context( HANDLE thread, HANDLE process, void *unknown, void *context )
{
    I386_CONTEXT *source = context;
    NTSTATUS status;

    (void)process;
    (void)unknown;
    TRACE( "set guest context thread %p flags %#lx eip %#lx esp %#lx\n",
           thread, (unsigned long)source->ContextFlags, (unsigned long)source->Eip,
           (unsigned long)source->Esp );
    status = set_thread_wow64_context( thread, context, sizeof(I386_CONTEXT) );
    TRACE( "set guest context returned %#x\n", (unsigned int)status );
    return status;
}

static BOOLEAN WINAPI madeira_cpu_feature( UINT feature )
{
    static const ULONGLONG features =
        (1ull << PF_COMPARE_EXCHANGE_DOUBLE) | (1ull << PF_MMX_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_XMMI_INSTRUCTIONS_AVAILABLE) | (1ull << PF_RDTSC_INSTRUCTION_AVAILABLE) |
        (1ull << PF_XMMI64_INSTRUCTIONS_AVAILABLE) | (1ull << PF_NX_ENABLED) |
        (1ull << PF_SSE3_INSTRUCTIONS_AVAILABLE) | (1ull << PF_COMPARE_EXCHANGE128) |
        (1ull << PF_FASTFAIL_AVAILABLE) | (1ull << PF_RDTSCP_INSTRUCTION_AVAILABLE) |
        (1ull << PF_SSSE3_INSTRUCTIONS_AVAILABLE) | (1ull << PF_SSE4_1_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SSE4_2_INSTRUCTIONS_AVAILABLE);

    return feature < 64 && !!(features & (1ull << feature));
}

static NTSTATUS WINAPI madeira_cpu_reset( EXCEPTION_POINTERS *pointers )
{
    (void)pointers;
    return STATUS_SUCCESS;
}

static void WINAPI madeira_cpu_flush( const void *address, SIZE_T size )
{
    NTSTATUS status = invalidate_memory( address, size );
    if (status) WARN( "instruction-cache invalidation failed, status %#x\n", (unsigned int)status );
}

static void WINAPI madeira_cpu_dirty( void *address, SIZE_T size )
{
    notify_memory( MADEIRA_SE_CPU_MEMORY_DIRTY, address, size, PAGE_READWRITE );
}

static void WINAPI madeira_cpu_alloc( void *address, SIZE_T size, ULONG type, ULONG protect,
                                      BOOL post, NTSTATUS status )
{
    (void)type;
    (void)protect;
    if (post && !status) map_address_range( address, size );
}

static void WINAPI madeira_cpu_protect( void *address, SIZE_T size, ULONG protect,
                                        BOOL post, NTSTATUS status )
{
    if (post && !status) notify_memory( MADEIRA_SE_CPU_MEMORY_PROTECT, address, size, protect );
}

static void WINAPI madeira_cpu_free( void *address, SIZE_T size, ULONG type,
                                     BOOL post, NTSTATUS status )
{
    (void)type;
    if (post && !status) notify_memory( MADEIRA_SE_CPU_MEMORY_UNMAP, address, size, 0 );
}

static NTSTATUS WINAPI madeira_cpu_map( void *unknown1, void *address, void *unknown2,
                                        SIZE_T size, ULONG type, ULONG protect )
{
    (void)unknown1;
    (void)unknown2;
    (void)type;
    (void)protect;
    return map_address_range( address, size );
}

static void WINAPI madeira_cpu_unmap( void *address, BOOL post, NTSTATUS status )
{
    if (post && !status) notify_memory( MADEIRA_SE_CPU_MEMORY_UNMAP, address, 0, 0 );
}

static void WINAPI madeira_cpu_read( HANDLE handle, void *address, SIZE_T size,
                                     BOOL post, NTSTATUS status )
{
    (void)handle;
    if (post && !status) notify_memory( MADEIRA_SE_CPU_MEMORY_DIRTY, address, size, PAGE_READWRITE );
}

static void WINAPI madeira_cpu_update_info( SYSTEM_CPU_INFORMATION *info )
{
    info->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
    info->ProcessorLevel = 6;
    info->ProcessorRevision = 0x3a09;
}

static void WINAPI madeira_cpu_thread_term( HANDLE thread, LONG exit_code )
{
    madeira_se_wine_cpu_thread_term_message_t message;
    THREAD_BASIC_INFORMATION info;
    ULONG_PTR id;
    uint64_t handle;

    if (!thread || thread == NtCurrentThread()) id = (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;
    else if (!NtQueryInformationThread( thread, ThreadBasicInformation, &info, sizeof(info), NULL ))
        id = (ULONG_PTR)info.ClientId.UniqueThread;
    else return;
    if (!(handle = remove_thread( id ))) return;
    init_message( &message, sizeof(message) );
    message.thread_handle = handle;
    message.exit_code = exit_code;
    dispatch( MADEIRA_SE_WINE_CPU_THREAD_TERM, &message, sizeof(message) );
}

static void WINAPI madeira_cpu_process_term( HANDLE process, BOOL post, NTSTATUS status )
{
    /*
     * Wine calls BTCpuProcessTerm around NtTerminateProcess(NULL, ...), which
     * only marks the process as exiting and returns to the guest.  It does not
     * carry the requested exit code, and guest ntdll still has termination work
     * to run afterwards.  Keep the interpreter alive until the native Wine
     * process exits and lets the OS reclaim the in-process runtime.
     */
    (void)process;
    (void)post;
    (void)status;
}

static const struct madeira_se_wow64_cpu_ops cpu_ops =
{
    madeira_cpu_initialize,
    madeira_cpu_get_bop_code,
    madeira_cpu_get_context,
    madeira_cpu_feature,
    madeira_cpu_process_init,
    madeira_cpu_set_context,
    madeira_cpu_thread_init,
    madeira_cpu_simulate,
    madeira_cpu_get_unix_opcode,
    madeira_cpu_reset,
    madeira_cpu_flush,
    madeira_cpu_map,
    madeira_cpu_alloc,
    madeira_cpu_dirty,
    madeira_cpu_free,
    madeira_cpu_protect,
    madeira_cpu_read,
    madeira_cpu_unmap,
    madeira_cpu_update_info,
    madeira_cpu_process_term,
    madeira_cpu_thread_term,
};

const struct madeira_se_wow64_cpu_ops *madeira_se_wow64_get_cpu_ops(void)
{
    return &cpu_ops;
}
