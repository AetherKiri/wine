/*
 * Madeira-SE native WoW64 bridge shared declarations.
 *
 * Copyright (C) 2026 The Madeira contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __WINE_MADEIRA_WOW64_H
#define __WINE_MADEIRA_WOW64_H

struct madeira_se_wow64_cpu_ops
{
    NTSTATUS (*initialize)(void);
    void *   (WINAPI *get_bop_code)(void);
    NTSTATUS (WINAPI *get_context)(HANDLE,HANDLE,void *,void *);
    BOOLEAN  (WINAPI *is_processor_feature_present)(UINT);
    void     (WINAPI *process_init)(void);
    NTSTATUS (WINAPI *set_context)(HANDLE,HANDLE,void *,void *);
    void     (WINAPI *thread_init)(void);
    void     (WINAPI *simulate)(void);
    void *   (WINAPI *get_unix_opcode)(void);
    NTSTATUS (WINAPI *reset_to_consistent_state)(EXCEPTION_POINTERS *);
    void     (WINAPI *flush_instruction_cache)(const void *,SIZE_T);
    NTSTATUS (WINAPI *notify_map_view)(void *,void *,void *,SIZE_T,ULONG,ULONG);
    void     (WINAPI *notify_memory_alloc)(void *,SIZE_T,ULONG,ULONG,BOOL,NTSTATUS);
    void     (WINAPI *notify_memory_dirty)(void *,SIZE_T);
    void     (WINAPI *notify_memory_free)(void *,SIZE_T,ULONG,BOOL,NTSTATUS);
    void     (WINAPI *notify_memory_protect)(void *,SIZE_T,ULONG,BOOL,NTSTATUS);
    void     (WINAPI *notify_read_file)(HANDLE,void *,SIZE_T,BOOL,NTSTATUS);
    void     (WINAPI *notify_unmap_view)(void *,BOOL,NTSTATUS);
    void     (WINAPI *update_processor_information)(SYSTEM_CPU_INFORMATION *);
    void     (WINAPI *process_term)(HANDLE,BOOL,NTSTATUS);
    void     (WINAPI *thread_term)(HANDLE,LONG);
};

extern const struct madeira_se_wow64_cpu_ops *madeira_se_wow64_get_cpu_ops(void);
extern NTSTATUS madeira_se_wow64_host_init( SYSTEM_DLL_INIT_BLOCK *init_block,
                                            WOW64INFO *info,
                                            ULONG highest_address,
                                            const struct madeira_se_wow64_cpu_ops *ops );
extern void madeira_se_wow64_set_win32_syscall_table( const SYSTEM_SERVICE_TABLE *table );
extern void WINAPI Wow64LdrpInitialize( CONTEXT *context );
extern NTSTATUS madeira_se_x64_host_init( SYSTEM_DLL_INIT_BLOCK *init_block, HMODULE module );
extern void WINAPI madeira_se_x64_ldr_initialize( CONTEXT *context );
extern BOOL madeira_se_x64_callback_ready(void);
extern NTSTATUS madeira_se_x64_user_callback( ULONG id, const void *args, ULONG len,
                                               void **ret_ptr, ULONG *ret_len );
extern DECLSPEC_EXPORT BOOL madeira_se_wow64_runtime_active(void);
extern DECLSPEC_NORETURN void WINAPI madeira_se_native_exception_dispatcher( EXCEPTION_RECORD *rec,
                                                                              CONTEXT *context );

#endif /* __WINE_MADEIRA_WOW64_H */
