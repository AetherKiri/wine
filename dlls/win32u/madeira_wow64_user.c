/* Madeira-SE native WoW64 USER thunk build glue. */

#if 0
#pragma makedep unix
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#define MADEIRA_SE_WOW64WIN_HOST 1
#define NtCallbackReturn madeira_se_wow64win_callback_return
#include "../wow64win/user.c"
#undef NtCallbackReturn

struct madeira_se_callback_state
{
    struct madeira_se_callback_state *previous;
    void *ret_ptr;
    ULONG ret_len;
    NTSTATUS status;
    BOOL returned;
};

static _Thread_local struct madeira_se_callback_state *callback_state;
static _Thread_local void *callback_result;
static _Thread_local SIZE_T callback_result_capacity;

NTSTATUS WINAPI madeira_se_wow64win_callback_return( void *ret_ptr, ULONG ret_len,
                                                      NTSTATUS status )
{
    struct madeira_se_callback_state *state = callback_state;
    void *buffer;

    if (!state) return STATUS_NO_CALLBACK_ACTIVE;
    if (ret_len > callback_result_capacity)
    {
        if (!(buffer = realloc( callback_result, ret_len ))) return STATUS_NO_MEMORY;
        callback_result = buffer;
        callback_result_capacity = ret_len;
    }
    if (ret_len) memcpy( callback_result, ret_ptr, ret_len );
    state->ret_ptr = callback_result;
    state->ret_len = ret_len;
    state->status = status;
    state->returned = TRUE;
    return status;
}

DECLSPEC_EXPORT NTSTATUS madeira_se_wow64win_dispatch_callback( ULONG id, const void *args,
                                                                ULONG len, void **ret_ptr,
                                                                ULONG *ret_len )
{
    struct madeira_se_callback_state state = { callback_state };
    NTSTATUS status;

    if (id >= NtUserCallCount || !ret_ptr || !ret_len) return STATUS_INVALID_PARAMETER;
    callback_state = &state;
    status = user_callbacks[id]( (void *)args, len );
    callback_state = state.previous;
    if (state.returned)
    {
        *ret_ptr = state.ret_ptr;
        *ret_len = state.ret_len;
        return state.status;
    }
    *ret_ptr = NULL;
    *ret_len = 0;
    return status;
}
#endif
