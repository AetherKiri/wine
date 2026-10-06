/* Madeira-SE native WoW64 GDI thunk build glue. */

#if 0
#pragma makedep unix
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#define MADEIRA_SE_WOW64WIN_HOST 1
#include "../wow64win/gdi.c"
#endif
