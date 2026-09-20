/* Madeira-SE: compile Wine's security WoW64 thunks into the signed Mach-O host. */
#if 0
#pragma makedep unix
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#include "madeira_wow64_host_private.h"
#include "../../wow64/security.c"
#endif
