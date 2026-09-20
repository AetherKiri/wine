/*
 * macOS driver entry points for other unix libraries.
 *
 * DXMT's winemetal.so resolves this table with
 * dlsym(RTLD_DEFAULT, "macdrv_functions") to attach a CAMetalLayer to a Wine
 * window: it needs the driver's window data, the Cocoa view and the Metal
 * view helpers. Wine's unix libraries hide their symbols by default, so the
 * table has to be exported explicitly.
 *
 * Copyright 2026 The Madeira contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"

#import <AppKit/AppKit.h>
#import <QuartzCore/QuartzCore.h>
#include <dispatch/dispatch.h>

#include "macdrv_cocoa.h"
#include "cocoa_event.h"

/*
 * These come from macdrv.h, which drags in the Win32 GDI headers that a unix
 * library must not use. HWND and BOOL are pointer/int sized, so declaring the
 * two helpers with equivalent types keeps the ABI identical.
 */
struct macdrv_win_data;
extern struct macdrv_win_data *get_win_data( void *hwnd );
extern void release_win_data( struct macdrv_win_data *data );
extern macdrv_window macdrv_get_cocoa_window( void *hwnd, int require_on_screen );

/* window.c: returns the Cocoa window, and its client view when one exists. */
extern void *macdrv_get_window_views( void *hwnd, void **client_view_out );

/*
 * A window has no client view until something presents into it, so fall back
 * to the Cocoa window's content view. Both are plain AppKit objects, which is
 * what keeps this callable from the guest CPU thread.
 */
static macdrv_view get_client_view( void *hwnd )
{
    void *client_view = NULL;
    macdrv_window window = macdrv_get_window_views( hwnd, &client_view );

    if (client_view) return (macdrv_view)client_view;
    if (window) return (macdrv_view)[(NSWindow *)window contentView];
    return NULL;
}

/* Layout must match the copy DXMT keeps in winemetal_unix.c. */
struct macdrv_functions_t
{
    void (*macdrv_init_display_devices)(int);
    struct macdrv_win_data *(*get_win_data)(void *hwnd);
    void (*release_win_data)(struct macdrv_win_data *data);
    macdrv_window (*macdrv_get_cocoa_window)(void *hwnd, int require_on_screen);
    macdrv_metal_device (*macdrv_create_metal_device)(void);
    void (*macdrv_release_metal_device)(macdrv_metal_device d);
    macdrv_metal_view (*macdrv_view_create_metal_view)(macdrv_view v, macdrv_metal_device d);
    macdrv_metal_layer (*macdrv_view_get_metal_layer)(macdrv_metal_view v);
    void (*macdrv_view_release_metal_view)(macdrv_metal_view v);
    void (*on_main_thread)(dispatch_block_t b);
    macdrv_view (*macdrv_get_client_view)(void *hwnd);
};

__attribute__((visibility("default")))
struct macdrv_functions_t macdrv_functions =
{
    NULL, /* this driver has no separate display-device initializer */
    get_win_data,
    release_win_data,
    macdrv_get_cocoa_window,
    macdrv_create_metal_device,
    macdrv_release_metal_device,
    macdrv_view_create_metal_view,
    macdrv_view_get_metal_layer,
    macdrv_view_release_metal_view,
    OnMainThread,
    get_client_view,
};
