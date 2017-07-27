// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef _pal_scan_h_
#define _pal_scan_h_

#include "common.h"
#include "prx_types.h"

//
// Represents a scan of the network or a machine
//
typedef struct pal_scan pal_scan_t;

//
// Called before the following functions are used
//
decl_public_0(int32_t, pal_scan_init,
    void
);

//
// Called for each found address
//
typedef void (*pal_scan_cb_t)(
    void *context,
    uint64_t itf_index,
    int32_t error,
    prx_socket_address_t *addr
    );

//
// Scan for addresses in subnets
//
decl_public_5(int32_t, pal_scan_net,
    int32_t, flags,
    uint16_t, port,
    pal_scan_cb_t, cb,
    void*, context,
    pal_scan_t**, scan
);

//
// Scan for ports on address
//
decl_public_7(int32_t, pal_scan_ports,
    const prx_socket_address_t*, addr,
    uint16_t, port_range_low,
    uint16_t, port_range_high,
    int32_t, flags,
    pal_scan_cb_t, cb,
    void*, context,
    pal_scan_t**, scan
);

//
// Release and abort in progress scan
//
decl_public_1(void, pal_scan_close,
    pal_scan_t*, scan
);

//
// Called when done using above functions
//
decl_public_0(void, pal_scan_deinit,
    void
);

#endif // _pal_scan_h_