// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef _pal_net_h_
#define _pal_net_h_

#include "common.h"
#include "prx_types.h"


//
// Called before the following functions are used
//
decl_public_0(int32_t, pal_net_init,
    void
);

//
// Convert an address string into an address
//
decl_public_2(int32_t, pal_pton,
    const char*, addr_string,
    prx_socket_address_t*, address
);

//
// Convert an address to a string
//
decl_public_3(int32_t, pal_ntop,
    prx_socket_address_t*, address,
    char*, addr_string,
    size_t, addr_string_size
);

//
// Returns the name of the host computer
//
decl_public_2(int32_t, pal_gethostname,
    char*, name,
    size_t, name_length
);

//
// Look up interface addresses
//
decl_public_4(int32_t, pal_getifaddrinfo,
    const char*, if_name,
    uint32_t, flags,
    prx_ifaddrinfo_t**, info,
    size_t*, info_count
);

//
// Frees interface address info
//
decl_public_1(int32_t, pal_freeifaddrinfo,
    prx_ifaddrinfo_t*, info
);

//
// Inverse of getifaddrinfo, converts interface address
//
decl_public_4(int32_t, pal_getifnameinfo,
    prx_socket_address_t*, if_address,
    char*, if_name,
    size_t, if_name_length,
    uint64_t*, if_index
);

//
// Look up host name
//
decl_public_6(int32_t, pal_getaddrinfo,
    const char*, host_name,
    const char*, service,
    prx_address_family_t, family,
    uint32_t, flags,
    prx_addrinfo_t**, info,
    size_t*, info_count
);

//
// Frees address info
//
decl_public_1(int32_t, pal_freeaddrinfo,
    prx_addrinfo_t*, info
);

//
// Inverse of getaddrinfo, from socket address to host
//
decl_public_6(int32_t, pal_getnameinfo,
    prx_socket_address_t*, address,
    char*, host,
    size_t, host_length,
    char*, service,
    size_t, service_length,
    int32_t, flags
);

//
// Called for each found address
//
typedef int32_t (*pal_scan_cb_t)(
    void *context,
    uint64_t itf_index,
    int32_t error,
    prx_socket_address_t *addr
    );

//
// Scan for addresses with open port in subnets
//
decl_public_4(int32_t, pal_ipscan,
    int32_t, flags,
    uint16_t, port,
    pal_scan_cb_t, cb,
    void*, context
);

//
// Scan for ports on address
//
decl_public_6(int32_t, pal_portscan,
    prx_socket_address_t*, addr,
    uint16_t, port_range_low,
    uint16_t, port_range_high,
    int32_t, flags,
    pal_scan_cb_t, cb,
    void*, context
);

//
// Returns a networking stack error
//
decl_public_0(int32_t, pal_os_last_net_error_as_prx_error,
    void
);

//
// Sets last networking stack error
//
decl_public_1(void, pal_os_set_net_error_as_prx_error,
    int32_t, error
);

//
// Called when done using above functions
//
decl_public_0(void, pal_net_deinit,
    void
);

#endif // _pal_net_h_