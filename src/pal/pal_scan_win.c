// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "os.h"
#include "util_mem.h"
#include "prx_sched.h"
#include "pal_scan.h"
#include "pal_net.h"
#include "pal_types.h"
#include "pal_err.h"
#include "util_string.h"
#include "util_misc.h"

//
// Represents a scanner
//
typedef struct pal_scan_context pal_scan_context_t;

//
// Scan task represents an individual probe
//
typedef struct pal_scan_probe pal_scan_probe_t;

//
// Tristate of scan probe
//
typedef enum pal_scan_probe_state
{
    pal_scan_probe_idle = 1,
    pal_scan_probe_working,
    pal_scan_probe_done
}
pal_scan_probe_state_t;

//
// Scan task represents an individual probe
//
struct pal_scan_probe
{
    OVERLAPPED ov;         // Must be first to cast from OVERLAPPED*
    pal_scan_context_t* scanner;
    pal_scan_probe_state_t state;
    bool timeout;
    SOCKADDR_INET from;
    int itf_index;
    SOCKADDR_INET to;
    SOCKET socket;
};

#define MAX_PROBES 1024
#define PROBE_TIMEOUT 1000

//
// The context for ip and port scanning
//
struct pal_scan_context
{
    prx_scheduler_t* scheduler;
    int32_t flags;

    SOCKADDR_INET address;     // Address of host when port scanning
    uint16_t port;  // Port or 0 if only addresses are to be scanned

    pal_scan_cb_t cb;
    void* context;

    uint32_t ip_scan_itf;
    uint32_t ip_scan_cur;        // next ip address or port to probe
    uint32_t ip_scan_end;         // End port or ip address to probe

    pal_scan_probe_t tasks[MAX_PROBES];            // Probe contexts
    PMIB_IPNET_TABLE2 neighbors;         // Originally returned head
    PIP_ADAPTER_ADDRESSES ifaddr;         // Allocated adapter infos

    size_t neighbors_index;           // First run through neighbors
    IP_ADAPTER_UNICAST_ADDRESS *uacur;
    PIP_ADAPTER_ADDRESSES ifcur;    // Then iterate through adapters
    log_t log;
};

//
// Creates, binds, and connects a socket - defined in pal_sk_win
//
extern int32_t pal_socket_create_bind_and_connect_async(
    int af,
    const struct sockaddr* from,
    int from_len,
    const struct sockaddr* to,
    int to_len,
    LPOVERLAPPED ov,
    LPOVERLAPPED_COMPLETION_ROUTINE completion,
    SOCKET* out
);

//
// Clear task
//
static void pal_scan_probe_clear(
    pal_scan_probe_t* task
)
{
    while (!HasOverlappedIoCompleted(&task->ov))
        CancelIoEx((HANDLE)task->socket, &task->ov);

    closesocket(task->socket);

    memset(&task->ov, 0, sizeof(OVERLAPPED));
    task->state = pal_scan_probe_idle;

    if (task->scanner->scheduler)
        prx_scheduler_clear(task->scanner->scheduler, NULL, task);
}

//
// Complete all scanning and free scan context
//
static void pal_scan_context_free(
    pal_scan_context_t* scanner
)
{
    for (size_t i = 0; i < _countof(scanner->tasks); i++)
    {
        if (scanner->tasks[i].state != pal_scan_probe_idle)
            pal_scan_probe_clear(&scanner->tasks[i]);
    }
    if (scanner->scheduler)
    {
        prx_scheduler_release(scanner->scheduler, scanner);
        prx_scheduler_at_exit(scanner->scheduler);
    }

    if (scanner->ifaddr)
        mem_free(scanner->ifaddr);
    if (scanner->neighbors)
        FreeMibTable(scanner->neighbors);

    // log_trace(scanner->log, "scan complete.");
    mem_free_type(pal_scan_context_t, scanner);
}

//
// Schedule next set of probe task for tasks that have completed
//
static void pal_scan_next(
    pal_scan_context_t* scanner
);

//
// Complete the task
//
static void pal_scan_probe_complete(
    pal_scan_probe_t* task
)
{
    int32_t result;
    bool found;
    prx_socket_address_t prx_addr;
    dbg_assert_ptr(task->scanner);
    dbg_assert_is_task(task->scanner->scheduler);

    result = pal_os_to_prx_socket_address(
        (const struct sockaddr*)&task->to, task->to.si_family == AF_INET6 ?
        sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in), &prx_addr);
    if (result != er_ok)
    {
        log_error(task->scanner->log, "Failed to convert address (%s)",
            prx_err_string(result));
    }
    else
    {
        found = task->state == pal_scan_probe_done;
        if (prx_addr.un.family == prx_address_family_inet6)
        {
            log_debug(task->scanner->log, "%s: [%x:%x:%x:%x:%x:%x:%x:%x]:%d",
                found ? "Found" : "Failed",
                prx_addr.un.ip.un.in6.un.u16[0], prx_addr.un.ip.un.in6.un.u16[1],
                prx_addr.un.ip.un.in6.un.u16[2], prx_addr.un.ip.un.in6.un.u16[3],
                prx_addr.un.ip.un.in6.un.u16[4], prx_addr.un.ip.un.in6.un.u16[5],
                prx_addr.un.ip.un.in6.un.u16[6], prx_addr.un.ip.un.in6.un.u16[7],
                prx_addr.un.ip.port);
        }
        else
        {
            dbg_assert(prx_addr.un.family == prx_address_family_inet, "af wrong");
            log_debug(task->scanner->log, "%s: %d.%d.%d.%d:%d",
                found ? "Found" : "Failed",
                prx_addr.un.ip.un.in4.un.u8[0], prx_addr.un.ip.un.in4.un.u8[1],
                prx_addr.un.ip.un.in4.un.u8[2], prx_addr.un.ip.un.in4.un.u8[3],
                prx_addr.un.ip.port);

        }
        if (found)
        {
            result = task->scanner->cb(task->scanner->context, task->itf_index,
                er_ok, &prx_addr);
            if (result != er_ok)
            {
                pal_scan_context_free(task->scanner); // Complete scan
                return;
            }
        }
    }

    pal_scan_probe_clear(task);
    __do_next(task->scanner, pal_scan_next);
}

//
// Io completion port operation callback when operation completed
//
static void CALLBACK pal_scan_result_from_OVERLAPPED(
    DWORD error,
    DWORD bytes,
    LPOVERLAPPED ov
)
{
    pal_scan_probe_t* task;
    (void)bytes;
    dbg_assert_ptr(ov);
    task = (pal_scan_probe_t*)ov;
    dbg_assert_ptr(task);
    dbg_assert_ptr(task->scanner);
    if (error == 0)
        task->state = pal_scan_probe_done;
    __do_next_s(task->scanner->scheduler, pal_scan_probe_complete, task);
}

//
// Send arp
//
static DWORD WINAPI pal_scan_probe_with_arp(
    void* context
)
{
    DWORD error;
    ULONG mac_addr[2];
    ULONG mac_addr_size = sizeof(mac_addr);
    pal_scan_probe_t* task;
    dbg_assert_ptr(context);

    task = (pal_scan_probe_t*)context;
    error = SendARP(task->to.Ipv4.sin_addr.s_addr, task->from.Ipv4.sin_addr.s_addr,
        mac_addr, &mac_addr_size);
    if (error == 0)
        task->state = pal_scan_probe_done;
    __do_next_s(task->scanner->scheduler, pal_scan_probe_complete, task);
    return 0;
}

//
// Timeout performing task
//
static void pal_scan_probe_timeout(
    pal_scan_probe_t* task
)
{
    dbg_assert_ptr(task->scanner);
    dbg_assert_is_task(task->scanner->scheduler);
    pal_scan_probe_complete(task);
}

//
// Schedule next ports to be scanned
//
static void pal_scan_next_port(
    pal_scan_context_t* scanner
)
{
    int32_t result;
    uint16_t port;

    dbg_assert_ptr(scanner);
    dbg_assert_is_task(scanner->scheduler);
    for (size_t i = 0; i < _countof(scanner->tasks); i++)
    {
        // Find next non-pending task
        if (scanner->tasks[i].state != pal_scan_probe_idle)
            continue;

        // Select next port
        if (scanner->ip_scan_cur >= scanner->ip_scan_end)
        {
            // No more candidates
            if (i == 0)
            {
                // Notify we are done.
                scanner->cb(scanner->context, 0, er_nomore, NULL);
                pal_scan_context_free(scanner);
            }
            return;
        }

        port = (uint16_t)scanner->ip_scan_cur++;

        // Perform actual scan action - update address with target and port
        scanner->tasks[i].state = pal_scan_probe_working;
        memcpy(&scanner->tasks[i].to, &scanner->address, sizeof(SOCKADDR_INET));
        if (scanner->tasks[i].to.si_family == AF_INET6)
        {
            scanner->tasks[i].to.Ipv6.sin6_port = swap_16(port);
            log_debug(scanner->log, "Probing [%x:%x:%x:%x:%x:%x:%x:%x]:%d",
                scanner->tasks[i].to.Ipv6.sin6_addr.u.Word[0],
                scanner->tasks[i].to.Ipv6.sin6_addr.u.Word[1],
                scanner->tasks[i].to.Ipv6.sin6_addr.u.Word[2],
                scanner->tasks[i].to.Ipv6.sin6_addr.u.Word[3],
                scanner->tasks[i].to.Ipv6.sin6_addr.u.Word[4],
                scanner->tasks[i].to.Ipv6.sin6_addr.u.Word[5],
                scanner->tasks[i].to.Ipv6.sin6_addr.u.Word[6],
                scanner->tasks[i].to.Ipv6.sin6_addr.u.Word[7], port);
        }
        else
        {
            dbg_assert(scanner->tasks[i].to.si_family == AF_INET, "af wrong");
            scanner->tasks[i].to.Ipv4.sin_port = swap_16(port);
            log_debug(scanner->log, "Probing %d.%d.%d.%d:%d",
                scanner->tasks[i].to.Ipv4.sin_addr.S_un.S_un_b.s_b1,
                scanner->tasks[i].to.Ipv4.sin_addr.S_un.S_un_b.s_b2,
                scanner->tasks[i].to.Ipv4.sin_addr.S_un.S_un_b.s_b3,
                scanner->tasks[i].to.Ipv4.sin_addr.S_un.S_un_b.s_b4, port);
        }

        // Connect to port
        memset(&scanner->tasks[i].ov, 0, sizeof(OVERLAPPED));
        scanner->tasks[i].from.si_family = scanner->tasks[i].to.si_family;
        result = pal_socket_create_bind_and_connect_async(
            scanner->tasks[i].to.si_family,
            (const struct sockaddr*)&scanner->tasks[i].from,
            scanner->tasks[i].from.si_family == AF_INET6 ?
                sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in),
            (const struct sockaddr*)&scanner->tasks[i].to,
            scanner->tasks[i].to.si_family == AF_INET6 ?
                sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in),
            &scanner->tasks[i].ov, pal_scan_result_from_OVERLAPPED,
            &scanner->tasks[i].socket);
        if (result != er_ok)
        {
            // Failed to connect, continue;
            log_trace(scanner->log, "Failed to call connect (%s)",
                prx_err_string(result));
            __do_next_s(scanner->scheduler, pal_scan_probe_complete,
                &scanner->tasks[i]);
            continue;
        }

        // Schedule timeout of this task
        __do_later_s(scanner->scheduler, pal_scan_probe_timeout,
            &scanner->tasks[i], PROBE_TIMEOUT);
    }
}

//
// Schedule next addresses to be scanned
//
static void pal_scan_next_address(
    pal_scan_context_t* scanner
)
{
    int32_t result;
    MIB_IPNET_ROW2* row;
    uint32_t subnet_mask;
    PIP_ADAPTER_ADDRESSES ifa;
    PIP_ADAPTER_UNICAST_ADDRESS uai;
    SOCKADDR_INET *to, *from;

    dbg_assert_ptr(scanner);
    dbg_assert_is_task(scanner->scheduler);

    for (size_t i = 0; i < _countof(scanner->tasks); i++)
    {
        // Find next non-pending task
        if (scanner->tasks[i].state != pal_scan_probe_idle)
            continue;

        to = &scanner->tasks[i].to;
        from = &scanner->tasks[i].from;
        while (true)
        {
            if (scanner->ip_scan_cur < scanner->ip_scan_end)
            {
                scanner->ip_scan_cur++;
                to->si_family = to->Ipv4.sin_family = AF_INET;  // Redundant
                to->Ipv4.sin_addr.s_addr = swap_32(scanner->ip_scan_cur);

                from->si_family = from->Ipv4.sin_family = AF_INET;  // Redundant
                from->Ipv4.sin_addr.s_addr = scanner->ip_scan_itf;
                break;
            }

            // Select candidate address
            if (scanner->neighbors)
            {
                if (scanner->neighbors->NumEntries == scanner->neighbors_index)
                {
                    FreeMibTable(scanner->neighbors);
                    scanner->neighbors = NULL;
                }
                else
                {
                    row = &scanner->neighbors->Table[scanner->neighbors_index++];
                    if (row->IsRouter)
                        continue;

                    scanner->tasks[i].itf_index = (int32_t)row->InterfaceIndex;
                    memcpy(to, &row->Address, sizeof(SOCKADDR_INET));

                    // Get adapter address to bind to
                    from->si_family = AF_UNSPEC;
                    for (ifa = scanner->ifaddr; ifa != NULL; ifa = ifa->Next)
                    {
                        if (ifa->IfIndex != row->InterfaceIndex)
                            continue;
                        if (IfOperStatusUp != ifa->OperStatus)
                            break;

                        for (uai = ifa->FirstUnicastAddress; uai; uai = uai->Next)
                        {
                            if (to->si_family != uai->Address.lpSockaddr->sa_family)
                                continue;
                            memcpy(from, uai->Address.lpSockaddr, uai->Address.iSockaddrLength);
                            break;
                        }

                        if (from->si_family != AF_UNSPEC)
                            break; // Found family address

                        log_debug(scanner->log, "Failed to find suitable interface address.");
                        // Continue anyway using "any".
                        memset(from, 0, sizeof(SOCKADDR_INET));
                        from->si_family = to->si_family;
                        break;
                    }

                    if (from->si_family == AF_UNSPEC)
                        continue; // No address found

                    break;
                }
            }

            // See if we can set next range from current unicast address
            if (scanner->uacur)
            {
                subnet_mask = (~0 << scanner->uacur->OnLinkPrefixLength);
                if (scanner->uacur->Address.lpSockaddr->sa_family == AF_INET)
                {
                    scanner->ip_scan_itf = ((struct sockaddr_in*)
                        scanner->uacur->Address.lpSockaddr)->sin_addr.s_addr;

                    scanner->ip_scan_end = scanner->ip_scan_itf | subnet_mask;
                    scanner->ip_scan_cur = scanner->ip_scan_itf & ~subnet_mask;

                    scanner->ip_scan_cur = swap_32(scanner->ip_scan_cur);
                    scanner->ip_scan_end = swap_32(scanner->ip_scan_end);
                    scanner->ip_scan_end++;

                    log_debug(scanner->log, "Scanning %x to %x for interface %x.",
                        scanner->ip_scan_cur, scanner->ip_scan_end, scanner->ip_scan_itf);
                }
                scanner->uacur = scanner->uacur->Next;
                continue;
            }

            if (scanner->ifcur)
            {
                log_trace(scanner->log,
                    "Enumerating interface '%S' (%S) (type:%d, flags:%x, status:%d)",
                    scanner->ifcur->FriendlyName, scanner->ifcur->Description,
                    scanner->ifcur->IfType, scanner->ifcur->Flags, scanner->ifcur->OperStatus);
                if (IfOperStatusUp == scanner->ifcur->OperStatus)
                {
                    if (scanner->ifcur->IfType == IF_TYPE_ETHERNET_CSMACD ||
                        scanner->ifcur->IfType == IF_TYPE_IEEE80211)
                    {
                        scanner->uacur = scanner->ifcur->FirstUnicastAddress;
                    }
                }
                scanner->ifcur = scanner->ifcur->Next; // Next adapter
                continue;
            }

            // No more candidates
            if (i == 0)
            {
                // Notify we are done.
                scanner->cb(scanner->context, 0, er_nomore, NULL);
                pal_scan_context_free(scanner);
            }
            return;
        }

        // Perform actual scan action
        if (scanner->port)
        {
            scanner->tasks[i].state = pal_scan_probe_working;
            // Update address to add port
            if (to->si_family == AF_INET6)
            {
                to->Ipv6.sin6_port = swap_16(scanner->port);

                log_debug(scanner->log,
                    "Connect on [%x:%x:%x:%x:%x:%x:%x:%x]:%d to [%x:%x:%x:%x:%x:%x:%x:%x]:%d",
                    from->Ipv6.sin6_addr.u.Word[0], from->Ipv6.sin6_addr.u.Word[1],
                    from->Ipv6.sin6_addr.u.Word[2], from->Ipv6.sin6_addr.u.Word[3],
                    from->Ipv6.sin6_addr.u.Word[4], from->Ipv6.sin6_addr.u.Word[5],
                    from->Ipv6.sin6_addr.u.Word[6], from->Ipv6.sin6_addr.u.Word[7],
                    swap_16(from->Ipv6.sin6_port),
                    to->Ipv6.sin6_addr.u.Word[0], to->Ipv6.sin6_addr.u.Word[1],
                    to->Ipv6.sin6_addr.u.Word[2], to->Ipv6.sin6_addr.u.Word[3],
                    to->Ipv6.sin6_addr.u.Word[4], to->Ipv6.sin6_addr.u.Word[5],
                    to->Ipv6.sin6_addr.u.Word[6], to->Ipv6.sin6_addr.u.Word[7],
                    scanner->port);
            }
            else
            {
                dbg_assert(to->si_family == AF_INET, "af wrong");
                to->Ipv4.sin_port = swap_16(scanner->port);

                log_debug(scanner->log, "Connect on %d.%d.%d.%d:%d to %d.%d.%d.%d:%d",
                    from->Ipv4.sin_addr.S_un.S_un_b.s_b1, from->Ipv4.sin_addr.S_un.S_un_b.s_b2,
                    from->Ipv4.sin_addr.S_un.S_un_b.s_b3, from->Ipv4.sin_addr.S_un.S_un_b.s_b4,
                    swap_16(from->Ipv4.sin_port),
                    to->Ipv4.sin_addr.S_un.S_un_b.s_b1, to->Ipv4.sin_addr.S_un.S_un_b.s_b2,
                    to->Ipv4.sin_addr.S_un.S_un_b.s_b3, to->Ipv4.sin_addr.S_un.S_un_b.s_b4,
                    scanner->port);
            }

            // Connect to port
            memset(&scanner->tasks[i].ov, 0, sizeof(OVERLAPPED));
            result = pal_socket_create_bind_and_connect_async(
                to->si_family, (const struct sockaddr*)from,
                from->si_family == AF_UNSPEC ? 0 : from->si_family == AF_INET6 ?
                sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in),
                (const struct sockaddr*)to, to->si_family == AF_INET6 ?
                sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in),
                &scanner->tasks[i].ov, pal_scan_result_from_OVERLAPPED,
                &scanner->tasks[i].socket);
            if (result != er_ok)
            {
                // Failed to connect, continue;
                log_trace(scanner->log, "Failed to call connect (%s)",
                    prx_err_string(result));
                __do_next_s(scanner->scheduler, pal_scan_probe_complete,
                    &scanner->tasks[i]);
                continue;
            }

            // Schedule timeout of this task
            __do_later_s(scanner->scheduler, pal_scan_probe_timeout,
                &scanner->tasks[i], PROBE_TIMEOUT);
        }
        else
        {
            if (to->si_family == AF_INET6)
            {
                continue;
            }

            dbg_assert(to->si_family == AF_INET, "af wrong");
            scanner->tasks[i].state = pal_scan_probe_working;
            if (!QueueUserWorkItem(pal_scan_probe_with_arp, &scanner->tasks[i], 0))
            {
                result = pal_os_last_error_as_prx_error();
                log_error(scanner->log, "Failed to queue arp request (%s)",
                    prx_err_string(result));

                result = er_ok;
                continue;
            }
        }
    }
}

//
// Schedule next set of probe task for tasks that have completed
//
static void pal_scan_next(
    pal_scan_context_t* scanner
)
{
    dbg_assert_ptr(scanner);
    dbg_assert_is_task(scanner->scheduler);

    // Do port or ip scanning
    if (scanner->address.si_family == AF_UNSPEC)
        pal_scan_next_address(scanner);
    else
        pal_scan_next_port(scanner);
    // Clear scheduler since we have filled all empty tasks
    prx_scheduler_clear(scanner->scheduler, (prx_task_t)pal_scan_next, scanner);
}

//
// Create scan context
//
static int32_t pal_scan_context_create(
    prx_scheduler_t* parent,
    int32_t flags,
    pal_scan_cb_t cb,
    void* context,
    pal_scan_context_t** created
)
{
    int32_t result;
    pal_scan_context_t* scanner;

    chk_arg_fault_return(cb);

    scanner = (pal_scan_context_t*)mem_zalloc_type(pal_scan_context_t);
    if (!scanner)
        return er_out_of_memory;
    do
    {
        // Initialize scanner
        scanner->log = log_get("pal.ipscan");
        scanner->flags = flags;
        scanner->cb = cb;
        scanner->context = context;

        for (size_t i = 0; i < _countof(scanner->tasks); i++)
        {
            scanner->tasks[i].state = pal_scan_probe_idle;
            scanner->tasks[i].scanner = scanner;
        }

        result = prx_scheduler_create(parent, &scanner->scheduler);
        if (result != er_ok)
            break;

        *created = scanner;
        return er_ok;
    }
    while (0);

    pal_scan_context_free(scanner);
    return result;
}

//
// Scan for addresses with open port in subnet
//
int32_t pal_ipscan(
    int32_t flags,
    uint16_t port,
    pal_scan_cb_t cb,
    void* context
)
{
    int32_t result;
    DWORD error;
    pal_scan_context_t* scanner;
    ULONG alloc_size = 15000;

    chk_arg_fault_return(cb);

    result = pal_scan_context_create(NULL, flags, cb, context, &scanner);
    if (result != er_ok)
        return result;
    do
    {
        scanner->port = port;

        // a) Get interface info
        while (true)
        {
            scanner->ifcur = (PIP_ADAPTER_ADDRESSES)mem_realloc(
                scanner->ifaddr, alloc_size);
            if (!scanner->ifcur)
            {
                result = er_out_of_memory;
                break;
            }

            scanner->ifaddr = scanner->ifcur;
            error = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_INCLUDE_PREFIX |
                GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME |
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                NULL, scanner->ifaddr, &alloc_size);

            if (error == ERROR_BUFFER_OVERFLOW)
                continue;

            if (error != 0)
            {
                result = pal_os_to_prx_error(error);
                log_error(scanner->log, "Failed to get adapter infos (%x, %s).",
                    error, prx_err_string(result));
                break;
            }
            result = er_ok;
            break;
        }

        if (result != er_ok)
            break;

        // b) Get neighbor table for ipv6 addresses
        error = GetIpNetTable2(AF_UNSPEC, &scanner->neighbors);
        if (error != 0)
        {
            result = pal_os_to_prx_net_error(error);
            log_error(scanner->log, "Failure to get neighbor table (%x, %s).",
                error, prx_err_string(result));
            break;
        }

        // Start scan
        __do_next(scanner, pal_scan_next);
        return er_ok;
    }
    while (0);

    pal_scan_context_free(scanner);
    return result;
}

//
// Scan for ports on address
//
int32_t pal_portscan(
    const prx_socket_address_t* addr,
    uint16_t port_range_low,
    uint16_t port_range_high,
    int32_t flags,
    pal_scan_cb_t cb,
    void* context
)
{
    int32_t result;
    pal_scan_context_t* scanner;
    socklen_t sa_len;

    chk_arg_fault_return(addr);
    chk_arg_fault_return(cb);

    if (!port_range_low)
        port_range_low = 1;
    if (!port_range_high)
        port_range_high = (uint16_t)-1;
    if (port_range_high <= port_range_low)
        return er_arg;

    result = pal_scan_context_create(NULL, flags, cb, context, &scanner);
    if (result != er_ok)
        return result;
    do
    {
        scanner->ip_scan_cur = port_range_low;
        scanner->ip_scan_end = port_range_high;
        scanner->ip_scan_end++;

        sa_len = sizeof(SOCKADDR_INET);
        result = pal_os_from_prx_socket_address(addr,
            (struct sockaddr*)&scanner->address, &sa_len);
        if (result != er_ok)
            break;

        // Start scan
        __do_next(scanner, pal_scan_next);
        return er_ok;
    }
    while (0);

    pal_scan_context_free(scanner);
    return result;
}

//
// Called before using scan layer
//
int32_t pal_scan_init(
    void
)
{
    return er_ok;
}

//
// Free networking layer
//
void pal_scan_deinit(
    void
)
{
}
