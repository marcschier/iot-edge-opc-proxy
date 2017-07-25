// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "os.h"
#include "util_mem.h"
#include "prx_sched.h"
#include "pal_net.h"
#include "pal_types.h"
#include "pal_err.h"
#include "util_string.h"
#include "util_misc.h"

//
// Returns a networking stack error as pal error
//
int32_t pal_os_to_prx_net_error(
    int error
)
{
    switch (error)
    {
    case 0:                           return er_ok;
    case WSAEINTR:                    return er_aborted;
    case WSAEBADF:                    return er_arg;
    case WSAEACCES:                   return er_permission;
    case WSAEFAULT:                   return er_fault;
    case WSAEINVAL:                   return er_arg;
    case WSAEMFILE:                   return er_out_of_memory;
    case WSAEWOULDBLOCK:              return er_retry;
    case WSAEINPROGRESS:              return er_retry;
    case WSAEALREADY:                 return er_waiting;
    case WSAENOTSOCK:                 return er_arg;
    case WSAEDESTADDRREQ:             return er_arg;
    case WSAEMSGSIZE:                 return er_arg;
    case WSAEPROTOTYPE:               return er_arg;
    case WSAENOPROTOOPT:              return er_arg;
    case WSAEPROTONOSUPPORT:          return er_not_impl;
    case WSAEOPNOTSUPP:               return er_not_impl;
    case WSAEAFNOSUPPORT:             return er_not_impl;
    case WSAEADDRINUSE:               return er_busy;
    case WSAEADDRNOTAVAIL:            return er_not_found;
    case WSAHOST_NOT_FOUND:           return er_host_unknown;
    case WSAENETDOWN:                 return er_network;
    case WSAENETUNREACH:              return er_undelivered;
    case WSAENETRESET:                return er_network;
    case WSAECONNABORTED:             return er_closed;
    case WSAECONNRESET:               return er_closed;
    case WSAENOBUFS:                  return er_out_of_memory;
    case WSAEISCONN:                  return er_connecting;
    case WSAENOTCONN:                 return er_closed;
    case WSAETIMEDOUT:                return er_timeout;
    case WSAECONNREFUSED:             return er_refused;
    case WSAELOOP:                    return er_arg;
    case WSAENAMETOOLONG:             return er_arg;
    case WSAEHOSTUNREACH:             return er_connecting;
    case WSAENOTEMPTY:                return er_disk_io;
    case WSA_IO_PENDING:              return er_waiting;
    case WSA_IO_INCOMPLETE:           return er_waiting;
    case WSA_INVALID_HANDLE:          return er_arg;
    case WSA_INVALID_PARAMETER:       return er_arg;
    case WSA_NOT_ENOUGH_MEMORY:       return er_out_of_memory;
    case WSA_OPERATION_ABORTED:       return er_aborted;
    case WSAESOCKTNOSUPPORT:          return er_not_impl;
    case WSAEPFNOSUPPORT:             return er_not_impl;
    case WSAESHUTDOWN:                return er_shutdown;
    case WSAETOOMANYREFS:             return er_out_of_memory;
    case WSAEHOSTDOWN:                return er_connecting;
    case WSAEPROCLIM:                 return er_out_of_memory;
    case WSAEUSERS:                   return er_out_of_memory;
    case WSAEDQUOT:                   return er_out_of_memory;
    case WSAESTALE:                   return er_disk_io;
    case WSAEREMOTE:                  return er_disk_io;
    case WSAEDISCON:                  return er_closed;
    case WSAENOMORE:                  return er_nomore;
    case WSAECANCELLED:               return er_aborted;
    case WSAEREFUSED:                 return er_refused;
    case WSANOTINITIALISED:           return er_bad_state;
    case WSASYSCALLFAILURE:           return er_unknown;
    default:
        dbg_assert(0, "Unknown os error %d", error);
    }
    return er_unknown;
}

//
// Returns a networking stack error as pal error
//
int pal_os_from_prx_net_error(
    int32_t error
)
{
    switch (error)
    {
    case er_ok:                       return 0;
    case er_out_of_memory:            return WSA_NOT_ENOUGH_MEMORY;
    case er_permission:               return WSAEACCES;
    case er_fault:                    return WSAEFAULT;
    case er_arg:                      return WSAEINVAL;
    case er_retry:                    return WSAEWOULDBLOCK;
    case er_waiting:                  return WSAEALREADY;
    case er_not_impl:                 return WSAEOPNOTSUPP;
    case er_not_supported:            return WSAEOPNOTSUPP;
    case er_busy:                     return WSAEADDRINUSE;
    case er_not_found:                return WSAEADDRNOTAVAIL;
    case er_host_unknown:             return WSAHOST_NOT_FOUND;
    case er_network:                  return WSAENETDOWN;
    case er_connecting:               return WSAECONNABORTED;
    case er_closed:                   return WSAENOTCONN;
    case er_shutdown:                 return WSAESHUTDOWN;
    case er_refused:                  return WSAEREFUSED;
    case er_timeout:                  return WSAETIMEDOUT;
    case er_disk_io:                  return WSAENOTEMPTY;
    case er_bad_state:                return WSANOTINITIALISED;
    case er_nomore:                   return WSAENOMORE;
    case er_aborted:                  return WSAECANCELLED;
    case er_unknown:                  return WSASYSCALLFAILURE;
    case er_undelivered:              return WSAENETUNREACH;
    default:
        dbg_assert(0, "Unknown pi error %d", error);
    }
    return -1;
}

//
// Sets last networking stack error
//
void pal_os_set_net_error_as_prx_error(
    int32_t error
)
{
    int32_t result;

    if (error != er_ok)
    {
        log_debug(NULL, "Error occurred: %s", prx_err_string(error));
    }

    result = pal_os_from_prx_net_error(error);

    WSASetLastError(result);
}

//
// Returns a networking stack error as pal error
//
int32_t pal_os_last_net_error_as_prx_error(
    void
)
{
    int32_t error;
    char* message = NULL;

    error = WSAGetLastError();
    if (error != 0 &&
        error != WSAEWOULDBLOCK &&
        error != WSA_IO_PENDING)
    {
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (char*)&message, 0, NULL);
        if (message)
            string_trim_back(message, "\r\n\t ");
        log_info(NULL, "Networking error code %d (%s)",
            error, message ? message : "<unknown>");
        LocalFree(message);
    }
    return pal_os_to_prx_net_error(error);
}

//
// Return platform independent interface address from ifaddrinfo
//
int32_t pal_os_to_prx_ifaddrinfo(
    ifinfo_t* ifi,
    ifaddr_t* ifa,
    prx_ifaddrinfo_t* prx_ifa
)
{
    int32_t result;

    IP_ADAPTER_UNICAST_ADDRESS* ifaddr = (IP_ADAPTER_UNICAST_ADDRESS*)ifa;
    IP_ADAPTER_ADDRESSES* ifinfo = (IP_ADAPTER_ADDRESSES*)ifi;

    memset(prx_ifa, 0, sizeof(prx_ifaddrinfo_t));
    result = pal_os_to_prx_socket_address(
        ifaddr->Address.lpSockaddr, ifaddr->Address.iSockaddrLength, &prx_ifa->address);
    if (result != er_ok)
        return result;

    if (IfOperStatusUp == ifinfo->OperStatus)
        prx_ifa->flags |= prx_ifa_up;
    if (IF_TYPE_SOFTWARE_LOOPBACK == ifinfo->IfType)
        prx_ifa->flags |= prx_ifa_loopback;
    if (0 == (ifinfo->Flags & IP_ADAPTER_NO_MULTICAST))
        prx_ifa->flags |= prx_ifa_multicast;

    prx_ifa->prefix = ifaddr->OnLinkPrefixLength;
    prx_ifa->index = ifinfo->IfIndex;
    strncpy(prx_ifa->name, ifinfo->AdapterName, sizeof(prx_ifa->name));
    return er_ok;
}

//
// Return OS interface address from platform independent ifaddr
//
int32_t pal_os_from_prx_ifaddrinfo(
    prx_ifaddrinfo_t* prx_ifa,
    ifinfo_t* ifinfo,
    ifaddr_t* iaddr
)
{
    chk_arg_fault_return(prx_ifa);
    chk_arg_fault_return(ifinfo);
    chk_arg_fault_return(iaddr);
    return er_not_impl;
}

//
// Look up interface addresses
//
int32_t pal_getifaddrinfo(
    const char* if_name,
    uint32_t flags,
    prx_ifaddrinfo_t** prx_ifa,
    size_t* prx_ifa_count
)
{
    int32_t result;
    size_t alloc_count = 0;
    PIP_ADAPTER_ADDRESSES ifaddr = NULL, ifa;
    IP_ADAPTER_UNICAST_ADDRESS *uai;
    ULONG alloc_size = 15000;
    (void)flags;

    chk_arg_fault_return(prx_ifa);
    chk_arg_fault_return(prx_ifa_count);

    *prx_ifa_count = 0;
    *prx_ifa = NULL;

    // Get all interface addresses
    while (true)
    {
        ifa = (PIP_ADAPTER_ADDRESSES)mem_realloc(ifaddr, alloc_size);
        if (!ifa)
        {
            result = er_out_of_memory;
            break;
        }

        ifaddr = ifa;
        result = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX |
            GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME |
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            NULL, ifaddr, &alloc_size);

        if (result == ERROR_BUFFER_OVERFLOW)
            continue;
        else if (result != 0)
        {
            result = pal_os_to_prx_error(result);
            break;
        }

        // First calculate length of returned structs
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->Next)
        {
            if (if_name &&
                0 != string_compare(ifa->AdapterName, if_name))
                continue;
            // Multiple addresses per adapter possible
            for (uai = ifa->FirstUnicastAddress; uai; uai = uai->Next)
            {
                if (AF_INET != uai->Address.lpSockaddr->sa_family &&
                    AF_INET6 != uai->Address.lpSockaddr->sa_family)
                    continue;
                ++alloc_count;
            }
        }

        if (alloc_count == 0)
        {
            result = er_not_found;
            break;
        }

        // then alloc a flat buffer of ifaddrinfo structures
        *prx_ifa = (prx_ifaddrinfo_t*)mem_zalloc(
            (alloc_count + 1) * sizeof(prx_ifaddrinfo_t));
        if (!*prx_ifa)
        {
            result = er_out_of_memory;
            break;
        }

        // and copy os ifaddr into flat buffer
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->Next)
        {
            prx_ifaddrinfo_t* prx_ifa_cur = &(*prx_ifa)[*prx_ifa_count];
            if (if_name &&
                0 != string_compare(ifa->AdapterName, if_name))
                continue;
            for (uai = ifa->FirstUnicastAddress; uai; uai = uai->Next)
            {
                if (AF_INET != uai->Address.lpSockaddr->sa_family &&
                    AF_INET6 != uai->Address.lpSockaddr->sa_family)
                    continue;

                result = pal_os_to_prx_ifaddrinfo(ifa, uai, prx_ifa_cur);
                if (result == er_ok)
                    (*prx_ifa_count)++;
            }
        }

        // If none were copied even though we had found some, return error
        if (*prx_ifa_count == 0)
        {
            log_error(NULL, "Error: %d ifaddrinfo(s) available, but failed to convert any! (%s)",
                alloc_count, prx_err_string(result));

            mem_free(*prx_ifa);
            *prx_ifa = NULL;

            if (result != er_ok)
                break;
            result = er_not_found;
            break;
        }

        // Otherwise success
        result = er_ok;
        break;
    }

    if (ifaddr)
        mem_free(ifaddr);
    return result;
}

//
// Frees interface address info
//
int32_t pal_freeifaddrinfo(
    prx_ifaddrinfo_t* info
)
{
    chk_arg_fault_return(info);
    mem_free(info);
    return er_ok;
}

//
// Inverse of getifaddrinfo, converts interface address
//
int32_t pal_getifnameinfo(
    prx_socket_address_t* if_address,
    char* if_name,
    size_t if_name_length,
    uint64_t *if_index
)
{
    chk_arg_fault_return(if_address);
    chk_arg_fault_return(if_name);
    chk_arg_fault_return(if_index);
    chk_arg_fault_return(if_name_length);
    return er_not_impl;
}

//
// Return host name
//
int32_t pal_gethostname(
    char* name,
    size_t namelen
)
{
    int32_t result;
    chk_arg_fault_return(name);
    chk_arg_fault_return(namelen);

    result = gethostname((char*)name, (uint32_t)namelen);
    if (result >= 0)
        result = er_ok;
    else
    {
        result = pal_os_last_net_error_as_prx_error();
        if (GetComputerNameA((LPSTR)name, (LPDWORD)&namelen))
            result = er_ok;
    }
    return result;
}

//
// Represents a scanner
//
typedef struct pal_ipscanner pal_ipscanner_t;

//
// Scan task represents an individual probe
//
typedef struct pal_ipscan_task pal_ipscan_task_t;

//
// State of scan task
//
typedef enum pal_ipscan_task_state
{
    pal_ipscan_task_empty = 1,
    pal_ipscan_task_waiting,
    pal_ipscan_task_success,
    pal_ipscan_task_failed
}
pal_ipscan_task_state_t;

//
// Scan task represents an individual probe
//
struct pal_ipscan_task
{
    OVERLAPPED ov;         // Must be first to cast from OVERLAPPED*
    pal_ipscanner_t* scanner;
    pal_ipscan_task_state_t state;
    SOCKADDR_INET from;
    int itf_index;
    SOCKADDR_INET to;
    SOCKET socket;
};

//
// The scan context
//
struct pal_ipscanner
{
    prx_scheduler_t* scheduler;
    int32_t flags;
    uint16_t port; // Port or 0 if only addresses are to be scanned
    pal_scan_cb_t cb;
    void* context;

    pal_ipscan_task_t tasks[1024];   // Use 1024 parallel tasks max
    PMIB_IPNET_TABLE2 neighbors;     // Originally returned head
    PIP_ADAPTER_ADDRESSES ifaddr;        // Allocated adapter infos

    uint32_t ip_scan_itf;
    uint32_t ip_scan_cur;
    uint32_t ip_scan_end;
    size_t neighbors_index;       // First run through neighbors
    IP_ADAPTER_UNICAST_ADDRESS *uacur;
    PIP_ADAPTER_ADDRESSES ifcur;   // Then iterate through adapters
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
    OVERLAPPED* ov,
    LPOVERLAPPED_COMPLETION_ROUTINE completion,
    SOCKET* out
);

//
// Clear task
//
static void pal_ipscan_task_clear(
    pal_ipscan_task_t* task
)
{
    while (!HasOverlappedIoCompleted(&task->ov))
        CancelIoEx((HANDLE)task->socket, &task->ov);

    closesocket(task->socket);

    memset(&task->ov, 0, sizeof(OVERLAPPED));
    task->state = pal_ipscan_task_empty;

    if (task->scanner->scheduler)
        prx_scheduler_clear(task->scanner->scheduler, NULL, task);
}

//
// Complete all scanning and free ip scanner
//
static void pal_ipscan_complete(
    pal_ipscanner_t* scanner
)
{
    for (size_t i = 0; i < _countof(scanner->tasks); i++)
    {
        if (scanner->tasks[i].state != pal_ipscan_task_empty)
            pal_ipscan_task_clear(&scanner->tasks[i]);
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

    // log_trace(scanner->log, "IpScan complete.");
    mem_free_type(pal_ipscanner_t, scanner);
}

//
// Schedule next set of probe task for tasks that have completed
//
static void pal_ipscan_next(
    pal_ipscanner_t* task
);

//
// Complete the task
//
static void pal_ipscan_task_complete(
    pal_ipscan_task_t* task
)
{
    int32_t result;
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
        if (prx_addr.un.family == prx_address_family_inet6)
        {
            log_debug(task->scanner->log, "%s: [%x:%x:%x:%x:%x:%x:%x:%x]:%d",
                task->state == pal_ipscan_task_success ? "Found" : "Failed",
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
                task->state == pal_ipscan_task_success ? "Found" : "Failed",
                prx_addr.un.ip.un.in4.un.u8[0], prx_addr.un.ip.un.in4.un.u8[1],
                prx_addr.un.ip.un.in4.un.u8[2], prx_addr.un.ip.un.in4.un.u8[3],
                prx_addr.un.ip.port);

        }
        if (task->state == pal_ipscan_task_success)
        {
            result = task->scanner->cb(task->scanner->context, task->itf_index,
                task->state == pal_ipscan_task_success ? er_ok : er_not_found, &prx_addr);
            if (result != er_ok)
            {
                pal_ipscan_complete(task->scanner); // Complete scan
                return;
            }
        }
    }

    pal_ipscan_task_clear(task);
    __do_next(task->scanner, pal_ipscan_next);
}

//
// Io completion port operation callback when operation completed
//
static void CALLBACK pal_ipscan_result_from_OVERLAPPED(
    DWORD error,
    DWORD bytes,
    LPOVERLAPPED ov
)
{
    pal_ipscan_task_t* task;
    (void)bytes;
    dbg_assert_ptr(ov);
    task = (pal_ipscan_task_t*)ov;
    dbg_assert_ptr(task);
    dbg_assert_ptr(task->scanner);
    task->state = error == er_ok ? pal_ipscan_task_success : pal_ipscan_task_failed;
    __do_next_s(task->scanner->scheduler, pal_ipscan_task_complete, task);
}

//
// Timeout performing task
//
static void pal_ipscan_task_timeout(
    pal_ipscan_task_t* task
)
{
    dbg_assert_ptr(task->scanner);
    dbg_assert_is_task(task->scanner->scheduler);
    task->state = pal_ipscan_task_failed;
    pal_ipscan_task_complete(task);
}

//
// Schedule next
//
static void pal_ipscan_next(
    pal_ipscanner_t* scanner
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
        if (scanner->tasks[i].state != pal_ipscan_task_empty)
            continue;

        to = &scanner->tasks[i].to;
        from = &scanner->tasks[i].from;
        while(true)
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

                       // log_trace(scanner->log, "Failed to find suitable interface address.");
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
                pal_ipscan_complete(scanner);
            }
            return;
        }

        // Perform actual scan action
        if (scanner->port)
        {
            scanner->tasks[i].state = pal_ipscan_task_waiting;
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
                &scanner->tasks[i].ov, pal_ipscan_result_from_OVERLAPPED,
                &scanner->tasks[i].socket);
            if (result != er_ok)
            {
                // Failed to connect, continue;
                // log_error(scanner->log, "Failed to call connect (%s)",
                //     prx_err_string(result));

                scanner->tasks[i].state = pal_ipscan_task_failed;
                __do_next_s(scanner->scheduler, pal_ipscan_task_complete,
                    &scanner->tasks[i]);
                continue;
            }
        }
        else
        {
            //    QueueUserWorkItem with
            //
            //    SendArp(to)
            continue;
        }

        // Schedule timeout of this task
        __do_later_s(scanner->scheduler, pal_ipscan_task_timeout,
            &scanner->tasks[i], 1000);
    }

    // Clear scheduler since we have filled all empty tasks
    prx_scheduler_clear(scanner->scheduler,
        (prx_task_t)pal_ipscan_next, scanner);
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
    pal_ipscanner_t* scanner;
    ULONG alloc_size = 15000;

    chk_arg_fault_return(cb);

    if (!port) // TODO Remove when arp scan supported
        return er_not_supported;

    scanner = (pal_ipscanner_t*)mem_zalloc_type(pal_ipscanner_t);
    if (!scanner)
        return er_out_of_memory;
    do
    {
        // Initialize scanner
        scanner->log = log_get("pal.ipscan");
        scanner->flags = flags;
        scanner->port = port;
        scanner->cb = cb;
        scanner->context = context;

        for (size_t i = 0; i < _countof(scanner->tasks); i++)
        {
            scanner->tasks[i].state = pal_ipscan_task_empty;
            scanner->tasks[i].scanner = scanner;
        }
        result = prx_scheduler_create(NULL, &scanner->scheduler);
        if (result != er_ok)
            break;

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
        __do_next(scanner, pal_ipscan_next);
        return er_ok;
    }
    while (0);

    pal_ipscan_complete(scanner);
    return result;
}

//
// Scan for ports on address
//
int32_t pal_portscan(
    prx_socket_address_t* addr,
    uint16_t port_range_low,
    uint16_t port_range_high,
    int32_t flags,
    pal_scan_cb_t cb,
    void* context
)
{
    (void)addr;
    (void)port_range_low;
    (void)port_range_high;
    (void)flags;
    (void)cb;
    (void)context;

    return er_not_supported;
}

//
// Called before using networking layer
//
int32_t pal_net_init(
    void
)
{
    int error;
    WSADATA wsd;
    error = WSAStartup(MAKEWORD(2, 2), &wsd);
    if (error != 0)
        return pal_os_to_prx_net_error(error);
    return er_ok;
}

//
// Free networking layer
//
void pal_net_deinit(
    void
)
{
    (void)WSACleanup();
}
