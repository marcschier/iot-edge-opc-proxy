// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "os.h"
#include "util_mem.h"

#include "pal_ev.h"
#include "pal_sk.h"
#include "pal_scan.h"
#include "pal_net.h"
#include "pal_err.h"
#include "pal_time.h"
#include "pal_types.h"

#include "util_string.h"
#include "util_misc.h"

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
#define PROBE_TIMEOUT 1000
    pal_scan_t* scan;                         // Owning scan session
    ticks_t probe_start;          // Start time of probe for timeout
    pal_scan_probe_state_t state;              // State of the probe
    int itf_index;
    struct sockaddr_in6 from;                      // Source address
    struct sockaddr_in6 to;                   // Destination address
    int sock_fd;                          // Socket used for probing
};

//
// The context for ip and port scanning
//
struct pal_scan
{
    int32_t flags;
    struct sockaddr_in6 address;    // Address of host for port scan
    uint16_t port;  // Port or 0 if only addresses are to be scanned
    pal_scan_cb_t cb;
    void* context;

    uint32_t ip_scan_itf;
    uint32_t ip_scan_cur;        // next ip address or port to probe
    uint32_t ip_scan_end;         // End port or ip address to probe

#define MAX_PROBES 1024
    pal_scan_probe_t tasks[MAX_PROBES];            // Probe contexts
    struct ifaddrs* ifaddr;                    // Allocated if infos
    bool destroy;                // Whether the scan should be freed

    struct ifaddrs* ifcur;               // Iterate through adapters
    bool cache_exhausted;        // Whether all lists were exhausted
    log_t log;
};

//
// Event loop / port to use for all async notifications
//
static uintptr_t event_port = 0;


//
// Dummy callback - ensure callbacks go nowhere after close.
//
static void pal_scan_dummy_cb(
    void *context,
    uint64_t itf_index,
    int32_t error,
    prx_socket_address_t *addr
)
{
    (void)context;
    (void)itf_index;
    (void)error;
    (void)addr;
}

//
// Schedule next set of probe task for tasks that have completed
//
static void pal_scan_next(
    pal_scan_t* scan
);

//
// Clear task
//
static void pal_scan_probe_cancel(
    pal_scan_probe_t* task
)
{
    if (task->sock_fd != -1)
    {
        close(task->sock_fd);
        task->sock_fd = -1;
    }

    task->state = pal_scan_probe_idle;
}

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
    dbg_assert_ptr(task->scan);
    result = pal_os_to_prx_socket_address(__sa_base(&task->to), __sa_size(&task->to), 
        &prx_addr);
    if (result != er_ok)
    {
        log_error(task->scan->log, "Failed to convert address (%s)",
            prx_err_string(result));
    }
    else
    {
        found = task->state == pal_scan_probe_done;
        if (prx_addr.un.family == prx_address_family_inet6)
        {
            log_debug(task->scan->log, "%s: " __prx_sa_in6_fmt,
                found ? "Found" : "Failed", __prx_sa_in6_args(&prx_addr));
        }
        else
        {
            dbg_assert(prx_addr.un.family == prx_address_family_inet, "af wrong");
            log_debug(task->scan->log, "%s: " __prx_sa_in4_fmt,
                found ? "Found" : "Failed", __prx_sa_in4_args(&prx_addr));
        }
        if (found)
        {
            task->scan->cb(task->scan->context, task->itf_index, er_ok, &prx_addr);
        }
    }

    pal_scan_probe_cancel(task);
    pal_scan_next(task->scan);
}

#if 0
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
    dbg_assert_ptr(task->scan);
    if (task->scan->destroy)
        return;
    if (error == 0)
        task->state = pal_scan_probe_done;
    __do_next_s(task->scan->scheduler, pal_scan_probe_complete, task);
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
    __do_next_s(task->scan->scheduler, pal_scan_probe_complete, task);
    return 0;
}
#endif

//
// Timeout performing task
//
static void pal_scan_probe_timeout(
    pal_scan_probe_t* task
)
{
    dbg_assert_ptr(task->scan);
    pal_scan_probe_complete(task);
}

//
// Schedule next ports to be scanned
//
static void pal_scan_next_port(
    pal_scan_t* scan
)
{
    int32_t result;
    uint16_t port;

    dbg_assert_ptr(scan);

    if (scan->cache_exhausted)
        return;

    for (size_t i = 0; i < _countof(scan->tasks); i++)
    {
        // Find next non-pending task
        if (scan->tasks[i].state != pal_scan_probe_idle)
            continue;

        // Select next port
        if (scan->ip_scan_cur >= scan->ip_scan_end)
        {
            // No more candidates
            if (i == 0)
            {
                // Notify we are done.
                scan->cache_exhausted = true;
                scan->cb(scan->context, 0, er_nomore, NULL);
                log_trace(scan->log, "Port scan completed.");
            }
            return;
        }

        port = (uint16_t)scan->ip_scan_cur++;

        // Perform actual scan action - update address with target and port
        scan->tasks[i].state = pal_scan_probe_working;
        memcpy(&scan->tasks[i].to, &scan->address, sizeof(struct sockaddr_in6));
        if (__sa_is_in6(&scan->tasks[i].to))
        {
            __sa_as_in6(&scan->tasks[i].to)->sin6_port = swap_16(port);
            log_debug(scan->log, "Probing " __sa_in6_fmt, 
                __sa_in6_args(&scan->tasks[i].to));
        }
        else
        {
            dbg_assert(__sa_is_in4(&scan->tasks[i].to), "af wrong");
            __sa_as_in4(&scan->tasks[i].to)->sin_port = swap_16(port);
            log_debug(scan->log, "Probing " __sa_in4_fmt,
                __sa_in4_args(&scan->tasks[i].to));
        }

        // Connect to port
        __sa_base(&scan->tasks[i].from)->sa_family =
            __sa_base(&scan->tasks[i].to)->sa_family;

        result = er_fault;
     //   result = pal_socket_create_bind_and_connect_async(
     //       __sa_base(&scan->tasks[i].to)->sa_family,
     //       __sa_base(&scan->tasks[i].from), __sa_size(&scan->tasks[i].from),
     //       __sa_base(&scan->tasks[i].to), __sa_size(&scan->tasks[i].to),
     //       &scan->tasks[i].sock_fd);
        if (result != er_ok)
        {
            // Failed to connect, continue;
            log_trace(scan->log, "Failed to call connect (%s)",
                prx_err_string(result));
            pal_scan_probe_complete(&scan->tasks[i]);
            continue;
        }

        // Schedule timeout of this task
       // __do_later_s(scan->scheduler, pal_scan_probe_timeout,
       //     &scan->tasks[i], PROBE_TIMEOUT);
    }
}

//
// Schedule next addresses to be scanned
//
static void pal_scan_next_address(
    pal_scan_t* scan
)
{
    int32_t result;
    uint32_t subnet_mask;
    struct sockaddr_in6 *to, *from;

    dbg_assert_ptr(scan);

    if (scan->cache_exhausted)
        return;

    for (size_t i = 0; i < _countof(scan->tasks); i++)
    {
        // Find next non-pending task
        if (scan->tasks[i].state != pal_scan_probe_idle)
            continue;

        to = &scan->tasks[i].to;
        from = &scan->tasks[i].from;
        while (true)
        {
            if (scan->ip_scan_cur < scan->ip_scan_end)
            {
                scan->ip_scan_cur++;
                __sa_base(to)->sa_family = AF_INET;  
                __sa_as_in4(to)->sin_addr.s_addr = swap_32(scan->ip_scan_cur);

                __sa_base(from)->sa_family = AF_INET;
                __sa_as_in4(from)->sin_addr.s_addr = scan->ip_scan_itf;
                break;
            }

            // See if we can set next range from current unicast address
            if (scan->ifcur)
            {
                log_trace(scan->log, "-> %S (flags:%x)", scan->ifcur->ifa_name, 
                    scan->ifcur->ifa_flags);
                if (0 != (scan->ifcur->ifa_flags & IFF_UP) &&
                    0 == (scan->ifcur->ifa_flags & IFF_LOOPBACK) &&
                    __sa_is_in4(scan->ifcur->ifa_addr))
                {
                    scan->ip_scan_itf = __sa_as_in4(&scan->ifcur->ifa_addr)->sin_addr.s_addr;
                    subnet_mask = __sa_as_in4(&scan->ifcur->ifa_netmask)->sin_addr.s_addr;

                    scan->ip_scan_end = scan->ip_scan_itf | subnet_mask;
                    scan->ip_scan_cur = scan->ip_scan_itf & ~subnet_mask;

                    scan->ip_scan_cur = swap_32(scan->ip_scan_cur);
                    scan->ip_scan_end = swap_32(scan->ip_scan_end);
                    scan->ip_scan_end++;

                    log_trace(scan->log, "Scanning %d.%d.%d.%d/%d.",
                        ((uint8_t*)&scan->ip_scan_itf)[0], ((uint8_t*)&scan->ip_scan_itf)[1],
                        ((uint8_t*)&scan->ip_scan_itf)[2], ((uint8_t*)&scan->ip_scan_itf)[3],
                        count_leading_ones_in_buf((uint8_t*)&subnet_mask, 4));
                }
                scan->ifcur = scan->ifcur->ifa_next;
                continue;
            }

            // No more candidates
            if (i == 0)
            {
                // Notify we are done.
                scan->cache_exhausted = true;
                scan->cb(scan->context, 0, er_nomore, NULL);
                log_trace(scan->log, "IP scan completed.");
            }
            return;
        }

        // Perform actual scan action
        if (scan->port)
        {
            scan->tasks[i].state = pal_scan_probe_working;
            // Update address to add port
            if (__sa_is_in6(&scan->tasks[i].to))
            {
                __sa_as_in6(&scan->tasks[i].to)->sin6_port = swap_16(scan->port);
                log_debug(scan->log, "Connect on " __sa_in6_fmt " to " __sa_in6_fmt,
                    __sa_in6_args(from), __sa_in6_args(to));
            }
            else
            {
                dbg_assert(__sa_is_in4(&scan->tasks[i].to), "af wrong");
                __sa_as_in4(to)->sin_port = swap_16(scan->port);
                log_debug(scan->log, "Connect on " __sa_in4_fmt " to " __sa_in4_fmt,
                    __sa_in4_args(from), __sa_in4_args(to));
            }

            // Connect to port
            result = er_fault;
            // result = pal_socket_create_bind_and_connect_async(__sa_base(to)->sa_family,
           //     __sa_base(from), __sa_size(from), __sa_base(to), __sa_size(to), 
           //     &scan->tasks[i].sock_fd);
            if (result != er_ok)
            {
                // Failed to connect, continue;
                log_trace(scan->log, "Failed to call connect (%s)",
                    prx_err_string(result));
                pal_scan_probe_complete(&scan->tasks[i]);
                continue;
            }

            // Schedule timeout of this task
           // __do_later_s(scan->scheduler, pal_scan_probe_timeout,
           //     &scan->tasks[i], PROBE_TIMEOUT);
        }
        else
        {
            if (__sa_is_in6(&scan->tasks[i].to))
            {
                continue;
            }

            dbg_assert(__sa_is_in4(&scan->tasks[i].to), "af wrong");
            
            // TODO
            //scan->tasks[i].state = pal_scan_probe_working;
            //if (!QueueUserWorkItem(pal_scan_probe_with_arp, &scan->tasks[i], 0))
            //{
            //    result = pal_os_last_error_as_prx_error();
            //    log_error(scan->log, "Failed to queue arp request (%s)",
            //        prx_err_string(result));
            //
            //    result = er_ok;
            //    continue;
            //}
        }
    }
}

//
// Free scan - once created is called on scheduler thread.
//
static void pal_scan_free(
    pal_scan_t* scan
)
{
    dbg_assert_ptr(scan);
    scan->destroy = true;

    for (size_t i = 0; i < _countof(scan->tasks); i++)
    {
        if (scan->tasks[i].state == pal_scan_probe_idle)
            continue;

        //
        // Cannot cancel threadpool task.  Wait for arp
        // to complete then come back...
        //
        if (scan->tasks[i].sock_fd == -1)
            return;

        pal_scan_probe_cancel(&scan->tasks[i]);
    }

    // All tasks are idle, now we can free...

    if (scan->ifaddr)
        freeifaddrs(scan->ifaddr);

    log_trace(scan->log, "Scan %p destroy.", scan);
    mem_free_type(pal_scan_t, scan);
}

//
// Schedule next set of probe task for tasks that have completed
//
static void pal_scan_next(
    pal_scan_t* scan
)
{
    dbg_assert_ptr(scan);

   // if (scan->destroy)
   // {
   //     // If scan is destroy, continue here by freeing it.
   //     pal_scan_free(scan);
   //     return;
   // }

    if (scan->address.sin6_family == AF_UNSPEC)
        pal_scan_next_address(scan);
    else
        pal_scan_next_port(scan);
}

//
// Create scan context
//
static int32_t pal_scan_create(
    int32_t flags,
    pal_scan_cb_t cb,
    void* context,
    pal_scan_t** created
)
{
  //  int32_t result;
    pal_scan_t* scan;

    chk_arg_fault_return(cb);

    scan = (pal_scan_t*)mem_zalloc_type(pal_scan_t);
    if (!scan)
        return er_out_of_memory;
  //  do
  //  {
        // Initialize scan
        scan->log = log_get("pal.scan");
        scan->flags = flags;
        scan->cb = cb;
        scan->context = context;

        for (size_t i = 0; i < _countof(scan->tasks); i++)
        {
            scan->tasks[i].state = pal_scan_probe_idle;
            scan->tasks[i].sock_fd = -1;
            scan->tasks[i].scan = scan;
        }

        *created = scan;
        return er_ok;
  //  } while (0);
  //
  //  pal_scan_free(scan);
  //  return result;
}

//
// Scan for addresses with open port in subnet
//
int32_t pal_scan_net(
    int32_t flags,
    uint16_t port,
    pal_scan_cb_t cb,
    void* context,
    pal_scan_t** created
)
{
    int32_t result;
    int error;
    pal_scan_t* scan;

    chk_arg_fault_return(cb);

    result = pal_scan_create(flags, cb, context, &scan);
    if (result != er_ok)
        return result;
    do
    {
        scan->port = port;
        // a) Get interface info
        error = getifaddrs(&scan->ifaddr);
        if (error != 0)
        {
            result = pal_os_to_prx_error(error);
            log_error(scan->log, "Failed to get adapter infos (%x, %s).",
                error, prx_err_string(result));
            break;
        }

        // b) Start neighbor table scan for ipv6 addresses

        // Todo.


        // Start scan
        pal_scan_next(scan);
        *created = scan;
        return er_ok;
    }
    while (0);

    pal_scan_free(scan);
    return result;
}

//
// Scan for ports on address
//
int32_t pal_scan_ports(
    const prx_socket_address_t* addr,
    uint16_t port_range_low,
    uint16_t port_range_high,
    int32_t flags,
    pal_scan_cb_t cb,
    void* context,
    pal_scan_t** created
)
{
    int32_t result;
    pal_scan_t* scan;
    socklen_t sa_len;

    chk_arg_fault_return(addr);
    chk_arg_fault_return(cb);

    if (!port_range_low)
        port_range_low = 1;
    if (!port_range_high)
        port_range_high = (uint16_t)-1;
    if (port_range_high <= port_range_low)
        return er_arg;

    result = pal_scan_create(flags, cb, context, &scan);
    if (result != er_ok)
        return result;
    do
    {
        scan->ip_scan_cur = port_range_low;
        scan->ip_scan_end = port_range_high;
        scan->ip_scan_end++;

        sa_len = sizeof(struct sockaddr_in6);
        result = pal_os_from_prx_socket_address(addr,
            (struct sockaddr*)&scan->address, &sa_len);
        if (result != er_ok)
            break;

        // Start scan
        pal_scan_next(scan);
        *created = scan;
        return er_ok;
    } while (0);

    pal_scan_free(scan);
    return result;
}

//
// Abort and close in progress scan
//
void pal_scan_close(
    pal_scan_t* scan
)
{
    // Detach callback
    scan->cb = pal_scan_dummy_cb;
    scan->destroy = true; 
//    pal_scan_abort(scan);
}

//
// Called before using scan layer
//
int32_t pal_scan_init(
    void
)
{
    int32_t result;

    result = pal_event_port_create(NULL, NULL, &event_port);
    if (result != er_ok)
    {
        log_error(NULL, "FATAL: Failed creating event port.");
    }

    return result;
}

//
// Free networking layer
//
void pal_scan_deinit(
    void
)
{
    if (event_port)
        pal_event_port_close(event_port);
    event_port = 0;
}
