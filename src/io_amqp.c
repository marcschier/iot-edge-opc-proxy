// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "util_mem.h"
#include "io_amqp.h"
#include "xio_socket.h"
#include "util_string.h"
#include "util_misc.h"

#include "azure_c_shared_utility/doublylinkedlist.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/wsio.h"
#include "azure_c_shared_utility/tlsio.h"

#include "azure_uamqp_c/cbs.h"
#include "azure_uamqp_c/link.h"
#include "azure_uamqp_c/message.h"
#include "azure_uamqp_c/message_receiver.h"
#include "azure_uamqp_c/message_sender.h"
#include "azure_uamqp_c/messaging.h"
#include "azure_uamqp_c/sasl_anonymous.h"
#include "azure_uamqp_c/sasl_plain.h"
#include "azure_uamqp_c/sasl_mssbcbs.h"
#include "azure_uamqp_c/saslclientio.h"

#include <limits.h>

// #define LOG_AMQP

#ifndef LLONG_MAX
#define LLONG_MAX LONG_LONG_MAX
#endif


typedef enum io_amqp_claim_status
{
    io_amqp_claim_status_pending,
    io_amqp_claim_status_claimed,
    io_amqp_claim_status_error
}
io_amqp_claim_status_t;

//
// Represents a token based claim on a remote resource
//
typedef struct io_amqp_claim
{
    io_token_provider_t* token_provider;
    uint64_t expiry;                                // Expiration of claim
    io_amqp_claim_status_t status;
    io_amqp_connection_t* connection;
    io_scheduler_t* scheduler;
    DLIST_ENTRY link;                     // Links into the list of claims
    DLIST_ENTRY qlink;                     // Links into the renewal queue
}
io_amqp_claim_t;

typedef enum io_amqp_connection_status
{
    io_amqp_connection_status_unknown = 0,
    io_amqp_connection_status_open,
    io_amqp_connection_status_reset,
    io_amqp_connection_status_closing,
    io_amqp_connection_status_closed
}
io_amqp_connection_status_t;

//
// Connection
//
struct io_amqp_connection
{
    io_url_t* address;
    bool is_websocket;
    io_amqp_connection_auth_t auth_type;

    XIO_HANDLE socket_io;                                  // The io layer
    XIO_HANDLE sasl_io; 

    CONNECTION_HANDLE connection;
    SESSION_HANDLE session;
    io_scheduler_t* scheduler;

    SASL_MECHANISM_HANDLE sasl_mechanism;
    AMQP_MANAGEMENT_STATE state;
    CBS_HANDLE cbs;

    DLIST_ENTRY claims;                                  // List of claims 
    DLIST_ENTRY renewals;                       // List of claims to renew
    DLIST_ENTRY endpoints;                         // Links in the session
    
    io_amqp_connection_status_t status;
    uint64_t last_success;                    // Last successful connected
    int32_t back_off_in_seconds;       // Delay until next connect attempt
    log_t log;
};

//
// Link state
//
typedef enum io_amqp_link_state
{
    io_amqp_link_state_unknown = 0,
    io_amqp_link_state_disconnected,      // link-detach response received
    io_amqp_link_state_connecting,              // Link open (link-attach)
    io_amqp_link_state_connected,                           // link-attach 
    io_amqp_link_state_disconnecting,     // Sent detach, wait, disconnect
    io_amqp_link_state_error,        // error state - back to disconnected
    io_amqp_link_state_destroyed
}
io_amqp_link_state_t;

//
// Amqp properties implementation, wraps a map value
//
struct io_amqp_properties
{
    AMQP_VALUE app;         // Map value containing application properties
    PROPERTIES_HANDLE props;         // System properties for this message
    log_t log;
};

//
// Amqp message to send
//
typedef struct io_amqp_link_message
{
    MESSAGE_HANDLE msg_handle;
    size_t buf_len;
    io_amqp_link_t* link;
    DLIST_ENTRY qlink;            
}
io_amqp_link_message_t;

//
// Represents a link to a broker endpoint on a connection
//
struct io_amqp_link
{
    STRING_HANDLE link_name;                           // Name of the link

    MESSAGE_SENDER_HANDLE sender;  // Sender link observes one or more ...
    DLIST_ENTRY send_queue;                       // Send queue (messages)
    io_amqp_link_message_t* cur;                        // Current message
    STRING_HANDLE route_address;       // Routing address for all messages
            // - or -
    MESSAGE_RECEIVER_HANDLE receiver;
    io_amqp_link_receiver_t receiver_cb;
    void* receiver_ctx;

    STRING_HANDLE link_target;
    STRING_HANDLE link_source;
    bool filter_receives;
    io_amqp_properties_t* properties;                 // attach properties
    io_amqp_link_state_t status;
    size_t message_size;
    LINK_HANDLE handle;

    io_amqp_connection_t* connection;
    io_scheduler_t* scheduler;
    DLIST_ENTRY link;
    log_t log;
};

//
// Clear back_off timer 
//
static void io_amqp_connection_clear_failures(
    io_amqp_connection_t* connection
)
{
    connection->last_success = ticks_get();
    connection->back_off_in_seconds = 0;
}

//
// Connect all unconnected layers
//
static void io_amqp_connection_reset(
    io_amqp_connection_t* connection
);

//
// Encode property value
// 
static int32_t io_amqp_properties_encode_value(
    io_amqp_property_type_t type,
    const void* buffer,
    AMQP_VALUE* amqp_value
)
{

    switch (type)
    {
    case io_amqp_property_type_string:
        *amqp_value = amqpvalue_create_string((const char*)buffer);
        break;
    case io_amqp_property_type_int32:
        *amqp_value = amqpvalue_create_int(*(const int*)buffer);
        break;
    case io_amqp_property_type_uuid:
        *amqp_value = amqpvalue_create_uuid((unsigned char*)buffer);
        break;
    default:
        dbg_assert(0, "Bad type %d passed.", type);
        return er_not_supported;
    }
    return *amqp_value ? er_ok : er_out_of_memory;
}

//
// Decode property value
// 
static int32_t io_amqp_properties_decode_value(
    AMQP_VALUE amqp_value,
    io_amqp_property_type_t type,
    void* buffer
)
{
    const char* name;
    switch (type)
    {
    case io_amqp_property_type_string:
        if (0 != amqpvalue_get_string(amqp_value, &name))
            return er_invalid_format;
        if (0 != STRING_concat((STRING_HANDLE)buffer, name))
            return er_out_of_memory;
        break;
    case io_amqp_property_type_int32:
        if (0 != amqpvalue_get_int(amqp_value, (int32_t*)buffer))
            return er_invalid_format;
        break;
    case io_amqp_property_type_uuid:
        if (0 != amqpvalue_get_uuid(amqp_value, (uuid*)&buffer))
            return er_invalid_format;
        break;
    default:
        dbg_assert(0, "Bad type %d passed.", type);
        return er_not_supported;
    }
    return er_ok;
}

//
// Create properties bag
//
int32_t io_amqp_properties_create(
    io_amqp_properties_t** created
)
{
    int32_t result;
    io_amqp_properties_t* properties;

    properties = mem_zalloc_type(io_amqp_properties_t);
    if (!properties)
        return er_out_of_memory;
    do
    {
        properties->log = log_get("amqp.properties");

        properties->app = amqpvalue_create_map();
        if (!properties->app)
        {
            result = er_out_of_memory;
            break;
        }

        properties->props = properties_create();
        if (!properties->props)
        {
            result = er_out_of_memory;
            break;
        }

        *created = properties;
        return er_ok;

    } while (0);

    io_amqp_properties_free(properties);
    return result;
}

//
// Free properties bag
//
void io_amqp_properties_free(
    io_amqp_properties_t* properties
)
{
    dbg_assert_ptr(properties);
    if (properties->app)
        amqpvalue_destroy(properties->app);
    if (properties->props)
        properties_destroy(properties->props);
    mem_free_type(io_amqp_properties_t, properties);
}

//
// Add properties
//
int32_t io_amqp_properties_add(
    io_amqp_properties_t* properties,
    const char* key,
    io_amqp_property_type_t type,
    const void* buffer
)
{
    int32_t result;
    AMQP_VALUE amqp_key = NULL;
    AMQP_VALUE amqp_value = NULL;

    result = io_amqp_properties_encode_value(type, buffer, &amqp_value);
    if (result != er_ok)
        return result;

    amqp_key = amqpvalue_create_symbol(key);
    if (!amqp_key || 0 != amqpvalue_set_map_value(
        properties->app, amqp_key, amqp_value))
        result = er_out_of_memory;
    else
        result = er_ok;

    if (amqp_key)
        amqpvalue_destroy(amqp_key);
    if (amqp_value)
        amqpvalue_destroy(amqp_value);

    return result;
}

//
// Get a property from a property bag
//
int32_t io_amqp_properties_get(
    io_amqp_properties_t* properties,
    const char* key,
    io_amqp_property_type_t type,
    void* buffer
)
{
    int32_t result;
    AMQP_VALUE amqp_key = NULL;
    AMQP_VALUE amqp_value = NULL;
    AMQP_VALUE map;
    uint32_t count;
    const char* name;

    if (!properties || !key)
        return er_fault;

    map = amqpvalue_get_inplace_described_value(properties->app);
    dbg_assert_ptr(map);
    result = amqpvalue_get_map_pair_count(map, &count);
    if (result != 0)
    {
        log_error(properties->log, 
            "Failure accessing properties count value.");
        return er_invalid_format;
    }

    // Look for value
    result = er_not_found;
    for (uint32_t index = 0; index < count; index++)
    {
        if (0 != amqpvalue_get_map_key_value_pair(map, index,
            &amqp_key, &amqp_value))
        {
            log_error(properties->log,
                "Failure accessing key value pair at index %d.", index);
            result = er_prop_get;
            break;
        }

        if(0 != amqpvalue_get_string(amqp_key, &name))
        {
            log_error(properties->log,
                "Failure accessing key value pair at index %d.", index);
            result = er_prop_get;
            break;
        }

        if (0 == string_compare_nocase(name, key))
        {
            // Found it!
            result = io_amqp_properties_decode_value(amqp_value, type, buffer);
            break;
        }

        amqpvalue_destroy(amqp_key);
        amqp_key = NULL;
        amqpvalue_destroy(amqp_value);
        amqp_value = NULL;
    }

    if (result != er_ok)
    {
        log_error(properties->log, 
            "Failed to get property %s from message (%s)",
            key, pi_error_string(result));
    }
    
    if (amqp_key)
        amqpvalue_destroy(amqp_key);
    if (amqp_value)
        amqpvalue_destroy(amqp_value);

    return result;
}

//
// Set correlation id property from property bag
//
int32_t io_amqp_properties_set_correlation_id(
    io_amqp_properties_t* properties,
    io_amqp_property_type_t type,
    const void* buffer
)
{
    int32_t result;
    AMQP_VALUE amqp_value = NULL;

    result = io_amqp_properties_encode_value(type, buffer, &amqp_value);
    if (result != er_ok)
        return result;

    if (0 != properties_set_correlation_id(properties->props, amqp_value))
        result = er_out_of_memory;
    else
        result = er_ok;
    amqpvalue_destroy(amqp_value);
    return result;
}

//
// Get correlation id property from property bag
//
int32_t io_amqp_properties_get_correlation_id(
    io_amqp_properties_t* properties,
    io_amqp_property_type_t type,
    void* buffer
)
{
    AMQP_VALUE amqp_value = NULL;
    if (0 != properties_get_correlation_id(properties->props, &amqp_value))
        return er_not_found;
    return io_amqp_properties_decode_value(amqp_value, type, buffer);
}

//
// Free message
//
static void io_amqp_link_message_free(
    io_amqp_link_message_t* message
)
{
    dbg_assert_ptr(message);

    if (message->msg_handle)
        message_destroy(message->msg_handle);

    mem_free_type(io_amqp_link_message_t, message);
}

//
// Create message for sending
//
static int32_t io_amqp_link_message_create(
    io_amqp_link_t* link,
    io_amqp_properties_t* header,
    const char* buffer,
    size_t buf_len,
    io_amqp_link_message_t** created
)
{
    int32_t result;
    io_amqp_link_message_t* message;
    AMQP_VALUE amqpvalue = NULL;
    BINARY_DATA binary;

    message = mem_zalloc_type(io_amqp_link_message_t);
    if (!message)
        return er_out_of_memory;
    do
    {
        message->link = link;
        message->msg_handle = message_create();
        if (!message->msg_handle)
        {
            log_error(link->log, "Sending message failed due to out of memory");
            result = er_out_of_memory;
            break;
        }

        if (link->route_address)
        {
            amqpvalue_destroy(amqpvalue);
            amqpvalue = amqpvalue_create_string(
                STRING_c_str(link->route_address));
            if (0 != properties_set_to(header->props, amqpvalue))
            {
                log_error(link->log, "Unable to set route address.");
                result = er_prop_set;
                break;
            }
        }

        if (0 != properties_set_absolute_expiry_time(header->props, LLONG_MAX / 2))
        {
            log_error(link->log,
                "Unable to set content type or message expiry time.");
            result = er_prop_set;
            break;
        }

        if (0 != message_set_properties(message->msg_handle, header->props))
        {
            log_error(link->log, "Unable to set system properties.");
            result = er_prop_set;
            break;
        }

        if (0 != message_set_application_properties(
            message->msg_handle, header->app))
        {
            log_error(link->log, "Unable to set application properties.");
            result = er_prop_set;
            break;
        }

        binary.bytes = (const unsigned char*)buffer;
        binary.length = buf_len;

        if (0 != message_add_body_amqp_data(message->msg_handle, binary))
        {
            log_error(link->log, "Unable to set message body.");
            result = er_prop_set;
            break;
        }

        amqpvalue_destroy(amqpvalue);
        *created = message;
        return er_ok;

    } while (0);

    if (amqpvalue)
        amqpvalue_destroy(amqpvalue);
    io_amqp_link_message_free(message);
    return result;
}

//
// Send a message on the link if one is available
//
static void io_amqp_link_send_message(
    io_amqp_link_t* link
);

//
// Message send callback, complete the payload and pump more messages
//
static void io_amqp_link_message_send_complete(
    void* context,
    MESSAGE_SEND_RESULT send_result
)
{
    io_amqp_link_message_t* message;
    io_amqp_link_t* link;

    message = (io_amqp_link_message_t*)context;
    dbg_assert_ptr(message);
    link = message->link;
    dbg_assert_ptr(link);

    if (send_result == MESSAGE_SEND_OK)
    {
        log_info(link->log, "SENT [size: %08d]", message->buf_len);

        // Clear all failures from connection
        io_amqp_connection_clear_failures(link->connection);

        // Remove and pick next to send
        DList_RemoveEntryList(&message->qlink);
        io_amqp_link_message_free(message);

        __do_next(link, io_amqp_link_send_message);
    }
    else
    {
        log_error(link->log, "ERROR sending [size: %08d]", message->buf_len);
        __do_next(link->connection, io_amqp_connection_reset);
    }
}

// 
// Message receive callback
//
static AMQP_VALUE io_amqp_link_message_receive_complete(
    const void* context,
    MESSAGE_HANDLE msg_handle
)
{
    int32_t result;
    AMQP_VALUE amqpvalue = NULL;
    PROPERTIES_HANDLE amqpproperties = NULL;
    MESSAGE_BODY_TYPE body_type;
    BINARY_DATA binary;
    io_amqp_properties_t header;
    io_amqp_link_t* link = (io_amqp_link_t*)context;

    dbg_assert_ptr(link);
    dbg_assert_ptr(msg_handle);

	dbg_assert(link->status == io_amqp_link_state_connected, "%x state while receiving",
        link->status);
    do
    {
        result = message_get_body_type(msg_handle, &body_type);
        if (result != 0 || body_type != MESSAGE_BODY_TYPE_DATA)
        {
            result = er_invalid_format;
            log_error(link->log, "Failed to get the message's body type");
            break;
        }

        result = message_get_application_properties(msg_handle, &amqpvalue);
        if (result != 0)
        {
            result = er_prop_get;
            break;
        }

        result = message_get_properties(msg_handle, &amqpproperties);
        if (result != 0)
        {
            result = er_prop_get;
            break;
        }

        header.props = amqpproperties;
        header.app = amqpvalue;
        header.log = link->log;

        // Get body of message
        result = message_get_body_amqp_data(msg_handle, 0, &binary);
        if (result != 0)
        {
            result = er_prop_get;
            log_error(link->log, "Failed to get the message's body");
            break;
        }

        log_info(link->log, "RECV [size: %08d]", binary.length);
        // Do callback
        result = link->receiver_cb(link->receiver_ctx, &header,
            (const char*)binary.bytes, binary.length);
        if (result != er_ok)
            break;

        properties_destroy(amqpproperties);
        amqpvalue_destroy(amqpvalue);

        io_amqp_connection_clear_failures(link->connection);
        return messaging_delivery_accepted();
    } 
    while (0);

    if (amqpvalue)
        amqpvalue_destroy(amqpvalue);
    if (amqpproperties)
        properties_destroy(amqpproperties);

    return messaging_delivery_rejected("amqp:decode-error", pi_error_string(result));
}

//
// Send a message on the link if one is available
//
static void io_amqp_link_send_message(
    io_amqp_link_t* link
)
{
    io_amqp_link_message_t* message;
    if (DList_IsListEmpty(&link->send_queue))
        return;
    message = containingRecord(
        link->send_queue.Flink, io_amqp_link_message_t, qlink);
    dbg_assert_ptr(message);

    if (0 != messagesender_send(link->sender, message->msg_handle, 
        io_amqp_link_message_send_complete, message))
    {
        log_error(link->log, "Failure sending messages payload, reset...");
        __do_next(link->connection, io_amqp_connection_reset);
    }
}

//
// Returns the status of the link
//
static void io_amqp_link_set_status(
    io_amqp_link_t* link,
    io_amqp_link_state_t status
)
{
    dbg_assert_ptr(link);
    if (status == link->status)
        return;
    link->status = status;
}

//
// Complete disconnecting
//
static void io_amqp_link_complete_disconnect(
    io_amqp_link_t* link
)
{
    dbg_assert_ptr(link);
    if (link->status == io_amqp_link_state_disconnected)
        return; // Happens if error encounted on begin
    dbg_assert(link->status == io_amqp_link_state_disconnecting, "Bad state");

    //
    // Destroy link handle
    //
    if (link->handle)
        link_destroy(link->handle);

    //
    // Clean up sender or receiver, which is now safe to do.
    //
    if (link->sender)
        messagesender_destroy(link->sender);
    if (link->receiver)
        messagereceiver_destroy(link->receiver);

    link->handle = NULL;
    link->receiver = NULL;
    link->sender = NULL;

    io_amqp_link_set_status(link, io_amqp_link_state_disconnected);
    log_info(link->log, "Link %p disconnected!", link);

   ///  __do_next(link->connection, io_amqp_connection_reconnect_endpoints);
}

//
// Disconnect a link
//
static void io_amqp_link_begin_disconnect(
    io_amqp_link_t* link
)
{
    dbg_assert_ptr(link);

    io_amqp_link_set_status(link, io_amqp_link_state_disconnecting);

    //
    // Close sender or receiver - causes link_detach to be sent
    //
    if (link->sender)
        messagesender_close(link->sender);
    if (link->receiver)
        messagereceiver_close(link->receiver);

    // Wait for idle or error status callback, then reset
}

//
// Connect any links that are disconnected
//
static void io_amqp_connection_reconnect_endpoints(
    io_amqp_connection_t* connection
);

//
// Complete connecting
//
static void io_amqp_link_complete_connect(
    io_amqp_link_t* link
)
{
    dbg_assert_ptr(link);
    dbg_assert(link->status == io_amqp_link_state_connecting, "Bad state");
    
    io_amqp_link_set_status(link, io_amqp_link_state_connected);

    log_debug(link->log, "Link %p connected!", link);

    // Check all other endpoints
    __do_next(link->connection, io_amqp_connection_reconnect_endpoints);
}

//
// Process error condition on link
//
static void io_amqp_link_handle_error(
    io_amqp_link_t* link
)
{
    io_amqp_link_state_t status = link->status;
    io_amqp_link_set_status(link, io_amqp_link_state_error);

    log_error(link->log, "Link %p in error state, reset connection...",
        link);
    switch (status)
    {
    case io_amqp_link_state_connecting:
        // Not connected, so close and destroy link
        __do_next(link, io_amqp_link_begin_disconnect);
        break;
    case io_amqp_link_state_connected:
        // Initiated detach
        __do_next(link, io_amqp_link_begin_disconnect);
        break;
    case io_amqp_link_state_disconnecting:
        // Complete disconnect
        __do_next(link, io_amqp_link_complete_disconnect);
        break;
    case io_amqp_link_state_error:
        // Complete disconnect
        io_amqp_link_begin_disconnect(link);
        __do_next(link, io_amqp_link_complete_disconnect);
    case io_amqp_link_state_disconnected:
        break;
    default:
        dbg_assert(0, "Unexpected error in state %d.", status);
        break;
    }
}

//
// Receiver state callback
//
static void io_amqp_link_receiver_state_callback(
    const void* context,
    MESSAGE_RECEIVER_STATE new_state,
    MESSAGE_RECEIVER_STATE previous_state
)
{
    io_amqp_link_t* link;
    if (!context)
        return;
    link = (io_amqp_link_t*)context;

    log_debug(link->log, "Receiver link state changed from %d to %d",
        previous_state, new_state);

    (void)previous_state;
    switch (new_state)
    {
    case MESSAGE_RECEIVER_STATE_CLOSING:
        // disconnect was initiated by calling messagereceiver_close
        dbg_assert(link->status == io_amqp_link_state_disconnecting,
            "Closing but not disconnecting");
        break;
    case MESSAGE_RECEIVER_STATE_IDLE:
        // Link detached, complete disconnect
        if (link->status == io_amqp_link_state_connected)
        {
            log_info(link->log, 
                "Remote sender detached, disconnect local receiver link %p",
                link);
            io_amqp_link_begin_disconnect(link);
        }
        __do_next(link, io_amqp_link_complete_disconnect);
        break;
    case MESSAGE_RECEIVER_STATE_OPENING:
        // Connect was initiated by calling messagereceiver_open
        dbg_assert(link->status == io_amqp_link_state_connecting,
            "Opening but not connecting");
        break;
    case MESSAGE_RECEIVER_STATE_OPEN:
        // Link attached, complete connect
        __do_next(link, io_amqp_link_complete_connect);
        break;
    default:
        dbg_assert(0, "Unexpected receiver state received %d.", new_state);
    case MESSAGE_RECEIVER_STATE_ERROR:
        io_amqp_link_handle_error(link);
        break;
    }
}

//
// Sender state callback
//
static void io_amqp_link_sender_state_callback(
    void* context,
    MESSAGE_SENDER_STATE new_state,
    MESSAGE_SENDER_STATE previous_state
)
{
    io_amqp_link_t* link;
    if (!context)
        return;
    link = (io_amqp_link_t*)context;

    log_debug(link->log, "Sender link state changed from %d to %d",
        previous_state, new_state);

    (void)previous_state;
    switch (new_state)
    {
    case MESSAGE_SENDER_STATE_CLOSING:
        dbg_assert(link->status == io_amqp_link_state_disconnecting,
            "Closing but not disconnecting");
        break;
    case MESSAGE_SENDER_STATE_IDLE:
        // Link detached, now complete disconnect
        if (link->status == io_amqp_link_state_connected)
        {
            log_info(link->log, 
                "Remote receiver detached, disconnect local sender link %p", 
                link);
            io_amqp_link_begin_disconnect(link);
        }
        __do_next(link, io_amqp_link_complete_disconnect);
        break;
    case MESSAGE_SENDER_STATE_OPENING:
        dbg_assert(link->status == io_amqp_link_state_connecting,
            "Opening but not connecting");
        break;
    case MESSAGE_SENDER_STATE_OPEN:
        // Link attached, complete connect
        __do_next(link, io_amqp_link_complete_connect);
        break;
    default:
        dbg_assert(0, "Unexpected sender state received %d.", new_state);
    case MESSAGE_SENDER_STATE_ERROR:
        io_amqp_link_handle_error(link);
        break;
    }
}

//
// Create target
//
static AMQP_VALUE io_amqp_link_create_target(
    io_amqp_link_t* link
)
{
    return messaging_create_target(STRING_c_str(link->link_target));
}

//
// Create source, if needed with filter
//
static AMQP_VALUE io_amqp_link_create_source(
    io_amqp_link_t* link
)
{
#define FILTER_SYMBOL "apache.org:selector-filter:string"
    time_t now;
    char temp_buffer[256];
    filter_set filter_set = NULL;
    SOURCE_HANDLE source_handle = NULL;
    AMQP_VALUE key = NULL, value = NULL, result = NULL, filter = NULL;
    if (!link->filter_receives)
        return messaging_create_source(STRING_c_str(link->link_source));
    do
    {
        now = get_time(NULL);
        now = mktime(get_gmtime(&now));
        now -= 330;

        sprintf(temp_buffer,
            "amqp.annotation.x-opt-enqueuedtimeutc > %llu",
            ((unsigned long long)now) * 10000000);

        key = amqpvalue_create_symbol(FILTER_SYMBOL);
        if (!key)
            break;
        value = amqpvalue_create_string(temp_buffer);
        if (!value)
            break;
        filter = amqpvalue_create_described(key, value);
        if (!filter)
            break;

        // Peculiar, create_described does not clone.
        value = NULL;
        key = NULL;

        key = amqpvalue_create_symbol(FILTER_SYMBOL);
        if (!key)
            break;
        filter_set = amqpvalue_create_map();
        if (!filter_set)
            break;
        if (0 != amqpvalue_set_map_value(filter_set, key, filter))
            break;

        source_handle = source_create();
        if (!source_handle)
            break;

        value = amqpvalue_create_string(STRING_c_str(link->link_source));
        if (!value)
            break;
        if (0 != source_set_address(source_handle, value) ||
            0 != source_set_filter(source_handle, filter_set))
            break;

        result = amqpvalue_create_source(source_handle);
        break;
    } while (0);

    if (filter)
        amqpvalue_destroy(filter);
    if (key)
        amqpvalue_destroy(key);
    if (value)
        amqpvalue_destroy(value);
    if (filter_set)
        amqpvalue_destroy(filter_set);
    if (source_handle)
        source_destroy(source_handle);

    return result;
}

//
// Connect a link
//
static int32_t io_amqp_link_begin_connect(
    io_amqp_link_t* link
)
{
    int32_t result;
    AMQP_VALUE source = NULL;
    AMQP_VALUE target = NULL;

    dbg_assert(!link->handle, "Not disconnected");
    dbg_assert(link->status == io_amqp_link_state_disconnected, "Bad state");

    log_debug(link->log, "Connecting link %p...", link);
    do
    {
        io_amqp_link_set_status(link, io_amqp_link_state_connecting);

        source = io_amqp_link_create_source(link);
        target = io_amqp_link_create_target(link);
        if (!source || !target)
        {
            result = er_out_of_memory;
            break;
        }

        link->handle = link_create(
            link->connection->session,
            STRING_c_str(link->link_name),
            !!link->receiver_cb ? role_receiver : role_sender,
            source, target);

        if (!link->handle ||
            0 != link_set_max_message_size(
                link->handle, link->message_size) ||
            0 != link_set_rcv_settle_mode(
                link->handle, receiver_settle_mode_first))
        {
            result = er_connecting;
            break;
        }

        if (link->properties && 0 != link_set_attach_properties(
            link->handle, link->properties->app))
        {
            result = er_out_of_memory;
            break;
        }

        if (link->receiver_cb)
        {
            link->receiver = messagereceiver_create(
                link->handle, io_amqp_link_receiver_state_callback, link);
            if (!link->receiver)
            {
                result = er_out_of_memory;
                break;
            }

            // Start attach
            if (0 != messagereceiver_open(
                link->receiver, io_amqp_link_message_receive_complete, link))
            {
                result = er_connecting;
                break;
            }
        }
        else
        {
            link->sender = messagesender_create(
                link->handle, io_amqp_link_sender_state_callback, link);
            if (!link->sender)
            {
                result = er_out_of_memory;
                break;
            }

            // Start attach
            if (0 != messagesender_open(link->sender))
            {
                result = er_connecting;
                break;
            }
        }
        result = er_ok;
        break;

    } while (0);

    if (source)
        amqpvalue_destroy(source);
    if (target)
        amqpvalue_destroy(target);
    if (result != er_ok)
    {
        log_error(link->log, "Connecting link %p failed! (%s)", link, 
            pi_error_string(result));
        io_amqp_link_handle_error(link);
    }
    return result;
}

//
// Free the link
//
static void io_amqp_link_free(
    io_amqp_link_t* link
)
{
    if (!link)
        return;

    dbg_assert(link->status == io_amqp_link_state_disconnected);

    if (link->scheduler)
        io_scheduler_clear(link->scheduler, link);

    if (link->link_name)
        STRING_delete(link->link_name);
    if (link->link_target)
        STRING_delete(link->link_target);
    if (link->link_source)
        STRING_delete(link->link_source);
    if (link->route_address)
        STRING_delete(link->route_address);
    if (link->properties)
        io_amqp_properties_free(link->properties);



   // TODO if (link->send_queue)
   // TODO     io_queue_free(link->send_queue);

    io_amqp_link_set_status(link, io_amqp_link_state_destroyed);
    log_info(link->log, "Link %p destroyed.", link);

    mem_free_type(io_amqp_link_t, link);
}

//
// Connection state change callback
//
static void io_amqp_connection_state_change_callback(
    void* context,
    CONNECTION_STATE new_connection_state,
    CONNECTION_STATE previous_connection_state
)
{
    io_amqp_connection_t* connection = (io_amqp_connection_t*)context;
    dbg_assert_ptr(connection);
	(void)previous_connection_state;

    if (new_connection_state == CONNECTION_STATE_END && connection->session)
    {
        log_info(connection->log, "Connection ending, reconnecting...");
        __do_next(connection, io_amqp_connection_reset);
    }
}

//
// Connection io error callback
//
static void io_amqp_connection_io_error_callback(
    void* context
)
{
    io_amqp_connection_t* connection = (io_amqp_connection_t*)context;
    dbg_assert_ptr(connection);

    log_error(connection->log, "Connection IO Error occurred, reset.");
    __do_next(connection, io_amqp_connection_reset);
}

//
// Cbs State change callback
//
static void io_amqp_connection_management_callback(
    void* context,
    AMQP_MANAGEMENT_STATE new_state,
    AMQP_MANAGEMENT_STATE previous_state
)
{
    io_amqp_connection_t* connection;
    if (!context)
        return;
    connection = (io_amqp_connection_t*)context;

    log_debug(connection->log, "Connection state changed from %d to %d",
        previous_state, new_state);

    (void)previous_state;
    connection->state = new_state;
}

//
// Create a link
//
int32_t io_amqp_connection_create_link(
    io_amqp_connection_t* connection,
    const char* source,
    const char* target,
    size_t message_size,
    io_amqp_link_receiver_t cb,
    void* context,
    bool filter_receives,
    io_amqp_link_t** created
)
{
    int32_t result = er_out_of_memory;
    io_amqp_link_t* link;

    if (!connection || !created)
        return er_fault;
    if (!target && !source)
        return er_arg;

    link = mem_zalloc_type(io_amqp_link_t);
    if (!link)
        return er_out_of_memory;
    do
    {
        link->log = log_get("amqp.link");
        DList_InitializeListHead(&link->link);

        link->message_size = message_size;
        link->filter_receives = filter_receives;
        link->connection = connection;
        link->scheduler = connection->scheduler;
        link->receiver_cb = cb;
        link->receiver_ctx = context;

        result = io_amqp_properties_create(&link->properties);
        if (result != er_ok)
            break;

        if (source)
            link->link_source = STRING_construct(source);
        else
            link->link_source = STRING_construct_random(8);
        if (target)
            link->link_target = STRING_construct(target);
        else
            link->link_target = STRING_construct_random(8);

        link->link_name = STRING_construct_random(12);

        if (!link->link_source || 
            !link->link_target ||
            !link->link_name)
        {
            result = er_out_of_memory;
            break;
        }

        io_amqp_link_set_status(link, io_amqp_link_state_disconnected);
        DList_InsertTailList(&connection->endpoints, &link->link);

        if (connection->status == io_amqp_connection_status_open)
            __do_next(connection, io_amqp_connection_reconnect_endpoints);

        *created = link;
        return er_ok;
    } while (0);

    io_amqp_link_free(link);
    return result;
}

//
// Attach Properties for the link
//
io_amqp_properties_t* io_amqp_link_properties(
    io_amqp_link_t* link
)
{
    if (!link)
        return NULL;
    return link->properties;
}

//
// Set default route address for the link
//
int32_t io_amqp_link_set_default_route_address(
    io_amqp_link_t* link,
    const char* route_address
)
{
    if (!link || !route_address)
        return er_fault;

    link->route_address = STRING_construct(route_address);
    if (!link->route_address)
        return er_out_of_memory;

    return er_ok;
}

//
// Send message, must be called from scheduler thread
//
int32_t io_amqp_link_send(
    io_amqp_link_t* link,
    io_amqp_properties_t* properties,
    const char* body,
    size_t body_len
)
{
    int32_t result;
    io_amqp_link_message_t* message;

    if (!link)
        return er_fault;
    if (link->receiver_cb)
        return er_arg;

    //
    // Create a message and add to end of send queue, which
    // allows retries while links are down
    //
    result = io_amqp_link_message_create(
        link, properties, body, body_len, &message);
    if (result != er_ok)
        return result;

    DList_InsertTailList(&link->send_queue, &message->qlink);
    __do_next(link, io_amqp_link_send_message);
    return er_ok;
}























//
// Close the link
//
void io_amqp_link_close(
    io_amqp_link_t* link
)
{
    io_amqp_link_free(link);
}


































//
// Free claim
//
static void io_amqp_claim_free(
    io_amqp_claim_t* claim
)
{
    if (!claim)
        return;

    if (claim->token_provider)
    {
        log_info(claim->connection->log, "Removing claim for %s...",
            io_token_provider_get_property(
                claim->token_provider, io_token_property_scope));

        io_token_provider_release(claim->token_provider);
    }

    mem_free_type(io_amqp_claim_t, claim);
}

//
// Create new claim
//
static int32_t io_amqp_claim_create(
    io_token_provider_t* token_provider,
    io_amqp_connection_t* connection,
    io_amqp_claim_t** created
)
{
    int32_t result;
    io_amqp_claim_t* claim;

    if (!created || !token_provider)
        return er_fault;

    claim = mem_zalloc_type(io_amqp_claim_t);
    if (!claim)
        return er_out_of_memory;
    do
    {
        DList_InitializeListHead(&claim->qlink);
        DList_InitializeListHead(&claim->link);

        claim->connection = connection;
        claim->scheduler = connection->scheduler;

        result = io_token_provider_clone(
            token_provider, &claim->token_provider);
        if (result != er_ok)
            break;

        *created = claim;
        return er_ok;
    } while (0);

    io_amqp_claim_free(claim);
    return result;
}

//
// Submit a renewal 
//
static void io_amqp_connection_submit_renewals(
    io_amqp_connection_t* connection
);

//
// Add claim to renewal queue and start renewing
//
static void io_amqp_claim_queue(
    io_amqp_claim_t* claim
)
{
    io_amqp_connection_t* connection;

    dbg_assert_ptr(claim);
    connection = claim->connection;
    dbg_assert_ptr(connection);

    if (DList_IsListEmpty(&connection->renewals))
    {
        // Schedule a renewal of this claim right away
        __do_next(connection, io_amqp_connection_submit_renewals);
    }

    claim->status = io_amqp_claim_status_pending;
    claim->expiry = 0;
    DList_InsertTailList(&connection->renewals, &claim->qlink);
}

//
// Called when the claim is complete
//
static void io_amqp_claim_complete(
    void* context,
    CBS_OPERATION_RESULT cbs_operation_result,
    uint32_t status_code,
    const char* status_description
)
{
    io_amqp_claim_t* claim;
    io_amqp_connection_t* connection;

    claim = (io_amqp_claim_t*)context;
    dbg_assert_ptr(claim);
    connection = claim->connection;
    dbg_assert_ptr(connection);

    if (cbs_operation_result == CBS_OPERATION_RESULT_OK)
    {
        claim->status = io_amqp_claim_status_claimed;

        log_info(connection->log,
            "Token issued to %s.",
            io_token_provider_get_property(
                claim->token_provider, io_token_property_scope));

        // requeue claim in expiry time
        __do_later(claim, io_amqp_claim_queue,
            (uint32_t)(0.8 * (claim->expiry - ticks_get())));
    }
    else
    {
        claim->status = io_amqp_claim_status_error;

        log_error(connection->log,
            "Failed issuing cbs token to %s, status code: %d - %s",
            io_token_provider_get_property(
                claim->token_provider, io_token_property_scope),
            status_code, status_description);

        // Requeue claim
        claim->expiry = 0;
        __do_next(claim, io_amqp_claim_queue);
    }

    // Remove from renewal queue
    DList_RemoveEntryList(&claim->qlink);

    //
    // Get next claim in the queue and renew if necessary,
    // otherwise reconnect endpoints
    //
    if (!DList_IsListEmpty(&connection->renewals))
        __do_next(connection, io_amqp_connection_submit_renewals);
    else
        __do_next(connection, io_amqp_connection_reconnect_endpoints);
}

//
// Submit a new renewal
//
static void io_amqp_connection_submit_renewals(
    io_amqp_connection_t* connection
)
{
    int32_t result;
    io_amqp_claim_t* claim;
    STRING_HANDLE token = NULL;

    // Get next claim to renew
    if (DList_IsListEmpty(&connection->renewals))
        return;
    claim = containingRecord(connection->renewals.Flink, io_amqp_claim_t, qlink);

    dbg_assert_ptr(claim);
    dbg_assert_ptr(claim->token_provider);
    dbg_assert_ptr(claim->connection);
    dbg_assert(claim->connection == connection, "");

    // Callback to get new token for claim
    result = io_token_provider_new_token(
        claim->token_provider, &token, &claim->expiry);
    if (result != er_ok)
    {
        log_error(connection->log, "Failed getting claim token for %s.",
            io_token_provider_get_property(
                claim->token_provider, io_token_property_scope));

        // An error occurred issuing token, mark this as error requeue and return
        claim->expiry = 0;
        claim->status = io_amqp_claim_status_error;
        __do_next(claim, io_amqp_claim_queue);
        return;
    }

    if (connection->auth_type == io_amqp_connection_auth_sasl_cbs)
    {
        log_info(connection->log, "Issuing token to %s...",
            io_token_provider_get_property(
                claim->token_provider, io_token_property_scope));

        result = cbs_put_token(connection->cbs,
            io_token_provider_get_property(
                claim->token_provider, io_token_property_type),
            io_token_provider_get_property(
                claim->token_provider, io_token_property_scope),
            STRING_c_str(token), io_amqp_claim_complete, claim);

        STRING_delete(token);

        if (result != 0)
        {
            log_error(connection->log,
                "cbs_put_token returned error, failing claim renewal...");
            claim->expiry = 0;
            claim->status = io_amqp_claim_status_error;
            __do_next(claim, io_amqp_claim_queue);
        }
        // else wait for completion callback or for timeout
    }
    else
    {
        // Sasl plain, provide token as password and reset connection
        dbg_assert(connection->auth_type == io_amqp_connection_auth_sasl_plain,
            "Must be sasl plain");
        dbg_assert(claim->link.Flink == connection->claims.Blink,
            "Must have one claim only");

        if (connection->address->password)
            STRING_delete(connection->address->password);
        if (connection->address->user_name)
            STRING_delete(connection->address->user_name);

        connection->address->user_name = STRING_construct(
            io_token_provider_get_property(claim->token_provider, io_token_property_policy));
        connection->address->password = token;

        // Reset connection and reconnect immediately
        io_amqp_connection_clear_failures(connection);
        __do_next(connection, io_amqp_connection_reset);
    }
}

//
// Reset renewal list
//
static void io_amqp_connection_reset_renewals(
    io_amqp_connection_t* connection
)
{
    // Clear renewals list and remove all claim tasks from scheduler
    while (!DList_IsListEmpty(&connection->renewals))
        io_scheduler_clear(connection->scheduler, containingRecord(
            DList_RemoveHeadList(&connection->renewals), io_amqp_claim_t, qlink));
}

//
// Start authentication on connection
//
static void io_amqp_connection_authenticate(
    io_amqp_connection_t* connection
)
{
    io_amqp_claim_t* claim = NULL;

    dbg_assert(DList_IsListEmpty(&connection->renewals),
        "Renewals should be empty");

    // Push all claims into the renewal queue
    for (PDLIST_ENTRY p = connection->claims.Flink;
        p != &connection->claims; p = p->Flink)
    {
        claim = containingRecord(p, io_amqp_claim_t, link);
        claim->status = io_amqp_claim_status_pending;
        claim->expiry = 0;
        DList_InsertTailList(&connection->renewals, &claim->qlink);
    }

    // Renew first claim
    __do_next(connection, io_amqp_connection_submit_renewals);
}

//
// Disconnect connection
//
static void io_amqp_connection_disconnect(
    io_amqp_connection_t* connection
)
{
    io_amqp_link_t* next;

    // Clear renewal list
    io_amqp_connection_reset_renewals(connection);

    if (connection->cbs)
        cbs_destroy(connection->cbs);
    connection->cbs = NULL;

    // Hard disconnect connected links, i.e. we do not wait for responses
    for (PDLIST_ENTRY p = connection->endpoints.Flink; 
        p != &connection->endpoints; p = p->Flink)
    {
        next = containingRecord(p, io_amqp_link_t, link);
        if (next->status == io_amqp_link_state_disconnected)
            continue;
        
        io_amqp_link_begin_disconnect(next);
        io_amqp_link_complete_disconnect(next);

        // Clear any task from scheduler that is related the connection's links
        io_scheduler_clear(connection->scheduler, next);
    }
    
    // Remove all scheduled tasks for this connection from scheduler
    io_scheduler_clear(connection->scheduler, connection);

    // Close session and socket
    if (connection->session)
		session_destroy(connection->session);
    connection->session = NULL;
    if (connection->connection)
        connection_destroy(connection->connection);
    connection->connection = NULL;
    if (connection->sasl_io)
        xio_destroy(connection->sasl_io);
    connection->sasl_io = NULL;
    if (connection->sasl_mechanism)
        saslmechanism_destroy(connection->sasl_mechanism);
    connection->sasl_mechanism = NULL;
    if (connection->socket_io)
        xio_destroy(connection->socket_io);
    connection->socket_io = NULL;

    log_info(connection->log, "Connection disconnected.");
}

//
// Connect any links that are disconnected
//
static void io_amqp_connection_reconnect_endpoints(
    io_amqp_connection_t* connection
)
{
    io_amqp_link_t* next;
    io_amqp_claim_t* claim;

    //
    // If we have claims and use cbs, ensure all claims were made 
    // before connecting endpoints...
    //
    if (connection->cbs)
    {
        for (PDLIST_ENTRY p = connection->claims.Flink; 
            p != &connection->claims; p = p->Flink)
        {
            claim = containingRecord(p, io_amqp_claim_t, link);
            if (claim->status != io_amqp_claim_status_claimed)
            {
                log_info(connection->log,
                    "Claim for %s was in state %d before connecting!",
                    io_token_provider_get_property(
                        claim->token_provider, io_token_property_scope),
                    claim->status);

                // reset
                __do_next(connection, io_amqp_connection_reset);
                return;
            }
        }
    }

    //
    // Now (re-)connect all links that are disconnected, 
    // remove and free any closing links...
    //
    for (PDLIST_ENTRY p = connection->endpoints.Flink; 
        p != &connection->endpoints; )
    {
        next = containingRecord(p, io_amqp_link_t, link);
        p = next->link.Flink;

        if (next->status == io_amqp_link_state_disconnected)
            __do_next(next, io_amqp_link_begin_connect);
    }
}

//
// Work the underlying stack periodically for keep alives
//
static void io_amqp_connection_work(
    io_amqp_connection_t* connection
)
{
    uint64_t next_deadline;

    // Calculate reschedule interval and send keep alive if needed
    next_deadline = connection_handle_deadlines(connection->connection);

    __do_later(connection, io_amqp_connection_work, (uint32_t)next_deadline);
}

//
// Connect all unconnected layers
//
static void io_amqp_connection_reconnect(
    io_amqp_connection_t* connection
)
{
    int32_t result;
    SASLCLIENTIO_CONFIG sasl_client_config;
    SASL_PLAIN_CONFIG sasl_plain_config;
    TLSIO_CONFIG tls_io_config;
    WSIO_CONFIG ws_io_config;

    dbg_assert_ptr(connection);
    do
    {
        result = er_connecting;

        if (!connection->socket_io)
        {
            // Either select explicit io or cycle the use of websockets and raw io
            if (!connection->address->scheme)
                connection->is_websocket = !connection->is_websocket;

            if (connection->is_websocket)
            {
                memset(&ws_io_config, 0, sizeof(WSIO_CONFIG));
                ws_io_config.port =
                    connection->address->port ? connection->address->port : 443;
                ws_io_config.host = 
                    STRING_c_str(connection->address->host_name);
                ws_io_config.protocol_name = 
                    "AMQPWSB10";
                ws_io_config.relative_path = 
                    STRING_c_str(connection->address->path);
                ws_io_config.use_ssl = true;

                connection->socket_io = xio_create(
                    wsio_get_interface_description(), &ws_io_config);
                if (!connection->socket_io)
                    break;
                if (connection->address->trusted_ca &&
                    0 != xio_setoption(connection->socket_io, "TrustedCerts", 
                        STRING_c_str(connection->address->trusted_ca)))
                    break;
            }
            else
            {
                tls_io_config.port =
                    connection->address->port ? connection->address->port : 5671;
                tls_io_config.hostname = 
                    STRING_c_str(connection->address->host_name);

                connection->socket_io = xio_create(
                    platform_get_default_tlsio(), &tls_io_config);
                if (!connection->socket_io)
                    break;
            }

            // Set scheduler after the fact - this will push receives back to us
            if (0 != xio_setoption(connection->socket_io,
                xio_socket_option_scheduler, connection->scheduler))
                break;
        }

        if (!connection->sasl_io &&
            connection->auth_type != io_amqp_connection_auth_none)
        {
            switch (connection->auth_type)
            {
            case io_amqp_connection_auth_sasl_plain:
                sasl_plain_config.authzid = NULL;
                sasl_plain_config.authcid = 
                    STRING_c_str(connection->address->user_name);
                sasl_plain_config.passwd = 
                    STRING_c_str(connection->address->password);
                connection->sasl_mechanism = saslmechanism_create(
                    saslplain_get_interface(), &sasl_plain_config);
                break;
            case io_amqp_connection_auth_sasl_anonymous:
                connection->sasl_mechanism = saslmechanism_create(
                    saslanonymous_get_interface(), NULL);
                break;
            case io_amqp_connection_auth_sasl_cbs:
                connection->sasl_mechanism = saslmechanism_create(
                    saslmssbcbs_get_interface(), NULL);
                break;
            }
            if (!connection->sasl_mechanism)
                break;

            sasl_client_config.underlying_io = connection->socket_io;
            sasl_client_config.sasl_mechanism = connection->sasl_mechanism;
            connection->sasl_io = xio_create(
                saslclientio_get_interface_description(), &sasl_client_config);
            if (!connection->sasl_io)
                break;
        }

        if (!connection->connection)
        {
            connection->connection = connection_create2(
                connection->sasl_io,
                STRING_c_str(connection->address->host_name), "default-container",
                NULL, NULL,
                io_amqp_connection_state_change_callback, connection,
                io_amqp_connection_io_error_callback, connection);
            if (!connection->connection)
                break;
        }

#ifdef LOG_AMQP
        connection_set_trace(connection->connection, true);
#endif

        if (!connection->session)
        {
            connection->session = session_create(
                connection->connection, NULL, NULL);
            if (!connection->session)
                break;

            if (0 != session_set_outgoing_window(
                connection->session, 2) ||
                0 != session_set_incoming_window(
                    connection->session, 2147483647))
            {
                log_error(connection->log, 
                    "Unable to configure session window sizes");
                break;
            }
        }

        if (!connection->cbs && 
            connection->auth_type == io_amqp_connection_auth_sasl_cbs)
        {
            connection->cbs = cbs_create(connection->session, 
                io_amqp_connection_management_callback, connection);
            if (!connection->cbs || 0 != cbs_open(connection->cbs))
            {
                log_error(connection->log, 
                    "Failed to open the connection with CBS.");
                result = er_connecting;
                break;
            }

            // Renew all claims, then schedule a connect for 60 seconds from now
            __do_next(connection, io_amqp_connection_authenticate);
            // if we do not have all claims, we fail here.
            __do_later(connection, io_amqp_connection_reconnect_endpoints, 60000);
        }
        else
        {
            // Connect all links immediately
            __do_next(connection, io_amqp_connection_reconnect_endpoints);
        }

        // Kick off working connections periodically
        __do_next(connection, io_amqp_connection_work);
        connection->status = io_amqp_connection_status_open;
        return;

    } while (0);

    log_error(connection->log, 
        "Failed to connect connection (%s)", pi_error_string(result));
    __do_next(connection, io_amqp_connection_reset);
}

//
// Connect all unconnected layers
//
static void io_amqp_connection_reset(
    io_amqp_connection_t* connection
)
{
    dbg_assert_ptr(connection);

    // Hard disconnect
    __do_next(connection, io_amqp_connection_disconnect);

    log_info(connection->log, "Reconnecting in %d seconds...",
        connection->back_off_in_seconds);

    __do_later(connection, io_amqp_connection_reconnect,
        connection->back_off_in_seconds * 1000);

    if (!connection->back_off_in_seconds)
        connection->back_off_in_seconds = 1;
    connection->back_off_in_seconds *= 2;
    if (connection->back_off_in_seconds > 24 * 60 * 60)
        connection->back_off_in_seconds = 24 * 60 * 60;

    connection->status = io_amqp_connection_status_reset;
}

//
// Adds a claim for a resource on the connection
//
int32_t io_amqp_connection_add_claim(
    io_amqp_connection_t* connection,
    io_token_provider_t* token_provider
)
{
    int32_t result;
    io_amqp_claim_t* claim = NULL;

    if (!token_provider || !connection)
        return er_fault;

    // Invalid to add claim for anything but cbs or plain
    if (connection->auth_type != io_amqp_connection_auth_sasl_cbs &&
        connection->auth_type != io_amqp_connection_auth_sasl_plain)
        return er_arg;

    // Cannot add claim for plain if there is already one laid to the connection
    if (connection->auth_type == io_amqp_connection_auth_sasl_plain &&
        !DList_IsListEmpty(&connection->claims))
        return er_arg;

    // Check whether we already have a claim
    result = er_not_found;
    for (PDLIST_ENTRY p = connection->claims.Flink; 
        p != &connection->claims; p = p->Flink)
    {
        claim = containingRecord(p, io_amqp_claim_t, link);
        if (io_token_provider_is_equivalent(token_provider, claim->token_provider))
        {
            if (connection->status == io_amqp_connection_status_open)
                __do_next(claim, io_amqp_claim_queue);
            return er_ok;
        }
    }

    if (result != er_ok)
    {
        log_info(connection->log, "Adding claim for %s...",
            io_token_provider_get_property(
                token_provider, io_token_property_scope));
        // Create new claim
        result = io_amqp_claim_create(token_provider, connection, &claim);
    }

    if (result == er_ok)
    {
        DList_InsertTailList(&connection->claims, &claim->link);
        if (connection->status == io_amqp_connection_status_open)
            __do_next(claim, io_amqp_claim_queue);
    }
    return result;
}

//
// Close the connection
//
void io_amqp_connection_close(
    io_amqp_connection_t* connection
)
{
    io_amqp_link_t* next;

    if (!connection)
        return;

    // Hard disconnect
    io_amqp_connection_disconnect(connection);

    for (PDLIST_ENTRY p = connection->endpoints.Flink; p != &connection->endpoints; )
    {
        next = containingRecord(p, io_amqp_link_t, link);
        p = next->link.Flink;
        if (connection->status == io_amqp_connection_status_closing)
        {
            DList_RemoveEntryList(&next->link);
            io_amqp_link_free(next);
        }
    }

    // Stop scheduling all connection related tasks
    if (connection->scheduler)
        io_scheduler_release(connection->scheduler, connection);

    // Free all claims
    while (!DList_IsListEmpty(&connection->claims))
        io_amqp_claim_free(containingRecord(
            DList_RemoveHeadList(&connection->claims), io_amqp_claim_t, link));

    if (connection->address)
        io_url_free(connection->address);

    log_info(connection->log, "Connection closed.");
    mem_free_type(io_amqp_connection_t, connection);
}

//
// Connect connection
//
int32_t io_amqp_connection_connect(
    io_amqp_connection_t* connection
)
{
    if (!connection)
        return er_fault;
    __do_next(connection, io_amqp_connection_reconnect);
    return er_ok;
}

//
// Allocate a connection resource
//
int32_t io_amqp_connection_create(
    io_url_t* address,
    io_scheduler_t* scheduler,
    io_amqp_connection_auth_t auth_type,
    io_amqp_connection_t** created
)
{
    int32_t result;
    io_amqp_connection_t* connection;

    if (!address || !created)
        return er_fault;

    connection = mem_zalloc_type(io_amqp_connection_t);
    if (!connection)
        return er_out_of_memory;
    do
    {
        DList_InitializeListHead(&connection->endpoints);
        DList_InitializeListHead(&connection->renewals);
        DList_InitializeListHead(&connection->claims);

        connection->log = log_get("amqp.link.connection");
        connection->auth_type = auth_type;
        connection->status = io_amqp_connection_status_closed;

        result = io_url_clone(address, &connection->address);
        if (result != er_ok)
            break;

        //
        // If no scheme or wss specified, start out as websocket being true, else 
        // always use raw socket io for amqps
        //
        if (!connection->address->scheme ||
            0 == STRING_compare_c_str_nocase(connection->address->scheme, "wss"))
            connection->is_websocket = true;

        result = io_scheduler_create(scheduler, &connection->scheduler);
        if (result != er_ok)
            break;

        // schedule connect

        // TODO:


        *created = connection;
        return result;

    } while (0);

    io_amqp_connection_close(connection);
    return result;
}
