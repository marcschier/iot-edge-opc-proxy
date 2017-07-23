// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef _io_amqp_h_
#define _io_amqp_h_

#include "common.h"
#include "io_url.h"
#include "io_token.h"
#include "prx_sched.h"

//
// Amqp connnection + session, bound to scheduler
//
typedef struct io_amqp_connection io_amqp_connection_t;

//
// Amqp link in session
//
typedef struct io_amqp_link io_amqp_link_t;

//
// Properties handle
//
typedef struct io_amqp_properties io_amqp_properties_t;

//
// Type of property
//
typedef enum io_amqp_property_type
{
    io_amqp_property_type_unknown,
    io_amqp_property_type_string,
    io_amqp_property_type_int32,
    io_amqp_property_type_uuid
}
io_amqp_property_type_t;

//
// Connection auth type
//
typedef enum io_amqp_connection_auth
{
    io_amqp_connection_auth_none,
    io_amqp_connection_auth_sasl_anonymous,
    io_amqp_connection_auth_sasl_plain,
    io_amqp_connection_auth_sasl_cbs
}
io_amqp_connection_auth_t;

//
// Open a connection to a endpoint with given address
//
decl_internal_4(int32_t, io_amqp_connection_create,
    io_url_t*, address,
    prx_scheduler_t*, scheduler,
    io_amqp_connection_auth_t, auth_type,
    io_amqp_connection_t**, created
);

//
// Adds a claim for a resource on the connection
//
decl_internal_2(int32_t, io_amqp_connection_add_claim,
    io_amqp_connection_t*, connection,
    io_token_provider_t*, token_provider
);

//
// Connection connection
//
decl_internal_1(int32_t, io_amqp_connection_connect,
    io_amqp_connection_t*, connection
);

//
// Close connection
//
decl_internal_1(void, io_amqp_connection_close,
    io_amqp_connection_t*, connection
);

//
// Receive callback
//
typedef int32_t (*io_amqp_link_receiver_t)(
    void* context,
    io_amqp_properties_t* properties,
    const char* body,
    size_t body_len
    );

//
// Open a link over a connection
//
decl_internal_8(int32_t, io_amqp_connection_create_link,
    io_amqp_connection_t*, connection,
    const char*, source,
    const char*, target,
    size_t, message_size,
    io_amqp_link_receiver_t, cb,
    void*, context,
    bool, filter_receives,
    io_amqp_link_t**, opened
);

//
// Get link properties
//
decl_internal_1(io_amqp_properties_t*, io_amqp_link_properties,
    io_amqp_link_t*, link
);

//
// Set default route address
//
decl_internal_2(int32_t, io_amqp_link_set_default_route_address,
    io_amqp_link_t*, link,
    const char*, route_address
);

//
// Set filter on receives
//
decl_internal_2(int32_t, io_amqp_link_set_filter,
    io_amqp_link_t*, link,
    bool, filter_receives
);

//
// Send data
//
decl_internal_4(int32_t, io_amqp_link_send,
    io_amqp_link_t*, link,
    io_amqp_properties_t*, properties,
    const char*, body,
    size_t, body_len
);

//
// Close the link
//
decl_internal_1(void, io_amqp_link_close,
    io_amqp_link_t*, link
);

//
// Create properties bag
//
decl_internal_1(int32_t, io_amqp_properties_create,
    io_amqp_properties_t**, properties
);

//
// Add property to bag
//
decl_internal_4(int32_t, io_amqp_properties_add,
    io_amqp_properties_t*, properties,
    const char*, key,
    io_amqp_property_type_t, type,
    const void*, buffer
);

//
// Get a property from a property bag
//
decl_internal_4(int32_t, io_amqp_properties_get,
    io_amqp_properties_t*, properties,
    const char*, key,
    io_amqp_property_type_t, type,
    void*, buffer  // STRING_HANDLE for string
);

//
// Get correlation id property from property bag
//
decl_internal_3(int32_t, io_amqp_properties_get_correlation_id,
    io_amqp_properties_t*, properties,
    io_amqp_property_type_t, type,
    void*, buffer
);

//
// Set correlation id property from property bag
//
decl_internal_3(int32_t, io_amqp_properties_set_correlation_id,
    io_amqp_properties_t*, properties,
    io_amqp_property_type_t, type,
    const void*, buffer
);

// ... add more if needed

//
// Free properties bag
//
decl_internal_1(void, io_amqp_properties_free,
    io_amqp_properties_t*, properties
);

#endif // _io_amqp_h_
