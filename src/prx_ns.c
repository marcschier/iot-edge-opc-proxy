// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "util_mem.h"
#include "util_string.h"
#include "util_stream.h"
#include "prx_ns.h"

#include "pal_file.h"
#include "pal_mt.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/httpapiexsas.h"
#include "azure_c_shared_utility/doublylinkedlist.h"
#include "parson.h"

#define API_VERSION "2016-11-14"

typedef struct prx_ns_iot_hub_twin_entry prx_ns_iot_hub_twin_entry_t;
typedef struct prx_ns_iot_hub_registry prx_ns_iot_hub_registry_t;

//
// A generic in memory entry
//
typedef struct prx_ns_generic_entry
{
#define prx_ns_entry_type_gw \
    (prx_ns_entry_type_startup | prx_ns_entry_type_proxy)

    prx_ns_entry_t itf;                              // Entry interface
    DLIST_ENTRY link;       // this must be here for generic result set

    STRING_HANDLE name;                    // Name of the entry or null
    io_ref_t id;                              // Unique id of the entry
    io_cs_t* cs;                    // Entry specific connection string
    uint32_t type;                                     // Type of entry
}
prx_ns_generic_entry_t;

//
// Simple in memory registry, loaded and saved to file
//
typedef struct prx_ns_generic_registry
{
    prx_ns_t itf;                                 // Database interface
    const char* file_name;            // file name to read and write to
    rw_lock_t entries_lock;
    DLIST_ENTRY entries;                      // Master list of entries
    size_t num_entries;
    log_t log;            // Log entry for iot registry database access
}
prx_ns_generic_registry_t;

//
// Generic result set
//
typedef struct prx_ns_generic_resultset
{
    prx_ns_result_t itf;                            // Result interface
    DLIST_ENTRY head;                 // head of result list of entries
    size_t count;                                   // Size of the list
}
prx_ns_generic_resultset_t;

//
// An entry retrieved or added to a database
//
struct prx_ns_iot_hub_twin_entry
{
    prx_ns_entry_t itf;                              // Entry interface
    DLIST_ENTRY link;       // this must be here for generic result set
    prx_ns_iot_hub_registry_t* registry;         // The owning database
    JSON_Value* twin;                       // Twin json representation
};

//
// Remote iot hub registry
//
struct prx_ns_iot_hub_registry
{
    prx_ns_t itf;                                 // Database interface
    DLIST_ENTRY link;      // Links registries together into composites
    prx_ns_generic_entry_t* hub_entry;    // Hub entry as parent to all
    log_t log;            // Log entry for iot registry database access
};

//
// Composite hub registry - supporting multiple hubs
//
typedef struct prx_ns_iot_hub_composite
{
    prx_ns_t itf;                                 // Database interface
    DLIST_ENTRY hubs;                            // Master list of hubs
    log_t log;           // Log entry for iot composite registry access
}
prx_ns_iot_hub_composite_t;


//
// Get next entry from the resultset
//
static prx_ns_entry_t* prx_ns_generic_resultset_pop(
    void* context
)
{
    prx_ns_generic_resultset_t* list = (prx_ns_generic_resultset_t*)context;
    dbg_assert_ptr(list);
    if (DList_IsListEmpty(&list->head))
    {
        dbg_assert(list->count == 0, "");
        return NULL;
    }
    list->count--;
    return &containingRecord(
        DList_RemoveHeadList(&list->head), prx_ns_generic_entry_t, link)->itf;
}

//
// Free the resultset
//
static void prx_ns_generic_resultset_free(
    void* context
)
{
    prx_ns_generic_resultset_t* list = (prx_ns_generic_resultset_t*)context;
    dbg_assert_ptr(list);
    while (!DList_IsListEmpty(&list->head))
    {
        prx_ns_entry_release(&containingRecord(
            DList_RemoveHeadList(&list->head), prx_ns_generic_entry_t, link)->itf);
    }
    mem_free_type(prx_ns_generic_resultset_t, list);
}

//
// Return size of resultset
//
static size_t prx_ns_generic_resultset_size(
    void* context
)
{
    dbg_assert_ptr(context);
    return ((prx_ns_generic_resultset_t*)context)->count;
}

//
// Helper to add generic entry to the resultset
//
void prx_ns_generic_resultset_add(
    prx_ns_generic_resultset_t* list,
    prx_ns_generic_entry_t* entry
)
{
    dbg_assert_ptr(list);
    list->count++;
    DList_InsertTailList(&list->head, &entry->link);
}

//
// Helper to concat generic result to the resultset
//
prx_ns_generic_resultset_t* prx_ns_generic_resultset_concat(
    prx_ns_generic_resultset_t* list,
    prx_ns_generic_resultset_t* add
)
{
    if (!add)
        return list;
    if (!list)
        return add;

    list->count += add->count;
    DList_AppendTailList(&list->head, &add->head);
    DList_InitializeListHead(&add->head);
    prx_ns_generic_resultset_free(add);
    return list;
}

//
// Helper to create resultset
//
int32_t prx_ns_generic_resultset_create(
    prx_ns_generic_resultset_t** created
)
{
    prx_ns_generic_resultset_t* list;
    list = mem_zalloc_type(prx_ns_generic_resultset_t);
    if (!list)
        return er_out_of_memory;
    DList_InitializeListHead(&list->head);

    list->itf.context =
        list;
    list->itf.release =
        prx_ns_generic_resultset_free;
    list->itf.pop =
        prx_ns_generic_resultset_pop;
    list->itf.size =
        prx_ns_generic_resultset_size;
    *created = list;
    return er_ok;
}

//
// Get a clone of the entry connection string 
//
static int32_t prx_ns_generic_entry_get_cs(
    void* context,
    io_cs_t** created
)
{
    dbg_assert_ptr(context);
    dbg_assert_ptr(created);
    return io_cs_clone(((prx_ns_generic_entry_t*)context)->cs, created);
}

//
// Returns name of entry, or device id if name is not given
//
static const char* prx_ns_generic_entry_get_name(
    void* context
)
{
    prx_ns_generic_entry_t* entry = (prx_ns_generic_entry_t*)context;
    dbg_assert_ptr(entry);
    if (entry->name)
        return STRING_c_str(((prx_ns_generic_entry_t*)context)->name);
    return io_cs_get_device_id(entry->cs);
}

//
// Returns id of entry
//
static const char* prx_ns_generic_entry_get_id(
    void* context
)
{
    dbg_assert_ptr(context);
    return io_cs_get_device_id(((prx_ns_generic_entry_t*)context)->cs);
}

//
// Returns index of entry
//
static int32_t prx_ns_generic_entry_get_index(
    void* context
)
{
    dbg_assert_ptr(context);
    return (int32_t)(intptr_t)context;
}

//
// Returns type of entry
//
static uint32_t prx_ns_generic_entry_get_type(
    void* context
)
{
    dbg_assert_ptr(context);
    return ((prx_ns_generic_entry_t*)context)->type;
}

//
// Returns address of entry
//
static int32_t prx_ns_generic_entry_get_addr(
    void* context,
    io_ref_t* id
)
{
    dbg_assert_ptr(context);
    dbg_assert_ptr(id);
    io_ref_copy(&((prx_ns_generic_entry_t*)context)->id, id);
    return er_ok;
}

//
// No op for generic entries
//
static int32_t prx_ns_generic_entry_get_routes(
    void* context,
    prx_ns_result_t** routes
)
{
    (void)context, routes;
    return er_not_found;
}

//
// No op for generic entries
//
static int32_t prx_ns_generic_entry_add_route(
    void* context,
    prx_ns_entry_t* route
)
{
    (void)context, route;
    return er_not_supported;
}

//
// Create generic entry from connection string
//
static int32_t prx_ns_generic_entry_create(
    uint32_t type,
    io_ref_t* id,
    const char* name,
    io_cs_t* cs,
    prx_ns_generic_entry_t** created
);

//
// Clone a generic entry
//
static int32_t prx_ns_generic_entry_clone(
    void* context,
    prx_ns_entry_t** clone
)
{
    int32_t result;
    prx_ns_generic_entry_t *created, *entry = (prx_ns_generic_entry_t*)context;
    dbg_assert_ptr(entry);

    result = prx_ns_generic_entry_create(entry->type, &entry->id,
        entry->name ? STRING_c_str(entry->name) : NULL, entry->cs, &created);
    if (result != er_ok)
        return result;

    *clone = &created->itf;
    return er_ok;
}

//
// Returns the generic entry if it has a connection string
//
static int32_t prx_ns_generic_entry_get_links(
    void* context,
    prx_ns_result_t** created
)
{
    int32_t result;
    prx_ns_generic_resultset_t* links;
    prx_ns_entry_t* clone;
    prx_ns_generic_entry_t* entry = (prx_ns_generic_entry_t*)context;

    if (!entry->cs)
        return er_not_found;

    result = prx_ns_generic_resultset_create(&links);
    if (result != er_ok)
        return result;
    do
    {
        result = prx_ns_generic_entry_clone(entry, &clone);
        if (result != er_ok)
            break;
        prx_ns_generic_resultset_add(links, (prx_ns_generic_entry_t*)clone->context);
        *created = &links->itf;
        return er_ok;
    } 
    while (0);
    prx_ns_generic_resultset_free(links);
    return result;
}

//
// Free entry
//
static void prx_ns_generic_entry_free(
    void* context
)
{
    prx_ns_generic_entry_t* entry = (prx_ns_generic_entry_t*)context;
    dbg_assert_ptr(entry);
    if (entry->name)
        STRING_delete(entry->name);
    if (entry->cs)
        io_cs_free(entry->cs);
    mem_free_type(prx_ns_generic_entry_t, entry);
}

//
// Create generic entry from connection string
//
static int32_t prx_ns_generic_entry_create(
    uint32_t type,
    io_ref_t* id,
    const char* name,
    io_cs_t* cs,
    prx_ns_generic_entry_t** created
)
{
    int32_t result;
    prx_ns_generic_entry_t* entry;

    if (!created)
        return er_fault;

    entry = mem_zalloc_type(prx_ns_generic_entry_t);
    if (!entry)
        return er_out_of_memory;
    do
    {
        DList_InitializeListHead(&entry->link);
        entry->type = type;

        if (id)
            io_ref_copy(id, &entry->id);
        else
        {
            result = io_ref_new(&entry->id);
            if (result != er_ok)
                break;
        }

        if (name)
        { 
            entry->name = STRING_construct(name);
            if (!entry->name)
            {
                result = er_out_of_memory;
                break;
            }
        }

        if (cs)
        {
            result = io_cs_clone(cs, &entry->cs);
            if (result != er_ok)
                break;
        }

        entry->itf.context =
            entry;
        entry->itf.clone =
            prx_ns_generic_entry_clone;
        entry->itf.release =
            prx_ns_generic_entry_free;
        entry->itf.get_addr =
            prx_ns_generic_entry_get_addr;
        entry->itf.get_cs =
            prx_ns_generic_entry_get_cs;
        entry->itf.get_id =
            prx_ns_generic_entry_get_id;
        entry->itf.get_index =
            prx_ns_generic_entry_get_index;
        entry->itf.get_name =
            prx_ns_generic_entry_get_name;
        entry->itf.get_routes =
            prx_ns_generic_entry_get_routes;
        entry->itf.add_route =
            prx_ns_generic_entry_add_route;
        entry->itf.get_links =
            prx_ns_generic_entry_get_links;
        entry->itf.get_type =
            prx_ns_generic_entry_get_type;

        *created = entry;
        return er_ok;
    } while (0);

    prx_ns_generic_entry_free(entry);
    return result;
}

//
// Encode a generic entry
//
static int32_t prx_ns_generic_entry_encode(
    io_codec_ctx_t* ctx,
    prx_ns_generic_entry_t* entry
)
{
    int32_t result;

    if (io_codec_json == io_codec_ctx_get_codec_id(ctx))
    {
        __io_encode_type_begin(ctx, entry, 
            entry->type != prx_ns_entry_type_gw ? 4 : 3);

        __io_encode_value(ctx, STRING_HANDLE, entry, name);
        result = io_encode_ref(ctx, &entry->id);
        if (result != er_ok)
            return result;
        result = io_encode_cs(ctx, &entry->cs);
        if (result != er_ok)
            return result;

        if (entry->type != prx_ns_entry_type_gw)
            __io_encode_value(ctx, uint32, entry, type);
        __io_encode_type_end(ctx);
    }
    else
    {
        __io_encode_type_begin(ctx, entry, 4);
        __io_encode_value(ctx, STRING_HANDLE, entry, name);
        __io_encode_object(ctx, ref, entry, id);
        __io_encode_object(ctx, cs, entry, cs);
        __io_encode_value(ctx, uint32, entry, type);
        __io_encode_type_end(ctx);
    }
    return result;
}

//
// Decode generic entry
//
static int32_t prx_ns_generic_entry_decode(
    io_codec_ctx_t* ctx,
    prx_ns_generic_entry_t* entry
)
{
    int32_t result;

    if (entry->name)
        STRING_delete(entry->name);
    if (entry->cs)
        io_cs_free(entry->cs);

    if (io_codec_json == io_codec_ctx_get_codec_id(ctx))
    {
        __io_decode_type_begin(ctx, entry, 3);
        __io_decode_value(ctx, STRING_HANDLE, entry, name);
        result = io_decode_ref(ctx, &entry->id);
        if (result != er_ok)
        {
            result = io_ref_new(&entry->id);
            if (result != er_ok)
                return result;
        }
        result = io_decode_cs(ctx, &entry->cs);
        if (result != er_ok)
            return result;

        result = io_decode_uint32(ctx, "type", &entry->type);
        if (result != er_ok)
            entry->type = prx_ns_entry_type_gw;
        __io_decode_type_end(ctx);
    }
    else
    {
        __io_decode_type_begin(ctx, entry, 4);
        __io_decode_value(ctx, STRING_HANDLE, entry, name);
        __io_decode_object(ctx, ref, entry, id);
        __io_decode_object(ctx, cs, entry, cs);
        __io_decode_value(ctx, uint32, entry, type);
        __io_decode_type_end(ctx);
    }
    return result;
}

//
// Remove all entries in registry - lock must be held
//
static void prx_ns_generic_registry_clear(
    prx_ns_generic_registry_t* registry
)
{
    dbg_assert_ptr(registry);

    while (!DList_IsListEmpty(&registry->entries))
    {
        prx_ns_generic_entry_free(containingRecord(
            DList_RemoveHeadList(&registry->entries), prx_ns_generic_entry_t, link));
    }

    registry->num_entries = 0;
}

//
// Encode a generic registry
//
static int32_t prx_ns_generic_registry_encode(
    io_codec_ctx_t* ctx,
    prx_ns_generic_registry_t* registry
)
{
    int32_t result;
    io_codec_ctx_t arr, obj;
    prx_ns_generic_entry_t* next;
    do
    {
        __io_encode_type_begin(ctx, registry, 1);
        result = io_encode_array(ctx, "entries", (size_t)registry->num_entries, &arr);
        if (result != er_ok)
            break;
        for (PDLIST_ENTRY p = registry->entries.Flink; p != &registry->entries; p = p->Flink)
        {
            next = containingRecord(p, prx_ns_generic_entry_t, link);
            result = io_encode_object(&arr, NULL, false, &obj);
            if (result != er_ok)
                break;
            result = prx_ns_generic_entry_encode(&obj, next);
            if (result != er_ok)
                break;
        }
        if (result != er_ok)
            break;
        __io_encode_type_end(ctx);
    } while (0);
    return result;
}

//
// Decode generic registry
//
static int32_t prx_ns_generic_registry_decode(
    io_codec_ctx_t* ctx,
    prx_ns_generic_registry_t* registry
)
{
    int32_t result;
    io_codec_ctx_t arr, obj;
    prx_ns_generic_entry_t* next;

    do
    {
        __io_decode_type_begin(ctx, registry, 1);
        if (registry->num_entries != 0)
            prx_ns_generic_registry_clear(registry);
        dbg_assert(registry->num_entries == 0, "Unexpected number of entries");
        result = io_decode_array(ctx, "entries", &registry->num_entries, &arr);
        if (result != er_ok)
            break;
        for (prx_size_t i = 0; i < registry->num_entries; i++)
        {
            result = io_decode_object(&arr, NULL, NULL, &obj);
            if (result != er_ok)
                break;
            result = prx_ns_generic_entry_create(0, NULL, NULL, NULL, &next);
            if (result != er_ok)
                break;
            DList_InsertTailList(&registry->entries, &next->link);
            result = prx_ns_generic_entry_decode(&obj, next);
            if (result != er_ok)
                break;
        }
        if (result != er_ok)
        {
            prx_ns_generic_registry_clear(registry);
            break;
        }
        __io_decode_type_end(ctx);
    } while (0);
    return result;
}

//
// Load database from configured file
//
static int32_t prx_ns_generic_registry_load(
    prx_ns_generic_registry_t* registry
)
{
    int32_t result;
    io_codec_ctx_t ctx;
    io_file_stream_t fs;
    io_stream_t* stream;

    dbg_assert_ptr(registry);
    if (!registry->file_name)
        return er_ok;

    stream = io_file_stream_init(&fs, registry->file_name, "r");
    if (!stream)
        return er_not_found;

    result = io_codec_ctx_init(
        io_codec_by_id(io_codec_json), &ctx, stream, true, NULL);
    if (result == er_ok)
    {
        result = prx_ns_generic_registry_decode(&ctx, registry);
        (void)io_codec_ctx_fini(&ctx, stream, false);
    }
    io_stream_close(stream);
    return result;
}

//
// Save database to configured file if any
//
static int32_t prx_ns_generic_registry_save(
    prx_ns_generic_registry_t* registry
)
{
    int32_t result;
    io_codec_ctx_t ctx;
    io_file_stream_t fs;
    io_stream_t* stream;

    dbg_assert_ptr(registry);
    if (!registry->file_name)
        return er_ok;

    stream = io_file_stream_init(&fs, registry->file_name, "w");
    if (!stream)
        return er_not_found;

    result = io_codec_ctx_init(
        io_codec_by_id(io_codec_json), &ctx, stream, false, NULL);
    if (result == er_ok)
    {
        result = prx_ns_generic_registry_encode(&ctx, registry);
        (void)io_codec_ctx_fini(&ctx, stream, true);
    }
    io_stream_close(stream);
    return result;
}

//
// Delete an entry from registry
//
static int32_t prx_ns_generic_registry_entry_delete(
    void* context,
    prx_ns_entry_t* entry
)
{
    int32_t result;
    io_ref_t id;
    prx_ns_generic_entry_t* next;
    prx_ns_generic_registry_t* registry = (prx_ns_generic_registry_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(entry);

    result = prx_ns_entry_get_addr(entry, &id);
    if (result != er_ok)
        return result;

    rw_lock_enter_w(registry->entries_lock);
    for (PDLIST_ENTRY p = registry->entries.Flink; p != &registry->entries; p = p->Flink)
    {
        next = containingRecord(p, prx_ns_generic_entry_t, link);
        if (!io_ref_equals(&next->id, &id))
            continue;

        DList_RemoveEntryList(&next->link);
        registry->num_entries--;
        (void)prx_ns_generic_registry_save(registry);
        rw_lock_exit_w(registry->entries_lock);
        prx_ns_generic_entry_free(next);
        return er_ok;
    }
    rw_lock_exit_w(registry->entries_lock);
    return er_not_found;
}

//
// Add or update entry in registry
//
static int32_t prx_ns_generic_registry_entry_create(
    void* context,
    prx_ns_entry_t* entry
)
{
    int32_t result;
    io_ref_t id;
    io_cs_t* cs = NULL;
    uint32_t type;
    prx_ns_generic_entry_t* next;
    prx_ns_generic_registry_t* registry = (prx_ns_generic_registry_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(entry);

    result = prx_ns_entry_get_addr(entry, &id);
    if (result != er_ok)
        return result;

    rw_lock_enter_w(registry->entries_lock);
    do
    {
        result = er_ok;
        for (PDLIST_ENTRY p = registry->entries.Flink; p != &registry->entries; p = p->Flink)
        {
            next = containingRecord(p, prx_ns_generic_entry_t, link);
            if (!io_ref_equals(&next->id, &id))
                continue;
            result = er_already_exists;
            break;
        }
        if (result != er_ok)
            break;
        result = prx_ns_entry_get_cs(entry, &cs);
        if (result != er_ok)
            break;

        // All proxy entries locally are gw entries
        type = prx_ns_entry_get_type(entry);
        if (type & prx_ns_entry_type_proxy)
            type |= prx_ns_entry_type_gw;

        result = prx_ns_generic_entry_create(
            type, &id, prx_ns_entry_get_name(entry), cs, &next);
        if (result != er_ok)
            break;
        DList_InsertTailList(&registry->entries, &next->link);
        registry->num_entries++;
        (void)prx_ns_generic_registry_save(registry);
        break;
    } while (0);
    rw_lock_exit_w(registry->entries_lock);

    if (cs)
        io_cs_free(cs);
    return result;
}

//
// Updates an entry in the registry
//
static int32_t prx_ns_generic_registry_entry_update(
    void* context,
    prx_ns_entry_t* entry
)
{
    int32_t result;
    io_ref_t id;
    io_cs_t* cs = NULL;
    prx_ns_generic_entry_t* next, *update;
    prx_ns_generic_registry_t* registry = (prx_ns_generic_registry_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(entry);

    result = prx_ns_entry_get_addr(entry, &id);
    if (result != er_ok)
        return result;
    rw_lock_enter_w(registry->entries_lock);
    do
    {
        // Simply find the entry, remove and add new one
        next = NULL;
        result = er_not_found;
        for (PDLIST_ENTRY p = registry->entries.Flink; p != &registry->entries; p = p->Flink)
        {
            next = containingRecord(p, prx_ns_generic_entry_t, link);
            if (!io_ref_equals(&next->id, &id))
                continue;
            result = er_ok;
            break;
        }
        if (result != er_ok)
            break;
        dbg_assert_ptr(next);
        result = prx_ns_entry_get_cs(entry, &cs);
        if (result != er_ok)
            break;
        result = prx_ns_generic_entry_create(
            prx_ns_entry_get_type(entry), &id, prx_ns_entry_get_name(entry), cs, &update);
        if (result != er_ok)
            break;
        DList_RemoveEntryList(&next->link);
        DList_InsertTailList(&registry->entries, &next->link);
        prx_ns_generic_entry_free(next);
        (void)prx_ns_generic_registry_save(registry);
        break;
    } while (0);
    rw_lock_exit_w(registry->entries_lock);

    if (cs)
        io_cs_free(cs);
    return result;
}

//
// Get entry for id
//
static int32_t prx_ns_generic_registry_entry_by_addr(
    void* context,
    io_ref_t* id,
    prx_ns_entry_t** created
)
{
    int32_t result;
    prx_ns_generic_entry_t* next;
    prx_ns_generic_registry_t* registry = (prx_ns_generic_registry_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(id);
    dbg_assert_ptr(created);

    rw_lock_enter(registry->entries_lock);
    for (PDLIST_ENTRY p = registry->entries.Flink; p != &registry->entries; p = p->Flink)
    {
        next = containingRecord(p, prx_ns_generic_entry_t, link);
        if (!io_ref_equals(&next->id, id))
            continue;

        result = prx_ns_generic_entry_clone(next, created);
        rw_lock_exit(registry->entries_lock);
        return result;
    }
    rw_lock_exit(registry->entries_lock);
    return er_not_found;
}

//
// Get entries that have the given name
//
static int32_t prx_ns_generic_registry_entry_by_name(
    void* context,
    const char* name,
    prx_ns_result_t** created
)
{
    int32_t result;
    prx_ns_generic_entry_t* next;
    prx_ns_entry_t* clone;
    prx_ns_generic_resultset_t* resultset;
    prx_ns_generic_registry_t* registry = (prx_ns_generic_registry_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(name);
    dbg_assert_ptr(created);

    result = prx_ns_generic_resultset_create(&resultset);
    if (result != er_ok)
        return result;

    result = er_not_found;
    rw_lock_enter(registry->entries_lock);
    for (PDLIST_ENTRY p = registry->entries.Flink; p != &registry->entries; p = p->Flink)
    {
        next = containingRecord(p, prx_ns_generic_entry_t, link);
        if (0 != STRING_compare_c_str_nocase(next->name, name))
            continue;

        result = prx_ns_generic_entry_clone(next, &clone);
        if (result != er_ok)
            break;
        prx_ns_generic_resultset_add(resultset, (prx_ns_generic_entry_t*)clone->context);
    }
    rw_lock_exit(registry->entries_lock);

    if (result == er_ok)
    {
        *created = &resultset->itf;
        return er_ok;
    }
    prx_ns_generic_resultset_free(resultset);
    return result;
}

//
// Get all entries with specified type
//
static int32_t prx_ns_generic_registry_entry_by_type(
    void* context,
    uint32_t type,
    prx_ns_result_t** created
)
{
    int32_t result;
    prx_ns_generic_entry_t* next;
    prx_ns_entry_t* clone;
    prx_ns_generic_resultset_t* resultset;
    prx_ns_generic_registry_t* registry = (prx_ns_generic_registry_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(created);

    result = prx_ns_generic_resultset_create(&resultset);
    if (result != er_ok)
        return result;

    result = er_not_found;
    rw_lock_enter(registry->entries_lock);
    for (PDLIST_ENTRY p = registry->entries.Flink; p != &registry->entries; p = p->Flink)
    {
        next = containingRecord(p, prx_ns_generic_entry_t, link);
        if (type != (next->type & type))
            continue;

        result = prx_ns_generic_entry_clone(next, &clone);
        if (result != er_ok)
            break;
        prx_ns_generic_resultset_add(resultset, (prx_ns_generic_entry_t*)clone->context);
    }
    rw_lock_exit(registry->entries_lock);

    if (result == er_ok)
    {
        *created = &resultset->itf;
        return er_ok;
    }
    prx_ns_generic_resultset_free(resultset);
    return result;
}

//
// Close hub database
//
static void prx_ns_generic_registry_close(
    void* context
)
{
    prx_ns_generic_registry_t* registry = (prx_ns_generic_registry_t*)context;
    dbg_assert_ptr(registry);

    if (registry->entries_lock)
        rw_lock_enter_w(registry->entries_lock);

    prx_ns_generic_registry_clear(registry);

    if (registry->entries_lock)
    {
        rw_lock_exit_w(registry->entries_lock);
        rw_lock_free(registry->entries_lock);
    }

    if (registry->file_name)
        pal_free_path(registry->file_name);

    mem_free_type(prx_ns_generic_registry_t, registry);
}

//
// Translate a rest status code to a pi error
//
static int32_t prx_ns_iot_hub_rest_status_code_to_prx_error(
    int32_t status_code
)
{
    switch (status_code)
    {
    case 200:
    case 201:
    case 204:
        return er_ok;
    case 400:
        return er_invalid_format;
    case 401:
        return er_permission; // Unauthorized
    case 403:
        return er_busy; // Quota exceeded
    case 404:
        return er_not_found;
    case 409:
    case 412:
        return er_already_exists;
    case 429:
        return er_retry; // Throttling error
    case 500:
        return er_fatal;
    case 503:
        return er_network;
    default:
        dbg_assert(0, "Unknown status code");
        return er_unknown;
    }
}

//
// Make REST call
//
static int32_t prx_ns_iot_hub_rest_call(
    io_cs_t* spec,
    HTTPAPI_REQUEST_TYPE type,
    const char* if_match,
    const char* uri,
    BUFFER_HANDLE request,
    HTTP_HEADERS_HANDLE req_headers,
    BUFFER_HANDLE response,
    HTTP_HEADERS_HANDLE resp_headers,
    int32_t* status_code
)
{
    int32_t result;
    HTTPAPIEX_RESULT http_result;
    HTTPAPIEX_HANDLE http_handle = NULL;
    HTTP_HEADERS_HANDLE request_headers = NULL, response_headers = NULL;
    HTTPAPIEX_SAS_HANDLE sas_handle = NULL;
    STRING_HANDLE path = NULL, key = NULL, key_name = NULL, request_id = NULL;

    dbg_assert_ptr(spec);
    dbg_assert_ptr(uri);
    dbg_assert_ptr(status_code);

    do
    {
        result = er_out_of_memory;
        path = STRING_construct(io_cs_get_host_name(spec));
        if (!path || 0 != STRING_concat(path, uri))
            break;

        key_name = STRING_construct(io_cs_get_shared_access_key_name(spec));
        key = STRING_construct(io_cs_get_shared_access_key(spec));
        sas_handle = HTTPAPIEX_SAS_Create(key, path, key_name);
        if (!sas_handle)
            break;

        if (!req_headers)
        {
            request_headers = req_headers = HTTPHeaders_Alloc();
            if (!request_headers)
                break;
        }

        if (!resp_headers)
        {
            response_headers = resp_headers= HTTPHeaders_Alloc();
            if (!response_headers)
                break;
        }

        request_id = STRING_construct_uuid();
        if (!request_id)
            break;

        if (0 != HTTPHeaders_AddHeaderNameValuePair(
                req_headers, "Authorization", " ") ||
            0 != HTTPHeaders_AddHeaderNameValuePair(
                req_headers, "Request-Id", STRING_c_str(request_id)) ||
            0 != HTTPHeaders_AddHeaderNameValuePair(
                req_headers, "User-Agent", "Microsoft.Azure.Devices/1.0.0") ||
            0 != HTTPHeaders_AddHeaderNameValuePair(
                req_headers, "Content-Type", "application/json; charset=utf-8"))
            break;

        if (if_match)
        {
            STRING_delete(path);
            path = STRING_construct("\"");
            if (!path)
                break;
            if (0 != STRING_concat(path, if_match) ||
                0 != STRING_concat(path, "\"") ||
                0 != HTTPHeaders_AddHeaderNameValuePair(
                    req_headers, "If-Match", STRING_c_str(path)))
                break;
        }

        STRING_delete(path);
        path = STRING_construct(uri);
        if (!path || 0 != STRING_concat(path, "?api-version=" API_VERSION))
            break;

        // Now make request
        http_handle = HTTPAPIEX_Create(io_cs_get_host_name(spec));
        if (!http_handle)
            break;

        http_result = HTTPAPIEX_SAS_ExecuteRequest(sas_handle, http_handle, type,
            STRING_c_str(path), req_headers,
            request, (unsigned int*)status_code, resp_headers, response);
        if (http_result != HTTPAPIEX_OK)
        {
            result = er_connecting;
            break;
        }

        if (*status_code == 429)
            result = er_retry;
        else
            result = er_ok;

    } while (result == er_retry);

    if (key)
        STRING_delete(key);
    if (key_name)
        STRING_delete(key_name);
    if (path)
        STRING_delete(path);
    if (request_id)
        STRING_delete(request_id);
    if (request_headers)
        HTTPHeaders_Free(request_headers);
    if (response_headers)
        HTTPHeaders_Free(response_headers);
    if (sas_handle)
        HTTPAPIEX_SAS_Destroy(sas_handle);
    if (http_handle)
        HTTPAPIEX_Destroy(http_handle);

    return result;
}

//
// Get entry connection string by unique db id
//
static int32_t prx_ns_iot_hub_twin_entry_get_cs(
    void* context,
    io_cs_t** created
)
{
    prx_ns_iot_hub_twin_entry_t* entry = (prx_ns_iot_hub_twin_entry_t*)context;

    if (!entry->registry)
        return er_arg;

    dbg_assert_ptr(entry);
    dbg_assert_ptr(created);

    int32_t result = er_out_of_memory;
    BUFFER_HANDLE response = NULL;
    STRING_HANDLE uri = NULL;
    JSON_Value* json = NULL;
    int32_t status_code;
    const char* key;

    response = BUFFER_new();
    if (!response)
        return er_out_of_memory;
    do
    {
        uri = STRING_construct("/devices/");
        if (!uri || STRING_concat(uri, prx_ns_entry_get_id(&entry->itf)))
            break;

        result = prx_ns_iot_hub_rest_call(entry->registry->hub_entry->cs, 
            HTTPAPI_REQUEST_GET, false, STRING_c_str(uri), NULL, NULL,
            response, NULL, &status_code);
        if (result != er_ok)
            break;

        // Make sure it is a string
        if (0 != BUFFER_enlarge(response, 1))
        {
            result = er_out_of_memory;
            break;
        }
        BUFFER_u_char(response)[BUFFER_length(response) - 1] = 0;

        result = prx_ns_iot_hub_rest_status_code_to_prx_error(status_code);
        if (result != er_ok)
        {
            log_error(NULL, "REST call returned %d : %s", status_code,
                (char*)BUFFER_u_char(response));
            break;
        }

        // Parse response
        result = er_not_found;
        json = json_parse_string((char*)BUFFER_u_char(response));
        if (!json)
            break;

        key = json_object_dotget_string(json_value_get_object(json),
            "authentication.symmetricKey.primaryKey");
        if (!key)
            break;

        result = io_cs_create(io_cs_get_host_name(entry->registry->hub_entry->cs), 
            prx_ns_entry_get_id(&entry->itf), NULL, key, created);
    } while (0);

    if (response)
        BUFFER_delete(response);
    if (json)
        json_value_free(json);
    if (uri)
        STRING_delete(uri);
    return result;
}

//
// Returns id of entry, which is device id and part of twin
//
static const char* prx_ns_iot_hub_twin_entry_get_id(
    void* context
)
{
    JSON_Object* obj;
    dbg_assert_ptr(context);

    obj = json_value_get_object(((prx_ns_iot_hub_twin_entry_t*)context)->twin);
    dbg_assert_ptr(obj);
    return json_object_get_string(obj, "deviceId");
}

//
// Returns name of entry, which is part of twin
//
static const char* prx_ns_iot_hub_twin_entry_get_name(
    void* context
)
{
    JSON_Object* obj;
    dbg_assert_ptr(context);

    obj = json_value_get_object(((prx_ns_iot_hub_twin_entry_t*)context)->twin);
    dbg_assert_ptr(obj);
    return json_object_dotget_string(obj, "tags.name");
}

//
// Returns index of entry, which is part of twin
//
static int32_t prx_ns_iot_hub_twin_entry_get_index(
    void* context
)
{
    dbg_assert_ptr(context);
    return (int32_t)(intptr_t)context;
}

//
// Returns type of entry, persisted as part of twin
//
static uint32_t prx_ns_iot_hub_twin_entry_get_type(
    void* context
)
{
    JSON_Object* obj;
    dbg_assert_ptr(context);

    obj = json_value_get_object(((prx_ns_iot_hub_twin_entry_t*)context)->twin);
    dbg_assert_ptr(obj);
    return (uint32_t)json_object_dotget_number(obj, "tags.type");
}

//
// Returns id of entry, which is part of twin
//
static int32_t prx_ns_iot_hub_twin_entry_get_addr(
    void* context,
    io_ref_t* id
)
{
    JSON_Object* obj;
    const char* id_string;
    dbg_assert_ptr(context);

    obj = json_value_get_object(((prx_ns_iot_hub_twin_entry_t*)context)->twin);
    dbg_assert_ptr(obj);

    id_string = json_object_dotget_string(obj, "tags.id");
    if (!id_string)
        return er_not_found;
    return io_ref_from_string(id_string, id);
}

//
// Returns a new generic entry representing the hub
//
static int32_t prx_ns_iot_hub_twin_entry_get_links(
    void* context,
    prx_ns_result_t** created
)
{
    int32_t result;
    prx_ns_generic_resultset_t* links;
    prx_ns_iot_hub_twin_entry_t *entry = (prx_ns_iot_hub_twin_entry_t*)context;
    prx_ns_entry_t* clone;

    if (0 == (prx_ns_iot_hub_twin_entry_get_type(entry) & 
        (prx_ns_entry_type_proxy | prx_ns_entry_type_host)))
        return er_not_found;

    result = prx_ns_generic_resultset_create(&links);
    if (result != er_ok)
        return result;
    do
    {
        result = prx_ns_generic_entry_clone(entry->registry->hub_entry, &clone);
        if (result != er_ok)
            break;
        // Set the entries device id
        result = io_cs_set_device_id(((prx_ns_generic_entry_t*)clone->context)->cs, 
            prx_ns_iot_hub_twin_entry_get_id(entry));
        if (result != er_ok)
            break;
        prx_ns_generic_resultset_add(links, (prx_ns_generic_entry_t*)clone->context);
        *created = &links->itf;
        return er_ok;
    } 
    while (0);
    prx_ns_generic_resultset_free(links);
    return result;
}

//
// Add route entry to this entry
//
static int32_t prx_ns_iot_hub_twin_entry_add_route(
    void* context,
    prx_ns_entry_t* route
)
{
    (void)context, route;
    return er_not_impl;
}

//
// Returns routing proxys for host, start to iterate
//
static int32_t prx_ns_iot_hub_twin_entry_get_routes(
    void* context,
    prx_ns_result_t** routes
)
{
    (void)context, routes;
    return er_not_found;
}

//
// Free entry
//
static void prx_ns_iot_hub_twin_entry_free(
    void* context
)
{
    prx_ns_iot_hub_twin_entry_t* entry = (prx_ns_iot_hub_twin_entry_t*)context;
    dbg_assert_ptr(entry);
    if (entry->twin)
        json_value_free(entry->twin);
    mem_free_type(prx_ns_iot_hub_twin_entry_t, entry);
}

//
// Helper to reconstitute an entry
//
static int32_t prx_ns_iot_hub_twin_entry_create(
    prx_ns_iot_hub_registry_t* db,
    JSON_Value* twin,
    prx_ns_iot_hub_twin_entry_t** created
);

//
// Deep clone entry
//
static int32_t prx_ns_iot_hub_twin_entry_clone(
    void* context,
    prx_ns_entry_t** clone
)
{
    int32_t result;
    prx_ns_iot_hub_twin_entry_t* entry, *orig = (prx_ns_iot_hub_twin_entry_t*)context;

    dbg_assert_ptr(orig);
    dbg_assert_ptr(clone);

    result = prx_ns_iot_hub_twin_entry_create(orig->registry, orig->twin, &entry);
    if (result != er_ok)
        return result;

    *clone = &entry->itf;
    return er_ok;
}

//
// Helper to reconstitute an entry
//
static int32_t prx_ns_iot_hub_twin_entry_create(
    prx_ns_iot_hub_registry_t* db,
    JSON_Value* twin,
    prx_ns_iot_hub_twin_entry_t** created
)
{
    int32_t result;
    prx_ns_iot_hub_twin_entry_t* entry;

    dbg_assert_ptr(db);
    dbg_assert_ptr(twin);
    dbg_assert_ptr(created);

    entry = mem_zalloc_type(prx_ns_iot_hub_twin_entry_t);
    if (!entry)
        return er_out_of_memory;

    do
    {
        DList_InitializeListHead(&entry->link);
        entry->registry = db;

        entry->twin = json_value_deep_copy(twin);
        if (!entry->twin)
        {
            result = er_out_of_memory;
            break;
        }

        entry->itf.context =
            entry;
        entry->itf.clone =
            prx_ns_iot_hub_twin_entry_clone;
        entry->itf.release =
            prx_ns_iot_hub_twin_entry_free;
        entry->itf.get_addr =
            prx_ns_iot_hub_twin_entry_get_addr;
        entry->itf.get_cs =
            prx_ns_iot_hub_twin_entry_get_cs;
        entry->itf.get_id =
            prx_ns_iot_hub_twin_entry_get_id;
        entry->itf.get_index =
            prx_ns_iot_hub_twin_entry_get_index;
        entry->itf.get_name =
            prx_ns_iot_hub_twin_entry_get_name;
        entry->itf.get_routes =
            prx_ns_iot_hub_twin_entry_get_routes;
        entry->itf.add_route =
            prx_ns_iot_hub_twin_entry_add_route;
        entry->itf.get_links =
            prx_ns_iot_hub_twin_entry_get_links;
        entry->itf.get_type =
            prx_ns_iot_hub_twin_entry_get_type;

        *created = entry;
        return er_ok;
    } while (0);

    prx_ns_iot_hub_twin_entry_free(entry);
    return result;
}

//
// Delete an entry from registry
//
static int32_t prx_ns_iot_hub_registry_entry_delete(
    void* context,
    prx_ns_entry_t* entry
)
{
    int32_t result;
    STRING_HANDLE uri = NULL;
    int32_t status_code;
    prx_ns_iot_hub_registry_t* registry = (prx_ns_iot_hub_registry_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(entry);

    do
    {
        result = er_out_of_memory;
        uri = STRING_construct("/devices/");
        if (!uri || 0 != STRING_concat(uri, prx_ns_entry_get_id(entry)))
            break;

        // Delete
        result = prx_ns_iot_hub_rest_call(registry->hub_entry->cs, HTTPAPI_REQUEST_DELETE,
            "*", STRING_c_str(uri), NULL, NULL, NULL, NULL, &status_code);
        if (result != er_ok)
            break;
        result = prx_ns_iot_hub_rest_status_code_to_prx_error(status_code);
        break;
    } while (0);

    if (uri)
        STRING_delete(uri);
    return result;
}

//
// Update entry tag properties of twin entry
//
static int32_t prx_ns_iot_hub_registry_entry_update(
    void* context,
    prx_ns_entry_t* entry
)
{
    int32_t result = er_out_of_memory;
    BUFFER_HANDLE request = NULL;
    JSON_Object* obj;
    JSON_Value* json = NULL;
    STRING_HANDLE uri = NULL, id_string = NULL;
    int32_t status_code;
    uint32_t type;
    io_ref_t id;
    const char* name;
    prx_ns_iot_hub_registry_t* registry = (prx_ns_iot_hub_registry_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(entry);

    request = BUFFER_new();
    if (!request)
        return er_out_of_memory;
    do
    {
        uri = STRING_construct("/twins/");
        if (!uri || 0 != STRING_concat(uri, prx_ns_entry_get_id(entry)))
            break;

        json = json_value_init_object();
        if (!json)
            break;
        obj = json_value_get_object(json);
        if (!obj)
            break;

        type = prx_ns_entry_get_type(entry);
        if (0 != json_object_dotset_number(obj, "tags.type", (type & ~prx_ns_entry_type_startup)))
            break;

        // No support for bit queries ...
        if (type & prx_ns_entry_type_proxy &&
            0 != json_object_dotset_number(obj, "tags.proxy", 1))
            break;
        if (type & prx_ns_entry_type_host &&
            0 != json_object_dotset_number(obj, "tags.host", 1))
            break;
        if (type & prx_ns_entry_type_link &&
            0 != json_object_dotset_number(obj, "tags.link", 1))
            break;

        result = prx_ns_entry_get_addr(entry, &id);
        if (result != er_ok)
            break;
        id_string = io_ref_to_STRING(&id);
        if (!id_string ||
            0 != json_object_dotset_string(obj, "tags.id", STRING_c_str(id_string)))
            break;
        name = prx_ns_entry_get_name(entry);
        if (name &&
            0 != json_object_dotset_string(obj, "tags.name", name))
            break;

        // Patch existing document
        if (0 != BUFFER_enlarge(request, json_serialization_size(json) + 1) ||
            0 != json_serialize_to_buffer(
                json, (char*)BUFFER_u_char(request), BUFFER_length(request)))
            break;
        result = prx_ns_iot_hub_rest_call(registry->hub_entry->cs, HTTPAPI_REQUEST_PATCH, 
            "*", STRING_c_str(uri), request, NULL, NULL, NULL, &status_code);
        if (result != er_ok)
            break;
        result = prx_ns_iot_hub_rest_status_code_to_prx_error(status_code);
        break;
    } while (0);

    if (json)
        json_value_free(json);
    if (request)
        BUFFER_delete(request);
    if (id_string)
        STRING_delete(id_string);
    if (uri)
        STRING_delete(uri);
    return result;
}

//
// Create a new entry in iothub
//
static int32_t prx_ns_iot_hub_registry_entry_create(
    void* context,
    prx_ns_entry_t* entry
)
{
    int32_t result;
    BUFFER_HANDLE request = NULL;
    JSON_Object* obj;
    JSON_Value*json = NULL;
    STRING_HANDLE id = NULL, uri = NULL;
    int32_t status_code;
    prx_ns_iot_hub_registry_t* registry = (prx_ns_iot_hub_registry_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(entry);

    do
    {
        result = er_out_of_memory;
        request = BUFFER_new();
        if (!request)
            break;
        uri = STRING_construct("/devices/");
        if (!uri || 0 != STRING_concat(uri, prx_ns_entry_get_id(entry)))
            break;
        json = json_value_init_object();
        if (!json)
            break;
        obj = json_value_get_object(json);
        if (!obj || 
            0 != json_object_set_string(obj, "deviceId", prx_ns_entry_get_id(entry)))
            break;
        if (0 != BUFFER_enlarge(request, json_serialization_size(json) + 1) ||
            0 != json_serialize_to_buffer(json, 
                (char*)BUFFER_u_char(request), BUFFER_length(request)))
            break;
        result = prx_ns_iot_hub_rest_call(registry->hub_entry->cs, HTTPAPI_REQUEST_PUT,
            NULL, STRING_c_str(uri), request, NULL, NULL, NULL, &status_code);
        if (result != er_ok)
            break;
        result = prx_ns_iot_hub_rest_status_code_to_prx_error(status_code);
        if (result != er_ok && result != er_already_exists)
            break;
        result = prx_ns_iot_hub_registry_entry_update(registry, entry);
        break;
    } while (0);

    if (json)
        json_value_free(json);
    if (request)
        BUFFER_delete(request);
    if (uri)
        STRING_delete(uri);
    if (id)
        STRING_delete(id);
    return result;
}

//
// Get entry for id
//
static int32_t prx_ns_iot_hub_registry_entry_query(
    prx_ns_iot_hub_registry_t* registry,
    const char* query_string,
    prx_ns_generic_resultset_t** created
)
{
    int32_t result;
    prx_ns_generic_resultset_t* list;
    prx_ns_iot_hub_twin_entry_t* entry;
    BUFFER_HANDLE response = NULL;
    BUFFER_HANDLE request = NULL;
    STRING_HANDLE json_query_spec = NULL;
    JSON_Value* json = NULL;
    JSON_Array* query_result;
    HTTP_HEADERS_HANDLE request_headers = NULL, response_headers = NULL;
    const char* continuation = NULL;
    int32_t status_code;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(query_string);
    dbg_assert_ptr(created);

    result = prx_ns_generic_resultset_create(&list);
    if (result != er_ok)
        return result;
    while (true)
    {
#define CONTINUATION_KEY "x-ms-continuation"
        result = er_out_of_memory;
        do
        {
            request_headers = HTTPHeaders_Alloc();
            response_headers = HTTPHeaders_Alloc();
            if (!request_headers || !response_headers)
                break;

            // Create query document
            json_query_spec = STRING_construct(
                "{"
                "\"query\": \"");
            if (!json_query_spec ||
                0 != STRING_concat(json_query_spec, query_string) ||
                0 != STRING_concat(json_query_spec,
                    "\" }"))
                break;

            if (continuation && 0 != HTTPHeaders_AddHeaderNameValuePair(request_headers, 
                CONTINUATION_KEY, continuation))
                break;

            request = BUFFER_new();
            if (!request || 0 != BUFFER_build(request,
                (const unsigned char*)STRING_c_str(json_query_spec),
                STRING_length(json_query_spec) + 1))
                break;

            response = BUFFER_new();
            if (!response)
                break;

            result = prx_ns_iot_hub_rest_call(registry->hub_entry->cs, HTTPAPI_REQUEST_POST,
                false, "/devices/query", request, request_headers, response, response_headers,
                &status_code);
            if (result != er_ok)
                break;

            // Make sure it is a string
            result = er_out_of_memory;
            if (0 != BUFFER_enlarge(response, 1))
                break;
            BUFFER_u_char(response)[BUFFER_length(response) - 1] = 0;

            result = prx_ns_iot_hub_rest_status_code_to_prx_error(status_code);
            if (result != er_ok)
            {
                log_error(NULL, "REST call returned %d : %s", status_code,
                    (char*)BUFFER_u_char(response));
                break;
            }

            // Parse response
            result = er_invalid_format;
            json = json_parse_string((char*)BUFFER_u_char(response));
            if (!json)
                break;

            query_result = json_value_get_array(json);
            if (!query_result)
                break;

            // Add items to list 
            result = er_not_found;
            for (size_t i = 0; i < json_array_get_count(query_result); i++)
            {
                result = prx_ns_iot_hub_twin_entry_create(
                    registry, json_array_get_value(query_result, i), &entry);
                if (result != er_ok)
                    break;
                prx_ns_generic_resultset_add(list, (prx_ns_generic_entry_t*)entry);
            }

            // Extract continuation header value
            continuation = HTTPHeaders_FindHeaderValue(response_headers, CONTINUATION_KEY);
        }
        while (0);

        if (json)
            json_value_free(json);
        if (json_query_spec)
            STRING_delete(json_query_spec);
        if (request)
            BUFFER_delete(request);
        if (response)
            BUFFER_delete(response);
        if (request_headers)
            HTTPHeaders_Free(request_headers);
        if (response_headers)
            HTTPHeaders_Free(response_headers);

        if (result != er_ok)
            break;

        if (!continuation)
        {
            *created = list;
            return er_ok;
        }
        // continue if we had continuation token in response
    }

    if (list)
        prx_ns_generic_resultset_free(list);
    return result;
}

//
// Get entry for id
//
static int32_t prx_ns_iot_hub_registry_entry_by_addr(
    void* context,
    io_ref_t* id,
    prx_ns_entry_t** created
)
{
    int32_t result;
    prx_ns_generic_resultset_t* results = NULL;
    STRING_HANDLE sql_query_string = NULL;
    prx_ns_iot_hub_registry_t* registry = (prx_ns_iot_hub_registry_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(id);
    dbg_assert_ptr(created);

    sql_query_string = STRING_construct(
        "SELECT * FROM devices WHERE tags.id='");
    if (!sql_query_string)
        return er_out_of_memory;
    do
    {
        // Address query parameter
        result = io_ref_append_to_STRING(id, sql_query_string);
        if (result != er_ok)
            break;

        if (0 != STRING_concat(sql_query_string, "'"))
        {
            result = er_out_of_memory;
            break;
        }

        result = prx_ns_iot_hub_registry_entry_query(
            registry, STRING_c_str(sql_query_string), &results);
        if (result != er_ok)
            break;
        if (prx_ns_generic_resultset_size(results) == 0)
        {
            result = er_not_found;
            break;
        }
        dbg_assert(prx_ns_generic_resultset_size(results) == 1,
            "More than 1 result returned");

        *created = prx_ns_generic_resultset_pop(results);
        break;
    } 
    while (0);

    if (results)
        prx_ns_generic_resultset_free(results);
    STRING_delete(sql_query_string);
    return result;
}

//
// Get all entries with given name
//
static int32_t prx_ns_iot_hub_registry_entry_by_name(
    void* context,
    const char* name,
    prx_ns_result_t** created
)
{
    int32_t result;
    STRING_HANDLE sql_query_string = NULL;
    prx_ns_iot_hub_registry_t* registry = (prx_ns_iot_hub_registry_t*)context;
    prx_ns_generic_resultset_t* results;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(name);
    dbg_assert_ptr(created);

    sql_query_string = STRING_construct(
        "SELECT * FROM devices WHERE tags.name='");
    if (!sql_query_string)
        return er_out_of_memory;
    do
    {
        // Name query parameter
        if (0 != STRING_concat(sql_query_string, name) ||
            0 != STRING_concat(sql_query_string, "'"))
        {
            result = er_out_of_memory;
            break;
        }

        result = prx_ns_iot_hub_registry_entry_query(
            registry, STRING_c_str(sql_query_string), &results);
        if (result != er_ok)
            break;

        *created = &results->itf;
        break;
    } 
    while (0);

    STRING_delete(sql_query_string);
    return result;
}

//
// Get all entries with specified type
//
static int32_t prx_ns_iot_hub_registry_entry_by_type(
    void* context,
    uint32_t type,
    prx_ns_result_t** created
)
{
    int32_t result;
    STRING_HANDLE sql_query_string = NULL;
    bool logic_concat = false;
    prx_ns_iot_hub_registry_t* registry = (prx_ns_iot_hub_registry_t*)context;
    prx_ns_generic_resultset_t* results;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(created);

    sql_query_string = STRING_construct(
        "SELECT * FROM devices WHERE ");
    if (!sql_query_string)
        return er_out_of_memory;
    do
    {
        result = er_out_of_memory;

        // No support for bit queries ...
        if (type & prx_ns_entry_type_proxy)
        {
            if (0 != STRING_concat(sql_query_string, "tags.proxy=1"))
                break;
            logic_concat = true;
        }
        if (type & prx_ns_entry_type_host)
        {
            if ((logic_concat &&
                0 != STRING_concat(sql_query_string, " OR ")) ||
                0 != STRING_concat(sql_query_string, "tags.host=1"))
                break;
            logic_concat = true;
        }
        if (type & prx_ns_entry_type_link)
        {
            if ((logic_concat &&
                0 != STRING_concat(sql_query_string, " OR ")) || 
                0 != STRING_concat(sql_query_string, "tags.link=1"))
                break;
            logic_concat = true;
        }

        if (!logic_concat)
        {
            // Type passed did not yield anything to look for, dont even bother
            result = er_not_found;
            break;
        }

        result = prx_ns_iot_hub_registry_entry_query(
            registry, STRING_c_str(sql_query_string), &results);
        if (result != er_ok)
            break;

        *created = &results->itf;
        break;
    } 
    while (0);

    STRING_delete(sql_query_string);
    return result;
}

//
// Close hub database
//
static void prx_ns_iot_hub_registry_close(
    void* context
)
{
    prx_ns_iot_hub_registry_t* registry = (prx_ns_iot_hub_registry_t*)context;
    dbg_assert_ptr(registry);

    if (registry->hub_entry)
        prx_ns_entry_release(&registry->hub_entry->itf);

    mem_free_type(prx_ns_iot_hub_registry_t, registry);
}

//
// Delete an entry from all hubs
//
static int32_t prx_ns_iot_hub_composite_entry_delete(
    void* context,
    prx_ns_entry_t* entry
)
{
    int32_t result, composite_result;
    prx_ns_iot_hub_registry_t* next;
    prx_ns_iot_hub_composite_t* registry = (prx_ns_iot_hub_composite_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(entry);

    composite_result = er_not_found;
    for (PDLIST_ENTRY p = registry->hubs.Flink; p != &registry->hubs; p = p->Flink)
    {
        next = containingRecord(p, prx_ns_iot_hub_registry_t, link);

        result = prx_ns_iot_hub_registry_entry_delete(next, entry);
        if (result != er_not_found)
            composite_result = result;
    }
    return composite_result;
}

//
// Create entry in the first hub we can connect to
//
static int32_t prx_ns_iot_hub_composite_entry_create(
    void* context,
    prx_ns_entry_t* entry
)
{
    int32_t result;
    prx_ns_iot_hub_registry_t* next;
    prx_ns_iot_hub_composite_t* registry = (prx_ns_iot_hub_composite_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(entry);

    result = er_not_supported;
    for (PDLIST_ENTRY p = registry->hubs.Flink; p != &registry->hubs; p = p->Flink)
    {
        next = containingRecord(p, prx_ns_iot_hub_registry_t, link);

        result = prx_ns_iot_hub_registry_entry_create(next, entry);
        if (result == er_connecting)
            continue;
        else
            break;
    }
    return result;
}

//
// Updates an entry in the hub it belongs in
//
static int32_t prx_ns_iot_hub_composite_entry_update(
    void* context,
    prx_ns_entry_t* entry
)
{
    int32_t result;
    io_ref_t id;
    prx_ns_iot_hub_registry_t* next;
    prx_ns_entry_t* tmp;
    prx_ns_iot_hub_composite_t* registry = (prx_ns_iot_hub_composite_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(entry);

    result = prx_ns_entry_get_addr(entry, &id);
    if (result != er_ok)
        return result;
    for (PDLIST_ENTRY p = registry->hubs.Flink; p != &registry->hubs; p = p->Flink)
    {
        next = containingRecord(p, prx_ns_iot_hub_registry_t, link);

        result = prx_ns_iot_hub_registry_entry_by_addr(next, &id, &tmp);
        if (result != er_ok)
            continue;
        prx_ns_entry_release(tmp);
        result = prx_ns_iot_hub_registry_entry_update(next, entry);
        break;
    }
    return result;
}

//
// Get entry for id
//
static int32_t prx_ns_iot_hub_composite_entry_by_addr(
    void* context,
    io_ref_t* id,
    prx_ns_entry_t** created
)
{
    int32_t result;
    prx_ns_iot_hub_registry_t* next;
    prx_ns_iot_hub_composite_t* registry = (prx_ns_iot_hub_composite_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(id);
    dbg_assert_ptr(created);

    result = er_not_found;
    for (PDLIST_ENTRY p = registry->hubs.Flink; p != &registry->hubs; p = p->Flink)
    {
        next = containingRecord(p, prx_ns_iot_hub_registry_t, link);
        result = prx_ns_iot_hub_registry_entry_by_addr(next, id, created);
        if (result == er_ok)
            break;
    }
    return result;
}

//
// Get all entries that match the name in all hubs
//
static int32_t prx_ns_iot_hub_composite_entry_by_name(
    void* context,
    const char* name,
    prx_ns_result_t** created
)
{
    int32_t result;
    prx_ns_iot_hub_registry_t* next;
    prx_ns_result_t* entries = NULL;
    prx_ns_generic_resultset_t* resultset = NULL;
    prx_ns_iot_hub_composite_t* registry = (prx_ns_iot_hub_composite_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(name);
    dbg_assert_ptr(created);

    result = er_not_found;
    for (PDLIST_ENTRY p = registry->hubs.Flink; p != &registry->hubs; p = p->Flink)
    {
        next = containingRecord(p, prx_ns_iot_hub_registry_t, link);
        result = prx_ns_iot_hub_registry_entry_by_name(next, name, &entries);
        if (result != er_ok)
            break;
        resultset = prx_ns_generic_resultset_concat(resultset,
            (prx_ns_generic_resultset_t*)entries->context);
    }

    if (!resultset)
        return result;
    
    if (result != er_ok)
        prx_ns_generic_resultset_free(resultset);
    else
        *created = &resultset->itf;
    return result;
}

//
// Get all entries with specified type
//
static int32_t prx_ns_iot_hub_composite_entry_by_type(
    void* context,
    uint32_t type,
    prx_ns_result_t** created
)
{
    int32_t result;
    prx_ns_iot_hub_registry_t* next;
    prx_ns_result_t* entries = NULL;
    prx_ns_generic_resultset_t* resultset = NULL;
    prx_ns_iot_hub_composite_t* registry = (prx_ns_iot_hub_composite_t*)context;

    dbg_assert_ptr(registry);
    dbg_assert_ptr(created);

    result = er_not_found;
    for (PDLIST_ENTRY p = registry->hubs.Flink; p != &registry->hubs; p = p->Flink)
    {
        next = containingRecord(p, prx_ns_iot_hub_registry_t, link);
        result = prx_ns_iot_hub_registry_entry_by_type(next, type, &entries);
        if (result != er_ok)
            break;
        resultset = prx_ns_generic_resultset_concat(resultset,
            (prx_ns_generic_resultset_t*)entries->context);
    }

    if (!resultset)
        return result;
    
    if (result != er_ok)
        prx_ns_generic_resultset_free(resultset);
    else
        *created = &resultset->itf;
    return result;
}

//
// Close composite registry
//
static void prx_ns_iot_hub_composite_close(
    void* context
)
{
    prx_ns_iot_hub_composite_t* registry = (prx_ns_iot_hub_composite_t*)context;
    dbg_assert_ptr(registry);

    while (!DList_IsListEmpty(&registry->hubs))
    {
        prx_ns_iot_hub_registry_close(containingRecord(
            DList_RemoveHeadList(&registry->hubs), prx_ns_iot_hub_registry_t, link));
    }

    mem_free_type(prx_ns_iot_hub_composite_t, registry);
}

//
// Decode composite registry
//
static int32_t prx_ns_iot_hub_composite_decode(
    io_codec_ctx_t* ctx,
    prx_ns_iot_hub_composite_t* registry
)
{
    int32_t result;
    io_codec_ctx_t arr, obj;
    prx_ns_t* next;
    size_t num_hubs;
    io_cs_t* cs;
    do
    {
        __io_decode_type_begin(ctx, registry, 1);

        dbg_assert(DList_IsListEmpty(&registry->hubs), "Unexpected number of hubs");
        result = io_decode_array(ctx, "hubs", &num_hubs, &arr);
        if (result != er_ok)
            break;
        for (prx_size_t i = 0; i < num_hubs; i++)
        {
            result = io_decode_object(&arr, NULL, NULL, &obj);
            if (result != er_ok)
                break;
            result = io_decode_cs(&obj, &cs);
            if (result != er_ok)
                break;
            result = prx_ns_iot_hub_create_from_cs(cs, &next);
            io_cs_free(cs);
            if (result != er_ok)
                break;
            DList_InsertTailList(&registry->hubs, 
                &((prx_ns_iot_hub_registry_t*)next->context)->link);
        }
        if (result != er_ok)
            break;
        __io_decode_type_end(ctx);
    } while (0);
    return result;
}

//
// Create generic registry
//
int32_t prx_ns_generic_create(
    const char* file_name,
    prx_ns_t** created
)
{
    int32_t result;
    prx_ns_generic_registry_t* registry;

    registry = mem_zalloc_type(prx_ns_generic_registry_t);
    if (!registry)
        return er_out_of_memory;
    do
    {
        registry->log = log_get("ns_generic");
        DList_InitializeListHead(&registry->entries);
        registry->num_entries = 0;

        result = rw_lock_create(&registry->entries_lock);
        if (result != er_ok)
            break;

        registry->itf.context =
            registry;
        registry->itf.create =
            prx_ns_generic_registry_entry_create;
        registry->itf.update =
            prx_ns_generic_registry_entry_update;
        registry->itf.remove =
            prx_ns_generic_registry_entry_delete;
        registry->itf.get_by_addr =
            prx_ns_generic_registry_entry_by_addr;
        registry->itf.get_by_type =
            prx_ns_generic_registry_entry_by_type;
        registry->itf.get_by_name =
            prx_ns_generic_registry_entry_by_name;
        registry->itf.close =
            prx_ns_generic_registry_close;

        if (!file_name)
        {
            *created = &registry->itf;
            return er_ok;
        }

        registry->file_name = pal_create_full_path(file_name);
        if (!registry->file_name)
        {
            result = er_out_of_memory;
            break;
        }

        result = prx_ns_generic_registry_load(registry);
        if (result != er_ok)
        {
            log_error(registry->log,
                "Failed to load registry from file %s (%s)",
                registry->file_name, prx_err_string(result));
        }
        *created = &registry->itf;
        return er_ok;
    } while (0);

    prx_ns_generic_registry_close(registry);
    return result;
}

//
// Create a hub registry
//
int32_t prx_ns_iot_hub_create_from_cs(
    io_cs_t* hub_cs,
    prx_ns_t** created
)
{
    int32_t result;
    prx_ns_iot_hub_registry_t* registry;

    if (!created || !hub_cs)
        return er_fault;

    registry = mem_zalloc_type(prx_ns_iot_hub_registry_t);
    if (!registry)
        return er_out_of_memory;
    do
    {
        registry->log = log_get("ns_hub");
        DList_InitializeListHead(&registry->link);

        result = prx_ns_generic_entry_create(
            prx_ns_entry_type_hub, NULL, NULL, hub_cs, &registry->hub_entry);
        if (result != er_ok)
            break;

        registry->itf.context =
            registry;
        registry->itf.create =
            prx_ns_iot_hub_registry_entry_create;
        registry->itf.update =
            prx_ns_iot_hub_registry_entry_update;
        registry->itf.remove =
            prx_ns_iot_hub_registry_entry_delete;
        registry->itf.get_by_addr =
            prx_ns_iot_hub_registry_entry_by_addr;
        registry->itf.get_by_type =
            prx_ns_iot_hub_registry_entry_by_type;
        registry->itf.get_by_name =
            prx_ns_iot_hub_registry_entry_by_name;
        registry->itf.close =
            prx_ns_iot_hub_registry_close;

        *created = &registry->itf;
        return er_ok;
    } while (0);

    prx_ns_iot_hub_registry_close(registry);
    return result;
}

//
// Create hub registry
//
int32_t prx_ns_iot_hub_create(
    const char* config,
    prx_ns_t** created
)
{
    int32_t result;
    io_cs_t* cs;
    io_codec_ctx_t ctx;
    io_file_stream_t fs;
    io_stream_t* stream = NULL;
    prx_ns_iot_hub_composite_t* registry;
    const char* file_name = NULL;

    if (!config)
        return er_fault;

    if (er_ok == io_cs_create_from_string(config, &cs))
    {
        result = prx_ns_iot_hub_create_from_cs(cs, created);
        io_cs_free(cs);
        return result;
    }

    registry = mem_zalloc_type(prx_ns_iot_hub_composite_t);
    if (!registry)
        return er_out_of_memory;
    do
    {
        registry->log = log_get("ns_composite");
        DList_InitializeListHead(&registry->hubs);

        file_name = pal_create_full_path(config);
        if (!file_name)
        {
            result = er_out_of_memory;
            break;
        }
        stream = io_file_stream_init(&fs, file_name, "r");
        if (!stream)
        {
            log_error(registry->log,
                "Could not find file %s to load registry from.", file_name);
            result = er_not_found;
            break;
        }

        result = io_codec_ctx_init(
            io_codec_by_id(io_codec_json), &ctx, stream, true, NULL);
        if (result != er_ok)
            break;

        result = prx_ns_iot_hub_composite_decode(&ctx, registry);
        (void)io_codec_ctx_fini(&ctx, stream, false);
        if (result == er_ok && DList_IsListEmpty(&registry->hubs))
            result = er_invalid_format;
        if (result != er_ok)
        {
            log_error(registry->log,
                "Failed to load registry from file %s (%s)",
                file_name, prx_err_string(result));
            break;
        }

        pal_free_path(file_name);

        registry->itf.context =
            registry;
        registry->itf.create =
            prx_ns_iot_hub_composite_entry_create;
        registry->itf.update =
            prx_ns_iot_hub_composite_entry_update;
        registry->itf.remove =
            prx_ns_iot_hub_composite_entry_delete;
        registry->itf.get_by_addr =
            prx_ns_iot_hub_composite_entry_by_addr;
        registry->itf.get_by_type =
            prx_ns_iot_hub_composite_entry_by_type;
        registry->itf.get_by_name =
            prx_ns_iot_hub_composite_entry_by_name;
        registry->itf.close =
            prx_ns_iot_hub_composite_close;

        *created = &registry->itf;
        return er_ok;
    } while (0);

    if (file_name)
        pal_free_path(file_name);
    if (stream)
        io_stream_close(stream);

    prx_ns_iot_hub_composite_close(registry);
    return result;
}

//
// Converts a host name to socket id
//
int32_t prx_ns_entry_to_prx_socket_address(
    prx_ns_entry_t* entry,
    prx_address_family_t family,
    prx_socket_address_t* socket_address
)
{
    int32_t result;
    const char* name;
    io_ref_t id;
    if (!entry || !socket_address)
        return er_fault;

    memset(socket_address, 0, sizeof(prx_socket_address_t));
    socket_address->un.family = family;
    switch (family)
    {
    case prx_address_family_proxy:
        name = prx_ns_entry_get_name(entry);
        if (!name)
            name = prx_ns_entry_get_id(entry);
        dbg_assert_ptr(name);
        name = strncpy(socket_address->un.proxy.host,
            name, sizeof(socket_address->un.proxy.host));
        dbg_assert_ptr(name);
        result = er_ok;
        break;
    case prx_address_family_unspec:
    case prx_address_family_inet6:
        socket_address->un.family = prx_address_family_inet6;
    case prx_address_family_inet:
        result = prx_ns_entry_get_addr(entry, &id);
        if (result != er_ok)
            break;
        result = io_ref_to_prx_socket_address(&id, socket_address);
        break;
    default:
        dbg_assert(0, "Not yet supported family %d", family);
        result = er_not_supported;
        break;
    }
    return result;
}

//
// Create in memory entry from connection string
//
int32_t prx_ns_entry_create_from_cs(
    uint32_t type,
    io_ref_t* address,
    io_cs_t* cs,
    prx_ns_entry_t** created
)
{
    int32_t result;
    prx_ns_generic_entry_t* entry;
        
    if (!cs || !created)
        return er_fault;

    result = prx_ns_generic_entry_create(type, address, NULL, cs, &entry);
    if (result != er_ok)
        return result;

    *created = &entry->itf;
    return er_ok;
}

//
// Create in memory entry 
//
int32_t prx_ns_entry_create(
    uint32_t type,
    const char* id,
    const char* name,
    prx_ns_entry_t** created
)
{
    int32_t result;
    prx_ns_generic_entry_t* entry;
    io_cs_t* cs;

    if (!name || !created)
        return er_fault;

    result = io_cs_create("proxy.localhost", id, NULL, NULL, &cs);
    if (result != er_ok)
        return result;
    result = prx_ns_generic_entry_create(type, NULL, name, cs, &entry);
    io_cs_free(cs);
    if (result != er_ok)
        return result;

    *created = &entry->itf;
    return er_ok;
}

//
// Create entry from a json configuration string
//
int32_t prx_ns_entry_create_from_string(
    const char* string,
    prx_ns_entry_t** entry
)
{
    int32_t result;
    io_codec_ctx_t ctx, obj;
    io_fixed_buffer_stream_t stream;
    prx_ns_generic_entry_t* generic_entry = NULL;
    io_stream_t* codec_stream;

    codec_stream = io_fixed_buffer_stream_init(
        &stream, (uint8_t*)string, strlen(string)+1, NULL, 0);
    dbg_assert_ptr(codec_stream);

    result = io_codec_ctx_init(
        io_codec_by_id(io_codec_json), &ctx, codec_stream, true, NULL);
    if (result != er_ok)
        return result;
    do
    {
        result = io_decode_object(&ctx, NULL, NULL, &obj);
        if (result != er_ok)
            break;
        result = prx_ns_generic_entry_create(0, NULL, NULL, NULL, &generic_entry);
        if (result != er_ok)
            break;

        result = prx_ns_generic_entry_decode(&obj, generic_entry);
        if (result != er_ok)
            break;

        *entry = &generic_entry->itf;
        generic_entry = NULL;
        break;
    } 
    while (0);

    (void)io_codec_ctx_fini(&ctx, codec_stream, false);
    if (generic_entry)
        prx_ns_generic_entry_free(generic_entry);
    return result;
}

//
// Serialize entry to json configuration string
//
int32_t prx_ns_entry_to_STRING(
    prx_ns_entry_t* entry,
    STRING_HANDLE* string
)
{
    int32_t result;
    io_codec_ctx_t ctx, obj;
    io_dynamic_buffer_stream_t stream;
    io_stream_t* codec_stream;
    io_ref_t addr;
    prx_ns_generic_entry_t* generic_entry;
    io_cs_t* cs = NULL;

    codec_stream = io_dynamic_buffer_stream_init(&stream, NULL, 0x100);
    if (!codec_stream)
        return er_out_of_memory;
    do
    {
        result = io_codec_ctx_init(io_codec_by_id(io_codec_json),
            &ctx, codec_stream, false, NULL);
        if (result != er_ok)
            break;

        // Create generic entry from entry
        result = prx_ns_entry_get_addr(entry, &addr);
        if (result != er_ok)
            break;
        result = prx_ns_entry_get_cs(entry, &cs);
        if (result != er_ok)
            break;
        result = prx_ns_generic_entry_create(prx_ns_entry_get_type(entry), &addr,
            prx_ns_entry_get_name(entry), cs, &generic_entry);
        if (result != er_ok)
            break;

        result = io_encode_object(&ctx, NULL, false, &obj);
        if (result == er_ok)
            result = prx_ns_generic_entry_encode(&obj, generic_entry);
        if (result != er_ok)
            break;

        // Dynamic stream has no close function, so no cleanup needed
        result = io_codec_ctx_fini(&ctx, codec_stream, true);
        if (result != er_ok)
            break;

        // Ensure null terminated...
        result = io_stream_write(&stream.itf, "\0", 1);
        if (result != er_ok)
            break;

        *string = STRING_construct((const char*)stream.out);
        if (!*string)
        {
            result = er_out_of_memory;
            break;
        }
        break;
    } 
    while (0);

    if (cs)
        io_cs_free(cs);
    if (stream.out)
        mem_free(stream.out);

    return result;
}
