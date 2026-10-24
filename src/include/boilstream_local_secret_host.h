#ifndef BOILSTREAM_LOCAL_SECRET_HOST_H
#define BOILSTREAM_LOCAL_SECRET_HOST_H

#include <stddef.h>
#include <stdint.h>

/* Private embedding ABI, never exposed through SQL. The host constructs this
 * only from a completed, currently valid authentication proof. Identity fields
 * describe that owner; they cannot construct or replace it.
 *
 * A descriptor is borrowed until retain(owner). Every native session owner must
 * retain once and release once. Each request is synchronous on a native worker;
 * never call it on a Rust async executor thread or while holding session/cache
 * locks. No global callback registry, OPAQUE key or copied sequence is involved.
 *
 * Requests are strict tagged JSON using the closed LocalSecretRequest vocabulary.
 * Call validate before serving a cached credential, not only on cache misses.
 * Native installation/cache validation wiring is still pending: this ABI is
 * not an enabled product login path. */
struct BoilstreamLocalSecretReplyV1 {
    uint32_t status;
    const uint8_t *data;
    size_t length;
    void *owner;
};
struct BoilstreamLocalSecretHostV2 {
    uint32_t version;
    uint32_t size;
    uint32_t internal_user_id;
    uint32_t tenant_id;
    int64_t expires_at_us;
    const void *owner;
    void (*retain)(const void *);
    void (*release)(const void *);
    /* Returns 1 after initializing reply, 0 only for a null output pointer.
     * Requests/replies use explicit lengths. Null data is valid only at length 0.
     * Release a nonnull reply owner exactly once, including parse/error paths.
     * Output must not already own a previous response. */
    /* Second argument is this call's live duckdb::ClientContext, never a
     * shared-session value. It must remain live for the synchronous call. */
    uint8_t (*request)(const void *, void *, const uint8_t *, size_t, struct BoilstreamLocalSecretReplyV1 *);
    void (*release_reply)(void *);
};
#endif
