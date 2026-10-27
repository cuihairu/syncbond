/* syncbond.h - stable C ABI for syncbond (ABI v1).
 *
 * This is the single interface every language binding consumes. All protocol
 * logic lives in syncbond-core; this header only describes handles, byte
 * buffers and owned strings. No Rust type ever crosses the boundary.
 *
 * Conventions:
 *  - Functions returning const char * allocate the text; free it with
 *    sb_free_string(). NULL plus sb_last_error() set means the call failed.
 *  - Functions returning a byte buffer take a pointer to an sb_buffer_t,
    fill it, and the caller releases it with sb_free_buffer().
 *  - Functions returning int use SB_ERR_* codes (0 == success) unless
 *    documented otherwise.
 *  - Handles are not synchronized internally: do not touch one handle from
 *    two threads at the same time. A handle releases its resource through
 *    its sb_*_free() function, which accepts NULL.
 *  - SB_ABI_VERSION increments whenever a semantic change lands here;
 *    purely additive functions do not change it.
 */

#ifndef SYNCBOND_H
#define SYNCBOND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYNCBOND_ABI_VERSION 1u

#define SB_ERR_NONE 0
#define SB_ERR_PROTOCOL (-1)
#define SB_ERR_INPUT (-2)
#define SB_ERR_VERSION_MISMATCH (-3)
#define SB_ERR_CROSS_GROUP (-4)
#define SB_ERR_KEY_EPOCH_MISMATCH (-5)
#define SB_ERR_REPLAY (-6)
#define SB_ERR_AUTH_FAILED (-7)
#define SB_ERR_INTERNAL (-8)

/* Returned by sb_replicator_get() when the key has no live value. */
#define SB_RESULT_ABSENT 1

/* Merge strategies accepted by sb_replicator_new(). */
#define SB_STRATEGY_LWW_HLC 0u
#define SB_STRATEGY_OR_SET 1u
#define SB_STRATEGY_PN_COUNTER 2u

typedef struct sb_identity sb_identity;
typedef struct sb_pair_result sb_pair_result;
typedef struct sb_session sb_session;
typedef struct sb_replicator sb_replicator;
typedef struct sb_keyring sb_keyring;

/* Caller-owned byte buffer. Release with sb_free_buffer(). */
typedef struct sb_buffer {
    uint8_t *data;
    size_t len;
    size_t cap;
} sb_buffer_t;

/* ---------------------------------------------------------------- version */

uint32_t sb_abi_version(void);
uint32_t sb_protocol_version(void);

/* Last error of the calling thread. The pointer stays valid only until the
 * next call into this library from the same thread; copy the text at once. */
const char *sb_last_error(void);

void sb_free_string(const char *s);
void sb_free_buffer(const sb_buffer_t *buffer);

/* --------------------------------------------------------------- identity */

sb_identity *sb_identity_generate(void);

/* Import a 64-byte Ed25519 keypair. */
sb_identity *sb_identity_import(const uint8_t *secret_key, size_t len);

void sb_identity_free(sb_identity *identity);

const char *sb_identity_device_id(const sb_identity *identity);

int sb_identity_public_key(const sb_identity *identity, uint8_t out_public_key[32]);
int sb_identity_secret_key(const sb_identity *identity, uint8_t out_secret_key[64]);

/* --------------------------------------------------------------- pairing */

/* Pair two freshly generated devices over an in-memory loopback; `code` may
 * be NULL to generate one. Both sides of the handshake run inside the call. */
sb_pair_result *sb_pair_memory(const char *code);

void sb_pair_result_free(sb_pair_result *result);

const char *sb_pair_result_code(const sb_pair_result *result);

/* Each call returns a fresh handle: the caller must free both. */
sb_session *sb_pair_result_initiator(const sb_pair_result *result);
sb_session *sb_pair_result_responder(const sb_pair_result *result);

void sb_session_free(sb_session *session);

const char *sb_session_group_id(const sb_session *session);
const char *sb_session_peer_device_id(const sb_session *session);
int sb_session_invalidated(const sb_session *session);

/* Encrypt and enqueue one application payload. */
int sb_session_send(const sb_session *session, const uint8_t *payload, size_t len);

/* Blocking: decrypt and return the next application payload. */
int sb_session_recv(const sb_session *session, sb_buffer_t *out_payload);

int sb_session_invalidate(sb_session *session);

/* ------------------------------------------------------------ replication */

sb_replicator *sb_replicator_new(const char *node_id, uint32_t strategy);

/* Same as sb_replicator_new() with a frozen clock: every stamp and merge
 * check uses `now_ms`, which makes runs reproducible. 0 falls back to the
 * wall clock. */
sb_replicator *sb_replicator_new_fixed_clock(const char *node_id, uint32_t strategy, uint64_t now_ms);

void sb_replicator_free(sb_replicator *replicator);

const char *sb_replicator_node_id(const sb_replicator *replicator);
uint32_t sb_replicator_record_count(const sb_replicator *replicator);
uint32_t sb_replicator_oplog_len(const sb_replicator *replicator);

int sb_replicator_put(sb_replicator *replicator, const char *key, const uint8_t *payload, size_t len);
int sb_replicator_delete(sb_replicator *replicator, const char *key);

int sb_replicator_get(sb_replicator *replicator, const char *key, sb_buffer_t *out_payload);

/* JSON array of live keys. */
const char *sb_replicator_live_keys_json(const sb_replicator *replicator);

/* Oplog entry as wire JSON; NULL plus sb_last_error() when out of range. */
const char *sb_replicator_op_json(const sb_replicator *replicator, uint32_t index);

/* Apply one wire op. 1 when applied, 0 when it was a duplicate or rejected
 * because it would resurrect a garbage-collected delete. */
int sb_replicator_apply_remote_json(sb_replicator *replicator, const char *op_json);

/* Full-duplex oplog exchange over a paired session. Blocking in one
 * direction, so run both sides concurrently. `send_first` is the initiator. */
int sb_replicator_sync(sb_replicator *replicator, sb_session *session, int send_first,
                       uint32_t *out_sent_ops);

/* Canonical, fully sorted dump of the local state. */
const char *sb_replicator_records_json(const sb_replicator *replicator);
const char *sb_replicator_gc_barriers_json(const sb_replicator *replicator);

/* Collect tombstones older than `older_than_ms` relative to `now_ms` that are
 * also causally dominated by every known replica. Returns the number of keys
 * collected, or a negative SB_ERR_* code. */
int sb_replicator_gc_tombstones(sb_replicator *replicator, uint64_t now_ms, uint64_t older_than_ms);

/* ------------------------------------------------------------ key material */

sb_keyring *sb_keyring_new(const char *group_id);

/* Import explicit key material, as a rotated key handed to this device. */
sb_keyring *sb_keyring_import(const char *group_id, uint64_t epoch, const uint8_t key[32]);

void sb_keyring_free(sb_keyring *keyring);

uint64_t sb_keyring_epoch(const sb_keyring *keyring);

/* Mint the next epoch and copy the new 32-byte key out for distribution to
 * members that remain authorized. */
int sb_keyring_rotate(sb_keyring *keyring, uint64_t *out_epoch, uint8_t out_key[32]);

/* Seal under the keyring's current epoch; returns envelope JSON. */
const char *sb_keyring_seal_json(const sb_keyring *keyring, const char *sender_device_id,
                                 const uint8_t *plaintext, size_t len);

/* Open an envelope with the keyring's current key and epoch, enforcing
 * version, group, epoch, replay and AEAD checks in that order. */
int sb_keyring_open_json(const sb_keyring *keyring, const char *envelope_json,
                         sb_buffer_t *out_payload);

/* ------------------------------------------------------- conformance runs */

/* Run a cross-language conformance fixture and return a canonical JSON
 * report. The fixture only drives public core APIs; see
 * fixtures/consistency/README.md for the schema. */
const char *sb_conformance_run(const char *fixture_json);

#ifdef __cplusplus
}
#endif

#endif /* SYNCBOND_H */
