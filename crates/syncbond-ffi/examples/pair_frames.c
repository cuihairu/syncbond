/* pair_frames.c - pure C consumer of the externally driven pairing interface
 * (todo.md DSR-34).
 *
 * Two ends are started from two existing identities, the pairing protocol
 * frames are routed by this host (never by the library), and cancel /
 * late-frame / ownership / error semantics are exercised. Build with the
 * flags used by tests/ffi_c.rs:
 *   gcc -Wall -Werror -o pair_frames examples/pair_frames.c \
 *       -I include -L <libdir> -lsyncbond_ffi -Wl,-rpath,<libdir> -lpthread
 */

#include "syncbond.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void fail(const char *what)
{
    const char *error = sb_last_error();
    fprintf(stderr, "FAIL: %s%s%s\n", what, error && *error ? ": " : "", error && *error ? error : "");
    failures++;
}

static void expect(int condition, const char *what)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    }
}

/* Protocol frame types. The host treats frames as opaque bytes and routes
 * them; only the goodbye is asserted by type. */
#define FRAME_P_A 0x01
#define FRAME_ABORT 0x07

/* The shared short code both ends are started with. */
static const char *CODE = "K7Q2M4";

/* Pop the next outbound frame into *frame. 1 when a frame was produced, 0
 * when the outbox is empty, -1 on a library error (recorded as a failure). */
static int take(sb_pair_end *end, sb_buffer_t *frame)
{
    int status = sb_pair_end_pop_outgoing(end, frame);
    if (status == SB_ERR_NONE) {
        return 1;
    }
    if (status == SB_RESULT_ABSENT) {
        return 0;
    }
    fail("sb_pair_end_pop_outgoing");
    return -1;
}

/* One wire round: drain both outboxes, deliver every frame to the other end
 * unless that end already finished, and report whether both ends are done. A
 * finished end refuses frames, so the host stops feeding it — the state a
 * routing loop gates on is sb_pair_end_is_finished(). */
static int wire_round(sb_pair_end *a, sb_pair_end *b)
{
    sb_buffer_t frame = { NULL, 0, 0 };
    while (take(a, &frame) == 1) {
        if (!sb_pair_end_is_finished(b) &&
            sb_pair_end_push(b, frame.data, frame.len) != SB_ERR_NONE) {
            fail("route a -> b");
        }
        sb_free_buffer(&frame);
    }
    while (take(b, &frame) == 1) {
        if (!sb_pair_end_is_finished(a) &&
            sb_pair_end_push(a, frame.data, frame.len) != SB_ERR_NONE) {
            fail("route b -> a");
        }
        sb_free_buffer(&frame);
    }
    return sb_pair_end_is_finished(a) && sb_pair_end_is_finished(b);
}

/* Drive two ends to their terminal events, with a hard round bound: the
 * protocol exchanges at most six frames, so six rounds must settle it. */
static void drive_to_completion(sb_pair_end *a, sb_pair_end *b)
{
    int rounds = 0;
    while (!wire_round(a, b)) {
        rounds++;
        if (rounds > 6) {
            expect(0, "the exchange wedged");
            return;
        }
    }
}

/* Two real, separated ends complete each other and hand over sessions that
 * agree on the group and cross-match the peer device ids. */
static void scenario_complete(void)
{
    sb_identity *ia = sb_identity_generate();
    sb_identity *ib = sb_identity_generate();
    sb_pair_end *a = sb_pair_end_new(ia, SB_PAIR_ROLE_INITIATOR, CODE);
    sb_pair_end *b = sb_pair_end_new(ib, SB_PAIR_ROLE_RESPONDER, CODE);
    expect(a && b, "both ends start from existing identities");

    /* The initiator opens with pA at once; the responder emits nothing
     * until pA arrives. */
    sb_buffer_t frame = { NULL, 0, 0 };
    expect(take(a, &frame) == 1 && frame.data[0] == FRAME_P_A,
           "the initiator opens with pA");
    expect(take(b, &frame) == 0, "the responder emits nothing before pA");
    expect(sb_pair_end_push(b, frame.data, frame.len) == SB_ERR_NONE,
           "the responder accepts pA");
    sb_free_buffer(&frame);

    drive_to_completion(a, b);
    expect(sb_pair_end_poll(a) == SB_PAIR_EVENT_COMPLETED, "initiator completed");
    expect(sb_pair_end_poll(b) == SB_PAIR_EVENT_COMPLETED, "responder completed");
    expect(sb_pair_end_poll(a) == SB_PAIR_EVENT_NONE, "polling is one-shot");
    expect(sb_pair_end_is_finished(a) == 1 && sb_pair_end_is_finished(b) == 1,
           "finished ends report finished");

    sb_session *sa = sb_pair_end_take_session(a);
    sb_session *sb_ = sb_pair_end_take_session(b);
    expect(sa && sb_, "both sessions hand over");
    if (sa && sb_) {
        const char *ga = sb_session_group_id(sa);
        const char *gb = sb_session_group_id(sb_);
        expect(ga && gb && strcmp(ga, gb) == 0, "both ends derive the same group id");
        const char *ida = sb_identity_device_id(ia);
        const char *idb = sb_identity_device_id(ib);
        const char *peer_a = sb_session_peer_device_id(sa);
        const char *peer_b = sb_session_peer_device_id(sb_);
        expect(peer_a && idb && strcmp(peer_a, idb) == 0,
               "the initiator sees the responder's device id");
        expect(peer_b && ida && strcmp(peer_b, ida) == 0,
               "the responder sees the initiator's device id");
        sb_free_string((char *)peer_a);
        sb_free_string((char *)peer_b);
        sb_free_string((char *)ida);
        sb_free_string((char *)idb);
        sb_free_string(ga);
        sb_free_string(gb);
        /* Taking the session again fails: it already moved to the caller. */
        expect(sb_pair_end_take_session(a) == NULL, "the session hands over once");
    }

    /* A finished end refuses frames: a late push is a host bug, not a peer
     * protocol violation. */
    uint8_t late[2] = { FRAME_P_A, 1 };
    expect(sb_pair_end_push(a, late, sizeof(late)) == SB_ERR_PROTOCOL,
           "a late frame is refused");

    sb_session_free(sa);
    sb_session_free(sb_);
    sb_pair_end_free(a);
    sb_pair_end_free(b);
    sb_identity_free(ia);
    sb_identity_free(ib);
}

/* Structurally valid frames but different codes: both sides derive secrets
 * from different codes, so the failure surfaces at the key confirmation, and
 * each side queues exactly one goodbye. */
static void scenario_wrong_code(void)
{
    sb_identity *ia = sb_identity_generate();
    sb_identity *ib = sb_identity_generate();
    sb_pair_end *a = sb_pair_end_new(ia, SB_PAIR_ROLE_INITIATOR, CODE);
    sb_pair_end *b = sb_pair_end_new(ib, SB_PAIR_ROLE_RESPONDER, "AAAAAA");
    expect(a && b, "wrong-code ends start");

    /* Hand-walk the exchange to the confirmation. */
    sb_buffer_t frame = { NULL, 0, 0 };
    expect(take(a, &frame) == 1, "pA queued");
    expect(sb_pair_end_push(b, frame.data, frame.len) == SB_ERR_NONE, "pA to b");
    sb_free_buffer(&frame);
    expect(take(b, &frame) == 1, "pB queued");
    expect(sb_pair_end_push(a, frame.data, frame.len) == SB_ERR_NONE, "pB to a");
    sb_free_buffer(&frame);
    expect(take(a, &frame) == 1, "cA queued");
    expect(sb_pair_end_push(b, frame.data, frame.len) == SB_ERR_NONE, "cA to b");
    sb_free_buffer(&frame);

    expect(sb_pair_end_poll(b) == SB_PAIR_EVENT_FAILED,
           "the responder fails at the key confirmation");
    const char *why_b = sb_pair_end_failure(b);
    expect(why_b != NULL, "the responder records why it failed");
    sb_free_string((char *)why_b);

    /* Exactly one abort frame for the peer; an explicit abort adds none. */
    expect(take(b, &frame) == 1 && frame.data[0] == FRAME_ABORT,
           "the responder says goodbye once");
    expect(sb_pair_end_push(a, frame.data, frame.len) == SB_ERR_NONE,
           "the initiator takes the goodbye");
    sb_free_buffer(&frame);
    expect(sb_pair_end_poll(a) == SB_PAIR_EVENT_FAILED,
           "the initiator learns of the refusal via the abort");
    const char *why_a = sb_pair_end_failure(a);
    expect(why_a && strstr(why_a, "peer aborted") != NULL,
           "the abort is the initiator's recorded reason");
    sb_free_string((char *)why_a);
    expect(take(a, &frame) == 1 && frame.data[0] == FRAME_ABORT,
           "the initiator says goodbye once");
    sb_free_buffer(&frame);
    sb_pair_end_abort(a);
    sb_pair_end_abort(b);
    expect(take(a, &frame) == 0 && take(b, &frame) == 0,
           "no second goodbye after a failure");

    sb_pair_end_free(a);
    sb_pair_end_free(b);
    sb_identity_free(ia);
    sb_identity_free(ib);
}

/* A host that gives up for transport reasons queues the goodbye once; the
 * peer learns via that frame and fails with the abort reason. */
static void scenario_abort(void)
{
    sb_identity *ia = sb_identity_generate();
    sb_identity *ib = sb_identity_generate();
    sb_pair_end *a = sb_pair_end_new(ia, SB_PAIR_ROLE_INITIATOR, CODE);
    sb_pair_end *b = sb_pair_end_new(ib, SB_PAIR_ROLE_RESPONDER, CODE);
    expect(a && b, "abort-scenario ends start");

    sb_buffer_t frame = { NULL, 0, 0 };
    sb_pair_end_abort(b);
    expect(take(b, &frame) == 1 && frame.data[0] == FRAME_ABORT,
           "abort queues the goodbye");
    sb_pair_end_abort(b);
    expect(take(b, &frame) == 0, "abort queues the goodbye only once");
    expect(sb_pair_end_push(a, frame.data, frame.len) == SB_ERR_NONE,
           "the initiator takes the goodbye");
    sb_free_buffer(&frame);
    expect(sb_pair_end_poll(a) == SB_PAIR_EVENT_FAILED,
           "the initiator fails on the peer's abort");
    const char *why = sb_pair_end_failure(a);
    expect(why && strstr(why, "peer aborted") != NULL, "the reason is the abort");
    sb_free_string((char *)why);
    expect(sb_pair_end_is_finished(a) == 1, "a failed end is finished");
    uint8_t late[2] = { FRAME_P_A, 1 };
    expect(sb_pair_end_push(a, late, sizeof(late)) == SB_ERR_PROTOCOL,
           "a finished end refuses a late frame");

    sb_pair_end_free(a);
    sb_pair_end_free(b);
    sb_identity_free(ia);
    sb_identity_free(ib);
}

/* Constructor and argument validation: a mistyped code, an unknown role, a
 * null identity or a null output buffer all fail with SB_ERR_INPUT before
 * any frame exists. */
static void scenario_validation(void)
{
    sb_identity *ia = sb_identity_generate();
    sb_pair_end *a = sb_pair_end_new(ia, SB_PAIR_ROLE_INITIATOR, CODE);
    expect(a != NULL, "a well-formed end starts");
    sb_buffer_t frame = { NULL, 0, 0 };
    expect(sb_pair_end_pop_outgoing(a, NULL) == SB_ERR_INPUT,
           "a null output buffer is refused");
    expect(sb_pair_end_pop_outgoing(NULL, &frame) == SB_ERR_INPUT,
           "a null end is refused");
    /* A null frame is a caller error: the return carries the entry point's
     * fallback code, the precise SB_ERR_INPUT lands in the error slot. */
    expect(sb_pair_end_push(a, NULL, 1) == SB_ERR_PROTOCOL &&
               sb_last_error_code() == SB_ERR_INPUT,
           "a null frame is refused");
    expect(sb_pair_end_poll(NULL) == SB_ERR_INPUT, "polling a null end is refused");
    expect(sb_pair_end_is_finished(NULL) == SB_ERR_INPUT,
           "querying a null end is refused");
    expect(sb_pair_end_take_session(NULL) == NULL, "taking from a null end is refused");

    expect(sb_pair_end_new(ia, 42, CODE) == NULL &&
               sb_last_error_code() == SB_ERR_INPUT,
           "an unknown role is refused");
    expect(sb_pair_end_new(ia, SB_PAIR_ROLE_INITIATOR, "K7Q2M!") == NULL &&
               sb_last_error_code() == SB_ERR_INPUT,
           "a mistyped code is refused before any frame");
    expect(sb_pair_end_new(NULL, SB_PAIR_ROLE_INITIATOR, CODE) == NULL &&
               sb_last_error_code() == SB_ERR_INPUT,
           "a null identity is refused");
    sb_pair_end_free(a);
    sb_identity_free(ia);
}

int main(void)
{
    expect(sb_abi_version() == SYNCBOND_ABI_VERSION, "abi version matches header");
    scenario_complete();
    scenario_wrong_code();
    scenario_abort();
    scenario_validation();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("pair_frames: all checks passed\n");
    return 0;
}
