/* syncbond_jni.c - JNI glue over the syncbond C ABI.
 *
 * Every function here converts JNI types and forwards to syncbond.h; no
 * protocol logic lives in this file. Failures surface as
 * syncbond.SyncbondException carrying the precise SB_ERR_* code read from
 * the thread-local slot (JNI calls run on the calling thread, so the slot is
 * the right one).
 *
 * Build (see build.gradle): cc -shared -fPIC against the JDK headers, with
 * libsyncbond_ffi loaded at runtime by the JVM.
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "syncbond.h"
#include "syncbond_Native.h"

/* Cached syncbond.SyncbondException class and (int, String) constructor. */
static jclass cls_exception;
static jmethodID mid_exception_init;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;
    JNIEnv* env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) != JNI_OK) {
        return JNI_ERR;
    }
    jclass local = (*env)->FindClass(env, "syncbond/SyncbondException");
    if (local == NULL) {
        return JNI_ERR;
    }
    cls_exception = (*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    if (cls_exception == NULL) {
        return JNI_ERR;
    }
    mid_exception_init =
        (*env)->GetMethodID(env, cls_exception, "<init>", "(ILjava/lang/String;)V");
    if (mid_exception_init == NULL) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_8;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    (void)reserved;
    JNIEnv* env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) == JNI_OK && cls_exception != NULL) {
        (*env)->DeleteGlobalRef(env, cls_exception);
        cls_exception = NULL;
    }
}

/* Throw SyncbondException(code, last error text) and return 0, so callers
 * can `return sb_throw(env, sb_last_error_code());`. */
static jlong throw_last(JNIEnv* env, int code) {
    const char* text = sb_last_error();
    jstring message = text != NULL ? (*env)->NewStringUTF(env, text) : NULL;
    jobject error = (*env)->NewObject(env, cls_exception, mid_exception_init, (jint)code, message);
    if (error != NULL) {
        (*env)->Throw(env, (jthrowable)error);
    }
    return 0;
}

/* Copy a jstring into C memory the caller frees. */
static char* java_string(JNIEnv* env, jstring value) {
    if (value == NULL) {
        return NULL;
    }
    const char* utf = (*env)->GetStringUTFChars(env, value, NULL);
    if (utf == NULL) {
        return NULL;
    }
    char* copy = strdup(utf);
    (*env)->ReleaseStringUTFChars(env, value, utf);
    return copy;
}

/* Copy a jbyteArray into C memory the caller frees; NULL for empty input. */
static uint8_t* java_bytes(JNIEnv* env, jbyteArray value, size_t* out_len) {
    *out_len = 0;
    if (value == NULL) {
        return NULL;
    }
    jsize len = (*env)->GetArrayLength(env, value);
    if (len <= 0) {
        return NULL;
    }
    uint8_t* copy = malloc((size_t)len);
    if (copy == NULL) {
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, value, 0, len, (jbyte*)copy);
    *out_len = (size_t)len;
    return copy;
}

/* Copy owned C bytes into a fresh jbyteArray. */
static jbyteArray new_java_bytes(JNIEnv* env, const uint8_t* data, size_t len) {
    jbyteArray out = (*env)->NewByteArray(env, (jsize)len);
    if (out == NULL) {
        return NULL;
    }
    if (len > 0) {
        (*env)->SetByteArrayRegion(env, out, 0, (jsize)len, (const jbyte*)data);
    }
    return out;
}

/* Copy an owned C string into a jstring, then release the C string. */
static jstring take_string(JNIEnv* env, const char* owned) {
    if (owned == NULL) {
        throw_last(env, sb_last_error_code());
        return NULL;
    }
    jstring out = (*env)->NewStringUTF(env, owned);
    sb_free_string(owned);
    return out; /* NULL only when NewStringUTF threw */
}

/* Copy an owned C buffer into a jbyteArray, then release the buffer. */
static jbyteArray take_buffer(JNIEnv* env, sb_buffer_t* buffer) {
    if (buffer->data == NULL) {
        sb_free_buffer(buffer);
        throw_last(env, sb_last_error_code());
        return NULL;
    }
    jbyteArray out = new_java_bytes(env, buffer->data, buffer->len);
    sb_free_buffer(buffer);
    return out;
}

/* ------------------------------------------------------------- version */

JNIEXPORT jint JNICALL Java_syncbond_Native_abiVersion(JNIEnv* env, jclass cls) {
    (void)env; (void)cls;
    return (jint)sb_abi_version();
}

JNIEXPORT jint JNICALL Java_syncbond_Native_protocolVersion(JNIEnv* env, jclass cls) {
    (void)env; (void)cls;
    return (jint)sb_protocol_version();
}

JNIEXPORT jint JNICALL Java_syncbond_Native_lastErrorCode(JNIEnv* env, jclass cls) {
    (void)env; (void)cls;
    return (jint)sb_last_error_code();
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_lastError(JNIEnv* env, jclass cls) {
    (void)cls;
    const char* text = sb_last_error();
    if (text == NULL) {
        return NULL;
    }
    return (*env)->NewStringUTF(env, text);
}

/* ------------------------------------------------------------ identity */

JNIEXPORT jlong JNICALL Java_syncbond_Native_identityGenerate(JNIEnv* env, jclass cls) {
    (void)cls;
    sb_identity* handle = sb_identity_generate();
    if (handle == NULL) {
        return throw_last(env, sb_last_error_code());
    }
    return (jlong)(intptr_t)handle;
}

JNIEXPORT jlong JNICALL Java_syncbond_Native_identityImport(
    JNIEnv* env, jclass cls, jbyteArray secret_key) {
    (void)cls;
    size_t len = 0;
    uint8_t* data = java_bytes(env, secret_key, &len);
    sb_identity* handle = sb_identity_import(data, len);
    free(data);
    if (handle == NULL) {
        return throw_last(env, sb_last_error_code());
    }
    return (jlong)(intptr_t)handle;
}

JNIEXPORT void JNICALL Java_syncbond_Native_identityFree(JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    sb_identity_free((sb_identity*)(intptr_t)handle);
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_identityDeviceId(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    return take_string(env, sb_identity_device_id((sb_identity*)(intptr_t)handle));
}

JNIEXPORT jbyteArray JNICALL Java_syncbond_Native_identityPublicKey(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    uint8_t out[32];
    if (sb_identity_public_key((sb_identity*)(intptr_t)handle, out) != SB_ERR_NONE) {
        return (jbyteArray)throw_last(env, sb_last_error_code());
    }
    return new_java_bytes(env, out, sizeof(out));
}

JNIEXPORT jbyteArray JNICALL Java_syncbond_Native_identitySecretKey(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    uint8_t out[64];
    if (sb_identity_secret_key((sb_identity*)(intptr_t)handle, out) != SB_ERR_NONE) {
        return (jbyteArray)throw_last(env, sb_last_error_code());
    }
    return new_java_bytes(env, out, sizeof(out));
}

/* ------------------------------------------------------------ pairing */

JNIEXPORT jlong JNICALL Java_syncbond_Native_pairMemory(JNIEnv* env, jclass cls, jstring code) {
    (void)cls;
    char* owned = java_string(env, code);
    sb_pair_result* handle = sb_pair_memory(owned);
    free(owned);
    if (handle == NULL) {
        return throw_last(env, sb_last_error_code());
    }
    return (jlong)(intptr_t)handle;
}

JNIEXPORT void JNICALL Java_syncbond_Native_pairFree(JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    sb_pair_result_free((sb_pair_result*)(intptr_t)handle);
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_pairCode(JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    return take_string(env, sb_pair_result_code((sb_pair_result*)(intptr_t)handle));
}

JNIEXPORT jlong JNICALL Java_syncbond_Native_pairInitiator(JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    return (jlong)(intptr_t)sb_pair_result_initiator((sb_pair_result*)(intptr_t)handle);
}

JNIEXPORT jlong JNICALL Java_syncbond_Native_pairResponder(JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    return (jlong)(intptr_t)sb_pair_result_responder((sb_pair_result*)(intptr_t)handle);
}

/* ------------------------------------------------------------- session */

JNIEXPORT void JNICALL Java_syncbond_Native_sessionFree(JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    sb_session_free((sb_session*)(intptr_t)handle);
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_sessionGroupId(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    return take_string(env, sb_session_group_id((sb_session*)(intptr_t)handle));
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_sessionPeerDeviceId(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    return take_string(env, sb_session_peer_device_id((sb_session*)(intptr_t)handle));
}

JNIEXPORT jboolean JNICALL Java_syncbond_Native_sessionInvalidated(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    return sb_session_invalidated((sb_session*)(intptr_t)handle) != 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL Java_syncbond_Native_sessionSend(
    JNIEnv* env, jclass cls, jlong handle, jbyteArray payload) {
    (void)cls;
    size_t len = 0;
    uint8_t* data = java_bytes(env, payload, &len);
    int code = sb_session_send((sb_session*)(intptr_t)handle, data, len);
    free(data);
    if (code != SB_ERR_NONE) {
        throw_last(env, sb_last_error_code());
    }
}

JNIEXPORT jbyteArray JNICALL Java_syncbond_Native_sessionRecv(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    sb_buffer_t out = {0};
    if (sb_session_recv((sb_session*)(intptr_t)handle, &out) != SB_ERR_NONE) {
        return (jbyteArray)throw_last(env, sb_last_error_code());
    }
    return take_buffer(env, &out);
}

JNIEXPORT void JNICALL Java_syncbond_Native_sessionInvalidate(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    if (sb_session_invalidate((sb_session*)(intptr_t)handle) != SB_ERR_NONE) {
        throw_last(env, sb_last_error_code());
    }
}

/* --------------------------------------------------------- replicator */

JNIEXPORT jlong JNICALL Java_syncbond_Native_replicatorNew(
    JNIEnv* env, jclass cls, jstring node_id, jint strategy) {
    (void)cls;
    char* owned = java_string(env, node_id);
    sb_replicator* handle = sb_replicator_new(owned, (uint32_t)strategy);
    free(owned);
    if (handle == NULL) {
        return throw_last(env, sb_last_error_code());
    }
    return (jlong)(intptr_t)handle;
}

JNIEXPORT jlong JNICALL Java_syncbond_Native_replicatorNewFixed(
    JNIEnv* env, jclass cls, jstring node_id, jint strategy, jlong now_ms) {
    (void)cls;
    char* owned = java_string(env, node_id);
    sb_replicator* handle =
        sb_replicator_new_fixed_clock(owned, (uint32_t)strategy, (uint64_t)now_ms);
    free(owned);
    if (handle == NULL) {
        return throw_last(env, sb_last_error_code());
    }
    return (jlong)(intptr_t)handle;
}

JNIEXPORT void JNICALL Java_syncbond_Native_replicatorFree(JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    sb_replicator_free((sb_replicator*)(intptr_t)handle);
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_replicatorNodeId(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    return take_string(env, sb_replicator_node_id((sb_replicator*)(intptr_t)handle));
}

JNIEXPORT jint JNICALL Java_syncbond_Native_replicatorRecordCount(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    return (jint)sb_replicator_record_count((sb_replicator*)(intptr_t)handle);
}

JNIEXPORT jint JNICALL Java_syncbond_Native_replicatorOplogLen(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    return (jint)sb_replicator_oplog_len((sb_replicator*)(intptr_t)handle);
}

JNIEXPORT void JNICALL Java_syncbond_Native_replicatorPut(
    JNIEnv* env, jclass cls, jlong handle, jstring key, jbyteArray payload) {
    (void)cls;
    char* owned_key = java_string(env, key);
    size_t len = 0;
    uint8_t* data = java_bytes(env, payload, &len);
    int code = sb_replicator_put((sb_replicator*)(intptr_t)handle, owned_key, data, len);
    free(data);
    free(owned_key);
    if (code != SB_ERR_NONE) {
        throw_last(env, sb_last_error_code());
    }
}

JNIEXPORT void JNICALL Java_syncbond_Native_replicatorDelete(
    JNIEnv* env, jclass cls, jlong handle, jstring key) {
    (void)cls;
    char* owned_key = java_string(env, key);
    int code = sb_replicator_delete((sb_replicator*)(intptr_t)handle, owned_key);
    free(owned_key);
    if (code != SB_ERR_NONE) {
        throw_last(env, sb_last_error_code());
    }
}

JNIEXPORT jbyteArray JNICALL Java_syncbond_Native_replicatorGet(
    JNIEnv* env, jclass cls, jlong handle, jstring key) {
    (void)cls;
    char* owned_key = java_string(env, key);
    sb_buffer_t out = {0};
    int code = sb_replicator_get((sb_replicator*)(intptr_t)handle, owned_key, &out);
    free(owned_key);
    if (code == SB_RESULT_ABSENT) {
        return NULL;
    }
    if (code != SB_ERR_NONE) {
        return (jbyteArray)throw_last(env, sb_last_error_code());
    }
    return take_buffer(env, &out);
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_replicatorLiveKeysJson(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    return take_string(env, sb_replicator_live_keys_json((sb_replicator*)(intptr_t)handle));
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_replicatorOpJson(
    JNIEnv* env, jclass cls, jlong handle, jint index) {
    (void)cls;
    return take_string(
        env, sb_replicator_op_json((sb_replicator*)(intptr_t)handle, (uint32_t)index));
}

JNIEXPORT jboolean JNICALL Java_syncbond_Native_replicatorApplyRemoteJson(
    JNIEnv* env, jclass cls, jlong handle, jstring op_json) {
    (void)cls;
    char* owned = java_string(env, op_json);
    int code = sb_replicator_apply_remote_json((sb_replicator*)(intptr_t)handle, owned);
    free(owned);
    if (code < 0) {
        return (jboolean)throw_last(env, sb_last_error_code());
    }
    return code != 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL Java_syncbond_Native_replicatorSync(
    JNIEnv* env, jclass cls, jlong handle, jlong session_handle, jboolean send_first) {
    (void)cls;
    uint32_t sent = 0;
    int code = sb_replicator_sync(
        (sb_replicator*)(intptr_t)handle,
        (sb_session*)(intptr_t)session_handle,
        send_first == JNI_TRUE ? 1 : 0,
        &sent);
    if (code != SB_ERR_NONE) {
        return (jint)throw_last(env, sb_last_error_code());
    }
    return (jint)sent;
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_replicatorRecordsJson(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    return take_string(env, sb_replicator_records_json((sb_replicator*)(intptr_t)handle));
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_replicatorGcBarriersJson(
    JNIEnv* env, jclass cls, jlong handle) {
    (void)cls;
    return take_string(env, sb_replicator_gc_barriers_json((sb_replicator*)(intptr_t)handle));
}

JNIEXPORT jint JNICALL Java_syncbond_Native_replicatorGcTombstones(
    JNIEnv* env, jclass cls, jlong handle, jlong now_ms, jlong older_than_ms) {
    (void)cls;
    int code = sb_replicator_gc_tombstones(
        (sb_replicator*)(intptr_t)handle, (uint64_t)now_ms, (uint64_t)older_than_ms);
    if (code < 0) {
        return (jint)throw_last(env, sb_last_error_code());
    }
    return (jint)code;
}

/* --------------------------------------------------------- key material */

JNIEXPORT jlong JNICALL Java_syncbond_Native_keyringNew(
    JNIEnv* env, jclass cls, jstring group_id) {
    (void)cls;
    char* owned = java_string(env, group_id);
    sb_keyring* handle = sb_keyring_new(owned);
    free(owned);
    if (handle == NULL) {
        return throw_last(env, sb_last_error_code());
    }
    return (jlong)(intptr_t)handle;
}

JNIEXPORT jlong JNICALL Java_syncbond_Native_keyringImport(
    JNIEnv* env, jclass cls, jstring group_id, jlong epoch, jbyteArray key) {
    (void)cls;
    char* owned = java_string(env, group_id);
    size_t len = 0;
    uint8_t* data = java_bytes(env, key, &len);
    sb_keyring* handle = sb_keyring_import(owned, (uint64_t)epoch, data);
    free(data);
    free(owned);
    if (handle == NULL) {
        return throw_last(env, sb_last_error_code());
    }
    return (jlong)(intptr_t)handle;
}

JNIEXPORT void JNICALL Java_syncbond_Native_keyringFree(JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    sb_keyring_free((sb_keyring*)(intptr_t)handle);
}

JNIEXPORT jlong JNICALL Java_syncbond_Native_keyringEpoch(JNIEnv* env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    return (jlong)sb_keyring_epoch((sb_keyring*)(intptr_t)handle);
}

JNIEXPORT jlong JNICALL Java_syncbond_Native_keyringRotate(
    JNIEnv* env, jclass cls, jlong handle, jbyteArray out_key) {
    (void)cls;
    uint64_t epoch = 0;
    uint8_t key[32];
    if (sb_keyring_rotate((sb_keyring*)(intptr_t)handle, &epoch, key) != SB_ERR_NONE) {
        return throw_last(env, sb_last_error_code());
    }
    (*env)->SetByteArrayRegion(env, out_key, 0, (jsize)sizeof(key), (const jbyte*)key);
    return (jlong)epoch;
}

JNIEXPORT jstring JNICALL Java_syncbond_Native_keyringSealJson(
    JNIEnv* env, jclass cls, jlong handle, jstring sender_device_id, jbyteArray plaintext) {
    (void)cls;
    char* owned_sender = java_string(env, sender_device_id);
    size_t len = 0;
    uint8_t* data = java_bytes(env, plaintext, &len);
    const char* sealed =
        sb_keyring_seal_json((sb_keyring*)(intptr_t)handle, owned_sender, data, len);
    free(data);
    free(owned_sender);
    return take_string(env, sealed);
}

JNIEXPORT jbyteArray JNICALL Java_syncbond_Native_keyringOpenJson(
    JNIEnv* env, jclass cls, jlong handle, jstring envelope_json) {
    (void)cls;
    char* owned = java_string(env, envelope_json);
    sb_buffer_t out = {0};
    int code = sb_keyring_open_json((sb_keyring*)(intptr_t)handle, owned, &out);
    free(owned);
    if (code != SB_ERR_NONE) {
        return (jbyteArray)throw_last(env, sb_last_error_code());
    }
    return take_buffer(env, &out);
}

/* ---------------------------------------------------------- conformance */

JNIEXPORT jstring JNICALL Java_syncbond_Native_conformanceRun(
    JNIEnv* env, jclass cls, jstring fixture_json) {
    (void)cls;
    char* owned = java_string(env, fixture_json);
    const char* report = sb_conformance_run(owned);
    free(owned);
    return take_string(env, report);
}
