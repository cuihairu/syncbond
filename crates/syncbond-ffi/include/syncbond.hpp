/* syncbond.hpp - C++ SDK over the syncbond C ABI.
 *
 * The contract is syncbond.h; this header only adds RAII for handles and
 * buffers, converts failures into exceptions, and returns std::string /
 * std::vector<uint8_t> instead of caller-owned raw pointers. It contains no
 * protocol logic: every call forwards to the C ABI, and Pair / Sync only
 * orchestrate which calls run where (the oplog exchange itself lives in
 * syncbond-core).
 *
 * Sync::run() drives a full-duplex oplog exchange between two replicators by
 * running the blocking responder half on a std::thread; both halves use
 * distinct handles, so the ABI rule "do not touch one handle from two
 * threads" still holds.
 */

#ifndef SYNCBOND_HPP
#define SYNCBOND_HPP

#include "syncbond.h"

#include <cstdint>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace syncbond {

/// RAII wrapper for the library's SB_ERR_* failures.
class Error : public std::runtime_error {
public:
  Error(int code, std::string message)
      : std::runtime_error(message), code_(code), message_(std::move(message)) {}

  /// SB_ERR_* value; SB_ERR_INTERNAL for a failure with no recorded text.
  int code() const { return code_; }

  const char* what() const noexcept override { return message_.c_str(); }

private:
  int code_;
  std::string message_;
};

inline std::string last_error() {
  const char* text = sb_last_error();
  return text ? text : "";
}

/// Fail with the thread-local SB_ERR_* code and text.
[[noreturn]] inline void fail(int code, const char* what) {
  const char* text = sb_last_error();
  throw Error(code, std::string(what) + (text && *text ? ": " : "") + (text ? text : ""));
}

/// Copy a `const char*` returned by the library, or throw on null.
inline std::string read(const char* text, const char* what) {
  if (text == nullptr) {
    fail(sb_last_error_code(), what);
  }
  return {text};
}



/// Take ownership of an `sb_buffer_t` filled by the library.
class Buffer {
public:
  Buffer() : buffer_{nullptr, 0, 0} {}
  Buffer(const Buffer&) = delete;
  Buffer& operator=(const Buffer&) = delete;
  Buffer(Buffer&& other) noexcept : buffer_(other.buffer_) {
    other.buffer_ = {nullptr, 0, 0};
  }
  Buffer& operator=(Buffer&& other) noexcept {
    if (this != &other) {
      release();
      buffer_ = other.buffer_;
      other.buffer_ = {nullptr, 0, 0};
    }
    return *this;
  }
  ~Buffer() { release(); }

  const uint8_t* data() const { return buffer_.data; }
  std::size_t size() const { return buffer_.len; }
  std::vector<uint8_t> bytes() const { return {buffer_.data, buffer_.data + buffer_.len}; }
  std::string text() const { return {reinterpret_cast<const char*>(buffer_.data), buffer_.len}; }

  /// For the C ABI's out-parameters only.
  sb_buffer_t* raw() { return &buffer_; }
  const sb_buffer_t* raw() const { return &buffer_; }

private:
  void release() {
    if (buffer_.data != nullptr) {
      sb_free_buffer(&buffer_);
      buffer_ = {nullptr, 0, 0};
    }
  }
  sb_buffer_t buffer_;
};



/// RAII wrapper for one device identity.
class Identity {
public:
  Identity() : handle_(nullptr) {}
  static Identity generate() {
    sb_identity* handle = sb_identity_generate();
    if (handle == nullptr) {
      fail(sb_last_error_code(), "sb_identity_generate");
    }
    return Identity(handle);
  }
  static Identity import(const uint8_t* secret_key, std::size_t len) {
    sb_identity* handle = sb_identity_import(secret_key, len);
    if (handle == nullptr) {
      fail(sb_last_error_code(), "sb_identity_import");
    }
    return Identity(handle);
  }
  Identity(const Identity&) = delete;
  Identity& operator=(const Identity&) = delete;
  Identity(Identity&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  Identity& operator=(Identity&& other) noexcept {
    if (this != &other) {
      release();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  ~Identity() { release(); }

  std::string device_id() const { return read(sb_identity_device_id(handle_), "device_id"); }
  std::string public_key_hex() const;
  std::vector<uint8_t> secret_key() const;

private:
  explicit Identity(sb_identity* handle) : handle_(handle) {}
  void release() {
    if (handle_ != nullptr) {
      sb_identity_free(handle_);
      handle_ = nullptr;
    }
  }
  sb_identity* handle_;
};

/// RAII wrapper for one authenticated session end.
class Session {
public:
  Session() : handle_(nullptr) {}
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;
  Session(Session&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  Session& operator=(Session&& other) noexcept {
    if (this != &other) {
      release();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  ~Session() { release(); }

  std::string group_id() const { return read(sb_session_group_id(handle_), "group_id"); }
  std::string peer_device_id() const {
    return read(sb_session_peer_device_id(handle_), "peer_device_id");
  }
  bool invalidated() const { return sb_session_invalidated(handle_) != 0; }
  void send(const uint8_t* payload, std::size_t len) const {
    if (sb_session_send(handle_, payload, len) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_session_send");
    }
  }
  void send(const std::string& payload) const {
    send(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
  }
  Buffer recv() const {
    Buffer out;
    if (sb_session_recv(handle_, out.raw()) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_session_recv");
    }
    return out;
  }
  void invalidate() {
    if (sb_session_invalidate(handle_) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_session_invalidate");
    }
  }

  /// For the sync helper, which passes the handle to the C ABI.
  sb_session* raw() const { return handle_; }

private:
  friend class PairResult;
  explicit Session(sb_session* handle) : handle_(handle) {}
  void release() {
    if (handle_ != nullptr) {
      sb_session_free(handle_);
      handle_ = nullptr;
    }
  }
  sb_session* handle_;
};

inline std::string Identity::public_key_hex() const {
  uint8_t key[32];
  if (sb_identity_public_key(handle_, key) != SB_ERR_NONE) {
    fail(sb_last_error_code(), "sb_identity_public_key");
  }
  static const char* digits = "0123456789abcdef";
  std::string out(64, '0');
  for (std::size_t i = 0; i < sizeof(key); ++i) {
    out[2 * i] = digits[key[i] >> 4];
    out[2 * i + 1] = digits[key[i] & 0xf];
  }
  return out;
}

inline std::vector<uint8_t> Identity::secret_key() const {
  uint8_t key[64];
  if (sb_identity_secret_key(handle_, key) != SB_ERR_NONE) {
    fail(sb_last_error_code(), "sb_identity_secret_key");
  }
  return {key, key + sizeof(key)};
}

/// RAII wrapper for the pairing result; extracting a session returns a fresh
/// handle the caller owns.
class PairResult {
public:
  PairResult() : handle_(nullptr) {}
  /// `code == nullptr` generates one.
  static PairResult memory(const char* code) {
    sb_pair_result* handle = sb_pair_memory(code);
    if (handle == nullptr) {
      fail(sb_last_error_code(), "sb_pair_memory");
    }
    return PairResult(handle);
  }
  static PairResult memory(const std::string& code) { return memory(code.c_str()); }
  static PairResult memory() { return memory(nullptr); }
  PairResult(const PairResult&) = delete;
  PairResult& operator=(const PairResult&) = delete;
  PairResult(PairResult&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  PairResult& operator=(PairResult&& other) noexcept {
    if (this != &other) {
      release();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  ~PairResult() { release(); }

  std::string code() const {
    return read(sb_pair_result_code(handle_), "sb_pair_result_code");
  }
  Session initiator() const {
    sb_session* handle = sb_pair_result_initiator(handle_);
    if (handle == nullptr) {
      fail(sb_last_error_code(), "sb_pair_result_initiator");
    }
    return Session(handle);
  }
  Session responder() const {
    sb_session* handle = sb_pair_result_responder(handle_);
    if (handle == nullptr) {
      fail(sb_last_error_code(), "sb_pair_result_responder");
    }
    return Session(handle);
  }

private:
  explicit PairResult(sb_pair_result* handle) : handle_(handle) {}
  void release() {
    if (handle_ != nullptr) {
      sb_pair_result_free(handle_);
      handle_ = nullptr;
    }
  }
  sb_pair_result* handle_;
};

/// RAII wrapper for one synchronizing device.
class Replicator {
public:
  static const uint32_t kLwwHlc = SB_STRATEGY_LWW_HLC;
  static const uint32_t kOrSet = SB_STRATEGY_OR_SET;
  static const uint32_t kPnCounter = SB_STRATEGY_PN_COUNTER;

  Replicator() : handle_(nullptr) {}
  static Replicator create(const std::string& node_id, uint32_t strategy) {
    sb_replicator* handle = sb_replicator_new(node_id.c_str(), strategy);
    if (handle == nullptr) {
      fail(sb_last_error_code(), "sb_replicator_new");
    }
    return Replicator(handle);
  }
  /// Frozen clock for reproducible runs; 0 falls back to the wall clock.
  static Replicator create(const std::string& node_id, uint32_t strategy, uint64_t now_ms) {
    sb_replicator* handle = sb_replicator_new_fixed_clock(node_id.c_str(), strategy, now_ms);
    if (handle == nullptr) {
      fail(sb_last_error_code(), "sb_replicator_new_fixed_clock");
    }
    return Replicator(handle);
  }
  Replicator(const Replicator&) = delete;
  Replicator& operator=(const Replicator&) = delete;
  Replicator(Replicator&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  Replicator& operator=(Replicator&& other) noexcept {
    if (this != &other) {
      release();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  ~Replicator() { release(); }

  std::string node_id() const {
    return read(sb_replicator_node_id(handle_), "node_id");
  }
  uint32_t record_count() const { return sb_replicator_record_count(handle_); }
  uint32_t oplog_len() const { return sb_replicator_oplog_len(handle_); }

  void put(const std::string& key, const uint8_t* payload, std::size_t len) {
    if (sb_replicator_put(handle_, key.c_str(), payload, len) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_replicator_put");
    }
  }
  void put(const std::string& key, const std::string& payload) {
    put(key, reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
  }
  void del(const std::string& key) {
    if (sb_replicator_delete(handle_, key.c_str()) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_replicator_delete");
    }
  }

  /// Empty when the key has no live value.
  std::optional<Buffer> get(const std::string& key) const {
    Buffer out;
    const int code = sb_replicator_get(handle_, key.c_str(), out.raw());
    if (code == SB_RESULT_ABSENT) {
      return std::nullopt;
    }
    if (code != SB_ERR_NONE) {
      fail(code, "sb_replicator_get");
    }
    return out;
  }

  std::string live_keys_json() const {
    return read(sb_replicator_live_keys_json(handle_), "live_keys_json");
  }
  std::string op_json(uint32_t index) const {
    return read(sb_replicator_op_json(handle_, index), "op_json");
  }
  /// 1 when applied, 0 when it was a duplicate or a resurrected delete.
  int apply_remote_json(const std::string& op_json) {
    const int applied = sb_replicator_apply_remote_json(handle_, op_json.c_str());
    if (applied < 0) {
      fail(applied, "sb_replicator_apply_remote_json");
    }
    return applied;
  }
  uint32_t sync(Session& session, bool send_first) {
    uint32_t sent_ops = 0;
    if (sb_replicator_sync(handle_, session.raw(), send_first ? 1 : 0,
                           &sent_ops) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_replicator_sync");
    }
    return sent_ops;
  }
  std::string records_json() const {
    return read(sb_replicator_records_json(handle_), "records_json");
  }
  std::string gc_barriers_json() const {
    return read(sb_replicator_gc_barriers_json(handle_), "gc_barriers_json");
  }
  int gc_tombstones(uint64_t now_ms, uint64_t older_than_ms) {
    const int collected = sb_replicator_gc_tombstones(handle_, now_ms, older_than_ms);
    if (collected < 0) {
      fail(collected, "sb_replicator_gc_tombstones");
    }
    return collected;
  }

private:
  explicit Replicator(sb_replicator* handle) : handle_(handle) {}
  void release() {
    if (handle_ != nullptr) {
      sb_replicator_free(handle_);
      handle_ = nullptr;
    }
  }
  sb_replicator* handle_;
};

/// RAII wrapper for group key material.
class Keyring {
public:
  Keyring() : handle_(nullptr) {}
  static Keyring create(const std::string& group_id) {
    sb_keyring* handle = sb_keyring_new(group_id.c_str());
    if (handle == nullptr) {
      fail(sb_last_error_code(), "sb_keyring_new");
    }
    return Keyring(handle);
  }
  static Keyring import(const std::string& group_id, uint64_t epoch, const uint8_t key[32]) {
    sb_keyring* handle = sb_keyring_import(group_id.c_str(), epoch, key);
    if (handle == nullptr) {
      fail(sb_last_error_code(), "sb_keyring_import");
    }
    return Keyring(handle);
  }
  Keyring(const Keyring&) = delete;
  Keyring& operator=(const Keyring&) = delete;
  Keyring(Keyring&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  Keyring& operator=(Keyring&& other) noexcept {
    if (this != &other) {
      release();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  ~Keyring() { release(); }

  uint64_t epoch() const { return sb_keyring_epoch(handle_); }
  /// Mint the next epoch and hand back the new key for distribution.
  std::vector<uint8_t> rotate() {
    uint64_t epoch = 0;
    uint8_t key[32];
    if (sb_keyring_rotate(handle_, &epoch, key) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_keyring_rotate");
    }
    return {key, key + sizeof(key)};
  }
  std::string seal(const std::string& sender_device_id, const std::string& plaintext) const {
    const char* text = sb_keyring_seal_json(
        handle_, sender_device_id.c_str(),
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    return read(text, "seal");
  }
  Buffer open(const std::string& envelope_json) const {
    Buffer out;
    if (sb_keyring_open_json(handle_, envelope_json.c_str(), out.raw()) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_keyring_open_json");
    }
    return out;
  }

private:
  explicit Keyring(sb_keyring* handle) : handle_(handle) {}
  void release() {
    if (handle_ != nullptr) {
      sb_keyring_free(handle_);
      handle_ = nullptr;
    }
  }
  sb_keyring* handle_;
};

/// Pair two freshly generated devices over an in-memory loopback.
struct Pair {
  Session initiator;
  Session responder;
  std::string code;

  static Pair memory(const std::string& code) {
    PairResult result = PairResult::memory(code);
    return Pair{result.initiator(), result.responder(), result.code()};
  }
  static Pair memory() {
    PairResult result = PairResult::memory();
    return Pair{result.initiator(), result.responder(), result.code()};
  }
};

/// Result of one full-duplex oplog exchange.
struct SyncStats {
  uint32_t left_ops = 0;
  uint32_t right_ops = 0;
};

/// Run both directions of one oplog exchange. `sb_replicator_sync()` blocks in
/// one direction, so the responder half runs on a std::thread; the two halves
/// use distinct handles.
struct Sync {
  static SyncStats run(Replicator& left, Session& initiator, Replicator& right, Session& responder) {
    SyncStats stats;
    std::thread responder_thread([&] { stats.right_ops = right.sync(responder, false); });
    stats.left_ops = left.sync(initiator, true);
    responder_thread.join();
    return stats;
  }
};

inline std::string conformance_run(const std::string& fixture_json) {
  const char* text = sb_conformance_run(fixture_json.c_str());
  if (text == nullptr) {
    fail(sb_last_error_code(), "sb_conformance_run");
  }
  return {text};
}

inline uint32_t abi_version() { return sb_abi_version(); }
inline uint32_t protocol_version() { return sb_protocol_version(); }

}  // namespace syncbond

#endif  // SYNCBOND_HPP
