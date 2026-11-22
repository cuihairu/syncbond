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
  friend struct StateSnapshot;
  friend class RelayDriver;
  explicit Identity(sb_identity* handle) : handle_(handle) {}
  /// Hand the raw handle to the relay driver: the driver owns it from here
  /// (success AND failure), so this object releases nothing on destruction.
  sb_identity* detach() {
    sb_identity* handle = handle_;
    handle_ = nullptr;
    return handle;
  }
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
  friend struct StateSnapshot;
  friend class RelayDriver;
  explicit Replicator(sb_replicator* handle) : handle_(handle) {}
  /// Hand the raw handle to the relay driver: the driver owns it from here
  /// (success AND failure), so this object releases nothing on destruction.
  sb_replicator* detach() {
    sb_replicator* handle = handle_;
    handle_ = nullptr;
    return handle;
  }
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
  friend class RelayDriver;
  explicit Keyring(sb_keyring* handle) : handle_(handle) {}
  /// Hand the raw handle to the relay driver: the driver owns it from here
  /// (success AND failure), so this object releases nothing on destruction.
  sb_keyring* detach() {
    sb_keyring* handle = handle_;
    handle_ = nullptr;
    return handle;
  }
  void release() {
    if (handle_ != nullptr) {
      sb_keyring_free(handle_);
      handle_ = nullptr;
    }
  }
  sb_keyring* handle_;
};

/// RAII wrapper for the receive-side pull position: the per-(server, channel)
/// committed sequence, the highest local cursor per replica, and the
/// already-opened message ids. Without it a restart re-pulls (and re-applies)
/// every remote operation already seen.
class ReceiveState {
public:
  ReceiveState() : handle_(nullptr) {}
  static ReceiveState create() {
    sb_receive_state* handle = sb_receive_state_new();
    if (handle == nullptr) {
      fail(sb_last_error_code(), "sb_receive_state_new");
    }
    return ReceiveState(handle);
  }
  ReceiveState(const ReceiveState&) = delete;
  ReceiveState& operator=(const ReceiveState&) = delete;
  ReceiveState(ReceiveState&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  ReceiveState& operator=(ReceiveState&& other) noexcept {
    if (this != &other) {
      release();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  ~ReceiveState() { release(); }

  /// Record the server-assigned sequence the next pull starts after.
  void server_cursor(const std::string& server_id, const std::string& channel_id,
                     uint64_t server_seq) {
    if (sb_receive_state_server_cursor(handle_, server_id.c_str(), channel_id.c_str(),
                                       server_seq) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_receive_state_server_cursor");
    }
  }
  /// Record the highest local cursor seen for one replica's "<node>:<n>" ids.
  void source_cursor(const std::string& node_id, uint64_t seq) {
    if (sb_receive_state_source_cursor(handle_, node_id.c_str(), seq) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_receive_state_source_cursor");
    }
  }
  /// Record one already-opened envelope so a redelivery is a no-op.
  void seen(const std::string& message_id) {
    if (sb_receive_state_seen(handle_, message_id.c_str()) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_receive_state_seen");
    }
  }
  /// The last committed server sequence; empty when never pulled.
  std::optional<uint64_t> server_seq(const std::string& server_id,
                                     const std::string& channel_id) const {
    uint64_t seq = 0;
    const int code = sb_receive_state_server_seq(handle_, server_id.c_str(),
                                                 channel_id.c_str(), &seq);
    if (code == SB_RESULT_ABSENT) {
      return std::nullopt;
    }
    if (code != SB_ERR_NONE) {
      fail(code, "sb_receive_state_server_seq");
    }
    return seq;
  }
  /// Canonical dump of the whole position; deterministic byte for byte.
  std::string json() const { return read(sb_receive_state_json(handle_), "receive_state_json"); }

private:
  friend struct StateSnapshot;
  friend class RelayDriver;
  explicit ReceiveState(sb_receive_state* handle) : handle_(handle) {}
  /// Hand the raw handle to the relay driver: the driver owns it from here
  /// (success AND failure), so this object releases nothing on destruction.
  sb_receive_state* detach() {
    sb_receive_state* handle = handle_;
    handle_ = nullptr;
    return handle;
  }
  void release() {
    if (handle_ != nullptr) {
      sb_receive_state_free(handle_);
      handle_ = nullptr;
    }
  }
  sb_receive_state* handle_;
};

/// The monotonic counters a running relay driver's worker has accumulated.
struct RelayProgress {
  bool running = false;
  uint64_t cycles = 0;
  uint64_t sent_batches = 0;
  uint64_t sent_envelopes = 0;
  uint64_t pages_pulled = 0;
  uint64_t applied = 0;
};

/// One exported device snapshot: the replicator and receive position restored
/// from a blob. `export_state()` writes the blob; `import()` rebuilds it.
struct StateSnapshot {
  Replicator replicator;
  ReceiveState receive;

  /// Write the replicator's committed state plus a receive position as one
  /// versioned snapshot. PRIVATE material (it embeds the device identity).
  static Buffer export_state(const Replicator& replicator, const Identity& identity,
                             const std::string& group_id, uint64_t key_epoch,
                             const ReceiveState& receive) {
    Buffer out;
    if (sb_state_export(replicator.handle_, identity.handle_, group_id.c_str(), key_epoch,
                        receive.handle_, out.raw()) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_state_export");
    }
    return out;
  }

  /// Rebuild a replicator and a receive position from a snapshot blob. The
  /// strategy must be the one the original used (the blob does not store it).
  static StateSnapshot import(const uint8_t* blob, std::size_t len, uint32_t strategy) {
    sb_replicator* replicator = nullptr;
    sb_receive_state* receive = nullptr;
    if (sb_state_import(blob, len, strategy, &replicator, &receive) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_state_import");
    }
    return StateSnapshot{Replicator(replicator), ReceiveState(receive)};
  }
  static StateSnapshot import(const std::vector<uint8_t>& blob, uint32_t strategy) {
    return import(blob.data(), blob.size(), strategy);
  }
};

/// One relay channel driver over the C ABI. The native driver owns the whole
/// network session (the relay client, its runtime and one worker thread) plus
/// the device state; the host only configures, starts, stops and interleaves
/// writes. The four sub-handles (identity, keyring, replicator, receive state)
/// transfer to the driver on success AND on failure, matching the ABI contract,
/// so `open()` leaves the objects it built emptied rather than freeing them.
class RelayDriver {
public:
  /// TLS certificate checking strictness, mirroring SB_TLS_*.
  static constexpr uint32_t kTlsValidate = SB_TLS_VALIDATE;
  static constexpr uint32_t kTlsValidateCa = SB_TLS_VALIDATE_CA;
  static constexpr uint32_t kTlsAcceptInvalid = SB_TLS_ACCEPT_INVALID;

  /// Why the loop ended, mirroring SB_DRIVER_STOP_*.
  static constexpr int kStopNone = SB_DRIVER_STOP_NONE;
  static constexpr int kStopCancelled = SB_DRIVER_STOP_CANCELLED;
  static constexpr int kStopExhausted = SB_DRIVER_STOP_EXHAUSTED;
  static constexpr int kStopFatal = SB_DRIVER_STOP_FATAL;

  /// Everything `open()` needs; the fields mirror the C ABI call.
  struct Config {
    std::string relay_url;
    std::string channel_id;
    std::string channel_token;
    std::string server_id;
    std::string cursor_channel;
    std::string group_id;
    uint64_t key_epoch = 1;
    /// Shared 32-byte group key material; two devices in one group import the
    /// same bytes.
    std::vector<uint8_t> group_key;
    /// Names a fresh replicator; ignored when `state` restores one.
    std::string node_id;
    uint64_t timeout_ms = 5000;
    uint32_t tls_mode = kTlsValidate;
    /// Pins a CA (DER) when `tls_mode` is kTlsValidateCa.
    std::vector<uint8_t> ca_der;
    /// An exported snapshot to resume from; empty starts fresh.
    std::vector<uint8_t> state;
  };

  /// Build the identity, keyring, replicator and receive state the driver
  /// needs and hand them to sb_relay_driver_new, whose ownership transfer
  /// (on success AND on failure) means none of them is a separate owner.
  static RelayDriver open(const Config& config) {
    if (config.group_key.size() != 32) {
      throw Error(SB_ERR_INPUT, "group key must be exactly 32 bytes");
    }
    Identity identity = Identity::generate();
    Keyring keyring = Keyring::import(config.group_id, config.key_epoch, config.group_key.data());
    Replicator replicator;
    ReceiveState receive;
    if (!config.state.empty()) {
      StateSnapshot restored = StateSnapshot::import(config.state, SB_STRATEGY_LWW_HLC);
      replicator = std::move(restored.replicator);
      receive = std::move(restored.receive);
    } else {
      replicator = Replicator::create(config.node_id, SB_STRATEGY_LWW_HLC);
      receive = ReceiveState::create();
    }
    sb_relay_driver* handle = sb_relay_driver_new(
        config.relay_url.c_str(), config.channel_id.c_str(), config.channel_token.c_str(),
        config.server_id.c_str(), config.cursor_channel.c_str(), config.group_id.c_str(),
        config.key_epoch, identity.detach(), keyring.detach(), replicator.detach(),
        receive.detach(), config.timeout_ms, config.tls_mode,
        config.ca_der.empty() ? nullptr : config.ca_der.data(), config.ca_der.size());
    if (handle == nullptr) {
      // The library freed all four detached handles already; the detached
      // locals are null so nothing frees them twice.
      fail(sb_last_error_code(), "sb_relay_driver_new");
    }
    return RelayDriver(handle);
  }

  RelayDriver() : handle_(nullptr) {}
  RelayDriver(const RelayDriver&) = delete;
  RelayDriver& operator=(const RelayDriver&) = delete;
  RelayDriver(RelayDriver&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
  }
  RelayDriver& operator=(RelayDriver&& other) noexcept {
    if (this != &other) {
      release();
      handle_ = other.handle_;
      other.handle_ = nullptr;
    }
    return *this;
  }
  ~RelayDriver() { release(); }

  /// Replace the loop's pacing knobs; only effective before start().
  void configure(uint16_t page_limit, std::size_t max_pages_per_cycle,
                 uint64_t initial_backoff_ms, uint64_t max_backoff_ms,
                 uint32_t max_attempts, uint64_t idle_interval_ms) {
    if (sb_relay_driver_config(handle_, page_limit, max_pages_per_cycle, initial_backoff_ms,
                               max_backoff_ms, max_attempts, idle_interval_ms) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_relay_driver_config");
    }
  }
  /// Spawn the worker thread. A second start() while running is an input
  /// error; after stop() the driver may be started again.
  void start() {
    if (sb_relay_driver_start(handle_) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_relay_driver_start");
    }
  }
  /// Cancel the loop and join the worker; idempotent.
  void stop() {
    if (sb_relay_driver_stop(handle_) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_relay_driver_stop");
    }
  }
  /// Stage a local write; the worker sends it on its next cycle.
  void write(const std::string& key, const uint8_t* payload, std::size_t len) {
    if (sb_relay_driver_write(handle_, key.c_str(), payload, len) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_relay_driver_write");
    }
  }
  void write(const std::string& key, const std::string& payload) {
    write(key, reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
  }
  /// Stage a local delete (a causal tombstone), like write().
  void del(const std::string& key) {
    if (sb_relay_driver_delete(handle_, key.c_str()) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_relay_driver_delete");
    }
  }
  /// The live payload; empty when the key has no live value.
  std::optional<Buffer> get(const std::string& key) const {
    Buffer out;
    const int code = sb_relay_driver_get(handle_, key.c_str(), out.raw());
    if (code == SB_RESULT_ABSENT) {
      return std::nullopt;
    }
    if (code != SB_ERR_NONE) {
      fail(code, "sb_relay_driver_get");
    }
    return out;
  }
  /// Whether the worker thread is up.
  bool running() const { return sb_relay_driver_running(handle_) != 0; }
  /// The monotonic counters (and the running flag).
  RelayProgress progress() const {
    sb_relay_progress_t raw{};
    if (sb_relay_driver_progress(handle_, &raw) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_relay_driver_progress");
    }
    return RelayProgress{raw.running != 0, raw.cycles, raw.sent_batches, raw.sent_envelopes,
                         raw.pages_pulled, raw.applied};
  }
  /// One of the kStop* values; kStopNone while running or never started.
  int stop_reason() const { return sb_relay_driver_stop_reason(handle_); }
  /// The text of the error that ended the loop; empty when it ended cleanly.
  std::string error() const {
    const char* text = sb_relay_driver_error(handle_);
    if (text == nullptr) {
      return {};
    }
    std::string out{text};
    sb_free_string(text);
    return out;
  }
  /// The device state plus the receive position as one versioned snapshot, the
  /// blob a later Config::state restores from. PRIVATE material: it embeds the
  /// device identity, so guard it accordingly.
  Buffer export_state() const {
    Buffer out;
    if (sb_relay_driver_export_state(handle_, out.raw()) != SB_ERR_NONE) {
      fail(sb_last_error_code(), "sb_relay_driver_export_state");
    }
    return out;
  }

private:
  explicit RelayDriver(sb_relay_driver* handle) : handle_(handle) {}
  void release() {
    if (handle_ != nullptr) {
      sb_relay_driver_free(handle_);
      handle_ = nullptr;
    }
  }
  sb_relay_driver* handle_;
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
