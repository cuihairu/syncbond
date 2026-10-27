/* pair_sync.cpp - pure C++ consumer of the syncbond C ABI through the RAII
 * wrapper in include/syncbond.hpp.
 *
 * Same flow as examples/pair_sync.c: pair, run a concurrent oplog sync
 * between two replicators, verify convergence, rotate a key epoch, and drive
 * the cross-language conformance runner. Build with the flags used by
 * tests/ffi_cpp.rs:
 *   g++ -std=c++17 -Wall -Werror -o pair_sync examples/pair_sync.cpp \
 *       -I include -L <libdir> -lsyncbond_ffi -Wl,-rpath,<libdir> -lpthread
 */

#include "syncbond.hpp"

#include <cstring>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const std::string& what) {
  if (!condition) {
    std::cerr << "FAIL: " << what << "\n";
    ++failures;
  }
}

const char* FIXTURE =
    "{"
    "\"version\":1,"
    "\"scenarios\":["
    "{\"type\":\"replication\",\"name\":\"lww\",\"strategy\":\"lww\","
    "\"nodes\":{\"left\":1000,\"right\":2000},"
    "\"steps\":["
    "{\"put\":{\"node\":\"left\",\"key\":\"k\",\"payload\":\"bGVmdA\"}},"
    "{\"put\":{\"node\":\"right\",\"key\":\"k\",\"payload\":\"cmlnaHQ\",\"name\":\"left_sees_newer_write\"}},"
    "{\"sync\":[\"left\",\"right\"]},"
    "{\"check\":{\"node\":\"left\",\"key\":\"k\",\"state\":\"live\",\"payload\":\"cmlnaHQ\",\"name\":\"left_sees_newer_write\"}},"
    "{\"check\":{\"node\":\"right\",\"key\":\"k\",\"state\":\"live\",\"payload\":\"cmlnaHQ\",\"name\":\"right_keeps_newer_write\"}}"
    "]},"
    "{\"type\":\"key_epoch\",\"name\":\"rotation\",\"group\":\"g\",\"epoch\":1,\"next_epoch\":2,"
    "\"key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
    "\"next_key\":\"__________________________________________8\","
    "\"survivors\":[\"s1\"],\"removed\":[\"gone\"],"
    "\"plaintext\":\"cGF5bG9hZA\"}"
    "]}";

}  // namespace

int main() {
  using namespace syncbond;

  expect(abi_version() == SYNCBOND_ABI_VERSION, "abi version matches header");
  expect(protocol_version() == 1, "protocol version is 1");

  try {
    /* Pair two freshly generated devices over the in-memory loopback. */
    Pair pair = Pair::memory();
    expect(pair.code.size() == 6, "pairing code has six characters");
    expect(pair.initiator.group_id() == pair.responder.group_id(),
           "both sides derive the same group id");
    expect(!pair.initiator.peer_device_id().empty(), "peer device id is present");

    /* Deterministic replicators on both ends of the paired session. */
    Replicator left = Replicator::create("left", Replicator::kLwwHlc, 1000);
    Replicator right = Replicator::create("right", Replicator::kLwwHlc, 2000);

    left.put("greeting", "hello from cpp");
    right.put("counter", "42");
    left.put("doomed", "x");
    left.del("doomed");

    SyncStats stats = Sync::run(left, pair.initiator, right, pair.responder);
    expect(stats.left_ops == 3, "initiator sent three ops");
    expect(stats.right_ops == 1, "responder sent one op");

    const Buffer greeting = *right.get("greeting");
    expect(greeting.size() == 14 && std::memcmp(greeting.data(), "hello from cpp", 14) == 0,
           "payload survived the sync");
    const Buffer counter = *left.get("counter");
    expect(counter.size() == 2 && std::memcmp(counter.data(), "42", 2) == 0,
           "counter arrived");
    expect(right.get("doomed").has_value() == false, "deleted key stays deleted after sync");

    const std::string dump_left = left.records_json();
    const std::string dump_right = right.records_json();
    expect(dump_left == dump_right, "canonical dumps of both sides are identical");
    std::cout << "converged state: " << dump_left << "\n";

    /* Session invalidation blocks further traffic. */
    expect(!pair.initiator.invalidated(), "session is live before invalidation");
    pair.initiator.invalidate();
    expect(pair.initiator.invalidated(), "session reports invalidated");
    bool rejected = false;
    try {
      pair.initiator.send("late");
    } catch (const Error&) {
      rejected = true;
    }
    expect(rejected, "send after invalidation throws");

    /* Key epoch rotation: seal under the new epoch, open with the same ring. */
    Keyring ring = Keyring::create("group-a");
    const std::vector<uint8_t> key = ring.rotate();
    expect(ring.epoch() == 2 && key.size() == 32, "rotation mints epoch 2 and 32 bytes");

    const std::string envelope = ring.seal("device-1", "secret");
    Buffer plain = ring.open(envelope);
    expect(plain.size() == 6 && std::memcmp(plain.data(), "secret", 6) == 0,
           "sealed payload round trips");

    /* A wrong-epoch keyring cannot open the envelope. */
    Keyring stale = Keyring::create("group-a");
    bool stale_rejected = false;
    try {
      stale.open(envelope);
    } catch (const Error& error) {
      stale_rejected = error.code() == SB_ERR_KEY_EPOCH_MISMATCH;
    }
    expect(stale_rejected, "stale epoch keyring is rejected with KEY_EPOCH_MISMATCH");

    /* Cross-language conformance: same runner, same fixture, every language. */
    const std::string report = conformance_run(FIXTURE);
    expect(report.find("\"ok\":true") != std::string::npos, "conformance report is ok");
    std::cout << "conformance: " << report << "\n";
  } catch (const Error& error) {
    std::cerr << "FAIL: unexpected error " << error.code() << ": " << error.what() << "\n";
    ++failures;
  }

  if (failures != 0) {
    std::cerr << failures << " check(s) failed\n";
    return 1;
  }
  std::cout << "pair_sync: all checks passed\n";
  return 0;
}
