/* relay_child.cpp - one C++ device in the two-process relay e2e (todo.md
 * DSR-42). A parent harness spawns two of these (the "two C++ processes" of
 * the acceptance) and a second pair after a restart, so recovery from an
 * exported state snapshot is exercised through real child processes.
 *
 * Usage: relay_child <phase> <config> <out>
 *
 *   phase  live    - a fresh device that writes and syncs.
 *          restart - a device restored from an exported state snapshot.
 *
 * Config lines (one directive per line, the rest is the value):
 *   relayUrl <url>  channelId <id>  token <tok>  groupKeyHex <hex>
 *   node <id>  waitMs <ms>  stateHex <hex>          (restart only)
 *   write <key>=<value>      repeatable
 *   expect <key>=<value>    repeatable
 *   expectBefore <key>=<value>  repeatable          (restart only)
 *
 * The child asserts its own invariants and exits non-zero on failure; the
 * parent checks the exit code and the reported output. Two 1ms ticker threads
 * run for the whole sync wait: the native driver does its blocking work on a
 * separate OS thread, so both must keep firing - the acceptance "blocking
 * work does not occupy the process".
 *
 * Build with the flags used by tests/ffi_cpp.rs:
 *   g++ -std=c++17 -Wall -Wextra -Werror -o relay_child examples/relay_child.cpp \
 *       -I include -L <libdir> -lsyncbond_ffi -Wl,-rpath,<libdir> -lpthread
 */

#include "syncbond.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

std::string g_phase;

void fail(const std::string& message) {
  std::cerr << "relay-child " << (g_phase.empty() ? "?" : g_phase) << ": " << message << "\n";
  std::exit(1);
}

int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string trim(const std::string& value) {
  const std::string space = " \t\r\n";
  const std::string::size_type end = value.find_last_not_of(space);
  return end == std::string::npos ? "" : value.substr(0, end + 1);
}

using KeyValue = std::pair<std::string, std::string>;

KeyValue split_key_value(const std::string& text) {
  const std::string::size_type at = text.find('=');
  if (at == std::string::npos) {
    fail("missing '=' in '" + text + "'");
  }
  return {trim(text.substr(0, at)), trim(text.substr(at + 1))};
}

/// One ticker: the longest gap between its own fires while it runs.
struct GapTracker {
  std::atomic<int64_t> last{now_ms()};
  std::atomic<int64_t> max_gap{0};
  std::atomic<bool> running{true};
};

void tick(GapTracker& tracker) {
  while (tracker.running.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    const int64_t now = now_ms();
    const int64_t gap = now - tracker.last.exchange(now);
    if (gap > tracker.max_gap.load()) {
      tracker.max_gap.store(gap);
    }
  }
}

std::vector<uint8_t> from_hex(const std::string& hex) {
  if (hex.size() % 2 != 0) {
    fail("hex blob has an odd number of digits");
  }
  const auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
  };
  std::vector<uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (std::string::size_type i = 0; i < hex.size(); i += 2) {
    const int high = digit(hex[i]);
    const int low = digit(hex[i + 1]);
    if (high < 0 || low < 0) {
      fail("bad hex digit at offset " + std::to_string(i));
    }
    bytes.push_back(static_cast<uint8_t>((high << 4) | low));
  }
  return bytes;
}

std::string to_hex(const std::vector<uint8_t>& bytes) {
  static const char* digits = "0123456789abcdef";
  std::string out(bytes.size() * 2, '0');
  for (std::vector<uint8_t>::size_type i = 0; i < bytes.size(); ++i) {
    out[2 * i] = digits[bytes[i] >> 4];
    out[2 * i + 1] = digits[bytes[i] & 0xf];
  }
  return out;
}

/// Read the live value, or "" when the key has no live value.
std::string read_value(const syncbond::RelayDriver& driver, const std::string& key) {
  const std::optional<syncbond::Buffer> value = driver.get(key);
  return value.has_value() ? value->text() : "";
}

/// One parsed child config.
struct ChildConfig {
  syncbond::RelayDriver::Config driver;
  std::vector<KeyValue> writes;
  std::vector<KeyValue> expect;
  std::vector<KeyValue> expect_before;
  int64_t wait_ms = 15000;
};

ChildConfig parse_config(const char* path) {
  std::ifstream file(path);
  if (!file) {
    fail(std::string("read config ") + path);
  }

  ChildConfig config;
  std::string state_hex;
  for (std::string line; std::getline(file, line);) {
    const std::string bare = trim(line);
    if (bare.empty() || bare[0] == '#') {
      continue;
    }
    const std::string::size_type at = bare.find_first_of(" \t");
    const std::string directive = at == std::string::npos ? bare : bare.substr(0, at);
    const std::string rest = at == std::string::npos ? "" : trim(bare.substr(at + 1));
    if (directive == "relayUrl") {
      config.driver.relay_url = rest;
    } else if (directive == "channelId") {
      config.driver.channel_id = rest;
    } else if (directive == "token") {
      config.driver.channel_token = rest;
    } else if (directive == "serverId") {
      config.driver.server_id = rest;
    } else if (directive == "cursorChannel") {
      config.driver.cursor_channel = rest;
    } else if (directive == "groupId") {
      config.driver.group_id = rest;
    } else if (directive == "groupKeyHex") {
      config.driver.group_key = from_hex(rest);
    } else if (directive == "node") {
      config.driver.node_id = rest;
    } else if (directive == "stateHex") {
      state_hex = rest;
    } else if (directive == "waitMs") {
      config.wait_ms = std::stoll(rest);
    } else if (directive == "write" || directive == "expect" || directive == "expectBefore") {
      const KeyValue key_value = split_key_value(rest);
      if (directive == "write") {
        config.writes.push_back(key_value);
      } else if (directive == "expect") {
        config.expect.push_back(key_value);
      } else {
        config.expect_before.push_back(key_value);
      }
    } else {
      fail("unknown config directive '" + directive + "'");
    }
  }
  if (!state_hex.empty()) {
    config.driver.state = from_hex(state_hex);
  }
  return config;
}

/// Drive one device through the whole acceptance and write its report. Any
/// failure exits the process; a clean run returns after the report is closed.
void run_device(const std::string& phase, const ChildConfig& config, const char* out_path) {
  using namespace syncbond;

  RelayDriver driver = RelayDriver::open(config.driver);

  // A restored device must already hold what it committed before the restart.
  for (const KeyValue& key_value : config.expect_before) {
    const std::string got = read_value(driver, key_value.first);
    if (got != key_value.second) {
      fail("restored state lost " + key_value.first + ": got '" + got + "', want '" +
           key_value.second + "'");
    }
  }
  driver.configure(2, 8, 1, 2, 1000, 1);

  // The responsiveness probe: if the native driver's blocking calls ran on the
  // process's only thread these tickers would stall while they run. What
  // matters is the longest gap between fires.
  //
  // A second reference ticker separates the two causes of a long gap: OS-level
  // CPU starvation stalls both together, so the relative gap stays near zero
  // and a loaded box does not trip the probe, while a ticker genuinely
  // starved of scheduling next to a freely running reference is a real
  // process stall. The stall reported and checked is the relative one.
  GapTracker ticker;
  GapTracker reference;
  std::thread ticker_thread(tick, std::ref(ticker));
  std::thread reference_thread(tick, std::ref(reference));

  driver.start();
  for (const KeyValue& key_value : config.writes) {
    driver.write(key_value.first, key_value.second);
  }

  const int64_t deadline = now_ms() + config.wait_ms;
  bool converged = false;
  for (;;) {
    bool all = true;
    for (const KeyValue& key_value : config.expect) {
      if (read_value(driver, key_value.first).empty()) {
        all = false;
        break;
      }
    }
    if (all) {
      converged = true;
      break;
    }
    if (now_ms() >= deadline) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }

  // Every write must have reached the relay before this device may report
  // success, or a peer can wait forever: a device converges on its own staged
  // write (it is visible locally) before the worker ships it, so "converged"
  // alone would let b/1 look delivered while it sits unsent in the outbox.
  // Each write seals exactly one envelope, so the relay must ack one per write.
  const uint64_t expected_envelopes = config.writes.size();
  const int64_t push_deadline = now_ms() + 5000;
  while (driver.progress().sent_envelopes < expected_envelopes &&
         now_ms() < push_deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }

  // A convergence failure carries the driver's final state so the cause is not
  // a bare "expected": whether the worker died (EXHAUSTED/FATAL), how far it
  // got, and what it is holding, all surface in one line.
  const RelayProgress before = driver.progress();
  if (driver.progress().sent_envelopes < expected_envelopes) {
    fail("only " + std::to_string(driver.progress().sent_envelopes) + " of " +
         std::to_string(expected_envelopes) + " write envelopes reached the relay (stop " +
         std::to_string(driver.stop_reason()) + ", error '" + driver.error() + "', sent batches " +
         std::to_string(before.sent_batches) + ", applied " + std::to_string(before.applied) + ")");
  }

  std::vector<KeyValue> got;
  got.reserve(config.expect.size());
  for (const KeyValue& key_value : config.expect) {
    const std::string value = read_value(driver, key_value.first);
    if (value != key_value.second) {
      fail("expected " + key_value.first + "='" + key_value.second + "', got '" + value +
           "' (stop " + std::to_string(driver.stop_reason()) + ", error '" + driver.error() +
           "', sent " + std::to_string(before.sent_batches) + ", applied " +
           std::to_string(before.applied) + ", pulled " + std::to_string(before.pages_pulled) +
           ")");
    }
    got.emplace_back(key_value.first, value);
  }
  if (!converged) {
    fail("did not converge on the expected keys (stop " + std::to_string(driver.stop_reason()) +
         ", error '" + driver.error() + "', sent " + std::to_string(before.sent_batches) +
         ", applied " + std::to_string(before.applied) + ")");
  }

  const int64_t reference_max = reference.max_gap.load();
  int64_t stall = ticker.max_gap.load() - reference_max;
  if (stall < 0) {
    stall = 0;
  }
  if (stall >= 250) {
    fail("the process stalled " + std::to_string(stall) + "ms during the sync (reference " +
         std::to_string(reference_max) + "ms)");
  }

  // Cancel the loop and join the worker before reading the outcome, so the
  // stop reason is the deterministic "cancelled" a clean host stop yields.
  driver.stop();
  ticker.running.store(false);
  reference.running.store(false);
  ticker_thread.join();
  reference_thread.join();
  if (driver.running()) {
    fail("driver still running after a clean stop");
  }
  if (driver.stop_reason() != RelayDriver::kStopCancelled) {
    fail("stop reason is " + std::to_string(driver.stop_reason()) + ", want cancelled");
  }
  const std::string error = driver.error();
  if (!error.empty()) {
    fail("clean stop must have no error: " + error);
  }
  const RelayProgress progress = driver.progress();
  const Buffer snapshot = driver.export_state();

  // The report carries the state hex for the parent to hand a restarted
  // device; the driver closes (stopping and freeing) after the write.
  std::ofstream out(out_path, std::ios::binary);
  if (!out) {
    fail(std::string("write output ") + out_path);
  }
  out << "phase=" << phase << "\n";
  out << "node=" << config.driver.node_id << "\n";
  out << "maxStallMs=" << stall << "\n";
  out << "referenceGapMs=" << reference_max << "\n";
  out << "converged=" << (converged ? 1 : 0) << "\n";
  out << "running=" << (progress.running ? 1 : 0) << "\n";
  out << "cycles=" << progress.cycles << "\n";
  out << "sentBatches=" << progress.sent_batches << "\n";
  out << "sentEnvelopes=" << progress.sent_envelopes << "\n";
  out << "pagesPulled=" << progress.pages_pulled << "\n";
  out << "applied=" << progress.applied << "\n";
  out << "stopReason=" << driver.stop_reason() << "\n";
  out << "error=" << error << "\n";
  out << "stateHex=" << to_hex(snapshot.bytes()) << "\n";
  for (const KeyValue& key_value : got) {
    out << "got " << key_value.first << "=" << key_value.second << "\n";
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 4) {
    fail("usage: relay_child <phase> <config> <out>");
  }
  const std::string phase = argv[1];
  g_phase = phase;
  const ChildConfig config = parse_config(argv[2]);
  try {
    run_device(phase, config, argv[3]);
  } catch (const syncbond::Error& error) {
    fail("native error " + std::to_string(error.code()) + ": " + error.what());
  }
  return 0;
}