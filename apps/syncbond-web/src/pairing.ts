// Pairing over the relay's pairing rooms, from the browser's seat.
//
// Two relay constraints shape this file. First, a browser `WebSocket`
// cannot set an `Authorization` header, and the relay admits a room only
// to bearers of the room capability — so the capability travels in the
// invite link's `cap` query parameter and the Vite dev proxy lifts it into
// the header, stripping the query before the relay sees the request. The
// capability therefore never rides a URL on the relay side (the frozen
// contract holds); it rides a URL only between the two demo browsers,
// which is the demo's own grade of transport.
//
// Second, the relay greets each join with `room.joined` carrying
// `peerJoined` — false for the first arrival, true for the second — and
// tells nobody that the peer arrived. Roles therefore come from the
// greeting: the second arrival is the SPAKE2 initiator (its first frame
// has a registered peer to reach), the first arrival the responder, which
// waits. Which end created the room is irrelevant; arrival order is what
// the greeting pins, exactly like the native bridge.
//
// After both ends reach `completed`, the initiator hands over the group
// facts (group id, key epoch, session key) through the session's
// host-wired app channel (`sealAppPayload` → a `pairing.frame` on the same
// room socket → `openAppFrame`). The session keyrings are independently
// random per end, so one canonical key must be imported by the other; the
// initiator is always exactly one end, so it is the sender.

import * as wasm from "@syncbond/bindings-ts/src/wasm-gen/syncbond_wasm.js";
import { bytesToB64 } from "./store";

const PROTOCOL_VERSION = 1;
export const RELAY_API = "/relay/api";
export const RELAY_WS = "/relay/ws";
/** The room lives 120 s server-side; give the humans a bit less. */
const PAIRING_TIMEOUT_MS = 110_000;

export interface Invite {
  code: string;
  roomId: string;
  capability: string;
}

/** The group facts the initiator hands the responder after the handshake. */
export interface GroupFacts {
  groupId: string;
  keyEpoch: number;
  groupKeyB64: string;
}

export interface PairOutcome {
  role: "initiator" | "responder";
  facts: GroupFacts;
  peerDeviceId: string;
}

// ------------------------------------------------------------ wire base64

function bytesToB64Url(bytes: Uint8Array): string {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64UrlToBytes(text: string): Uint8Array {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ------------------------------------------------------------ invite side

/** Mint a pairing code and open a relay room for it. */
export async function createInvite(): Promise<Invite> {
  const code = wasm.generate_pairing_code();
  const response = await fetch(`${RELAY_API}/v1/pairing/rooms`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      protocolVersion: PROTOCOL_VERSION,
      requestId: crypto.randomUUID(),
    }),
  });
  if (response.status !== 201) {
    throw new Error(`room creation failed (${response.status}): ${await response.text()}`);
  }
  const created = await response.json();
  return { code, roomId: created.roomId, capability: created.capability };
}

/** The link the second browser opens: room id, capability, and the code. */
export function inviteUrl(invite: Invite): string {
  const url = new URL(window.location.href);
  url.search = "";
  url.hash = "";
  url.searchParams.set("room", invite.roomId);
  url.searchParams.set("cap", invite.capability);
  url.searchParams.set("code", invite.code);
  return url.toString();
}

/** The invite carried by the current page URL, if this is the joiner. */
export function inviteFromLocation(): Invite | null {
  const params = new URLSearchParams(window.location.search);
  const roomId = params.get("room");
  const capability = params.get("cap");
  const code = params.get("code");
  if (!roomId || !capability || !code) return null;
  return { roomId, capability, code };
}

// ------------------------------------------------------------- the pairing

/**
 * Drive one pairing to completion over a room socket, then exchange group
 * facts. Resolves with the facts both ends must agree on (the initiator's
 * session key wins) plus this end's role and peer.
 */
export function pairOverRoom(
  invite: Invite,
  identity: wasm.WasmIdentity,
  log: (line: string) => void,
): Promise<PairOutcome> {
  return new Promise((resolve, reject) => {
    // The proxy owns the Authorization header; the query param is its
    // pickup point and is stripped server-side of the proxy.
    const socket = new WebSocket(
      `${RELAY_WS}/v1/pairing/${invite.roomId}?cap=${encodeURIComponent(invite.capability)}`,
    );

    let end: wasm.WasmPairingEnd | null = null;
    let role: "initiator" | "responder" = "responder";
    let settled = false;
    /** Responder side: the session, held open until the facts frame lands. */
    let pendingFacts: { session: wasm.WasmSession; facts: GroupFacts } | null = null;
    const timer = setTimeout(() => {
      fail(new Error("pairing timed out (a room lives 120 s; create a new invite)"));
      socket.close();
    }, PAIRING_TIMEOUT_MS);

    const succeed = (outcome: PairOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(outcome);
    };
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    };

    const pump = () => {
      if (!end) return;
      while (!end.is_finished) {
        const frame = end.pop_outgoing();
        if (!frame) break;
        socket.send(
          JSON.stringify({
            type: "pairing.frame",
            protocolVersion: PROTOCOL_VERSION,
            data: bytesToB64Url(frame),
          }),
        );
      }
      const event = end.poll();
      if (event === wasm.pairing_event_completed()) {
        const session = end.take_session();
        const facts: GroupFacts = {
          groupId: session.group_id,
          keyEpoch: session.group_key_epoch,
          groupKeyB64: bytesToB64(session.group_key),
        };
        if (role === "initiator") {
          // Hand the canonical key material to the responder through the
          // session's encrypted app channel, over the same socket.
          socket.send(
            JSON.stringify({
              type: "pairing.frame",
              protocolVersion: PROTOCOL_VERSION,
              data: bytesToB64Url(session.seal_app_payload(new TextEncoder().encode(JSON.stringify(facts)))),
            }),
          );
          log(`paired with ${session.peer_device_id}; group facts sent`);
          // Resolve at once: the facts frame is queued ahead of the close
          // frame (TCP ordering), and the responder's goodbye may beat any
          // linger timer — a 1001 from the room teardown is then expected,
          // not a failure.
          socket.close();
          succeed({ role, facts, peerDeviceId: session.peer_device_id });
        }
        // The responder keeps the socket open until the facts frame lands
        // (handled in onmessage below).
        if (role === "responder") {
          pendingFacts = { session, facts };
        }
      } else if (event === wasm.pairing_event_failed()) {
        end.abort();
        fail(new Error(`pairing failed: ${end.failure() ?? "unknown reason"}`));
      }
    };

    socket.onerror = () => fail(new Error("pairing socket error (is the relay running?)"));
    socket.onclose = (event) => {
      if (!settled && !pendingFacts) {
        fail(new Error(`pairing socket closed early (code ${event.code})`));
      }
    };
    socket.onmessage = (raw) => {
      let message: { type: string; peerJoined?: boolean; data?: string; code?: string; message?: string };
      try {
        message = JSON.parse(raw.data as string);
      } catch {
        return;
      }
      if (message.type === "room.joined") {
        role = message.peerJoined ? "initiator" : "responder";
        log(`room joined as ${role} (code ${invite.code})`);
        end = new wasm.WasmPairingEnd(
          identity,
          role === "initiator" ? wasm.pairing_role_initiator() : wasm.pairing_role_responder(),
          invite.code,
        );
        pump();
      } else if (message.type === "pairing.frame") {
        if (!end) return;
        const frame = b64UrlToBytes(message.data ?? "");
        if (!end.is_finished) {
          end.push(frame);
          pump();
        } else if (pendingFacts) {
          // Post-handshake frames on this socket are the initiator's group
          // facts, sealed with the fresh session key.
          try {
            const plaintext = pendingFacts.session.open_app_frame(frame);
            const facts = JSON.parse(new TextDecoder().decode(plaintext)) as GroupFacts;
            log("group facts received; key material imported");
            socket.close();
            succeed({
              role,
              facts,
              peerDeviceId: pendingFacts.session.peer_device_id,
            });
          } catch (error) {
            fail(new Error(`group facts did not open: ${error}`));
          }
        }
      } else if (message.type === "error") {
        fail(new Error(`relay refused: ${message.code} ${message.message}`));
      }
    };
  });
}
