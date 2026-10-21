/**
 * TypeScript bindings skeleton for the syncbond Rust core (`crates/syncbond-core`).
 *
 * This file declares the planned binding surface so applications can be
 * typed against it before the napi-rs implementation lands. The Rust core is
 * the single source of truth; these types mirror its public API
 * (docs/design/language.md).
 */

/** Wire protocol version (crates/syncbond-core/src/crypto.rs). */
export const PROTOCOL_VERSION = 1;

/** Opaque payload bytes — the SDK never interprets these. */
export type Payload = Uint8Array;

/** Long-term device identity (Ed25519), as produced by the core. */
export interface DeviceIdentity {
  readonly deviceId: string;
  readonly publicKey: Uint8Array;
}

/** Public (shareable) subset of a device identity. */
export interface PublicIdentity {
  readonly deviceId: string;
  readonly publicKey: Uint8Array;
}

/** An authenticated, encrypted session established by pairing. */
export interface PairingSession {
  readonly groupId: string;
  readonly sessionKey: Uint8Array;
  readonly role: "initiator" | "responder";
  readonly peerIdentity: PublicIdentity;
  sealAndSend(plaintext: Payload): Promise<void>;
  recvAndOpen(): Promise<Payload>;
  invalidate(): void;
}

/**
 * Initiator side of short-code pairing (displays the code).
 * Throws when codes differ or the peer speaks another protocol version.
 */
export declare function pair(
  displayCode: string,
  identity: DeviceIdentity,
  transport: Transport,
): Promise<PairingSession>;

/** Responder side of short-code pairing (types in the peer's code). */
export declare function accept(
  displayCode: string,
  identity: DeviceIdentity,
  transport: Transport,
): Promise<PairingSession>;

/** Frame-based transport the core talks over (memory loopback included). */
export interface Transport {
  send(frame: Uint8Array): Promise<void>;
  recv(): Promise<Uint8Array>;
}

/**
 * Encrypted envelope, mirroring schemas/envelope.schema.json. All fields
 * except ciphertext are AEAD-associated data.
 */
export interface EncryptedEnvelope {
  protocolVersion: number;
  groupId: string;
  senderDeviceId: string;
  keyEpoch: number;
  messageId: string;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

/** Per-group key material with monotonic epochs (revocation primitive). */
export interface KeyRing {
  readonly groupId: string;
  currentEpoch(): number;
  rotate(): { epoch: number; key: Uint8Array };
}

/**
 * Pluggable conflict strategy. The core ships built-ins (HLC-LWW with
 * tombstones, OR-Set, PN-Counter) but never imposes one.
 */
export interface MergeStrategy {
  merge(local: SyncRecord | undefined, incoming: SyncRecord): SyncRecord;
}

export interface HlcStamp {
  pt: number;
  ct: number;
  id: string;
}

export interface SyncRecord {
  key: string;
  payload: Payload;
  deleted: boolean;
  stamp: HlcStamp;
  witness: { [nodeId: string]: HlcStamp };
  conflicts: SyncRecord[];
}

/** Oplog-based replication engine over any `Transport`. */
export interface Replicator {
  readonly nodeId: string;
  put(key: string, payload: Payload): void;
  delete(key: string): void;
  get(key: string): SyncRecord | undefined;
  syncOver(session: PairingSession, sendFirst: boolean): Promise<SyncStats>;
}

export interface SyncStats {
  sentOps: number;
  receivedOps: number;
  appliedOps: number;
}

/** Swappable persistence (crash-restart consistency is a release gate). */
export interface SyncStorage {
  save(state: Uint8Array): Promise<void>;
  load(): Promise<Uint8Array | null>;
}
