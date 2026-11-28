// Ambient declarations for the two untyped deep imports the demo makes into
// packages/ts-bindings. The raw wasm classes are NOT declared here: they
// resolve to the generated `src/wasm-gen/syncbond_wasm.d.ts`, which is the
// one source of truth for that surface (wasm-bindgen emits snake_case
// methods and getter properties). Run the bindings' `build:wasm` before
// typechecking — the generated module does not exist in a fresh checkout.

declare module "@syncbond/bindings-ts/src/wasm/wrapper.js" {
  export function loadSyncbondWasm(): Promise<void>;
}

declare module "@syncbond/bindings-ts/src/wasm/browser-driver.js" {
  import type {
    WasmIdentity,
    WasmKeyring,
    WasmReplicator,
    WasmReceiveState,
  } from "@syncbond/bindings-ts/src/wasm-gen/syncbond_wasm.js";

  export interface RelayDeviceConfig {
    nodeId: string;
    relayUrl: string;
    channelId: string;
    token: string;
    serverId: string;
    cursorChannel: string;
    groupId: string;
    keyEpoch: number;
    groupKey32: Uint8Array;
    identity?: WasmIdentity;
    dbName?: string;
    snapshotBytes?: Uint8Array;
  }

  export interface RelayDevice {
    identity: WasmIdentity;
    keyring: WasmKeyring;
    nodeId: string;
    relayUrl: string;
    channelId: string;
    outbox: string[];
    replicator: WasmReplicator;
    receive: WasmReceiveState;
    mode: "indexeddb" | "memory";
    persistenceWarning: string | null;
  }

  export interface SyncReport {
    appended: number;
    pulled: number;
    applied: number;
  }

  export function createRelayDevice(config: RelayDeviceConfig): Promise<RelayDevice>;
  /** Persist the device snapshot; `commit` marks the cursor-advance write. */
  export function persistDevice(device: RelayDevice, commit?: boolean): Promise<void>;
  export function write(device: RelayDevice, key: string, payload: Uint8Array): Promise<string>;
  export function remove(device: RelayDevice, key: string): Promise<string>;
  export function syncOnce(device: RelayDevice): Promise<SyncReport>;
  export function get(device: RelayDevice, key: string): string | null;
  export function keys(device: RelayDevice): string[];
  export function recordCount(device: RelayDevice): number;
}
