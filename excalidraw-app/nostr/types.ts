/**
 * Nostr identity contracts for the excalidraw app (leaf 0 of
 * PLANS/EXCALIDRAW_NOSTR_AUTH_SPEC.md §4).
 *
 * These types are the shared interface between the signer implementations
 * (leaf 1), the relay-backed drawing storage (leaf 2) and the UI (leaf 3).
 * They must stay free of behaviour so the leaves can be built in parallel.
 *
 * Security invariant (spec §5): the user's private key never appears here.
 * Everything that needs a key goes through `NostrSigner`.
 */
import type { EventTemplate, VerifiedEvent } from "nostr-tools";

export type SignerKind = "nip07" | "nip46";

/** An unsigned event as handed to the signer (nostr-tools shape). */
export type NostrUnsignedEvent = EventTemplate;
/** A signed, id-verified event as returned by the signer. */
export type NostrSignedEvent = VerifiedEvent;

/**
 * Minimal signer surface the app relies on. Implemented for NIP-07
 * (`window.nostr`) and NIP-46 (remote signer) in leaf 1.
 */
export interface NostrSigner {
  readonly kind: SignerKind;
  /** Hex-encoded x-only public key of the user. */
  getPublicKey(): Promise<string>;
  signEvent(event: NostrUnsignedEvent): Promise<NostrSignedEvent>;
  /** NIP-44 v2 encryption to `peerPubkey` (hex). Use the user's own pubkey to encrypt to self. */
  nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
  nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
}

/** Subset of a kind 0 metadata event the app displays. */
export interface NostrProfile {
  name?: string;
  displayName?: string;
  picture?: string;
  nip05?: string;
}

/** What is persisted across reloads. Never contains the user's private key. */
export interface NostrSession {
  /** Hex pubkey of the signed-in user. */
  pubkey: string;
  signerKind: SignerKind;
  /**
   * NIP-46 only. `clientSecretKeyHex` is the app's own ephemeral client key
   * (not the user's), needed to keep talking to the same remote signer.
   */
  nip46?: {
    clientSecretKeyHex: string;
    bunkerPubkey: string;
    relays: string[];
  };
}

export interface NostrRelays {
  read: string[];
  write: string[];
}

export interface NostrIdentity {
  session: NostrSession;
  /** `null` until the kind 0 fetch completes or when the user has no profile. */
  profile: NostrProfile | null;
  /** From kind 10002 (NIP-65); falls back to `DEFAULT_RELAYS` for both lists. */
  relays: NostrRelays;
}

export type NostrAuthState =
  | { status: "signedOut" }
  | { status: "connecting"; kind: SignerKind }
  | { status: "signedIn"; identity: NostrIdentity }
  | { status: "error"; kind: SignerKind; message: string };

/** Display helpers shared by collab and UI (leaf 1 implements, leaf 3/5 consume). */
export interface NostrDisplayIdentity {
  /** Profile display name → name → short npub. Never empty. */
  displayName: string;
  /** Profile picture URL, or `undefined` to fall back to initials. */
  avatarUrl?: string;
  npub: string;
}
