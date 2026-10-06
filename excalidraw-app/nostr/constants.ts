/**
 * Nostr constants (leaf 0, spec §4.3). Values here are part of the wire
 * format of saved drawings: changing `DRAWING_KIND` or the tags breaks
 * compatibility with drawings already on relays.
 */

/** NIP-78 application-specific data (addressable). */
export const DRAWING_KIND = 30078;

/** `d` tag prefix; the full value is `excalidraw:<drawing uuid>`. */
export const DRAWING_D_TAG_PREFIX = "excalidraw:";

/**
 * Plaintext marker so the app can list its own drawings with a single
 * `#t` filter. Leaks only "this pubkey has excalidraw drawings" plus event
 * timestamps; titles and content are inside the NIP-44 ciphertext.
 */
export const DRAWING_MARKER_TAG = "excalidraw-drawing";

/** Kind 5 deletion request (NIP-09) used to delete a saved drawing. */
export const DELETION_KIND = 5;

/**
 * Plaintext size cap for a serialized drawing envelope, in bytes. Most public
 * relays reject events above 64–128 KiB; NIP-44 and JSON add overhead.
 * Enforced before encryption and before any relay publish.
 */
export const MAX_DRAWING_BYTES = 100_000;

/** NIP-46 request timeout. A timeout is an error state, never a hang. */
export const NIP46_TIMEOUT_MS = 30_000;

/** Prefix of every localStorage key the Nostr feature owns (cleared on sign out). */
export const NOSTR_STORAGE_PREFIX = "nostr.";
export const NOSTR_STORAGE_KEYS = {
  SESSION: `${NOSTR_STORAGE_PREFIX}session`,
} as const;

const FALLBACK_RELAYS = [
  "wss://relay.damus.io",
  "wss://nos.lol",
  "wss://relay.nostr.band",
] as const;

/**
 * Relay URL validation (spec §5): `wss://` always; `ws://` only in dev builds.
 */
export const isAllowedRelayUrl = (url: string): boolean => {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol === "wss:") {
    return true;
  }
  return parsed.protocol === "ws:" && import.meta.env.DEV === true;
};

const parseRelayList = (raw: string | undefined): string[] =>
  (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && isAllowedRelayUrl(s));

/**
 * Relays used before the user's NIP-65 list is known (and as the fallback when
 * they have none). Configurable with `VITE_APP_NOSTR_RELAYS` (comma-separated).
 */
export const DEFAULT_RELAYS: readonly string[] = (() => {
  const configured = parseRelayList(import.meta.env.VITE_APP_NOSTR_RELAYS);
  return configured.length > 0 ? configured : [...FALLBACK_RELAYS];
})();
