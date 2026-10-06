/**
 * Wire format of a drawing saved to relays (leaf 0, spec §4.4). The envelope
 * is JSON-serialized, NIP-44-encrypted to the user's own pubkey and stored as
 * the `content` of a kind `DRAWING_KIND` event. Only the summary fields that
 * come from event metadata (`updatedAt` from `created_at`, `eventId`) are
 * visible to relays; everything in the envelope is ciphertext.
 */
import type { NonDeletedExcalidrawElement } from "@excalidraw/element/types";
import type { AppState, BinaryFiles } from "@excalidraw/excalidraw/types";

export const DRAWING_ENVELOPE_VERSION = 1 as const;

/** The appState subset worth persisting; same spirit as `exportToBackend`. */
export type DrawingAppState = Partial<
  Pick<
    AppState,
    "viewBackgroundColor" | "gridSize" | "gridStep" | "gridModeEnabled" | "name"
  >
>;

export interface DrawingEnvelope {
  v: typeof DRAWING_ENVELOPE_VERSION;
  /** Stable drawing id; `d` tag is `${DRAWING_D_TAG_PREFIX}${id}`. */
  id: string;
  title: string;
  /** Unix seconds, client clock at save time. */
  updatedAt: number;
  elements: readonly NonDeletedExcalidrawElement[];
  appState: DrawingAppState;
  /** Inlined files; `null` when the drawing has none. Subject to MAX_DRAWING_BYTES. */
  files: BinaryFiles | null;
}

/** What the "My drawings" list shows per saved drawing (decrypted title). */
export interface SavedDrawingSummary {
  id: string;
  title: string;
  updatedAt: number;
  /** Ciphertext size in bytes as seen on the relay. */
  bytes: number;
  eventId: string;
  /** `true` when the envelope could not be decrypted; title is then a placeholder. */
  undecryptable?: boolean;
}

export type PublishResult = {
  eventId: string;
  accepted: string[];
  rejected: { relay: string; reason: string }[];
};

/** Thrown before publish when the plaintext envelope exceeds the cap. */
export class DrawingTooLargeError extends Error {
  constructor(public readonly bytes: number, public readonly max: number) {
    super(`Drawing is ${bytes} bytes; the maximum is ${max} bytes`);
    this.name = "DrawingTooLargeError";
  }
}
