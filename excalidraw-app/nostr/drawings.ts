/**
 * Relay-backed drawing storage (leaf 2 of PLANS/EXCALIDRAW_NOSTR_AUTH_SPEC.md
 * §4/§6): serialize → size guard → NIP-44 encrypt → publish, and the
 * matching list / load / delete operations.
 *
 * Every operation goes through the caller-supplied `NostrSigner` (leaf 1);
 * this module never sees or derives the user's private key, only ciphertext
 * and signed events (spec §5).
 */

import { randomId } from "@excalidraw/common";

import type { NonDeletedExcalidrawElement } from "@excalidraw/element/types";
import type { BinaryFiles } from "@excalidraw/excalidraw/types";

import {
  DELETION_KIND,
  DRAWING_D_TAG_PREFIX,
  DRAWING_KIND,
  DRAWING_MARKER_TAG,
  MAX_DRAWING_BYTES,
} from "./constants";

import {
  DRAWING_ENVELOPE_VERSION,
  DrawingTooLargeError,
} from "./drawingEnvelope";

import type { Event as NostrToolsEvent, Filter, SimplePool } from "nostr-tools";

import type {
  DrawingAppState,
  DrawingEnvelope,
  PublishResult,
  SavedDrawingSummary,
} from "./drawingEnvelope";
import type { NostrSigner } from "./types";

/** The two `SimplePool` methods this module actually uses; narrowed so tests
 * can supply an in-memory fake instead of opening real WebSocket relays. */
export type RelayPool = Pick<SimplePool, "publish" | "querySync">;

/**
 * Everything a drawings operation needs to talk to relays as a given user.
 *
 * Invariant callers must hold: `pubkey` is always `signer`'s own pubkey
 * (`NostrSession.pubkey`, leaf 1). This module does not re-derive or verify
 * that on every call — `signer.getPublicKey()` is a network round trip for
 * NIP-46 — so build a fresh `DrawingsContext` from the current identity
 * rather than caching one across a sign-out/sign-in. A stale or mismatched
 * `pubkey` here self-encrypts to, signs as, and lists under the wrong key;
 * it cannot leak another user's data, but it can silently save a drawing
 * nobody — including the current user — can read back.
 */
export interface DrawingsContext {
  pool: RelayPool;
  signer: NostrSigner;
  /** Hex pubkey of the signed-in user (same as `signer.getPublicKey()`). */
  pubkey: string;
}

export interface SaveDrawingInput {
  /** Existing drawing id to overwrite (replaceable event); omit to create a new one. */
  id?: string;
  title: string;
  elements: readonly NonDeletedExcalidrawElement[];
  appState: DrawingAppState;
  files: BinaryFiles | null;
}

export interface SaveDrawingResult {
  envelope: DrawingEnvelope;
  publish: PublishResult;
}

export class DrawingNotFoundError extends Error {
  constructor(id: string) {
    super(`No drawing found for id "${id}"`);
    this.name = "DrawingNotFoundError";
  }
}

export class DrawingDecryptError extends Error {
  constructor(id: string, cause: unknown) {
    super(`Failed to decrypt drawing "${id}": ${String(cause)}`);
    this.name = "DrawingDecryptError";
  }
}

export class DrawingEnvelopeParseError extends Error {
  constructor(cause: unknown) {
    super(
      `Decrypted drawing content is not a valid envelope: ${String(cause)}`,
    );
    this.name = "DrawingEnvelopeParseError";
  }
}

const dTagFor = (id: string) => `${DRAWING_D_TAG_PREFIX}${id}`;
const idFromDTag = (dTag: string) => dTag.slice(DRAWING_D_TAG_PREFIX.length);
const nowSeconds = () => Math.floor(Date.now() / 1000);
const byteLength = (s: string) => new TextEncoder().encode(s).length;

const addressableCoordinate = (pubkey: string, id: string) =>
  `${DRAWING_KIND}:${pubkey}:${dTagFor(id)}`;

/** Builds the plaintext envelope; throws `DrawingTooLargeError` before anything is encrypted or sent. */
const buildEnvelope = (
  input: SaveDrawingInput,
): { envelope: DrawingEnvelope; plaintext: string } => {
  const envelope: DrawingEnvelope = {
    v: DRAWING_ENVELOPE_VERSION,
    id: input.id ?? randomId(),
    title: input.title,
    updatedAt: nowSeconds(),
    elements: input.elements,
    appState: input.appState,
    files: input.files,
  };
  const plaintext = JSON.stringify(envelope);
  const bytes = byteLength(plaintext);
  if (bytes > MAX_DRAWING_BYTES) {
    throw new DrawingTooLargeError(bytes, MAX_DRAWING_BYTES);
  }
  return { envelope, plaintext };
};

/** Parses and minimally validates a decrypted envelope; never throws a bare `JSON.parse` error. */
const parseEnvelope = (plaintext: string): DrawingEnvelope => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext);
  } catch (cause) {
    throw new DrawingEnvelopeParseError(cause);
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    (parsed as Partial<DrawingEnvelope>).v !== DRAWING_ENVELOPE_VERSION ||
    typeof (parsed as Partial<DrawingEnvelope>).id !== "string" ||
    typeof (parsed as Partial<DrawingEnvelope>).title !== "string" ||
    typeof (parsed as Partial<DrawingEnvelope>).updatedAt !== "number" ||
    !Array.isArray((parsed as Partial<DrawingEnvelope>).elements)
  ) {
    throw new DrawingEnvelopeParseError("unexpected shape");
  }
  return parsed as DrawingEnvelope;
};

/** Publishes `event` to every relay, settling independently; a relay rejection never throws. */
const publishEvent = async (
  pool: RelayPool,
  relays: readonly string[],
  event: NostrToolsEvent,
): Promise<PublishResult> => {
  const results = await Promise.allSettled(pool.publish([...relays], event));
  const accepted: string[] = [];
  const rejected: { relay: string; reason: string }[] = [];
  results.forEach((result, i) => {
    const relay = relays[i];
    if (result.status === "fulfilled") {
      accepted.push(relay);
    } else {
      rejected.push({ relay, reason: String(result.reason) });
    }
  });
  return { eventId: event.id, accepted, rejected };
};

/**
 * Builds the set of drawing ids the user has deleted (NIP-09, spec §4.3's
 * `DELETION_KIND`), keyed by the latest deletion `created_at` for that id.
 * A drawing event is only considered deleted when it is not newer than the
 * deletion request — an older deletion must never hide a later re-save.
 */
const fetchDeletedIds = async (
  ctx: DrawingsContext,
  relays: readonly string[],
): Promise<Map<string, number>> => {
  const filter: Filter = { kinds: [DELETION_KIND], authors: [ctx.pubkey] };
  const events = await ctx.pool.querySync([...relays], filter);
  const prefix = `${DRAWING_KIND}:${ctx.pubkey}:${DRAWING_D_TAG_PREFIX}`;
  const deleted = new Map<string, number>();
  for (const event of events) {
    for (const tag of event.tags) {
      if (
        tag[0] === "a" &&
        typeof tag[1] === "string" &&
        tag[1].startsWith(prefix)
      ) {
        const id = idFromDTag(
          tag[1].slice(`${DRAWING_KIND}:${ctx.pubkey}:`.length),
        );
        const existing = deleted.get(id);
        if (existing === undefined || event.created_at > existing) {
          deleted.set(id, event.created_at);
        }
      }
    }
  }
  return deleted;
};

/** Keeps only the newest event per `d` tag across every relay queried (addressable last-write-wins). */
const latestPerDTag = (
  events: readonly NostrToolsEvent[],
): NostrToolsEvent[] => {
  const latest = new Map<string, NostrToolsEvent>();
  for (const event of events) {
    const dTag = event.tags.find((tag) => tag[0] === "d")?.[1];
    if (dTag === undefined) {
      continue;
    }
    const existing = latest.get(dTag);
    if (
      existing === undefined ||
      event.created_at > existing.created_at ||
      (event.created_at === existing.created_at && event.id > existing.id)
    ) {
      latest.set(dTag, event);
    }
  }
  return [...latest.values()];
};

/** Saves (or overwrites, when `input.id` is set) a drawing as a self-encrypted addressable event. */
export const saveDrawing = async (
  ctx: DrawingsContext,
  relays: readonly string[],
  input: SaveDrawingInput,
): Promise<SaveDrawingResult> => {
  const { envelope, plaintext } = buildEnvelope(input);
  const ciphertext = await ctx.signer.nip44Encrypt(ctx.pubkey, plaintext);
  const signed = await ctx.signer.signEvent({
    kind: DRAWING_KIND,
    created_at: envelope.updatedAt,
    tags: [
      ["d", dTagFor(envelope.id)],
      ["t", DRAWING_MARKER_TAG],
    ],
    content: ciphertext,
  });
  const publish = await publishEvent(ctx.pool, relays, signed);
  return { envelope, publish };
};

/** Lists the user's drawings, newest first. Decrypt failures become `undecryptable` rows, never thrown errors. */
export const listDrawings = async (
  ctx: DrawingsContext,
  relays: readonly string[],
): Promise<SavedDrawingSummary[]> => {
  const filter: Filter = {
    kinds: [DRAWING_KIND],
    authors: [ctx.pubkey],
    "#t": [DRAWING_MARKER_TAG],
  };
  const [rawEvents, deletedIds] = await Promise.all([
    ctx.pool.querySync([...relays], filter),
    fetchDeletedIds(ctx, relays),
  ]);

  const summaries: SavedDrawingSummary[] = [];
  for (const event of latestPerDTag(rawEvents)) {
    const dTag = event.tags.find((tag) => tag[0] === "d")?.[1];
    if (dTag === undefined) {
      continue;
    }
    const id = idFromDTag(dTag);
    const deletedAt = deletedIds.get(id);
    if (deletedAt !== undefined && deletedAt >= event.created_at) {
      continue;
    }

    const bytes = byteLength(event.content);
    try {
      const plaintext = await ctx.signer.nip44Decrypt(
        ctx.pubkey,
        event.content,
      );
      const envelope = parseEnvelope(plaintext);
      summaries.push({
        id: envelope.id,
        title: envelope.title,
        updatedAt: envelope.updatedAt,
        bytes,
        eventId: event.id,
      });
    } catch {
      summaries.push({
        id,
        title: "",
        updatedAt: event.created_at,
        bytes,
        eventId: event.id,
        undecryptable: true,
      });
    }
  }

  return summaries.sort((a, b) => b.updatedAt - a.updatedAt);
};

/** Loads and decrypts a single drawing by id. Throws rather than returning a partial result. */
export const loadDrawing = async (
  ctx: DrawingsContext,
  relays: readonly string[],
  id: string,
): Promise<DrawingEnvelope> => {
  const filter: Filter = {
    kinds: [DRAWING_KIND],
    authors: [ctx.pubkey],
    "#d": [dTagFor(id)],
  };
  const [events, deletedIds] = await Promise.all([
    ctx.pool.querySync([...relays], filter),
    fetchDeletedIds(ctx, relays),
  ]);
  const [latest] = latestPerDTag(events);
  const deletedAt = deletedIds.get(id);
  // A relay that never processed the NIP-09 deletion (or simply lags) can
  // still serve the pre-deletion event; without this check a deleted
  // drawing could be resurrected by loading it directly (e.g. a stale
  // bookmark), even though listDrawings correctly hides it.
  if (!latest || (deletedAt !== undefined && deletedAt >= latest.created_at)) {
    throw new DrawingNotFoundError(id);
  }

  let plaintext: string;
  try {
    plaintext = await ctx.signer.nip44Decrypt(ctx.pubkey, latest.content);
  } catch (cause) {
    throw new DrawingDecryptError(id, cause);
  }
  return parseEnvelope(plaintext);
};

/** Publishes a NIP-09 deletion request for the drawing's addressable coordinate. */
export const deleteDrawing = async (
  ctx: DrawingsContext,
  relays: readonly string[],
  id: string,
): Promise<PublishResult> => {
  const signed = await ctx.signer.signEvent({
    kind: DELETION_KIND,
    created_at: nowSeconds(),
    tags: [["a", addressableCoordinate(ctx.pubkey, id)]],
    content: "",
  });
  return publishEvent(ctx.pool, relays, signed);
};
