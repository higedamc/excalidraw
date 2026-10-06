import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  matchFilter,
  nip44,
} from "nostr-tools";
import { describe, expect, test, vi } from "vitest";

import { API } from "@excalidraw/excalidraw/tests/helpers/api";

import {
  DrawingDecryptError,
  DrawingNotFoundError,
  deleteDrawing,
  listDrawings,
  loadDrawing,
  saveDrawing,
} from "./drawings";

import {
  DRAWING_D_TAG_PREFIX,
  DRAWING_KIND,
  MAX_DRAWING_BYTES,
} from "./constants";
import { DrawingTooLargeError } from "./drawingEnvelope";

import type { Event as NostrToolsEvent, Filter } from "nostr-tools";

import type { DrawingsContext, RelayPool, SaveDrawingInput } from "./drawings";
import type { NostrSigner, NostrUnsignedEvent } from "./types";

/** A signer backed by a local secret key, for round-trip tests only — never used in the app. */
class TestLocalKeySigner implements NostrSigner {
  readonly kind = "nip07" as const;
  private readonly secretKey: Uint8Array;

  constructor(secretKey: Uint8Array = generateSecretKey()) {
    this.secretKey = secretKey;
  }

  async getPublicKey() {
    return getPublicKey(this.secretKey);
  }

  async signEvent(event: NostrUnsignedEvent) {
    return finalizeEvent(event, this.secretKey);
  }

  async nip44Encrypt(peerPubkey: string, plaintext: string) {
    const key = nip44.v2.utils.getConversationKey(this.secretKey, peerPubkey);
    return nip44.v2.encrypt(plaintext, key);
  }

  async nip44Decrypt(peerPubkey: string, ciphertext: string) {
    const key = nip44.v2.utils.getConversationKey(this.secretKey, peerPubkey);
    return nip44.v2.decrypt(ciphertext, key);
  }
}

/** In-memory stand-in for `SimplePool`; no real relay/network I/O in these tests. */
class FakeRelayPool implements RelayPool {
  readonly events: NostrToolsEvent[] = [];

  publish(relays: string[], event: NostrToolsEvent): Promise<string>[] {
    this.events.push(event);
    return relays.map(() => Promise.resolve(""));
  }

  async querySync(
    _relays: string[],
    filter: Filter,
  ): Promise<NostrToolsEvent[]> {
    return this.events.filter((event) => matchFilter(filter, event));
  }
}

const sampleInput = (
  overrides: Partial<SaveDrawingInput> = {},
): SaveDrawingInput => ({
  title: "Groceries",
  elements: [API.createElement({ type: "rectangle" })],
  appState: { viewBackgroundColor: "#ffffff" },
  files: null,
  ...overrides,
});

const makeContext = async (): Promise<{
  ctx: DrawingsContext;
  pool: FakeRelayPool;
}> => {
  const signer = new TestLocalKeySigner();
  const pool = new FakeRelayPool();
  const pubkey = await signer.getPublicKey();
  return { ctx: { pool, signer, pubkey }, pool };
};

const RELAYS = ["wss://relay.example"];

describe("drawings", () => {
  test("round trip: saveDrawing then loadDrawing returns the same content", async () => {
    const { ctx } = await makeContext();
    const { envelope, publish } = await saveDrawing(ctx, RELAYS, sampleInput());

    expect(publish.accepted).toEqual(RELAYS);
    expect(publish.rejected).toEqual([]);

    const loaded = await loadDrawing(ctx, RELAYS, envelope.id);
    expect(loaded.title).toBe("Groceries");
    expect(loaded.elements).toEqual(envelope.elements);
    expect(loaded.appState).toEqual({ viewBackgroundColor: "#ffffff" });
  });

  test("the raw relay event content is NIP-44 ciphertext, not the plaintext title", async () => {
    const { ctx, pool } = await makeContext();
    await saveDrawing(ctx, RELAYS, sampleInput());

    expect(pool.events).toHaveLength(1);
    expect(pool.events[0].content).not.toContain("Groceries");
  });

  test("listDrawings surfaces title, updatedAt, bytes and eventId", async () => {
    const { ctx } = await makeContext();
    const { envelope } = await saveDrawing(ctx, RELAYS, sampleInput());

    const list = await listDrawings(ctx, RELAYS);
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      id: envelope.id,
      title: "Groceries",
      updatedAt: envelope.updatedAt,
    });
    expect(list[0].undecryptable).toBeUndefined();
    expect(list[0].bytes).toBeGreaterThan(0);
  });

  test("overwriting an existing id (same d tag) leaves exactly one, newest, entry", async () => {
    vi.useFakeTimers();
    try {
      const { ctx, pool } = await makeContext();
      const { envelope } = await saveDrawing(
        ctx,
        RELAYS,
        sampleInput({ title: "v1" }),
      );
      // Nostr timestamps are 1-second resolution; advance the clock so the
      // second save is unambiguously newer, same as two real-world saves a
      // beat apart.
      vi.advanceTimersByTime(1000);
      await saveDrawing(
        ctx,
        RELAYS,
        sampleInput({ id: envelope.id, title: "v2" }),
      );

      expect(pool.events).toHaveLength(2); // both revisions reach the relay...
      const list = await listDrawings(ctx, RELAYS);
      expect(list).toHaveLength(1); // ...but only the newest is listed
      expect(list[0].title).toBe("v2");
    } finally {
      vi.useRealTimers();
    }
  });

  test("another signer's garbled event is listed as undecryptable, not thrown", async () => {
    const { ctx, pool } = await makeContext();
    const signed = await ctx.signer.signEvent({
      kind: DRAWING_KIND,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["d", `${DRAWING_D_TAG_PREFIX}corrupted`],
        ["t", "excalidraw-drawing"],
      ],
      content: "not-valid-nip44-ciphertext",
    });
    pool.events.push(signed);

    const list = await listDrawings(ctx, RELAYS);
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ id: "corrupted", undecryptable: true });
  });

  test("loadDrawing throws DrawingDecryptError instead of returning a partial result", async () => {
    const { ctx, pool } = await makeContext();
    const signed = await ctx.signer.signEvent({
      kind: DRAWING_KIND,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["d", `${DRAWING_D_TAG_PREFIX}corrupted`],
        ["t", "excalidraw-drawing"],
      ],
      content: "not-valid-nip44-ciphertext",
    });
    pool.events.push(signed);

    await expect(loadDrawing(ctx, RELAYS, "corrupted")).rejects.toBeInstanceOf(
      DrawingDecryptError,
    );
  });

  test("loadDrawing throws DrawingNotFoundError for an unknown id", async () => {
    const { ctx } = await makeContext();
    await expect(loadDrawing(ctx, RELAYS, "missing")).rejects.toBeInstanceOf(
      DrawingNotFoundError,
    );
  });

  test("deleteDrawing hides the drawing from subsequent listDrawings calls", async () => {
    const { ctx } = await makeContext();
    const { envelope } = await saveDrawing(ctx, RELAYS, sampleInput());
    expect(await listDrawings(ctx, RELAYS)).toHaveLength(1);

    await deleteDrawing(ctx, RELAYS, envelope.id);
    expect(await listDrawings(ctx, RELAYS)).toHaveLength(0);
  });

  test("a deleted drawing cannot be resurrected by loading it directly", async () => {
    // Simulates a relay that still serves the pre-deletion event (stale or
    // non-compliant with NIP-09) and a stale bookmark/tab that still has the
    // id — loadDrawing must not trust the relay's deletion enforcement.
    const { ctx } = await makeContext();
    const { envelope } = await saveDrawing(ctx, RELAYS, sampleInput());
    await deleteDrawing(ctx, RELAYS, envelope.id);

    await expect(loadDrawing(ctx, RELAYS, envelope.id)).rejects.toBeInstanceOf(
      DrawingNotFoundError,
    );
  });

  test("an oversized drawing is rejected before touching the relay", async () => {
    const { ctx, pool } = await makeContext();
    const oversizedTitle = "x".repeat(MAX_DRAWING_BYTES + 1);

    await expect(
      saveDrawing(ctx, RELAYS, sampleInput({ title: oversizedTitle })),
    ).rejects.toBeInstanceOf(DrawingTooLargeError);
    expect(pool.events).toHaveLength(0);
  });
});
