/**
 * Jotai atoms for the Nostr identity (leaf 0, spec §4.2). Live in the app
 * store (`appJotaiStore`) like the collab atoms do, so non-React code
 * (Collab.tsx, command palette actions) can read and write them.
 */
import { atom } from "../app-jotai";

import type { NostrAuthState, NostrSigner } from "./types";

export const nostrAuthAtom = atom<NostrAuthState>({ status: "signedOut" });

/** The active signer while signed in; `null` otherwise. Not persisted. */
export const nostrSignerAtom = atom<NostrSigner | null>(null);

/** UI-only: which Nostr dialog is open, if any (leaf 3 consumes). */
export type NostrDialog = "signIn" | "drawings" | null;
export const nostrDialogAtom = atom<NostrDialog>(null);
