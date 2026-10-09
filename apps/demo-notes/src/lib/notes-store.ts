/** Demo storage: in memory, per user (`sub`). Restarting the container clears it. */
import "server-only";
import { randomUUID } from "node:crypto";

export type Note = { id: string; text: string; createdAt: string };

const globalStore = globalThis as unknown as { __notes?: Map<string, Note[]> };
const store = (globalStore.__notes ??= new Map<string, Note[]>());

export const notes = {
  list: (sub: string): Note[] => store.get(sub) ?? [],
  add(sub: string, text: string): Note {
    const note = { id: randomUUID(), text, createdAt: new Date().toISOString() };
    store.set(sub, [note, ...notes.list(sub)]);
    return note;
  },
  remove(sub: string, id: string): boolean {
    const before = notes.list(sub);
    const after = before.filter((n) => n.id !== id);
    store.set(sub, after);
    return after.length !== before.length;
  },
};
