import { parseUrlState, stateParams, type UrlState } from "./urlState";

export interface SavedView {
  id: string;
  name: string;
  state: UrlState;
}

const cleanName = (name: string) => {
  const value = name.trim();
  if (
    !value ||
    value.length > 80 ||
    [...value].some(
      (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
    )
  )
    throw new Error("View name must be 1–80 printable characters.");
  return value;
};
const validState = (value: unknown): UrlState | undefined => {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return undefined;
  try {
    const params = stateParams(value as UrlState);
    return parseUrlState(params, false);
  } catch {
    return undefined;
  }
};

export function savedViewsFor(user?: string, storage?: Storage) {
  const identity = typeof user === "string" ? user.trim() : "";
  const enabled = !!identity;
  const key = enabled
    ? `splunk_adm:${encodeURIComponent(identity)}:views:v1`
    : "";
  const getStorage = () => {
    try {
      if (storage) return storage;
      if (typeof localStorage === "undefined") return undefined;
      return localStorage;
    } catch {
      return undefined;
    }
  };
  const read = (): SavedView[] => {
    if (!enabled) return [];
    try {
      const parsed: unknown = JSON.parse(getStorage()?.getItem(key) ?? "[]");
      if (!Array.isArray(parsed)) return [];
      return parsed.flatMap((item) => {
        if (!item || typeof item !== "object") return [];
        const record = item as Record<string, unknown>;
        const state = validState(record.state);
        if (
          typeof record.id !== "string" ||
          typeof record.name !== "string" ||
          !state
        )
          return [];
        try {
          cleanName(record.name);
        } catch {
          return [];
        }
        return [{ id: record.id, name: record.name, state }];
      });
    } catch {
      return [];
    }
  };
  const write = (views: SavedView[]) => {
    if (!enabled) throw new Error("Sign in to save views.");
    const target = getStorage();
    if (!target) throw new Error("Browser storage is unavailable.");
    try {
      target.setItem(key, JSON.stringify(views));
    } catch {
      throw new Error("Saved views could not be stored.");
    }
  };
  return {
    enabled,
    read,
    save(name: string, state: UrlState): SavedView {
      const view = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
        name: cleanName(name),
        state: validState(state),
      };
      if (!view.state) throw new Error("Current view state is invalid.");
      const saved = view as SavedView;
      write(
        [saved, ...read().filter((item) => item.name !== saved.name)].slice(
          0,
          50,
        ),
      );
      return saved;
    },
    remove(id: string) {
      write(read().filter((view) => view.id !== id));
    },
  };
}
