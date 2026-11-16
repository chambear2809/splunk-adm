import { previewBusinessServiceImport, type ImportPreview } from "./import";

const KEY = "application-atlas.business-service-import.v1";
export type LocalImportResult =
  | { status: "ready"; preview: ImportPreview }
  | { status: "empty" }
  | { status: "unavailable" }
  | { status: "uncertain" };

/** Browser-local data is untrusted and is revalidated on every read. */
export function readLocalImport(
  storage: Storage | undefined,
): LocalImportResult {
  if (!storage) return { status: "unavailable" };
  try {
    const value = storage.getItem(KEY);
    if (value === null) return { status: "empty" };
    const preview = previewBusinessServiceImport(value);
    return preview.errors.length
      ? { status: "uncertain" }
      : { status: "ready", preview };
  } catch {
    return { status: "unavailable" };
  }
}

/** Replace one local batch only after explicit user action and whole-batch validation. */
export function saveLocalImport(
  storage: Storage | undefined,
  input: string,
): LocalImportResult {
  const preview = previewBusinessServiceImport(input);
  if (preview.errors.length) return { status: "uncertain" };
  if (!storage) return { status: "unavailable" };
  try {
    storage.setItem(KEY, input);
    const result = readLocalImport(storage);
    return result.status === "empty" ? { status: "uncertain" } : result;
  } catch {
    return { status: "unavailable" };
  }
}
export function clearLocalImport(
  storage: Storage | undefined,
): LocalImportResult {
  if (!storage) return { status: "unavailable" };
  try {
    storage.removeItem(KEY);
    const result = readLocalImport(storage);
    return result.status === "ready" ? { status: "uncertain" } : result;
  } catch {
    return { status: "unavailable" };
  }
}
export function browserLocalStorage(): Storage | undefined {
  try {
    return typeof window === "undefined" ? undefined : window.localStorage;
  } catch {
    return undefined;
  }
}
