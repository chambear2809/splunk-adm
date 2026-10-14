/** User-specific preferences. Storage is optional (private browsing / policy). */
export function prefsFor(
  user: string,
  storage: Storage | undefined = typeof localStorage === "undefined"
    ? undefined
    : localStorage,
) {
  const key = `splunk_adm:${encodeURIComponent(user)}:prefs:v1`;
  return {
    read(): Record<string, unknown> {
      try {
        const value: unknown = JSON.parse(storage?.getItem(key) ?? "{}");
        return value && typeof value === "object" && !Array.isArray(value)
          ? (value as Record<string, unknown>)
          : {};
      } catch {
        return {};
      }
    },
    write(value: Record<string, unknown>): void {
      try {
        storage?.setItem(key, JSON.stringify(value));
      } catch {
        /* Storage is not required to use Atlas. */
      }
    },
  };
}
