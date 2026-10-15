/** User-specific preferences. Storage is optional (private browsing / policy). */
export function prefsFor(user: string, storage?: Storage) {
  try {
    storage ??= typeof localStorage === "undefined" ? undefined : localStorage;
  } catch {
    /* Browser policy may prevent even reading the storage property. */
  }
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

export const PERSONAS = {
  network: "Network operations",
  application: "Application operations",
} as const;
export type Persona = keyof typeof PERSONAS;
export const PERSONA_VIEWS = {
  network: "network",
  application: "services",
} as const;
export function mapPreferences(value: Record<string, unknown>) {
  const persona: Persona =
    value.persona === "application" ? "application" : "network";
  return {
    persona,
    view: PERSONA_VIEWS[persona],
    mergeFrontends: value.mergeFrontends !== false,
  };
}
