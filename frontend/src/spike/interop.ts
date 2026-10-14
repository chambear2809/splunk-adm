/** Vite 8 preserves the namespace of Toolkit's webpack CommonJS bundles. */
export function toolkitDefault<T>(value: T): T {
  return (value as T & { default?: T }).default ?? value;
}
