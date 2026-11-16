/** Detect repeated keys before JSON.parse can silently discard a conflicting value. */
export function rejectDuplicateKeys(input: string) {
  let i = 0;
  const ws = () => {
    while (/\s/.test(input[i] ?? "") && i < input.length) i++;
  };
  const string = (): string => {
    const start = i++;
    while (i < input.length) {
      if (input[i] === "\\") {
        i += 2;
        continue;
      }
      if (input[i++] === '"')
        return JSON.parse(input.slice(start, i)) as string;
    }
    throw new Error("Invalid JSON.");
  };
  const value = (depth: number): void => {
    if (depth > 20) throw new Error("JSON nesting is too deep.");
    ws();
    if (input[i] === '"') {
      string();
      return;
    }
    if (input[i] === "{") {
      i++;
      ws();
      const keys = new Set<string>();
      if (input[i] === "}") {
        i++;
        return;
      }
      while (i < input.length) {
        ws();
        if (input[i] !== '"') throw new Error("Invalid JSON.");
        const key = string();
        if (keys.has(key)) throw new Error(`Duplicate JSON field: ${key}.`);
        keys.add(key);
        ws();
        if (input[i++] !== ":") throw new Error("Invalid JSON.");
        value(depth + 1);
        ws();
        if (input[i] === "}") {
          i++;
          return;
        }
        if (input[i++] !== ",") throw new Error("Invalid JSON.");
      }
      throw new Error("Invalid JSON.");
    }
    if (input[i] === "[") {
      i++;
      ws();
      if (input[i] === "]") {
        i++;
        return;
      }
      while (i < input.length) {
        value(depth + 1);
        ws();
        if (input[i] === "]") {
          i++;
          return;
        }
        if (input[i++] !== ",") throw new Error("Invalid JSON.");
      }
      throw new Error("Invalid JSON.");
    }
    const match =
      /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
        input.slice(i),
      );
    if (!match) throw new Error("Invalid JSON.");
    i += match[0].length;
  };
  value(0);
  ws();
  if (i !== input.length) throw new Error("Invalid JSON.");
}
