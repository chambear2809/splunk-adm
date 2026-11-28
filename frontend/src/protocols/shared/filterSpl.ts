import { literal } from "../../data/evidence";
import type { ProtocolFilter } from "./contract";

function orFields(fields: readonly string[], rawValue: string): string {
  const val = literal(rawValue, 128);
  if (fields.length === 1) return `${fields[0]}="${val}"`;
  return `(${fields.map((f) => `${f}="${val}"`).join(" OR ")})`;
}

/**
 * Builds literal-quoted SPL predicates for flow endpoints (`src`, `dst`) and
 * optional L4 `port`, supporting directional (`src -> dst`) and bidirectional
 * (`A <-> B`) matching so request and reply flows can be inspected together.
 */
export function buildFlowEndpointPredicates(options: {
  filter?: ProtocolFilter;
  srcFields: readonly string[];
  dstFields: readonly string[];
  portFields?: readonly string[];
}): string[] {
  const { filter, srcFields, dstFields, portFields } = options;
  if (!filter) return [];
  const predicates: string[] = [];

  if (filter.bidirectional) {
    if (filter.src && filter.dst) {
      const fwd = `(${orFields(srcFields, filter.src)} AND ${orFields(dstFields, filter.dst)})`;
      const rev = `(${orFields(srcFields, filter.dst)} AND ${orFields(dstFields, filter.src)})`;
      predicates.push(`(${fwd} OR ${rev})`);
    } else if (filter.src || filter.dst) {
      const endpoint = (filter.src ?? filter.dst)!;
      const allFields = [...new Set([...srcFields, ...dstFields])];
      predicates.push(orFields(allFields, endpoint));
    }
  } else {
    if (filter.src) predicates.push(orFields(srcFields, filter.src));
    if (filter.dst) predicates.push(orFields(dstFields, filter.dst));
  }

  if (filter.port && portFields && portFields.length > 0) {
    predicates.push(orFields(portFields, filter.port));
  }

  return predicates;
}

/**
 * Client-side bidirectional/directional check matching `buildFlowEndpointPredicates`.
 */
export function matchesFlowEndpoints(
  filter: ProtocolFilter | undefined,
  srcValue: string | undefined,
  dstValue: string | undefined,
  ports?: readonly (number | string | undefined)[],
): boolean {
  if (!filter) return true;
  const s = srcValue?.toLowerCase();
  const d = dstValue?.toLowerCase();
  const wantSrc = filter.src?.toLowerCase();
  const wantDst = filter.dst?.toLowerCase();

  if (filter.bidirectional) {
    if (wantSrc && wantDst) {
      const fwd = s === wantSrc && d === wantDst;
      const rev = s === wantDst && d === wantSrc;
      if (!fwd && !rev) return false;
    } else if (wantSrc || wantDst) {
      const target = (wantSrc ?? wantDst)!;
      if (s !== target && d !== target) return false;
    }
  } else {
    if (wantSrc && s !== wantSrc) return false;
    if (wantDst && d !== wantDst) return false;
  }

  if (filter.port && ports && ports.length > 0) {
    const matched = ports.some(
      (p) => p !== undefined && String(p) === filter.port,
    );
    if (!matched) return false;
  }
  return true;
}

/**
 * Collects unique non-empty values for `<datalist>` filter autocomplete,
 * capped to keep DOM compact.
 */
export function collectFilterSuggestions(
  values: Iterable<string | number | undefined | null>,
  limit = 24,
): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of values) {
    if (raw === undefined || raw === null) continue;
    const s = String(raw).trim();
    if (!s || s === "—" || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
    if (out.length >= limit) break;
  }
  return out;
}
