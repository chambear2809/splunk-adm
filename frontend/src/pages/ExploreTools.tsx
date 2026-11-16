import { useId, useState } from "react";
import { isSafeIdentifier, pageURL } from "../app/urlState";

const currentParams = () =>
  new URLSearchParams(typeof location === "undefined" ? "" : location.search);

/** Map link that carries the current scope plus a trace request. */
export function traceURL(
  src: string,
  dst: string,
  params: URLSearchParams = currentParams(),
  scope?: string,
): string {
  const next = new URLSearchParams(params);
  next.delete("id");
  next.set("trace_src", src);
  next.set("trace_dst", dst);
  if (scope) next.set("trace_scope", scope);
  else next.delete("trace_scope");
  return pageURL("map", next);
}

/** Device links retain the selected time and other navigation context. */
export function deviceURL(
  deviceId: string,
  params: URLSearchParams = currentParams(),
): string {
  const next = new URLSearchParams(params);
  next.delete("trace_src");
  next.delete("trace_dst");
  next.delete("trace_scope");
  if (next.has("window") && !next.has("earliest")) {
    next.set("earliest", next.get("window")!);
    if (!next.has("latest")) next.set("latest", "now");
  }
  next.delete("window");
  next.set("id", deviceId);
  return pageURL("device", next);
}

const navigate = (href: string) => location.assign(href);

/** Source → destination trace request (IP or name). */
export function TracePathForm({
  onSubmit = (src, dst, scope) =>
    navigate(traceURL(src, dst, currentParams(), scope)),
  initial,
  compact = false,
}: {
  onSubmit?: (src: string, dst: string, scope?: string) => void;
  initial?: { src: string; dst: string; scope?: string };
  /** Map toolbar: no visible label. */
  compact?: boolean;
}) {
  const id = useId();
  const [src, setSrc] = useState(initial?.src ?? "");
  const [dst, setDst] = useState(initial?.dst ?? "");
  const [scope, setScope] = useState(initial?.scope ?? "");
  const valid = isSafeIdentifier(src.trim()) && isSafeIdentifier(dst.trim());
  return (
    <form
      className={`atlas-tool ${compact ? "compact" : ""}`}
      aria-label="Trace path"
      onSubmit={(event) => {
        event.preventDefault();
        if (valid) onSubmit(src.trim(), dst.trim(), scope.trim() || undefined);
      }}
    >
      <label htmlFor={`${id}-src`} className={compact ? "sr-only" : undefined}>
        Trace
      </label>
      <input
        id={`${id}-src`}
        className="atlas-input"
        aria-label="Trace source"
        placeholder="Source IP or name"
        autoComplete="off"
        spellCheck={false}
        value={src}
        onChange={(e) => setSrc(e.target.value)}
      />
      <span aria-hidden="true">→</span>
      <input
        className="atlas-input"
        aria-label="Trace destination"
        placeholder="Destination"
        autoComplete="off"
        spellCheck={false}
        value={dst}
        onChange={(e) => setDst(e.target.value)}
      />
      <button className="atlas-button" type="submit" disabled={!valid}>
        Trace
      </button>
      <input
        className="atlas-input"
        aria-label="Routing scope"
        placeholder="Routing scope"
        autoComplete="off"
        spellCheck={false}
        value={scope}
        onChange={(e) => setScope(e.target.value)}
      />
    </form>
  );
}

/** Device lookup by name, IP, serial or DN. */
export function DeviceLookup({
  onSelect = (deviceId) => navigate(deviceURL(deviceId)),
  initial = "",
}: {
  onSelect?: (deviceId: string) => void;
  initial?: string;
}) {
  const id = useId();
  const [value, setValue] = useState(initial);
  const valid = isSafeIdentifier(value.trim());
  return (
    <form
      className="atlas-tool"
      aria-label="Device lookup"
      onSubmit={(event) => {
        event.preventDefault();
        if (valid) onSelect(value.trim());
      }}
    >
      <label htmlFor={id}>Device</label>
      <input
        id={id}
        className="atlas-input"
        aria-label="Device name or ID"
        placeholder="Name, IP, serial or DN"
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <button className="atlas-button" type="submit" disabled={!valid}>
        Open
      </button>
    </form>
  );
}

const EXPLORE_TABS = [
  ["applications", "Applications"],
  ["endpoints", "Endpoints"],
] as const;
const ENDPOINT_KEYS = [
  "endpoint_ip",
  "endpoint_scope",
  "endpoint_start",
  "endpoint_end",
];

/** Explore views share one header; endpoint links keep only endpoint state. */
export function ExploreTabs({
  active,
}: {
  /** Undefined on pages reached from Explore, such as a device. */
  active?: (typeof EXPLORE_TABS)[number][0];
}) {
  const params = currentParams();
  return (
    <nav className="atlas-tabs" aria-label="Explore">
      {EXPLORE_TABS.map(([page, label]) => (
        <a
          key={page}
          href={pageURL(
            page,
            page === "endpoints"
              ? new URLSearchParams(
                  [...params].filter(([key]) => ENDPOINT_KEYS.includes(key)),
                )
              : new URLSearchParams(
                  [...params].filter(([key]) => !ENDPOINT_KEYS.includes(key)),
                ),
          )}
          aria-current={active === page ? "page" : undefined}
        >
          {label}
        </a>
      ))}
    </nav>
  );
}
