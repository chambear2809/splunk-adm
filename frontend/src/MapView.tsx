import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Box,
  ChevronDown,
  CircleHelp,
  DoorOpen,
  Globe,
  HardDrive,
  Layers,
  Maximize2,
  Minus,
  Plus,
  Server,
  Split,
  Users,
} from "lucide-react";
import {
  tunnelOf,
  type GraphEdge,
  type GraphIndex,
  type GraphNode,
} from "./graph";
import { edgeIdentity, endpointKindLabel, isUnknown } from "./glossary";
import type { Item, Layout, RoutedEdge } from "./layout";
import { HEADER_H, policyBadge, policyText } from "./layout";

export type Selection = { kind: "node" | "edge"; id: string };
export interface Transform {
  k: number;
  x: number;
  y: number;
}
export interface Box2 {
  x: number;
  y: number;
  w: number;
  h: number;
}
const MIN_K = 0.25,
  MAX_K = 2;
/** Below this scale card text drops under ~11px; collapse pods and pan instead. */
export const FIT_MIN = 0.85;
const FAMILY = 'system-ui, -apple-system, "Segoe UI", sans-serif';
const FONT = `13px ${FAMILY}`;
const HEADER_FONT = `650 14px ${FAMILY}`;
const META_FONT = `12.5px ${FAMILY}`;

/** Middle ellipsis keeps the unique suffix of long pod names. */
export function truncateMiddle(text: string, max: number): string {
  if (text.length <= max) return text;
  const head = Math.ceil((max - 1) * 0.55);
  return `${text.slice(0, head)}…${text.slice(text.length - (max - 1 - head))}`;
}
let measureCtx: CanvasRenderingContext2D | null | undefined;
export function textWidth(text: string, font = FONT): number {
  if (measureCtx === undefined) {
    try {
      measureCtx = document.createElement("canvas").getContext("2d");
    } catch {
      measureCtx = null;
    }
  }
  if (!measureCtx) {
    // No canvas (tests): estimate from the font size, slightly generous.
    const px = Number(/(\d+(?:\.\d+)?)px/.exec(font)?.[1] ?? 13);
    const bold = /^\s*(6|7|8|9)\d\d\b|bold/.test(font) ? 0.04 : 0;
    return text.length * px * (0.58 + bold);
  }
  measureCtx.font = font;
  return measureCtx.measureText(text).width;
}
/** Longest middle-truncation of `text` that fits in `px`. */
export function fitText(text: string, px: number, font = FONT): string {
  if (textWidth(text, font) <= px) return text;
  let lo = 4,
    hi = text.length - 1;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (textWidth(truncateMiddle(text, mid), font) <= px) lo = mid;
    else hi = mid - 1;
  }
  return truncateMiddle(text, lo);
}

/** Shortest prefix a truncated name keeps, so it stays recognizable. */
export const NAME_PREFIX = 8;
/**
 * Truncates a name so it stays identifiable: names fit whole when they can;
 * otherwise a prefix of at least NAME_PREFIX characters and the last
 * dash-separated segment (a pod hash, a VM number) are kept around "…".
 */
export function fitName(text: string, px: number, font = FONT): string {
  if (textWidth(text, font) <= px) return text;
  const dash = text.lastIndexOf("-");
  const tail =
    dash > 0 && text.length - dash - 1 <= 8 ? text.slice(dash + 1) : "";
  if (!tail || dash < NAME_PREFIX) return fitText(text, px, font);
  let head = dash;
  while (
    head > NAME_PREFIX &&
    textWidth(`${text.slice(0, head)}…${tail}`, font) > px
  )
    head--;
  return `${text.slice(0, head)}…${tail}`;
}
/**
 * A row's name and side text (IP, node, status). The side text moves to a
 * second line whenever it would cost the name characters.
 */
export function rowLabel(
  name: string,
  side: string | undefined,
  width: number,
  sidePx: number,
  font = FONT,
): { name: string; stacked: boolean } {
  const avail = width - 46;
  if (!side || textWidth(name, font) <= avail - sidePx)
    return {
      name: fitName(name, avail - (side ? sidePx : 0), font),
      stacked: false,
    };
  return { name: fitName(name, avail, font), stacked: true };
}

/** Fit scale that would show the whole layout in a viewport. */
export const rawFit = (layout: Layout, w: number, h: number) =>
  Math.min((w - 32) / layout.width, (h - 32) / layout.height);

/** Pans the least distance that brings `box` fully on screen; centres it if it cannot fit. */
export function ensureVisible(
  t: Transform,
  box: Box2,
  view: { w: number; h: number },
  margin = 24,
): Transform {
  const shift = (lo: number, hi: number, size: number) => {
    if (hi - lo > size - 2 * margin) return size / 2 - (lo + hi) / 2;
    if (lo < margin) return margin - lo;
    if (hi > size - margin) return size - margin - hi;
    return 0;
  };
  const dx = shift(box.x * t.k + t.x, (box.x + box.w) * t.k + t.x, view.w);
  const dy = shift(box.y * t.k + t.y, (box.y + box.h) * t.k + t.y, view.h);
  return dx || dy ? { k: t.k, x: t.x + dx, y: t.y + dy } : t;
}

function NodeIcon({ node, x, y }: { node?: GraphNode; x: number; y: number }) {
  const props = { x, y, size: 15, strokeWidth: 1.8, "aria-hidden": true };
  if (!node || node.kind === "workload") return <Box {...props} />;
  if (node.kind === "service") return <Layers {...props} />;
  if (node.endpoint_kind === "k8s_node") return <Server {...props} />;
  if (node.endpoint_kind === "k8s_service") return <DoorOpen {...props} />;
  if (node.endpoint_kind === "k8s_node_proxy") return <Split {...props} />;
  if (node.endpoint_kind === "vm") return <HardDrive {...props} />;
  if (node.endpoint_kind === "ambiguous") return <Users {...props} />;
  if (node.endpoint_kind === "unresolved") return <CircleHelp {...props} />;
  return <Globe {...props} />;
}

const CHIP_W = 74;
/** Secondary text shown with a row: node, IP, attachment leaf, Service type. */
function rowMeta(n: GraphNode, deviceLabel: (raw: string) => string) {
  if (n.kind === "workload") return n.attributes?.node;
  if (n.endpoint_kind === "k8s_service")
    return n.attributes?.type === "LoadBalancer"
      ? "LB VIP"
      : n.attributes?.type;
  if (n.endpoint_kind === "k8s_node_proxy" || n.endpoint_kind === "vm")
    return n.addresses?.[0];
  if (n.endpoint_kind === "k8s_node" && n.attributes?.attach_device)
    return deviceLabel(n.attributes.attach_device);
  return undefined;
}
/** Everything a card shows as text, and how its name was fitted. */
export function itemText(
  it: Item,
  n: GraphNode | undefined,
  deviceLabel: (raw: string) => string,
) {
  const header = it.role === "header";
  const summary = it.role === "summary";
  const unknown = !!n && isUnknown(n);
  // A Service frontend whose backend no evidence determined.
  const noBackend = header && n?.attributes?.handoff === "service_only";
  const meta =
    n && !header
      ? rowMeta(n, deviceLabel)
      : n?.endpoint_kind === "k8s_service" &&
          n.attributes?.handoff !== "service_only"
        ? policyBadge(n.attributes ?? {}) || undefined
        : undefined;
  const kindText = summary
    ? "Pods"
    : n?.endpoint_kind
      ? endpointKindLabel[n.endpoint_kind]
      : n?.kind === "workload"
        ? "Pod"
        : "Service";
  const text = summary
    ? `${it.members!.length} pods`
    : n?.endpoint_kind === "k8s_service"
      ? header
        ? (n.attributes?.service ?? n.label)
        : (n.attributes?.frontend ?? n.label)
      : n?.endpoint_kind === "k8s_node_proxy"
        ? (n.attributes?.node ?? n.label)
        : (n?.label ?? it.nodeId);
  const metaW = meta ? textWidth(meta, META_FONT) + 12 : 0;
  const font = header ? HEADER_FONT : FONT;
  // Headers keep their subtitle line; rows may stack side text.
  const sideText = unknown ? kindText : noBackend ? "No backend" : meta;
  const sideW = unknown ? 108 : noBackend ? CHIP_W + 6 : metaW;
  // Rows stack side text under the name; headers move it to the subtitle line.
  const fitted = summary
    ? { name: fitName(text, it.w - 46, font), stacked: false }
    : rowLabel(text, sideText, it.w, sideW, font);
  return { header, summary, unknown, noBackend, meta, kindText, text, fitted };
}

export interface EdgeDescription {
  title: string;
  lines: string[];
}

export function MapView({
  layout,
  index,
  matchNodes,
  matchEdges,
  selection,
  onSelect,
  focusTarget,
  focusRequest,
  onFitScale,
  onExpand,
  deviceLabel,
  describeEdge,
  label,
}: {
  layout: Layout;
  index: GraphIndex;
  /** Defined while a search is active. */
  matchNodes?: ReadonlySet<string>;
  matchEdges?: ReadonlySet<string>;
  selection: Selection | null;
  onSelect: (s: Selection | null) => void;
  /** Pan to a node or edge when the nonce changes. */
  focusTarget?: { kind: "node" | "edge"; id: string; nonce: number };
  /** Move keyboard focus to a node's card when the nonce changes. */
  focusRequest?: { id: string; nonce: number };
  onFitScale?: (raw: number) => void;
  onExpand: (groupId: string) => void;
  deviceLabel: (raw: string) => string;
  describeEdge: (edge: GraphEdge) => EdgeDescription;
  label: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [t, setT] = useState<Transform>({ k: 1, x: 0, y: 0 });
  const [active, setActive] = useState<string | undefined>(layout.order[0]);
  const [focused, setFocused] = useState<string>();
  const [hover, setHover] = useState<{ id: string; x: number; y: number }>();
  const drag = useRef<{ x: number; y: number; t: Transform } | null>(null);
  const itemRefs = useRef(new Map<string, SVGGElement>());

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      if (width && height) setSize({ w: width, h: height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const fitTo = useCallback(
    (w: number, h: number): Transform => {
      const raw = rawFit(layout, w, h);
      const k = Math.min(1.15, Math.max(FIT_MIN, raw));
      return {
        k,
        x: raw < FIT_MIN ? 12 : (w - layout.width * k) / 2,
        y: Math.max(8, (h - layout.height * k) / 2),
      };
    },
    [layout],
  );
  const fit = useCallback(() => setT(fitTo(size.w, size.h)), [fitTo, size]);

  const itemBox = useCallback(
    (s: Selection | null): Box2 | undefined => {
      if (!s) return undefined;
      if (s.kind === "node") return layout.items.get(s.id);
      const e = index.edge.get(s.id);
      const a = e && layout.items.get(e.source),
        b = e && layout.items.get(e.target);
      if (!a || !b) return undefined;
      const x = Math.min(a.x, b.x),
        y = Math.min(a.y, b.y);
      return {
        x,
        y,
        w: Math.max(a.x + a.w, b.x + b.w) - x,
        h: Math.max(a.y + a.h, b.y + b.h) - y,
      };
    },
    [layout, index],
  );

  // Fit once per layout. Later resizes (inspector, path strip) keep the
  // view centred and keep the selection on screen.
  const fitted = useRef<Layout | null>(null);
  const lastSize = useRef(size);
  useEffect(() => {
    if (!size.w || !size.h) return;
    if (fitted.current !== layout || !lastSize.current.w) {
      fitted.current = layout;
      setT(fitTo(size.w, size.h));
      if (!layout.collapsed) onFitScale?.(rawFit(layout, size.w, size.h));
    } else {
      const dx = (size.w - lastSize.current.w) / 2;
      const dy = (size.h - lastSize.current.h) / 2;
      if (dx || dy) setT((cur) => ({ ...cur, x: cur.x + dx, y: cur.y + dy }));
    }
    lastSize.current = size;
  }, [layout, size, fitTo, onFitScale]);
  useEffect(() => {
    const b = itemBox(selection);
    if (!b || !size.w) return;
    // On narrow screens the inspector overlays the right of the map.
    const overlay =
      selection && window.matchMedia?.("(max-width: 900px)").matches
        ? Math.min(320, size.w * 0.92)
        : 0;
    const view = { w: size.w - overlay, h: size.h };
    setT((cur) => {
      // An edge too long to show whole: bring its server end into view.
      const tooBig = b.w * cur.k > view.w - 48 || b.h * cur.k > view.h - 48;
      const target =
        tooBig && selection?.kind === "edge"
          ? layout.items.get(index.edge.get(selection.id)?.target ?? "")
          : undefined;
      return ensureVisible(cur, target ?? b, view);
    });
  }, [selection, size, itemBox, layout, index]);
  useEffect(() => setActive(layout.order[0]), [layout]);

  const centerOn = useCallback(
    (b: Box2) =>
      setT((cur) => {
        const k = Math.max(cur.k, FIT_MIN);
        return {
          k,
          x: size.w / 2 - (b.x + b.w / 2) * k,
          y: size.h / 2 - (b.y + b.h / 2) * k,
        };
      }),
    [size],
  );
  useEffect(() => {
    if (!focusTarget) return;
    if (focusTarget.kind === "node") {
      const it = layout.items.get(focusTarget.id);
      if (it) centerOn(it);
    } else {
      const r = layout.edges.find((e) => e.members.includes(focusTarget.id));
      if (r) centerOn({ x: r.mid.x - 20, y: r.mid.y - 20, w: 40, h: 40 });
    }
  }, [focusTarget, layout, centerOn]);
  useEffect(() => {
    if (!focusRequest) return;
    const it = layout.items.get(focusRequest.id);
    if (it) {
      setActive(it.nodeId);
      itemRefs.current.get(it.nodeId)?.focus();
    }
  }, [focusRequest, layout]);

  const zoomBy = useCallback(
    (factor: number, cx?: number, cy?: number) =>
      setT((cur) => {
        const px = cx ?? size.w / 2,
          py = cy ?? size.h / 2;
        const k = Math.min(MAX_K, Math.max(MIN_K, cur.k * factor));
        return {
          k,
          x: px - ((px - cur.x) * k) / cur.k,
          y: py - ((py - cur.y) * k) / cur.k,
        };
      }),
    [size],
  );
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const wheel = (ev: WheelEvent) => {
      ev.preventDefault();
      const rect = el.getBoundingClientRect();
      if (ev.ctrlKey || ev.metaKey)
        zoomBy(
          Math.exp(-ev.deltaY * 0.0025),
          ev.clientX - rect.left,
          ev.clientY - rect.top,
        );
      else
        setT((cur) => ({ ...cur, x: cur.x - ev.deltaX, y: cur.y - ev.deltaY }));
    };
    el.addEventListener("wheel", wheel, { passive: false });
    return () => el.removeEventListener("wheel", wheel);
  }, [zoomBy]);

  const matching = matchNodes !== undefined;
  const neighborhood = useMemo(() => {
    if (!selection) return undefined;
    const nodes = new Set<string>(),
      edges = new Set<string>();
    if (selection.kind === "node") {
      nodes.add(selection.id);
      for (const e of index.incident.get(selection.id) ?? []) {
        edges.add(e.id);
        nodes.add(e.source);
        nodes.add(e.target);
      }
    } else {
      const e = index.edge.get(selection.id);
      if (e) {
        edges.add(e.id);
        nodes.add(e.source);
        nodes.add(e.target);
        // A conversation into a Service frontend continues to its backends.
        if (index.node.get(e.target)?.endpoint_kind === "k8s_service")
          for (const f of index.outgoing.get(e.target) ?? [])
            if (f.relationship === "forwards_to") {
              edges.add(f.id);
              nodes.add(f.target);
            }
      }
    }
    return { nodes, edges };
  }, [selection, index]);
  const matchEnds = useMemo(() => {
    const s = new Set<string>();
    for (const id of matchEdges ?? []) {
      const e = index.edge.get(id);
      if (e) s.add(e.source).add(e.target);
    }
    return s;
  }, [matchEdges, index]);
  const ids = (it: Item) => it.members ?? [it.nodeId];
  const itemDim = (it: Item) =>
    matching
      ? !ids(it).some((id) => matchNodes!.has(id) || matchEnds.has(id))
      : neighborhood
        ? !ids(it).some((id) => neighborhood.nodes.has(id))
        : false;
  const edgeDim = (e: GraphEdge) =>
    matching
      ? !(
          matchEdges?.has(e.id) ||
          matchNodes!.has(e.source) ||
          matchNodes!.has(e.target)
        )
      : neighborhood
        ? !neighborhood.edges.has(e.id)
        : false;
  const node = (id: string) => index.node.get(id);
  const edgeClass = (e: GraphEdge) => {
    if (e.relationship === "calls") return "call";
    if (e.relationship === "forwards_to")
      return e.confidence === "inferred" ? "forward inferred" : "forward";
    if (e.acl_action === "drop") return "conv blocked";
    if (tunnelOf(e)) return "tunnel";
    const s = edgeIdentity(e, node);
    return s === "identified"
      ? "conv"
      : s === "external"
        ? "conv external"
        : "conv unknown";
  };

  const columnItems = useMemo(() => {
    const cols = new Map<number, string[]>();
    for (const id of layout.order) {
      const it = layout.items.get(id)!;
      cols.set(it.column, [...(cols.get(it.column) ?? []), id]);
    }
    return cols;
  }, [layout]);
  const moveFocus = (id: string | undefined) => {
    if (!id) return;
    setActive(id);
    itemRefs.current.get(id)?.focus();
    const it = layout.items.get(id);
    if (it) setT((cur) => ensureVisible(cur, it, size));
  };
  const onItemKey = (ev: React.KeyboardEvent, it: Item) => {
    const col = columnItems.get(it.column)!;
    const i = col.indexOf(it.nodeId);
    const nearest = (c: number) => {
      const list = columnItems.get(c);
      if (!list?.length) return undefined;
      const mid = it.y + it.h / 2;
      return list.reduce((best, cand) => {
        const a = layout.items.get(cand)!,
          b = layout.items.get(best)!;
        return Math.abs(a.y + a.h / 2 - mid) < Math.abs(b.y + b.h / 2 - mid)
          ? cand
          : best;
      });
    };
    const keyMap: Record<string, () => string | undefined> = {
      ArrowDown: () => col[Math.min(col.length - 1, i + 1)],
      ArrowUp: () => col[Math.max(0, i - 1)],
      ArrowRight: () => nearest(it.column + 1),
      ArrowLeft: () => nearest(it.column - 1),
      Home: () => layout.order[0],
      End: () => layout.order[layout.order.length - 1],
    };
    if (keyMap[ev.key]) {
      ev.preventDefault();
      moveFocus(keyMap[ev.key]());
    } else if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      if (it.role === "summary") onExpand(it.groupId);
      else onSelect({ kind: "node", id: it.nodeId });
    } else if (ev.key === "Escape") {
      ev.preventDefault();
      ev.stopPropagation();
      onSelect(null);
    }
  };

  const selectedItem =
    selection?.kind === "node" ? layout.items.get(selection.id) : undefined;
  const selectedEdge = selection?.kind === "edge" ? selection.id : undefined;
  const hovered = hover && index.edge.get(hover.id);
  const tip = hovered && describeEdge(hovered);

  const renderEdge = (r: RoutedEdge) => {
    const cls = edgeClass(r.edge);
    const selected = !!selectedEdge && r.members.includes(selectedEdge);
    const marker =
      r.arrow === "none"
        ? undefined
        : `url(#adm-arrow-${selected ? "ink" : cls.replace(" ", "-")})`;
    const dim = r.members.every((id) => {
      const e = index.edge.get(id);
      return !e || edgeDim(e);
    });
    return (
      <g
        key={r.id}
        className={`edge ${cls} ${selected ? "selected" : ""} ${dim && hover?.id !== r.id ? "dim" : ""} ${hover?.id === r.id ? "hover" : ""} ${r.members.some((id) => matchEdges?.has(id)) ? "match" : ""}`}
        data-hit
        onClick={(ev) => {
          ev.stopPropagation();
          onSelect({ kind: "edge", id: r.id });
        }}
        onPointerMove={(ev) => {
          const rect = box.current!.getBoundingClientRect();
          setHover({
            id: r.id,
            x: ev.clientX - rect.left,
            y: ev.clientY - rect.top,
          });
        }}
        onPointerLeave={() => setHover(undefined)}
      >
        <path d={r.d} className="edge-hit" />
        <path d={r.d} className="edge-line" markerEnd={marker} />
        {r.blocked && (
          <g
            className="blocked-badge"
            transform={`translate(${r.mid.x},${r.mid.y})`}
          >
            <title>Blocked by the fabric (ACI ACL log drop)</title>
            <rect x={-38} y={-10} width={76} height={20} rx={10} />
            <circle cx={-25} cy={0} r={5} />
            <line x1={-28.5} y1={3.5} x2={-21.5} y2={-3.5} />
            <text x={5} y={4} textAnchor="middle">
              Blocked
            </text>
          </g>
        )}
        {r.label && (
          <g className="edge-label">
            <rect
              x={r.mid.x + 6}
              y={r.mid.y - 10}
              width={textWidth(r.label, `650 11px ${FAMILY}`) + 14}
              height={20}
              rx={10}
            />
            <text x={r.mid.x + 13} y={r.mid.y + 4}>
              {r.label}
            </text>
          </g>
        )}
      </g>
    );
  };

  return (
    <div
      className="map-canvas"
      ref={box}
      onPointerDown={(ev) => {
        // Cards, lines and the zoom buttons handle their own clicks.
        if ((ev.target as Element).closest("[data-hit], .zoom-controls"))
          return;
        drag.current = { x: ev.clientX, y: ev.clientY, t };
        (ev.currentTarget as HTMLElement).setPointerCapture(ev.pointerId);
      }}
      onPointerMove={(ev) => {
        const d = drag.current;
        if (d)
          setT({
            ...d.t,
            x: d.t.x + ev.clientX - d.x,
            y: d.t.y + ev.clientY - d.y,
          });
      }}
      onPointerUp={(ev) => {
        const d = drag.current;
        drag.current = null;
        if (d && Math.hypot(ev.clientX - d.x, ev.clientY - d.y) < 4)
          onSelect(null);
      }}
    >
      <svg
        role="group"
        aria-label={label}
        width={size.w || undefined}
        height={size.h || undefined}
        className="map-svg"
      >
        <defs>
          {[
            "call",
            "conv",
            "conv-unknown",
            "conv-external",
            "conv-blocked",
            "forward",
            "forward-inferred",
            "tunnel",
            "ink",
          ].map((c) => (
            <marker
              key={c}
              id={`adm-arrow-${c}`}
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M0,1 L9,5 L0,9 z" className={`arrow ${c}`} />
            </marker>
          ))}
        </defs>
        <g transform={`translate(${t.x},${t.y}) scale(${t.k})`}>
          {layout.lanes.map((lane) => (
            <g key={`${lane.x}:${lane.y}`} className="lane">
              <text x={lane.x} y={lane.y} className="lane-title">
                {lane.title.toUpperCase()}
              </text>
              <line
                x1={lane.x}
                x2={lane.x + lane.width}
                y1={lane.y + 9}
                y2={lane.y + 9}
                className="lane-rule"
              />
            </g>
          ))}
          {layout.groups.map((g) => (
            <g key={g.id} className={`group ${g.kind}`}>
              <rect
                x={g.x}
                y={g.y}
                width={g.w}
                height={g.h}
                rx={10}
                className="group-card"
              />
              {!g.headerNodeId && (
                <>
                  <text x={g.x + 14} y={g.y + 19} className="group-title">
                    {fitText(g.title, g.w - 28, HEADER_FONT)}
                  </text>
                  {g.subtitle && (
                    <text x={g.x + 14} y={g.y + 35} className="group-sub">
                      {fitText(g.subtitle, g.w - 28, META_FONT)}
                    </text>
                  )}
                </>
              )}
              {g.headerNodeId && g.items.length > 1 && (
                <line
                  x1={g.x}
                  x2={g.x + g.w}
                  y1={g.y + HEADER_H}
                  y2={g.y + HEADER_H}
                  className="group-rule"
                />
              )}
            </g>
          ))}
          <g className="edges">{layout.edges.map(renderEdge)}</g>
          <g className="pills">
            {layout.pills.map((p) => {
              const edges = p.edgeIds.map((id) => index.edge.get(id)!);
              const dim = edges.every((e) => edgeDim(e));
              const selected = edges.some((e) => e.id === selectedEdge);
              // A pill shared with permitted conversations keeps their colour.
              const cls = edgeClass(
                edges.find((e) => e.acl_action !== "drop") ?? edges[0],
              ).replace(" ", "-");
              return (
                <g
                  key={p.id}
                  className={`pill ${dim ? "dim" : ""} ${selected ? "selected" : ""}`}
                >
                  <title>{`${p.label} · ${edges.length} conversation${edges.length === 1 ? "" : "s"}`}</title>
                  <line
                    x1={p.connector.x1}
                    x2={p.connector.x2 + (p.side === "left" ? -1 : 1)}
                    y1={p.connector.y}
                    y2={p.connector.y}
                    className={`pill-link ${cls}`}
                    markerEnd={`url(#adm-arrow-${selected ? "ink" : cls})`}
                  />
                  <rect x={p.x} y={p.y} width={p.w} height={p.h} rx={p.h / 2} />
                  <text
                    x={p.x + p.w / 2}
                    y={p.y + p.h / 2 + 4}
                    textAnchor="middle"
                  >
                    {p.label}
                  </text>
                </g>
              );
            })}
          </g>
          {layout.groups.flatMap((g) =>
            g.items.map((it) => {
              const n = it.role === "summary" ? undefined : node(it.nodeId);
              const {
                header,
                summary,
                unknown,
                noBackend,
                meta,
                kindText,
                text,
                fitted,
              } = itemText(it, n, deviceLabel);
              const stacked = fitted.stacked;
              const chipW = CHIP_W;
              const selected = !!selectedItem && selectedItem === it;
              const labelY = header
                ? it.y + 19
                : stacked
                  ? it.y + 17
                  : it.y + it.h / 2 + 4.5;
              const sideY = header
                ? stacked
                  ? it.y + 35
                  : it.y + 19
                : stacked
                  ? it.y + it.h - 9
                  : it.y + it.h / 2 + 4.5;
              // A stacked header shares its subtitle line with the side text.
              const subW =
                it.w -
                46 -
                (header && stacked
                  ? noBackend
                    ? chipW + 6
                    : meta
                      ? textWidth(meta, META_FONT) + 12
                      : 0
                  : 0);
              const focusRing =
                focused === it.nodeId ||
                (matching &&
                  focusTarget?.kind === "node" &&
                  layout.items.get(focusTarget.id) === it);
              return (
                <g
                  key={it.nodeId}
                  ref={(el) => {
                    if (el) itemRefs.current.set(it.nodeId, el);
                    else itemRefs.current.delete(it.nodeId);
                  }}
                  className={`item ${it.role} ${n?.kind ?? "workload"} ${unknown ? "unknown" : ""} ${n?.endpoint_kind === "external" ? "external" : ""} ${selected ? "selected" : ""} ${itemDim(it) ? "dim" : ""} ${matching && ids(it).some((id) => matchNodes!.has(id)) ? "match" : ""}`}
                  data-hit
                  role="button"
                  tabIndex={it.nodeId === active ? 0 : -1}
                  aria-label={
                    summary
                      ? `${text} in ${g.title}, collapsed. Press Enter to show them.`
                      : `${kindText} ${n?.endpoint_kind === "k8s_service" ? (n.label ?? text) : text}${unknown ? ", identity unknown" : ""}`
                  }
                  aria-pressed={summary ? undefined : selected}
                  aria-expanded={summary ? false : undefined}
                  onFocus={() => {
                    setFocused(it.nodeId);
                    setActive(it.nodeId);
                  }}
                  onBlur={() => setFocused(undefined)}
                  onKeyDown={(ev) => onItemKey(ev, it)}
                  onClick={(ev) => {
                    ev.stopPropagation();
                    setActive(it.nodeId);
                    if (summary) onExpand(it.groupId);
                    else onSelect({ kind: "node", id: it.nodeId });
                  }}
                >
                  <title>
                    {summary
                      ? `${text}: ${it.members!.map((m) => node(m)?.label).join(", ")}`
                      : `${kindText}: ${n?.endpoint_kind === "k8s_service" ? `${n.label}${policyText(n.attributes ?? {}) ? ` · ${policyText(n.attributes ?? {})}` : ""}` : text}`}
                  </title>
                  <rect
                    x={it.x + 3}
                    y={it.y + 3}
                    width={it.w - 6}
                    height={it.h - 6}
                    rx={7}
                    className="item-bg"
                  />
                  <NodeIcon
                    node={n}
                    x={it.x + 12}
                    y={it.y + (header ? 8 : stacked ? 6 : (it.h - 15) / 2)}
                  />
                  <text x={it.x + 34} y={labelY} className="item-label">
                    {fitted.name}
                  </text>
                  {header && (
                    <text x={it.x + 34} y={it.y + 35} className="item-sub">
                      {fitText(
                        `${g.subtitle ?? ""}${
                          g.items.length > 1
                            ? ` · ${g.collapsed ? g.items[1].members!.length : g.items.length - 1} pod${(g.collapsed ? g.items[1].members!.length : g.items.length - 1) === 1 ? "" : "s"}`
                            : ""
                        }`,
                        subW,
                        META_FONT,
                      )}
                    </text>
                  )}
                  {summary && (
                    <g className="summary-more">
                      <text
                        x={it.x + it.w - 32}
                        y={it.y + it.h / 2 + 4.5}
                        textAnchor="end"
                      >
                        Show
                      </text>
                      <ChevronDown
                        x={it.x + it.w - 28}
                        y={it.y + it.h / 2 - 7}
                        size={14}
                        aria-hidden
                      />
                    </g>
                  )}
                  {noBackend && (
                    <g className="status-chip">
                      <title>
                        Backend not determined (
                        {n?.attributes?.candidates ?? "?"} candidates)
                      </title>
                      <rect
                        x={it.x + it.w - 10 - chipW}
                        y={sideY - 13}
                        width={chipW}
                        height={18}
                        rx={9}
                      />
                      <text
                        x={it.x + it.w - 10 - chipW / 2}
                        y={sideY}
                        textAnchor="middle"
                      >
                        No backend
                      </text>
                    </g>
                  )}
                  {unknown && (
                    <g className="status-chip">
                      <rect
                        x={stacked ? it.x + 32 : it.x + it.w - 108}
                        y={stacked ? sideY - 12 : it.y + it.h / 2 - 10}
                        width={98}
                        height={stacked ? 16 : 20}
                        rx={8}
                      />
                      <text
                        x={stacked ? it.x + 81 : it.x + it.w - 59}
                        y={stacked ? sideY : it.y + it.h / 2 + 4}
                        textAnchor="middle"
                      >
                        {kindText}
                      </text>
                    </g>
                  )}
                  {!unknown && meta && (
                    <text
                      x={stacked && !header ? it.x + 34 : it.x + it.w - 12}
                      y={sideY}
                      textAnchor={stacked && !header ? "start" : "end"}
                      className="item-meta"
                    >
                      {meta}
                    </text>
                  )}
                  {focusRing && (
                    <rect
                      x={it.x + 1}
                      y={it.y + 1}
                      width={it.w - 2}
                      height={it.h - 2}
                      rx={9}
                      className="focus-ring"
                    />
                  )}
                </g>
              );
            }),
          )}
        </g>
      </svg>
      {tip && hover && (
        <div
          className="map-tooltip"
          role="tooltip"
          style={{
            left: Math.min(hover.x + 14, Math.max(0, size.w - 300)),
            top: Math.min(hover.y + 14, Math.max(0, size.h - 110)),
          }}
        >
          <strong>{tip.title}</strong>
          {tip.lines.map((l) => (
            <span key={l}>{l}</span>
          ))}
        </div>
      )}
      <div className="zoom-controls" role="group" aria-label="Zoom">
        <button aria-label="Zoom out" onClick={() => zoomBy(1 / 1.25)}>
          <Minus size={16} />
        </button>
        <span aria-live="polite">{Math.round(t.k * 100)}%</span>
        <button aria-label="Zoom in" onClick={() => zoomBy(1.25)}>
          <Plus size={16} />
        </button>
        <button aria-label="Fit map to view" onClick={fit}>
          <Maximize2 size={15} />
        </button>
      </div>
    </div>
  );
}
