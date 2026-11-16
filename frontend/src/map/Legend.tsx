import { useState } from "react";
import type { GraphEdge, GraphIndex } from "../graph";

export function Legend({
  edges,
  collapsed,
  alwaysOpen = false,
}: {
  edges: GraphEdge[];
  index: GraphIndex;
  collapsed: boolean;
  /** Rendered inside a menu popover: no toggle of its own. */
  alwaysOpen?: boolean;
}) {
  const [toggled, setOpen] = useState(false);
  const open = alwaysOpen || toggled;
  // Lines are neutral when observed, dashed when inferred, red when blocked.
  const types = new Map<string, string>();
  for (const edge of edges) {
    if (edge.relationship === "runs_on") continue;
    if (edge.acl_action === "drop") types.set("conv blocked", "Blocked");
    else if (edge.confidence === "inferred")
      types.set("forward inferred", "Inferred");
    else types.set("conv", "Observed");
  }
  // A traced-call-only view (Services) names what its lines are.
  if (
    types.has("conv") &&
    edges.every(
      (e) => e.relationship === "calls" || e.relationship === "runs_on",
    )
  )
    types.set("conv", "Traced call");
  const order = ["conv", "forward inferred", "conv blocked"];
  const sorted = [...types].sort(
    (a, b) => order.indexOf(a[0]) - order.indexOf(b[0]),
  );
  return (
    <div
      className={`legend ${alwaysOpen ? "legend-panel" : ""}`}
      aria-label="Legend"
    >
      {!alwaysOpen && (
        <button
          className="link"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          Legend
        </button>
      )}
      {open && (
        <>
          {sorted.map(([cls, label]) => (
            <span key={cls}>
              <svg width="28" height="10" aria-hidden>
                <line x1="2" y1="5" x2="26" y2="5" className={`lg ${cls}`} />
              </svg>
              {label}
            </span>
          ))}
          {collapsed && (
            <span className="legend-note">Pod lists collapsed to fit</span>
          )}
        </>
      )}
    </div>
  );
}
