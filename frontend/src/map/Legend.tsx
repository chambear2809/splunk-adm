import { useState } from "react";
import { edgeIdentity } from "../glossary";
import { tunnelOf, type GraphEdge, type GraphIndex } from "../graph";

export function Legend({
  edges,
  index,
  collapsed,
}: {
  edges: GraphEdge[];
  index: GraphIndex;
  collapsed: boolean;
}) {
  const [open, setOpen] = useState(false);
  const types = new Map<string, string>();
  for (const edge of edges) {
    if (edge.relationship === "calls") types.set("call", "Traced call");
    else if (edge.relationship === "forwards_to") {
      if (edge.confidence === "inferred")
        types.set("forward inferred", "Backend inferred");
      else types.set("forward", "To backend");
    } else if (edge.relationship === "communicates_with") {
      if (edge.acl_action === "drop") types.set("conv blocked", "Blocked");
      else if (tunnelOf(edge)) types.set("tunnel", "Node tunnel");
      else {
        const identity = edgeIdentity(edge, (id) => index.node.get(id));
        if (identity === "identified")
          types.set("conv", "Network conversation");
        else if (identity === "external")
          types.set("conv external", "External");
        else types.set("conv unknown", "Unknown or multiple owners");
      }
    }
  }
  return (
    <div className="legend" aria-label="Legend">
      <button
        className="link"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        Legend
      </button>
      {open && (
        <>
          {[...types].map(([cls, label]) => (
            <span key={cls}>
              <svg width="28" height="10" aria-hidden>
                <line x1="2" y1="5" x2="26" y2="5" className={`lg ${cls}`} />
              </svg>
              {label}
            </span>
          ))}
          {edges.some(
            (e) =>
              e.relationship === "communicates_with" &&
              e.server_port !== undefined,
          ) && (
            <span>
              <span className="lg-pill">8080/tcp</span>Server port
            </span>
          )}
          {collapsed && (
            <span className="legend-note">Pod lists collapsed to fit</span>
          )}
        </>
      )}
    </div>
  );
}
