import { Ban } from "lucide-react";
import type { View } from "../layout";
export function Legend({
  view,
  collapsed,
  forwards,
  blocked,
}: {
  view: View;
  collapsed: boolean;
  forwards: boolean;
  blocked: boolean;
}) {
  const line = (cls: string) => (
    <svg width="28" height="10" aria-hidden>
      <line x1="2" y1="5" x2="26" y2="5" className={`lg ${cls}`} />
    </svg>
  );
  return (
    <div className="legend" aria-label="Legend">
      <span>{line("call")}Traced call</span>
      {view === "network" && (
        <>
          <span>{line("conv")}Network conversation</span>
          <span>{line("conv unknown")}Unknown IP</span>
          <span>{line("conv external")}External</span>
          <span>{line("tunnel")}Node tunnel</span>
          {forwards && (
            <>
              <span>{line("forward")}To backend</span>
              <span>{line("forward inferred")}Backend inferred</span>
            </>
          )}
          {blocked && (
            <span>
              {line("conv blocked")}
              <Ban size={13} aria-hidden /> Blocked
            </span>
          )}
          <span>
            <span className="lg-pill">8080/tcp</span>Server port
          </span>
          {collapsed && (
            <span className="legend-note">Pod lists collapsed to fit</span>
          )}
        </>
      )}
    </div>
  );
}
