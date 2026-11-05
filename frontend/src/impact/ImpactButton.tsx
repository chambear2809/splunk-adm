import { Zap } from "lucide-react";
import { isImpactToken } from "./elements";
import { impactURL } from "./url";
import "./impact.css";

const ifaceName = (s: string) =>
  s
    .replace(/\s*\(inferred\)$/, "")
    .replace(/^→\s*/, "")
    .trim();

/**
 * The one Impact entry point: "If this fails" for an element. With
 * interfaces, a compact list offers each one (vmnic, port-channel, vPC leg).
 */
export function ImpactButton({
  token,
  label,
  interfaces = [],
  compact = false,
}: {
  token?: string;
  /** Accessible name suffix, e.g. the card or device name. */
  label?: string;
  interfaces?: string[];
  compact?: boolean;
}) {
  const ok = !!token && isImpactToken(token);
  const ifs = [
    ...new Set(
      interfaces
        .map(ifaceName)
        .filter(
          (i) =>
            i &&
            i !== "fabric" &&
            i !== "?" &&
            !/^(?:port|ifindex) \d+$/i.test(i),
        ),
    ),
  ]
    .filter((i) => isImpactToken(`${token}|${i}`))
    .slice(0, 16);
  if (!ok)
    return (
      <span
        className={`atlas-impact-btn disabled ${compact ? "compact" : ""}`}
        aria-disabled="true"
        title="Select an element"
      >
        <Zap size={13} aria-hidden /> Impact
      </span>
    );
  return (
    <span className="atlas-impact-entry">
      <a
        className={`atlas-impact-btn ${compact ? "compact" : ""}`}
        href={impactURL([token])}
        aria-label={`Impact if ${label ?? token} fails`}
        title="If this fails"
      >
        <Zap size={13} aria-hidden /> Impact
      </a>
      {ifs.length > 0 && (
        <details className="atlas-impact-ifs">
          <summary aria-label="Impact of one interface">Interface</summary>
          <ul>
            {ifs.map((i) => (
              <li key={i}>
                <a href={impactURL([`${token}|${i}`])}>{i}</a>
              </li>
            ))}
          </ul>
        </details>
      )}
    </span>
  );
}
