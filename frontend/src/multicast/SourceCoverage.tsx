import type { SourceOutcome } from "./contract";

export const sourceLabel = {
  multicast_igmp: "Stream IGMP",
  multicast_netflow: "Stream NetFlow",
  multicast_nxos: "NX-OS forwarding snapshots",
  device_state: "Device forwarding state",
} as const;

/**
 * Per-source outcome list ("Coverage and source status"), shared by the
 * group detail, Overview and Matrix so a blocked or unavailable source is
 * never invisible. `notices` carries scope-level facts (e.g. a missing
 * complementary profile kind) that apply to the whole scope, not one source.
 */
export function SourceCoverage({
  outcomes,
  notices = [],
}: {
  outcomes: SourceOutcome[];
  notices?: string[];
}) {
  return (
    <>
      {notices.map((notice, index) => (
        <p key={index} className="multicast-notice" role="status">
          {notice}
        </p>
      ))}
      <details open>
        <summary>Coverage and source status</summary>
        <ul>
          {outcomes.map((item, index) => (
            <li key={`${item.source}-${item.profile ?? ""}-${index}`}>
              <strong>
                {sourceLabel[item.source]}
                {item.profile ? ` / ${item.profile}` : ""}: {item.state}
              </strong>
              {item.detail ? ` — ${item.detail}` : ""}
            </li>
          ))}
        </ul>
      </details>
    </>
  );
}
