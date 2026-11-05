/** One home for evidence caveats so the working views can stay terse. */
export function HelpPage() {
  return (
    <main className="atlas-page atlas-help">
      <h1>Help</h1>
      <h2>Views</h2>
      <dl className="atlas-help-terms">
        <dt>Explore</dt>
        <dd>
          Search applications, IPs, MACs, EPGs and devices. Endpoints tab.
        </dd>
        <dt>Map</dt>
        <dd>
          Sources → entry points → application → dependencies. Click a card or
          line for details.
        </dd>
        <dt>Impact</dt>
        <dd>
          Blast radius of any card, device, interface or trace hop.{" "}
          <b>If this fails</b>: conversations through it. <b>Depends on</b>:
          what it needs. Add up to 5 elements to fail together.
        </dd>
        <dt>Admin</dt>
        <dd>Setup and data health.</dd>
      </dl>
      <h2 id="about-evidence">About evidence</h2>
      <ul className="atlas-help-list">
        <li>Findings cover the loaded window and sources only.</li>
        <li>
          Source findings use the last app-wide health check, independent of map
          filters.
        </li>
        <li>
          Devices view: observer groups are not devices, routes or hops; flow
          record counts are source-reported, not connection or byte totals.
        </li>
        <li>
          Traces and flows are sampled; a missing line is not proof of no
          traffic.
        </li>
        <li>
          Missing identity or policy is a limit of the collected evidence.
        </li>
        <li>
          <b>Contract</b> = policy intent from ACI objects. <b>ACL log</b> =
          observed by the enforcing leaf. <b>Blocked</b> = fabric logged drops.
        </li>
        <li>
          Candidate paths come from inventory (CDP, LLDP, ACI links). Between
          leaves, one of N spines (ECMP) is shown.
        </li>
        <li>
          Wireless attribution (Meraki association + IPFIX) and client
          attachment records do not establish a packet route.
        </li>
        <li>
          Service membership uses qualified OTel span association in the
          selected window.
        </li>
        <li>
          Find returns applications bound to a matching pod or observed talking
          to the endpoint. Exact IPv4/MAC also returns client attachment
          evidence.
        </li>
        <li>
          Catalog rows report a finite observation window. Legacy rows stay
          quarantined.
        </li>
        <li>Demo data is synthetic and cannot be searched in live indexes.</li>
        <li>
          Impact: <b>Outage</b> = no alternate path; <b>Degraded</b> = an
          alternate exists (vPC peer, other FI, ECMP spine, other uplink or
          replica); <b>Unverified</b> = seen there, redundancy not collected.
          Observed = exported at the element; inferred = topology only. Apps
          count only when identity, Hubble or traces attribute the traffic; ~N
          possibly affected = apps with pods on affected nodes. Conversations
          come from the window; unseen traffic is not counted.
        </li>
        <li>
          Focus explores observed neighbours (no redundancy). Unknown direction
          is followed both ways; blocked conversations are drawn, not followed.
        </li>
      </ul>
      <h2>Badges</h2>
      <p>
        Only exceptions are badged: <b>Unknown</b>, <b>Multiple owners</b>,{" "}
        <b>External</b>, <b>Blocked</b>, <b>Inferred</b>.
      </p>
      <h2>Keyboard</h2>
      <p>
        Tab into the map · ←/→ columns · ↑/↓ cards · Enter select · Esc clear ·
        Enter/Shift+Enter cycle highlights · Ctrl/⌘+scroll zoom.
      </p>
    </main>
  );
}
