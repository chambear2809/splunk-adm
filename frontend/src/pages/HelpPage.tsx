export function HelpPage() {
  return (
    <main className="atlas-page">
      <h1>Help</h1>
      <p>
        Application Atlas combines traced calls with network conversations.
        Select a card or line on the map to inspect the evidence behind it.
      </p>
      <h2>Read the map</h2>
      <p>
        Sources, entry points, applications and dependencies run from left to
        right. Arrows show client to server direction. Unknown addresses remain
        visible so evidence gaps can be investigated.
      </p>
      <p>
        Fabric contracts describe policy intent; ACL drops describe observed
        blocking. Candidate paths come from inventory and do not establish the
        exact path packets took.
      </p>
      <h2>Follow observed callers and dependencies</h2>
      <p>
        Select a card, then choose Focus. Callers lists the clients observed
        reaching the selection; Dependencies lists what the selection was
        observed reaching. Each hop is one observed conversation or traced call
        in the loaded window and sources, so an empty Dependencies result means
        none were observed, not that none exist. A connection of unknown
        direction is followed both ways, a direction inferred from ports is
        followed as drawn, and the filter summary counts both. A blocked
        conversation between shown cards is drawn but not followed.
      </p>
      <h2>Navigate</h2>
      <p>
        Use Applications to choose a scope, Map to inspect dependencies, and
        Data health to check source visibility. Map settings let you select
        captured demo scenarios or a live Splunk scope.
      </p>
      <p>
        Tab into the map. Arrow keys move between cards; Enter selects and
        Escape clears. Highlight results with Enter and Shift+Enter.
      </p>
    </main>
  );
}
