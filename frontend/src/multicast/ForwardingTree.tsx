import type { ForwardingBranch, MulticastResult } from "./contract";

interface TreeBranch {
  branch: ForwardingBranch;
  children: TreeBranch[];
}

function buildTree(branches: ForwardingBranch[]) {
  const children = new Map<string, ForwardingBranch[]>();
  const incoming = new Map<string, number>();
  const seen = new Set<ForwardingBranch>();
  for (const branch of branches) {
    const siblings = children.get(branch.from);
    if (siblings) siblings.push(branch);
    else children.set(branch.from, [branch]);
    if (branch.state === "supported" && branch.to)
      incoming.set(branch.to, (incoming.get(branch.to) ?? 0) + 1);
  }
  function visit(device: string, depth: number): TreeBranch[] {
    if (depth >= 8) return [];
    const next: TreeBranch[] = [];
    for (const branch of children.get(device) ?? []) {
      if (seen.has(branch)) continue;
      seen.add(branch);
      // Converging or cyclic edges stay inspectable without implying a unique chain.
      next.push({
        branch,
        children:
          branch.state === "supported" &&
          branch.to &&
          incoming.get(branch.to) === 1
            ? visit(branch.to, depth + 1)
            : [],
      });
    }
    return next;
  }
  const roots = [...children.keys()]
    .filter((device) => !incoming.has(device))
    .map((device) => ({ device, branches: visit(device, 0) }));
  return { roots, remaining: branches.filter((branch) => !seen.has(branch)) };
}

const branchLabel = {
  supported: "Supported link",
  unresolved: "Next hop unresolved",
  stale: "Stale state",
} as const;

function BranchButton({
  branch,
  inspect,
}: {
  branch: ForwardingBranch;
  inspect: (id: string) => void;
}) {
  return (
    <button type="button" onClick={() => inspect(branch.evidenceId)}>
      <strong>
        {branch.from} / {branch.output}
        {branch.state === "supported" && branch.to ? ` → ${branch.to}` : ""}
      </strong>
      <small>{branchLabel[branch.state]}</small>
    </button>
  );
}

function BranchList({
  nodes,
  inspect,
}: {
  nodes: TreeBranch[];
  inspect: (id: string) => void;
}) {
  return (
    <ul className="multicast-tree">
      {nodes.map(({ branch, children }, index) => (
        <li key={index}>
          <BranchButton branch={branch} inspect={inspect} />
          {children.length > 0 && (
            <BranchList nodes={children} inspect={inspect} />
          )}
        </li>
      ))}
    </ul>
  );
}

export function ForwardingTree({
  result,
  inspect,
}: {
  result: MulticastResult;
  inspect: (id: string) => void;
}) {
  if (result.branches.length === 0)
    return (
      <div className="multicast-tree-gap">
        <strong>Forwarding tree unavailable</strong>
        <p>
          A verified device-state source is required to draw forwarding links.
        </p>
      </div>
    );

  const senders = new Map(
    result.evidence
      .filter((row) => row.kind === "forwarding")
      .map((row) => [row.id, row.sender ?? "*"]),
  );
  const groups = new Map<string, ForwardingBranch[]>();
  for (const branch of result.branches) {
    const sender = senders.get(branch.evidenceId);
    if (sender === undefined) continue;
    const group = groups.get(sender);
    if (group) group.push(branch);
    else groups.set(sender, [branch]);
  }
  return [...groups].map(([sender, branches]) => {
    const { roots, remaining } = buildTree(branches);
    return (
      <section key={sender} className="multicast-tree-group">
        <h5>
          ({sender}, {result.request.group})
        </h5>
        {roots.map(({ device, branches: nodes }) => (
          <BranchList key={device} nodes={nodes} inspect={inspect} />
        ))}
        {remaining.length > 0 && (
          <details>
            <summary>Additional reported branches ({remaining.length})</summary>
            <BranchList
              nodes={remaining.map((branch) => ({ branch, children: [] }))}
              inspect={inspect}
            />
          </details>
        )}
      </section>
    );
  });
}
