import { useEffect, useMemo, useState } from "react";
import type { SearchClient } from "./data/searchClient";
import {
  loadAciFabricSnapshot,
  type AciFabricSnapshot,
} from "./data/aciFabric";
import {
  enumerateAciFabricPaths,
  type AciFabricPath,
} from "./data/aciFabricPaths";

export function pathHopLabel(path: AciFabricPath, index: number): string {
  const device = path.devices[index];
  if (!device) return "";
  const link = path.links[index];
  if (!link)
    return `Hop ${index}: ${device.name} (${device.id}) · ${device.role}`;
  const forward = link.source === device.id;
  const localInterface = forward
    ? link.source_interface
    : link.target_interface;
  const remoteInterface = forward
    ? link.target_interface
    : link.source_interface;
  const remote = path.devices[index + 1];
  return `Hop ${index}: ${device.name} (${device.id}) · ${device.role} · ${localInterface ?? "?"} → ${remoteInterface ?? "?"} · next ${remote?.name ?? "unknown"} (${remote?.id ?? "unknown"})`;
}

export function AciFabricPanel({
  client,
  live,
  earliest,
  latest,
}: {
  client?: SearchClient;
  live: boolean;
  earliest: string;
  latest?: string;
}) {
  const [snapshot, setSnapshot] = useState<AciFabricSnapshot>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  const [sourceId, setSourceId] = useState("");
  const [destinationId, setDestinationId] = useState("");
  useEffect(() => {
    if (!client || !live) {
      setSnapshot(undefined);
      setError(undefined);
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setError(undefined);
    void loadAciFabricSnapshot(client, controller.signal, earliest, latest)
      .then((value) => {
        if (!controller.signal.aborted) {
          setSnapshot(value);
          setSourceId("");
          setDestinationId("");
        }
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setSnapshot(undefined);
          setError(
            reason instanceof Error
              ? reason.message
              : "ACI fabric snapshot is unavailable.",
          );
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [client, live, earliest, latest]);

  return (
    <section className="device-card" aria-label="ACI fabric snapshot">
      <header>
        <div>
          <h3>ACI fabric snapshot</h3>
          <p className="muted small">
            Independent current APIC capture; this snapshot is not historical
            attachment evidence and does not prove traversal of a selected flow
            or that these devices saw its traffic.
          </p>
        </div>
      </header>
      {!live || !client ? (
        <p className="muted small">
          Available when running a live Splunk search.
        </p>
      ) : loading ? (
        <p role="status">Loading current ACI fabric snapshot…</p>
      ) : error ? (
        <p role="status">ACI fabric snapshot unavailable: {error}</p>
      ) : !snapshot ? (
        <p role="status">ACI fabric snapshot returned no verified result.</p>
      ) : (
        <>
          <p className="muted small">
            Current capture · Authority {snapshot.authority} · Scope{" "}
            {snapshot.scope} · Captured{" "}
            {new Date(snapshot.captured_at * 1000).toISOString()}
          </p>
          <h4>Devices ({snapshot.devices.length})</h4>
          <ul className="seen-list">
            {snapshot.devices.map((device) => (
              <li key={device.id}>
                <b>{device.name}</b>
                <small>
                  {device.role} · {device.id}
                  {device.serial ? ` · Serial ${device.serial}` : ""}
                  {device.oob_management_ip
                    ? ` · OOB management ${device.oob_management_ip}`
                    : ""}
                  {device.inband_management_ip
                    ? ` · In-band management ${device.inband_management_ip}`
                    : ""}
                  {device.fabric_address
                    ? ` · Fabric address ${device.fabric_address}`
                    : device.management_ip
                      ? ` · Management ${device.management_ip}`
                      : ""}
                </small>
              </li>
            ))}
          </ul>
          <h4>Validated routed interface context</h4>
          <p className="muted small">
            Current APIC routed-interface facts are shown separately from
            physical candidates. They do not establish flow egress or a route.
          </p>
          <ul className="seen-list">
            {snapshot.routed_interfaces.map((routed, index) => (
              <li key={`${routed.id}-${index}`}>
                <b>
                  {routed.device} · {routed.parent_interface}
                  {routed.interface !== routed.parent_interface
                    ? ` (${routed.interface})`
                    : ""}
                </b>
                <small>
                  Physical source {routed.physical_source}
                  {routed.encap ? ` · Encapsulation ${routed.encap}` : ""}
                  {routed.admin_state
                    ? ` · Routed admin ${routed.admin_state}`
                    : ""}
                  {routed.oper_state
                    ? ` · Routed oper ${routed.oper_state}`
                    : ""}
                  {routed.connection_dn
                    ? ` · Connection ${routed.connection_dn}`
                    : ""}
                  {routed.routed_out_definition_dn
                    ? ` · Routed L3Out ${routed.routed_out_definition_dn}`
                    : ""}
                </small>
              </li>
            ))}
          </ul>
          <h4>Physical links ({snapshot.links.length})</h4>
          <ul className="seen-list">
            {snapshot.links.map((link) => (
              <li key={link.id}>
                <b>
                  {link.source} ↔ {link.target}
                </b>
                <small>
                  {link.source_interface || link.target_interface
                    ? `${link.source_interface ?? "?"} ↔ ${link.target_interface ?? "?"}`
                    : "Interface details unavailable"}
                </small>
              </li>
            ))}
          </ul>
          <FabricPathCandidates
            snapshot={snapshot}
            sourceId={sourceId}
            destinationId={destinationId}
            onSourceChange={setSourceId}
            onDestinationChange={setDestinationId}
          />
          <p className="muted small">
            Physical links provide fabric context only; they are not evidence
            that the selected flow traversed these devices.
          </p>
        </>
      )}
    </section>
  );
}

export function FabricPathCandidates({
  snapshot,
  sourceId,
  destinationId,
  onSourceChange,
  onDestinationChange,
}: {
  snapshot: AciFabricSnapshot;
  sourceId: string;
  destinationId: string;
  onSourceChange: (id: string) => void;
  onDestinationChange: (id: string) => void;
}) {
  const switches = snapshot.devices.filter(
    (device) => device.role === "leaf" || device.role === "spine",
  );
  const result = useMemo(
    () => enumerateAciFabricPaths(snapshot, sourceId, destinationId),
    [snapshot, sourceId, destinationId],
  );
  const [selectedPath, setSelectedPath] = useState<number>();
  useEffect(
    () => setSelectedPath(undefined),
    [snapshot, sourceId, destinationId],
  );
  const selected =
    selectedPath === undefined ? undefined : result.paths[selectedPath];
  const [selectedExit, setSelectedExit] = useState("");
  useEffect(
    () => setSelectedExit(""),
    [snapshot, sourceId, destinationId, selectedPath],
  );
  const destination = selected?.devices.at(-1);
  const exits = destination
    ? snapshot.routed_interfaces.filter(
        (routed) => routed.device === destination.id,
      )
    : [];
  return (
    <section aria-label="ACI topology candidates">
      <h4>Topology candidates</h4>
      <p className="muted small">
        Select qualified source and destination leaves or spines. Candidate
        paths use physical switch links only; they do not establish traversal.
      </p>
      <label>
        Source leaf or spine
        <select
          aria-label="Source leaf or spine"
          value={sourceId}
          onChange={(event) => onSourceChange(event.target.value)}
        >
          <option value="">Select source</option>
          {switches.map((device) => (
            <option key={device.id} value={device.id}>
              {device.name}
            </option>
          ))}
        </select>
      </label>{" "}
      <label>
        Destination leaf or spine
        <select
          aria-label="Destination leaf or spine"
          value={destinationId}
          onChange={(event) => onDestinationChange(event.target.value)}
        >
          <option value="">Select destination</option>
          {switches.map((device) => (
            <option key={device.id} value={device.id}>
              {device.name}
            </option>
          ))}
        </select>
      </label>
      {sourceId && destinationId && (
        <div>
          <p className="muted small">
            {result.paths.length} candidate path
            {result.paths.length === 1 ? "" : "s"}
            {result.truncated
              ? ` shown; ${result.reason ?? "additional candidates were bounded."}`
              : " found."}
          </p>
          {result.paths.map((path, index) => (
            <button
              type="button"
              key={`${path.links.map((link) => link.id).join("/")}-${index}`}
              className={`path-candidate${selectedPath === index ? " selected" : ""}`}
              aria-pressed={selectedPath === index}
              onClick={() => setSelectedPath(index)}
            >
              <b>Topology candidate — traversal not established</b>
              <small>
                {path.devices.map((device) => device.name).join(" → ")} ·{" "}
                {path.links.length} hop{path.links.length === 1 ? "" : "s"}
              </small>
            </button>
          ))}
          {selected && (
            <div
              className="path-candidate-detail"
              aria-label="Selected topology candidate"
            >
              <b>Selected candidate · traversal not established</b>
              <small>
                Capture {snapshot.snapshot_id} ·{" "}
                {new Date(snapshot.captured_at * 1000).toISOString()}
              </small>
              {selected.devices.map((device, index) => (
                <small key={`${device.id}-${index}`}>
                  {pathHopLabel(selected, index)}
                </small>
              ))}
            </div>
          )}
          {selected && exits.length > 0 && (
            <div className="path-candidate-exit">
              <label>
                Exit interface context for {destination?.name}
                <select
                  aria-label="Exit interface context"
                  value={selectedExit}
                  onChange={(event) => setSelectedExit(event.target.value)}
                >
                  <option value="">Select exit context</option>
                  {exits.map((exit, index) => (
                    <option key={`${exit.id}-${index}`} value={String(index)}>
                      {exit.parent_interface}
                      {exit.interface !== exit.parent_interface
                        ? ` (${exit.interface})`
                        : ""}{" "}
                      · {exit.encap ?? "encapsulation unknown"}
                    </option>
                  ))}
                </select>
              </label>
              {selectedExit !== "" && exits[Number(selectedExit)] && (
                <p className="muted small">
                  Exit context only — not proof of flow egress. Physical port{" "}
                  {exits[Number(selectedExit)].parent_interface}
                  {exits[Number(selectedExit)].interface !==
                  exits[Number(selectedExit)].parent_interface
                    ? ` · subinterface ${exits[Number(selectedExit)].interface}`
                    : ""}
                  {exits[Number(selectedExit)].encap
                    ? ` · ${exits[Number(selectedExit)].encap}`
                    : ""}
                  {exits[Number(selectedExit)].admin_state
                    ? ` · routed admin ${exits[Number(selectedExit)].admin_state}`
                    : ""}
                  {exits[Number(selectedExit)].oper_state
                    ? ` · routed oper ${exits[Number(selectedExit)].oper_state}`
                    : ""}
                  {exits[Number(selectedExit)].connection_dn
                    ? ` · ${exits[Number(selectedExit)].connection_dn}`
                    : ""}
                  {exits[Number(selectedExit)].routed_out_definition_dn
                    ? ` · ${exits[Number(selectedExit)].routed_out_definition_dn}`
                    : ""}
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
