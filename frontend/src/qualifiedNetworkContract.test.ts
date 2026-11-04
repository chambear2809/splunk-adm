import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { filterGraph } from "./filters";
import { rowsToGraph, type Row } from "./rows";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const python =
  process.env.ATLAS_PYTHON ??
  (process.platform === "win32" ? "python" : "python3");

const pythonFixture = String.raw`
import copy, json, sys
sys.path.insert(0, "tests")
from test_qualified_network import NETWORK, PROFILE, SELECTION, native
from test_qualified_identity import interval_rows, span
from splunk_app.splunk_adm.bin.adm_identity_lib.network_graph import assemble, configuration
from splunk_app.splunk_adm.bin.adm_identity_lib.qualified import qualify

config = copy.deepcopy(NETWORK)
config["profiles"].append({
    "id": "exporter-a", "kind": "netflow", "index": "flows",
    "source": "stream:netflow", "sourcetype": "stream:netflow",
    "scope": "routing-a", "cluster": "cluster-a",
    "exporter_ip": "192.0.2.30", "netflow_version": 10,
    "observation_domain_present": True, "observation_domain_id": 0,
})
config["frontends"] = [{
    **SELECTION, "scope": "routing-a", "address": "192.0.2.20",
    "valid_from": 10, "valid_to": 30,
}]
raw = {
    "exporter_ip": "192.0.2.30", "netflow_version": 10,
    "observation_domain_id": 0, "timestamp": "1970-01-01T00:00:14Z",
    "endtime": "1970-01-01T00:00:15Z", "src_ip": "192.0.2.10",
    "dest_ip": "192.0.2.20", "src_port": 1234, "dest_port": 8080,
    "protoid": 6, "bytes_in": 200, "packets_in": 4, "flow_dir": 0,
}
netflow = {
    "_raw": json.dumps(raw), "index": "flows", "source": "stream:netflow",
    "sourcetype": "stream:netflow", "event_time": "15", "receipt_time": "16",
    "_bkt": "flows~1~a", "_cd": "1:2",
}
result = qualify(interval_rows() + [span()], PROFILE, 0, 100)
print(json.dumps(assemble(
    result, [native(), netflow], configuration(config, PROFILE), SELECTION,
)))
`;

const qualifiedRows = (): Row[] =>
  (
    JSON.parse(
      execFileSync(python, ["-c", pythonFixture], {
        cwd: repoRoot,
        encoding: "utf8",
      }),
    ) as Row[]
  ).map((row) =>
    Object.fromEntries(
      Object.entries(row).map(([key, value]) => [
        key,
        typeof value === "number" || typeof value === "boolean"
          ? String(value)
          : value,
      ]),
    ),
  );

describe("qualified native network contract", () => {
  it("accepts Python assemble output as observation-only graph evidence", () => {
    const graph = rowsToGraph(qualifiedRows(), {
      service: "checkout",
      environment: "prod",
      cluster: "cluster-a",
      namespace: "shop",
    });
    const observations = graph.edges.filter(
      (edge) => edge.relationship === "traffic_observation",
    );
    expect(observations).toHaveLength(2);
    expect(graph.edges.some((edge) => edge.relationship === "calls")).toBe(
      false,
    );
    expect(
      graph.edges.some((edge) =>
        ["communicates_with", "forwards_to"].includes(edge.relationship),
      ),
    ).toBe(false);

    const bySource = new Map(
      observations.map((edge) => [edge.sources?.[0], edge]),
    );
    const hubble = bySource.get("hubble")!;
    const netflow = bySource.get("netflow")!;
    expect(hubble.traffic_observations?.[0]).toMatchObject({
      source: "hubble",
      source_port: 1234,
      destination_port: 443,
      is_reply: false,
      verdict: "FORWARDED",
      records: 1,
      metrics_authoritative: false,
    });
    expect(netflow.traffic_observations?.[0]).toMatchObject({
      source: "netflow",
      netflow_version: 10,
      source_port: 1234,
      destination_port: 8080,
      records: 1,
      raw_bytes: 200,
      metrics_authoritative: false,
    });
    expect(hubble.server_port).toBeUndefined();
    expect(netflow.server_port).toBeUndefined();
    expect(hubble.traffic_observations?.[0].record_fingerprint).toMatch(
      /^[0-9a-f]{64}$/,
    );
    expect(netflow.traffic_observations?.[0].record_fingerprint).toMatch(
      /^[0-9a-f]{64}$/,
    );

    const hubbleFiltered = filterGraph(graph, { source: "hubble" });
    const netflowFiltered = filterGraph(graph, { source: "netflow" });
    expect(hubbleFiltered.edges.map((edge) => edge.id)).toContain(hubble.id);
    expect(hubbleFiltered.edges.map((edge) => edge.id)).not.toContain(
      netflow.id,
    );
    expect(
      hubbleFiltered.edges.some((edge) => edge.relationship === "runs_on"),
    ).toBe(true);
    expect(netflowFiltered.edges.map((edge) => edge.id)).toContain(netflow.id);
    expect(netflowFiltered.edges.map((edge) => edge.id)).not.toContain(
      hubble.id,
    );
    const portFiltered = filterGraph(graph, { port: 1234 });
    expect(portFiltered.edges.map((edge) => edge.id)).toEqual(
      expect.arrayContaining([hubble.id, netflow.id]),
    );
  });
});
