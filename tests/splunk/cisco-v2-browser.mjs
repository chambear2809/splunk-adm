// Read-only native post-cutover qualification. One stdin JSON carries ephemeral
// authentication and recorded scenarios; no credentials, HAR or traces are saved.
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  selectScenarioEvidence,
  assertScenarioCsv,
  expectedBackendText,
} from "./cisco-v2-evidence.mjs";
const require = createRequire(new URL("../../package.json", import.meta.url));
const { chromium, expect } = require("@playwright/test");
let input = "";
for await (const chunk of process.stdin) input += chunk;
const payload = JSON.parse(input);
input = "";
const { auth, scenarios, dependencies, artifactDirectory } = payload;
if (!auth?.username || !auth?.password || scenarios?.length !== 2)
  throw new Error(
    "protected stdin authentication and two recorded scenarios required",
  );
const BASE = "http://127.0.0.1:8000";
const digest = (value) => createHash("sha256").update(value).digest("hex");
const safe = (value) =>
  String(value)
    .replaceAll(auth.password, "[redacted]")
    .replaceAll(auth.username, "[user]")
    .replace(/https?:\/\/[^\s"'<>]+/gi, "[url]")
    .slice(0, 800);
let stage = "browser startup";
const evidence = {
  ok: false,
  scenarios: [],
  demoRequests: 0,
  configurationWrites: 0,
};
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({
    acceptDownloads: true,
    viewport: { width: 1440, height: 1100 },
  });
  const page = await context.newPage();
  const searches = [];
  const metadata = [];
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(safe(error.message)));
  page.on("request", (request) => {
    const path = decodeURIComponent(new URL(request.url()).pathname);
    if (/\/search\/(v2\/)?jobs\/?$/.test(path) && request.method() === "POST") {
      const data = new URLSearchParams(request.postData() || "");
      const search = data.get("search") || "";
      searches.push({
        macro: search.match(/`(adm_[a-z0-9_]+)/)?.[1],
        earliest: data.get("earliest_time"),
        latest: data.get("latest_time"),
      });
    }
    if (
      request.method() !== "GET" &&
      /\/(configs\/conf-macros|saved\/searches|adm\/deployment-settings)(\/|$)/.test(
        path,
      )
    )
      evidence.configurationWrites += 1;
  });
  page.on("response", (response) => {
    const path = decodeURIComponent(new URL(response.url()).pathname);
    if (
      response.request().method() === "GET" &&
      /\/servicesNS\/nobody\/splunk_adm\/(configs\/conf-macros\/|adm\/deployment-settings)/.test(
        path,
      )
    )
      metadata.push({
        name: path.split("/splunk_adm/")[1],
        status: response.status(),
      });
  });
  await page.route("**/demo/*.json", (route) => {
    evidence.demoRequests += 1;
    return route.abort();
  });
  stage = "native login";
  await page.goto(`${BASE}/en-US/account/login`);
  await page.locator('input[name="username"]').fill(auth.username);
  await page.locator('input[name="password"]').fill(auth.password);
  await Promise.all([
    page.waitForURL((url) => !url.pathname.includes("/account/login"), {
      timeout: 30000,
    }),
    page.locator('input[type="submit"],button[type="submit"]').first().click(),
  ]);
  async function download(label, destination) {
    const region = page.getByRole("region", { name: "Export", exact: true });
    if (!(await region.isVisible()))
      await page.getByRole("button", { name: "Export", exact: true }).click();
    const waiting = page.waitForEvent("download");
    await page.getByRole("button", { name: label }).click();
    const item = await waiting;
    const value = await readFile(await item.path(), "utf8");
    expect(value.length).toBeGreaterThan(0);
    await writeFile(destination, value, { mode: 0o600, flag: "wx" });
    // JSON/CSV export handlers close the popover after starting the download.
    await expect(region).not.toBeVisible();
    return value;
  }
  async function selectMapCard(card, previous) {
    await expect(card).toHaveCount(1);
    await expect(card).toBeVisible();
    // Findings can keep Details open beside the SVG even without a selection.
    // Exercise the card's supported keyboard handler instead of depending on
    // its pointer center remaining outside that docked panel after layout.
    await card.focus();
    await expect(card).toBeFocused();
    await card.press("Enter");
    await expect(card).toHaveAttribute("aria-pressed", "true");
    await expect(card).toBeFocused();
    if (previous)
      await expect(previous).toHaveAttribute("aria-pressed", "false");
  }
  async function map(scenario) {
    const args = new URLSearchParams({
      mode: "live",
      service: "checkout",
      environment: "demo",
      cluster: scenario.cluster,
      namespace: "shop",
      earliest: scenario.earliest,
      latest: scenario.latest,
    });
    const response = await page.goto(
      `${BASE}/en-US/app/splunk_adm/map?${args}`,
    );
    expect(response.status()).toBeLessThan(400);
    const adm = page.locator('#atlas-root .adm[data-loaded="true"]');
    await adm.waitFor({ timeout: 150000 });
    await expect(adm.locator(".scope-service")).toHaveText("checkout");
    await expect(adm.locator(".scope-dims")).toContainText(scenario.cluster);
    expect(Number(await adm.getAttribute("data-node-count"))).toBe(
      scenario.nodes,
    );
    expect(Number(await adm.getAttribute("data-edge-count"))).toBe(
      scenario.edges,
    );
    return adm;
  }
  for (const [number, scenario] of scenarios.entries()) {
    stage = `${scenario.cluster}: public map and JSON export`;
    const start = searches.length;
    let adm = await map(scenario);
    const dispatched = searches
      .slice(start)
      .find((row) => row.macro === "adm_graph");
    expect(dispatched).toEqual({
      macro: "adm_graph",
      earliest: scenario.earliest,
      latest: scenario.latest,
    });
    const prefix = join(artifactDirectory, `post-cutover-${number}`);
    const text = await download(/Map data \(JSON\)/, prefix + "-map.json");
    const graph = JSON.parse(text);
    expect(graph.nodes).toHaveLength(scenario.nodes);
    expect(graph.edges).toHaveLength(scenario.edges);
    const client = graph.nodes.find((node) => node.id === scenario.clientId);
    expect(client).toBeTruthy();
    expect(client.attributes.source_authority).toBe(scenario.sourceAuthority);
    expect(client.attributes.attachment_device_id).toBe(
      scenario.attachmentDeviceId,
    );
    expect(client.attributes.attachment_basis).toBe(scenario.attachmentBasis);
    expect(Number(client.attributes.source_time)).toBe(
      Number(scenario.sourceTime),
    );
    expect(Number(client.attributes.received_time)).toBe(
      Number(scenario.receivedTime),
    );
    expect(client.attributes.collected_time).toBeUndefined();
    expect(client.attributes.attachment_collected_time).toBeUndefined();
    const selected = selectScenarioEvidence(graph, scenario);
    const { observations, connection, ipClient, bindings } = selected;
    const byId = new Map(graph.nodes.map((node) => [node.id, node]));
    stage = `${scenario.cluster}: client Inspector provenance`;
    const card = adm.locator(".map-canvas").getByRole("button", {
      name: `Network client ${client.label}`,
      exact: true,
    });
    await selectMapCard(card);
    const details = page.getByRole("complementary", { name: "Details" });
    await expect(details).toContainText(scenario.sourceAuthority);
    await expect(details).toContainText(scenario.attachmentDeviceId);
    await expect(details).toContainText("Source event time");
    await expect(details).toContainText("Received time");
    const sourceTime = client.attributes.source_time_status;
    if (sourceTime) await expect(details).toContainText(sourceTime);
    const trafficDetails = details.getByRole("region", {
      name: "Traffic observations",
      exact: true,
    });
    await expect(trafficDetails).toContainText(scenario.clientIp);
    await expect(trafficDetails).toContainText(scenario.scope);
    for (const observation of observations)
      for (const record of observation.traffic_observations)
        await expect(trafficDetails).toContainText(record.source_authority);
    stage = `${scenario.cluster}: separate unresolved IP identity and tuple-bound path`;
    const ipCard = adm.locator(".map-canvas").getByRole("button", {
      name: `Unknown IP ${scenario.clientIp}, identity unknown`,
      exact: true,
    });
    await selectMapCard(ipCard, card);
    await expect(details).toContainText(
      "No identity record covers this address",
    );
    await expect(details).toContainText(scenario.clientIp);
    await adm.getByRole("button", { name: "Table", exact: true }).click();
    const row = adm
      .locator(".table-view tbody tr")
      .filter({ hasText: scenario.clientIp })
      .filter({ hasText: byId.get(connection.target).label });
    await expect(row).toHaveCount(1);
    await row.locator("button").first().click();
    const fact = (name) =>
      details
        .locator(".facts dt")
        .filter({ hasText: new RegExp(`^${name}$`) })
        .locator("xpath=following-sibling::dd[1]");
    await expect(fact("Identity")).toHaveText("Unknown IP");
    await expect(fact("Backend")).toHaveText(
      expectedBackendText(connection, graph, ", "),
    );
    const receivers = [
      ...new Set(
        connection.client_handoffs.flatMap((record) => record.receiving_nodes),
      ),
    ];
    await expect(fact("Received on")).toHaveText(
      receivers.length === 1 ? receivers[0] : `one of ${receivers.join(", ")}`,
    );
    await details
      .getByRole("button", { name: "Show candidate path", exact: true })
      .click();
    const path = page.locator(".path-strip");
    await expect(path).toBeVisible();
    const targets = [
      ...new Set(connection.client_handoffs.map((record) => record.target)),
    ];
    const chooser = path.getByRole("combobox", {
      name: "Backend",
      exact: true,
    });
    if (targets.length > 1) {
      expect(
        await chooser
          .locator("option")
          .evaluateAll((options) =>
            options.map((option) => option.value).sort(),
          ),
      ).toEqual([...targets].sort());
    } else await expect(chooser).toHaveCount(0);
    const stageTitles = (kind) =>
      path
        .locator(`.stage.${kind} .stage-card`)
        .evaluateAll((cards) =>
          cards.map((card) => card.getAttribute("title").split("\n")[0]).sort(),
        );
    for (const target of targets) {
      if (targets.length > 1) await chooser.selectOption(target);
      const expectedReceivers = [
        ...new Set(
          connection.client_handoffs
            .filter((record) => record.target === target)
            .flatMap((record) => record.receiving_nodes),
        ),
      ].sort();
      await expect
        .poll(() => stageTitles("entity"))
        .toEqual([ipClient.label, byId.get(target).label].sort());
      await expect.poll(() => stageTitles("host")).toEqual(expectedReceivers);
    }
    stage = `${scenario.cluster}: physical attachment inventory`;
    await adm.getByRole("button", { name: "Devices", exact: true }).click();
    const attachments = page.getByRole("region", {
      name: "Client attachment devices",
    });
    await expect(attachments).toContainText(scenario.attachmentDeviceId);
    await expect(attachments).toContainText(scenario.attachmentDeviceName);
    expect(
      searches
        .slice(start)
        .some(
          (query) =>
            query.macro === "adm_topology" &&
            query.earliest === scenario.earliest &&
            query.latest === scenario.latest,
        ),
    ).toBe(true);
    stage = `${scenario.cluster}: context CSV and reload`;
    const csv = await download(
      /Context evidence \(CSV\)/,
      prefix + "-context.csv",
    );
    expect(csv).toContain(scenario.clientId);
    expect(csv).toContain(scenario.sourceAuthority);
    expect(csv).toContain(scenario.attachmentDeviceId);
    expect(csv).toContain("traffic_observation");
    expect(csv).toContain("attachment_evidence");
    const flows = await download(
      /Required flows \(CSV\)/,
      prefix + "-flows.csv",
    );
    assertScenarioCsv(csv, flows, selected, graph, scenario);
    adm = await map(scenario);
    stage = `${scenario.cluster}: absolute comparison`;
    const beforeComparison = searches.length;
    await adm.getByRole("button", { name: "Changes", exact: true }).click();
    await page
      .getByRole("button", { name: "Compare previous window", exact: true })
      .click();
    await expect(page.getByText(/^Previous:/)).toBeVisible({ timeout: 150000 });
    await expect(page.getByText(/^Current:/)).toBeVisible();
    const previous = searches
      .slice(beforeComparison)
      .find((query) => query.macro === "adm_graph");
    const width = Number(scenario.latest) - Number(scenario.earliest);
    expect(previous).toEqual({
      macro: "adm_graph",
      earliest: String(Number(scenario.earliest) - width),
      latest: scenario.earliest,
    });
    const compared = JSON.parse(
      await download(/Map data \(JSON\)/, prefix + "-comparison-map.json"),
    );
    const comparedSelected = selectScenarioEvidence(compared, scenario);
    expect(comparedSelected.client).toEqual(client);
    expect(comparedSelected.ipClient).toEqual(ipClient);
    expect(comparedSelected.observations).toEqual(observations);
    expect(comparedSelected.connection).toEqual(connection);
    const comparisonContext = await download(
      /Context evidence \(CSV\)/,
      prefix + "-comparison-context.csv",
    );
    const comparisonFlows = await download(
      /Required flows \(CSV\)/,
      prefix + "-comparison-flows.csv",
    );
    assertScenarioCsv(
      comparisonContext,
      comparisonFlows,
      comparedSelected,
      compared,
      scenario,
    );
    stage = `${scenario.cluster}: public and network-client Find`;
    const args = new URLSearchParams({
      mode: "live",
      earliest: scenario.earliest,
      latest: scenario.latest,
      service: "checkout",
      environment: "demo",
      cluster: scenario.cluster,
      namespace: "shop",
    });
    const beforeFind = searches.length;
    await page.goto(`${BASE}/en-US/app/splunk_adm/applications?${args}`);
    await page.locator("#atlas-find-value").fill(scenario.clientIp);
    await page
      .locator("main.atlas-page")
      .getByRole("button", { name: "Find", exact: true })
      .click();
    const find = page.locator('[aria-label="Network client evidence"]');
    await expect(find).toContainText(scenario.clientMac, { timeout: 150000 });
    for (const value of [
      scenario.sourceAuthority,
      scenario.attachmentDeviceId,
      scenario.scope,
      scenario.findAttachmentBasis,
    ])
      await expect(find).toContainText(value);
    const findMacros = searches.slice(beforeFind).map((query) => query.macro);
    expect(findMacros).toContain("adm_find");
    expect(findMacros).toContain("adm_find_network_client");
    evidence.scenarios.push({
      cluster: scenario.cluster,
      nodes: graph.nodes.length,
      edges: graph.edges.length,
      publicGraph: true,
      inspectorProvenance: true,
      networkClient: {
        id: client.id,
        mac: scenario.clientMac,
        authority: scenario.sourceAuthority,
        attachmentDeviceId: scenario.attachmentDeviceId,
        attachmentBasis: scenario.attachmentBasis,
        trafficObservationIds: observations.map((edge) => edge.id),
        inspectorObservationProvenance: true,
        contextExportRecords: true,
      },
      scopedIpConversation: {
        nodeId: ipClient.id,
        edgeId: connection.id,
        scope: scenario.scope,
        clientIp: scenario.clientIp,
        serviceId: connection.target,
        identity: ipClient.endpoint_kind,
        unresolvedReason: ipClient.reason,
        handoffBasis: "hubble_client_tuple",
        handoffs: connection.client_handoffs,
        candidatePath: true,
        requiredFlowsExport: true,
      },
      observedTupleAgreement: bindings.map((binding) => ({
        observationId: binding.observationId,
        recordFingerprint: binding.recordFingerprint,
        connections: binding.matches.map((row) => ({
          id: row.adm_cid,
          sourcePort: row.adm_cport,
          firstSeen: row.adm_ct,
          lastSeen: row.adm_cend,
          serviceCandidates: row.adm_cands,
        })),
      })),
      macIpIdentityContinuity: "not established by tuple agreement",
      attachmentInventory: true,
      reload: true,
      absoluteComparison: {
        query: previous,
        networkClientObservationsPreserved: true,
        scopedIpConversationAndUnresolvedIdentityPreserved: true,
        contextCsvSha256: digest(comparisonContext),
        requiredFlowsCsvSha256: digest(comparisonFlows),
      },
      publicFind: true,
      networkClientFind: true,
      json: { sha256: digest(text), bytes: Buffer.byteLength(text) },
      contextCsv: { sha256: digest(csv), bytes: Buffer.byteLength(csv) },
      requiredFlowsCsv: {
        sha256: digest(flows),
        bytes: Buffer.byteLength(flows),
      },
    });
  }
  stage = "Setup actual V2 dependency configuration";
  const setupStart = searches.length;
  const metadataStart = metadata.length;
  await page.goto(`${BASE}/en-US/app/splunk_adm/setup?mode=live`);
  const root = page.locator("#atlas-root");
  await expect(
    root.getByText(
      "Version 2 selectors and scheduled writer configuration were observed. This is a read-only configuration check; review Data health for receipt and run evidence.",
    ),
  ).toBeVisible({ timeout: 150000 });
  await expect(
    root.getByText("Saved expectations; active data contract: 2."),
  ).toBeVisible();
  await expect
    .poll(() => searches.slice(setupStart).map((query) => query.macro))
    .toContain("adm_health_jobs");
  for (const name of dependencies.selectors)
    expect(
      metadata
        .slice(metadataStart)
        .some(
          (row) =>
            row.name === `configs/conf-macros/${name}` && row.status === 200,
        ),
    ).toBe(true);
  expect(
    metadata
      .slice(metadataStart)
      .some(
        (row) => row.name === "adm/deployment-settings" && row.status === 200,
      ),
  ).toBe(true);
  const setupMacros = searches.slice(setupStart).map((query) => query.macro);
  expect(
    setupMacros
      .filter((macro) => macro?.startsWith("adm_health_"))
      .every((macro) => macro === "adm_health_jobs"),
  ).toBe(true);
  stage =
    "Data health actual configured V2 source, quality and scheduler chain";
  const healthStart = searches.length;
  const healthMetadataStart = metadata.length;
  await page.goto(`${BASE}/en-US/app/splunk_adm/data_health?mode=live`);
  await expect(
    page.getByRole("heading", { name: "Data health", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Check again", exact: true }),
  ).toBeEnabled({ timeout: 180000 });
  await expect(
    page.getByRole("heading", { name: "Data sources", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Scheduled searches", exact: true }),
  ).toBeVisible();
  const healthText = await root.innerText();
  expect(healthText).not.toContain("Deployment expectations are unknown");
  await expect(
    root.getByRole("alert").filter({ hasText: "Health check is incomplete" }),
  ).toHaveCount(0);
  for (const label of dependencies.sourceLabels)
    expect(healthText).toContain(label);
  for (const name of dependencies.requiredJobs)
    expect(healthText).toContain(name);
  const healthQueries = searches.slice(healthStart);
  for (const macro of dependencies.healthProbes)
    expect(
      healthQueries.some(
        (query) =>
          query.macro === macro &&
          query.earliest === "-7d" &&
          query.latest === "now",
      ),
      `missing native health dependency ${macro}`,
    ).toBe(true);
  for (const macro of dependencies.indexMacros)
    expect(
      metadata
        .slice(healthMetadataStart)
        .some(
          (row) =>
            row.name === `configs/conf-macros/${macro}` && row.status === 200,
        ),
    ).toBe(true);
  expect(pageErrors).toEqual([]);
  expect(evidence.configurationWrites).toBe(0);
  expect(evidence.demoRequests).toBe(0);
  evidence.setup = {
    activeContract: 2,
    verifiedPublicSelectors: dependencies.selectors,
    schedulerEvidence: true,
    healthMacros: setupMacros.filter((macro) =>
      macro?.startsWith("adm_health_"),
    ),
  };
  evidence.health = {
    configuredExpectations: true,
    sourceLabels: dependencies.sourceLabels,
    requiredJobs: dependencies.requiredJobs,
    probes: healthQueries,
    indexMetadata: dependencies.indexMacros,
    tableRows: await root.locator("table tbody tr").allInnerTexts(),
    statusEvidenceSha256: digest(healthText),
  };
  evidence.ok = true;
  await context.close();
} catch (error) {
  evidence.stage = stage;
  evidence.error = safe(error.message);
  process.exitCode = 1;
} finally {
  await browser.close();
  process.stdout.write(JSON.stringify(evidence) + "\n");
}
