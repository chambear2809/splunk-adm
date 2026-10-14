import { useState } from "react";
import ButtonExport from "@splunk/react-ui/Button";
import { ScopeBar } from "../map/ScopeBar";
import { TimePicker } from "../map/TimePicker";
import type { SearchClient } from "../data/searchClient";
import { demoArgs, DEMO_WINDOW } from "../data/demoClient";
import { toolkitDefault } from "../app/interop";
import { pageURL, stateParams, type UrlState } from "../app/urlState";
import { argError } from "../provider";
import { timeError } from "../data/timeBounds";
import type { GraphArgs } from "../rows";
const Button = toolkitDefault(ButtonExport);

export function ApplicationsPage({
  state,
  client,
  timezone,
  inSplunk = false,
}: {
  state: UrlState;
  client?: SearchClient;
  timezone?: string;
  inSplunk?: boolean;
}) {
  const [args, setArgs] = useState(
    state.mode === "demo" ? demoArgs : state.args,
  );
  const [earliest, setEarliest] = useState(
    state.mode === "demo" ? DEMO_WINDOW.earliest : state.earliest,
  );
  const [latest, setLatest] = useState(
    state.mode === "demo" ? DEMO_WINDOW.latest : state.latest,
  );
  const keys = Object.keys(args) as (keyof GraphArgs)[];
  const errors = [
    ...keys.map((key) => argError(key, args[key])),
    timeError(earliest, latest, timezone),
  ].filter(Boolean);
  return (
    <main className="atlas-page">
      <h1>Applications</h1>
      <p>
        Choose an application scope to explore its services and network
        dependencies.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!errors.length)
            location.assign(
              pageURL("map", stateParams({ ...state, args, earliest, latest })),
            );
        }}
      >
        <ScopeBar
          args={args}
          onChange={setArgs}
          live={state.mode === "live"}
          client={client}
          demoArgs={state.mode === "demo" ? demoArgs : undefined}
        />
        <TimePicker
          earliest={earliest}
          latest={latest}
          timezone={timezone}
          live={inSplunk}
          disabled={state.mode === "demo"}
          onChange={(start, end) => {
            setEarliest(start);
            setLatest(end);
          }}
        />
        <Button
          type="submit"
          appearance="primary"
          disabled={!!errors.length}
          label="Open map"
        />
      </form>
      <p>
        <a href={pageURL("map", stateParams({ ...state, mode: "demo" }))}>
          Explore captured synthetic demo data
        </a>
      </p>
    </main>
  );
}
