import { useState } from "react";
import ButtonExport from "@splunk/react-ui/Button";
import TextExport from "@splunk/react-ui/Text";
import { toolkitDefault } from "../app/interop";
import { pageURL, stateParams, type UrlState } from "../app/urlState";
import { argError } from "../provider";
import type { GraphArgs } from "../rows";
const Button = toolkitDefault(ButtonExport);
const Text = toolkitDefault(TextExport);

export function ApplicationsPage({ state }: { state: UrlState }) {
  const [args, setArgs] = useState(state.args);
  const keys = Object.keys(args) as (keyof GraphArgs)[];
  const errors = keys.map((key) => argError(key, args[key])).filter(Boolean);
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
            location.assign(pageURL("map", stateParams({ ...state, args })));
        }}
      >
        {keys.map((key) => (
          <label className="atlas-field" key={key}>
            <span>{key[0].toUpperCase() + key.slice(1)}</span>
            <Text
              value={args[key]}
              onChange={(_e, { value }) =>
                setArgs((current) => ({ ...current, [key]: value }))
              }
              error={!!argError(key, args[key])}
            />
            <small>{argError(key, args[key])}</small>
          </label>
        ))}
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
