import { useEffect, useId, useRef } from "react";
import ComboBoxExport from "@splunk/react-ui/ComboBox";
import ButtonExport from "@splunk/react-ui/Button";
import { toolkitDefault } from "../app/interop";
import { argError } from "../provider";
import { SCOPE_FIELDS, scopeValues, cascadeScope } from "../data/scopes";
import { useScopeOptions } from "../data/useScopeOptions";
import type { GraphArgs } from "../rows";
import type { SearchClient } from "../data/searchClient";
import type { DemoScenario } from "../data/demoClient";
const ComboBox = toolkitDefault(ComboBoxExport);
const Button = toolkitDefault(ButtonExport);
export function ScopeBar({
  args,
  onChange,
  live,
  client,
  demoArgs,
  scenario = "aci",
  autoSelectSingle = false,
}: {
  args: GraphArgs;
  onChange: (args: GraphArgs) => void;
  live: boolean;
  client?: SearchClient;
  demoArgs?: GraphArgs;
  scenario?: DemoScenario;
  autoSelectSingle?: boolean;
}) {
  const id = useId();
  const options = useScopeOptions(live, client, scenario);
  const selectedSingle = useRef(false);
  useEffect(() => {
    if (!autoSelectSingle || !live || selectedSingle.current || options.loading)
      return;
    selectedSingle.current = true;
    if (
      !options.error &&
      !options.warnings?.length &&
      options.rows.length === 1 &&
      SCOPE_FIELDS.every((key) => !args[key]) &&
      SCOPE_FIELDS.every((key) => !argError(key, options.rows[0][key]))
    ) {
      const row = options.rows[0];
      onChange({
        environment: row.environment,
        cluster: row.cluster,
        namespace: row.namespace,
        service: row.service,
      });
    }
  }, [autoSelectSingle, live, options, args, onChange]);
  return (
    <section className="atlas-scope-fields" aria-label="Application scope">
      {SCOPE_FIELDS.map((key, index) => {
        const error = argError(key, args[key]);
        const disabled =
          options.loading ||
          SCOPE_FIELDS.slice(0, index).some(
            (parent) => !!argError(parent, args[parent]),
          );
        return (
          <div className="atlas-scope-field" key={key}>
            <label id={`${id}-${key}-label`} htmlFor={`${id}-${key}`}>
              {key[0].toUpperCase() + key.slice(1)}
            </label>
            <ComboBox
              inputId={`${id}-${key}`}
              labelledBy={`${id}-${key}-label`}
              describedBy={`${id}-${key}-help`}
              value={demoArgs?.[key] ?? args[key]}
              controlledFilter={!!demoArgs}
              disabled={disabled}
              isLoadingOptions={options.loading}
              error={!!error}
              placeholder={`Choose ${key}`}
              noOptionsMessage="No matching scope options"
              onChange={(_e, { value }) =>
                demoArgs
                  ? value === demoArgs[key] && onChange(demoArgs)
                  : onChange(cascadeScope(args, key, value))
              }
            >
              {scopeValues(options.rows, args, key).map((value) => {
                const reason =
                  argError(key, value) ??
                  (demoArgs && demoArgs[key] !== value
                    ? "This scope has no captured demo map."
                    : undefined);
                return (
                  <ComboBox.Option
                    key={value}
                    value={value}
                    label={value || "(empty — unavailable)"}
                    disabled={!!reason}
                    description={reason}
                    descriptionPosition="bottom"
                  />
                );
              })}
            </ComboBox>
            <small id={`${id}-${key}-help`}>
              {error ??
                (disabled && !options.loading
                  ? "Choose the preceding scope first."
                  : "")}
            </small>
          </div>
        );
      })}
      {options.error && (
        <div className="atlas-scope-message">
          <p role="alert">
            Scope options: {options.error} You can enter a valid scope manually.
          </p>
          <Button label="Retry scope options" onClick={options.retry} />
        </div>
      )}
      {!options.loading && !options.error && options.rows.length === 0 && (
        <p className="atlas-scope-message">
          No service bindings found. Enter a valid scope or ask an administrator
          to enable service binding.
        </p>
      )}
      {options.warnings?.map((warning) => (
        <p className="atlas-scope-message" key={warning}>
          {warning}
        </p>
      ))}
    </section>
  );
}
