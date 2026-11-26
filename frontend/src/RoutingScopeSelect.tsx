import { useEffect, useId, useRef, useState } from "react";
import { pageURL } from "./app/urlState";
import {
  filterScopeOptions,
  isUnlistedScope,
  SCOPE_FILTER_THRESHOLD,
  singleScope,
  type RoutingScopeState,
} from "./data/routingScopes";

/**
 * Routing scope picker backed by caller-visible observer mappings. Without a
 * loaded list it falls back to free-text entry so links and manual scopes keep
 * working.
 */
export function RoutingScopeSelect({
  value,
  onChange,
  state,
  label = "Routing scope",
  showLabel = false,
  compact = false,
  required = false,
  commitOnBlur = false,
  onRetry,
  className,
}: {
  value: string;
  onChange: (scope: string) => void;
  state: RoutingScopeState;
  label?: string;
  showLabel?: boolean;
  /** One bare control for dense toolbars; status goes into its title. */
  compact?: boolean;
  required?: boolean;
  /** Free-text fallback commits on blur or Enter instead of every keystroke. */
  commitOnBlur?: boolean;
  onRetry?: () => void;
  /** Extra class for the control itself, for toolbar grid placement. */
  className?: string;
}) {
  const id = useId();
  const controlId = `${id}-scope`;
  const hintId = `${id}-hint`;
  const [query, setQuery] = useState("");
  const autoSelected = useRef(false);
  const preselect = singleScope(state, value);
  useEffect(() => {
    if (preselect === undefined || autoSelected.current) return;
    autoSelected.current = true;
    onChange(preselect);
  }, [preselect, onChange]);

  const options = state.status === "ready" ? state.options : [];
  const listed = state.status === "loading" || state.status === "ready";
  const unlisted = isUnlistedScope(state, value);
  const empty = state.status === "ready" && options.length === 0;
  const filterable = !compact && options.length > SCOPE_FILTER_THRESHOLD;
  const hint =
    state.status === "error"
      ? "Routing scope list unavailable; enter a mapped scope."
      : empty
        ? "No mapped routing scopes yet."
        : undefined;

  const control = !listed ? (
    <ScopeText
      key={commitOnBlur ? value : undefined}
      id={controlId}
      value={value}
      onChange={onChange}
      label={label}
      placeholder={compact ? label : undefined}
      required={required}
      commitOnBlur={commitOnBlur}
      title={hint}
      describedBy={hint && !compact ? hintId : undefined}
      className={className}
    />
  ) : (
    <select
      id={controlId}
      className={["atlas-compact-select", className].filter(Boolean).join(" ")}
      aria-label={label}
      aria-busy={state.status === "loading" || undefined}
      aria-describedby={hint && !compact ? hintId : undefined}
      title={
        unlisted
          ? "This linked scope is not in the mapped scope list."
          : empty
            ? "An administrator maps observers to routing scopes in Setup."
            : undefined
      }
      value={value}
      required={required}
      disabled={!value && (state.status === "loading" || empty)}
      onChange={(event) => onChange(event.target.value)}
    >
      <option value="">
        {state.status === "loading"
          ? "Loading scopes…"
          : empty
            ? "No mapped routing scopes yet"
            : "Choose a routing scope"}
      </option>
      {value && (unlisted || state.status === "loading") && (
        <option value={value}>
          {unlisted ? `${value} (not in mapped list)` : value}
        </option>
      )}
      {(filterable ? filterScopeOptions(options, query, value) : options).map(
        (option) => (
          <option key={option.scope} value={option.scope}>
            {option.scope}
          </option>
        ),
      )}
    </select>
  );
  if (compact) return control;
  return (
    <span className="atlas-scope-picker">
      {showLabel && <label htmlFor={controlId}>{label}</label>}
      {filterable && (
        <input
          type="search"
          className="atlas-input atlas-scope-filter"
          aria-label={`Filter ${label.toLowerCase()} options`}
          aria-controls={controlId}
          placeholder={`Filter ${options.length} scopes`}
          autoComplete="off"
          spellCheck={false}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      )}
      {control}
      {hint && (
        <small id={hintId} className="muted" role="status">
          {hint}{" "}
          {state.status === "error" && onRetry ? (
            <button type="button" className="link" onClick={onRetry}>
              Retry scope list
            </button>
          ) : (
            empty && <a href={pageURL("setup")}>Map observers in Setup</a>
          )}
        </small>
      )}
    </span>
  );
}

function ScopeText({
  id,
  value,
  onChange,
  label,
  placeholder,
  required,
  commitOnBlur,
  title,
  describedBy,
  className,
}: {
  id: string;
  value: string;
  onChange: (scope: string) => void;
  label: string;
  placeholder?: string;
  required: boolean;
  commitOnBlur: boolean;
  title?: string;
  describedBy?: string;
  className?: string;
}) {
  const [draft, setDraft] = useState(value);
  const commit = () => {
    if (draft.trim() !== value) onChange(draft.trim());
  };
  return (
    <input
      id={id}
      className={["atlas-input", className].filter(Boolean).join(" ")}
      aria-label={label}
      aria-describedby={describedBy}
      placeholder={placeholder}
      title={title}
      autoComplete="off"
      spellCheck={false}
      required={required}
      value={commitOnBlur ? draft : value}
      onChange={(event) =>
        commitOnBlur
          ? setDraft(event.target.value)
          : onChange(event.target.value)
      }
      onBlur={commitOnBlur ? commit : undefined}
      onKeyDown={
        commitOnBlur
          ? (event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                commit();
              }
            }
          : undefined
      }
    />
  );
}
