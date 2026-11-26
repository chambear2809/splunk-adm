import { useId, useState, type InputHTMLAttributes } from "react";
import type { SearchClient } from "./data/searchClient";
import {
  SUGGEST_MIN_CHARS,
  mergeEndpointSuggestions,
  useEndpointSuggestions,
  type EndpointSuggestion,
  type EndpointSuggestState,
} from "./data/endpointSuggest";

export interface ComboboxKeyState {
  open: boolean;
  active: number;
}
export interface ComboboxKeyResult extends ComboboxKeyState {
  select?: number;
  preventDefault: boolean;
}

/** APG list-autocomplete keyboard model; Enter without an active option submits. */
export function comboboxKey(
  state: ComboboxKeyState,
  key: string,
  count: number,
): ComboboxKeyResult {
  const unchanged = { ...state, preventDefault: false };
  switch (key) {
    case "ArrowDown":
      if (!count) return { open: true, active: -1, preventDefault: true };
      return {
        open: true,
        active: !state.open ? 0 : (state.active + 1) % count,
        preventDefault: true,
      };
    case "ArrowUp":
      if (!count) return { open: true, active: -1, preventDefault: true };
      return {
        open: true,
        active: !state.open || state.active <= 0 ? count - 1 : state.active - 1,
        preventDefault: true,
      };
    case "Enter":
      return state.open && state.active >= 0 && state.active < count
        ? {
            open: false,
            active: -1,
            select: state.active,
            preventDefault: true,
          }
        : unchanged;
    case "Escape":
      return state.open
        ? { open: false, active: -1, preventDefault: true }
        : unchanged;
    case "Tab":
      return { open: false, active: -1, preventDefault: false };
    default:
      return unchanged;
  }
}

export interface SuggestOption {
  value: string;
  label?: string;
  kind?: string;
}

/** Page-local options containing the query (value or label), capped. */
export function filterSuggestOptions(
  options: readonly SuggestOption[],
  query: string,
  limit = 20,
): SuggestOption[] {
  const needle = query.trim().toLowerCase();
  const out: SuggestOption[] = [];
  const seen = new Set<string>();
  for (const option of options) {
    if (out.length >= limit) break;
    if (seen.has(option.value) || option.value === query.trim()) continue;
    if (
      needle &&
      !option.value.toLowerCase().includes(needle) &&
      !option.label?.toLowerCase().includes(needle)
    )
      continue;
    seen.add(option.value);
    out.push(option);
  }
  return out;
}

type InputProps = Omit<
  InputHTMLAttributes<HTMLInputElement>,
  | "value"
  | "onChange"
  | "role"
  | "list"
  | "autoComplete"
  | "aria-autocomplete"
  | "aria-expanded"
  | "aria-controls"
  | "aria-activedescendant"
>;

export function SuggestCombobox({
  value,
  onChange,
  onType,
  options,
  status,
  wrapperClassName,
  ...input
}: InputProps & {
  value: string;
  onChange: (value: string) => void;
  /** Called only for user typing, not for option selection. */
  onType?: (value: string) => void;
  options: readonly SuggestOption[];
  status?: string;
  wrapperClassName?: string;
}) {
  const listId = useId();
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const expanded = open && options.length > 0;
  const optionId = (index: number) => `${listId}-option-${index}`;
  const choose = (index: number) => {
    const option = options[index];
    if (option) onChange(option.value);
    setOpen(false);
    setActive(-1);
  };
  return (
    <span
      className={["atlas-combobox", wrapperClassName].filter(Boolean).join(" ")}
    >
      <input
        {...input}
        value={value}
        role="combobox"
        autoComplete="off"
        aria-autocomplete="list"
        aria-expanded={expanded}
        aria-controls={listId}
        aria-activedescendant={
          expanded && active >= 0 && active < options.length
            ? optionId(active)
            : undefined
        }
        onChange={(event) => {
          onChange(event.target.value);
          onType?.(event.target.value);
          setOpen(true);
          setActive(-1);
        }}
        onFocus={(event) => {
          setOpen(true);
          input.onFocus?.(event);
        }}
        onBlur={(event) => {
          setOpen(false);
          setActive(-1);
          input.onBlur?.(event);
        }}
        onKeyDown={(event) => {
          const next = comboboxKey({ open, active }, event.key, options.length);
          if (next.preventDefault) event.preventDefault();
          setOpen(next.open);
          setActive(next.active);
          if (next.select !== undefined) choose(next.select);
          input.onKeyDown?.(event);
        }}
      />
      <span
        className="atlas-combobox-popup"
        hidden={!open || (!options.length && !status)}
      >
        <ul
          id={listId}
          role="listbox"
          aria-label="Suggestions"
          hidden={!expanded}
        >
          {expanded &&
            options.map((option, index) => (
              <li
                key={option.value}
                id={optionId(index)}
                role="option"
                aria-selected={index === active}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => choose(index)}
              >
                <span>{option.value}</span>
                {(option.label || option.kind) && (
                  <small>
                    {[option.label, option.kind].filter(Boolean).join(" · ")}
                  </small>
                )}
              </li>
            ))}
        </ul>
        <small className="atlas-combobox-status" aria-live="polite">
          {open ? status : undefined}
        </small>
      </span>
    </span>
  );
}

export function endpointStatus(
  state: EndpointSuggestState,
  query: string,
  scope: string,
  live: boolean,
): string | undefined {
  if (!live) return undefined;
  if (!scope.trim()) return "Choose a routing scope for address suggestions.";
  if (query.trim().length < SUGGEST_MIN_CHARS)
    return `Type ${SUGGEST_MIN_CHARS}+ characters for scope suggestions.`;
  if (state.status === "loading") return "Searching this scope…";
  if (state.status === "error")
    return "Suggestions unavailable; enter a value.";
  if (state.status === "ready" && state.truncated)
    return "More matches in this scope; keep typing.";
  if (state.status === "ready" && !state.suggestions.length)
    return "No identity matches in this scope.";
  return undefined;
}

/**
 * Free-text address or host field. Page suggestions come first; once a scope
 * is chosen and 3+ characters are typed, `adm_ip_suggest` adds scope matches.
 */
export function EndpointCombobox({
  value,
  onChange,
  scope,
  client,
  live = false,
  local = [],
  ...input
}: InputProps & {
  value: string;
  onChange: (value: string) => void;
  scope: string;
  client?: SearchClient;
  live?: boolean;
  local?: readonly string[];
  wrapperClassName?: string;
}) {
  const [typed, setTyped] = useState("");
  const state = useEndpointSuggestions(live ? client : undefined, scope, typed);
  const server: EndpointSuggestion[] =
    state.status === "ready" ? state.suggestions : [];
  const options = mergeEndpointSuggestions(local, value, server);
  return (
    <SuggestCombobox
      {...input}
      value={value}
      onChange={onChange}
      onType={setTyped}
      options={options}
      status={
        client && live && typed
          ? endpointStatus(state, typed, scope, live)
          : undefined
      }
    />
  );
}
