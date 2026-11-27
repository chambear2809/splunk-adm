# Protocol worker brief template

The orchestrator fills one brief per lens. Workers do not expand the brief or delegate.

## 1. Outcome and acceptance criteria

- Lens id:
- Views (Overview, Matrix, drawer):
- Flags:
- UX checklist: [docs/superpowers/specs/2026-11-27-protocol-lenses-ux.md](2026-11-27-protocol-lenses-ux.md)

## 2. Allowed and forbidden paths

- Allowed writes: `frontend/src/protocols/lenses/<lens>/`, `fixtures/raw/protocols/<lens>/`, `docs/operators/protocol-<lens>.md`
- Forbidden: git; `npm run build`; `npm run package`; repo-wide `npm run format` (use scoped `npx prettier --write frontend/src/protocols/lenses/<lens>`); shared SDK; `registry.ts`; routing; nav; collections; Vite; `package.json`; other lenses

## 3. Grounding files and field allowlist

- **MANDATORY FIRST STEP:** Read the matching vendor extract in `research/extracted/` (e.g., `splunk-app-for-stream_816/splunk_app_stream/default/streams/<proto>`, `cisco-dc-networking-app-for-splunk_2010/`, etc.) AND `fixtures/raw/FIELDS.md` BEFORE writing any SPL field name, unit, or status code. Never guess field names or bitmasks when the TA extract is present.
- Lens `FIELDS.md`: `fixtures/raw/protocols/<lens>/FIELDS.md`
- Allowlist (never select outside `LENS_FIELD_ALLOWLISTS.<lens>` in `frontend/src/protocols/shared/fields.ts`; never project `_raw`, `src_content`, `dest_content`, `cookie`, `form_data`, `uri_query`, SQL `query`, `community`, `login`, `password`):
- Row-expansion fields only (if any):
- Config recheck testing note: In unit tests exercising `withProtocolConfigRecheck`, spy on `protocolConfigClient.readProtocolProfileDocument` from `../../../data/evidenceConfig` so no real `fetch` runs.
- Syslog-backed lenses MUST use `frontend/src/protocols/shared/adapters/nxosSyslog.ts` and document **SC4S (Splunk Connect for Syslog)** as the primary recommended collector in `docs/operators/protocol-<lens>.md`.
- **Standardized correctness & UX rules (from Wave 1 pilot):**
  - Put the profile validator in a tiny `validate.ts` (zero adapter/UI imports) so `registry.ts` stays small.
  - Pair/row IDs MUST match `ITEM_ID` (`^[A-Za-z0-9._:/-]{1,128}$`) — use `__` (e.g. `${src}__${dst}`), NEVER `->`.
  - Abort any in-flight search in `onScopeChange` and stamp every result with `{ scope, earliest, latest, filter }`; ignore results whose stamp does not match current props.
  - Pass `profileValidators` prop through to `withProtocolConfigRecheck` (falling back to `{ [lens]: validateExtra }`).
  - Always treat any `"blocked"` or `"unavailable"` outcome as degraded coverage (never `none_observed` when 0 events, and always `partial` with cause-specific banner reason when >0 events).
  - Emit `| head ${maxRows + 1}` BEFORE `buildAllowedFieldsClause` (`| table ...`) so indexers cap rows before sending to the search head and drop `_raw` server-side.
  - Keep state updaters pure (read current state from a ref instead of calling a second `setState` inside an updater).
  - Never mark a fallback-only row as `ok` when primary health metrics weren't collected — use `not_covered` with a reason, and show what the fallback source *does* collect (bytes, flows, ports) instead of repeating "Not covered".
  - `HeatMatrix`: pass `missingStatus={result.capped ? "unknown" : "none_observed"}` and show the top reason label in attention cells.
  - One metric per KPI tile with readable units (no combined `4.8% / 1 rst` tiles). Use `≥` (not `>=`) and keep thresholds in tooltips, not the verdict sentence.
  - Detail drawer: show Status chip first, Exceptions as `<ul className="pl-kv-list">`, individual `<CopyableIp>` controls, and a `literal()`-quoted `/app/splunk_adm/search?...` raw-events link.

## 4. Commands

```
npx prettier --write frontend/src/protocols/lenses/<lens>
npm run lint
npx vitest run frontend/src/protocols/lenses/<lens>
```

## 5. Handoff

- Changed paths
- Decisions
- Test results
- SDK requests
- Risks
- Fields not verified in a deployed feed
