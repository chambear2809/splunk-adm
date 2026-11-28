# Ecosystem worker brief template

The Distinguished Engineer (root Orchestrator) fills one brief per non-lens network ecosystem capability. Workers do not expand the brief or delegate.

## 1. Outcome and acceptance criteria

- Capability / source id:
- Target Atlas surface (Path Trace, Blast Radius Impact, Segmentation Policy, Ecosystem panel, or Data Adapter):
- Contracts & guardrails: `docs/SUPPLEMENTAL_EVIDENCE_CONTRACT.md`, `docs/ECOSYSTEM_TRAFFIC_EVIDENCE_DESIGN.md`

## 2. Allowed and forbidden paths

- Allowed writes: only the brief-assigned module directory (e.g. `frontend/src/trace/<source>/`), `fixtures/<source>/` (including `FIELDS.md`), `tests/splunk/test_<source>.py`, and `docs/operators/<guide>.md`
- Forbidden: git; `npm run build`; `npm run package`; repo-wide `npm run lint` or `npm run format`; `frontend/src/protocols/shared/`; `frontend/src/data/evidence.ts`; `macros.conf`; `collections.conf`; `transforms.conf`; `savedsearches.conf`; `metadata/default.meta`; `registry.ts`; `config/deployment-health.json`; `evidenceConfig.ts`; `setupClient.ts`; `tools/*`; `tests/browser/*`; Vite configs; `package.json`; executing vendor scripts under `research/extracted/`.

## 3. Grounding and privacy

- Read the matching static vendor extract in `research/extracted/` (when present) OR pin primary-source vendor/collector documentation versions and URLs in `fixtures/<source>/FIELDS.md`.
- Never project `_raw`, credentials, tokens, cookies, SQL query text, SNMP communities/varbinds, sFlow `http_url`/`src_user`/`dest_user`, or user identifiers outside explicit single-row expansion.
- Never sum flow counts across distinct sensors or promote inventory/configured policy into observed packet traversal.

## 4. Scoped validation commands

```sh
npx prettier --write <allowed-ts-dir>
npx eslint <allowed-ts-dir>
npx vitest run <allowed-ts-dir>
ruff check <allowed-py-test>
```

## 5. Handoff

- Changed paths
- Decisions
- Test results
- Proposed Orchestrator integration patches (macros, `setupClient.ts`, `registry.ts`, `collections.conf`, `deployment-health.json`)
- Risks and fields not verified in a deployed feed
