# Protocol worker brief template

The orchestrator fills one brief per lens. Workers do not expand the brief or delegate.

## 1. Outcome and acceptance criteria

- Lens id:
- Views (Overview, Matrix, drawer):
- Flags:
- UX checklist: [docs/superpowers/specs/2026-11-27-protocol-lenses-ux.md](2026-11-27-protocol-lenses-ux.md)

## 2. Allowed and forbidden paths

- Allowed writes: `frontend/src/protocols/<lens>/`, `fixtures/protocols/<lens>/`, `docs/operators/protocol-<lens>.md`
- Forbidden: git; `npm run build`; `npm run package`; shared SDK; routing; nav; collections; Vite; `package.json`; other lenses

## 3. Grounding files and field allowlist

- Vendor extracts:
- Lens `FIELDS.md`:
- Allowlist (never select outside it):
- Row-expansion fields only (if any):

## 4. Commands

```
npm run lint
npx vitest run frontend/src/protocols/<lens>
```

## 5. Handoff

- Changed paths
- Decisions
- Test results
- SDK requests
- Risks
- Fields not verified in a deployed feed
