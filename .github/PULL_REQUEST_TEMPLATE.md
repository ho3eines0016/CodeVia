## Summary

<!-- One or two sentences: what does this change and why? Link the issue it closes. -->

## Verification

<!-- Check everything that applies. CI enforces the first four. -->

- [ ] `npm run typecheck` passes
- [ ] `npm run lint` passes
- [ ] `npm run format:check` passes
- [ ] `npm test` passes (add/extend tests for every behavior change)
- [ ] `npm run smoke` passes (required for HTTP route, queue, or repository-state changes)
- [ ] `scripts/audit-pipeline.mjs` / `scripts/audit-repository-state.mjs` still exit `0` (required when touching those paths)

## Notes for reviewers

- Does this change any access-control rule? If yes, which regression test pins it down?
- Does this change the `CodeVia/` file format or the restore/migration paths?
- Does it keep the fully offline mode (Mock AI/GitHub/Telegram) working?
- Any new dependency? `npm audit --omit=dev` must stay clean.
