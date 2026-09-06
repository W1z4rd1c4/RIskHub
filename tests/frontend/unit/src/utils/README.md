# Frontend utility tests

Unit tests for shared frontend utilities in `frontend/src/utils`.

## Coverage

- `userSettingsStorage.intent.test.ts` verifies that late server preference
  hydration cannot overwrite a newer user choice of theme or language.

Run this test from `frontend/` with:

```sh
npm run test:run -- ../tests/frontend/unit/src/utils/userSettingsStorage.intent.test.ts
```
