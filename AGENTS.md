# AGENTS.md

`secret-effects` is a public, MIT-licensed secret service for Paperkeel projects.

## Commands

- Install dependencies with `pnpm install`.
- Run all checks with `pnpm check`.
- Format files with `pnpm format`.
- Plan production infrastructure with `pnpm infra:plan`.
- Deploy production infrastructure with `pnpm run deploy`.

## Rules

- Never commit a credential, private key, secret value, environment file, or
  Alchemy state.
- Never log a credential, private key, decrypted bundle, or secret value.
- Never use Secret Effects to supply this repository's deployment or release secrets.
- Configure bootstrap secrets in GitHub and inject Worker secrets through Alchemy.
- Publish the npm client only from the canonical `paperkeel/secret-effects` repository.
- Treat each canonical `master` push as a complete production release.
- Increment every workspace package version before a canonical merge to
  `master`.
- Cache only encrypted bundles.
- Keep decrypted values in request-local memory.
- Use Effect v4 for application services and typed errors.
- Use Zod and `@t3-oss/env-core` for repository environment schemas.
- Use Alchemy v2 for all Cloudflare resources.
- Use Blacksmith runners for all build, test, deploy, and release finalization
  jobs.
- Use a GitHub-hosted runner only for the npm Trusted Publishing job. That job
  publishes the package artifact that Blacksmith built and tested.
- Use `master` as the default branch.
- Run `pnpm check` before each commit.

## Pull requests

- Wait for all CI and review checks.
- Fix failures that the pull request causes.
- Review and resolve valid CodeRabbit feedback.
- Add a comment that starts with `#AI-Automation` and lists automated fixes.

## Semark Protocol

Load `semark-protocol` before you add or change TypeScript comments. Do not add
or keep source comments except Semark file signatures, method signatures, and
approved directives. Update an affected signature in the same change as the
documented behavior.

### Validation

Run `pnpm semark:check` before you complete a change. The command runs
`scripts/check-semark.mjs`. `pnpm check` also runs Semark validation.

This repository does not use `@paperkeel/oxlint-plugin-semark`. Oxlint handles
general lint only.

### Scope

Apply Semark to top-level `.ts`, `.tsx`, `.mts`, and `.cts` files in the
repository root, and to all TypeScript files under `apps/` and `packages/`.
Declaration-only `.d.ts` files use the protocol default exclusion. TypeScript
files in other root subdirectories, such as `scripts/`, are outside scope.

### Audit output

Map `pnpm semark:check` violations to audit categories as follows:

| Checker label      | Audit category                                                                        |
| ------------------ | ------------------------------------------------------------------------------------- |
| `readme-coverage`  | `README_MISSING` or `README_NAME_INVALID`                                             |
| `file-signature`   | `FILE_SIGNATURE_MISSING`, `FILE_SIGNATURE_POSITION`, or `FILE_SIGNATURE_FORMAT`       |
| `method-signature` | `METHOD_SIGNATURE_MISSING`, `METHOD_SIGNATURE_POSITION`, or `METHOD_SIGNATURE_FORMAT` |
| `comment-policy`   | `COMMENT_UNAUTHORIZED` or `DIRECTIVE_INVALID`                                         |
