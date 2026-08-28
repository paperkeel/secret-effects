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
- Treat each successful canonical `master` CI run as a complete production
  release.
- Increment every workspace package version before a canonical merge to
  `master`.
- Cache only encrypted bundles.
- Keep decrypted values in request-local memory.
- Use Effect v4 for application services and typed errors.
- Use Zod and `@t3-oss/env-core` for repository environment schemas.
- Use Alchemy v2 for all Cloudflare resources.
- Use Blacksmith runners for all GitHub Actions jobs.
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
documented behavior. All applicable TypeScript files in the root, `apps/*`, and
`packages/*` comply. Declaration-only `.d.ts` files use the protocol default
exclusion. Run `pnpm semark:check` before you complete a change.
