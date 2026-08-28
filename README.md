# Secret Effects

## About

Secret Effects is an API-only secret service for applications and coding agents.
It stores complete environment bundles as encrypted data on Cloudflare. The
service cannot decrypt those bundles because each client keeps its private key.

Each runtime needs one `SECRET_EFFECTS_KEY`. That credential contains the
service URL, project scope, environment scope, and decryption key. Application
repositories define their secret schema with Zod and `@t3-oss/env-core`.

Secret Effects uses Effect v4, Alchemy v2, Workers, D1, R2, Durable Objects, and
Queues. The project is API-only, open source, and available under the
[MIT license](LICENSE).

The setup has two stages. First, deploy your own service instance. Then migrate
each application repository to that instance.

## Agent prompt 1: Deploy your instance

Use this prompt with an agent that can access GitHub and your Cloudflare
account. Replace the values in angle brackets before you start.

> Deploy a private Secret Effects instance for me from
> `https://github.com/paperkeel/secret-effects`.
>
> Use `<GITHUB_OWNER>/<PRIVATE_REPOSITORY>` for the deployment repository. Keep
> that repository private by default. If GitHub cannot make a fork of the public
> repository private, create a duplicate instead. Keep the duplicate private
> when possible. If GitHub cannot make the duplicate private, make it public.
> Preserve the commit history, license, and attribution. Add the public
> repository as the `upstream` remote.
>
> Read `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, and
> `docs/OPERATIONS.md` before you change anything. Use Node.js 24, pnpm, Alchemy
> v2, Cloudflare, and the existing Blacksmith GitHub Actions workflows. Do not
> replace the architecture or add a web interface.
>
> Inspect my Cloudflare account before deployment. Reuse the default resource
> names only when they cannot conflict with another instance. Otherwise, select
> one stable instance name and apply it to every Cloudflare resource. Keep
> production retain protection and resource adoption.
>
> Create a Cloudflare API token for the target account. Give the token only these
> account permissions:
>
> - `Account / Workers Scripts / Edit`
> - `Account / D1 / Edit`
> - `Account / Workers R2 Storage / Edit`
> - `Account / Queues / Edit`
> - `Account / Account Settings / Read`
>
> Do not give the token zone permissions. The deployment uses its `workers.dev`
> origin and does not create a route or custom domain.
>
> Generate the issuer key as 32 random bytes in lowercase hexadecimal. Generate
> the global admin token with at least 32 random bytes. Use the global admin
> token only to authorize the first bootstrap request. Never print, commit, or
> place either value in a pull request. Store all deployment credentials in the
> deployment repository's protected `production` environment.
>
> Configure these production secrets:
>
> - `CLOUDFLARE_ACCOUNT_ID`
> - `CLOUDFLARE_API_TOKEN`
> - `SECRET_EFFECTS_ISSUER_PRIVATE_KEY`
> - `SECRET_EFFECTS_GLOBAL_ADMIN_TOKEN`
>
> Configure `SECRET_EFFECTS_API_URL` as a production environment variable. Use
> the final HTTPS Worker origin. Configure the protected `release` environment
> only if I ask you to publish releases from the private repository.
>
> Ask me if I want Sentry error monitoring. If I enable it, create or select one
> Sentry JavaScript project. Store its DSN as the optional `SENTRY_DSN`
> production secret. Do not add `SENTRY_ORG`, `SENTRY_PROJECT`, or
> `SENTRY_AUTH_TOKEN`. This deployment does not upload source maps.
>
> Run `pnpm install --frozen-lockfile`, `pnpm check`, `pnpm build`, and
> `pnpm infra:plan`. Make all required instance-name or deployment changes in a
> pull request. Wait for the required checks, merge the pull request, and let
> the `master` deployment workflow deploy the successful commit.
>
> Check the production `/health` endpoint. Then build the `secreteffects`
> command interface. Set `SECRET_EFFECTS_GLOBAL_ADMIN_TOKEN` for the process and
> call the bootstrap endpoint exactly once. Write the resulting Global
> credential to a new file with mode `0600`. Move it to the secure offline
> location `<GLOBAL_CREDENTIAL_PATH>`. Never configure the Global credential in
> CI or an application runtime.
>
> Use the Global credential to create one CI/CD credential and one Agent
> credential. Store them only in the approved credential locations that I give
> you. The Agent credential has management inspection access and no secret read
> access. Do not use it as a runtime credential.
>
> Confirm that deployment, authentication, credential inspection, and the health
> check succeed. Give me the private repository URL, API URL, deployed commit,
> resource names, credential file locations, and check results. Never include a
> credential value in your response.

## Agent prompt 2: Migrate an application

Use this prompt after the first prompt completes. Give the agent access to the
application repository, the `secreteffects` command, and the CI/CD credential.

> Migrate `<APPLICATION_REPOSITORY>` to my Secret Effects instance at
> `<SECRET_EFFECTS_API_URL>`. Treat this as an application change, not a service
> redesign. Read the application repository's agent instructions before you edit
> files.
>
> Inspect the application, its deployment targets, and its current secret
> providers. Identify every environment variable, its type, its validation rule,
> and each environment that needs it. Find existing values through authorized
> local or provider commands. Never print, log, commit, or place a secret value
> in a pull request. Do not invent unavailable values for an application that
> has no deployment.
>
> Use the CI/CD credential to create one Secret Effects project with a stable
> alphanumeric name. The service creates `local`, `dev`, and `production`.
> Create each additional environment that the repository uses. Do not delete or
> rename an environment.
>
> Use the CI/CD credential to issue one Project credential. Save the credential
> with mode `0600`. Do not commit it or configure it in an application runtime.
>
> Add a repository-owned Secret Effects configuration. Define every secret with
> Zod and `@t3-oss/env-core`. Define accurate required environments. Use
> explicit mirrors when one environment must use another environment's value.
> Keep public configuration outside Secret Effects.
>
> Use compatible, version-pinned `@secret-effects/config` and
> `@secret-effects/client` packages. Prefer their public package releases. If no
> release exists, use a reproducible package artifact from the exact Secret
> Effects commit. Do not depend on a moving Git branch.
>
> Generate the public schema manifest from the repository configuration. Publish
> the manifest with the Project credential. Create one Environment credential
> for each runtime environment in use. Save each private credential with mode
> `0600`, and create its public recipient descriptor.
>
> Validate and publish one complete encrypted bundle for each environment that
> has known values. Use the Project credential for publication and the matching
> public Environment descriptor as its recipient. Do not upload a placeholder as
> a real secret. Report missing values by name and environment only.
>
> Replace the application's old environment loader with `loadEnv(config)`. Keep
> type inference at the application boundary. Configure only the matching
> `SECRET_EFFECTS_KEY` Environment credential in each runtime. Remove old secret
> injections only after the new runtime reads and validates its complete bundle.
>
> Test local reads without exposing values. Run the repository's complete check
> suite. Open a pull request with the required migration changes, but no secret
> values or private credential files. Deploy each existing target after the pull
> request passes and merges. Check its health and main secret-dependent path.
>
> Give me the pull request, deployed commit, migrated environments, configured
> runtime targets, removed legacy integrations, missing secret names, and check
> results. Never include secret values or credential values in your response.

## Repository map

| Path                | Purpose                                                  |
| ------------------- | -------------------------------------------------------- |
| `apps/api`          | Cloudflare Worker API and Durable Objects                |
| `apps/cli`          | `secreteffects` command interface and terminal interface |
| `packages/protocol` | API schemas and shared names                             |
| `packages/crypto`   | Credentials, signatures, and bundle encryption           |
| `packages/config`   | Repository-owned Zod configuration                       |
| `packages/client`   | Whole-environment runtime reader                         |
| `migrations`        | D1 migrations                                            |
| `alchemy.run.ts`    | Cloudflare infrastructure                                |

The applications use the workspace packages for protocol, cryptography,
configuration, and runtime loading. The API stores credential records, audit
records, and encrypted bundles. It never decrypts bundle contents.

## Development

Use Node.js 22.19.0 or later and pnpm 10.33.4.

```sh
pnpm install
pnpm semark:check
pnpm check
pnpm build
pnpm wrangler:types
```

For implementation details, read [Architecture](docs/ARCHITECTURE.md),
[Security](docs/SECURITY.md), and [Operations](docs/OPERATIONS.md).
