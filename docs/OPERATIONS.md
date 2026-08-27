# Operations

## Infrastructure inputs

Production deployment needs these values:

| Name                                | Purpose                                |
| ----------------------------------- | -------------------------------------- |
| `CLOUDFLARE_ACCOUNT_ID`             | Selects the Cloudflare account         |
| `CLOUDFLARE_API_TOKEN`              | Manages the Alchemy resources          |
| `SECRET_EFFECTS_ISSUER_PRIVATE_KEY` | Signs credential descriptors           |
| `SECRET_EFFECTS_GLOBAL_ADMIN_TOKEN` | Authorizes the first Global credential |
| `SECRET_EFFECTS_API_URL`            | Pins the signed production API origin  |
| `SENTRY_DSN`                        | Enables optional Sentry error reports  |

Generate the issuer key as 32 random bytes and lowercase hexadecimal. Generate
the global admin token with at least 32 random bytes. Store both as GitHub
production environment secrets. Use the global admin token only for bootstrap.

Store `SECRET_EFFECTS_API_URL` as a GitHub production environment variable.
The URL must use HTTPS. Store `SENTRY_DSN` as a production environment secret
only when the deployment uses Sentry.

Create the Cloudflare API token with these account permissions:

- `Account / Workers Scripts / Edit`
- `Account / D1 / Edit`
- `Account / Workers R2 Storage / Edit`
- `Account / Queues / Edit`
- `Account / Account Settings / Read`

Limit the token to the target account. Do not add zone permissions. The default
deployment uses a `workers.dev` origin.

The Sentry runtime integration needs only `SENTRY_DSN`. Sentry organization and
project slugs apply to source-map uploads. This deployment does not upload
source maps and does not need `SENTRY_ORG`, `SENTRY_PROJECT`, or
`SENTRY_AUTH_TOKEN`.

## Deploy

```sh
pnpm install --frozen-lockfile
pnpm check
pnpm infra:plan
pnpm run deploy
```

Alchemy owns D1, R2, Queue, Worker, cache, and Durable Object bindings. Production
resources use retain protection and adopt existing named resources.

In the canonical repository, each successful `master` CI run is a complete
release. The release workflow checks and builds the exact commit. It deploys the
commit, checks the commit from `/health`, publishes the matching npm package,
creates a signed version tag, and creates the GitHub release.

Increment the root, API, command interface, client, cryptography, and protocol
versions before each canonical merge. The workflow rejects a version that
belongs to a different commit. GitHub queues up to 100 release runs and does not
replace an earlier pending `master` release.

## Bootstrap

Build the command interface first.

```sh
pnpm build
```

Set the global admin token. Send the only bootstrap request.

```sh
umask 077
SECRET_EFFECTS_GLOBAL_ADMIN_TOKEN='<token>' \
  node apps/cli/dist/secreteffects.js bootstrap \
  --api https://<worker-host> > global.secret-effects-key
chmod 600 global.secret-effects-key
```

Move the resulting Global credential to durable offline storage. Do not commit
the file. Do not configure the Global credential in CI.

The service rejects bootstrap after five rejected attempts per minute per
deployment. This limit slows token guessing. It does not remove the need for a
strong global admin token.

## Rotate the Global credential

A Global credential can revoke any credential type, including itself. To rotate
the Global credential:

1. Revoke the current Global credential with the Global credential itself.
2. Run the bootstrap command again with the global admin token.
3. Store the new Global credential in durable offline storage.

The global admin token authorizes each bootstrap. Keep the token available in
the production environment.

## Create a project

```sh
export SECRET_EFFECTS_KEY='<global-or-cicd-credential>'
node apps/cli/dist/secreteffects.js project create \
  --name example --display-name "Example"
node apps/cli/dist/secreteffects.js key issue \
  --type project --project example
```

The create operation also creates `local`, `dev`, and `production`.

## Register a schema

Application code creates a manifest with `schemaManifest(config)`. Save that
public manifest as JSON. A Project credential can register it.

```sh
export SECRET_EFFECTS_KEY='<project-credential>'
node apps/cli/dist/secreteffects.js schema publish \
  --project example --manifest schema.json
```

## Publish an environment

Create an Environment credential for each runtime. Provide its credential file
as a publication recipient.

```sh
umask 077
node apps/cli/dist/secreteffects.js key issue \
  --type environment \
  --project example \
  --environment production > production.secret-effects-key
chmod 600 production.secret-effects-key

SECRET_EFFECTS_KEY="$(<production.secret-effects-key)" \
  node apps/cli/dist/secreteffects.js key public \
  > production.public-credential.json

node apps/cli/dist/secreteffects.js bundle publish \
  --environment production \
  --values production.values.json \
  --schema-digest <schema-digest> \
  --recipient production.public-credential.json
```

The publication process receives only a signed public descriptor. It does not
receive the Environment credential master key. Delete the plaintext values file
after publication. Prefer a process-managed temporary file for automation.

## Bootstrap secret boundary

Secret Effects does not load its own deployment or release secrets. Configure
these values manually in GitHub:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_API_TOKEN`
- `SECRET_EFFECTS_ISSUER_PRIVATE_KEY`
- `SECRET_EFFECTS_GLOBAL_ADMIN_TOKEN`
- `SENTRY_DSN`, when Sentry is active
- `NPM_TOKEN`, only in the canonical Paperkeel release environment
- `RELEASE_SIGNING_PRIVATE_KEY`, only in the canonical Paperkeel release
  environment

Configure `SECRET_EFFECTS_API_URL` as a GitHub environment variable. The deploy
workflow gives the values to Alchemy. Alchemy injects only the required Worker
bindings into Cloudflare. Do not configure `SECRET_EFFECTS_KEY` for this
repository.

Forks and deployment copies do not publish the client package or create
Paperkeel release tags. Their release workflow deploys the successful `master`
commit and skips the canonical publication job. Applications install the
canonical public package from Paperkeel.

## Runtime use

Configure only one environment value in the runtime:

```text
SECRET_EFFECTS_KEY=<environment-credential>
```

Install `@paperkeel/secret-effects-client`. Import `defineEnv`, `secret`,
`loadEnv`, and `z` from that package. Call `loadEnv(config)` in the request or
operation that needs the values. The client obtains the service URL and scope
from the credential. It does not cache the decrypted result.

## Revoke a credential

```sh
node apps/cli/dist/secreteffects.js key revoke \
  --id <credential-identifier> \
  --reason "Replaced during scheduled rotation"
```

Use a Global or CI/CD credential for broad revocation. A Project credential can
revoke only Environment credentials in its project.

## Inspect and purge

```sh
node apps/cli/dist/secreteffects.js project list
node apps/cli/dist/secreteffects.js environment list --project example
node apps/cli/dist/secreteffects.js key list
node apps/cli/dist/secreteffects.js schema list --project example
node apps/cli/dist/secreteffects.js audit list --project example
node apps/cli/dist/secreteffects.js cache purge \
  --project example --environment production
```

Inspection commands return JSON. They never return private keys or decrypted
values. `environment read` is the explicit exception for authorized local use.
