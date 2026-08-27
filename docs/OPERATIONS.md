# Operations

## Infrastructure inputs

Production deployment needs these values:

| Name                                | Purpose                                |
| ----------------------------------- | -------------------------------------- |
| `CLOUDFLARE_ACCOUNT_ID`             | Selects the Cloudflare account         |
| `CLOUDFLARE_API_TOKEN`              | Manages the Alchemy resources          |
| `SECRET_EFFECTS_ISSUER_PRIVATE_KEY` | Signs credential descriptors           |
| `SECRET_EFFECTS_BOOTSTRAP_TOKEN`    | Authorizes the first Global credential |

Generate the issuer key as 32 random bytes and lowercase hexadecimal. Generate
the bootstrap token with at least 32 random bytes. Store both as GitHub
production environment secrets.

## Deploy

```sh
pnpm install --frozen-lockfile
pnpm check
pnpm infra:plan
pnpm deploy
```

Alchemy owns D1, R2, Queue, Worker, cache, and Durable Object bindings. Production
resources use retain protection and adopt existing named resources.

## Bootstrap

Build the command interface first.

```sh
pnpm build
```

Set the temporary bootstrap token. Send the only bootstrap request.

```sh
SECRET_EFFECTS_BOOTSTRAP_TOKEN='<token>' \
  node apps/cli/dist/secreteffects.js bootstrap \
  --api https://<worker-host> > global.secret-effects-key
chmod 600 global.secret-effects-key
```

Move the resulting Global credential to durable offline storage. Do not commit
the file. Do not configure the Global credential in CI.

## Create a project

```sh
export SECRET_EFFECTS_KEY='<global-or-cicd-credential>'
secreteffects project create --name example --display-name "Example"
secreteffects key issue --type project --project example
```

The create operation also creates `local`, `dev`, and `production`.

## Register a schema

Application code creates a manifest with `schemaManifest(config)`. Save that
public manifest as JSON. A Project credential can register it.

```sh
export SECRET_EFFECTS_KEY='<project-credential>'
secreteffects schema publish --project example --manifest schema.json
```

## Publish an environment

Create an Environment credential for each runtime. Provide its credential file
as a publication recipient.

```sh
secreteffects key issue \
  --type environment \
  --project example \
  --environment production > production.secret-effects-key

secreteffects bundle publish \
  --environment production \
  --values production.values.json \
  --schema-digest <schema-digest> \
  --recipient production.secret-effects-key
```

Delete the plaintext values file after the publication procedure. Prefer a
process-managed temporary file for automation.

## Runtime use

Configure only one environment value in the runtime:

```text
SECRET_EFFECTS_KEY=<environment-credential>
```

Call `loadEnv(config)` from `@secret-effects/client`. The client obtains the
service URL and scope from the credential.

## Revoke a credential

```sh
secreteffects key revoke \
  --id <credential-identifier> \
  --reason "Replaced during scheduled rotation"
```

Use a Global or CI/CD credential for broad revocation. A Project credential can
revoke only Environment credentials in its project.

## Inspect and purge

```sh
secreteffects project list
secreteffects environment list --project example
secreteffects key list
secreteffects schema list --project example
secreteffects audit list --project example
secreteffects cache purge --project example --environment production
```

Inspection commands return JSON. They never return private keys or decrypted
values. `environment read` is the explicit exception for authorized local use.
