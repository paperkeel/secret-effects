# Secret Effects

Secret Effects is an agent-first service for fast, central secret management.
It has an API, a command interface, and no web interface.

The service stores only encrypted environment bundles. Clients hold all bundle
decryption keys. Each deployed environment needs one `SECRET_EFFECTS_KEY` value.
That value includes its service URL, signed scope, identity, and private key.

This repository is public under the MIT license. It has no dependency on
Infisical or the former Bearfire Infisical control plane.

## Current scope

- Effect v4 service code and typed errors
- Alchemy v2 Cloudflare infrastructure
- D1 control metadata
- one SQLite Durable Object for each project's write serialization
- one SQLite Durable Object for the audit hash chain
- R2 encrypted bundle storage
- a five-minute Cloudflare cache for encrypted bundles only
- Queue retries for failed cache purges
- Zod and `@t3-oss/env-core` runtime validation
- OpenTUI React command interface
- noninteractive `secreteffects` commands

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

## Development

Use Node.js 24 or later and pnpm 10.33.4.

```sh
pnpm install
pnpm check
pnpm build
pnpm wrangler:types
```

Apply the local D1 migration before local API tests.

```sh
pnpm exec wrangler d1 migrations apply secret-effects-catalog-local \
  --local --config apps/api/wrangler.jsonc
```

Start the local Worker with development-only values.

```sh
pnpm exec wrangler dev --local --config apps/api/wrangler.jsonc \
  --var ISSUER_PRIVATE_KEY:<64-hex-characters> \
  --var BOOTSTRAP_TOKEN:<development-token>
```

## Repository configuration

Each application owns its secret names, Zod rules, environments, and mirrors.

```ts
import { z } from "zod";
import { defineConfig, secret } from "@secret-effects/config";

export default defineConfig({
	project: "example",
	environments: ["preview"],
	secrets: {
		API_URL: secret(z.url(), {
			mirror: { local: "dev" },
		}),
		API_TOKEN: secret(z.string().min(32), {
			requiredIn: ["dev", "production"],
		}),
	},
});
```

The configuration always includes `local`, `dev`, and `production`. An
application can add any number of environments. It cannot remove the defaults.

The publisher resolves mirrors before encryption. The read path always fetches
one complete, materialized environment.

See [Architecture](docs/ARCHITECTURE.md), [Security](docs/SECURITY.md), and
[Operations](docs/OPERATIONS.md).
