# Secret Effects Client

`@paperkeel/secret-effects-client` is the application package for Secret
Effects. It combines these functions:

- Zod schema definition
- T3 Env validation and type inference
- Signed bundle retrieval
- Bundle scope and schema checks
- Secret decryption
- Node.js environment and Cloudflare Worker binding support

Install only this package:

```sh
pnpm add @paperkeel/secret-effects-client@0.2.1
```

Paperkeel publishes this package from the canonical Secret Effects repository.
Forks and deployment copies do not publish another package.

## Define an environment

Use a plain Zod schema for a platform value. Use `secret()` for a value that
Secret Effects supplies.

```ts
import {
	defineEnv,
	loadEnv,
	secret,
	z,
} from "@paperkeel/secret-effects-client";

const config = defineEnv({
	project: "example",

	server: {
		DATABASE_URL: secret(z.url()),
		PORT: z.coerce.number().int().positive(),
	},

	clientPrefix: "PUBLIC_",
	client: {
		PUBLIC_APP_NAME: z.string().min(1),
	},

	shared: {
		NODE_ENV: z.enum(["development", "production", "test"]),
	},
});

export async function environmentForRequest() {
	return loadEnv(config);
}
```

The result contains the inferred output types from all schemas. The result does
not contain `SECRET_EFFECTS_KEY`.

## Use Cloudflare Worker bindings

Pass the Worker binding object for each request. The client ignores nonprimitive
bindings such as D1 databases and service bindings.

```ts
export default {
	async fetch(request: Request, bindings: Env): Promise<Response> {
		const env = await loadEnv(config, { runtimeEnv: bindings });
		return handleRequest(request, env);
	},
};
```

Configure only the matching Environment credential as the
`SECRET_EFFECTS_KEY` platform secret. A Project credential also requires the
`environment` load option.

## Source rules

A plain server, client, or shared schema reads a platform value. A schema inside
`secret()` reads a Secret Effects value. The client rejects a nonempty platform
value when `secret()` owns the same name.

This rule prevents silent source precedence.

The client fetches and decrypts a new bundle for each call. It does not cache a
decrypted result. Keep the returned object in the request or operation that
needs it.

Before each bundle request, the client reads the service well-known record. It
uses that record to check the credential issuer key and API origin.

Each request has a 10-second deadline. Set `timeoutMs` in the `loadEnv` options
when an application needs a shorter deadline.

## Errors

`loadEnv()` rejects with `SecretEffectsClientError`. Its `code` is one of these
stable categories:

- `CREDENTIAL`
- `DECRYPTION`
- `INTERNAL`
- `REQUEST`
- `RESPONSE`
- `SCOPE`
- `SOURCE_CONFLICT`
- `VALIDATION`

Error messages can contain variable names. They do not contain credentials,
response bodies, or decrypted values.
