# Secret Effects API

This application supplies the Secret Effects Cloudflare Worker API. It owns
request authentication, access control, credential records, schemas, encrypted
bundle storage, cache invalidation, and audit records.

The application accepts signed API requests and delegates cryptography and wire
schemas to workspace packages. It never decrypts a secret bundle.

The public health response includes the deployed commit. The release workflow
checks that commit before npm publication.

## Organization

- `src/index.ts` routes API requests and coordinates Cloudflare resources.
- `src/project-state.ts` serializes bundle publication for one project.
- `src/audit-log.ts` stores the global audit hash chain.
- `wrangler.jsonc` defines local Worker bindings.

Run the root `pnpm check` command to validate this application.
