# Secret Effects Configuration

This package defines repository secret configuration. It validates project and
environment names, resolves environment mirrors, builds Zod schemas, and creates
stable schema manifests and digests.

The package does not read credentials, contact the API, or encrypt secret
values. The client and command applications consume its public API from
`src/index.ts`.

Run the root `pnpm check` command to validate the package and its tests.
