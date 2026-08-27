# Secret Effects Protocol

This package defines shared wire schemas, constants, names, cache keys, and
canonical JSON encoding for Secret Effects clients and services.

The package validates protocol data but does not authenticate requests, persist
records, or encrypt bundles. All other workspaces depend on this package for
shared boundaries.

The public API is in `src/index.ts`. Run the root `pnpm check` command to
validate the package and its tests.
