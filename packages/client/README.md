# Secret Effects Client

This package supplies the runtime environment reader. It authenticates one
bundle request, validates the bundle scope and schema digest, decrypts the
bundle, and validates the resulting environment.

The package accepts a repository configuration and an Environment or Project
credential. It delegates configuration rules, cryptography, and wire schemas to
workspace packages.

The public API is in `src/index.ts`. Run the root `pnpm check` command to
validate the package.
