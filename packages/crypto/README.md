# Secret Effects Cryptography

This package implements credential encoding, key derivation, request signatures,
and encrypted bundle envelopes. It validates signed credential and bundle data
before it returns trusted values.

The package accepts protocol types and uses Web Crypto with Noble primitives. It
does not persist keys, credentials, decrypted bundles, or secret values.

The public API is in `src/index.ts`. Run the root `pnpm check` command to
validate the package and its tests.
