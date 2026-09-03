# Source scope

Apply Semark to hand-authored `.ts`, `.tsx`, `.mts`, and `.cts` files in the
configured source roots.

Default source roots:

- repository root, non-recursive: only top-level TypeScript files
- `apps/**`, recursive
- `packages/**`, recursive

Files in other directories, such as `scripts/`, are out of scope unless the
repository configuration extends the roots.

Exclude these files by default:

- declaration-only `.d.ts` files
- generated files with an approved generated-file marker
- vendored source that the repository does not maintain
- fixtures whose comments are test data

Permit more exclusions when the Semark configuration defines them. Require a stable path
rule and a concise reason for each exclusion.
