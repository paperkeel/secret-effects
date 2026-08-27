# Source scope

Apply Semark to hand-authored `.ts`, `.tsx`, `.mts`, and `.cts` files. Include source
files, tests, build scripts, and TypeScript configuration files in this scope.

Exclude these files by default:

- declaration-only `.d.ts` files
- generated files with an approved generated-file marker
- vendored source that the repository does not maintain
- fixtures whose comments are test data

Permit more exclusions when the Semark configuration defines them. Require a stable path
rule and a concise reason for each exclusion.
