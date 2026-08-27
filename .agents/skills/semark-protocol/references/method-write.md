# Write a method signature

Use this workflow to write or update a method signature. Before the edit, read these rule modules:

- [source-scope.md](../rules/source-scope.md)
- [comments.md](../rules/comments.md)
- [method-signature.md](../rules/method-signature.md)
- [accuracy.md](../rules/accuracy.md)

Treat their formats and limits as requirements.

## Inspect the callable

1. Read the enclosing file signature.
2. Identify the behavior, inputs, results, side effects, failures, invariants, and limits.

## Write the signature

Document only behavior that matters across the callable boundary. Treat the TypeScript
declaration as the structural authority.

Use parameter descriptions to explain meaning or constraints. Do not repeat a parameter
name without new information.

Use `@throws` only for an intentional failure category that can cross the boundary. Omit
converted or contained internal exceptions.

Use remarks labels only for non-obvious behavior. Omit empty labels and tags.
