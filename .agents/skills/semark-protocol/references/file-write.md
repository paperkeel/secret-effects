# Write a file signature

Use this workflow to write or update a file signature. Before the edit, read these rule modules:

- [source-scope.md](../rules/source-scope.md)
- [comments.md](../rules/comments.md)
- [file-signature.md](../rules/file-signature.md)
- [accuracy.md](../rules/accuracy.md)

Treat their formats and limits as requirements.

## Inspect the file

1. Read the package `README.md`.
2. Identify the file purpose, owned responsibility, boundary, and relationships.

## Write the signature

Use the filename, exports, types, callers, and tests as evidence. Do not infer
responsibility that the implementation does not own.

State why the file exists in the purpose. State the behavior that the file owns in the
responsibility.
State what the file accepts, delegates, or does not own in the boundary.

Do not list symbols or describe control flow. Omit facts that the filename and types
make fully clear.
