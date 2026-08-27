# Approved source comments

Permit only these comment forms in an applicable source file:

1. A file signature.
2. A method signature.
3. A recognized compiler, tooling, license, or generated-code directive.

Do not use narrative implementation comments, commented-out code, informal TODO notes,
scratch notes, history, speculation, duplicated documentation, or arbitrary comments.
Track pending work in the repository issue system.

Permit these directive categories:

- TypeScript directives such as `@ts-expect-error` and `@ts-ignore`
- lint directives with the exact syntax of the linter
- coverage directives for the configured coverage tool
- formatter directives with the exact syntax of the formatter
- license headers
- generated-file markers
- TypeScript triple-slash directives

Use recognizable tool syntax for each directive. Add only the explanation that the tool
requires. Do not use a directive as general documentation.
