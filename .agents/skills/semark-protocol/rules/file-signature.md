# File signatures

Add one file signature to the start of each applicable file. Put it after an approved
shebang, license header, generated marker, or triple-slash directive. Put it before
imports, exports, declarations, and executable statements.

Use this exact structure:

```ts
/**
 * Creates and persists authenticated sessions.
 *
 * @remarks
 * Responsibility: Owns session construction and persistence.
 *
 * Boundary: Accepts verified identities and does not verify credentials.
 */
```

State the file purpose in the first sentence. State owned behavior in the
`Responsibility:` paragraph. State ownership limits and relevant relationships in the
`Boundary:` paragraph.

Apply these limits:

- Keep the purpose to one sentence and at most 25 words.
- Keep each required paragraph to two sentences and 50 words at most.
- Keep the complete signature to 120 words at most.
- Describe one responsibility or boundary in each statement.

Do not list imports or exports. Do not include implementation steps, change history,
temporary notes, speculation, or unrelated behavior.
Do not use `@semarkFile` in a source comment.
