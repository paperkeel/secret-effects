---
name: semark-protocol
description: Use when a TypeScript repository task requires Semark Protocol. Apply it to installation, configuration, compliance audits, signatures, or protocol questions.
---

# Semark Protocol

Use this skill for all Semark Protocol work. Select each workflow that applies to the
request. Treat the modules in `rules/` as the source of truth.

## Select a workflow


| Request                                     | Read                                                     |
| ------------------------------------------- | -------------------------------------------------------- |
| Install or configure Semark                 | [references/install.md](references/install.md)           |
| Audit compliance or report findings         | [references/audit.md](references/audit.md)               |
| Write or update a file signature            | [references/file-write.md](references/file-write.md)     |
| Write or update method signatures           | [references/method-write.md](references/method-write.md) |
| Answer a Semark rule or compliance question | The matching rule module below                           |


Read each selected workflow completely. For each workflow, also read
[rules/writing.md](rules/writing.md) and [rules/validation.md](rules/validation.md).
Then read the additional rule modules that the workflow identifies.

If the request contains multiple operations, read each shared module one time. Do not read unrelated workflows or rules.

## Obey these shared instructions

- Obey the injected repository instructions.
- Inspect a nearer `AGENTS.md` or `AGENTS.override.md` when the target is below the current directory.
- Start with the smallest relevant context.
- Inspect related code only when you must resolve an uncertainty.
- Treat the source code and configuration as the implementation authority.
- Do not infer unsupported behavior.
- Do not change source behavior unless the user requests the change.
- Run the configured Semark check when it exists.
- After an edit, run the focused repository checks.
- Correct violations that the edit causes.
- Report the scope, changes or findings, check results, and unresolved work outside the requested scope.

## Change a signature

For a file or method signature:

1. Read the complete implementation that the signature documents.
2. Inspect related types, callers, and tests only when the documented boundary is unclear.
3. Derive each statement from implementation evidence.
4. Write or update one signature.
5. Remove unauthorized comments from the changed area.
6. Preserve approved directives, decorators, and their required positions.

If a signature conflicts with the implementation, update the signature. Report the mismatch.
Also report the target and the behavior or boundary that the signature records.

## Select a rule module


| Module                                                   | Use                                            |
| -------------------------------------------------------- | ---------------------------------------------- |
| [rules/purpose.md](rules/purpose.md)                     | Apply Semark principles and requirements.      |
| [rules/discovery.md](rules/discovery.md)                 | Use the discovery hierarchy and workflow.      |
| [rules/readme-boundaries.md](rules/readme-boundaries.md) | Set `AGENTS.md`, README, and skill boundaries. |
| [rules/naming.md](rules/naming.md)                       | Apply the naming protocol.                     |
| [rules/source-scope.md](rules/source-scope.md)           | Select applicable files and exclusions.        |
| [rules/comments.md](rules/comments.md)                   | Classify source comments and directives.       |
| [rules/file-signature.md](rules/file-signature.md)       | Apply the file-signature format and limits.    |
| [rules/method-signature.md](rules/method-signature.md)   | Apply the method-signature format and limits.  |
| [rules/writing.md](rules/writing.md)                     | Apply the Semark writing rules.                |
| [rules/accuracy.md](rules/accuracy.md)                   | Keep signatures accurate.                      |
| [rules/validation.md](rules/validation.md)               | Apply the validation requirements.             |
