# Install or configure Semark

Use this workflow to install or configure Semark in a target repository. Before the
change, read these rule modules:

- [purpose.md](../rules/purpose.md)
- [discovery.md](../rules/discovery.md)
- [readme-boundaries.md](../rules/readme-boundaries.md)
- [source-scope.md](../rules/source-scope.md)
- [comments.md](../rules/comments.md)
- [file-signature.md](../rules/file-signature.md)
- [method-signature.md](../rules/method-signature.md)
- [accuracy.md](../rules/accuracy.md)

Treat their definitions and formats as requirements.

## Keep the authorized scope

Install Semark only in the repositories or packages that the user includes. Do not
rewrite source comments without user authorization.
Do not write semantic signatures without user authorization.

## Configure the repository

1. Inspect the root README, package layout, package manager, and existing TSDoc tools.
2. Locate each instruction file that the installation must update.
3. Identify applicable TypeScript files and explicit exclusions.
4. Record the initial migration scope before you change enforcement.
5. Add repository-local validation that fits the existing toolchain.
6. Add a package script or documented command for the Semark check.
7. Add the Semark check to the existing continuous integration workflow.
8. Add missing root or package README files within the requested scope.
9. Add the required Semark policy to `AGENTS.md`.
10. Configure approved directive patterns and stable path exclusions.

If no continuous integration workflow exists, report this limit. Do not create one
unless the user requests it.

## Add the repository instructions

Add this section to the applicable `AGENTS.md` file. Replace the placeholder with the
configured Semark command.

```markdown
## Semark Protocol

Load `semark-protocol` before you add or change TypeScript comments.
Do not add or keep source comments except Semark file signatures, method signatures,
and approved directives.
Update an affected signature in the same change as the documented behavior.
Run `<semark-check-command>` before you complete a change.
```

Keep this policy in `AGENTS.md` as the canonical agent instruction. Do not weaken a
stricter existing comment rule.
For other agent instruction files, link them to `AGENTS.md` or add an equivalent policy.

## Set the migration baseline

Do not enable a failing repository-wide check without a migration plan. Select one
explicit baseline:

- All applicable files comply at this time.
- Only changed files must comply during an incremental migration.
- Listed packages comply while other packages remain excluded.

State the selected baseline in the repository configuration or instructions. Give each
temporary exclusion an owner, reason, or removal condition.
Add this metadata only when the repository supports it.

Do not silently exempt a violation. Do not weaken a canonical format to preserve an
existing comment.

## Add validation

If the repository uses Oxlint, configure the GitHub Packages registry for the
`@bearfire-dev` scope. Install `@bearfire-dev/oxlint-plugin-semark`. Load it through
`jsPlugins` and enable `semark/valid` in the root Oxlint configuration.

Keep the scope-to-registry mapping in the project `.npmrc` file. Keep the token mapping
in the trusted user-level `.npmrc` file. Do not commit a package token.

For GitHub Actions, grant the consuming repository read access under the package
`Manage Actions access` setting. Set `packages: read` in the workflow. Configure
`actions/setup-node` with the GitHub Packages registry and `@bearfire-dev` scope. Pass
the repository `GITHUB_TOKEN` as `NODE_AUTH_TOKEN` to the dependency installation step.

Use a repository-local validator for requirements outside the Oxlint rule boundary.
These requirements can include README coverage, migration scope, exclusions, naming,
and changed-code signature updates.

If the repository does not use Oxlint, add the smallest local tool that can check the
configured scope, placement, tags, order, lengths, directives, and comment policy.

Make the check return a nonzero status for violations. Report the file, source location,
and violation type.
Do not make the check write semantic descriptions.

## Report completion

Report the changed files, instruction paths, scope, exclusions, migration baseline,
check command, continuous integration status, and check results.
Report migration work that remains outside the user request.
