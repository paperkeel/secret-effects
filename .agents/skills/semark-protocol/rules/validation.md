# Validation

Make validation return a nonzero status for a violation. Check the applicable items from this list:

- root and package README coverage
- exact README names
- file-signature presence and placement
- method-signature presence and placement
- TSDoc syntax and tag order
- signature length limits
- prohibited tags and comments
- directive syntax
- configured source coverage
- changed-code signature updates

Do not make validation generate semantic descriptions. Require a human or agent to write
the descriptions.

Check unauthorized comments and invalid directives in every Semark installation. Apply
this check to the configured source scope.

If the repository uses Oxlint, load `@paperkeel/oxlint-plugin-semark` through
`jsPlugins`. Enable `semark/valid` as an error.

Use repository validation for requirements outside the Oxlint rule boundary. These
requirements include README coverage, semantic accuracy, naming, exclusions, migration
scope, and changed-code signature updates.

Run the configured Semark check before you complete a change. Correct violations that
your change causes.
