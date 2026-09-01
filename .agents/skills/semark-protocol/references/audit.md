# Audit Semark compliance

Use this workflow to audit Semark compliance or to report findings. Report findings only
unless the user also requests corrections.

Read only the rule modules that apply to the requested scope. For a complete audit, read
all rule modules except:

- `purpose.md`
- `discovery.md`

## Audit workflow

1. Identify the configured source scope, exclusions, and migration baseline.
2. Locate the root README and package README files.
3. Inspect applicable source comments and TSDoc blocks.
4. If the scope includes a Git range, compare changed code with changed signatures.
5. Inspect each reported naming problem in its domain context.
6. Compare each finding with the applicable rule.

Do not infer semantic inaccuracy from wording alone. Read more evidence when a finding
depends on behavior.
Use the implementation, related types, callers, and tests as evidence when necessary.

## Map checker labels to audit categories

When the repository uses `scripts/check-semark.mjs`, translate checker labels in the
`[label]` field to audit categories:

| Checker label | Audit categories |
| --- | --- |
| `readme-coverage` | `README_MISSING`, `README_NAME_INVALID` |
| `file-signature` | `FILE_SIGNATURE_MISSING`, `FILE_SIGNATURE_POSITION`, `FILE_SIGNATURE_FORMAT`, `TSDOC_INVALID`, `TAG_ORDER_INVALID`, `LENGTH_LIMIT` |
| `method-signature` | `METHOD_SIGNATURE_MISSING`, `METHOD_SIGNATURE_POSITION`, `METHOD_SIGNATURE_FORMAT`, `TSDOC_INVALID`, `TAG_ORDER_INVALID`, `LENGTH_LIMIT` |
| `comment-policy` | `COMMENT_UNAUTHORIZED`, `DIRECTIVE_INVALID` |

Use `SIGNATURE_STALE`, `NAME_AMBIGUOUS`, and `CONFIGURATION_INVALID` when the finding
does not map to a checker label.

## Use stable finding categories

- `README_MISSING`
- `README_NAME_INVALID`
- `FILE_SIGNATURE_MISSING`
- `FILE_SIGNATURE_POSITION`
- `FILE_SIGNATURE_FORMAT`
- `METHOD_SIGNATURE_MISSING`
- `METHOD_SIGNATURE_POSITION`
- `METHOD_SIGNATURE_FORMAT`
- `TSDOC_INVALID`
- `TAG_ORDER_INVALID`
- `LENGTH_LIMIT`
- `COMMENT_UNAUTHORIZED`
- `DIRECTIVE_INVALID`
- `SIGNATURE_STALE`
- `NAME_AMBIGUOUS`
- `CONFIGURATION_INVALID`

## Format the output

Return one Markdown table. Do not return JSON, YAML, or record-style code blocks.
Use exactly these columns:

| Status | Location | Category | Problem | Required change | Evidence |
| --- | --- | --- | --- | --- | --- |

Use `Confirmed` or `Review` in the `Status` column. Put `path:line` in the `Location` column.
Use one row for each finding. Escape each pipe character that occurs in a cell.

Sort confirmed violations before review items. Then sort the rows by path and source location.
Do not report style preferences as protocol violations.

If the audit finds no violations, return the table header without finding rows. Then
state the audited scope and command results.
Also state the Git range when the audit uses one. Do not claim compliance outside the audited scope.
