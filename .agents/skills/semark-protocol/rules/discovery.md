# Discovery hierarchy

Use this fixed hierarchy:

```text
Repository instructions
    -> Repository README
    -> Package README
    -> File signature
    -> Method signature
    -> Implementation and tests
```

Start with the smallest relevant context surface. Inspect the next level only when the
current level does not supply enough information.

Use tools such as `ls`, `find`, `rg`, `head`, `sed`, `cat`, and `git`. Do not read a
complete package if its README excludes that package from the task.

## Progressive discovery workflow

1. Read the relevant root `README.md` sections.
2. Locate candidate packages with names, `find`, and `rg`.
3. Read only the relevant package `README.md`.
4. Locate candidate files with filenames and symbol searches.
5. Read the first 40 lines of each candidate file.
6. Read the relevant method signatures.
7. Read complete implementations and tests only when the prior levels show relevance.
