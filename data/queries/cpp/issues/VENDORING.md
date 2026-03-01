# Vendored CodeQL Queries — How This Works

## What we did

We copied 14 standard CodeQL queries from the `codeql/cpp-queries` pack into this
flat directory so Vulnhalla can run them via `codeql database analyze`.

## The helper module problem

Some queries import local helper modules (`.qll` files) that live alongside them
in the original pack directory structure. When you copy just the `.ql` file into a
flat folder, those imports break with errors like:

    could not resolve module ScanfChecks

### Which queries need helpers

| Query | Imports | Helper file |
|-------|---------|-------------|
| Incorrect return-value check for a 'scanf'-like function.ql | `ScanfChecks` | ScanfChecks.qll |
| Missing return-value check for a 'scanf'-like function.ql | `ScanfChecks` | ScanfChecks.qll |
| 'new[]' array freed with 'delete'.ql | `NewDelete` | NewDelete.qll |
| Unchecked return value used as offset.ql | `Negativity` | Negativity.qll |

The remaining 10 queries only import standard library modules (`import cpp`,
`import semmle.code.cpp.*`) and work fine as standalone copies.

## How to add a new query

1. Find the query in the installed pack:
   ```
   ~/.codeql/packages/codeql/cpp-queries/<version>/
   ```

2. Check its `@name` metadata — this must match the `.template` filename exactly.

3. Copy the `.ql` file here, named exactly as the `@name` value.

4. Check for local imports (anything that isn't `import cpp` or `import semmle.*`).
   If present, find the `.qll` file in the same pack directory and copy it here too.

5. Create a matching template in `data/templates/cpp/<exact @name>.template`.

6. Verify compilation:
   ```
   codeql query compile "data/queries/cpp/issues/<name>.ql"
   ```

## Source pack version

All files sourced from: `codeql/cpp-queries@1.5.11`

See `query_manifest.json` in the repo root for exact paths and SHA256 hashes.

## qlpack.yml dependencies

The local `qlpack.yml` must include both:
```yaml
dependencies:
  codeql/cpp-all: "*"
  codeql/cpp-queries: "*"
```

The `cpp-queries` dependency is needed so the helper `.qll` modules can resolve
their own transitive imports from the pack.
