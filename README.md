# Veracode SBOM Trim

Removes first-party components, unmatched files and build paths from Veracode SCA CycloneDX SBOMs. Every reference to a removed component is fixed up, and the output is checked against the CycloneDX schema before it's written.

**Why:** Veracode SBOMs list everything the scan saw. That includes your own artifacts, files Veracode couldn't identify, and build paths like `\app\target\verademo\WEB-INF\lib\x.jar`. Deleting entries by hand leaves broken `dependencies`, `vulnerabilities` and `compositions` refs, and often makes the file schema-invalid.

- Input: CycloneDX 1.4–1.6, JSON or XML, from the Veracode SBOM REST API (`type=application` / `type=agent`), the Veracode CLI (`veracode sbom`) or the agent CLI (`srcclr scan --sbom ...`). SPDX is rejected.
- Output: same format as the input; `--output-format json|xml` converts. The input file is never overwritten.
- Encoding: UTF-8, or UTF-16/32 with a BOM (what PowerShell `>` writes).
- Malformed input (wrong types, components nested > 64 deep, DOCTYPE/entities in XML) exits with code `2` and the JSON path of the problem; it never writes partial output.
- Python 3.9+, standard library only, no network calls.

## Install

```bash
pip install -r requirements.txt   # optional: enables schema validation (JSON schema / XSD)
```

Without it the tool still runs and prints a warning that validation was skipped.

## Examples

```bash
# REST API export: keep only libraries Veracode matched, and drop your own packages
python sbom_trim.py app_sbom.json -o app_sbom.trimmed.json \
  --public-only --exclude 'pkg:maven/com.acme/*' --report

# Veracode CLI (Syft) XML: drop your artifact and all build paths, keep XML
python sbom_trim.py cli_sbom.xml -o cli_sbom.trimmed.xml \
  --exclude 'pkg:maven/com.acme/*' --strip-paths

# Same input, JSON output
python sbom_trim.py cli_sbom.xml -o cli_sbom.trimmed.json --output-format json \
  --exclude 'pkg:maven/com.acme/*' --strip-paths

# Keep a component in the graph but hide what it is
python sbom_trim.py app_sbom.json -o out.json --redact 'pkg:maven/com.acme/secret-*'

# Regex instead of glob
python sbom_trim.py app_sbom.json -o out.json --exclude 're:^pkg:maven/com\.acme\.(core|internal)/'

# Only drop the files Veracode couldn't identify (the scanned .war, <undefined> entries)
python sbom_trim.py agent_sbom.json -o out.json --drop-unmatched

# Agent export, direct dependencies only (heuristic; misses transitive deps)
python sbom_trim.py agent_sbom.json -o out.json --direct-only --infer-direct

# Check a pattern before relying on it: --report lists every removal and the rule behind it
python sbom_trim.py app_sbom.json -o preview.json --exclude 'com.acme*' --report
```

`--report` on a Veracode CLI SBOM (`--exclude 'pkg:maven/com.veracode/*' --strip-paths`):

```text
sbom_trim report
SBOM source: syft

                  before   after
components           164     163
dependencies           0       0
vulnerabilities        0       0

Removed components (1):
  - com.veracode:verademo@0.0.1-SNAPSHOT  [exclude pkg:maven/com.veracode/*]
Redacted components (0):
  (none)
Path properties stripped: 310
Composition aggregate for root: incomplete_third_party_only
Note: the SBOM has no dependency edges (Veracode CLI `veracode sbom` / Syft output), so transitive dependencies of removed components cannot be identified and were kept
```

## Flags

| Flag | Effect |
|---|---|
| `--exclude PATTERN` | Remove components whose purl, group or name matches. Repeatable. |
| `--redact PATTERN` | Replace matches with a placeholder: name `REDACTED`, `bom-ref` `redacted-N`, property `external:redacted=true`. Graph edges are kept; version, purl, hashes and licenses are dropped. Repeatable. |
| `--public-only` | Keep only components Veracode matched to a known library (has a purl, not `Match Type: Unmatched`). Commercial/private jars are unmatched too and get dropped. REST API exports only. |
| `--drop-unmatched` | Remove only `Match Type: Unmatched` components. REST API exports only. |
| `--strip-paths` | Remove build-path properties: Veracode `File Path`, Syft `syft:location:N:path` and `syft:metadata:virtualPath`. Use when paths contain internal names `--exclude` can't reach (e.g. an exploded `verademo/` directory). |
| `--runtime-only` | Drop `scope: excluded`. Fails if no component has a scope. |
| `--drop-optional` | With `--runtime-only`, also drop `scope: optional`. |
| `--direct-only` | Keep only the root's direct dependencies. Fails without a dependency graph. Prints a CISA 2026 Minimum Elements warning. |
| `--infer-direct` | With `--direct-only`: treat components with no incoming edge as direct. Needed for agent exports, where the root has no `dependsOn`. |
| `--output-format json\|xml` | Output format. Default: same as input. |
| `--report` | Print before/after counts, each removed or redacted `name@version` with its rule, and notes. |
| `--no-validate` | Skip schema validation. |
| `--indent N` | Output indent (default 2). |

**Patterns:** shell globs matched against the whole value (`pkg:maven/com.acme/*`, `com.acme*`), or a regex with a `re:` prefix. `--exclude` wins over `--redact`. The root component is never removed.

Match exact groups: `com.veracode*` also matches the public `com.veracode.annotation` library; `pkg:maven/com.veracode/*` doesn't.

## Which flags work on which export

| | REST API `type=application` | REST API `type=agent` | Veracode CLI `veracode sbom` |
|---|---|---|---|
| `--exclude` / `--redact` / `--strip-paths` | ✓ | ✓ | ✓ |
| `--public-only` / `--drop-unmatched` | ✓ | ✓ | ✗ no match data: every file gets a purl, including your own artifact |
| `--direct-only` | ✗ no `dependsOn` | ✓ with `--infer-direct` | ✗ no graph |
| `--runtime-only` | ✗ no `scope` | ✗ no `scope` | ✗ no `scope` |
| Orphan pruning | ✗ no graph | ✓ | ✗ no graph |

Unsupported flags exit with code `2` and say why. Without a graph, a removed component's transitive dependencies are kept and the report says so.

Veracode CLI output lists most libraries 2–3 times (inside the `.war`, in the exploded directory, and from `pom.xml`); the tool leaves these as-is. Syft also writes pom version ranges into purls (`@[1.0.4,)`), which makes its own XML fail the 1.6 XSD. XML output percent-encodes them (`@%5B1.0.4,)`).

## What changes in the output

- **References:** `dependencies`, `dependsOn`/`provides`, `vulnerabilities[].affects`, `compositions` and `annotations` refs to removed components are removed; refs to redacted ones are remapped. Dangling refs already in the input are dropped with a note.
- **Orphans:** components reachable only through removed components are removed (when there's a graph).
- **Vulnerabilities:** entries that only affect removed components are removed. Entries on redacted components are removed too, since a CVE identifies the package.
- **Nested paths:** paths of jars inside an excluded/redacted jar are rewritten to `.../REDACTED:inner.jar`.
- **Compositions:** the root gets `incomplete_third_party_only` when only first-party/unmatched components were removed, otherwise `incomplete`.
- **Metadata:** new `serialNumber`, new timestamp, `version` + 1, `sbom_trim` added to `metadata.tools`.
- Everything else, including key order, is preserved.

Exit codes: `0` ok, `2` input/option/output-path error, `3` output failed schema validation (nothing written).

## CI (GitHub Actions)

Runs after the Veracode scan. Needs secrets `VERACODE_API_ID` and `VERACODE_API_KEY` for an API account with the **Results API** role. The SBOM API needs a scan from the last 13 months.

```yaml
  sbom:
    runs-on: ubuntu-latest
    needs: veracode-policy-scan          # your scan job
    env:
      APP_NAME: Verademo
      VERACODE_API_KEY_ID: ${{ secrets.VERACODE_API_ID }}
      VERACODE_API_KEY_SECRET: ${{ secrets.VERACODE_API_KEY }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install httpie veracode-api-signing -r requirements.txt

      - name: Export SBOM
        run: |
          APP_GUID=$(http --auth-type=veracode_hmac --check-status GET \
            "https://api.veracode.com/appsec/v1/applications" name=="$APP_NAME" \
            | jq -r --arg n "$APP_NAME" '._embedded.applications[]? | select(.profile.name==$n) | .guid')
          test -n "$APP_GUID" || { echo "application '$APP_NAME' not found"; exit 1; }
          http --auth-type=veracode_hmac --check-status GET \
            "https://api.veracode.com/srcclr/sbom/v1/targets/$APP_GUID/cyclonedx" \
            type==application > sbom.full.json

      - name: Trim SBOM
        run: |
          python sbom_trim.py sbom.full.json -o sbom.trimmed.json \
            --public-only --exclude 'pkg:maven/com.acme/*' --report

      - uses: actions/upload-artifact@v4
        with:
          name: sbom-trimmed
          path: sbom.trimmed.json
```

- **Agent project:** use the project GUID with `type==agent` (from `/srcclr/v3/workspaces/{workspaceGuid}/projects`), or run `srcclr scan . --sbom cyclonedx1.6+json --output sbom.full.json`.
- **Veracode CLI:** `veracode sbom --type directory --source . -o sbom.full.xml`, then trim with `--exclude ... --strip-paths`.
- **EU / FedRAMP:** use `api.veracode.eu` / `api.veracode.us`.
