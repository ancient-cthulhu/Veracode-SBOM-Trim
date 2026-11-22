# How it works

Every number below comes from real Veracode SCA exports of [Verademo](https://github.com/veracode/verademo), Veracode's intentionally vulnerable demo app.

## Pipeline

```
read → check → decide → remove / redact → fix references → stamp → validate → write
```

1. **Read** JSON or XML (UTF-8/16/32). XML is converted to the JSON model, so every flag behaves the same for both.
2. **Check** structure and detect the source (REST `application`, REST `agent`, or Veracode CLI) from the SBOM's own metadata. Each source carries different data, and the tool uses what's there.
3. **Decide** per component: keep, remove (with the rule that matched), or redact.
4. **Remove / redact.** Redacted components become a `REDACTED` placeholder that keeps its place in the dependency graph.
5. **Fix references** in `dependencies`, `dependsOn`, `vulnerabilities[].affects`, `compositions` and `annotations`. With a dependency graph, components only reachable through removed ones are pruned.
6. **Stamp** a new `serialNumber`, timestamp, `version` + 1, the tool in `metadata.tools`, and a `compositions` entry stating the inventory was trimmed. Because it is a new BOM, build any VEX from the trimmed SBOM (see [README: VEX](../README.md#vex-generate-it-from-the-trimmed-sbom)).
7. **Validate** against the CycloneDX JSON schema or XSD. On failure nothing is written (exit `3`).
8. **Write** atomically. The input is never overwritten.

## What each Veracode source gives you

| | REST API `type=application` (Upload & Scan) | REST API `type=agent` | Veracode CLI `veracode sbom` |
|---|---|---|---|
| Format | CycloneDX 1.4 JSON | CycloneDX 1.4 JSON | CycloneDX 1.6 JSON or XML |
| Library identification | `Match Type` per component: matched or `Unmatched` | `Match Type` per component | File-level discovery; purl per artifact |
| Dependency graph | Flat | Transitive graph (60 edges) | — |
| Location detail | `File Path` inside the archive | `File Path` to the manifest | Exact file and archive paths |
| Best flags | `--public-only`, `--exclude` | `--public-only`, `--exclude`, `--redact`, `--direct-only --infer-direct` | `--exclude`, `--strip-paths` |

## Example 1: agent scan, using the dependency graph

Veracode's agent scan records the full transitive graph, so removing a package also removes everything that only it pulled in.

```bash
python sbom_trim.py agent_sbom.json -o out.json --report \
  --exclude 'pkg:maven/org.apache.maven/*' --exclude '<undefined>*' \
  --redact com.veracode.annotation
```

```text
SBOM source: agent
                  before   after
components            78      61
dependencies          78      61

Removed components (17):
  - org.apache.maven:maven-project@2.0          [exclude pkg:maven/org.apache.maven/*]
  - ... 7 more org.apache.maven artifacts      [exclude pkg:maven/org.apache.maven/*]
  - <undefined>:<undefined>                     [exclude <undefined>*]
  - org.codehaus.plexus:plexus-utils@1.0.4      [orphan (only reachable through removed components)]
  - junit:junit@4.13                            [orphan (only reachable through removed components)]
  - ... 6 more orphans
Redacted components (1):
  - com.veracode.annotation:VeracodeAnnotations@1.2.1  [redact com.veracode.annotation]
Composition aggregate for root: incomplete
```

- 9 components matched the patterns; the graph identified **8 more** (plexus, wagon, hamcrest, junit, classworlds) that existed only because of them.
- `VeracodeAnnotations` stays in the tree as `REDACTED`, with no version, purl or hashes, so the graph keeps its shape.
- `incomplete` (not `incomplete_third_party_only`) because the orphans include third-party libraries, so the output says so.

## Example 2: keep only identified libraries

Veracode SCA matches each component against its library database. Anything it doesn't match, like your own build output, is marked `Unmatched`, and `--public-only` uses that.

```bash
python sbom_trim.py app_sbom.json -o out.json --public-only --report
```

| Export | Before | After | Removed |
|---|---|---|---|
| Upload & Scan | 97 | 96 | `verademo.war` (the application itself) |
| Agent | 78 | 77 | `<undefined>:<undefined>` |

One flag, no patterns to maintain. Result: `incomplete_third_party_only`, meaning only first-party content is missing.

Add `--exclude 'pkg:maven/com.yourco/*'` for your own packages that are published to a repository, because Veracode can identify those too.

## Example 3: nested archives

Upload & Scan records where each jar sits inside the archive (`verademo.war#zip:WEB-INF/lib-provided/...`). When an excluded jar contains other jars, their paths would still name it. The tool rewrites them:

```bash
python sbom_trim.py app_sbom.json -o out.json --exclude '*tomcat-embed-core*'
```

```text
verademo.war#zip:WEB-INF/lib-provided/REDACTED:tomcat-juli-9.0.37.jar
verademo.war#zip:WEB-INF/lib-provided/REDACTED:tomcat-servlet-api-9.0.35.jar
verademo.war#zip:WEB-INF/lib-provided/REDACTED:tomcat-jni-9.0.36.jar
```

Rewritten paths (and `--strip-paths`) no longer match the `File Path` that the [VEX Generator](https://github.com/ancient-cthulhu/Veracode-VEX-Generator) uses for exact Upload & Scan matching, so it falls back to file names. If you need exact matching, skip `--strip-paths` and build the VEX from that trimmed output.

## Example 4: Veracode CLI

`veracode sbom --type directory` inventories every artifact on disk with its exact location: 164 components for Verademo, including the app's own `com.veracode:verademo` artifact.

```bash
python sbom_trim.py cli_sbom.xml -o out.xml --report \
  --exclude 'pkg:maven/com.veracode/*' --strip-paths
```

```text
SBOM source: syft
                  before   after
components           164     163
Removed components (1):
  - com.veracode:verademo@0.0.1-SNAPSHOT  [exclude pkg:maven/com.veracode/*]
Path properties stripped: 310
Composition aggregate for root: incomplete_third_party_only
```

- `--exclude` removes the app. The exact group pattern keeps the public `com.veracode.annotation` library; `com.veracode*` would have removed it too.
- The app's name also appears in other components' locations (`\app\target\verademo\WEB-INF\lib\...`). `--strip-paths` removes all 310 location properties, so "verademo" appears nowhere in the output.
- XML in, XML out, validated against the CycloneDX 1.6 XSD.

## When a flag can't apply

The tool checks that the data a flag needs is present. If it isn't, the flag exits with `2` and an explanation instead of silently doing nothing:

| Flag | Needs |
|---|---|
| `--public-only`, `--drop-unmatched` | Veracode `Match Type` (REST API exports) |
| `--direct-only` | A dependency graph (agent exports, with `--infer-direct`) |
| `--runtime-only` | `scope` on components |

## Choosing flags

| Source | Start with |
|---|---|
| REST API, Upload & Scan | `--public-only --exclude 'pkg:maven/com.yourco/*'` |
| REST API, agent | `--public-only --exclude 'pkg:maven/com.yourco/*'` (orphans pruned automatically) |
| Veracode CLI | `--exclude 'pkg:maven/com.yourco/*' --strip-paths` |

Add `--report` until the removals match what you expect.
