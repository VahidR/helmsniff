# helmsniff

A Go CLI tool that scans rendered Kubernetes/Helm manifests and produces a CSV or JSON report of security misconfigurations.

> 📖 **New to helmsniff? Start here:** [**Scanning Helm Charts at Scale with helmsniff**](https://vahid-r.com/posts/helmsniff-tutorial/) — a full tutorial that walks through real scans, explains every check, and shows how to analyze thousands of charts. It is the fastest way to get a complete grasp of the tool.

## Security Checks

Every output row begins with two context columns, followed by one column per
check. Check columns are binary integers (`1` = violation/detected, `0` = ok),
while `K8S_STATUS` and `HELM_STATUS` are booleans (`true`/`false`).

| Column | Type | Description |
|--------|------|-------------|
| `DIR` | string | Parent directory (chart) path, or input label for stdin mode |
| `YAML_FULL_PATH` | string | Full path to the analyzed YAML file, or input label for stdin mode |
| `WITHIN_MANIFEST_SECRET` | int | Document is a `Secret` with non-empty `data`/`stringData` |
| `VALID_TAINT_SECRET` | int | Reserved for taint-based secret detection (always `0`; not yet implemented) |
| `SEC_CONT_OVER_PRIVIL` | int | Container running in privileged mode |
| `INSECURE_HTTP` | int | A plaintext `http://` URL found anywhere in the document |
| `NO_SECU_CONTEXT` | int | No `securityContext` at pod level or on any container |
| `NO_DEFAULT_NSPACE` | int | No namespace specified in resource metadata |
| `NO_RESO` | int | A container is missing both resource requests and limits |
| `NO_ROLLING_UPDATE` | int | Deployment uses `Recreate` or lacks a `rollingUpdate` strategy |
| `NO_NETWORK_POLICY` | int | Chart contains no `NetworkPolicy` resource |
| `TRUE_HOST_PID` | int | `hostPID: true` |
| `TRUE_HOST_IPC` | int | `hostIPC: true` |
| `DOCKERSOCK_PATH` | int | `/var/run/docker.sock` mounted via `hostPath` |
| `TRUE_HOST_NET` | int | `hostNetwork: true` |
| `CAP_SYS_ADMIN` | int | `SYS_ADMIN` capability added to a container |
| `HOST_ALIAS` | int | `hostAliases` present in the pod spec |
| `ALLOW_PRIVI` | int | `allowPrivilegeEscalation: true` |
| `SECCOMP_UNCONFINED` | int | `seccompProfile.type` set to `Unconfined` |
| `CAP_SYS_MODULE` | int | `SYS_MODULE` capability added to a container |
| `K8S_STATUS` | bool | Document is a valid Kubernetes resource (has `apiVersion` and `kind`) |
| `HELM_STATUS` | bool | Document is managed by Helm (`managed-by: Helm` label or `helm.sh/chart` label) |

## Download

Pre-built binaries for Linux, Windows, and macOS are published on the
[**Releases**](https://github.com/VahidR/helmsniff/releases) page.

```bash
# Linux (amd64)
curl -L https://github.com/VahidR/helmsniff/releases/latest/download/helmsniff-linux-amd64.tar.gz | tar xz
./helmsniff --root <rendered_dir|-> --out <output_path|->

# macOS (Apple Silicon / arm64)
curl -L https://github.com/VahidR/helmsniff/releases/latest/download/helmsniff-macos-arm64.zip -o helmsniff.zip
unzip helmsniff.zip
```

On Windows, download `helmsniff-windows-amd64.zip` from the Releases page and
extract `helmsniff.exe`.

## Prerequisites

- Go 1.22+
- GNU Make

## Build

```bash
make build
```

The binary is compiled to `bin/helmsniff`.

## Usage

```bash
./bin/helmsniff --root <rendered_dir|-> --out <output_path|-> [--format csv|json]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--root` | Path to directory containing rendered Kubernetes manifests, or `-` to read from stdin |
| `--out` | Path to output file, or `-` to write to stdout |
| `--format` | Output format: `csv` (default) or `json` |

### Batch processing

Scan multiple charts in parallel using GNU `parallel`:

```bash
parallel ./bin/helmsniff --root {} --out reports/{/}.csv ::: datasets/rendered/*/
```

### JSON output

Generate a JSON report instead of CSV:

```bash
./bin/helmsniff --root datasets/rendered/mychart --out report.json --format json
```

### Stdin pipe

Pipe `helm template` output directly without writing intermediate files:

```bash
helm template mychart ./charts/mychart | ./bin/helmsniff --root - --out - --format json
```

Or save to a file:

```bash
helm template mychart ./charts/mychart | ./bin/helmsniff --root - --out report.csv
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Compile the binary |
| `make clean` | Remove `bin/` directory |
| `make tidy` | Run `go mod tidy` |
| `make vet` | Run `go vet ./...` |
| `make lint` | Run `golangci-lint` (must be installed) |
| `make test` | Run tests with race detector |

## Project Structure

```
helmsniff/
├── cmd/main.go                      # CLI entry point (flags, walking, CSV/JSON output)
├── internal/
│   ├── config/constants.go          # CSV header definition
│   ├── parser/
│   │   ├── parser.go                # YAML document loader (file & reader)
│   │   └── parser_test.go
│   └── scanner/
│       ├── scanner.go               # File walking & analysis orchestration
│       ├── security_checks.go       # Individual check implementations
│       ├── row.go                   # Row data structure
│       ├── scanner_test.go
│       └── security_checks_test.go
├── ARCHITECTURE.md                  # Design notes & detailed check reference
├── Makefile
├── go.mod
└── go.sum
```

## Releasing

Releases are automated via GitHub Actions
([`.github/workflows/release.yml`](.github/workflows/release.yml)). Pushing a
semver tag builds the binary for Linux, Windows, and macOS and publishes a
GitHub Release with archives and auto-generated release notes:

```bash
git tag v1.0.0
git push origin v1.0.0
```

## License

[MIT](LICENSE)


