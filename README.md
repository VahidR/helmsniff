# helmsniff

A Go CLI tool that scans rendered Kubernetes/Helm manifests and produces a CSV report of security misconfigurations.

## Security Checks

Each YAML document is analyzed for the following:

| Column | Description |
|--------|-------------|
| `WITHIN_MANIFEST_SECRET` | Secret data found in manifest |
| `VALID_TAINT_SECRET` | Valid taint-based secret detected |
| `SEC_CONT_OVER_PRIVIL` | SecurityContext with `privileged: true` |
| `INSECURE_HTTP` | Insecure HTTP usage detected |
| `NO_SECU_CONTEXT` | Missing securityContext |
| `NO_DEFAULT_NSPACE` | Missing namespace (defaults to `default`) |
| `NO_RESO` | Missing resource requests/limits |
| `NO_ROLLING_UPDATE` | Deployment without rollingUpdate strategy |
| `NO_NETWORK_POLICY` | Chart has no NetworkPolicy resource |
| `TRUE_HOST_PID` | `hostPID: true` |
| `TRUE_HOST_IPC` | `hostIPC: true` |
| `DOCKERSOCK_PATH` | docker.sock mounted via hostPath |
| `TRUE_HOST_NET` | `hostNetwork: true` |
| `CAP_SYS_ADMIN` | `SYS_ADMIN` capability added |
| `HOST_ALIAS` | hostAliases present |
| `ALLOW_PRIVI` | `allowPrivilegeEscalation: true` |
| `SECCOMP_UNCONFINED` | seccompProfile set to Unconfined |
| `CAP_SYS_MODULE` | `SYS_MODULE` capability added |
| `K8S_STATUS` | Kubernetes status metadata present |
| `HELM_STATUS` | Helm status metadata present |

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
├── cmd/main.go              # CLI entry point
├── internal/
│   ├── config/constants.go  # CSV header definition
│   ├── parser/parser.go     # YAML document loader
│   └── scanner/
│       ├── scanner.go       # File walking & analysis orchestration
│       ├── security_checks.go # Individual check implementations
│       └── row.go           # Row data structure
├── test-datasets/           # Sample Helm charts for testing
├── Makefile
└── go.mod
```

## License

See repository for license details.
