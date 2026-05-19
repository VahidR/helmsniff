package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/VahidR/helmsniff/internal/config"
	"github.com/VahidR/helmsniff/internal/scanner"
)

// main is the entry point for the helmsniff CLI tool. It statically analyzes
// pre-rendered Kubernetes/Helm YAML manifests and produces a structured report
// (CSV or JSON) of security misconfigurations suitable for downstream analysis
// with tools like Python/pandas.
//
// The tool supports two input modes:
//   - Directory mode: recursively walks a directory of rendered manifests,
//     performing a two-pass scan — first checking for NetworkPolicy presence
//     across the entire chart, then analyzing each YAML document individually.
//   - Stdin mode (--root -): reads YAML from standard input, enabling piped
//     workflows such as: helm template mychart | helmsniff --root - --out -
//
// Command-line flags:
//
//	--root   : Path to the directory containing rendered Kubernetes manifests,
//	           or '-' to read multi-document YAML from stdin.
//	--out    : Path to the output file, or '-' to write to stdout.
//	--format : Output format, either 'csv' (default) or 'json'.
//
// Exit codes:
//
//	0 — success
//	1 — runtime error (e.g., stdin read failure)
//	2 — invalid usage (missing or invalid flags)
//
// In directory mode, malformed YAML files are silently skipped to support
// batch processing of large chart repositories. The output contains one row
// per YAML document, with binary (0/1) columns indicating security violations
// and boolean columns for K8s/Helm validity status.
//
// Examples:
//
//	helmsniff --root datasets/rendered/mychart --out reports/mychart_report.csv
//	helmsniff --root datasets/rendered/mychart --out report.json --format json
//	helm template mychart | helmsniff --root - --out - --format json
func main() {
	var root string
	var out string
	var format string
	flag.StringVar(&root, "root", "", "path to rendered manifests directory, or '-' to read from stdin")
	flag.StringVar(&out, "out", "", "path to output file (use '-' for stdout)")
	flag.StringVar(&format, "format", "csv", "output format: csv or json")
	flag.Parse()

	if root == "" || out == "" {
		fmt.Fprintf(os.Stderr, "usage: %s --root <rendered_dir|-> --out <path|-> [--format csv|json]\n", os.Args[0])
		os.Exit(2)
	}

	if format != "csv" && format != "json" {
		fmt.Fprintf(os.Stderr, "error: --format must be 'csv' or 'json'\n")
		os.Exit(2)
	}

	// Determine output destination
	var fout *os.File
	if out == "-" {
		fout = os.Stdout
	} else {
		outDir := filepath.Dir(out)
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			panic(err)
		}
		var err error
		fout, err = os.Create(out)
		if err != nil {
			panic(err)
		}
		defer fout.Close()
	}

	var allRows []scanner.Row

	if root == "-" {
		// Stdin mode: read YAML from stdin (e.g. helm template | helmsniff --root - --out -)
		rows, err := scanner.AnalyzeReader(os.Stdin, "stdin")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
			os.Exit(1)
		}
		allRows = rows
	} else {
		// Directory mode: walk rendered manifests
		hasNP := scanner.HasNetworkPolicy(root)

		err := filepath.WalkDir(root, func(filePath string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(filePath))
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}

			rows, aerr := scanner.AnalyzeFile(filePath, root, hasNP)
			if aerr != nil {
				return nil
			}
			allRows = append(allRows, rows...)
			return nil
		})
		if err != nil {
			panic(err)
		}
	}

	if format == "json" {
		writeJSON(fout, allRows)
	} else {
		writeCSV(fout, allRows)
	}
}

// writeCSV writes the scan results to the given file in CSV format.
// It first emits the header row defined in config.CSVHeader, then writes one
// data row per scanner.Row. The column order must exactly match the CSVHeader
// definition in internal/config/constants.go — any mismatch will produce a
// corrupt report. Integer check fields are formatted as "0" or "1" for
// compatibility with downstream numeric pipelines; boolean status fields are
// formatted as "true"/"false". The writer is flushed before returning.
// Panics if any write to the underlying file fails.
func writeCSV(fout *os.File, allRows []scanner.Row) {
	w := csv.NewWriter(fout)
	defer w.Flush()

	if err := w.Write(config.CSVHeader); err != nil {
		panic(err)
	}

	for _, r := range allRows {
		record := []string{
			r.Dir,
			r.YAMLFullPath,
			fmt.Sprint(r.WithinManifestSecret),
			fmt.Sprint(r.ValidTaintSecret),
			fmt.Sprint(r.SecContOverPrivil),
			fmt.Sprint(r.InsecureHTTP),
			fmt.Sprint(r.NoSecuContext),
			fmt.Sprint(r.NoDefaultNSpace),
			fmt.Sprint(r.NoReso),
			fmt.Sprint(r.NoRollingUpdate),
			fmt.Sprint(r.NoNetworkPolicy),
			fmt.Sprint(r.TrueHostPID),
			fmt.Sprint(r.TrueHostIPC),
			fmt.Sprint(r.DockerSockPath),
			fmt.Sprint(r.TrueHostNet),
			fmt.Sprint(r.CapSysAdmin),
			fmt.Sprint(r.HostAlias),
			fmt.Sprint(r.AllowPrivi),
			fmt.Sprint(r.SeccompUnconfined),
			fmt.Sprint(r.CapSysModule),
			fmt.Sprintf("%t", r.K8sStatus),
			fmt.Sprintf("%t", r.HelmStatus),
		}
		if err := w.Write(record); err != nil {
			panic(err)
		}
	}
}

// writeJSON writes the scan results to the given file as a pretty-printed
// JSON array. Each element in the array is a scanner.Row struct serialized
// using its json struct tags. The output is indented with two spaces for
// human readability. Panics if JSON encoding or the underlying write fails.
func writeJSON(fout *os.File, allRows []scanner.Row) {
	enc := json.NewEncoder(fout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(allRows); err != nil {
		panic(err)
	}
}
