package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"strings"
	"path/filepath"

	"github.com/VahidR/helmsniff/internal/config"
	"github.com/VahidR/helmsniff/internal/scanner"
)


// main is a command-line tool that scans rendered Kubernetes manifests
// in a specified directory and outputs a CSV report of security features.
// Usage: go-tool --root <rendered_dir> --out <csv_path>
// Example: go-tool --root datasets/rendered/mychart --out reports/mychart_report.csv
// The tool analyzes each YAML file in the rendered directory, checking for
// various security features and outputs the results in CSV format.
// It also performs a one-time scan to check for the presence of NetworkPolicy
// resources in the entire chart.
// Command-line flags:
//   --root : Path to the directory containing rendered Kubernetes manifests.
//   --out  : Path to the output CSV file where the report will be saved.
// The output CSV will contain a header row followed by one row per YAML document
// analyzed, with columns representing different security features and their presence.
func main() {
	var root string
	var out string
	flag.StringVar(&root, "root", "", "path to rendered manifests directory (datasets/rendered/<chart>)")
	flag.StringVar(&out, "out", "", "path to output CSV")
	flag.Parse()

	if root == "" || out == "" {
		fmt.Fprintf(os.Stderr, "usage: %s --root <rendered_dir> --out <csv_path>\n", os.Args[0])
		os.Exit(2)
	}

	// check and create output dir
	outDir := filepath.Dir(out)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}

	fout, err := os.Create(out)
	if err != nil {
		panic(err)
	}
	defer fout.Close()

	//
	w := csv.NewWriter(fout)
	defer w.Flush()

	if err := w.Write(config.CSVHeader); err != nil {
		panic(err)
	}

	// One-shot chart-level scan for NetworkPolicy presence
	// NO_NETWORK_POLICY is a chart-level flag, not a per-document one, so it's a separate pass because the information is global 
	// to the chart, not local to any single document.
	hasNP := scanner.HasNetworkPolicy(root)

	// Walk all manifest_*.yaml in the rendered dir
	err = filepath.WalkDir(root, func(filePath string, d os.DirEntry, err error) error {
		if err != nil { return nil }
		if d.IsDir() { return nil }
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext != ".yaml" && ext != ".yml" { return nil }

		rows, aerr := scanner.AnalyzeFile(filePath, root, hasNP)
		if aerr != nil { return nil }
		for _, r := range rows {
			record := []string{
				r.Dir,
				r.YAMLFullPath,
				// 3..19 feature columns:
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
				// status
				fmt.Sprintf("%t", r.K8sStatus),
				fmt.Sprintf("%t", r.HelmStatus),
			}
			if err := w.Write(record); err != nil { return err }
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
}
