package scanner

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/VahidR/helmsniff/internal/parser"
)

// helper
func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// HasNetworkPolicy scans all YAML docs under a rendered chart dir once
// to decide the chart-level NO_NETWORK_POLICY flag.
func HasNetworkPolicy(rootDir string) bool {
	hasNP := false
	_ = filepath.WalkDir(rootDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !isYAML(p) {
			return nil
		}
		docs, derr := parser.LoadYAMLDocs(p)
		if derr != nil {
			return nil
		}
		for _, doc := range docs {
			if strings.EqualFold(str(doc["kind"]), "NetworkPolicy") {
				hasNP = true
				return fs.SkipAll
			}
		}
		return nil
	})
	return hasNP
}

// AnalyzeFile parses each YAML document in a multi-doc YAML file and returns one Row per doc.
// hasNP is computed once per chart and applied to every row.
// NOTE: signature takes hasNP and we reuse isYAML(p) in the caller (main.go)
func AnalyzeFile(path string, rootDir string, hasNP bool) ([]Row, error) {
	docs, err := parser.LoadYAMLDocs(path)
	if err != nil {
		return nil, err
	}

	rows := make([]Row, 0, len(docs))
	for _, doc := range docs {
		row := Row{
			Dir:          rootDir,
			YAMLFullPath: filepath.Clean(path),
		}
		row.K8sStatus = hasAPIVersionAndKind(doc)
		row.HelmStatus = detectHelmManaged(doc)

		// Per-doc checks
		row.WithinManifestSecret = countSecretsInDoc(doc)
		row.InsecureHTTP = hasInsecureHTTP(doc)

		ps := podSpecFromDoc(doc)
		row.NoSecuContext = lackSecurityContext(ps)
		row.NoReso = lackResources(ps)
		row.TrueHostPID,
			row.TrueHostIPC,
			row.TrueHostNet = checkHostFlags(ps)
		row.DockerSockPath = checkDockerSock(ps)
		row.CapSysAdmin,
			row.CapSysModule,
			row.AllowPrivi,
			row.SeccompUnconfined = checkCaps(ps)
		row.HostAlias = hasHostAliases(ps)
		row.NoRollingUpdate = lackRollingUpdate(doc)
		row.NoDefaultNSpace = lackNamespace(doc)

		// Chart-level NO_NETWORK_POLICY parity with Python
		if hasNP {
			row.NoNetworkPolicy = 0
		} else {
			row.NoNetworkPolicy = 1
		}

		rows = append(rows, row)
	}
	return rows, nil
}
