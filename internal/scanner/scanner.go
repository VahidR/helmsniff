package scanner

import (
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/VahidR/helmsniff/internal/parser"
)

// isYAML returns true if the file path has a .yaml or .yml extension (case-insensitive).
func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// HasNetworkPolicy walks all YAML files under rootDir and returns true if any
// document has kind "NetworkPolicy". This is a chart-level pre-scan used to
// set the NoNetworkPolicy flag on every row produced from that chart.
// Short-circuits on the first NetworkPolicy found for efficiency.
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

// AnalyzeFile parses a multi-document YAML file and runs all security checks
// on each document, returning one Row per document. The hasNP parameter is a
// pre-computed chart-level flag indicating whether a NetworkPolicy exists in
// the chart (from HasNetworkPolicy). rootDir is recorded in each Row for CSV
// output context. Returns an error only if YAML parsing fails entirely.
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
		row.SecContOverPrivil = checkPrivileged(ps)
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

// AnalyzeReader reads multi-document YAML from an io.Reader (e.g. stdin) and
// runs all security checks on each document. Since the input is a single stream,
// the NetworkPolicy pre-scan is performed inline over the parsed documents.
// The label parameter is used as the Dir/YAMLFullPath value in each Row.
func AnalyzeReader(r io.Reader, label string) ([]Row, error) {
	docs, err := parser.LoadYAMLDocsFromReader(r)
	if err != nil {
		return nil, err
	}

	// Determine chart-level NetworkPolicy presence from the parsed docs
	hasNP := false
	for _, doc := range docs {
		if strings.EqualFold(str(doc["kind"]), "NetworkPolicy") {
			hasNP = true
			break
		}
	}

	rows := make([]Row, 0, len(docs))
	for _, doc := range docs {
		row := Row{
			Dir:          label,
			YAMLFullPath: label,
		}
		row.K8sStatus = hasAPIVersionAndKind(doc)
		row.HelmStatus = detectHelmManaged(doc)

		row.WithinManifestSecret = countSecretsInDoc(doc)
		row.InsecureHTTP = hasInsecureHTTP(doc)

		ps := podSpecFromDoc(doc)
		row.NoSecuContext = lackSecurityContext(ps)
		row.NoReso = lackResources(ps)
		row.TrueHostPID,
			row.TrueHostIPC,
			row.TrueHostNet = checkHostFlags(ps)
		row.DockerSockPath = checkDockerSock(ps)
		row.SecContOverPrivil = checkPrivileged(ps)
		row.CapSysAdmin,
			row.CapSysModule,
			row.AllowPrivi,
			row.SeccompUnconfined = checkCaps(ps)
		row.HostAlias = hasHostAliases(ps)
		row.NoRollingUpdate = lackRollingUpdate(doc)
		row.NoDefaultNSpace = lackNamespace(doc)

		if hasNP {
			row.NoNetworkPolicy = 0
		} else {
			row.NoNetworkPolicy = 1
		}

		rows = append(rows, row)
	}
	return rows, nil
}
