// Package parser provides YAML loading utilities for multi-document Kubernetes
// manifest files. It produces untyped map representations suitable for the
// scanner's security analysis checks.
package parser

import (
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadYAMLDocs reads a multi-document YAML file at the given path and returns
// each non-empty document as a map[string]interface{}. Empty documents (e.g.
// those produced by Helm template separators "---") are silently skipped.
// Returns an error if the file cannot be opened or contains malformed YAML.
func LoadYAMLDocs(path string) ([]map[string]interface{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	var out []map[string]interface{}
	for {
		var node map[string]interface{}
		if err := dec.Decode(&node); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(node) == 0 {
			continue
		}
		out = append(out, node)
	}
	return out, nil
}
