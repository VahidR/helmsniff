package parser

import (
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadYAMLDocs reads all YAML documents from a file and returns them as a slice of generic maps.
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
