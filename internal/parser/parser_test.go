package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- LoadYAMLDocs ----------

func TestLoadYAMLDocs_SingleDocument(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
data:
  key: value
`
	path := writeTestFile(t, dir, "single.yaml", content)

	docs, err := LoadYAMLDocs(path)
	if err != nil {
		t.Fatalf("LoadYAMLDocs() error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("got %d docs, want 1", len(docs))
	}
	if docs[0]["kind"] != "ConfigMap" {
		t.Errorf("kind = %v, want ConfigMap", docs[0]["kind"])
	}
}

func TestLoadYAMLDocs_MultiDocument(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: Service
metadata:
  name: svc
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
`
	path := writeTestFile(t, dir, "multi.yaml", content)

	docs, err := LoadYAMLDocs(path)
	if err != nil {
		t.Fatalf("LoadYAMLDocs() error: %v", err)
	}
	if len(docs) != 3 {
		t.Fatalf("got %d docs, want 3", len(docs))
	}
	kinds := []string{"Service", "Deployment", "ConfigMap"}
	for i, want := range kinds {
		if docs[i]["kind"] != want {
			t.Errorf("doc[%d].kind = %v, want %s", i, docs[i]["kind"], want)
		}
	}
}

func TestLoadYAMLDocs_EmptyDocumentsSkipped(t *testing.T) {
	dir := t.TempDir()
	content := `---
---
apiVersion: v1
kind: Pod
metadata:
  name: test
---
---
`
	path := writeTestFile(t, dir, "empty_docs.yaml", content)

	docs, err := LoadYAMLDocs(path)
	if err != nil {
		t.Fatalf("LoadYAMLDocs() error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("got %d docs, want 1 (empty docs should be skipped)", len(docs))
	}
	if docs[0]["kind"] != "Pod" {
		t.Errorf("kind = %v, want Pod", docs[0]["kind"])
	}
}

func TestLoadYAMLDocs_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "empty.yaml", "")

	docs, err := LoadYAMLDocs(path)
	if err != nil {
		t.Fatalf("LoadYAMLDocs() error: %v", err)
	}
	if len(docs) != 0 {
		t.Errorf("got %d docs, want 0", len(docs))
	}
}

func TestLoadYAMLDocs_OnlySeparators(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "seps.yaml", "---\n---\n---\n")

	docs, err := LoadYAMLDocs(path)
	if err != nil {
		t.Fatalf("LoadYAMLDocs() error: %v", err)
	}
	if len(docs) != 0 {
		t.Errorf("got %d docs, want 0", len(docs))
	}
}

func TestLoadYAMLDocs_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "bad.yaml", "{{{{ not valid yaml")

	_, err := LoadYAMLDocs(path)
	if err == nil {
		t.Error("LoadYAMLDocs() expected error for malformed YAML, got nil")
	}
}

func TestLoadYAMLDocs_FileNotFound(t *testing.T) {
	_, err := LoadYAMLDocs("/nonexistent/path/file.yaml")
	if err == nil {
		t.Error("LoadYAMLDocs() expected error for nonexistent file, got nil")
	}
}

func TestLoadYAMLDocs_NestedStructure(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  labels:
    app: myapp
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.21
        ports:
        - containerPort: 80
        env:
        - name: FOO
          value: bar
`
	path := writeTestFile(t, dir, "nested.yaml", content)

	docs, err := LoadYAMLDocs(path)
	if err != nil {
		t.Fatalf("LoadYAMLDocs() error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("got %d docs, want 1", len(docs))
	}

	// Verify nested structure preserved
	spec, ok := docs[0]["spec"].(map[string]interface{})
	if !ok {
		t.Fatal("spec is not a map")
	}
	replicas, ok := spec["replicas"].(int)
	if !ok || replicas != 3 {
		t.Errorf("spec.replicas = %v, want 3", spec["replicas"])
	}
}

func TestLoadYAMLDocs_BooleanValues(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  hostPID: true
  hostIPC: false
`
	path := writeTestFile(t, dir, "bools.yaml", content)

	docs, err := LoadYAMLDocs(path)
	if err != nil {
		t.Fatalf("LoadYAMLDocs() error: %v", err)
	}

	spec, _ := docs[0]["spec"].(map[string]interface{})
	if spec["hostPID"] != true {
		t.Errorf("hostPID = %v, want true", spec["hostPID"])
	}
	if spec["hostIPC"] != false {
		t.Errorf("hostIPC = %v, want false", spec["hostIPC"])
	}
}

func TestLoadYAMLDocs_PermissionDenied(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "noperm.yaml", "key: value")
	os.Chmod(path, 0o000)
	t.Cleanup(func() { os.Chmod(path, 0o644) })

	_, err := LoadYAMLDocs(path)
	if err == nil {
		t.Error("LoadYAMLDocs() expected error for permission denied, got nil")
	}
}

// ---------- LoadYAMLDocsFromReader ----------

func TestLoadYAMLDocsFromReader_SingleDocument(t *testing.T) {
	input := `apiVersion: v1
kind: Service
metadata:
  name: svc
spec:
  type: ClusterIP
`
	docs, err := LoadYAMLDocsFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadYAMLDocsFromReader() error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("got %d docs, want 1", len(docs))
	}
	if docs[0]["kind"] != "Service" {
		t.Errorf("kind = %v, want Service", docs[0]["kind"])
	}
}

func TestLoadYAMLDocsFromReader_MultiDocument(t *testing.T) {
	input := `apiVersion: v1
kind: Namespace
metadata:
  name: prod
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
`
	docs, err := LoadYAMLDocsFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadYAMLDocsFromReader() error: %v", err)
	}
	if len(docs) != 3 {
		t.Fatalf("got %d docs, want 3", len(docs))
	}
	if docs[0]["kind"] != "Namespace" {
		t.Errorf("doc[0].kind = %v, want Namespace", docs[0]["kind"])
	}
	if docs[2]["kind"] != "NetworkPolicy" {
		t.Errorf("doc[2].kind = %v, want NetworkPolicy", docs[2]["kind"])
	}
}

func TestLoadYAMLDocsFromReader_EmptyInput(t *testing.T) {
	docs, err := LoadYAMLDocsFromReader(strings.NewReader(""))
	if err != nil {
		t.Fatalf("LoadYAMLDocsFromReader() error: %v", err)
	}
	if len(docs) != 0 {
		t.Errorf("got %d docs, want 0", len(docs))
	}
}

func TestLoadYAMLDocsFromReader_EmptyDocsSkipped(t *testing.T) {
	input := "---\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: x\n---\n"
	docs, err := LoadYAMLDocsFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadYAMLDocsFromReader() error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("got %d docs, want 1", len(docs))
	}
}

func TestLoadYAMLDocsFromReader_MalformedYAML(t *testing.T) {
	_, err := LoadYAMLDocsFromReader(strings.NewReader("{{{{ invalid"))
	if err == nil {
		t.Error("LoadYAMLDocsFromReader() expected error for malformed YAML, got nil")
	}
}

func TestLoadYAMLDocsFromReader_MalformedAfterValid(t *testing.T) {
	input := `apiVersion: v1
kind: ConfigMap
metadata:
  name: ok
---
{{{{ bad yaml
`
	_, err := LoadYAMLDocsFromReader(strings.NewReader(input))
	if err == nil {
		t.Error("LoadYAMLDocsFromReader() expected error when second doc is malformed, got nil")
	}
}

func TestLoadYAMLDocsFromReader_ListValues(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: test
spec:
  containers:
  - name: c1
    image: img1
  - name: c2
    image: img2
`
	docs, err := LoadYAMLDocsFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadYAMLDocsFromReader() error: %v", err)
	}

	spec, _ := docs[0]["spec"].(map[string]interface{})
	containers, ok := spec["containers"].([]interface{})
	if !ok {
		t.Fatal("containers is not a slice")
	}
	if len(containers) != 2 {
		t.Errorf("got %d containers, want 2", len(containers))
	}
}

func TestLoadYAMLDocsFromReader_NullValues(t *testing.T) {
	input := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
data:
  key1: ~
  key2: null
  key3: value
`
	docs, err := LoadYAMLDocsFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadYAMLDocsFromReader() error: %v", err)
	}

	data, _ := docs[0]["data"].(map[string]interface{})
	if data["key1"] != nil {
		t.Errorf("key1 = %v, want nil", data["key1"])
	}
	if data["key2"] != nil {
		t.Errorf("key2 = %v, want nil", data["key2"])
	}
	if data["key3"] != "value" {
		t.Errorf("key3 = %v, want 'value'", data["key3"])
	}
}

func TestLoadYAMLDocsFromReader_NumericValues(t *testing.T) {
	input := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
data:
  replicas: 3
  ratio: 1.5
`
	docs, err := LoadYAMLDocsFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadYAMLDocsFromReader() error: %v", err)
	}

	data, _ := docs[0]["data"].(map[string]interface{})
	if data["replicas"] != 3 {
		t.Errorf("replicas = %v (%T), want 3", data["replicas"], data["replicas"])
	}
	if data["ratio"] != 1.5 {
		t.Errorf("ratio = %v (%T), want 1.5", data["ratio"], data["ratio"])
	}
}

func TestLoadYAMLDocsFromReader_MultilineString(t *testing.T) {
	input := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
data:
  script: |
    #!/bin/bash
    echo "hello"
    exit 0
`
	docs, err := LoadYAMLDocsFromReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadYAMLDocsFromReader() error: %v", err)
	}

	data, _ := docs[0]["data"].(map[string]interface{})
	script, ok := data["script"].(string)
	if !ok {
		t.Fatal("script is not a string")
	}
	if !strings.Contains(script, "echo") {
		t.Errorf("script does not contain 'echo': %q", script)
	}
}

func TestLoadYAMLDocsFromReader_LargeDocument(t *testing.T) {
	// Build a doc with many unique keys to verify no issues with larger content
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: large\ndata:\n")
	for i := 0; i < 100; i++ {
		b.WriteString("  key" + strings.Repeat("x", 5) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ": value\n")
	}

	docs, err := LoadYAMLDocsFromReader(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("LoadYAMLDocsFromReader() error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("got %d docs, want 1", len(docs))
	}
}

// ---------- test helpers ----------

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
	return path
}
