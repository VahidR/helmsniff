package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- isYAML ----------

func TestIsYAML(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"deployment.yaml", true},
		{"service.yml", true},
		{"chart.YAML", true},
		{"values.YML", true},
		{"readme.md", false},
		{"config.json", false},
		{"noext", false},
		{"path/to/file.yaml", true},
		{"path/to/file.txt", false},
		{".yaml", true},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := isYAML(tc.path); got != tc.want {
				t.Errorf("isYAML(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// ---------- HasNetworkPolicy ----------

func TestHasNetworkPolicy_Found(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
`
	writeFile(t, dir, "netpol.yaml", content)

	if !HasNetworkPolicy(dir) {
		t.Error("HasNetworkPolicy() = false, want true")
	}
}

func TestHasNetworkPolicy_NotFound(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
`
	writeFile(t, dir, "deploy.yaml", content)

	if HasNetworkPolicy(dir) {
		t.Error("HasNetworkPolicy() = true, want false")
	}
}

func TestHasNetworkPolicy_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: networking.k8s.io/v1
kind: networkpolicy
metadata:
  name: test
`
	writeFile(t, dir, "np.yaml", content)

	if !HasNetworkPolicy(dir) {
		t.Error("HasNetworkPolicy() = false for lowercase 'networkpolicy', want true")
	}
}

func TestHasNetworkPolicy_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	if HasNetworkPolicy(dir) {
		t.Error("HasNetworkPolicy() = true for empty dir, want false")
	}
}

func TestHasNetworkPolicy_NonYAMLFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test
`
	writeFile(t, dir, "netpol.json", content) // Not a YAML extension

	if HasNetworkPolicy(dir) {
		t.Error("HasNetworkPolicy() = true for non-YAML file, want false")
	}
}

func TestHasNetworkPolicy_MultiDoc(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: Service
metadata:
  name: svc
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
`
	writeFile(t, dir, "multi.yaml", content)

	if !HasNetworkPolicy(dir) {
		t.Error("HasNetworkPolicy() = false for multi-doc with NetworkPolicy, want true")
	}
}

func TestHasNetworkPolicy_NestedDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "templates")
	os.MkdirAll(sub, 0o755)

	content := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
`
	writeFile(t, sub, "netpol.yaml", content)

	if !HasNetworkPolicy(dir) {
		t.Error("HasNetworkPolicy() = false for nested dir, want true")
	}
}

func TestHasNetworkPolicy_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bad.yaml", "{{{{ not valid yaml")

	// Should not panic and should return false
	if HasNetworkPolicy(dir) {
		t.Error("HasNetworkPolicy() = true for malformed YAML, want false")
	}
}

// ---------- AnalyzeFile ----------

func TestAnalyzeFile_Deployment(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: production
  labels:
    app.kubernetes.io/managed-by: Helm
    helm.sh/chart: mychart-1.0.0
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.21
        resources:
          limits:
            cpu: 100m
            memory: 128Mi
        securityContext:
          runAsNonRoot: true
`
	writeFile(t, dir, "deploy.yaml", content)
	path := filepath.Join(dir, "deploy.yaml")

	rows, err := AnalyzeFile(path, dir, true)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}

	r := rows[0]
	assertEqual(t, "K8sStatus", boolToInt(r.K8sStatus), 1)
	assertEqual(t, "HelmStatus", boolToInt(r.HelmStatus), 1)
	assertEqual(t, "NoSecuContext", r.NoSecuContext, 0)
	assertEqual(t, "NoReso", r.NoReso, 0)
	assertEqual(t, "NoRollingUpdate", r.NoRollingUpdate, 0)
	assertEqual(t, "NoDefaultNSpace", r.NoDefaultNSpace, 0)
	assertEqual(t, "NoNetworkPolicy", r.NoNetworkPolicy, 0)
	assertEqual(t, "InsecureHTTP", r.InsecureHTTP, 0)
}

func TestAnalyzeFile_Violations(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
spec:
  template:
    spec:
      hostPID: true
      hostIPC: true
      hostNetwork: true
      hostAliases:
      - ip: "1.2.3.4"
        hostnames:
        - "evil.com"
      containers:
      - name: app
        image: nginx
        env:
        - name: ENDPOINT
          value: "http://insecure-api.example.com"
        securityContext:
          allowPrivilegeEscalation: true
          capabilities:
            add:
            - SYS_ADMIN
            - SYS_MODULE
          seccompProfile:
            type: Unconfined
      volumes:
      - name: docker
        hostPath:
          path: /var/run/docker.sock
`
	writeFile(t, dir, "insecure.yaml", content)
	path := filepath.Join(dir, "insecure.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}

	r := rows[0]
	assertEqual(t, "TrueHostPID", r.TrueHostPID, 1)
	assertEqual(t, "TrueHostIPC", r.TrueHostIPC, 1)
	assertEqual(t, "TrueHostNet", r.TrueHostNet, 1)
	assertEqual(t, "HostAlias", r.HostAlias, 1)
	assertEqual(t, "InsecureHTTP", r.InsecureHTTP, 1)
	assertEqual(t, "AllowPrivi", r.AllowPrivi, 1)
	assertEqual(t, "CapSysAdmin", r.CapSysAdmin, 1)
	assertEqual(t, "CapSysModule", r.CapSysModule, 1)
	assertEqual(t, "SeccompUnconfined", r.SeccompUnconfined, 1)
	assertEqual(t, "DockerSockPath", r.DockerSockPath, 1)
	assertEqual(t, "NoNetworkPolicy", r.NoNetworkPolicy, 1)
	assertEqual(t, "NoRollingUpdate", r.NoRollingUpdate, 1)
	assertEqual(t, "NoDefaultNSpace", r.NoDefaultNSpace, 1)
	assertEqual(t, "NoReso", r.NoReso, 1)
}

func TestAnalyzeFile_Secret(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  namespace: default
data:
  password: cGFzc3dvcmQ=
`
	writeFile(t, dir, "secret.yaml", content)
	path := filepath.Join(dir, "secret.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}

	assertEqual(t, "WithinManifestSecret", rows[0].WithinManifestSecret, 1)
}

func TestAnalyzeFile_SecretStringData(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  namespace: default
stringData:
  token: abc123
`
	writeFile(t, dir, "secret.yaml", content)
	path := filepath.Join(dir, "secret.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	assertEqual(t, "WithinManifestSecret", rows[0].WithinManifestSecret, 1)
}

func TestAnalyzeFile_SecretEmptyData(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: Secret
metadata:
  name: empty-secret
  namespace: default
data: {}
`
	writeFile(t, dir, "secret.yaml", content)
	path := filepath.Join(dir, "secret.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	assertEqual(t, "WithinManifestSecret", rows[0].WithinManifestSecret, 0)
}

func TestAnalyzeFile_MultiDocument(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: Service
metadata:
  name: svc
  namespace: prod
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
  template:
    spec:
      containers:
      - name: app
        image: nginx
        resources:
          limits:
            cpu: 100m
        securityContext:
          runAsNonRoot: true
`
	writeFile(t, dir, "multi.yaml", content)
	path := filepath.Join(dir, "multi.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}

	// Service - non-workload, pod-level checks should be 0
	assertEqual(t, "Service.NoSecuContext", rows[0].NoSecuContext, 0)
	assertEqual(t, "Service.NoReso", rows[0].NoReso, 0)
	assertEqual(t, "Service.TrueHostPID", rows[0].TrueHostPID, 0)

	// Deployment
	assertEqual(t, "Deployment.K8sStatus", boolToInt(rows[1].K8sStatus), 1)
}

func TestAnalyzeFile_Pod(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  containers:
  - name: app
    image: busybox
    resources:
      requests:
        memory: 64Mi
    securityContext:
      runAsNonRoot: true
`
	writeFile(t, dir, "pod.yaml", content)
	path := filepath.Join(dir, "pod.yaml")

	rows, err := AnalyzeFile(path, dir, true)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}

	r := rows[0]
	assertEqual(t, "K8sStatus", boolToInt(r.K8sStatus), 1)
	assertEqual(t, "NoSecuContext", r.NoSecuContext, 0)
	assertEqual(t, "NoReso", r.NoReso, 0)
	assertEqual(t, "NoNetworkPolicy", r.NoNetworkPolicy, 0)
}

func TestAnalyzeFile_NonWorkloadKind(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
  namespace: default
data:
  key: value
`
	writeFile(t, dir, "cm.yaml", content)
	path := filepath.Join(dir, "cm.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	r := rows[0]
	// Non-workload: all pod-level checks return 0
	assertEqual(t, "NoSecuContext", r.NoSecuContext, 0)
	assertEqual(t, "NoReso", r.NoReso, 0)
	assertEqual(t, "TrueHostPID", r.TrueHostPID, 0)
	assertEqual(t, "TrueHostIPC", r.TrueHostIPC, 0)
	assertEqual(t, "TrueHostNet", r.TrueHostNet, 0)
	assertEqual(t, "DockerSockPath", r.DockerSockPath, 0)
	assertEqual(t, "CapSysAdmin", r.CapSysAdmin, 0)
	assertEqual(t, "HostAlias", r.HostAlias, 0)
}

func TestAnalyzeFile_InvalidPath(t *testing.T) {
	_, err := AnalyzeFile("/nonexistent/path.yaml", "/nonexistent", false)
	if err == nil {
		t.Error("AnalyzeFile() expected error for nonexistent file, got nil")
	}
}

func TestAnalyzeFile_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "bad.yaml", "{{{{ invalid yaml content")
	path := filepath.Join(dir, "bad.yaml")

	_, err := AnalyzeFile(path, dir, false)
	if err == nil {
		t.Error("AnalyzeFile() expected error for malformed YAML, got nil")
	}
}

func TestAnalyzeFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "empty.yaml", "")
	path := filepath.Join(dir, "empty.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("got %d rows, want 0 for empty file", len(rows))
	}
}

func TestAnalyzeFile_OnlySeparators(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "seps.yaml", "---\n---\n---\n")
	path := filepath.Join(dir, "seps.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("got %d rows, want 0 for only separators", len(rows))
	}
}

func TestAnalyzeFile_RecreateStrategy(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  strategy:
    type: Recreate
  template:
    spec:
      containers:
      - name: app
        image: nginx
        resources:
          limits:
            cpu: 100m
        securityContext:
          runAsNonRoot: true
`
	writeFile(t, dir, "deploy.yaml", content)
	path := filepath.Join(dir, "deploy.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	assertEqual(t, "NoRollingUpdate", rows[0].NoRollingUpdate, 1)
}

func TestAnalyzeFile_StatefulSet(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
  namespace: data
spec:
  template:
    spec:
      containers:
      - name: postgres
        image: postgres:14
        resources:
          limits:
            memory: 1Gi
        securityContext:
          runAsUser: 999
`
	writeFile(t, dir, "sts.yaml", content)
	path := filepath.Join(dir, "sts.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	r := rows[0]
	assertEqual(t, "K8sStatus", boolToInt(r.K8sStatus), 1)
	assertEqual(t, "NoSecuContext", r.NoSecuContext, 0)
	assertEqual(t, "NoReso", r.NoReso, 0)
	assertEqual(t, "NoRollingUpdate", r.NoRollingUpdate, 0) // Not a Deployment
}

func TestAnalyzeFile_DaemonSet(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: logger
  namespace: monitoring
spec:
  template:
    spec:
      containers:
      - name: fluentd
        image: fluentd:latest
`
	writeFile(t, dir, "ds.yaml", content)
	path := filepath.Join(dir, "ds.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	r := rows[0]
	assertEqual(t, "NoSecuContext", r.NoSecuContext, 1)
	assertEqual(t, "NoReso", r.NoReso, 1)
}

func TestAnalyzeFile_CronJob(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
  namespace: ops
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: backup:latest
            resources:
              limits:
                cpu: 500m
            securityContext:
              runAsNonRoot: true
`
	writeFile(t, dir, "cron.yaml", content)
	path := filepath.Join(dir, "cron.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	r := rows[0]
	assertEqual(t, "K8sStatus", boolToInt(r.K8sStatus), 1)
}

func TestAnalyzeFile_InitContainers(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
  template:
    spec:
      initContainers:
      - name: init
        image: busybox
      containers:
      - name: app
        image: nginx
        resources:
          limits:
            cpu: 100m
        securityContext:
          runAsNonRoot: true
`
	writeFile(t, dir, "init.yaml", content)
	path := filepath.Join(dir, "init.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	r := rows[0]
	// initContainer lacks resources
	assertEqual(t, "NoReso", r.NoReso, 1)
}

func TestAnalyzeFile_PathCleaning(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
`
	writeFile(t, dir, "test.yaml", content)
	// Use a path with redundant separators
	path := filepath.Join(dir, ".", "test.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	// YAMLFullPath should be cleaned
	if strings.Contains(rows[0].YAMLFullPath, "/.") {
		t.Errorf("YAMLFullPath not cleaned: %s", rows[0].YAMLFullPath)
	}
}

func TestAnalyzeFile_RowMetadata(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
`
	writeFile(t, dir, "test.yaml", content)
	path := filepath.Join(dir, "test.yaml")

	rows, err := AnalyzeFile(path, "/charts/mychart", false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	if rows[0].Dir != "/charts/mychart" {
		t.Errorf("Dir = %q, want %q", rows[0].Dir, "/charts/mychart")
	}
	if rows[0].YAMLFullPath != filepath.Clean(path) {
		t.Errorf("YAMLFullPath = %q, want %q", rows[0].YAMLFullPath, filepath.Clean(path))
	}
}

func TestAnalyzeFile_NoHelmLabels(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: Service
metadata:
  name: svc
  labels:
    app: myapp
`
	writeFile(t, dir, "svc.yaml", content)
	path := filepath.Join(dir, "svc.yaml")

	rows, err := AnalyzeFile(path, dir, false)
	if err != nil {
		t.Fatalf("AnalyzeFile() error: %v", err)
	}

	if rows[0].HelmStatus {
		t.Error("HelmStatus = true, want false for non-Helm resource")
	}
}

func TestAnalyzeFile_HasNPFlag(t *testing.T) {
	dir := t.TempDir()
	content := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
`
	writeFile(t, dir, "cm.yaml", content)
	path := filepath.Join(dir, "cm.yaml")

	rowsWithNP, _ := AnalyzeFile(path, dir, true)
	rowsWithoutNP, _ := AnalyzeFile(path, dir, false)

	assertEqual(t, "hasNP=true", rowsWithNP[0].NoNetworkPolicy, 0)
	assertEqual(t, "hasNP=false", rowsWithoutNP[0].NoNetworkPolicy, 1)
}

// ---------- AnalyzeReader ----------

func TestAnalyzeReader_SingleDoc(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
  template:
    spec:
      containers:
      - name: app
        image: nginx
        resources:
          limits:
            cpu: 100m
        securityContext:
          runAsNonRoot: true
`
	rows, err := AnalyzeReader(strings.NewReader(input), "stdin")
	if err != nil {
		t.Fatalf("AnalyzeReader() error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}

	r := rows[0]
	if r.Dir != "stdin" {
		t.Errorf("Dir = %q, want %q", r.Dir, "stdin")
	}
	if r.YAMLFullPath != "stdin" {
		t.Errorf("YAMLFullPath = %q, want %q", r.YAMLFullPath, "stdin")
	}
	assertEqual(t, "K8sStatus", boolToInt(r.K8sStatus), 1)
	assertEqual(t, "NoNetworkPolicy", r.NoNetworkPolicy, 1)
}

func TestAnalyzeReader_WithNetworkPolicy(t *testing.T) {
	input := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
  template:
    spec:
      containers:
      - name: app
        image: nginx
        resources:
          limits:
            cpu: 100m
        securityContext:
          runAsNonRoot: true
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: default
spec:
  podSelector: {}
`
	rows, err := AnalyzeReader(strings.NewReader(input), "pipe")
	if err != nil {
		t.Fatalf("AnalyzeReader() error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}

	// All rows should have NoNetworkPolicy = 0 because NP exists in stream
	for i, r := range rows {
		assertEqual(t, "row["+string(rune('0'+i))+"].NoNetworkPolicy", r.NoNetworkPolicy, 0)
	}
}

func TestAnalyzeReader_Empty(t *testing.T) {
	rows, err := AnalyzeReader(strings.NewReader(""), "empty")
	if err != nil {
		t.Fatalf("AnalyzeReader() error: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("got %d rows, want 0", len(rows))
	}
}

func TestAnalyzeReader_MalformedYAML(t *testing.T) {
	_, err := AnalyzeReader(strings.NewReader("{{{{ bad yaml"), "bad")
	if err == nil {
		t.Error("AnalyzeReader() expected error for malformed YAML, got nil")
	}
}

func TestAnalyzeReader_MultipleViolations(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: danger-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: evil
    image: evil:latest
    securityContext:
      allowPrivilegeEscalation: true
      capabilities:
        add:
        - SYS_ADMIN
  volumes:
  - name: docker
    hostPath:
      path: /var/run/docker.sock
`
	rows, err := AnalyzeReader(strings.NewReader(input), "test")
	if err != nil {
		t.Fatalf("AnalyzeReader() error: %v", err)
	}

	r := rows[0]
	assertEqual(t, "TrueHostPID", r.TrueHostPID, 1)
	assertEqual(t, "TrueHostNet", r.TrueHostNet, 1)
	assertEqual(t, "AllowPrivi", r.AllowPrivi, 1)
	assertEqual(t, "CapSysAdmin", r.CapSysAdmin, 1)
	assertEqual(t, "DockerSockPath", r.DockerSockPath, 1)
	assertEqual(t, "NoReso", r.NoReso, 1)
	assertEqual(t, "NoDefaultNSpace", r.NoDefaultNSpace, 1)
}

func TestAnalyzeReader_PodSecurityContext(t *testing.T) {
	input := `apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: prod
spec:
  securityContext:
    runAsNonRoot: true
    fsGroup: 1000
  containers:
  - name: app
    image: app:latest
    resources:
      limits:
        cpu: 100m
`
	rows, err := AnalyzeReader(strings.NewReader(input), "test")
	if err != nil {
		t.Fatalf("AnalyzeReader() error: %v", err)
	}

	// Pod-level securityContext suffices
	assertEqual(t, "NoSecuContext", rows[0].NoSecuContext, 0)
}

func TestAnalyzeReader_HelmChartLabel(t *testing.T) {
	input := `apiVersion: v1
kind: Service
metadata:
  name: svc
  namespace: default
  labels:
    helm.sh/chart: myapp-0.1.0
`
	rows, err := AnalyzeReader(strings.NewReader(input), "test")
	if err != nil {
		t.Fatalf("AnalyzeReader() error: %v", err)
	}

	if !rows[0].HelmStatus {
		t.Error("HelmStatus = false, want true for helm.sh/chart label")
	}
}

func TestAnalyzeReader_NoAPIVersion(t *testing.T) {
	input := `kind: ConfigMap
metadata:
  name: test
data:
  key: value
`
	rows, err := AnalyzeReader(strings.NewReader(input), "test")
	if err != nil {
		t.Fatalf("AnalyzeReader() error: %v", err)
	}

	if rows[0].K8sStatus {
		t.Error("K8sStatus = true, want false when apiVersion is missing")
	}
}

func TestAnalyzeReader_NoKind(t *testing.T) {
	input := `apiVersion: v1
metadata:
  name: test
data:
  key: value
`
	rows, err := AnalyzeReader(strings.NewReader(input), "test")
	if err != nil {
		t.Fatalf("AnalyzeReader() error: %v", err)
	}

	if rows[0].K8sStatus {
		t.Error("K8sStatus = true, want false when kind is missing")
	}
}

func TestAnalyzeReader_InsecureHTTPInKey(t *testing.T) {
	input := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
  namespace: default
data:
  http://example.com: value
`
	rows, err := AnalyzeReader(strings.NewReader(input), "test")
	if err != nil {
		t.Fatalf("AnalyzeReader() error: %v", err)
	}

	assertEqual(t, "InsecureHTTP", rows[0].InsecureHTTP, 1)
}

// ---------- helpers ----------

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func assertEqual(t *testing.T, field string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", field, got, want)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
