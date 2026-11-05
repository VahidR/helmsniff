package scanner

import (
	"testing"
)

// ---------- asMap ----------

func TestAsMap(t *testing.T) {
	tests := []struct {
		name   string
		input  interface{}
		isNil  bool
		length int
	}{
		{"valid map", map[string]interface{}{"a": 1}, false, 1},
		{"empty map", map[string]interface{}{}, false, 0},
		{"nil", nil, true, 0},
		{"string", "hello", true, 0},
		{"int", 42, true, 0},
		{"slice", []interface{}{1, 2}, true, 0},
		{"bool", true, true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := asMap(tc.input)
			if tc.isNil && got != nil {
				t.Errorf("asMap(%v) = %v, want nil", tc.input, got)
			}
			if !tc.isNil {
				if got == nil {
					t.Fatalf("asMap(%v) = nil, want non-nil", tc.input)
				}
				if len(got) != tc.length {
					t.Errorf("len(asMap(%v)) = %d, want %d", tc.input, len(got), tc.length)
				}
			}
		})
	}
}

// ---------- asSlice ----------

func TestAsSlice(t *testing.T) {
	tests := []struct {
		name   string
		input  interface{}
		isNil  bool
		length int
	}{
		{"valid slice", []interface{}{1, "a"}, false, 2},
		{"empty slice", []interface{}{}, false, 0},
		{"nil", nil, true, 0},
		{"string", "hello", true, 0},
		{"map", map[string]interface{}{}, true, 0},
		{"int", 123, true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := asSlice(tc.input)
			if tc.isNil && got != nil {
				t.Errorf("asSlice(%v) = %v, want nil", tc.input, got)
			}
			if !tc.isNil {
				if got == nil {
					t.Fatalf("asSlice(%v) = nil, want non-nil", tc.input)
				}
				if len(got) != tc.length {
					t.Errorf("len(asSlice(%v)) = %d, want %d", tc.input, len(got), tc.length)
				}
			}
		})
	}
}

// ---------- str ----------

func TestStr(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  string
	}{
		{"string", "hello", "hello"},
		{"empty string", "", ""},
		{"nil", nil, ""},
		{"int", 42, ""},
		{"bool", true, ""},
		{"map", map[string]interface{}{}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := str(tc.input); got != tc.want {
				t.Errorf("str(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------- boolVal ----------

func TestBoolVal(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  bool
	}{
		{"true", true, true},
		{"false", false, false},
		{"nil", nil, false},
		{"string true", "true", false},
		{"int 1", 1, false},
		{"string", "hello", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := boolVal(tc.input); got != tc.want {
				t.Errorf("boolVal(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ---------- hasAPIVersionAndKind ----------

func TestHasAPIVersionAndKind(t *testing.T) {
	tests := []struct {
		name string
		doc  map[string]interface{}
		want bool
	}{
		{
			"both present",
			map[string]interface{}{"apiVersion": "v1", "kind": "Pod"},
			true,
		},
		{
			"missing apiVersion",
			map[string]interface{}{"kind": "Pod"},
			false,
		},
		{
			"missing kind",
			map[string]interface{}{"apiVersion": "v1"},
			false,
		},
		{
			"both missing",
			map[string]interface{}{"metadata": map[string]interface{}{}},
			false,
		},
		{
			"empty apiVersion",
			map[string]interface{}{"apiVersion": "", "kind": "Pod"},
			false,
		},
		{
			"empty kind",
			map[string]interface{}{"apiVersion": "v1", "kind": ""},
			false,
		},
		{
			"non-string apiVersion",
			map[string]interface{}{"apiVersion": 1, "kind": "Pod"},
			false,
		},
		{
			"empty doc",
			map[string]interface{}{},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasAPIVersionAndKind(tc.doc); got != tc.want {
				t.Errorf("hasAPIVersionAndKind() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------- detectHelmManaged ----------

func TestDetectHelmManaged(t *testing.T) {
	tests := []struct {
		name string
		doc  map[string]interface{}
		want bool
	}{
		{
			"managed-by Helm",
			map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"app.kubernetes.io/managed-by": "Helm",
					},
				},
			},
			true,
		},
		{
			"helm.sh/chart label present",
			map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"helm.sh/chart": "myapp-1.0.0",
					},
				},
			},
			true,
		},
		{
			"both helm labels",
			map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"app.kubernetes.io/managed-by": "Helm",
						"helm.sh/chart":                "myapp-1.0.0",
					},
				},
			},
			true,
		},
		{
			"managed-by not Helm",
			map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"app.kubernetes.io/managed-by": "kustomize",
					},
				},
			},
			false,
		},
		{
			"no labels",
			map[string]interface{}{
				"metadata": map[string]interface{}{},
			},
			false,
		},
		{
			"no metadata",
			map[string]interface{}{"kind": "Pod"},
			false,
		},
		{
			"labels not a map",
			map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": "invalid",
				},
			},
			false,
		},
		{
			"metadata not a map",
			map[string]interface{}{
				"metadata": "invalid",
			},
			false,
		},
		{
			"empty doc",
			map[string]interface{}{},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectHelmManaged(tc.doc); got != tc.want {
				t.Errorf("detectHelmManaged() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------- isWorkloadKind ----------

func TestIsWorkloadKind(t *testing.T) {
	workloads := []string{
		"Deployment", "deployment", "DEPLOYMENT",
		"StatefulSet", "statefulset",
		"DaemonSet", "daemonset",
		"Job", "job",
		"CronJob", "cronjob",
		"ReplicaSet", "replicaset",
		"ReplicationController", "replicationcontroller",
		"Pod", "pod",
	}
	for _, k := range workloads {
		t.Run(k, func(t *testing.T) {
			if !isWorkloadKind(k) {
				t.Errorf("isWorkloadKind(%q) = false, want true", k)
			}
		})
	}

	nonWorkloads := []string{
		"Service", "ConfigMap", "Secret", "NetworkPolicy",
		"Ingress", "PersistentVolumeClaim", "Namespace",
		"ServiceAccount", "ClusterRole", "",
	}
	for _, k := range nonWorkloads {
		t.Run("non_"+k, func(t *testing.T) {
			if isWorkloadKind(k) {
				t.Errorf("isWorkloadKind(%q) = true, want false", k)
			}
		})
	}
}

// ---------- countSecretsInDoc ----------

func TestCountSecretsInDoc(t *testing.T) {
	tests := []struct {
		name string
		doc  map[string]interface{}
		want int
	}{
		{
			"secret with data",
			map[string]interface{}{
				"kind": "Secret",
				"data": map[string]interface{}{"key": "dmFsdWU="},
			},
			1,
		},
		{
			"secret with stringData",
			map[string]interface{}{
				"kind":       "Secret",
				"stringData": map[string]interface{}{"key": "value"},
			},
			1,
		},
		{
			"secret with both",
			map[string]interface{}{
				"kind":       "Secret",
				"data":       map[string]interface{}{"a": "b"},
				"stringData": map[string]interface{}{"c": "d"},
			},
			1,
		},
		{
			"secret with empty data",
			map[string]interface{}{
				"kind": "Secret",
				"data": map[string]interface{}{},
			},
			0,
		},
		{
			"secret with no data field",
			map[string]interface{}{
				"kind": "Secret",
			},
			0,
		},
		{
			"secret case insensitive",
			map[string]interface{}{
				"kind": "secret",
				"data": map[string]interface{}{"key": "val"},
			},
			1,
		},
		{
			"not a secret",
			map[string]interface{}{
				"kind": "ConfigMap",
				"data": map[string]interface{}{"key": "value"},
			},
			0,
		},
		{
			"empty doc",
			map[string]interface{}{},
			0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := countSecretsInDoc(tc.doc); got != tc.want {
				t.Errorf("countSecretsInDoc() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------- hasInsecureHTTP ----------

func TestHasInsecureHTTP(t *testing.T) {
	tests := []struct {
		name string
		doc  map[string]interface{}
		want int
	}{
		{
			"http in value",
			map[string]interface{}{
				"data": map[string]interface{}{
					"url": "http://example.com",
				},
			},
			1,
		},
		{
			"https only",
			map[string]interface{}{
				"data": map[string]interface{}{
					"url": "https://example.com",
				},
			},
			0,
		},
		{
			"http in key",
			map[string]interface{}{
				"http://key": "value",
			},
			1,
		},
		{
			"http in nested slice",
			map[string]interface{}{
				"items": []interface{}{
					"https://safe.com",
					"http://insecure.com",
				},
			},
			1,
		},
		{
			"http deeply nested",
			map[string]interface{}{
				"level1": map[string]interface{}{
					"level2": map[string]interface{}{
						"level3": "http://deep.com",
					},
				},
			},
			1,
		},
		{
			"case insensitive HTTP",
			map[string]interface{}{
				"url": "HTTP://EXAMPLE.COM",
			},
			1,
		},
		{
			"no http anywhere",
			map[string]interface{}{
				"name": "myapp",
				"port": 8080,
			},
			0,
		},
		{
			"empty doc",
			map[string]interface{}{},
			0,
		},
		{
			"nil values",
			map[string]interface{}{
				"key": nil,
			},
			0,
		},
		{
			"http in slice of maps",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"env": []interface{}{
							map[string]interface{}{
								"value": "http://api.local",
							},
						},
					},
				},
			},
			1,
		},
		{
			"non-string types only",
			map[string]interface{}{
				"replicas": 3,
				"enabled":  true,
			},
			0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasInsecureHTTP(tc.doc); got != tc.want {
				t.Errorf("hasInsecureHTTP() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------- containersFromSpec ----------

func TestContainersFromSpec(t *testing.T) {
	tests := []struct {
		name  string
		spec  map[string]interface{}
		count int
	}{
		{
			"nil spec",
			nil,
			0,
		},
		{
			"containers only",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
					map[string]interface{}{"name": "sidecar"},
				},
			},
			2,
		},
		{
			"initContainers only",
			map[string]interface{}{
				"initContainers": []interface{}{
					map[string]interface{}{"name": "init"},
				},
			},
			1,
		},
		{
			"both containers and initContainers",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
				},
				"initContainers": []interface{}{
					map[string]interface{}{"name": "init"},
				},
			},
			2,
		},
		{
			"template.spec containers",
			map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{"name": "tmpl-app"},
						},
						"initContainers": []interface{}{
							map[string]interface{}{"name": "tmpl-init"},
						},
					},
				},
			},
			2,
		},
		{
			"both direct and template containers",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "direct"},
				},
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{"name": "tmpl"},
						},
					},
				},
			},
			2,
		},
		{
			"empty containers slice",
			map[string]interface{}{
				"containers": []interface{}{},
			},
			0,
		},
		{
			"no containers at all",
			map[string]interface{}{
				"serviceAccountName": "default",
			},
			0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := containersFromSpec(tc.spec)
			if len(got) != tc.count {
				t.Errorf("containersFromSpec() returned %d containers, want %d", len(got), tc.count)
			}
		})
	}
}

// ---------- podSpecFromDoc ----------

func TestPodSpecFromDoc(t *testing.T) {
	tests := []struct {
		name   string
		doc    map[string]interface{}
		isNil  bool
		hasKey string // a key expected in the returned spec
	}{
		{
			"Pod returns spec directly",
			map[string]interface{}{
				"kind": "Pod",
				"spec": map[string]interface{}{
					"containers": []interface{}{},
				},
			},
			false,
			"containers",
		},
		{
			"Deployment returns template.spec",
			map[string]interface{}{
				"kind": "Deployment",
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"hostPID": true,
						},
					},
				},
			},
			false,
			"hostPID",
		},
		{
			"StatefulSet returns template.spec",
			map[string]interface{}{
				"kind": "StatefulSet",
				"spec": map[string]interface{}{
					"template": map[string]interface{}{
						"spec": map[string]interface{}{
							"containers": []interface{}{},
						},
					},
				},
			},
			false,
			"containers",
		},
		{
			"Service returns nil",
			map[string]interface{}{
				"kind": "Service",
				"spec": map[string]interface{}{
					"ports": []interface{}{},
				},
			},
			true,
			"",
		},
		{
			"ConfigMap returns nil",
			map[string]interface{}{
				"kind": "ConfigMap",
				"data": map[string]interface{}{},
			},
			true,
			"",
		},
		{
			"no spec field",
			map[string]interface{}{
				"kind": "Deployment",
			},
			true,
			"",
		},
		{
			"Pod with nil spec",
			map[string]interface{}{
				"kind": "Pod",
				"spec": "not-a-map",
			},
			true,
			"",
		},
		{
			"Deployment with no template",
			map[string]interface{}{
				"kind": "Deployment",
				"spec": map[string]interface{}{
					"replicas": 3,
				},
			},
			true,
			"",
		},
		{
			"CronJob returns jobTemplate.spec.template.spec",
			map[string]interface{}{
				"kind": "CronJob",
				"spec": map[string]interface{}{
					"schedule": "0 2 * * *",
					"jobTemplate": map[string]interface{}{
						"spec": map[string]interface{}{
							"template": map[string]interface{}{
								"spec": map[string]interface{}{
									"hostPID": true,
								},
							},
						},
					},
				},
			},
			false,
			"hostPID",
		},
		{
			"CronJob with jobTemplate but no template",
			map[string]interface{}{
				"kind": "CronJob",
				"spec": map[string]interface{}{
					"jobTemplate": map[string]interface{}{
						"spec": map[string]interface{}{
							"backoffLimit": 3,
						},
					},
				},
			},
			true,
			"",
		},
		{
			"CronJob with non-map jobTemplate",
			map[string]interface{}{
				"kind": "CronJob",
				"spec": map[string]interface{}{
					"jobTemplate": "bad",
				},
			},
			true,
			"",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := podSpecFromDoc(tc.doc)
			if tc.isNil {
				if got != nil {
					t.Errorf("podSpecFromDoc() = %v, want nil", got)
				}
			} else {
				if got == nil {
					t.Fatal("podSpecFromDoc() = nil, want non-nil")
				}
				if tc.hasKey != "" {
					if _, ok := got[tc.hasKey]; !ok {
						t.Errorf("podSpecFromDoc() missing key %q", tc.hasKey)
					}
				}
			}
		})
	}
}

// ---------- lackSecurityContext ----------

func TestLackSecurityContext(t *testing.T) {
	tests := []struct {
		name string
		spec map[string]interface{}
		want int
	}{
		{
			"nil spec",
			nil,
			0,
		},
		{
			"pod-level securityContext present",
			map[string]interface{}{
				"securityContext": map[string]interface{}{"runAsNonRoot": true},
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
				},
			},
			0,
		},
		{
			"container-level securityContext present",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":            "app",
						"securityContext": map[string]interface{}{"runAsNonRoot": true},
					},
				},
			},
			0,
		},
		{
			"no securityContext anywhere",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
				},
			},
			1,
		},
		{
			"multiple containers one with securityContext",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
					map[string]interface{}{
						"name":            "sidecar",
						"securityContext": map[string]interface{}{"readOnlyRootFilesystem": true},
					},
				},
			},
			0,
		},
		{
			"multiple containers none with securityContext",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
					map[string]interface{}{"name": "sidecar"},
				},
			},
			1,
		},
		{
			"no containers",
			map[string]interface{}{
				"serviceAccountName": "default",
			},
			0,
		},
		{
			"empty containers slice",
			map[string]interface{}{
				"containers": []interface{}{},
			},
			0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lackSecurityContext(tc.spec); got != tc.want {
				t.Errorf("lackSecurityContext() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------- lackResources ----------

func TestLackResources(t *testing.T) {
	tests := []struct {
		name string
		spec map[string]interface{}
		want int
	}{
		{
			"nil spec",
			nil,
			0,
		},
		{
			"has limits",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "app",
						"resources": map[string]interface{}{
							"limits": map[string]interface{}{"cpu": "100m"},
						},
					},
				},
			},
			0,
		},
		{
			"has requests",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "app",
						"resources": map[string]interface{}{
							"requests": map[string]interface{}{"memory": "64Mi"},
						},
					},
				},
			},
			0,
		},
		{
			"has both",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "app",
						"resources": map[string]interface{}{
							"limits":   map[string]interface{}{"cpu": "100m"},
							"requests": map[string]interface{}{"cpu": "50m"},
						},
					},
				},
			},
			0,
		},
		{
			"no resources at all",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
				},
			},
			1,
		},
		{
			"empty resources map",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":      "app",
						"resources": map[string]interface{}{},
					},
				},
			},
			1,
		},
		{
			"one container ok one missing",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "app",
						"resources": map[string]interface{}{
							"limits": map[string]interface{}{"cpu": "100m"},
						},
					},
					map[string]interface{}{"name": "sidecar"},
				},
			},
			1,
		},
		{
			"no containers",
			map[string]interface{}{
				"serviceAccountName": "default",
			},
			0,
		},
		{
			"empty containers slice",
			map[string]interface{}{
				"containers": []interface{}{},
			},
			0,
		},
		{
			"empty limits and requests",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "app",
						"resources": map[string]interface{}{
							"limits":   map[string]interface{}{},
							"requests": map[string]interface{}{},
						},
					},
				},
			},
			1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lackResources(tc.spec); got != tc.want {
				t.Errorf("lackResources() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------- checkHostFlags ----------

func TestCheckHostFlags(t *testing.T) {
	tests := []struct {
		name    string
		spec    map[string]interface{}
		wantPID int
		wantIPC int
		wantNet int
	}{
		{
			"nil spec",
			nil, 0, 0, 0,
		},
		{
			"all true",
			map[string]interface{}{
				"hostPID":     true,
				"hostIPC":     true,
				"hostNetwork": true,
			},
			1, 1, 1,
		},
		{
			"all false",
			map[string]interface{}{
				"hostPID":     false,
				"hostIPC":     false,
				"hostNetwork": false,
			},
			0, 0, 0,
		},
		{
			"only hostPID",
			map[string]interface{}{
				"hostPID": true,
			},
			1, 0, 0,
		},
		{
			"only hostIPC",
			map[string]interface{}{
				"hostIPC": true,
			},
			0, 1, 0,
		},
		{
			"only hostNetwork",
			map[string]interface{}{
				"hostNetwork": true,
			},
			0, 0, 1,
		},
		{
			"non-bool values",
			map[string]interface{}{
				"hostPID":     "true",
				"hostIPC":     1,
				"hostNetwork": "yes",
			},
			0, 0, 0,
		},
		{
			"fields not present",
			map[string]interface{}{
				"containers": []interface{}{},
			},
			0, 0, 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pid, ipc, net := checkHostFlags(tc.spec)
			if pid != tc.wantPID {
				t.Errorf("hostPID = %d, want %d", pid, tc.wantPID)
			}
			if ipc != tc.wantIPC {
				t.Errorf("hostIPC = %d, want %d", ipc, tc.wantIPC)
			}
			if net != tc.wantNet {
				t.Errorf("hostNetwork = %d, want %d", net, tc.wantNet)
			}
		})
	}
}

// ---------- checkDockerSock ----------

func TestCheckDockerSock(t *testing.T) {
	tests := []struct {
		name string
		spec map[string]interface{}
		want int
	}{
		{
			"nil spec",
			nil,
			0,
		},
		{
			"docker sock mounted",
			map[string]interface{}{
				"volumes": []interface{}{
					map[string]interface{}{
						"name": "docker",
						"hostPath": map[string]interface{}{
							"path": "/var/run/docker.sock",
						},
					},
				},
			},
			1,
		},
		{
			"docker sock in subpath",
			map[string]interface{}{
				"volumes": []interface{}{
					map[string]interface{}{
						"name": "docker",
						"hostPath": map[string]interface{}{
							"path": "/host/var/run/docker.sock",
						},
					},
				},
			},
			1,
		},
		{
			"no docker sock",
			map[string]interface{}{
				"volumes": []interface{}{
					map[string]interface{}{
						"name": "data",
						"hostPath": map[string]interface{}{
							"path": "/var/data",
						},
					},
				},
			},
			0,
		},
		{
			"no volumes",
			map[string]interface{}{
				"containers": []interface{}{},
			},
			0,
		},
		{
			"volume without hostPath",
			map[string]interface{}{
				"volumes": []interface{}{
					map[string]interface{}{
						"name": "config",
						"configMap": map[string]interface{}{
							"name": "my-config",
						},
					},
				},
			},
			0,
		},
		{
			"multiple volumes one with docker sock",
			map[string]interface{}{
				"volumes": []interface{}{
					map[string]interface{}{
						"name": "data",
						"hostPath": map[string]interface{}{
							"path": "/var/data",
						},
					},
					map[string]interface{}{
						"name": "docker",
						"hostPath": map[string]interface{}{
							"path": "/var/run/docker.sock",
						},
					},
				},
			},
			1,
		},
		{
			"empty volumes",
			map[string]interface{}{
				"volumes": []interface{}{},
			},
			0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkDockerSock(tc.spec); got != tc.want {
				t.Errorf("checkDockerSock() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------- checkCaps ----------

func TestCheckCaps(t *testing.T) {
	tests := []struct {
		name              string
		spec              map[string]interface{}
		wantSysAdmin      int
		wantSysModule     int
		wantAllowPrivi    int
		wantSeccompUnconf int
	}{
		{
			"nil spec",
			nil, 0, 0, 0, 0,
		},
		{
			"SYS_ADMIN capability",
			mkSpecWithSC(map[string]interface{}{
				"capabilities": map[string]interface{}{
					"add": []interface{}{"SYS_ADMIN"},
				},
			}),
			1, 0, 0, 0,
		},
		{
			"SYS_MODULE capability",
			mkSpecWithSC(map[string]interface{}{
				"capabilities": map[string]interface{}{
					"add": []interface{}{"SYS_MODULE"},
				},
			}),
			0, 1, 0, 0,
		},
		{
			"both SYS_ADMIN and SYS_MODULE",
			mkSpecWithSC(map[string]interface{}{
				"capabilities": map[string]interface{}{
					"add": []interface{}{"SYS_ADMIN", "SYS_MODULE"},
				},
			}),
			1, 1, 0, 0,
		},
		{
			"allowPrivilegeEscalation",
			mkSpecWithSC(map[string]interface{}{
				"allowPrivilegeEscalation": true,
			}),
			0, 0, 1, 0,
		},
		{
			"seccomp Unconfined",
			mkSpecWithSC(map[string]interface{}{
				"seccompProfile": map[string]interface{}{
					"type": "Unconfined",
				},
			}),
			0, 0, 0, 1,
		},
		{
			"seccomp unconfined lowercase",
			mkSpecWithSC(map[string]interface{}{
				"seccompProfile": map[string]interface{}{
					"type": "unconfined",
				},
			}),
			0, 0, 0, 1,
		},
		{
			"all violations",
			mkSpecWithSC(map[string]interface{}{
				"capabilities": map[string]interface{}{
					"add": []interface{}{"SYS_ADMIN", "SYS_MODULE"},
				},
				"allowPrivilegeEscalation": true,
				"seccompProfile": map[string]interface{}{
					"type": "Unconfined",
				},
			}),
			1, 1, 1, 1,
		},
		{
			"no violations",
			mkSpecWithSC(map[string]interface{}{
				"capabilities": map[string]interface{}{
					"add": []interface{}{"NET_BIND_SERVICE"},
				},
				"allowPrivilegeEscalation": false,
				"seccompProfile": map[string]interface{}{
					"type": "RuntimeDefault",
				},
			}),
			0, 0, 0, 0,
		},
		{
			"no securityContext on container",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
				},
			},
			0, 0, 0, 0,
		},
		{
			"caps lowercase",
			mkSpecWithSC(map[string]interface{}{
				"capabilities": map[string]interface{}{
					"add": []interface{}{"sys_admin", "sys_module"},
				},
			}),
			1, 1, 0, 0,
		},
		{
			"multiple containers mixed",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "safe",
						"securityContext": map[string]interface{}{
							"allowPrivilegeEscalation": false,
						},
					},
					map[string]interface{}{
						"name": "dangerous",
						"securityContext": map[string]interface{}{
							"allowPrivilegeEscalation": true,
							"capabilities": map[string]interface{}{
								"add": []interface{}{"SYS_ADMIN"},
							},
						},
					},
				},
			},
			1, 0, 1, 0,
		},
		{
			"empty add list",
			mkSpecWithSC(map[string]interface{}{
				"capabilities": map[string]interface{}{
					"add": []interface{}{},
				},
			}),
			0, 0, 0, 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sysAdmin, sysModule, allowPrivi, seccomp := checkCaps(tc.spec)
			if sysAdmin != tc.wantSysAdmin {
				t.Errorf("capSysAdmin = %d, want %d", sysAdmin, tc.wantSysAdmin)
			}
			if sysModule != tc.wantSysModule {
				t.Errorf("capSysModule = %d, want %d", sysModule, tc.wantSysModule)
			}
			if allowPrivi != tc.wantAllowPrivi {
				t.Errorf("allowPrivi = %d, want %d", allowPrivi, tc.wantAllowPrivi)
			}
			if seccomp != tc.wantSeccompUnconf {
				t.Errorf("seccompUnconfined = %d, want %d", seccomp, tc.wantSeccompUnconf)
			}
		})
	}
}

// ---------- checkPrivileged ----------

func TestCheckPrivileged(t *testing.T) {
	tests := []struct {
		name string
		spec map[string]interface{}
		want int
	}{
		{
			"nil spec",
			nil,
			0,
		},
		{
			"no containers",
			map[string]interface{}{},
			0,
		},
		{
			"container without securityContext",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
				},
			},
			0,
		},
		{
			"privileged false",
			mkSpecWithSC(map[string]interface{}{"privileged": false}),
			0,
		},
		{
			"privileged true",
			mkSpecWithSC(map[string]interface{}{"privileged": true}),
			1,
		},
		{
			"privileged as string is ignored",
			mkSpecWithSC(map[string]interface{}{"privileged": "true"}),
			0,
		},
		{
			"privileged initContainer",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
				},
				"initContainers": []interface{}{
					map[string]interface{}{
						"name": "init",
						"securityContext": map[string]interface{}{
							"privileged": true,
						},
					},
				},
			},
			1,
		},
		{
			"one of many containers privileged",
			map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":            "a",
						"securityContext": map[string]interface{}{"privileged": false},
					},
					map[string]interface{}{
						"name":            "b",
						"securityContext": map[string]interface{}{"privileged": true},
					},
				},
			},
			1,
		},
		{
			"pod-level securityContext.privileged is not a container flag",
			map[string]interface{}{
				"securityContext": map[string]interface{}{"privileged": true},
				"containers": []interface{}{
					map[string]interface{}{"name": "app"},
				},
			},
			0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkPrivileged(tc.spec); got != tc.want {
				t.Errorf("checkPrivileged() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------- hasHostAliases ----------

func TestHasHostAliases(t *testing.T) {
	tests := []struct {
		name string
		spec map[string]interface{}
		want int
	}{
		{
			"nil spec",
			nil,
			0,
		},
		{
			"hostAliases present",
			map[string]interface{}{
				"hostAliases": []interface{}{
					map[string]interface{}{
						"ip":        "1.2.3.4",
						"hostnames": []interface{}{"evil.com"},
					},
				},
			},
			1,
		},
		{
			"empty hostAliases",
			map[string]interface{}{
				"hostAliases": []interface{}{},
			},
			0,
		},
		{
			"no hostAliases field",
			map[string]interface{}{
				"containers": []interface{}{},
			},
			0,
		},
		{
			"hostAliases not a slice",
			map[string]interface{}{
				"hostAliases": "not-a-slice",
			},
			0,
		},
		{
			"multiple hostAliases",
			map[string]interface{}{
				"hostAliases": []interface{}{
					map[string]interface{}{"ip": "1.1.1.1"},
					map[string]interface{}{"ip": "2.2.2.2"},
				},
			},
			1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasHostAliases(tc.spec); got != tc.want {
				t.Errorf("hasHostAliases() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------- lackRollingUpdate ----------

func TestLackRollingUpdate(t *testing.T) {
	tests := []struct {
		name string
		doc  map[string]interface{}
		want int
	}{
		{
			"Deployment with RollingUpdate configured",
			map[string]interface{}{
				"kind": "Deployment",
				"spec": map[string]interface{}{
					"strategy": map[string]interface{}{
						"type": "RollingUpdate",
						"rollingUpdate": map[string]interface{}{
							"maxSurge":       1,
							"maxUnavailable": 0,
						},
					},
				},
			},
			0,
		},
		{
			"Deployment with Recreate strategy",
			map[string]interface{}{
				"kind": "Deployment",
				"spec": map[string]interface{}{
					"strategy": map[string]interface{}{
						"type": "Recreate",
					},
				},
			},
			1,
		},
		{
			"Deployment with no rollingUpdate config",
			map[string]interface{}{
				"kind": "Deployment",
				"spec": map[string]interface{}{
					"strategy": map[string]interface{}{
						"type": "RollingUpdate",
					},
				},
			},
			1,
		},
		{
			"Deployment with no strategy at all",
			map[string]interface{}{
				"kind": "Deployment",
				"spec": map[string]interface{}{},
			},
			1,
		},
		{
			"Deployment with nil spec",
			map[string]interface{}{
				"kind": "Deployment",
			},
			1,
		},
		{
			"StatefulSet (not Deployment)",
			map[string]interface{}{
				"kind": "StatefulSet",
				"spec": map[string]interface{}{},
			},
			0,
		},
		{
			"Service (not Deployment)",
			map[string]interface{}{
				"kind": "Service",
			},
			0,
		},
		{
			"empty doc",
			map[string]interface{}{},
			0,
		},
		{
			"deployment lowercase",
			map[string]interface{}{
				"kind": "deployment",
				"spec": map[string]interface{}{},
			},
			1,
		},
		{
			"recreate lowercase",
			map[string]interface{}{
				"kind": "Deployment",
				"spec": map[string]interface{}{
					"strategy": map[string]interface{}{
						"type": "recreate",
					},
				},
			},
			1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lackRollingUpdate(tc.doc); got != tc.want {
				t.Errorf("lackRollingUpdate() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------- lackNamespace ----------

func TestLackNamespace(t *testing.T) {
	tests := []struct {
		name string
		doc  map[string]interface{}
		want int
	}{
		{
			"namespace present",
			map[string]interface{}{
				"metadata": map[string]interface{}{
					"namespace": "production",
				},
			},
			0,
		},
		{
			"namespace empty",
			map[string]interface{}{
				"metadata": map[string]interface{}{
					"namespace": "",
				},
			},
			1,
		},
		{
			"no namespace field",
			map[string]interface{}{
				"metadata": map[string]interface{}{
					"name": "myapp",
				},
			},
			1,
		},
		{
			"no metadata",
			map[string]interface{}{
				"kind": "Pod",
			},
			1,
		},
		{
			"metadata not a map",
			map[string]interface{}{
				"metadata": "invalid",
			},
			1,
		},
		{
			"namespace is non-string",
			map[string]interface{}{
				"metadata": map[string]interface{}{
					"namespace": 123,
				},
			},
			1,
		},
		{
			"empty doc",
			map[string]interface{}{},
			1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lackNamespace(tc.doc); got != tc.want {
				t.Errorf("lackNamespace() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ---------- test helpers ----------

// mkSpecWithSC creates a pod spec with a single container having the given securityContext.
func mkSpecWithSC(sc map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"containers": []interface{}{
			map[string]interface{}{
				"name":            "app",
				"securityContext": sc,
			},
		},
	}
}
