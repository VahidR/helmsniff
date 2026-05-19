package scanner

import (
	"strings"
)

// ---------- helpers ----------

// asMap safely type-asserts v to map[string]interface{}.
// Returns nil if the assertion fails.
func asMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}
// asSlice safely type-asserts v to []interface{}.
// Returns nil if the assertion fails.
func asSlice(v interface{}) []interface{} {
	if s, ok := v.([]interface{}); ok {
		return s
	}
	return nil
}
// str safely type-asserts v to string.
// Returns an empty string if v is not a string.
func str(v interface{}) string {
	s, _ := v.(string)
	return s
}
// boolVal safely type-asserts v to bool.
// Returns false if v is not a bool.
func boolVal(v interface{}) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

// hasAPIVersionAndKind returns true if the document contains non-empty
// "apiVersion" and "kind" fields, indicating a valid Kubernetes resource.
func hasAPIVersionAndKind(doc map[string]interface{}) bool {
	return str(doc["apiVersion"]) != "" && str(doc["kind"]) != ""
}

// detectHelmManaged returns true if the document's metadata labels indicate
// it is managed by Helm (either via "app.kubernetes.io/managed-by: Helm"
// or the presence of a "helm.sh/chart" label).
func detectHelmManaged(doc map[string]interface{}) bool {
	meta := asMap(doc["metadata"])
	if meta == nil {
		return false
	}
	labels := asMap(meta["labels"])
	if labels == nil {
		return false
	}
	if str(labels["app.kubernetes.io/managed-by"]) == "Helm" {
		return true
	}
	if labels["helm.sh/chart"] != nil {
		return true
	}
	return false
}

// isWorkloadKind returns true if the given kind (case-insensitive) represents
// a Kubernetes workload resource that contains a pod spec (e.g. Deployment,
// StatefulSet, DaemonSet, Job, CronJob, ReplicaSet, ReplicationController, Pod).
func isWorkloadKind(kind string) bool {
	k := strings.ToLower(kind)
	switch k {
	case "deployment", "statefulset", "daemonset", "job", "cronjob",
		"replicaset", "replicationcontroller", "pod":
		return true
	default:
		return false
	}
}

// ---------- rules ----------

// countSecretsInDoc returns 1 if the document is a Kubernetes Secret that
// contains at least one entry in "data" or "stringData", otherwise 0.
func countSecretsInDoc(doc map[string]interface{}) int {
	if strings.EqualFold(str(doc["kind"]), "Secret") {
		m := asMap(doc["data"])
		sd := asMap(doc["stringData"])
		if len(m) > 0 || len(sd) > 0 {
			return 1
		}
	}
	return 0
}

// hasInsecureHTTP recursively walks all keys and values in the document and
// returns 1 if any string contains "http://" (case-insensitive), indicating
// use of an insecure plaintext HTTP connection. Returns 0 otherwise.
func hasInsecureHTTP(doc map[string]interface{}) int {
	found := 0
	var walk func(x interface{})
	walk = func(x interface{}) {
		if found == 1 || x == nil {
			return
		}
		switch t := x.(type) {
		case string:
			if strings.Contains(strings.ToLower(t), "http://") {
				found = 1
			}
		case []interface{}:
			for _, v := range t {
				walk(v)
				if found == 1 {
					return
				}
			}
		case map[string]interface{}:
			for k, v := range t {
				if strings.Contains(strings.ToLower(k), "http://") {
					found = 1
					return
				}
				walk(v)
				if found == 1 {
					return
				}
			}
		}
	}
	walk(doc)
	return found
}

// containersFromSpec collects all container definitions (both regular and init
// containers) from a pod spec. It also descends into spec.template.spec for
// workload resources like Deployments. Returns nil if spec is nil.
func containersFromSpec(spec map[string]interface{}) []interface{} {
	if spec == nil {
		return nil
	}
	var all []interface{}
	if c := asSlice(spec["containers"]); len(c) > 0 {
		all = append(all, c...)
	}
	if ic := asSlice(spec["initContainers"]); len(ic) > 0 {
		all = append(all, ic...)
	}
	// workload specs often have template.spec
	if tpl := asMap(spec["template"]); tpl != nil {
		if s2 := asMap(tpl["spec"]); s2 != nil {
			if c := asSlice(s2["containers"]); len(c) > 0 {
				all = append(all, c...)
			}
			if ic := asSlice(s2["initContainers"]); len(ic) > 0 {
				all = append(all, ic...)
			}
		}
	}
	return all
}

// podSpecFromDoc extracts the pod-level spec from a Kubernetes document.
// For Pods it returns doc.spec directly; for workload kinds (Deployment, etc.)
// it returns doc.spec.template.spec. Returns nil for non-workload documents.
func podSpecFromDoc(doc map[string]interface{}) map[string]interface{} {
	sp := asMap(doc["spec"])
	if strings.EqualFold(str(doc["kind"]), "Pod") {
		return sp
	}
	if tpl := asMap(sp["template"]); tpl != nil {
		return asMap(tpl["spec"])
	}
	return nil
}

// lackSecurityContext returns 1 if the pod spec has no pod-level securityContext
// AND none of its containers define one. Returns 0 for non-workload documents
// (spec == nil) or if at least one security context is present.
func lackSecurityContext(spec map[string]interface{}) int {
	if spec == nil {
		return 0
	}
	if asMap(spec["securityContext"]) != nil {
		return 0
	}
	containers := containersFromSpec(spec)
	if len(containers) == 0 {
		return 0
	}
	missingAll := 1
	for _, c := range containers {
		if asMap(c)["securityContext"] != nil {
			missingAll = 0
		}
	}
	return missingAll
}

// lackResources returns 1 if any container in the pod spec lacks both resource
// limits and requests entirely. Returns 0 for non-workload documents (spec == nil)
// or if all containers have at least one of limits/requests defined.
func lackResources(spec map[string]interface{}) int {
	if spec == nil { return 0 }
	containers := containersFromSpec(spec)
	if len(containers) == 0 { return 0 }

	anyMissing := 0
	for _, c := range containers {
		res := asMap(asMap(c)["resources"])
		limits := asMap(res["limits"])
		requests := asMap(res["requests"])
		if len(limits) == 0 && len(requests) == 0 {
			anyMissing = 1
			break
		}
	}
	return anyMissing
}

// checkHostFlags inspects the pod spec for host namespace sharing flags.
// Returns 1 for each of hostPID, hostIPC, and hostNetwork that is set to true.
// All return 0 if spec is nil.
func checkHostFlags(spec map[string]interface{}) (hostPID, hostIPC, hostNet int) {
	if spec == nil {
		return
	}
	if boolVal(spec["hostPID"]) {
		hostPID = 1
	}
	if boolVal(spec["hostIPC"]) {
		hostIPC = 1
	}
	if boolVal(spec["hostNetwork"]) {
		hostNet = 1
	}
	return
}

// checkDockerSock returns 1 if any volume in the pod spec mounts the Docker
// socket path (/var/run/docker.sock) via a hostPath volume. Returns 0 otherwise.
func checkDockerSock(spec map[string]interface{}) int {
	if spec == nil {
		return 0
	}
	vols := asSlice(spec["volumes"])
	for _, v := range vols {
		hp := asMap(asMap(v)["hostPath"])
		if strings.Contains(str(hp["path"]), "/var/run/docker.sock") {
			return 1
		}
	}
	return 0
}

// checkCaps inspects all containers in the pod spec for dangerous security
// settings. Returns 1 for each condition found: SYS_ADMIN capability added,
// SYS_MODULE capability added, allowPrivilegeEscalation set to true, or
// seccomp profile type set to "Unconfined". All return 0 if spec is nil.
func checkCaps(spec map[string]interface{}) (capSysAdmin, capSysModule int, allowPrivi int, seccompUnconfined int) {
	if spec == nil {
		return
	}
	containers := containersFromSpec(spec)
	for _, c := range containers {
		sc := asMap(asMap(c)["securityContext"])
		if sc == nil {
			continue
		}
		caps := asMap(sc["capabilities"])
		adds := asSlice(caps["add"])
		for _, a := range adds {
			val := strings.ToUpper(str(a))
			if val == "SYS_ADMIN" {
				capSysAdmin = 1
			}
			if val == "SYS_MODULE" {
				capSysModule = 1
			}
		}
		if boolVal(sc["allowPrivilegeEscalation"]) {
			allowPrivi = 1
		}
		if sp := asMap(sc["seccompProfile"]); sp != nil {
			if strings.EqualFold(str(sp["type"]), "Unconfined") {
				seccompUnconfined = 1
			}
		}
	}
	return
}

// hasHostAliases returns 1 if the pod spec defines any hostAliases entries
// (custom /etc/hosts mappings), which can be used for DNS spoofing. Returns 0
// if spec is nil or no hostAliases are present.
func hasHostAliases(spec map[string]interface{}) int {
	if spec == nil {
		return 0
	}
	if s := asSlice(spec["hostAliases"]); len(s) > 0 {
		return 1
	}
	return 0
}

// lackRollingUpdate returns 1 if the document is a Deployment that either uses
// the "Recreate" strategy or has no rollingUpdate configuration specified.
// Returns 0 for non-Deployment kinds or properly configured rolling updates.
func lackRollingUpdate(doc map[string]interface{}) int {
	if strings.EqualFold(str(doc["kind"]), "Deployment") {
		spec := asMap(doc["spec"])
		strat := asMap(spec["strategy"])
		if strings.ToLower(str(strat["type"])) == "recreate" {
			return 1
		}
		if asMap(strat["rollingUpdate"]) == nil {
			return 1
		}
		return 0
	}
	return 0
}

// lackNamespace returns 1 if the document's metadata does not specify a
// namespace, which may indicate deployment to the default namespace.
// Note: cluster-scoped kinds will also be flagged.
func lackNamespace(doc map[string]interface{}) int {
	meta := asMap(doc["metadata"])
	ns := str(meta["namespace"])
	if ns == "" {
		return 1
	}
	return 0
}
