package scanner

import (
	"strings"
)

// ---------- helpers ----------
func asMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}
func asSlice(v interface{}) []interface{} {
	if s, ok := v.([]interface{}); ok {
		return s
	}
	return nil
}
func str(v interface{}) string {
	s, _ := v.(string)
	return s
}
func boolVal(v interface{}) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func hasAPIVersionAndKind(doc map[string]interface{}) bool {
	return str(doc["apiVersion"]) != "" && str(doc["kind"]) != ""
}

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

// Raw-ish “http://” detector across common string fields (closer to Py’s grep)
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

// Extracts the pod spec from a doc, if any.
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

// Py’s behavior: flag only when pod-level secCtx absent AND all containers lack it.
// Also: if spec == nil (non-workload), treat as N/A ⇒ 0
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

// Py flags when any container lacks resources (limits/requests) entirely.
// If spec == nil (non-workload), return 0.
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

func hasHostAliases(spec map[string]interface{}) int {
	if spec == nil {
		return 0
	}
	if s := asSlice(spec["hostAliases"]); len(s) > 0 {
		return 1
	}
	return 0
}

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

func lackNamespace(doc map[string]interface{}) int {
	// Keep simple/consistent with Py; cluster-scoped kinds may inflate counts, but this matches earlier data.
	// TODO:‌ add this namespace is default or not.
	meta := asMap(doc["metadata"])
	ns := str(meta["namespace"])
	if ns == "" {
		return 1
	}
	return 0
}
