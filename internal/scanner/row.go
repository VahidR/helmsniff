package scanner

// Row represents a single CSV output row containing the results of all security
// checks performed on one YAML document. Each int field is binary (0 or 1) where
// 1 indicates a violation was detected. Fields map 1:1 to CSV columns.
type Row struct {
	Dir                  string // Parent directory (chart) path
	YAMLFullPath         string // Full path to the analyzed YAML file
	WithinManifestSecret int    // 1 if the document is a Secret with data/stringData entries
	ValidTaintSecret     int    // 1 if a Secret is detected via taint analysis (reserved)
	SecContOverPrivil    int    // 1 if any container runs in privileged mode
	InsecureHTTP         int    // 1 if any value contains an "http://" URL
	NoSecuContext        int    // 1 if no securityContext is defined at pod or container level
	NoDefaultNSpace      int    // 1 if the resource has no namespace specified in metadata
	NoReso               int    // 1 if any container lacks resource limits/requests
	NoRollingUpdate      int    // 1 if a Deployment lacks rolling update strategy
	NoNetworkPolicy      int    // 1 if no NetworkPolicy exists in the chart
	TrueHostPID          int    // 1 if hostPID is set to true
	TrueHostIPC          int    // 1 if hostIPC is set to true
	DockerSockPath       int    // 1 if /var/run/docker.sock is mounted via hostPath
	TrueHostNet          int    // 1 if hostNetwork is set to true
	CapSysAdmin          int    // 1 if SYS_ADMIN capability is added
	HostAlias            int    // 1 if hostAliases are defined in the pod spec
	AllowPrivi           int    // 1 if allowPrivilegeEscalation is true
	SeccompUnconfined    int    // 1 if seccomp profile is set to Unconfined
	CapSysModule         int    // 1 if SYS_MODULE capability is added
	K8sStatus            bool   // true if the document is a valid Kubernetes resource
	HelmStatus           bool   // true if the document is managed by Helm
}
