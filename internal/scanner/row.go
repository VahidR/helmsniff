package scanner

// Row represents a single CSV output row containing the results of all security
// checks performed on one YAML document. Each int field is binary (0 or 1) where
// 1 indicates a violation was detected. Fields map 1:1 to CSV columns.
type Row struct {
	Dir                  string `json:"dir"`                    // Parent directory (chart) path
	YAMLFullPath         string `json:"yaml_full_path"`         // Full path to the analyzed YAML file
	WithinManifestSecret int    `json:"within_manifest_secret"` // 1 if the document is a Secret with data/stringData entries
	ValidTaintSecret     int    `json:"valid_taint_secret"`     // 1 if a Secret is detected via taint analysis (reserved)
	SecContOverPrivil    int    `json:"sec_cont_over_privil"`   // 1 if any container runs in privileged mode
	InsecureHTTP         int    `json:"insecure_http"`          // 1 if any value contains an "http://" URL
	NoSecuContext        int    `json:"no_secu_context"`        // 1 if no securityContext is defined at pod or container level
	NoDefaultNSpace      int    `json:"no_default_nspace"`      // 1 if the resource has no namespace specified in metadata
	NoReso               int    `json:"no_reso"`                // 1 if any container lacks resource limits/requests
	NoRollingUpdate      int    `json:"no_rolling_update"`      // 1 if a Deployment lacks rolling update strategy
	NoNetworkPolicy      int    `json:"no_network_policy"`      // 1 if no NetworkPolicy exists in the chart
	TrueHostPID          int    `json:"true_host_pid"`          // 1 if hostPID is set to true
	TrueHostIPC          int    `json:"true_host_ipc"`          // 1 if hostIPC is set to true
	DockerSockPath       int    `json:"dockersock_path"`        // 1 if /var/run/docker.sock is mounted via hostPath
	TrueHostNet          int    `json:"true_host_net"`          // 1 if hostNetwork is set to true
	CapSysAdmin          int    `json:"cap_sys_admin"`          // 1 if SYS_ADMIN capability is added
	HostAlias            int    `json:"host_alias"`             // 1 if hostAliases are defined in the pod spec
	AllowPrivi           int    `json:"allow_privi"`            // 1 if allowPrivilegeEscalation is true
	SeccompUnconfined    int    `json:"seccomp_unconfined"`     // 1 if seccomp profile is set to Unconfined
	CapSysModule         int    `json:"cap_sys_module"`         // 1 if SYS_MODULE capability is added
	K8sStatus            bool   `json:"k8s_status"`             // true if the document is a valid Kubernetes resource
	HelmStatus           bool   `json:"helm_status"`            // true if the document is managed by Helm
}
