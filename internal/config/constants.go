// Package config holds global configuration constants shared across the CLI.
package config

// CSVHeader defines the ordered column names for the output CSV report.
// The order must match the record slice built in cmd/main.go and corresponds
// 1:1 to the fields in scanner.Row.
var CSVHeader = []string{
	"DIR",                    // Parent directory (chart) path
	"YAML_FULL_PATH",        // Full path to the analyzed YAML file
	"WITHIN_MANIFEST_SECRET", // Secret with data/stringData found in manifest
	"VALID_TAINT_SECRET",    // Secret detected via taint analysis (reserved)
	"SEC_CONT_OVER_PRIVIL",  // Container running in privileged mode
	"INSECURE_HTTP",         // Plaintext http:// URL found in any value
	"NO_SECU_CONTEXT",       // No securityContext at pod or container level
	"NO_DEFAULT_NSPACE",     // No namespace specified in resource metadata
	"NO_RESO",               // Container missing resource limits/requests
	"NO_ROLLING_UPDATE",     // Deployment lacks rolling update strategy
	"NO_NETWORK_POLICY",     // No NetworkPolicy resource in the chart
	"TRUE_HOST_PID",         // hostPID enabled on pod spec
	"TRUE_HOST_IPC",         // hostIPC enabled on pod spec
	"DOCKERSOCK_PATH",       // Docker socket mounted via hostPath volume
	"TRUE_HOST_NET",         // hostNetwork enabled on pod spec
	"CAP_SYS_ADMIN",        // SYS_ADMIN capability added to a container
	"HOST_ALIAS",            // hostAliases defined (custom /etc/hosts entries)
	"ALLOW_PRIVI",           // allowPrivilegeEscalation set to true
	"SECCOMP_UNCONFINED",    // Seccomp profile set to Unconfined
	"CAP_SYS_MODULE",        // SYS_MODULE capability added to a container
	"K8S_STATUS",            // Document is a valid Kubernetes resource
	"HELM_STATUS",           // Document is managed by Helm
}
