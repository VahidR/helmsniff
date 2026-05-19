package scanner

type Row struct {
	Dir                string
	YAMLFullPath       string
	WithinManifestSecret int
	ValidTaintSecret     int
	SecContOverPrivil    int
	InsecureHTTP         int
	NoSecuContext        int
	NoDefaultNSpace      int
	NoReso               int
	NoRollingUpdate      int
	NoNetworkPolicy      int
	TrueHostPID          int
	TrueHostIPC          int
	DockerSockPath       int
	TrueHostNet          int
	CapSysAdmin          int
	HostAlias            int
	AllowPrivi           int
	SeccompUnconfined    int
	CapSysModule         int
	K8sStatus            bool
	HelmStatus           bool
}
