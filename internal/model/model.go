package model

const SchemaVersion = "linux-nixer.scan.v1"

type Decision string

const (
	DecisionConfirmed     Decision = "confirmed"
	DecisionCandidate     Decision = "candidate"
	DecisionTODO          Decision = "todo"
	DecisionMigrationNote Decision = "migration-note"
	DecisionExcluded      Decision = "excluded"
)

type ScanReport struct {
	SchemaVersion  string        `json:"schemaVersion"`
	Host           Host          `json:"host"`
	Users          []User        `json:"users,omitempty"`
	Packages       []Package     `json:"packages,omitempty"`
	Languages      Languages     `json:"languages,omitempty"`
	GitSources     []GitSource   `json:"gitSources,omitempty"`
	Containers     []Container   `json:"containers,omitempty"`
	Desktop        Desktop       `json:"desktop,omitempty"`
	Services       []Service     `json:"services,omitempty"`
	FilesystemDiff []FileFinding `json:"filesystemDiff,omitempty"`
	StatefulData   []FileFinding `json:"statefulData,omitempty"`
	Items          []Item        `json:"items,omitempty"`
	Warnings       []Warning     `json:"warnings,omitempty"`
}

type Host struct {
	Hostname string `json:"hostname,omitempty"`
	Distro   string `json:"distro,omitempty"`
	Release  string `json:"release,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
}

type User struct {
	Name   string   `json:"name"`
	UID    string   `json:"uid,omitempty"`
	GID    string   `json:"gid,omitempty"`
	Home   string   `json:"home,omitempty"`
	Shell  string   `json:"shell,omitempty"`
	Groups []string `json:"groups,omitempty"`
	System bool     `json:"system,omitempty"`
}

type Package struct {
	Manager  string            `json:"manager"`
	Name     string            `json:"name"`
	Version  string            `json:"version,omitempty"`
	Source   string            `json:"source,omitempty"`
	NixNames []string          `json:"nixNames,omitempty"`
	Decision Decision          `json:"decision,omitempty"`
	Details  map[string]string `json:"details,omitempty"`
}

type Languages struct {
	NPM    []Package     `json:"npm,omitempty"`
	Python []PythonEnv   `json:"python,omitempty"`
	Conda  []Package     `json:"conda,omitempty"`
	Cargo  []Package     `json:"cargo,omitempty"`
	Gem    []Package     `json:"gem,omitempty"`
	Go     []Package     `json:"go,omitempty"`
	VMs    []VersionTool `json:"versionManagers,omitempty"`
}

type PythonEnv struct {
	Path     string    `json:"path"`
	Kind     string    `json:"kind"`
	Packages []Package `json:"packages,omitempty"`
}

type VersionTool struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
}

type GitSource struct {
	Path     string   `json:"path"`
	Remote   string   `json:"remote,omitempty"`
	Commit   string   `json:"commit,omitempty"`
	Dirty    bool     `json:"dirty,omitempty"`
	Build    []string `json:"buildHints,omitempty"`
	Decision Decision `json:"decision,omitempty"`
}

type Container struct {
	Runtime  string            `json:"runtime"`
	Name     string            `json:"name,omitempty"`
	Image    string            `json:"image,omitempty"`
	Digest   string            `json:"digest,omitempty"`
	Compose  string            `json:"compose,omitempty"`
	Ports    []string          `json:"ports,omitempty"`
	Mounts   []string          `json:"mounts,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	Decision Decision          `json:"decision,omitempty"`
}

type Desktop struct {
	Environment string        `json:"environment,omitempty"`
	Fonts       []string      `json:"fonts,omitempty"`
	Themes      []string      `json:"themes,omitempty"`
	Autostart   []FileFinding `json:"autostart,omitempty"`
	Dconf       []string      `json:"dconf,omitempty"`
}

type Service struct {
	Manager          string   `json:"manager"`
	Name             string   `json:"name"`
	Path             string   `json:"path,omitempty"`
	Enabled          bool     `json:"enabled,omitempty"`
	Description      string   `json:"description,omitempty"`
	User             string   `json:"user,omitempty"`
	WorkingDirectory string   `json:"workingDirectory,omitempty"`
	ExecStart        string   `json:"execStart,omitempty"`
	EnvironmentFiles []string `json:"environmentFiles,omitempty"`
	WantedBy         []string `json:"wantedBy,omitempty"`
	Schedule         string   `json:"schedule,omitempty"`
	Decision         Decision `json:"decision,omitempty"`
}

type FileFinding struct {
	Path       string   `json:"path"`
	Type       string   `json:"type"`
	Mode       string   `json:"mode,omitempty"`
	Owner      string   `json:"owner,omitempty"`
	Size       int64    `json:"size,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Category   string   `json:"category,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Decision   Decision `json:"decision,omitempty"`
	SecretRisk bool     `json:"secretRisk,omitempty"`
}

type Item struct {
	Kind     string            `json:"kind"`
	Name     string            `json:"name"`
	Path     string            `json:"path,omitempty"`
	Source   string            `json:"source,omitempty"`
	Decision Decision          `json:"decision"`
	Reason   string            `json:"reason,omitempty"`
	Details  map[string]string `json:"details,omitempty"`
}

type Warning struct {
	Source  string `json:"source"`
	Message string `json:"message"`
}
