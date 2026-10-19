// Package packages inventories user-level package managers (uv, pnpm, cargo,
// go, gem, gh) and checks the installs around them.
package packages

import "time"

// Package is one installed package.
type Package struct {
	Manager        string `json:"manager"`
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	Runtime        string `json:"runtime,omitempty"`
	RuntimeVersion string `json:"runtime_version,omitempty"`
	// Source says where it was installed from: registry name, git URL or
	// local path.
	Source      string   `json:"source,omitempty"`
	Location    string   `json:"location,omitempty"`
	Executables []string `json:"executables,omitempty"`
	// Ident is the registry identifier for version lookups when it differs
	// from Name (go module path, gh owner/repo, flatpak ref).
	Ident string `json:"ident,omitempty"`
	// Available is the newer version a system manager (apt, snap, flatpak)
	// offers itself; "" when it is current.
	Available string `json:"available,omitempty"`
	// Held marks an apt package pinned with apt-mark hold.
	Held bool `json:"held,omitempty"`
}

// Runtime is the interpreter or toolchain a manager installs against.
type Runtime struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
}

// Inventory is the result of collecting one manager.
type Inventory struct {
	Manager        string        `json:"manager"`
	Available      bool          `json:"available"`
	Packages       []Package     `json:"packages,omitempty"`
	Runtime        *Runtime      `json:"runtime,omitempty"`
	ManagerVersion string        `json:"manager_version,omitempty"`
	BinDirs        []string      `json:"bin_dirs,omitempty"`
	Error          string        `json:"error,omitempty"`
	Duration       time.Duration `json:"duration"`
}

// Data is what a packages run stores in run.Run.Data.
type Data struct {
	Inventories []Inventory `json:"inventories"`
	// Runtimes describes the runtimes the managers install against.
	Runtimes []RuntimeStatus `json:"runtimes,omitempty"`
	// NodeMajor is the node major the pnpm globals were last installed
	// under.
	NodeMajor string `json:"node_major,omitempty"`
}
