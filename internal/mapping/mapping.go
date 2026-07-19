package mapping

func Candidates(manager, name string) []string {
	table := mappings[manager]
	if table == nil {
		return nil
	}
	if value, ok := table[name]; ok {
		return []string{value}
	}
	return nil
}

var mappings = map[string]map[string]string{
	"apt": {
		"build-essential": "gcc",
		"cargo":           "cargo",
		"cmake":           "cmake",
		"curl":            "curl",
		"docker.io":       "docker",
		"fd-find":         "fd",
		"fish":            "fish",
		"flatpak":         "flatpak",
		"fzf":             "fzf",
		"git":             "git",
		"golang-go":       "go",
		"htop":            "htop",
		"jq":              "jq",
		"make":            "gnumake",
		"neovim":          "neovim",
		"nodejs":          "nodejs",
		"npm":             "nodePackages.npm",
		"pipx":            "pipx",
		"pkg-config":      "pkg-config",
		"podman":          "podman",
		"python3":         "python3",
		"python3-pip":     "python3Packages.pip",
		"ripgrep":         "ripgrep",
		"rustc":           "rustc",
		"snapd":           "snapd",
		"tmux":            "tmux",
		"tree":            "tree",
		"unzip":           "unzip",
		"vim":             "vim",
		"wget":            "wget",
		"zip":             "zip",
		"zsh":             "zsh",
	},
	"npm": {
		"eslint":            "nodePackages.eslint",
		"npm-check-updates": "nodePackages.npm-check-updates",
		"pnpm":              "nodePackages.pnpm",
		"prettier":          "nodePackages.prettier",
		"typescript":        "nodePackages.typescript",
		"yarn":              "yarn",
	},
	"pipx": {
		"black":  "python3Packages.black",
		"httpie": "httpie",
		"pipenv": "pipenv",
		"poetry": "poetry",
		"ruff":   "ruff",
		"yt-dlp": "yt-dlp",
	},
	"python": {
		"black":  "python3Packages.black",
		"httpie": "httpie",
		"pipenv": "pipenv",
		"poetry": "poetry",
		"ruff":   "ruff",
		"yt-dlp": "yt-dlp",
	},
	"cargo": {
		"bat":      "bat",
		"exa":      "exa",
		"fd":       "fd",
		"ripgrep":  "ripgrep",
		"starship": "starship",
		"zellij":   "zellij",
	},
	"go-install": {
		"dlv":           "delve",
		"gofumpt":       "gofumpt",
		"golangci-lint": "golangci-lint",
		"gopls":         "gopls",
		"staticcheck":   "staticcheck",
	},
	"gem": {
		"bundler": "bundler",
		"rake":    "rake",
	},
}
