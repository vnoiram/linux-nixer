package mapping

import "strings"

func Candidates(manager, name string) []string {
	manager = strings.ToLower(strings.TrimSpace(manager))
	name = normalizeName(manager, name)
	table := mappings[manager]
	if table == nil {
		return nil
	}
	if value, ok := table[name]; ok {
		return []string{value}
	}
	return nil
}

func normalizeName(manager, name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if aliases := mappingAliases[manager]; aliases != nil {
		if alias, ok := aliases[name]; ok {
			return alias
		}
	}
	return name
}

var mappingAliases = map[string]map[string]string{
	"apt": {
		"fd": "fd-find",
	},
	"cargo": {
		"bottom":  "btm",
		"fd-find": "fd",
	},
	"go-install": {
		"delve": "dlv",
	},
}

var mappings = map[string]map[string]string{
	"apt": {
		"ansible":           "ansible",
		"bat":               "bat",
		"btop":              "btop",
		"build-essential":   "gcc",
		"cargo":             "cargo",
		"cmake":             "cmake",
		"curl":              "curl",
		"direnv":            "direnv",
		"dnsutils":          "dnsutils",
		"docker.io":         "docker",
		"fd-find":           "fd",
		"fish":              "fish",
		"flatpak":           "flatpak",
		"fzf":               "fzf",
		"g++":               "gcc",
		"gcc":               "gcc",
		"gdb":               "gdb",
		"gh":                "gh",
		"git":               "git",
		"golang-go":         "go",
		"htop":              "htop",
		"imagemagick":       "imagemagick",
		"iproute2":          "iproute2",
		"jq":                "jq",
		"just":              "just",
		"lazygit":           "lazygit",
		"make":              "gnumake",
		"net-tools":         "nettools",
		"neovim":            "neovim",
		"ninja-build":       "ninja",
		"nodejs":            "nodejs",
		"npm":               "nodePackages.npm",
		"openssh-client":    "openssh",
		"pipx":              "pipx",
		"pkg-config":        "pkg-config",
		"podman":            "podman",
		"postgresql-client": "postgresql",
		"python3":           "python3",
		"python3-pip":       "python3Packages.pip",
		"redis-tools":       "redis",
		"ripgrep":           "ripgrep",
		"rsync":             "rsync",
		"rustc":             "rustc",
		"shellcheck":        "shellcheck",
		"snapd":             "snapd",
		"sqlite3":           "sqlite",
		"stow":              "stow",
		"tmux":              "tmux",
		"tree":              "tree",
		"unzip":             "unzip",
		"vim":               "vim",
		"wget":              "wget",
		"yq":                "yq",
		"zip":               "zip",
		"zsh":               "zsh",
	},
	"npm": {
		"@anthropic-ai/claude-code": "claude-code",
		"@vue/cli":                  "nodePackages.vue-cli",
		"corepack":                  "corepack",
		"eslint":                    "nodePackages.eslint",
		"http-server":               "nodePackages.http-server",
		"nodemon":                   "nodePackages.nodemon",
		"npm":                       "nodePackages.npm",
		"npm-check-updates":         "nodePackages.npm-check-updates",
		"pnpm":                      "nodePackages.pnpm",
		"prettier":                  "nodePackages.prettier",
		"typescript":                "nodePackages.typescript",
		"vercel":                    "nodePackages.vercel",
		"vite":                      "nodePackages.vite",
		"yarn":                      "yarn",
	},
	"pipx": {
		"ansible":      "ansible",
		"awscli":       "awscli2",
		"black":        "python3Packages.black",
		"cookiecutter": "cookiecutter",
		"glances":      "glances",
		"httpie":       "httpie",
		"ipython":      "python3Packages.ipython",
		"mypy":         "mypy",
		"pipenv":       "pipenv",
		"poetry":       "poetry",
		"pre-commit":   "pre-commit",
		"ruff":         "ruff",
		"tox":          "tox",
		"uv":           "uv",
		"yt-dlp":       "yt-dlp",
	},
	"python": {
		"ansible":      "ansible",
		"awscli":       "awscli2",
		"black":        "python3Packages.black",
		"cookiecutter": "cookiecutter",
		"glances":      "glances",
		"httpie":       "httpie",
		"ipython":      "python3Packages.ipython",
		"mypy":         "mypy",
		"pipenv":       "pipenv",
		"poetry":       "poetry",
		"pre-commit":   "pre-commit",
		"ruff":         "ruff",
		"tox":          "tox",
		"uv":           "uv",
		"yt-dlp":       "yt-dlp",
	},
	"cargo": {
		"bat":           "bat",
		"btm":           "bottom",
		"cargo-edit":    "cargo-edit",
		"cargo-nextest": "cargo-nextest",
		"exa":           "exa",
		"eza":           "eza",
		"fd":            "fd",
		"git-delta":     "delta",
		"hyperfine":     "hyperfine",
		"just":          "just",
		"ripgrep":       "ripgrep",
		"sd":            "sd",
		"starship":      "starship",
		"tealdeer":      "tealdeer",
		"zellij":        "zellij",
	},
	"go-install": {
		"air":           "air",
		"buf":           "buf",
		"dlv":           "delve",
		"gofumpt":       "gofumpt",
		"golangci-lint": "golangci-lint",
		"gopls":         "gopls",
		"mockgen":       "mockgen",
		"staticcheck":   "staticcheck",
	},
	"gem": {
		"bundler": "bundler",
		"foreman": "foreman",
		"jekyll":  "jekyll",
		"rake":    "rake",
		"rubocop": "rubocop",
	},
}
