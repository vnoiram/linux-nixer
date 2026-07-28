# linux-nixer

English version: [README.md](README.md)

`linux-nixer` は Debian/Ubuntu 系 Linux 環境をスキャンし、編集可能な NixOS + Home Manager flake を生成するツールです。

このプロジェクトは意図的に保守的です。幅広いシステム状態を検出しますが、自動で Nix に変換するのは信頼度の高い項目だけです。シークレット、鍵、大きな状態付きデータ、ブラウザプロファイル、クラウド認証情報などの危険な項目は、生成される Nix ファイルへ埋め込まず、移行メモとして報告します。

生成される Nix 設定には `confirmed` と判定された findings のみが含まれます。`candidate` のままの findings は、レビューされるまでレポートと TODO コメントに残ります。

設計上の前提、安全境界、今後の予定は [DESIGN_AND_ROADMAP.md](DESIGN_AND_ROADMAP.md) を参照してください。

## 現在の状態

初期実装の scaffold ですが、次の機能を含みます。

- Go CLI コマンド: `scan`, `capture`, `review`, `summary`, `validate`, `generate`, `doctor`, `baseline create`/`fetch`/`import`/`list`/`check`, `policy init`, `plugin check`, `plugin scaffold`
- ホスト/ユーザー情報、グループ、apt、言語ツール、Git ソース、コンテナ、シークレット、システム設定ファイル、DevOps/プロジェクト設定、ユーザー shell 設定、デスクトップ設定、ハードウェア/周辺機器設定、filesystem findings の registry ベース scanner
- snap、flatpak、AppImage、Linux 上の Homebrew 向けの専用 scanner と安全な詳細サマリ
- rootfs 比較用 baseline manifest の作成
- Nix flake プロジェクトのレンダリング
- パッケージソース、代替パッケージエコシステム、サービス、コンテナ、言語エコシステム、filesystem findings、システム設定、DevOps 設定、ユーザー shell 設定、デスクトップ設定、ハードウェア/周辺機器設定、開発プロジェクト向けの生成 module と report
- systemd unit、timer、cron schedule のサービス詳細レポート
- system package、Home Manager package、container runtime enable の confirmed-only レンダリング
- 検出ユーザー、安全な shell enable、一部の confirmed Home Manager program enable に対する保守的な Nix option レンダリング
- apt、npm、pipx/Python CLI、cargo、go-install、gem findings に対する保守的な Nix package mapping
- findings の confirm/exclude/defer を行う非対話 review rule
- Go 標準ライブラリだけで動く対話 review mode
- Nix 生成前の review summary と pending-finding gate
- scan JSON の schema、decision、protected finding 検証
- scan、auto-safe review、summary、Nix generation をまとめて実行する one-shot capture workflow
- 反復可能な scan/review rule 用 JSON policy file
- 生成された NixOS VM derivation を build する `doctor --vm`
- 生成 VM script の起動確認を timeout 付きで行う任意の `doctor --boot`
- `ubuntu:24.04` のような baseline ID の local `baselines/` または user cache 解決
- 一部ホストファイル用の read-only `scan --sudo` fallback
- unit test と fixture-style test
- GitHub Actions CI と tag ベースの release workflow
- 外部 scanner plugin を実行する `scan`/`capture --plugin PATH`
- Docker/Podman や network access なしで common release の組み込み manifest を使う `baseline fetch --offline`

## 使い方

```sh
go build -o bin/linux-nixer ./cmd/linux-nixer

bin/linux-nixer scan --out scan.json
bin/linux-nixer scan --sudo --out scan.json
bin/linux-nixer capture --out linux-nixer-output --sudo --deep
bin/linux-nixer policy init --out linux-nixer-policy.json
bin/linux-nixer capture --policy linux-nixer-policy.json --out linux-nixer-output
bin/linux-nixer review --scan scan.json --out reviewed.json --auto-safe
bin/linux-nixer validate --scan reviewed.json
bin/linux-nixer summary --scan reviewed.json
bin/linux-nixer summary --scan reviewed.json --fail-on-pending
bin/linux-nixer generate --scan reviewed.json --out nix-config
bin/linux-nixer doctor --project nix-config
bin/linux-nixer help capture
```

fixture や mounted rootfs を scan する場合:

```sh
bin/linux-nixer scan --root /path/to/rootfs --include /random-seed-42 --out scan.json
bin/linux-nixer capture --root /path/to/rootfs --include /random-seed-42 --out linux-nixer-output
```

`capture` は output directory の下に `scan.json`, `reviewed.json`, `summary.md`, `nix-config/` を書き出します。`review --auto-safe` と同じ保守的な auto-safe review を適用します。Nix を生成する前に手動で findings を承認したい場合は、`scan` と `review --interactive` を分けて使ってください。

capture 後は `nix-config/reports/migration-checklist.md` を確認し、手動移行が必要な package、secret、stateful data、configuration の作業を確認します。

## Plugin scanner

`--plugin PATH` は `scan`/`capture` で繰り返し指定でき、外部実行ファイルを追加 scanner として実行します。plugin は任意の言語で実装でき、stdin/stdout の小さな JSON protocol でやりとりします。

```sh
bin/linux-nixer scan --plugin ./my-scanner --out scan.json
```

plugin は常に現在のユーザー権限で実行され、`--sudo` 昇格は行いません。既定 timeout は 30 秒で、`--plugin-timeout DURATION` で変更できます。protocol と最小例は [DESIGN_AND_ROADMAP.md](DESIGN_AND_ROADMAP.md) の "Plugin scanners" を参照してください。

plugin は 1 つの scan JSON document または newline-delimited scan JSON fragments を出力できます。`capabilities` subcommand を任意で実装すると、name、version、domain、runtime needs などの metadata を返せます。例は [examples/plugins](examples/plugins) を参照してください。

```sh
bin/linux-nixer plugin scaffold --type shell --out ./my-scanner
bin/linux-nixer plugin check --plugin ./my-scanner
bin/linux-nixer plugin check --plugin ./examples/plugins/shell/sample-scanner --capabilities
```

## Policy と review

policy file を使うと、scan と review の判断を反復可能にできます。

```sh
bin/linux-nixer policy init --out linux-nixer-policy.json
bin/linux-nixer scan --policy linux-nixer-policy.json --out scan.json
bin/linux-nixer review --policy linux-nixer-policy.json --scan scan.json --out reviewed.json
bin/linux-nixer capture --policy linux-nixer-policy.json --out linux-nixer-output
```

`policy init --preset <name>` は common migration style 向けの template から開始します。利用できる preset は `workstation`, `server`, `developer-machine`, `minimal-audit` です。`minimal-audit` は何も自動承認しない最も保守的な開始点です。

保存やカスタマイズが不要な one-shot run では、組み込み preset を直接使えます。

```sh
bin/linux-nixer capture --preset developer-machine --out linux-nixer-output
```

`--preset` と `--policy` は同時指定できません。両方省略した場合は `--preset default` と同等です。

finding ごとの判断を再利用したい場合は `--export-decisions`/`--import-decisions` を使います。

```sh
bin/linux-nixer review --scan scan.json --out reviewed.json --confirm-kind service --export-decisions decisions.json
bin/linux-nixer review --scan scan-later.json --out reviewed-later.json --import-decisions decisions.json
bin/linux-nixer validate --decisions decisions.json --policy policy.json
bin/linux-nixer summary --scan reviewed-later.json --compare-decisions decisions.json
```

import された decision は同じ finding に対する policy の `confirmKinds`/`excludeKinds` より優先されます。

対話 review では JSON を直接編集せずに判断を調整できます。

```sh
bin/linux-nixer review \
  --scan scan.json \
  --out reviewed.json \
  --auto-safe \
  --interactive \
  --confirm-manager apt \
  --confirm-kind service \
  --exclude-path /home/alice/Downloads
```

対話 review は Nix mapping impact、limited details、unmapped package marker、protected-finding reason などの安全な context を表示します。入力は `c` confirmed、`k` candidate、`t` todo、`m` migration-note、`x` excluded、`s` skip、`q` quit です。secret-like/stateful findings は対話で confirmed にできず、exclude しない限り migration note のままです。

## Summary、validate、doctor

Nix 生成前に reviewed decision を要約します。

```sh
bin/linux-nixer summary --scan reviewed.json
bin/linux-nixer summary --scan reviewed.json --json
bin/linux-nixer summary --scan reviewed.json --fail-on-pending
```

`--fail-on-pending` は `candidate` または `todo` が残っている場合に非ゼロ終了します。`migration-note` は想定された手動移行作業として扱われ、gate failure にはなりません。

scan/reviewed JSON は生成前に検証できます。

```sh
bin/linux-nixer validate --scan reviewed.json
bin/linux-nixer validate --scan reviewed.json --json
bin/linux-nixer validate --scan reviewed.json --strict
```

`--strict` は schema version、known decision values、required identifiers、protected secret/stateful findings に加えて、未知の JSON field も拒否します。

Nix が利用できる環境では、生成された NixOS VM derivation を build できます。

```sh
bin/linux-nixer doctor --project nix-config --vm --host generated
bin/linux-nixer doctor --project nix-config --vm --boot --timeout 20s --host generated
```

## Baseline

Docker または Podman が使える場合、`baseline fetch` は distro の official image から manifest を作成します。対応する distro/release は curated catalog に限定されます。

```sh
bin/linux-nixer baseline list
bin/linux-nixer baseline fetch --distro ubuntu --release 24.04
bin/linux-nixer scan --root /path/to/current-root --baseline ubuntu:24.04 --out scan.json
```

Docker/Podman も network access もない場合は、binary に組み込まれた manifest を `--offline` で使えます。

```sh
bin/linux-nixer baseline fetch --distro ubuntu --release 24.04 --offline
```

custom/offline rootfs では `baseline create` を使います。

```sh
mkdir -p baselines
bin/linux-nixer baseline create --distro ubuntu --release 24.04 --root /path/to/rootfs --out baselines/ubuntu-24.04.json
```

pre-downloaded flat rootfs tarball しかない完全 offline host では `baseline import` を使います。

```sh
bin/linux-nixer baseline import --distro ubuntu --release 24.04 --tar ubuntu-base-24.04-base-amd64.tar.gz
```

`--baseline` は JSON path または `ubuntu:24.04` のような ID を受け付けます。ID は current project の `baselines/ubuntu-24.04.json`、次に user cache の `linux-nixer/baselines/` から解決されます。

## 生成される project

生成 project には次のファイルが含まれます。

- `flake.nix`
- `hosts/generated/configuration.nix`
- `users/home.nix`
- `modules/containers.nix`
- `modules/services.nix`
- `modules/filesystem-findings.nix`
- `reports/package-sources.md`
- `reports/filesystem.md`
- `reports/users.md`
- `reports/containers.md`
- `reports/git-sources.md`
- `reports/languages.md`
- `reports/migration-report.md`
- `reports/migration-checklist.md`
- `reports/system-config.md`
- `reports/devops-config.md`
- `reports/backup-sync.md`
- `reports/dev-projects.md`
- `reports/user-config.md`
- `reports/desktop.md`
- `reports/hardware.md`

## Scanner domains

主な scanner domain は次の通りです。

- apt/dpkg package、manual install hint、apt repository、keyring、preference、apt config
- Linux user、login shell、home directory、system-user hint、supplementary group、privileged group membership
- snap、flatpak、AppImage、Linux 上の Homebrew
- npm/pnpm/yarn global package と local node package manager metadata
- Python venv、pipx、pyproject、requirements、Poetry、Pipenv、uv、Conda environment marker
- asdf、mise、nvm、fnm、volta、pyenv、rbenv、sdkman、conda などの version manager
- cargo、gem、`go install` 形式の user binary、Rust/Go/Ruby project manifest
- common source location 配下の Git checkout
- Docker/Podman container、inspect metadata、compose file
- database、queue、search、monitoring、container runtime、VM image、`/srv` application data などの stateful data marker
- restic、borg、kopia、rclone、rsync、syncthing、Timeshift、Duplicati などの backup/sync config
- systemd、cron、network/firewall/SSH/VPN safe summary、sudo/PAM/polkit/AppArmor/fail2ban/auditd marker、web server、CI/CD automation、kernel/device tuning marker
- Kubernetes、Docker client config、Helm、Terraform、AWS、GCP、Azure などの DevOps config marker
- bash、zsh、fish、profile/env file、direnv、git、ssh key/known hosts、gpg/key store、tmux、starship、shell plugin tree、`.local/bin` executable
- desktop environment、font、theme/icon、autostart entry、GNOME dconf dump、KDE/i3/sway/input method config、browser profile/extension、terminal/editor setting
- CUPS printer、Bluetooth/BlueZ、SANE scanner、PipeWire/PulseAudio/ALSA、fprint/U2F/YubiKey/smartcard config、fwupd/TLP/UPower、input remapping tool
- ELF executable、shebang script、desktop entry、systemd unit、config、secret、stateful data、`/opt`、`/usr/local`、`/srv`、user-local path の location hint

package mapping と Nix option rendering は意図的に保守的です。apt と common language CLI tools は既知の場合に static Nix candidate を持ちますが、snap、flatpak、AppImage、Homebrew、secret、stateful data、raw dotfile、service unit body、repository key は既定では自動 Nix 置換せず report に残します。

## 開発

```sh
make fmt-check
make vet
make test
make build
```

制限された環境では、`GOCACHE` を書き込み可能な directory に向ける必要がある場合があります。Makefile は既定で `/tmp/codex-go-build` を使います。

## Release

version は SemVer と annotated tag を使います。tag を打つ前に `CHANGELOG.md` に `## [vX.Y.Z]` entry を追加し、release workflow と同じ検証を実行してください。

```sh
make release-check VERSION=v0.1.0
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

`make release-check` は matching version heading の確認、format/vet/test、Linux `amd64`/`arm64` archive の build、smoke test を行います。`v*` tag を push すると release workflow が同じ script を実行し、checksum と GitHub Release を作成します。tag は `vMAJOR.MINOR.PATCH` または `v0.1.0-rc.1` のような SemVer prerelease に一致する必要があります。
