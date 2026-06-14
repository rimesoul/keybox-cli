# keybox

跨平台 CLI 凭据管理器。安全存储密码、Token、API Key，提供三个独立安全等级的加密存储。支持 macOS、Linux、Windows，包括无 GUI 的 SSH 终端环境。

## 安全模型

三个安全等级，各自独立的加密存储。所有凭据使用 [age](https://age-encryption.org)（X25519 + ChaCha20-Poly1305）加密。差异在于 age 身份私钥的保护方式：

| 等级 | Flag | 私钥保护 | 安全根基 |
|------|------|---------|---------|
| **秘密** | `--secret` | 系统绑定（Keychain / DPAPI / machine-id） | 机器物理访问 |
| **机密** | `--confidential` | 密码派生（age passphrase / scrypt） | 人脑记忆 |
| **绝密** | `--top-secret` | 文件哈希派生（SHA-256 → AES-256-GCM） | 物理介质持有 |

- 三个等级**完全独立** — 破解一个不会影响其他
- 凭据永不以明文存储于磁盘
- 机密和绝密等级支持守护进程，将解密后的私钥缓存在内存中（类似 ssh-agent）

## 安装

### 预编译二进制

从 [GitHub Releases](https://github.com/rimesoul/keybox-cli/releases) 下载对应平台。

### 源码编译

```bash
git clone https://github.com/rimesoul/keybox-cli.git
cd keybox-cli
cargo build --release
# 二进制文件: target/release/keybox
```

## 快速开始

```bash
# 秘密等级（默认）— 自动初始化，无需任何设置
keybox add gitea pat               # 交互式输入 Token
keybox get gitea pat               # 输出到 stdout

# 非交互模式（脚本/自动化）
keybox add gitea pat --non-interactive --password "ghp_xxx"

# 机密等级 — 需要先初始化并设置主密码
keybox --confidential init
keybox --confidential add ldap workuser

# 注入子进程环境变量，不在终端显示凭据
keybox get gitea pat --env GITEA_TOKEN -- ./my-script.sh

# 复制到剪贴板（终端不显示）
keybox get gitea pat --clipboard
```

## 命令参考

```
keybox [--secret|-s|--sec] [--confidential|-c|--con] [--top-secret|-t|--top]
       <operation> [args...]
```

### 操作

| 命令 | 说明 |
|---------|-------------|
| `add <domain> <account>` | 添加凭据（交互式提示或 `--non-interactive --password`） |
| `get <domain> <account>` | 获取凭据（`--clipboard` / `--env <VAR>` / stdout） |
| `list [domain]` | 列出所有 domain，或指定 domain 下的 account（`--json`） |
| `update <domain> <account>` | 更新已有凭据 |
| `delete <domain> <account>` | 删除凭据（需确认） |
| `init` | 初始化当前等级（机密/绝密需显式调用） |
| `serve` | 启动守护进程（仅机密/绝密） |
| `unlock` | 预解锁守护进程 |
| `lock` | 锁定守护进程（清除内存中的私钥） |
| `stop` | 停止守护进程 |

### `get` 输出选项

| Flag | 行为 |
|------|----------|
| *(默认)* | 输出到 stdout |
| `--clipboard` | 复制到系统剪贴板 |
| `--env <VAR> -- <cmd>` | 注入子进程环境变量 |

### 等级 Flag 别名

| 全称 | 短写 | 别名 |
|------|-------|-------|
| `--secret` | `-s` | `--sec` |
| `--confidential` | `-c` | `--con` |
| `--top-secret` | `-t` | `--top` |

Flag 可以放在命令的任意位置。默认等级为 `--secret`。

## 守护进程

机密和绝密等级使用后台守护进程将解密后的身份私钥缓存在内存中：

```bash
# 启动守护进程（LOCKED 状态）
keybox --confidential serve

# 解锁（输入一次主密码）
keybox --confidential unlock

# 之后所有命令无需重复输入密码
keybox --confidential get gitea pat
keybox --confidential list openai

# 完成后锁定
keybox --confidential lock

# 或者完全停止
keybox --confidential stop
```

当 CLI 命令需要守护进程但未运行时，会自动启动。

## 非交互模式

用于脚本、CI/CD，或 stdin 不是 TTY 的场景：

```bash
keybox add gitea pat --non-interactive --password "token123"
keybox update gitea pat --non-interactive --password "new-token"
keybox --confidential init --non-interactive --password "master123"
keybox --top-secret init --non-interactive --file /path/to/key
```

当检测到子进程调用（或设置了 `KEYBOX_LLM_CALLING=1`），keybox 会拒绝交互并给出引导：

```
Error: keybox requires interactive input (LLM calling mode detected).
Possible resolutions (in order of preference):
  1. Ask the user to unlock the daemon directly on the machine:
     `keybox --confidential unlock` (or `--top-secret`).
     Once unlocked, all commands will work without prompts.
  2. Use non-interactive mode with a credential provided by the human:
     `--non-interactive --password <value>`
  3. If the daemon is already running but locked, ask the user to unlock it.
  4. Ask the human for the credential directly:
     "I need access to [description]. Can you provide the value or unlock keybox?"
```

## 存储结构

所有数据在 `~/.config/keybox/` 下：

```
~/.config/keybox/
├── secret/                    # 秘密等级：系统绑定
│   ├── identity.private.enc
│   ├── identity.pub
│   └── store/<domain>/<account>.enc
├── confidential/              # 机密等级：密码保护
│   ├── identity.private.enc   # age passphrase 加密
│   ├── identity.pub
│   └── store/<domain>/<account>.enc
└── top-secret/                # 绝密等级：文件哈希保护
    ├── identity.private.enc   # AES-256-GCM 加密
    ├── identity.pub
    └── store/<domain>/<account>.enc
```

## 平台差异

| 平台 | 秘密等级保护机制 |
|------|----------------|
| macOS | Keychain Services |
| Windows | DPAPI（CryptProtectData） |
| Linux | /etc/machine-id + AES-256-GCM + chmod 600 |

守护进程在 macOS/Linux 上使用 Unix domain socket，Windows 暂不支持守护进程（返回错误提示 — 秘密等级在 Windows 上可独立正常使用）。

## 构建与测试

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

每次 push 到 main 分支，CI 自动在 ubuntu、macos、windows 三平台构建和测试。

## License

MIT
