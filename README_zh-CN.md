# keybox

跨平台 CLI 凭据管理器。将密码、Token、API Key 存储在单个加密凭据库中，支持三个安全等级和元数据标记，方便 LLM 自动推理选择合适的凭据。支持 macOS、Linux、Windows。

## 安全模型

所有凭据存储在单个文件（`~/.config/keybox/keybox.keystore`）中。**双层加密**同时保护元数据和凭据值：

| 层 | 用途 | 加密算法 |
|----|------|---------|
| **外层** | 保护元数据 + 加密的凭据 + 密钥对 | AES-256-GCM（系统保护器） |
| **内层** | 独立保护每个凭据的密码值 | age X25519 + ChaCha20-Poly1305 |

三个加密等级决定了内层 age 私钥的保护方式：

| 等级 | 安全根基 | 私钥保护方式 |
|------|---------|-------------|
| **secret**（默认） | 机器物理访问 | 系统保护器（Keychain / DPAPI / machine-id）— 自动解密 |
| **confidential**（机密，`con`） | 人脑记忆 | 主密码通过 age scrypt 保护 |
| **top-secret**（绝密，`top`） | 物理介质持有 | 密钥文件内容 SHA-256 → AES-256-GCM |

- **加密**（添加凭据）只需公钥 — 永远不需要输入密码或密钥文件
- **解密**（获取密码）需要通过对应等级的安全根基解锁私钥
- 所有元数据（名称、描述、标签、时间戳）由外层加密保护
- 双层 AEAD 完整性：AES-256-GCM 保护文件，age AEAD 保护每个凭据

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
# 初始化（secret 等级自动初始化，confidential/top-secret 可选）
keybox init

# 添加凭据
keybox add github.com:brian           # 交互式输入 token，默认 secret 等级
keybox add aws:admin --level confidential      # 存储在机密等级
keybox add :my-root --tags "default"  # 省略 domain 使用默认值

# 获取凭据（默认显示警告，需指定 --clipboard/--env/--force）
keybox get password -u github.com:brian --clipboard   # 复制到剪贴板（secret 自动解密）
keybox get password -u aws:admin --clipboard          # 提示输入主密码（confidential 等级）
keybox get password -u github.com:brian --force       # 强制明文输出
keybox get password -u github.com:brian --env GITHUB_TOKEN  # 注入环境变量
keybox get description -u github.com:brian            # 输出元数据（无需解密）

# 列出所有凭据（默认 JSON 格式）
keybox list
keybox list --fmt table --tag git

# 生成随机密码
keybox gen --length 32 --clipboard
keybox gen --save github.com:new-token --description "CI 机器人"
```

## 命令参考

```
keybox [--base <dir>] <command> [args...]
```

### 命令

| 命令 | 说明 |
|------|------|
| `init [--level <secret\|confidential\|top-secret>]` | 初始化凭据库和/或加密等级 |
| `add <domain:account> [--level] [--description] [--tags]` | 添加凭据（默认 secret 等级） |
| `get [field] -u <domain:account>` | 获取字段：password、description、tags、metadata、all |
| `list [--fmt json\|table] [--level] [--tag]` | 列出凭据（默认 JSON，密码显示为 `<masked>`） |
| `edit <domain:account> --description/--tags` | 编辑凭据元数据 |
| `update password <domain:account>` | 更新凭据密码（先验证旧密码） |
| `delete <domain:account>` | 删除凭据 |
| `gen [--length] [--passphrase] [--save]` | 生成随机密码/助记短语 |
| `serve` | 启动后台守护进程 |
| `unlock --level <confidential\|top-secret> [--timeout]` | 解锁守护进程，获取访问令牌 |
| `lock` | 锁定守护进程（吊销所有令牌） |
| `stop` | 停止守护进程 |

### `get` 输出选项

| Flag | 行为 |
|------|------|
| *(默认)* | 显示安全警告 — 不加 `--force` 不输出明文密码 |
| `--clipboard, -c` | 复制密码到剪贴板 |
| `--env, -e <VAR>` 或 `-e <VAR1:VAR2>` | 注入为环境变量 |
| `--force, -f` | 强制输出密码明文到 stdout |
| `--access-token <token>` | 使用守护进程令牌（confidential/top-secret，非交互） |

### 加密等级

等级通过 `--level` 在每个命令中指定，不再是全局 flag：

```bash
keybox init --level confidential              # 初始化机密等级
keybox add aws:root --level top-secret      # 以绝密等级添加
keybox unlock --level confidential          # 解锁机密等级
```

未指定时默认为 `secret`。`:account` 简写形式使用 `default` 作为域名。

## 守护进程与令牌访问

守护进程（`keybox serve`）将凭据库保持在内存中。对于 confidential/top-secret 等级，解锁后会生成有时限的访问令牌：

```bash
# 启动守护进程
keybox serve

# 解锁 confidential 等级（提示输入主密码），获取 30 分钟有效令牌
keybox unlock --level confidential --timeout 30
# → Token: dGhpcyBpcyBhIHRva2Vu...

# 使用令牌进行非交互访问
keybox get password -u aws:admin --access-token dGhpcyBpcyBhIHRva2Vu...

# 锁定会吊销所有令牌
keybox lock
```

Secret 等级的凭据不需要守护进程 — 直接自动解密。

## 非交互模式

用于脚本和 CI/CD，使用 `--no-interactive` 配合环境变量。

> **⚠️  不要在命令行直接设置敏感环境变量：**
> `KEYBOX_MASTER_PASSPHRASE=mysecret keybox get ...` 会将密码暴露在
> shell 历史记录中（`.bash_history`、`.zsh_history`）。请在包装脚本或
> 子 shell 中设置敏感环境变量：

```bash
# ✅ 推荐：包装脚本
#!/bin/bash
export KEYBOX_MASTER_PASSPHRASE="mysecret"
keybox get password -u aws:admin --no-interactive --clipboard

# ✅ 或使用子 shell
env KEYBOX_MASTER_PASSPHRASE="mysecret" \
    keybox get password -u aws:admin --no-interactive --clipboard

# ✅ 添加凭据（自动读取 KEYBOX_SET_PASSWORD_ONESHOT）
keybox add github.com:ci --no-interactive

# ✅ 使用守护进程令牌
keybox get password -u aws:admin --no-interactive --clipboard \
    --access-token "$KEYBOX_CON_ACCESS_TOKEN"
```

所有敏感环境变量在读取后会被**清空**（设为空字符串），防止在 shell 会话中残留。

当检测到子进程调用（或设置了 `KEYBOX_LLM_CALLING=1`），keybox 会拒绝交互并给出引导提示。

## 存储结构

单个凭据库文件 `~/.config/keybox/keybox.keystore`：

```
二进制头部（26 字节）：
  magic "KBOX" | version | key_ref | nonce
加密体（AES-256-GCM）：
  JSON 包含 key_pairs + credentials + metadata
```

每个凭据记录包含：
- `id`、`domain`、`account` — 标识符
- `description`、`tags` — LLM 友好的元数据
- `created_at`、`updated_at` — 时间戳
- `crypt_level` — secret / confidential / top-secret
- `secret` — age 加密的凭据值（base64）

## 平台差异

| 平台 | 系统保护器 |
|------|-----------|
| macOS | Keychain Services |
| Windows | DPAPI（CryptProtectData） |
| Linux | /etc/machine-id + AES-256-GCM + chmod 600 |

守护进程在 macOS/Linux 上使用 Unix domain socket，Windows 使用命名管道。

## 构建与测试

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

每次 push 到 main 分支，CI 自动在 ubuntu、macos、windows 三平台构建和测试。

## License

MIT
