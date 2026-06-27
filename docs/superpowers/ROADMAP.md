# Keybox 后续需求清单

Date: 2026-06-27
Status: Draft

---

## P0 — 功能缺口

| # | 项 | 说明 | 范围 |
|---|-----|------|------|
| 1 | `keybox unlock --level con,top` 多级别解锁 | ✅ 完成 — 一个 token 多 scope，默认解锁 con+top | 中 |
| 2 | con/top 端到端集成测试 | init→add→serve→unlock→get with token 完整流程 | 中 |

## P1 — 新功能（需 spec/plan）

| # | 项 | 说明 | 范围 |
|---|-----|------|------|
| 3 | 自动更新检查 / 更新 | `keybox update` 命令，检查 GitHub Releases 新版本，下载替换 binary | 大 |
| 4 | Rotate master key | 改 con 主密码 / top 密钥文件，重加密 age 私钥（凭据值不动） | 中 |
| 5 | Export 导出 | 导出 keystore 为可传输格式（加密 or 明文选项、指定 level、指定凭据） | 中 |
| 6 | Import 导入 | 从其他设备的 export 文件导入，合并/替换/冲突处理 | 中 |

## P2 — 工程质量

| # | 项 | 说明 | 范围 |
|---|-----|------|------|
| 7 | `Result<_, String>` → `KeyboxError` enum 收尾 | 全局 String error 已部分替换，检查剩余 | 小 |
| 8 | daemon 不感知外部 keystore 修改 | 非 daemon 方式修改后 daemon 不会重载 | 中 |
| 9 | daemon 闲置超时自动 lock | 当前只有手动 `keybox lock` | 小 |
| 10 | `update password` 非交互模式 | 当前不支持 `--no-interactive` | 小 |
| 11 | unlock ROT retry（3次） | spec 设计要求，当前只单次尝试 | 小 |
| 12 | `protect_to_bytes`/`unprotect_from_bytes` 清理 | macOS 路径问题已绕开，这些函数 unused | 小 |
| 13 | Context-aware credential suggestions | 根据上下文输出最适合的凭据 | 大 |
| 13 | Environment-based auto-detection | 优先级逻辑 | 大 |
| 14 | TLS safe credential retrieval | 确保安全传输 | 大 |
| 15 | Third-party plugin support | 扩展集成 | 大 |
| 16 | Automated credential rotation | 定期更新凭据 | 大 |
| 17 | Interactive TUI | 终端UI | 大 |
| 18 | Notification system | 到期提醒 | 中 |
| 19 | Automated initial key generation | 自动生成初始密钥 | 小 |
| 20 | Fine-grained permission control | 细粒度权限 | 大 |
| 21 | Cloud sync/backup | 云同步备份 | 大 |
