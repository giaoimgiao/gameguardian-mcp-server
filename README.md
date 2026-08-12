# GameGuardian MCP Server · 终端版 GameGuardian（GG修改器）

把 **GameGuardian（GG修改器）** 的核心能力搬到 MCP（Model Context Protocol）——让 AI 助手可以直接选择进程、搜索内存、模糊搜索、读写修改、计算偏移、冻结数值、暂停/恢复进程，全部通过标准 MCP 工具调用，**内核级读写、抗检测**。

```
┌─────────────┐   MCP (JSON-RPC over HTTP)   ┌──────────────────┐
│  AI / MCP   │ ───────────────────────────▶ │  gg-mcp-server   │
│  Client     │ ◀─────────────────────────── │  (Go, root)      │
└─────────────┘      127.0.0.1:8788/mcp      └────────┬─────────┘
                                                       │ ioctl(fd, 0x7e1a/0x7e1b)
                                                       ▼
                                          ┌──────────────────────┐
                                          │ MemoryDriver KPM     │
                                          │ (kernel module)      │
                                          │ 页表级读写, 无ptrace │
                                          └──────────────────────┘
```

## ✨ 功能（26 个 MCP 工具）

### 进程管理
| 工具 | 说明 |
|---|---|
| `gg_list_processes` | 列出所有进程（pid/名称/命令行/uid），支持过滤 |
| `gg_attach` | 附加目标进程（pid 或包名），自动初始化内核通道 |
| `gg_detach` | 分离进程 |
| `gg_target_info` | 目标进程内存映射概况 + 模块列表 |
| `gg_module_list` | 已加载模块（路径+基址+大小） |

### 内存搜索
| 工具 | 说明 |
|---|---|
| `gg_search` | 已知值精确搜索（byte/word/dword/qword/float/double） |
| `gg_search_unknown_init` | 模糊搜索初始化（未知初值，位图+快照） |
| `gg_search_refine` | 模糊细化：increased/decreased/unchanged/changed |
| `gg_search_range` | 区间搜索（min~max） |
| `gg_result_count` | 结果数量 |
| `gg_get_results` | 查看结果（地址+当前值） |
| `gg_clear_results` | 清空结果 |

### 读写修改
| 工具 | 说明 |
|---|---|
| `gg_read` / `gg_read_bytes` / `gg_hex_dump` | 读值/读字节/hex 转储 |
| `gg_write` | 写指定地址 |
| `gg_set_results` | 批量修改搜索结果（按 index 或 address） |
| `gg_freeze` / `gg_unfreeze` | 冻结值（持续写入）/ 解冻 |

### 分析定位
| 工具 | 说明 |
|---|---|
| `gg_module_base` | 模块基址 |
| `gg_calc_offset` | 地址相对模块基址偏移 |
| `gg_pointer_scan` | 指针扫描（找指向目标地址的指针链） |
| `gg_pause` / `gg_resume` | 暂停/恢复进程（断点模拟，SIGSTOP/SIGCONT） |
| `gg_status` / `gg_shell` | 会话状态 / 执行 shell 命令 |

## 🧠 内核读写引擎

`engine.go` 实现了与 **MemoryDriver KPM**（内核补丁模块）的直连协议：

- 创建 `socket(AF_INET, SOCK_DGRAM)` 作为驱动通道（伪装网络操作）
- **读**：`ioctl(fd, 0x7e1a, &{pid, pad, addr, buffer, size})`
- **写**：`ioctl(fd, 0x7e1b, &{pid, pad, addr, buffer, size})`
- 三重复用降级：内核驱动 → `process_vm_readv` → `/proc/<pid>/mem`，任何一层失败自动切换

> 协议通过逆向 8KB 的 hook 库（`libKernelGg.so`）得出，完整笔记见 [docs/PROTOCOL.md](docs/PROTOCOL.md)

## 🚀 部署

### 前置条件
- Android 11+，已 Root（Magisk/KitsuneMagisk）
- **KPatch-Next**（给 Magisk 加 KPM 支持）：https://github.com/KernelSU-Next/KPatch-Next-Module
- **MemoryDriver_IOCTLhook.kpm** 内核模块已加载

### 编译
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o ggmcp main.go engine.go
```

### 部署
```bash
adb push ggmcp /data/local/tmp/ggmcp/
adb shell su -c 'sh /data/local/tmp/ggmcp/start_ggmcp.sh'
# 或直接:
adb shell su -c 'setsid nohup /data/local/tmp/ggmcp/ggmcp :8788 > /data/local/tmp/ggmcp/ggmcp.log 2>&1 < /dev/null &'
```

### 注册到 MCP 客户端
在 MCP 配置中注册：
```json
{ "endpoint": "http://127.0.0.1:8788/mcp" }
```

### 开机自启
```bash
adb shell su -c 'cp scripts/start_ggmcp.sh /data/adb/service.d/ggmcp.sh && chmod 755 /data/adb/service.d/ggmcp.sh'
```

## 🎮 使用示例

```bash
# 搜索金币
curl -X POST http://127.0.0.1:8788/mcp -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"tools/call",
  "params":{"name":"gg_search","arguments":{"value":"100","type":"dword","region":"anonymous"}}
}'

# 批量改成 99999
curl -X POST http://127.0.0.1:8788/mcp -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":2,"method":"tools/call",
  "params":{"name":"gg_set_results","arguments":{"values":[{"index":0,"value":"99999"}]}}
}'
```

## 📁 项目结构

```
├── main.go          # MCP HTTP 服务器 + 26 个工具实现
├── engine.go        # 内核内存引擎（MemoryDriver协议/搜索算法/进程管理）
├── lib5_stub.c      # GG内核对接: ELF桩加载器（保持lib5.so为合法ELF并注入钩子）
├── scripts/
│   └── start_ggmcp.sh  # 部署/启动脚本
└── docs/
    └── PROTOCOL.md  # MemoryDriver 协议逆向笔记
```

## ⚠️ 免责声明

本项目仅供**技术研究与学习**。请勿用于：
- 联网游戏的作弊（可能违反服务条款并被封号）
- 任何商业或非法用途

使用者需自行承担一切后果。

## 📄 License

[GPL-3.0](LICENSE)

## 🙏 致谢

- [GameGuardian](https://gameguardian.net) — 内存修改器先驱
- [KernelSU-Next/KPatch-Next](https://github.com/KernelSU-Next/KPatch-Next) — KPM 内核补丁框架
- [ZYPyDoki/Gg_Docking_Kernel](https://github.com/ZYPyDoki/Gg_Docking_Kernel) — GG 内核对接思路与驱动仓库
