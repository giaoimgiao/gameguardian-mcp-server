# MemoryDriver 内核驱动协议逆向笔记

本仓库的 `engine.go` 通过直连 **MemoryDriver** 内核模块（KPM, Kernel Patch Module）实现无 ptrace 内存读写。协议通过逆向 `libKernelGg.so`（8KB hook 库）得出。

## 背景

GG101（GameGuardian）的守护进程架构：

```
GG主程序 → su → lib05.so(守护进程, arm64) → exec lib5.so(内存引擎)
```

社区内核方案通过替换/包装 `lib5.so` 注入 hook 库，拦截 `process_vm_readv`（syscall 270）并重定向到内核驱动。

## 关键发现

### 1. GG101 守护进程要求 lib5.so 必须是合法 ELF

脚本方案（`#!/bin/sh` + LD_PRELOAD + exec）会被守护进程拒绝（表现为 "already run" —— 实际是 GG 的 `exitValue()` 抛异常时的提示语）。**解决方案**：编译一个静态 PIE 的 ELF 桩加载器（`lib5_stub.c`），保持 ELF 身份，内部设置 `LD_PRELOAD` 后 exec 原始库。

### 2. KPatch-Next 的 supercall 通道

KPatch-Next 劫持 **syscall 45**（arm64 的 truncate）作为 KPM 控制通道：

```
syscall(45, key, compact_cmd(key, SUPERCALL_KPM_CONTROL), module_name, cmd_name, buf, len)
```

- hello 测试：`syscall(45, "hello2026", 0x1000)` → `0x20262026`
- 版本查询：`0x1008` → KP 版本号
- KMA（King777 闭源驱动）客户端硬编码使用 **syscall 117**，与 KPatch-Next 的 45 错位 → 表现为 `ENOENT`（truncate 把 key 当路径）

### 3. MemoryDriver 协议（本仓库使用）

```
fd = socket(AF_INET, SOCK_DGRAM, 0)          // 伪装UDP socket
读: ioctl(fd, 0x7e1a, &struct{pid:u32, pad:u32, addr:u64, buffer:u64, size:u64})
写: ioctl(fd, 0x7e1b, &struct{...})
```

- **无密钥认证**，struct 第一个字段就是目标 pid
- 返回值为实际读/写字节数
- 用 UDP socket fd 做 ioctl 通道（而非 `fd=-1`），从反检测角度看更像正常网络操作
- 驱动在 kernel 内部通过 `get_task_mm` + `mmap_read_lock` + `probe_kernel_read/write` 完成页表级访问

### 4. 逆向方法

1. `strings` 发现 hook 库导入 `socket`/`ioctl`，无 /dev 路径（字符串混淆）
2. `objdump -d` 定位 `svc #0` 与 `ioctl@plt`/`socket@plt` 调用点
3. 发现构造器创建 UDP socket（`socket(2,2,0)`）
4. ioctl 调用点寄存器追踪：`w1=#0x7e1a`，struct 通过 `stp xzr,x0,[sp,#8]` 等指令组装
5. 暴力试错：`0x7e1c` 返回 ESRCH（"no such process"）→ 确认内核劫持生效，字段含义逐渐确定
6. 最终验证：跨进程读 libc ELF 头返回 `7f454c46`，写入测试值生效

## 协议摘要

| 项目 | 值 |
|---|---|
| 通道 | UDP socket fd |
| 读 request | `0x7e1a` |
| 写 request | `0x7e1b` |
| struct | `{u32 pid; u32 pad; u64 addr; u64 buffer; u64 size}` |
| 返回 | 实际传输字节数 |

## 备选驱动（仓库 Gg_Docking_Kernel 中）

| 驱动 | hook库大小 | 说明 |
|---|---|---|
| KMA-RW-DRIVER | 2MB | King777 闭源，需 syscall117 supercall，4.19 内核 init 成功但客户端错位 |
| ApReadioctl | 229KB | 走 syscall45 KPM_CONTROL + ioctl(-1)，`[kpm_kread] init error -1`（本内核失败） |
| **MemoryDriver_IOCTLhook** | **8KB** | ✅ 本仓库使用，socket+ioctl，4.19 内核 init 成功 |
| fscan-ioctl (FastScan) | 7KB | ioctl 类，可用 |
| ditPro_kpm | 8.6KB | ioctl 类，可用 |
