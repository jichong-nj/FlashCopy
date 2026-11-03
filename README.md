# FlashCopy

`FlashSend` / `FlashReceive` 是一对 Windows 命令行工具：把任意文件切分成带编号的
ICMP Echo Request（Ping）报文，借助 `nping.exe`（Nmap 自带）把报文发出去；接收端用
Raw Socket 混杂模式监听目的地址为指定 IP 的所有 Ping 包，并按逆逻辑还原出文件。

**核心特点**

- **只发不等收**：发送端全程不调用任何 `recv*`，不等待任何 Echo Reply，目的 IP
  是否存在、是否可达都不影响发送流程。
- **目的 IP 可虚构**：报文里写的目的地址不必是真实主机（适合用子网广播地址做
  同网段验证）。
- **即时打印**：收发两端每处理一个报文都实时打印；接收端实时显示进度，例如
  `已收到 10/100 (10.0%)`，收齐后写出文件。
- **健壮重组**：乱序、重复分片去重、元信息报文丢失（自动用默认名）、分片丢失
  （超时补零写成 `.partial`）均能处理；每个分片带 CRC32 校验。

---

## 1. 快速开始

> `FlashReceive` **需要管理员权限**（依赖 Raw Socket + `SIO_RCVALL` 混杂模式）；
> `FlashSend` 通过 `nping.exe` 发包，同样建议以管理员身份运行，且要求 `nping.exe`
> （随 Nmap 安装）位于 `PATH`。

### 1.1 编译

**本机已用 MSVC 编译好 `FlashSend.exe` / `FlashReceive.exe`。** 重新编译：

```bat
build.bat
```

`build.bat` 调用 VS 的 `vcvars64` 环境后用 `cl` 编译，关键开关已带 `/utf-8`
（源码为 UTF-8，否则中文即时打印会乱码），并链接 `ws2_32.lib`。

若使用 MinGW-w64 / MSYS2：

```sh
make
```

### 1.2 运行示例

接收端先启动（监听目的 IP 为 `192.168.1.255` 的所有 Ping 包）：

```bat
FlashReceive.exe 192.168.1.255 -o D:\recv -t 60 -v
```

发送端（只发不等收，经 nping 发包）：

```bat
FlashSend.exe 192.168.1.255 D:\test.zip -s 1024 -d 2 -r 1 -m 3
```

发送端每片打印（实际由 nping 发出 ICMP Echo Request）：

```
[发送] 第 12/100 片  1024 B  重发=1  会话=0x1A2B3C4D -> 192.168.1.255
```

接收端实时进度：

```
[接收] 会话=0x1A2B3C4D 分片 12/100  1024 B  源=192.168.1.10 -> 目的=192.168.1.255  已收到 10/100 (10.0%)
...
[完成] 会话=0x1A2B3C4D 文件 "test.zip" 已还原 100/100 分片，123456 字节 -> D:\recv\test.zip
```

**离线还原（从抓包文件）**：若已经用 Wireshark / tcpdump 录下了 `FlashSend` 发出的包（`.pcap`），
可直接事后还原，**无需管理员、无需网卡权限**：

```bat
FlashPcap.exe capture.pcap 192.168.1.255 -o D:\recv
```

`FlashPcap` 读取 pcap、取出目的 IP 等于 `192.168.1.255` 的所有 ICMP Echo 报文，复用与
`FlashReceive` 完全相同的重组逻辑还原文件。链路层类型自动识别（以太网/Linux SLL/原始 IP 等），
特殊抓包可用 `-l <链路层头字节>` 手工指定。

**实时抓包（Npcap / 与 Wireshark 相同方式，非混杂模式）**：若想实时抓包还原、又不想用 `FlashReceive`
的 Raw Socket + `SIO_RCVALL` 混杂模式，可用 `FlashRecvPcap`（依赖本机已装的 Npcap，与 Wireshark 同款）：

```bat
FlashRecvPcap.exe 192.168.1.255 -o D:\recv
```

省略 `-i` 时会列出本机所有抓包设备并交互选择；也可用 `-i <设备名>` 直接指定。程序以 `promisc=0`
（非混杂模式）打开，只捕获发往本机 / 广播 / 组播的 ICMP 包，并自动用 BPF 过滤器 `icmp and dst host
<目的IP>` 缩小范围。注意：实时抓包在 Windows 上仍需要**管理员权限**（与 Wireshark 一致）。
`FlashRecvPcap` 通过 `LoadLibrary` 动态加载 `wpcap.dll`，无需安装 Npcap SDK 即可编译。

**目的 IP 可省略——抓本机自己发出的 ping**：`<目的IP>` 是可选的。省略时 BPF 改为只抓 `icmp`
（不限定目的地址），这样连**本机自己发出的 ICMP** 也能抓到——例如你在同一台机器上 `ping` 一个不存在的
IP，只要抓包设备选对了（普通外网 IP 走物理网卡，如上面的 Realtek；`127.0.0.1` 走 Loopback 适配器），
就能看到那些 Echo Request 被捕获（普通 ping 不含文件数据，会显示为「[普通ping]」并计入统计，但无法还原成文件）。
指定目的 IP 时则回到「只收发往该 IP 的 ICMP」的精确过滤。

---

## 2. 命令行参数

### FlashSend（发送端）

```
FlashSend <目的IP> <文件> [选项]
```

| 参数 | 说明 | 默认 |
|---|---|---|
| `<目的IP>` | 写入 IP 头的目的地址，可是一个并不存在的地址 | 必填 |
| `<文件>` | 要发送的文件路径 | 必填 |
| `-s <字节>` | 分片大小，范围 `64..1400` | `1024` |
| `-d <毫秒>` | 报文之间的间隔（`0` = 不等待） | `2` |
| `-r <次数>` | 整份文件重复发送轮数 | `1` |
| `-m <次数>` | 元信息报文在每轮中的重发次数（对抗丢包） | `3` |
| `-b <本机IP>` | 通过 `nping -S` 指定源 IP（选出口网卡）；不填则由系统路由决定 | 系统路由 |
| `-x` | 打印每个报文传给 `nping --data` 的载荷（`FlashHeader` + body）十六进制转储 | 关闭 |
| `-h` / `--help` | 显示帮助 | — |

> 发送端依赖 `nping.exe`（Nmap 自带）。它会为每个分片起一个 `nping` 进程，用
> `nping --icmp --icmp-type 8 --icmp-id 1 --data <载荷> -c <重发次数> -N` 发包；
> `-N` 表示**不等待任何回显**（只发不等收）。

### FlashReceive（接收端）

```
FlashReceive <目的IP> [选项]
```

| 参数 | 说明 | 默认 |
|---|---|---|
| `<目的IP>` | 只处理 IP 头中目的地址等于该值的 ICMP 报文 | 必填 |
| `-o <目录>` | 还原文件的输出目录 | 当前目录 |
| `-b <本机IP>` | 绑定到哪块本地网卡（默认自动探测） | 自动 |
| `-t <秒>` | 空闲超时；超时后把未收齐的文件写成 `.partial`；`0` = 不超时 | `60` |
| `-v` | 详细模式，打印所有命中目的 IP 的 Ping 报文 | 关闭 |
| `-h` / `--help` | 显示帮助 | — |

---

## 3. 报文格式

报文承载在 **ICMP Echo Request (Type=8, Code=0)** 的载荷里（Wireshark 可直接看）：

```
+----------------+----------------+----------------------------------+
| ICMP 头 (8B)   | FlashHeader    | body                             |
|                | (48B, 网络序)  |                                  |
+----------------+----------------+----------------------------------+
```

- ICMP 头：由 `nping` 生成（`FlashSend` 调用
  `nping --icmp --icmp-type 8 --icmp-id 1 --data <载荷>`），**对齐常见 `ping` 抓包**——
  `type/code=8/0`，`id=1`（纯外观，接收端只认载荷里的 `session`），
  `seq` 由 `nping` 自增。分片编号写在载荷 `FlashHeader.index` 里。
- 载荷（`nping --data` 的内容）：`FlashHeader`(48B) + body，格式与下方完全一致。
- `FlashHeader`（12 个 `uint32_t`，全部网络序大端，共 48 字节）：

| 字段 | 含义 |
|---|---|
| `magic` | `0x46535350` (`"FSSP"`)，用于识别本工具报文 |
| `version` | 协议版本（当前 `1`） |
| `session` | 一次传输的随机 ID，区分不同文件 |
| `type` | `0`=元信息（携带文件名），`1`=数据分片 |
| `index` | 分片编号：`0`=元信息，`1..total`=数据分片 |
| `total` | 数据分片总数 |
| `length` | 紧跟其后的 body 字节数 |
| `file_size_hi/lo` | 原文件大小（64 位） |
| `name_len` | 文件名长度（仅元信息报文有效） |
| `chunk_size` | 分片大小，便于缺失分片补零还原 |
| `crc32` | body（文件名或分片数据）的 CRC32 |

- `body`：
  - 元信息报文（`index=0`）→ 文件名原始字节；
  - 数据报文（`index=1..total`）→ 文件分片原始字节。

ICMP 校验和覆盖 ICMP 头 + `FlashHeader` + body（RFC 1071）；body 另带 CRC32，
接收端对每条分片做校验，失败即丢弃。

---

## 4. 接收端重组逻辑

- 以 `session` 区分不同传输会话，会话内以 `index` 区分分片。
- 支持**乱序**到达；已收到的分片用内存位图记录，**重复分片直接忽略**。
- 元信息报文（`index=0`，携带文件名）若丢失，接收端会从数据报文里补齐
  `total/chunk_size/file_size`，并生成默认文件名 `flash_<session>.bin`。
- 每收到一个数据分片实时打印 `已收到 X/Y (Z%)` 进度。
- 当 `received == total` 时，自动落盘并报告 `[完成]`。
- 若指定了 `-t` 空闲超时（或 `Ctrl+C` 退出），未收齐的会话会写出
  `xxx.partial`，缺失分片以 `0x00` 补齐，便于后续手工对齐。

---

## 5. 实践注意事项

1. **两台机器分别运行**：Windows 的 `SIO_RCVALL` 一般只抓「进入网卡」的包，
   抓不到本机发出的包。建议发送端、接收端分别跑在不同机器；或接收机接在
   Hub / 交换机镜像口 / 网关上。

2. **交换机环境下虚构单播 IP 抓不到**：发往不存在的单播 IP 时，帧的目的 MAC
   是网关或 ARP 失败被丢弃，同网段其它端口收不到。最省事的验证方式：把
   目的 IP 填成**子网广播地址**（如 `192.168.1.255`，它本身不对应任何主机），
   发送端已自动置 `SO_BROADCAST`，帧以广播 MAC 发出，接收端用同一地址作过滤
   目标即可抓到。**若确需任意虚构 IP，接收机必须处在流量路径上（镜像口/网关）。**

3. **管理员权限**：非管理员时 `FlashReceive` 会报 `WSAGetLastError=10013` 并提示。
   发送端经 `nping.exe` 发包，`nping` 注入原始报文同样需要管理员权限。

4. **分片大小上限**：`-s` 最大 `1400`，以保证 `20(IP)+8(ICMP)+48(Flash)+1400 ≤ 1476`
   不超过以太网 `1500` 的 MTU，避免 IP 分片。

---

## 6. 文件清单

| 文件 | 说明 |
|---|---|
| `FlashSend.c` | 发送端源码（构造载荷并调用 `nping.exe` 发包） |
| `FlashReceive.c` | 接收端源码（实时混杂抓包与主控；重组核心在 `flash_common.c`） |
| `FlashRecvPcap.c` | 实时抓包还原源码：用 Npcap（与 Wireshark 相同方式）**非混杂模式**抓 ICMP 并还原文件（动态加载 `wpcap.dll`，无需 SDK） |
| `FlashPcap.c` | 离线还原源码：从 `.pcap` 抓包文件按目的 IP 过滤 ICMP 并还原文件（复用同一份重组核心） |
| `flash_common.h` / `flash_common.c` | 共用报文格式、ICMP 校验和、CRC32、IP 解析，以及**接收端重组核心**（被 `FlashReceive` / `FlashPcap` / 自测共享） |
| `selftest.c` | 回归自测：直接驱动真实接收逻辑，验证乱序/去重/缺片/过滤 |
| `build.bat` | MSVC 构建脚本（已带 `/utf-8`，同时编译 `FlashPcap.exe` 与 `selftest.exe`） |
| `Makefile` | MinGW-w64 / MSYS2 构建 |
| `FlashSend.exe` / `FlashReceive.exe` / `FlashPcap.exe` / `selftest.exe` | 已编译的可执行文件 |

---

## 7. 协议兼容性说明

- 仅发送 ICMP Echo Request，**不发送任何其它 ICMP**，也不接收任何回显。
- 目的 IP 可填广播地址（`nping` 会以广播形式发出，发送端不再自行设置 `SO_BROADCAST`）。
- 接收端解析时跳过 IP 分片（`frag_off` 非零）与 IP 选项，仅处理完整的
  Echo Request / Reply，并按 `magic+version` 过滤本工具报文，避免被网内其它
  Ping 流量干扰。
