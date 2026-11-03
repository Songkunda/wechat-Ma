# wechatMa — macOS 微信消息读写服务

在 macOS 上读取微信（WeChat for Mac）的聊天消息，并能通过程序发送消息。
对外提供一个本地 HTTP Server，任何外部系统 / 脚本 / Agent 都可以通过 REST API 调用。

核心方法：使用 [REA](https://github.com/morluto/rea)（Reverse Engineer Anything，MCP 化的逆向分析工具箱）
对 WeChat.app 做离线逆向分析，摸清消息收发与存储的内部实现，据此选择并构建运行时读写链路。

## 1. 项目目标

| 能力 | 说明 |
| :--- | :--- |
| 读消息 | 实时收取新消息事件 + 查询全量历史（发送者 / 文本 / 类型 / 时间） |
| 发消息 | 按联系人或群名直接向内部接口发送文本消息（可扩展图片 / 文件） |
| 多账号 | 同时监控多个微信进程实例 / 多账号，互不串扰 |
| Server | 本地 HTTP REST API，JSON 输入输出，支持外部调用 |

非目标：不实现完整微信客户端、不分发微信二进制或从中提取的资产。
逆向分析仅针对本机自有客户端，用于定位读写路径。

## 2. 功能需求

### 2.1 读取（Read）

- [ ] 实时新消息事件流：注入 agent hook 接收函数 → 事件推送（SSE / webhook）
- [ ] 获取会话列表 / 历史消息：DB 解密直查（会话名、类型、未读数、发送者、正文、类型、时间）
- [ ] 按会话名读消息：`fetch_messages(chat, limit)`，会话名 → wxid 由联系人 DB 解析
- [ ] fsnotify 增量监听作为实时事件的备份通道

### 2.2 发送（Write）

- [ ] 显示名 → wxid 解析（名称归一化：全半角、大小写、空白差异容错；重名 / 歧义拒绝）
- [ ] agent 调用内部发送函数，返回 msgid
- [ ] 发送后回查 DB / 事件流确认入库（best-effort）

### 2.3 多实例（Multi-instance）

- [ ] 自动发现运行中的微信进程，按需注入 agent，按 `wxid` / `pid` 路由
- [ ] 每个实例独立收发，互不串扰；微信重启后自动重新注入

### 2.4 Server

- [ ] HTTP REST API，默认绑定 `127.0.0.1`，端口可配
- [ ] 请求 / 响应均为 JSON
- [ ] `GET /api/health`：实例在线状态 + agent 注入状态 + 版本 profile 匹配自检
- [ ] 可选：Token 鉴权、绑定 `0.0.0.0` 供局域网调用（需显式开启）

## 3. 技术选型

### 3.1 逆向分析工具链：REA

[REA](https://github.com/morluto/rea)（Reverse Engineer Anything）是开源的逆向分析编排层：
本身不是反汇编器，而是把 Ghidra / Hopper / IDA / JADX / pwntools 等引擎包装成
MCP 工具和 CLI，供 Agent 直接调用，产出带证据与局限性说明的分析结论。

| 项 | 说明 |
| :--- | :--- |
| 安装 | `npx rea-agents@latest setup`（注册 MCP + 工作流说明） |
| 运行环境 | Node.js `^22.19` / `^24.11` / `>=26`，macOS 12+ |
| 分析后端 | Ghidra（免费，headless）；可选 Hopper / IDA |
| 分析目标 | `/Applications/WeChat.app` 主二进制（Mach-O）、内嵌 Frameworks、JS/前端资源 |
| 要回答的问题 | 消息如何存储（DB 结构 / SQLCipher 密钥派生）、收消息入口、发消息调用链、是否存在可利用的本地接口（XPC / IPC / 本地 HTTP） |
| 产出 | `docs/analysis/` 分析报告：关键函数、数据结构、定位到的读写路径及证据 |

**定位**：REA 是**开发期**工具，负责回答"微信内部怎么工作"；
它不提供运行时 API，运行时的读写机制由分析结论决定。

### 3.2 消息获取方案对比（运行时机制）

| 方案 | 原理 | 优点 | 缺点 | 结论 |
| :--- | :--- | :--- | :--- | :--- |
| **进程内 hook（主路线·实时）** | 向微信进程注入 agent dylib，hook 消息接收/分发函数拿事件流；调用内部函数发消息 | 真·实时收发；每个进程一个 agent，**天然支持多开**；不依赖 UI | 需要注入向量（task_for_pid / 重签名 / Frida），要关 SIP；hook 点随版本变（REA + profile 解决）；有封号风险 | **选定**：REA 找 hook 点 + 函数签名 |
| **DB 解密（历史 + 准实时）** | REA 定位密钥派生逻辑，sqlcipher 解密本地 SQLite；fsnotify 监听增量 | 全量历史 + 亚秒级新消息（收消息会即时写库）；每个 wxid 数据目录独立 → **支持多账号** | 不能发消息；4.1.x 密钥方案未知（M0 要解） | **选定**：补齐 hook 覆盖不了的历史查询 |
| Accessibility API | 读 UI 控件树 | 零侵入 | **串行化**：一次只能看一个窗口的一个会话，无法同时监控多账号/多会话 | ❌ 弃用（仅留作开发期调试工具） |
| 截图 + OCR / 视觉模型 | 截图识别 | 版本无关 | 慢、不准 | ❌ 弃用 |

**策略**：读 = 注入 hook 实时事件 + DB 解密历史；写 = 注入 agent 调用内部发送接口。
M0 用 REA 确认三件事：可注入向量、接收 hook 点、发送函数签名。

### 3.3 发送方案

- 注入微信进程的 agent dylib 直接调用内部发送函数（函数地址 / 签名 / 调用约定由 REA 在 M0 产出，按版本存 profile）
- 会话定位：`显示名 → wxid` 通过联系人 DB 解析（不走 UI 搜索）；重名 / 歧义拒绝执行
- 发送确认：内部函数返回 msgid + 回查 DB / hook 事件流确认入库（best-effort）
- 调用通道：agent 暴露 unix domain socket，Server 按实例路由

### 3.4 语言与框架

| 层 | 选型 | 说明 |
| :--- | :--- | :--- |
| 逆向分析 | REA（`rea-agents`，Node.js）+ Ghidra | 开发期使用，反编译 / 追踪 / 产出分析报告 |
| 注入 agent | C / ObjC / C++ dylib，hook 用 fishhook 或手写 inline hook | 驻留微信进程内：hook 收事件、调用发送函数、暴露 unix socket |
| 注入器 | lldb `dlopen` / Frida（开发期）；正式注入向量由 M0 确定 | task_for_pid 需要 SIP 关闭 |
| 语言（Server） | Python 3.11+ | FastAPI + 各实例 agent 的 socket 客户端 |
| DB 解密 | sqlcipher / pysqlcipher3 + lldb | 由 REA 分析结论决定具体密钥方案 |
| HTTP Server | FastAPI + uvicorn | 类型友好、自动 OpenAPI 文档（`/docs` 可直接调试） |
| 数据模型 | pydantic | 请求 / 响应校验 |
| 包管理 | uv（或 pip + venv） | |
| 常驻运行 | launchd（可选） | 开机自启、崩溃重启 |

备选方案：Swift + AXSwift + Hummingbird/Vapor，性能更好、可编译为单二进制，但开发成本更高，一期不采用。

### 3.5 所需权限

| 权限 | 用途 | 授权路径 |
| :--- | :--- | :--- |
| **SIP 关闭** | 注入 / task_for_pid / lldb 读进程内存（**核心硬依赖**） | 恢复模式 → `csrutil disable`（需重启；用完可 `csrutil enable` 恢复） |
| 开发者工具（lldb） | 注入 PoC、密钥提取 | 安装 Xcode CLT；`DevToolsSecurity -enable` |
| 辅助功能（Accessibility） | 仅开发期调试 UI 结构（可选） | 系统设置 → 隐私与安全性 → 辅助功能 |

## 4. 架构

### 4.1 开发期（REA 分析管线）

```text
Agent / 开发者
    │  MCP 调用
    ▼
REA (rea-agents) ──► Ghidra headless（反编译 / 伪代码 / 字符串 / 符号 / 调用图）
    │
    ▼
分析报告 docs/analysis/：消息存储结构、密钥派生、收发调用链、可用本地接口
    │
    ▼ 决定运行时主链路
```

### 4.2 运行期（Server）

```text
外部调用方 (curl / 脚本 / Agent)
        │  HTTP + JSON
        ▼
┌──────────────────────────────────┐
│  FastAPI Server                  │  路由 / 鉴权 / 参数校验
├──────────────────────────────────┤
│  Instance Manager                │  发现微信进程 → 注入 → 注册 agent
│  （支持多实例：按 wxid/pid 路由）   │
├───────────────┬──────────────────┤
│  Event Bus    │  History Reader  │
│  (实时事件)    │  (DB 解密+增量)   │
└───────┬───────┴────────┬─────────┘
        │ unix socket    │ sqlcipher
        ▼                ▼
┌──────────────┐   ┌──────────────────┐
│ injected     │   │  xwechat_files/   │
│ agent dylib  │   │  <wxid>/*.db      │
│ (每进程一个)  │   │  (每账号一份)      │
└──────┬───────┘   └────────▲─────────┘
       │ hook + call        │ 写库
       ▼                    │
   WeChat.app 进程 #1       │
   WeChat.app 进程 #2 (多开)─┘
```

### 4.3 读消息流程

#### 实时事件（注入 hook，主路线）

```text
injector: task_for_pid(wechat_pid) → dlopen(agent.dylib)
agent: 在消息接收/分发函数上装 hook（hook 点由 REA 定位，按版本存 profile）
  → 微信收到消息 → 内部函数被调用 → hook 拦截参数 → 解析出 发送者/会话/正文/类型/时间
  → 序列化为事件帧 → unix socket 推给 Server → Server 进 Event Bus → API/SSE 输出
```

多开场景：每个微信进程注入一个 agent，socket 按实例区分，事件带 `wxid` 归属。

#### 历史 + 准实时增量（DB 解密）

```text
REA + Ghidra 反编译 WeChat.app → 定位 SQLCipher 密钥派生逻辑
  → 运行时按相同逻辑计算密钥（或 lldb 提取）
  → sqlcipher 只读打开 ~/Library/Containers/.../xwechat_files/<wxid>/ 下的消息库
  → SQL 直查消息表（发送者 / 正文 / 类型 / 时间戳）
  → fsnotify 监听库文件 → 新消息入库即发现（亚秒级，hook 之外的第二通道/备份）
```

### 4.4 发消息流程

```text
POST /api/chats/{name}/messages {"text": "..."}
  → 显示名 → wxid：查联系人 DB 解析（名称归一化：全半角/大小写/空白容错，歧义则拒绝）
  → Instance Manager 路由到对应微信进程的 agent（unix socket）
  → agent 调用内部发送函数（构造消息对象 → call → 拿 msgid）
  → 回查 DB / 等 hook 事件确认入库 → 返回 API 调用方
```

不经 UI、不占前台，多实例并发互不影响。

### 4.5 M0 需要 REA 回答的问题清单

| 问题 | 产出 |
| :--- | :--- |
| 注入向量 | `task_for_pid` 可行 / 需重签名 + `DYLD_INSERT` / 其他；微信硬化运行时与完整性校验点 |
| 接收 hook 点 | 消息接收/分发函数的符号或偏移、参数结构（消息对象字段偏移） |
| 发送函数签名 | 内部 send 函数的地址、调用约定、参数构造方式 |
| 密钥派生 | SQLCipher 密钥的来源算法（4.1.x 每库一密钥）或内存定位特征 |
| 数据结构 | 消息/会话/联系人核心结构体字段偏移 |
| 版本画像 | 以上全部按版本存 `profiles/wechat-<ver>.json`（字节特征码定位，非硬编码偏移） |

## 5. API 草案

```text
GET  /api/health                       # 实例在线 / agent 注入状态 / 版本 profile 自检
GET  /api/instances                    # 已发现的微信实例（wxid、pid、版本、agent 状态）
GET  /api/instances/{id}/chats         # 会话列表（含未读数）
GET  /api/instances/{id}/chats/{name}/messages?limit=20   # 历史消息
POST /api/instances/{id}/chats/{name}/messages           # 发送  body: {"text": "..."}
GET  /api/events                       # 全实例新消息流（SSE，每条事件带 wxid 归属）
POST /api/webhook                      # 注册 webhook 推送（可选替代 SSE）
```

统一错误格式：`{"error": {"code": "...", "message": "..."}}`，如
`WECHAT_NOT_RUNNING` / `INJECT_FAILED` / `UNSUPPORTED_VERSION` / `CHAT_NOT_FOUND` / `CHAT_AMBIGUOUS`。

## 6. 约束、限制与合规

### 6.1 技术限制

- **SIP 必须关闭**：`task_for_pid`（注入 / lldb 读内存）在 SIP 开启下对第三方签名进程不可用——这是注入路线的硬依赖
- 注入状态随微信重启失效，需自动重注入；微信崩溃概率非零（hook 质量直接影响稳定性）
- 可能触发微信完整性校验 / 反调试，M0 需评估；有**封号风险**（见 6.2）
- DB 解密：4.0.3.80 之后密钥不再长时间驻留内存（chatlog 社区结论），4.1.x 每库一密钥方案待 M0 确认；密钥在同一大版本内通用
- hook 点 / 函数签名 / 结构体偏移按 build 变化，必须靠 REA 产出 + 版本 profile + 特征码匹配，不能硬编码
- 所有数据留在本机，无云端转发

### 6.2 合规与风险

- **前车之鉴**：`sjzar/chatlog`（最知名的微信聊天记录工具，9k+ star）于 2025-10 收到微信官方函件后**主动删除全部代码与历史**；`WeChatExtension-ForMac` 作者明确警告注入式插件"已不安全、可能导致封号"，并有第三方售卖外挂获刑的判例。本项目务必：仅供个人本机使用、不对外提供服务、不分发
- 逆向分析仅限本机自有客户端的合法研究用途（与 REA 的免责声明一致）
- 自动化操作微信可能违反腾讯软件许可条款，存在**账号被限制 / 封禁**的风险
- 禁止把微信二进制、反编译产物、密钥、数据库明文提交到仓库或对外分发
- `.gitignore` 需覆盖：`docs/analysis/` 中的敏感产物、`wechat_keys.json`、解密后的 DB 文件

## 7. 多版本兼容策略

微信升级是本项目最大的维护成本来源，各路线敏感度不同：

| 路线 | 升级敏感度 | 典型破坏面 |
| :--- | :--- | :--- |
| 内部接口 hook | 最高 | 函数偏移 / 签名 / 结构体偏移每个 build 都变，靠特征码匹配 + 版本 profile |
| DB 解密 | 高 | 加密方案可能整体更换（如 4.1.x 改为每库一密钥） |

**设计原则：代码一次写好，差异收敛到 profile。**

1. **版本探测**：启动时读 `WeChat.app/Contents/Info.plist` 的 `CFBundleShortVersionString`，按版本区间选择 profile
2. **Profile 外置**：`profiles/wechat-<版本区间>.json` 描述 hook 点特征码、函数签名、结构体偏移、密钥方案、功能开关；新增支持 = 加一份 profile，不改代码
3. **特征码定位**：不用硬编码偏移，用 REA 产出的字节模式（byte pattern）在内存中扫描定位函数，同一大版本内小更新通常自恢复
4. **降级策略**：注入失败时降级为只读模式（DB 历史 + fsnotify 准实时），发消息能力单独熔断，而不是整个服务不可用
5. **明确报错**：版本超出已知区间时 `/api/health` 返回 `UNSUPPORTED_VERSION` 并给出当前检测到的版本，不静默出错
6. **REA 复跑**：大版本更新后用 REA 重新分析生成新 profile / 新密钥方案，属正常维护流程而非重写

### 7.1 新版本适配工作流（已实现）

微信升级后**只需运行一次**生成脚本，自动产出该版本的全部运行配置：

```bash
python3 tools/gen_profile.py          # 快速静态提取（约 1 分钟）
python3 tools/gen_profile.py --deep   # 追加 REA/Ghidra 深度分析（后台跑，耗时长）
```

脚本自动完成：

1. 读 `WeChat.app/Info.plist` 拿 bundle 版本 + 容器里最高 Magicdy 插件号
2. 定位实际运行的核心库（Magicdy extracted 优先，bundle 兜底）与 `ilink2.framework`
3. `lipo -thin arm64` 切片（REA/Ghidra 不支持 universal 选架构）
4. `nm -gU | c++filt` 按 `tools/hook-symbols.txt` 的正则表解析全部 hook 符号 →
   偏移 + demangled 签名 + 函数头部 24 字节特征码（`sig_hex`，供内存扫描复核）
5. `strings` 扫核心库提取内嵌 `<cgi reqid="..">name</cgi>` 表 → `cgi_cmdids`
   （sendmsg=2 / newsendmsg=237 / newsync=121 …），及服务名存在性标记
6. 两库 sha256 指纹 + 写出 `profiles/wechat-<ver>-magicdy<n>.json`

运行时 `src/wechatma/profiles.py` 自动选择 profile：精确匹配 bundle+magicdy →
同 bundle 降级 → 同主版本降级 → 都没有报 `UNSUPPORTED_VERSION`。
`/api/health` 会返回检测到的版本与命中的 profile/match 级别。

**注意**：ilink2 的符号表使偏移解析是确定性的；`sig_hex` 特征码用于验证
运行期内存中的函数与 profile 一致（防热更新错位）。核心库 stripped，深度
细节（SendMsg 构造、密钥派生）靠 `--deep` 产出的 Ghidra 伪代码补齐。

## 8. 参考项目

| 项目 | 路线 | 状态 | 可借鉴点 |
| :--- | :--- | :--- | :--- |
| [macos-wechat-cli](https://github.com/qiqijin/macos-wechat-cli) | AX 读 UI + CLI，WeChat 3.8 | 可用 | UI 定位链文档、JSON 输出、0.5s 级 AX 性能优化思路 |
| [wechat-mac-automation](https://github.com/voidvon/wechat-mac-automation) | Python + pyobjc AX + MCP/CLI | 活跃 | 与本项目技术栈最接近：fetch/reply/moments/加好友的 API 划分 |
| [wechat-fastbridge](https://github.com/huj28-creator/wechat-fastbridge) | MCP + 原生 AX bridge | 活跃 | 发送安全实践：名称归一化、歧义拒绝、写前校验会话头、后台控制 |
| [send-wechat-message](https://github.com/tonyshield/send-wechat-message) | Codex skill + AX | 活跃 | `AXValue` 直写优于粘贴的实证、发送前显式确认、视口归一化 |
| [wechat-mac-reader](https://github.com/xingfanxia/wechat-mac-reader) | lldb 取密钥 + chatlog-bot HTTP + AX 发送 | 可用 | DB 读 + HTTP 服务编排先例；其 4.1.x lldb 取密钥实现值得在 M0 对照验证 |
| [chatlog](https://github.com/sjzar/chatlog) | 内存扫描取密钥 + DB 解密 + HTTP/MCP | ⚠️ 已删库（2025-10 微信发函） | API 设计（`/chatlog?time=&talker=` `/contact` `/chatroom`）、webhook 推送、fsnotify 增量解密；4.0.3.80+ 密钥不驻留内存的社区结论 |
| [WeChatExtension-ForMac](https://github.com/MustangYM/WeChatExtension-ForMac)（本机已有 clone） | dylib 注入 + OC method hook，仅支持 WeChat ~3.x | 停更 | **本项目主路线的直接先例**：证明注入 + hook 可实现实时收发（MessageService 类 OC 接口）；hook 点命名/消息对象结构可参考，4.x 等价物靠 REA 找；风险实证：作者自警封号 |
| [wx4py](https://github.com/youziming1275777810-beep/wx4py) | macOS 端 System Events + 剪贴板 | 活跃 | 群消息轮询、AI 自动回复的产品形态参考（剪贴板方案不采用） |
| [weclaw-cua](https://github.com/Numaira-Technology/weclaw-cua) | 截图 + 视觉 LLM | 活跃 | 版本无关的兜底思路；证实 OCR 路线重、慢，仅作极端兜底 |

**结论**：本项目 = WeChatExtension 的注入 hook 收发（4.x 版，hook 点靠 REA 找）+ chatlog 的 DB 读 +
多实例管理 + HTTP Server。AX 类项目不再作为运行时参考，仅保留其 API/交互设计借鉴价值。

## 9. 里程碑

- **M0 REA 逆向分析**：安装 `rea-agents` + Ghidra → 反编译 WeChat.app 4.1.15 → 产出 4.5 清单：注入向量 / 接收 hook 点 / 发送函数签名 / 密钥派生 / 结构体偏移 → `docs/analysis/` + 首个 `profiles/wechat-4.1.x.json`
- **M1 注入 PoC**：写最小 agent dylib（只 hook 接收函数打日志）→ lldb/Frida 注入运行中微信 → 验证能截获实时消息事件
- **M2 发送链路**：agent 增加内部发送函数调用 → wxid 解析 → 发文本消息 → 回查确认
- **M3 FastAPI Server**：instance manager + `/instances` `/chats` `/messages` `/events` 全套 API
- **M4 增强**：DB 解密历史补齐、多实例、断注重注入、Token 鉴权、launchd、图片/文件消息

## 附录：本机可行性验证记录（2026-11-03）

| 检查项 | 实测结果 | 结论 |
| :--- | :--- | :--- |
| 微信 | `/Applications/WeChat.app` **4.1.15**，运行中 | ✓ 目标存在；版本 > 4.0.3.80，证实内存扫描取密钥已失效，必须走 REA 分析密钥派生 |
| Node.js / npm | v22.23.2 / 10.9.8 | ✓ 满足 REA 要求（`^22.19`） |
| `rea-agents` | npm **6.8.0** 已验证可用（analyze / decompile 实跑通过） | ✓ `GHIDRA_INSTALL_DIR` + `JAVA_HOME` 见 `tools/rea-env.sh`；doctor 对 Node 22.23.2 误报 FAIL（文档要求 ^22.19，实测功能正常） |
| Python | 3.14.10（uv 管理，`.venv`） | ✓ fastapi/uvicorn/pydantic/pytest 已装；pip 在本机 macOS 版本解析有 bug，统一用 uv |
| Xcode / lldb | 完整 Xcode + lldb 22.1.1 | ✓ |
| Ghidra | **12.1.4** 已装 `~/opt/ghidra_12.1.4_PUBLIC`（brew cask 已移除，走 GitHub release zip；mac_arm_64 decompiler 官方未发包，已从自带源码编译并装回 `Support/decompile`） | ✓ REA doctor ghidra 四项全 OK |
| SIP | enabled | ⚠️ **注入路线硬依赖**：`task_for_pid` / lldb / Frida 均需先 `csrutil disable`（重启）；REA 静态分析不受影响 |
| 辅助功能权限 | 未授权 | 已不需要——AX 路线已弃用，仅开发期调试可选 |

## 附录：二进制侦察记录（WeChat 4.1.15，静态分析未跑前的实况）

### 包结构

| 路径 | 大小 | 角色 |
| :--- | :--- | :--- |
| `Contents/MacOS/WeChat` | 184KB / 2 导出符号 | 壳启动器 |
| `Contents/Frameworks/wechat.dylib` | 82KB | 壳转发 |
| **`Contents/Resources/wechat.dylib`** | **335MB** | 核心库（stripped） |
| `xplugin/plugins/Magicdy/965/extracted/wechat.dylib`（容器内） | 341MB | **插件热更新的核心库**（与 bundle 版不同大小 → 已自更新过） |
| `WeChatAppEx Framework` | 407MB 已映射 | Chromium 系 UI/运行时框架，主进程直接加载 |
| `roam_server` / `ilink2` / `mmcronet` / `andromeda` | 8–24MB | 漫游同步 / 网络 / 组件框架 |

### 关键结论

- **语言构成**：核心 335MB dylib 仅 133 个 ObjC 类（无消息相关）、0 Swift 符号、未链接 libswift → **本体是 stripped C++**。Swift 不是障碍；不能用 ObjC swizzle，hook 手段 = inline hook（Dobby 等）/ vtable patch / 跨模块符号重绑（fishhook）
- **核心库不在 `lsof txt` 中** → 疑似经 Magicdy 自定义加载（读文件→解密→内存映射，而非正常 dlopen）。影响：运行时用 `_dyld_get_image_*` 找不到它，hook 定位要靠**匿名可执行内存扫描**或**hook 框架边界**（roam_server / ilink2 等正常加载的镜像里调用核心的导出接口）
- **版本号要取 Magicdy 插件版本（如 965）而非 App 版本**——核心库可独立热更新，`profiles/` 按模块版本管理
- **签名**：hardened runtime 开启，无 `allow-dyld-environment-variables` / `disable-library-validation` entitlement → `DYLD_INSERT_LIBRARIES` 无效；无 `get-task-allow`；app-sandbox 开启（`network.server`/`client` 有 → agent ↔ Server 用 localhost TCP）
- **注入向量收敛为**：`task_for_pid` + mach 线程创建 + `dlopen`（lldb/Frida 同款路径），SIP 关闭为前提
