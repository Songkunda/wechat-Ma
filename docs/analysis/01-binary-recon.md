# 二进制侦察报告（WeChat 4.1.15 / Magicdy 965）

> 纯静态侦察（nm / strings / otool / lsof / vmmap），Ghidra 分析前的结论。
> 日期：2026-11-03，机器：macOS arm64，微信运行中（pid 4053）

## 1. 模块地图

| 模块 | 大小 | 符号 | 角色 | hook 价值 |
| :--- | :--- | :--- | :--- | :--- |
| `Resources/wechat.dylib` | 335MB | stripped（2 exports） | 业务核心（Magicdy 自定义内存加载） | 需 REA/Ghidra 定位偏移 |
| `xplugin/Magicdy/965/extracted/wechat.dylib` | 341MB | stripped | **实际运行的核心**（已热更新，与 bundle 版不同） | 同上，分析对象以它为准 |
| `ilink2.framework` | 17.8MB | **963 exports，全符号** | 长连接协议层（protobuf, `ilink::zidl_export`） | 主 hook 面 |
| `roam_server.framework` | 24MB | 95 exports | 多设备漫游同步（mars::xlog） | 备选 |
| `andromeda.framework` | 9MB | 133 exports | QUIC 传输（`_gquic_send/recv`） | 太底层，不用 |
| `WeChatAppEx Framework` | 407MB | — | Chromium 系 UI/小程序框架 | 不管 |
| `MacOS/WeChat` | 184KB | 2 exports | 启动壳 | — |

核心业务库 = **stripped C++**（133 个 ObjC 类、0 Swift 符号）；UI 栈是 Chromium 系。
`wcdb_lv_` 字符串证实 DB 层为 **WCDB**（SQLCipher 系加密）。

## 2. ilink2 边界接口（关键资产）

收消息路径候选 hook 点（均有符号、位于正常 dlopen 的镜像）：

```text
ilink::zidl_export::NetworkManager::OnReceiveNotify()              @ 0x94d28
ilink::zidl_export::NetworkManagerEvents::OnReceiveNotifyEvent(uint, string const&)  @ 0x92154
ilink::pb_export::IlinkAddMsgCmd    <- 新消息命令的 protobuf 类型
ilink::pb_export::IlinkBypassMsgItem / IlinkMsgIotAppMsg
ilink::zidl_export::NetworkManager::SubscribeNotify(vector<uint>)
ilink::zidl_export::AppSession::DisableAppMsgBypass() / StartSync()
```

发消息路径候选：

```text
ilink::zidl_export::NetworkManager::SendRequestAsync(IlinkRequestInfo const&)       @ 0x933f4
ilink::zidl_export::NetworkManager::SendRequestAsync(IlinkRequestInfo const&, function<void(int,string const&)>)  @ 0x932a4
ilink::zidl_export::AppSession::NewNetworkManager() / StartSync() / GetAuthManager()
ilink::zidl_export::CloudSession::OnSendCloudCgiRequest()

# Ghidra decompile 已确认（REA, ghidra 12.1.4）：
#   0x933f4 仅是壳 -> 带默认空 callback 调 0x932a4；
#   真实入口 = 0x932a4:  SendRequestAsync(NetworkManager* this,
#                       ilink::pb_export::IlinkRequestInfo const& req,
#                       function<void(int,string const&)> cb)
#   -> 返回 pair<shared_ptr,...>（请求句柄）；IlinkRequestInfo 在 pb_export 命名空间
#   0x932a4 内部：lock weak 上下文 -> req->SerializeAsString()
#     -> FUN_000b5aa8(ctx, ch1, ch2, bytes, cb) 入队发送
#   => IlinkRequestInfo 是标准 protobuf MessageLite，agent 可反射构造
#   0x92154 OnReceiveNotifyEvent(uint cmdid, string const& data)
#     只是转发 this+0x80 的事件处理器 -> 接收 hook 放它或 OnReceiveNotify 均可

# 额外发现（nm 符号表，gen_profile 已覆盖）：
#   *NoPB 全家桶：NetworkManagerNoPB::SendRequestAsync(string const&) 等
#     -> 裸 payload 发送面，可能比 pb 反射构造更简单
#   IlinkContext::NewNetworkManager(string, u64) / SingletonSession::NewNetworkManager()
#     -> agent 拿 NetworkManager 实例的入口
```

**方案价值**：在 `SendRequestAsync` / `OnReceiveNotify*` 上 hook，拿到的是协议层
protobuf 帧——无需理解核心库内部结构即可先实现「原始事件捕获 + 原始发包」。

**解码捷径**：`ilink::pb_export::*` 各类型导出 `classInfo_` / `dynamicClassInfo()` /
`NewInstance()`（protobuf 反射元数据仍在导出表里）。注入的 agent 可链接这些符号、
实例化 `IlinkAddMsgCmd` 并用反射解码字段——不必手工逆偏移，版本间只跟 pb schema 走。
出站同理：`IlinkRequestInfo` 是出站信封（cmdid + payload），SendMsg 载荷 schema
待 Ghidra 追核心构造侧确认。

### 2.1 注入 agent 实现备注

- hook 手段：ilink2 镜像有正常 dyld 符号表，agent 内用 Dobby/手写 trampoline 对导出
  函数做 inline hook；不需要进自定义加载的核心段
- 消息解码：`ilink::pb_export::*::dynamicClassInfo()` / `classInfo_` 提供 protobuf
  反射，agent 内可解 `IlinkAddMsgCmd` 与 `IlinkRequestInfo` 的 payload（cmd id 分发）
- 多开：每个进程各自加载各自的核心/ilink2，agent 逐进程注入，socket 按实例区分

### 2.2 核心库字符串证据（strings -arch arm64）

341MB 核心虽 stripped，但嵌入字符串暴露整条消息管线，可作 Ghidra 锚点：

```text
<cgi reqid="2"    respid="1000000002">sendmsg</cgi>
<cgi reqid="237"  respid="1000000237">newsendmsg</cgi>
<cgi reqid="121"  respid="1000000121">newsync</cgi>
<cgi reqid="536">revokemsg</cgi>  <cgi reqid="107">sendappmsg</cgi>  <cgi reqid="68">sendemoji</cgi>
长连接域名：uslong1-8.wechat.com / usshort1-8.wechat.com
```

服务/处理器名（日志串）：`SendMsg` `SendMsgFtouserna` `AddMsgCmdHandler`
`ReceiveAddMsgLis...` `NewSync`/`NewSyncStart`/`NewSyncEnd` `micromsg.AddMsg`
`micromsg.SyncKey` `addmsg parse fai` `HandleSendFailed` `PreprocessIpxxMsProcessStashMsg`

**价值**：reqid ↔ cgi 名映射大概率就是 `IlinkRequestInfo` 的 cmdid 取值表；
`AddMsgCmdHandler`/`micromsg.AddMsg` 是收消息落地的处理入口——Ghidra 里按字符串
引用反查即可定位构造/消费点。

## 3. 注入向量收敛

- hardened runtime ON，无 `allow-dyld-environment-variables` / `disable-library-validation`
  → `DYLD_INSERT_LIBRARIES` 无效
- 无 `get-task-allow`，app-sandbox ON（network.server/client ✓ → agent↔Server 走 localhost TCP）
- ✅ 唯一现实向量：`task_for_pid` + `mach_thread` + `dlopen`（lldb / Frida 同路）→ **SIP 必须关**
- 核心库不在 `lsof txt` → 自定义加载实锤；用边界 hook 方案后**不需要碰它**

## 4. DB（WCDB）路线现状

- 确认 WCDB 存在（`wcdb_lv_`）；密钥派生逻辑在 stripped 核心里 → 靠 Ghidra
- 4.0.3.80+ 密钥不驻留内存（社区结论）；4.1.x 每库一密钥
- lldb 内存路径需关 SIP（与注入同一前提）

## 5. 下一步（等 Ghidra 就绪）

1. Ghidra 导入 `Magicdy/965/extracted/wechat.dylib`（341MB，分析耗时长）
2. 找 `IlinkAddMsgCmd` 的消费方 → 消息对象结构（P1）
3. 找 `SendRequestAsync` 的调用方里构造 SendMsg 请求的位置（P2）
4. 搜 WCDB key 调用链 → 密钥派生（P3）
5. 上述每个点生成字节特征码 → `profiles/wechat-4.1.15-magicdy965.json`（P4）
