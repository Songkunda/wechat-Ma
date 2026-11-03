# M0 逆向分析目标清单（WeChat 4.1.15 / Magicdy 965）

分析对象：`~/Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/xplugin/plugins/Magicdy/965/extracted/wechat.dylib`（341MB，arm64+x86_64，stripped）

对照对象：`/Applications/WeChat.app/Contents/Resources/wechat.dylib`（335MB，bundle 内置版）

## 必须回答的问题（按优先级）

### P0 — 注入向量与加载机制

- [ ] Magicdy 加载器如何把核心库映射进内存（自定义 loader？解密？），加载完成后能否用 dyld API 枚举到
- [ ] 进程内核心代码的形态：匿名可执行内存段 / 私有 dyld image
- [ ] 最佳注入点：核心库加载完成的事件/回调，或框架边界上的稳定函数

### P1 — 消息接收 hook 点

- [ ] 消息接收/分发函数：网络包 → 消息对象 → 写库 → UI 通知 的调用链
- [ ] 候选切入点（框架边界，正常 dlopen 镜像）：`ilink2` / `roam_server` / `andromeda` 中与核心交互的导出函数
- [ ] 消息对象结构体字段偏移（发送者 wxid / 会话 id / 正文 / 类型 / 时间戳）

### P2 — 发送函数

- [ ] 发送文本消息的函数签名（参数：会话 id、正文、消息类型？）与调用约定
- [ ] 构造消息对象的工厂函数 / 消息类型枚举

### P3 — 密钥派生（DB 解密路线）

- [ ] SQLCipher 打开数据库的调用点（搜 `sqlite3_key` / `PRAGMA key` / sqlcipher 字符串）
- [ ] 4.1.x 每库密钥的来源：从哪派生、存哪、生命周期
- [ ] 消息库的 schema：表名 / 字段（先静态找 SQL 语句字符串）

### P4 — 版本画像

- [ ] 每个定位点生成字节特征码（byte pattern）→ `profiles/wechat-4.1.15-magicdy965.json`
- [ ] Magicdy 插件版本枚举方式（`plugin_version_info_Magicdy` 文件格式）

## 分析工具

- `rea` CLI：`analyze` / `inspect` / `decompile` / `function` / `search-*` / `inspect-binary-layout`
- Ghidra headless（安装中）：`analyzeHeadless` 批量反编译
- 手工：`nm` / `strings` / `otool`

## 输出

- 本目录下各主题的 `.md` 报告（证据 + 局限性）
- `profiles/wechat-4.1.15-magicdy965.json`
- 结论：注入向量选型 + hook 点 + 发送签名 + DB 方案 go/no-go
