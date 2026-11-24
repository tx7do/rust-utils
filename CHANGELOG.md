# 更新日志

本项目的所有重要变更记录于此。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/),
版本遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 对齐上游 go-utils 14-17 批次(maputils SyncMap / currency / sfs2x / netutil HTTP 调优)

#### 新增模块

- **currency**(默认,零依赖):ISO 4217 两层单位体系——minor units(分,按币种指数 0/2/3 位)与定精度账本单位(统一 4 位小数,与币种指数解耦);`Money` 类型:整数账本域算术(币种不匹配即报错、溢出 fail-fast)、Fowler 式精确守恒分配/拆分(最大余数法)、整数域精确汇率与比例乘法(全程无浮点)、方向舍入变体(floor/ceil)、千分位/符号格式化与解析(字符串往返无损);全量 ISO 4217 活跃码元数据表(161 条:数字码 + 英文名 + 常用符号)
- **sfs2x**(`sfs2x`):SFS2X 二进制协议编解码——类型化对象(`Value` 枚举承载类型码,排序确定性编码 + 插入序官方字节忠实双模式)、帧封装(uint16/BIG_SIZE uint32 自动切换、zlib 压缩阈值可配、AES-128-CBC 加密的官方固定 key+IV 与随机 IV 自描述两模式)、消息信封({c,a,p} + 握手/系统 action 码)、官方 CLASS($C/$F)识别;解压输出 64 MiB 上限防炸弹;与 ZewSFS Python 参考实现的黄金向量互操作(解码值 + 重编码字节级一致,资产在 `assets/sfs2x/`,不入发布包)

#### 既有模块深化

- **maputil**:`SyncMap<K, V>` 类型化并发映射(对位上游 maputils 的 `SyncMap`)——`load`/`load_or_store`/`store`/`delete`/`range`/`len` 与 Go `sync.Map` 语义对齐;`RwLock<HashMap>` 等价实现(零依赖),`len` O(1) 优于上游 O(n)
- **netutil**:`tuned_http_agent` 调优连接池的 ureq Agent(对位上游 `TunedHTTPTransport`:总空闲 100/单主机空闲 16;ureq 无 IdleConnTimeout 旋钮,文档注明);服务端超时(读头 10s/空闲 120s/读写截止不设保 SSE)以指引形式落在文档——本 crate 不含 HTTP 服务器

## [0.2.0] - 2026-11-22

相对 0.1.0 的主体是一次大扩容:对齐上游 go-utils 全部模块清单,并把若干「壳」升级为带真实后端与真实实例测试的落地。

### 新增模块(feature 门控,均为零 unsafe、边界 fail-fast)

- **sensitive**(默认):敏感词过滤——词典树逐位最长匹配、ASCII 大小写不敏感、穿插字符跳过(`敏*感*词` 可命中)、按字符数打码
- **qrcode**(`qrcode`;PNG 用 `qrcode-png`):QR 码模块矩阵 + SVG + 终端块字符;单测含 rqrr 扫码解码回读整链路
- **xlsx**(`xlsx`):Excel 读写(calamine 读 + rust_xlsxwriter 写),写出→读回在库内闭环测试
- **code_generator**(`code-generator`):模板驱动代码生成——mustache 子集渲染(变量/点路径/段落/反转段落/数组迭代;缺字段即报错),目录与内存模板源,落盘守卫(拒覆盖、拒路径逃逸)
- **mapper**(`mapper`):entity↔DTO 字段映射(serde_json 桥)——rename/嵌套搬移/枚举转换/缺省/剔除/白名单 + 强类型 convert
- **prost_time**(`prost-time`):chrono ↔ prost_types Timestamp/Duration 互转(全 fail-fast)
- **structutil**(`structutil`):结构体字段遍历——serde 版 ForEach/ToMap(rename/skip 语义由 serde 属性承载)

### 既有模块深化

- **jwt**:新增 `*_with_key` 一族——RS256/RS384/RS512/PS256/PS384/ES256/ES384(PEM 私钥签发、公钥校验);校验端算法钉死,防 alg 混淆
- **otp**:RFC 4226 HOTP 与 RFC 6238 TOTP 全量形态——SHA-1/256/512 三摘要、6~8 位、可配窗口、HOTP lookahead;`otpauth://` URI 构造与解析;RFC 附录向量钉死
- **printrender**:内容源改 `PrintSource::{Html, Url}`(URL 直印);页边距/缩放/页码范围/浏览器页眉脚;`render_screenshot`(PNG/JPEG);参数校验纯函数化
- **crypto / sm**:统一 `Signer` 签名面(ECDSA / RSA / SM2 可互换);RsaCipher 补 PKCS#1 v1.5-SHA256 签名验签
- **authorizer**:内置 `PolicyEngine`(纯 std RBAC:角色传递闭包带环保护、`/*`/`/**` 路径通配、RwLock 热更)
- **ossutil**:阿里云 OSS 预签名 URL(RESTful V1 签名,HMAC-SHA1,离线可验证)
- **doctext**:xlsx 文本化(`doctext-xlsx`,复用 xlsx 模块)
- **sliceutil**:`number_slice_to_string` 泛型化——全部有符号/无符号整型位宽直接可传(对位上游同款泛型化)
- **mailer**:`SendOption` 选项面 + `send_mail_with`/`build_message_with`——HTML 正文(`text/html; charset=utf-8`,缺省仍纯文本);`Date` 头(RFC 5322)由 lettre 自动补齐
- **auditutil**:`sign_log_content` 租户/用户 ID 升 `i64`——与下游 ID int64 契约对齐;小值(<2^53)JSON 序列化与旧 u32 版逐字节一致,存量签名仍可验证
- **translator/baidu**:BCP47 语种归一(`zh-CN`→`zh`,未收录去地区后缀透传)、端点与 HTTP 客户端可配(`with_endpoint`/`with_agent`)、凭据与空输入守卫、多段译文按换行合并、salt 升 u64、10MB 响应体积防护;错误语与上游逐字对齐
- **otp**:补 `generate_secret`(160-bit 密码学随机 Base32)/`validate_secret`(大写/去填充/去空格规范化);TOTP 校验对非规范形态 secret 同样可用

### 真实引擎落地(此前仅壳/兜底)

- **authorizer-casbin**(`authorizer-casbin`):`"casbin"` 类型接入真实 casbin 引擎;缺省模型 RBAC 四元(sub, obj, act, dom),keyMatch2+keyMatch 双匹配器,角色绑定经 `g` 规则;策略整建热更
- **authorizer-opa**(`authorizer-opa`):`"opa"` 类型接入 OPA HTTP 评引擎(`/v1/data`);未定义决策即拒绝,非 200/坏响应 fail-closed 可观测;策略由 OPA bundle 自管,引擎只读
- **distlock-etcd**(`distlock-etcd`):etcd 分布式锁——lease+txn 原子抢锁、keep-alive 续期(含持锁确认)、令牌比对释放;`block_wait` 选项生效;实例测试在端点可达时自动执行

### distlock 选项面补全

- `Lock::ttl()`:剩余有效期(Redis `PTTL` / etcd `lease_time_to_live`)
- `with_token` / `with_metadata`:自定义令牌与锁值元数据(Redis 同令牌前缀重入以令牌长度为界)
- `with_backoff`:Linear / Exponential / NoRetry 三种退避策略(两后端共用同一序列器)

### 工程与质量

- CI(`.github/workflows/ci.yml`):fmt check + clippy `-D warnings` + 全量测试 + 示例编译 + 基准烟雾;services 挂 redis 与 etcd
- criterion 基准 7 份(stringcase/collections/parsers/sensitive/qrcode/jwt/mapper)
- 可运行示例 23 个(required-features 门控,零 feature 亦可编译)
- 测试资产模式:assets/jwt(PEM 密钥)与 assets/geoip 同款约定——不入发布包,缺失时用例自动跳过

### 破坏性变更

- **printrender**:`PrintOptions.html` 字段改为 `source: PrintSource` 枚举(换取 URL 直印能力),调用点需同步
- **Lock trait**:新增 `ttl()` 方法(外部自行实现 `Lock` 的下游需补齐)
- `sha2` 依赖启用 `oid` feature(RSA PKCS#1 v1.5 签名所需)
- `RedisLocker` 获取脚本的令牌前缀参数由 `value.len()` 改为显式 `token_len`(协议兼容,仅函数签名内部变化)

### 明确不做

- zanzibar 引擎(需专用服务端,保留 DenyAll 兜底)
- printrender 远程 HTTP renderer(服务契约未定)
- trans 包(Go 指针惯用件,Rust 引用/Option 语义下无对应痛点)

## [0.1.0] - 2026-11-11

首个公开版本:移植 go-utils 的通用工具面——string/slice/map 辅助、大小写转换(缩写词与数字段感知)、雪花 ID/订单号/机器码、查询条件解析、MySQL DDL 解析、优先级事件循环、关联数据回填、密码哈希策略、AES/HMAC、JWT(HS256)、随机昵称、银行卡 BIN、图形验证码、IP 归属地三后端、机器翻译四后端、分布式锁(Redis)、国密 SM2/SM3/SM4 等;核心模块零依赖,重依赖按 feature 门控,全库 `#![forbid(unsafe_code)]`。
