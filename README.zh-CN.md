# crackweb

维护者：**guaidao2 & coolmoon**

[English](README.md) · **简体中文**

> 流量驱动的 Web DAST 漏洞扫描器 —— 把浏览器挂到代理上，正常访问，crackweb 对经过的流量做测试。

crackweb 是用 Go 编写的动态应用安全测试（DAST）工具，形态参考
[xray](https://github.com/chaitin/xray)：把浏览器（或任意 HTTP 客户端）的代理指向
crackweb，然后正常访问目标站点，经过代理的每个请求都会被分析；只要请求里带参数，
crackweb 就会主动发起变异重放去测试它。另有一个爬虫模式，对不方便手动点击的目标驱动同一套扫描引擎。

单一静态二进制，无运行时依赖，MIT 开源。默认英文，可显式切换简体中文。

---

## 快速开始

```sh
git clone https://github.com/guaidao2/crackweb && cd crackweb
make build          # -> bin/crackweb
```

**边浏览边扫描。** 启动代理，把浏览器代理指向 `127.0.0.1:7777`，装上它打印出来的 CA 证书，
然后像平时一样使用这个应用即可。漏洞会实时出现在终端里。

```sh
crackweb proxy --listen 127.0.0.1:7777 --export-ca ~/crackweb-ca.crt
```

**或者交给爬虫去走。**

```sh
crackweb crawl -u https://example.com --engine hybrid -o report.html
```

**或者只测一个请求。**

```sh
crackweb scan -u "https://example.com/api/items?category=books" -o report.html
crackweb scan -r request.txt          # 扫描从 Burp 保存下来的报文
crackweb scan -u https://example.com/login --forms   # 并提交该页面声明的表单
```

`--forms` 补上单 URL 扫描本来测不到的情况：真正的参数不在 URL 里的页面。加上它之后，
crackweb 会提交页面声明的内容 —— HTML 表单，以及页面脚本自己发起的请求（搜索调用带 JSON 体、
上传带 multipart 体）—— 与爬虫的做法一致。这些请求各自提交到自己的地址、带自己的请求体和编码，
seed 请求带的任何东西都到不了那里；登录页、搜索框、上传控件因此不必爬整个站点就能测。页面只以
PUT / PATCH / DELETE 发起的调用仍然排除：表单不会用这些方法提交。

## 语言

无论系统 locale 是什么，默认输出语言都是英文。中文始终是一个**显式**选择：

```sh
crackweb --help                   # 英文
crackweb --lang zh --help         # 中文
CRACKWEB_LANG=zh crackweb --help  # 通过环境变量达到同样效果
```

报告同样如此：带 `--lang zh` 跑出来的就是中文报告。

## 子命令

| 子命令 | 用途 |
| --- | --- |
| `proxy` | 启动中间代理：浏览器挂上来正常访问，crackweb 对经过的流量做测试 |
| `crawl` | 爬取目标，并扫描爬到的每个请求 |
| `scan` | 扫描单个目标，或一份其它工具保存下来的原始 HTTP 请求 |
| `oob` | 启动带外交互服务器（DNS 与 HTTP 回调） |
| `ca` | 创建、查看并导出用于 HTTPS 拦截的 CA 证书 |
| `local` | 对已有的物件做离线分析：JWT、hash——不发送任何流量 |

离线分析接收的是物件本身（一个 token、一个 hash），不向任何地方发送流量。`crackweb local`
会列出全部子命令，每个子命令有自己的选项。

**JSON Web Token**

```sh
crackweb local jwt "<token>"                            # 解码，并用内置密钥列表尝试
crackweb local jwt "<token>" -w words.txt               # 同时试你自己的字典
crackweb local jwt "<token>" -s "<密钥>" --forge \
  --claim role=admin --claim is_admin=true              # 用密钥签出你自己的 token
```

每一次猜测都是对你手上这个物件做运算：不发请求，因此不存在锁账号或污染日志的问题。候选
来自内置列表、你的字典，以及 token 自身的声明——`iss: "NeuraTech-OA"` 能推出
`NeuraTech2024`，而任何通用字典都不会收录它。能还原签名的密钥会被报出，并说明持有它的人
可以为任意身份伪造 token。`--forge` 回答随之而来的问题：拿这个密钥能签出什么。值写成
`true`、`42` 或 `{"a":1}` 时按对应类型处理。

**Hash**

```sh
crackweb local hash 5f4dcc3b5aa765d61d8327deb882cf99        # 识别，并用字典尝试
crackweb local hash "$2y$10$..." -w rockyou.txt             # 只识别：bcrypt 带盐
```

识别本身就有价值，而且答案可能是一组：32 位 hex 可能是 MD5、NTLM 或 MD4，只有上下文能
区分。若是无盐摘要，内置口令表与你的字典都会拿上去试。带盐或刻意变慢的算法（bcrypt、
argon2、scrypt、crypt(3)、PBKDF2）只报出身份、不做尝试——复现它们需要盐和一个参数化的
实现，而猜 bcrypt 不是离线模式该做的事。

`crackweb <子命令> --help` 里有每个选项的说明；`crackweb scan --list-checks` 列出全部检测项。

## 工作原理

### 统一报文模型

crackweb 接触到的一切 —— 代理抓到的流量、爬虫发现的请求、从 Burp 粘贴进来的请求、
扫描器变异参数时构造的请求 —— 都是同一个 `httpmsg.Request`。这正是代理、爬虫、扫描器
能成为一个工具而不是三个工具的原因：任意一方看到的东西，另外两方都能重放、变异、上报。

请求头以**保序、保留原始大小写**的列表存储，而不是 map，因此一份报文可以被改动之后
原样写回，除了那处有意的修改之外与抓到的内容逐字节一致。

### 流量驱动的测试

```
                    ┌──── 流量来源 ────┐
  浏览器 →[代理]────▶  代理流量        │
                    │  爬虫发现        ├──▶ httpmsg.Request ──▶ 扫描队列
  原始报文文件 ─────▶  手工导入        │
                    └──────────────────┘
                              │
   第 0 层  被动分析   不额外发包   安全头、Cookie、CORS、信息泄露
   第 1 层  重放变异   注入 payload  SQLi、XSS、SSRF、RCE、SSTI、LFI ……
   第 2 层  模板匹配   nuclei 兼容   直接复用公开的模板库
                              │
                              ▼
                漏洞结果 → HTML / JSON / SARIF / Markdown
```

第 1 层是核心：扫描器取出浏览器真正发过的每个请求，提取其中的参数，针对性地重放变异请求，
再用一套归一化 + 相似度引擎判断"到底变了没有" —— 时间戳、CSRF token 之类的动态噪声会被抹平，
页面里只有内嵌时钟在变时不会被当成变化，因此没起作用的 payload 不会被报出来。

因为覆盖面跟着真实流量走，而不是跟着爬虫走，扫描一开始就有产出，能覆盖用户能到达的一切
（包括登录之后的页面），也不会把请求浪费在根本不存在参数上。

### 带外检测

盲 SSRF、盲命令注入、存储型 XSS 在响应里不留任何痕迹。crackweb 自带 DNS 与 HTTP 回调监听，
把回调本身当作证据：

```sh
crackweb proxy --listen 127.0.0.1:7777 --oob-http 0.0.0.0:8081 --oob-dns 0.0.0.0:5353
crackweb oob --domain oob.example.com      # 也可独立部署在目标能回连的主机上
```

这个监听器只在**目标能回连本机**时才有用 —— 实验网络，或者本机有可达地址的场合。对其它目标
（NAT 后面的笔记本、公网上的站点）payload 发得出去而回执永远到不了，所以 crackweb **不会**
默认启动监听：不给 `--oob-http`、`--oob-dns` 或 `--oob-interactsh` 时，带外类检查会自己跳过，
而不是发出注定收不到回应的 payload。

这些目标请指向一个 [interactsh](https://github.com/projectdiscovery/interactsh) 部署 ——
自建的，或者公共实例。回调名在该域名下解析，从任何位置都有效：

```sh
crackweb scan -u https://target.example --oob-interactsh oob.example.com
crackweb scan -u https://target.example --oob-interactsh oob.example.com --oob-token "$TOKEN"
```

crackweb 在启动时向该部署注册，并轮询取回交互记录；部署拒绝注册时会给出提示，带外测试随即
关闭，而不是跑在一条永远不可能送达的通道上。

## 检测能力

**被动检测** —— 只分析已有的流量，可以安全地对生产环境运行。

| 检测项 | 发现什么 |
| --- | --- |
| `passive-security-headers` | 缺少 CSP、HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy |
| `passive-csp` | 存在 Content-Security-Policy 但被削弱（`unsafe-inline`、通配符、缺少 nonce） |
| `passive-cookie-flags` | Cookie 缺少 Secure、HttpOnly 或 SameSite |
| `passive-cors` | 回显 Origin 或使用通配符的 `Access-Control-Allow-Origin`，且允许携带凭据 |
| `passive-info-disclosure` | `Server`、`X-Powered-By` 等响应头泄露版本号 |
| `passive-mixed-content` | HTTPS 页面里加载的明文 HTTP 子资源 |
| `passive-cache-control` | 建立会话的响应可能被缓存 |
| `passive-directory-listing` | 自动生成的目录索引 |
| `passive-cleartext-password` | 凭据经 http:// 提交 —— 报告中绝不复现其值 |
| `passive-sri` | 从其它源加载的脚本与样式表未携带 Subresource Integrity 哈希 |
| `passive-error-disclosure` | 响应体中出现调用栈或框架报错信息 |
| `passive-content-disclosure` | 响应体中出现内网 IP、服务端路径或邮箱地址 |
| `passive-private-key` | 通过 HTTP 提供了 PEM 私钥 —— 报告中绝不复现密钥内容 |
| `passive-insecure-transport` | 密码输入框通过明文 HTTP 提供 |
| `passive-vulnerable-library` | 前端库的版本存在已公开漏洞，报告中点名对应的安全公告 |

**主动检测** —— 发送 payload 并根据返回结果判定。

| 检测项 | 严重性 |
| --- | --- |
| `sqli-error` | 严重 |
| `sqli-boolean` | 高危 |
| `sqli-union` | 严重 |
| `sqli-time` | 高危 |
| `xss-reflected` | 高危 |
| `xss-stored` | 高危 |
| `sqli-order-by` | 高危 |
| `path-traversal` | 高危 |
| `ssti` | 高危 |
| `ssrf` | 高危 |
| `command-injection` | 严重 |
| `open-redirect` | 中危 |
| `crlf-injection` | 中危 |
| `nosqli` | 高危 |
| `xxe` | 高危 |
| `deserialization` | 高危 |
| `second-order-injection` | 高危 |
| `jwt` | 严重 |
| `upload` | 中危 |
| `csrf` | 中危 |
| `host-header` | 中危 |
| `method-override` | 中危 |
| `idor` | 高危（需要两个会话） |
| `access-control-variants` | 高危（仅在被 401/403 拒绝时运行） |
| `pagination-bypass` | 中危 |
| `parameter-type-bypass` | 中危 |
| `dom-xss` | 高危（需显式开启：会在浏览器里真实加载并执行页面） |
| `prototype-pollution` | High *（需显式开启：会在浏览器里加载页面）* |
| `client-template-injection` | 高危（需显式开启：会在浏览器里真实加载页面） |
| `ldap-injection` | 高危 |
| `xpath-injection` | 高危 |
| `odata-injection` | 高危 |
| `graphql-introspection` | 低危 |
| `cache-poisoning` | 高危（需显式开启：会写入共享缓存） |
| `request-smuggling` | 高危（需显式开启） |
| `path-override` | 高危 |
| `ip-spoof` | 高危 |
| `http-put` | 高危（需显式开启：会在目标上写入文件） |
| `cors-origin` | 高危 |
| `exposed-path` | 高危 |
| `jsonp` | 低危 |
| `content-type-bypass` | 中危 |
| `referer-bypass` | 高危 |
| `websocket-origin` | 低危 |

按名字或标签筛选：`--checks sqli`、`--checks injection`、`--checks all`。
`--passive-only` 会把代理变成纯粹观察哨，绝不主动发出任何请求。

### 越权访问（IDOR）

检测水平越权需要两个身份，因为要回答的不是"响应变了没有"，而是"**别人能不能看到**"。
提供两个会话后，crackweb 会把它们各自看到的内容与匿名请求做三方对比：

```sh
crackweb scan -u "https://shop.example.com/order?id=42" \
  --session "Cookie: sess=alice-token" \
  --session "Cookie: sess=bob-token"
```

只有在**两个会话拿到相同内容、而匿名请求拿不到**时才报出漏洞。
这个组合意味着对象本身受保护，却没有按归属者隔离。
任何人都能读的公开页面不会报，各用户正确看到自己记录的情况也不会报 ——
这正是让该检测值得一读的原因。

会话也可以是 Bearer token 或任意自定义头：`--session "Authorization: Bearer x"`。
不足两个会话时该检测会被跳过，并明确提示。

### 需显式开启的检测项

`request-smuggling` **默认不跑**，`--checks all` 也不会把它拉进来。
它的探测会在目标连接上留下排队字节，该连接上的下一个请求可能读到它们 ——
对一个你不拥有的系统来说，这不是测试，是事故。按名字选中它即表示同意：

```sh
crackweb scan -u https://staging.example.com --checks request-smuggling
crackweb scan -u https://staging.example.com --enable-unsafe-checks --checks all
```

两种方式都会在发包前主动声明。

`dom-xss` 需显式开启是出于另一个原因：它会把页面放进真实浏览器里加载，而浏览器会执行页面携带的每一个脚本 —— 包括去拉取后续数据的，以及去写数据的。对页面本身带副作用的系统而言，这已经超出了“测试它收到的那个请求”的范围。按名字选中它，或加 `--enable-unsafe-checks`，即表示同意；机器上没有浏览器时，该检查不会报任何结果，而不是去猜。
`prototype-pollution` 同样需显式开启，它回答的是另一个问题：它加载页面，然后询问运行时——查询串里命名的那个属性是否落到了 `Object.prototype` 上。


```sh
crackweb scan -u https://app.example.com/page --checks dom-xss
```

## WAF 规避

一个自带固定 payload（`' OR 1=1--`、`<script>alert(1)</script>`）的扫描器，
会在第一个请求就被任何基于签名的防火墙拦住。所以 crackweb 不"自带" payload，而是**推导**出它们：

```
种子（少量确定正确的表达式）
  ↓ 结构改写   注释分割、关键字拆分、空白替换
  ↓ 编码       URL、双重 URL、Unicode、hex、HTML 实体、base64
代数         第 0 代 = 原样 · 第 1 代 = 一次改写 · 第 2 代 = 两次 · …
```

**变体按代数排列，能停就停。** 第 0 代就是原样 payload，
所以没有防护的目标每个种子只花一个请求，且永远不会收到变异版本；
只有被拒绝时才升到下一代 —— 而某一代一旦通过，这个事实会**按主机记下来**，
后续 payload 直接从那一代起步，不必重新试探防火墙。

两条规则保证变体是有意义的：同一族的变形器永不叠加
（三种藏空格的手法叠在一起，得到的 payload 谁都不是），
编码只施加一次 —— 如果最后一个变形器产出的已经是传输形态，
就直接原样发送，再编码一次会让应用收到一个字面的百分号序列。

探测是刻意保守的：只有在探针得到**防火墙已知会产生**的响应时才判定有防护 ——
带拒绝措辞的拦截状态码，或厂商指纹（Cloudflare、AWS WAF、ModSecurity、Sucuri、
安全狗、宝塔、长亭雷池…）。"响应变了"不算数：
判错一次，后续每个 payload 都会白白多跑几代。

```sh
crackweb scan -u https://example.com --no-waf        # 连厂商指纹探测一起关掉
crackweb scan -u https://example.com --no-assume-waf # 已知无防护时，省下那两代请求
```

但探测有个它解决不了的场景：**现代边缘常常改写 payload 却回 `200`**，
响应里没有任何东西表明它过滤过。这种目标上，升级规则永远不会触发 —— 它依赖的那份证据
恰恰是被扣下的 —— 而那些变异（真正能穿过去的部分）就永远不会被发出去。

所以 crackweb **不等这份证据**：它**假定前面就是有防护**，无论是否被拒绝，
每个 payload 都额外发送前两代。是两代而不是一代，因为第一代的预算全花在结构变异上，
而能击败「规范化一次、匹配一次」那种防护的组合（一次改写套一层编码）要到第二代才出现。
代价是真实的：对没有防护的目标，请求量大约变成四倍。`--no-assume-waf` 保留探测但去掉这个假定，
适用于你已经知道前面什么都没有的目标。

## 高级技巧

除了常规注入，crackweb 还用了下面这些把扫描器和 fuzzer 区分开的手法：

| 手法 | 做什么 |
| --- | --- |
| **统计判定，而不是秒表** | 时间盲注要四条同时成立：延迟达到请求量级的大部分、**不超出**它 —— `SLEEP(3)` 不可能让一次请求花掉 5 秒，超出的部分量的是别的东西（例如另一个检查正占着连接）、远超目标自身实测波动（3 倍四分位距）、且多次采样可复现。一次慢响应什么都证明不了。 |
| **HTTP 参数污染** | payload 单独发送被拒时，改为作为同名参数的**第二次出现**发送 —— 只读第一个取值的过滤器看不到它，而取最后一个取值的框架会执行它。 |
| **列数探测** | UNION 两侧列数不一致，在任何数据库里都是语法错误，所以列数是靠试出来的；每一列都填入一个唯一数字，这样"注入进去的值"才能跟"回显到表单里的 payload"区分开。搜索页还会把词印在正文里，剥掉 payload 也够不到，所以检查会先索取一个纯标记，量出这一页重复了它几次。 |
| **路径规范化** | `//etc/passwd`、`/.//etc/passwd`、`/etc//passwd` —— 针对那些正确剥掉了 `../`、却把 `//` 折叠错的实现。 |
| **二次注入** | 用一个请求把 payload 写进去，再重放**已观察到的**页面，看读回它时是否破坏了什么。比对基准是这些页面在写入**之前**的响应，所以证据是"写入造成的改变"。 |
| **带外盲测** | 盲 SSRF、命令注入、XXE 在响应里什么都不留。每次探测植入一个唯一回调地址，证据随后从另一个监听器到达。 |
| **编码后的参数文档** | 参数值本身是一段 JSON（无论是否再经 base64 包装）时，会把它展开并逐个字段测试。每次变异都会把外层信封重新拼好，让文档里的 payload 仍以合法输入抵达应用，而不是把承载它的那个参数弄坏。 |

## 登录态扫描

对匿名爬虫来说，登录后的一切都是不可见的；而瞄准匿名视图的检测，测的是错误的那一面。
给客户端一个身份，它就会在每个请求上带着它 —— 包括检测项自己构造的请求：

```sh
crackweb crawl -u https://app.example.com --cookie "session=abc; csrf=xyz"
crackweb crawl -u https://app.example.com --header "Authorization: Bearer eyJ..."
crackweb crawl -u https://staging.example.com --basic-auth alice:s3cret
```

- `-C, --cookie` 会与请求自带的 Cookie **合并**，
  因为丢掉一个 CSRF token 就毁掉了它本该维持的那个会话。
- `-H, --header` 可重复，且**只补空缺**：
  请求自己声明的身份比命令行默认值更具体，绝不被覆盖。
- `--basic-auth` 接受 `user:password`；只有第一个冒号是分隔符，因为密码里本来就可能含冒号。

`--session` 是另一回事。重复给两次就是两个或更多身份，供越权检测比较各自能访问到什么：

```sh
crackweb scan -u https://app.example.com/orders/1001 \
  --session "Cookie: session=alice" --session "Cookie: session=bob"
```

### 已经知道签名密钥时

JWT 的密钥往往来自配置文件、打包产物、代码仓库或一张截图 —— 而密钥在手，距离证据只差一个
请求。`--jwt-secret` 接收一个密钥，对目标签发的每个 token 重新签名并回送：

```sh
crackweb scan -u https://app.example.com/api/me -H "Authorization: Bearer $TOKEN" \
  --jwt-secret "配置文件里的那串密钥"
```

结论来自"服务端接受了"，而不是"拿到了密钥"：接受这个密钥签名的 token，意味着持有它的人
可以为任意身份签发。不给 `--jwt-secret` 时行为与之前完全一致。若目标用的是非对称算法，
不存在"可复现的密钥"，也就不会尝试。

密钥本身怎么拿到是离线的事 —— `crackweb local jwt` —— 两者是配套的：本地还原，再在这里
证明。

## User-Agent

默认情况下 crackweb 会表明自己是谁，所以扫描会留痕在目标日志里。
对一个用于「你有权测试的系统」的工具来说，这是诚实的默认值。

`--random-ua` 则改为**为每个请求现编一个合理的 User-Agent**。
池子由真实浏览器对外宣称的各个部分（引擎、平台、版本）**组合**而成，而不是一份固定清单 ——
因为短清单本身就是指纹。适用场景：工具自己的名字会污染你要看的日志，
或者不希望扫描流量因某个固定请求头而被归组。

## 模板

crackweb 可以直接运行 **nuclei 兼容的 YAML 模板**，公开模板库无需改写即可复用：

```sh
crackweb scan -u https://example.com --templates ./my-templates
crackweb crawl -u https://example.com --templates ./templates --checks template
```

```yaml
id: example-sqli-error

info:
  name: Error-based SQL injection
  author: crackweb
  severity: high
  description: The parameter reaches a SQL statement unparameterised.
  tags: sqli,injection
  classification:
    cwe-id: CWE-89

http:
  - method: GET
    path:
      - "{{RootURL}}/?id=1'"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "You have an error in your SQL syntax"
          - "SQLSTATE"
        condition: or
      - type: status
        status: [200]
```

已支持：`id`/`info`、`variables`、`http`（也接受 `requests` 写法）、`path` 与 `raw` 两种请求形式、
`headers`、`body`、`payloads` 与 `{{name}}` 替换、extractor（regex / kval / json / dsl）并把结果传给后续请求，
以及 `word`、`regex`、`status`、`size`、`binary`、`dsl` 六种 matcher，含 `condition`、
`matchers-condition`、`negative`、`case-insensitive`。

`dsl` 求值器支持比较运算、`&&`/`||`/`!`，以及常用函数 ——
`contains`、`contains_all`、`contains_any`、`starts_with`、`ends_with`、`len`、`tolower`、
`toupper`、`trim`、`replace`、`concat`、`substr`、`reverse`、`regex`、`md5`、`sha1`、
`sha256`、`base64`、`base64_decode`、`url_encode`、`url_decode`、`hex_encode`、
`hex_decode`、`rand_int`、`randstr`、`unix_time` —— 可作用于 `body`、`all_headers`、`raw`、
`status_code`、`content_length`、`duration` 以及任意响应头。

使用了 crackweb 无法执行的功能的模板（`flow`、`raw unsafe` 请求、pipelining、xpath matcher、
非 batteringram 的 attack 类型）会被**跳过并给出警告**，绝不会半途执行。可以从
`examples/templates/` 开始。

## 报告

`-o report.html` —— 另外 `.json`、`.sarif`、`.md` 按扩展名自动识别。

HTML 报告是一个自包含的单文件：严重性概览、过滤框，以及每个漏洞一张可折叠卡片，
包含说明、修复建议、命中的证据、原始请求、响应、用于比对的基线，以及可直接粘贴的 `curl` 复现命令。
它跟随阅读者的浅色/深色偏好，并且打印排版干净。

报告里还会带上**覆盖边界**：有多少请求没有拿到响应，以及哪些主机前面有东西代替应用作答。
从外面看，一次被拒绝的扫描和一次干净的扫描长得一样，所以报告直接说明是哪一种，而不是留给读者去猜。

SARIF 输出可直接接入 GitHub code scanning。

## 性能

以下数字来自真实运行：4 核 / 3.8 GB 的机器，目标与扫描器同机，
因此它们描述的是扫描器本身，而不是网络。

| | |
| --- | --- |
| 二进制 | 约 17 MB，单个静态文件 —— 无运行时、无解释器、无依赖树 |
| 冷启动 | 约 5 ms |
| 吞吐 | 8 线程下 60–90 请求/秒，由 `--rate` 封顶 |
| 一次完整爬取 + 主动扫描 | 约 200 页、约 16000 个请求、耗时约 3 分钟 |
| 仅被动模式 | 只读已经在流动的流量，自身不发任何请求 |

并发数与速率都是显式开关，而不是写死的常量，
因为合适的值取决于目标而不是工具：实验机可以吃下 8 线程 × 80 请求/秒，
生产系统通常不行。

## 设计取舍

**误报是最大的敌人。** 一个什么都报的扫描器会训练用户忽略它。有三道防线：上面那套归一化引擎；
每个漏洞都带置信度（`certain`、`firm`、`tentative`）；以及要求**正向证据**的检测逻辑 ——
数据库错误串、系统文件内容，或带外回调 —— 而不是仅仅"响应变了"。

**作用域是强制的。** 代理只拦截匹配 `--scope` 的主机，其余流量原样隧道转发，
因此无关的浏览不受影响也不会被改写。爬虫除非另有指定，否则不会离开起始主机。

**失败要看得见。** 没有拿到响应的请求会被计数并上报，而不是静默跳过：
一个拒绝连接的靶标不能看起来像一次干净的扫描。

**爬虫降级而不是失败。** headless 引擎需要基于 Chromium 的浏览器。
crackweb 按这个顺序查找：`CRACKWEB_CHROME` → `PATH` → 各平台实际的安装位置
（包含 Edge —— 每台 Windows 都有）→ Playwright / Puppeteer 留下的浏览器缓存。
一个都找不到时，它只提示一次，然后继续用不需要浏览器的 HTTP 引擎 ——
所以没有 Chromium 的机器上 `--engine hybrid` 依然能爬，只是对 JavaScript 的覆盖浅一些。

**浏览器自己发出的请求会被原样重放。** 爬虫的原则是：扫描器看到的一切请求都由 HTTP 引擎发出，
这样只有一条代码路径在生产它们。带着 body 的请求是这条原则覆盖不到的例外：
请求的方法、字节与 Content-Type 是页面脚本自己决定的，而这些都无法从它发往的地址反推出来。
把那个地址当成 GET 去取，会完全错过这个端点 —— 浏览器一路在用的 JSON API 就是这样变成"没测过"的。
所以这类请求会按它发出去的原样再发一次，发 JSON 的页面因此和别的页面一样被扫描。
没有 body 的 POST 不动它：没有参数可测，而重发它确实会产生影响。

**会读取对外发布的 API 描述。** 一份 OpenAPI / Swagger 文档是扫描器能拿到的最好输入 ——
每一条 path、每一个方法，以及各自的参数 —— 而它列出的东西里，大部分靠跟随链接是到不了的，
因为没有任何地方链接到一个 API。crackweb 会去问这类文档常见的发布地址，
会跟随页面或脚本指向的那些（Swagger UI 会在自己的初始化脚本里带上地址），
两种版本的格式都会读，并把每个 operation 变成一个请求：path 与 query 参数按声明的类型填值，
请求体按 schema 生成，然后像任何其它请求一样交给扫描器。文档可以点名任意主机，
但真正发出请求之前，会先按 scope 过滤它点名的对象。

**站点的 robots 文件与 sitemap 也会读**，理由正好相反。sitemap 是一份不用爬就能拿到的页面清单，
而且它是可嵌套的 —— 索引指向更多 sitemap，那些也会被跟随。robots 文件列的是站点不希望别人去看的东西，
而那里往往正是有价值的目标：写进去的每一条，都是有人决定不去链接的路径。读它是**刻意的选择，不是疏忽** ——
这条约定是为搜索引擎立的，它们要避免成为麻烦；而一次经授权的扫描问的是另一个问题。
这些路径会像其它地址一样被请求，并在日志里标明来源。只有真正指名路径的条目才会被采用：
空值表示“全部允许”，单独一个 `/` 表示“全部禁止”，而带 `*` 或 `$` 的是模式而不是地址。`--no-discovery` 可以把这一整套关掉，
适用于那种“连一个用户没有点名的地址都嫌多”的目标。

常见的那些地址覆盖的是「把描述固定发布在某个位置」的框架。如果一个站点把它挪了地方 ——
加了版本前缀、用了内部代号、路径是某人自己起的 —— 那是猜不到的，所以 `--api-doc <path>`
可以按名字额外请求一个地址。该选项可重复。

### 页面脚本调用的端点

单页应用把端点写在字符串字面量里，而不是链接里：删除按钮的处理函数、自己拼请求的表单、
提交时才发请求的搜索框。页面上没有链接指向它们，浏览器加载页面时也不会发出它们，
所以只跟链接的爬虫永远看不到。它们会被从脚本里提取出来 —— 其中的插值段
（`/api/documents/${id}`）会用一个数字补上，否则那个地址根本无法请求 —— 然后像其它地址一样入队。

例外是那些脚本只以 POST / PUT / PATCH / DELETE 调用的端点。爬虫对自己发现的地址一律用 GET 抓取，
而一个脚本自己写着「删除」的地址，对它背后的东西并不是显然无害的。只有加上 `--allow-state-change`
才会把它们排进队列；当你在扫一个允许写入的目标时，就该用它。

## 项目结构

```
cmd/crackweb/          可执行入口
internal/
  ca/                  CA 生成与按主机签发叶子证书
  checks/              检测接口、注册表与注入上下文
    passive/           不发送流量的检测
    active/            注入 payload 的检测
  cli/                 参数解析、命令分发、双语帮助
  crawl/               HTTP 与 headless 爬虫、HTML 与表单提取
  diff/                归一化、响应指纹、差异判定
  finding/             结果模型
  httpclient/          请求发送：超时、重试、限速、代理
  httpmsg/             共享的请求/响应模型、原始报文解析、参数提取
  i18n/                中英双语文案表
  oob/                 带外 DNS 与 HTTP 交互服务器
  payload/             payload 种子、变形器目录、代数分层
  proxy/               中间代理：CONNECT、TLS 中间人、WebSocket 转发
  report/              HTML、JSON、SARIF、Markdown 报告
  scan/                扫描队列、调度、去重
  scope/               主机匹配
  sitemap/             已见流量存储
  template/            nuclei 兼容模板引擎与 DSL
  version/             版本与署名
  waf/                 防火墙探测、指纹识别、升级记忆
```

## 参与开发

提交 PR 前必须通过 `make check`（gofmt + vet + test）。

这里有两条约定。第一，所有面向用户的文案都应放在 `internal/i18n` 里：漏翻一条文案，
或翻译里的 printf 占位符与英文原文不一致，测试都会直接让构建失败。第二，每个检测项自己声明
严重性、标签与修复建议，并且只通过传给它的 `checks.Context` 做事情 —— 没有全局状态，
这正是每个检测项都能被独立测试的原因。

## 免责声明

crackweb 仅供获得合法授权的安全测试、CTF 比赛与教学研究使用，请勿用于未获得授权的目标。

## 许可

MIT —— 见 [LICENSE](LICENSE)。
