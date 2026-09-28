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
```

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

## 检测能力

**被动检测** —— 只分析已有的流量，可以安全地对生产环境运行。

| 检测项 | 发现什么 |
| --- | --- |
| `passive-security-headers` | 缺少 CSP、HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy |
| `passive-cookie-flags` | Cookie 缺少 Secure、HttpOnly 或 SameSite |
| `passive-cors` | 回显 Origin 或使用通配符的 `Access-Control-Allow-Origin`，且允许携带凭据 |
| `passive-info-disclosure` | `Server`、`X-Powered-By` 等响应头泄露版本号 |
| `passive-mixed-content` | HTTPS 页面里加载的明文 HTTP 子资源 |
| `passive-cache-control` | 建立会话的响应可能被缓存 |
| `passive-directory-listing` | 自动生成的目录索引 |
| `passive-cleartext-password` | 凭据经 http:// 提交 —— 报告中绝不复现其值 |

**主动检测** —— 发送 payload 并根据返回结果判定。

| 检测项 | 严重性 |
| --- | --- |
| `sqli-error` | 严重 |
| `sqli-boolean` | 高危 |
| `sqli-union` | 严重 |
| `sqli-time` | 高危 |
| `xss-reflected` | 高危 |
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
| `request-smuggling` | 高危（需显式开启） |

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
crackweb scan -u https://example.com --no-waf    # 关闭探测与变形
```

## 高级技巧

除了常规注入，crackweb 还用了下面这些把扫描器和 fuzzer 区分开的手法：

| 手法 | 做什么 |
| --- | --- |
| **统计判定，而不是秒表** | 时间盲注要三条同时成立：延迟达到请求量级的大部分、远超目标自身实测波动（3 倍四分位距）、且多次采样可复现。一次慢响应什么都证明不了。 |
| **HTTP 参数污染** | payload 单独发送被拒时，改为作为同名参数的**第二次出现**发送 —— 只读第一个取值的过滤器看不到它，而取最后一个取值的框架会执行它。 |
| **列数探测** | UNION 两侧列数不一致，在任何数据库里都是语法错误，所以列数是靠试出来的；每一列都填入一个唯一数字，这样"注入进去的值"才能跟"回显到表单里的 payload"区分开。 |
| **路径规范化** | `//etc/passwd`、`/.//etc/passwd`、`/etc//passwd` —— 针对那些正确剥掉了 `../`、却把 `//` 折叠错的实现。 |
| **二次注入** | 用一个请求把 payload 写进去，再重放**已观察到的**页面，看读回它时是否破坏了什么。比对基准是这些页面在写入**之前**的响应，所以证据是"写入造成的改变"。 |
| **带外盲测** | 盲 SSRF、命令注入、XXE 在响应里什么都不留。每次探测植入一个唯一回调地址，证据随后从另一个监听器到达。 |

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
