package i18n

// chinese is the Simplified Chinese catalogue. It is an opt-in language: the
// default is English, switched on with --lang zh or CRACKWEB_LANG=zh.
var chinese = map[Key]string{
	KeyAppTagline: "流量驱动的 Web DAST 漏洞扫描器 —— 把浏览器挂到代理上，边浏览边发现漏洞。",
	KeyAppDisclaimer: "crackweb 仅供获得合法授权的安全测试、CTF 比赛与教学研究使用，" +
		"请勿用于未获得授权的目标。",

	KeyHelpUsage:           "用法",
	KeyHelpUsageLine:       "crackweb [全局选项] <子命令> [子命令选项]",
	KeyHelpCommandsTitle:   "子命令",
	KeyHelpOptionsTitle:    "全局选项",
	KeyHelpCmdOptionsTitle: "选项",
	KeyHelpExamplesTitle:   "示例",
	KeyHelpSubcommandHint:  "执行 'crackweb <子命令> --help' 查看该子命令的选项。",
	KeyHelpGlobalHint:      "全局选项（如 --lang、--no-color、--quiet）同样适用于本命令。",
	KeyHelpMoreInfoTitle:   "更多信息",
	KeyHelpCommandUsageFmt: "crackweb %s",
	KeyRepoLabel:           "项目地址：",
	KeyHelpExamples: `  # 启动中间代理，浏览器挂着它去访问目标
  crackweb proxy --listen 127.0.0.1:7777

  # 爬取目标并扫描爬到的每个请求
  crackweb crawl -u https://example.com

  # 扫描一份从 Burp 保存下来的请求
  crackweb scan -r request.txt

  # 启动带外交互服务器
  crackweb oob --dns 0.0.0.0:5353 --http 0.0.0.0:8081`,

	KeyFlagLang:    "输出语言：en（默认）或 zh。设置 CRACKWEB_LANG=zh 效果相同。",
	KeyFlagHelp:    "显示本帮助并退出。",
	KeyFlagVersion: "显示版本信息并退出。",
	KeyFlagNoColor: "关闭彩色输出。",
	KeyFlagQuiet:   "只输出漏洞结果，隐藏进度与状态信息。",

	KeyCmdProxySummary: "启动中间代理：浏览器挂上来正常访问，crackweb 对经过的流量做测试。",
	KeyCmdCrawlSummary: "爬取目标，并扫描爬到的每个请求。",
	KeyCmdScanSummary:  "扫描单个目标，或一份其它工具保存下来的原始 HTTP 请求。",
	KeyCmdOobSummary:   "启动带外交互服务器（DNS 与 HTTP 回调）。",
	KeyCmdCaSummary:    "管理用于 HTTPS 拦截的 CA 证书。",

	KeyUsageProxy: "proxy [选项]",
	KeyUsageCrawl: "crawl -u <url> [选项]",
	KeyUsageScan:  "scan (-u <url> | -r <文件>) [选项]",
	KeyUsageOob:   "oob [选项]",
	KeyUsageCa:    "ca [选项]",

	KeyFlagListen:      "监听地址，例如 127.0.0.1:7777。",
	KeyFlagUpstream:    "把拦截到的流量转发给上游代理（http:// 或 socks5://）。",
	KeyFlagScope:       "只测试匹配该模式的主机，可重复；不匹配的主机原样透传。",
	KeyFlagPassiveOnly: "只分析流量，不重放任何改写过的请求。",

	KeyFlagURL:      "起始 URL。",
	KeyFlagDepth:    "最大爬取深度；0 表示不限。",
	KeyFlagEngine:   "爬虫引擎：http、headless 或 hybrid（默认）。",
	KeyFlagMaxPages: "访问页面数达到该上限后停止；0 表示不限。",

	KeyFlagScanURL:    "要扫描的目标 URL。",
	KeyFlagScanMethod: "使用的 HTTP 方法。",
	KeyFlagScanData:   "请求体；带有请求体时默认按表单 POST 发送。",
	KeyFlagScanHeader: "额外的请求头，例如 'Cookie: a=b'；可重复。",
	KeyFlagRaw:        "从原始 HTTP 请求文件读取要扫描的请求，例如 Burp 保存的报文。",
	KeyFlagChecks:     "逗号分隔的检测项名称或标签，或 all。标为「需显式开启」的检测项不会被 all 拉进来。",
	KeyFlagScanOutput: "报告输出路径，格式由扩展名决定（.html、.json、.sarif、.md）。",

	KeyFlagDNSAddr:   "DNS 交互服务器的监听地址，例如 0.0.0.0:5353。",
	KeyFlagHTTPAddr:  "HTTP 交互服务器的监听地址，例如 0.0.0.0:8081。",
	KeyFlagOOBToken:  "用于把回调与触发它的请求关联起来的共享密钥。",
	KeyFlagOOBDomain: "指向本服务器的基础域名，使用域名委派时填写。",

	KeyFlagOutDir: "生成或导出 CA 材料的目录。",
	KeyFlagForce:  "覆盖已存在的 CA 材料。",

	KeyErrUnknownCommand: "未知子命令 %q",
	KeyErrUnknownFlag:    "未知选项 %s",
	KeyErrFlagNeedsValue: "选项 %s 需要一个值",
	KeyErrInvalidValue:   "%q 不是 %s 的合法取值：%s",
	KeyErrBadLang:        "不支持的语言 %q；当前支持：en、zh",
	KeyErrNeedTarget:     "请通过 -u/--url 或 -r/--raw 指定目标",
	KeyErrURLRequired:    "必须通过 -u/--url 指定目标 URL",

	KeyMsgNotImplemented: "%s 已有骨架，但本次构建尚未实现。",
	KeyMsgPlannedFor:     "计划在里程碑 %s 完成。",

	KeyDiffReasonStatus:     "状态码 %d → %d",
	KeyDiffReasonRedirect:   "跳转目标变化：%s → %s",
	KeyDiffReasonTitle:      "标题 %q → %q",
	KeyDiffReasonLength:     "归一化长度 %d → %d（%+d 字节，原始长度 %d → %d）",
	KeyDiffReasonBinaryLen:  "二进制响应长度 %d → %d（%+d 字节）",
	KeyDiffReasonContent:    "内容相似度 %.3f 低于阈值 %.3f",
	KeyDiffReasonKeyword:    "响应中出现新的敏感特征：%s",
	KeyDiffReasonEmpty:      "响应正文变为空",
	KeyDiffReasonType:       "响应类型变化：%s → %s",
	KeyDiffReasonError:      "请求失败：%s",
	KeyDiffReasonBaseError:  "基线请求失败（%s），本次判定不可靠",
	KeyDiffReasonEcho:       "参数值被页面回显：%s",
	KeyDiffReasonNoBaseline: "没有可用于比对的基线响应",

	KeyDiffCodeStatus:     "状态码变化",
	KeyDiffCodeRedirect:   "跳转目标变化",
	KeyDiffCodeTitle:      "页面标题变化",
	KeyDiffCodeLength:     "长度突变",
	KeyDiffCodeContent:    "内容突变",
	KeyDiffCodeKeyword:    "敏感关键字",
	KeyDiffCodeEmpty:      "响应内容为空",
	KeyDiffCodeType:       "响应类型变化",
	KeyDiffCodeError:      "请求异常",
	KeyDiffCodeEcho:       "参数回显",
	KeyDiffCodeNoBaseline: "缺少基线",

	KeyDiffNone:       "无差异",
	KeyDiffEmptyValue: "（空）",
	KeyDiffElided:     "……（其余 %d 行已省略）",

	KeyCheckSecHeadersTitle: "缺少安全响应头",
	KeyCheckSecHeadersDesc: "响应中缺少一个或多个用于抵御跨站脚本、点击劫持与协议降级攻击的响应头。" +
		"单独缺少它们并不算漏洞，但会失去一层本可限制漏洞影响的防线。",
	KeyCheckSecHeadersFix: "在每一个响应上补齐缺失的响应头：Content-Security-Policy、" +
		"Strict-Transport-Security、X-Content-Type-Options、X-Frame-Options、Referrer-Policy " +
		"与 Permissions-Policy。策略应按业务定制，而不要照抄模板。",

	KeyCheckCookieFlagsTitle: "Cookie 缺少安全属性",
	KeyCheckCookieFlagsDesc: "Cookie 在设置时缺少 Secure、HttpOnly 或 SameSite 策略。" +
		"缺少 HttpOnly 的 Cookie 能被注入的脚本读取；缺少 Secure 的 Cookie 会在明文 HTTP 下泄露；" +
		"缺少 SameSite 的 Cookie 会随跨站请求一起发送。",
	KeyCheckCookieFlagsFix: "为会话 Cookie 设置 Secure、HttpOnly 与 SameSite=Lax（或 Strict）；" +
		"在作用域允许时使用 __Host- 或 __Secure- 前缀。",

	KeyCheckCORSTitle: "跨域资源共享配置过宽",
	KeyCheckCORSDesc: "响应允许任意来源读取，要么使用通配符，要么直接回显请求中的 Origin。" +
		"若同时允许携带凭据，任何站点都能以受害者的身份读取已认证的数据。",
	KeyCheckCORSFix: "Access-Control-Allow-Origin 只返回显式白名单中的来源；" +
		"绝不要把回显的 Origin 与 Access-Control-Allow-Credentials: true 一起使用。",

	KeyCheckInfoDisclosureTitle: "技术栈与版本信息泄露",
	KeyCheckInfoDisclosureDesc: "响应中暴露了服务器软件、框架或版本号。" +
		"这等于给攻击者一份已知漏洞的候选清单，省去了他们自行识别的功夫。",
	KeyCheckInfoDisclosureFix: "在 Web 服务器或反向代理上去除或泛化 Server、X-Powered-By、" +
		"X-AspNet-Version 等标识性响应头。",

	KeyCheckMixedContentTitle: "HTTPS 页面加载混合内容",
	KeyCheckMixedContentDesc: "HTTPS 页面通过明文 HTTP 加载子资源。该资源可被传输途中篡改，" +
		"攻击者因此能向一个本已加密的页面注入脚本。",
	KeyCheckMixedContentFix: "所有子资源一律使用 HTTPS 加载；并在 Content-Security-Policy 中" +
		"启用 upgrade-insecure-requests 作为兜底。",

	KeyCheckCacheTitle: "敏感响应可被缓存",
	KeyCheckCacheDesc: "已认证的响应没有携带 Cache-Control 指令，共享缓存或浏览器磁盘缓存" +
		"可能保留它，并将其提供给同一设备或代理上的其他用户。",
	KeyCheckCacheFix: "对包含用户专属或敏感数据的响应发送 Cache-Control: no-store。",

	KeyCheckDirListingTitle: "开启了目录列表",
	KeyCheckDirListingDesc: "服务器返回了自动生成的目录索引，暴露了从未被链接过的文件名，" +
		"其中可能包含备份文件与源码文件。",
	KeyCheckDirListingFix: "关闭自动目录索引（Apache 的 Options -Indexes，nginx 的 autoindex off），" +
		"并清理本不应对外提供的文件。",

	KeyCheckSRITitle: "第三方子资源未做完整性校验",
	KeyCheckSRIDesc: "页面从其它源加载了脚本或样式表，却没有携带 Subresource Integrity " +
		"哈希。一旦那个源被入侵，或者文件被替换，浏览器就会执行它拿到的任何内容，而页面无从察觉。",
	KeyCheckSRIFix: "为每一个跨源加载的脚本与样式表补上 integrity 属性（SHA-256 或更强），" +
		"并加上 crossorigin，否则浏览器不会真正执行该校验。",

	KeyCheckErrorDisclosureTitle: "泄露了应用报错细节",
	KeyCheckErrorDisclosureDesc: "响应中带有调用栈或框架报错信息，暴露了内部组件、" +
		"文件路径与依赖库版本，往往还直接指出了应用是在哪个输入上出错的。",
	KeyCheckErrorDisclosureFix: "在应用边界统一兜住异常，对外只返回通用提示与一个便于检索的" +
		"关联 ID；详细报错写入服务端日志，并在生产环境关闭框架的调试模式。",

	KeyCheckContentDisclosureTitle: "泄露了内网地址、路径或邮箱",
	KeyCheckContentDisclosureDesc: "响应体里出现了描述部署环境而非页面内容的信息：" +
		"内网 IP、服务端文件路径或邮箱地址。这些都不应出现在对外响应中，" +
		"而合在一起足以让攻击者摸清站点背后的基础设施。",
	KeyCheckContentDisclosureFix: "从访客可读的一切内容中移除部署细节：改造错误页使其不再打印路径，" +
		"并让生成的页面经过构建流程去掉源码注释。",

	KeyCheckPrivateKeyTitle: "泄露了私钥",
	KeyCheckPrivateKeyDesc: "响应中出现了形如 PEM 私钥的内容。任何人取到该 URL，" +
		"就等于掌握了这把密钥所保护的一切：TLS 会话、签名令牌，甚至另一套系统的访问权。",
	KeyCheckPrivateKeyFix: "立即把该文件移出站点根目录，并轮换这把密钥——" +
		"已经被对外提供的密钥必须视为已泄露。私钥材料不应放在服务器对外发布的任何目录里。",

	KeyCheckInsecureTransportTitle: "密码输入框通过明文 HTTP 提供",
	KeyCheckInsecureTransportDesc: "该页面包含密码输入框，却未经 TLS 提供。" +
		"用户输入的内容以及随后的会话，都会经过路径上任何人都可以读取或篡改的通道。",
	KeyCheckInsecureTransportFix: "应用只通过 HTTPS 提供服务，并将明文 HTTP 请求重定向过去。" +
		"证书就位后补上 HSTS，让浏览器不再尝试明文连接。",

	KeyCheckLibraryTitle: "加载了存在已知漏洞的前端库",
	KeyCheckLibraryDesc: "页面加载的这个库，其版本存在已公开的漏洞。该库由发布页面的一方维护，" +
		"但在升级之前，这个缺陷会出现在每一个加载它的页面上——包括那些没人想到要去测的页面，" +
		"因为问题并不出在它们自己的代码里。",
	KeyCheckLibraryFix: "把库升级到包含修复的版本，并像管理服务端依赖那样跟踪前端依赖，" +
		"让版本成为构建过程控制的东西。从 CDN 加载并不会把维护责任转移给 CDN。",

	KeyCheckSQLiErrorTitle: "SQL 注入（报错型）",
	KeyCheckSQLiErrorDesc: "向该参数注入 SQL 语法后，数据库返回了语法错误。" +
		"这说明参数值未经参数化就进入了 SQL 语句，攻击者可以读写、甚至删除该数据库账号能触及的一切数据。",
	KeyCheckSQLiErrorFix: "所有进入数据库的值一律使用参数化查询（预编译语句）；" +
		"并为应用分配最小权限的数据库账号。",

	KeyCheckSQLiBoolTitle: "SQL 注入（布尔盲注）",
	KeyCheckSQLiBoolDesc: "注入布尔条件后，响应的差异与条件的真假保持一致。" +
		"页面虽然不报错，但页面内容本身就成了预言机，攻击者可以据此逐位提取数据。",
	KeyCheckSQLiBoolFix: "所有进入数据库的值一律使用参数化查询，不要用字符串拼接构造 SQL。",

	KeyCheckSQLiTimeTitle: "SQL 注入（时间盲注）",
	KeyCheckSQLiTimeDesc: "向该参数注入延时指令后，服务器出现了明显停顿。" +
		"即使应用不报错、页面看起来毫无变化，这种方式依然成立，" +
		"因此它是确认参数是否进入数据库最可靠的依据。",
	KeyCheckSQLiTimeFix: "所有进入数据库的值一律使用参数化查询；" +
		"并排查为什么数据库会因用户输入而执行长耗时查询。",

	KeyCheckXSSTitle: "反射型跨站脚本",
	KeyCheckXSSDesc: "该参数的值未经编码就写入了响应，因而被浏览器当作标记解析。" +
		"攻击者只要能诱使受害者点击构造好的链接，就能在该站点的会话中执行脚本。",
	KeyCheckXSSFix: "按下文语境（HTML 文本、属性、URL、脚本）分别编码输出；" +
		"并配置禁止内联脚本的 Content-Security-Policy。",

	KeyCheckPathTraversalTitle: "目录穿越 / 本地文件包含",
	KeyCheckPathTraversalDesc: "该参数使请求的路径越出了既定目录：" +
		"一串 ../ 走到了预期位置之外，服务器返回了系统文件。" +
		"攻击者可借此读取配置、凭据与源码。",
	KeyCheckPathTraversalFix: "把路径解析到固定基础目录之下，并拒绝任何越界的路径；" +
		"更稳妥的做法是只接受标识符白名单，而不接受文件名。",

	KeyCheckSSTITitle: "服务端模板注入",
	KeyCheckSSTIDesc: "注入的模板表达式被服务端求值，而不是被当作普通文本。" +
		"视模板引擎而定，危害会从读取服务端变量一路升级到执行任意代码。",
	KeyCheckSSTIFix: "绝不用用户输入拼接模板；把值作为数据传入固定模板；" +
		"并在引擎支持时启用沙箱模式。",

	KeyCheckRedirectTitle: "开放重定向",
	KeyCheckRedirectDesc: "该参数控制着跳转目标，并且接受绝对 URL，" +
		"因此应用会把用户转发到攻击者指定的任意站点。" +
		"这常被用来让钓鱼链接看起来属于本域名。",
	KeyCheckRedirectFix: "只跳转到固定白名单中的目标；或只接受相对路径，" +
		"拒绝任何带 scheme 或带 authority 的值。",

	KeyCheckCRLFTitle: "CRLF 注入 / 响应头注入",
	KeyCheckCRLFDesc: "该参数中的回车换行序列被写入了响应头，使注入的响应头得以送达客户端。" +
		"视响应情形，这可能导致响应拆分、Cookie 固定或缓存投毒。",
	KeyCheckCRLFFix: "对任何最终进入响应头的值，过滤掉 CR 与 LF；" +
		"并拒绝参数中含 CRLF 的请求。",

	KeyCheckNoSQLTitle: "NoSQL 注入",
	KeyCheckNoSQLDesc: "向该参数注入操作符或查询片段后，数据库对查询的解析被改变，" +
		"通常可以绕过认证，或读取调用方本不该看到的记录。",
	KeyCheckNoSQLFix: "把传入参数强制转换到预期的标量类型；" +
		"不要把请求数据直接当作查询文档使用。",

	KeyCheckSSRFTitle: "服务端请求伪造",
	KeyCheckSSRFDesc: "该参数使服务器向攻击者控制的目标发起请求。" +
		"服务器处在内网之中，因此可以触达外部无法访问的内网服务、云元数据端点与管理接口。",
	KeyCheckSSRFFix: "对目标地址做白名单校验；封禁链路本地与私有网段；" +
		"对用户提供的 URL 不要跟随跳转。",

	KeyCheckIDORTitle: "越权访问（水平权限绕过）",
	KeyCheckIDORDesc: "两个不同的已认证会话拿到了同一个受保护对象的相同内容，而匿名请求拿不到。" +
		"该对象由客户端可控的取值来寻址，却没有按归属做隔离，" +
		"因此任何已登录用户只要改一下这个值，就能读到别人的数据。",
	KeyCheckIDORFix: "对象的归属应从会话自身的身份推导，而不是从请求里取：" +
		"用（归属者, 对象 ID）联合查询，或在返回前校验归属。" +
		"客户端传来的标识符永远不能当作授权凭据。",

	KeyCheckAccessVariantsTitle: "换一种方法或路径写法即可绕过访问控制",
	KeyCheckAccessVariantsDesc: "原始请求被拒绝了，但把同一个资源换一种方式寻址——换方法，" +
		"或同一路径换一种写法——就得到了响应。规则由某一层按某一种写法执行，" +
		"而真正提供资源的是另一层，于是这个拒绝只对被测的那种请求成立，对没被测的那种不成立。",
	KeyCheckAccessVariantsFix: "把规则下沉到真正提供资源的那一层，并覆盖所有写法：" +
		"在任何规则生效之前先对路径做一次规范化，并且按“动作”而非“承载动作的方法”做授权。",

	KeyEvidenceIDOR:       "两个认证会话读到了同一个对象（响应有 %s 与 %s 一致），而匿名请求读不到",
	KeyEvidenceAccessRule: "原始请求被以 %d 拒绝，而变体 %q 被以 %d 应答",

	KeyCheckPaginationTitle: "分页参数没有真正限制返回量",
	KeyCheckPaginationDesc: "先把请求限定为只取一条，再换成一个超出该参数预期范围的取值，" +
		"返回的数据量发生了明显变化。这个参数被当作“建议”而非限制来读，" +
		"调用方因此可以一次取走整个集合——本来应该分页的接口就这样变成了批量导出。",
	KeyCheckPaginationFix: "在服务端把分页大小夹到一个有上限的范围内，" +
		"对越界取值直接拒绝而不是自行解释。并且在序列化之前就按调用方身份对集合做鉴权，" +
		"不要让“返回多少条”成为用户和他人数据之间唯一的屏障。",

	KeyEvidencePagination: "限定为 %d 条时响应为 %d 字节，而取值为 %q 时返回了 %d 字节",

	KeyCheckTypeBypassTitle: "换一种参数写法即可绕过输入校验",
	KeyCheckTypeBypassDesc: "同一个取值，单独提交时被拒绝，把参数写成数组形式后却被接受了。" +
		"这段校验是按标量写的，而框架交给处理逻辑的是别的东西，" +
		"于是校验根本看不到它本该拒绝的内容——相当一部分越权问题就是这条路径。",
	KeyCheckTypeBypassFix: "按框架实际交付的类型做校验，而不是先看值；" +
		"对形态不对的参数直接拒绝，不要做隐式转换。" +
		"鉴权要基于解析后的取值，而不是原始字符串。",

	KeyEvidenceTypeBypass: "取值 %q 被以 %d 拒绝，而同样取值写成 %q 后被以 %d 应答",

	KeyCheckDOMXSSTitle: "页面自身脚本导致的跨站脚本",
	KeyCheckDOMXSSDesc: "页面从 URL 里取了一个值，并把它当成标记写进了文档，浏览器执行时把它运行了。" +
		"服务端根本没有看到这个 payload——值来自地址栏——所以任何服务端侧过滤都无从拦截，" +
		"响应体里也看不出这个缺陷。",
	KeyCheckDOMXSSFix: "用文本而不是标记来构建 DOM：用 textContent 而不是 innerHTML，" +
		"通过创建元素并设置属性来代替拼接字符串；把来自 location、postMessage 或存储的值" +
		"一律当作不可信输入。不带 unsafe-inline 的 Content-Security-Policy 是兜底，不是修复。",

	KeyCheckLDAPTitle: "LDAP 注入",
	KeyCheckLDAPDesc: "一个携带 LDAP 过滤语法的值到达了目录查询：响应里出现了目录库自己对畸形过滤器的报错。" +
		"过滤器本身就是一门查询语言，拼进去的值不再是一个值，而是一个语项——" +
		"本该询问「是否存在匹配条目」的认证检查，就此变成了「这个过滤器能否解析」。",
	KeyCheckLDAPFix: "把值作为过滤器参数传入，而不是用它拼出过滤器；" +
		"或者在拼接之前转义 LDAP 中有特殊含义的字符：* ( ) \\ NUL。" +
		"先解析出用户，再比对凭据，不要让目录一次性同时匹配两者。",

	KeyCheckXPathTitle: "XPath 注入",
	KeyCheckXPathDesc: "一个携带 XPath 语法的值到达了 XPath 表达式：响应里出现了解析器自己的报错。" +
		"XPath 没有参数绑定机制，值只能靠引号放进表达式里，而值自带的引号就足以闭合作者打开的那个字面量。",
	KeyCheckXPathFix: "使用 XPath API 的变量绑定（带 resolver 编译出来的表达式），不要用字符串拼表达式；" +
		"或者在使用前按严格白名单校验取值。转义只是退路，不是修复方案。",

	KeyCheckODataTitle: "OData 查询注入",
	KeyCheckODataDesc: "一个携带 OData 查询语法的值到达了服务端查询：响应里出现了库自己对畸形查询的报错。" +
		"系统查询选项——$filter、$orderby、$expand——是写在 URL 里的查询语言，" +
		"拼进去的值可以闭合它本该只是其中一个语项的那个表达式。",
	KeyCheckODataFix: "用库的类型化 API 构造查询，而不是把取值拼进去；" +
		"当某处期望的是字面量时，拒绝携带查询语法的值。",

	KeyCheckGraphQLTitle: "GraphQL 内省泄露了 schema",
	KeyCheckGraphQLDesc: "该端点会响应 schema 查询，任何人都能读到完整的类型系统：" +
		"每一个 query、mutation 与字段，包括没有客户端在调用的，以及本就不打算公开的。" +
		"这等于把攻击者本来要自己画的那张地图直接交给他。",
	KeyCheckGraphQLFix: "在生产环境关闭内省；工具确实需要时，也只对已认证的开发者开放。" +
		"再加一层查询白名单，让 schema 即便泄露也换不来一组可执行的操作。",

	KeyEvidenceParser: "响应中出现了 %q，只有 %s 在收到无法解析的输入时才会产生它",

	KeyCheckCachePoisonTitle: "缓存响应被请求头污染",
	KeyCheckCachePoisonDesc: "一个写在请求头里的值出现在了响应中，随后在一个根本没有发送该头的请求里又出现了一次。" +
		"第二个响应来自缓存：这个值被写进了页面的共享副本，缓存把这份副本发给谁，谁就会收到它。" +
		"它会造成什么后果取决于页面把它放在哪里——链接、脚本、跳转——而全程都不需要受害者发送任何东西。",
	KeyCheckCachePoisonFix: "把所有会进入响应的请求头都纳入缓存键，或者在边缘直接丢弃应用用不到的那些。" +
		"不要用请求头拼 URL 或链接：从配置里取，或把该头校验在你可控的主机白名单内。" +
		"对这类响应回 Cache-Control: private 或 no-store 是兜底，不是修复方案。",

	KeyEvidenceCache:   "携带 %s 的请求返回了该值，而去掉它之后同样的请求随即拿到了那份缓存副本",
	KeyEvidenceVariant: "payload 变形：%s（第 %d 代，变形链：%s）",
	KeyEvidenceCSRF: "把防 CSRF 字段 %s 换成 %s —— 一个服务端不可能签发过的值 —— 请求仍被接受" +
		"（响应与基线的相似度 %.0f%%）。服务端从不校验的令牌只是摆设。",
	KeyEvidenceWAF: "目标位于 %s 之后；payload 已升级到第 %d 代变形",

	KeyFlagSession: "一个已认证会话，写成 '名称: 值' 形式的请求头，例如 'Cookie: sess=abc'；" +
		"至少提供两个不同会话才能启用越权检测。",

	KeyMsgSessionsLoaded:    "已载入 %d 个会话用于越权对比",
	KeyMsgIDORNeedsSessions: "越权检测至少需要两个 --session，已跳过",

	KeyCheckCMDiTitle: "命令注入",
	KeyCheckCMDiDesc: "该参数未经转义就传给了 shell，攻击者因此能以 Web 服务器的权限" +
		"执行任意操作系统命令。",
	KeyCheckCMDiFix: "尽量避免走 shell：使用 API，或以参数数组的形式调用 exec。" +
		"若确实无法避免 shell，请对允许的字符与取值做白名单限制。",

	KeyEvidenceBoolean: "真条件与基线一致（%.3f），假条件不一致（%.3f），两个分支之间也有差异（%.3f）",
	KeyEvidenceTiming:  "响应耗时 %s，基线为 %s",
	KeyEvidenceReflect: "payload 未经编码地被回显：%s",
	KeyEvidenceOOB:     "目标回调了 %s（%s，来自 %s）",

	KeyReportTitle:       "crackweb 漏洞报告",
	KeyReportSubtitle:    "流量驱动的 DAST 扫描",
	KeyReportSummary:     "概览",
	KeyReportTarget:      "目标",
	KeyReportStarted:     "开始时间",
	KeyReportFinished:    "结束时间",
	KeyReportDuration:    "耗时",
	KeyReportHosts:       "主机",
	KeyReportEndpoints:   "测试端点",
	KeyReportRequests:    "发送请求",
	KeyReportFindings:    "漏洞",
	KeyReportNoFindings:  "未发现漏洞。",
	KeyReportGeneratedBy: "由 %s 生成",
	KeyReportDisclaimer: "本报告描述的是扫描当时目标的状况，未报出某项漏洞并不代表它不存在。" +
		"请仅在获得授权的系统上使用 crackweb。",
	KeyReportFilter:      "按严重性、主机、检测项或 URL 过滤……",
	KeyReportExpandAll:   "全部展开",
	KeyReportCollapseAll: "全部收起",

	KeyReportFieldCheck:       "检测项",
	KeyReportFieldSeverity:    "严重性",
	KeyReportFieldConfidence:  "置信度",
	KeyReportFieldURL:         "URL",
	KeyReportFieldParam:       "参数",
	KeyReportFieldPayload:     "Payload",
	KeyReportFieldDescription: "说明",
	KeyReportFieldRemediation: "修复建议",
	KeyReportFieldReferences:  "参考",
	KeyReportFieldRequest:     "请求",
	KeyReportFieldResponse:    "响应",
	KeyReportFieldBaseline:    "基线响应",
	KeyReportFieldEvidence:    "证据",
	KeyReportFieldDiff:        "差异",
	KeyReportCurl:             "用 curl 复现",
	KeyReportCWE:              "CWE",

	KeySeverityCritical: "严重",
	KeySeverityHigh:     "高危",
	KeySeverityMedium:   "中危",
	KeySeverityLow:      "低危",
	KeySeverityInfo:     "信息",
	KeySeverityUnknown:  "未知",

	KeyConfidenceCertain:   "确定",
	KeyConfidenceFirm:      "较大把握",
	KeyConfidenceTentative: "待确认",

	KeyMsgReportWritten: "报告已写入 %s",
	KeyFlagTimeout:      "单请求超时，例如 10s 或 500ms。",
	KeyFlagRate:         "每秒最多发出多少请求；0 表示不限速。",
	KeyFlagThreads:      "同时运行多少个检测项。",
	KeyFlagInsecure:     "与目标通信时跳过 TLS 证书校验。",
	KeyFlagUserAgent:    "要发送的 User-Agent；默认会标明 crackweb 自身。",
	KeyFlagProxy:        "让出站请求经由该代理（http:// 或 socks5://）。",
	KeyFlagSensitivity:  "差异灵敏度 1~5；数值越大报得越多，误报也随之增加。",
	KeyFlagSkipParams:   "永不注入的参数名；可重复。",
	KeyFlagListChecks:   "列出所有可用检测项并退出。",
	KeyFlagVerbose:      "打印 crackweb 发出的每一个请求。",
	KeyFlagTemplates:    "nuclei 兼容 YAML 模板所在目录；可重复。",
	KeyFlagExportCA:     "把 CA 证书写入该 PEM 文件，便于安装。",
	KeyFlagNoNormalize:  "逐字节比对响应，不做动态内容归一化。",

	KeyMsgProxyListening:      "crackweb 代理已监听 %s",
	KeyMsgProxyCAHint:         "把 CA 证书（%s）装进浏览器或系统信任库，crackweb 才能读取 HTTPS 流量。",
	KeyMsgProxyStopped:        "代理已停止",
	KeyMsgCAGenerated:         "已在 %s 生成新的 CA",
	KeyMsgCALoaded:            "已从 %s 载入 CA",
	KeyMsgScanStarted:         "正在扫描 %s",
	KeyMsgScanFinished:        "扫描完成：%d 个漏洞，共发出 %d 个请求，耗时 %s",
	KeyMsgNoFindings:          "未发现漏洞",
	KeyMsgOOBListening:        "带外交互服务器已监听：http %s，dns %s",
	KeyMsgUnknownChecks:       "未知的检测项或标签：%s",
	KeyMsgChecksLoaded:        "已加载 %d 个检测项：被动 %d 个，主动 %d 个",
	KeyMsgRequestError:        "请求失败：%v",
	KeyMsgTemplateLoaded:      "已载入 %d 个模板（来自 %s）",
	KeyMsgChecksListed:        "检测项",
	KeyMsgOOBCallbackExample:  "回调 URL 形如 %s（每次注入都会生成不同的一个）",
	KeyMsgCAExported:          "CA 证书已导出到 %s",
	KeyMsgCrawlStats:          "爬取：抓取 %d 个页面，发现 %d 个 URL，扫描 %d 个请求",
	KeyMsgTemplateUnsupported: "模板 %s 使用了 crackweb 无法执行的功能，已跳过：%s",
	KeyMsgNoBrowser:           "未找到基于 Chromium 的浏览器，headless 爬虫不可用，将退回 HTTP 引擎。请安装 Chrome、Chromium 或 Edge，或用 CRACKWEB_CHROME 指定浏览器路径，也可显式使用 --engine http 以不再提示。",

	KeyErrBadSensitivity:      "灵敏度必须在 1 到 5 之间",
	KeyErrNoChecks:            "所请求的检测项都不存在；用 --list-checks 查看可用项",
	KeyErrLoadCA:              "无法载入或创建 CA：%v",
	KeyErrReadRaw:             "无法读取 %s：%v",
	KeyErrStartProxy:          "无法启动代理：%v",
	KeyReportBoundaryTitle:    "覆盖边界",
	KeyReportUnanswered:       "没有得到响应的请求数：%d",
	KeyReportProtectedTitle:   "有东西代替应用作答的主机：",
	KeyReportProtectedNothing: "本次运行中没有任何请求被拒绝。",

	KeyMsgUnanswered:          "%d 个请求没有得到响应",
	KeyMsgProtectedHost:       "%s 前有东西代替应用作答",
	KeyMsgProtectedWithVendor: "%s 前有东西代替应用作答（%s）",
	KeyMsgChecksOptIn:         "需显式开启",
	KeyMsgProbing:             "正在向各主机询问 API 描述、robots.txt 与 sitemap",
	KeyMsgSelfDescribed:       "读到了 %d 份描述与 %d 个站点文件",

	KeyFlagAPIDoc: "除了那些常见的地址，额外在这个路径上请求一次 API 描述。" +
		"很多站点会用自己的名字发布它 —— 带版本前缀、内部代号 —— 猜是猜不到的。可重复。",
	KeyFlagAllowStateChange: "把页面脚本只以 POST / PUT / PATCH / DELETE 调用的端点也加入队列。" +
		"默认会跳过它们：爬虫对自己发现的地址一律用 GET 抓取，而一个脚本自己写着「删除」的地址，" +
		"对它背后的东西并不是显然无害的 —— 上传表单就属于这一类。" +
		"页面里用 <form> 声明的表单不受影响：它们走的是另一条提交路径。",
	KeyFlagNoDiscovery: "不去询问 API 描述、robots.txt 或 sitemap；只测爬取能到达的内容。",
	KeyFlagNoAssumeWAF: "保留 WAF 探测，只去掉「前面有防护」这个假定：" +
		"只有在确实探测到拒绝时，才发送额外的代数。默认情况下无论有没有证据都会发，" +
		"因为现代边缘常常改写 payload 却回 200，而不是拒绝它，检测因此无从看见。" +
		"适用于你已经知道前面什么都没有的目标。",
	KeyFlagNoWAF: "连 WAF 探测一起关掉。不再寻找厂商指纹，于是用自己方式拒绝的防护" +
		"不会被认出，它的 payload 也就永远不会被变异。--no-assume-waf 保留探测、只去掉假定；" +
		"这个是把两者都去掉。明说拒绝的响应在两种情况下都仍会被识别。",
	KeyCheckXXETitle: "XML 外部实体注入",
	KeyCheckXXEDesc: "XML 解析器解析了请求中声明的外部实体。" +
		"只要开启了实体解析，解析器就会去抓取调用方指定的 URL，" +
		"于是上传一份文档就变成了读取本地文件、或访问防火墙后服务的手段。",
	KeyCheckXXEFix: "在所有 XML 解析器上关闭外部实体与 DTD 处理（如 LIBXML_NOENT 等），" +
		"并优先选用不携带 schema 的数据格式。",

	KeyCheckJWTTitle: "JSON Web Token 签名校验可被绕过",
	KeyCheckJWTDesc: "应用接受了签名被移除、或算法被改写的 token。" +
		"这样一来任何人都能伪造一个声称任意身份的 token，" +
		"下游所有基于身份的授权判断也就都失去了意义。",
	KeyCheckJWTFix: "在验证端固定可接受的算法，直接拒绝 alg:none；" +
		"绝不要让 token 自己的 header 决定用哪个密钥或哪种校验方式。",

	KeyCheckCSRFTitle: "状态变更请求缺少 CSRF 防护",
	KeyCheckCSRFDesc: "该请求会改变服务端状态，却在没有 token 的情况下被接受，" +
		"而且会话 Cookie 会随跨站请求一起发送。" +
		"受害者访问的任何页面都能以他的身份提交这个请求。",
	KeyCheckCSRFFix: "对每个会改变状态的请求都要求携带会话级 token 并在服务端校验；" +
		"同时把会话 Cookie 的 SameSite 设为 Lax 作为第二道防线。",

	KeyCheckHostHeaderTitle: "Host 头注入",
	KeyCheckHostHeaderDesc: "应用信任了 Host 头：攻击者提供的值出现在了响应或生成的链接里。" +
		"据此可以实施密码重置投毒与缓存投毒，全程都不需要接触受害者。",
	KeyCheckHostHeaderFix: "用配置里的规范主机名构造绝对 URL，而不要从请求里取；" +
		"并拒绝 Host 不在白名单内的请求。",
	KeyCheckUploadTitle: "文件上传处理不当",
	KeyCheckUploadDesc: "上传接口接受了文件名危险的请求 —— 可执行扩展名、" +
		"能骗过简单校验的双扩展名，或者会跳出上传目录的路径。" +
		"接受不等于可利用：它说明服务端没有拒绝一个做了加固的接口本该拒绝的输入。",
	KeyCheckUploadFix: "按内容而不是按文件名判断类型；把上传文件存放在 Web 根目录之外并重命名为随机名；" +
		"拒绝任何包含路径分隔符的文件名。",

	KeyCheckDeserialTitle: "存在不可信数据反序列化入口",
	KeyCheckDeserialDesc: "发送畸形的序列化对象后，应用返回了反序列化错误，" +
		"说明它会解析请求中的序列化数据。若攻击者能找到适配当前运行时的 gadget 链，" +
		"这就可以升级为远程代码执行 —— 这里确认的是入口，不是利用链。",
	KeyCheckDeserialFix: "不要接受客户端传来的序列化对象；" +
		"改用带显式 schema 的数据格式（如 JSON）；" +
		"若确实无法避免序列化格式，请把可反序列化的类型限制在白名单内。",
	KeyEvidenceTimingStat: "%d 次采样中位数为 %s，基线为 %s（波动 %s）；%s",
	KeyEvidenceHPP: "payload 作为同名参数的第二次出现发送，" +
		"因此只读第一个取值的过滤器看不到它",
	KeyCheckSecondOrderTitle: "存储型注入（二次注入）",
	KeyCheckSecondOrderDesc: "经由一个请求写入的值，在后续被另一个请求不安全地使用了：" +
		"某个原本正常返回的页面，在这次写入之后开始返回数据库错误。" +
		"写入 payload 的那个请求本身看起来完全无害，" +
		"这正是这类漏洞能躲过“一次只检查一个请求”的测试的原因。",
	KeyCheckSecondOrderFix: "把存储数据在**读取时**也当作不可信输入，而不只是在写入时校验：" +
		"消费它的查询要参数化，出口同样需要校验。",
	KeyFlagUnsafeChecks: "额外运行 --list-checks 中标为「需显式开启」的检测项。它们的探测不只是发一个请求：" +
		"走私探测会在连接上留下字节供下一个请求读取，DOM 探测会执行页面携带的每一个脚本，" +
		"缓存探测会写入共享缓存。请仅对自己拥有的系统使用。",
	KeyMsgUnsafeChecks:          "正在运行有副作用的检测项：%s",
	KeyCheckMethodOverrideTitle: "服务端接受 HTTP 方法覆盖",
	KeyCheckMethodOverrideDesc: "应用接受了一个请求：它的真实方法是无害的，" +
		"却通过一个请求头要求被当作会改变状态的方法处理。" +
		"如果访问控制是按请求行来实现的、而没有考虑这个覆盖头，" +
		"那么一个本应被拒绝的方法就会变得可达。",
	KeyCheckMethodOverrideFix: "除非前面有网关会剥掉这些头，否则不要支持方法覆盖头；" +
		"也绝不要仅凭请求行就做出授权判断。",

	KeyCheckSmugglingTitle: "HTTP 请求走私（解析不同步）",
	KeyCheckSmugglingDesc: "一个帧头自相矛盾的请求被返回了不止一个响应，" +
		"说明前端与后端对“这个请求在哪里结束”的理解不一致。" +
		"剩余字节随后会被当作该连接上下一个请求的开头 —— 也就是别人的请求。" +
		"该检测会发送带副作用的探测请求，默认关闭。",
	KeyCheckSmugglingFix: "让每一跳的判断一致：拒绝同时带 Content-Length 与 Transfer-Encoding 的请求，" +
		"在边缘做规范化，并尽量让整条链路都使用 HTTP/2。",
	KeyCheckSQLiUnionTitle: "SQL 注入（UNION 型）",
	KeyCheckSQLiUnionDesc: "查询的结果集被追加了调用方自己选定的行。" +
		"列数是靠试出来的，每一列都填了一个唯一数字，" +
		"这样才能把注入的值认作“页面显示的数据”而不是“输入的反射”。" +
		"与基于报错的发现不同，这一条不需要数据库给出任何错误消息 —— " +
		"页面只是把被要求的内容显示出来，就等于报告了成功。",
	KeyCheckSQLiUnionFix:           "把查询参数化。确实需要 UNION 的场合，也绝不能把调用方提供的文本拼进去。",
	KeyCheckCleartextPasswordTitle: "密码经未加密连接提交",
	KeyCheckCleartextPasswordDesc: "凭据经 http:// 发送到服务端，在网络上以明文形式传输。" +
		"任何能观察这段流量的人 —— 同一台交换机、会议网络、上游任一环节 —— 都能读到并使用它。" +
		"本报告刻意不复现该值：字段名与请求行已足以定位问题，不必把口令散播出去。",
	KeyCheckCleartextPasswordFix: "让整个应用走 HTTPS，并把 http:// 重定向过去，" +
		"同时启用 HSTS 以免重定向被剥离。" +
		"在此之前，任何以这种方式提交过的凭据都应视为已泄露。",
	KeyFlagCookie:            "随每个请求发送的会话 Cookie，例如 session=abc; csrf=xyz。可重复；多写一个前导的 Cookie: 也能识别。",
	KeyFlagHeader:            "随每个请求发送的额外请求头，格式为 名称: 值。可重复 —— 用于 Bearer token、API key 等。",
	KeyFlagBasicAuth:         "HTTP Basic 凭据，格式 user:password，会以 Authorization 头发送。",
	KeyFlagRandomUA:          "为每个请求现编一个合理的 User-Agent，而不是以 crackweb 标识自身。适合两种情况：工具自己的名字会污染你要看的日志，或者不想让扫描流量因固定指纹而被归组。",
	KeyCheckSQLiOrderByTitle: "SQL 注入（ORDER BY）",
	KeyCheckSQLiOrderByDesc: "用于指定排序列的参数被拼进了 ORDER BY 子句。" +
		"这个位置无法用别处那套办法修 —— 列名没法绑定 —— " +
		"所以即使框架把其他所有输入都参数化了，这个洞依然在；" +
		"也正因如此，其他的 SQL 检测看不到它：该子句不接受带引号的字符串，也无法用 UNION 续接。" +
		"判定依据来自子句自身的行为：追加在范围之内的排序项被接受、页面不变，" +
		"而超出结果集列数的列序号被拒绝。",
	KeyCheckSQLiOrderByFix: "把调用方的取值映射到一份固定的允许列名清单，而不是直接透传。" +
		"行数上限是另一个位置：绑定为整数，交给分页检查去发现。",
	KeyCheckXSSStoredTitle: "存储型 XSS",
	KeyCheckXSSStoredDesc: "提交给应用的值被保存下来，之后又作为标记语言返回给访问者，" +
		"于是脚本在对方的浏览器里执行。与反射型不同，这个 payload 会持久存在：" +
		"每个打开该页面的访客都会中招，不需要诱导他们点击任何东西。",
	KeyCheckXSSStoredFix: "在**输出**时编码，而不仅仅在输入时 —— " +
		"值可能是从一条路径写入、由另一条路径渲染的。" +
		"使用默认转义的模板引擎；确需富文本时，按公开的白名单做净化。",
}
