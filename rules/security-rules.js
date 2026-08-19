/**
 * dsh-code-vetter — 安全检测规则库
 *
 * 规则分类（对应 OWASP Top 10 与 CWE 常见类别）：
 *   1. 注入类（SQL/命令/代码注入）
 *   2. 密钥与敏感信息泄露
 *   3. 危险函数调用（eval/exec 等）
 *   4. 不安全依赖与配置
 *   5. 不安全实践（弱加密、明文密码等）
 *
 * 每条规则：{ id, severity, cwe, category, patterns, message, fix }
 * severity: critical / high / medium / low
 */

export const SECURITY_RULES = [
  // ========== 1. 注入类 ==========
  {
    id: 'SQL-INJ-001',
    severity: 'critical',
    cwe: 'CWE-89',
    category: '注入',
    patterns: [
      // SQL 字符串拼接（常见注入点）
      /(execute|query|exec|raw)\s*\(\s*["'`][^"'`]*(\+|\$\{)/i,
      /(SELECT|INSERT|UPDATE|DELETE)\s+.*(\+|\$\{)\s*[^"'`]+/i,
    ],
    message: '检测到 SQL 拼接，可能存在 SQL 注入（CWE-89）',
    fix: '使用参数化查询 / 预编译语句，禁止字符串拼接 SQL',
  },
  {
    id: 'CMD-INJ-001',
    severity: 'critical',
    cwe: 'CWE-78',
    category: '注入',
    patterns: [
      /(?:exec|spawn|system|popen|run)\s*\(\s*["'`][^"'`]*["'`]\s*\+/i,
      /child_process\.(?:exec|spawn|execSync|spawnSync)\s*\([^)]*\+/i,
    ],
    message: '检测到命令执行拼接，可能存在命令注入（CWE-78）',
    fix: '使用参数数组方式传参（如 spawn(cmd, args)），禁止拼接 shell 命令',
  },
  {
    id: 'Eval-CODE-001',
    severity: 'high',
    cwe: 'CWE-95',
    category: '代码执行',
    patterns: [
      /\beval\s*\(/i,
      /new\s+Function\s*\(/i,
      /vm\.runInNewContext\s*\(/i,
    ],
    message: '检测到动态代码执行（eval/Function/vm），可能被注入利用（CWE-95）',
    fix: '避免 eval；确需动态执行时严格校验输入并隔离环境',
  },

  // ========== 2. 密钥与敏感信息泄露 ==========
  {
    id: 'SECRET-001',
    severity: 'critical',
    cwe: 'CWE-798',
    category: '密钥泄露',
    patterns: [
      /(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']/i,
      /(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,})/i,
    ],
    message: '检测到疑似硬编码密钥/口令（CWE-798）',
    fix: '密钥移入环境变量/密钥管理系统，禁止提交到代码库',
  },
  {
    id: 'SECRET-002',
    severity: 'high',
    cwe: 'CWE-312',
    category: '敏感信息',
    patterns: [
      /(private[_-]?key|BEGIN\s+RSA\s+PRIVATE|BEGIN\s+EC\s+PRIVATE)/i,
      /(password|passwd)\s*[:=]\s*["'][^"']{3,}["']/i,
    ],
    message: '检测到疑似私钥/明文口令（CWE-312）',
    fix: '私钥使用密钥管理服务，口令使用哈希存储（如 bcrypt/argon2）',
  },

  // ========== 3. 危险函数 ==========
  {
    id: 'DANGER-001',
    severity: 'high',
    cwe: 'CWE-676',
    category: '危险函数',
    patterns: [
      /\b(gethostbyname|strcpy|strcat|sprintf|gets)\s*\(/i,
      /(innerHTML|outerHTML|document\.write)\s*=/i,
    ],
    message: '检测到危险函数使用（CWE-676：内存不安全函数 / XSS 风险）',
    fix: '使用安全替代（如 textContent 替代 innerHTML），C 语言用安全字符串函数',
  },
  {
    id: 'XSS-001',
    severity: 'high',
    cwe: 'CWE-79',
    category: 'XSS',
    patterns: [
      /dangerouslySetInnerHTML\s*=/i,
      /(v-html|innerHTML|outerHTML|document\.write)\s*=/i,
      /(?:res\.send|res\.write|response\.write|document\.write)\s*\(\s*["'`][^"'`]*["'`]\s*\+/i,
    ],
    message: '检测到不安全 HTML 渲染/输出拼接，可能存在 XSS（CWE-79）',
    fix: '使用安全的渲染方式（textContent/v-html 需转义），严格过滤用户输入',
  },

  // ========== 4. 不安全依赖 ==========
  {
    id: 'DEP-001',
    severity: 'medium',
    cwe: 'CWE-1104',
    category: '依赖',
    patterns: [
      /"dependencies"\s*:\s*\{[^}]*"\*"/,
      /(npm|pip|go get|gem install)\s+install\s+[^ ]+/i,
    ],
    message: '检测到依赖版本锁定不严（通配符版本）或安装命令（CWE-1104）',
    fix: '锁定依赖精确版本，使用锁文件（package-lock.json/requirements.lock）',
  },

  // ========== 5. 不安全实践 ==========
  {
    id: 'CRYPTO-001',
    severity: 'high',
    cwe: 'CWE-327',
    category: '弱加密',
    patterns: [
      /\b(MD5|SHA-?1|DES|RC4|3DES)\b/i,
      /\b(crypto\.createHash\s*\(\s*["']md5|sha1["'])/i,
    ],
    message: '检测到弱加密算法（MD5/SHA1/DES/RC4）（CWE-327）',
    fix: '使用安全算法（SHA-256+、AES-256、国密 SM3/SM4），MD5/SHA1 仅限非安全校验',
  },
  {
    id: 'AUTH-001',
    severity: 'high',
    cwe: 'CWE-287',
    category: '认证',
    patterns: [
      /(allowAll|skipAuth|disableAuth|noAuth|bypassAuth|ignoreAuth)\s*(?:=|==|===)\s*(?:true|1)/i,
      /(bypassAuth|ignoreAuth)\s*\(/i,
      /(authEnabled|requireAuth)\s*(?:=|==|===)\s*(?:false|0)/i,
    ],
    message: '检测到认证绕过/跳过配置（CWE-287）',
    fix: '移除认证绕过配置，确保所有接口经过鉴权',
  },
  {
    id: 'HTTP-001',
    severity: 'medium',
    cwe: 'CWE-319',
    category: '传输安全',
    patterns: [
      /http:\/\/(?!localhost|127\.0\.0\.1)/i,
    ],
    message: '检测到明文 HTTP 地址（CWE-319：明文传输敏感信息）',
    fix: '使用 HTTPS，禁止明文传输敏感数据',
  },
];

/** 按严重度排序规则 */
export function rulesBySeverity() {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...SECURITY_RULES].sort((a, b) => order[a.severity] - order[b.severity]);
}

/** 规则统计 */
export function rulesSummary() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of SECURITY_RULES) counts[r.severity]++;
  return { total: SECURITY_RULES.length, ...counts };
}
