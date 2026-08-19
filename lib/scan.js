/**
 * dsh-code-vetter — 扫描引擎
 *
 * 对代码文本执行安全规则匹配，生成安全报告。
 * 支持：单文件扫描、多文件批量扫描、目录扫描。
 */

import { SECURITY_RULES, rulesSummary } from '../rules/security-rules.js';

/**
 * 扫描一段代码文本
 * @param {string} code - 代码内容
 * @param {string} filename - 文件名（用于报告）
 * @param {object} opts - { rules: 自定义规则数组 }
 * @returns {Array} findings - [{rule, severity, category, line, message, fix, cwe}]
 */
export function scanCode(code, filename = 'unknown', opts = {}) {
  const findings = [];
  const rules = opts.rules || SECURITY_RULES;
  const lines = code.split('\n');

  for (const rule of rules) {
    for (const pattern of rule.patterns) {
      const re = new RegExp(pattern.source, pattern.flags + 'g' || 'i');
      let match;
      while ((match = re.exec(code)) !== null) {
        // 定位所在行
        const lineNo = findLine(code, match.index);
        findings.push({
          rule: rule.id,
          severity: rule.severity,
          category: rule.category,
          cwe: rule.cwe,
          line: lineNo,
          snippet: lines[lineNo - 1]?.trim().slice(0, 120) || '',
          message: rule.message,
          fix: rule.fix,
        });
        // 防止零宽匹配死循环
        if (match.index === re.lastIndex) re.lastIndex++;
      }
    }
  }
  return findings;
}

/**
 * 扫描多个文件
 * @param {Array<{name, content}>} files
 * @returns {object} - { findings, perFile }
 */
export function scanFiles(files, opts = {}) {
  const all = [];
  const perFile = [];
  for (const f of files) {
    const findings = scanCode(f.content, f.name, opts);
    perFile.push({ name: f.name, count: findings.length, findings });
    all.push(...findings);
  }
  return { findings: all, perFile };
}

function findLine(code, index) {
  let line = 1;
  for (let i = 0; i < index && i < code.length; i++) {
    if (code[i] === '\n') line++;
  }
  return line;
}

/**
 * 生成安全评分（0-100，从 100 扣）
 */
export function scoreFindings(findings) {
  const weights = { critical: 25, high: 10, medium: 5, low: 2 };
  let score = 100;
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    counts[f.severity]++;
    score -= weights[f.severity] || 2;
  }
  return { score: Math.max(0, score), counts };
}

/** 生成人类可读的安全报告 */
export function formatReport(scanResult, { target = '代码' } = {}) {
  const { findings, perFile } = scanResult;
  const { score, counts } = scoreFindings(findings);
  const lines = [];
  lines.push('🛡️ AI 代码安全审查报告');
  lines.push('='.repeat(50));
  lines.push(`审查对象: ${target}`);
  lines.push(`文件数: ${perFile.length} ｜ 发现: ${findings.length} 个安全问题`);
  lines.push(`严重度: 🔴关键 ${counts.critical} ｜ 🟠高危 ${counts.high} ｜ 🟡中危 ${counts.medium} ｜ 🔵低危 ${counts.low}`);
  lines.push(`安全评分: ${score}/100 ${score >= 85 ? '✅' : score >= 60 ? '⚠️' : '🚨'}`);
  lines.push('');

  if (!findings.length) {
    lines.push('未发现安全问题。代码安全状态良好 ✅');
    return lines.join('\n');
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  const seen = new Set();
  for (const f of sorted) {
    const key = `${f.rule}-${f.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const tag = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' }[f.severity];
    lines.push(`${tag} [${f.severity.toUpperCase()}] ${f.rule} ${f.category}${f.cwe ? ` (${f.cwe})` : ''}`);
    lines.push(`   位置: ${f.filename || ''}:${f.line}`);
    if (f.snippet) lines.push(`   代码: ${f.snippet}`);
    lines.push(`   问题: ${f.message}`);
    lines.push(`   修复: ${f.fix}`);
    lines.push('');
  }
  return lines.join('\n');
}

export { rulesSummary };
