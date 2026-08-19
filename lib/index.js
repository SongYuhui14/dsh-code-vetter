/**
 * dsh-code-vetter — AI 代码安全审查器（Host 端入口）
 *
 * 审查 AI 生成代码 / 任何代码片段的安全性：
 *   注入、密钥泄露、危险函数、不安全依赖、弱加密、认证绕过、明文传输
 */

import { scanCode, scanFiles, formatReport, rulesSummary } from './scan.js';

export const name = 'dsh-code-vetter';
export const inject = {
  optional: ['agent'],
};

export function apply(ctx) {
  const handleScan = async (args = {}) => {
    // 支持两种输入：代码文本 或 文件列表
    const code = args.code || '';
    const files = args.files || [];

    if (!code && !files.length) {
      return '请提供要审查的代码（code 参数）或文件列表（files 参数）。';
    }

    if (code) {
      const findings = scanCode(code, args.filename || 'inline-code.js');
      return formatReport({ findings, perFile: [{ name: args.filename || 'inline', count: findings.length }] });
    }

    const result = scanFiles(files);
    return formatReport(result, { target: files.length > 1 ? `${files.length} 个文件` : files[0]?.name || '代码' });
  };

  ctx.tool?.(
    'vet-code-security',
    {
      description:
        '审查代码安全性：SQL/命令注入、硬编码密钥、危险函数（eval/exec）、弱加密算法、认证绕过、明文传输等。用户提到"审查代码安全"、"代码有没有漏洞"、"这段代码安全吗"、"检查AI生成的代码"时调用。参数: code(代码文本), files(文件数组), filename。',
    },
    async (args) => handleScan(args),
  );

  ctx.command?.('vet-code [code]', '审查代码安全（注入/密钥/危险函数等）', async (_, code) => {
    return handleScan({ code });
  });

  ctx.on?.('ready', () => {
    const summary = rulesSummary();
    ctx.logger?.info?.(
      `[dsh-code-vetter] 已加载。${summary.total} 条安全规则（关键 ${summary.critical} / 高危 ${summary.high}）。输入"审查代码安全"使用。`,
    );
  });
}
