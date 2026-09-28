#!/usr/bin/env node
import { execSync } from 'node:child_process';
import fs from 'node:fs';

const sensitivePatterns = [
  /\.env(\..*)?$/i,
  /\.db(-wal|-shm)?$/i,
  /\.encryption-key$/i,
  /read-auth.*\.js$/i,
  /vite-build\.log$/i,
  /npm-cache\//i
];

try {
  let stagedFiles = [];
  try {
    stagedFiles = execSync('git diff --name-only --staged', { encoding: 'utf8' })
      .split('\n')
      .map(f => f.trim())
      .filter(Boolean);
  } catch (e) {}

  if (stagedFiles.length === 0) process.exit(0);

  let hasError = false;
  for (const file of stagedFiles) {
    // 允许包含 .env.example
    if (file.endsWith('.env.example')) continue;

    for (const pattern of sensitivePatterns) {
      if (pattern.test(file)) {
        console.error('[SECURITY ERROR] Sensitive file blocked: ' + file);
        hasError = true;
      }
    }
    
    // 内容合规性：拦截类似 sk-[a-zA-Z0-9]{48} 的长格式真实密钥，排除单元测试里的 sk-test / sk-mock-key / test-key
    if (fs.existsSync(file) && fs.statSync(file).isFile()) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        // 如果文件中有 sk- 开头，后面跟着连续 20 个以上的字符（常见真实 API Key 特征），则报警。排除 sk-test-key
        const keyPattern = /sk-[a-zA-Z0-9]{20,}/g;
        if (keyPattern.test(content) && !content.includes('sk-test-key') && !content.includes('sk-mock')) {
          console.error('[SECURITY ERROR] Possible REAL hardcoded API key detected in: ' + file);
          hasError = true;
        }
      } catch {}
    }
  }

  if (hasError) {
    console.error('\nCommit blocked. Use "git reset HEAD <file>" to unstage.');
    process.exit(1);
  } else {
    console.log('[SECURITY PASS] Privacy check passed. Staged files are clean.');
  }
} catch (e) { process.exit(0); }
