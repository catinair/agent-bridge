#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const entry = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli', 'index.js');
import(entry).catch((err) => {
  if (err instanceof Error && err.code === 'ERR_MODULE_NOT_FOUND') {
    console.error('CLI 尚未构建，请先执行: npm run build');
  } else {
    console.error(err instanceof Error ? err.message : String(err));
  }
  process.exit(1);
});
