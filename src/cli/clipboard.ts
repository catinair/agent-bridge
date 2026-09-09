import { spawnSync } from 'node:child_process';

/** Best-effort clipboard write; returns false when no tool is available. */
export function copyToClipboard(text: string): boolean {
  const candidates: string[][] =
    process.platform === 'darwin'
      ? [['pbcopy']]
      : process.platform === 'win32'
        ? [['clip']]
        : [
            ['wl-copy'],
            ['xclip', '-selection', 'clipboard'],
            ['xsel', '--clipboard', '--input'],
          ];
  for (const candidate of candidates) {
    const [cmd, ...args] = candidate;
    if (!cmd) continue;
    try {
      const r = spawnSync(cmd, args, { input: text, stdio: ['pipe', 'ignore', 'ignore'] });
      if (r.status === 0) return true;
    } catch {
      // try next candidate
    }
  }
  return false;
}
