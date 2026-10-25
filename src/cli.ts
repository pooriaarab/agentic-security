#!/usr/bin/env node
import { scan } from './index.js';
export async function main(args = process.argv.slice(2)): Promise<void> {
  if (args.length === 1 && ['--help','-h'].includes(args[0])) {
    console.log('Usage: agentic-security scan [root] [--online] [--fail-on high|critical|any]\nOnline mode can disclose private package names to the npm registry.'); return;
  }
  if (args.shift() !== 'scan') throw new Error();
  let root: string | undefined, online = false, threshold: string | undefined;
  while (args.length) {
    const arg = args.shift()!;
    if (arg === '--online') online = true;
    else if (arg === '--fail-on') { threshold = args.shift(); if (!threshold || !['high','critical','any'].includes(threshold)) throw new Error(); }
    else if (arg.startsWith('-') || root !== undefined) throw new Error();
    else root = arg;
  }
  if (online) console.error('Online lookup can disclose private package names to the registry.');
  const report = await scan(root ?? '.',{online}); console.log(JSON.stringify(report));
  if (!report.complete) process.exitCode = 2;
  else if (threshold && report.findings.some(f => threshold === 'any' || f.severity === 'critical' || (threshold === 'high' && f.severity === 'high'))) process.exitCode = 1;
}
main().catch(() => { console.error('Scan failed. Check the command and directory access. Use --help for usage.'); process.exitCode = 1; });
