#!/usr/bin/env node
import { scan, audit } from './index.js';
export async function main(args = process.argv.slice(2)): Promise<void> {
  if (args.length === 1 && ['--help','-h'].includes(args[0])) {
    console.log('Usage: agentic-security scan [root] [--online] [--fail-on high|critical|any]\nUsage: agentic-security audit [root] [--online] [--manager auto|npm|bun]\nOnline mode can disclose private package names to the npm registry.'); return;
  }
  const command = args.shift();
  if (command !== 'scan' && command !== 'audit') throw new Error();
  let manager: 'auto'|'npm'|'bun' = 'auto';
  let root: string | undefined, online = false, threshold: string | undefined;
  while (args.length) {
    const arg = args.shift()!;
    if (arg === '--online') online = true;
    else if (arg === '--manager' && command === 'audit') { const value = args.shift(); if (value !== 'auto' && value !== 'npm' && value !== 'bun') throw new Error(); manager = value; }
    else if (arg === '--fail-on' && command === 'scan') { threshold = args.shift(); if (!threshold || !['high','critical','any'].includes(threshold)) throw new Error(); }
    else if (arg.startsWith('-') || root !== undefined) throw new Error();
    else root = arg;
  }
  if (online) console.error('Online lookup can disclose private package names to the registry.');
  if (command === 'audit') {
    const report = await audit(root ?? '.',{online,manager}); console.log(JSON.stringify(report));
    process.exitCode = !report.complete ? 2 : report.advisories.length ? 1 : 0; return;
  }
  const report = await scan(root ?? '.',{online}); console.log(JSON.stringify(report));
  if (!report.complete) process.exitCode = 2;
  else if (threshold && report.findings.some(f => threshold === 'any' || f.severity === 'critical' || (threshold === 'high' && f.severity === 'high'))) process.exitCode = 1;
}
main().catch(() => { console.error('Scan failed. Check the command and directory access. Use --help for usage.'); process.exitCode = 1; });
