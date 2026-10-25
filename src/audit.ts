import { constants } from 'node:fs';
import { lstat, realpath, open, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import semver from 'semver';
import { parse as parseJsonc, type ParseError } from 'jsonc-parser';

type Manager = 'auto'|'npm'|'bun';
type Severity = 'info'|'low'|'moderate'|'medium'|'high'|'critical';
export type Advisory = {name: string; severity: Severity; range: string; id?: string; url?: string};
export type AuditReport = {schemaVersion: 1; complete: boolean; manager: Manager; advisories: Advisory[]; errors: {code: string; message: string}[]; command?: string[]};
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const limit = 8 * 1024 * 1024;
const messages = {
  offline: 'Online audit requires explicit permission.',
  input: 'Root or lockfile is invalid, unsupported, ambiguous, changed, or exceeds limits.',
  tool: 'Audit tool failed, is unavailable, or exceeded limits.',
  output: 'Audit output is invalid or incomplete.',
  cleanup: 'Temporary audit files could not be removed.',
  source: 'Lockfile sources require review; only the default npm registry is supported.',
  format: 'Binary Bun lockfiles are unsupported; use a reviewed text lockfile.',
} as const;

/** Audit a stable snapshot with a trusted host-installed package manager. */
export async function audit(root: string, {online = false, manager = 'auto'}: {online?: boolean; manager?: Manager} = {}): Promise<AuditReport> {
  const report: AuditReport = {schemaVersion: 1, complete: false, manager: ['auto','npm','bun'].includes(manager) ? manager : 'auto', advisories: [], errors: []};
  const fail = (code: keyof typeof messages) => { report.complete = false; report.errors.push({code,message:messages[code]}); };
  if (online !== true) { fail('offline'); return report; }
  let temp: string | undefined;
  let stage: keyof typeof messages = 'input';
  try {
    if (!['auto','npm','bun'].includes(manager)) throw new Error();
    const requested = resolve(root), initial = await lstat(requested), base = await realpath(requested);
    if (!initial.isDirectory() || initial.isSymbolicLink()) throw new Error();
    const guard = async () => {
      const current = await lstat(requested);
      if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== initial.dev || current.ino !== initial.ino || await realpath(requested) !== base) throw new Error();
    };
    const names = ['bun.lock','bun.lockb','npm-shrinkwrap.json','package-lock.json','yarn.lock','pnpm-lock.yaml'];
    const found: string[] = [];
    for (const name of names) {
      try { await lstat(join(base,name)); found.push(name); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    }
    const bun = found.filter(n => n.startsWith('bun.')), npm = found.filter(n => n === 'package-lock.json' || n === 'npm-shrinkwrap.json');
    if (found.some(n => n === 'yarn.lock' || n === 'pnpm-lock.yaml') || (bun.length && npm.length)) throw new Error();
    const selected = manager === 'auto' ? bun.length ? 'bun' : 'npm' : manager;
    const file = (selected === 'bun' ? bun : npm)[0];
    if (!file) throw new Error();
    report.manager = selected;
    await guard();
    const path = join(base,file), handle = await open(path,constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let data: Buffer;
    try {
      const before = await handle.stat();
      if (!before.isFile() || before.size > limit) throw new Error();
      data = Buffer.alloc(limit + 1);
      let size = 0;
      while (size < data.length) {
        const read = await handle.read(data,size,data.length-size,size);
        if (!read.bytesRead) break;
        size += read.bytesRead;
      }
      const after = await handle.stat(), current = await lstat(path);
      if (size > limit || size !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || current.isSymbolicLink() || current.dev !== before.dev || current.ino !== before.ino) throw new Error();
      data = data.subarray(0,size);
      await guard();
    } finally { await handle.close(); }
    stage = 'source';
    if (file === 'bun.lockb') { stage = 'format'; throw new Error(); }
    const parseErrors: ParseError[] = [];
    const lock: unknown = selected === 'bun' ? parseJsonc(data.toString('utf8'),parseErrors,{allowTrailingComma:true}) : JSON.parse(data.toString('utf8'));
    if (!object(lock) || parseErrors.length) throw new Error();
    const safeLocal = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 2048 && /^[A-Za-z0-9@_./-]+$/.test(value) && !value.startsWith('/') && !value.split('/').includes('..');
    const official = (value: unknown) => {
      if (typeof value !== 'string') throw new Error();
      if (!value) return;
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.port || url.username || url.password || url.search || url.hash) throw new Error();
    };
    if (selected === 'bun') {
      if (!object(lock.packages)) throw new Error();
      for (const value of Object.values(lock.packages)) {
        if (!Array.isArray(value) || typeof value[0] !== 'string') throw new Error();
        const local = value[0].match(/@(?:workspace|file):(.+)$/);
        if (local) { if (!safeLocal(local[1])) throw new Error(); continue; }
        const version = value[0].slice(value[0].lastIndexOf('@')+1);
        if (!semver.valid(version)) throw new Error();
        official(value[1]);
      }
    } else {
      const stack: unknown[] = [];
      if (object(lock.packages)) stack.push(...Object.values(lock.packages));
      if (object(lock.dependencies)) stack.push(...Object.values(lock.dependencies));
      let inspected = 0;
      while (stack.length) {
        if (++inspected > 100000) throw new Error();
        const value = stack.pop(); if (!object(value)) continue;
        if ('resolved' in value) {
          const resolved = value.resolved;
          const localLink = value.link === true && safeLocal(resolved);
          if (!localLink) official(resolved);
        }
        if (object(value.dependencies)) stack.push(...Object.values(value.dependencies));
      }
    }
    temp = await mkdtemp(join(tmpdir(),'agentic-security-audit-'));
    await writeFile(join(temp,file),data,{mode:0o600});
    await writeFile(join(temp,'package.json'),'{"private":true}',{mode:0o600});
    const config = join(temp,'user-config'), globalConfig = join(temp,'global-config');
    await Promise.all([writeFile(config,'',{mode:0o600}),writeFile(globalConfig,'',{mode:0o600})]);
    const args = selected === 'npm'
      ? ['audit','--package-lock-only','--ignore-scripts','--json','--registry=https://registry.npmjs.org',`--userconfig=${config}`,`--globalconfig=${globalConfig}`]
      : ['audit','--json'];
    report.command = [selected,...(selected === 'npm' ? args.slice(0,5) : args)];
    // Only host process essentials survive. No project or package-manager settings survive.
    const env: NodeJS.ProcessEnv = {};
    for (const key of ['PATH','HOME','USERPROFILE','SystemRoot','WINDIR','TMPDIR','TMP','TEMP']) if (process.env[key] !== undefined) env[key] = process.env[key];
    stage = 'tool';
    const result = await new Promise<{stdout: string; status: number}>((accept,reject) => {
      execFile(selected,args,{cwd:temp,env,timeout:60_000,maxBuffer:limit,encoding:'utf8'},(error,stdout) => {
        if (error && (error.killed || error.code !== 1)) { reject(new Error()); return; }
        accept({stdout,status:error ? 1 : 0});
      });
    });
    stage = 'output';
    const parsed: unknown = JSON.parse(result.stdout);
    if (!object(parsed) || 'error' in parsed) throw new Error();
    const advisories: Advisory[] = [];
    const add = (name: string, value: unknown, range: unknown) => {
      if (!/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(name) || name.length > 214 || !object(value) || typeof range !== 'string' || !range.trim() || range.length > 256 || !semver.validRange(range)) throw new Error();
      const severity = value.severity;
      if (typeof severity !== 'string' || !['info','low','moderate','medium','high','critical'].includes(severity)) throw new Error();
      const entry: Advisory = {name,severity:severity as Severity,range};
      if (typeof value.url === 'string' && /^https:\/\/github\.com\/advisories\/GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/.test(value.url)) {
        entry.url = value.url; entry.id = value.url.split('/').at(-1);
      }
      advisories.push(entry);
    };
    if (selected === 'bun') {
      for (const [name,items] of Object.entries(parsed)) {
        if (!Array.isArray(items)) throw new Error();
        for (const item of items) { if (!object(item)) throw new Error(); add(name,item,item.vulnerable_versions); }
      }
    } else {
      if (!object(parsed.metadata) || !object(parsed.metadata.vulnerabilities) || !object(parsed.vulnerabilities)) throw new Error();
      for (const [name,item] of Object.entries(parsed.vulnerabilities)) {
        if (!object(item) || !Array.isArray(item.via)) throw new Error();
        const direct = item.via.filter(v => typeof v !== 'string');
        if (!direct.length) add(name,item,item.range);
        for (const via of item.via) {
          if (typeof via === 'string') continue;
          if (!object(via)) throw new Error();
          add(name,via,via.range);
        }
      }
      const total = parsed.metadata.vulnerabilities.total;
      const severities = ['info','low','moderate','high','critical'];
      const entries = Object.values(parsed.vulnerabilities);
      let sum = 0;
      for (const severity of severities) {
        const count = parsed.metadata.vulnerabilities[severity] ?? 0;
        if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0 || count !== entries.filter(v => object(v) && v.severity === severity).length) throw new Error();
        sum += count;
      }
      if (typeof total !== 'number' || !Number.isSafeInteger(total) || total < 0 || total !== sum || total !== entries.length || (total > 0) !== (advisories.length > 0)) throw new Error();
    }
    if (result.status === 1 && !advisories.length) throw new Error();
    report.advisories = advisories.filter((a,i,all) => all.findIndex(b => JSON.stringify(a) === JSON.stringify(b)) === i);
    report.complete = true;
  } catch { fail(stage); }
  finally { if (temp) { try { await rm(temp,{recursive:true,force:true}); } catch { fail('cleanup'); } } }
  return report;
}
