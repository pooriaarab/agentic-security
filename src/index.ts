import { opendir, open, lstat, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, join, relative } from 'node:path';
import semver from 'semver';

export type Finding = { rule: string; severity: 'info'|'low'|'medium'|'high'|'critical'; file: string; message: string };
export type Update = { file: string; section: string; name: string; current: string; latest: string; kind: 'patch'|'minor'|'major'|'review'; decisionRequired: boolean };
export type Report = { schemaVersion: 1; generatedAt: string; complete: boolean; manifests: number; findings: Finding[]; updates: Update[]; errors: {file: string; message: string; dependency?: string}[] };
export const guidance = 'Review lifecycle scripts before installation. Pin GitHub actions to full commit SHAs. Use lockfiles and a publish files allowlist. Age alone does not prove vulnerability. Next.js upgrades require routing, rendering, and deployment checks. React upgrades require matching react-dom and peer dependency checks. Node upgrades require engine, native module, and runtime compatibility checks. Online scans can disclose private package names to the registry. No commands or fixes run.';
const skip = new Set(['.git','node_modules','dist','build','.next','.secrets','coverage','vendor']);
const sections = ['dependencies','devDependencies','optionalDependencies','peerDependencies'];
const nameOK = (s: string) => s.length <= 214 && /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(s);
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
export async function scan(root: string, {online = false, registry = 'https://registry.npmjs.org'}: {online?: boolean; registry?: string} = {}): Promise<Report> {
  const requested = resolve(root), initial = await lstat(requested);
  if (!initial.isDirectory() || initial.isSymbolicLink()) throw new Error('Invalid scan directory.');
  const base = await realpath(requested), report: Report = {schemaVersion: 1, generatedAt: new Date().toISOString(), complete: true, manifests: 0, findings: [], updates: [], errors: []};
  const add = (rule: string, severity: Finding['severity'], file: string, message: string) => report.findings.push({rule,severity,file,message});
  const fail = (file: string, message: string, dependency?: string) => { report.complete = false; if (report.errors.length < 100) report.errors.push({file,message,...(dependency ? {dependency} : {})}); };
  const tasks: {file: string; section: string; name: string; current: string}[] = [];
  let entries = 0, bytes = 0, lock = false, npmrc = false, changed = false;
  const identities = new Map<string, string>();
  const guard = async (path: string) => {
    const st = await lstat(path), key = `${st.dev}:${st.ino}`, canonical = await realpath(path);
    if (st.isSymbolicLink() || canonical !== path || (identities.has(path) && identities.get(path) !== key)) { changed = true; throw new Error(); }
    identities.set(path,key);
    return st;
  };
  const parents = async (path: string) => {
    let dir = base; await guard(dir);
    for (const part of relative(base,path).split('/').slice(0,-1)) { dir = join(dir,part); await guard(dir); }
  };
  const read = async (path: string, file: string) => {
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      await parents(path);
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > 262144 || bytes + stat.size > 8388608) throw new Error();
      await parents(path);
      const current = await lstat(path);
      if (current.dev !== stat.dev || current.ino !== stat.ino) { changed = true; throw new Error(); }
      const data = Buffer.alloc(262145);
      const result = await handle.read(data, 0, data.length, 0);
      bytes += result.bytesRead;
      if (result.bytesRead > 262144 || bytes > 8388608) throw new Error();
      await parents(path);
      return data.subarray(0,result.bytesRead).toString('utf8');
    } catch { fail(file, 'File cannot be read within scan limits.'); return undefined; }
    finally { await handle?.close(); }
  };
  const manifest = (text: string, file: string) => {
    let p: Record<string, unknown>;
    try { const value: unknown = JSON.parse(text); if (!object(value)) throw new Error(); p = value; }
    catch { fail(file,'Manifest is invalid.'); add('manifest-invalid','medium',file,'Manifest is invalid.'); return; }
    if (object(p.scripts)) for (const key of ['preinstall','install','postinstall','prepare','prepublish','prepublishOnly','prepack','postpack','postpublish','preprepare','postprepare']) {
      if (key in p.scripts) add('lifecycle-script','medium',file,`Lifecycle script ${key} requires review.`);
    }
    if (p.private !== true && (!Array.isArray(p.files) || p.files.length === 0)) add('publish-allowlist','low',file,'Publishable package has no files allowlist.');
    for (const section of sections) {
      if (p[section] === undefined) continue;
      if (!object(p[section])) { fail(file,'Dependency section is invalid.'); continue; }
      for (const [name, value] of Object.entries(p[section])) {
        if (tasks.length >= 5000) { fail(file,'Dependency limit reached.'); break; }
        if (!nameOK(name) || typeof value !== 'string' || value.length > 256 || !semver.validRange(value) || !value.trim()) {
          add('dependency-review','medium',file,'Dependency name or source requires manual review; registry lookup skipped.');
          if (typeof value === 'string' && /^(?:workspace:|file:|link:|git|https?:|ssh:|npm:|github:)|\//.test(value)) add('nonregistry-dependency','medium',file,'Dependency uses a nonregistry source or alias.');
          continue;
        }
        tasks.push({file,section,name,current:value});
      }
    }
  };
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > 32) { fail(relative(base,dir),'Traversal depth limit reached.'); return; }
    try {
      await guard(dir);
      const stream = await opendir(dir);
      try { await guard(dir); } catch { await stream.close(); throw new Error(); }
      for await (const entry of stream) {
        if (++entries > 10000) { fail('.','Traversal entry limit reached.'); break; }
        const path = join(dir,entry.name), file = relative(base,path);
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) { if (!skip.has(entry.name)) await walk(path,depth+1); continue; }
        if (!entry.isFile()) continue;
        if (dir === base && ['package-lock.json','npm-shrinkwrap.json','yarn.lock','pnpm-lock.yaml','bun.lock','bun.lockb'].includes(entry.name)) lock = true;
        const workflow = /^\.github\/workflows\/[^/]+\.ya?ml$/.test(file);
        if (entry.name !== 'package.json' && !(dir === base && entry.name === '.npmrc') && !workflow) continue;
        if (entry.name === 'package.json') report.manifests++;
        const text = await read(path,file); if (text === undefined) continue;
        if (entry.name === 'package.json') manifest(text,file);
        else if (entry.name === '.npmrc') {
          npmrc = true;
          const policies = [...text.matchAll(/^\s*ignore-scripts\s*=\s*([^#;\r\n]*)/gmi)];
          if (policies.at(-1)?.[1].trim().replace(/^['"]|['"]$/g,'').toLowerCase() !== 'true') add('script-policy','low',file,'No effective ignore-scripts policy found.');
        } else {
          if (/\bpull_request_target\b/.test(text)) add('pull-request-target','high',file,'Review privileged pull_request_target permissions and untrusted checkout.');
          const uses = /\buses\s*:\s*["']?([^\s"'#]+)/g;
          for (const match of text.matchAll(uses)) if (!match[1].startsWith('./') && !/@[a-f0-9]{40}$/i.test(match[1])) add('action-unpinned','medium',file,'Action is not pinned to a full commit SHA.');
        }
      }
    } catch { fail(relative(base,dir) || '.','Directory or file cannot be read.'); }
  };
  const stat = await lstat(base); if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Invalid scan directory.');
  await walk(base,0);
  if (report.manifests && !lock) add('lockfile-missing','medium','package.json','Root lockfile is missing; nested workspace packages share the root lockfile.');
  if (report.manifests && !npmrc) add('script-policy','low','.npmrc','No root .npmrc script policy found.');
  if (online && !changed) {
    add('registry-privacy','info','.', 'Online lookup can disclose private package names to the registry.');
    let endpoint: URL;
    try { endpoint = new URL(registry); if (!['https:','http:'].includes(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error(); }
    catch { fail('.','Registry URL is invalid.'); return report; }
    const cache = new Map<string,Promise<string | undefined>>();
    const latest = (name: string) => {
      let pending = cache.get(name);
      if (!pending) {
        pending = (async () => {
          try {
            const response = await fetch(`${endpoint.href.replace(/\/$/,'')}/${encodeURIComponent(name)}/latest`,{signal:AbortSignal.timeout(5000),redirect:'error'});
            if (!response.ok) { await response.body?.cancel(); throw new Error(); }
            const reader = response.body?.getReader(); if (!reader) throw new Error();
            let text = '', size = 0;
            try { for (;;) { const chunk = await reader.read(); if (chunk.done) break; size += chunk.value.length; if (size > 262144) throw new Error(); text += new TextDecoder().decode(chunk.value); } }
            finally { await reader.cancel().catch(() => {}); }
            const data: unknown = JSON.parse(text);
            if (!object(data) || typeof data.version !== 'string' || !semver.valid(data.version)) throw new Error();
            return data.version;
          } catch { fail('.','Registry lookup failed or returned invalid metadata.',name); return undefined; }
        })();
        cache.set(name,pending);
      }
      return pending;
    };
    let cursor = 0;
    await Promise.all(Array.from({length:Math.min(6,tasks.length)},async () => {
      while (cursor < tasks.length) {
        const task = tasks[cursor++], version = await latest(task.name); if (!version) continue;
        const minimum = semver.minVersion(task.current); if (!minimum || !semver.gt(version,minimum)) continue;
        const kind = semver.major(version) > minimum.major ? 'major' : semver.minor(version) > minimum.minor ? 'minor' : 'patch';
        report.updates.push({...task,latest:version,kind,decisionRequired:kind === 'major'});
        if (['next','react','react-dom','node','@types/node'].includes(task.name)) add('upgrade-guidance','info',task.file,guidance);
      }
    }));
  }
  report.updates.sort((a,b) => `${a.file}/${a.section}/${a.name}`.localeCompare(`${b.file}/${b.section}/${b.name}`));
  return report;
}
