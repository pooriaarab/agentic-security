import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';
const cli = resolve('dist/cli.js');
test('installed CLI scans nested manifests, skips symlinks, redacts secrets, and does not mutate', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'agentic-security-e2e-'));
  try {
    await mkdir(join(dir,'packages','nested'),{recursive:true});
    await mkdir(join(dir,'.github','workflows'),{recursive:true});
    const manifest = JSON.stringify({name:'fixture',dependencies:{next:'15.0.0'},scripts:{postinstall:'echo private-canary-123'}});
    await writeFile(join(dir,'package.json'),manifest);
    await writeFile(join(dir,'packages','nested','package.json'),'{broken private-canary-123');
    await writeFile(join(dir,'.env'),'TOKEN=private-canary-123');
    await writeFile(join(dir,'.github','workflows','test.yml'),'on: pull_request_target\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n');
    await symlink(dir,join(dir,'loop'));
    await symlink(cli,join(dir,'security'));
    const run=spawnSync(process.execPath,[join(dir,'security'),'scan',dir],{encoding:'utf8',timeout:15000});
    assert.equal(run.status,2,run.stderr);
    const report=JSON.parse(run.stdout);
    assert.equal(report.schemaVersion,1);
    assert.equal(report.complete,false);
    assert.ok(report.findings.some(x=>x.rule==='manifest-invalid'));
    assert.ok(report.findings.some(x=>x.rule==='lifecycle-script'));
    assert.ok(report.findings.some(x=>x.rule==='action-unpinned'));
    assert.ok(!run.stdout.includes('private-canary-123'));
    assert.equal(await readFile(join(dir,'package.json'),'utf8'),manifest);
    const bad=spawnSync(process.execPath,[cli,'unknown'],{encoding:'utf8'});
    assert.notEqual(bad.status,0);
    const missing=spawnSync(process.execPath,[cli,'scan',join(dir,'absent')],{encoding:'utf8'});
    assert.notEqual(missing.status,0);
    console.log(JSON.stringify({artifact:'cli-e2e',nestedManifest:true,secretRedacted:true,sourceUnchanged:true,symlinkBin:true}));
  } finally { await rm(dir,{recursive:true,force:true}); }
});
