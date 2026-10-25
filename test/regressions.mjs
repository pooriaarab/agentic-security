import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
test('CLI refuses incomplete scans',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'security-limit-'));
  try {
    await writeFile(join(dir,'package.json'),' '.repeat(262145));
    await writeFile(join(dir,'package-lock.json'),'{}');await writeFile(join(dir,'.npmrc'),'ignore-scripts=true');
    const run=spawnSync(process.execPath,[resolve('dist/cli.js'),'scan',dir,'--fail-on','any'],{encoding:'utf8'});
    assert.equal(JSON.parse(run.stdout).complete,false);assert.equal(run.status,2);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('scan refuses a directory replaced by a symlink before traversal',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'security-race-'));
  try {
    await mkdir(join(dir,'root','nested'),{recursive:true});await mkdir(join(dir,'external'));
    await writeFile(join(dir,'external','package.json'),JSON.stringify({dependencies:{externalcanary:'1.0.0'}}));
    const preload=join(dir,'preload.mjs');
    await writeFile(preload,`import fs from 'node:fs/promises';import{syncBuiltinESMExports}from'node:module';const original=fs.opendir;let changed=false;fs.opendir=async function(p,...args){if(!changed&&String(p).endsWith('/nested')){changed=true;await fs.rmdir(p);await fs.symlink(${JSON.stringify(join(dir,'external'))},p);}return original.call(this,p,...args)};syncBuiltinESMExports();`);
    const run=spawnSync(process.execPath,['--import',preload,resolve('dist/cli.js'),'scan',join(dir,'root')],{encoding:'utf8'});
    const report=JSON.parse(run.stdout);assert.equal(report.manifests,0);assert.equal(report.complete,false);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('file read errors retain sibling findings and npm policy uses the last assignment',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'security-policy-'));
  try{
    await mkdir(join(dir,'.github','workflows'),{recursive:true});
    await writeFile(join(dir,'package.json'),'{}');await writeFile(join(dir,'.npmrc'),'ignore-scripts=true\nignore-scripts=false\n');
    await writeFile(join(dir,'.github','workflows','a.yml'),'name: unreadable');await writeFile(join(dir,'.github','workflows','b.yml'),'jobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4');
    const preload=join(dir,'deny.mjs');await writeFile(preload,`import fs from'node:fs/promises';import{syncBuiltinESMExports}from'node:module';const original=fs.open,originalDir=fs.opendir;fs.opendir=async(...a)=>{const d=await originalDir(...a),all=[];for await(const e of d)all.push(e);return{async*[Symbol.asyncIterator](){yield*all.sort((a,b)=>a.name.localeCompare(b.name))},async close(){}}};fs.open=async function(p,...args){if(String(p).endsWith('/a.yml')){if(process.env.FAIL_CLOSE){const h=await original.call(this,p,...args);const close=h.close.bind(h);h.close=async()=>{await close();throw Error('secret-canary')};return h;}throw Error('secret-canary');}return original.call(this,p,...args)};syncBuiltinESMExports();`);
    for (const FAIL_CLOSE of ['', '1']) {
    const run=spawnSync(process.execPath,['--import',preload,resolve('dist/cli.js'),'scan',dir],{encoding:'utf8',env:{...process.env,FAIL_CLOSE}});const p=JSON.parse(run.stdout);
    assert.equal(p.complete,false);assert.ok(p.findings.some(x=>x.rule==='action-unpinned'));assert.ok(p.findings.some(x=>x.rule==='script-policy'));assert.ok(!run.stdout.includes('secret-canary')); }
  }finally{await rm(dir,{recursive:true,force:true});}
});
