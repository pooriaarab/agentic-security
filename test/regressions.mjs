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
