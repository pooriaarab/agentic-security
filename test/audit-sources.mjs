import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,chmod,rm,readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
test('audit rejects nondefault sources and binary locks before running a manager',async()=>{
 const root=await mkdtemp(join(tmpdir(),'audit-sources-')),bin=join(root,'bin'),project=join(root,'project'),marker=join(root,'ran');
 try{
  await mkdir(bin);await mkdir(project);await writeFile(join(project,'package.json'),'{}');
  for(const manager of ['npm','bun']){const p=join(bin,manager);await writeFile(p,`#!${process.execPath}\nrequire('fs').writeFileSync(${JSON.stringify(marker)},'called');console.log(JSON.stringify(${manager==='npm'?'{metadata:{vulnerabilities:{total:0}},vulnerabilities:{}}':'{}'}))`);await chmod(p,0o755);}
  const run=()=>spawnSync(process.execPath,[resolve('dist/cli.js'),'audit',project,'--online'],{encoding:'utf8',env:{...process.env,PATH:bin+':'+process.env.PATH}});
  const npmLock=resolved=>JSON.stringify({lockfileVersion:3,packages:{'node_modules/example':{version:'1.0.0',resolved,dependencies:{registry:'1.0.0'},funding:{url:'https://funding.invalid'}}}});
  await writeFile(join(project,'package-lock.json'),npmLock('https://unapproved.invalid/example.tgz'));
  let result=run();assert.equal(JSON.parse(result.stdout).complete,false);assert.equal(result.status,2);await assert.rejects(readFile(marker));
  await writeFile(join(project,'package-lock.json'),npmLock('https://registry.npmjs.org/example/-/example-1.0.0.tgz'));
  result=run();assert.equal(JSON.parse(result.stdout).complete,true);assert.equal(result.status,0);assert.equal(await readFile(marker,'utf8'),'called');
  await rm(marker);await rm(join(project,'package-lock.json'));
  await writeFile(join(project,'bun.lock'),'// JSONC lock\n{"lockfileVersion":1,"packages":{"example":["example@1.0.0","https://unapproved.invalid",{},""]},}');
  result=run();assert.equal(JSON.parse(result.stdout).complete,false);await assert.rejects(readFile(marker));
  await writeFile(join(project,'bun.lock'),'// JSONC lock\n{"lockfileVersion":1,"packages":{"example":["example@1.0.0","",{},""]},}');
  result=run();assert.equal(JSON.parse(result.stdout).complete,true);assert.equal(result.status,0);await rm(marker);await rm(join(project,'bun.lock'));
  await writeFile(join(project,'bun.lockb'),Buffer.from([0,1,2,3]));result=run();assert.equal(JSON.parse(result.stdout).complete,false);await assert.rejects(readFile(marker));
  console.log(JSON.stringify({artifact:'audit-source-policy',customRegistryRejected:true,officialSourceAccepted:true,fundingMetadataAccepted:true,binaryUnsupported:true}));
 }finally{await rm(root,{recursive:true,force:true});}
});
