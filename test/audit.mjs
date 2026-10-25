import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,chmod,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
test('audit uses a clean snapshot without running project code or copying credentials',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'security-audit-'));
 try{
  const bin=join(dir,'bin'),project=join(dir,'project');await mkdir(bin);await mkdir(project);
  await writeFile(join(project,'package.json'),JSON.stringify({scripts:{preinstall:'touch SENTINEL'},private:true}));
  await writeFile(join(project,'package-lock.json'),'{}');await writeFile(join(project,'.npmrc'),'registry=https://secret-canary.invalid');
  const manager=join(bin,'npm');await writeFile(manager,`#!${process.execPath}\nconst fs=require('fs');const files=fs.readdirSync('.');if(files.includes('.npmrc')||process.env.NPM_TOKEN||process.env.NODE_AUTH_TOKEN)process.exit(9);if(!process.argv.includes('--ignore-scripts'))process.exit(8);if(process.argv.find(x=>x.startsWith('--userconfig=')).split('=')[1]===process.argv.find(x=>x.startsWith('--globalconfig=')).split('=')[1])process.exit(7);console.log(JSON.stringify({metadata:{vulnerabilities:{high:1,total:1}},vulnerabilities:{example:{severity:'high',range:'<2.0.0',via:[{source:1,url:'https://github.com/advisories/GHSA-2222-3333-4444',severity:'high',range:'<2.0.0'}]}}}));process.exit(1);`);await chmod(manager,0o755);
  const args=[resolve('dist/cli.js'),'audit',project];const env={...process.env,PATH:bin+':'+process.env.PATH,NPM_TOKEN:'secret-canary',NODE_AUTH_TOKEN:'secret-canary'};
  const offline=spawnSync(process.execPath,args,{env,encoding:'utf8'});assert.notEqual(offline.status,0);assert.equal(JSON.parse(offline.stdout).complete,false);
  const run=spawnSync(process.execPath,[...args,'--online'],{env,encoding:'utf8'});const report=JSON.parse(run.stdout);assert.equal(report.complete,true,run.stderr);assert.equal(report.advisories[0].name,'example');assert.equal(run.status,1);
  assert.ok(!run.stdout.includes('secret-canary'));assert.equal(await readFile(join(project,'package-lock.json'),'utf8'),'{}');
  await assert.rejects(readFile(join(project,'SENTINEL')));
  await writeFile(manager,`#!${process.execPath}\nconsole.log('secret-canary');process.exit(2)`);
  const bad=spawnSync(process.execPath,[...args,'--online'],{env,encoding:'utf8'});assert.equal(JSON.parse(bad.stdout).complete,false);assert.ok(!bad.stdout.includes('secret-canary'));
  await writeFile(join(project,'npm-shrinkwrap.json'),'{}');
  await writeFile(manager,`#!${process.execPath}\nconst fs=require('fs');if(!fs.existsSync('npm-shrinkwrap.json')||fs.existsSync('package-lock.json'))process.exit(8);console.log(JSON.stringify({metadata:{vulnerabilities:{total:0}},vulnerabilities:{}}))`);
  const precedence=spawnSync(process.execPath,[...args,'--online'],{env,encoding:'utf8'});assert.equal(JSON.parse(precedence.stdout).complete,true);assert.equal(precedence.status,0);
  await writeFile(manager,`#!${process.execPath}\nconsole.log(JSON.stringify({metadata:{vulnerabilities:{total:0,high:4}},vulnerabilities:{}}))`);
  const inconsistent=spawnSync(process.execPath,[...args,'--online'],{env,encoding:'utf8'});assert.equal(JSON.parse(inconsistent.stdout).complete,false);assert.equal(inconsistent.status,2);
  console.log(JSON.stringify({artifact:'lockfile-audit-e2e',credentialsExcluded:true,projectUnchanged:true,projectScriptsNotRun:true}));
 }finally{await rm(dir,{recursive:true,force:true});}
});
