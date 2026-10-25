import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,mkdir,writeFile,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join,resolve } from 'node:path';
import { createServer } from 'node:http';
import { scan } from '../dist/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
test('online scan uses bounded registry requests and marks failed lookups incomplete', async () => {
  const dir=await mkdtemp(join(tmpdir(),'security-registry-'));
  const calls=[];
  const server=createServer((req,res)=>{calls.push(req.url);res.setHeader('Content-Type','application/json');res.end(JSON.stringify({version:'2.0.0'}));});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try {
    await writeFile(join(dir,'package.json'),JSON.stringify({private:true,dependencies:{example:'1.0.0',local:'file:../secret-canary'}}));
    const registry=`http://127.0.0.1:${server.address().port}`;
    const offline=await scan(dir);assert.equal(calls.length,0);assert.equal(offline.updates.length,0);
    const report=await scan(dir,{online:true,registry});
    assert.equal(report.complete,true);assert.equal(calls.length,1);assert.equal(report.updates[0].kind,'major');
    assert.equal(report.updates[0].decisionRequired,true);assert.ok(!JSON.stringify(report).includes('secret-canary'));
    server.removeAllListeners('request');server.on('request',(_q,r)=>{r.statusCode=503;r.end('secret-canary');});
    const failure=await scan(dir,{online:true,registry});assert.equal(failure.complete,false);
    assert.ok(!JSON.stringify(failure).includes('secret-canary'));
    console.log(JSON.stringify({artifact:'registry-e2e',offlineNoNetwork:true,majorDecision:true,httpFailureIncomplete:true}));
  } finally { server.closeAllConnections();await new Promise(r=>server.close(r));await rm(dir,{recursive:true,force:true}); }
});
test('MCP stdio initializes and calls the shared scanner',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'security-mcp-'));
  const client=new Client({name:'e2e',version:'1.0.0'});
  try {
    await writeFile(join(dir,'package.json'),JSON.stringify({private:true}));
    await client.connect(new StdioClientTransport({command:process.execPath,args:[resolve('dist/mcp-bin.js')]}));
    const tools=await client.listTools();assert.ok(tools.tools.some(t=>t.name==='security_scan'));
    const result=await client.callTool({name:'security_scan',arguments:{path:dir}});
    const report=JSON.parse(result.content[0].text);assert.equal(report.manifests,1);assert.equal(report.complete,true);
    console.log(JSON.stringify({artifact:'mcp-e2e',stdio:true,sharedEngine:true}));
  } finally {await client.close();await rm(dir,{recursive:true,force:true});}
});
