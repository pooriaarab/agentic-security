import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { scan, audit, guidance } from './index.js';
export function createServer(): McpServer {
  const server = new McpServer({name:'agentic-security',version:'0.2.2'});
  server.registerTool('security_scan',{description:'Read-only scan. Online mode can disclose private package names.',inputSchema:{path:z.string().default('.'),online:z.boolean().default(false)}},async ({path,online}) => {
    try { return {content:[{type:'text',text:JSON.stringify(await scan(path,{online}))}]}; }
    catch { return {isError:true,content:[{type:'text',text:'Scan failed. Check directory access.'}]}; }
  });
  server.registerTool('security_audit',{description:'Read-only lockfile audit with a trusted host manager. Online permission can disclose dependency names.',inputSchema:{path:z.string().default('.'),online:z.boolean().default(false),manager:z.enum(['auto','npm','bun']).default('auto')}},async ({path,online,manager}) => ({content:[{type:'text',text:JSON.stringify(await audit(path,{online,manager}))}]}));
  server.registerTool('security_guidance',{description:'Static security and upgrade guidance.',inputSchema:{}},async () => ({content:[{type:'text',text:guidance}]}));
  return server;
}
