#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './mcp.js';
createServer().connect(new StdioServerTransport()).catch(() => { console.error('MCP server failed.'); process.exitCode = 1; });
