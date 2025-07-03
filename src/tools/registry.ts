import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ToolDefinition } from './types';

export function registerTool(server: McpServer, tool: ToolDefinition) {
    server.tool(
        tool.name,
        tool.description,
        tool.schema,
        tool.handler
    );
}
