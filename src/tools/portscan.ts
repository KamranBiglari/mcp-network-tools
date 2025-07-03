import { z } from "zod";
import { ToolDefinition } from './types';

export const portscanTool: ToolDefinition = {
    name: 'portscan',
    description: 'Check if specific ports are open on a host',
    schema: z.object({
        host: z.string().describe("The hostname or IP address to scan"),
        ports: z.array(z.number()).describe("Array of port numbers to check"),
        timeout: z.number().optional().default(5000).describe("Timeout in milliseconds")
    }),
    handler: async ({ host, ports, timeout }) => {
        // Implementation using fetch with timeouts
        try {
            const results = await Promise.all(
                ports.map(async (port) => {
                    const controller = new AbortController();
                    const id = setTimeout(() => controller.abort(), timeout);
                    try {
                        await fetch(`https://${host}`, { method: 'HEAD', mode: 'no-cors', signal: controller.signal });
                        return { port, open: true };
                    } catch (err: any) {
                        if (err.name === 'AbortError') {
                            return { port, open: false, error: 'timeout' };
                        }
                        return { port, open: false, error: err.message };
                    } finally {
                        clearTimeout(id);
                    }
                })
            );
            return { 
                content:[{
                    type: "text",
                    text: `Port scan results for ${host}:\n\n${JSON.stringify(results, null, 2)}`
                }]
            };
        } catch (err: unknown) {
            const error = err as Error;
            return { 
                content: [{
                    type: "text",
                    text: `Error performing port scan on ${host}: ${error.message}`
                }],
                isError: true
            };
        }
    }
};
