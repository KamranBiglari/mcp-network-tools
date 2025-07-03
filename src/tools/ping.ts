import { z } from "zod";
import { ToolDefinition } from './types';

export const pingTool: ToolDefinition = {
    name: 'ping',
    description: 'Test connectivity to a host',
    schema: {
        host: z.string().describe("The hostname or IP address to ping"),
        count: z.number().optional().default(4).describe("Number of ping packets to send")
    },
    handler: async ({ host, count }) => {
        // Implementation using HTTP requests to simulate ping
        try {
            const results = [];
            for (let i = 0; i < count; i++) {
                const start = Date.now();
                await fetch(`https://${host}`, { method: 'HEAD', mode: 'no-cors' });
                const end = Date.now();
                results.push({ 
                    packet: i + 1, 
                    time: end - start 
                });
            }
            return { 
                content:[{
                    type: "text",
                    text: `Ping results for ${host}:\n\n${JSON.stringify(results, null, 2)}`
                }]
            };
        } catch (err: unknown) {
            const error = err as Error;
            return { 
                content: [{
                    type: "text",
                    text: `Error pinging host ${host}: ${error.message}`
                }],
                isError: true
            };
        }
    }
};
