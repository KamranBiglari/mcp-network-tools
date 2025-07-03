import { z } from "zod";
import { whoisIp } from 'whoiser';
import { ToolDefinition } from './types';

export const ipTool: ToolDefinition = {
    name: 'ip',
    description: 'Get IP whois information',
    schema: {
        ip: z.string().ip().describe("The IP address to query"),
    },
    handler: async ({ ip }) => {
        try {
            const result = await whoisIp(ip);
            return { 
                content:[{
                    type: "text",
                    text: `Whois information for IP ${ip}:\n\n${JSON.stringify(result)}`
                }]
            };
        } catch (err: unknown) {
            const error = err as Error;
            return { 
                content: [{
                    type: "text",
                    text: `Error fetching whois information for IP ${ip}: ${error.message}`
                }],
                isError: true
            };
        }
    }
};
