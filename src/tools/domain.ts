import { z } from "zod";
import { whoisDomain } from 'whoiser';
import { ToolDefinition } from './types';

export const domainTool: ToolDefinition = {
    name: 'domain',
    description: 'Get domain whois information',
    schema:{
        domain: z.string().describe("The domain name to query"),
    },
    handler: async ({ domain }) => {
        try {
            const result = await whoisDomain(domain);
            return { 
                content:[{
                    type: "text",
                    text: `Whois information for domain ${domain}:\n\n${JSON.stringify(result)}`
                }]
            };
        } catch (err: unknown) {
            const error = err as Error;
            return { 
                content: [{
                    type: "text",
                    text: `Error fetching whois information for domain ${domain}: ${error.message}`
                }],
                isError: true
            };
        }
    }
};
